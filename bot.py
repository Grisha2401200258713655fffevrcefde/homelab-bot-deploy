#!/usr/bin/env python3
"""Homelab Sentinel v7 — Clean rewrite. AI intent, smart deploy, persistent storage."""
import os, re, json, time, asyncio, logging, io, concurrent.futures
from datetime import datetime
from pathlib import Path
import aiohttp, paramiko
from minio import Minio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── CONFIG ────────────────────────────────────────────────────────────────
BOT_TOKEN    = os.environ["BOT_TOKEN"]
ADMIN_ID     = int(os.environ["ADMIN_CHAT_ID"])
MINIO_URL    = os.environ["MINIO_URL"]
MINIO_USER   = os.environ["MINIO_USER"]
MINIO_PASS   = os.environ["MINIO_PASS"]
SANDBOX_HOST = os.environ["SANDBOX_HOST"]
SANDBOX_USER = os.environ["SANDBOX_USER"]
SANDBOX_PASS = os.environ["SANDBOX_PASS"]
PROD_HOST    = os.environ["PROD_HOST"]
PROD_USER    = os.environ["PROD_USER"]
PROD_PASS    = os.environ["PROD_PASS"]
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
SSH_KEY      = os.environ.get("SSH_KEY_PATH", "")
TRIVY_URL    = "http://192.168.31.178:4954"
OLLAMA_URL   = "http://192.168.31.178:11434"
OLLAMA_MODEL = "qwen2.5:0.5b"
DASHBOARD_PATH = "/opt/homelab/dashboard/index.html"

# ── AI INTENT STACKS ─────────────────────────────────────────────────────
INTENT_STACKS = {
    "фильм|кино|видео|медиа|jellyfin|plex": ["jellyfin"],
    "фото|фотографи|immich|галере|снимок": ["immich"],
    "пароль|bitwarden|vaultwarden|секрет|логин": ["vaultwarden"],
    "автоматизац|workflow|zapier|n8n|ботов": ["n8n"],
    "мониторинг|uptime|алерт|следи|доступн": ["uptime-kuma", "beszel"],
    "файл|хранилищ|облак|nextcloud|диск": ["nextcloud"],
    "документ|paperless|ocr|скан|бумаг": ["paperless-ngx"],
    "дашборд|главн|стартов|панел": ["glance", "homepage"],
    "бюджет|финанс|деньг|расход": ["actual-budget"],
    "рецепт|еда|готовить|кухн": ["mealie"],
    "dns|реклам|блокир|adguard": ["adguard-home"],
    "vpn|туннель|wireguard|сет": ["headscale"],
    "график|метрик|grafana|prometheus": ["grafana"],
    "pdf|документ|конверт|merge": ["stirling-pdf"],
    "docker|контейнер|portainer|управл": ["portainer"],
    "закладк|bookmark|linkwarden|ссылк": ["linkwarden"],
    "рецепт|планировщ|меню": ["mealie"],
    "сайт|измен|monitor|changedetection": ["changedetection"],
}

# ── SERVICES DB ───────────────────────────────────────────────────────────
CAT_NAME  = {"M":"Мониторинг","V":"Медиа","S":"Безопасность","F":"Файлы","N":"Сеть","P":"Продуктивность","A":"Автоматизация","I":"Инфраструктура","G":"Аналитика","C":"Коммуникации","D":"Базы данных"}
CAT_EMOJI = {"M":"📊","V":"🎬","S":"🔐","F":"📁","N":"🌐","P":"📝","A":"🤖","I":"🛠","G":"📈","C":"💬","D":"🗄"}

SVC = {
    "uptime-kuma":     {"img":"louislam/uptime-kuma","c":"M","s":87000,"d":"Мониторинг с уведомлениями","port":3001,"login":None,"pass":None,"note":"Создать аккаунт при первом входе","setup":["mkdir -p {data}/uptime-kuma"],"vols":["{data}/uptime-kuma:/app/data"],"env":{},"w":12,"hc":"http://localhost:{port}"},
    "beszel":          {"img":"henrygd/beszel","c":"M","s":9000,"d":"Лёгкий мониторинг серверов","port":8090,"login":"admin@admin.com","pass":"admin","note":None,"setup":["mkdir -p {data}/beszel"],"vols":["{data}/beszel:/beszel_data"],"env":{},"w":10,"hc":"http://localhost:{port}"},
    "dozzle":          {"img":"amir20/dozzle","c":"M","s":7000,"d":"Логи Docker в реальном времени","port":8082,"login":None,"pass":None,"note":"Без авторизации","setup":[],"vols":["/var/run/docker.sock:/var/run/docker.sock"],"env":{},"w":5,"hc":"http://localhost:{port}"},
    "netdata":         {"img":"netdata/netdata","c":"M","s":73000,"d":"Мониторинг производительности","port":19999,"login":None,"pass":None,"note":"Без авторизации","setup":[],"vols":["/proc:/host/proc:ro","/sys:/host/sys:ro","/var/run/docker.sock:/var/run/docker.sock:ro"],"env":{},"w":15,"hc":"http://localhost:{port}"},
    "jellyfin":        {"img":"jellyfin/jellyfin","c":"V","s":37000,"d":"Медиасервер — замена Plex","port":8096,"login":None,"pass":None,"note":"Мастер при первом входе","setup":["mkdir -p {data}/jellyfin/config {data}/jellyfin/cache {data}/jellyfin/media"],"vols":["{data}/jellyfin/config:/config","{data}/jellyfin/cache:/cache","{data}/jellyfin/media:/media"],"env":{},"w":25,"hc":"http://localhost:{port}/health"},
    "vaultwarden":     {"img":"vaultwarden/server","c":"S","s":41000,"d":"Bitwarden-совместимый сервер паролей","port":80,"login":None,"pass":None,"note":"Создать аккаунт при первом входе","setup":["mkdir -p {data}/vaultwarden"],"vols":["{data}/vaultwarden:/data"],"env":{"ADMIN_TOKEN":"hlsecret123"},"w":10,"hc":"http://localhost:{port}"},
    "filebrowser":     {"img":"filebrowser/filebrowser","c":"F","s":28000,"d":"Веб файловый менеджер","port":8080,"login":"admin","pass":"admin","note":None,"setup":["mkdir -p {data}/filebrowser","touch {data}/filebrowser/db.db"],"vols":["{data}/filebrowser:/srv","{data}/filebrowser/db.db:/database.db"],"env":{},"w":6,"hc":"http://localhost:{port}"},
    "nextcloud":       {"img":"nextcloud","c":"F","s":28000,"d":"Self-hosted облако","port":8080,"login":"admin","pass":"adminpassword","note":None,"setup":["mkdir -p {data}/nextcloud"],"vols":["{data}/nextcloud:/var/www/html"],"env":{"NEXTCLOUD_ADMIN_USER":"admin","NEXTCLOUD_ADMIN_PASSWORD":"adminpassword","NEXTCLOUD_TRUSTED_DOMAINS":"localhost"},"w":30,"hc":"http://localhost:{port}"},
    "paperless-ngx":   {"img":"ghcr.io/paperless-ngx/paperless-ngx","c":"F","s":24000,"d":"Управление документами с OCR","port":8000,"login":"admin","pass":"admin","note":None,"setup":["mkdir -p {data}/paperless/data {data}/paperless/media {data}/paperless/export {data}/paperless/consume"],"vols":["{data}/paperless/data:/usr/src/paperless/data","{data}/paperless/media:/usr/src/paperless/media","{data}/paperless/export:/usr/src/paperless/export","{data}/paperless/consume:/usr/src/paperless/consume"],"env":{"PAPERLESS_SECRET_KEY":"hlsecret123","PAPERLESS_OCR_LANGUAGE":"rus+eng"},"w":40,"hc":"http://localhost:{port}"},
    "nginx-proxy-manager":{"img":"jc21/nginx-proxy-manager","c":"N","s":23000,"d":"Reverse proxy с SSL","port":81,"login":"admin@example.com","pass":"changeme","note":None,"setup":["mkdir -p {data}/npm/data {data}/npm/le"],"vols":["{data}/npm/data:/data","{data}/npm/le:/etc/letsencrypt"],"env":{},"w":20,"hc":"http://localhost:{port}"},
    "adguard-home":    {"img":"adguard/adguardhome","c":"N","s":26000,"d":"DNS с блокировкой рекламы","port":3000,"login":None,"pass":None,"note":"Настройка при первом входе","setup":["mkdir -p {data}/adguard/work {data}/adguard/conf"],"vols":["{data}/adguard/work:/opt/adguardhome/work","{data}/adguard/conf:/opt/adguardhome/conf"],"env":{},"w":10,"hc":"http://localhost:{port}"},
    "actual-budget":   {"img":"actualbudget/actual-server","c":"P","s":16000,"d":"Локальный менеджер бюджета","port":5006,"login":None,"pass":None,"note":"Создать аккаунт при первом входе","setup":["mkdir -p {data}/actual"],"vols":["{data}/actual:/data"],"env":{},"w":10,"hc":"http://localhost:{port}"},
    "mealie":          {"img":"ghcr.io/mealie-recipes/mealie","c":"P","s":8000,"d":"Менеджер рецептов","port":9000,"login":"changeme@example.com","pass":"MyPassword","note":None,"setup":["mkdir -p {data}/mealie"],"vols":["{data}/mealie:/app/data"],"env":{"ALLOW_SIGNUP":"true","TZ":"Europe/Moscow"},"w":18,"hc":"http://localhost:{port}"},
    "n8n":             {"img":"n8nio/n8n","c":"A","s":52000,"d":"Визуальная автоматизация","port":5678,"login":"admin","pass":"changeme","note":None,"setup":["mkdir -p {data}/n8n"],"vols":["{data}/n8n:/home/node/.n8n"],"env":{"N8N_BASIC_AUTH_ACTIVE":"true","N8N_BASIC_AUTH_USER":"admin","N8N_BASIC_AUTH_PASSWORD":"hlsecret123","N8N_SECURE_COOKIE":"false"},"w":15,"hc":"http://localhost:{port}"},
    "changedetection": {"img":"ghcr.io/dgtlmoon/changedetection.io","c":"A","s":21000,"d":"Мониторинг изменений сайтов","port":5000,"login":None,"pass":None,"note":"Без авторизации","setup":["mkdir -p {data}/changedetection"],"vols":["{data}/changedetection:/datastore"],"env":{},"w":10,"hc":"http://localhost:{port}"},
    "glance":          {"img":"glanceapp/glance","c":"I","s":34000,"d":"Красивый дашборд с виджетами","port":8080,"login":None,"pass":None,"note":"Без авторизации","setup":["mkdir -p {data}/glance","printf 'pages:\\n  - name: Home\\n    columns:\\n      - size: full\\n        widgets:\\n          - type: clock\\n            hour-format: 24h\\n' > {data}/glance/glance.yml"],"vols":["{data}/glance:/app/config"],"env":{},"w":6,"hc":"http://localhost:{port}"},
    "homepage":        {"img":"ghcr.io/gethomepage/homepage","c":"I","s":22000,"d":"Современный дашборд","port":3000,"login":None,"pass":None,"note":"Без авторизации","setup":["mkdir -p {data}/homepage","echo '{}' > {data}/homepage/settings.yaml","echo '[]' > {data}/homepage/services.yaml","echo '[]' > {data}/homepage/bookmarks.yaml","echo '[]' > {data}/homepage/widgets.yaml"],"vols":["{data}/homepage:/app/config","/var/run/docker.sock:/var/run/docker.sock:ro"],"env":{},"w":12,"hc":"http://localhost:{port}"},
    "stirling-pdf":    {"img":"frooodle/s-pdf","c":"I","s":48000,"d":"PDF: merge/split/OCR/convert","port":8080,"login":None,"pass":None,"note":"Без авторизации","setup":["mkdir -p {data}/stirling-pdf"],"vols":["{data}/stirling-pdf:/configs"],"env":{"DOCKER_ENABLE_SECURITY":"false"},"w":20,"hc":"http://localhost:{port}"},
    "portainer":       {"img":"portainer/portainer-ce","c":"I","s":32000,"d":"Веб-интерфейс для Docker","port":9000,"login":None,"pass":None,"note":"Создать admin при первом входе","setup":["mkdir -p {data}/portainer"],"vols":["/var/run/docker.sock:/var/run/docker.sock","{data}/portainer:/data"],"env":{},"w":8,"hc":"http://localhost:{port}"},
    "grafana":         {"img":"grafana/grafana","c":"G","s":65000,"d":"Дашборды и метрики","port":3000,"login":"admin","pass":"adminpassword","note":None,"setup":["mkdir -p {data}/grafana"],"vols":["{data}/grafana:/var/lib/grafana"],"env":{"GF_SECURITY_ADMIN_PASSWORD":"adminpassword","GF_USERS_ALLOW_SIGN_UP":"false"},"w":10,"hc":"http://localhost:{port}"},
    "linkwarden":      {"img":"ghcr.io/linkwarden/linkwarden","c":"P","s":9000,"d":"Менеджер закладок с архивацией","port":3000,"login":None,"pass":None,"note":"Создать аккаунт при первом входе","setup":["mkdir -p {data}/linkwarden"],"vols":["{data}/linkwarden:/data/data"],"env":{"NEXTAUTH_SECRET":"hlsecret123","NEXTAUTH_URL":"http://localhost:3000"},"w":20,"hc":"http://localhost:{port}"},
    "postgres":        {"img":"postgres","c":"D","s":15000,"d":"PostgreSQL — реляционная СУБД","port":5432,"login":"admin","pass":"adminpassword","note":None,"setup":["mkdir -p {data}/postgres"],"vols":["{data}/postgres:/var/lib/postgresql/data"],"env":{"POSTGRES_USER":"admin","POSTGRES_PASSWORD":"adminpass","POSTGRES_DB":"testdb"},"w":10,"hc":None},
}

DATA_DIR = "/opt/hl-data"

def resolve_svc(svc, port=None):
    """Подставляем реальные пути в конфиге сервиса."""
    p = port or svc.get("port", 8080)
    def r(s): return s.replace("{data}", DATA_DIR).replace("{port}", str(p))
    return {
        **svc,
        "setup": [r(c) for c in svc.get("setup", [])],
        "vols":  [r(v) for v in svc.get("vols", [])],
        "hc":    r(svc["hc"]) if svc.get("hc") else None,
    }

def find_svc(image):
    img = image.lower().split(":")[0]
    name = img.split("/")[-1]
    for k, v in SVC.items():
        if v["img"].lower() == img: return k, v
        if k == name: return k, v
        if k in img: return k, v
    return None, None

# ── MINIO ─────────────────────────────────────────────────────────────────
_mc = None
def get_mc():
    global _mc
    if _mc is None:
        _mc = Minio(MINIO_URL.replace("http://","").replace("https://",""), access_key=MINIO_USER, secret_key=MINIO_PASS, secure=False)
        for b in ["test-results","deployed","saved-later","history","trivy-scans"]:
            try:
                if not _mc.bucket_exists(b): _mc.make_bucket(b)
            except: pass
    return _mc

def mput(bucket, key, data):
    try:
        p = json.dumps(data, ensure_ascii=False, indent=2, default=str).encode()
        get_mc().put_object(bucket, key, io.BytesIO(p), len(p), content_type="application/json")
    except Exception as e: log.warning(f"mput: {e}")

def mget(bucket, key):
    try:
        r = get_mc().get_object(bucket, key)
        return json.loads(r.read())
    except: return None

def mlist(bucket, prefix="", limit=10):
    out = []
    try:
        keys = sorted([o.object_name for o in get_mc().list_objects(bucket, prefix=prefix, recursive=True)], reverse=True)[:limit]
        for k in keys:
            try:
                r = get_mc().get_object(bucket, k)
                out.append(json.loads(r.read()))
            except: pass
    except: pass
    return out

# ── SEEN / PORT DB в MinIO ────────────────────────────────────────────────
def load_seen():
    try:
        r = get_mc().get_object("deployed", "seen/projects.txt")
        return set(r.read().decode().splitlines())
    except: return set()

def save_seen(names):
    s = load_seen()
    s.update(n.lower() for n in names)
    data = "\n".join(sorted(s)).encode()
    try:
        get_mc().put_object("deployed", "seen/projects.txt", io.BytesIO(data), len(data), content_type="text/plain")
    except: pass

def reset_seen():
    try: get_mc().remove_object("deployed", "seen/projects.txt")
    except: pass

def load_port_db():
    """Загружаем БД занятых портов из MinIO."""
    return mget("deployed", "ports/db.json") or {}

def save_port_db(db):
    mput("deployed", "ports/db.json", db)

def get_used_ports_on_prod():
    """Получаем реально занятые порты с mini-prod."""
    out, _, _ = pr("docker ps --format '{{.Ports}}' 2>/dev/null")
    used = set()
    for line in out.strip().splitlines():
        for m in re.finditer(r':(\d+)->', line):
            used.add(int(m.group(1)))
    return used

def find_free_port(preferred, used_ports, start=10000, end=19999):
    if preferred and preferred not in used_ports:
        return preferred
    for port in range(start, end):
        if port not in used_ports:
            return port
    return None

# ── SSH ───────────────────────────────────────────────────────────────────
def ssh_run(host, user, pwd, cmd, t=60):
    for attempt in range(3):
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if SSH_KEY and os.path.exists(SSH_KEY):
                c.connect(host, username=user, key_filename=SSH_KEY, timeout=10)
            else:
                c.connect(host, username=user, password=pwd, timeout=10)
            _, out, err = c.exec_command(cmd, timeout=t)
            o = out.read().decode(errors="replace")
            e = err.read().decode(errors="replace")
            code = out.channel.recv_exit_status()
            c.close()
            return o, e, code
        except Exception as ex:
            if attempt == 2: return "", str(ex), -1
            time.sleep(2 ** attempt)

def sb(cmd, t=60): return ssh_run(SANDBOX_HOST, SANDBOX_USER, SANDBOX_PASS, cmd, t)
def pr(cmd, t=60): return ssh_run(PROD_HOST, PROD_USER, PROD_PASS, cmd, t)
def s1(cmd, t=60): return ssh_run("192.168.31.178", SANDBOX_USER, SANDBOX_PASS, cmd, t)

# ── AI INTENT ─────────────────────────────────────────────────────────────
async def ai_find_stack(text):
    """Определяем намерение через ключевые слова, потом Ollama."""
    text_lower = text.lower()
    # Сначала ключевые слова
    for pattern, stack in INTENT_STACKS.items():
        for kw in pattern.split("|"):
            if kw in text_lower:
                return stack
    # Потом Ollama
    prompt = (
        f'Пользователь homelab написал: "{text}"\n'
        f'Что он хочет развернуть? Ответь одним словом из списка:\n'
        f'фильм, фото, пароль, автоматизация, мониторинг, файл, документ, дашборд, бюджет, рецепт, dns, vpn, grafana, pdf, docker, закладки, сайт, неизвестно\n'
        f'Ответ:'
    )
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=aiohttp.ClientTimeout(total=45)
            ) as r:
                if r.status == 200:
                    d = await r.json()
                    intent = d.get("response", "").strip().lower()
                    log.info(f"Ollama intent: {intent!r}")
                    for pattern, stack in INTENT_STACKS.items():
                        for kw in pattern.split("|"):
                            if kw in intent:
                                return stack
    except Exception as e:
        log.warning(f"Ollama error: {e}")
    return []

# ── PIPELINE ──────────────────────────────────────────────────────────────
def pipeline(image, version, prog):
    target = f"{image}:{version}"
    _, svc = find_svc(image)
    rsvc = resolve_svc(svc) if svc else None
    cn = "hlt_" + re.sub(r'[^a-z0-9]', '_', image.split("/")[-1].lower())
    res = {"image": image, "version": version, "ts": datetime.now().isoformat(),
           "status": "error", "score": 0, "steps": {}, "metrics": {}, "fail": "", "diag": "", "rec": ""}

    def p(m): prog.append(m)

    # Pull
    p("📥 Pull...")
    o, e, code = sb(f"docker pull {target} 2>&1", 180)
    if code != 0:
        res["steps"]["pull"] = {"ok": False, "d": (e or o)[:100]}
        res["fail"] = "pull"; res["diag"] = (e or o)[:300]; res["rec"] = "Образ недоступен"; return res
    try:
        so, _, _ = sb(f"docker image inspect {target} --format '{{{{.Size}}}}' 2>/dev/null")
        size = int(so.strip()) // 1024 // 1024
        res["metrics"]["size_mb"] = size
        res["steps"]["pull"] = {"ok": True, "d": f"{size}MB"}; p(f"✓ Pull — {size}MB")
    except:
        res["steps"]["pull"] = {"ok": True, "d": "ok"}; p("✓ Pull")

    # Trivy
    p("🔒 Trivy...")
    to, _, _ = sb(f"trivy image --server {TRIVY_URL} --format json --quiet {target} 2>/dev/null", 120)
    crit = high = med = 0
    try:
        for r2 in json.loads(to).get("Results", []):
            for v in (r2.get("Vulnerabilities") or []):
                s = v.get("Severity", "")
                if s == "CRITICAL": crit += 1
                elif s == "HIGH": high += 1
                elif s == "MEDIUM": med += 1
    except: pass
    res["metrics"].update({"crit": crit, "high": high, "med": med})
    res["steps"]["sec"] = {"ok": crit == 0, "d": f"CRIT:{crit} HIGH:{high} MED:{med}"}
    p(f"{'✓' if crit == 0 else '⚠'} Security — CRIT:{crit} HIGH:{high} MED:{med}")

    # Setup
    if rsvc:
        for cmd in rsvc.get("setup", []):
            sb(cmd.replace(DATA_DIR, "/tmp/t"), 15)

    sb(f"docker rm -f {cn} 2>/dev/null || true")

    # Run
    p("💨 Запуск...")
    ef = " ".join(f'-e "{k}={v}"' for k, v in (svc.get("env", {}) if svc else {}).items())
    vf_list = []
    for v in (svc.get("vols", []) if svc else []):
        vf_list.append(v.replace("{data}", "/tmp/t").replace("{port}", str(svc.get("port", 8080) if svc else 8080)))
    vf = " ".join(f"-v {v}" for v in vf_list)
    pf = ""
    if rsvc:
        tp = {rsvc["port"]: rsvc["port"] + 10000}
        pf = " ".join(f"-p {h}:{c}" for c, h in tp.items())

    o, e, code = sb(f"docker run -d --name {cn} --restart=no --memory=512m {ef} {vf} {pf} {target} 2>&1", 30)
    if code != 0:
        res["steps"]["smoke"] = {"ok": False, "d": (e or o)[:100]}
        res["fail"] = "smoke"; res["diag"] = (e or o)[:400]; res["rec"] = "Не запускается"
        sb(f"docker rm -f {cn} 2>/dev/null || true"); return res

    wait = rsvc["w"] if rsvc else 10
    p(f"⏳ Жду {wait}с..."); time.sleep(wait)
    state, _, _ = sb(f"docker inspect {cn} --format '{{{{.State.Running}}}}' 2>/dev/null")
    if "true" not in state.lower():
        crash, _, _ = sb(f"docker logs {cn} 2>&1 | tail -8")
        res["steps"]["smoke"] = {"ok": False, "d": "упал"}
        res["diag"] = crash[:400]; res["fail"] = "smoke"; res["rec"] = "Падает — проверь конфиг"
        sb(f"docker rm -f {cn} 2>/dev/null || true"); return res
    res["steps"]["smoke"] = {"ok": True, "d": f"живёт {wait}с"}; p("✓ Smoke")

    # HTTP
    hc = rsvc["hc"] if rsvc else None
    if hc:
        p("🌐 HTTP...")
        ho, _, _ = sb(f"curl -sf --max-time 10 -o /dev/null -w '%{{http_code}}|%{{time_total}}' {hc} 2>/dev/null")
        pts = ho.strip().split("|")
        hcode = pts[0] if pts else ""
        try: ms = int(float(pts[1]) * 1000) if len(pts) > 1 else 0
        except: ms = 0
        ok = hcode in ("200","201","204","301","302","401","403")
        res["metrics"]["resp_ms"] = ms
        res["steps"]["http"] = {"ok": ok, "d": f"HTTP {hcode} {ms}мс"}
        p(f"{'✓' if ok else '✗'} HTTP — {hcode} {ms}мс")

    # Resources
    p("📊 Ресурсы...")
    st, _, _ = sb(f"docker stats {cn} --no-stream --format '{{{{.MemUsage}}}}|{{{{.CPUPerc}}}}' 2>/dev/null")
    mem = cpu = 0
    try:
        mp, cp = st.strip().split("|")
        m = re.search(r'([\d.]+)([MG]iB)', mp)
        if m: v2 = float(m.group(1)); mem = int(v2 * 1024 if m.group(2) == "GiB" else v2)
        c2 = re.search(r'([\d.]+)', cp)
        if c2: cpu = float(c2.group(1))
    except: pass
    res["metrics"].update({"mem_mb": mem, "cpu": cpu})
    res["steps"]["res"] = {"ok": mem < 400, "d": f"RAM {mem}MB CPU {cpu:.1f}%"}
    p(f"✓ Ресурсы — RAM:{mem}MB CPU:{cpu:.1f}%")

    # Restart
    p("🔄 Restart...")
    sb(f"docker restart {cn}", 30); time.sleep(min(wait, 8))
    s2, _, _ = sb(f"docker inspect {cn} --format '{{{{.State.Running}}}}' 2>/dev/null")
    rok = "true" in s2.lower()
    res["steps"]["rst"] = {"ok": rok, "d": "выжил" if rok else "упал"}
    p(f"{'✓' if rok else '✗'} Restart")

    # Cleanup
    sb(f"docker rm -f {cn} 2>/dev/null || true")
    res["steps"]["clean"] = {"ok": True, "d": "ok"}; p("✓ Cleanup")

    # Score
    w = {"pull": 10, "sec": 20, "smoke": 25, "http": 15, "res": 10, "rst": 15, "clean": 5}
    score = sum(wt for k, wt in w.items() if res["steps"].get(k, {}).get("ok"))
    score -= min(crit * 10, 30); score -= min(high * 2, 10); score = max(0, min(100, score))
    res["score"] = score; res["status"] = "pass" if score >= 60 else "fail"
    if score >= 85: res["rec"] = "Отлично — готов к деплою"
    elif score >= 70: res["rec"] = "Хорошо — можно деплоить"
    elif score >= 60: res["rec"] = "Работает, есть замечания"
    elif crit > 0: res["rec"] = f"Не деплоить — {crit} CRITICAL CVE"
    else: res["rec"] = "Нестабильная работа"
    return res

# ── DEPLOY ────────────────────────────────────────────────────────────────
async def do_deploy(message, image, version):
    _, svc = find_svc(image)
    target = f"{image}:{version}"
    cname = image.split("/")[-1].lower().split(":")[0]
    loop = asyncio.get_event_loop()

    # Проверяем не запущен ли уже
    existing, _, _ = await loop.run_in_executor(None, lambda: pr(f"docker inspect {cname} --format '{{{{.State.Running}}}}' 2>/dev/null"))
    if "true" in existing.lower():
        await message.reply_text(f"INFO: `{cname}` уже запущен. Используй /manage для управления.", parse_mode="Markdown")
        return

    await message.reply_text(f"Разворачиваю `{image}:{version}`...", parse_mode="Markdown")

    # Определяем порт
    preferred_port = svc["port"] if svc else None
    if not preferred_port:
        o, _, _ = await loop.run_in_executor(None, lambda: pr(f"docker image inspect {target} --format '{{{{json .Config.ExposedPorts}}}}' 2>/dev/null"))
        try:
            ports = json.loads(o)
            if ports: preferred_port = int(list(ports.keys())[0].split("/")[0])
        except: pass

    # Smart port
    used_ports = await loop.run_in_executor(None, get_used_ports_on_prod)
    free_port = find_free_port(preferred_port, used_ports) if preferred_port else None
    if preferred_port and free_port != preferred_port:
        log.info(f"Port {preferred_port} busy, using {free_port} for {cname}")

    # Resolv svc с реальным портом
    rsvc = resolve_svc(svc, free_port) if svc else None

    # Setup на проде
    if rsvc:
        for cmd in rsvc.get("setup", []):
            await loop.run_in_executor(None, lambda c=cmd: pr(f"sudo mkdir -p {DATA_DIR} 2>/dev/null; {c}"))

    # Сохраняем rollback
    await loop.run_in_executor(None, lambda: pr(f"docker inspect {cname} --format '{{{{.Config.Image}}}}' 2>/dev/null | sudo tee /opt/homelab/rollback_{cname}.txt >/dev/null 2>&1 || true"))
    await loop.run_in_executor(None, lambda: pr(f"docker rm -f {cname} 2>/dev/null || true"))

    # Собираем параметры
    ef = ""
    vf = ""
    if rsvc:
        if rsvc.get("env"):
            ef = " ".join(f'-e "{k}={v}"' for k, v in rsvc["env"].items())
        if rsvc.get("vols"):
            prod_vols = []
            for vol in rsvc["vols"]:
                prod_vols.append(vol)
            vf = " ".join(f"-v {v}" for v in prod_vols)

    pf = f"-p {free_port}:{preferred_port}" if free_port and preferred_port else ""

    o, e, code = await loop.run_in_executor(None, lambda: pr(
        f"docker run -d --restart unless-stopped --name {cname} {pf} {ef} {vf} "
        f"--label com.centurylinklabs.watchtower.enable=true {target} 2>&1", 60))

    if code != 0:
        await message.reply_text(f"Ошибка:\n```\n{(e or o)[:200]}\n```", parse_mode="Markdown"); return

    await asyncio.sleep(5)
    state, _, _ = await loop.run_in_executor(None, lambda: pr(f"docker inspect {cname} --format '{{{{.State.Running}}}}' 2>/dev/null"))
    if "true" not in state.lower():
        logs, _, _ = await loop.run_in_executor(None, lambda: pr(f"docker logs {cname} 2>&1 | tail -10"))
        await message.reply_text(f"Контейнер упал:\n```\n{logs[:300]}\n```", parse_mode="Markdown"); return

    # Сохраняем в БД
    port_db = load_port_db()
    port_db[cname] = {"port": free_port, "image": target, "deployed_at": datetime.now().isoformat()}
    save_port_db(port_db)
    mput("deployed", f"{image.replace('/','_')}/{version}.json", {"image": target, "container": cname, "port": free_port, "deployed_at": datetime.now().isoformat()})
    mput("history", f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_{image.replace('/','_')}.json", {"image": target, "action": "deploy", "port": free_port, "ts": datetime.now().isoformat()})
    save_seen([cname])
    asyncio.create_task(generate_dashboard())

    url = f"http://{PROD_HOST}:{free_port}" if free_port else None
    lines = [f"✅ `{image}:{version}` запущен!\n"]
    if url: lines.append(f"Адрес: {url}")
    if preferred_port and free_port != preferred_port:
        lines.append(f"Порт изменён: {preferred_port} -> {free_port}")
    login = svc.get("login") if svc else None
    passwd = svc.get("pass") if svc else None
    note = svc.get("note") if svc else None
    if login and passwd:
        lines += [f"Логин: `{login}`", f"Пароль: `{passwd}`"]
    elif note:
        lines.append(f"_{note}_")
    rows = []
    if url: rows.append([url_btn("Открыть", url)])
    rows.append([btn("Rollback", f"do:rbk:{cname}:x")])
    await message.reply_text("\n".join(lines), parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(rows))

# ── TEST ──────────────────────────────────────────────────────────────────
async def do_test(message, image, version):
    pmsg = await message.reply_text(f"Pipeline: `{image}:{version}`\n\nСтарт...", parse_mode="Markdown")
    prog = [f"`{image}:{version}`\n"]
    async def upd():
        try: await pmsg.edit_text("\n".join(prog[-12:]), parse_mode="Markdown")
        except: pass
    loop = asyncio.get_event_loop(); pl = []
    with concurrent.futures.ThreadPoolExecutor() as pool:
        fut = loop.run_in_executor(pool, pipeline, image, version, pl)
        while not fut.done():
            await asyncio.sleep(3)
            if pl: prog.extend(pl); pl.clear(); await upd()
        result = await fut
    if pl: prog.extend(pl)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    mput("test-results", f"{image.replace('/','_')}/{version}/{ts}.json", result)
    mput("history", f"{ts}_{image.replace('/','_')}.json", {**result, "action": "test"})
    icon = "✅" if result["status"] == "pass" else "❌"
    score = result["score"]; steps = result.get("steps", {}); metrics = result.get("metrics", {})
    lines = [f"{icon} `{image}:{version}`", f"Оценка: *{score}/100*", "", "*Этапы:*"]
    for k, lbl in [("pull","📥 Pull"),("sec","🔒 Security"),("smoke","💨 Smoke"),("http","🌐 HTTP"),("res","📊 Ресурсы"),("rst","🔄 Restart"),("clean","🧹 Cleanup")]:
        if k not in steps: continue
        s = steps[k]; ico = "✓" if s.get("ok") else "✗"; det = s.get("d", "")
        lines.append(f"  {ico} {lbl}" + (f": {det}" if det else ""))
    if metrics:
        lines += ["", "*Метрики:*"]
        if "size_mb" in metrics: lines.append(f"  {metrics['size_mb']}MB")
        if "mem_mb" in metrics: lines.append(f"  RAM {metrics['mem_mb']}MB")
        if "cpu" in metrics: lines.append(f"  CPU {metrics['cpu']:.1f}%")
        if metrics.get("crit"): lines.append(f"  CRITICAL: {metrics['crit']}")
        if metrics.get("high"): lines.append(f"  HIGH: {metrics['high']}")
        if "resp_ms" in metrics: lines.append(f"  {metrics['resp_ms']}мс")
    diag = result.get("diag", "")
    if diag and result["status"] != "pass": lines += ["", f"```\n{diag[:250]}\n```"]
    rec = result.get("rec", "")
    if rec: lines += ["", f"_{rec}_"]
    if result["status"] == "pass":
        kb = InlineKeyboardMarkup([
            [btn("Развернуть на mini-prod", f"do:deploy:{image}:{version}")],
            [btn("Перетест", f"do:test:{image}:{version}"), btn("Отмена", f"do:rej:x:x")]
        ])
    else:
        kb = InlineKeyboardMarkup([
            [btn("Сохранить для доработки", f"do:save:{image}:{version}")],
            [btn("Перетест", f"do:test:{image}:{version}"), btn("Отмена", f"do:rej:x:x")]
        ])
    await message.reply_text("\n".join(lines), parse_mode="Markdown", reply_markup=kb)

# ── DASHBOARD ─────────────────────────────────────────────────────────────
async def generate_dashboard():
    loop = asyncio.get_event_loop()
    out, _, _ = await loop.run_in_executor(None, lambda: pr("docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'"))
    containers = []
    for line in out.strip().splitlines():
        if "|" not in line: continue
        parts = line.split("|")
        name = parts[0]; img = parts[1]; status = parts[2]; ports = parts[3] if len(parts) > 3 else ""
        m = re.search(r':(\d+)->', ports)
        port = m.group(1) if m else None
        url = f"http://{PROD_HOST}:{port}" if port else None
        is_up = status.lower().startswith("up")
        _, svc = find_svc(name)
        containers.append({"name": name, "img": img, "status": status, "url": url, "is_up": is_up,
                           "login": svc["login"] if svc else None, "pass": svc["pass"] if svc else None,
                           "note": svc["note"] if svc else None})
    saved = mlist("saved-later", limit=30)
    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    up = [c for c in containers if c["is_up"]]
    down = [c for c in containers if not c["is_up"]]

    def card(c, cls):
        url_b = f'<a href="{c["url"]}" target="_blank" class="btn">Открыть</a>' if c.get("url") else ""
        creds = ""
        if c.get("login") and c.get("pass"):
            creds = f'<div class="creds"><span class="label">Логин</span> <code>{c["login"]}</code><br><span class="label">Пароль</span> <code>{c["pass"]}</code></div>'
        elif c.get("note"):
            creds = f'<div class="creds">{c["note"]}</div>'
        badge = "Работает" if cls == "up" else "Упал"
        nm = c["name"]
        mgmt = f'''<div class="mgmt">
  <button onclick="doAction(\'restart\',\'{nm}\')" class="mbtn restart">Рестарт</button>
  <button onclick="doAction(\'stop\',\'{nm}\')" class="mbtn stop">Стоп</button>
  <button onclick="if(confirm(\'Удалить {nm}?\'))doAction(\'remove\',\'{nm}\')" class="mbtn remove">Удалить</button>
  <button onclick="doAction(\'logs\',\'{nm}\')" class="mbtn logs">Логи</button>
</div>'''
        return f'<div class="card {cls}"><div class="card-top"><span class="name">{nm}</span><span class="badge {cls}">{badge}</span></div><div class="img-tag">{c["img"]}</div><div class="status">{c["status"]}</div>{creds}{url_b}{mgmt}</div>'

    def saved_card(s):
        img = s.get("image", "?")
        rec = s.get("rec", "?")
        diag = s.get("diag", "")[:150].replace("<", "&lt;").replace(">", "&gt;")
        ts = s.get("ts", "")[:10]
        gh = ""
        if "/" in img and "." not in img.split("/")[0]:
            gh = f'<a href="https://github.com/{img.split(":")[0]}" target="_blank" class="btn btn-gh">GitHub</a>'
        return f'<div class="card saved"><div class="card-top"><span class="name">{img.split("/")[-1].split(":")[0]}</span><span class="badge saved">Доработка</span></div><div class="img-tag">{img}</div><div class="status">{rec}</div><div class="diag">{diag}</div><div class="ts">{ts}</div>{gh}</div>'

    up_cards = "".join(card(c, "up") for c in up) or '<div class="empty">Нет работающих сервисов</div>'
    down_cards = "".join(card(c, "down") for c in down) or '<div class="empty">Все сервисы работают</div>'
    seen_saved = set()
    sc_list = []
    for s in saved:
        img = s.get("image", "?")
        if img not in seen_saved:
            seen_saved.add(img)
            sc_list.append(saved_card(s))
    saved_cards = "".join(sc_list) or '<div class="empty">Нет для доработки</div>'

    html = f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>Homelab Dashboard</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}}
.header{{background:#161b22;border-bottom:1px solid #30363d;padding:20px 32px;display:flex;justify-content:space-between;align-items:center}}
.header h1{{font-size:22px;font-weight:700;color:#58a6ff}}
.header .time{{color:#8b949e;font-size:13px}}
.wrap{{max-width:1200px;margin:0 auto;padding:24px 32px}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;text-align:center}}
.stat .n{{font-size:40px;font-weight:800;line-height:1}}
.stat .l{{color:#8b949e;font-size:13px;margin-top:6px}}
.n.green{{color:#3fb950}}.n.red{{color:#f85149}}.n.yellow{{color:#d29922}}
.section{{margin-bottom:32px}}
.stitle{{font-size:16px;font-weight:600;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #30363d}}
.stitle.green{{color:#3fb950}}.stitle.red{{color:#f85149}}.stitle.yellow{{color:#d29922}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:18px}}
.card.up{{border-left:4px solid #3fb950}}.card.down{{border-left:4px solid #f85149}}.card.saved{{border-left:4px solid #d29922}}
.card-top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
.name{{font-size:15px;font-weight:600}}
.badge{{font-size:11px;padding:3px 10px;border-radius:20px;font-weight:500}}
.badge.up{{background:#0d4429;color:#3fb950}}.badge.down{{background:#3d0c0c;color:#f85149}}.badge.saved{{background:#3d2800;color:#d29922}}
.img-tag{{font-size:12px;color:#8b949e;font-family:monospace;margin-bottom:6px}}
.status{{font-size:13px;color:#8b949e;margin-bottom:10px}}
.creds{{background:#0d1117;border-radius:8px;padding:10px;margin-bottom:12px;font-size:13px}}
.label{{color:#8b949e;font-size:11px}}
code{{background:#21262d;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:12px;color:#79c0ff}}
.diag{{background:#0d1117;border-radius:8px;padding:10px;font-size:11px;font-family:monospace;color:#8b949e;margin-bottom:8px;max-height:60px;overflow:hidden}}
.ts{{font-size:11px;color:#484f58;margin-bottom:10px}}
.btn{{display:inline-block;padding:8px 16px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:500;background:#1f6feb;color:#fff;margin-right:8px;margin-top:8px}}
.btn:hover{{background:#388bfd}}.btn-gh{{background:#21262d;color:#e6edf3}}.btn-gh:hover{{background:#30363d}}
.empty{{color:#484f58;font-style:italic;padding:20px;text-align:center;background:#161b22;border-radius:12px;border:1px solid #30363d}}
.mgmt{{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;padding-top:10px;border-top:1px solid #30363d}}
.mbtn{{padding:5px 10px;border-radius:6px;border:none;cursor:pointer;font-size:12px;font-weight:500}}
.mbtn.restart{{background:#1f4788;color:#79c0ff}}.mbtn.stop{{background:#3d2800;color:#d29922}}
.mbtn.remove{{background:#3d0c0c;color:#f85149}}.mbtn.logs{{background:#21262d;color:#8b949e}}
.modal{{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:1000;align-items:center;justify-content:center}}
.modal.active{{display:flex}}
.modal-box{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:24px;max-width:600px;width:90%;max-height:80vh;overflow:auto}}
.modal-title{{font-size:16px;font-weight:600;margin-bottom:16px;color:#e6edf3;display:flex;justify-content:space-between}}
.modal-close{{cursor:pointer;color:#8b949e;font-size:20px}}
.modal-content{{font-family:monospace;font-size:12px;color:#8b949e;white-space:pre-wrap;background:#0d1117;padding:12px;border-radius:8px}}
.toast{{position:fixed;bottom:24px;right:24px;background:#1f6feb;color:#fff;padding:12px 20px;border-radius:8px;font-size:14px;opacity:0;transition:opacity .3s;z-index:2000}}
.toast.show{{opacity:1}}.toast.error{{background:#b91c1c}}.toast.ok{{background:#166534}}
</style>
<script>
const API="http://192.168.31.178:8098";
async function doAction(a,n){{
  if(a==="logs"){{showToast("Загружаю...");try{{const r=await fetch(API+"/logs/"+n);const d=await r.json();showModal("Логи: "+n,d.logs||d.error||"Нет данных");}}catch(e){{showToast("Ошибка: "+e,true);}}return;}}
  showToast(a+" "+n+"...");
  try{{const r=await fetch(API+"/"+a+"/"+n,{{method:"POST"}});const d=await r.json();
  if(d.ok){{showToast("OK: "+a+" "+n,false,true);setTimeout(()=>location.reload(),2000);}}
  else{{showToast("Ошибка: "+(d.error||"?"),true);}}}}catch(e){{showToast("Нет связи с API",true);}}
}}
function showToast(m,e=false,s=false){{const t=document.getElementById("toast");t.textContent=m;t.className="toast show"+(e?" error":(s?" ok":""));setTimeout(()=>t.className="toast",3000);}}
function showModal(t,c){{document.getElementById("modal-title").textContent=t;document.getElementById("modal-content").textContent=c;document.getElementById("modal").className="modal active";}}
function closeModal(){{document.getElementById("modal").className="modal";}}
</script>
</head><body>
<div id="modal" class="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal-box"><div class="modal-title"><span id="modal-title"></span><span class="modal-close" onclick="closeModal()">X</span></div>
  <div class="modal-content" id="modal-content"></div></div>
</div>
<div id="toast" class="toast"></div>
<div class="header"><h1>Homelab Dashboard</h1><div class="time">Обновлено: {now} (каждые 30с)</div></div>
<div class="wrap">
<div class="stats">
  <div class="stat"><div class="n green">{len(up)}</div><div class="l">Работают</div></div>
  <div class="stat"><div class="n red">{len(down)}</div><div class="l">Упали</div></div>
  <div class="stat"><div class="n yellow">{len(seen_saved)}</div><div class="l">Доработка</div></div>
</div>
<div class="section"><div class="stitle green">Работающие ({len(up)})</div><div class="grid">{up_cards}</div></div>
<div class="section"><div class="stitle red">Упавшие ({len(down)})</div><div class="grid">{down_cards}</div></div>
<div class="section"><div class="stitle yellow">Требуют доработки ({len(seen_saved)})</div><div class="grid">{saved_cards}</div></div>
</div></body></html>"""

    def write_file():
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if SSH_KEY and os.path.exists(SSH_KEY):
                c.connect("192.168.31.178", username=SANDBOX_USER, key_filename=SSH_KEY, timeout=10)
            else:
                c.connect("192.168.31.178", username=SANDBOX_USER, password=SANDBOX_PASS, timeout=10)
            sftp = c.open_sftp()
            with sftp.file(DASHBOARD_PATH, "w") as f:
                f.write(html)
            sftp.close(); c.close()
            return True
        except Exception as e:
            log.error(f"Dashboard write: {e}")
            return False
    return await loop.run_in_executor(None, write_file)

# ── HELPERS ───────────────────────────────────────────────────────────────
def admin_only(func):
    async def wrapper(update, ctx):
        uid = update.effective_user.id if update.effective_user else update.callback_query.from_user.id
        if uid != ADMIN_ID: return
        return await func(update, ctx)
    return wrapper

def btn(text, data): return InlineKeyboardButton(text, callback_data=data)
def url_btn(text, u): return InlineKeyboardButton(text, url=u)

def build_cat_menu():
    seen = load_seen(); available = {}
    for name, svc in SVC.items():
        if name.lower() not in seen:
            c = svc["c"]; available[c] = available.get(c, 0) + 1
    return available

# ── COMMANDS ──────────────────────────────────────────────────────────────
@admin_only
async def cmd_start(update, ctx):
    kb = InlineKeyboardMarkup([
        [btn("Каталог по категориям", "sc:MENU:0")],
        [btn("Поиск по интернету", "ap:EXPLORE:x")],
        [btn("Автопилот", "ap:AUTO:x")],
        [btn("Управление сервисами", "ap:MANAGE:x")],
        [btn("Статус серверов", "ap:STATUS:x")],
        [btn("Dashboard", "ap:DASH:x")],
    ])
    await update.message.reply_text(
        "*Homelab Sentinel v7*\n\n"
        "Пиши мне что хочешь:\n"
        "_хочу смотреть фильмы_\n"
        "_хочу хранить пароли_\n"
        "_хочу мониторинг_\n\n"
        "Или используй команды:\n"
        "/search /explore /manage /status\n"
        "/logs /history /deployed /trivy /reset",
        parse_mode="Markdown",
        reply_markup=kb
    )

@admin_only
async def cmd_search(update, ctx):
    available = build_cat_menu()
    if not available:
        await update.message.reply_text("Всё просмотрено. /reset — сбросить кэш"); return
    rows = []
    for code in sorted(available.keys(), key=lambda x: CAT_NAME.get(x, x)):
        name = CAT_NAME.get(code, code); em = CAT_EMOJI.get(code, ""); cnt = available[code]
        rows.append([btn(f"{em} {name} ({cnt})", "sc:" + code + ":0")])
    rows.append([btn("Все категории", "sc:ALL:0"), btn("Сброс кэша", "sc:RST:0")])
    await update.message.reply_text("Выбери категорию:", reply_markup=InlineKeyboardMarkup(rows))

@admin_only
async def cmd_explore(update, ctx):
    query = " ".join(ctx.args) if ctx.args else ""
    if not query:
        await update.message.reply_text("Использование: /explore тема\nНапример: /explore osint"); return
    await _do_explore(update.message, query)

async def _do_explore(message, query):
    msg = await message.reply_text(f"Ищу *{query}* по интернету...", parse_mode="Markdown")
    try:
        results = await asyncio.wait_for(_search_github_only(query), timeout=30)
    except:
        results = []
    if not results:
        await msg.edit_text(f"По запросу *{query}* ничего не нашёл", parse_mode="Markdown"); return
    await msg.edit_text(f"Нашёл *{len(results)}* результатов по *{query}*", parse_mode="Markdown")
    for item in results[:8]:
        stars = item.get("stars", 0)
        desc = item.get("desc", "")[:120]
        lines = [f"*{item['name']}* (gh)", f"⭐{stars:,}", f"_{desc}_"]
        rows = []
        docker_img = item.get("docker_img")
        if docker_img:
            rows.append([btn("Тест Docker", f"do:test:{docker_img}:latest")])
        if item.get("url"):
            rows.append([url_btn("GitHub", item["url"])])
        await message.reply_text("\n".join(lines), parse_mode="Markdown",
                                 reply_markup=InlineKeyboardMarkup(rows) if rows else None,
                                 disable_web_page_preview=True)
        await asyncio.sleep(0.3)

async def _search_github_only(query, limit=8):
    results = []
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN: headers["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.github.com/search/repositories",
                headers=headers,
                params={"q": f"{query} stars:>100", "sort": "stars", "order": "desc", "per_page": limit},
                timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                if r.status != 200: return results
                data = await r.json()
        for repo in data.get("items", []):
            if repo.get("archived"): continue
            desc = repo.get("description", "") or ""
            has_docker = "docker" in desc.lower() or "docker" in repo.get("topics", [])
            results.append({
                "name": repo["name"], "url": repo["html_url"], "desc": desc[:200],
                "stars": repo["stargazers_count"], "has_docker": has_docker,
                "docker_img": f"{repo['owner']['login']}/{repo['name']}".lower() if has_docker else None
            })
    except Exception as e:
        log.warning(f"GitHub search: {e}")
    return results

@admin_only
async def cmd_manage(update, ctx):
    await _show_manage(update.message)

async def _show_manage(message):
    loop = asyncio.get_event_loop()
    out, _, _ = await loop.run_in_executor(None, lambda: pr("docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'"))
    lines = ["*Запущенные сервисы на mini-prod:*\n"]
    rows = []
    for line in out.strip().splitlines():
        if "|" not in line: continue
        parts = line.split("|"); name = parts[0]; img = parts[1]; status = parts[2]; ports = parts[3] if len(parts) > 3 else ""
        pm = re.search(r':(\d+)->', ports)
        port = pm.group(1) if pm else None
        url = f"http://{PROD_HOST}:{port}" if port else None
        lines.append(f"* `{name}`\n  {img}\n  {status}")
        row = [btn("Рестарт", f"mg:restart:{name}:x"), btn("Стоп", f"mg:stop:{name}:x"),
               btn("Удалить", f"mg:remove:{name}:x"), btn("Логи", f"mg:logs:{name}:x")]
        if url: row.append(url_btn("Открыть", url))
        rows.append(row)
    if len(lines) == 1: lines.append("Пусто")
    await message.reply_text("\n".join(lines), parse_mode="Markdown",
                             reply_markup=InlineKeyboardMarkup(rows) if rows else None)

@admin_only
async def cmd_find(update, ctx):
    if not ctx.args:
        await update.message.reply_text("Использование: /find jellyfin"); return
    query = " ".join(ctx.args).lower()
    found = [(n, v) for n, v in SVC.items() if query in n.lower() or query in v.get("d", "").lower()]
    if not found:
        await update.message.reply_text(f"'{query}' не найден\nПопробуй /explore {query}"); return
    for name, svc in found[:5]:
        cat = CAT_NAME.get(svc["c"], svc["c"]); em = CAT_EMOJI.get(svc["c"], "")
        lines = [f"*{name}* {em} {cat} ⭐{svc['s']:,}", f"`{svc['img']}`", f"_{svc['d']}_"]
        kb = InlineKeyboardMarkup([[btn("Тест", f"do:test:{svc['img']}:latest"), btn("Пропустить", f"do:skip:{name}:x")]])
        await update.message.reply_text("\n".join(lines), parse_mode="Markdown", reply_markup=kb)

@admin_only
async def cmd_logs(update, ctx):
    if not ctx.args:
        await update.message.reply_text("Использование: /logs имя_контейнера"); return
    name = ctx.args[0]
    loop = asyncio.get_event_loop()
    out, _, code = await loop.run_in_executor(None, lambda: pr(f"docker logs {name} --tail 40 2>&1"))
    if code != 0 or not out.strip():
        await update.message.reply_text(f"Контейнер `{name}` не найден", parse_mode="Markdown"); return
    lines = out.strip().splitlines()[-25:]
    await update.message.reply_text(f"*Логи {name}*\n```\n{chr(10).join(lines)[:3500]}\n```", parse_mode="Markdown")

@admin_only
async def cmd_status(update, ctx):
    msg = await update.message.reply_text("Проверяю серверы...")
    async def chk(name, host, user, pwd):
        loop = asyncio.get_event_loop()
        try:
            o, _, _ = await loop.run_in_executor(None, lambda: ssh_run(host, user, pwd,
                "docker ps --format '{{.Names}}' | wc -l && free -h|awk '/Mem/{print $3\"/\"$2}' && df -h /|awk 'NR==2{print $3\"/\"$2}'", 15))
            parts = o.strip().splitlines()
            count = parts[0].strip() if parts else "?"
            ram = parts[1].strip() if len(parts) > 1 else "?"
            disk = parts[2].strip() if len(parts) > 2 else "?"
            return name, True, count, ram, disk
        except Exception as e:
            return name, False, "?", str(e)[:60], "?"
    res = await asyncio.gather(
        chk("srv1", "192.168.31.178", SANDBOX_USER, SANDBOX_PASS),
        chk("sand-box", SANDBOX_HOST, SANDBOX_USER, SANDBOX_PASS),
        chk("mini-prod", PROD_HOST, PROD_USER, PROD_PASS),
    )
    lines = ["*Статус серверов*\n"]
    for name, ok, count, ram, disk in res:
        if ok: lines.append(f"OK *{name}*: {count} контейнеров, RAM {ram}, Диск {disk}")
        else: lines.append(f"ERR *{name}* — {ram}")
    await msg.edit_text("\n".join(lines), parse_mode="Markdown")

@admin_only
async def cmd_history(update, ctx):
    tests = mlist("test-results", limit=10); deployed = mlist("deployed", limit=10)
    lines = ["*История*\n"]
    if deployed:
        lines.append("*Задеплоено:*")
        for d in deployed[:5]:
            ts = d.get("deployed_at", "")[:10]; img = d.get("image", "?")
            lines.append(f"  OK `{img}` — {ts}")
    if tests:
        lines.append("\n*Последние тесты:*")
        for t in tests[:5]:
            ts = t.get("ts", "")[:10]; img = t.get("image", "?"); score = t.get("score", 0)
            icon = "OK" if t.get("status") == "pass" else "FAIL"
            lines.append(f"  {icon} `{img}` — {score}/100 — {ts}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

@admin_only
async def cmd_deployed(update, ctx):
    loop = asyncio.get_event_loop()
    o, _, _ = await loop.run_in_executor(None, lambda: pr("docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}'"))
    lines = ["*На mini-prod:*\n"]
    for line in o.strip().splitlines():
        if "|" in line:
            p = line.split("|"); lines.append(f"* `{p[0]}`\n  {p[1]}\n  {p[2]}")
    if len(lines) == 1: lines.append("Пусто")
    await update.message.reply_text("\n\n".join(lines), parse_mode="Markdown")

@admin_only
async def cmd_saved(update, ctx):
    items = mlist("saved-later", limit=20)
    if not items:
        await update.message.reply_text("Нет сохранённых"); return
    lines = [f"*Сохранено ({len(items)}):*\n"]
    rows = []
    seen_imgs = set()
    for item in items:
        img = item.get("image", "?")
        if img in seen_imgs: continue
        seen_imgs.add(img)
        ts = item.get("ts", "")[:10]; rec = item.get("rec", "?")
        lines.append(f"*{img}*\n  _{rec}_\n  _{ts}_")
        rows.append([btn("Ретест", f"do:test:{img}:latest"), btn("Удалить", f"do:del:{img}:x")])
    await update.message.reply_text("\n\n".join(lines), parse_mode="Markdown",
                                   reply_markup=InlineKeyboardMarkup(rows) if rows else None)

@admin_only
async def cmd_trivy(update, ctx):
    msg = await update.message.reply_text("Trivy скан запущен...")
    loop = asyncio.get_event_loop()
    out, _, _ = await loop.run_in_executor(None, lambda: pr("docker ps --format '{{.Names}}|{{.Image}}'"))
    containers = []
    for line in out.strip().splitlines():
        if "|" in line:
            parts = line.split("|"); containers.append((parts[0], parts[1]))
    if not containers:
        await msg.edit_text("Нет запущенных контейнеров"); return
    results = []; total_crit = 0
    for name, img in containers:
        to, _, _ = await loop.run_in_executor(None, lambda i=img: sb(f"trivy image --server {TRIVY_URL} --format json --quiet {i} 2>/dev/null", 120))
        crit = high = 0
        try:
            for r2 in json.loads(to).get("Results", []):
                for v in (r2.get("Vulnerabilities") or []):
                    s = v.get("Severity", "")
                    if s == "CRITICAL": crit += 1
                    elif s == "HIGH": high += 1
        except: pass
        total_crit += crit
        results.append(f"{'CRIT' if crit > 0 else 'OK'} `{name}` — CRIT:{crit} HIGH:{high}")
    ts = datetime.now().strftime("%Y%m%d")
    mput("trivy-scans", f"weekly_{ts}.json", {"ts": ts, "results": results, "total_crit": total_crit})
    alert = "ВНИМАНИЕ! Критические CVE!\n\n" if total_crit > 0 else "Критических CVE нет\n\n"
    await msg.edit_text(alert + "\n".join(results[:15]), parse_mode="Markdown")

@admin_only
async def cmd_dashboard(update, ctx):
    msg = await update.message.reply_text("Генерирую dashboard...")
    ok = await generate_dashboard()
    url = "http://192.168.31.178:8099"
    if ok:
        await msg.edit_text(f"Dashboard готов!\n{url}",
                           reply_markup=InlineKeyboardMarkup([[url_btn("Открыть", url)]]))
    else:
        await msg.edit_text("Ошибка генерации dashboard")

@admin_only
async def cmd_reset(update, ctx):
    reset_seen()
    await update.message.reply_text("Кэш сброшен — /search покажет всё заново")

@admin_only
async def cmd_test(update, ctx):
    if not ctx.args:
        await update.message.reply_text("Использование: /test image:tag"); return
    t = ctx.args[0]; img, ver = (t.rsplit(":", 1) if ":" in t else (t, "latest"))
    _, svc = find_svc(img)
    if svc: img = svc["img"]
    await do_test(update.message, img, ver)

# ── SHOW CATEGORY ─────────────────────────────────────────────────────────
async def show_category(message, cat_code, offset):
    seen = load_seen(); PAGE = 4
    if cat_code == "ALL": projs = [(n, v) for n, v in SVC.items() if n.lower() not in seen]
    else: projs = [(n, v) for n, v in SVC.items() if v["c"] == cat_code and n.lower() not in seen]
    total = len(projs); page = projs[offset:offset + PAGE]
    if not page:
        await message.reply_text("В этой категории больше нет проектов\n/reset — сбросить кэш"); return
    for name, svc in page:
        cat_name = CAT_NAME.get(svc["c"], svc["c"]); em = CAT_EMOJI.get(svc["c"], "")
        lines = [f"*{name}* {em} {cat_name} ⭐{svc['s']:,}", f"`{svc['img']}`", f"_{svc['d']}_"]
        login = svc.get("login"); passwd = svc.get("pass"); note = svc.get("note")
        if login and passwd: lines.append(f"Логин: `{login}` Пароль: `{passwd}`")
        elif note: lines.append(f"_{note}_")
        kb = InlineKeyboardMarkup([[btn("Тест", f"do:test:{svc['img']}:latest"), btn("Пропустить", f"do:skip:{name}:x")]])
        await message.reply_text("\n".join(lines), parse_mode="Markdown", reply_markup=kb)
        await asyncio.sleep(0.3)
    nav = []
    if offset + PAGE < total: nav.append(btn(f"Ещё ({total - offset - PAGE})", "sc:" + cat_code + ":" + str(offset + PAGE)))
    nav.append(btn("Категории", "sc:MENU:0"))
    autotest = [btn("Автотест всей категории", "do:autotest:" + cat_code + ":0")]
    await message.reply_text(f"_{min(offset + PAGE, total)} из {total}_", parse_mode="Markdown",
                             reply_markup=InlineKeyboardMarkup([nav, autotest]))

# ── CALLBACKS ─────────────────────────────────────────────────────────────
@admin_only
async def on_callback(update, ctx):
    q = update.callback_query; data = q.data
    log.info(f"CB: {data!r}")
    try:
        await q.answer()
        if data.startswith("sc:"):
            parts = data.split(":"); code = parts[1]; offset = int(parts[2]) if len(parts) > 2 else 0
            if code == "RST":
                reset_seen(); await q.edit_message_reply_markup(None)
                await q.message.reply_text("Кэш сброшен"); return
            if code == "MENU":
                await q.edit_message_reply_markup(None)
                available = build_cat_menu(); rows = []
                for c in sorted(available.keys(), key=lambda x: CAT_NAME.get(x, x)):
                    n = CAT_NAME.get(c, c); em = CAT_EMOJI.get(c, ""); cnt = available[c]
                    rows.append([btn(f"{em} {n} ({cnt})", "sc:" + c + ":0")])
                rows.append([btn("Все", "sc:ALL:0"), btn("Сброс", "sc:RST:0")])
                await q.message.reply_text("Выбери категорию:", reply_markup=InlineKeyboardMarkup(rows)); return
            await q.edit_message_reply_markup(None)
            await show_category(q.message, code, offset); return

        if data.startswith("ap:"):
            parts = data.split(":"); action = parts[1]
            await q.edit_message_reply_markup(None)
            if action == "EXPLORE":
                await q.message.reply_text("Введи тему для поиска:\nНапример: osint / kubernetes / backup")
                ctx.user_data["mode"] = "explore"; return
            if action == "AUTO":
                kb = InlineKeyboardMarkup([
                    [btn("Полный автопилот", "ap:FULL:x")],
                    [btn("Только поиск", "ap:SEARCH_ONLY:x"), btn("Только тест", "ap:TEST_ONLY:x")],
                ])
                await q.message.reply_text("Автопилот — выбери режим:", reply_markup=kb); return
            if action == "FULL": await run_autopilot(q.message, "NORMAL"); return
            if action == "SEARCH_ONLY": await run_autopilot(q.message, "NORMAL", search_only=True); return
            if action == "TEST_ONLY": await run_autopilot(q.message, "NORMAL", test_only=True); return
            if action == "MANAGE": await _show_manage(q.message); return
            if action == "STATUS":
                msg2 = await q.message.reply_text("Проверяю...")
                async def chk2(name, host, user, pwd):
                    loop = asyncio.get_event_loop()
                    try:
                        o, _, _ = await loop.run_in_executor(None, lambda: ssh_run(host, user, pwd, "docker ps --format '{{.Names}}' | wc -l && free -h|awk '/Mem/{print $3\"/\"$2}'", 15))
                        p = o.strip().splitlines()
                        return name, True, p[0].strip() if p else "?", p[1].strip() if len(p) > 1 else "?"
                    except Exception as e:
                        return name, False, "?", str(e)[:40]
                res2 = await asyncio.gather(
                    chk2("srv1", "192.168.31.178", SANDBOX_USER, SANDBOX_PASS),
                    chk2("sand-box", SANDBOX_HOST, SANDBOX_USER, SANDBOX_PASS),
                    chk2("mini-prod", PROD_HOST, PROD_USER, PROD_PASS),
                )
                lines2 = ["*Серверы*\n"]
                for name2, ok2, count2, ram2 in res2:
                    if ok2: lines2.append(f"OK *{name2}*: {count2} контейнеров, RAM {ram2}")
                    else: lines2.append(f"ERR *{name2}* — {ram2}")
                await msg2.edit_text("\n".join(lines2), parse_mode="Markdown"); return
            if action == "DASH":
                msg3 = await q.message.reply_text("Генерирую...")
                ok = await generate_dashboard()
                url = "http://192.168.31.178:8099"
                await msg3.edit_text(f"Dashboard {'готов' if ok else 'ошибка'}!\n{url}",
                                    reply_markup=InlineKeyboardMarkup([[url_btn("Открыть", url)]]) if ok else None)
                return
            return

        if data.startswith("mg:"):
            parts = data.split(":"); action = parts[1]; cname = parts[2]
            loop = asyncio.get_event_loop()
            await q.edit_message_reply_markup(None)
            if action == "restart":
                _, _, code = await loop.run_in_executor(None, lambda: pr(f"docker restart {cname} 2>&1"))
                await q.message.reply_text(f"{'OK' if code == 0 else 'ERR'} Рестарт `{cname}`", parse_mode="Markdown")
            elif action == "stop":
                _, _, code = await loop.run_in_executor(None, lambda: pr(f"docker stop {cname} 2>&1"))
                await q.message.reply_text(f"{'OK' if code == 0 else 'ERR'} Остановлен `{cname}`", parse_mode="Markdown")
            elif action == "remove":
                _, _, code = await loop.run_in_executor(None, lambda: pr(f"docker rm -f {cname} 2>&1"))
                await q.message.reply_text(f"{'OK' if code == 0 else 'ERR'} Удалён `{cname}`", parse_mode="Markdown")
            elif action == "logs":
                out, _, _ = await loop.run_in_executor(None, lambda: pr(f"docker logs {cname} --tail 30 2>&1"))
                lines = out.strip().splitlines()[-20:]
                await q.message.reply_text(f"*{cname}*\n```\n{chr(10).join(lines)[:3000]}\n```", parse_mode="Markdown")
            asyncio.create_task(generate_dashboard())
            return

        if data.startswith("do:"):
            parts = data.split(":", 3); action = parts[1]
            a1 = parts[2] if len(parts) > 2 else "x"
            a2 = parts[3] if len(parts) > 3 else "latest"
            if action == "test":
                await q.edit_message_reply_markup(None)
                await do_test(q.message, a1, a2)
            elif action == "deploy":
                await q.edit_message_reply_markup(None)
                await do_deploy(q.message, a1, a2)
            elif action == "save":
                await q.edit_message_reply_markup(None)
                res = mlist("test-results", prefix=f"{a1.replace('/','_')}/{a2}/", limit=1)
                if res:
                    mput("saved-later", f"{a1.replace('/','_')}/{datetime.now().strftime('%Y%m%d-%H%M%S')}.json", res[0])
                await q.message.reply_text(f"Сохранено `{a1}` — /saved", parse_mode="Markdown")
            elif action in ("skip", "rej", "del"):
                await q.edit_message_reply_markup(None)
                if action == "skip" and a1 != "x": save_seen([a1])
            elif action == "autotest":
                await q.edit_message_reply_markup(None)
                cat_code_at = a1; seen = load_seen()
                if cat_code_at == "ALL": to_test = [(n, v) for n, v in SVC.items() if n.lower() not in seen]
                else: to_test = [(n, v) for n, v in SVC.items() if v["c"] == cat_code_at and n.lower() not in seen]
                if not to_test:
                    await q.message.reply_text("Нет новых сервисов для теста"); return
                await q.message.reply_text(f"Автотест {len(to_test)} сервисов...")
                dep = []; fail = []
                for name, svc in to_test:
                    img = svc["img"]
                    smsg = await q.message.reply_text(f"Тестирую `{img}`...", parse_mode="Markdown")
                    pl = []
                    loop = asyncio.get_event_loop()
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        result = await loop.run_in_executor(pool, pipeline, img, "latest", pl)
                    score = result["score"]; crit = result["metrics"].get("crit", 0)
                    save_seen([name])
                    if result["status"] == "pass" and score >= 70 and crit == 0:
                        await smsg.edit_text(f"OK `{img}` — {score}/100 -> деплою", parse_mode="Markdown")
                        await do_deploy(q.message, img, "latest")
                        dep.append(f"`{img}` ({score}/100)")
                    else:
                        reason = f"CRIT:{crit}" if crit > 0 else f"score:{score}/100"
                        await smsg.edit_text(f"FAIL `{img}` — {reason}", parse_mode="Markdown")
                        fail.append(f"`{img}` — {reason}")
                    await asyncio.sleep(1)
                lines3 = ["*Автотест завершён*\n"]
                if dep: lines3 += ["*Задеплоено:*"] + [f"  OK {x}" for x in dep]
                if fail: lines3 += ["\n*Пропущено:*"] + [f"  FAIL {x}" for x in fail]
                await q.message.reply_text("\n".join(lines3), parse_mode="Markdown")
            elif action == "rbk":
                await q.edit_message_reply_markup(None)
                loop = asyncio.get_event_loop()
                prev, _, code = await loop.run_in_executor(None, lambda: pr(f"cat /opt/homelab/rollback_{a1}.txt 2>/dev/null"))
                if code != 0 or not prev.strip():
                    await q.message.reply_text("Нет данных для rollback"); return
                await loop.run_in_executor(None, lambda: pr(f"docker rm -f {a1} 2>/dev/null || true"))
                _, e, code = await loop.run_in_executor(None, lambda: pr(f"docker run -d --restart unless-stopped --name {a1} {prev.strip()} 2>&1", 60))
                if code == 0: await q.message.reply_text(f"Rollback: `{prev.strip()}`", parse_mode="Markdown")
                else: await q.message.reply_text(f"Ошибка rollback: {e[:150]}")
    except Exception as e:
        log.error(f"CB error {data!r}: {e}", exc_info=True)
        try: await q.message.reply_text(f"Ошибка: {e}")
        except: pass

# ── AUTOPILOT ─────────────────────────────────────────────────────────────
async def run_autopilot(message, mode="NORMAL", search_only=False, test_only=False):
    thresholds = {"STRICT": (85, 0), "NORMAL": (70, 0), "SOFT": (60, 0)}
    min_score, max_crit = thresholds.get(mode, (70, 0))
    await message.reply_text(f"Автопилот запущен (score>={min_score}, CRIT={max_crit})\nИщу непросмотренные проекты...")
    seen = load_seen()
    catalog_unseen = [(n, v) for n, v in SVC.items() if n.lower() not in seen][:6]
    if not catalog_unseen:
        await message.reply_text("Нет новых проектов\n/reset — сбросить кэш"); return
    await message.reply_text(f"Найдено {len(catalog_unseen)} новых проектов")
    if search_only:
        lines = ["*Новые проекты:*\n"]
        for n, v in catalog_unseen:
            lines.append(f"* *{n}* — {v['d'][:80]}")
        await message.reply_text("\n".join(lines), parse_mode="Markdown"); return
    dep = []; fail = []
    for name, svc in catalog_unseen:
        img = svc["img"]
        smsg = await message.reply_text(f"Тестирую `{img}`...", parse_mode="Markdown")
        pl = []
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = await loop.run_in_executor(pool, pipeline, img, "latest", pl)
        score = result["score"]; crit = result["metrics"].get("crit", 0)
        save_seen([name])
        if result["status"] == "pass" and score >= min_score and crit <= max_crit:
            if not test_only:
                await smsg.edit_text(f"OK `{img}` — {score}/100 -> деплою", parse_mode="Markdown")
                await do_deploy(message, img, "latest")
                dep.append(f"`{img}` ({score}/100)")
            else:
                await smsg.edit_text(f"OK `{img}` — {score}/100 (тест)", parse_mode="Markdown")
                dep.append(f"`{img}` ({score}/100)")
        else:
            reason = f"CRIT:{crit}" if crit > max_crit else f"score:{score}/100"
            await smsg.edit_text(f"FAIL `{img}` — {reason}", parse_mode="Markdown")
            fail.append(f"`{img}` — {reason}")
        await asyncio.sleep(1)
    lines = ["*Автопилот завершён*\n"]
    if dep: lines += ["*Задеплоено:*"] + [f"  OK {x}" for x in dep]
    if fail: lines += ["\n*Пропущено:*"] + [f"  FAIL {x}" for x in fail]
    await message.reply_text("\n".join(lines), parse_mode="Markdown")

# ── TEXT & DOCUMENT HANDLERS ──────────────────────────────────────────────
@admin_only
async def handle_text(update, ctx):
    text = update.message.text.strip()
    uid = update.effective_user.id

    # Режим поиска
    if ctx.user_data.get("mode") == "explore":
        ctx.user_data.pop("mode", None)
        await _do_explore(update.message, text); return

    # Режим исправления
    if ctx.user_data.get("fix_image"):
        fix_img = ctx.user_data["fix_image"]; fix_ver = ctx.user_data.get("fix_version", "latest")
        env_lines = [l.strip() for l in text.splitlines() if "=" in l and not l.startswith("#")]
        if env_lines:
            ctx.user_data.pop("fix_image", None)
            custom_env = {k: v for k, v in [l.split("=", 1) for l in env_lines if "=" in l]}
            await update.message.reply_text(f"Применяю {len(custom_env)} env и тестирую `{fix_img}`...", parse_mode="Markdown")
            _, svc = find_svc(fix_img)
            if svc:
                orig = svc.get("env", {}).copy(); svc["env"].update(custom_env)
                await do_test(update.message, fix_img, fix_ver); svc["env"] = orig
            else:
                await do_test(update.message, fix_img, fix_ver)
            return
        else:
            await update.message.reply_text("Формат: `KEY=value` каждая строка", parse_mode="Markdown"); return

    # GitHub URL
    m = re.search(r'github\.com/([^/\s]+)/([^/\s#?]+)', text)
    if m:
        owner, repo = m.group(1), m.group(2).rstrip("/")
        _, svc = find_svc(repo); img = svc["img"] if svc else f"{owner}/{repo}".lower()
        await update.message.reply_text(f"*{owner}/{repo}*\n`{img}`", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[btn("Тест", f"do:test:{img}:latest"), btn("Пропустить", "do:skip:x:x")]])); return

    # image:tag
    if re.match(r'^[a-z0-9._/-]+:[a-z0-9._-]+$', text) or re.match(r'^[a-z0-9._-]+/[a-z0-9._-]+$', text):
        img, ver = (text.rsplit(":", 1) if ":" in text else (text, "latest"))
        _, svc = find_svc(img)
        if svc: img = svc["img"]
        await do_test(update.message, img, ver); return

    # AI намерение
    thinking = await update.message.reply_text("Думаю...", parse_mode="Markdown")
    stack = await ai_find_stack(text)
    if stack:
        lines = ["Понял! Предлагаю развернуть:\n"]
        keyboards = []
        for svc_name in stack:
            svc = SVC.get(svc_name)
            if svc:
                lines.append(f"*{svc_name}* — {svc['d']}")
                keyboards.append([
                    btn(f"Развернуть {svc_name}", f"do:deploy:{svc['img']}:latest"),
                    btn(f"Тест {svc_name}", f"do:test:{svc['img']}:latest")
                ])
        keyboards.append([btn("Поиск по интернету", "ap:EXPLORE:x")])
        await thinking.edit_text("\n".join(lines), parse_mode="Markdown",
                                reply_markup=InlineKeyboardMarkup(keyboards))
    else:
        await thinking.edit_text(
            f"Поискать *{text[:40]}* по интернету?",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[
                btn("Искать", "ap:EXPLORE:x"),
                btn("Отмена", "do:rej:x:x")
            ]])
        )

@admin_only
async def handle_document(update, ctx):
    doc = update.message.document
    if doc.file_size > 200 * 1024:
        await update.message.reply_text("Файл >200KB"); return
    file = await doc.get_file()
    content_bytes = await file.download_as_bytearray()
    content_str = content_bytes.decode(errors="replace")
    fname = doc.file_name or ""
    fix_img = ctx.user_data.get("fix_image", "")
    fix_ver = ctx.user_data.get("fix_version", "latest")
    if fname.endswith((".yml", ".yaml")) and fix_img:
        ctx.user_data.pop("fix_image", None)
        await update.message.reply_text(f"Получен `{fname}`\nТестирую `{fix_img}`...", parse_mode="Markdown")
        await do_test(update.message, fix_img, fix_ver)
    elif fname.endswith(".env") or "=" in content_str:
        env_lines = [l.strip() for l in content_str.splitlines() if "=" in l and not l.startswith("#")]
        env_dict = {k: v for k, v in [l.split("=", 1) for l in env_lines if "=" in l]}
        if fix_img and env_dict:
            ctx.user_data.pop("fix_image", None)
            await update.message.reply_text(f"Получен `{fname}` ({len(env_dict)} переменных)\nТестирую `{fix_img}`...", parse_mode="Markdown")
            _, svc = find_svc(fix_img)
            if svc:
                orig = svc.get("env", {}).copy(); svc["env"].update(env_dict)
                await do_test(update.message, fix_img, fix_ver); svc["env"] = orig
            else:
                await do_test(update.message, fix_img, fix_ver)
        else:
            await update.message.reply_text(f"{len(env_dict)} env переменных\nСкинь image:tag для теста")
    else:
        await update.message.reply_text(f"Не понял файл `{fname}`", parse_mode="Markdown")

# ── BACKGROUND ────────────────────────────────────────────────────────────
async def run_api_server(app):
    from aiohttp import web
    async def handle_action(request):
        action = request.match_info["action"]; name = request.match_info["name"]
        loop = asyncio.get_event_loop()
        headers = {"Access-Control-Allow-Origin": "*", "Content-Type": "application/json"}
        if action not in ("restart", "stop", "remove"):
            return web.Response(text=json.dumps({"ok": False, "error": "Unknown action"}), headers=headers)
        if action == "restart": _, e, code = await loop.run_in_executor(None, lambda: pr(f"docker restart {name} 2>&1"))
        elif action == "stop": _, e, code = await loop.run_in_executor(None, lambda: pr(f"docker stop {name} 2>&1"))
        elif action == "remove": _, e, code = await loop.run_in_executor(None, lambda: pr(f"docker rm -f {name} 2>&1"))
        if code == 0:
            await app.bot.send_message(ADMIN_ID, f"Dashboard: {action} `{name}`", parse_mode="Markdown")
            asyncio.create_task(generate_dashboard())
            return web.Response(text=json.dumps({"ok": True}), headers=headers)
        else:
            return web.Response(text=json.dumps({"ok": False, "error": e[:200]}), headers=headers)

    async def handle_logs(request):
        name = request.match_info["name"]; loop = asyncio.get_event_loop()
        headers = {"Access-Control-Allow-Origin": "*", "Content-Type": "application/json"}
        out, _, _ = await loop.run_in_executor(None, lambda: pr(f"docker logs {name} --tail 50 2>&1"))
        return web.Response(text=json.dumps({"logs": out[-3000:]}), headers=headers)

    async def handle_options(request):
        return web.Response(headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type"})

    webapp = web.Application()
    webapp.router.add_post("/{action}/{name}", handle_action)
    webapp.router.add_get("/logs/{name}", handle_logs)
    webapp.router.add_route("OPTIONS", "/{action}/{name}", handle_options)
    webapp.router.add_route("OPTIONS", "/logs/{name}", handle_options)
    runner = web.AppRunner(webapp)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8098)
    await site.start()
    log.info("API server started on :8098")

async def background_monitor(app):
    await asyncio.sleep(60)
    known = {}
    while True:
        try:
            loop = asyncio.get_event_loop()
            out, _, _ = await loop.run_in_executor(None, lambda: pr("docker ps -a --format '{{.Names}}|{{.Status}}'"))
            for line in out.strip().splitlines():
                if "|" not in line: continue
                name, status = line.split("|", 1)
                was_up = known.get(name, True)
                is_up = status.lower().startswith("up")
                if was_up and not is_up:
                    await app.bot.send_message(ADMIN_ID, f"АЛЕРТ: `{name}` упал!\nСтатус: `{status}`\n/logs {name}", parse_mode="Markdown")
                elif not was_up and is_up:
                    await app.bot.send_message(ADMIN_ID, f"OK `{name}` восстановился", parse_mode="Markdown")
                known[name] = is_up
        except Exception as e: log.warning(f"Monitor: {e}")
        await asyncio.sleep(300)

async def background_digest(app):
    while True:
        try:
            now = datetime.now()
            if now.hour == 9 and now.minute < 5:
                loop = asyncio.get_event_loop()
                lines = [f"Утренний дайджест {now.strftime('%d.%m.%Y')}\n"]
                for host, name in [("192.168.31.178", "srv1"), (SANDBOX_HOST, "sand-box"), (PROD_HOST, "mini-prod")]:
                    out, _, _ = await loop.run_in_executor(None, lambda h=host: ssh_run(h, SANDBOX_USER, SANDBOX_PASS, "docker ps --format '{{.Names}}' | wc -l && free -h|awk '/Mem/{print $3\"/\"$2}'", 10))
                    parts = out.strip().splitlines()
                    count = parts[0].strip() if parts else "?"
                    ram = parts[1].strip() if len(parts) > 1 else "?"
                    lines.append(f"* *{name}*: {count} контейнеров, RAM {ram}")
                await app.bot.send_message(ADMIN_ID, "\n".join(lines), parse_mode="Markdown")
                await asyncio.sleep(300)
            else:
                await asyncio.sleep(60)
        except Exception as e: log.warning(f"Digest: {e}"); await asyncio.sleep(60)

async def post_init(app):
    asyncio.create_task(background_monitor(app))
    asyncio.create_task(background_digest(app))
    asyncio.create_task(run_api_server(app))
    log.info("Background tasks started")

async def error_handler(update, context):
    log.error(f"Error: {context.error}", exc_info=True)

# ── MAIN ──────────────────────────────────────────────────────────────────
def main():
    app = (Application.builder().token(BOT_TOKEN)
           .connect_timeout(60).read_timeout(60).write_timeout(60)
           .get_updates_connect_timeout(60).get_updates_read_timeout(60)
           .post_init(post_init).build())
    app.add_handler(CommandHandler("start",     cmd_start))
    app.add_handler(CommandHandler("help",      cmd_start))
    app.add_handler(CommandHandler("search",    cmd_search))
    app.add_handler(CommandHandler("explore",   cmd_explore))
    app.add_handler(CommandHandler("manage",    cmd_manage))
    app.add_handler(CommandHandler("find",      cmd_find))
    app.add_handler(CommandHandler("logs",      cmd_logs))
    app.add_handler(CommandHandler("status",    cmd_status))
    app.add_handler(CommandHandler("history",   cmd_history))
    app.add_handler(CommandHandler("deployed",  cmd_deployed))
    app.add_handler(CommandHandler("saved",     cmd_saved))
    app.add_handler(CommandHandler("trivy",     cmd_trivy))
    app.add_handler(CommandHandler("dashboard", cmd_dashboard))
    app.add_handler(CommandHandler("test",      cmd_test))
    app.add_handler(CommandHandler("reset",     cmd_reset))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)
    log.info("Homelab Sentinel v7 started")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
