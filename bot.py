#!/usr/bin/env python3
"""Homelab Sentinel v6 — Full autopilot, universal search, management."""
import os, re, json, time, asyncio, logging, io, concurrent.futures
from datetime import datetime, timedelta
from pathlib import Path
import aiohttp, paramiko
from minio import Minio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── CONFIG ───────────────────────────────────────────────────────────────
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
SEEN_FILE    = Path("/tmp/hl_seen.txt")
FIX_CTX      = {}  # user_id -> {image, version}

# ── SERVICES DB ──────────────────────────────────────────────────────────
CAT_NAME  = {"M":"Мониторинг","V":"Медиа","S":"Безопасность","F":"Файлы","N":"Сеть","P":"Продуктивность","A":"Автоматизация","I":"Инфраструктура","G":"Аналитика","C":"Коммуникации","D":"Базы данных"}
CAT_EMOJI = {"M":"📊","V":"🎬","S":"🔐","F":"📁","N":"🌐","P":"📝","A":"🤖","I":"🛠","G":"📈","C":"💬","D":"🗄"}

SVC = {
    "uptime-kuma":        {"img":"louislam/uptime-kuma",               "c":"M","s":87000,"d":"Self-hosted мониторинг с уведомлениями",       "port":3001,"login":None,                   "pass":None,           "note":"Создать аккаунт при первом входе","setup":["mkdir -p /tmp/t-uk"],                                                                                                                                     "vols":["/tmp/t-uk:/app/data"],                                                    "env":{},                                                                                                                                        "tp":{3001:13001},"hc":"http://localhost:13001","w":12},
    "beszel":             {"img":"henrygd/beszel",                      "c":"M","s":9000, "d":"Лёгкий мониторинг серверов и Docker",          "port":8090,"login":"admin@admin.com",       "pass":"admin",        "note":None,                              "setup":["mkdir -p /tmp/t-bz"],                                                                                                                                     "vols":["/tmp/t-bz:/beszel_data"],                                                 "env":{},                                                                                                                                        "tp":{8090:18090},"hc":"http://localhost:18090","w":10},
    "dozzle":             {"img":"amir20/dozzle",                       "c":"M","s":7000, "d":"Логи Docker контейнеров в реальном времени",   "port":8080,"login":None,                   "pass":None,           "note":"Без авторизации",                 "setup":[],                                                                                                                                                 "vols":["/var/run/docker.sock:/var/run/docker.sock"],                               "env":{},                                                                                                                                        "tp":{8080:18082},"hc":"http://localhost:18082","w":5},
    "netdata":            {"img":"netdata/netdata",                     "c":"M","s":73000,"d":"Мониторинг производительности системы",        "port":19999,"login":None,                  "pass":None,           "note":"Без авторизации",                 "setup":[],                                                                                                                                                 "vols":["/proc:/host/proc:ro","/sys:/host/sys:ro","/var/run/docker.sock:/var/run/docker.sock:ro"],"env":{},                                                                                                                                "tp":{19999:19999},"hc":"http://localhost:19999","w":15},
    "whats-up-docker":    {"img":"fmartinou/whats-up-docker",           "c":"M","s":3000, "d":"Мониторинг обновлений Docker образов",         "port":3000,"login":None,                   "pass":None,           "note":"Без авторизации",                 "setup":[],                                                                                                                                                 "vols":["/var/run/docker.sock:/var/run/docker.sock"],                               "env":{},                                                                                                                                        "tp":{3000:13002},"hc":"http://localhost:13002","w":10},
    "jellyfin":           {"img":"jellyfin/jellyfin",                   "c":"V","s":37000,"d":"Медиасервер — бесплатная замена Plex",         "port":8096,"login":None,                   "pass":None,           "note":"Мастер настройки при первом входе","setup":["mkdir -p /tmp/t-jf/config /tmp/t-jf/cache /tmp/t-jf/media"],                                                                                                   "vols":["/tmp/t-jf/config:/config","/tmp/t-jf/cache:/cache","/tmp/t-jf/media:/media"],"env":{},                                                                                                                                         "tp":{8096:18096},"hc":"http://localhost:18096/health","w":25},
    "vaultwarden":        {"img":"vaultwarden/server",                  "c":"S","s":41000,"d":"Bitwarden совместимый сервер паролей",        "port":80,  "login":None,                   "pass":None,           "note":"Создать аккаунт при первом входе","setup":["mkdir -p /tmp/t-vw"],                                                                                                                                     "vols":["/tmp/t-vw:/data"],                                                        "env":{"ADMIN_TOKEN":"hltest123"},                                                                                                               "tp":{80:18766},"hc":"http://localhost:18766","w":10},
    "filebrowser":        {"img":"filebrowser/filebrowser",             "c":"F","s":28000,"d":"Веб файловый менеджер",                       "port":8080,"login":"admin",                 "pass":"admin",        "note":None,                              "setup":["mkdir -p /tmp/t-fb","touch /tmp/t-fb/db.db"],                                                                                                             "vols":["/tmp/t-fb:/srv","/tmp/t-fb/db.db:/database.db"],                          "env":{},                                                                                                                                        "tp":{80:18767},"hc":"http://localhost:18767","w":6},
    "paperless-ngx":      {"img":"ghcr.io/paperless-ngx/paperless-ngx", "c":"F","s":24000,"d":"Система управления документами с OCR",        "port":8000,"login":"admin",                 "pass":"admin",        "note":None,                              "setup":["mkdir -p /tmp/t-pl/data /tmp/t-pl/media /tmp/t-pl/export /tmp/t-pl/consume"],                                                                             "vols":["/tmp/t-pl/data:/usr/src/paperless/data","/tmp/t-pl/media:/usr/src/paperless/media","/tmp/t-pl/export:/usr/src/paperless/export","/tmp/t-pl/consume:/usr/src/paperless/consume"],"env":{"PAPERLESS_SECRET_KEY":"hltest123","PAPERLESS_TIME_ZONE":"Europe/Moscow","PAPERLESS_OCR_LANGUAGE":"rus+eng"},"tp":{8000:18001},"hc":"http://localhost:18001","w":40},
    "nextcloud":          {"img":"nextcloud",                           "c":"F","s":28000,"d":"Self-hosted Google Drive — файлы фото календарь","port":8080,"login":"admin",              "pass":"adminpassword","note":None,                              "setup":["mkdir -p /tmp/t-nc"],                                                                                                                                     "vols":["/tmp/t-nc:/var/www/html"],                                                "env":{"MYSQL_HOST":"localhost","MYSQL_DATABASE":"nextcloud","MYSQL_USER":"nextcloud","MYSQL_PASSWORD":"ncpassword","NEXTCLOUD_ADMIN_USER":"admin","NEXTCLOUD_ADMIN_PASSWORD":"adminpassword","NEXTCLOUD_TRUSTED_DOMAINS":"localhost"},"tp":{80:18080},"hc":"http://localhost:18080","w":30},
    "nginx-proxy-manager":{"img":"jc21/nginx-proxy-manager",            "c":"N","s":23000,"d":"Reverse proxy с веб-интерфейсом и SSL",       "port":81,  "login":"admin@example.com",     "pass":"changeme",     "note":None,                              "setup":["mkdir -p /tmp/t-npm/data /tmp/t-npm/le"],                                                                                                                  "vols":["/tmp/t-npm/data:/data","/tmp/t-npm/le:/etc/letsencrypt"],                 "env":{},                                                                                                                                        "tp":{81:18181},"hc":"http://localhost:18181","w":20},
    "adguard-home":       {"img":"adguard/adguardhome",                 "c":"N","s":26000,"d":"DNS сервер с блокировкой рекламы",            "port":3000,"login":None,                   "pass":None,           "note":"Настройка при первом входе",      "setup":["mkdir -p /tmp/t-adg/work /tmp/t-adg/conf"],                                                                                                               "vols":["/tmp/t-adg/work:/opt/adguardhome/work","/tmp/t-adg/conf:/opt/adguardhome/conf"],"env":{},                                                                                                                                     "tp":{3000:13003},"hc":"http://localhost:13003","w":10},
    "speedtest-tracker":  {"img":"henrywhitaker3/speedtest-tracker",    "c":"N","s":3000, "d":"Автоматические тесты скорости интернета",     "port":8765,"login":"admin@example.com",     "pass":"password",     "note":None,                              "setup":["mkdir -p /tmp/t-st"],                                                                                                                                     "vols":["/tmp/t-st:/config"],                                                      "env":{"OOKLA_EULA_GDPR":"true"},                                                                                                                "tp":{80:18765},"hc":"http://localhost:18765","w":12},
    "actual-budget":      {"img":"actualbudget/actual-server",          "c":"P","s":16000,"d":"Локальный менеджер личного бюджета",          "port":5006,"login":None,                   "pass":None,           "note":"Создать аккаунт при первом входе","setup":["mkdir -p /tmp/t-ac"],                                                                                                                                     "vols":["/tmp/t-ac:/data"],                                                        "env":{},                                                                                                                                        "tp":{5006:15006},"hc":"http://localhost:15006","w":10},
    "mealie":             {"img":"ghcr.io/mealie-recipes/mealie",       "c":"P","s":8000, "d":"Менеджер рецептов и планировщик меню",        "port":9000,"login":"changeme@example.com",  "pass":"MyPassword",   "note":None,                              "setup":["mkdir -p /tmp/t-ml"],                                                                                                                                     "vols":["/tmp/t-ml:/app/data"],                                                    "env":{"ALLOW_SIGNUP":"true","PUID":"1000","PGID":"1000","TZ":"Europe/Moscow","BASE_URL":"http://localhost:19000"},                               "tp":{9000:19000},"hc":"http://localhost:19000","w":18},
    "maybe":              {"img":"ghcr.io/maybe-finance/maybe",         "c":"P","s":42000,"d":"Личные финансы и инвестиционный портфель",    "port":3000,"login":None,                   "pass":None,           "note":"Создать аккаунт при первом входе","setup":["mkdir -p /tmp/t-mb/storage"],                                                                                                                              "vols":["/tmp/t-mb/storage:/rails/storage"],                                       "env":{"SELF_HOSTED":"true","RAILS_FORCE_SSL":"false","RAILS_ASSUME_SSL":"false","SECRET_KEY_BASE":"hltest_secret_key_base_1234567890abcdef"},    "tp":{3000:13100},"hc":"http://localhost:13100","w":25},
    "linkwarden":         {"img":"ghcr.io/linkwarden/linkwarden",       "c":"P","s":9000, "d":"Менеджер закладок с архивацией страниц",      "port":3000,"login":None,                   "pass":None,           "note":"Создать аккаунт при первом входе","setup":["mkdir -p /tmp/t-lw/data"],                                                                                                                                "vols":["/tmp/t-lw/data:/data/data"],                                              "env":{"NEXTAUTH_SECRET":"hltest_secret","NEXTAUTH_URL":"http://localhost:13101"},                                                                "tp":{3000:13101},"hc":"http://localhost:13101","w":20},
    "changedetection":    {"img":"ghcr.io/dgtlmoon/changedetection.io", "c":"A","s":21000,"d":"Мониторинг изменений веб-страниц",           "port":5000,"login":None,                   "pass":None,           "note":"Без авторизации",                 "setup":["mkdir -p /tmp/t-cd"],                                                                                                                                     "vols":["/tmp/t-cd:/datastore"],                                                   "env":{},                                                                                                                                        "tp":{5000:15000},"hc":"http://localhost:15000","w":10},
    "n8n":                {"img":"n8nio/n8n",                           "c":"A","s":52000,"d":"Визуальная автоматизация как Zapier",         "port":5678,"login":"admin",                 "pass":"changeme",     "note":None,                              "setup":["mkdir -p /tmp/t-n8n"],                                                                                                                                    "vols":["/tmp/t-n8n:/home/node/.n8n"],                                             "env":{"N8N_BASIC_AUTH_ACTIVE":"true","N8N_BASIC_AUTH_USER":"admin","N8N_BASIC_AUTH_PASSWORD":"hltest123","N8N_SECURE_COOKIE":"false","N8N_DIAGNOSTICS_ENABLED":"false"},"tp":{5678:15678},"hc":"http://localhost:15678","w":15},
    "glance":             {"img":"glanceapp/glance",                    "c":"I","s":34000,"d":"Красивый дашборд с виджетами",               "port":8080,"login":None,                   "pass":None,           "note":"Без авторизации",                 "setup":["mkdir -p /tmp/t-gl/config","printf 'pages:\\n  - name: Home\\n    columns:\\n      - size: full\\n        widgets:\\n          - type: clock\\n' > /tmp/t-gl/config/glance.yml"],"vols":["/tmp/t-gl/config/glance.yml:/app/assets/glance.yml"],                    "env":{},                                                                                                                                        "tp":{8080:18091},"hc":"http://localhost:18091","w":6},
    "homepage":           {"img":"ghcr.io/gethomepage/homepage",        "c":"I","s":22000,"d":"Современный дашборд для хомлаба",            "port":3000,"login":None,                   "pass":None,           "note":"Без авторизации",                 "setup":["mkdir -p /tmp/t-hp/config","echo '{}' > /tmp/t-hp/config/settings.yaml","echo '[]' > /tmp/t-hp/config/services.yaml","echo '[]' > /tmp/t-hp/config/bookmarks.yaml","echo '[]' > /tmp/t-hp/config/widgets.yaml"],"vols":["/tmp/t-hp/config:/app/config"],                                          "env":{},                                                                                                                                        "tp":{3000:13000},"hc":"http://localhost:13000","w":12},
    "stirling-pdf":       {"img":"frooodle/s-pdf",                      "c":"I","s":48000,"d":"PDF: merge/split/OCR/convert/compress",      "port":8080,"login":None,                   "pass":None,           "note":"Без авторизации",                 "setup":["mkdir -p /tmp/t-sp/configs"],                                                                                                                             "vols":["/tmp/t-sp/configs:/configs"],                                             "env":{"DOCKER_ENABLE_SECURITY":"false","LANGS":"en_GB"},                                                                                        "tp":{8080:18095},"hc":"http://localhost:18095","w":20},
    "portainer":          {"img":"portainer/portainer-ce",              "c":"I","s":32000,"d":"Веб-интерфейс для управления Docker",        "port":9000,"login":None,                   "pass":None,           "note":"Создать admin при первом входе",  "setup":["mkdir -p /tmp/t-pt"],                                                                                                                                     "vols":["/var/run/docker.sock:/var/run/docker.sock","/tmp/t-pt:/data"],            "env":{},                                                                                                                                        "tp":{9000:19010},"hc":"http://localhost:19010","w":8},
    "grafana":            {"img":"grafana/grafana",                     "c":"G","s":65000,"d":"Дашборды и визуализация метрик",             "port":3000,"login":"admin",                 "pass":"adminpassword","note":None,                              "setup":["mkdir -p /tmp/t-gr"],                                                                                                                                     "vols":["/tmp/t-gr:/var/lib/grafana"],                                             "env":{"GF_SECURITY_ADMIN_PASSWORD":"adminpassword","GF_USERS_ALLOW_SIGN_UP":"false"},                                                           "tp":{3000:13200},"hc":"http://localhost:13200","w":10},
    "matrix-synapse":     {"img":"matrixdotorg/synapse",                "c":"C","s":13000,"d":"Self-hosted Matrix мессенджер",             "port":8008,"login":None,                   "pass":None,           "note":"Требует регистрации",             "setup":["mkdir -p /tmp/t-syn"],                                                                                                                                    "vols":["/tmp/t-syn:/data"],                                                       "env":{"SYNAPSE_SERVER_NAME":"localhost","SYNAPSE_REPORT_STATS":"no"},                                                                           "tp":{8008:18008},"hc":"http://localhost:18008/_matrix/client/versions","w":20},
    "postgres":           {"img":"postgres",                            "c":"D","s":15000,"d":"PostgreSQL — мощная реляционная СУБД",      "port":5432,"login":"admin",                 "pass":"adminpassword","note":None,                              "setup":["mkdir -p /tmp/t-pg"],                                                                                                                                     "vols":["/tmp/t-pg:/var/lib/postgresql/data"],                                     "env":{"POSTGRES_USER":"admin","POSTGRES_PASSWORD":"adminpass","POSTGRES_DB":"testdb"},                                                          "tp":{5432:15432},"hc":None,"hcmd":"pg_isready -U admin","w":10},
}

def find_svc(image):
    img=image.lower().split(":")[0]; name=img.split("/")[-1]
    for k,v in SVC.items():
        if v["img"].lower()==img: return k,v
        if k==name: return k,v
        if k in img: return k,v
    return None,None

def load_seen():
    try: return set(SEEN_FILE.read_text().splitlines())
    except: return set()

def save_seen(names):
    s=load_seen(); s.update(n.lower() for n in names)
    SEEN_FILE.write_text("\n".join(sorted(s)))

def reset_seen(): SEEN_FILE.unlink(missing_ok=True)

# ── MINIO ─────────────────────────────────────────────────────────────────
_mc=None
def get_mc():
    global _mc
    if _mc is None:
        _mc=Minio(MINIO_URL.replace("http://","").replace("https://",""),access_key=MINIO_USER,secret_key=MINIO_PASS,secure=False)
        for b in ["test-results","deployed","saved-later","history","trivy-scans"]:
            try:
                if not _mc.bucket_exists(b): _mc.make_bucket(b)
            except: pass
    return _mc

def mput(bucket,key,data):
    try:
        p=json.dumps(data,ensure_ascii=False,indent=2,default=str).encode()
        get_mc().put_object(bucket,key,io.BytesIO(p),len(p),content_type="application/json")
    except Exception as e: log.warning(f"mput: {e}")

def mlist(bucket,prefix="",limit=10):
    out=[]
    try:
        keys=sorted([o.object_name for o in get_mc().list_objects(bucket,prefix=prefix,recursive=True)],reverse=True)[:limit]
        for k in keys:
            try: r=get_mc().get_object(bucket,k); out.append(json.loads(r.read()))
            except: pass
    except: pass
    return out

# ── SSH ───────────────────────────────────────────────────────────────────
def ssh(host,user,pwd,cmd,t=60):
    for attempt in range(3):
        try:
            c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if SSH_KEY and os.path.exists(SSH_KEY): c.connect(host,username=user,key_filename=SSH_KEY,timeout=10)
            else: c.connect(host,username=user,password=pwd,timeout=10)
            _,out,err=c.exec_command(cmd,timeout=t)
            o=out.read().decode(errors="replace"); e=err.read().decode(errors="replace")
            code=out.channel.recv_exit_status(); c.close()
            return o,e,code
        except Exception as ex:
            if attempt==2: return "",str(ex),-1
            time.sleep(2**attempt)

def sb(cmd,t=60): return ssh(SANDBOX_HOST,SANDBOX_USER,SANDBOX_PASS,cmd,t)
def pr(cmd,t=60): return ssh(PROD_HOST,PROD_USER,PROD_PASS,cmd,t)
def s1(cmd,t=60): return ssh("192.168.31.178",SANDBOX_USER,SANDBOX_PASS,cmd,t)

# ── PIPELINE ──────────────────────────────────────────────────────────────
def pipeline(image,version,prog):
    target=f"{image}:{version}"; _,svc=find_svc(image)
    cn="hlt_"+re.sub(r'[^a-z0-9]','_',image.split("/")[-1].lower())
    res={"image":image,"version":version,"ts":datetime.now().isoformat(),"status":"error","score":0,"steps":{},"metrics":{},"fail":"","diag":"","rec":""}
    def p(m): prog.append(m)

    p("📥 Pull образа...")
    o,e,code=sb(f"docker pull {target} 2>&1",180)
    if code!=0:
        res["steps"]["pull"]={"ok":False,"d":(e or o)[:100]}; res["fail"]="pull"
        res["diag"]=(e or o)[:300]; res["rec"]="Образ недоступен"; return res
    try:
        so,_,_=sb(f"docker image inspect {target} --format '{{{{.Size}}}}' 2>/dev/null")
        size=int(so.strip())//1024//1024; res["metrics"]["size_mb"]=size
        res["steps"]["pull"]={"ok":True,"d":f"{size}MB"}; p(f"✓ Pull — {size}MB")
    except: res["steps"]["pull"]={"ok":True,"d":"ok"}; p("✓ Pull")

    p("🔒 Trivy scan...")
    to,_,_=sb(f"trivy image --server {TRIVY_URL} --format json --quiet {target} 2>/dev/null",120)
    crit=high=med=0
    try:
        td=json.loads(to)
        for r in td.get("Results",[]):
            for v in (r.get("Vulnerabilities") or []):
                s=v.get("Severity","")
                if s=="CRITICAL": crit+=1
                elif s=="HIGH": high+=1
                elif s=="MEDIUM": med+=1
    except: pass
    res["metrics"].update({"crit":crit,"high":high,"med":med})
    res["steps"]["sec"]={"ok":crit==0,"d":f"CRIT:{crit} HIGH:{high} MED:{med}"}
    p(f"{'✓' if crit==0 else '⚠'} Security — CRIT:{crit} HIGH:{high} MED:{med}")

    if svc:
        for cmd in svc.get("setup",[]): sb(cmd,15)
    sb(f"docker rm -f {cn} 2>/dev/null || true")

    p("💨 Запуск контейнера...")
    ef=" ".join(f'-e "{k}={v}"' for k,v in (svc.get("env",{}) if svc else {}).items())
    vf=" ".join(f"-v {v}" for v in (svc.get("vols",[]) if svc else []))
    pf=" ".join(f"-p {h}:{c}" for c,h in (svc.get("tp",{}) if svc else {}).items())
    o,e,code=sb(f"docker run -d --name {cn} --restart=no --memory=512m {ef} {vf} {pf} {target} 2>&1",30)
    if code!=0:
        res["steps"]["smoke"]={"ok":False,"d":(e or o)[:100]}; res["fail"]="smoke"
        res["diag"]=(e or o)[:400]; res["rec"]="Не запускается — нужна настройка"
        sb(f"docker rm -f {cn} 2>/dev/null || true"); return res

    wait=svc["w"] if svc else 10
    p(f"⏳ Инициализация {wait}с..."); time.sleep(wait)
    state,_,_=sb(f"docker inspect {cn} --format '{{{{.State.Running}}}}' 2>/dev/null")
    running="true" in state.lower()
    if not running:
        crash,_,_=sb(f"docker logs {cn} 2>&1 | tail -8")
        oom,_,_=sb(f"docker inspect {cn} --format '{{{{.State.OOMKilled}}}}' 2>/dev/null")
        res["steps"]["smoke"]={"ok":False,"d":"упал"}; res["diag"]=crash[:400]
        res["fail"]="oom" if "true" in oom.lower() else "smoke"
        res["rec"]="OOM — мало памяти" if "true" in oom.lower() else "Падает — проверь конфиг"
        sb(f"docker rm -f {cn} 2>/dev/null || true"); return res
    res["steps"]["smoke"]={"ok":True,"d":f"живёт {wait}с"}; p("✓ Smoke")

    hc=svc["hc"] if svc else None
    if hc:
        p("🌐 HTTP check...")
        ho,_,_=sb(f"curl -sf --max-time 10 -o /dev/null -w '%{{http_code}}|%{{time_total}}' {hc} 2>/dev/null")
        pts=ho.strip().split("|"); hcode=pts[0] if pts else ""
        try: ms=int(float(pts[1])*1000) if len(pts)>1 else 0
        except: ms=0
        ok=hcode in ("200","201","204","301","302","401","403")
        res["metrics"]["resp_ms"]=ms; res["steps"]["http"]={"ok":ok,"d":f"HTTP {hcode} {ms}мс"}
        p(f"{'✓' if ok else '✗'} HTTP — {hcode} {ms}мс")

    hcmd=svc.get("hcmd","") if svc else ""
    if hcmd:
        _,_,hc2=sb(f"docker exec {cn} sh -c '{hcmd}' 2>/dev/null",15)
        res["steps"]["hc"]={"ok":hc2==0,"d":"ok" if hc2==0 else "fail"}
        p(f"{'✓' if hc2==0 else '✗'} Healthcheck")

    p("📊 Ресурсы...")
    st,_,_=sb(f"docker stats {cn} --no-stream --format '{{{{.MemUsage}}}}|{{{{.CPUPerc}}}}' 2>/dev/null")
    mem=cpu=0
    try:
        mp,cp=st.strip().split("|")
        m=re.search(r'([\d.]+)([MG]iB)',mp)
        if m: v=float(m.group(1)); mem=int(v*1024 if m.group(2)=="GiB" else v)
        c=re.search(r'([\d.]+)',cp)
        if c: cpu=float(c.group(1))
    except: pass
    res["metrics"].update({"mem_mb":mem,"cpu":cpu})
    res["steps"]["res"]={"ok":mem<400,"d":f"RAM {mem}MB CPU {cpu:.1f}%"}
    p(f"✓ Ресурсы — RAM:{mem}MB CPU:{cpu:.1f}%")

    p("🔄 Restart test...")
    sb(f"docker restart {cn}",30); time.sleep(min(wait,8))
    s2,_,_=sb(f"docker inspect {cn} --format '{{{{.State.Running}}}}' 2>/dev/null")
    rok="true" in s2.lower()
    res["steps"]["rst"]={"ok":rok,"d":"выжил" if rok else "упал"}
    p(f"{'✓' if rok else '✗'} Restart")

    sb(f"docker rm -f {cn} 2>/dev/null || true")
    if svc:
        for v in svc.get("vols",[]):
            hp=v.split(":")[0]
            if hp.startswith("/tmp/t-"): sb(f"rm -rf {hp} 2>/dev/null || true")
    res["steps"]["clean"]={"ok":True,"d":"ok"}; p("✓ Cleanup")

    w={"pull":10,"sec":20,"smoke":25,"http":15,"res":10,"rst":15,"clean":5}
    score=sum(wt for k,wt in w.items() if res["steps"].get(k,{}).get("ok"))
    score-=min(crit*10,30); score-=min(high*2,10); score=max(0,min(100,score))
    res["score"]=score; res["status"]="pass" if score>=60 else "fail"
    if score>=85: res["rec"]="Отлично — готов к деплою"
    elif score>=70: res["rec"]="Хорошо — можно деплоить"
    elif score>=60: res["rec"]="Работает, есть замечания"
    elif crit>0: res["rec"]=f"Не деплоить — {crit} CRITICAL CVE"
    else: res["rec"]="Нестабильная работа"
    return res

# ── UNIVERSAL SEARCH ──────────────────────────────────────────────────────
async def universal_search(query, limit=10):
    """Ищет по всему интернету — GitHub, Reddit, HN, DockerHub."""
    results = []
    headers_gh = {"Accept":"application/vnd.github.v3+json"}
    if GITHUB_TOKEN: headers_gh["Authorization"] = f"token {GITHUB_TOKEN}"

    async with aiohttp.ClientSession() as session:
        tasks = [
            _search_github(session, query, headers_gh, limit),
            _search_reddit(session, query, limit//2),
            _search_hackernews(session, query, limit//2),
            _search_dockerhub(session, query, limit//2),
            _search_awesome(session, query, limit//2),
        ]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

    seen_names = set()
    for batch in all_results:
        if isinstance(batch, list):
            for item in batch:
                key = item.get("name","").lower()
                if key and key not in seen_names:
                    seen_names.add(key)
                    results.append(item)

    results.sort(key=lambda x: x.get("stars",0), reverse=True)
    return results[:limit]

async def _search_github(session, query, headers, limit=8):
    results = []
    try:
        async with session.get(
            "https://api.github.com/search/repositories",
            headers=headers,
            params={"q":f"{query} stars:>100","sort":"stars","order":"desc","per_page":limit},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status != 200: return results
            data = await r.json()
        for repo in data.get("items",[]):
            if repo.get("archived"): continue
            desc = repo.get("description","") or ""
            topics = repo.get("topics",[])
            has_docker = "docker" in topics or "docker" in desc.lower()
            lang = repo.get("language","")
            # Определяем тип
            if has_docker: ptype = "docker"
            elif lang == "Python": ptype = "python"
            elif lang in ("Go","Rust","C","C++"): ptype = "binary"
            elif lang == "Shell": ptype = "shell"
            else: ptype = "repo"
            results.append({
                "name": repo["name"],
                "full_name": repo["full_name"],
                "url": repo["html_url"],
                "desc": desc[:200],
                "stars": repo["stargazers_count"],
                "lang": lang,
                "type": ptype,
                "has_docker": has_docker,
                "topics": topics[:5],
                "source": "github",
                "docker_img": f"{repo['owner']['login']}/{repo['name']}".lower() if has_docker else None
            })
    except Exception as e: log.warning(f"GitHub search: {e}")
    return results

async def _search_reddit(session, query, limit=5):
    results = []
    try:
        for sub in ["selfhosted","homelab","opensource"]:
            async with session.get(
                f"https://www.reddit.com/r/{sub}/search.json",
                params={"q":query,"sort":"relevance","limit":limit,"restrict_sr":"on"},
                headers={"User-Agent":"homelab-sentinel/1.0"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status != 200: continue
                data = await r.json()
            gh_re = re.compile(r'github\.com/([^/\s"]+)/([^/\s"#?]+)')
            for post in data.get("data",{}).get("children",[]):
                p = post.get("data",{})
                if p.get("score",0) < 20: continue
                combined = f"{p.get('title','')} {p.get('selftext','')} {p.get('url','')}"
                m = gh_re.search(combined)
                if not m: continue
                owner,repo = m.group(1),m.group(2).rstrip("/")
                results.append({
                    "name": repo, "full_name": f"{owner}/{repo}",
                    "url": f"https://github.com/{owner}/{repo}",
                    "desc": p.get("title","")[:200],
                    "stars": p.get("score",0)*5,
                    "type": "repo", "has_docker": "docker" in combined.lower(),
                    "source": "reddit",
                    "docker_img": f"{owner}/{repo}".lower() if "docker" in combined.lower() else None
                })
    except Exception as e: log.warning(f"Reddit search: {e}")
    return results

async def _search_hackernews(session, query, limit=5):
    results = []
    try:
        async with session.get(
            "https://hn.algolia.com/api/v1/search",
            params={"query":f"Show HN {query}","tags":"show_hn","numericFilters":"points>10"},
            timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status != 200: return results
            data = await r.json()
        gh_re = re.compile(r'github\.com/([^/\s"]+)/([^/\s"#?]+)')
        for hit in data.get("hits",[])[:limit]:
            url = hit.get("url","") or ""
            title = hit.get("title","")
            m = gh_re.search(url+title)
            if not m: continue
            owner,repo = m.group(1),m.group(2).rstrip("/")
            results.append({
                "name": repo, "full_name": f"{owner}/{repo}",
                "url": f"https://github.com/{owner}/{repo}",
                "desc": title[:200], "stars": hit.get("points",0)*3,
                "type": "repo", "has_docker": "docker" in title.lower(),
                "source": "hackernews",
                "docker_img": None
            })
    except Exception as e: log.warning(f"HN search: {e}")
    return results

async def _search_dockerhub(session, query, limit=5):
    results = []
    try:
        async with session.get(
            f"https://hub.docker.com/v2/search/repositories/",
            params={"query":query,"page_size":limit},
            timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status != 200: return results
            data = await r.json()
        for repo in data.get("results",[]):
            name = repo.get("repo_name","")
            results.append({
                "name": name.split("/")[-1],
                "full_name": name,
                "url": f"https://hub.docker.com/r/{name}",
                "desc": (repo.get("short_description","") or "")[:200],
                "stars": repo.get("star_count",0),
                "pulls": repo.get("pull_count",0),
                "type": "docker",
                "has_docker": True,
                "source": "dockerhub",
                "docker_img": name
            })
    except Exception as e: log.warning(f"DockerHub search: {e}")
    return results

async def _search_awesome(session, query, limit=5):
    """Ищет в awesome-selfhosted списке."""
    results = []
    try:
        async with session.get(
            "https://raw.githubusercontent.com/awesome-selfhosted/awesome-selfhosted/master/README.md",
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status != 200: return results
            text = await r.text()
        q_lower = query.lower()
        gh_re = re.compile(r'\[([^\]]+)\]\((https://github\.com/[^)]+)\)')
        lines = text.splitlines()
        for line in lines:
            if q_lower not in line.lower(): continue
            m = gh_re.search(line)
            if not m: continue
            name_found = m.group(1); url_found = m.group(2)
            parts = url_found.replace("https://github.com/","").split("/")
            if len(parts) < 2: continue
            results.append({
                "name": parts[1], "full_name": "/".join(parts[:2]),
                "url": url_found, "desc": line.strip()[:200],
                "stars": 1000, "type": "repo", "has_docker": True,
                "source": "awesome-selfhosted",
                "docker_img": "/".join(parts[:2]).lower()
            })
            if len(results) >= limit: break
    except Exception as e: log.warning(f"Awesome search: {e}")
    return results

# ── HELPERS ───────────────────────────────────────────────────────────────
def admin_only(func):
    async def wrapper(update,ctx):
        uid=update.effective_user.id if update.effective_user else update.callback_query.from_user.id
        if uid!=ADMIN_ID: return
        return await func(update,ctx)
    return wrapper

def btn(text,data): return InlineKeyboardButton(text,callback_data=data)
def url_btn(text,u): return InlineKeyboardButton(text,url=u)

def build_cat_menu():
    seen=load_seen(); available={}
    for name,svc in SVC.items():
        if name.lower() not in seen:
            c=svc["c"]; available[c]=available.get(c,0)+1
    return available

# ── COMMANDS ──────────────────────────────────────────────────────────────
@admin_only
async def cmd_start(update,ctx):
    kb=InlineKeyboardMarkup([
        [btn("🔍 Каталог по категориям","sc:MENU:0")],
        [btn("🌐 Поиск по интернету","ap:EXPLORE:x")],
        [btn("🤖 Автопилот","ap:AUTO:x")],
        [btn("📋 Управление сервисами","ap:MANAGE:x")],
        [btn("📊 Статус серверов","ap:STATUS:x")],
    ])
    await update.message.reply_text(
        "🤖 *Homelab Sentinel v6*\n\n"
        "Полностью автономная система управления хомлабом\n\n"
        "*Команды:*\n"
        "/search — каталог по категориям\n"
        "/explore тема — поиск по всему интернету\n"
        "/autopilot — автоматический поиск→тест→деплой\n"
        "/manage — управление запущенными\n"
        "/find имя — поиск в каталоге\n"
        "/logs имя — логи сервиса\n"
        "/status — статус серверов\n"
        "/history — история\n"
        "/deployed — запущено\n"
        "/saved — сохранено для доработки\n"
        "/trivy — скан запущенных\n"
        "/reset — сброс кэша",
        parse_mode="Markdown",
        reply_markup=kb
    )

@admin_only
async def cmd_search(update,ctx):
    available=build_cat_menu()
    if not available:
        await update.message.reply_text("😕 Всё просмотрено\n/reset — сбросить кэш"); return
    rows=[]
    for code in sorted(available.keys(),key=lambda x:CAT_NAME.get(x,x)):
        name=CAT_NAME.get(code,code); em=CAT_EMOJI.get(code,"📦"); cnt=available[code]
        rows.append([btn(f"{em} {name} ({cnt})","sc:"+code+":0")])
    rows.append([btn("🔀 Все категории","sc:ALL:0"),btn("🔄 Сброс кэша","sc:RST:0")])
    rows.append([btn("🌐 Поиск по интернету","ap:EXPLORE:x"),btn("🤖 Автопилот","ap:AUTO:x")])
    await update.message.reply_text("🔍 *Выбери категорию:*",parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows))

@admin_only
async def cmd_explore(update,ctx):
    query=" ".join(ctx.args) if ctx.args else ""
    if not query:
        await update.message.reply_text("Использование: /explore тема\nНапример: /explore osint\nИли: /explore мониторинг kubernetes"); return
    await _do_explore(update.message, query)

async def _do_explore(message, query):
    msg=await message.reply_text(f"🌐 Ищу *{query}* по всему интернету...\n_GitHub + Reddit + HN + DockerHub + Awesome lists_",parse_mode="Markdown")
    try:
        results=await asyncio.wait_for(universal_search(query,limit=10),timeout=45)
    except asyncio.TimeoutError:
        await msg.edit_text("⏱ Таймаут поиска — попробуй ещё раз"); return

    if not results:
        await msg.edit_text(f"😕 По запросу *{query}* ничего не нашёл",parse_mode="Markdown"); return

    type_icons={"docker":"🐳","python":"🐍","shell":"📜","binary":"⚙️","repo":"📦"}
    src_icons={"github":"🐙","reddit":"🔥","hackernews":"🟧","dockerhub":"🐳","awesome-selfhosted":"⭐"}
    await msg.edit_text(f"✅ Нашёл *{len(results)}* результатов по *{query}*",parse_mode="Markdown")

    for item in results:
        ti=type_icons.get(item.get("type","repo"),"📦")
        si=src_icons.get(item.get("source",""),"📦")
        stars=item.get("stars",0)
        desc=item.get("desc","")[:150]
        lang=item.get("lang","")
        lines=[
            f"{ti} *{item['name']}* {si}",
            f"⭐{stars:,}" + (f" · {lang}" if lang else ""),
            f"_{desc}_",
        ]
        rows=[]
        docker_img=item.get("docker_img")
        if docker_img:
            rows.append([btn("▶️ Тест Docker образа",f"do:test:{docker_img}:latest")])
        if item.get("url"):
            rows.append([url_btn("🔗 Открыть на "+item.get("source","GitHub"),item["url"])])
        if rows:
            await message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows),disable_web_page_preview=True)
        else:
            await message.reply_text("\n".join(lines),parse_mode="Markdown",disable_web_page_preview=True)
        await asyncio.sleep(0.3)

@admin_only
async def cmd_autopilot(update,ctx):
    kb=InlineKeyboardMarkup([
        [btn("🤖 Полный автопилот (поиск→тест→деплой)","ap:FULL:x")],
        [btn("🔍 Только поиск","ap:SEARCH_ONLY:x"),btn("🧪 Только тест","ap:TEST_ONLY:x")],
        [btn("📊 Строгий (≥85, CRIT=0)","ap:STRICT:x"),btn("✅ Обычный (≥70, CRIT=0)","ap:NORMAL:x"),btn("🔓 Мягкий (≥60)","ap:SOFT:x")],
    ])
    await update.message.reply_text(
        "🤖 *Автопилот*\n\nВыбери режим работы:",
        parse_mode="Markdown",
        reply_markup=kb
    )

@admin_only
async def cmd_manage(update,ctx):
    await _show_manage(update.message)

async def _show_manage(message):
    loop=asyncio.get_event_loop()
    out,_,_=await loop.run_in_executor(None,lambda:pr("docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'"))
    lines=["📋 *Запущенные сервисы на mini-prod:*\n"]
    rows=[]
    for line in out.strip().splitlines():
        if "|" not in line: continue
        parts=line.split("|"); name=parts[0]; img=parts[1]; status=parts[2]; ports=parts[3] if len(parts)>3 else ""
        port_match=re.search(r':(\d+)->',ports)
        port=port_match.group(1) if port_match else None
        url=f"http://{PROD_HOST}:{port}" if port else None
        lines.append(f"• *{name}*\n  `{img}`\n  {status}")
        row=[btn("🔄",f"mg:restart:{name}:x"),btn("⏹",f"mg:stop:{name}:x"),btn("🗑",f"mg:remove:{name}:x"),btn("📋",f"mg:logs:{name}:x")]
        if url: row.append(url_btn("🌐",url))
        rows.append(row)
    if len(lines)==1: lines.append("Пусто")
    await message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows) if rows else None)

@admin_only
async def cmd_find(update,ctx):
    if not ctx.args:
        await update.message.reply_text("Использование: /find jellyfin"); return
    query=" ".join(ctx.args).lower()
    found=[(n,v) for n,v in SVC.items() if query in n.lower() or query in v.get("d","").lower() or query in v.get("img","").lower()]
    if not found:
        await update.message.reply_text(f"😕 '{query}' не найден в каталоге\nПопробуй /explore {query}"); return
    for name,svc in found[:5]:
        cat=CAT_NAME.get(svc["c"],svc["c"]); em=CAT_EMOJI.get(svc["c"],"📦")
        login=svc.get("login"); passwd=svc.get("pass"); note=svc.get("note")
        lines=[f"🐳 *{name}* {em} {cat} ⭐{svc['s']:,}",f"`{svc['img']}`",f"_{svc['d']}_"]
        if login and passwd: lines.append(f"👤 `{login}` 🔑 `{passwd}`")
        elif note: lines.append(f"ℹ️ _{note}_")
        kb=InlineKeyboardMarkup([[btn("▶️ Тест",f"do:test:{svc['img']}:latest"),btn("⏭","do:skip:"+name+":x")]])
        await update.message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=kb)

@admin_only
async def cmd_logs(update,ctx):
    if not ctx.args:
        await update.message.reply_text("Использование: /logs имя_контейнера"); return
    name=ctx.args[0]
    loop=asyncio.get_event_loop()
    out,_,code=await loop.run_in_executor(None,lambda:pr(f"docker logs {name} --tail 50 2>&1"))
    if code!=0 or not out.strip():
        await update.message.reply_text(f"❌ Контейнер `{name}` не найден или нет логов",parse_mode="Markdown"); return
    # Разбиваем на части если длинный
    lines=out.strip().splitlines()[-30:]
    text="\n".join(lines)
    await update.message.reply_text(f"📋 *Логи {name}* (последние 30 строк)\n```\n{text[:3500]}\n```",parse_mode="Markdown")

@admin_only
async def cmd_status(update,ctx):
    msg=await update.message.reply_text("🔍 Проверяю серверы...")
    async def chk(name,host,user,pwd):
        loop=asyncio.get_event_loop()
        try:
            o,_,_=await loop.run_in_executor(None,lambda:ssh(host,user,pwd,"docker ps --format '{{.Names}}|{{.Status}}' && free -h|awk '/Mem/{print \"M:\"$3\"/\"$2}' && df -h /|awk 'NR==2{print \"D:\"$3\"/\"$2}'",15))
            ctrs=[l for l in o.splitlines() if "|" in l]
            ram=next((l[2:] for l in o.splitlines() if l.startswith("M:")),"?")
            disk=next((l[2:] for l in o.splitlines() if l.startswith("D:")),"?")
            return name,True,ctrs,ram,disk
        except Exception as e: return name,False,[],str(e)[:60],"?"
    res=await asyncio.gather(
        chk("🧠 srv1","192.168.31.178",SANDBOX_USER,SANDBOX_PASS),
        chk("🧪 sand-box",SANDBOX_HOST,SANDBOX_USER,SANDBOX_PASS),
        chk("🚀 mini-prod",PROD_HOST,PROD_USER,PROD_PASS),
    )
    lines=["📊 *Статус серверов*\n"]
    for name,ok,ctrs,ram,disk in res:
        if ok:
            cl="\n".join(f"  • `{c.split('|')[0]}`" for c in ctrs[:5]) or "  —"
            lines.append(f"✅ *{name}*\n  RAM:`{ram}` Диск:`{disk}`\n{cl}")
        else:
            lines.append(f"❌ *{name}* — {ram}")
    await msg.edit_text("\n\n".join(lines),parse_mode="Markdown")

@admin_only
async def cmd_history(update,ctx):
    tests=mlist("test-results",limit=10); deployed=mlist("deployed",limit=10)
    lines=["📋 *История*\n"]
    if deployed:
        lines.append("*Задеплоено:*")
        for d in deployed[:5]:
            ts=d.get("deployed_at","")[:10]; img=d.get("image","?")
            lines.append(f"  ✅ `{img}` — {ts}")
    if tests:
        lines.append("\n*Последние тесты:*")
        for t in tests[:5]:
            ts=t.get("ts","")[:10]; img=t.get("image","?"); score=t.get("score",0)
            icon="✅" if t.get("status")=="pass" else "❌"
            lines.append(f"  {icon} `{img}` — {score}/100 — {ts}")
    await update.message.reply_text("\n".join(lines),parse_mode="Markdown")

@admin_only
async def cmd_deployed(update,ctx):
    loop=asyncio.get_event_loop()
    o,_,_=await loop.run_in_executor(None,lambda:pr("docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}'"))
    lines=["🚀 *На mini-prod:*\n"]
    for line in o.strip().splitlines():
        if "|" in line:
            p=line.split("|"); lines.append(f"• `{p[0]}`\n  {p[1]}\n  {p[2]}")
    if len(lines)==1: lines.append("Пусто")
    await update.message.reply_text("\n\n".join(lines),parse_mode="Markdown")

@admin_only
async def cmd_saved(update,ctx):
    items=mlist("saved-later",limit=20)
    if not items:
        await update.message.reply_text("📭 Нет сохранённых"); return
    lines=[f"💾 *Сохранено ({len(items)}):*\n"]; rows=[]; seen_imgs=set()
    for item in items:
        img=item.get("image","?")
        if img in seen_imgs: continue
        seen_imgs.add(img)
        ts=item.get("ts","")[:10]; rec=item.get("rec","?")
        diag=item.get("diag","")[:60].replace("\n"," ")
        lines.append(f"*{img}*\n  _{rec}_\n  `{diag}`\n  _{ts}_")
        rows.append([btn("🔄 Ретест",f"do:test:{img}:latest"),btn("✏️ Исправить",f"do:fix:{img}:latest"),btn("🗑",f"do:del:{img}:x")])
    await update.message.reply_text("\n\n".join(lines),parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows) if rows else None)

@admin_only
async def cmd_trivy(update,ctx):
    msg=await update.message.reply_text("🔒 Запускаю Trivy скан всех запущенных контейнеров...")
    loop=asyncio.get_event_loop()
    out,_,_=await loop.run_in_executor(None,lambda:pr("docker ps --format '{{.Names}}|{{.Image}}'"))
    containers=[]
    for line in out.strip().splitlines():
        if "|" in line:
            parts=line.split("|"); containers.append((parts[0],parts[1]))
    if not containers:
        await msg.edit_text("Нет запущенных контейнеров"); return
    results=[]; total_crit=0
    for name,img in containers:
        to,_,_=await loop.run_in_executor(None,lambda i=img:sb(f"trivy image --server {TRIVY_URL} --format json --quiet {i} 2>/dev/null",120))
        crit=high=0
        try:
            td=json.loads(to)
            for r in td.get("Results",[]):
                for v in (r.get("Vulnerabilities") or []):
                    s=v.get("Severity","")
                    if s=="CRITICAL": crit+=1
                    elif s=="HIGH": high+=1
        except: pass
        total_crit+=crit
        icon="🔴" if crit>0 else "✅"
        results.append(f"{icon} `{name}` — CRIT:{crit} HIGH:{high}")
    ts=datetime.now().strftime("%Y%m%d-%H%M%S")
    mput("trivy-scans",f"{ts}.json",{"ts":ts,"results":results,"total_crit":total_crit})
    alert="⚠️ *Внимание! Найдены критические CVE!*\n\n" if total_crit>0 else "✅ *Критических CVE не найдено*\n\n"
    await msg.edit_text(alert+"\n".join(results),parse_mode="Markdown")

@admin_only
async def cmd_test(update,ctx):
    if not ctx.args:
        await update.message.reply_text("Использование: /test image:tag"); return
    t=ctx.args[0]; img,ver=(t.rsplit(":",1) if ":" in t else (t,"latest"))
    _,svc=find_svc(img)
    if svc: img=svc["img"]
    await do_test(update.message,img,ver)

@admin_only
async def cmd_testall(update,ctx):
    if not ctx.args:
        await update.message.reply_text("Использование: /testall img1 img2 img3"); return
    items=[]
    for t in ctx.args[:3]:
        img,ver=(t.rsplit(":",1) if ":" in t else (t,"latest"))
        _,svc=find_svc(img)
        if svc: img=svc["img"]
        items.append((img,ver))
    await update.message.reply_text(f"🚀 Параллельный тест {len(items)}:\n"+"\n".join(f"  • `{i}:{v}`" for i,v in items),parse_mode="Markdown")
    await asyncio.gather(*[do_test(update.message,img,ver) for img,ver in items])

@admin_only
async def cmd_reset(update,ctx):
    reset_seen()
    await update.message.reply_text("✅ Кэш сброшен — /search покажет всё заново")

# ── SHOW CATEGORY ─────────────────────────────────────────────────────────
async def show_category(message,cat_code,offset):
    log.info(f"show_category cat={cat_code!r} offset={offset}")
    seen=load_seen(); PAGE=4
    if cat_code=="ALL": projs=[(n,v) for n,v in SVC.items() if n.lower() not in seen]
    else: projs=[(n,v) for n,v in SVC.items() if v["c"]==cat_code and n.lower() not in seen]
    total=len(projs); page=projs[offset:offset+PAGE]
    if not page:
        await message.reply_text("😕 В этой категории больше нет проектов\n/reset — сбросить кэш"); return
    for name,svc in page:
        cat_name=CAT_NAME.get(svc["c"],svc["c"]); em=CAT_EMOJI.get(svc["c"],"📦")
        login=svc.get("login"); passwd=svc.get("pass"); note=svc.get("note")
        lines=[f"🐳 *{name}*  {em} {cat_name}  ⭐{svc['s']:,}",f"`{svc['img']}`",f"_{svc['d']}_"]
        if login and passwd: lines.append(f"👤 `{login}` 🔑 `{passwd}`")
        elif note: lines.append(f"ℹ️ _{note}_")
        kb=InlineKeyboardMarkup([[btn("▶️ Тест",f"do:test:{svc['img']}:latest"),btn("⏭ Пропустить",f"do:skip:{name}:x")]])
        await message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=kb)
        await asyncio.sleep(0.3)
    nav=[]; cat_code_nav=cat_code
    if offset+PAGE<total: nav.append(btn(f"➡️ Ещё ({total-offset-PAGE})","sc:"+cat_code_nav+":"+str(offset+PAGE)))
    nav.append(btn("🔙 Категории","sc:MENU:0"))
    autotest=[btn(f"🤖 Автотест всей категории","do:autotest:"+cat_code+":0")]
    await message.reply_text(f"_{min(offset+PAGE,total)} из {total}_",parse_mode="Markdown",reply_markup=InlineKeyboardMarkup([nav,autotest]))

# ── DO TEST ───────────────────────────────────────────────────────────────
async def do_test(message,image,version):
    pmsg=await message.reply_text(f"🚀 *Pipeline: `{image}:{version}`*\n\n⏳ Старт...",parse_mode="Markdown")
    prog=[f"🚀 *{image}:{version}*\n"]
    async def upd():
        try: await pmsg.edit_text("\n".join(prog[-12:]),parse_mode="Markdown")
        except: pass
    loop=asyncio.get_event_loop(); pl=[]
    with concurrent.futures.ThreadPoolExecutor() as pool:
        fut=loop.run_in_executor(pool,pipeline,image,version,pl)
        while not fut.done():
            await asyncio.sleep(3)
            if pl: prog.extend(pl); pl.clear(); await upd()
        result=await fut
    if pl: prog.extend(pl)
    ts=datetime.now().strftime("%Y%m%d-%H%M%S")
    mput("test-results",f"{image.replace('/','_')}/{version}/{ts}.json",result)
    mput("history",f"{ts}_{image.replace('/','_')}.json",{**result,"action":"test"})
    icon="✅" if result["status"]=="pass" else "❌"
    score=result["score"]; steps=result.get("steps",{}); metrics=result.get("metrics",{})
    lines=[f"{icon} *{image}:{version}*",f"Оценка: *{score}/100*","","*Этапы:*"]
    for k,lbl in [("pull","📥 Pull"),("sec","🔒 Security"),("smoke","💨 Smoke"),("http","🌐 HTTP"),("hc","💊 HC"),("res","📊 Ресурсы"),("rst","🔄 Restart"),("clean","🧹 Cleanup")]:
        if k not in steps: continue
        s=steps[k]; ico="✓" if s.get("ok") else "✗"; det=s.get("d","")
        lines.append(f"  {ico} {lbl}"+(f": {det}" if det else ""))
    if metrics:
        lines+=["","*Метрики:*"]
        if "size_mb" in metrics: lines.append(f"  📦 {metrics['size_mb']}MB")
        if "mem_mb" in metrics: lines.append(f"  🧠 RAM {metrics['mem_mb']}MB")
        if "cpu" in metrics: lines.append(f"  ⚡ CPU {metrics['cpu']:.1f}%")
        if metrics.get("crit",0): lines.append(f"  🔴 CRITICAL: {metrics['crit']}")
        if metrics.get("high",0): lines.append(f"  🟠 HIGH: {metrics['high']}")
        if "resp_ms" in metrics: lines.append(f"  ⚡ {metrics['resp_ms']}мс")
    diag=result.get("diag","")
    if diag and result["status"]!="pass": lines+=["","*Диагноз:*",f"```\n{diag[:250]}\n```"]
    rec=result.get("rec","")
    if rec: lines+=["",f"💡 _{rec}_"]
    if result["status"]=="pass":
        kb=InlineKeyboardMarkup([
            [btn("🚀 Развернуть на mini-prod",f"do:deploy:{image}:{version}")],
            [btn("🔄 Перетест",f"do:test:{image}:{version}"),btn("❌",f"do:rej:x:x")]
        ])
    else:
        kb=InlineKeyboardMarkup([
            [btn("💾 Сохранить для доработки",f"do:save:{image}:{version}")],
            [btn("✏️ Исправить и перетестировать",f"do:fix:{image}:{version}")],
            [btn("🔄 Перетест",f"do:test:{image}:{version}"),btn("❌",f"do:rej:x:x")]
        ])
    await message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=kb)

# ── DO DEPLOY ─────────────────────────────────────────────────────────────
async def do_deploy(message,image,version):
    _,svc=find_svc(image); port=svc["port"] if svc else None
    target=f"{image}:{version}"; cname=image.split("/")[-1].lower().split(":")[0]
    await message.reply_text(f"🚀 Разворачиваю *{image}:{version}*...",parse_mode="Markdown")
    loop=asyncio.get_event_loop()
    if not port:
        o,_,_=await loop.run_in_executor(None,lambda:pr(f"docker image inspect {target} --format '{{{{json .Config.ExposedPorts}}}}' 2>/dev/null"))
        try:
            ports=json.loads(o)
            if ports: port=int(list(ports.keys())[0].split("/")[0])
        except: pass
    await loop.run_in_executor(None,lambda:pr(f"docker inspect {cname} --format '{{{{.Config.Image}}}}' 2>/dev/null | tee /opt/homelab/data/rollback_{cname}.txt >/dev/null 2>&1 || true"))
    await loop.run_in_executor(None,lambda:pr(f"docker rm -f {cname} 2>/dev/null || true"))
    pf=f"-p {port}:{port}" if port else ""
    o,e,code=await loop.run_in_executor(None,lambda:pr(f"docker run -d --restart unless-stopped --name {cname} {pf} --label com.centurylinklabs.watchtower.enable=true {target} 2>&1",60))
    if code!=0:
        await message.reply_text(f"❌ Ошибка:\n```\n{(e or o)[:200]}\n```",parse_mode="Markdown"); return
    state,_,_=await loop.run_in_executor(None,lambda:pr(f"docker inspect {cname} --format '{{{{.State.Running}}}}' 2>/dev/null"))
    if "true" not in state.lower():
        await message.reply_text("❌ Контейнер упал сразу после старта"); return
    mput("deployed",f"{image.replace('/','_')}/{version}.json",{"image":target,"container":cname,"port":port,"deployed_at":datetime.now().isoformat(),"host":PROD_HOST})
    mput("history",f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_{image.replace('/','_')}.json",{"image":target,"action":"deploy","port":port,"ts":datetime.now().isoformat()})
    url=f"http://{PROD_HOST}:{port}" if port else None
    lines=[f"✅ *{image}:{version}* запущен!\n"]
    if url: lines.append(f"🌐 *Адрес:* {url}")
    if port: lines.append(f"🔌 *Порт:* `{port}`")
    login=svc.get("login") if svc else None
    passwd=svc.get("pass") if svc else None
    note=svc.get("note") if svc else None
    if login and passwd: lines+=["",f"👤 *Логин:* `{login}`",f"🔑 *Пароль:* `{passwd}`"]
    elif login is None and not note: lines+=["","🔓 _Без авторизации_"]
    if note: lines+=["",f"ℹ️ _{note}_"]
    lines+=["","_Watchtower следит за обновлениями автоматически_"]
    rows=[]
    if url: rows.append([url_btn("🌐 Открыть",url)])
    rows.append([btn("↩️ Rollback",f"do:rbk:{cname}:x")])
    await message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows))

# ── AUTOPILOT ─────────────────────────────────────────────────────────────
async def run_autopilot(message, mode="NORMAL", search_only=False, test_only=False):
    thresholds={"STRICT":(85,0,5),"NORMAL":(70,0,20),"SOFT":(60,0,50)}
    min_score,max_crit,max_high=thresholds.get(mode,(70,0,20))

    await message.reply_text(
        f"🤖 *Автопилот запущен*\n"
        f"Режим: *{mode}* (score≥{min_score}, CRIT={max_crit})\n"
        f"{'🔍 Только поиск' if search_only else '🧪 Тест + деплой'}\n\n"
        f"Ищу интересные проекты...",
        parse_mode="Markdown"
    )

    # Ищем новые проекты
    queries=["homelab self-hosted","monitoring docker","productivity self-hosted","automation homelab"]
    all_projects=[]; seen=load_seen()
    for query in queries:
        try:
            results=await asyncio.wait_for(universal_search(query,limit=5),timeout=30)
            for r in results:
                if r.get("name","").lower() not in seen and r.get("has_docker"):
                    all_projects.append(r)
        except: pass

    # Также берём из каталога непросмотренные
    catalog_unseen=[(n,v) for n,v in SVC.items() if n.lower() not in seen][:5]

    if not all_projects and not catalog_unseen:
        await message.reply_text("😕 Нет новых проектов для автопилота\n/reset — сбросить кэш"); return

    total=len(all_projects)+len(catalog_unseen)
    await message.reply_text(f"📋 Найдено *{total}* новых проектов для обработки",parse_mode="Markdown")

    if search_only:
        lines=["🔍 *Найденные проекты:*\n"]
        for p in all_projects[:8]:
            lines.append(f"• *{p['name']}* — {p.get('desc','')[:80]}")
        for n,v in catalog_unseen[:5]:
            lines.append(f"• *{n}* — {v['d'][:80]}")
        await message.reply_text("\n".join(lines),parse_mode="Markdown"); return

    # Тестируем и деплоим
    deployed_list=[]; failed_list=[]; skipped_list=[]

    # Сначала из каталога (конфиги готовы)
    for name,svc in catalog_unseen:
        img=svc["img"]
        smsg=await message.reply_text(f"⏳ `{img}`...",parse_mode="Markdown")
        pl=[]
        loop=asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result=await loop.run_in_executor(pool,pipeline,img,"latest",pl)
        score=result["score"]; crit=result["metrics"].get("crit",0); high=result["metrics"].get("high",0)
        save_seen([name])
        if result["status"]=="pass" and score>=min_score and crit<=max_crit:
            if not test_only:
                await smsg.edit_text(f"✅ `{img}` — {score}/100 → деплою",parse_mode="Markdown")
                await do_deploy(message,img,"latest")
                deployed_list.append(f"`{img}` ({score}/100)")
            else:
                await smsg.edit_text(f"✅ `{img}` — {score}/100 (тест пройден)",parse_mode="Markdown")
                deployed_list.append(f"`{img}` ({score}/100)")
        else:
            reason=f"CRIT:{crit}" if crit>max_crit else f"score:{score}/100"
            await smsg.edit_text(f"❌ `{img}` — пропускаю ({reason})",parse_mode="Markdown")
            failed_list.append(f"`{img}` — {reason}")
        await asyncio.sleep(1)

    # Итоговый отчёт
    lines=[f"🤖 *Автопилот завершён*\n"]
    if deployed_list:
        action="Протестировано" if test_only else "Задеплоено"
        lines+=[f"*{action} ({len(deployed_list)}):*"]+[f"  ✅ {x}" for x in deployed_list]
    if failed_list:
        lines+=[f"\n*Пропущено ({len(failed_list)}):*"]+[f"  ❌ {x}" for x in failed_list]
    await message.reply_text("\n".join(lines),parse_mode="Markdown")

# ── CALLBACKS ─────────────────────────────────────────────────────────────
@admin_only
async def on_callback(update,ctx):
    q=update.callback_query; data=q.data
    log.info(f"CB: {data!r}")
    try:
        await q.answer()

        # sc: — category navigation
        if data.startswith("sc:"):
            parts=data.split(":"); code=parts[1]; offset=int(parts[2]) if len(parts)>2 else 0
            if code=="RST":
                reset_seen(); await q.edit_message_reply_markup(None)
                await q.message.reply_text("✅ Кэш сброшен"); return
            if code=="MENU":
                await q.edit_message_reply_markup(None)
                available=build_cat_menu(); rows=[]
                for c in sorted(available.keys(),key=lambda x:CAT_NAME.get(x,x)):
                    n=CAT_NAME.get(c,c); em=CAT_EMOJI.get(c,"📦"); cnt=available[c]
                    rows.append([btn(f"{em} {n} ({cnt})","sc:"+c+":0")])
                rows.append([btn("🔀 Все","sc:ALL:0"),btn("🔄 Сброс","sc:RST:0")])
                rows.append([btn("🌐 Поиск по интернету","ap:EXPLORE:x"),btn("🤖 Автопилот","ap:AUTO:x")])
                await q.message.reply_text("🔍 *Выбери категорию:*",parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows)); return
            await q.edit_message_reply_markup(None)
            await show_category(q.message,code,offset); return

        # ap: — autopilot actions
        if data.startswith("ap:"):
            parts=data.split(":"); action=parts[1]
            await q.edit_message_reply_markup(None)
            if action=="EXPLORE":
                await q.message.reply_text("🌐 Введи тему для поиска:\nНапример: osint / kubernetes / backup / мониторинг")
                FIX_CTX[q.from_user.id]={"mode":"explore"}; return
            if action=="AUTO":
                kb=InlineKeyboardMarkup([
                    [btn("🤖 Полный автопилот","ap:FULL:x")],
                    [btn("🔍 Только поиск","ap:SEARCH_ONLY:x"),btn("🧪 Только тест","ap:TEST_ONLY:x")],
                    [btn("📊 Строгий ≥85","ap:STRICT:x"),btn("✅ Обычный ≥70","ap:NORMAL:x"),btn("🔓 Мягкий ≥60","ap:SOFT:x")],
                ])
                await q.message.reply_text("🤖 *Автопилот — выбери режим:*",parse_mode="Markdown",reply_markup=kb); return
            if action=="FULL": await run_autopilot(q.message,"NORMAL"); return
            if action=="SEARCH_ONLY": await run_autopilot(q.message,"NORMAL",search_only=True); return
            if action=="TEST_ONLY": await run_autopilot(q.message,"NORMAL",test_only=True); return
            if action in ("STRICT","NORMAL","SOFT"): await run_autopilot(q.message,action); return
            if action=="STATUS": await _show_status_inline(q.message); return
            if action=="MANAGE": await _show_manage(q.message); return
            return

        # mg: — container management
        if data.startswith("mg:"):
            parts=data.split(":"); action=parts[1]; cname=parts[2]
            loop=asyncio.get_event_loop()
            await q.edit_message_reply_markup(None)
            if action=="restart":
                _,_,code=await loop.run_in_executor(None,lambda:pr(f"docker restart {cname} 2>&1"))
                await q.message.reply_text(f"{'✅' if code==0 else '❌'} Рестарт `{cname}`",parse_mode="Markdown")
            elif action=="stop":
                _,_,code=await loop.run_in_executor(None,lambda:pr(f"docker stop {cname} 2>&1"))
                await q.message.reply_text(f"{'✅' if code==0 else '❌'} Остановлен `{cname}`",parse_mode="Markdown")
            elif action=="remove":
                _,_,code=await loop.run_in_executor(None,lambda:pr(f"docker rm -f {cname} 2>&1"))
                await q.message.reply_text(f"{'✅' if code==0 else '❌'} Удалён `{cname}`",parse_mode="Markdown")
            elif action=="logs":
                out,_,_=await loop.run_in_executor(None,lambda:pr(f"docker logs {cname} --tail 30 2>&1"))
                lines=out.strip().splitlines()[-20:]
                text="\n".join(lines)
                await q.message.reply_text(f"📋 *{cname}*\n```\n{text[:3000]}\n```",parse_mode="Markdown")
            return

        # do: — main actions
        if data.startswith("do:"):
            parts=data.split(":",3); action=parts[1]
            a1=parts[2] if len(parts)>2 else "x"
            a2=parts[3] if len(parts)>3 else "latest"

            if action=="test":
                await q.edit_message_reply_markup(None)
                await do_test(q.message,a1,a2)

            elif action=="deploy":
                await q.edit_message_reply_markup(None)
                await do_deploy(q.message,a1,a2)

            elif action=="save":
                await q.edit_message_reply_markup(None)
                res=mlist("test-results",prefix=f"{a1.replace('/','_')}/{a2}/",limit=1)
                if res:
                    r=res[0]; mput("saved-later",f"{a1.replace('/','_')}/{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",r)
                    diag=r.get("diag","")[:300]; rec=r.get("rec","")
                    lines=[f"💾 *{a1}:{a2}* сохранён\n",f"*Причина:* _{rec}_\n"]
                    if diag: lines+=[f"*Диагноз:*",f"```\n{diag}\n```",""]
                    lines.append("_Скинь исправленный compose файл или env переменные_")
                    rows=[]
                    if "/" in a1 and "." not in a1.split("/")[0]:
                        rows.append([url_btn("📋 GitHub",f"https://github.com/{a1.split(':')[0]}")])
                    elif "ghcr.io/" in a1:
                        rows.append([url_btn("📋 GitHub",f"https://github.com/{a1.replace('ghcr.io/','').split(':')[0]}")])
                    rows.append([btn("✏️ Исправить",f"do:fix:{a1}:{a2}"),btn("🔄 Ретест",f"do:test:{a1}:{a2}")])
                    await q.message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows))
                else:
                    await q.message.reply_text("💾 Сохранено — /saved")

            elif action=="fix":
                await q.edit_message_reply_markup(None)
                FIX_CTX[q.from_user.id]={"image":a1,"version":a2}
                _,svc=find_svc(a1)
                hints=""
                if svc:
                    env_keys=list(svc.get("env",{}).keys())
                    hints=f"Текущие env: {', '.join(env_keys) if env_keys else 'нет'}\nПорт: {svc.get('port','?')}"
                await q.message.reply_text(
                    f"✏️ *Режим исправления: `{a1}`*\n\n{hints}\n\n"
                    f"Скинь что нужно изменить:\n"
                    f"• Файл `docker-compose.yml` или `.env`\n"
                    f"• Или напиши env переменные:\n"
                    f"  `KEY=value`\n"
                    f"  `KEY2=value2`\n\n"
                    f"_Бот применит и протестирует снова_",
                    parse_mode="Markdown"
                )

            elif action=="skip":
                await q.edit_message_reply_markup(None)
                if a1!="x": save_seen([a1])

            elif action in ("rej","del"):
                await q.edit_message_reply_markup(None)

            elif action=="autotest":
                cat_code_at=a1
                await q.edit_message_reply_markup(None)
                cat_name=CAT_NAME.get(cat_code_at,"Все"); seen=load_seen()
                if cat_code_at=="ALL": to_test=[(n,v) for n,v in SVC.items() if n.lower() not in seen]
                else: to_test=[(n,v) for n,v in SVC.items() if v["c"]==cat_code_at and n.lower() not in seen]
                if not to_test:
                    await q.message.reply_text("😕 Нет новых сервисов для теста"); return
                await q.message.reply_text(f"🤖 *Автотест {cat_name}*\nТестирую {len(to_test)} сервисов...",parse_mode="Markdown")
                deployed_auto=[]; failed_auto=[]
                for name,svc in to_test:
                    img=svc["img"]
                    smsg=await q.message.reply_text(f"⏳ `{img}`...",parse_mode="Markdown")
                    pl=[]
                    loop=asyncio.get_event_loop()
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        result=await loop.run_in_executor(pool,pipeline,img,"latest",pl)
                    score=result["score"]; crit=result["metrics"].get("crit",0)
                    save_seen([name])
                    if result["status"]=="pass" and score>=70 and crit==0:
                        await smsg.edit_text(f"✅ `{img}` — {score}/100 → деплою",parse_mode="Markdown")
                        await do_deploy(q.message,img,"latest")
                        deployed_auto.append(f"`{img}` ({score}/100)")
                    else:
                        reason=f"CRIT:{crit}" if crit>0 else f"score:{score}/100"
                        await smsg.edit_text(f"❌ `{img}` — пропускаю ({reason})",parse_mode="Markdown")
                        failed_auto.append(f"`{img}` — {reason}")
                    await asyncio.sleep(1)
                lines=[f"🤖 *Автотест завершён*\n"]
                if deployed_auto: lines+=["*Задеплоено:*"]+[f"  ✅ {x}" for x in deployed_auto]
                if failed_auto: lines+=["\n*Пропущено:*"]+[f"  ❌ {x}" for x in failed_auto]
                await q.message.reply_text("\n".join(lines),parse_mode="Markdown")

            elif action=="rbk":
                await q.edit_message_reply_markup(None)
                loop=asyncio.get_event_loop()
                prev,_,code=await loop.run_in_executor(None,lambda:pr(f"cat /opt/homelab/data/rollback_{a1}.txt 2>/dev/null"))
                if code!=0 or not prev.strip():
                    await q.message.reply_text("❌ Нет данных для rollback"); return
                await loop.run_in_executor(None,lambda:pr(f"docker rm -f {a1} 2>/dev/null || true"))
                _,e,code=await loop.run_in_executor(None,lambda:pr(f"docker run -d --restart unless-stopped --name {a1} {prev.strip()} 2>&1",60))
                if code==0: await q.message.reply_text(f"↩️ Rollback: `{prev.strip()}`",parse_mode="Markdown")
                else: await q.message.reply_text(f"❌ Failed: {e[:150]}")

    except Exception as e:
        log.error(f"CB error {data!r}: {e}",exc_info=True)
        try: await q.message.reply_text(f"❌ Ошибка: {e}")
        except: pass

async def _show_status_inline(message):
    await cmd_status.__wrapped__(None,None) if hasattr(cmd_status,'__wrapped__') else None

# ── TEXT & DOCUMENT HANDLERS ──────────────────────────────────────────────
@admin_only
async def handle_text(update,ctx):
    text=update.message.text.strip()
    uid=update.effective_user.id

    # Режим поиска
    if FIX_CTX.get(uid,{}).get("mode")=="explore":
        FIX_CTX.pop(uid,None)
        await _do_explore(update.message,text); return

    # Режим исправления — env переменные
    if FIX_CTX.get(uid,{}).get("image"):
        fix_img=FIX_CTX[uid]["image"]; fix_ver=FIX_CTX[uid].get("version","latest")
        env_lines=[l.strip() for l in text.splitlines() if "=" in l and not l.startswith("#")]
        if env_lines:
            FIX_CTX.pop(uid,None)
            custom_env={k:v for k,v in [l.split("=",1) for l in env_lines if "=" in l]}
            await update.message.reply_text(f"✏️ Применяю {len(custom_env)} env переменных...\nТестирую `{fix_img}`...",parse_mode="Markdown")
            _,svc=find_svc(fix_img)
            if svc:
                orig=svc.get("env",{}).copy(); svc["env"].update(custom_env)
                await do_test(update.message,fix_img,fix_ver)
                svc["env"]=orig
            else:
                await do_test(update.message,fix_img,fix_ver)
            return
        else:
            await update.message.reply_text("❓ Формат: `KEY=value` каждая на новой строке\nИли скинь .env файл",parse_mode="Markdown"); return

    # GitHub URL
    m=re.search(r'github\.com/([^/\s]+)/([^/\s#?]+)',text)
    if m:
        owner,repo=m.group(1),m.group(2).rstrip("/")
        _,svc=find_svc(repo); img=svc["img"] if svc else f"{owner}/{repo}".lower()
        await update.message.reply_text(f"📦 *{owner}/{repo}*\n`{img}`",parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[btn("▶️ Тест",f"do:test:{img}:latest"),btn("⏭","do:skip:x:x")]])); return

    # image:tag
    if re.match(r'^[a-z0-9._/-]+:[a-z0-9._-]+$',text) or re.match(r'^[a-z0-9._-]+/[a-z0-9._-]+$',text):
        img,ver=(text.rsplit(":",1) if ":" in text else (text,"latest"))
        _,svc=find_svc(img)
        if svc: img=svc["img"]
        await do_test(update.message,img,ver); return

    # Просто текст — предлагаем поиск
    await update.message.reply_text(
        f"🔍 Ищу *{text[:50]}* по интернету?",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[
            btn(f"🌐 Искать '{text[:20]}'",f"ap:EXPLORE_Q:{text[:30]}"),
            btn("❌ Отмена","do:rej:x:x")
        ]])
    )

@admin_only
async def handle_document(update,ctx):
    doc=update.message.document; uid=update.effective_user.id
    if doc.file_size>200*1024:
        await update.message.reply_text("❌ Файл >200KB"); return
    file=await doc.get_file()
    content_bytes=await file.download_as_bytearray()
    content_str=content_bytes.decode(errors="replace")
    fname=doc.file_name or ""
    fix_img=FIX_CTX.get(uid,{}).get("image","")
    fix_ver=FIX_CTX.get(uid,{}).get("version","latest")

    if fname.endswith((".yml",".yaml")):
        if fix_img:
            FIX_CTX.pop(uid,None)
            await update.message.reply_text(f"📄 *{fname}* получен\nТестирую `{fix_img}` с новым compose...",parse_mode="Markdown")
            mput("saved-later",f"custom_compose/{fix_img.replace('/','_')}.json",{"image":fix_img,"compose":content_str,"ts":datetime.now().isoformat()})
            await do_test(update.message,fix_img,fix_ver)
        else:
            await update.message.reply_text(f"📄 *{fname}* получен\nНапиши `image:tag` для теста с этим compose",parse_mode="Markdown")

    elif fname.endswith(".env") or (not fname.endswith((".yml",".yaml",".json")) and "=" in content_str):
        env_lines=[l.strip() for l in content_str.splitlines() if "=" in l and not l.startswith("#")]
        env_dict={k:v for k,v in [l.split("=",1) for l in env_lines if "=" in l]}
        if fix_img and env_dict:
            FIX_CTX.pop(uid,None)
            await update.message.reply_text(f"📄 *{fname}* — {len(env_dict)} переменных\nТестирую `{fix_img}`...",parse_mode="Markdown")
            _,svc=find_svc(fix_img)
            if svc:
                orig=svc.get("env",{}).copy(); svc["env"].update(env_dict)
                await do_test(update.message,fix_img,fix_ver); svc["env"]=orig
            else:
                await do_test(update.message,fix_img,fix_ver)
        else:
            await update.message.reply_text(f"📄 {len(env_dict)} переменных\nСкинь image:tag для теста")
    else:
        await update.message.reply_text(f"❓ Не понял файл *{fname}*\nОжидаю .yml, .yaml или .env",parse_mode="Markdown")

# ── BACKGROUND TASKS ──────────────────────────────────────────────────────
async def background_monitor(app):
    """Фоновый мониторинг — алерты о падении сервисов."""
    await asyncio.sleep(30)
    known_states={}
    while True:
        try:
            loop=asyncio.get_event_loop()
            out,_,_=await loop.run_in_executor(None,lambda:pr("docker ps -a --format '{{.Names}}|{{.Status}}'"))
            for line in out.strip().splitlines():
                if "|" not in line: continue
                name,status=line.split("|",1)
                was_running=known_states.get(name,True)
                is_running=status.lower().startswith("up")
                if was_running and not is_running:
                    await app.bot.send_message(ADMIN_ID,f"🚨 *АЛЕРТ: `{name}` упал!*\nСтатус: `{status}`\n\nПроверь: /logs {name}",parse_mode="Markdown")
                elif not was_running and is_running:
                    await app.bot.send_message(ADMIN_ID,f"✅ `{name}` восстановился",parse_mode="Markdown")
                known_states[name]=is_running
        except Exception as e: log.warning(f"Monitor error: {e}")
        await asyncio.sleep(300)  # каждые 5 минут

async def background_digest(app):
    """Утренний дайджест в 9:00."""
    while True:
        try:
            now=datetime.now()
            if now.hour==9 and now.minute<5:
                loop=asyncio.get_event_loop()
                # Статус серверов
                lines=["🌅 *Утренний дайджест*\n",f"_{now.strftime('%d.%m.%Y')}_\n"]
                for host,name in [("192.168.31.178","srv1"),(SANDBOX_HOST,"sand-box"),(PROD_HOST,"mini-prod")]:
                    out,_,_=await loop.run_in_executor(None,lambda h=host:ssh(h,SANDBOX_USER,SANDBOX_PASS,"docker ps --format '{{.Names}}' | wc -l && free -h|awk '/Mem/{print $3\"/\"$2}'",10))
                    parts=out.strip().splitlines()
                    count=parts[0].strip() if parts else "?"
                    ram=parts[1].strip() if len(parts)>1 else "?"
                    lines.append(f"• *{name}*: {count} контейнеров, RAM {ram}")
                # История за день
                history=mlist("history",limit=5)
                if history:
                    lines+=["","*Вчера:*"]
                    for h in history[:3]:
                        action=h.get("action","?"); img=h.get("image","?")
                        lines.append(f"  {'✅' if action=='deploy' else '🧪'} {action}: `{img}`")
                await app.bot.send_message(ADMIN_ID,"\n".join(lines),parse_mode="Markdown")
                await asyncio.sleep(300)
            else:
                await asyncio.sleep(60)
        except Exception as e: log.warning(f"Digest error: {e}"); await asyncio.sleep(60)

async def background_weekly_trivy(app):
    """Еженедельный Trivy скан по воскресеньям в 3:00."""
    while True:
        try:
            now=datetime.now()
            if now.weekday()==6 and now.hour==3 and now.minute<5:
                await app.bot.send_message(ADMIN_ID,"🔒 *Еженедельный Trivy скан запущен...*",parse_mode="Markdown")
                loop=asyncio.get_event_loop()
                out,_,_=await loop.run_in_executor(None,lambda:pr("docker ps --format '{{.Names}}|{{.Image}}'"))
                total_crit=0; results=[]
                for line in out.strip().splitlines():
                    if "|" not in line: continue
                    name,img=line.split("|",1)
                    to,_,_=await loop.run_in_executor(None,lambda i=img:sb(f"trivy image --server {TRIVY_URL} --format json --quiet {i} 2>/dev/null",120))
                    crit=high=0
                    try:
                        td=json.loads(to)
                        for r in td.get("Results",[]):
                            for v in (r.get("Vulnerabilities") or []):
                                s=v.get("Severity","")
                                if s=="CRITICAL": crit+=1
                                elif s=="HIGH": high+=1
                    except: pass
                    total_crit+=crit
                    results.append(f"{'🔴' if crit>0 else '✅'} `{name}` CRIT:{crit} HIGH:{high}")
                ts=datetime.now().strftime("%Y%m%d")
                mput("trivy-scans",f"weekly_{ts}.json",{"ts":ts,"results":results,"total_crit":total_crit})
                msg="⚠️ *Найдены критические CVE!*\n\n" if total_crit>0 else "✅ *Критических CVE нет*\n\n"
                await app.bot.send_message(ADMIN_ID,msg+"\n".join(results[:15]),parse_mode="Markdown")
                await asyncio.sleep(3600)
            else:
                await asyncio.sleep(300)
        except Exception as e: log.warning(f"Trivy weekly error: {e}"); await asyncio.sleep(300)

async def post_init(app):
    asyncio.create_task(background_monitor(app))
    asyncio.create_task(background_digest(app))
    asyncio.create_task(background_weekly_trivy(app))
    log.info("Background tasks started")

async def error_handler(update,context):
    import traceback
    log.error(f"Error: {context.error}\n{traceback.format_exc()}")

# ── MAIN ──────────────────────────────────────────────────────────────────
def main():
    app=(Application.builder().token(BOT_TOKEN)
         .connect_timeout(60).read_timeout(60).write_timeout(60)
         .get_updates_connect_timeout(60).get_updates_read_timeout(60)
         .post_init(post_init)
         .build())
    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("help",     cmd_start))
    app.add_handler(CommandHandler("search",   cmd_search))
    app.add_handler(CommandHandler("explore",  cmd_explore))
    app.add_handler(CommandHandler("autopilot",cmd_autopilot))
    app.add_handler(CommandHandler("manage",   cmd_manage))
    app.add_handler(CommandHandler("find",     cmd_find))
    app.add_handler(CommandHandler("logs",     cmd_logs))
    app.add_handler(CommandHandler("status",   cmd_status))
    app.add_handler(CommandHandler("history",  cmd_history))
    app.add_handler(CommandHandler("deployed", cmd_deployed))
    app.add_handler(CommandHandler("saved",    cmd_saved))
    app.add_handler(CommandHandler("trivy",    cmd_trivy))
    app.add_handler(CommandHandler("test",     cmd_test))
    app.add_handler(CommandHandler("testall",  cmd_testall))
    app.add_handler(CommandHandler("reset",    cmd_reset))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.Document.ALL,handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND,handle_text))
    app.add_error_handler(error_handler)
    log.info("Homelab Sentinel v6 started")
    app.run_polling(drop_pending_updates=True)

if __name__=="__main__":
    main()
