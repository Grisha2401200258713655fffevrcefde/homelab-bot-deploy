#!/usr/bin/env python3
"""Homelab Sentinel v5 — final stable release."""
import os, re, json, time, asyncio, logging, io, concurrent.futures
from datetime import datetime
from pathlib import Path
import aiohttp, paramiko
from minio import Minio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── CONFIG ──────────────────────────────────────────────────────────────
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

# ── SERVICES ─────────────────────────────────────────────────────────────
# cat codes: M=Monitor V=Video S=Security F=Files N=Net P=Productivity A=Auto I=Infra G=Analytics C=Comms D=DB
SVC = {
    "uptime-kuma":        {"img":"louislam/uptime-kuma",               "c":"M","s":87000,"d":"Self-hosted мониторинг с уведомлениями",         "port":3001,"login":None,                    "pass":None,             "note":"Создать аккаунт при первом входе", "setup":["mkdir -p /tmp/t-uk"],                                                                                                                                    "vols":["/tmp/t-uk:/app/data"],                                                   "env":{},                                                                                                                                       "tp":{3001:13001},"hc":"http://localhost:13001","w":12},
    "beszel":             {"img":"henrygd/beszel",                      "c":"M","s":9000, "d":"Лёгкий мониторинг серверов и Docker",            "port":8090,"login":"admin@admin.com",        "pass":"admin",          "note":None,                               "setup":["mkdir -p /tmp/t-bz"],                                                                                                                                    "vols":["/tmp/t-bz:/beszel_data"],                                                "env":{},                                                                                                                                       "tp":{8090:18090},"hc":"http://localhost:18090","w":10},
    "dozzle":             {"img":"amir20/dozzle",                       "c":"M","s":7000, "d":"Логи Docker контейнеров в реальном времени",     "port":8080,"login":None,                    "pass":None,             "note":"Без авторизации",                  "setup":[],                                                                                                                                                "vols":["/var/run/docker.sock:/var/run/docker.sock"],                              "env":{},                                                                                                                                       "tp":{8080:18082},"hc":"http://localhost:18082","w":5},
    "netdata":            {"img":"netdata/netdata",                     "c":"M","s":73000,"d":"Мониторинг производительности системы",          "port":19999,"login":None,                   "pass":None,             "note":"Без авторизации",                  "setup":[],                                                                                                                                                "vols":["/proc:/host/proc:ro","/sys:/host/sys:ro","/var/run/docker.sock:/var/run/docker.sock:ro"],"env":{},                                                                                                                               "tp":{19999:19999},"hc":"http://localhost:19999","w":15},
    "whats-up-docker":    {"img":"fmartinou/whats-up-docker",           "c":"M","s":3000, "d":"Мониторинг обновлений Docker образов",           "port":3000,"login":None,                    "pass":None,             "note":"Без авторизации",                  "setup":[],                                                                                                                                                "vols":["/var/run/docker.sock:/var/run/docker.sock"],                              "env":{},                                                                                                                                       "tp":{3000:13002},"hc":"http://localhost:13002","w":10},
    "jellyfin":           {"img":"jellyfin/jellyfin",                   "c":"V","s":37000,"d":"Медиасервер — бесплатная замена Plex",           "port":8096,"login":None,                    "pass":None,             "note":"Мастер настройки при первом входе","setup":["mkdir -p /tmp/t-jf/config /tmp/t-jf/cache /tmp/t-jf/media"],                                                                                                  "vols":["/tmp/t-jf/config:/config","/tmp/t-jf/cache:/cache","/tmp/t-jf/media:/media"],"env":{},                                                                                                                                        "tp":{8096:18096},"hc":"http://localhost:18096/health","w":25},
    "tubearchivist":      {"img":"bbilly1/tubearchivist",               "c":"V","s":15000,"d":"YouTube архив для хомлаба",                     "port":8000,"login":"admin",                 "pass":"adminpassword",  "note":None,                               "setup":["mkdir -p /tmp/t-ta"],                                                                                                                                    "vols":["/tmp/t-ta:/youtube"],                                                    "env":{"ES_URL":"http://localhost:9200","REDIS_HOST":"localhost","HOST_UID":"1000","HOST_GID":"1000","TA_HOST":"localhost","TA_USERNAME":"admin","TA_PASSWORD":"adminpassword","ELASTIC_PASSWORD":"elasticpass"}, "tp":{8000:18000},"hc":"http://localhost:18000","w":20},
    "vaultwarden":        {"img":"vaultwarden/server",                  "c":"S","s":41000,"d":"Bitwarden совместимый сервер паролей",          "port":80,  "login":None,                    "pass":None,             "note":"Создать аккаунт при первом входе", "setup":["mkdir -p /tmp/t-vw"],                                                                                                                                    "vols":["/tmp/t-vw:/data"],                                                       "env":{"ADMIN_TOKEN":"hltest123"},                                                                                                              "tp":{80:18766},"hc":"http://localhost:18766","w":10},
    "authelia":           {"img":"authelia/authelia",                   "c":"S","s":22000,"d":"SSO и 2FA для всех сервисов",                   "port":9091,"login":None,                    "pass":None,             "note":"Требует настройки",                "setup":["mkdir -p /tmp/t-au/config","printf 'host: 0.0.0.0\\njwt_secret: test123\\ndefault_redirection_url: http://localhost\\n' > /tmp/t-au/config/configuration.yml"],"vols":["/tmp/t-au/config:/config"],                                             "env":{},                                                                                                                                       "tp":{9091:19091},"hc":"http://localhost:19091/api/health","w":15},
    "filebrowser":        {"img":"filebrowser/filebrowser",             "c":"F","s":28000,"d":"Веб файловый менеджер",                         "port":8080,"login":"admin",                 "pass":"admin",          "note":None,                               "setup":["mkdir -p /tmp/t-fb","touch /tmp/t-fb/db.db"],                                                                                                            "vols":["/tmp/t-fb:/srv","/tmp/t-fb/db.db:/database.db"],                         "env":{},                                                                                                                                       "tp":{80:18767},"hc":"http://localhost:18767","w":6},
    "paperless-ngx":      {"img":"ghcr.io/paperless-ngx/paperless-ngx", "c":"F","s":24000,"d":"Система управления документами с OCR",          "port":8000,"login":"admin",                 "pass":"admin",          "note":None,                               "setup":["mkdir -p /tmp/t-pl/data /tmp/t-pl/media /tmp/t-pl/export /tmp/t-pl/consume"],                                                                            "vols":["/tmp/t-pl/data:/usr/src/paperless/data","/tmp/t-pl/media:/usr/src/paperless/media","/tmp/t-pl/export:/usr/src/paperless/export","/tmp/t-pl/consume:/usr/src/paperless/consume"],"env":{"PAPERLESS_SECRET_KEY":"hltest123","PAPERLESS_TIME_ZONE":"Europe/Moscow","PAPERLESS_OCR_LANGUAGE":"rus+eng"},"tp":{8000:18001},"hc":"http://localhost:18001","w":40},
    "nextcloud":          {"img":"nextcloud",                           "c":"F","s":28000,"d":"Self-hosted Google Drive — файлы фото календарь","port":8080,"login":"admin",                 "pass":"adminpassword",  "note":None,                               "setup":["mkdir -p /tmp/t-nc"],                                                                                                                                    "vols":["/tmp/t-nc:/var/www/html"],                                               "env":{"MYSQL_HOST":"localhost","MYSQL_DATABASE":"nextcloud","MYSQL_USER":"nextcloud","MYSQL_PASSWORD":"ncpassword","NEXTCLOUD_ADMIN_USER":"admin","NEXTCLOUD_ADMIN_PASSWORD":"adminpassword","NEXTCLOUD_TRUSTED_DOMAINS":"localhost"},"tp":{80:18080},"hc":"http://localhost:18080","w":30},
    "nginx-proxy-manager":{"img":"jc21/nginx-proxy-manager",            "c":"N","s":23000,"d":"Reverse proxy с веб-интерфейсом и SSL",         "port":81,  "login":"admin@example.com",     "pass":"changeme",       "note":None,                               "setup":["mkdir -p /tmp/t-npm/data /tmp/t-npm/le"],                                                                                                                "vols":["/tmp/t-npm/data:/data","/tmp/t-npm/le:/etc/letsencrypt"],                "env":{},                                                                                                                                       "tp":{81:18181},"hc":"http://localhost:18181","w":20},
    "adguard-home":       {"img":"adguard/adguardhome",                 "c":"N","s":26000,"d":"DNS сервер с блокировкой рекламы",              "port":3000,"login":None,                    "pass":None,             "note":"Настройка при первом входе",       "setup":["mkdir -p /tmp/t-adg/work /tmp/t-adg/conf"],                                                                                                              "vols":["/tmp/t-adg/work:/opt/adguardhome/work","/tmp/t-adg/conf:/opt/adguardhome/conf"],"env":{},                                                                                                                                     "tp":{3000:13003},"hc":"http://localhost:13003","w":10},
    "speedtest-tracker":  {"img":"henrywhitaker3/speedtest-tracker",    "c":"N","s":3000, "d":"Автоматические тесты скорости интернета",       "port":8765,"login":"admin@example.com",     "pass":"password",       "note":None,                               "setup":["mkdir -p /tmp/t-st"],                                                                                                                                    "vols":["/tmp/t-st:/config"],                                                     "env":{"OOKLA_EULA_GDPR":"true"},                                                                                                               "tp":{80:18765},"hc":"http://localhost:18765","w":12},
    "actual-budget":      {"img":"actualbudget/actual-server",          "c":"P","s":16000,"d":"Локальный менеджер личного бюджета",            "port":5006,"login":None,                    "pass":None,             "note":"Создать аккаунт при первом входе", "setup":["mkdir -p /tmp/t-ac"],                                                                                                                                    "vols":["/tmp/t-ac:/data"],                                                       "env":{},                                                                                                                                       "tp":{5006:15006},"hc":"http://localhost:15006","w":10},
    "mealie":             {"img":"ghcr.io/mealie-recipes/mealie",       "c":"P","s":8000, "d":"Менеджер рецептов и планировщик меню",          "port":9000,"login":"changeme@example.com",  "pass":"MyPassword",     "note":None,                               "setup":["mkdir -p /tmp/t-ml"],                                                                                                                                    "vols":["/tmp/t-ml:/app/data"],                                                   "env":{"ALLOW_SIGNUP":"true","PUID":"1000","PGID":"1000","TZ":"Europe/Moscow","BASE_URL":"http://localhost:19000"},                              "tp":{9000:19000},"hc":"http://localhost:19000","w":18},
    "maybe":              {"img":"ghcr.io/maybe-finance/maybe",         "c":"P","s":42000,"d":"Личные финансы и инвестиционный портфель",      "port":3000,"login":None,                    "pass":None,             "note":"Создать аккаунт при первом входе", "setup":["mkdir -p /tmp/t-mb/storage"],                                                                                                                            "vols":["/tmp/t-mb/storage:/rails/storage"],                                      "env":{"SELF_HOSTED":"true","RAILS_FORCE_SSL":"false","RAILS_ASSUME_SSL":"false","SECRET_KEY_BASE":"hltest_secret_key_base_1234567890abcdef"},   "tp":{3000:13100},"hc":"http://localhost:13100","w":25},
    "linkwarden":         {"img":"ghcr.io/linkwarden/linkwarden",       "c":"P","s":9000, "d":"Менеджер закладок с архивацией страниц",        "port":3000,"login":None,                    "pass":None,             "note":"Создать аккаунт при первом входе", "setup":["mkdir -p /tmp/t-lw/data"],                                                                                                                               "vols":["/tmp/t-lw/data:/data/data"],                                             "env":{"NEXTAUTH_SECRET":"hltest_secret","NEXTAUTH_URL":"http://localhost:13101"},                                                               "tp":{3000:13101},"hc":"http://localhost:13101","w":20},
    "changedetection":    {"img":"ghcr.io/dgtlmoon/changedetection.io", "c":"A","s":21000,"d":"Мониторинг изменений веб-страниц",             "port":5000,"login":None,                    "pass":None,             "note":"Без авторизации",                  "setup":["mkdir -p /tmp/t-cd"],                                                                                                                                    "vols":["/tmp/t-cd:/datastore"],                                                  "env":{},                                                                                                                                       "tp":{5000:15000},"hc":"http://localhost:15000","w":10},
    "n8n":                {"img":"n8nio/n8n",                           "c":"A","s":52000,"d":"Визуальная автоматизация как Zapier",           "port":5678,"login":"admin",                 "pass":"changeme",       "note":None,                               "setup":["mkdir -p /tmp/t-n8n"],                                                                                                                                   "vols":["/tmp/t-n8n:/home/node/.n8n"],                                            "env":{"N8N_BASIC_AUTH_ACTIVE":"true","N8N_BASIC_AUTH_USER":"admin","N8N_BASIC_AUTH_PASSWORD":"hltest123","N8N_SECURE_COOKIE":"false","N8N_DIAGNOSTICS_ENABLED":"false"},"tp":{5678:15678},"hc":"http://localhost:15678","w":15},
    "glance":             {"img":"glanceapp/glance",                    "c":"I","s":34000,"d":"Красивый дашборд с виджетами",                 "port":8080,"login":None,                    "pass":None,             "note":"Без авторизации",                  "setup":["mkdir -p /tmp/t-gl/config","printf 'pages:\\n  - name: Home\\n    columns:\\n      - size: full\\n        widgets:\\n          - type: clock\\n' > /tmp/t-gl/config/glance.yml"],"vols":["/tmp/t-gl/config/glance.yml:/app/assets/glance.yml"],                   "env":{},                                                                                                                                       "tp":{8080:18091},"hc":"http://localhost:18091","w":6},
    "homepage":           {"img":"ghcr.io/gethomepage/homepage",        "c":"I","s":22000,"d":"Современный дашборд для хомлаба",              "port":3000,"login":None,                    "pass":None,             "note":"Без авторизации",                  "setup":["mkdir -p /tmp/t-hp/config","echo '{}' > /tmp/t-hp/config/settings.yaml","echo '[]' > /tmp/t-hp/config/services.yaml","echo '[]' > /tmp/t-hp/config/bookmarks.yaml","echo '[]' > /tmp/t-hp/config/widgets.yaml"],"vols":["/tmp/t-hp/config:/app/config"],                                         "env":{},                                                                                                                                       "tp":{3000:13000},"hc":"http://localhost:13000","w":12},
    "stirling-pdf":       {"img":"frooodle/s-pdf",                      "c":"I","s":48000,"d":"PDF: merge/split/OCR/convert/compress",        "port":8080,"login":None,                    "pass":None,             "note":"Без авторизации",                  "setup":["mkdir -p /tmp/t-sp/configs"],                                                                                                                            "vols":["/tmp/t-sp/configs:/configs"],                                            "env":{"DOCKER_ENABLE_SECURITY":"false","LANGS":"en_GB"},                                                                                       "tp":{8080:18095},"hc":"http://localhost:18095","w":20},
    "portainer":          {"img":"portainer/portainer-ce",              "c":"I","s":32000,"d":"Веб-интерфейс для управления Docker",          "port":9000,"login":None,                    "pass":None,             "note":"Создать admin при первом входе",   "setup":["mkdir -p /tmp/t-pt"],                                                                                                                                    "vols":["/var/run/docker.sock:/var/run/docker.sock","/tmp/t-pt:/data"],           "env":{},                                                                                                                                       "tp":{9000:19010},"hc":"http://localhost:19010","w":8},
    "grafana":            {"img":"grafana/grafana",                     "c":"G","s":65000,"d":"Дашборды и визуализация метрик",               "port":3000,"login":"admin",                 "pass":"adminpassword",  "note":None,                               "setup":["mkdir -p /tmp/t-gr"],                                                                                                                                    "vols":["/tmp/t-gr:/var/lib/grafana"],                                            "env":{"GF_SECURITY_ADMIN_PASSWORD":"adminpassword","GF_USERS_ALLOW_SIGN_UP":"false"},                                                          "tp":{3000:13200},"hc":"http://localhost:13200","w":10},
    "matrix-synapse":     {"img":"matrixdotorg/synapse",                "c":"C","s":13000,"d":"Self-hosted Matrix мессенджер",               "port":8008,"login":None,                    "pass":None,             "note":"Требует регистрации",              "setup":["mkdir -p /tmp/t-syn"],                                                                                                                                   "vols":["/tmp/t-syn:/data"],                                                      "env":{"SYNAPSE_SERVER_NAME":"localhost","SYNAPSE_REPORT_STATS":"no"},                                                                          "tp":{8008:18008},"hc":"http://localhost:18008/_matrix/client/versions","w":20},
    "postgres":           {"img":"postgres",                            "c":"D","s":15000,"d":"PostgreSQL — мощная реляционная СУБД",        "port":5432,"login":"admin",                 "pass":"adminpassword",  "note":None,                               "setup":["mkdir -p /tmp/t-pg"],                                                                                                                                    "vols":["/tmp/t-pg:/var/lib/postgresql/data"],                                    "env":{"POSTGRES_USER":"admin","POSTGRES_PASSWORD":"adminpass","POSTGRES_DB":"testdb"},                                                         "tp":{5432:15432},"hc":None,"hcmd":"pg_isready -U admin","w":10},
}

CAT_NAME = {"M":"Мониторинг","V":"Медиа","S":"Безопасность","F":"Файлы","N":"Сеть","P":"Продуктивность","A":"Автоматизация","I":"Инфраструктура","G":"Аналитика","C":"Коммуникации","D":"Базы данных"}
CAT_EMOJI = {"M":"📊","V":"🎬","S":"🔐","F":"📁","N":"🌐","P":"📝","A":"🤖","I":"🛠","G":"📈","C":"💬","D":"🗄"}

def find_svc(image):
    img = image.lower().split(":")[0]
    name = img.split("/")[-1]
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

_mc=None
def get_mc():
    global _mc
    if _mc is None:
        _mc=Minio(MINIO_URL.replace("http://","").replace("https://",""),access_key=MINIO_USER,secret_key=MINIO_PASS,secure=False)
        for b in ["test-results","deployed","saved-later"]:
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

def ssh(host,user,pwd,cmd,t=60):
    for attempt in range(3):
        try:
            c=paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if SSH_KEY and os.path.exists(SSH_KEY):
                c.connect(host,username=user,key_filename=SSH_KEY,timeout=10)
            else:
                c.connect(host,username=user,password=pwd,timeout=10)
            _,out,err=c.exec_command(cmd,timeout=t)
            o=out.read().decode(errors="replace")
            e=err.read().decode(errors="replace")
            code=out.channel.recv_exit_status()
            c.close()
            return o,e,code
        except Exception as ex:
            if attempt==2: return "",str(ex),-1
            time.sleep(2**attempt)

def sb(cmd,t=60): return ssh(SANDBOX_HOST,SANDBOX_USER,SANDBOX_PASS,cmd,t)
def pr(cmd,t=60): return ssh(PROD_HOST,PROD_USER,PROD_PASS,cmd,t)

# ── PIPELINE ──────────────────────────────────────────────────────────────
def pipeline(image,version,prog):
    target=f"{image}:{version}"
    _,svc=find_svc(image)
    cn="hlt_"+re.sub(r'[^a-z0-9]','_',image.split("/")[-1].lower())
    res={"image":image,"version":version,"ts":datetime.now().isoformat(),"status":"error","score":0,"steps":{},"metrics":{},"fail":"","diag":"","rec":""}

    def p(m): prog.append(m)

    # PULL
    p("📥 Pull образа...")
    o,e,code=sb(f"docker pull {target} 2>&1",180)
    if code!=0:
        res["steps"]["pull"]={"ok":False,"d":(e or o)[:100]}
        res["fail"]="pull"; res["diag"]=(e or o)[:300]
        res["rec"]="Образ недоступен или не существует"
        return res
    try:
        so,_,_=sb(f"docker image inspect {target} --format '{{{{.Size}}}}' 2>/dev/null")
        size=int(so.strip())//1024//1024
        res["metrics"]["size_mb"]=size
        res["steps"]["pull"]={"ok":True,"d":f"{size}MB"}
        p(f"✓ Pull — {size}MB")
    except:
        res["steps"]["pull"]={"ok":True,"d":"ok"}; p("✓ Pull")

    # SECURITY
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

    # SETUP
    if svc:
        for cmd in svc.get("setup",[]): sb(cmd,15)
    sb(f"docker rm -f {cn} 2>/dev/null || true")

    # SMOKE
    p("💨 Запуск контейнера...")
    ef=" ".join(f'-e "{k}={v}"' for k,v in (svc.get("env",{}) if svc else {}).items())
    vf=" ".join(f"-v {v}" for v in (svc.get("vols",[]) if svc else []))
    pf=" ".join(f"-p {h}:{c}" for c,h in (svc.get("tp",{}) if svc else {}).items())
    o,e,code=sb(f"docker run -d --name {cn} --restart=no --memory=512m {ef} {vf} {pf} {target} 2>&1",30)
    if code!=0:
        res["steps"]["smoke"]={"ok":False,"d":(e or o)[:100]}
        res["fail"]="smoke"; res["diag"]=(e or o)[:400]
        res["rec"]="Контейнер не запускается — нужна настройка окружения"
        sb(f"docker rm -f {cn} 2>/dev/null || true")
        return res

    wait=svc["w"] if svc else 10
    p(f"⏳ Инициализация {wait}с...")
    time.sleep(wait)

    state,_,_=sb(f"docker inspect {cn} --format '{{{{.State.Running}}}}' 2>/dev/null")
    running="true" in state.lower()
    if not running:
        crash,_,_=sb(f"docker logs {cn} 2>&1 | tail -8")
        oom,_,_=sb(f"docker inspect {cn} --format '{{{{.State.OOMKilled}}}}' 2>/dev/null")
        res["steps"]["smoke"]={"ok":False,"d":"упал"}
        res["diag"]=crash[:400]
        res["fail"]="oom" if "true" in oom.lower() else "smoke"
        res["rec"]="OOM — недостаточно памяти" if "true" in oom.lower() else "Контейнер падает — проверь конфиг"
        sb(f"docker rm -f {cn} 2>/dev/null || true")
        return res

    res["steps"]["smoke"]={"ok":True,"d":f"живёт {wait}с"}; p("✓ Smoke")

    # HTTP
    hc=svc["hc"] if svc else None
    if hc:
        p("🌐 HTTP check...")
        ho,_,_=sb(f"curl -sf --max-time 10 -o /dev/null -w '%{{http_code}}|%{{time_total}}' {hc} 2>/dev/null")
        pts=ho.strip().split("|")
        hcode=pts[0] if pts else ""
        try: ms=int(float(pts[1])*1000) if len(pts)>1 else 0
        except: ms=0
        ok=hcode in ("200","201","204","301","302","401","403")
        res["metrics"]["resp_ms"]=ms
        res["steps"]["http"]={"ok":ok,"d":f"HTTP {hcode} {ms}мс"}
        p(f"{'✓' if ok else '✗'} HTTP — {hcode} {ms}мс")

    hcmd=svc.get("hcmd","") if svc else ""
    if hcmd:
        _,_,hc2=sb(f"docker exec {cn} sh -c '{hcmd}' 2>/dev/null",15)
        res["steps"]["hc"]={"ok":hc2==0,"d":"ok" if hc2==0 else "fail"}
        p(f"{'✓' if hc2==0 else '✗'} Healthcheck")

    # RESOURCES
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

    # RESTART
    p("🔄 Restart test...")
    sb(f"docker restart {cn}",30)
    time.sleep(min(wait,8))
    s2,_,_=sb(f"docker inspect {cn} --format '{{{{.State.Running}}}}' 2>/dev/null")
    rok="true" in s2.lower()
    res["steps"]["rst"]={"ok":rok,"d":"выжил" if rok else "упал"}
    p(f"{'✓' if rok else '✗'} Restart — {'выжил' if rok else 'упал'}")

    # CLEANUP
    sb(f"docker rm -f {cn} 2>/dev/null || true")
    if svc:
        for v in svc.get("vols",[]):
            hp=v.split(":")[0]
            if hp.startswith("/tmp/t-"): sb(f"rm -rf {hp} 2>/dev/null || true")
    res["steps"]["clean"]={"ok":True,"d":"ok"}; p("✓ Cleanup")

    # SCORE
    w={"pull":10,"sec":20,"smoke":25,"http":15,"res":10,"rst":15,"clean":5}
    score=sum(wt for k,wt in w.items() if res["steps"].get(k,{}).get("ok"))
    score-=min(crit*10,30); score-=min(high*2,10)
    score=max(0,min(100,score))
    res["score"]=score
    res["status"]="pass" if score>=60 else "fail"
    if score>=85: res["rec"]="Отлично — готов к деплою"
    elif score>=70: res["rec"]="Хорошо — можно деплоить"
    elif score>=60: res["rec"]="Работает, есть замечания"
    elif crit>0: res["rec"]=f"Не деплоить — {crit} CRITICAL CVE"
    else: res["rec"]="Нестабильная работа"
    return res

# ── HELPERS ───────────────────────────────────────────────────────────────
def admin_only(func):
    async def wrapper(update,ctx):
        uid=update.effective_user.id if update.effective_user else update.callback_query.from_user.id
        if uid!=ADMIN_ID: return
        return await func(update,ctx)
    return wrapper

def build_cat_menu():
    seen=load_seen()
    available={}
    for name,svc in SVC.items():
        if name.lower() not in seen:
            c=svc["c"]
            available[c]=available.get(c,0)+1
    return available

def make_kb(*rows): return InlineKeyboardMarkup(list(rows))
def btn(text,data): return InlineKeyboardButton(text,callback_data=data)
def url_btn(text,url): return InlineKeyboardButton(text,url=url)

# ── COMMANDS ──────────────────────────────────────────────────────────────
@admin_only
async def cmd_start(update,ctx):
    cats={}
    for v in SVC.values():
        cn=CAT_NAME.get(v["c"],v["c"]); cats[cn]=cats.get(cn,0)+1
    lines=["🤖 *Homelab Sentinel v5*\n","/search — выбрать категорию","/status — статус серверов","/test image:tag — тест","/testall img1 img2 — параллельно","/deployed — запущено на прод","/saved — сохранено для доработки","/reset — сбросить кэш\n","*Категорий:* "+str(len(cats))+" | *Сервисов:* "+str(len(SVC))]
    await update.message.reply_text("\n".join(lines),parse_mode="Markdown")

@admin_only
async def cmd_search(update,ctx):
    available=build_cat_menu()
    if not available:
        await update.message.reply_text("😕 Все просмотрено\n/reset — сбросить кэш"); return
    rows=[]
    for code in sorted(available.keys(), key=lambda x: CAT_NAME.get(x,x)):
        name=CAT_NAME.get(code,code); em=CAT_EMOJI.get(code,"📦"); count=available[code]
        rows.append([btn(f"{em} {name} ({count})", f"sc:{code}:0")])
    rows.append([btn("🔀 Все категории","sc:ALL:0"), btn("🔄 Сброс кэша","sc:RST:0")])
    await update.message.reply_text(
        "🔍 *Выбери категорию:*",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(rows)
    )

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
    await update.message.reply_text(f"🚀 Параллельный тест {len(items)} образов:\n"+"\n".join(f"  • `{i}:{v}`" for i,v in items),parse_mode="Markdown")
    await asyncio.gather(*[do_test(update.message,img,ver) for img,ver in items])

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
    lines=[f"💾 *Сохранено ({len(items)}):*\n"]
    rows=[]
    seen_imgs=set()
    for item in items:
        img=item.get("image","?")
        if img in seen_imgs: continue
        seen_imgs.add(img)
        ts=item.get("ts","")[:10]; rec=item.get("rec","?")
        diag=item.get("diag","")[:60].replace("\n"," ")
        lines.append(f"*{img}*\n  _{rec}_\n  `{diag}`\n  _{ts}_")
        rows.append([btn(f"🔄 Ретест",f"do:test:{img}:latest"),btn("🗑",f"do:del:{img}:x")])
    await update.message.reply_text("\n\n".join(lines),parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows) if rows else None)

@admin_only
async def cmd_reset(update,ctx):
    reset_seen()
    await update.message.reply_text("✅ Кэш сброшен — /search покажет всё заново")

# ── SHOW CATEGORY ─────────────────────────────────────────────────────────
async def show_category(message,cat_code,offset):
    log.info(f"show_category cat={cat_code!r} offset={offset}")
    seen=load_seen()
    PAGE=4
    if cat_code=="ALL":
        projs=[(n,v) for n,v in SVC.items() if n.lower() not in seen]
    else:
        projs=[(n,v) for n,v in SVC.items() if v["c"]==cat_code and n.lower() not in seen]
    total=len(projs)
    page=projs[offset:offset+PAGE]
    log.info(f"total={total} page_len={len(page)}")
    if not page:
        await message.reply_text("😕 В этой категории больше нет проектов\n/reset — сбросить кэш"); return
    for name,svc in page:
        cat_name=CAT_NAME.get(svc["c"],svc["c"]); em=CAT_EMOJI.get(svc["c"],"📦")
        stars=svc.get("s",0); desc=svc.get("d","")
        login=svc.get("login"); passwd=svc.get("pass"); note=svc.get("note")
        lines=[f"🐳 *{name}*  {em} {cat_name}  ⭐{stars:,}",f"`{svc['img']}`",f"_{desc}_"]
        if login and passwd: lines.append(f"👤 `{login}` 🔑 `{passwd}`")
        elif note: lines.append(f"ℹ️ _{note}_")
        kb=InlineKeyboardMarkup([[btn("▶️ Тест",f"do:test:{svc['img']}:latest"),btn("⏭ Пропустить",f"do:skip:{name}:x")]])
        await message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=kb)
        await asyncio.sleep(0.3)
    nav=[]
    if offset+PAGE<total: nav.append(btn(f"➡️ Ещё ({total-offset-PAGE})",f"sc:{cat_code}:{offset+PAGE}"))
    nav.append(btn("🔙 Категории","sc:MENU:0"))
    await message.reply_text(f"_{min(offset+PAGE,total)} из {total}_",parse_mode="Markdown",reply_markup=InlineKeyboardMarkup([nav]))

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
        kb=InlineKeyboardMarkup([[btn("🚀 Развернуть на mini-prod",f"do:deploy:{image}:{version}")],[btn("🔄 Перетест",f"do:test:{image}:{version}"),btn("❌",f"do:rej:x:x")]])
    else:
        kb=InlineKeyboardMarkup([[btn("💾 Сохранить для доработки",f"do:save:{image}:{version}")],[btn("🔄 Перетест",f"do:test:{image}:{version}"),btn("❌",f"do:rej:x:x")]])
    await message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=kb)

# ── DO DEPLOY ─────────────────────────────────────────────────────────────
async def do_deploy(message,image,version):
    _,svc=find_svc(image)
    port=svc["port"] if svc else None
    target=f"{image}:{version}"
    cname=image.split("/")[-1].lower().split(":")[0]
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
        await message.reply_text("❌ Контейнер запустился но упал"); return
    mput("deployed",f"{image.replace('/','_')}/{version}.json",{"image":target,"container":cname,"port":port,"deployed_at":datetime.now().isoformat(),"host":PROD_HOST})
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

# ── CALLBACKS ─────────────────────────────────────────────────────────────
@admin_only
async def on_callback(update,ctx):
    q=update.callback_query
    data=q.data
    log.info(f"CB: {data!r}")
    try:
        await q.answer()
        # sc: — search/category navigation
        if data.startswith("sc:"):
            parts=data.split(":")
            code=parts[1]
            offset=int(parts[2]) if len(parts)>2 else 0
            if code=="RST":
                reset_seen()
                await q.edit_message_reply_markup(None)
                await q.message.reply_text("✅ Кэш сброшен — /search покажет всё заново")
                return
            if code=="MENU":
                await q.edit_message_reply_markup(None)
                available=build_cat_menu()
                rows=[]
                for c in sorted(available.keys(),key=lambda x:CAT_NAME.get(x,x)):
                    n=CAT_NAME.get(c,c); em=CAT_EMOJI.get(c,"📦"); cnt=available[c]
                    rows.append([btn(f"{em} {n} ({cnt})",f"sc:{c}:0")])
                rows.append([btn("🔀 Все","sc:ALL:0"),btn("🔄 Сброс","sc:RST:0")])
                await q.message.reply_text("🔍 *Выбери категорию:*",parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows))
                return
            await q.edit_message_reply_markup(None)
            await show_category(q.message,code,offset)
            return

        # do: — actions
        if data.startswith("do:"):
            parts=data.split(":",3)
            action=parts[1]
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
                    r=res[0]
                    mput("saved-later",f"{a1.replace('/','_')}/{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",r)
                    diag=r.get("diag","")[:300]; rec=r.get("rec","")
                    lines=[f"💾 *{a1}:{a2}* сохранён\n",f"*Причина:* _{rec}_\n"]
                    if diag: lines+=[f"*Диагноз:*",f"```\n{diag}\n```",""]
                    lines.append("_Скинь исправленный compose и бот протестирует снова_")
                    rows=[]
                    if "/" in a1 and "." not in a1.split("/")[0]:
                        gh=f"https://github.com/{a1.split(':')[0]}"
                        rows.append([url_btn("📋 GitHub",gh)])
                    elif "ghcr.io/" in a1:
                        gh=f"https://github.com/{a1.replace('ghcr.io/','').split(':')[0]}"
                        rows.append([url_btn("📋 GitHub",gh)])
                    rows.append([btn("🔄 Ретест",f"do:test:{a1}:{a2}")])
                    await q.message.reply_text("\n".join(lines),parse_mode="Markdown",reply_markup=InlineKeyboardMarkup(rows))
                else:
                    await q.message.reply_text("💾 Сохранено — /saved")
            elif action=="skip":
                await q.edit_message_reply_markup(None)
                if a1!="x": save_seen([a1])
            elif action in ("rej","del"):
                await q.edit_message_reply_markup(None)
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

# ── TEXT HANDLER ──────────────────────────────────────────────────────────
@admin_only
async def handle_text(update,ctx):
    text=update.message.text.strip()
    m=re.search(r'github\.com/([^/\s]+)/([^/\s#?]+)',text)
    if m:
        owner,repo=m.group(1),m.group(2).rstrip("/")
        _,svc=find_svc(repo)
        img=svc["img"] if svc else f"{owner}/{repo}".lower()
        await update.message.reply_text(f"📦 *{owner}/{repo}*\n`{img}`",parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[btn("▶️ Тест",f"do:test:{img}:latest"),btn("⏭","do:skip:x:x")]]))
        return
    if re.match(r'^[a-z0-9._/-]+:[a-z0-9._-]+$',text) or re.match(r'^[a-z0-9._-]+/[a-z0-9._-]+$',text):
        img,ver=(text.rsplit(":",1) if ":" in text else (text,"latest"))
        _,svc=find_svc(img)
        if svc: img=svc["img"]
        await do_test(update.message,img,ver)
        return
    await update.message.reply_text("❓ Скинь GitHub ссылку, image:tag, или /search")

async def error_handler(update,context):
    import traceback
    log.error(f"Error: {context.error}\n{traceback.format_exc()}")

# ── MAIN ──────────────────────────────────────────────────────────────────
def main():
    app=(Application.builder().token(BOT_TOKEN)
         .connect_timeout(60).read_timeout(60).write_timeout(60)
         .get_updates_connect_timeout(60).get_updates_read_timeout(60)
         .build())
    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_start))
    app.add_handler(CommandHandler("status",  cmd_status))
    app.add_handler(CommandHandler("search",  cmd_search))
    app.add_handler(CommandHandler("test",    cmd_test))
    app.add_handler(CommandHandler("testall", cmd_testall))
    app.add_handler(CommandHandler("deployed",cmd_deployed))
    app.add_handler(CommandHandler("saved",   cmd_saved))
    app.add_handler(CommandHandler("reset",   cmd_reset))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND,handle_text))
    app.add_error_handler(error_handler)
    log.info("Homelab Sentinel v5 started")
    app.run_polling(drop_pending_updates=True)

if __name__=="__main__":
    main()
