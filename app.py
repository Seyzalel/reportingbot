import os
import re
import json
import base64
import logging
import secrets
import threading
import time
import queue
from io import BytesIO
from datetime import datetime, timedelta
from urllib.parse import quote_plus
from functools import wraps
from decimal import Decimal, ROUND_HALF_UP
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any
import requests
import qrcode
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, Response, stream_with_context
from pymongo import MongoClient, ASCENDING, errors
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from werkzeug.exceptions import HTTPException
from admin import admin_bp
from faker import Faker
import unicodedata
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logging.basicConfig(level=logging.INFO)

USER = quote_plus(os.environ.get("DB_USER", "seyzalel"))
PWD = quote_plus(os.environ.get("DB_PASS", "Sey17zalel17@$"))
MONGO_URI = f"mongodb+srv://{USER}:{PWD}@cluster0.krrj4yp.mongodb.net/bcbravus?retryWrites=true&w=majority&appName=Cluster0"
MONGO_OPTS = {
    "serverSelectionTimeoutMS": int(os.environ.get("MONGO_SERVER_TIMEOUT_MS", "5000")),
    "maxPoolSize": int(os.environ.get("MONGO_MAX_POOL", "200")),
    "minPoolSize": int(os.environ.get("MONGO_MIN_POOL", "0")),
    "connect": True,
}
client = MongoClient(MONGO_URI, **MONGO_OPTS)
db = client["reportingbot"]
users = db["users"]
transactions = db["transactions"]
usage = db["usage"]
settings = db["settings"]
orders = db["orders"]

def safe_create_indexes():
    try:
        users.create_indexes([
            {"key": [("username", ASCENDING)], "name": "username_1", "unique": True},
            {"key": [("username_lower", ASCENDING)], "name": "username_lower_1", "unique": True, "partialFilterExpression": {"username_lower": {"$type": "string"}}},
            {"key": [("email", ASCENDING)], "name": "email_1", "unique": True},
        ])
    except Exception:
        logging.exception("create_index_users")
    try:
        transactions.create_indexes([
            {"key": [("hash", ASCENDING)], "name": "hash_1", "unique": True},
            {"key": [("user_id", ASCENDING)], "name": "user_id_1"},
        ])
    except Exception:
        logging.exception("create_index_transactions")
    try:
        usage.create_indexes([
            {"key": [("user_id", ASCENDING), ("date", ASCENDING)], "name": "user_id_date_1", "unique": True},
        ])
    except Exception:
        logging.exception("create_index_usage")
    try:
        settings.create_indexes([
            {"key": [("key", ASCENDING)], "name": "key_1", "unique": True},
        ])
    except Exception:
        logging.exception("create_index_settings")
    try:
        orders.create_indexes([
            {"key": [("user_id", ASCENDING), ("created_at", ASCENDING)], "name": "user_id_created_at_1"},
        ])
    except Exception:
        logging.exception("create_index_orders")

safe_create_indexes()

app = Flask(__name__, template_folder=".")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "sk_live_dX9hK2#vT3qZm!2Lw7FeXp9@RuYpG4o%BnMfVjA6HsE")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(int(os.environ.get("SESSION_COOKIE_SECURE", "0")))
app.config["SESSION_COOKIE_NAME"] = "rb_session"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=15)
app.config["users"] = users
app.config["transactions"] = transactions
app.config["usage"] = usage
app.config["settings"] = settings
app.config["orders"] = orders
app.register_blueprint(admin_bp)

USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{3,32}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
CPF_RE = re.compile(r"^\d{11}$")

TRIBOPAY_TOKEN = os.environ.get("TRIBOPAY_API_TOKEN", "UcsGgIwEkBW5FrLbjtJbVkSda7fOrSk2paZ8sIYqYwKBEpORYWSiupTG58n4")
TRIBOPAY_API = "https://api.tribopay.com.br/api/public/v1/transactions"
TRIBO_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}

PLANS_DEFAULT = {
    "Essencial": {"amount_cents": 3500, "product_hash": "tiz24o81ww", "offer_hash": "cz664sul2g", "title": "Plano Essencial", "active": True},
    "Profissional": {"amount_cents": 4550, "product_hash": "tiz24o81ww", "offer_hash": "cz664sul2g", "title": "Plano Profissional", "active": True},
    "Vitalício": {"amount_cents": 11900, "product_hash": "tiz24o81ww", "offer_hash": "cz664sul2g", "title": "Plano Vitalício", "active": True},
}

PLAN_CODES = {"Essencial": "essencial", "Profissional": "profissional", "Vitalício": "vitalicio"}
PLAN_LIMITS = {"padrao": 0, "essencial": 5, "profissional": 15, "vitalicio": 25}
PAID_STATUSES = {"paid", "approved", "completed", "confirmed", "paid_out", "finished", "success", "settled", "captured", "accredited", "credited", "confirmed_payment"}
FAILED_STATUSES = {"canceled", "cancelled", "refunded", "chargeback", "reversed", "voided", "failed", "expired", "denied"}
USER_SCHEMA_VERSION = 1

FAKER = Faker("pt_BR")

http_session = requests.Session()
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET", "POST"])
adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=100)
http_session.mount("https://", adapter)
http_session.mount("http://", adapter)

WORKER_THREADS = int(os.environ.get("WORKER_THREADS", "8"))
executor = ThreadPoolExecutor(max_workers=WORKER_THREADS)
monitored_hashes_lock = threading.Lock()
monitored_hashes = set()
sse_queues_lock = threading.Lock()
sse_queues: Dict[str, queue.Queue] = {}

def is_logged_in():
    return "user_id" in session

def login_required(fn):
    @wraps(fn)
    def _wrap(*args, **kwargs):
        if not is_logged_in():
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="unauthorized"), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return _wrap

def brl_from_cents(c):
    d = (Decimal(int(c)) / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"R$ {str(d).replace('.', ',')}"

def generate_qr_base64(emv):
    img = qrcode.make(emv)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def _normalize_text(s):
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", str(s))
    s = s.encode("ascii", "ignore").decode("ascii")
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s.-]", "", s)
    s = re.sub(r"\s+", ".", s)
    s = re.sub(r"\.+", ".", s).strip(".")
    return s

def generate_coherent_gmail(user_name=None):
    if user_name and user_name.strip():
        first = str(user_name).strip().split()[0]
    else:
        first = FAKER.first_name()
    last = FAKER.last_name()
    local = f"{_normalize_text(first)}.{_normalize_text(last)}"
    if not re.search(r"[a-z0-9]", local):
        local = secrets.token_hex(6)
    if len(local) > 60:
        local = local[:60]
    suffix = str(secrets.randbelow(9999))
    local = f"{local}{suffix}"
    return f"{local}@gmail.com"

def get_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        u = users.find_one({"_id": ObjectId(uid)})
        return u
    except Exception:
        app.logger.exception("get_user_error")
        return None

def normalize_plan(user_doc):
    code = (user_doc or {}).get("plans") or "padrao"
    exp = (user_doc or {}).get("plan_expires_at")
    now = datetime.utcnow()
    if code in ("essencial", "profissional") and exp and now > exp:
        try:
            users.update_one({"_id": user_doc["_id"]}, {"$set": {"plans": "padrao", "plan_started_at": None, "plan_expires_at": None}})
        except Exception:
            app.logger.exception("normalize_plan_db_update")
        code = "padrao"
        exp = None
    return code, exp

def plan_meta(code):
    return PLAN_LIMITS.get(code, 0)

def date_key_utc(dt=None):
    dt = dt or datetime.utcnow()
    return dt.strftime("%Y-%m-%d")

def get_plans():
    try:
        doc = settings.find_one({"key": "plans"}) or {}
        custom = doc.get("value") or {}
    except Exception:
        app.logger.exception("get_plans_db")
        custom = {}
    out = {}
    for k, v in PLANS_DEFAULT.items():
        c = dict(v)
        if k in custom:
            if isinstance(custom[k].get("amount_cents"), int):
                c["amount_cents"] = int(custom[k]["amount_cents"])
            if isinstance(custom[k].get("active"), bool):
                c["active"] = custom[k]["active"]
        out[k] = c
    return out

def save_plans(payload):
    base = get_plans()
    for k, cfg in (payload or {}).items():
        if k in base:
            if "amount_cents" in cfg:
                base[k]["amount_cents"] = int(cfg["amount_cents"])
            if "active" in cfg:
                base[k]["active"] = bool(cfg["active"])
    try:
        settings.update_one({"key": "plans"}, {"$set": {"key": "plans", "value": base, "updated_at": datetime.utcnow()}}, upsert=True)
    except Exception:
        app.logger.exception("save_plans_db")
    return base

def tribopay_fetch_status(tx_hash) -> (Optional[str], Optional[Dict[str, Any]]):
    try:
        r = http_session.get(f"{TRIBOPAY_API}/{tx_hash}?api_token={TRIBOPAY_TOKEN}", headers=TRIBO_HEADERS, timeout=15)
        r.raise_for_status()
        resp = r.json()
    except Exception:
        app.logger.exception("tribopay_fetch_status_error")
        return None, None
    obj = resp.get("data") if isinstance(resp, dict) else None
    if not obj and isinstance(resp, dict):
        obj = resp
    status = None
    if isinstance(obj, dict):
        status = obj.get("status") or obj.get("status_payment") or obj.get("payment_status")
    return (status.lower() if isinstance(status, str) else None), obj

def plan_name_to_code(plan_name):
    if not plan_name:
        return None
    s = unicodedata.normalize("NFKD", str(plan_name))
    s = s.encode("ascii", "ignore").decode("ascii").lower()
    s = re.sub(r"[^a-z0-9]+", "", s)
    for k, v in PLAN_CODES.items():
        nk = unicodedata.normalize("NFKD", str(k)).encode("ascii", "ignore").decode("ascii").lower()
        nk = re.sub(r"[^a-z0-9]+", "", nk)
        if s == nk:
            return v
    if plan_name in PLAN_CODES.values():
        return plan_name
    return None

def try_activation_by_hash(tx_hash):
    attempts = 0
    max_attempts = 3
    while attempts < max_attempts:
        try:
            tx = transactions.find_one({"hash": tx_hash})
            if not tx:
                app.logger.error(f"Transação {tx_hash} não encontrada para ativação")
                return False
            st = (tx.get("payment_status") or "").lower()
            app.logger.info(f"Tentativa {attempts+1} de ativação para {tx_hash}, status: {st}")
            if st not in PAID_STATUSES:
                app.logger.warning(f"Status {st} não é pago para transação {tx_hash}")
                return False
            if tx.get("activated_at"):
                app.logger.info(f"Transação {tx_hash} já ativada anteriormente")
                return True
            result = transactions.update_one(
                {
                    "_id": tx["_id"],
                    "activated_at": {"$exists": False},
                    "payment_status": {"$in": list(PAID_STATUSES)}
                },
                {
                    "$set": {
                        "activated_at": datetime.utcnow(),
                        "last_activation_attempt": datetime.utcnow()
                    }
                }
            )
            if result.modified_count > 0:
                app.logger.info(f"Ativação BEM-SUCEDIDA para transação {tx_hash}")
                uid = tx.get("user_id")
                plan_name = tx.get("plan")
                code = plan_name_to_code(plan_name) if plan_name else None
                app.logger.info(f"Ativando usuário {uid} com plano {plan_name} → código: {code}")
                if not uid or not code:
                    app.logger.error(f"Dados insuficientes para ativação: uid={uid}, code={code}")
                    return False
                exp = None
                if code in ("essencial", "profissional"):
                    exp = datetime.utcnow() + timedelta(days=30)
                try:
                    try:
                        oid = ObjectId(uid)
                        users.update_one({"_id": oid}, {"$set": {"plans": code, "plan_started_at": datetime.utcnow(), "plan_expires_at": exp}})
                    except Exception:
                        users.update_one({"_id": uid}, {"$set": {"plans": code, "plan_started_at": datetime.utcnow(), "plan_expires_at": exp}})
                except Exception as e:
                    app.logger.error(f"Erro ao ativar usuário {uid}: {str(e)}")
                    return False
                app.logger.info(f"Usuário {uid} ativado com plano {code}")
                return True
            else:
                app.logger.warning(f"Ativação não modificou transação {tx_hash} - possível race condition")
                attempts += 1
                time.sleep(1)
        except Exception as e:
            app.logger.error(f"Erro na tentativa {attempts+1} de ativação para {tx_hash}: {str(e)}")
            attempts += 1
            time.sleep(2)
    app.logger.error(f"Todas as tentativas de ativação falharam para {tx_hash}")
    return False

def try_activation(tx):
    st = (tx.get("payment_status") or "").lower()
    if st not in PAID_STATUSES:
        return
    try:
        res = transactions.update_one({"_id": tx["_id"], "activated_at": {"$exists": False}}, {"$set": {"activated_at": datetime.utcnow()}})
    except Exception:
        app.logger.exception("try_activation_update")
        return
    if not getattr(res, "modified_count", 0):
        return
    uid = tx.get("user_id")
    plan_name = tx.get("plan")
    code = plan_name_to_code(plan_name) if plan_name else None
    if not code and isinstance(plan_name, str):
        pn = plan_name.strip().lower()
        if pn in PLAN_CODES.values():
            code = pn
    if not uid or not code:
        return
    exp = None
    if code in ("essencial", "profissional"):
        exp = datetime.utcnow() + timedelta(days=30)
    try:
        try:
            oid = ObjectId(uid)
            users.update_one({"_id": oid}, {"$set": {"plans": code, "plan_started_at": datetime.utcnow(), "plan_expires_at": exp}})
        except Exception:
            users.update_one({"_id": uid}, {"$set": {"plans": code, "plan_started_at": datetime.utcnow(), "plan_expires_at": exp}})
    except Exception:
        app.logger.exception("try_activation_user_update")

def apply_user_migrations(user_doc):
    if not user_doc:
        return None
    set_fields = {}
    now = datetime.utcnow()
    lower = (user_doc.get("username") or "").lower()
    if user_doc.get("username_lower") != lower:
        set_fields["username_lower"] = lower
    if "plans" not in user_doc:
        set_fields["plans"] = "padrao"
    if "plan_started_at" not in user_doc:
        set_fields["plan_started_at"] = None
    if "plan_expires_at" not in user_doc:
        set_fields["plan_expires_at"] = None
    if "admin_permission" not in user_doc:
        set_fields["admin_permission"] = "no"
    if "disabled" not in user_doc:
        set_fields["disabled"] = False
    if "created_at" not in user_doc or not isinstance(user_doc.get("created_at"), datetime):
        set_fields["created_at"] = now
    if "last_login_at" not in user_doc:
        set_fields["last_login_at"] = None
    current_version = int(user_doc.get("schema_version", 0)) if isinstance(user_doc.get("schema_version", 0), int) else 0
    if current_version < USER_SCHEMA_VERSION:
        set_fields["schema_version"] = USER_SCHEMA_VERSION
    if set_fields:
        try:
            users.update_one({"_id": user_doc["_id"]}, {"$set": set_fields})
            return users.find_one({"_id": user_doc["_id"]})
        except Exception:
            app.logger.exception("apply_user_migrations_db")
            return user_doc
    return user_doc

def publish_event(user_id: Optional[str], event: Dict[str, Any]):
    if not user_id:
        return
    key = user_id
    with sse_queues_lock:
        q = sse_queues.get(key)
    if q:
        try:
            q.put_nowait(event)
        except Exception:
            pass

def monitor_transaction_worker(tx_hash):
    with monitored_hashes_lock:
        if tx_hash in monitored_hashes:
            return
        monitored_hashes.add(tx_hash)
    try:
        backoff = [1, 2, 4, 8, 16, 30, 45, 60]
        max_attempts = 96
        attempt = 0
        last_status = None
        activation_attempted = False
        while attempt < max_attempts:
            st, payload = tribopay_fetch_status(tx_hash)
            current_status = st if st else "unknown"
            app.logger.info(f"Transação {tx_hash} - Status: {current_status} (tentativa {attempt + 1})")
            if st:
                now = datetime.utcnow()
                try:
                    transactions.update_one(
                        {"hash": tx_hash}, 
                        {
                            "$set": {
                                "payment_status": st, 
                                "updated_at": now, 
                                "raw_last": payload,
                                "last_status_check": now
                            }
                        }
                    )
                except Exception:
                    app.logger.exception("monitor_transaction_db_update")
                if st in PAID_STATUSES and not activation_attempted:
                    app.logger.info(f"Status PAGO detectado para {tx_hash}, tentando ativação...")
                    activation_success = try_activation_by_hash(tx_hash)
                    if activation_success:
                        app.logger.info(f"Ativação CONCLUÍDA com sucesso para {tx_hash}")
                        activation_attempted = True
                        break
                    else:
                        app.logger.warning(f"Ativação FALHOU para {tx_hash}, continuando monitoramento...")
                        activation_attempted = True
                elif st in FAILED_STATUSES:
                    app.logger.info(f"Status FALHA detectado para {tx_hash}, parando monitoramento")
                    try:
                        transactions.update_one({"hash": tx_hash}, {"$set": {"failed_at": now}})
                        tx = transactions.find_one({"hash": tx_hash})
                        if tx:
                            publish_event(tx.get("user_id"), {"type": "tx_update", "hash": tx_hash, "status": st, "timestamp": now.isoformat()})
                    except Exception:
                        app.logger.exception("monitor_failed_publish")
                    break
                elif last_status != st:
                    app.logger.info(f"Mudança de status: {last_status} → {st} para {tx_hash}")
                    last_status = st
                    try:
                        tx = transactions.find_one({"hash": tx_hash})
                        if tx:
                            publish_event(tx.get("user_id"), {"type": "tx_update", "hash": tx_hash, "status": st, "timestamp": now.isoformat()})
                    except Exception:
                        app.logger.exception("monitor_status_change_publish")
            else:
                app.logger.warning(f"Status vazio/nulo para transação {tx_hash}")
            sleep_interval = backoff[min(attempt, len(backoff) - 1)]
            if st in ["pending", "processing", "under_review", "analyzing"]:
                sleep_interval = min(sleep_interval * 2, 300)
                app.logger.info(f"Status de revisão detectado, aumentando intervalo para {sleep_interval}s")
            time.sleep(sleep_interval)
            attempt += 1
        app.logger.info(f"FINALIZANDO monitoramento para transação {tx_hash} após {attempt} tentativas")
    except Exception as e:
        app.logger.error(f"ERRO CRÍTICO no monitoramento de {tx_hash}: {str(e)}")
    finally:
        with monitored_hashes_lock:
            monitored_hashes.discard(tx_hash)

def ensure_monitoring_started(tx_hash):
    with monitored_hashes_lock:
        if tx_hash in monitored_hashes:
            return False
        monitored_hashes.add(tx_hash)
    try:
        executor.submit(monitor_transaction_worker, tx_hash)
        return True
    except Exception:
        with monitored_hashes_lock:
            monitored_hashes.discard(tx_hash)
        app.logger.exception("ensure_monitoring_started_submit")
        return False

def cpf_is_valid(cpf):
    s = re.sub(r"\D+", "", str(cpf or ""))
    if len(s) != 11:
        return False
    if s == s[0] * 11:
        return False
    sm = 0
    for i in range(9):
        sm += int(s[i]) * (10 - i)
    dv1 = (sm * 10) % 11
    if dv1 == 10:
        dv1 = 0
    if dv1 != int(s[9]):
        return False
    sm = 0
    for i in range(10):
        sm += int(s[i]) * (11 - i)
    dv2 = (sm * 10) % 11
    if dv2 == 10:
        dv2 = 0
    return dv2 == int(s[10])

def name_is_valid(name):
    parts = re.split(r"\s+", str(name or "").strip())
    parts = [p for p in parts if len(p) >= 2]
    return len(parts) >= 2

def wants_json():
    a = str(request.headers.get("Accept", "")).lower()
    x = str(request.headers.get("X-Requested-With", "")).lower()
    ct = str(request.headers.get("Content-Type", "")).lower()
    return request.is_json or "application/json" in a or x in ("xmlhttprequest", "fetch") or "application/json" in ct

@app.before_request
def redirect_auth_pages_when_logged():
    if request.method == "GET" and is_logged_in() and request.endpoint in ("login", "register"):
        return redirect(url_for("dashboard"))
    if is_logged_in():
        u = get_user()
        if u:
            u = apply_user_migrations(u)
        if not u or u.get("disabled") is True:
            session.clear()
            return redirect(url_for("login"))
        issued = session.get("issued_at")
        flo = u.get("force_logout_at")
        if issued and flo and isinstance(flo, datetime):
            try:
                if float(issued) < float(flo.timestamp()):
                    session.clear()
                    return redirect(url_for("login"))
            except Exception:
                pass

@app.errorhandler(Exception)
def handle_exceptions(e):
    if isinstance(e, HTTPException):
        try:
            return jsonify(ok=False, error=e.description), e.code
        except Exception:
            return jsonify(ok=False, error="http_error"), e.code
    app.logger.exception("unhandled_exception")
    return jsonify(ok=False, error="internal_error"), 500

@app.route("/")
def landing_page():
    return render_template("landing_page.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    try:
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        remember = str(data.get("remember", "")).lower() in ("1", "true", "on", "yes")
        if not USERNAME_RE.match(username) or len(password) < 8:
            return jsonify(ok=False, error="Credenciais inválidas"), 400
        user = users.find_one({"$or": [{"username": username}, {"username_lower": username.lower()}]})
        if not user or not check_password_hash(user.get("password_hash", ""), password):
            return jsonify(ok=False, error="Usuário ou senha incorretos"), 401
        if user.get("disabled") is True:
            return jsonify(ok=False, error="Conta desativada"), 403
        user = apply_user_migrations(user)
        session.clear()
        session["user_id"] = str(user["_id"])
        session["username"] = user["username"]
        session["issued_at"] = float(datetime.utcnow().timestamp())
        session.permanent = bool(remember)
        try:
            users.update_one({"_id": user["_id"]}, {"$set": {"last_login_at": datetime.utcnow()}})
        except Exception:
            app.logger.exception("login_update_last_login")
        return jsonify(ok=True, redirect=url_for("dashboard"))
    except Exception:
        app.logger.exception("login_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("cadastro.html")
    try:
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        confirm = data.get("confirm") or ""
        if not USERNAME_RE.match(username):
            return jsonify(ok=False, field="username", error="Nome de usuário inválido"), 400
        if not EMAIL_RE.match(email):
            return jsonify(ok=False, field="email", error="E-mail inválido"), 400
        if len(password) < 8:
            return jsonify(ok=False, field="password", error="Senha muito curta"), 400
        if confirm != password:
            return jsonify(ok=False, field="confirm", error="As senhas não coincidem"), 400
        if users.find_one({"$or": [{"username_lower": username.lower()}, {"email": email}]}):
            return jsonify(ok=False, error="Usuário ou e-mail já cadastrado"), 409
        password_hash = generate_password_hash(password)
        try:
            ins = users.insert_one({"username": username, "username_lower": username.lower(), "email": email, "password_hash": password_hash, "created_at": datetime.utcnow(), "last_login_at": None, "plans": "padrao", "plan_started_at": None, "plan_expires_at": None, "admin_permission": "no", "disabled": False, "schema_version": USER_SCHEMA_VERSION})
        except errors.DuplicateKeyError:
            return jsonify(ok=False, error="Usuário ou e-mail já cadastrado"), 409
        except Exception:
            app.logger.exception("register_insert_error")
            return jsonify(ok=False, error="internal_error"), 500
        session.clear()
        session["user_id"] = str(ins.inserted_id)
        session["username"] = username
        session["issued_at"] = float(datetime.utcnow().timestamp())
        session.permanent = False
        return jsonify(ok=True, redirect=url_for("dashboard")), 201
    except Exception:
        app.logger.exception("register_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/dashboard")
@login_required
def dashboard():
    try:
        u = get_user()
        if u:
            u = apply_user_migrations(u)
            normalize_plan(u)
        return render_template("dashboard.html", username=session.get("username"))
    except Exception:
        app.logger.exception("dashboard_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/logout", methods=["POST", "GET"])
def logout():
    try:
        session.clear()
        return redirect(url_for("login"))
    except Exception:
        app.logger.exception("logout_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/plans", methods=["GET"])
@login_required
def plans():
    try:
        u = get_user()
        if u:
            apply_user_migrations(u)
        return render_template("planos.html", username=session.get("username"), plans=get_plans())
    except Exception:
        app.logger.exception("plans_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/pixPayment", methods=["GET", "POST"])
@login_required
def pix_payment():
    if request.method == "GET":
        try:
            h = request.args.get("hash") or ""
            if not h:
                return redirect(url_for("plans"))
            tx = transactions.find_one({"hash": h, "user_id": session.get("user_id")})
            if not tx:
                return redirect(url_for("plans"))
            qr_b64 = tx.get("qr_code_base64") or (generate_qr_base64(tx.get("pix_qr_code")) if tx.get("pix_qr_code") else None)
            if qr_b64 and not tx.get("qr_code_base64"):
                try:
                    transactions.update_one({"_id": tx["_id"]}, {"$set": {"qr_code_base64": qr_b64}})
                except Exception:
                    app.logger.exception("pix_payment_update_qr_b64")
            return render_template("checkout.html", username=session.get("username"), plan=tx.get("plan"), amount_brl=brl_from_cents(tx.get("amount_cents", 0)), status=tx.get("payment_status", "waiting_payment"), hash=tx.get("hash"), pix_url=tx.get("pix_url"), emv=tx.get("pix_qr_code"), qr_b64=qr_b64)
        except Exception:
            app.logger.exception("pix_payment_get_error")
            return redirect(url_for("plans"))
    try:
        data = request.get_json(silent=True) or request.form
        plan = (data.get("plan") or "").strip()
        plans_cfg = get_plans()
        if plan not in plans_cfg:
            msg = "Plano inválido"
            if wants_json():
                return jsonify(ok=False, code="invalid_plan", message=msg), 400
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 400
        p = plans_cfg[plan]
        if not p.get("active", True):
            msg = "Plano indisponível"
            if wants_json():
                return jsonify(ok=False, code="plan_unavailable", message=msg), 400
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 400
        uid = session.get("user_id")
        user_doc = None
        if uid:
            try:
                user_doc = users.find_one({"_id": ObjectId(uid)})
            except Exception:
                user_doc = None
        if not user_doc and session.get("username"):
            try:
                user_doc = users.find_one({"username_lower": session.get("username", "").lower()})
            except Exception:
                user_doc = None
        if user_doc:
            apply_user_migrations(user_doc)
        name = (data.get("name") or "").strip()
        cpf_raw = data.get("cpf") or ""
        cpf = re.sub(r"\D+", "", cpf_raw)
        if not name:
            name = "DFINTEL GATEWAY LTDA"
        if not cpf:
            cpf = "09115751031"
        if data.get("name") and not name_is_valid(name):
            msg = "Nome informado inválido"
            if wants_json():
                return jsonify(ok=False, code="invalid_document", message=msg), 422
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 422
        if data.get("cpf") and not cpf_is_valid(cpf):
            msg = "CPF informado inválido"
            if wants_json():
                return jsonify(ok=False, code="invalid_document", message=msg), 422
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 422
        random_email = generate_coherent_gmail(name)
        try:
            postback_url = url_for("tribopay_webhook", _external=True)
        except Exception:
            postback_url = url_for("tribopay_webhook")
        payload = {
            "amount": p["amount_cents"],
            "offer_hash": p["offer_hash"],
            "payment_method": "pix",
            "installments": 1,
            "customer": {
                "name": name,
                "email": random_email,
                "phone_number": "21999999999",
                "document": cpf,
                "street_name": "Rua das Flores",
                "number": "123",
                "complement": "Apt 45",
                "neighborhood": "Centro",
                "city": "Rio de Janeiro",
                "state": "RJ",
                "zip_code": "20040020",
            },
            "cart": [
                {
                    "product_hash": p["product_hash"],
                    "title": p["title"],
                    "cover": None,
                    "price": p["amount_cents"],
                    "quantity": 1,
                    "operation_type": 1,
                    "tangible": False,
                }
            ],
            "expire_in_days": 1,
            "transaction_origin": "api",
            "tracking": {
                "src": "",
                "utm_source": "google",
                "utm_medium": "cpc",
                "utm_campaign": "curso-programacao",
                "utm_term": "",
                "utm_content": "",
            },
            "postback_url": postback_url,
        }
        try:
            r = http_session.post(f"{TRIBOPAY_API}?api_token={TRIBOPAY_TOKEN}", headers=TRIBO_HEADERS, json=payload, timeout=30)
            r.raise_for_status()
            data = r.json()
        except requests.HTTPError as e:
            status_code = 502
            body = None
            try:
                body = e.response.json()
            except Exception:
                try:
                    body = {"error": e.response.text if e.response is not None else str(e)}
                except Exception:
                    body = {"error": str(e)}
            text = json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body
            lower = str(text or "").lower()
            if e.response is not None and e.response.status_code in (400, 401, 403, 422):
                msg = "Por favor, informe seu nome completo e um CPF válido que corresponda ao banco de origem do pagamento."
                if "document" in lower or "cpf" in lower or "customer" in lower:
                    if wants_json():
                        return jsonify(ok=False, code="invalid_document", message=msg, details=body), 422
                    return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 422
                msg = "Não foi possível gerar a cobrança Pix. Tente novamente em instantes."
                if wants_json():
                    return jsonify(ok=False, code="gateway_error", message=msg, details=body), 502
                return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 502
            msg = "Não foi possível gerar a cobrança Pix. Tente novamente em instantes."
            if wants_json():
                return jsonify(ok=False, code="gateway_error", message=msg, details=body), status_code
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), status_code
        except Exception:
            app.logger.exception("pix_create_error")
            msg = "Não foi possível gerar a cobrança Pix. Tente novamente em instantes."
            if wants_json():
                return jsonify(ok=False, code="gateway_error", message=msg), 502
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 502
        resp = data if isinstance(data, dict) else {}
        d = resp.get("data") if isinstance(resp.get("data", None), dict) else resp
        pix = d.get("pix") or {}
        pix_url = pix.get("pix_url") or d.get("pix_url")
        emv = pix.get("pix_qr_code") or pix.get("copy_and_paste") or pix.get("emv") or d.get("pix_qr_code") or d.get("copy_and_paste") or d.get("emv")
        h = d.get("hash") or pix.get("hash") or d.get("transaction_hash") or d.get("id_hash") or ""
        raw_status = d.get("payment_status") or d.get("status") or d.get("status_payment")
        if isinstance(raw_status, str):
            status = raw_status.lower()
        elif isinstance(raw_status, bool):
            status = "paid" if raw_status else "waiting_payment"
        elif isinstance(raw_status, (int, float)):
            status = "waiting_payment"
        elif isinstance(raw_status, dict):
            code = raw_status.get("code")
            status = code.lower() if isinstance(code, str) else "waiting_payment"
        else:
            status = "waiting_payment"
        if not h:
            msg = "Não foi possível gerar a cobrança Pix. Tente novamente em instantes."
            if wants_json():
                return jsonify(ok=False, code="gateway_error", message=msg, details={"reason": "missing_hash"}), 502
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 502
        if not emv:
            msg = "Não foi possível gerar a cobrança Pix. Tente novamente em instantes."
            if wants_json():
                return jsonify(ok=False, code="gateway_error", message=msg), 502
            return render_template("planos.html", username=session.get("username"), plans=plans_cfg, error_message=msg), 502
        qr_b64 = generate_qr_base64(emv)
        tx_doc = {
            "user_id": session.get("user_id"),
            "username": session.get("username"),
            "plan": plan,
            "amount_cents": p["amount_cents"],
            "tribopay_id": d.get("id") or resp.get("id"),
            "hash": h,
            "payment_status": status,
            "pix_url": pix_url,
            "pix_qr_code": emv,
            "qr_code_base64": qr_b64,
            "customer_email": random_email,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        try:
            transactions.update_one({"hash": h}, {"$set": tx_doc}, upsert=True)
        except Exception:
            app.logger.exception("pix_payment_tx_upsert")
        try:
            res = transactions.update_one({"hash": h, "monitoring": {"$ne": True}}, {"$set": {"monitoring": True}})
        except Exception:
            res = None
            app.logger.exception("pix_payment_monitor_flag")
        started = False
        try:
            started = ensure_monitoring_started(h)
        except Exception:
            app.logger.exception("pix_payment_ensure_monitor")
        if wants_json():
            return jsonify(ok=True, redirect=url_for("pix_payment", hash=h))
        return render_template("checkout.html", username=session.get("username"), plan=plan, amount_brl=brl_from_cents(p["amount_cents"]), status=status, hash=h, pix_url=pix_url, emv=emv, qr_b64=qr_b64)
    except Exception:
        app.logger.exception("pix_payment_error")
        if wants_json():
            return jsonify(ok=False, code="internal_error", message="Erro interno"), 500
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/pix/status", methods=["GET"])
@login_required
def pix_status():
    try:
        h = request.args.get("hash") or ""
        if not h:
            return jsonify(ok=False, error="Hash ausente"), 400
        st, payload = tribopay_fetch_status(h)
        if st:
            now = datetime.utcnow()
            try:
                transactions.update_one({"hash": h, "user_id": session.get("user_id")}, {"$set": {"payment_status": st, "updated_at": now, "raw_last": payload}})
            except Exception:
                app.logger.exception("pix_status_db_update")
            if st in PAID_STATUSES:
                tx = transactions.find_one({"hash": h, "user_id": session.get("user_id")})
                if tx:
                    try_activation(tx)
            if st in FAILED_STATUSES:
                try:
                    transactions.update_one({"hash": h, "user_id": session.get("user_id")}, {"$set": {"failed_at": now}})
                except Exception:
                    app.logger.exception("pix_status_failed_update")
        tx = transactions.find_one({"hash": h, "user_id": session.get("user_id")})
        if not tx:
            return jsonify(ok=False, error="Transação não encontrada"), 404
        return jsonify(ok=True, status=tx.get("payment_status"), hash=h)
    except Exception:
        app.logger.exception("pix_status_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/webhook/tribopay", methods=["POST"])
def tribopay_webhook():
    try:
        app.logger.info("WEBHOOK TriboPay recebido")
        data = request.get_json(force=True, silent=False)
        app.logger.info(f"Dados do webhook: {json.dumps(data, indent=2)}")
    except Exception:
        return jsonify(ok=False), 400
    try:
        if not isinstance(data, dict):
            return jsonify(ok=False), 400
        h = data.get("hash") or ""
        if not h:
            pix = data.get("pix") or {}
            h = pix.get("hash") or ""
        if not h:
            h = data.get("transaction_hash") or data.get("id_hash") or ""
        if not h:
            app.logger.error("Hash não encontrado nos dados do webhook")
            return jsonify(ok=False, error="missing_hash"), 400
        app.logger.info(f"Processando webhook para hash: {h}")
        current_status = data.get("status") or data.get("payment_status") or ""
        app.logger.info(f"Status no webhook: {current_status}")
        if current_status and current_status.lower() in PAID_STATUSES:
            app.logger.info(f"Webhook com status PAGO, tentando ativação imediata para {h}")
            activation_success = try_activation_by_hash(h)
            if activation_success:
                app.logger.info(f"Ativação VIA WEBHOOK bem-sucedida para {h}")
            else:
                app.logger.warning(f"Ativação via webhook FALHOU para {h}, iniciando monitoramento")
        try:
            transactions.update_one(
                {"hash": h}, 
                {
                    "$set": {
                        "monitoring": True,
                        "last_webhook": datetime.utcnow(),
                        "webhook_data": data
                    }
                }
            )
        except Exception as db_error:
            app.logger.error(f"Erro ao atualizar transação {h}: {str(db_error)}")
        ensure_monitoring_started(h)
        app.logger.info(f"Webhook processado com sucesso para {h}")
        return jsonify(ok=True, hash=h, activation_attempted=True)
    except Exception:
        app.logger.exception("webhook_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/api/plan/status", methods=["GET"])
@login_required
def api_plan_status():
    try:
        u = get_user()
        if not u:
            return jsonify(ok=False), 401
        u = apply_user_migrations(u)
        code, exp = normalize_plan(u)
        limit = plan_meta(code)
        today = date_key_utc()
        used = 0
        if limit and limit != None:
            try:
                rec = usage.find_one({"user_id": str(u["_id"]), "date": today})
                used = rec.get("used", 0) if rec else 0
            except Exception:
                app.logger.exception("api_plan_status_usage_find")
                used = 0
        remaining = None if limit is None else max(0, int(limit) - int(used))
        return jsonify(ok=True, plan=code, expires_at=(exp.isoformat() if exp else None), daily_limit=limit, used_today=used if limit and limit != None else 0, remaining_today=remaining)
    except Exception:
        app.logger.exception("plan_status_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/api/usage/consume", methods=["POST"])
@login_required
def api_usage_consume():
    try:
        u = get_user()
        if not u:
            return jsonify(ok=False), 401
        u = apply_user_migrations(u)
        code, exp = normalize_plan(u)
        if code == "padrao":
            return jsonify(ok=False, error="Plano insuficiente"), 403
        limit = plan_meta(code)
        if limit is None:
            return jsonify(ok=True, remaining_today=None)
        try:
            data = request.get_json(silent=True) or request.form
            count = int(str(data.get("count", "0")))
        except Exception:
            return jsonify(ok=False, error="Parâmetro inválido"), 400
        if count <= 0:
            return jsonify(ok=False, error="Parâmetro inválido"), 400
        today = date_key_utc()
        base = {"user_id": str(u["_id"]), "date": today}
        guard = {"$expr": {"$lte": [{"$add": [{"$ifNull": ["$used", 0]}, count]}, int(limit)]}}
        try:
            res = usage.update_one({**base, **guard}, {"$inc": {"used": count}}, upsert=False)
            if getattr(res, "matched_count", 0) == 1:
                rec = usage.find_one(base) or {"used": 0}
                remaining = max(0, int(limit) - int(rec.get("used", 0)))
                return jsonify(ok=True, remaining_today=remaining)
            try:
                usage.insert_one({**base, "used": count})
                remaining = max(0, int(limit) - count)
                return jsonify(ok=True, remaining_today=remaining)
            except errors.DuplicateKeyError:
                res2 = usage.update_one({**base, **guard}, {"$inc": {"used": count}}, upsert=False)
                if getattr(res2, "matched_count", 0) == 1:
                    rec = usage.find_one(base) or {"used": 0}
                    remaining = max(0, int(limit) - int(rec.get("used", 0)))
                    return jsonify(ok=True, remaining_today=remaining)
        except Exception:
            app.logger.exception("usage_consume_db")
        rec = usage.find_one(base) or {"used": 0}
        used_now = int(rec.get("used", 0))
        return jsonify(ok=False, error="Limite diário excedido", remaining=max(0, int(limit) - used_now)), 400
    except Exception:
        app.logger.exception("usage_consume_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/api/orders/create", methods=["POST"])
@login_required
def api_orders_create():
    try:
        u = get_user()
        if not u:
            return jsonify(ok=False, error="unauthorized"), 401
        u = apply_user_migrations(u)
        code, exp = normalize_plan(u)
        if code == "padrao":
            return jsonify(ok=False, error="Plano insuficiente"), 403
        data = request.get_json(silent=True) or request.form
        platform = str(data.get("platform", "")).strip().lower()
        url = str(data.get("url", "")).strip()
        try:
            reports = int(str(data.get("reports", "0")))
        except Exception:
            return jsonify(ok=False, error="Parâmetro inválido"), 400
        try:
            proxies = int(str(data.get("proxies", "0")))
        except Exception:
            return jsonify(ok=False, error="Parâmetro inválido"), 400
        if platform not in ("instagram", "facebook", "tiktok", "whatsapp", "twitter", "youtube"):
            return jsonify(ok=False, error="Plataforma inválida"), 400
        if not url:
            return jsonify(ok=False, error="URL inválida"), 400
        if proxies < 0 or proxies > 1065:
            return jsonify(ok=False, error="Quantidade de proxies inválida"), 400
        ranges = {"essencial": (100, 500), "profissional": (100, 5000), "vitalicio": (100, 15950)}
        if code not in ranges:
            return jsonify(ok=False, error="Plano insuficiente"), 403
        rmin, rmax = ranges[code]
        if reports < rmin or reports > rmax:
            return jsonify(ok=False, error=f"Quantidade permitida para o seu plano: {rmin}-{rmax}"), 400
        limit = plan_meta(code)
        if limit is not None:
            today = date_key_utc()
            base = {"user_id": str(u["_id"]), "date": today}
            guard = {"$expr": {"$lte": [{"$add": [{"$ifNull": ["$used", 0]}, 1]}, int(limit)]}}
            try:
                res = usage.update_one({**base, **guard}, {"$inc": {"used": 1}}, upsert=False)
                if getattr(res, "matched_count", 0) != 1:
                    try:
                        usage.insert_one({**base, "used": 1})
                        remaining = max(0, int(limit) - 1)
                    except errors.DuplicateKeyError:
                        res2 = usage.update_one({**base, **guard}, {"$inc": {"used": 1}}, upsert=False)
                        if getattr(res2, "matched_count", 0) != 1:
                            rec = usage.find_one(base) or {"used": 0}
                            used_now = int(rec.get("used", 0))
                            return jsonify(ok=False, error="Limite diário excedido", remaining=max(0, int(limit) - used_now)), 400
                        rec = usage.find_one(base) or {"used": 0}
                        remaining = max(0, int(limit) - int(rec.get("used", 0)))
                else:
                    rec = usage.find_one(base) or {"used": 0}
                    remaining = max(0, int(limit) - int(rec.get("used", 0)))
            except Exception:
                app.logger.exception("orders_create_usage_db")
                return jsonify(ok=False, error="internal_error"), 500
        else:
            remaining = None
        doc = {
            "user_id": str(u["_id"]),
            "username": u.get("username"),
            "platform": platform,
            "url": url,
            "reports": int(reports),
            "proxies": int(proxies),
            "created_at": datetime.utcnow(),
        }
        try:
            ins = orders.insert_one(doc)
        except Exception:
            app.logger.exception("orders_insert_error")
            return jsonify(ok=False, error="internal_error"), 500
        return jsonify(ok=True, order_id=str(ins.inserted_id), remaining_today=remaining)
    except Exception:
        app.logger.exception("orders_create_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/api/orders/list", methods=["GET"])
@login_required
def api_orders_list():
    try:
        u = get_user()
        if not u:
            return jsonify(ok=False, error="unauthorized"), 401
        cur = orders.find({"user_id": str(u["_id"])}).sort([("created_at", -1)]).limit(20)
        out = []
        for d in cur:
            out.append({
                "id": str(d.get("_id")),
                "platform": d.get("platform"),
                "url": d.get("url"),
                "reports": int(d.get("reports", 0)),
                "proxies": int(d.get("proxies", 0)),
                "created_at": (d.get("created_at").isoformat() if isinstance(d.get("created_at"), datetime) else None),
            })
        return jsonify(ok=True, items=out)
    except Exception:
        app.logger.exception("orders_list_error")
        return jsonify(ok=False, error="internal_error"), 500

@app.route("/events/subscribe")
@login_required
def sse_subscribe():
    user_id = session.get("user_id")
    q = queue.Queue(maxsize=1024)
    with sse_queues_lock:
        sse_queues[user_id] = q
    def gen():
        heartbeat = 0
        try:
            while True:
                try:
                    evt = q.get(timeout=25)
                    data = json.dumps(evt, ensure_ascii=False)
                    yield f"event: message\ndata: {data}\n\n"
                except queue.Empty:
                    heartbeat += 1
                    yield f"event: heartbeat\ndata: {{\"t\": \"{datetime.utcnow().isoformat()}\", \"hb\": {heartbeat}}}\n\n"
        finally:
            with sse_queues_lock:
                try:
                    del sse_queues[user_id]
                except Exception:
                    pass
    return Response(stream_with_context(gen()), mimetype="text/event-stream")

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = bool(int(os.environ.get("FLASK_DEBUG", "0")))
    app.run(host=host, port=port, threaded=True, debug=debug)
