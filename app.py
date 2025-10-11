import os
import re
import json
import base64
import logging
import secrets
import threading
import time
from io import BytesIO
from datetime import datetime, timedelta
from urllib.parse import quote_plus
from functools import wraps
from decimal import Decimal, ROUND_HALF_UP
import requests
import qrcode
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from pymongo import MongoClient, ASCENDING, errors
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from werkzeug.exceptions import HTTPException
from admin import admin_bp
from faker import Faker
import unicodedata

logging.basicConfig(level=logging.INFO)

USER = quote_plus(os.environ.get('DB_USER', 'seyzalel'))
PWD = quote_plus(os.environ.get('DB_PASS', 'Sey17zalel17@$'))
MONGO_URI = f"mongodb+srv://{USER}:{PWD}@cluster0.krrj4yp.mongodb.net/bcbravus?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client['reportingbot']
users = db['users']
transactions = db['transactions']
usage = db['usage']
settings = db['settings']
orders = db['orders']

def safe_create_index(coll, keys, **kwargs):
    try:
        return coll.create_index(keys, **kwargs)
    except errors.OperationFailure as e:
        if getattr(e, 'code', None) == 86:
            return None
        logging.exception('index_error')
        return None
    except Exception:
        logging.exception('index_error')
        return None

def ensure_indexes():
    safe_create_index(users, [('username', ASCENDING)], name='username_1', unique=True)
    safe_create_index(users, [('username_lower', ASCENDING)], name='username_lower_1', unique=True, partialFilterExpression={'username_lower': {'$type': 'string'}})
    safe_create_index(users, [('email', ASCENDING)], name='email_1', unique=True)
    safe_create_index(transactions, [('hash', ASCENDING)], name='hash_1', unique=True)
    safe_create_index(transactions, [('user_id', ASCENDING)], name='user_id_1')
    safe_create_index(usage, [('user_id', ASCENDING), ('date', ASCENDING)], name='user_id_date_1', unique=True)
    safe_create_index(settings, [('key', ASCENDING)], name='key_1', unique=True)
    safe_create_index(orders, [('user_id', ASCENDING), ('created_at', ASCENDING)], name='user_id_created_at_1')

ensure_indexes()

app = Flask(__name__, template_folder='.')
app.secret_key = 'sk_live_dX9hK2#vT3qZm!2Lw7FeXp9@RuYpG4o%BnMfVjA6HsE'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = bool(int(os.environ.get('SESSION_COOKIE_SECURE', '0')))
app.config['SESSION_COOKIE_NAME'] = 'rb_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=15)
app.config['users'] = users
app.config['transactions'] = transactions
app.config['usage'] = usage
app.config['settings'] = settings
app.config['orders'] = orders
app.register_blueprint(admin_bp)

USERNAME_RE = re.compile(r'^[A-Za-z0-9._]{3,32}$')
EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
CPF_RE = re.compile(r'^\d{11}$')

TRIBOPAY_TOKEN = os.environ.get('TRIBOPAY_API_TOKEN', 'sIg8rIdfc59BBjAy5Q5JDJQi1otmn5iyGRbLOW1nn6yEDjQeV8fD4NRa6mhB')
TRIBOPAY_API = 'https://api.invictuspay.app.br/api/public/v1/transactions'
TRIBO_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}

PLANS_DEFAULT = {
    'Essencial': {'amount_cents': 3500, 'product_hash': 'enzibgumue', 'offer_hash': '1t8jk9bdfl', 'title': 'Plano Essencial', 'active': True},
    'Profissional': {'amount_cents': 4550, 'product_hash': 'enzibgumue', 'offer_hash': '1t8jk9bdfl', 'title': 'Plano Profissional', 'active': True},
    'Vitalício': {'amount_cents': 11900, 'product_hash': 'enzibgumue', 'offer_hash': '1t8jk9bdfl', 'title': 'Plano Vitalício', 'active': True}
}

PLAN_CODES = {'Essencial': 'essencial', 'Profissional': 'profissional', 'Vitalício': 'vitalicio'}
PLAN_LIMITS = {'padrao': 0, 'essencial': 5, 'profissional': 15, 'vitalicio': None}
PAID_STATUSES = {'paid', 'approved', 'completed', 'confirmed', 'paid_out', 'finished', 'success', 'settled', 'captured', 'accredited', 'credited', 'confirmed_payment'}
FAILED_STATUSES = {'canceled', 'cancelled', 'refunded', 'chargeback', 'reversed', 'voided', 'failed', 'expired', 'denied'}
USER_SCHEMA_VERSION = 1

FAKER = Faker('pt_BR')

def is_logged_in():
    return 'user_id' in session

def login_required(fn):
    @wraps(fn)
    def _wrap(*args, **kwargs):
        if not is_logged_in():
            if request.path.startswith('/api/'):
                return jsonify(ok=False, error='unauthorized'), 401
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return _wrap

def brl_from_cents(c):
    d = (Decimal(c) / Decimal(100)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    return f'R$ {str(d).replace(".", ",")}'

def generate_qr_base64(emv):
    img = qrcode.make(emv)
    buf = BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def _normalize_text(s):
    if not s:
        return ''
    s = unicodedata.normalize('NFKD', str(s))
    s = s.encode('ascii', 'ignore').decode('ascii')
    s = s.lower()
    s = re.sub(r'[^a-z0-9\s.-]', '', s)
    s = re.sub(r'\s+', '.', s)
    s = re.sub(r'\.+', '.', s).strip('.')
    return s

def generate_coherent_gmail(user_name=None):
    if user_name and user_name.strip():
        first = str(user_name).strip().split()[0]
    else:
        first = FAKER.first_name()
    last = FAKER.last_name()
    local = f"{_normalize_text(first)}.{_normalize_text(last)}"
    if not re.search(r'[a-z0-9]', local):
        local = secrets.token_hex(6)
    if len(local) > 60:
        local = local[:60]
    suffix = str(secrets.randbelow(9999))
    local = f"{local}{suffix}"
    return f"{local}@gmail.com"

def get_user():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        u = users.find_one({'_id': ObjectId(uid)})
        return u
    except Exception:
        return None

def normalize_plan(user_doc):
    code = (user_doc or {}).get('plans') or 'padrao'
    exp = (user_doc or {}).get('plan_expires_at')
    now = datetime.utcnow()
    if code in ('essencial', 'profissional') and exp and now > exp:
        users.update_one({'_id': user_doc['_id']}, {'$set': {'plans': 'padrao', 'plan_started_at': None, 'plan_expires_at': None}})
        code = 'padrao'
        exp = None
    return code, exp

def plan_meta(code):
    limit = PLAN_LIMITS.get(code, 0)
    return limit

def date_key_utc(dt=None):
    dt = dt or datetime.utcnow()
    return dt.strftime('%Y-%m-%d')

def get_plans():
    doc = settings.find_one({'key': 'plans'}) or {}
    custom = doc.get('value') or {}
    out = {}
    for k, v in PLANS_DEFAULT.items():
        c = dict(v)
        if k in custom:
            if isinstance(custom[k].get('amount_cents'), int):
                c['amount_cents'] = int(custom[k]['amount_cents'])
            if isinstance(custom[k].get('active'), bool):
                c['active'] = custom[k]['active']
        out[k] = c
    return out

def save_plans(payload):
    base = get_plans()
    for k, cfg in payload.items():
        if k in base:
            if 'amount_cents' in cfg:
                base[k]['amount_cents'] = int(cfg['amount_cents'])
            if 'active' in cfg:
                base[k]['active'] = bool(cfg['active'])
    settings.update_one({'key': 'plans'}, {'$set': {'key': 'plans', 'value': base, 'updated_at': datetime.utcnow()}}, upsert=True)
    return base

def tribopay_fetch_status(tx_hash):
    try:
        r = requests.get(f"{TRIBOPAY_API}/{tx_hash}?api_token={TRIBOPAY_TOKEN}", headers=TRIBO_HEADERS, timeout=15)
        r.raise_for_status()
        resp = r.json()
    except Exception:
        return None, None
    obj = resp.get('data') if isinstance(resp, dict) else None
    if not obj and isinstance(resp, dict):
        obj = resp
    status = None
    if isinstance(obj, dict):
        status = obj.get('status') or obj.get('status_payment') or obj.get('payment_status')
    return (status.lower() if isinstance(status, str) else None), obj

def try_activation(tx):
    st = (tx.get('payment_status') or '').lower()
    if st not in PAID_STATUSES:
        return
    res = transactions.update_one({'_id': tx['_id'], 'activated_at': {'$exists': False}}, {'$set': {'activated_at': datetime.utcnow()}})
    if not res.modified_count:
        return
    uid = tx.get('user_id')
    plan_name = tx.get('plan')
    code = PLAN_CODES.get(plan_name)
    if not uid or not code:
        return
    exp = None
    if code in ('essencial', 'profissional'):
        exp = datetime.utcnow() + timedelta(days=30)
    try:
        users.update_one({'_id': ObjectId(uid)}, {'$set': {'plans': code, 'plan_started_at': datetime.utcnow(), 'plan_expires_at': exp}})
    except Exception:
        pass

def apply_user_migrations(user_doc):
    if not user_doc:
        return None
    set_fields = {}
    now = datetime.utcnow()
    lower = (user_doc.get('username') or '').lower()
    if user_doc.get('username_lower') != lower:
        set_fields['username_lower'] = lower
    if 'plans' not in user_doc:
        set_fields['plans'] = 'padrao'
    if 'plan_started_at' not in user_doc:
        set_fields['plan_started_at'] = None
    if 'plan_expires_at' not in user_doc:
        set_fields['plan_expires_at'] = None
    if 'admin_permission' not in user_doc:
        set_fields['admin_permission'] = 'no'
    if 'disabled' not in user_doc:
        set_fields['disabled'] = False
    if 'created_at' not in user_doc or not isinstance(user_doc.get('created_at'), datetime):
        set_fields['created_at'] = now
    if 'last_login_at' not in user_doc:
        set_fields['last_login_at'] = None
    current_version = int(user_doc.get('schema_version', 0)) if isinstance(user_doc.get('schema_version', 0), int) else 0
    if current_version < USER_SCHEMA_VERSION:
        set_fields['schema_version'] = USER_SCHEMA_VERSION
    if set_fields:
        users.update_one({'_id': user_doc['_id']}, {'$set': set_fields})
        return users.find_one({'_id': user_doc['_id']})
    return user_doc

def monitor_transaction(tx_hash):
    for _ in range(86400):
        st, payload = tribopay_fetch_status(tx_hash)
        if st:
            now = datetime.utcnow()
            transactions.update_one({'hash': tx_hash}, {'$set': {'payment_status': st, 'updated_at': now, 'raw_last': payload}})
            if st in PAID_STATUSES:
                tx = transactions.find_one({'hash': tx_hash})
                if tx:
                    try_activation(tx)
                break
            if st in FAILED_STATUSES:
                transactions.update_one({'hash': tx_hash}, {'$set': {'failed_at': now}})
                break
        time.sleep(1)

def cpf_is_valid(cpf):
    s = re.sub(r'\D+', '', str(cpf or ''))
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
    parts = re.split(r'\s+', str(name or '').strip())
    parts = [p for p in parts if len(p) >= 2]
    return len(parts) >= 2

def wants_json():
    a = str(request.headers.get('Accept', '')).lower()
    x = str(request.headers.get('X-Requested-With', '')).lower()
    ct = str(request.headers.get('Content-Type', '')).lower()
    return request.is_json or 'application/json' in a or x in ('xmlhttprequest', 'fetch') or 'application/json' in ct

@app.before_request
def redirect_auth_pages_when_logged():
    if request.method == 'GET' and is_logged_in() and request.endpoint in ('login', 'register'):
        return redirect(url_for('dashboard'))
    if is_logged_in():
        u = get_user()
        if u:
            u = apply_user_migrations(u)
        if not u or u.get('disabled') is True:
            session.clear()
            return redirect(url_for('login'))
        issued = session.get('issued_at')
        flo = u.get('force_logout_at')
        if issued and flo and isinstance(flo, datetime):
            try:
                if float(issued) < float(flo.timestamp()):
                    session.clear()
                    return redirect(url_for('login'))
            except Exception:
                pass

@app.errorhandler(Exception)
def handle_exceptions(e):
    if isinstance(e, HTTPException):
        try:
            return jsonify(ok=False, error=e.description), e.code
        except Exception:
            return jsonify(ok=False, error='http_error'), e.code
    logging.exception('unhandled_exception')
    return jsonify(ok=False, error='internal_error'), 500

@app.route('/')
def landing_page():
    return render_template('landing_page.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    try:
        data = request.get_json(silent=True) or request.form
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        remember = str(data.get('remember', '')).lower() in ('1', 'true', 'on', 'yes')
        if not USERNAME_RE.match(username) or len(password) < 8:
            return jsonify(ok=False, error='Credenciais inválidas'), 400
        user = users.find_one({'$or': [{'username': username}, {'username_lower': username.lower()}]})
        if not user or not check_password_hash(user.get('password_hash', ''), password):
            return jsonify(ok=False, error='Usuário ou senha incorretos'), 401
        if user.get('disabled') is True:
            return jsonify(ok=False, error='Conta desativada'), 403
        user = apply_user_migrations(user)
        session.clear()
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['issued_at'] = float(datetime.utcnow().timestamp())
        session.permanent = bool(remember)
        users.update_one({'_id': user['_id']}, {'$set': {'last_login_at': datetime.utcnow()}})
        return jsonify(ok=True, redirect=url_for('dashboard'))
    except Exception:
        logging.exception('login_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('cadastro.html')
    try:
        data = request.get_json(silent=True) or request.form
        username = (data.get('username') or '').strip()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        confirm = data.get('confirm') or ''
        if not USERNAME_RE.match(username):
            return jsonify(ok=False, field='username', error='Nome de usuário inválido'), 400
        if not EMAIL_RE.match(email):
            return jsonify(ok=False, field='email', error='E-mail inválido'), 400
        if len(password) < 8:
            return jsonify(ok=False, field='password', error='Senha muito curta'), 400
        if confirm != password:
            return jsonify(ok=False, field='confirm', error='As senhas não coincidem'), 400
        if users.find_one({'$or': [{'username_lower': username.lower()}, {'email': email}]}):
            return jsonify(ok=False, error='Usuário ou e-mail já cadastrado'), 409
        password_hash = generate_password_hash(password)
        try:
            ins = users.insert_one({'username': username, 'username_lower': username.lower(), 'email': email, 'password_hash': password_hash, 'created_at': datetime.utcnow(), 'last_login_at': None, 'plans': 'padrao', 'plan_started_at': None, 'plan_expires_at': None, 'admin_permission': 'no', 'disabled': False, 'schema_version': USER_SCHEMA_VERSION})
        except errors.DuplicateKeyError:
            return jsonify(ok=False, error='Usuário ou e-mail já cadastrado'), 409
        session.clear()
        session['user_id'] = str(ins.inserted_id)
        session['username'] = username
        session['issued_at'] = float(datetime.utcnow().timestamp())
        session.permanent = False
        return jsonify(ok=True, redirect=url_for('dashboard')), 201
    except Exception:
        logging.exception('register_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        u = get_user()
        if u:
            u = apply_user_migrations(u)
            normalize_plan(u)
        return render_template('dashboard.html', username=session.get('username'))
    except Exception:
        logging.exception('dashboard_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    try:
        session.clear()
        return redirect(url_for('login'))
    except Exception:
        logging.exception('logout_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/plans', methods=['GET'])
@login_required
def plans():
    try:
        u = get_user()
        if u:
            apply_user_migrations(u)
        return render_template('planos.html', username=session.get('username'), plans=get_plans())
    except Exception:
        logging.exception('plans_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/pixPayment', methods=['GET', 'POST'])
@login_required
def pix_payment():
    try:
        if request.method == 'GET':
            h = request.args.get('hash') or ''
            if not h:
                return redirect(url_for('plans'))
            tx = transactions.find_one({'hash': h, 'user_id': session.get('user_id')})
            if not tx:
                return redirect(url_for('plans'))
            qr_b64 = tx.get('qr_code_base64') or (generate_qr_base64(tx.get('pix_qr_code')) if tx.get('pix_qr_code') else None)
            if qr_b64 and not tx.get('qr_code_base64'):
                transactions.update_one({'_id': tx['_id']}, {'$set': {'qr_code_base64': qr_b64}})
            return render_template('checkout.html', username=session.get('username'), plan=tx.get('plan'), amount_brl=brl_from_cents(tx.get('amount_cents', 0)), status=tx.get('payment_status', 'waiting_payment'), hash=tx.get('hash'), pix_url=tx.get('pix_url'), emv=tx.get('pix_qr_code'), qr_b64=qr_b64)
        data = request.get_json(silent=True) or request.form
        plan = (data.get('plan') or '').strip()
        plans_cfg = get_plans()
        if plan not in plans_cfg:
            msg = 'Plano inválido'
            if wants_json():
                return jsonify(ok=False, code='invalid_plan', message=msg), 400
            return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 400
        p = plans_cfg[plan]
        if not p.get('active', True):
            msg = 'Plano indisponível'
            if wants_json():
                return jsonify(ok=False, code='plan_unavailable', message=msg), 400
            return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 400
        uid = session.get('user_id')
        user_doc = None
        if uid:
            try:
                user_doc = users.find_one({'_id': ObjectId(uid)})
            except Exception:
                user_doc = None
        if not user_doc and session.get('username'):
            user_doc = users.find_one({'username_lower': session.get('username', '').lower()})
        if user_doc:
            apply_user_migrations(user_doc)
        name = (data.get('name') or '').strip()
        cpf_raw = data.get('cpf') or ''
        cpf = re.sub(r'\D+', '', cpf_raw)
        if not name and user_doc:
            name = (user_doc.get('name') or user_doc.get('full_name') or user_doc.get('username') or '').strip()
        if not cpf and user_doc:
            cpf = re.sub(r'\D+', '', (user_doc.get('document') or user_doc.get('cpf') or ''))
        if not name_is_valid(name) or not cpf_is_valid(cpf):
            msg = 'Por favor, informe seu nome completo e um CPF válido que corresponda ao banco de origem do pagamento.'
            if wants_json():
                return jsonify(ok=False, code='invalid_document', message=msg), 422
            return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 422
        random_email = generate_coherent_gmail(name)
        try:
            postback_url = url_for('tribopay_webhook', _external=True)
        except Exception:
            postback_url = url_for('tribopay_webhook')
        payload = {
            "amount": p['amount_cents'],
            "offer_hash": p['offer_hash'],
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
                "zip_code": "20040020"
            },
            "cart": [
                {
                    "product_hash": p['product_hash'],
                    "title": p['title'],
                    "cover": None,
                    "price": p['amount_cents'],
                    "quantity": 1,
                    "operation_type": 1,
                    "tangible": False
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
                "utm_content": ""
            },
            "postback_url": postback_url
        }
        try:
            r = requests.post(f"{TRIBOPAY_API}?api_token={TRIBOPAY_TOKEN}", headers=TRIBO_HEADERS, json=payload, timeout=30)
            r.raise_for_status()
            data = r.json()
        except requests.HTTPError as e:
            status_code = 502
            body = None
            try:
                body = e.response.json()
            except Exception:
                body = {'error': e.response.text if e.response is not None else str(e)}
            text = json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body
            lower = str(text or '').lower()
            if e.response is not None and e.response.status_code in (400, 401, 403, 422):
                msg = 'Por favor, informe seu nome completo e um CPF válido que corresponda ao banco de origem do pagamento.'
                if 'document' in lower or 'cpf' in lower or 'customer' in lower:
                    if wants_json():
                        return jsonify(ok=False, code='invalid_document', message=msg, details=body), 422
                    return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 422
                msg = 'Não foi possível gerar a cobrança Pix. Tente novamente em instantes.'
                if wants_json():
                    return jsonify(ok=False, code='gateway_error', message=msg, details=body), 502
                return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 502
            msg = 'Não foi possível gerar a cobrança Pix. Tente novamente em instantes.'
            if wants_json():
                return jsonify(ok=False, code='gateway_error', message=msg, details=body), status_code
            return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), status_code
        except Exception as e:
            logging.exception('pix_create_error')
            msg = 'Não foi possível gerar a cobrança Pix. Tente novamente em instantes.'
            if wants_json():
                return jsonify(ok=False, code='gateway_error', message=msg), 502
            return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 502
        resp = data if isinstance(data, dict) else {}
        d = resp.get('data') if isinstance(resp.get('data', None), dict) else resp
        pix = d.get('pix') or {}
        pix_url = pix.get('pix_url') or d.get('pix_url')
        emv = pix.get('pix_qr_code') or pix.get('copy_and_paste') or pix.get('emv') or d.get('pix_qr_code') or d.get('copy_and_paste') or d.get('emv')
        h = d.get('hash') or pix.get('hash') or d.get('transaction_hash') or d.get('id_hash') or ''
        raw_status = d.get('payment_status') or d.get('status') or d.get('status_payment')
        if isinstance(raw_status, str):
            status = raw_status.lower()
        elif isinstance(raw_status, bool):
            status = 'paid' if raw_status else 'waiting_payment'
        elif isinstance(raw_status, (int, float)):
            status = 'waiting_payment'
        elif isinstance(raw_status, dict):
            code = raw_status.get('code')
            status = code.lower() if isinstance(code, str) else 'waiting_payment'
        else:
            status = 'waiting_payment'
        if not h:
            msg = 'Não foi possível gerar a cobrança Pix. Tente novamente em instantes.'
            if wants_json():
                return jsonify(ok=False, code='gateway_error', message=msg, details={'reason': 'missing_hash'}), 502
            return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 502
        if not emv:
            msg = 'Não foi possível gerar a cobrança Pix. Tente novamente em instantes.'
            if wants_json():
                return jsonify(ok=False, code='gateway_error', message=msg), 502
            return render_template('planos.html', username=session.get('username'), plans=plans_cfg, error_message=msg), 502
        qr_b64 = generate_qr_base64(emv)
        tx_doc = {
            'user_id': session.get('user_id'),
            'username': session.get('username'),
            'plan': plan,
            'amount_cents': p['amount_cents'],
            'tribopay_id': d.get('id') or resp.get('id'),
            'hash': h,
            'payment_status': status,
            'pix_url': pix_url,
            'pix_qr_code': emv,
            'qr_code_base64': qr_b64,
            'customer_email': random_email,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        transactions.update_one({'hash': h}, {'$set': tx_doc}, upsert=True)
        res = transactions.update_one({'hash': h, 'monitoring': {'$ne': True}}, {'$set': {'monitoring': True}})
        if res.modified_count:
            threading.Thread(target=monitor_transaction, args=(h,), daemon=True).start()
        if wants_json():
            return jsonify(ok=True, redirect=url_for('pix_payment', hash=h))
        return render_template('checkout.html', username=session.get('username'), plan=plan, amount_brl=brl_from_cents(p['amount_cents']), status=status, hash=h, pix_url=pix_url, emv=emv, qr_b64=qr_b64)
    except Exception:
        logging.exception('pix_payment_error')
        if wants_json():
            return jsonify(ok=False, code='internal_error', message='Erro interno'), 500
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/pix/status', methods=['GET'])
@login_required
def pix_status():
    try:
        h = request.args.get('hash') or ''
        if not h:
            return jsonify(ok=False, error='Hash ausente'), 400
        st, payload = tribopay_fetch_status(h)
        if st:
            now = datetime.utcnow()
            transactions.update_one({'hash': h, 'user_id': session.get('user_id')}, {'$set': {'payment_status': st, 'updated_at': now, 'raw_last': payload}})
            if st in PAID_STATUSES:
                tx = transactions.find_one({'hash': h, 'user_id': session.get('user_id')})
                if tx:
                    try_activation(tx)
            if st in FAILED_STATUSES:
                transactions.update_one({'hash': h, 'user_id': session.get('user_id')}, {'$set': {'failed_at': now}})
        tx = transactions.find_one({'hash': h, 'user_id': session.get('user_id')})
        if not tx:
            return jsonify(ok=False, error='Transação não encontrada'), 404
        return jsonify(ok=True, status=tx.get('payment_status'), hash=h)
    except Exception:
        logging.exception('pix_status_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/webhook/tribopay', methods=['POST'])
def tribopay_webhook():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify(ok=False), 400
    try:
        if not isinstance(data, dict):
            return jsonify(ok=False), 400
        h = data.get('hash') or ''
        if not h:
            pix = data.get('pix') or {}
            h = pix.get('hash') or ''
        if not h:
            return jsonify(ok=False), 400
        res = transactions.update_one({'hash': h, 'monitoring': {'$ne': True}}, {'$set': {'monitoring': True}})
        if res.modified_count:
            threading.Thread(target=monitor_transaction, args=(h,), daemon=True).start()
        return jsonify(ok=True)
    except Exception:
        logging.exception('webhook_error')
        return jsonify(ok=False), 500

@app.route('/api/plan/status', methods=['GET'])
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
        if limit:
            rec = usage.find_one({'user_id': str(u['_id']), 'date': today})
            used = rec.get('used', 0) if rec else 0
        remaining = None if limit is None else max(0, int(limit) - int(used))
        return jsonify(ok=True, plan=code, expires_at=(exp.isoformat() if exp else None), daily_limit=limit, used_today=used if limit else 0, remaining_today=remaining)
    except Exception:
        logging.exception('plan_status_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/api/usage/consume', methods=['POST'])
@login_required
def api_usage_consume():
    try:
        u = get_user()
        if not u:
            return jsonify(ok=False), 401
        u = apply_user_migrations(u)
        code, exp = normalize_plan(u)
        if code == 'padrao':
            return jsonify(ok=False, error='Plano insuficiente'), 403
        limit = plan_meta(code)
        if limit is None:
            return jsonify(ok=True, remaining_today=None)
        try:
            data = request.get_json(silent=True) or request.form
            count = int(str(data.get('count', '0')))
        except Exception:
            return jsonify(ok=False, error='Parâmetro inválido'), 400
        if count <= 0:
            return jsonify(ok=False, error='Parâmetro inválido'), 400
        today = date_key_utc()
        base = {'user_id': str(u['_id']), 'date': today}
        guard = {'$expr': {'$lte': [{'$add': [{'$ifNull': ['$used', 0]}, count]}, int(limit)]}}
        res = usage.update_one({**base, **guard}, {'$inc': {'used': count}}, upsert=False)
        if res.matched_count == 1:
            rec = usage.find_one(base) or {'used': 0}
            remaining = max(0, int(limit) - int(rec.get('used', 0)))
            return jsonify(ok=True, remaining_today=remaining)
        try:
            usage.insert_one({**base, 'used': count})
            remaining = max(0, int(limit) - count)
            return jsonify(ok=True, remaining_today=remaining)
        except errors.DuplicateKeyError:
            res2 = usage.update_one({**base, **guard}, {'$inc': {'used': count}}, upsert=False)
            if res2.matched_count == 1:
                rec = usage.find_one(base) or {'used': 0}
                remaining = max(0, int(limit) - int(rec.get('used', 0)))
                return jsonify(ok=True, remaining_today=remaining)
        rec = usage.find_one(base) or {'used': 0}
        used_now = int(rec.get('used', 0))
        return jsonify(ok=False, error='Limite diário excedido', remaining=max(0, int(limit) - used_now)), 400
    except Exception:
        logging.exception('usage_consume_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/api/orders/create', methods=['POST'])
@login_required
def api_orders_create():
    try:
        u = get_user()
        if not u:
            return jsonify(ok=False, error='unauthorized'), 401
        u = apply_user_migrations(u)
        code, exp = normalize_plan(u)
        if code == 'padrao':
            return jsonify(ok=False, error='Plano insuficiente'), 403
        data = request.get_json(silent=True) or request.form
        platform = str(data.get('platform', '')).strip().lower()
        url = str(data.get('url', '')).strip()
        try:
            reports = int(str(data.get('reports', '0')))
        except Exception:
            return jsonify(ok=False, error='Parâmetro inválido'), 400
        try:
            proxies = int(str(data.get('proxies', '0')))
        except Exception:
            return jsonify(ok=False, error='Parâmetro inválido'), 400
        if platform not in ('instagram', 'facebook', 'tiktok', 'whatsapp', 'twitter', 'youtube'):
            return jsonify(ok=False, error='Plataforma inválida'), 400
        if not url:
            return jsonify(ok=False, error='URL inválida'), 400
        if proxies < 0 or proxies > 1065:
            return jsonify(ok=False, error='Quantidade de proxies inválida'), 400
        ranges = {'essencial': (100, 500), 'profissional': (100, 5000), 'vitalicio': (100, 15950)}
        if code not in ranges:
            return jsonify(ok=False, error='Plano insuficiente'), 403
        rmin, rmax = ranges[code]
        if reports < rmin or reports > rmax:
            return jsonify(ok=False, error=f'Quantidade permitida para o seu plano: {rmin}-{rmax}'), 400
        limit = plan_meta(code)
        if limit is not None:
            today = date_key_utc()
            base = {'user_id': str(u['_id']), 'date': today}
            guard = {'$expr': {'$lte': [{'$add': [{'$ifNull': ['$used', 0]}, 1]}, int(limit)]}}
            res = usage.update_one({**base, **guard}, {'$inc': {'used': 1}}, upsert=False)
            if res.matched_count != 1:
                try:
                    usage.insert_one({**base, 'used': 1})
                    remaining = max(0, int(limit) - 1)
                except errors.DuplicateKeyError:
                    res2 = usage.update_one({**base, **guard}, {'$inc': {'used': 1}}, upsert=False)
                    if res2.matched_count != 1:
                        rec = usage.find_one(base) or {'used': 0}
                        used_now = int(rec.get('used', 0))
                        return jsonify(ok=False, error='Limite diário excedido', remaining=max(0, int(limit) - used_now)), 400
                    rec = usage.find_one(base) or {'used': 0}
                    remaining = max(0, int(limit) - int(rec.get('used', 0)))
            else:
                rec = usage.find_one(base) or {'used': 0}
                remaining = max(0, int(limit) - int(rec.get('used', 0)))
        else:
            remaining = None
        doc = {
            'user_id': str(u['_id']),
            'username': u.get('username'),
            'platform': platform,
            'url': url,
            'reports': int(reports),
            'proxies': int(proxies),
            'created_at': datetime.utcnow()
        }
        ins = orders.insert_one(doc)
        return jsonify(ok=True, order_id=str(ins.inserted_id), remaining_today=remaining)
    except Exception:
        logging.exception('orders_create_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/api/orders/list', methods=['GET'])
@login_required
def api_orders_list():
    try:
        u = get_user()
        if not u:
            return jsonify(ok=False, error='unauthorized'), 401
        cur = orders.find({'user_id': str(u['_id'])}).sort([('created_at', -1)]).limit(20)
        out = []
        for d in cur:
            out.append({
                'id': str(d.get('_id')),
                'platform': d.get('platform'),
                'url': d.get('url'),
                'reports': int(d.get('reports', 0)),
                'proxies': int(d.get('proxies', 0)),
                'created_at': (d.get('created_at').isoformat() if isinstance(d.get('created_at'), datetime) else None)
            })
        return jsonify(ok=True, items=out)
    except Exception:
        logging.exception('orders_list_error')
        return jsonify(ok=False, error='internal_error'), 500

if __name__ == '__main__':
    app.run(host=os.environ.get('HOST', '0.0.0.0'), port=int(os.environ.get('PORT', 5000)))
