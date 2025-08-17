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

logging.basicConfig(level=logging.INFO)

USER = quote_plus(os.environ.get('DB_USER', 'seyzalel'))
PWD = quote_plus(os.environ.get('DB_PASS', 'Sey17zalel17@$'))
MONGO_URI = f"mongodb+srv://{USER}:{PWD}@cluster0.krrj4yp.mongodb.net/bcbravus?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client['reportingbot']
users = db['users']
users.create_index([('username', ASCENDING)], unique=True)
users.create_index([('username_lower', ASCENDING)], unique=True)
users.create_index([('email', ASCENDING)], unique=True)
transactions = db['transactions']
transactions.create_index([('hash', ASCENDING)], unique=True)
transactions.create_index([('user_id', ASCENDING)])
usage = db['usage']
usage.create_index([('user_id', ASCENDING), ('date', ASCENDING)], unique=True)
settings = db['settings']
settings.create_index([('key', ASCENDING)], unique=True)

app = Flask(__name__, template_folder='.')
_app_secret_env = os.environ.get('SECRET_KEY', '')
app.secret_key = _app_secret_env if isinstance(_app_secret_env, str) and len(_app_secret_env) >= 32 else secrets.token_urlsafe(64)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = bool(int(os.environ.get('SESSION_COOKIE_SECURE', '0')))
app.config['SESSION_COOKIE_NAME'] = 'rb_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=15)

USERNAME_RE = re.compile(r'^[A-Za-z0-9._]{3,32}$')
EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
CPF_RE = re.compile(r'^\d{11}$')

TRIBOPAY_TOKEN = os.environ.get('TRIBOPAY_API_TOKEN', 'UcsGgIwEkBW5FrLbjtJbVkSda7fOrSk2paZ8sIYqYwKBEpORYWSiupTG58n4')
TRIBOPAY_API = 'https://api.tribopay.com.br/api/public/v1/transactions'
TRIBO_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}

PLANS_DEFAULT = {
    'Essencial': {'amount_cents': 3500, 'product_hash': 'ufgvfzaxun', 'offer_hash': 'fjthlgwzum', 'title': 'Plano Essencial', 'active': True},
    'Profissional': {'amount_cents': 4550, 'product_hash': 'rf8ctqw43w', 'offer_hash': 'fndb7wny84', 'title': 'Plano Profissional', 'active': True},
    'Vitalício': {'amount_cents': 11900, 'product_hash': 'sixft0cqgo', 'offer_hash': 'iayrjqznxp', 'title': 'Plano Vitalício', 'active': True}
}

PLAN_CODES = {'Essencial': 'essencial', 'Profissional': 'profissional', 'Vitalício': 'vitalicio'}
PLAN_LIMITS = {'padrao': 0, 'essencial': 5, 'profissional': 15, 'vitalicio': None}
PAID_STATUSES = {'paid', 'approved', 'completed', 'confirmed', 'paid_out', 'finished', 'success', 'settled', 'captured', 'accredited', 'credited', 'confirmed_payment'}
FAILED_STATUSES = {'canceled', 'cancelled', 'refunded', 'chargeback', 'reversed', 'voided', 'failed', 'expired', 'denied'}
USER_SCHEMA_VERSION = 1

def is_logged_in():
    return 'user_id' in session

def admin_allowed():
    u = get_user()
    return bool(u and (u.get('admin_permission') == 'yes'))

def login_required(fn):
    @wraps(fn)
    def _wrap(*args, **kwargs):
        if not is_logged_in():
            if request.path.startswith('/api/'):
                return jsonify(ok=False, error='unauthorized'), 401
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return _wrap

def admin_required(fn):
    @wraps(fn)
    def _wrap(*args, **kwargs):
        if not is_logged_in():
            if request.path.startswith('/admin/api') or request.path.startswith('/api/'):
                return jsonify(ok=False, error='unauthorized'), 401
            return redirect(url_for('login'))
        if not admin_allowed():
            return jsonify(ok=False, error='forbidden'), 403
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

@app.route('/')
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
        return render_template('planos.html', username=session.get('username'))
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
        name = (data.get('name') or '').strip()
        cpf = re.sub(r'\D+', '', data.get('cpf') or '')
        plans_cfg = get_plans()
        if plan not in plans_cfg:
            return jsonify(ok=False, error='Plano inválido'), 400
        p = plans_cfg[plan]
        if not p.get('active', True):
            return jsonify(ok=False, error='Plano indisponível'), 400
        if not name or not CPF_RE.match(cpf):
            return jsonify(ok=False, error='Dados inválidos'), 400
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
        user_email = (user_doc or {}).get('email') or ''
        payload = {
            "amount": p['amount_cents'],
            "offer_hash": p['offer_hash'],
            "payment_method": "pix",
            "installments": 1,
            "customer": {
                "name": name,
                "email": user_email,
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
            "postback_url": url_for('tribopay_webhook', _external=True)
        }
        try:
            r = requests.post(f"{TRIBOPAY_API}?api_token={TRIBOPAY_TOKEN}", headers=TRIBO_HEADERS, json=payload, timeout=30)
            r.raise_for_status()
            data = r.json()
        except requests.HTTPError as e:
            try:
                body = e.response.json()
            except Exception:
                body = {'error': e.response.text if e.response is not None else str(e)}
            return jsonify(ok=False, error=body), 502
        except Exception as e:
            logging.exception('pix_create_error')
            return jsonify(ok=False, error=str(e)), 502
        d = data if isinstance(data, dict) else {}
        pix = d.get('pix') or {}
        pix_url = pix.get('pix_url') or d.get('pix_url')
        emv = pix.get('pix_qr_code') or pix.get('copy_and_paste') or pix.get('emv') or d.get('pix_qr_code')
        h = d.get('hash') or ''
        status = (d.get('payment_status') or 'waiting_payment').lower()
        if not emv:
            return jsonify(ok=False, error='Falha ao criar cobrança Pix'), 502
        qr_b64 = generate_qr_base64(emv)
        tx_doc = {
            'user_id': session.get('user_id'),
            'username': session.get('username'),
            'plan': plan,
            'amount_cents': p['amount_cents'],
            'tribopay_id': d.get('id'),
            'hash': h,
            'payment_status': status,
            'pix_url': pix_url,
            'pix_qr_code': emv,
            'qr_code_base64': qr_b64,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        transactions.update_one({'hash': h}, {'$set': tx_doc}, upsert=True)
        res = transactions.update_one({'hash': h, 'monitoring': {'$ne': True}}, {'$set': {'monitoring': True}})
        if res.modified_count:
            threading.Thread(target=monitor_transaction, args=(h,), daemon=True).start()
        return render_template('checkout.html', username=session.get('username'), plan=plan, amount_brl=brl_from_cents(p['amount_cents']), status=status, hash=h, pix_url=pix_url, emv=emv, qr_b64=qr_b64)
    except Exception:
        logging.exception('pix_payment_error')
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

@app.route('/admin_panel', methods=['GET'])
@login_required
def admin_panel():
    try:
        if not admin_allowed():
            return jsonify(ok=False, error='forbidden'), 403
        u = get_user()
        if u:
            apply_user_migrations(u)
        return render_template('admin_panel.html', username=session.get('username'))
    except Exception:
        logging.exception('admin_panel_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/metrics', methods=['GET'])
@admin_required
def admin_metrics():
    try:
        now = datetime.utcnow()
        def sum_range(start_dt):
            pipe = [
                {'$match': {'activated_at': {'$gte': start_dt, '$lte': now}}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount_cents'}, 'count': {'$sum': 1}}}
            ]
            agg = list(transactions.aggregate(pipe))
            if agg:
                return int(agg[0].get('total', 0)), int(agg[0].get('count', 0))
            return 0, 0
        start_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        t_total, t_count = sum_range(start_today)
        d7 = now - timedelta(days=7)
        d7_total, d7_count = sum_range(d7)
        d30 = now - timedelta(days=30)
        d30_total, d30_count = sum_range(d30)
        pending = transactions.count_documents({'payment_status': {'$nin': list(PAID_STATUSES | FAILED_STATUSES)}})
        paid = transactions.count_documents({'payment_status': {'$in': list(PAID_STATUSES)}})
        failed = transactions.count_documents({'payment_status': {'$in': list(FAILED_STATUSES)}})
        return jsonify(ok=True, revenue_today_cents=t_total, revenue_7d_cents=d7_total, revenue_30d_cents=d30_total, count_today=t_count, count_7d=d7_count, count_30d=d30_count, tx_counts={'pending': pending, 'paid': paid, 'failed': failed})
    except Exception:
        logging.exception('admin_metrics_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/transactions', methods=['GET'])
@admin_required
def admin_list_transactions():
    try:
        q = {}
        status = (request.args.get('status') or '').strip().lower()
        text = (request.args.get('q') or '').strip()
        plan = (request.args.get('plan') or '').strip()
        date_from = request.args.get('from')
        date_to = request.args.get('to')
        if status:
            q['payment_status'] = status
        if plan:
            q['plan'] = plan
        if date_from:
            try:
                dtf = datetime.fromisoformat(date_from)
                q['created_at'] = q.get('created_at', {})
                q['created_at']['$gte'] = dtf
            except Exception:
                pass
        if date_to:
            try:
                dtt = datetime.fromisoformat(date_to)
                q['created_at'] = q.get('created_at', {})
                q['created_at']['$lte'] = dtt
            except Exception:
                pass
        if text:
            q['$or'] = [{'hash': {'$regex': text, '$options': 'i'}}, {'username': {'$regex': text, '$options': 'i'}}]
        page = max(1, int(request.args.get('page', '1')))
        size = max(1, min(100, int(request.args.get('page_size', '20'))))
        skip = (page - 1) * size
        total = transactions.count_documents(q)
        cur = transactions.find(q).sort('created_at', -1).skip(skip).limit(size)
        items = []
        for t in cur:
            items.append({
                'id': str(t.get('_id')),
                'user_id': t.get('user_id'),
                'username': t.get('username'),
                'plan': t.get('plan'),
                'amount_cents': t.get('amount_cents'),
                'hash': t.get('hash'),
                'payment_status': t.get('payment_status'),
                'created_at': t.get('created_at').isoformat() if t.get('created_at') else None,
                'updated_at': t.get('updated_at').isoformat() if t.get('updated_at') else None,
                'activated_at': t.get('activated_at').isoformat() if t.get('activated_at') else None,
                'failed_at': t.get('failed_at').isoformat() if t.get('failed_at') else None
            })
        return jsonify(ok=True, total=total, page=page, page_size=size, items=items)
    except Exception:
        logging.exception('admin_list_transactions_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/transactions/<tid>', methods=['DELETE', 'PATCH'])
@admin_required
def admin_tx_modify(tid):
    try:
        try:
            oid = ObjectId(tid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        if request.method == 'DELETE':
            transactions.delete_one({'_id': oid})
            return jsonify(ok=True)
        data = request.get_json(silent=True) or {}
        updates = {}
        ps = data.get('payment_status')
        if isinstance(ps, str) and ps:
            updates['payment_status'] = ps.lower()
            updates['updated_at'] = datetime.utcnow()
        if not updates:
            return jsonify(ok=False, error='no_updates'), 400
        tx = transactions.find_one({'_id': oid})
        if not tx:
            return jsonify(ok=False, error='not_found'), 404
        transactions.update_one({'_id': oid}, {'$set': updates})
        tx = transactions.find_one({'_id': oid})
        if tx.get('payment_status') in PAID_STATUSES:
            try_activation(tx)
        return jsonify(ok=True)
    except Exception:
        logging.exception('admin_tx_modify_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/users', methods=['GET'])
@admin_required
def admin_users_list():
    try:
        text = (request.args.get('q') or '').strip()
        adm = request.args.get('admin')
        disabled = request.args.get('disabled')
        q = {}
        if text:
            q['$or'] = [{'username': {'$regex': text, '$options': 'i'}}, {'email': {'$regex': text, '$options': 'i'}}]
        if adm in ('yes', 'no'):
            q['admin_permission'] = adm
        if disabled in ('true', 'false'):
            q['disabled'] = (disabled == 'true')
        page = max(1, int(request.args.get('page', '1')))
        size = max(1, min(100, int(request.args.get('page_size', '20'))))
        skip = (page - 1) * size
        total = users.count_documents(q)
        cur = users.find(q).sort('created_at', -1).skip(skip).limit(size)
        items = []
        for u in cur:
            items.append({
                'id': str(u.get('_id')),
                'username': u.get('username'),
                'email': u.get('email'),
                'plans': u.get('plans'),
                'plan_started_at': u.get('plan_started_at').isoformat() if u.get('plan_started_at') else None,
                'plan_expires_at': u.get('plan_expires_at').isoformat() if u.get('plan_expires_at') else None,
                'admin_permission': u.get('admin_permission'),
                'disabled': bool(u.get('disabled')),
                'created_at': u.get('created_at').isoformat() if u.get('created_at') else None,
                'last_login_at': u.get('last_login_at').isoformat() if u.get('last_login_at') else None
            })
        return jsonify(ok=True, total=total, page=page, page_size=size, items=items)
    except Exception:
        logging.exception('admin_users_list_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/users/<uid>/set_admin', methods=['POST'])
@admin_required
def admin_user_set_admin(uid):
    try:
        data = request.get_json(silent=True) or {}
        val = data.get('admin_permission')
        if val not in ('yes', 'no'):
            return jsonify(ok=False, error='invalid_value'), 400
        try:
            oid = ObjectId(uid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        users.update_one({'_id': oid}, {'$set': {'admin_permission': val}})
        return jsonify(ok=True)
    except Exception:
        logging.exception('admin_user_set_admin_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/users/<uid>/disable', methods=['POST'])
@admin_required
def admin_user_disable(uid):
    try:
        data = request.get_json(silent=True) or {}
        if 'disabled' not in data:
            return jsonify(ok=False, error='invalid_value'), 400
        try:
            oid = ObjectId(uid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        users.update_one({'_id': oid}, {'$set': {'disabled': bool(data.get('disabled'))}})
        return jsonify(ok=True)
    except Exception:
        logging.exception('admin_user_disable_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/users/<uid>/force_logout', methods=['POST'])
@admin_required
def admin_user_force_logout(uid):
    try:
        try:
            oid = ObjectId(uid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        users.update_one({'_id': oid}, {'$set': {'force_logout_at': datetime.utcnow()}})
        return jsonify(ok=True)
    except Exception:
        logging.exception('admin_user_force_logout_error')
        return jsonify(ok=False, error='internal_error'), 500

@app.route('/admin/api/plans', methods=['GET', 'PUT'])
@admin_required
def admin_plans():
    try:
        if request.method == 'GET':
            plans = get_plans()
            return jsonify(ok=True, plans=plans)
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or not data:
            return jsonify(ok=False, error='invalid_payload'), 400
        updated = save_plans(data)
        return jsonify(ok=True, plans=updated)
    except Exception:
        logging.exception('admin_plans_error')
        return jsonify(ok=False, error='internal_error'), 500

if __name__ == '__main__':
    app.run(host=os.environ.get('HOST', '0.0.0.0'), port=int(os.environ.get('PORT', 5000)))