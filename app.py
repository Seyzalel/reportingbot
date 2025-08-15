import os
import re
import json
import base64
import logging
import secrets
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

logging.basicConfig(level=logging.INFO)

USER = quote_plus(os.environ.get('DB_USER', 'seyzalel'))
PWD = quote_plus(os.environ.get('DB_PASS', 'Sey17zalel17@$'))
MONGO_URI = f"mongodb+srv://{USER}:{PWD}@cluster0.krrj4yp.mongodb.net/bcbravus?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client['reportingbot']
users = db['users']
users.create_index([('username', ASCENDING)], unique=True)
users.create_index([('email', ASCENDING)], unique=True)
transactions = db['transactions']
transactions.create_index([('hash', ASCENDING)], unique=True)
transactions.create_index([('user_id', ASCENDING)])

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

PLANS = {
    'Essencial': {'amount_cents': 3500, 'product_hash': 'ufgvfzaxun', 'offer_hash': 'fjthlgwzum', 'title': 'Plano Essencial'},
    'Profissional': {'amount_cents': 4550, 'product_hash': 'rf8ctqw43w', 'offer_hash': 'fndb7wny84', 'title': 'Plano Profissional'},
    'Vitalício': {'amount_cents': 11900, 'product_hash': 'sixft0cqgo', 'offer_hash': 'iayrjqznxp', 'title': 'Plano Vitalício'}
}

def is_logged_in():
    return 'user_id' in session

def login_required(fn):
    @wraps(fn)
    def _wrap(*args, **kwargs):
        if not is_logged_in():
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

@app.before_request
def redirect_auth_pages_when_logged():
    if request.method == 'GET' and is_logged_in() and request.endpoint in ('login', 'register'):
        return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    data = request.get_json(silent=True) or request.form
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    remember = str(data.get('remember', '')).lower() in ('1', 'true', 'on', 'yes')
    if not USERNAME_RE.match(username) or len(password) < 8:
        return jsonify(ok=False, error='Credenciais inválidas'), 400
    user = users.find_one({'username': username})
    if not user or not check_password_hash(user.get('password_hash', ''), password):
        return jsonify(ok=False, error='Usuário ou senha incorretos'), 401
    session.clear()
    session['user_id'] = str(user['_id'])
    session['username'] = user['username']
    session.permanent = bool(remember)
    users.update_one({'_id': user['_id']}, {'$set': {'last_login_at': datetime.utcnow()}})
    return jsonify(ok=True, redirect=url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('cadastro.html')
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
    if users.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify(ok=False, error='Usuário ou e-mail já cadastrado'), 409
    password_hash = generate_password_hash(password)
    try:
        ins = users.insert_one({'username': username, 'email': email, 'password_hash': password_hash, 'created_at': datetime.utcnow(), 'last_login_at': None})
    except errors.DuplicateKeyError:
        return jsonify(ok=False, error='Usuário ou e-mail já cadastrado'), 409
    session.clear()
    session['user_id'] = str(ins.inserted_id)
    session['username'] = username
    session.permanent = False
    return jsonify(ok=True, redirect=url_for('dashboard')), 201

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/plans', methods=['GET'])
@login_required
def plans():
    return render_template('planos.html', username=session.get('username'))

@app.route('/pixPayment', methods=['GET', 'POST'])
@login_required
def pix_payment():
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
    if plan not in PLANS:
        return jsonify(ok=False, error='Plano inválido'), 400
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
        user_doc = users.find_one({'username': session.get('username')})
    user_email = (user_doc or {}).get('email') or ''
    p = PLANS[plan]
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
        return jsonify(ok=False, error=str(e)), 502
    d = data if isinstance(data, dict) else {}
    pix = d.get('pix') or {}
    pix_url = pix.get('pix_url') or d.get('pix_url')
    emv = pix.get('pix_qr_code') or pix.get('copy_and_paste') or pix.get('emv') or d.get('pix_qr_code')
    h = d.get('hash') or ''
    status = d.get('payment_status') or 'waiting_payment'
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
    return render_template('checkout.html', username=session.get('username'), plan=plan, amount_brl=brl_from_cents(p['amount_cents']), status=status, hash=h, pix_url=pix_url, emv=emv, qr_b64=qr_b64)

@app.route('/pix/status', methods=['GET'])
@login_required
def pix_status():
    h = request.args.get('hash') or ''
    if not h:
        return jsonify(ok=False, error='Hash ausente'), 400
    tx = transactions.find_one({'hash': h, 'user_id': session.get('user_id')})
    if not tx:
        return jsonify(ok=False, error='Transação não encontrada'), 404
    return jsonify(ok=True, status=tx.get('payment_status'), hash=h)

@app.route('/webhook/tribopay', methods=['POST'])
def tribopay_webhook():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify(ok=False), 400
    if not isinstance(data, dict):
        return jsonify(ok=False), 400
    h = data.get('hash') or ''
    status = data.get('payment_status') or ''
    if not h:
        pix = data.get('pix') or {}
        h = pix.get('hash') or ''
    if not h:
        return jsonify(ok=False), 400
    tx = transactions.find_one({'hash': h})
    if not tx:
        transactions.update_one({'hash': h}, {'$setOnInsert': {'created_at': datetime.utcnow()}, '$set': {'raw': data}}, upsert=True)
        return jsonify(ok=True)
    st = status or data.get('status') or tx.get('payment_status')
    transactions.update_one({'_id': tx['_id']}, {'$set': {'payment_status': st, 'updated_at': datetime.utcnow(), 'raw': data}})
    return jsonify(ok=True)

if __name__ == '__main__':
    app.run(host=os.environ.get('HOST', '0.0.0.0'), port=int(os.environ.get('PORT', 5000)))