from flask import Blueprint, request, session, redirect, url_for, render_template, jsonify, current_app
from datetime import datetime, timedelta, timezone
from bson.objectid import ObjectId
from functools import wraps
import hashlib
import hmac
import json
import os
import re

admin_bp = Blueprint("admin", __name__)

PAID_STATUSES = {'paid', 'approved', 'completed', 'confirmed', 'paid_out', 'finished', 'success', 'settled', 'captured', 'accredited', 'credited', 'confirmed_payment'}
FAILED_STATUSES = {'canceled', 'cancelled', 'refunded', 'chargeback', 'reversed', 'voided', 'failed', 'expired', 'denied'}
USER_SCHEMA_VERSION = 1

PLANS_DEFAULT = {
    'Essencial': {'amount_cents': 3500, 'product_hash': 'ufgvfzaxun', 'offer_hash': 'fjthlgwzum', 'title': 'Plano Essencial', 'active': True},
    'Profissional': {'amount_cents': 4550, 'product_hash': 'rf8ctqw43w', 'offer_hash': 'fndb7wny84', 'title': 'Plano Profissional', 'active': True},
    'Vitalício': {'amount_cents': 11900, 'product_hash': 'sixft0cqgo', 'offer_hash': 'iayrjqznxp', 'title': 'Plano Vitalício', 'active': True}
}

PLAN_CODES = {'Essencial': 'essencial', 'Profissional': 'profissional', 'Vitalício': 'vitalicio'}

def is_logged_in():
    return 'user_id' in session

def get_user():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        u = current_app.config['users'].find_one({'_id': ObjectId(uid)})
        return u
    except Exception:
        return None

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
        current_app.config['users'].update_one({'_id': user_doc['_id']}, {'$set': set_fields})
        return current_app.config['users'].find_one({'_id': user_doc['_id']})
    return user_doc

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

def get_plans():
    doc = current_app.config['settings'].find_one({'key': 'plans'}) or {}
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
    current_app.config['settings'].update_one({'key': 'plans'}, {'$set': {'key': 'plans', 'value': base, 'updated_at': datetime.utcnow()}}, upsert=True)
    return base

def build_receipt_payload(tx, user_doc):
    now = datetime.utcnow()
    plans_catalog = get_plans()
    plan_name = tx.get('plan')
    plan_cfg = plans_catalog.get(plan_name) or PLANS_DEFAULT.get(plan_name) or {}
    code = PLAN_CODES.get(plan_name)
    activated_at = tx.get('activated_at')
    user_plan_expires = None
    if user_doc and isinstance(user_doc.get('plan_expires_at'), datetime):
        user_plan_expires = user_doc.get('plan_expires_at')
    period_days = 30 if code in ('essencial', 'profissional') else None
    cust_name = None
    cust_document = None
    c = tx.get('customer')
    if isinstance(c, dict):
        cust_name = c.get('name') or cust_name
        cust_document = c.get('document') or c.get('cpf') or cust_document
    rl = tx.get('raw_last')
    if isinstance(rl, dict):
        c2 = rl.get('customer')
        if isinstance(c2, dict):
            cust_name = cust_name or c2.get('name')
            cust_document = cust_document or c2.get('document') or c2.get('cpf')
        pix = rl.get('pix')
        if isinstance(pix, dict):
            c3 = pix.get('customer') or pix.get('payer')
            if isinstance(c3, dict):
                cust_name = cust_name or c3.get('name')
                cust_document = cust_document or c3.get('document') or c3.get('cpf')
    receipt = {
        'receipt_id': 'rcpt_' + str(tx.get('_id')),
        'issued_at': now.isoformat(),
        'currency': 'BRL',
        'user': {
            'id': str(user_doc.get('_id')) if user_doc and user_doc.get('_id') else None,
            'username': user_doc.get('username') if user_doc else None,
            'email': user_doc.get('email') if user_doc else None,
            'created_at': user_doc.get('created_at').isoformat() if user_doc and user_doc.get('created_at') else None,
            'last_login_at': user_doc.get('last_login_at').isoformat() if user_doc and user_doc.get('last_login_at') else None,
            'disabled': bool(user_doc.get('disabled')) if user_doc else None,
            'admin_permission': user_doc.get('admin_permission') if user_doc else None
        },
        'transaction': {
            'id': str(tx.get('_id')) if tx.get('_id') else None,
            'user_id': tx.get('user_id'),
            'username': tx.get('username'),
            'hash': tx.get('hash'),
            'plan_name': plan_name,
            'amount_cents': tx.get('amount_cents'),
            'payment_status': tx.get('payment_status'),
            'created_at': tx.get('created_at').isoformat() if tx.get('created_at') else None,
            'updated_at': tx.get('updated_at').isoformat() if tx.get('updated_at') else None,
            'activated_at': activated_at.isoformat() if activated_at else None,
            'failed_at': tx.get('failed_at').isoformat() if tx.get('failed_at') else None
        },
        'plan': {
            'code': code,
            'title': plan_cfg.get('title'),
            'product_hash': plan_cfg.get('product_hash'),
            'offer_hash': plan_cfg.get('offer_hash'),
            'period_days': period_days
        },
        'service_delivery': {
            'granted': True if activated_at else False,
            'granted_at': activated_at.isoformat() if activated_at else None,
            'expires_at': user_plan_expires.isoformat() if user_plan_expires else None,
            'access_level': code
        },
        'customer': {
            'name': cust_name,
            'document': cust_document
        }
    }
    key = (current_app.config.get('RECEIPT_SECRET') or current_app.config.get('SECRET_KEY') or '').encode()
    payload_for_sig = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()
    sig = hmac.new(key, payload_for_sig, hashlib.sha256).hexdigest() if key else hashlib.sha256(payload_for_sig).hexdigest()
    receipt['signature'] = sig
    return receipt

def ensure_receipt(tx):
    if not tx or (tx.get('payment_status') or '').lower() not in PAID_STATUSES:
        return
    if tx.get('receipt'):
        return
    uid = tx.get('user_id')
    user_doc = None
    try:
        if uid:
            user_doc = current_app.config['users'].find_one({'_id': ObjectId(uid)})
    except Exception:
        user_doc = None
    rec = build_receipt_payload(tx, user_doc)
    current_app.config['transactions'].update_one({'_id': tx['_id']}, {'$set': {'receipt': rec, 'receipt_issued_at': datetime.utcnow()}})

def try_activation(tx):
    st = (tx.get('payment_status') or '').lower()
    if st not in PAID_STATUSES:
        return
    res = current_app.config['transactions'].update_one({'_id': tx['_id'], 'activated_at': {'$exists': False}}, {'$set': {'activated_at': datetime.utcnow()}})
    activated_now = bool(res.modified_count)
    uid = tx.get('user_id')
    plan_name = tx.get('plan')
    code = PLAN_CODES.get(plan_name)
    exp = None
    if activated_now and uid and code:
        if code in ('essencial', 'profissional'):
            exp = datetime.utcnow() + timedelta(days=30)
        try:
            current_app.config['users'].update_one({'_id': ObjectId(uid)}, {'$set': {'plans': code, 'plan_started_at': datetime.utcnow(), 'plan_expires_at': exp}})
        except Exception:
            pass
    tx = current_app.config['transactions'].find_one({'_id': tx['_id']})
    ensure_receipt(tx)

def _parse_client_iso(s):
    try:
        s2 = (s or '').strip()
        if not s2:
            return None
        if s2.endswith('Z'):
            s2 = s2[:-1]
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None

@admin_bp.route('/admin_panel', methods=['GET'])
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
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/metrics', methods=['GET'])
@admin_required
def admin_metrics():
    try:
        now = datetime.utcnow()
        def sum_range(start_dt):
            pipe = [
                {'$match': {'activated_at': {'$gte': start_dt, '$lte': now}}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount_cents'}, 'count': {'$sum': 1}}}
            ]
            agg = list(current_app.config['transactions'].aggregate(pipe))
            if agg:
                return int(agg[0].get('total', 0)), int(agg[0].get('count', 0))
            return 0, 0
        def sum_all():
            pipe = [
                {'$match': {'activated_at': {'$exists': True, '$lte': now}}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount_cents'}, 'count': {'$sum': 1}}}
            ]
            agg = list(current_app.config['transactions'].aggregate(pipe))
            if agg:
                return int(agg[0].get('total', 0)), int(agg[0].get('count', 0))
            return 0, 0
        start_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        t_total, t_count = sum_range(start_today)
        d7 = now - timedelta(days=7)
        d7_total, d7_count = sum_range(d7)
        d30 = now - timedelta(days=30)
        d30_total, d30_count = sum_range(d30)
        all_total, all_count = sum_all()
        pending = current_app.config['transactions'].count_documents({'payment_status': {'$nin': list(PAID_STATUSES | FAILED_STATUSES)}})
        paid = current_app.config['transactions'].count_documents({'payment_status': {'$in': list(PAID_STATUSES)}})
        failed = current_app.config['transactions'].count_documents({'payment_status': {'$in': list(FAILED_STATUSES)}})
        return jsonify(ok=True, revenue_today_cents=t_total, revenue_7d_cents=d7_total, revenue_30d_cents=d30_total, revenue_all_time_cents=all_total, count_today=t_count, count_7d=d7_count, count_30d=d30_count, count_all_time=all_count, tx_counts={'pending': pending, 'paid': paid, 'failed': failed})
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/transactions', methods=['GET'])
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
            if status == 'pending':
                q['payment_status'] = {'$nin': list(PAID_STATUSES | FAILED_STATUSES)}
            else:
                q['payment_status'] = status
        if plan:
            q['plan'] = plan
        if date_from:
            dtf = _parse_client_iso(date_from)
            if dtf:
                q['created_at'] = q.get('created_at', {})
                q['created_at']['$gte'] = dtf
        if date_to:
            dtt = _parse_client_iso(date_to)
            if dtt:
                q['created_at'] = q.get('created_at', {})
                q['created_at']['$lte'] = dtt
        if text:
            patt = re.escape(text)
            q['$or'] = [{'hash': {'$regex': patt, '$options': 'i'}}, {'username': {'$regex': patt, '$options': 'i'}}]
        page = max(1, int(request.args.get('page', '1')))
        size = max(1, min(100, int(request.args.get('page_size', '20'))))
        skip = (page - 1) * size
        total = current_app.config['transactions'].count_documents(q)
        cur = current_app.config['transactions'].find(q).sort('created_at', -1).skip(skip).limit(size)
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
                'failed_at': t.get('failed_at').isoformat() if t.get('failed_at') else None,
                'has_receipt': bool(t.get('receipt')),
                'receipt_id': (t.get('receipt') or {}).get('receipt_id') if t.get('receipt') else None
            })
        return jsonify(ok=True, total=total, page=page, page_size=size, items=items)
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/transactions/<tid>', methods=['DELETE', 'PATCH'])
@admin_required
def admin_tx_modify(tid):
    try:
        try:
            oid = ObjectId(tid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        if request.method == 'DELETE':
            current_app.config['transactions'].delete_one({'_id': oid})
            return jsonify(ok=True)
        data = request.get_json(silent=True) or {}
        updates = {}
        ps = data.get('payment_status')
        if isinstance(ps, str) and ps:
            updates['payment_status'] = ps.lower()
            updates['updated_at'] = datetime.utcnow()
        if not updates:
            return jsonify(ok=False, error='no_updates'), 400
        tx = current_app.config['transactions'].find_one({'_id': oid})
        if not tx:
            return jsonify(ok=False, error='not_found'), 404
        current_app.config['transactions'].update_one({'_id': oid}, {'$set': updates})
        tx = current_app.config['transactions'].find_one({'_id': oid})
        if (tx.get('payment_status') or '').lower() in PAID_STATUSES:
            try_activation(tx)
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/transactions/<tid>/receipt', methods=['GET'])
@admin_required
def admin_tx_receipt(tid):
    try:
        try:
            oid = ObjectId(tid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        tx = current_app.config['transactions'].find_one({'_id': oid})
        if not tx:
            return jsonify(ok=False, error='not_found'), 404
        st = (tx.get('payment_status') or '').lower()
        if st not in PAID_STATUSES:
            return jsonify(ok=False, error='not_paid'), 400
        if not tx.get('receipt'):
            ensure_receipt(tx)
            tx = current_app.config['transactions'].find_one({'_id': oid})
        return jsonify(ok=True, receipt=tx.get('receipt'))
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/users', methods=['GET'])
@admin_required
def admin_users_list():
    try:
        text = (request.args.get('q') or '').strip()
        adm = request.args.get('admin')
        disabled = request.args.get('disabled')
        q = {}
        if text:
            patt = re.escape(text)
            q['$or'] = [{'username': {'$regex': patt, '$options': 'i'}}, {'email': {'$regex': patt, '$options': 'i'}}]
        if adm in ('yes', 'no'):
            q['admin_permission'] = adm
        if disabled in ('true', 'false'):
            q['disabled'] = (disabled == 'true')
        page = max(1, int(request.args.get('page', '1')))
        size = max(1, min(100, int(request.args.get('page_size', '20'))))
        skip = (page - 1) * size
        total = current_app.config['users'].count_documents(q)
        cur = current_app.config['users'].find(q).sort('created_at', -1).skip(skip).limit(size)
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
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/users/summary', methods=['GET'])
@admin_required
def admin_users_summary():
    try:
        total = current_app.config['users'].count_documents({})
        total_subscribers = current_app.config['users'].count_documents({'plans': {'$in': ['essencial', 'profissional', 'vitalicio']}})
        return jsonify(ok=True, total=total, subscribers=total_subscribers)
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/users/<uid>/set_admin', methods=['POST'])
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
        current_app.config['users'].update_one({'_id': oid}, {'$set': {'admin_permission': val}})
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/users/<uid>/disable', methods=['POST'])
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
        current_app.config['users'].update_one({'_id': oid}, {'$set': {'disabled': bool(data.get('disabled'))}})
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/users/<uid>/force_logout', methods=['POST'])
@admin_required
def admin_user_force_logout(uid):
    try:
        try:
            oid = ObjectId(uid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        current_app.config['users'].update_one({'_id': oid}, {'$set': {'force_logout_at': datetime.utcnow()}})
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/users/<uid>/reset_password', methods=['POST'])
@admin_required
def admin_user_reset_password(uid):
    try:
        data = request.get_json(silent=True) or {}
        pw = data.get('new_password')
        if not isinstance(pw, str) or not pw:
            return jsonify(ok=False, error='invalid_value'), 400
        try:
            oid = ObjectId(uid)
        except Exception:
            return jsonify(ok=False, error='invalid_id'), 400
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, 200000)
        current_app.config['users'].update_one({'_id': oid}, {'$set': {'password_algo': 'pbkdf2_sha256', 'password_salt': salt.hex(), 'password_hash': dk.hex(), 'password_updated_at': datetime.utcnow()}})
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False, error='internal_error'), 500

@admin_bp.route('/admin/api/plans', methods=['GET', 'PUT'])
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
        return jsonify(ok=False, error='internal_error'), 500
