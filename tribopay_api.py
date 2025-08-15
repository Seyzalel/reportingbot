import sys, re, json, requests

API_TOKEN = "UcsGgIwEkBW5FrLbjtJbVkSda7fOrSk2paZ8sIYqYwKBEpORYWSiupTG58n4"
OFFER_HASH = "fjthlgwzum"
PRODUCT_HASH = "sixft0cqgo"
DEFAULT_AMOUNT_CENTS = 11900

API_URL = f"https://api.tribopay.com.br/api/public/v1/transactions?api_token={API_TOKEN}"
HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}

def parse_amount(argv):
    if len(argv) < 2:
        return DEFAULT_AMOUNT_CENTS
    raw = argv[1].strip().replace("R$", "").strip().replace(",", ".")
    if not re.match(r"^\d+(\.\d{1,2})?$", raw):
        print("Valor inválido"); sys.exit(2)
    return int(round(float(raw) * 100))

def build_payload(amount_cents):
    return {
        "amount": amount_cents,
        "offer_hash": OFFER_HASH,
        "payment_method": "pix",
        "installments": 1,
        "customer": {
            "name": "João Silva",
            "email": "joao@email.com",
            "phone_number": "21999999999",
            "document": "09115751031",
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
                "product_hash": PRODUCT_HASH,
                "title": "Curso de Programação",
                "cover": None,
                "price": amount_cents,
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
        "postback_url": "https://meusite.com/webhook/tribopay"
    }

def extract_values(d):
    link = None
    copia = None
    if isinstance(d, dict):
        p = d.get("pix") or {}
        link = p.get("pix_url") or p.get("url") or d.get("pix_url")
        copia = p.get("pix_qr_code") or p.get("copy_and_paste") or p.get("emv") or d.get("pix_qr_code")
    return link, copia

def main():
    amount = parse_amount(sys.argv)
    payload = build_payload(amount)
    try:
        r = requests.post(API_URL, headers=HEADERS, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
    except requests.HTTPError as e:
        body = ""
        if e.response is not None:
            try: body = json.dumps(e.response.json(), ensure_ascii=False, indent=2)
            except Exception: body = e.response.text or ""
        print(body or str(e)); sys.exit(1)
    except Exception as e:
        print(str(e)); sys.exit(1)
    link, copia = extract_values(data)
    if link: print(link)
    if copia: print(copia)
    if not link and not copia:
        print(json.dumps(data, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()