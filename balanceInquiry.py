#!/usr/bin/env python3
"""UBL SOA Proxy - Balance Inquiry (same pattern as UpdatedProxy, stdlib + openssl only)"""

# ============ CONFIGURATION - CHANGE THESE ============
PORT = 443
PASSWORD = 'ainext123'
PUBLIC_KEY = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdXh2VbzkwRMDTwn7zM9NfOhTfmYREP5Pf5/Kj14bfhstRBF5Fz3YR97bPyGRxfzGIpEXybCQxm0USC3Ib8HIjDZM3VrW//c2P0R8EJaM9XxuOfXRnyi+ADKlSQQZ4md3PcLAToPwTQ2U9RabDjT/O3gdQp6ocaIAyXcgj8pmCuQIDAQAB'
CA_CERT = '/etc/ssl/ubl/ubl-ca-chain.pem'  # UBL CA certificate chain

# Balance inquiry specific
ACCOUNT_NUMBER = '187201007756'
ACCOUNT_TYPE = '20'
ACCOUNT_CURRENCY = '586'
APP_CODE = 'BALINQ'
WORKSTATION = 'tdl-mobile-app'
SCREEN_NO = 'DA'
SOURCE_USER_ID = 'FOREE852741'
BRANCH_CODE = '0605'
BRANCH_NAME = 'UBL CBS'
# ======================================================

import base64, os, subprocess, tempfile, time, random, json, ssl, uuid, http.client, http.server
from datetime import datetime

def encrypt(ref_id):
    pwd_str = f"{PASSWORD}:{ref_id}"
    key = os.urandom(32)
    p = subprocess.run(['openssl','enc','-aes-256-ecb','-K',key.hex(),'-nosalt'],
                       input=pwd_str.encode(), capture_output=True, check=True)
    enc_pwd = base64.b64encode(p.stdout).decode()
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.der') as f:
        f.write(base64.b64decode(PUBLIC_KEY))
        der_file = f.name
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
        pem_file = f.name
    subprocess.run(['openssl','rsa','-pubin','-inform','DER','-in',der_file,'-outform','PEM','-out',pem_file],
                   check=True, capture_output=True)
    p = subprocess.run(['openssl','pkeyutl','-encrypt','-pubin','-inkey',pem_file,'-pkeyopt','rsa_padding_mode:pkcs1'],
                       input=key, capture_output=True, check=True)
    os.unlink(der_file)
    os.unlink(pem_file)
    return enc_pwd, base64.b64encode(p.stdout).decode()

def call_api():
    ref = str(uuid.uuid4())
    pwd, auth = encrypt(ref)
    payload = {
        'serviceHeader': {
            'channel': 'AINEXT',
            'processingType': 'SYNC',
            'authInfo': {
                'username': 'AINEXT',
                'password': pwd,
                'authenticationType': 'type1',
                'authKey': auth
            },
            'parameters': {},
            'fromRegionInfo': {'bicCode': 'UNILPKKA', 'countryCode': 'PAKISTAN'},
            'toRegionInfo': {'bicCode': '', 'countryCode': ''}
        },
        'transactionInfo': {
            'transactionDate': datetime.now().strftime('%Y-%m-%d'),
            'transactionTime': datetime.now().strftime('%H:%M:%S'),
            'transactionType': 'BALANCE_INQUIRY',
            'referenceId': ref,
            'stan': str(random.randint(100000, 999999)),
            'transmissionDateTime': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            'attributeList': [
                {'attributeKey': 'appCode', 'attributeValue': APP_CODE},
                {'attributeKey': 'workstation', 'attributeValue': WORKSTATION},
                {'attributeKey': 'screenNo', 'attributeValue': SCREEN_NO},
                {'attributeKey': 'sourceUserId', 'attributeValue': SOURCE_USER_ID}
            ]
        },
        'balanceInquiryRequest': {
            'accountDetail': {
                'accountIdentifier': {'accountNumber': ACCOUNT_NUMBER},
                'accountType': ACCOUNT_TYPE,
                'accountCurrency': ACCOUNT_CURRENCY,
                'branchInfo': {
                    'bankInfo': {'name': 'United Bank Limited', 'bankIMD': '588974'},
                    'branchCode': BRANCH_CODE,
                    'branchName': BRANCH_NAME,
                    'telephoneNumber': '0',
                    'branchAddress': {
                        'country': 'Pakistan',
                        'state': 'Sindh',
                        'city': 'Karachi',
                        'zipCode': '74800',
                        'addressLine': 'Shaheed-e-millat Road'
                    }
                }
            }
        }
    }
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.load_verify_locations(CA_CERT)
    ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
    conn = http.client.HTTPSConnection('soatest.ubl.com.pk', 7857, context=ctx, timeout=30)
    conn.request('POST', '/balanceinquiry/v1/single', json.dumps(payload), {'Content-Type': 'application/json'})
    r = conn.getresponse()
    data = json.loads(r.read().decode())
    conn.close()
    return {'success': r.status == 200, 'data': data, 'referenceId': ref}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == '/balance':
            try:
                res = call_api()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(res).encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'error': str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    do_POST = do_GET

if __name__ == '__main__':
    print(f"Server running on port {PORT}\nCall: curl http://localhost:{PORT}/balance")
    http.server.HTTPServer(('0.0.0.0', PORT), H).serve_forever()
