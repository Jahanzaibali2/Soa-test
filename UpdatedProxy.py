#!/usr/bin/env python3
"""UBL SOA Proxy - One file, no dependencies (Python stdlib + openssl only)"""

# ============ CONFIGURATION - CHANGE THESE ============
PORT = 443
PAN = '540375******5663'
EXPIRY = '0131'
CNIC = '3740526710805'
CUSTOMER_ID = '3740526710805'
PASSWORD = 'ainext123'
PUBLIC_KEY = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD2V+edgdxR2tajv/8T0PcLlBSk3E681QcrnDwz+eLbH7zKopLK4bNjD/lEe6dZt8vNER0SEfbA6JYaKUzwuKplbFe3eEyhgufMWf53AqfJ/3scT+brOjkyol696F+HVPCKkxIAeaX+HIu4EjQNyiybTQ1zMZrRFpd5NjWskNCAqQIDAQAB'
CA_CERT = '/etc/ssl/ubl/ubl-ca-chain.pem'  # UBL CA certificate chain
# ======================================================

import base64, os, subprocess, tempfile, time, random, json, ssl, http.client, http.server
from datetime import datetime
from urllib.parse import urlparse

def encrypt(ref_id):
    pwd_str = f"{PASSWORD}:{ref_id}"
    key = os.urandom(32)
    # AES encrypt - using AES-256-ECB (matches AES/ECB/PKCS5Padding in Java)
    p = subprocess.run(['openssl','enc','-aes-256-ecb','-K',key.hex(),'-nosalt'], 
                       input=pwd_str.encode(), capture_output=True, check=True)
    enc_pwd = base64.b64encode(p.stdout).decode()
    # RSA encrypt - Convert X509 DER to PEM format first, then encrypt with PKCS1 padding
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.der') as f:
        f.write(base64.b64decode(PUBLIC_KEY))
        der_file = f.name
    # Convert DER to PEM format
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
        pem_file = f.name
    subprocess.run(['openssl','rsa','-pubin','-inform','DER','-in',der_file,'-outform','PEM','-out',pem_file], 
                   check=True, capture_output=True)
    # Encrypt with RSA using PKCS1 padding (matches RSA/ECB/PKCS1Padding in Java)
    p = subprocess.run(['openssl','pkeyutl','-encrypt','-pubin','-inkey',pem_file,'-pkeyopt','rsa_padding_mode:pkcs1'],
                       input=key, capture_output=True, check=True)
    os.unlink(der_file)
    os.unlink(pem_file)
    return enc_pwd, base64.b64encode(p.stdout).decode()

def call_api():
    ref = f"{int(time.time()*1000)}{random.randint(100000,999999)}"
    pwd, auth = encrypt(ref)
    payload = {
        'serviceHeader': {'channel':'AINEXT','processingType':'SYNC',
            'authInfo':{'username':'AINEXT','password':pwd,'authenticationType':'type1','authKey':auth},
            'parameters':{},'fromRegionInfo':{'bicCode':'UNILPKKA','countryCode':'PAKISTAN'},
            'toRegionInfo':{'bicCode':'','countryCode':''}},
        'transactionInfo': {'transactionDate':datetime.now().strftime('%Y-%m-%d'),
            'transactionTime':datetime.now().strftime('%H:%M:%S'),'transactionType':'DEBIT_CARD',
            'transactionSubType':'ACTIVATION','referenceId':ref,'stan':str(random.randint(100000,999999)),
            'transmissionDateTime':datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            'attributeList':[{'attributeKey':'customerId','attributeValue':CUSTOMER_ID}]},
        'activationRequest':{'pan':PAN,'expiry':EXPIRY,'isMaskCard':'Y','cnic':CNIC}}
    # SSL context with TLSv1.2 and specific cipher (matching curl command)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.load_verify_locations(CA_CERT)
    ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
    conn = http.client.HTTPSConnection('soatest.ubl.com.pk',7857,context=ctx,timeout=30)
    conn.request('POST','/debitcardmanagementservice/v1/activation',json.dumps(payload),{'Content-Type':'application/json'})
    r = conn.getresponse()
    data = json.loads(r.read().decode())
    conn.close()
    return {'success':r.status==200,'data':data,'referenceId':ref}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_GET(self):
        if self.path=='/activate':
            try:
                res = call_api()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.end_headers()
                self.wfile.write(json.dumps(res).encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({'success':False,'error':str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    do_POST = do_GET

if __name__=='__main__':
    print(f"Server running on port {PORT}\nCall: curl http://localhost:{PORT}/activate")
    http.server.HTTPServer(('0.0.0.0',PORT),H).serve_forever()
