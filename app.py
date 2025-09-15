from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Inicia o servidor web
app = Flask(__name__)

# --- Suas Credenciais do Ambiente de Teste (as mesmas de antes) ---
ACCOUNT_ID = "tgt_api_test"
SIGN_KEY = "ECCB3EBA090A4AE082C49DA66B114892"
SECRET_KEY = "DB81255FC06344F3"
VECTOR = "96461F19FC7E57FB"
API_VERSION = "1.0"
BASE_URL = "http://enterpriseapiuat.tugegroup.com:8060/api-publicappmodule/"

# --- Funções de Criptografia (sem alterações) ---
def aes_encrypt(data_str):
    key = SECRET_KEY.encode('utf-8')
    iv = VECTOR.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_str.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    return ''.join([f"{chr(((b >> 4) & 0xF) + ord('a'))}{chr(((b & 0xF) + ord('a')))}" for b in encrypted_bytes])

def aes_decrypt(encrypted_hex):
    key = SECRET_KEY.encode('utf-8')
    iv = VECTOR.encode('utf-8')
    encrypted_bytes = bytes([((ord(encrypted_hex[i]) - ord('a')) << 4) + (ord(encrypted_hex[i+1]) - ord('a')) for i in range(0, len(encrypted_hex), 2)])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
    unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size)
    return unpadded_bytes.decode('utf-8')

def create_signature(service_name, request_time, encrypted_data):
    raw_string = f"{ACCOUNT_ID}{service_name}{request_time}{encrypted_data}{API_VERSION}{SIGN_KEY}"
    md5_hash = hashlib.md5(raw_string.encode('utf-8')).hexdigest()
    return md5_hash

# --- Rota Principal da nossa API ---
# O Make.com irá chamar este endereço.
@app.route('/get_plans', methods=['POST'])
def get_esim_plans():
    try:
        request_body = request.get_json() or {}
        service_name = "queryEsimProductListByParams"
        endpoint = "productApi/queryEsimProductListByParams"
        
        data_payload = {
            "page": request_body.get("page", 1),
            "pageSize": request_body.get("pageSize", 100),
            "productType": request_body.get("productType", ""),
            "lang": request_body.get("lang", "en")
        }

        data_str = json.dumps(data_payload)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name, request_time, encrypted_data)

        final_payload = {
            "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time,
            "data": encrypted_data, "version": API_VERSION, "sign": sign
        }
        
        headers = {'Content-Type': 'application/json'}
        response = requests.post(BASE_URL + endpoint, data=json.dumps(final_payload), headers=headers, timeout=20)
        response.raise_for_status()
        
        response_json = response.json()
        
        if response_json.get("code") == "0000":
            decrypted_data = aes_decrypt(response_json["data"])
            return jsonify(json.loads(decrypted_data)), 200
        else:
            return jsonify({"error": response_json}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)