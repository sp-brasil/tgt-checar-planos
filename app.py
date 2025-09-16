from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import traceback # Importamos esta biblioteca para logs detalhados

app = Flask(__name__)

# --- Credenciais e Configurações (sem alterações) ---
ACCOUNT_ID = "RE_simpremium"
SIGN_KEY = "3GIJ0119BNP3G6UN6A5I6BB4PZS2QVWQ"
SECRET_KEY = "UYHUR49SEVWFR6WI"
VECTOR = "0Q75CKOMYKQDKCOO"
API_VERSION = "1.0"
BASE_URL = "http://enterpriseapi.tugegroup.com:8060/api-publicappmodule/"

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

# --- Rota para Consultar Planos ---
@app.route('/get_plans', methods=['POST'])
def get_esim_plans():
    try:
        request_body = request.get_json() or {}
        service_name = "queryEsimProductListByParams"
        endpoint = "productApi/queryEsimProductListByParams"
        data_payload = { "page": request_body.get("page", 1), "pageSize": request_body.get("pageSize", 100), "productType": request_body.get("productType", ""), "lang": request_body.get("lang", "en") }
        data_str = json.dumps(data_payload)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name, request_time, encrypted_data)
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
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
        # ******** ALTERAÇÃO AQUI ********
        print("!!!!!!!!!! ERRO DETALHADO EM /get_plans !!!!!!!!!!")
        traceback.print_exc() # Imprime o erro completo no log
        return jsonify({"error": str(e)}), 500

# --- Rota para Criar Pedidos ---
@app.route('/create_order', methods=['POST'])
def create_esim_order():
    try:
        # ... (código existente, sem necessidade de colar aqui) ...
        request_body = request.get_json()
        if not request_body:
            return jsonify({"error": "Request body is missing or not JSON"}), 400
        product_code = request_body.get("productCode")
        notify_url = request_body.get("notifyUrl")
        if not product_code or not notify_url:
            return jsonify({"error": "Missing required fields: productCode and notifyUrl"}), 400
        service_name = "openCard"
        endpoint = "saleOrderApi/openCard"
        data_payload = { "productCode": product_code, "currency": request_body.get("currency", "USD"), "startDate": request_body.get("startDate", ""), "lang": request_body.get("lang", "en"), "otaOrderNo": request_body.get("otaOrderNo", ""), "email": request_body.get("email", ""), "notifyUrl": notify_url, "iccidAmount": 1, "requestId": request_body.get("requestId", "") }
        data_str = json.dumps(data_payload)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name, request_time, encrypted_data)
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
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
        # ******** ALTERAÇÃO AQUI ********
        print("!!!!!!!!!! ERRO DETALHADO EM /create_order !!!!!!!!!!")
        traceback.print_exc() # Imprime o erro completo no log
        return jsonify({"error": str(e)}), 500

# --- Rota para Descriptografar Notificações ---
@app.route('/decrypt_notification', methods=['POST'])
def decrypt_notification():
    try:
        request_body = request.get_json()
        encrypted_data = request_body.get("data")
        if not encrypted_data:
            return jsonify({"error": "Missing 'data' field to decrypt"}), 400
        decrypted_data = aes_decrypt(encrypted_data)
        return jsonify(json.loads(decrypted_data)), 200
    except Exception as e:
        # ******** ALTERAÇÃO AQUI ********
        print("!!!!!!!!!! ERRO DETALHADO EM /decrypt_notification !!!!!!!!!!")
        traceback.print_exc() # Imprime o erro completo no log
        return jsonify({"error": "Decryption failed", "details": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)
