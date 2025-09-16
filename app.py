from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import traceback
import math # Importamos a biblioteca de matemática

app = Flask(__name__)

# --- Credenciais e Configurações ---
ACCOUNT_ID = "RE_simpremium"
SIGN_KEY = "3GIJ0119BNP3G6UN6A5I6BB4PZS2QVWQ"
SECRET_KEY = "UYHUR49SEVWFR6WI"
VECTOR = "OQ75CK0MYKQDKC0O" # Corrigido conforme sua última informação
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

# --- NOVA ROTA OTIMIZADA PARA BUSCAR TUDO ---
@app.route('/get_all_plans', methods=['POST'])
def get_all_esim_plans():
    all_plans = []
    try:
        # Passo 1: Fazer a primeira chamada para descobrir o total
        service_name = "queryEsimProductListByParams"
        endpoint = "productApi/queryEsimProductListByParams"
        
        data_payload = {"page": 1, "pageSize": 100, "lang": "en"}
        data_str = json.dumps(data_payload)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name, request_time, encrypted_data)
        
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(BASE_URL + endpoint, data=json.dumps(final_payload), headers=headers, timeout=30)
        response.raise_for_status()
        response_json = response.json()

        if response_json.get("code") != "0000":
            return jsonify({"error": "Failed on first API call", "details": response_json}), 400

        decrypted_data = json.loads(aes_decrypt(response_json["data"]))
        total_records = decrypted_data.get("total", 0)
        
        if total_records == 0:
            return jsonify({"total": 0, "data": []}), 200
        
        all_plans.extend(decrypted_data.get("data", []))
        total_pages = math.ceil(total_records / 100)

        # Passo 2: Fazer o loop para as páginas restantes
        for page_num in range(2, total_pages + 1):
            data_payload["page"] = page_num
            data_str = json.dumps(data_payload)
            encrypted_data = aes_encrypt(data_str)
            request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            sign = create_signature(service_name, request_time, encrypted_data)
            final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
            
            response = requests.post(BASE_URL + endpoint, data=json.dumps(final_payload), headers=headers, timeout=30)
            response.raise_for_status()
            response_json = response.json()
            
            if response_json.get("code") == "0000":
                page_data = json.loads(aes_decrypt(response_json["data"]))
                all_plans.extend(page_data.get("data", []))

        return jsonify({"total": total_records, "data": all_plans}), 200

    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /get_all_plans !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# As outras rotas (/create_order, /decrypt_notification) continuam aqui sem alterações.
# (O código completo das outras rotas que já fizemos continua aqui embaixo)
# ...
