from cryptography.fernet import Fernet
import os
import json

KEY_FILE = 'scan_secret.key'

def generate_key():
    """
    Generate a new encryption key and save to key file.
    """
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

def load_key():
    """
    Load encryption key from file, generate one if not present.
    """
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, 'rb') as f:
        return f.read()

fernet = Fernet(load_key())

def encrypt_data(data_bytes):
    """
    Encrypt bytes with Fernet key.
    """
    return fernet.encrypt(data_bytes)

def decrypt_data(encrypted_bytes):
    """
    Decrypt bytes with Fernet key.
    """
    return fernet.decrypt(encrypted_bytes)

def save_results_json_encrypted(filename, data):
    """
    Serialize JSON data and encrypt save to filename.
    """
    json_bytes = json.dumps(data, indent=4).encode('utf-8')
    encrypted_data = encrypt_data(json_bytes)
    with open(filename, 'wb') as f:
        f.write(encrypted_data)

def load_results_json_encrypted(filename):
    """
    Load and decrypt encrypted JSON file, return Python data.
    """
    with open(filename, 'rb') as f:
        encrypted_data = f.read()
    decrypted_bytes = decrypt_data(encrypted_data)
    return json.loads(decrypted_bytes.decode('utf-8'))
