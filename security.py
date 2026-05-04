import hashlib
import os
from cryptography.fernet import Fernet
import base64
import json
from datetime import datetime

class SecurityManager:
    def __init__(self):
        # Generate or use existing key (in production, store in environment variable)
        key_file = 'encryption.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            self.encryption_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
        
        self.cipher = Fernet(self.encryption_key)
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password, hash_value):
        """Verify password against hash"""
        return self.hash_password(password) == hash_value
    
    def encrypt_data(self, data):
        """Encrypt sensitive medical data"""
        if not data:
            return ""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            encrypted = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"Encryption error: {e}")
            return ""
    
    def decrypt_data(self, encrypted_data):
        """Decrypt medical data"""
        if not encrypted_data:
            return ""
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return ""
    
    def decrypt_record_data(self, encrypted_json):
        """Decrypt structured record data"""
        try:
            decrypted = self.decrypt_data(encrypted_json)
            if decrypted:
                return json.loads(decrypted)
            return {}
        except:
            return {}
    
    def encrypt_record_data(self, diagnosis, prescription, notes):
        """Encrypt record data into JSON"""
        data = {
            'diagnosis': diagnosis,
            'prescription': prescription,
            'notes': notes,
            'timestamp': datetime.now().isoformat()
        }
        return self.encrypt_data(data)

security = SecurityManager()

# Export functions
hash_password = security.hash_password
verify_password = security.verify_password
encrypt_data = security.encrypt_data
decrypt_data = security.decrypt_data
encrypt_record_data = security.encrypt_record_data
decrypt_record_data = security.decrypt_record_data