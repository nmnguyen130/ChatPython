import base64
from crypto_utils import CryptoUtils
import json
import os
import datetime

class UserAuth:
    def __init__(self, users_file='users.json'):
        self.users_file = users_file
        self.users = self._load_users()
    
    def _load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)
    
    def register_user(self, username, password):
        if not username or not password:
            raise ValueError("Username and password are required")
        
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
            
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters")
        
        if username in self.users:
            raise ValueError("Username already exists")
        
        if not username.replace('_', '').isalnum():
            raise ValueError("Username can only contain letters, numbers, and underscores")
        
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one number")
        
        key, salt = CryptoUtils.hash_password(password)
        self.users[username] = {
            'key': key.decode(),
            'salt': base64.b64encode(salt).decode(),
            'created_at': datetime.datetime.now().isoformat()
        }
        self._save_users()
        return True
    
    def authenticate_user(self, username, password):
        if not username or not password:
            raise ValueError("Username and password are required")
        
        if username not in self.users:
            raise ValueError("Invalid username or password")
        
        user_data = self.users[username]
        stored_key = user_data['key'].encode()
        salt = base64.b64decode(user_data['salt'].encode())
        
        if not CryptoUtils.verify_password(password, stored_key, salt):
            raise ValueError("Invalid username or password")
        
        return True
