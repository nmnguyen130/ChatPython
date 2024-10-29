from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class CryptoUtils:
    @staticmethod
    def generate_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def verify_password(password: str, stored_key: bytes, salt: bytes):
        new_key, _ = CryptoUtils.hash_password(password, salt)
        return new_key == stored_key
    
    @staticmethod
    def generate_symmetric_key():
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_message(message: str, key: bytes):
        f = Fernet(key)
        return f.encrypt(message.encode())
    
    @staticmethod
    def decrypt_message(encrypted_message: bytes, key: bytes):
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode()
    
    @staticmethod
    def sign_message(message: bytes, private_key):
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(message: bytes, signature: bytes, public_key):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False