import json
from crypto_utils import CryptoUtils
import base64

class Message:
    def __init__(self, sender, content, signature=None):
        self.sender = sender
        self.content = content
        self.signature = signature

    def encrypt(self, symmetric_key):
        self.content = base64.b64encode(
            CryptoUtils.encrypt_message(self.content, symmetric_key)
        ).decode()
        
    def decrypt(self, symmetric_key):
        self.content = CryptoUtils.decrypt_message(
            base64.b64decode(self.content.encode()),
            symmetric_key
        )
    
    def sign(self, private_key):
        message_bytes = self.content.encode()
        self.signature = base64.b64encode(
            CryptoUtils.sign_message(message_bytes, private_key)
        ).decode()
    
    def verify(self, public_key):
        message_bytes = self.content.encode()
        signature_bytes = base64.b64decode(self.signature.encode())
        return CryptoUtils.verify_signature(message_bytes, signature_bytes, public_key)

    def to_json(self):
        return json.dumps({
            'sender': self.sender,
            'content': self.content,
            'signature': self.signature
        })

    @staticmethod
    def from_json(json_str):
        data = json.loads(json_str)
        return Message(
            data['sender'],
            data['content'],
            data.get('signature')
        )

    def __str__(self):
        return f"{self.sender}: {self.content}"