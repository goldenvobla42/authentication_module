import os
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class AuthModuleAsym:
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key or rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = public_key or self.private_key.public_key()

    def create_token(self, user_id, roles=None, expiry_time_minutes=30):
        expiry_time = datetime.now() + timedelta(minutes=expiry_time_minutes)
        payload = {
            "user_id": user_id,
            "roles": roles or [],
            "exp": expiry_time.timestamp()
        }
        return jwt.encode(payload, self.private_key, algorithm="RS512")

    def validate_token(self, token):
        try:
            payload = jwt.decode(token, self.public_key, algorithms=["RS512"])
            expiry_time = datetime.fromtimestamp(payload["exp"])
            return expiry_time > datetime.now()
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False

    def validate_token_role(self, token, role):
        try:
            payload = jwt.decode(token, self.public_key, algorithms=["RS512"])
            expiry_time = payload.get("exp")
            if role not in payload["roles"]:
                return False
            expiry_time = datetime.fromtimestamp(payload["exp"])
            return expiry_time > datetime.now()
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
