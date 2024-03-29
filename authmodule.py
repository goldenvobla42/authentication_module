import os
import jwt
from datetime import datetime, timedelta


class AuthModule:
    def __init__(self, secret_key):
        self.secret_key = os.getenv("SECRET_KEY")

    def create_token(self, user_id, roles, expiry_time_minutes=30):
        expiry_time = datetime.now() + timedelta(minutes=expiry_time_minutes)
        payload = {
            "user_id": user_id,
            "roles": roles or [],
            "exp": expiry_time
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS512").encode()

    def validate_token(self, token, user_id, role):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS512"])
            if payload["user_id"] != user_id or role not in payload["roles"]:
                return False
            expiry_time = datetime.fromtimestamp(payload["exp"])
            return expiry_time > datetime.now()
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
