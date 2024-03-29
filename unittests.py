import os
import unittest
from authmodule import AuthModule
from datetime import datetime, timedelta
import jwt


class TestAuthModule(unittest.TestCase):
    def setUp(self):
        self.secret_key = os.getenv("SECRET_KEY")
        self.auth_module = AuthModule(self.secret_key)

    def test_create_token(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time_minutes = 30
        token = self.auth_module.create_token(user_id, roles, expiry_time_minutes)
        self.assertIsNotNone(token)

    def test_validate_token_valid(self):
        user_id = "user123"
        roles = ["admin"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, self.secret_key, algorithm="HS512")
        is_valid = self.auth_module.validate_token(token, user_id, "admin")
        self.assertTrue(is_valid)

    def test_validate_token_invalid_user_id(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, self.secret_key, algorithm="HS512")
        is_valid = self.auth_module.validate_token(token, "invalid_user_id", "admin")
        self.assertFalse(is_valid)

    def test_validate_token_invalid_role(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, self.secret_key, algorithm="HS512")
        is_valid = self.auth_module.validate_token(token, user_id, "invalid_role")
        self.assertFalse(is_valid)

    def test_validate_token_expired(self):
        user_id = "user123"
        roles = "user"
        expiry_time = datetime.now() - timedelta(seconds=1)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, self.secret_key, algorithm="HS512")
        is_valid = self.auth_module.validate_token(token, user_id, "admin")
        self.assertFalse(is_valid)

    def test_validate_token_invalid_signature(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, "invalid_secret_key", algorithm="HS512")
        is_valid = self.auth_module.validate_token(token, user_id, "admin")
        self.assertFalse(is_valid)


if __name__ == "__main__":
    unittest.main()
