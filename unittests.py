import os
import unittest
from unittest.mock import patch
from authmodule import AuthModule
from authmodule_asym import AuthModuleAsym
from datetime import datetime, timedelta
import jwt


class TestAuthModule(unittest.TestCase):
    def setUp(self):
        self.secret_key = os.getenv("SECRET_KEY")
        self.authmodule = AuthModule(self.secret_key)


    def test_create_token(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time_minutes = 30
        token = self.authmodule.create_token(user_id, roles, expiry_time_minutes)
        self.assertIsNotNone(token)

    def test_validate_token_valid(self):
        user_id = "user123"
        roles = ["admin"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, self.secret_key, algorithm="HS512")
        is_valid = self.authmodule.validate_token(token)
        self.assertTrue(is_valid)

    def test_validate_token_role_valid(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, self.secret_key, algorithm="HS512")
        is_valid = self.authmodule.validate_token_role(token, "admin")
        self.assertTrue(is_valid)

    def test_validate_token_role_invalid(self):
        user_id = "user123"
        roles = ["user"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, self.secret_key, algorithm="HS512")
        is_valid = self.authmodule.validate_token_role(token, "admin")
        self.assertFalse(is_valid)

    def test_validate_token_expired(self):
        user_id = "123"
        roles = ["admin", "user"]
        expiry_time = datetime.now() - timedelta(minutes=31)
        with patch("authmodule.datetime") as mock_datetime:
            mock_datetime.now.return_value = expiry_time
            token = self.authmodule.create_token(user_id, roles)
        valid = self.authmodule.validate_token(token)
        self.assertFalse(valid, "Token should be invalid due to expiration")


    def test_validate_token_invalid_signature(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time = datetime.now() + timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "roles": roles, "exp": expiry_time}, "invalid_secret_key", algorithm="HS512")
        is_valid = self.authmodule.validate_token(token)
        self.assertFalse(is_valid)

class TestAuthModuleAsym(unittest.TestCase):
    def setUp(self):
        self.auth_module_asym = AuthModuleAsym()
    def test_create_token(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time_minutes = 30
        token = self.auth_module_asym.create_token(user_id, roles, expiry_time_minutes)
        self.assertIsNotNone(token)

    def test_validate_token_valid(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time_minutes = 30
        token = self.auth_module_asym.create_token(user_id, roles, expiry_time_minutes)
        is_valid = self.auth_module_asym.validate_token(token)
        self.assertTrue(is_valid)

    def test_validate_token_expired(self):
        user_id = "user123"
        roles = ["admin", "user"]
        expiry_time = datetime.now() - timedelta(minutes=31)
        with patch("authmodule_asym.datetime") as mock_datetime:
            mock_datetime.now.return_value = expiry_time
            token = self.auth_module_asym.create_token(user_id, roles)
        is_valid = self.auth_module_asym.validate_token(token)
        self.assertFalse(is_valid)

    def test_validate_token_role(self):
        user_id = "user123"
        roles = ["admin", "user"]
        token = self.auth_module_asym.create_token(user_id, roles)
        is_valid_role = self.auth_module_asym.validate_token_role(token, "admin")
        self.assertTrue(is_valid_role)


if __name__ == "__main__":
    unittest.main()
