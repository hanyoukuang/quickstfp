"""CryptoManager 单元测试"""
import os
import pytest
from database.user_model import CryptoManager


class TestCryptoManager:

    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        key_file = tmp_path / ".secret.key"
        cm = CryptoManager(key_file=str(key_file))
        assert key_file.exists()

        plain = "my_secret_password"
        encrypted = cm.encrypt(plain)
        assert encrypted != plain
        assert cm.decrypt(encrypted) == plain

    def test_empty_string_passthrough(self, tmp_path):
        cm = CryptoManager(key_file=str(tmp_path / ".key"))
        assert cm.encrypt("") == ""
        assert cm.decrypt("") == ""

    def test_key_persistence(self, tmp_path):
        key_file = tmp_path / ".secret.key"
        cm1 = CryptoManager(key_file=str(key_file))
        plain = "test123"
        encrypted = cm1.encrypt(plain)

        cm2 = CryptoManager(key_file=str(key_file))
        assert cm2.decrypt(encrypted) == plain
