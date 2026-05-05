import os
from typing import Optional


class Settings:
    def __init__(self):
        self.app_host: str = self._env("APP_HOST", "0.0.0.0")
        self.app_port: int = int(self._env("APP_PORT", "8022"))
        self.db_path: str = self._env("DB_PATH", "userinfo.db")
        self.secret_key_path: str = self._env("SECRET_KEY_PATH", ".secret.key")
        self.snippets_file: str = self._env("SNIPPETS_FILE", "quick_snippets_v2.json")
        self.tmp_dir: str = self._env("TMP_DIR", "tmp")
        self.app_secret_key: str = self._env("APP_SECRET_KEY", "change-me")
        self.app_auth_token: Optional[str] = os.getenv("APP_AUTH_TOKEN")
        self.session_ttl_seconds: int = int(self._env("SESSION_TTL", "300"))

    def _env(self, key: str, default: str) -> str:
        return os.getenv(key, default)


settings = Settings()
