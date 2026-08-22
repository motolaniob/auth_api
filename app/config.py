"""
Application settings, loaded from a .env file via pydantic-settings.
See .env.example for the full list of required variables.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
class Settings(BaseSettings):
    database_url: str
    test_database_url: str
    redis_url: str
    debug_mode: bool
    keys_directory: Path
    resend_api_key: str
    resend_email_address: str
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    app_base_url: str

    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
