from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
class Settings(BaseSettings):
    database_url: str
    test_database_url: str
    debug_mode: bool
    print(f"Looking for .env at: {BASE_DIR / '.env'}")
    print(f"Exists: {(BASE_DIR / '.env').exists()}")
    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", env_file_encoding="utf-8",extra="ignore")
    keys_directory: Path
    resend_api_key: str
    resend_email_address: str

settings = Settings()