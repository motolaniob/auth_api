from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    debug_mode: bool
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8",extra="ignore")

settings = Settings()