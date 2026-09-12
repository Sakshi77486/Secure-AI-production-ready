from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "SecureAI"
    APP_VERSION: str = "0.1.0"

    DEBUG: bool = True

    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    DATABASE_URL: str = (
        "postgresql+psycopg://"
        "postgres:YOUR_PASSWORD"
        "@localhost:5432/secureai_db"
    )

    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"
    OLLAMA_TIMEOUT: int = 120

    MAX_UPLOAD_SIZE_MB: int = 25
    MAX_EXTRACTED_SIZE_MB: int = 100
    MAX_FILES_IN_REPOSITORY: int = 1000
    MAX_FILE_SIZE_KB: int = 500

    ALLOWED_ORIGINS: str = "http://localhost:5173"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @property
    def cors_origins(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.ALLOWED_ORIGINS.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()