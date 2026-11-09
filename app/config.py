import os
import json
from typing import List, Literal, Union
from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Pre-load .env into environment variables as an extra safeguard
load_dotenv(override=False)


class Settings(BaseSettings):
    """ZeroGuard Application Configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Core Provider Configuration
    LLM_PROVIDER: Literal["groq", "gemini", "ollama"] = Field(
        default="groq",
        description="Active LLM provider for semantic reasoning"
    )

    # 1. Groq Cloud (Free Tier)
    GROQ_API_KEY: str = Field(
        default="",
        description="Groq API Key for llama-3.3-70b-versatile"
    )
    GROQ_MODEL: str = Field(
        default="llama-3.3-70b-versatile"
    )

    # 2. Google Gemini (Free Tier)
    GEMINI_API_KEY: str = Field(
        default="",
        description="Gemini API Key for fallback"
    )
    GEMINI_MODEL: str = Field(
        default="gemini-2.0-flash"
    )

    # 3. Ollama Local Endpoint
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434/v1"
    )
    OLLAMA_MODEL: str = Field(
        default="qwen2.5-coder:7b"
    )

    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "info"
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "*"
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    return json.loads(v_stripped)
                except Exception:
                    pass
            # Split comma-separated string
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [str(origin).strip() for origin in v]
        return ["*"]


settings = Settings()
