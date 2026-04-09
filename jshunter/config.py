"""
JSHunter — Configuration
Configs por ambiente: Development / Production
"""

import os
from dotenv import load_dotenv

load_dotenv(override=True)


class BaseConfig:
    """Configuracao base compartilhada"""
    APP_NAME = "JSHunter"
    APP_VERSION = "2.0.0"
    APP_AUTHOR = "HuntBox"

    # Analysis
    RECURSION_LIMIT = 3000
    FETCH_TIMEOUT = 60
    FETCH_MAX_RETRIES = 2
    FETCH_RETRY_DELAY = 2
    MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
    ENTROPY_THRESHOLD = 4.5
    BEAUTIFY_LINE_THRESHOLD = 5
    BEAUTIFY_SIZE_THRESHOLD = 1000
    CONTEXT_LINES = 2

    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32).hex())
    CORS_ORIGINS = "*"

    # AI / Groq
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    GROQ_MODEL = "llama-3.3-70b-versatile"
    AI_ENABLED = True
    AI_BATCH_SIZE = 30
    AI_TIMEOUT = 30

    # User Agent for requests
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )


class DevelopmentConfig(BaseConfig):
    """Ambiente de desenvolvimento"""
    DEBUG = True
    HOST = "0.0.0.0"
    PORT = 5000


class ProductionConfig(BaseConfig):
    """Ambiente de producao"""
    DEBUG = False
    HOST = "127.0.0.1"
    PORT = 8080
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")


# Mapa de configs
configs = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(env=None):
    """Retorna config baseada no ambiente"""
    if env is None:
        env = os.environ.get("JSHUNTER_ENV", "development")
    return configs.get(env, configs["default"])
