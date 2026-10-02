import os
from dotenv import load_dotenv

load_dotenv()

# Detect if running on a production platform (Railway or Render)
IS_RAILWAY = bool(os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_PROJECT_ID"))
IS_RENDER  = bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))
IS_PRODUCTION = IS_RAILWAY or IS_RENDER

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dnswatch-default-secret-key-2026")

    # Database Settings
    # Railway injects MYSQLHOST / MYSQLUSER / MYSQLPASSWORD / MYSQLDATABASE / MYSQLPORT
    # Fall back to .env variable names for local development
    DB_USER     = os.getenv("MYSQLUSER")     or os.getenv("DB_USER",     "root")
    DB_PASSWORD = os.getenv("MYSQLPASSWORD") or os.getenv("DB_PASSWORD", "")
    DB_HOST     = os.getenv("MYSQLHOST")     or os.getenv("DB_HOST",     "127.0.0.1")
    DB_PORT     = os.getenv("MYSQLPORT")     or os.getenv("DB_PORT",     "3306")
    DB_NAME     = os.getenv("MYSQLDATABASE") or os.getenv("DB_NAME",     "dnswatch_db")

    # Railway also provides a full DATABASE_URL — use it directly if present
    _DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("MYSQL_URL") or os.getenv("MYSQL_PRIVATE_URL")
    if _DATABASE_URL:
        # SQLAlchemy requires mysql+pymysql:// scheme
        SQLALCHEMY_DATABASE_URI = _DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)
    else:
        SQLALCHEMY_DATABASE_URI = (
            f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
    }

    # Sniffer Settings
    DEFAULT_CAPTURE_INTERFACE = os.getenv("DEFAULT_CAPTURE_INTERFACE", "")
    CAPTURE_FILTER            = os.getenv("CAPTURE_FILTER", "udp port 53 or tcp port 53")
    BATCH_FLUSH_INTERVAL      = float(os.getenv("BATCH_FLUSH_INTERVAL", "1.0"))
    BATCH_SIZE                = int(os.getenv("BATCH_SIZE", "25"))

    # Frequency Rule Defaults
    DEFAULT_FREQUENCY_THRESHOLD = int(os.getenv("DEFAULT_FREQUENCY_THRESHOLD", "100"))
    DEFAULT_FREQUENCY_WINDOW    = int(os.getenv("DEFAULT_FREQUENCY_WINDOW",    "60"))

    # Session / Cookie security
    # Enable Secure cookies on any production platform (Railway, Render, etc.)
    SESSION_COOKIE_SECURE   = IS_PRODUCTION
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_HTTPONLY = True
