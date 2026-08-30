import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dnswatch-default-secret-key-2026")
    
    # Database Settings
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = os.getenv("DB_PORT", "3306")
    DB_NAME = os.getenv("DB_NAME", "dnswatch_db")
    
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20
    }
    
    # Sniffer Settings
    DEFAULT_CAPTURE_INTERFACE = os.getenv("DEFAULT_CAPTURE_INTERFACE", "")
    CAPTURE_FILTER = os.getenv("CAPTURE_FILTER", "udp port 53 or tcp port 53")
    BATCH_FLUSH_INTERVAL = float(os.getenv("BATCH_FLUSH_INTERVAL", "1.0"))
    BATCH_SIZE = int(os.getenv("BATCH_SIZE", "25"))
    
    # Frequency Rule Defaults
    DEFAULT_FREQUENCY_THRESHOLD = int(os.getenv("DEFAULT_FREQUENCY_THRESHOLD", "100"))
    DEFAULT_FREQUENCY_WINDOW = int(os.getenv("DEFAULT_FREQUENCY_WINDOW", "60"))
