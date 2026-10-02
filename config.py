import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "sqli_lab_super_secret_key_2026")
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASS = os.getenv("DB_PASS", "root")
    DB_NAME = os.getenv("DB_NAME", "sqli_lab_db")
