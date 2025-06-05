import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dash1234')
    # URL encode the password to handle special characters
    password = quote_plus(os.getenv('DB_PASSWORD', 'Darshan@22'))
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'postgresql://postgres:{password}@db.jyhsxqeykfeawuhuewhd.supabase.co:5432/postgres?sslmode=require')
    SQLALCHEMY_TRACK_MODIFICATIONS = False 