import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dash1234')
    
    # Get the direct connection string from environment variable
    # This should be the full connection string from Supabase dashboard
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 
        'postgresql://postgres:Darshan%4022@db.jyhsxqeykfeawuhuewhd.supabase.co:5432/postgres?pgbouncer=true&connection_limit=1')
    
    # If DATABASE_URL is not set, construct it from components
    if not os.getenv('DATABASE_URL'):
        DB_USER = 'postgres'
        DB_PASSWORD = quote_plus('Darshan@22')  # URL encode the password
        DB_HOST = 'db.jyhsxqeykfeawuhuewhd.supabase.co'
        DB_NAME = 'postgres'
        DB_PORT = '5432'
        
        SQLALCHEMY_DATABASE_URI = (
            f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
            '?pgbouncer=true&connection_limit=1'
        )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Optimize for serverless environment
    SQLALCHEMY_ENGINE_OPTIONS = {
        'poolclass': None,  # Disable connection pooling for serverless
        'connect_args': {
            'connect_timeout': 30,  # Increased timeout
            'keepalives': 1,
            'keepalives_idle': 30,
            'keepalives_interval': 10,
            'keepalives_count': 5,
            'application_name': 'genix_app'  # Add application name for better tracking
        }
    } 