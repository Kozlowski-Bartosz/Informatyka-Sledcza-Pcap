import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    UPLOAD_FOLDER = 'frontend/static/uploads'
    DEBUG = True
