import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    UPLOAD_FOLDER = 'frontend/static/uploads'
    DEBUG = True
    MEGABYTE = (2 ** 10) ** 2
    MAX_CONTENT_LENGTH = None
    MAX_FORM_MEMORY_SIZE = 50 * MEGABYTE # Set max file size for saving