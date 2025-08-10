import os
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-super-secret-key-that-is-long-and-random'