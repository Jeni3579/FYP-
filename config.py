import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secure-and-random-string-for-sessions'