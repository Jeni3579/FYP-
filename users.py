from flask_login import UserMixin
from werkzeug.security import generate_password_hash
import json, os

USERS_FILE = 'users.json'

class User(UserMixin):
    def __init__(self, id, username, password_hash, role):
        self.id, self.username, self.password, self.role = id, username, password_hash, role

def load_user_data():
    if not os.path.exists(USERS_FILE):
        default_users = [
            {"id": "1", "username": "it_staff", "password": generate_password_hash("adminpass"), "role": "it_staff"},
            {"id": "2", "username": "hospital_staff", "password": generate_password_hash("hospitalpass"), "role": "hospital_staff"}
        ]
        with open(USERS_FILE, 'w') as f: json.dump(default_users, f, indent=4)
        return default_users
    with open(USERS_FILE, 'r') as f: return json.load(f)

def save_user_data(users_list_of_dicts):
    with open(USERS_FILE, 'w') as f: json.dump(users_list_of_dicts, f, indent=4)

users = {u['id']: User(id=u['id'], username=u['username'], password_hash=u['password'], role=u['role']) for u in load_user_data()}