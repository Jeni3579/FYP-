from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from datetime import datetime
import logging, json, base64, os
from encryption_util import load_public_key, hybrid_encrypt
from users import User, load_user_data
from . import login_manager

hospital_bp = Blueprint('hospital_staff', __name__, url_prefix='/hospital')
login_manager.login_view = 'hospital_staff.login'
REPORTS_FILE = 'reports.json'

@hospital_bp.route('/')
def index(): return redirect(url_for('hospital_staff.login'))

@hospital_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        all_users = {u['id']: User(id=u['id'], username=u['username'], password_hash=u['password'], role=u['role']) for u in load_user_data()}
        user = next((u for u in all_users.values() if u.username == request.form['username'] and u.role == 'hospital_staff'), None)
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('hospital_staff.register'))
        flash("Invalid Hospital Staff credentials.", "danger")
    return render_template('login_hospital.html')

@hospital_bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.role != 'hospital_staff': return redirect(url_for('hospital_staff.login'))
    if request.method == 'POST':
        public_key = load_public_key()
        
        # Helper function to encrypt a single form field
        def encrypt_field(field_name_or_data):
            data = request.form.get(field_name_or_data, field_name_or_data)
            enc_data, enc_key, data_hash = hybrid_encrypt(data, public_key)
            return {"data": base64.b64encode(enc_data).decode('utf-8'), "key": base64.b64encode(enc_key).decode('utf-8'), "hash": data_hash}

        # Encrypt medical details with hash
        medical_details_string = f"Diagnosis: {request.form.get('diagnosis')}\nHistory: {request.form.get('medical_history')}"
        
        new_report = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'name_encrypted': encrypt_field('name'),
            'age_encrypted': encrypt_field('age'),
            'blood_group_encrypted': encrypt_field('blood_group'),
            'address_encrypted': encrypt_field('address'),
            'phone_number_encrypted': encrypt_field('phone_number'),
            'patients_relative_encrypted': encrypt_field('patients_relative'),
            'doctor_name_encrypted': encrypt_field('doctor_name'),
            'medical_details_encrypted': encrypt_field(medical_details_string)
        }
        
        if os.path.exists(REPORTS_FILE):
            with open(REPORTS_FILE, 'r') as f: reports = json.load(f)
        else:
            reports = []
        reports.append(new_report)
        with open(REPORTS_FILE, 'w') as f: json.dump(reports, f, indent=4)
        
        flash("Patient record fully encrypted and saved successfully!", "success")
        return redirect(url_for('hospital_staff.register'))
    return render_template('register_report.html')

@hospital_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hospital_staff.login'))