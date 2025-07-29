from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging
import json
import base64
import os

# Import from other project files
from encryption_util import load_public_key, hybrid_encrypt
from users import users
from . import login_manager

# Create the blueprint for the Hospital Staff section
hospital_bp = Blueprint('hospital_staff', __name__, url_prefix='/hospital')

# Set the default login page for this blueprint
login_manager.login_view = 'hospital_staff.login'
REPORTS_FILE = 'reports.json'

@hospital_bp.route('/')
def index():
    """Redirects the base /hospital/ URL to the login page."""
    return redirect(url_for('hospital_staff.login'))

@hospital_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles the login process for hospital staff."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = next((u for u in users.values() if u.username == username and u.role == 'hospital_staff'), None)
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            logging.info(f"Hospital Staff '{username}' logged in.")
            # CORRECTED: Always redirect to the registration page
            return redirect(url_for('hospital_staff.register'))
        else:
            flash("Invalid Hospital Staff credentials.", "danger")
            
    return render_template('login_hospital.html')

@hospital_bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    """This is the main page for logged-in hospital staff."""
    if current_user.role != 'hospital_staff':
        return redirect(url_for('hospital_staff.login'))

    if request.method == 'POST':
        public_key = load_public_key()
        
        full_medical_details = f"Diagnosis: {request.form.get('diagnosis')}\nHistory: {request.form.get('medical_history')}"
        encrypted_details, enc_key, data_hash = hybrid_encrypt(full_medical_details, public_key)
        
        new_report = {
            'name': request.form.get('name'),
            'age': request.form.get('age'),
            'blood_group': request.form.get('blood_group'),
            'address': request.form.get('address'),
            'phone_number': request.form.get('phone_number'),
            'patients_relative': request.form.get('patients_relative'),
            'doctor_name': request.form.get('doctor_name'),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'medical_data_encrypted': base64.b64encode(encrypted_details).decode('utf-8'),
            'medical_data_key': base64.b64encode(enc_key).decode('utf-8'),
            'medical_data_hash': data_hash,
        }
        
        if os.path.exists(REPORTS_FILE):
            with open(REPORTS_FILE, 'r') as f: reports = json.load(f)
        else:
            reports = []
        
        reports.append(new_report)
        with open(REPORTS_FILE, 'w') as f: json.dump(reports, f, indent=4)
        
        flash("Patient record saved and encrypted successfully!", "success")
        return redirect(url_for('hospital_staff.register'))

    return render_template('register_report.html')

@hospital_bp.route('/logout')
@login_required
def logout():
    """Logs the hospital staff user out."""
    logout_user()
    return redirect(url_for('hospital_staff.login'))