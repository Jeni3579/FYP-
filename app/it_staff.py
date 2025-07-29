from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging
import json
import base64
import pandas as pd
import joblib
import random

# Import from other project files
from encryption_util import load_private_key, hybrid_decrypt, verify_data_integrity
from users import User, load_user_data, save_user_data
from . import login_manager

# Create the blueprint for the IT Staff section
it_bp = Blueprint('it_staff', __name__, url_prefix='/it')

# Set the default login page for this blueprint
login_manager.login_view = 'it_staff.login'

@it_bp.route('/')
def index():
    """Redirects the base /it/ URL to the login page."""
    return redirect(url_for('it_staff.login'))

@it_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles the login process for IT staff."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Load the latest user data to check against
        all_users = {u['id']: User(id=u['id'], username=u['username'], password_hash=u['password'], role=u['role']) for u in load_user_data()}
        user = next((u for u in all_users.values() if u.username == username and u.role == 'it_staff'), None)

        if user and check_password_hash(user.password, password):
            login_user(user)
            logging.info(f"IT Staff '{username}' logged in.")
            return redirect(url_for('it_staff.dashboard'))
        else:
            flash("Invalid IT Staff credentials.", "danger")
            logging.warning(f"Failed IT login attempt for username '{username}'.")
            
    return render_template('login_it.html')

@it_bp.route('/instructions')
def instructions():
    """Renders the public instruction page."""
    return render_template('instructions.html')

@it_bp.route('/dashboard')
@login_required
def dashboard():
    """Displays the main navigation dashboard for IT staff."""
    if current_user.role != 'it_staff':
        return redirect(url_for('it_staff.login'))
    return render_template('it_dashboard.html', username=current_user.username)

@it_bp.route('/threat_dashboard')
@login_required
def threat_dashboard():
    """Renders the live threat detection chart and alert feed."""
    if current_user.role != 'it_staff':
        return redirect(url_for('it_staff.login'))
    return render_template('threat_dashboard.html')

@it_bp.route('/reports')
@login_required
def view_reports():
    """Displays all patient reports, decrypting them for viewing."""
    if current_user.role != 'it_staff':
        return redirect(url_for('it_staff.login'))

    try:
        private_key = load_private_key()
        with open('reports.json') as f:
            encrypted_reports = json.load(f)
    except FileNotFoundError:
        encrypted_reports = []
        flash("Could not find reports.json.", "warning")
    
    decrypted_reports = []
    for report in encrypted_reports:
        try:
            decrypted_report = report.copy()
            enc_data = base64.b64decode(report['medical_data_encrypted'])
            enc_key = base64.b64decode(report['medical_data_key'])
            
            decrypted_details = hybrid_decrypt(enc_data, enc_key, private_key)
            integrity_ok = verify_data_integrity(decrypted_details, report['medical_data_hash'])
            
            decrypted_report['decrypted_medical_history'] = f"{decrypted_details} {'✅' if integrity_ok else '⚠️ TAMPERED'}"
            decrypted_reports.append(decrypted_report)

        except Exception as e:
            logging.error(f"Decryption failed for patient '{report.get('name')}': {e}")
            report['decrypted_medical_history'] = "⛔ DECRYPTION FAILED"
            decrypted_reports.append(report)
        
    return render_template('view_reports.html', reports=decrypted_reports)

@it_bp.route('/user_management')
@login_required
def user_management():
    """Renders the user management page for the main admin."""
    if current_user.id != '1':
        flash("Access Denied: Only the main admin can manage users.", "danger")
        return redirect(url_for('it_staff.dashboard'))
    
    all_users = [u for u in load_user_data()]
    return render_template('user_management.html', all_users=all_users)

@it_bp.route('/create_user', methods=['POST'])
@login_required
def create_user():
    """Handles the creation of new user accounts by the admin."""
    if current_user.id != '1': return redirect(url_for('it_staff.dashboard'))
    
    all_users_data = load_user_data()
    username = request.form['username']

    if any(u['username'] == username for u in all_users_data):
        flash(f"Username '{username}' already exists.", "danger")
    else:
        new_user = {
            "id": str(len(all_users_data) + 1),
            "username": username,
            "password": generate_password_hash(request.form['password']),
            "role": request.form['role']
        }
        all_users_data.append(new_user)
        save_user_data(all_users_data)
        flash(f"User '{username}' created successfully.", "success")
        
    return redirect(url_for('it_staff.user_management'))

@it_bp.route('/delete_user/<user_id>')
@login_required
def delete_user(user_id):
    """Handles the deletion of user accounts by the admin."""
    if current_user.id != '1': return redirect(url_for('it_staff.dashboard'))
    
    if user_id == '1':
        flash("Cannot delete the main admin account.", "danger")
    else:
        all_users_data = load_user_data()
        users_to_keep = [user for user in all_users_data if user['id'] != user_id]
        save_user_data(users_to_keep)
        flash("User deleted successfully.", "success")
        
    return redirect(url_for('it_staff.user_management'))

@it_bp.route('/logout')
@login_required
def logout():
    """Logs the IT staff user out."""
    logout_user()
    return redirect(url_for('it_staff.login'))

# --- API Route for Live Threat Chart ---
@it_bp.route('/api/live_threat_feed')
@login_required
def live_threat_feed():
    """Feeds the dashboard with AI-powered threat analysis."""
    try:
        model = joblib.load('malware_model.pkl')
        events_df = pd.read_csv('security_events.csv')

        random_event = events_df.sample(1).iloc[0]
        feature_string = random_event['event_type'] + " " + random_event['user']
        prediction = model.predict([feature_string])[0]

        return jsonify({
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'prediction': prediction,
            'details': f"Event '{random_event['event_type']}' by user '{random_event['user']}'"
        })
        
    except Exception as e:
        logging.error(f"Error in threat feed API: {e}")
        return jsonify({'prediction': 'Error'})