import pandas as pd
import json
import os
import base64
from datetime import datetime
from encryption_util import load_public_key, hybrid_encrypt

CSV_FILE = 'patient_records.csv'
REPORTS_FILE = 'reports.json'

def preload_and_encrypt_all():
    df = pd.read_csv(CSV_FILE)
    public_key = load_public_key()
    all_reports = []
    
    print(f"Processing {len(df)} records for full field-by-field encryption...")

    for index, row in df.iterrows():
        # Helper function to encrypt a value and return its parts
        def encrypt_field(data_string):
            enc_data, enc_key, data_hash = hybrid_encrypt(str(data_string), public_key)
            return {
                "data": base64.b64encode(enc_data).decode('utf-8'),
                "key": base64.b64encode(enc_key).decode('utf-8'),
                "hash": data_hash
            }

        # Encrypt every single field
        new_report = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'name_encrypted': encrypt_field(row['name']),
            'age_encrypted': encrypt_field(row['age']),
            'blood_group_encrypted': encrypt_field(row['blood_group']),
            'address_encrypted': encrypt_field(row['address']),
            'phone_number_encrypted': encrypt_field(row['phone_number']),
            'patients_relative_encrypted': encrypt_field(row['patients_relative']),
            'doctor_name_encrypted': encrypt_field(row['doctor_name']),
            'medical_details_encrypted': encrypt_field(f"Diagnosis: {row['diagnosis']}\nHistory: {row['medical_history']}")
        }
        all_reports.append(new_report)

    with open(REPORTS_FILE, 'w') as f:
        json.dump(all_reports, f, indent=4)
        
    print(f"Successfully created '{REPORTS_FILE}' with all fields individually encrypted.")

if __name__ == '__main__':
    preload_and_encrypt_all()