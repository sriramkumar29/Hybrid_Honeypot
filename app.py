from flask import Flask, request, jsonify, render_template, url_for, redirect, send_from_directory
from datetime import datetime
import joblib
import datetime
import os
import json
import torch
import tensorflow as tf
import numpy as np
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import load_model
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from tensorflow.keras.losses import MeanSquaredError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# MODEL_PATH = "E:\SIP\honeypot-main\model"  # Path to the downloaded model
# try:
#     tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
#     model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
# except Exception as e:
#     print(f"Error loading model or tokenizer: {e}")

MODEL_PATH = "sqli_cnn_model.h5"
TOKENIZER_PATH = "tokenizer.pkl"

try:
    model = load_model(MODEL_PATH)
    tokenizer = joblib.load(TOKENIZER_PATH)
except Exception as e:
    print(f"Error loading model or tokenizer: {e}")

AUTOENCODER_MODEL_PATH = "autoencoder_model.h5"
AUTOENCODER_TOKENIZER_PATH = "autoencoder_tokenizer.pkl"

try:
    autoencoder_model = tf.keras.models.load_model(
        AUTOENCODER_MODEL_PATH,
        custom_objects={'mse': MeanSquaredError()}
    )
    autoencoder_tokenizer = joblib.load(AUTOENCODER_TOKENIZER_PATH)
except Exception as e:
    autoencoder_model = None
    autoencoder_tokenizer = None
    print(f"Error loading autoencoder model or tokenizer: {e}")

except Exception as e:
    autoencoder_model = None
    autoencoder_scaler = None
    autoencoder_tokenizers = None
    print(f"Error loading autoencoder components: {e}")


# Ensure honeypot directory exists
HONEYPOT_FILES_DIR = "honeypot_files/"
os.makedirs(HONEYPOT_FILES_DIR, exist_ok=True)

LOG_FILE = "honeypot_logs.json"
last_login_attempt = {}

# Fake Data Dictionary
fake_data = {
    "User Management": [
        {"username": "fake_admin", "role": "superuser", "email": "fake_admin@company.com", "last_login": "2025-03-10 10:45"},
        {"username": "test_user", "role": "editor", "email": "test_user@company.com", "last_login": "2025-03-08 16:20"},
        {"username": "guest_user", "role": "viewer", "email": "guest_user@company.com", "last_login": "2025-03-07 12:10"}
    ],
    "Financial Reports": {
        "Total Revenue": "$1,000,000",
        "Profit Margin": "50%",
        "Expenses": "$500,000",
        "Net Profit": "$500,000",
        "Quarterly Performance": {"Q1": "$250,000", "Q2": "$260,000", "Q3": "$240,000", "Q4": "$250,000"},
        "Investment Plans": ["Cryptocurrency Fund: $50,000", "Real Estate: $200,000"]
    },
    "Database Access": [
        "Table: users (2,000 records)",
        "Table: transactions (5,000 records)",
        "Table: inventory (200 items)",
        "Table: customer_support (1,000 records)"
    ],
    "API Keys": ["API_KEY_1234567890", "SECRET_KEY_0987654321", "PUBLIC_KEY_ABCDEF098765"],
    "Admin Credentials": [
        {"username": "admin", "password": "P@ssw0rd123"},
        {"username": "superadmin", "password": "SuperSecret!456"},
        {"username": "sysadmin", "password": "System@2025"}
    ],
    "Backup Files": ["backup_2025-01-01.sql", "backup_2025-02-01.zip", "backup_2025-03-01.tar"],
    "System Logs": [
        "2025-03-01 12:00 - Failed Login Attempt from 192.168.1.10",
        "2025-03-02 15:30 - SQL Injection Attempt Detected from 45.76.98.123",
        "2025-03-05 10:10 - Unauthorized API Access Attempt from 172.16.254.1"
    ],
    "Security Logs": [
        "2025-03-06 14:00 - Multiple brute force login attempts detected",
        "2025-03-07 08:45 - Firewall rule updated to block suspicious IP",
        "2025-03-09 22:30 - Admin session hijacking attempt logged"
    ],
    "Analytics": {
        "Total Users": 10_000,
        "Active Users This Month": 2_500,
        "Page Views": 150_000,
        "Avg. Session Duration": "3m 20s",
        "Bounce Rate": "45%"
    },
     "System Configurations": {
        "Server OS": "Ubuntu 22.04",
        "Database": "PostgreSQL 14",
        "Web Server": "Nginx 1.21",
        "SSL": "Let's Encrypt - Valid until 2025-06-30"
    }
}

real_data = {
    "User Management": [
        {"username": "john_doe", "role": "admin", "email": "john.doe@company.com", "last_login": "2025-03-10 09:30"},
        {"username": "jane_smith", "role": "editor", "email": "jane.smith@company.com", "last_login": "2025-03-09 18:50"},
        {"username": "michael_brown", "role": "viewer", "email": "michael.brown@company.com", "last_login": "2025-03-08 14:15"},
        {"username": "alex_jones", "role": "manager", "email": "alex.jones@company.com", "last_login": "2025-03-07 08:40"}
    ],
    "Financial Reports": {
        "Total Revenue": "$1,250,000",
        "Profit Margin": "42%",
        "Expenses": "$720,000",
        "Net Profit": "$530,000",
        "Quarterly Performance": {"Q1": "$310,000", "Q2": "$300,000", "Q3": "$320,000", "Q4": "$320,000"},
        "Investment Plans": [
            {"Investment Type": "Stocks", "Amount": "$300,000", "ROI": "12%"},
            {"Investment Type": "Bonds", "Amount": "$200,000", "ROI": "5%"},
            {"Investment Type": "Real Estate", "Amount": "$250,000", "ROI": "8%"}
        ]
    },
    "Database Access": [
        "Table: customers (50,000 records)",
        "Table: transactions (120,000 records)",
        "Table: products (2,500 items)",
        "Table: orders (30,000 records)",
        "Table: employees (1,200 records)"
    ],
    "API Activity Logs": [
        "2025-03-10 14:23 - GET /api/orders - 200 OK",
        "2025-03-10 14:25 - POST /api/payment - 201 Created",
        "2025-03-10 14:30 - DELETE /api/user/23 - 403 Forbidden",
        "2025-03-10 14:35 - PATCH /api/settings - 401 Unauthorized"
    ],
    "Admin Credentials": [
        {"username": "finance_team", "password_hash": "e99a18c428cb38d5f260853678922e03"},
        {"username": "it_support", "password_hash": "d8578edf8458ce06fbc5bb76a58c5ca4"},
        {"username": "operations_manager", "password_hash": "8e4c3f6cd8a77ed2ff5fbc3b7c9f38d5"}
    ],
    "Backup Files": [
        "backup_2025-02-15.sql",
        "backup_2025-03-01.zip",
        "backup_2025-03-10.tar.gz",
        "backup_2025-03-15_encrypted.bak"
    ],
    "System Logs": [
        "2025-03-10 09:15 - User login successful (john_doe)",
        "2025-03-10 09:20 - Database backup completed",
        "2025-03-10 10:00 - Unauthorized API access attempt detected",
        "2025-03-10 11:30 - Payment transaction failed for order #456789",
        "2025-03-10 13:00 - Security patch applied",
        "2025-03-10 14:00 - System rebooted successfully"
    ],
    "Security Logs": [
        "2025-03-10 12:30 - Suspicious login attempt from IP 205.178.98.24",
        "2025-03-10 15:20 - User session timeout enforced",
        "2025-03-10 16:45 - Two-factor authentication enabled for admin"
    ],
    "System Configurations": {
        "Server OS": "Ubuntu 22.04",
        "Database": "PostgreSQL 14",
        "Web Server": "Nginx 1.21",
        "SSL": "Let's Encrypt - Valid until 2025-06-30"
    }
}



def load_logs():
    try:
        with open(LOG_FILE, "r") as log_file:
            return json.load(log_file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_logs(logs):
    with open(LOG_FILE, "w") as log_file:
        json.dump(logs, log_file, indent=4)

def log_honeypot_activity(log_entry):
    """Log honeypot interactions when attackers access fake data."""
    try:
        # Load existing logs
        if os.path.exists("honeypot_accessed_section.json"):
            with open("honeypot_accessed_section.json", "r") as file:
                logs = json.load(file)
        else:
            logs = []
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    
    # Append the new log entry
    logs.append(log_entry)
    
    # Save the updated logs
    with open("honeypot_accessed_section.json", "w") as file:
        json.dump(logs, file, indent=4)

# Email configuration
EMAIL_SENDER = "prsnn450@gmail.com"
EMAIL_PASSWORD = "ljnh nkib dyvs zzkg"
EMAIL_RECEIVER = "rj03072004@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

def send_email_report(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Use SMTP_SSL for port 465
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        print("Email sent successfully!")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def log_attack(log_entry):
    logs = load_logs()
    username, password = log_entry["payload"].get("username"), log_entry["payload"].get("password")
    attack_type, detection_type = log_entry["attack_type"], log_entry["detection_type"]
    existing_entry = next((log for log in logs if log.get("username") == username and log.get("password") == password), None)

    if existing_entry:
        existing_entry["accessed_sections"].extend(log_entry.get("accessed_sections", []))
    else:
        attack_details = {
            "timestamp": str(datetime.datetime.now()),
            "attacker_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
            "attack_type": attack_type,
            "payload": {"username": username, "password": password},
            "sql_query_attempted": log_entry["sql_query_attempted"],
            "detection_type": detection_type,
            "confidence_level": log_entry["confidence_level"],
            "sqli_possibility": log_entry["sqli_possibility"],
            "request_method": request.method,
            "request_url": request.url,
            "request_headers": dict(request.headers),
            "action_taken": "Redirected",
            "accessed_sections": []
        }
        logs.append(attack_details)

    # Constructing email body
    email_subject = f"Honeypot Alert: {attack_type} Detected from {request.remote_addr}"
    email_body = f"""
    Time: {attack_details['timestamp']}
    IP: {attack_details['attacker_ip']}
    User Agent: {attack_details['user_agent']}
    Attack Type: {attack_type}
    Payload: {attack_details['payload']}
    Detection: {detection_type}
    Confidence: {log_entry['confidence_level']}
    SQLi Probability: {log_entry['sqli_possibility']}
    URL: {request.url}
    """

    # Send the email with the attack details
    send_email_report(email_subject, email_body)

    # Save the logs after the attack
    save_logs(logs)



def detect_sql_injection(payload):
    try:
        X_test = tokenizer.texts_to_sequences([payload])
        X_test_padded = pad_sequences(X_test, maxlen=100, padding='post')
        prediction_prob = model.predict(X_test_padded)[0][0]
        return prediction_prob > 0.5, prediction_prob
    except Exception as e:
        print(f"Error in SQL Injection Detection: {e}")
        return False, 0

# Function to detect zero-day attack
def detect_zero_day(payload, threshold=0.01):
    try:
        if not autoencoder_tokenizer:
            print("Warning: Autoencoder tokenizer is not available.")
            return False, 0.0
        
        sequence = autoencoder_tokenizer.texts_to_sequences([payload])
        padded = pad_sequences(sequence, maxlen=10, padding='post')
        reconstruction = autoencoder_model.predict(padded)[0]
        error = np.mean((padded[0] - reconstruction) ** 2)

        is_anomalous = error > threshold
        return is_anomalous, float(error)
    except Exception as e:
        print(f"Error in zero-day detection: {e}")
        return False, 0.0


@app.route("/", methods=["GET"])
def home():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    global last_login_attempt
    
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user_agent = request.headers.get("User-Agent", "Unknown")
    attacker_ip = request.remote_addr
    payload = f"{username} {password}"
    
    legitimate_users = {"user1": "pass1", "user2": "pass2", "user3": "pass3"}
    legitimate_admin = {"admin": "password"}
    
    # Store credentials of the last login attempt
    last_login_attempt = {"username": username, "password": password, "user_agent": user_agent, "ip": attacker_ip}
    
    if username in legitimate_admin and password == legitimate_admin[username]:
        return jsonify({"redirect": url_for("homepage", data_type="real")})
    
    if username in legitimate_users and password == legitimate_users[username]:
        return jsonify({"message": "Login successful"}), 200
    if username == "admin":
        return jsonify({"message": "Invalid credentials"}), 401

    # Simulated SQL injection detection function
    attack_detected, prediction_prob = detect_sql_injection(payload)
    
    if attack_detected:
        log_attack({
            "timestamp": str(datetime.datetime.now()),
            "attacker_ip": attacker_ip,
            "user_agent": user_agent,
            "attack_type": "SQL Injection",
            "payload": {"username": username, "password": password},
            "sql_query_attempted": f"SELECT * FROM users WHERE username='{username}' AND password='{password}'",
            "detection_type": "SQL Injection CNN Model",
            "confidence_level": f"{prediction_prob:.4f}",
            "sqli_possibility": "High" if prediction_prob > 0.75 else "Medium",
        })
        return jsonify({"redirect": url_for("homepage", data_type="fake")})
    
    zero_day_detected, anomaly_score = detect_zero_day(payload)
    if zero_day_detected:
        log_attack({
            "timestamp": str(datetime.datetime.now()),
            "attacker_ip": attacker_ip,
            "user_agent": user_agent,
            "attack_type": "Zero-Day Anomaly",
            "payload": {"username": username, "password": password},
            "sql_query_attempted": f"SELECT * FROM users WHERE username='{username}' AND password='{password}'",
            "confidence_level": f"{anomaly_score:.4f}",
            "sqli_possibility": "Unknown",
            "detection_type": "Zero-Day Autoencoder",
        })
        return jsonify({"redirect": url_for("homepage", data_type="fake")})
    
    return jsonify({"message": "Invalid credentials"}), 401

@app.route("/homepage", methods=["GET"])
def homepage():
    data_type = request.args.get("data_type", "fake")  # Default to fake_data if not specified
    files = os.listdir(HONEYPOT_FILES_DIR)  # List fake honeypot files
    
    # Choose data based on data_type
    data = real_data if data_type == "real" else fake_data
    
    return render_template("homepage.html", files=files, data=data)


@app.route("/honeypot_files/<path:filename>")
def honeypot_files(filename):
    return send_from_directory(HONEYPOT_FILES_DIR, filename)

# Route to Serve Fake Data
# Route to serve data dynamically based on user type
# Global variable to store the start time and user information
last_access_info = {}

@app.route('/get_data/<section>', methods=['GET'])
def get_data(section):
    global last_access_info
    data_type = request.args.get("data_type", "fake")  # Default to fake data
    data_source = real_data if data_type == "real" else fake_data
    
    if section in data_source:
        current_time = datetime.datetime.now()
        
        # If there's a previous access, calculate the duration and log it
        if last_access_info:
            duration = (current_time - last_access_info['start_time']).total_seconds()
            
            # Log the last accessed section with its duration
            log_honeypot_activity({
                "timestamp": str(last_access_info['start_time']),
                "attacker_ip": last_access_info.get("ip", "Unknown"),
                "user_agent": last_access_info.get("user_agent", "Unknown"),
                "username": last_access_info.get("username", "Unknown"),
                "password": last_access_info.get("password", "Unknown"),
                "accessed_section": last_access_info.get("section", "Unknown"),
                "data_type": "fake",
                "duration": duration
            })
        
        # Update the last access info for the new section
        last_access_info = {
            "start_time": current_time,
            "ip": last_login_attempt.get("ip", "Unknown"),
            "user_agent": last_login_attempt.get("user_agent", "Unknown"),
            "username": last_login_attempt.get("username", "Unknown"),
            "password": last_login_attempt.get("password", "Unknown"),
            "section": section
        }
        
        return jsonify(data_source[section])
    
    return jsonify({"error": "Invalid section"}), 404


# Route to Log Hacker Interactions
@app.route("/log_interaction", methods=["POST"])
def log_interaction():
    data = request.get_json()
    section = data.get('section', 'Unknown Section')
    print(f"{section}")
    logs = load_logs()
    
    if logs and "attack_type" in logs[-1]:
        logs[-1]["accessed_sections"].append(section)
    else:
        logs.append({
            "timestamp": str(datetime.datetime.now()),
            "user_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
            "accessed_section": section
        })
    
    save_logs(logs)
    print(f"User accessed: {section}")
    return jsonify({"status": "logged"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)