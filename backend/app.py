from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import pandas as pd
import os
import csv

app = Flask(__name__)
# Allow CORS for all domains (simplifies development)
CORS(app)

# --- SECURITY CONFIG ---
app.config["JWT_SECRET_KEY"] = "super-secret-key-change-this-later"  
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- DATABASE FILES ---
FAKE_DB_FILE = "darkweb_dump.csv" # The leak data
USERS_DB_FILE = "users.csv"       # The registered users

# Ensure users.csv exists
if not os.path.exists(USERS_DB_FILE):
    with open(USERS_DB_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["email", "password_hash"]) # Header

@app.route('/')
def home():
    return "Sentinel Backend is Running!"

# --- AUTH ROUTES ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    # Check if user already exists
    df = pd.read_csv(USERS_DB_FILE)
    if not df.empty and email in df['email'].values:
        return jsonify({"error": "User already exists"}), 400

    # Hash password
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

    # Append to CSV
    with open(USERS_DB_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([email, hashed_pw])

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Load users
    try:
        df = pd.read_csv(USERS_DB_FILE)
    except:
        return jsonify({"error": "No users found"}), 400

    # Find user
    user = df[df['email'] == email]
    
    if user.empty:
        return jsonify({"error": "Invalid credentials"}), 401

    # Verify password
    stored_hash = user.iloc[0]['password_hash']
    if bcrypt.check_password_hash(stored_hash, password):
        # Create Token
        access_token = create_access_token(identity=email)
        return jsonify({"token": access_token, "email": email}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# --- PROTECTED SCAN ROUTE ---

@app.route('/scan', methods=['POST'])
@jwt_required()  # <--- This locks the route!
def scan_email():
    data = request.json
    email_to_check = data.get('email')
    
    if not email_to_check:
        return jsonify({"error": "No email provided"}), 400

    try:
        df = pd.read_csv(FAKE_DB_FILE)
        results = df[df['email'].str.lower() == email_to_check.lower()]
        
        if not results.empty:
            return jsonify({
                "status": "LEAK_FOUND",
                "data": results.to_dict(orient='records')
            })
        else:
            return jsonify({"status": "CLEAN"})
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
