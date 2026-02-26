from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
import os
import pandas as pd

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION ---
# This creates a file named 'sentinel.db' in your project folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sentinel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "change-this-for-production-security" 

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- DATABASE MODELS (The "Real" Database Structure) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class LeakedCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, nullable=False)
    password_hash = db.Column(db.String(200))
    source_market = db.Column(db.String(100))
    leak_date = db.Column(db.String(50))

# --- INITIALIZATION SCRIPT ---
# This runs once to convert your CSV into the real database
def init_db():
    with app.app_context():
        db.create_all()
        # Import Leaks from CSV if the database is empty
        if not LeakedCredential.query.first():
            if os.path.exists("darkweb_dump.csv"):
                df = pd.read_csv("darkweb_dump.csv")
                for _, row in df.iterrows():
                    leak = LeakedCredential(
                        email=row['email'],
                        password_hash=row['password_hash'],
                        source_market=row['source_market'],
                        leak_date=row['leak_date']
                    )
                    db.session.add(leak)
                db.session.commit()
                print("Successfully migrated CSV to SQL Database.")

@app.route('/')
def home():
    return jsonify({"status": "Sentinel Engine Online", "database": "SQLite Connected"})

# --- AUTH ROUTES ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Identity already exists in system"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password_hash=hashed_pw)
    
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Operator profile initialized"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, data.get('password')):
        access_token = create_access_token(identity=user.email)
        return jsonify({"token": access_token, "email": user.email}), 200
    
    return jsonify({"error": "Invalid Access Credentials"}), 401

# --- SCAN ROUTE ---

@app.route('/scan', methods=['POST'])
@jwt_required()
def scan_email():
    email_to_check = request.json.get('email').lower()
    
    # Query the SQL database instead of reading a CSV file every time
    results = LeakedCredential.query.filter_by(email=email_to_check).all()
    
    if results:
        # Format results for the frontend
        leaks = []
        for r in results:
            leaks.append({
                "email": r.email,
                "password_hash": r.password_hash,
                "source_market": r.source_market,
                "leak_date": r.leak_date
            })
        return jsonify({"status": "LEAK_FOUND", "data": leaks})
    
    return jsonify({"status": "CLEAN"})

if __name__ == '__main__':
    init_db() # Create tables and import CSV
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
