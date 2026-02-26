from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_sqlalchemy import SQLAlchemy
import os
import pandas as pd

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION ---
# Database file: sentinel.db (SQLite)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'sentinel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "sentinel-intelligence-secret-2026" 

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- DATABASE MODELS ---
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

# --- DATABASE INITIALIZATION ---
# This function creates the DB and imports your CSV data
def init_db():
    db.create_all()
    # Only import if the LeakedCredential table is empty
    if not LeakedCredential.query.first():
        csv_path = os.path.join(basedir, "darkweb_dump.csv")
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            for _, row in df.iterrows():
                leak = LeakedCredential(
                    email=str(row['email']).lower(),
                    password_hash=row['password_hash'],
                    source_market=row['source_market'],
                    leak_date=row['leak_date']
                )
                db.session.add(leak)
            db.session.commit()
            print("Successfully migrated darkweb_dump.csv to SQL Database.")

# CRITICAL: This runs the initialization as soon as Gunicorn/Render starts the app
with app.app_context():
    init_db()

# --- ROUTES ---

@app.route('/')
def home():
    return jsonify({"status": "Sentinel Engine Online", "database": "SQLite Connected"})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email', '').lower()
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Operator identity already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password_hash=hashed_pw)
    
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Operator profile initialized"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email', '').lower()).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, data.get('password')):
        access_token = create_access_token(identity=user.email)
        return jsonify({"token": access_token, "email": user.email}), 200
    
    return jsonify({"error": "Invalid Access Credentials"}), 401

@app.route('/scan', methods=['POST'])
@jwt_required()
def scan_email():
    email_to_check = request.json.get('email', '').lower()
    results = LeakedCredential.query.filter_by(email=email_to_check).all()
    
    if results:
        leaks = [{"email": r.email, "password_hash": r.password_hash, 
                  "source_market": r.source_market, "leak_date": r.leak_date} for r in results]
        return jsonify({"status": "LEAK_FOUND", "data": leaks})
    
    return jsonify({"status": "CLEAN"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
