from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import os

app = Flask(__name__)
# CORS allows your Vercel frontend to talk to this Render backend
CORS(app)

# The mock database file
FAKE_DB_FILE = "darkweb_dump.csv"

@app.route('/')
def home():
    return "Sentinel Backend is Running!"

@app.route('/scan', methods=['POST'])
def scan_email():
    data = request.json
    email_to_check = data.get('email')
    
    if not email_to_check:
        return jsonify({"error": "No email provided"}), 400

    try:
        # Load database
        # We assume the CSV is in the same folder as app.py
        df = pd.read_csv(FAKE_DB_FILE)
        
        # Search for email (case insensitive)
        results = df[df['email'].str.lower() == email_to_check.lower()]
        
        if not results.empty:
            # Convert found rows to JSON
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
