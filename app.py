from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import sqlite3
import os
import base64
import re

app = Flask(__name__)
CORS(app)  # Enable CORS

app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize SQLite database
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                uploader_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                FOREIGN KEY (uploader_id) REFERENCES users (id),
                FOREIGN KEY (recipient_id) REFERENCES users (id)
            )
        ''')
        conn.commit()


init_db()

def is_valid_username(username):
    return re.match("'^[a-zA-Z0-9_]+$", username)

# Register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    public_key = data['public_key']

    if not is_valid_username(username):
        return jsonify({"message": "Invalid username"}), 400
    
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    hashed_password = generate_password_hash(password + salt, method='scrypt')
    
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, public_key, salt) VALUES (?, ?, ?, ?)', 
                      (username, hashed_password, public_key, salt))
            conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 400

# Login user
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, password, salt FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and check_password_hash(user[1], password + user[2]):
            return jsonify({"message": "Login successful", "user_id": user[0]}), 200
        else:
            return jsonify({"message": "Invalid username or password"}), 401

# Fetch public key
@app.route('/getPublicKey', methods=['GET'])
def get_public_key():
    username = request.args.get('username')
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT public_key FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user:
            return jsonify({"public_key": user[0]}), 200
        else:
            return jsonify({"message": "User not found"}), 404

# Upload file
@app.route('/upload', methods=['POST'])
def upload():
    data = request.json
    file_content = data['fileContent']
    uploader_id = data['uploaderId']
    recipient_username = data['recipient']
    original_filename = data['filename']
    file_type = data['fileType']
    
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (recipient_username,))
        recipient = c.fetchone()
        if recipient:
            recipient_id = recipient[0]
            filename = base64.b64encode(os.urandom(16)).decode('utf-8')
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(file_path, 'wb') as f:
                f.write(base64.b64decode(file_content))
            
            c.execute('INSERT INTO files (filename, original_filename, file_type, uploader_id, recipient_id) VALUES (?, ?, ?, ?, ?)', 
                      (filename, original_filename, file_type, uploader_id, recipient_id))
            conn.commit()
            return jsonify({"message": "File uploaded successfully"}), 201
        else:
            return jsonify({"message": "Recipient not found"}), 404

# Download file
@app.route('/download', methods=['POST'])
def download():
    data = request.json
    user_id = data['userId']
    
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT filename, original_filename, file_type FROM files WHERE recipient_id = ?', (user_id,))
        files = c.fetchall()
        if files:
            file_content = []
            for file in files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
                with open(file_path, 'rb') as f:
                    file_content.append({
                        "filename": file[1],
                        "fileType": file[2],
                        "content": base64.b64encode(f.read()).decode('utf-8')
                    })
            return jsonify({"fileContent": file_content}), 200
        else:
            return jsonify({"message": "No files found"}), 404

# Fetch all users
@app.route('/users', methods=['GET'])
def get_users():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users')
        users = c.fetchall()
        user_list = [user[0] for user in users]
        return jsonify({"users": user_list}), 200

# Reset the database
@app.route('/reset', methods=['POST'])
def reset_database():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('DROP TABLE IF EXISTS users')
        c.execute('DROP TABLE IF EXISTS files')
        init_db()
        return jsonify({"message": "Database reset successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
