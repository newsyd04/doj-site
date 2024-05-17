# app.py

from flask import Flask, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from secrets import token_hex
from Crypto.Cipher import AES
import base64
import os

app = Flask(__name__)

# Placeholder database
users_db = {}

# Function to generate AES key
def generate_aes_key():
    return os.urandom(32)  # 256-bit key

# Function to encrypt data with AES-GCM
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag, cipher.nonce

# Function to decrypt data with AES-GCM
def decrypt_data(ciphertext, tag, nonce, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    # Generate salt and hash password
    salt = token_hex(16)
    hashed_password = generate_password_hash(password + salt)
    
    # Store user in database
    users_db[username] = {'hashed_password': hashed_password, 'salt': salt}
    
    return jsonify({'message': 'Registration successful'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    # Check if user exists
    if username not in users_db:
        return jsonify({'message': 'User not found'}), 404
    
    # Verify password
    stored_password = users_db[username]['hashed_password']
    salt = users_db[username]['salt']
    if not check_password_hash(stored_password, password + salt):
        return jsonify({'message': 'Incorrect password'}), 401
    
    return jsonify({'message': 'Login successful'})

# Route for file upload
@app.route('/upload', methods=['POST'])
def upload():
    data = request.get_json()
    username = data['username']
    file_content = data['file_content']
    recipient = data['recipient']
    
    # Check if recipient exists
    if recipient not in users_db:
        return jsonify({'message': 'Recipient not found'}), 404
    
    # Generate AES key for encryption
    aes_key = generate_aes_key()
    
    # Encrypt file content
    ciphertext, tag, nonce = encrypt_data(file_content.encode(), aes_key)
    
    # Store encrypted file in database (for demonstration, you'd save this in a database or file system)
    encrypted_file = {'ciphertext': base64.b64encode(ciphertext).decode(),
                      'tag': base64.b64encode(tag).decode(),
                      'nonce': base64.b64encode(nonce).decode(),
                      'sender': username,
                      'recipient': recipient}
    
    return jsonify({'message': 'File uploaded successfully', 'encrypted_file': encrypted_file})

# Route for file download
@app.route('/download', methods=['POST'])
def download():
    data = request.get_json()
    username = data['username']
    file_info = data['file_info']
    
    # Decrypt file
    ciphertext = base64.b64decode(file_info['ciphertext'])
    tag = base64.b64decode(file_info['tag'])
    nonce = base64.b64decode(file_info['nonce'])
    sender = file_info['sender']
    
    # Check if user has access to the file
    if username != sender:
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Retrieve sender's AES key (for demonstration, you'd implement a secure key exchange)
    aes_key = generate_aes_key()  # Placeholder, should retrieve from a secure storage
    
    # Decrypt file content
    decrypted_file_content = decrypt_data(ciphertext, tag, nonce, aes_key)
    
    return jsonify({'message': 'File downloaded successfully', 'file_content': decrypted_file_content.decode()})

if __name__ == "__main__":
    app.run(debug=True)
