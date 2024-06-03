from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS, cross_origin
from twilio.rest import Client
from functools import wraps
import random
import datetime
import jwt
import sqlite3
import os
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
 
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Enable CORS for all routes
 
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['GLYNNY_KEY'] = 'your_secret_key'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
account_sid = 'AC4d823c1fddffabcb067008f2e8b263ab'
auth_token = '9295a1344feaf8046b4a63e34a840535'
twilio_phone_number = '+14795527254'
client = Client(account_sid, auth_token)
 
# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)
 
# Initialize SQLite database
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Create the users and files tables
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT NOT NULL,
                salt TEXT NOT NULL,
                phone TEXT NOT NULL,
                verification_code TEXT
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
 
# Register a new user
@app.route('/register', methods=['POST'])
@cross_origin()
@limiter.limit("5 per minute")
def register():
    # Get user data from request
    data = request.json
    username = data['registerUsername']
    password = data['registerPassword']
    phone = data['registerPhone']
    public_key = data['public_key']
    # Generate salt and hash the password
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    hashed_password = generate_password_hash(password + salt, method='scrypt')
   
    # Insert user data into the database
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, public_key, salt, phone) VALUES (?, ?, ?, ?, ?)',
                      (username, hashed_password, public_key, salt, phone))
            c.execute('SELECT id, password, salt FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            conn.commit()
        token = jwt.encode({'user': username, 'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)}, app.config['GLYNNY_KEY'], algorithm="HS256")
        return jsonify({"message": "User registered successfully", "user_id": user[0], "token": token}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 400
 
# Login user
@app.route('/login', methods=['POST'])
@cross_origin()
@limiter.limit("5 per minute")
def login():
    # Get user data from request
    data = request.json
    username = data['signInUsername']
    password = data['signInPassword']
   
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, password, salt, phone FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        print("User:", user)
        if user and check_password_hash(user[1], password + user[2]):
            verification_code = ''.join(random.choices('0123456789', k=6))
            c.execute('UPDATE users SET verification_code = ? WHERE username = ?', (verification_code, username))
            message = client.messages.create(
                body=f"Your verification code is {verification_code}",
                from_=twilio_phone_number,
                to=user[3]
            )
            return jsonify({"message": "Verification code sent successfully", "phone": user[3]}), 200
        else:
            return jsonify({"message": "Invalid username or password"}), 401
   
@app.route('/verifyCode', methods=['POST'])
@cross_origin()
@limiter.limit("5 per minute")
def verify_code():
    data = request.json
    username = data['signInUsername']
    password = data['signInPassword']
    verification_code = data['verificationCode']
    # Check if the user exists and the password is correct
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, password, salt FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and verification_code and check_password_hash(user[1], password + user[2]) and check_verification_code(username, verification_code):
            token = jwt.encode({'user': username, 'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)}, app.config['GLYNNY_KEY'], algorithm="HS256")
            return jsonify({"message": "Login successful", "user_id": user[0], "token": token}), 200
        else:
            return jsonify({"message": "Invalid username or password or verification code"}), 401
     
#
def check_verification_code(username, verification_code):
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT verification_code FROM users WHERE username = ?', (username,))
        code = c.fetchone()[0]
        # Clear the verification code after an request verification
        # Otherwise spamming the verification code will allow the user to login
        c.execute('UPDATE users SET verification_code = NULL WHERE username = ?', (username,))
        if code == verification_code:
            return True
        else:
            # Return False if the verification code is incorrect
            return False
 
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Token is missing!'}), 403
 
        try:
            token = auth_header.split(" ")[1]  # Extract token after 'Bearer'
            data = jwt.decode(token, app.config['GLYNNY_KEY'], algorithms=["HS256"])
            print("Decoded JWT data:", data)  # Debugging line
        except IndexError:
            return jsonify({'message': 'Token is missing!'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated
 
# Fetch public key
@app.route('/getPublicKey', methods=['GET'])
@cross_origin()
@token_required
@limiter.limit("10 per minute")
def get_public_key():
    user_id_or_name = request.args.get('userId')
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Check if the provided identifier is a username or an ID
        if user_id_or_name.isdigit():
            c.execute('SELECT public_key FROM users WHERE id = ?', (user_id_or_name,))
        else:
            c.execute('SELECT public_key FROM users WHERE username = ?', (user_id_or_name,))
        user = c.fetchone()
        if user:
            public_key = user[0]
            try:
                base64.b64decode(public_key)  # Validate base64 format
                return jsonify({"public_key": public_key}), 200
            except Exception as e:
                return jsonify({"message": "Invalid public key format"}), 400
        else:
            return jsonify({"message": "User not found"}), 404
 
# Upload file
@app.route('/upload', methods=['POST'])
@cross_origin()
@token_required
@limiter.limit("10 per minute")
def upload():
    try:
        data = request.json
        file_content = data['fileContent']
        uploader_id = data['uploaderId']
        recipient_username = data['recipient']
        original_filename = data['filename']
        file_type = data['fileType']
       
        print(f"Received upload request: uploader_id={uploader_id}, recipient={recipient_username}, filename={original_filename}, file_type={file_type}")
 
        if ':' not in file_content:
            return jsonify({"message": "Invalid file content format"}), 400
 
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE username = ?', (recipient_username,))
            recipient = c.fetchone()
            if recipient:
                recipient_id = recipient[0]
                filename = base64.b64encode(os.urandom(16)).decode('utf-8')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
               
                try:
                    with open(file_path, 'w') as f:
                        f.write(file_content)
                        print(f"File written to {file_path} successfully")
                except Exception as e:
                    print(f"Error writing file: {e}")
                    return jsonify({"message": "Error writing file"}), 500
 
                try:
                    c.execute('INSERT INTO files (filename, original_filename, file_type, uploader_id, recipient_id) VALUES (?, ?, ?, ?, ?)',
                              (filename, original_filename, file_type, uploader_id, recipient_id))
                    conn.commit()
                    print(f"File metadata inserted into database successfully")
                except Exception as e:
                    print(f"Error inserting into database: {e}")
                    return jsonify({"message": "Error inserting into database"}), 500
 
                return jsonify({"message": "File uploaded successfully"}), 201
            else:
                print("Recipient not found")
                return jsonify({"message": "Recipient not found"}), 404
    except Exception as e:
        print(f"Internal server error: {e}")
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500
 
# Download file
@app.route('/download', methods=['POST'])
@cross_origin()
@token_required
@limiter.limit("10 per minute")
def download():
    data = request.json
    user_id = data.get('userId')
   
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400
   
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT filename, original_filename, file_type FROM files WHERE recipient_id = ?', (user_id,))
        files = c.fetchall()
       
        if not files:
            return jsonify({"fileContent": []}), 200
       
        file_content = []
        for file in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    file_content.append({
                        "filename": file[1],
                        "fileType": file[2],
                        "content": content
                    })
            else:
                file_content.append({
                    "filename": file[1],
                    "fileType": file[2],
                    "content": None,
                    "error": "File not found"
                })
       
        return jsonify({"fileContent": file_content}), 200
 
# Fetch all users
@app.route('/users', methods=['GET'])
@cross_origin()
@token_required
@limiter.limit("10 per minute")
def get_users():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users')
        users = c.fetchall()
        print("Fetched users:", users)
        user_list = [user[0] for user in users]
        return jsonify({"users": user_list}), 200
 
# Reset the database
@app.route('/reset', methods=['POST'])
@cross_origin()
@token_required
@limiter.limit("1 per minute")
def reset_database():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('DROP TABLE IF EXISTS users')
        c.execute('DROP TABLE IF EXISTS files')
        init_db()
        return jsonify({"message": "Database reset successfully"}), 200
 
if __name__ == '__main__':
    app.run(debug=True, port=5000)