from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS, cross_origin
from functools import wraps
import datetime
import jwt
import sqlite3
import os
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'your_secret_key'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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

# Register a new user
@app.route('/register', methods=['POST'])
@cross_origin()
@limiter.limit("5 per minute")
def register():
    # Get user data from request
    data = request.json
    username = data['registerUsername']
    password = data['registerPassword']
    public_key = data['public_key']
    # Generate salt and hash the password
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    hashed_password = generate_password_hash(password + salt, method='scrypt')
    
    # Insert user data into the database
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, public_key, salt) VALUES (?, ?, ?, ?)', 
                      (username, hashed_password, public_key, salt))
            c.execute('SELECT id, password, salt FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            conn.commit()
        token = jwt.encode({'user': username, 'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
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
    
    # Check if the user exists and the password is correct
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, password, salt FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and check_password_hash(user[1], password + user[2]):
            token = jwt.encode({'user': username, 'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({"message": "Login successful", "user_id": user[0], "token": token}), 200
        else:
            return jsonify({"message": "Invalid username or password"}), 401
     
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            token = auth_header.split(" ")[1]  # Extract token after 'Bearer'
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
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
@limiter.limit("10 per minute")
def get_public_key():
    # Get username from request
    username = request.args.get('userId')
    # Fetch public key from the database
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT public_key FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        # Return the public key if the user exists
        if user:
            return jsonify({"public_key": user[0]}), 200
        else:
            return jsonify({"message": "User not found"}), 404

# Upload file
@app.route('/upload', methods=['POST'])
@cross_origin()
@token_required
@limiter.limit("10 per minute")
def upload():
    try:
        # Get file data from request
        data = request.json
        file_content = data['fileContent']
        uploader_id = data['uploaderId']
        recipient_username = data['recipient']
        original_filename = data['filename']
        file_type = data['fileType']
        
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            # Check if the recipient exists
            c.execute('SELECT id FROM users WHERE username = ?', (recipient_username,))
            recipient = c.fetchone()
            if recipient:
                recipient_id = recipient[0] # Get the recipient ID
                filename = base64.b64encode(os.urandom(16)).decode('utf-8') # Generate a random filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) # Store the file in the uploads folder
                with open(file_path, 'wb') as f:
                    f.write(file_content.encode())  # Store as text
                # Insert file data into the database
                c.execute('INSERT INTO files (filename, original_filename, file_type, uploader_id, recipient_id) VALUES (?, ?, ?, ?, ?)', 
                          (filename, original_filename, file_type, uploader_id, recipient_id))
                conn.commit()
                return jsonify({"message": "File uploaded successfully"}), 201
            else:
                return jsonify({"message": "Recipient not found"}), 404
    except Exception as e:
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
        c.execute('SELECT filename, original_filename, file_type FROM files WHERE recipient_id = ?', (user_id,)) # Fetch files uploaded for the user
        files = c.fetchall()
        
        if not files:
            return jsonify({"message": "No files found"}), 404 # Return 404 if no files are found
        
        file_content = []
        for file in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0]) # Get the file path
            if os.path.exists(file_path): # Check if the file exists
                with open(file_path, 'r') as f: # Open the file
                    file_content.append({ # Append the file content to the list
                        "filename": file[1],
                        "fileType": file[2],
                        "content": f.read()  # Read as text
                    })
            else:
                file_content.append({ # Append an error message if the file is not found
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
        # Fetch all users from the database
        c.execute('SELECT username FROM users')
        # Convert the list of tuples to a list of strings
        users = c.fetchall()
        # Extract the usernames from the list of tuples
        user_list = [user[0] for user in users]
        # Return the list of usernames
        return jsonify({"users": user_list}), 200

# Reset the database
@app.route('/reset', methods=['POST'])
@cross_origin()
@token_required
@limiter.limit("1 per minute")
def reset_database():
    # Drop the tables and reinitialize them
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Drop the tables
        c.execute('DROP TABLE IF EXISTS users')
        c.execute('DROP TABLE IF EXISTS files')
        # Reinitialize the database
        init_db()
        return jsonify({"message": "Database reset successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
