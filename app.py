from flask import request, jsonify, g, send_file, Flask
import os
import bcrypt
from flask_cors import CORS
import sqlite3
import jwt
import datetime
from werkzeug.utils import secure_filename
import base64

# Set the secret key to a random string
SECRET_KEY = 'your_secret_key'

# Create the uploads folder if it doesn't exist
UPLOAD_FOLDER = './uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Enable CORS with specific origins
CORS(app, resources={r"/*": {"origins": "*"}})

# Database configuration
DATABASE = 'database.db'

# Encode the auth token
def encode_auth_token(user_id):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    except Exception as e:
        return e

# Decode the auth token
def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

# Database connection functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Reset the database
@app.route('/reset', methods=['POST'])
def reset():
    db = get_db()
    cur = db.cursor()
    cur.execute('''DROP TABLE IF EXISTS users''')
    cur.execute('''DROP TABLE IF EXISTS files''')
    cur.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    public_key TEXT NOT NULL)''')
    cur.execute('''CREATE TABLE files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    sender_id INTEGER NOT NULL,
                    iv BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    FOREIGN KEY (recipient_id) REFERENCES users(id),
                    FOREIGN KEY (sender_id) REFERENCES users(id))''')
    db.commit()
    cur.close()
    return jsonify({'message': 'Database reset successfully!'}), 200

# Register a new user
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password').encode('utf-8')
        public_key = data.get('publicKey')
        
        if not username or not password or not public_key:
            raise ValueError("Missing data")
        
        # Generate a salt and hash the password
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        # Insert into the database
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("INSERT INTO users(username, password, public_key) VALUES (?, ?, ?)", 
                        (username, hashed.decode('utf-8'), public_key))
            db.commit()
            return jsonify({'message': 'User registered successfully!'}), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 400
        finally:
            cur.close()
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Login a user
@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password'].encode('utf-8')

    db = get_db()
    cur = db.cursor()
    result = cur.execute("SELECT id, password FROM users WHERE username = ?", [username])
    
    row = result.fetchone()
    if row:
        user_id, stored_password = row
        stored_password = stored_password.encode('utf-8')
        if bcrypt.checkpw(password, stored_password):
            auth_token = encode_auth_token(user_id)
            if auth_token:
                return jsonify({'message': 'Login successful', 'auth_token': auth_token}), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    else:
        return jsonify({'error': 'User not found'}), 404

# Upload a file
@app.route('/upload', methods=['POST'])
def upload_file():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Authorization header missing'}), 403
    
    auth_token = auth_header.split(" ")[1]
    user_id = decode_auth_token(auth_token)
    if isinstance(user_id, str):
        return jsonify({'error': user_id}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    recipient = request.form['recipient']
    iv = base64.b64decode(request.form['iv'])
    tag = base64.b64decode(request.form['tag'])

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", [recipient])
        recipient_row = cur.fetchone()
        if recipient_row:
            recipient_id = recipient_row[0]
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cur.execute("INSERT INTO files(filename, recipient_id, sender_id, iv, tag) VALUES (?, ?, ?, ?, ?)", 
                        (filename, recipient_id, user_id, iv, tag))
            db.commit()
            return jsonify({'message': 'File uploaded successfully'}), 201
        else:
            return jsonify({'error': 'Recipient not found'}), 404

# Download a file
@app.route('/download', methods=['GET'])
def download_file():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Authorization header missing'}), 403
    
    auth_token = auth_header.split(" ")[1]
    user_id = decode_auth_token(auth_token)
    if isinstance(user_id, str):
        return jsonify({'error': user_id}), 403

    filename = request.args.get('filename')
    if filename:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT recipient_id, iv, tag FROM files WHERE filename = ?", [filename])
        file_row = cur.fetchone()
        if file_row and file_row[0] == user_id:
            iv = base64.b64encode(file_row[1]).decode('utf-8')
            tag = base64.b64encode(file_row[2]).decode('utf-8')
            return jsonify({'file': send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True),
                            'iv': iv, 'tag': tag})
        else:
            return jsonify({'error': 'File not found or access denied'}), 404
    else:
        return jsonify({'error': 'Filename not provided'}), 400

# List files
@app.route('/files', methods=['GET'])
def list_files():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Authorization header missing'}), 403
    
    auth_token = auth_header.split(" ")[1]
    user_id = decode_auth_token(auth_token)
    if isinstance(user_id, str):
        return jsonify({'error': user_id}), 403

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT filename FROM files WHERE recipient_id = ?", [user_id])
    files = [row[0] for row in cur.fetchall()]
    return jsonify({'files': files}), 200

# Get public key
@app.route('/getPublicKey', methods=['POST'])
def get_public_key():
    recipient = request.json['recipient']
    db = get_db()
    cur = db.cursor()
    result = cur.execute("SELECT public_key FROM users WHERE username = ?", [recipient])
    row = result.fetchone()
    if row:
        public_key = row[0]
        return jsonify({'publicKey': public_key}), 200
    else:
        return jsonify({'error': 'Recipient not found'}), 404

# List all users
@app.route('/users', methods=['GET'])
def list_users():
    db = get_db()
    cur = db.cursor()
    result = cur.execute("SELECT username FROM users")
    users = [row[0] for row in result.fetchall()]
    cur.close()
    return jsonify({'users': users}), 200

if __name__ == "__main__":
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       username TEXT UNIQUE NOT NULL,
                       password TEXT NOT NULL,
                       public_key TEXT NOT NULL)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS files
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       filename TEXT NOT NULL,
                       recipient_id INTEGER NOT NULL,
                       sender_id INTEGER NOT NULL,
                       iv BLOB NOT NULL,
                       tag BLOB NOT NULL,
                       FOREIGN KEY (recipient_id) REFERENCES users(id),
                       FOREIGN KEY (sender_id) REFERENCES users(id))''')
        db.commit()
        cur.close()
    app.run(debug=True)  # Remove SSL
