# Secure File Sharing Application

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Cryptographic Algorithms](#cryptographic-algorithms)
- [Setup and Installation](#setup-and-installation)
- [Detailed Walkthrough](#detailed-walkthrough)
- [API Endpoints](#api-endpoints)
- [Error Handling](#error-handling)


## Introduction
This is a Secure File Sharing Application that allows users to securely upload and download files. The application leverages modern cryptographic techniques to ensure data confidentiality and integrity during storage and transfer. Users can register, login, upload files encrypted with their public key, and download files decrypted with their private key.

## Features
- User Registration and Login
- Secure File Upload and Download
- Public Key Encryption
- Cross-Origin Resource Sharing (CORS) enabled
- User and File Management
- JWT Session Authentication
- Rate Limiting enabled
- Minimum Password Requirements
- SQL Injection Attack Prevention
- 2 Factor Authentication

## Technology Stack
- **Frontend**: React.js
- **Backend**: Flask (Python)
- **Database**: SQLite
- **Cryptography**: WebCrypto API (Frontend), Python `cryptography` library (Backend)

## Cryptographic Algorithms
- **Key Pair Generation**: Elliptic-curve Diffie–Hellman (ECDH)
- **Symmetric Encryption**: AES-GCM (Galois/Counter Mode)
- **Password Hashing**: Scrypt

## Setup and Installation

### Prerequisites
- Node.js and npm
- Python 3
- pip (Python package installer)

### Backend Setup
1. Clone the repository:
    ```bash
    git clone https://github.com/newsyd04/doj-site.git
    cd ./cybersecuritysite/
    ```

2. Run the Flask server:
    ```bash
    python app.py
    ```

### Frontend Setup
1. Navigate to the frontend directory:
    ```bash
    cd ./doj-site
    ```

2. Install the required packages:
    ```bash
    npm install
    ```

3. Start the React development server:
    ```bash
    npm start
    ```


## Detailed Walkthrough

### Registration and Login
1. **Registration**: Users register by providing a username and password. The password is salted and hashed using `scrypt` before being stored in the database along with the user's public key.
2. **Login**: Users log in with their username and password. The password is verified using the stored hash and salt.

### File Upload
1. **File Selection**: Users select a file to upload.
2. **Encryption**: The file is read as text and encrypted using a derived AES-GCM key. The encrypted content is formatted as `IV:EncryptedData`.
3. **Upload**: The encrypted file content, along with metadata, is sent to the backend and stored in the database and filesystem.

### File Download
1. **Fetch Files**: Users can fetch a list of files available to them.
2. **Decryption**: The selected file's content (formatted as `IV:EncryptedData`) is retrieved and decrypted using the user's private key.
3. **Download**: The decrypted file is downloaded to the user's device.

### Cryptography Details
- **ECDH**: Used for generating a key pair (public/private keys) for each user.
- **AES-GCM**: Used for symmetric encryption and decryption of files.
- **Scrypt**: Used for securely hashing passwords.

## API Endpoints

### User Endpoints
- **POST /register**: Register a new user.
- **POST /login**: Login an existing user.

### File Endpoints
- **POST /upload**: Upload an encrypted file.
- **POST /download**: Download an encrypted file.
- **GET /getPublicKey**: Fetch a user's public key.
- **GET /users**: Fetch all registered users.
- **POST /reset**: Reset the database.

## Error Handling
The application handles various errors such as:
- User already exists during registration.
- Invalid username or password during login.
- File not found during download.
- Internal server errors.


