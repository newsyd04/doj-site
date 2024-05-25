import React, { useState, useEffect, useCallback } from 'react';
import '../src/App.css';

function App() {
  // State variables to manage form inputs and application data
  const [username, setUsername] = useState(''); // State to manage username input
  const [password, setPassword] = useState(''); // State to manage password input
  const [file, setFile] = useState(null); // State to manage file upload
  const [recipient, setRecipient] = useState(''); // State to manage selected recipient for file sharing
  const [loggedInUser, setLoggedInUser] = useState(null); // State to manage the currently logged-in user
  const [message, setMessage] = useState(''); // State to manage status messages
  const [files, setFiles] = useState([]); // State to manage list of files
  const [selectedFile, setSelectedFile] = useState(null); // State to manage selected file for download
  const [users, setUsers] = useState([]); // State to manage list of users
  const [userId, setUserId] = useState(null); // State to manage the user ID of the logged-in user

  // Fetch users when the component mounts
  useEffect(() => {
    fetchUsers();
  }, []);

  // Update recipient when users or loggedInUser change
  useEffect(() => {
    if (loggedInUser) {
      setRecipient(users.filter(user => user !== loggedInUser)[0] || '');
    }
  }, [users, loggedInUser]);



  // Fetch Users, Register, Login, Logout

  // Function to fetch the list of users from the server
  const fetchUsers = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/users');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setUsers(data.users);
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error fetching users.');
    }
  };

  // Function to handle user registration
  const handleRegister = async () => {
    const keyPair = await generateKeyPair();
    const publicKey = await exportKey(keyPair.publicKey);
    try {
      const response = await fetch('http://127.0.0.1:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, public_key: publicKey })
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error registering user.');
    }
  };

  // Function to handle user login
  const handleLogin = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.user_id) {
        setUserId(data.user_id);
        setLoggedInUser(username);
        setMessage(data.message);
      }
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error logging in.');
    }
  };

  // Function to handle user logout
  const handleLogout = () => {
    setUserId(null);
    setLoggedInUser(null);
    setFiles([]);
    setMessage('');
  };



  // Fetch files, download, and upload a file to the server

  // Function to handle file upload
  const handleFileUpload = async () => {
    if (!file) {
      setMessage('Please select a file.');
      return;
    }

    const fileContent = await file.text(); // Read file content as text
    const keyPair = await getKeyPair(); // Get key pair for the current user
    const recipientPublicKey = await fetchPublicKey(recipient); // Fetch recipient's public key
    const secretKey = await deriveSecretKey(keyPair.privateKey, recipientPublicKey); // Derive a shared secret key
    const encryptedContent = await encryptData(secretKey, fileContent); // Encrypt the file content

    try {
      const response = await fetch('http://127.0.0.1:5000/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileContent: encryptedContent, 
          uploaderId: userId, 
          recipient,
          filename: file.name,
          fileType: file.type
        })
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setMessage(data.message);
      fetchFiles(userId); // Fetch files after uploading a new file
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error uploading file.');
    }
  };


  // Function to fetch the list of files from the server
  const fetchFiles = useCallback(async (id) => {
    console.log('Fetching files for user ID:', id); // Debug log
    if (!id) {
      setMessage('User ID is required to fetch files.');
      return;
    }

    try {
      const response = await fetch('http://127.0.0.1:5000/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: id })
      });
      console.log('Response status:', response.status); // Debug log
      if (!response.ok) {
        if (response.status === 404) {
          setMessage('No files found.');
        } else {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
      } else {
        const data = await response.json();
        console.log('Files data:', data); // Debug log
        if (data.fileContent) {
          const validFiles = data.fileContent.filter(file => file.content !== null);
          const invalidFiles = data.fileContent.filter(file => file.content === null);

          if (invalidFiles.length > 0) {
            setMessage(`Some files could not be found: ${invalidFiles.map(file => file.filename).join(', ')}`);
          }
          
          setFiles(validFiles);
          setSelectedFile(validFiles[0] || null);
        } else {
          setMessage('No files found.');
        }
      }
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error fetching files.');
    }
  }, []);



  // Function to handle file download
  const handleFileDownload = async () => {
    if (!selectedFile) {
      setMessage('Please select a file to download.');
      return;
    }

    const keyPair = await getKeyPair(); // Get key pair for the current user
    const recipientPublicKey = await fetchPublicKey(username); // Fetch public key of the current user
    const secretKey = await deriveSecretKey(keyPair.privateKey, recipientPublicKey); // Derive a shared secret key

    try {
      // Log the content to be decrypted
      console.log('Selected File Content:', selectedFile.content);

      if (!selectedFile.content || typeof selectedFile.content !== 'string' || !selectedFile.content.includes(':')) {
        throw new Error('Selected file content is not a valid base64 string or is incorrectly formatted.');
      }

      const decryptedContent = await decryptData(secretKey, selectedFile.content); // Decrypt the file content
      const blob = new Blob([decryptedContent], { type: selectedFile.fileType }); // Create a Blob from the decrypted content
      const url = window.URL.createObjectURL(blob); // Create a URL for the Blob
      const a = document.createElement('a'); // Create an anchor element
      a.href = url; // Set the href attribute to the Blob URL
      a.download = selectedFile.filename; // Set the download attribute to the file name
      a.click(); // Trigger a click event to download the file
      window.URL.revokeObjectURL(url); // Revoke the Blob URL
    } catch (error) {
      setMessage('Error decrypting file.');
      console.error('Error during file download:', error);
    }
  };



  // utility functions

  // Function to reset the database
  const resetDatabase = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setMessage(data.message);
      setUsers([]); // Clear the users list
      setFiles([]); // Clear the files list
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error resetting database.');
    }
  };

  // WebCrypto API functions for cryptographic operations

  // Generate an ECDH key pair with P-256 curve
  const generateKeyPair = async () => {
    try {
      // Generate an ECDH key pair with P-256 curve
      return await crypto.subtle.generateKey({
        // ECDH key generation options
        name: "ECDH",
        namedCurve: "P-256"
      }, true, ["deriveKey"]);
    } catch (error) {
      console.error('Error generating key pair:', error);
      throw error;
    }
  };

  // Export the public key in SPKI format
  const exportKey = async (key) => {
    try {
      const exported = await crypto.subtle.exportKey("spki", key);
      return bufferToBase64(exported);
    } catch (error) {
      console.error('Error exporting key:', error);
      throw error;
    }
  };

  // Import the public key from SPKI format
  const importKey = async (keyData) => {
    try {
      // Convert the base64-encoded key to a buffer
      const binaryKey = base64ToBuffer(keyData);
      return await crypto.subtle.importKey("spki", binaryKey, {
        name: "ECDH",
        namedCurve: "P-256"
      }, true, []);
    } catch (error) {
      console.error('Error importing key:', error);
      throw error;
    }
  };

  // Derive a shared secret key using ECDH and AES-GCM
  const deriveSecretKey = async (privateKey, publicKey) => {
    try {
      return await crypto.subtle.deriveKey({
        name: "ECDH",
        public: publicKey
      }, privateKey, {
        name: "AES-GCM",
        length: 256
      }, false, ["encrypt", "decrypt"]);
    } catch (error) {
      console.error('Error deriving secret key:', error);
      throw error;
    }
  };

  // Encrypt data using AES-GCM with a shared secret key
  const encryptData = async (key, data) => {
    try {
      const encoder = new TextEncoder(); // TextEncoder to encode the data
      const encoded = encoder.encode(data); // Encode the data as a Uint8Array
      const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate a random IV
      const encrypted = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv: iv
      }, key, encoded);

      // Return IV and encrypted data in the format IV:EncryptedData
      return `${bufferToBase64(iv)}:${bufferToBase64(encrypted)}`;
    } catch (error) {
      console.error('Error encrypting data:', error);
      throw error;
    }
  };

  // Decrypt data using AES-GCM with a shared secret key
  const decryptData = async (key, data) => {
    try {
      const parts = data.split(':');
      if (parts.length !== 2) {
        throw new Error('Invalid base64 string format. Expected format: IV:EncryptedData');
      }

      const [ivBase64, encryptedDataBase64] = parts;

      // Log base64 strings before decoding
      console.log('IV Base64:', ivBase64);
      console.log('Encrypted Data Base64:', encryptedDataBase64);

      const iv = base64ToBuffer(ivBase64); // Convert IV from base64 to buffer
      const encryptedData = base64ToBuffer(encryptedDataBase64); // Convert encrypted data from base64 to buffer

      // Log the types of iv and encryptedData to ensure they are correct
      console.log('IV Type:', iv instanceof ArrayBuffer || ArrayBuffer.isView(iv)); // Should log true
      console.log('Encrypted Data Type:', encryptedData instanceof ArrayBuffer || ArrayBuffer.isView(encryptedData)); // Should log true

      const decrypted = await crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: iv
      }, key, encryptedData);

      const decoder = new TextDecoder(); // TextDecoder to decode the data
      return decoder.decode(decrypted); // Decode the decrypted data
    } catch (error) {
      console.error('Error decrypting data:', error);
      throw error;
    }
  };

  // Helper functions to convert between buffers and base64 strings
  const bufferToBase64 = (buffer) => {
    let binary = ''; // Create a binary string from the buffer
    const bytes = new Uint8Array(buffer); // Create a byte array from the buffer
    const len = bytes.byteLength; // Get the byte length of the buffer
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary); // Return the base64 string
  };


  // Helper function to convert base64 strings to buffers
  const base64ToBuffer = (base64) => {
    try {
      const binary = window.atob(base64); // Decode the base64 string
      const len = binary.length; // Get the length of the binary string
      const buffer = new Uint8Array(len); // Create a buffer from the binary string
      // Fill the buffer with the binary data
      for (let i = 0; i < len; i++) {
        buffer[i] = binary.charCodeAt(i);
      }
      return buffer; // Return the buffer
    } catch (error) {
      console.error('Error converting base64 to buffer:', error);
      throw new Error('Failed to convert base64 to buffer: The string to be decoded is not correctly encoded.');
    }
  };


  // Function to fetch the public key of a user
  const fetchPublicKey = async (username) => {
    try {
      // Fetch the public key from the server
      const response = await fetch(`http://127.0.0.1:5000/getPublicKey?username=${username}`);
      const data = await response.json(); // Parse the JSON response
      return await importKey(data.public_key);
    } catch (error) {
      console.error('Error fetching public key:', error);
      throw error;
    }
  };

  // Function to get the key pair for the current user
  const getKeyPair = async () => {
    if (!localStorage.getItem('privateKey') || !localStorage.getItem('publicKey')) { // Check if keys are stored in local storage
      const keyPair = await generateKeyPair(); // Generate a new key pair
      const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey); // Export the private key
      const exportedPublicKey = await exportKey(keyPair.publicKey); // Export the public key
      localStorage.setItem('privateKey', bufferToBase64(exportedPrivateKey)); // Store the private key in local storage
      localStorage.setItem('publicKey', exportedPublicKey); // Store the public key in local storage
    }
    try {
      const privateKey = await crypto.subtle.importKey('pkcs8', base64ToBuffer(localStorage.getItem('privateKey')), { // Import the private key
        name: "ECDH",
        namedCurve: "P-256"
      }, true, ["deriveKey"]);
      const publicKey = await importKey(localStorage.getItem('publicKey')); // Import the public key
      return { privateKey, publicKey }; // Return the key pair
    } catch (error) {
      console.error('Error getting key pair:', error);
      throw error;
    }
  };

  // Render the component UI
  return (
    <div className="App container">
      <header className="App-header container">
        <h1>Secure File Sharing</h1>
        <p>{message}</p>
        {loggedInUser && <p>Logged in as: {loggedInUser}</p>}
        <div className="grid">
          <div>
            <article>
              <h2>Login/Register</h2>
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
              <button className='buttonpadding' onClick={handleRegister}>Register</button>
              <button className='buttonpadding' onClick={handleLogin}>Login</button>
              {loggedInUser && <button className='buttonpadding' onClick={handleLogout}>Logout</button>}
            </article>
          </div>
          <div>
            <article>
              <h2>Current Users</h2>
              <ul>
                {users.map(user => (
                  <li key={user}>{user}</li>
                ))}
              </ul>
              <button onClick={resetDatabase}>Reset Database</button>
            </article>
          </div>
        </div>
        {loggedInUser && (
          <div className='grid'>
            <div>
              <article>
                <h2>File Sharing</h2>
                <input
                  type="file"
                  onChange={e => setFile(e.target.files[0])}
                />
                <select
                  value={recipient}
                  onChange={e => setRecipient(e.target.value)}
                >
                  {users.filter(user => user !== loggedInUser).map(user => (
                    <option key={user} value={user}>{user}</option>
                  ))}
                </select>
                <button className='buttonpadding' onClick={handleFileUpload}>Upload</button>
              </article>
            </div>
            <div>
              <article>
                <h2>Received Files</h2>
                <select
                  value={selectedFile ? selectedFile.content : ''}
                  onChange={e => setSelectedFile(files.find(file => file.content === e.target.value))}
                >
                  {files.map(file => (
                    <option key={file.content} value={file.content}>{file.filename}</option>
                  ))}
                </select>
                <button className='buttonpadding' onClick={() => fetchFiles(userId)}>Fetch Files</button> {/* Button to manually fetch files */}
                <button className='buttonpadding' onClick={handleFileDownload}>Download</button>
              </article>
            </div>
          </div>
        )}
      </header>
    </div>
  );
}

export default App;
