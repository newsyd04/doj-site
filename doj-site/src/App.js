import React, { useState, useEffect } from 'react';
import '../src/App.css';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [file, setFile] = useState(null);
  const [recipient, setRecipient] = useState('');
  const [loggedInUser, setLoggedInUser] = useState(null);
  const [message, setMessage] = useState('');
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [users, setUsers] = useState([]);
  const [userId, setUserId] = useState(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  useEffect(() => {
    if (loggedInUser) {
      setRecipient(users.filter(user => user !== loggedInUser)[0] || '');
      fetchFiles();
    }
  }, [users, loggedInUser]);

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
        fetchFiles();  // Fetch files upon login
      }
      setMessage(data.message);
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error logging in.');
    }
  };

  const handleLogout = () => {
    setUserId(null);
    setLoggedInUser(null);
    setFiles([]);
    setMessage('');
  };

  const handleFileUpload = async () => {
    if (!file) {
      setMessage('Please select a file.');
      return;
    }

    const fileContent = await file.text();
    const keyPair = await getKeyPair();
    const recipientPublicKey = await fetchPublicKey(recipient);
    const secretKey = await deriveSecretKey(keyPair.privateKey, recipientPublicKey);
    const encryptedContent = await encryptData(secretKey, fileContent);

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
      fetchFiles();  // Fetch files after uploading a new file
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error uploading file.');
    }
  };

  const fetchFiles = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId })
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data.fileContent) {
        setFiles(data.fileContent);
        setSelectedFile(data.fileContent[0] || null);
      } else {
        setMessage('No files found.');
      }
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error fetching files.');
    }
  };

  const handleFileDownload = async () => {
    if (!selectedFile) {
      setMessage('Please select a file to download.');
      return;
    }

    const keyPair = await getKeyPair();
    const recipientPublicKey = await fetchPublicKey(username);
    const secretKey = await deriveSecretKey(keyPair.privateKey, recipientPublicKey);
    const decryptedContent = await decryptData(secretKey, selectedFile.content);
    const blob = new Blob([decryptedContent], { type: selectedFile.fileType });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedFile.filename;
    a.click();
    window.URL.revokeObjectURL(url);
  };

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
      setUsers([]);
      setFiles([]);
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error resetting database.');
    }
  };

  // WebCrypto functions
  const generateKeyPair = async () => {
    try {
      return await crypto.subtle.generateKey({
        name: "ECDH",
        namedCurve: "P-256"
      }, true, ["deriveKey"]);
    } catch (error) {
      console.error('Error generating key pair:', error);
      throw error;
    }
  };

  const exportKey = async (key) => {
    try {
      const exported = await crypto.subtle.exportKey("spki", key);
      return bufferToBase64(exported);
    } catch (error) {
      console.error('Error exporting key:', error);
      throw error;
    }
  };

  const importKey = async (keyData) => {
    try {
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

  const encryptData = async (key, data) => {
    try {
      const encoder = new TextEncoder();
      const encoded = encoder.encode(data);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv: iv
      }, key, encoded);
      return bufferToBase64(iv) + ':' + bufferToBase64(encrypted);
    } catch (error) {
      console.error('Error encrypting data:', error);
      throw error;
    }
  };

  const decryptData = async (key, data) => {
    try {
      const [iv, encryptedData] = data.split(':').map(base64ToBuffer);
      const decrypted = await crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: iv
      }, key, encryptedData);
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error('Error decrypting data:', error);
      throw error;
    }
  };

  const bufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  const base64ToBuffer = (base64) => {
    const binary = window.atob(base64);
    const len = binary.length;
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      buffer[i] = binary.charCodeAt(i);
    }
    return buffer.buffer;
  };

  const fetchPublicKey = async (username) => {
    try {
      const response = await fetch(`http://127.0.0.1:5000/getPublicKey?username=${username}`);
      const data = await response.json();
      return await importKey(data.public_key);
    } catch (error) {
      console.error('Error fetching public key:', error);
      throw error;
    }
  };

  const getKeyPair = async () => {
    if (!localStorage.getItem('privateKey') || !localStorage.getItem('publicKey')) {
      const keyPair = await generateKeyPair();
      const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const exportedPublicKey = await exportKey(keyPair.publicKey);
      localStorage.setItem('privateKey', bufferToBase64(exportedPrivateKey));
      localStorage.setItem('publicKey', exportedPublicKey);
    }
    try {
      const privateKey = await crypto.subtle.importKey('pkcs8', base64ToBuffer(localStorage.getItem('privateKey')), {
        name: "ECDH",
        namedCurve: "P-256"
      }, true, ["deriveKey"]);
      const publicKey = await importKey(localStorage.getItem('publicKey'));
      return { privateKey, publicKey };
    } catch (error) {
      console.error('Error getting key pair:', error);
      throw error;
    }
  };

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
