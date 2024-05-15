import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [file, setFile] = useState(null);
  const [recipient, setRecipient] = useState('');
  const [files, setFiles] = useState([]);
  const [users, setUsers] = useState([]);
  const [loggedInUser, setLoggedInUser] = useState(localStorage.getItem('loggedInUser') || '');

  const handleRegister = () => {
    generateKeyPair().then(() => {
      const publicKey = localStorage.getItem('publicKey');
      console.log('Registering with:', { username, password, publicKey });
      fetch('http://localhost:5000/register', {  // Use HTTP
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password, publicKey }),
      })
        .then(response => {
          if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error); });
          }
          return response.json();
        })
        .then(data => setMessage(data.message))
        .catch(error => {
          console.error('Error:', error);
          setMessage(error.message || 'Registration failed');
        });
    });
  };

  const handleLogin = () => {
    fetch('http://localhost:5000/login', {  // Use HTTP
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    })
      .then(response => response.json())
      .then(data => {
        if (data.auth_token) {
          localStorage.setItem('auth_token', data.auth_token);
          localStorage.setItem('loggedInUser', username);
          setLoggedInUser(username);
          setMessage('Login successful');
        } else {
          setMessage(data.error);
        }
      })
      .catch(error => console.error('Error:', error));
  };

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('loggedInUser');
    setLoggedInUser('');
    setMessage('Logged out successfully');
  };

  const generateKeyPair = async () => {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );

    const privateKey = await window.crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );

    // Encode keys in base64 and store them
    localStorage.setItem("publicKey", btoa(String.fromCharCode(...new Uint8Array(publicKey))));
    localStorage.setItem("privateKey", btoa(String.fromCharCode(...new Uint8Array(privateKey))));
  };

  const stringToUint8Array = (str) => {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
  };

  const encryptFile = async (file, recipientPublicKey) => {
    console.log('Encrypting file with recipient public key:', recipientPublicKey);

    try {
      // Decode the base64-encoded public key
      const publicKeyArrayBuffer = stringToUint8Array(recipientPublicKey);
      console.log('Decoded public key array buffer:', publicKeyArrayBuffer);

      const publicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyArrayBuffer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["encrypt"]
      );

      console.log('Public key imported successfully:', publicKey);

      const aesKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      const fileArrayBuffer = await file.arrayBuffer();
      console.log('File array buffer:', fileArrayBuffer);

      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encryptedContent = await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        aesKey,
        fileArrayBuffer
      );

      const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
      const encryptedAesKey = await window.crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP'
        },
        publicKey,
        exportedAesKey
      );

      const encryptedFile = new Blob([iv, new Uint8Array(encryptedContent)], { type: file.type });
      const ivString = btoa(String.fromCharCode(...iv));
      const tag = encryptedContent.slice(-16); // AES-GCM authentication tag
      const tagString = btoa(String.fromCharCode(...new Uint8Array(tag)));
      console.log('Encrypted file:', encryptedFile);
      console.log('IV:', ivString);
      console.log('Tag:', tagString);

      return { encryptedFile, ivString, tagString };
    } catch (error) {
      console.error('Error during file encryption:', error);
      throw error;
    }
  };

  const decryptFile = async (file, iv, tag) => {
    try {
      const privateKeyString = localStorage.getItem('privateKey');
      const privateKeyArrayBuffer = stringToUint8Array(privateKeyString);
      const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        privateKeyArrayBuffer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["decrypt"]
      );

      console.log('Private key imported successfully:', privateKey);

      const encryptedFileArrayBuffer = await file.arrayBuffer();
      const ivArrayBuffer = stringToUint8Array(iv);
      const tagArrayBuffer = stringToUint8Array(tag);

      const aesKeyArrayBuffer = encryptedFileArrayBuffer.slice(0, 256); // Adjust based on actual key length
      const encryptedContentArrayBuffer = encryptedFileArrayBuffer.slice(256); // Adjust based on actual key length

      const aesKey = await window.crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        aesKeyArrayBuffer
      );

      const decryptedContent = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ivArrayBuffer,
          additionalData: tagArrayBuffer
        },
        aesKey,
        encryptedContentArrayBuffer
      );

      const decryptedFile = new Blob([new Uint8Array(decryptedContent)], { type: file.type });
      console.log('Decrypted file:', decryptedFile);

      return decryptedFile;
    } catch (error) {
      console.error('Error during file decryption:', error);
      throw error;
    }
  };

  const handleFileUpload = async () => {
    const recipientPublicKey = await fetch('http://localhost:5000/getPublicKey', {  // Use HTTP
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ recipient })
    })
    .then(response => response.json())
    .then(data => {
      console.log('Fetched recipient public key:', data.publicKey);
      return data.publicKey;
    })
    .catch(error => {
      console.error('Error fetching public key:', error);
      throw error;
    });

    try {
      const { encryptedFile, ivString, tagString } = await encryptFile(file, recipientPublicKey);

      const formData = new FormData();
      formData.append('file', encryptedFile, file.name);  // Ensure the original filename is preserved
      formData.append('recipient', recipient);
      formData.append('iv', ivString);
      formData.append('tag', tagString);

      fetch('http://localhost:5000/upload', {  // Use HTTP
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: formData,
      })
        .then(response => response.json())
        .then(data => setMessage(data.message))
        .catch(error => console.error('Error during file upload:', error));
    } catch (error) {
      console.error('Error during file encryption or upload:', error);
      setMessage('File upload failed');
    }
  };

  const handleFileDownload = (filename) => {
    fetch(`http://localhost:5000/download?filename=${filename}`, {  // Use HTTP
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
      },
    })
      .then(response => response.json())
      .then(async data => {
        const blob = data.file;
        const iv = data.iv;
        const tag = data.tag;

        try {
          const decryptedBlob = await decryptFile(blob, iv, tag);
          const url = window.URL.createObjectURL(decryptedBlob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;  // Preserve the original filename during download
          a.click();
        } catch (error) {
          console.error('Error during file decryption:', error);
          setMessage('File decryption failed');
        }
      })
      .catch(error => console.error('Error during file download:', error));
  };

  const fetchFiles = () => {
    fetch('http://localhost:5000/files', {  // Use HTTP
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
      },
    })
      .then(response => response.json())
      .then(data => setFiles(data.files))
      .catch(error => console.error('Error fetching files:', error));
  };

  const fetchUsers = () => {
    fetch('http://localhost:5000/users', {  // Use HTTP
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
      },
    })
      .then(response => response.json())
      .then(data => setUsers(data.users))
      .catch(error => console.error('Error fetching users:', error));
  };

  const resetDatabase = () => {
    fetch('http://localhost:5000/reset', {  // Use HTTP
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    })
      .then(response => response.json())
      .then(data => {
        setMessage(data.message);
        fetchUsers();
        setFiles([]);
      })
      .catch(error => {
        console.error('Error resetting database:', error);
        setMessage('Database reset failed');
      });
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>Secure File Sharing</h1>
        {loggedInUser && <p>Logged in as: {loggedInUser}</p>}
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
        <button onClick={handleRegister}>Register</button>
        <button onClick={handleLogin}>Login</button>
        {loggedInUser && <button onClick={handleLogout}>Logout</button>}
        <p>{message}</p>
        <input
          type="file"
          onChange={e => setFile(e.target.files[0])}
        />
        <input
          type="text"
          placeholder="Recipient"
          value={recipient}
          onChange={e => setRecipient(e.target.value)}
        />
        <button onClick={handleFileUpload}>Upload</button>
        <button onClick={fetchFiles}>Fetch Files</button>
        <ul>
          {files.map(file => (
            <li key={file}>
              {file} <button onClick={() => handleFileDownload(file)}>Download</button>
            </li>
          ))}
        </ul>
        <h2>Current Users</h2>
        <ul>
          {users.map(user => (
            <li key={user}>{user}</li>
          ))}
        </ul>
        <button onClick={resetDatabase}>Reset Database</button>
      </header>
    </div>
  );
}

export default App;
