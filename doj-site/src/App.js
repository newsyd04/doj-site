// app.js

import React, { useState } from 'react';
import '../src/App.css';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [recipient, setRecipient] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [uploadedFile, setUploadedFile] = useState('');
  const [downloadedFile, setDownloadedFile] = useState('');

  const handleRegister = async () => {
    try {
      const response = await fetch('/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      console.log(data);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const handleLogin = async () => {
    try {
      const response = await fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      console.log(data);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const handleUpload = async () => {
    try {
      const response = await fetch('/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, file_content: fileContent, recipient }),
      });
      const data = await response.json();
      console.log(data);
      setUploadedFile(data.encrypted_file);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const handleDownload = async () => {
    try {
      const response = await fetch('/download', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, file_info: uploadedFile }),
      });
      const data = await response.json();
      console.log(data);
      setDownloadedFile(data.file_content);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  return (
    <div className="App container">
      <header className="container">
        <h1>Secure File Sharing</h1>
        <div>
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
        </div>
        <div>
          <h2>Upload File</h2>
          <textarea
            placeholder="File Content"
            value={fileContent}
            onChange={e => setFileContent(e.target.value)}
          ></textarea>
          <input
            type="text"
            placeholder="Recipient"
            value={recipient}
            onChange={e => setRecipient(e.target.value)}
          />
          <button onClick={handleUpload}>Upload</button>
          {uploadedFile && <p>File Uploaded: {JSON.stringify(uploadedFile)}</p>}
        </div>
        <div>
          <h2>Download File</h2>
          <button onClick={handleDownload}>Download</button>
          {downloadedFile && <p>File Content: {downloadedFile}</p>}
        </div>
      </header>
    </div>
  );
}

export default App;
