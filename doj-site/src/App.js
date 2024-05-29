import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import HomePage from './pages/Home';
import FileUploadPage from './pages/FileUpload';
import '../src/App.css';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [users, setUsers] = useState([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchUsers();
  }, []);

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

  return (
    <div className="App container">
      <header className="App-header container">

      <BrowserRouter>
        <Routes>
          <Route index element={<HomePage 
          username={username} setUsername={setUsername}
          password={password} setPassword={setPassword}
          />} />
          <Route path="fileUpload" element={<FileUploadPage/>} />
        </Routes>
    </BrowserRouter>
      </header>
    </div>
  );
}

export default App;
