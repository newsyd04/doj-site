import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import HomePage from './pages/Home';
import FileUploadPage from './pages/FileUpload';
import { ToastNotification } from '@carbon/react';
import '@carbon/react/scss/components/notification/_index.scss';
import '../src/App.css';
import './styling/notification.css';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [users, setUsers] = useState([]);
  const [message, setMessage] = useState('');
  const [userId, setUserId] = useState('');
  const [successToastOpen, setSuccessToastOpen] = useState(false);
  const [isErrorMessage, setIsErrorMessage] = useState(true);

  

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

  const showToast = (message, isErrorMessage) => {
    setMessage(message);
    setIsErrorMessage(isErrorMessage);
    setSuccessToastOpen(true);

    setTimeout(() => {
      setSuccessToastOpen(false);
    }, 6000);
  };

  return (
    <div className="App container">
      <header className="App-header container">
      {successToastOpen && (
              <ToastNotification
                className='notification'
                kind={isErrorMessage ? 'error' : 'success'} // or "error", "info", "warning"
                title={message}
                onCloseButtonClick={() => setSuccessToastOpen(false)}
              />
            )}

      <BrowserRouter>
        <Routes>
          <Route index element={<HomePage 
          username={username} setUsername={setUsername}
          password={password} setPassword={setPassword}
          showToast={showToast}
          userId={userId} setUserId={setUserId}
          />} />
          <Route path="fileUpload" element={<FileUploadPage/>} />
        </Routes>
    </BrowserRouter>
      </header>
    </div>
  );
}

export default App;
