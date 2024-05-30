import React, { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import HomePage from './pages/Home';
import FileUploadPage from './pages/FileUpload';
import { ToastNotification } from '@carbon/react';
import '@carbon/react/scss/components/notification/_index.scss';
import '../src/App.css';
import './styling/notification.css';

function App() {
  const [message, setMessage] = useState('');
  const [userId, setUserId] = useState('');
  const [successToastOpen, setSuccessToastOpen] = useState(false);
  const [isErrorMessage, setIsErrorMessage] = useState(true);
  const [JWT, setJWT] = useState('');

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
          showToast={showToast}
          userId={userId} setUserId={setUserId}
          JWT={JWT} setJWT={setJWT}
          />} />
          <Route path="fileUpload" element={<FileUploadPage
          showToast={showToast}
          JWT={JWT}
          userId={userId}
          />} />
        </Routes>
    </BrowserRouter>
      </header>
    </div>
  );
}

export default App;
