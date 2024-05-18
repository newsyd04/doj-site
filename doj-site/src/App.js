// app.js
import React, { useState } from 'react';
import '../src/App.css';
import { BrowserRouter, Routes, Route} from 'react-router-dom';
import HomePage from './pages/Home';
import FileUploadPage from './pages/FileUpload';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [recipient, setRecipient] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [uploadedFile, setUploadedFile] = useState('');
  const [downloadedFile, setDownloadedFile] = useState('');

  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route index element={<HomePage 
          username={username} setUsername={setUsername}
          password={password} setPassword={setPassword}
          />} />
          <Route path="fileUpload" element={<FileUploadPage/>} />
        </Routes>
    </BrowserRouter>
    </div>
  );
}

export default App;
