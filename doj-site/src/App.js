import React, { useEffect, useState } from 'react';
import './App.css';

function App() {
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetch('http://localhost:5000/') // Flask runs on port 5000 by default
      .then(response => response.text())
      .then(message => setMessage(message));
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <p>
          Message from Flask: {message}
        </p>
      </header>
    </div>
  );
}

export default App;
