import React, { useState, useEffect } from 'react';
import { Tile, TextInput, FormGroup, Button } from '@carbon/react';
import { useNavigate } from 'react-router-dom';
import '@carbon/react/scss/components/tile/_index.scss';
import '@carbon/react/scss/components/text-input/_index.scss';
import '@carbon/react/scss/components/button/_index.scss';
import '@carbon/react/scss/components/stack/_index.scss';

export default function Home({ setUsername, setPassword}) {

    const [registerUsername, setRegisterUsername] = useState('');
    const [registerPassword, setRegisterPassword] = useState('');
    const [confirmRegisterPassword, setConfirmRegisterPassword] = useState('');

    const [signInUsername, setSignInUsername] = useState('');
    const [signInPassword, setSignInPassword] = useState('');
    const [confirmSignInPassword, setConfirmSignInPassword] = useState('');


    const [message, setMessage] = useState('');

    const navigate = useNavigate();


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


      const handleLogout = () => {
        setUserId(null);
        setLoggedInUser(null);
        setFiles([]);
        setMessage('');
      };


    return (
        <div className='tile-container'>
            <div style={{border: '5px solid rgb(54, 198, 255)'}}>
                <Tile>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                        <FormGroup legendText="">
                            <h3>Register</h3>
                            <TextInput
                                id="register-username"
                                labelText="Username"
                                autoComplete="true"
                                value={registerUsername}
                                onChange={(e) => setRegisterUsername(e.target.value)}
                            />
                            <TextInput.PasswordInput
                                id="register-password"
                                labelText="Enter password"
                                autoComplete="true"
                                value={registerPassword}
                                onChange={(e) => setRegisterPassword(e.target.value)}
                            />
                            <TextInput.PasswordInput
                                id="register-confirm-password"
                                labelText="Confirm password"
                                autoComplete="true"
                                value={confirmRegisterPassword}
                                onChange={(e) => setConfirmRegisterPassword(e.target.value)}
                            />
                        </FormGroup>
                        <br />
                        <Button onClick={handleRegister}>Register</Button>
                    </div>
                </Tile>
            </div>
            <div style={{border: '5px solid rgb(54, 198, 255)'}}>
                <Tile>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                        <FormGroup legendText="">
                            <h3>Sign In</h3>
                            <TextInput
                                id="sign-in-username"
                                labelText="Enter Username"
                                autoComplete="true"
                                value={signInUsername}
                                onChange={(e) => setSignInUsername(e.target.value)}
                            />
                            <TextInput.PasswordInput
                                id="sign-in-password"
                                labelText="Enter password"
                                autoComplete="true"
                                value={signInPassword}
                                onChange={(e) => setSignInPassword(e.target.value)}
                            />
                            <TextInput.PasswordInput
                                id="sign-in-confirm-password"
                                labelText="Confirm password"
                                autoComplete="true"
                                value={confirmSignInPassword}
                                onChange={(e) => setConfirmSignInPassword(e.target.value)}
                            />
                        </FormGroup>
                        <br />
                        <Button onClick={handleLogin}>Sign In</Button>
                    </div>
                </Tile>
            </div>
        </div>
    )
}