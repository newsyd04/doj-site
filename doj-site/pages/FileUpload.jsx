import React, { useState } from 'react';

export default function FileUpload() {

    
    const [file, setFile] = useState(null);
    const [files, setFiles] = useState([]);
    const [selectedFile, setSelectedFile] = useState(null);
    const [message, setMessage] = useState('');

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

    const base64ToBuffer = (base64) => {
        const binary = window.atob(base64);
        const len = binary.length;
        const buffer = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
          buffer[i] = binary.charCodeAt(i);
        }
        return buffer.buffer;
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

      const exportKey = async (key) => {
        try {
          const exported = await crypto.subtle.exportKey("spki", key);
          return bufferToBase64(exported);
        } catch (error) {
          console.error('Error exporting key:', error);
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
}

