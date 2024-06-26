import React, { useState, useEffect } from 'react';

export default function FileUpload({ showToast, JWT , userId}) {

    
    const [file, setFile] = useState(null);
    const [files, setFiles] = useState([]);
    const [selectedFile, setSelectedFile] = useState(null);
    const [recipient, setRecipient] = useState('');
    const [users, setUsers] = useState([]);

    // Helper function to fetch a user's public key
    const fetchPublicKey = async (usernameOrId) => {
      try {
          const response = await fetch(`http://127.0.0.1:3500/getPublicKey?userId=${usernameOrId}`, {
              method: 'GET',
              headers: { 'Authorization': `Bearer ${JWT}`, 'Content-Type': 'application/json' }
          });
          if (!response.ok) {
              throw new Error(`HTTP error! status: ${response.status}`);
          }
          const data = await response.json();
          return await importKey(data.public_key);
      } catch (error) {
          console.error('Error fetching public key:', error);
          throw error;
      }
  };
  
  
  // Helper function to import a public key
  const importKey = async (keyData) => {
    try {
        // Convert the base64 string to a buffer
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

// Helper function to convert a base64 string to a buffer
const base64ToBuffer = (base64) => {
  try {
      // Convert the base64 string to a binary string
      console.log("Base64 string to decode:", base64);
      const binaryString = window.atob(base64);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
          bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
  } catch (error) {
      console.error('Error decoding base64 string:', error);
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

    // Helper function to encrypt data
    const encryptData = async (key, data) => {
      try {
        const encoder = new TextEncoder();
        const encoded = encoder.encode(data);
        // get initialization vector
        const iv = crypto.getRandomValues(new Uint8Array(12));
        // encrypt the data using AES-GCM
        const encrypted = await crypto.subtle.encrypt({
          name: "AES-GCM",
          iv: iv
        }, key, encoded);
        
        const ivBase64 = bufferToBase64(iv);
        const encryptedBase64 = bufferToBase64(encrypted);
        
        console.log("IV (base64):", ivBase64);
        console.log("Encrypted data (base64):", encryptedBase64);
        
        return `${ivBase64}:${encryptedBase64}`;
      } catch (error) {
        console.error('Error encrypting data:', error);
        throw error;
      }
    };
    
    // Fetch users on component mount
    useEffect(() => {
      fetchUsers();
    }, []);

    // Fetch users
    const fetchUsers = async () => {
      try {
        const response = await fetch('http://127.0.0.1:3500/users', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${JWT}` , 'Content-Type': 'application/json' }
        });
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log(JSON.stringify(data.users));
        setUsers(data.users);
      } catch (error) {
        console.error('Error:', error);
        showToast('Error fetching users.', true);
      }
    };

    // Handle file upload
    const handleFileUpload = async () => {
      try {
        // ensure file is uploaded
        if (!file) {
          showToast('No file selected.', true);
          return;
        }
        // ensure recipient is selected
        if (!recipient) {
          showToast('No recipient selected.', true);
          return;
        }
    
        // get recipients public key and encrypt the file
        const fileContent = await file.text();
        const keyPair = await getKeyPair();
        const recipientPublicKey = await fetchPublicKey(recipient);
        const secretKey = await deriveSecretKey(keyPair.privateKey, recipientPublicKey);
        const encryptedContent = await encryptData(secretKey, fileContent);
    
        if (!encryptedContent) {
          throw new Error('Encryption failed, no data returned');
        }
    
        console.log("Encrypted content (base64):", encryptedContent);
        console.log("File details:", {
          uploaderId: userId,
          recipient,
          filename: file.name,
          fileType: file.type
        });
    
        // upload the encrypted file
        const response = await fetch('http://127.0.0.1:3500/upload', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${JWT}`
          },
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
        showToast(data.message, false);
        fetchFiles();
      } catch (error) {
        console.error('Error:', error);
        showToast('Error uploading file.', true);
      }
    };
  
    // Fetch files
    const fetchFiles = async () => {
      try {
          const response = await fetch('http://127.0.0.1:3500/download', {
              method: 'POST',
              headers: { 
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${JWT}`
              },
              body: JSON.stringify({ userId })
          });
    
          if (!response.ok) {
              throw new Error(`HTTP error! status: ${response.status}`);
          }
    

          const data = await response.json();
          if (data.fileContent && data.fileContent.length > 0) {
              // set files and select the first file
              setFiles(data.fileContent);
              setSelectedFile(data.fileContent[0] || null);
          } else {
              showToast('No files found.', true);
              setFiles([]);
              setSelectedFile(null);
          }
      } catch (error) {
          console.error('Error:', error);
          showToast('Error fetching files.', true);
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

    // Helper function to get the key pair
    // Generates key pair if user does not have one
    const getKeyPair = async () => {
      if (!localStorage.getItem('privateKey') || !localStorage.getItem('publicKey')) {
        const keyPair = await generateKeyPair();
        const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const exportedPublicKey = await exportKey(keyPair.publicKey);
        localStorage.setItem('privateKey', bufferToBase64(exportedPrivateKey));
        localStorage.setItem('publicKey', exportedPublicKey);
      }
      try {
        console.log("this far");
        console.log(localStorage.getItem('privateKey'));
        // something seems to be failing in this line below
        const privateKey = await crypto.subtle.importKey('pkcs8', base64ToBuffer(localStorage.getItem('privateKey')), {
          name: "ECDH",
          namedCurve: "P-256"
        }, true, ["deriveKey"]);
        console.log("this far2");
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

    // Helper function to derive a secret key
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
      
    // Handle file download
    const handleFileDownload = async () => {
      try {
        // get users key pair and recipients address
        const keyPair = await getKeyPair();
        const recipientPublicKey = await fetchPublicKey(userId);

        // decrypt the file
        const secretKey = await deriveSecretKey(keyPair.privateKey, recipientPublicKey);
        const decryptedContent = await decryptData(secretKey, selectedFile.content);
    
        if (!decryptedContent) {
          throw new Error('Decryption failed, no data returned');
        }
    
        console.log("Decrypted content:", decryptedContent);
    
        // download the decrypted file to users device
        const blob = new Blob([decryptedContent], { type: selectedFile.fileType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = selectedFile.filename;
        a.click();
        window.URL.revokeObjectURL(url);
      } catch (error) {
        console.error('Error:', error);
      }
    };
        
    // Helper function to decrypt data
    const decryptData = async (key, data) => {
      try {
        const [ivBase64, encryptedDataBase64] = data.split(':');
    
        console.log("IV base64:", ivBase64);
        console.log("Encrypted data base64:", encryptedDataBase64);
    
        // ensure data is in correct format
        if (!ivBase64 || !encryptedDataBase64) {
          throw new Error("Invalid data format for decryption.");
        }
    
        // convert base64 strings to buffers
        const iv = base64ToBuffer(ivBase64);
        const encryptedData = base64ToBuffer(encryptedDataBase64);
    
        console.log("IV buffer:", iv);
        console.log("Encrypted data buffer:", encryptedData);
    
        // decrypt the data using AES-GCM
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
    
    return (
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
            <option value="">Select recipient</option>
            {users.map(user => (
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
            <option value="">Select file</option>
            {files.map(file => (
              <option key={file.content} value={file.content}>{file.filename}</option>
            ))}
          </select>
          <button className='buttonpadding' onClick={() => fetchFiles(userId)}>Fetch Files</button> {/* Button to manually fetch files */}
          <button className='buttonpadding' onClick={handleFileDownload}>Download</button>
        </article>
      </div>
    </div>
      );
}
