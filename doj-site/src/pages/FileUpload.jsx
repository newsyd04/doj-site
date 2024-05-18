import React, { useState } from 'react';


export default function FileUpload({username}) {

    const [recipient, setRecipient] = useState('');
    const [fileContent, setFileContent] = useState('');
    const [uploadedFile, setUploadedFile] = useState('');
    const [downloadedFile, setDownloadedFile] = useState('');

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
        <div>
            <p>
                file upload
            </p>
        </div>
    )
}



