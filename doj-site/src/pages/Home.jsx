import React, { useState } from 'react';
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

    const navigate = useNavigate();


    const handleRegister = async () => {
        try {
        const response = await fetch('http://localhost:5000/register', {
            method: 'POST',
            headers: {
            'Content-Type': 'application/json',
            },
            body: JSON.stringify({ registerUsername, registerPassword }),
        });
        const data = await response.json();
        setUsername(registerUsername);
        setPassword(registerPassword);
        navigate('/fileUpload');
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
            body: JSON.stringify({ signInUsername, signInPassword }),
        });
        const data = await response.json();
        setUsername(signInUsername);
        setPassword(signInPassword);
        navigate('/fileUpload');
        console.log(data);
        } catch (error) {
        console.error('Error:', error);
        }
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
