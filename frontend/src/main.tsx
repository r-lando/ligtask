import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import AuthGate from './components/AuthGate'
import PasswordRecovery from './components/PasswordRecovery'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PasswordRecovery><AuthGate><App /></AuthGate></PasswordRecovery>
  </React.StrictMode>,
)
