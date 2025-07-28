import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

import { sessionManager } from './services/sessionManager.js'

// Log session initialization for debugging
console.log('Frontend session initialized:', sessionManager.getSessionId())

ReactDOM.createRoot(document.getElementById('root')).render(<App />)