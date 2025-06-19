import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/index.css'
import App from './app.jsx'

/**
 * Simplified main.jsx without Azure AD for development
 * This completely bypasses the crypto issues by not using MSAL at all
 */

// Render the app directly without MSAL
createRoot(document.getElementById('root')).render(
    <StrictMode>
        <App />
    </StrictMode>,
)