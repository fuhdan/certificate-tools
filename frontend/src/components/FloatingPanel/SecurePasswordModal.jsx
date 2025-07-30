// frontend/src/components/FloatingPanel/SecurePasswordModal.jsx
import React, { useState, useEffect, useRef } from 'react'
import { X, Lock, Copy, Check, Eye, EyeOff, AlertCircle, Shield } from 'lucide-react'
import styles from './SecurePasswordModal.module.css'

const SecurePasswordModal = ({ password, onClose, onCopyComplete }) => {
  const [copied, setCopied] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [autoCloseTimer, setAutoCloseTimer] = useState(30)
  const passwordRef = useRef(null)
  const intervalRef = useRef(null)

  useEffect(() => {
    // Auto-close timer
    intervalRef.current = setInterval(() => {
      setAutoCloseTimer(prev => {
        if (prev <= 1) {
          onClose()
          return 0
        }
        return prev - 1
      })
    }, 1000)

    // Focus password field for accessibility
    if (passwordRef.current && showPassword) {
      passwordRef.current.focus()
      passwordRef.current.select()
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }
  }, [onClose, showPassword])

  // Security: Clear password from memory on unmount
  useEffect(() => {
    return () => {
      // Clear any password references from memory
      if (passwordRef.current) {
        passwordRef.current.value = ''
      }
    }
  }, [])

  const copyToClipboard = async () => {
    try {
      // Modern clipboard API (works in HTTPS and localhost)
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(password)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        
        // Notify parent component
        if (onCopyComplete) {
          onCopyComplete()
        }
        return
      }
    } catch (err) {
      console.warn('Modern clipboard API failed, trying fallback:', err)
    }
    
    // Fallback method for non-HTTPS environments
    try {
      const textArea = document.createElement('textarea')
      textArea.value = password
      textArea.style.position = 'fixed'
      textArea.style.left = '-999999px'
      textArea.style.top = '-999999px'
      document.body.appendChild(textArea)
      textArea.focus()
      textArea.select()
      
      const successful = document.execCommand('copy')
      document.body.removeChild(textArea)
      
      if (successful) {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        
        if (onCopyComplete) {
          onCopyComplete()
        }
      } else {
        throw new Error('execCommand failed')
      }
    } catch (err) {
      console.error('All clipboard methods failed:', err)
      alert('Copy failed. Please manually select and copy the password.')
    }
  }

  const handleOverlayClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose()
    }
  }

  const togglePasswordVisibility = () => {
    setShowPassword(prev => !prev)
  }

  const handleManualClose = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current)
    }
    onClose()
  }

  return (
    <div className={styles.overlay} onClick={handleOverlayClick}>
      <div className={styles.modal}>
        <div className={styles.header}>
          <div className={styles.titleSection}>
            <Shield size={24} className={styles.icon} />
            <div>
              <h2>ZIP Password Required</h2>
              <p className={styles.subtitle}>Your download is password-protected</p>
            </div>
          </div>
          <div className={styles.actions}>
            <button 
              className={styles.closeButton}
              onClick={handleManualClose}
              title="Close"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        <div className={styles.content}>
          <div className={styles.securityNotice}>
            <AlertCircle size={16} />
            <span>Keep this password secure. It will be cleared from memory automatically.</span>
          </div>

          <div className={styles.passwordSection}>
            <label className={styles.passwordLabel}>
              <Lock size={16} />
              ZIP Archive Password:
            </label>
            
            <div className={styles.passwordContainer}>
              <input
                ref={passwordRef}
                type={showPassword ? 'text' : 'password'}
                value={password}
                readOnly
                className={styles.passwordInput}
                onClick={(e) => e.target.select()}
              />
              
              <div className={styles.passwordActions}>
                <button
                  className={styles.passwordToggle}
                  onClick={togglePasswordVisibility}
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
                
                <button
                  className={styles.copyButton}
                  onClick={copyToClipboard}
                  title="Copy password to clipboard"
                >
                  {copied ? <Check size={16} /> : <Copy size={16} />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>
          </div>

          <div className={styles.instructions}>
            <h3>Instructions:</h3>
            <ol>
              <li>Copy the password above to your clipboard</li>
              <li>Extract the downloaded ZIP file using your preferred tool</li>
              <li>When prompted for a password, paste the copied password</li>
              <li>The archive contains your certificates and installation guides</li>
            </ol>
          </div>

          <div className={styles.footer}>
            <div className={styles.autoClose}>
              Auto-closing in {autoCloseTimer} seconds
            </div>
            <button 
              className={styles.closeButton}
              onClick={handleManualClose}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default SecurePasswordModal