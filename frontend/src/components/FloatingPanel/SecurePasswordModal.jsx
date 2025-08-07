// frontend/src/components/FloatingPanel/SecurePasswordModal.jsx
import React, { useState, useEffect, useRef } from 'react'
import { X, Lock, Copy, Check, Eye, EyeOff, AlertCircle, Shield, Key } from 'lucide-react'
import styles from './SecurePasswordModal.module.css'

const SecurePasswordModal = ({ password, encryptionPassword, onClose, onCopyComplete }) => {
  const [copiedZip, setCopiedZip] = useState(false)
  const [copiedP12, setCopiedP12] = useState(false)
  const [showZipPassword, setShowZipPassword] = useState(false)
  const [showP12Password, setShowP12Password] = useState(false)
  const [autoCloseTimer, setAutoCloseTimer] = useState(30)
  const zipPasswordRef = useRef(null)
  const p12PasswordRef = useRef(null)
  const intervalRef = useRef(null)

  // Determine if this is dual password mode (both ZIP and P12)
  const isDualMode = !!(password && encryptionPassword)

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

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }
  }, [onClose])

  // Security: Clear passwords from memory on unmount
  useEffect(() => {
    return () => {
      // Clear any password references from memory
      if (zipPasswordRef.current) {
        zipPasswordRef.current.value = ''
      }
      if (p12PasswordRef.current) {
        p12PasswordRef.current.value = ''
      }
    }
  }, [])

  const copyToClipboard = async (textToCopy, isP12 = false) => {
    try {
      // Modern clipboard API (works in HTTPS and localhost)
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(textToCopy)
        
        if (isP12) {
          setCopiedP12(true)
          setTimeout(() => setCopiedP12(false), 2000)
        } else {
          setCopiedZip(true)
          setTimeout(() => setCopiedZip(false), 2000)
        }
        
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
      textArea.value = textToCopy
      textArea.style.position = 'fixed'
      textArea.style.left = '-999999px'
      textArea.style.top = '-999999px'
      document.body.appendChild(textArea)
      textArea.focus()
      textArea.select()
      
      const successful = document.execCommand('copy')
      document.body.removeChild(textArea)
      
      if (successful) {
        if (isP12) {
          setCopiedP12(true)
          setTimeout(() => setCopiedP12(false), 2000)
        } else {
          setCopiedZip(true)
          setTimeout(() => setCopiedZip(false), 2000)
        }
        
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

  const toggleZipPasswordVisibility = () => {
    setShowZipPassword(prev => !prev)
  }

  const toggleP12PasswordVisibility = () => {
    setShowP12Password(prev => !prev)
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
              <h2>{isDualMode ? '🔐 DOWNLOAD PASSWORDS' : 'ZIP Password Required'}</h2>
              <p className={styles.subtitle}>
                {isDualMode 
                  ? 'Two passwords are required for this download' 
                  : 'Your download is password-protected'
                }
              </p>
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
          <div className={styles.scrollableContent}>
            <div className={styles.securityNotice}>
              <AlertCircle size={16} />
              <span>Keep these passwords secure. They will be cleared from memory automatically.</span>
            </div>

            {/* ZIP Password Section */}
            {password && (
              <div className={styles.passwordSection}>
                <label className={styles.passwordLabel}>
                  <Lock size={16} />
                  {isDualMode ? 'ZIP File Password (to extract files):' : 'ZIP Archive Password:'}
                </label>
                
                <div className={styles.passwordContainer}>
                  <input
                    ref={zipPasswordRef}
                    type={showZipPassword ? 'text' : 'password'}
                    value={password}
                    readOnly
                    className={styles.passwordInput}
                    onClick={(e) => e.target.select()}
                  />
                  
                  <div className={styles.passwordActions}>
                    <button
                      className={styles.passwordToggle}
                      onClick={toggleZipPasswordVisibility}
                      title={showZipPassword ? 'Hide password' : 'Show password'}
                    >
                      {showZipPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                    
                    <button
                      className={styles.copyButton}
                      onClick={() => copyToClipboard(password, false)}
                      title="Copy ZIP password to clipboard"
                    >
                      {copiedZip ? <Check size={16} /> : <Copy size={16} />}
                      {copiedZip ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* P12 Password Section (only show in dual mode) */}
            {encryptionPassword && (
              <div className={styles.passwordSection}>
                <label className={styles.passwordLabel}>
                  <Key size={16} />
                  Encryption Password (for certificate import):
                </label>
                
                <div className={styles.passwordContainer}>
                  <input
                    ref={p12PasswordRef}
                    type={showP12Password ? 'text' : 'password'}
                    value={encryptionPassword}
                    readOnly
                    className={styles.passwordInput}
                    onClick={(e) => e.target.select()}
                  />
                  
                  <div className={styles.passwordActions}>
                    <button
                      className={styles.passwordToggle}
                      onClick={toggleP12PasswordVisibility}
                      title={showP12Password ? 'Hide password' : 'Show password'}
                    >
                      {showP12Password ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                    
                    <button
                      className={styles.copyButton}
                      onClick={() => copyToClipboard(encryptionPassword, true)}
                      title="Copy P12 password to clipboard"
                    >
                      {copiedP12 ? <Check size={16} /> : <Copy size={16} />}
                      {copiedP12 ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>
              </div>
            )}

            <div className={styles.instructions}>
              <h3>Instructions:</h3>
              {isDualMode ? (
                <ol>
                  <li>Use ZIP password to extract the downloaded file</li>
                  <li>Use P12 password when importing certificate in IIS</li>
                  <li>Keep both passwords secure!</li>
                  <li>The archive contains your certificate bundle and installation guides</li>
                </ol>
              ) : (
                <ol>
                  <li>Copy the password above to your clipboard</li>
                  <li>Extract the downloaded ZIP file using your preferred tool</li>
                  <li>When prompted for a password, paste the copied password</li>
                  <li>The archive contains your certificates and installation guides</li>
                </ol>
              )}
            </div>
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