// frontend/src/components/FloatingPanel/SecurePasswordModal.jsx

import React, { useState, useEffect, useRef } from 'react'
import { X, Lock, Copy, Check, Eye, EyeOff, AlertCircle, Shield, Key } from 'lucide-react'
import styles from './SecurePasswordModal.module.css'

// Import comprehensive logging
import {
  securePasswordModalError,
  securePasswordModalWarn,
  securePasswordModalInfo,
  securePasswordModalDebug,
  securePasswordModalLifecycle,
  securePasswordModalSecurity,
  securePasswordModalCopy,
  securePasswordModalInteraction,
  securePasswordModalState,
  securePasswordModalTimer,
  securePasswordModalVisibility,
  securePasswordModalClipboard,
  securePasswordModalErrorHandling,
  securePasswordModalConfig,
  securePasswordModalPerformance,
  time,
  timeEnd
} from '../../utils/logger'

const SecurePasswordModal = ({ password, encryptionPassword, onClose, onCopyComplete, bundleType }) => {
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

  // Log initial configuration
  useEffect(() => {
    time('SecurePasswordModal.initialization')
    
    securePasswordModalLifecycle('COMPONENT_MOUNT', {
      bundle_type: bundleType,
      has_zip_password: !!password,
      has_encryption_password: !!encryptionPassword,
      is_dual_mode: isDualMode,
      zip_password_length: password?.length || 0,
      encryption_password_length: encryptionPassword?.length || 0
    })

    securePasswordModalConfig('MODAL_SETUP', {
      isDualMode,
      bundleType,
      hasZipPassword: !!password,
      hasEncryptionPassword: !!encryptionPassword
    }, {
      auto_close_timer: 30,
      security_level: isDualMode ? 'dual_password' : 'single_password'
    })

    timeEnd('SecurePasswordModal.initialization')
  }, [])

  // Helper function to determine instruction content based on bundle type
  const getInstructionContent = (isDualMode, bundleType) => {
    securePasswordModalDebug('Generating instruction content', {
      is_dual_mode: isDualMode,
      bundle_type: bundleType
    })

    // Server bundles with installation guides
    const serverBundles = ['apache', 'nginx', 'iis']
    const hasInstallationGuides = bundleType && serverBundles.includes(bundleType.toLowerCase())
    
    securePasswordModalConfig('INSTRUCTION_GENERATION', {
      isDualMode,
      bundleType,
      hasZipPassword: !!password,
      hasEncryptionPassword: !!encryptionPassword
    }, {
      has_installation_guides: hasInstallationGuides,
      server_bundles: serverBundles
    })
    
    if (isDualMode) {
      return (
        <ol>
          <li>Use ZIP password to extract the downloaded file</li>
          <li>Use encryption password when importing or using the encrypted content</li>
          <li>Keep both passwords secure!</li>
          <li>The archive contains your {hasInstallationGuides ? 'certificate bundle and installation guides' : 'selected files'}</li>
        </ol>
      )
    } else {
      return (
        <ol>
          <li>Copy the password above to your clipboard</li>
          <li>Extract the downloaded ZIP file using your preferred tool</li>
          <li>When prompted for a password, paste the copied password</li>
          <li>The archive contains your {hasInstallationGuides ? 'certificates and installation guides' : 'selected files'}</li>
        </ol>
      )
    }
  }

  useEffect(() => {
    securePasswordModalTimer('AUTO_CLOSE_TIMER_START', {
      initial_timer_value: 30,
      interval_ms: 1000
    })

    // Auto-close timer
    intervalRef.current = setInterval(() => {
      setAutoCloseTimer(prev => {
        const newValue = prev - 1
        
        securePasswordModalTimer('TIMER_TICK', {
          previous_value: prev,
          new_value: newValue,
          will_close: newValue <= 0
        })

        if (newValue <= 0) {
          securePasswordModalTimer('AUTO_CLOSE_TRIGGERED', {
            final_timer_value: newValue
          })
          onClose()
          return 0
        }
        
        // Log warnings as timer gets low
        if (newValue === 10) {
          securePasswordModalWarn('Auto-close timer: 10 seconds remaining', {
            timer_value: newValue
          })
        } else if (newValue === 5) {
          securePasswordModalWarn('Auto-close timer: 5 seconds remaining', {
            timer_value: newValue
          })
        }
        
        return newValue
      })
    }, 1000)

    return () => {
      if (intervalRef.current) {
        securePasswordModalTimer('AUTO_CLOSE_TIMER_CLEANUP', {
          timer_cleared: true
        })
        clearInterval(intervalRef.current)
      }
    }
  }, [onClose])

  // Security: Clear passwords from memory on unmount
  useEffect(() => {
    return () => {
      time('SecurePasswordModal.security_cleanup')
      
      securePasswordModalSecurity('PASSWORD_MEMORY_CLEANUP_START', {
        has_zip_ref: !!zipPasswordRef.current,
        has_p12_ref: !!p12PasswordRef.current
      })

      // Clear any password references from memory
      if (zipPasswordRef.current) {
        zipPasswordRef.current.value = ''
        securePasswordModalSecurity('ZIP_PASSWORD_CLEARED', {
          ref_cleared: true
        })
      }
      if (p12PasswordRef.current) {
        p12PasswordRef.current.value = ''
        securePasswordModalSecurity('P12_PASSWORD_CLEARED', {
          ref_cleared: true
        })
      }

      securePasswordModalLifecycle('COMPONENT_UNMOUNT', {
        cleanup_completed: true,
        security_cleanup: true
      })

      timeEnd('SecurePasswordModal.security_cleanup')
    }
  }, [])

  const copyToClipboard = async (textToCopy, isP12 = false) => {
    time('SecurePasswordModal.clipboard_operation')
    
    securePasswordModalCopy('COPY_OPERATION_START', {
      is_p12_password: isP12,
      password_type: isP12 ? 'encryption' : 'zip',
      password_length: textToCopy?.length || 0
    })

    try {
      // Modern clipboard API (works in HTTPS and localhost)
      if (navigator.clipboard && navigator.clipboard.writeText) {
        securePasswordModalClipboard('ATTEMPTING_MODERN_API', {
          password_type: isP12 ? 'encryption' : 'zip',
          password_length: textToCopy?.length || 0,
          method_used: 'navigator.clipboard'
        })

        await navigator.clipboard.writeText(textToCopy)
        
        securePasswordModalClipboard('MODERN_API_SUCCESS', {
          success: true,
          method_used: 'navigator.clipboard',
          password_type: isP12 ? 'encryption' : 'zip',
          password_length: textToCopy?.length || 0
        })
        
        if (isP12) {
          setCopiedP12(true)
          securePasswordModalState('P12_COPIED_STATE_SET', { copiedP12: true })
          setTimeout(() => {
            setCopiedP12(false)
            securePasswordModalState('P12_COPIED_STATE_RESET', { copiedP12: false })
          }, 2000)
        } else {
          setCopiedZip(true)
          securePasswordModalState('ZIP_COPIED_STATE_SET', { copiedZip: true })
          setTimeout(() => {
            setCopiedZip(false)
            securePasswordModalState('ZIP_COPIED_STATE_RESET', { copiedZip: false })
          }, 2000)
        }
        
        // Notify parent component
        if (onCopyComplete) {
          securePasswordModalCopy('NOTIFY_PARENT_COPY_COMPLETE', {
            password_type: isP12 ? 'encryption' : 'zip',
            has_callback: !!onCopyComplete
          })
          onCopyComplete()
        }

        timeEnd('SecurePasswordModal.clipboard_operation')
        return
      }
    } catch (err) {
      securePasswordModalErrorHandling('MODERN_CLIPBOARD_API_FAILED', err, {
        fallback_attempted: true,
        password_type: isP12 ? 'encryption' : 'zip'
      })
    }
    
    // Fallback method for non-HTTPS environments
    try {
      securePasswordModalClipboard('ATTEMPTING_FALLBACK_METHOD', {
        password_type: isP12 ? 'encryption' : 'zip',
        password_length: textToCopy?.length || 0,
        method_used: 'document.execCommand'
      })

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
      
      securePasswordModalClipboard('FALLBACK_METHOD_RESULT', {
        success: successful,
        method_used: 'document.execCommand',
        password_type: isP12 ? 'encryption' : 'zip',
        password_length: textToCopy?.length || 0
      })
      
      if (successful) {
        if (isP12) {
          setCopiedP12(true)
          securePasswordModalState('P12_COPIED_STATE_SET_FALLBACK', { copiedP12: true })
          setTimeout(() => {
            setCopiedP12(false)
            securePasswordModalState('P12_COPIED_STATE_RESET_FALLBACK', { copiedP12: false })
          }, 2000)
        } else {
          setCopiedZip(true)
          securePasswordModalState('ZIP_COPIED_STATE_SET_FALLBACK', { copiedZip: true })
          setTimeout(() => {
            setCopiedZip(false)
            securePasswordModalState('ZIP_COPIED_STATE_RESET_FALLBACK', { copiedZip: false })
          }, 2000)
        }
        
        if (onCopyComplete) {
          securePasswordModalCopy('NOTIFY_PARENT_COPY_COMPLETE_FALLBACK', {
            password_type: isP12 ? 'encryption' : 'zip',
            has_callback: !!onCopyComplete
          })
          onCopyComplete()
        }
      } else {
        throw new Error('execCommand failed')
      }
    } catch (err) {
      securePasswordModalErrorHandling('ALL_CLIPBOARD_METHODS_FAILED', err, {
        password_type: isP12 ? 'encryption' : 'zip',
        fallback_attempted: true,
        modern_api_attempted: true
      })
      
      securePasswordModalError('All clipboard copy methods failed', {
        error_message: err.message,
        password_type: isP12 ? 'encryption' : 'zip'
      })
      
      alert('Copy failed. Please manually select and copy the password.')
    }

    timeEnd('SecurePasswordModal.clipboard_operation')
  }

  const handleOverlayClick = (e) => {
    if (e.target === e.currentTarget) {
      securePasswordModalInteraction('OVERLAY_CLICK_CLOSE', {
        close_method: 'overlay_click',
        timer_remaining: autoCloseTimer
      })
      onClose()
    }
  }

  const toggleZipPasswordVisibility = () => {
    const newVisibility = !showZipPassword
    
    securePasswordModalVisibility('ZIP_PASSWORD_VISIBILITY_TOGGLE', {
      previous_state: showZipPassword,
      new_state: newVisibility,
      password_type: 'zip'
    })
    
    setShowZipPassword(newVisibility)
  }

  const toggleP12PasswordVisibility = () => {
    const newVisibility = !showP12Password
    
    securePasswordModalVisibility('P12_PASSWORD_VISIBILITY_TOGGLE', {
      previous_state: showP12Password,
      new_state: newVisibility,
      password_type: 'encryption'
    })
    
    setShowP12Password(newVisibility)
  }

  const handleManualClose = () => {
    securePasswordModalInteraction('MANUAL_CLOSE_BUTTON', {
      close_method: 'manual_button',
      timer_remaining: autoCloseTimer,
      timer_cancelled: true
    })

    if (intervalRef.current) {
      securePasswordModalTimer('MANUAL_TIMER_CLEAR', {
        timer_remaining: autoCloseTimer
      })
      clearInterval(intervalRef.current)
    }
    
    onClose()
  }

  // Log state changes
  useEffect(() => {
    securePasswordModalState('COPIED_STATES_CHANGE', {
      copiedZip,
      copiedP12
    })
  }, [copiedZip, copiedP12])

  useEffect(() => {
    securePasswordModalState('VISIBILITY_STATES_CHANGE', {
      showZipPassword,
      showP12Password
    })
  }, [showZipPassword, showP12Password])

  useEffect(() => {
    securePasswordModalTimer('TIMER_VALUE_CHANGE', {
      timer_value: autoCloseTimer,
      is_critical: autoCloseTimer <= 10
    })
  }, [autoCloseTimer])

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
              onClick={() => {
                securePasswordModalInteraction('HEADER_CLOSE_BUTTON', {
                  close_method: 'header_close_button',
                  timer_remaining: autoCloseTimer
                })
                handleManualClose()
              }}
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
                    onClick={(e) => {
                      securePasswordModalInteraction('ZIP_PASSWORD_INPUT_CLICK', {
                        password_type: 'zip',
                        auto_select: true
                      })
                      e.target.select()
                    }}
                  />
                  
                  <div className={styles.passwordActions}>
                    <button
                      className={styles.passwordToggle}
                      onClick={() => {
                        securePasswordModalInteraction('ZIP_VISIBILITY_BUTTON_CLICK', {
                          current_visibility: showZipPassword,
                          password_type: 'zip'
                        })
                        toggleZipPasswordVisibility()
                      }}
                      title={showZipPassword ? 'Hide password' : 'Show password'}
                    >
                      {showZipPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                    
                    <button
                      className={styles.copyButton}
                      onClick={() => {
                        securePasswordModalInteraction('ZIP_COPY_BUTTON_CLICK', {
                          password_type: 'zip',
                          password_length: password?.length || 0
                        })
                        copyToClipboard(password, false)
                      }}
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
                    onClick={(e) => {
                      securePasswordModalInteraction('P12_PASSWORD_INPUT_CLICK', {
                        password_type: 'encryption',
                        auto_select: true
                      })
                      e.target.select()
                    }}
                  />
                  
                  <div className={styles.passwordActions}>
                    <button
                      className={styles.passwordToggle}
                      onClick={() => {
                        securePasswordModalInteraction('P12_VISIBILITY_BUTTON_CLICK', {
                          current_visibility: showP12Password,
                          password_type: 'encryption'
                        })
                        toggleP12PasswordVisibility()
                      }}
                      title={showP12Password ? 'Hide password' : 'Show password'}
                    >
                      {showP12Password ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                    
                    <button
                      className={styles.copyButton}
                      onClick={() => {
                        securePasswordModalInteraction('P12_COPY_BUTTON_CLICK', {
                          password_type: 'encryption',
                          password_length: encryptionPassword?.length || 0
                        })
                        copyToClipboard(encryptionPassword, true)
                      }}
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
              {getInstructionContent(isDualMode, bundleType)}
            </div>
          </div>

          <div className={styles.footer}>
            <div className={styles.autoClose}>
              Auto-closing in {autoCloseTimer} seconds
            </div>
            <button 
              className={styles.closeButton}
              onClick={() => {
                securePasswordModalInteraction('FOOTER_CLOSE_BUTTON', {
                  close_method: 'footer_close_button',
                  timer_remaining: autoCloseTimer
                })
                handleManualClose()
              }}
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