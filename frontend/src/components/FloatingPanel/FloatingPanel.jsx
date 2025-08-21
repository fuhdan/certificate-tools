// frontend/src/components/FloatingPanel/FloatingPanel.jsx

import React, { useState, useEffect, useRef } from 'react'
import {
  Settings,
  Download,
  Files,
  Package,
  Trash2,
  Monitor,
  Wrench,
  GripVertical,
  Minimize2,
  Maximize2,
  Shield
} from 'lucide-react'
import styles from './FloatingPanel.module.css'
import ConnectionStatus from './ConnectionStatus'
import SystemMessages from './SystemMessages'
import FileManager from './FileManager'
import AdvancedModal from './AdvancedModal'
import SecurePasswordModal from './SecurePasswordModal'
import NotificationToast from '../common/NotificationToast'
import { useCertificates } from '../../contexts/CertificateContext'
import { downloadAPI } from '../../services/api'
import api from '../../services/api'

// Import comprehensive logging
import {
  floatingPanelError,
  floatingPanelWarn,
  floatingPanelInfo,
  floatingPanelDebug,
  floatingPanelLifecycle,
  floatingPanelInteraction,
  floatingPanelState,
  floatingPanelPosition,
  floatingPanelDownload,
  floatingPanelValidation,
  floatingPanelModal,
  floatingPanelFileManagement,
  floatingPanelPerformance,
  floatingPanelErrorHandling,
  floatingPanelDragResize,
  floatingPanelCertificateAnalysis,
  time,
  timeEnd
} from '@/utils/logger'

const FloatingPanel = ({ showValidationPanel, onToggleValidationPanel }) => {
  const { certificates, clearAllFiles } = useCertificates()
  const [showAdvanced, setShowAdvanced] = useState(false)
  
  // NEW: Download-related state
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [zipPassword, setZipPassword] = useState('')
  const [encryptionPassword, setP12Password] = useState('')
  const [isDownloading, setIsDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState(null)
  const [showSuccessNotification, setShowSuccessNotification] = useState(false)
  const [successMessage, setSuccessMessage] = useState('')
  
  // Original state
  const [hasRequiredForLinux, setHasRequiredForLinux] = useState(false)
  const [hasRequiredForWindows, setHasRequiredForWindows] = useState(false)
  const [hasAnyFiles, setHasAnyFiles] = useState(false)

  const [connectionStatus, setConnectionStatus] = useState('checking')
  const [isMinimized, setIsMinimized] = useState(false)
  const [savedPosition, setSavedPosition] = useState({ x: 0, y: 0 })
  const [savedSize, setSavedSize] = useState({ width: 250, height: 500 })
  const [minimizedPosition, setMinimizedPosition] = useState({ x: 16, y: window.innerHeight - 80 })

  const panelRef = useRef(null)
  const [isDragging, setIsDragging] = useState(false)
  const [isResizing, setIsResizing] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  const [panelPosition, setPanelPosition] = useState(() => {
    const initialX = window.innerWidth - 250 - 16
    const initialY = window.innerHeight * 0.2
    
    floatingPanelLifecycle('COMPONENT_INIT', {
      initial_position: { x: initialX, y: initialY },
      window_size: { width: window.innerWidth, height: window.innerHeight }
    })
    
    return { x: initialX, y: initialY }
  })
  const [panelSize, setPanelSize] = useState({ width: 250, height: 500 })

  // Initialize starting position based on visual CSS defaults
  useEffect(() => {
    time('FloatingPanel.position_initialization')
    
    const initialX = window.innerWidth - 250 - 16 // width + margin
    const initialY = window.innerHeight * 0.2
    
    floatingPanelPosition('POSITION_INIT', { x: initialX, y: initialY }, {
      calculation_basis: 'CSS_defaults',
      window_dimensions: { width: window.innerWidth, height: window.innerHeight }
    })
    
    setPanelPosition({ x: initialX, y: initialY })
    
    timeEnd('FloatingPanel.position_initialization')
  }, [])

  useEffect(() => {
    const checkConnection = async () => {
      time('FloatingPanel.connection_check')
      
      try {
        floatingPanelDebug('Starting connection health check')
        const response = await api.get('/health')
        
        // Ensure exact string matching
        if (response.data.status === 'online') {
          setConnectionStatus('connected')
          floatingPanelInfo('Connection status: CONNECTED', {
            response_status: response.data.status,
            response_time_ms: response.config?.timeout || 'unknown'
          })
        } else {
          setConnectionStatus('disconnected')
          floatingPanelWarn('Connection status: DISCONNECTED - unexpected response', {
            expected: 'online',
            received: response.data.status,
            full_response: response.data
          })
        }
      } catch (error) {
        setConnectionStatus('disconnected')
        floatingPanelErrorHandling('CONNECTION_HEALTH_CHECK', error, {
          error_details: {
            message: error.message,
            code: error.code,
            status: error.response?.status
          }
        })
      } finally {
        timeEnd('FloatingPanel.connection_check')
      }
    }

    floatingPanelLifecycle('CONNECTION_MONITORING_START')
    checkConnection()
    
    const interval = setInterval(() => {
      floatingPanelDebug('Scheduled connection health check')
      checkConnection()
    }, 10000)
    
    return () => {
      floatingPanelLifecycle('CONNECTION_MONITORING_STOP')
      clearInterval(interval)
    }
  }, [])

  useEffect(() => {
    time('FloatingPanel.certificate_analysis')
    
    floatingPanelCertificateAnalysis('CERTIFICATE_REQUIREMENT_CHECK_START', {
      certificates_count: certificates?.length || 0,
      certificates_type: typeof certificates
    })

    if (!certificates || certificates.length === 0) {
      floatingPanelCertificateAnalysis('NO_CERTIFICATES_FOUND', {
        previous_linux_required: hasRequiredForLinux,
        previous_windows_required: hasRequiredForWindows,
        previous_has_files: hasAnyFiles
      })
      
      setHasRequiredForLinux(false)
      setHasRequiredForWindows(false)
      setHasAnyFiles(false)
      
      timeEnd('FloatingPanel.certificate_analysis')
      return
    }
  
    // 🔍 DEBUG: Log the certificates array structure
    floatingPanelDebug('Certificate array analysis', {
      full_certificates_array: certificates,
      array_length: certificates.length,
      array_type: typeof certificates
    })
    
    // 🔍 DEBUG: Print each certificate in detail
    floatingPanelDebug('Individual certificate analysis')
    certificates.forEach((cert, index) => {
      if (cert) {
        floatingPanelDebug(`Certificate [${index}] details`, {
          index,
          full_cert_object: cert,
          type: cert.type,
          type_of_type: typeof cert.type,
          has_type_property: 'type' in cert,
          object_keys: Object.keys(cert)
        })
      } else {
        floatingPanelWarn(`Invalid certificate at index [${index}]`, {
          index,
          cert_value: cert
        })
      }
    })
  
    // FIXED: More robust type checking with fallbacks
    const hasEndEntityCert = certificates.some(cert => {
      if (!cert) return false
      
      const type = cert.type || cert.fileType || cert.componentType
      
      floatingPanelDebug('Checking for end-entity certificate', {
        cert_type: type,
        is_certificate_type: type === 'Certificate'
      })
      
      return type === 'Certificate' // End-entity certificate
    })
  
    const hasPrivateKey = certificates.some(cert => {
      if (!cert) return false
      
      const type = cert.type || cert.fileType || cert.componentType
      
      floatingPanelDebug('Checking for private key', {
        cert_type: type,
        is_private_key_type: type === 'PrivateKey'
      })
      
      return type === 'PrivateKey'
    })
  
    floatingPanelCertificateAnalysis('REQUIREMENT_DETECTION_RESULTS', {
      has_end_entity_cert: hasEndEntityCert,
      has_private_key: hasPrivateKey,
      linux_requirements_met: hasEndEntityCert,
      windows_requirements_met: hasEndEntityCert && hasPrivateKey
    })
  
    setHasRequiredForLinux(hasEndEntityCert)
    setHasRequiredForWindows(hasEndEntityCert && hasPrivateKey)
    setHasAnyFiles(true)
    
    timeEnd('FloatingPanel.certificate_analysis')
  }, [certificates])

  // ONLY CHANGED: Download handlers - using unified API
  const handleLinuxApacheDownload = async () => {
    if (!hasRequiredForLinux || isDownloading) {
      floatingPanelWarn('Linux Apache download prevented', {
        has_required: hasRequiredForLinux,
        is_downloading: isDownloading,
        reason: !hasRequiredForLinux ? 'missing_requirements' : 'download_in_progress'
      })
      return
    }

    time('FloatingPanel.linux_apache_download')
    setIsDownloading(true)
    setDownloadError(null)

    floatingPanelDownload('LINUX_APACHE_DOWNLOAD_START', {
      certificates_count: certificates?.length || 0,
      has_required_certs: hasRequiredForLinux
    })

    try {
      floatingPanelDownload('USING_UNIFIED_API', { api_type: 'Apache', with_passwords: true })
      
      // Use unified download API
      const result = await downloadAPI.downloadApacheBundle(true)

      floatingPanelDownload('APACHE_DOWNLOAD_SUCCESS', {
        has_zip_password: !!result.zipPassword,
        has_encryption_password: !!result.encryptionPassword,
        zip_password_length: result.zipPassword?.length || 0,
        encryption_password_length: result.encryptionPassword?.length || 0
      })

      // Show password modal
      setZipPassword(result.zipPassword)
      setP12Password(result.encryptionPassword || '')
      
      floatingPanelModal('SHOW_PASSWORD_MODAL', 'apache_passwords', {
        zip_password_set: !!result.zipPassword,
        encryption_password_set: !!result.encryptionPassword
      })
      
      setShowPasswordModal(true)

      // Show success notification
      setSuccessMessage('Apache certificate bundle downloaded successfully!')
      setShowSuccessNotification(true)
      
      floatingPanelDownload('APACHE_DOWNLOAD_COMPLETE', {
        success: true,
        notification_shown: true
      })

    } catch (error) {
      floatingPanelErrorHandling('APACHE_DOWNLOAD_ERROR', error, {
        error_details: {
          message: error.message,
          status: error.response?.status,
          data: error.response?.data
        }
      })
      
      if (error.message.includes('404')) {
        setDownloadError('No certificates found. Please upload required certificates first.')
      } else if (error.message.includes('400')) {
        setDownloadError('Invalid session or missing required certificates.')
      } else if (error.message.includes('timeout')) {
        setDownloadError('Download timeout. Please try again.')
      } else {
        setDownloadError('Download failed. Please try again.')
      }
      
      floatingPanelDownload('APACHE_DOWNLOAD_FAILED', {
        error_type: error.message.includes('404') ? '404_not_found' : 
                   error.message.includes('400') ? '400_bad_request' :
                   error.message.includes('timeout') ? 'timeout' : 'unknown',
        error_message: error.message
      })
    } finally {
      setIsDownloading(false)
      timeEnd('FloatingPanel.linux_apache_download')
    }
  }

  // ONLY CHANGED: Windows IIS download handler - using unified API
  const handleWindowsIISDownload = async () => {
    if (!hasRequiredForWindows || isDownloading) {
      floatingPanelWarn('Windows IIS download prevented', {
        has_required: hasRequiredForWindows,
        is_downloading: isDownloading,
        reason: !hasRequiredForWindows ? 'missing_requirements' : 'download_in_progress'
      })
      return
    }

    time('FloatingPanel.windows_iis_download')
    setIsDownloading(true)
    setDownloadError(null)

    floatingPanelDownload('WINDOWS_IIS_DOWNLOAD_START', {
      certificates_count: certificates?.length || 0,
      has_required_certs: hasRequiredForWindows
    })

    try {
      floatingPanelDownload('USING_UNIFIED_API', { api_type: 'IIS', with_passwords: true })
      
      // Use unified download API
      const result = await downloadAPI.downloadIISBundle(true)

      // Extract both passwords from response
      const zipPassword = result.zipPassword
      const encryptionPassword = result.encryptionPassword
      
      floatingPanelDownload('IIS_DOWNLOAD_SUCCESS', {
        has_zip_password: !!zipPassword,
        has_encryption_password: !!encryptionPassword,
        zip_password_length: zipPassword?.length || 0,
        encryption_password_length: encryptionPassword?.length || 0
      })
      
      if (!zipPassword || !encryptionPassword) {
        const errorMsg = 'Required passwords not found in response'
        floatingPanelErrorHandling('IIS_PASSWORD_VALIDATION', new Error(errorMsg), {
          zip_password_present: !!zipPassword,
          encryption_password_present: !!encryptionPassword,
          response_keys: Object.keys(result)
        })
        throw new Error(errorMsg)
      }

      // Show dual password modal
      setZipPassword(zipPassword)
      setP12Password(encryptionPassword)
      
      floatingPanelModal('SHOW_PASSWORD_MODAL', 'iis_passwords', {
        zip_password_set: !!zipPassword,
        encryption_password_set: !!encryptionPassword
      })
      
      setShowPasswordModal(true)

      // Show success notification
      setSuccessMessage('Windows IIS certificate bundle downloaded successfully!')
      setShowSuccessNotification(true)
      
      floatingPanelDownload('IIS_DOWNLOAD_COMPLETE', {
        success: true,
        notification_shown: true
      })

    } catch (error) {
      floatingPanelErrorHandling('IIS_DOWNLOAD_ERROR', error, {
        error_details: {
          message: error.message,
          status: error.response?.status,
          data: error.response?.data
        }
      })
      
      if (error.message.includes('404')) {
        setDownloadError('No certificates found. Please upload required certificates first.')
      } else if (error.message.includes('400')) {
        setDownloadError('Invalid session or missing required certificate chain.')
      } else if (error.message.includes('timeout')) {
        setDownloadError('Download timeout. Please try again.')
      } else {
        setDownloadError('Download failed. Please try again.')
      }
      
      floatingPanelDownload('IIS_DOWNLOAD_FAILED', {
        error_type: error.message.includes('404') ? '404_not_found' : 
                   error.message.includes('400') ? '400_bad_request' :
                   error.message.includes('timeout') ? 'timeout' : 'unknown',
        error_message: error.message
      })
    } finally {
      setIsDownloading(false)
      timeEnd('FloatingPanel.windows_iis_download')
    }
  }

  const handlePasswordModalClose = () => {
    floatingPanelModal('CLOSE_PASSWORD_MODAL', 'password_cleanup', {
      had_zip_password: !!zipPassword,
      had_encryption_password: !!encryptionPassword
    })
    
    setShowPasswordModal(false)
    // Security: Clear passwords from memory
    setZipPassword('')
    setP12Password('')
    
    floatingPanelInfo('Password modal closed - passwords cleared from memory')
  }

  const handlePasswordCopyComplete = () => {
    floatingPanelInteraction('PASSWORD_COPY_COMPLETE', {
      action: 'clipboard_copy',
      success: true
    })
    
    // Show brief notification when password is copied
    setSuccessMessage('Password copied to clipboard!')
    setShowSuccessNotification(true)
  }

  const handleSuccessNotificationClose = () => {
    floatingPanelInteraction('SUCCESS_NOTIFICATION_CLOSE', {
      previous_message: successMessage
    })
    
    setShowSuccessNotification(false)
    setSuccessMessage('')
  }

  // Original handlers
  const handleMinimize = (e) => {
    e.stopPropagation()
    
    floatingPanelInteraction('PANEL_MINIMIZE', {
      current_position: panelPosition,
      current_size: panelSize
    })
    
    setSavedPosition(panelPosition)
    setSavedSize(panelSize)
    setIsMinimized(true)
    
    floatingPanelState('MINIMIZED', { isMinimized: true }, {
      saved_position: panelPosition,
      saved_size: panelSize
    })
  }

  const handleRestore = (e) => {
    e.stopPropagation()
    
    floatingPanelInteraction('PANEL_RESTORE', {
      restoring_to_position: savedPosition,
      restoring_to_size: savedSize
    })
    
    setIsMinimized(false)
    setPanelPosition(savedPosition)
    setPanelSize(savedSize)
    
    floatingPanelState('RESTORED', { isMinimized: false }, {
      restored_position: savedPosition,
      restored_size: savedSize
    })
  }

  const handleMouseDown = (e) => {
    const target = e.target

    if (!isMinimized && target.closest(`.${styles.resizeHandle}`)) {
      e.preventDefault()
      e.stopPropagation()
      
      floatingPanelDragResize('RESIZE_START', {
        current_size: panelSize,
        cursor_position: { x: e.clientX, y: e.clientY }
      })
      
      setIsResizing(true)
      setDragStart({
        x: e.clientX,
        y: e.clientY,
        width: panelSize.width,
        height: panelSize.height
      })
      return
    }

    const headerElement = target.closest(`.${styles.header}`)
    if (headerElement && !target.closest('button')) {
      e.preventDefault()
      e.stopPropagation()

      const panel = panelRef.current
      if (panel) {
        const rect = panel.getBoundingClientRect()
        
        floatingPanelDragResize('DRAG_START', {
          panel_rect: { x: rect.left, y: rect.top, width: rect.width, height: rect.height },
          cursor_position: { x: e.clientX, y: e.clientY },
          drag_offset: { x: e.clientX - rect.left, y: e.clientY - rect.top }
        })
        
        setDragStart({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top
        })
        setIsDragging(true)
      }
    }
  }

  const handleMouseMove = (e) => {
    if (isDragging) {
      e.preventDefault()
      const newX = e.clientX - dragStart.x
      const newY = e.clientY - dragStart.y

      if (isMinimized) {
        const maxX = window.innerWidth - 200
        const maxY = window.innerHeight - 60
        const constrainedPosition = {
          x: Math.max(0, Math.min(newX, maxX)),
          y: Math.max(0, Math.min(newY, maxY))
        }
        
        floatingPanelPosition('MINIMIZED_DRAG', constrainedPosition, {
          unconstrained: { x: newX, y: newY },
          constraints: { maxX, maxY }
        })
        
        setMinimizedPosition(constrainedPosition)
      } else {
        const maxX = window.innerWidth - panelSize.width
        const maxY = window.innerHeight - panelSize.height
        const constrainedPosition = {
          x: Math.max(0, Math.min(newX, maxX)),
          y: Math.max(0, Math.min(newY, maxY))
        }
        
        floatingPanelPosition('NORMAL_DRAG', constrainedPosition, {
          unconstrained: { x: newX, y: newY },
          constraints: { maxX, maxY },
          panel_size: panelSize
        })
        
        setPanelPosition(constrainedPosition)
      }
    } else if (isResizing) {
      e.preventDefault()
      const deltaX = e.clientX - dragStart.x
      const deltaY = e.clientY - dragStart.y

      const newWidth = Math.max(200, Math.min(600, dragStart.width + deltaX))
      const newHeight = Math.max(300, Math.min(800, dragStart.height + deltaY))
      const newSize = { width: newWidth, height: newHeight }

      floatingPanelDragResize('RESIZE_MOVE', {
        delta: { x: deltaX, y: deltaY },
        new_size: newSize,
        constraints_applied: {
          width: { min: 200, max: 600 },
          height: { min: 300, max: 800 }
        }
      })

      setPanelSize(newSize)
    }
  }

  const handleMouseUp = () => {
    if (isDragging) {
      floatingPanelDragResize('DRAG_END', {
        final_position: isMinimized ? minimizedPosition : panelPosition
      })
    } else if (isResizing) {
      floatingPanelDragResize('RESIZE_END', {
        final_size: panelSize
      })
    }
    
    setIsDragging(false)
    setIsResizing(false)
  }

  useEffect(() => {
    if (isDragging || isResizing) {
      floatingPanelDragResize('MOUSE_LISTENERS_ATTACHED', {
        is_dragging: isDragging,
        is_resizing: isResizing
      })
      
      document.addEventListener('mousemove', handleMouseMove)
      document.addEventListener('mouseup', handleMouseUp)
      document.body.style.cursor = isDragging ? 'move' : 'nw-resize'
      document.body.style.userSelect = 'none'

      return () => {
        floatingPanelDragResize('MOUSE_LISTENERS_REMOVED', {
          was_dragging: isDragging,
          was_resizing: isResizing
        })
        
        document.removeEventListener('mousemove', handleMouseMove)
        document.removeEventListener('mouseup', handleMouseUp)
        document.body.style.cursor = ''
        document.body.style.userSelect = ''
      }
    }
  }, [isDragging, isResizing, dragStart, panelSize.width, panelSize.height])

  const handleShowAdvanced = () => {
    floatingPanelModal('SHOW_ADVANCED_MODAL', 'advanced_download', {
      certificates_count: certificates?.length || 0,
      has_any_files: hasAnyFiles
    })
    
    setShowAdvanced(true)
  }

  const handleCloseAdvanced = () => {
    floatingPanelModal('CLOSE_ADVANCED_MODAL', 'advanced_download', {
      was_showing: showAdvanced
    })
    
    setShowAdvanced(false)
  }

  const handleClearAllFiles = () => {
    floatingPanelFileManagement('CLEAR_ALL_FILES_START', {
      current_certificates_count: certificates?.length || 0,
      has_linux_required: hasRequiredForLinux,
      has_windows_required: hasRequiredForWindows,
      has_any_files: hasAnyFiles
    })
    
    clearAllFiles()
    
    floatingPanelFileManagement('CLEAR_ALL_FILES_COMPLETE', {
      action: 'all_files_cleared'
    })
  }

  // Validation panel toggle handler with comprehensive logging
  const handleValidationPanelToggle = (checked) => {
    floatingPanelValidation('VALIDATION_PANEL_TOGGLE', {
      previous_state: showValidationPanel,
      new_state: checked,
      toggle_source: 'user_interaction'
    })
    
    if (typeof onToggleValidationPanel === 'function') {
      floatingPanelValidation('CALLING_PARENT_HANDLER', {
        handler_available: true,
        new_state: checked
      })
      onToggleValidationPanel(checked)
    } else {
      floatingPanelWarn('Validation panel toggle handler not available', {
        handler_type: typeof onToggleValidationPanel,
        attempted_state: checked
      })
    }
  }

  const panelStyle = isMinimized
    ? {
        left: `${minimizedPosition.x}px`,
        top: `${minimizedPosition.y}px`,
        bottom: 'auto'
      }
    : {
        left: 0,
        top: 0,
        transform: `translate(${panelPosition.x}px, ${panelPosition.y}px)`,
        width: `${panelSize.width}px`,
        height: `${panelSize.height}px`
      }

  // Log panel style changes
  useEffect(() => {
    floatingPanelPosition('PANEL_STYLE_UPDATE', {
      is_minimized: isMinimized,
      style: panelStyle
    })
  }, [isMinimized, minimizedPosition, panelPosition, panelSize])

  // Log connection status changes
  useEffect(() => {
    floatingPanelState('CONNECTION_STATUS_CHANGE', { connectionStatus }, {
      previous_status: 'unknown',
      new_status: connectionStatus,
      timestamp: new Date().toISOString()
    })
  }, [connectionStatus])

  // Log download state changes
  useEffect(() => {
    floatingPanelState('DOWNLOAD_STATE_CHANGE', {
      isDownloading,
      downloadError: !!downloadError,
      showPasswordModal,
      showSuccessNotification
    }, {
      error_message: downloadError,
      success_message: successMessage
    })
  }, [isDownloading, downloadError, showPasswordModal, showSuccessNotification])

  // Log certificate requirements changes
  useEffect(() => {
    floatingPanelState('CERTIFICATE_REQUIREMENTS_CHANGE', {
      hasRequiredForLinux,
      hasRequiredForWindows,
      hasAnyFiles
    }, {
      certificates_count: certificates?.length || 0
    })
  }, [hasRequiredForLinux, hasRequiredForWindows, hasAnyFiles])

  // Component lifecycle logging
  useEffect(() => {
    floatingPanelLifecycle('COMPONENT_MOUNT', {
      initial_state: {
        isMinimized,
        connectionStatus,
        hasAnyFiles,
        showValidationPanel
      }
    })

    return () => {
      floatingPanelLifecycle('COMPONENT_UNMOUNT', {
        final_state: {
          isMinimized,
          connectionStatus,
          certificates_count: certificates?.length || 0
        }
      })
    }
  }, [])

  return (
    <>
      <div
        ref={panelRef}
        className={`${styles.panel} ${isMinimized ? styles.minimized : ''}`}
        style={panelStyle}
        onMouseDown={handleMouseDown}
      >
        <div className={`${styles.header} ${isMinimized && connectionStatus === 'connected' ? styles.connected : ''} ${isMinimized && connectionStatus === 'disconnected' ? styles.disconnected : ''}`}>
          <h3>System Panel</h3>
          <div className={styles.dragHandle}>
            <GripVertical size={16} />
            {!isMinimized ? (
              <button 
                className={styles.minimizeButton} 
                onClick={handleMinimize} 
                title="Minimize panel"
                onMouseDown={(e) => {
                  floatingPanelInteraction('MINIMIZE_BUTTON_CLICK', {
                    current_state: 'normal'
                  })
                }}
              >
                <Minimize2 size={14} />
              </button>
            ) : (
              <button 
                className={styles.minimizeButton} 
                onClick={handleRestore} 
                title="Restore panel"
                onMouseDown={(e) => {
                  floatingPanelInteraction('RESTORE_BUTTON_CLICK', {
                    current_state: 'minimized'
                  })
                }}
              >
                <Maximize2 size={14} />
              </button>
            )}
          </div>
        </div>

        <div className={styles.content}>
          {/* General Section */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <Settings size={16} />
              <h4 className={styles.sectionTitle}>General</h4>
            </div>
            <div className={styles.sectionContent}>
              <ConnectionStatus />
              <SystemMessages />
              
              {/* NEW: Validation Panel Toggle */}
              <div className={styles.validationToggleSection}>
                <div className={styles.sectionHeader}>
                  <Shield size={16} />
                  <span className={styles.sectionTitle}>Validation Panel</span>
                </div>
                <label className={styles.checkboxLabel}>
                  <input 
                    type="checkbox"
                    checked={showValidationPanel || false}
                    onChange={(e) => {
                      floatingPanelInteraction('VALIDATION_CHECKBOX_CHANGE', {
                        checked: e.target.checked,
                        previous_value: showValidationPanel
                      })
                      handleValidationPanelToggle(e.target.checked)
                    }}
                    className={styles.checkbox}
                  />
                  <span>Show Validation Results</span>
                </label>
              </div>
              
              <button 
                className={styles.clearAllButton} 
                onClick={() => {
                  floatingPanelInteraction('CLEAR_ALL_BUTTON_CLICK', {
                    files_to_clear: certificates?.length || 0
                  })
                  handleClearAllFiles()
                }}
              >
                <Trash2 size={16} />
                Clear All Files
              </button>
            </div>
          </div>

          {/* Download Section */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <Download size={16} />
              <h4 className={styles.sectionTitle}>Download</h4>
            </div>
            <div className={styles.sectionContent}>
              {/* Show download error if present */}
              {downloadError && (
                <div className={styles.errorMessage}>
                  {downloadError}
                </div>
              )}
              
              <button
                className={`${styles.downloadButton} ${!hasRequiredForLinux || isDownloading ? styles.disabled : ''}`}
                disabled={!hasRequiredForLinux || isDownloading}
                onClick={() => {
                  floatingPanelInteraction('LINUX_APACHE_BUTTON_CLICK', {
                    has_requirements: hasRequiredForLinux,
                    is_downloading: isDownloading
                  })
                  handleLinuxApacheDownload()
                }}
                title={
                  isDownloading 
                    ? "Downloading..." 
                    : hasRequiredForLinux 
                      ? "Download certificate bundle for Apache/Nginx" 
                      : "Certificate and private key required"
                }
              >
                <Monitor size={16} />
                {isDownloading ? 'Downloading...' : 'Linux (Apache)'}
              </button>
              <button
                className={`${styles.downloadButton} ${!hasRequiredForWindows || isDownloading ? styles.disabled : ''}`}
                disabled={!hasRequiredForWindows || isDownloading}
                onClick={() => {
                  floatingPanelInteraction('WINDOWS_IIS_BUTTON_CLICK', {
                    has_requirements: hasRequiredForWindows,
                    is_downloading: isDownloading
                  })
                  handleWindowsIISDownload()
                }}
                title={
                  isDownloading 
                    ? "Downloading..." 
                    : hasRequiredForWindows 
                      ? "Download PKCS#12 bundle for Windows IIS" 
                      : "Full certificate chain required"
                }
              >
                <Package size={16} />
                {isDownloading ? 'Downloading...' : 'Windows (IIS)'}
              </button>
              <button
                className={`${styles.downloadButton} ${!hasAnyFiles ? styles.disabled : ''}`}
                onClick={() => {
                  floatingPanelInteraction('ADVANCED_BUTTON_CLICK', {
                    has_any_files: hasAnyFiles,
                    certificates_count: certificates?.length || 0
                  })
                  handleShowAdvanced()
                }}
                disabled={!hasAnyFiles}
                title={hasAnyFiles ? "Advanced download options" : "Upload files to enable advanced options"}
              >
                <Wrench size={16} />
                Advanced
              </button>
            </div>
          </div>

          {/* File Manager Section */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <Files size={16} />
              <h4 className={styles.sectionTitle}>File Manager</h4>
            </div>
            <div className={styles.sectionContent}>
              <FileManager />
            </div>
          </div>
        </div>

        <div className={styles.resizeHandle}></div>
      </div>

      {showAdvanced && (
        <AdvancedModal 
          onClose={() => {
            floatingPanelInteraction('ADVANCED_MODAL_CLOSE', {
              close_source: 'modal_close_button'
            })
            handleCloseAdvanced()
          }} 
        />
      )}

      {showPasswordModal && (zipPassword || encryptionPassword) && (
        <SecurePasswordModal
          password={zipPassword}
          encryptionPassword={encryptionPassword}
          bundleType="iis"  // ← ADD THIS LINE
          onClose={() => {
            floatingPanelInteraction('PASSWORD_MODAL_CLOSE', {
              close_source: 'modal_close_button',
              had_passwords: !!(zipPassword || encryptionPassword)
            })
            handlePasswordModalClose()
          }}
          onCopyComplete={() => {
            floatingPanelInteraction('PASSWORD_COPY_FROM_MODAL', {
              copy_source: 'modal_copy_button'
            })
            handlePasswordCopyComplete()
          }}
        />
      )}

      <NotificationToast
        type="success"
        message={successMessage}
        show={showSuccessNotification}
        onClose={() => {
          floatingPanelInteraction('SUCCESS_NOTIFICATION_CLOSE', {
            close_source: 'notification_close_button',
            message: successMessage
          })
          handleSuccessNotificationClose()
        }}
        duration={4000}
      />
    </>
  )
}

export default FloatingPanel