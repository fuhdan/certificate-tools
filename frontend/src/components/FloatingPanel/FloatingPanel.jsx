// frontend/src/components/FloatingPanel/FloatingPanel.jsx (Fixed - Preserving Original Logic)
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
  Maximize2
} from 'lucide-react'
import styles from './FloatingPanel.module.css'
import ConnectionStatus from './ConnectionStatus'
import SystemMessages from './SystemMessages'
import FileManager from './FileManager'
import PKIBundleViewer from './PKIBundleViewer'
import AdvancedModal from './AdvancedModal'
import SecurePasswordModal from './SecurePasswordModal'
import NotificationToast from '../common/NotificationToast'
import { useCertificates } from '../../contexts/CertificateContext'
import { sessionManager } from '../../services/sessionManager'
import api from '../../services/api'

const FloatingPanel = ({ isAuthenticated }) => {
  const { certificates, clearAllFiles } = useCertificates()
  const [showPKIBundle, setShowPKIBundle] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  
  // NEW: Download-related state
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [zipPassword, setZipPassword] = useState('')
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
  const [savedSize, setSavedSize] = useState({ width: 250, height: 400 })
  const [minimizedPosition, setMinimizedPosition] = useState({ x: 16, y: window.innerHeight - 80 })

  const panelRef = useRef(null)
  const [isDragging, setIsDragging] = useState(false)
  const [isResizing, setIsResizing] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  const [panelPosition, setPanelPosition] = useState(() => {
    const initialX = window.innerWidth - 250 - 16
    const initialY = window.innerHeight * 0.2
    return { x: initialX, y: initialY }
  })
  const [panelSize, setPanelSize] = useState({ width: 250, height: 400 })

  // Initialize starting position based on visual CSS defaults
  useEffect(() => {
    const initialX = window.innerWidth - 250 - 16 // width + margin
    const initialY = window.innerHeight * 0.2
    setPanelPosition({ x: initialX, y: initialY })
  }, [])

  useEffect(() => {
    const checkConnection = async () => {
      try {
        const response = await api.get('/health')
        setConnectionStatus(response.data.status === 'online' ? 'connected' : 'disconnected')
      } catch {
        setConnectionStatus('disconnected')
      }
    }

    checkConnection()
    const interval = setInterval(checkConnection, 10000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    console.log('Certificates:', certificates);
    
    if (!certificates || certificates.length === 0) {
      setHasRequiredForLinux(false);
      setHasRequiredForWindows(false);
      setHasAnyFiles(false);
      return;
    }
  
    // Normalize type strings to lowercase and check
    const hasEndEntityCert = certificates.some(cert => {
      const typeStr = (cert.analysis?.type || cert.Type || cert.type || '').toLowerCase();
      // Consider certificate present if type includes 'certificate' and not 'ca certificate'
      return typeStr.includes('certificate') && !typeStr.includes('ca certificate');
    });
  
    const hasPrivateKey = certificates.some(cert => {
      const typeStr = (cert.type || cert.Type || cert.analysis?.type || '').toLowerCase();
      return typeStr === 'private key' || typeStr === 'private_key';
    });
  
    const certificates_analysis = certificates.map(cert => cert.analysis).filter(Boolean);
    const hasCACertificates = certificates_analysis.some(a => a?.type === 'Intermediate CA Certificate');
    const hasRootCA = certificates_analysis.some(a => a?.type === 'Root CA Certificate');
  
    console.log('hasEndEntityCert:', hasEndEntityCert, 'hasPrivateKey:', hasPrivateKey);
  
    setHasRequiredForLinux(hasEndEntityCert && hasPrivateKey);
    setHasRequiredForWindows(hasEndEntityCert && hasPrivateKey && hasCACertificates && hasRootCA);
    setHasAnyFiles(certificates.length > 0);
  }, [certificates]);

  // NEW: Download handlers
  const handleLinuxApacheDownload = async () => {
    if (!hasRequiredForLinux || isDownloading) return

    setIsDownloading(true)
    setDownloadError(null)

    try {
      const sessionId = sessionManager.getSessionId()
      
      console.log('Making API call to:', `/api/downloads/apache/${sessionId}`)
      
      // Make API call to download Apache bundle - compensate for proxy stripping /api
      const response = await api.post(`/api/downloads/apache/${sessionId}`, {}, {
        responseType: 'blob', // Important for binary data
        timeout: 30000 // 30 second timeout for large files
      })

      // Extract password from response headers
      const password = response.headers['x-zip-password']
      
      if (!password) {
        throw new Error('ZIP password not found in response headers')
      }

      // Create blob URL and trigger download
      const blob = new Blob([response.data], { type: 'application/zip' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `apache-bundle-${sessionId.substring(0, 8)}.zip`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)

      // Show password modal
      setZipPassword(password)
      setShowPasswordModal(true)

      // Show success notification
      setSuccessMessage('Apache certificate bundle downloaded successfully!')
      setShowSuccessNotification(true)

    } catch (error) {
      console.error('Apache download failed:', error)
      
      if (error.response?.status === 404) {
        setDownloadError('No certificates found. Please upload required certificates first.')
      } else if (error.response?.status === 400) {
        setDownloadError('Invalid session or missing required certificates.')
      } else if (error.code === 'ECONNABORTED') {
        setDownloadError('Download timeout. Please try again.')
      } else {
        setDownloadError('Download failed. Please try again.')
      }
    } finally {
      setIsDownloading(false)
    }
  }

  const handlePasswordModalClose = () => {
    setShowPasswordModal(false)
    // Security: Clear password from memory
    setZipPassword('')
  }

  const handlePasswordCopyComplete = () => {
    // Show brief notification when password is copied
    setSuccessMessage('ZIP password copied to clipboard!')
    setShowSuccessNotification(true)
  }

  const handleSuccessNotificationClose = () => {
    setShowSuccessNotification(false)
    setSuccessMessage('')
  }

  // Original handlers
  const handleMinimize = (e) => {
    e.stopPropagation()
    setSavedPosition(panelPosition)
    setSavedSize(panelSize)
    setIsMinimized(true)
  }

  const handleRestore = (e) => {
    e.stopPropagation()
    setIsMinimized(false)
    setPanelPosition(savedPosition)
    setPanelSize(savedSize)
  }

  const handleMouseDown = (e) => {
    const target = e.target

    if (!isMinimized && target.closest(`.${styles.resizeHandle}`)) {
      e.preventDefault()
      e.stopPropagation()
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
        setMinimizedPosition({
          x: Math.max(0, Math.min(newX, maxX)),
          y: Math.max(0, Math.min(newY, maxY))
        })
      } else {
        const maxX = window.innerWidth - panelSize.width
        const maxY = window.innerHeight - panelSize.height
        setPanelPosition({
          x: Math.max(0, Math.min(newX, maxX)),
          y: Math.max(0, Math.min(newY, maxY))
        })
      }
    } else if (isResizing) {
      e.preventDefault()
      const deltaX = e.clientX - dragStart.x
      const deltaY = e.clientY - dragStart.y

      const newWidth = Math.max(200, Math.min(600, dragStart.width + deltaX))
      const newHeight = Math.max(300, Math.min(800, dragStart.height + deltaY))

      setPanelSize({ width: newWidth, height: newHeight })
    }
  }

  const handleMouseUp = () => {
    setIsDragging(false)
    setIsResizing(false)
  }

  useEffect(() => {
    if (isDragging || isResizing) {
      document.addEventListener('mousemove', handleMouseMove)
      document.addEventListener('mouseup', handleMouseUp)
      document.body.style.cursor = isDragging ? 'move' : 'nw-resize'
      document.body.style.userSelect = 'none'

      return () => {
        document.removeEventListener('mousemove', handleMouseMove)
        document.removeEventListener('mouseup', handleMouseUp)
        document.body.style.cursor = ''
        document.body.style.userSelect = ''
      }
    }
  }, [isDragging, isResizing, dragStart, panelSize.width, panelSize.height])

  const handleShowPKIBundle = () => {
    setShowPKIBundle(true)
  }

  const handleClosePKIBundle = () => {
    setShowPKIBundle(false)
  }

  const handleShowAdvanced = () => {
    setShowAdvanced(true)
  }

  const handleCloseAdvanced = () => {
    setShowAdvanced(false)
  }

  const handleClearAllFiles = () => {
    clearAllFiles()
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
              <button className={styles.minimizeButton} onClick={handleMinimize} title="Minimize panel">
                <Minimize2 size={14} />
              </button>
            ) : (
              <button className={styles.minimizeButton} onClick={handleRestore} title="Restore panel">
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
              <button
                className={`${styles.pkiBundleButton} ${!isAuthenticated ? styles.disabled : ''}`}
                onClick={handleShowPKIBundle}
                title={isAuthenticated ? "View PKI Bundle JSON" : "Login required to view PKI Bundle"}
                disabled={!isAuthenticated}
              >
                <Package size={16} />
                View PKI Bundle
              </button>
              <button className={styles.clearAllButton} onClick={handleClearAllFiles}>
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
                onClick={handleLinuxApacheDownload}
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
                className={`${styles.downloadButton} ${!hasRequiredForWindows ? styles.disabled : ''}`}
                disabled={!hasRequiredForWindows}
                title={hasRequiredForWindows ? "Download PKCS#12 bundle for Windows IIS" : "Full certificate chain required"}
              >
                <Package size={16} />
                Windows (IIS)
              </button>
              <button
                className={`${styles.downloadButton} ${!hasAnyFiles ? styles.disabled : ''}`}
                onClick={handleShowAdvanced}
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

      {showPKIBundle && isAuthenticated && (
        <PKIBundleViewer onClose={handleClosePKIBundle} />
      )}

      {showAdvanced && (
        <AdvancedModal onClose={handleCloseAdvanced} />
      )}

      {showPasswordModal && zipPassword && (
        <SecurePasswordModal
          password={zipPassword}
          onClose={handlePasswordModalClose}
          onCopyComplete={handlePasswordCopyComplete}
        />
      )}

      <NotificationToast
        type="success"
        message={successMessage}
        show={showSuccessNotification}
        onClose={handleSuccessNotificationClose}
        duration={4000}
      />
    </>
  )
}

export default FloatingPanel