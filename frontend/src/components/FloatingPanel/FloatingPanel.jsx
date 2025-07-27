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
import { useCertificates } from '../../contexts/CertificateContext'
import api from '../../services/api'

const FloatingPanel = ({ isAuthenticated }) => {
  const { certificates, clearAllFiles } = useCertificates()
  const [showPKIBundle, setShowPKIBundle] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
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
    if (!certificates || certificates.length === 0) {
      setHasRequiredForLinux(false)
      setHasRequiredForWindows(false)
      setHasAnyFiles(false)
      return
    }

    const certificates_analysis = certificates.map(cert => cert.analysis).filter(Boolean)

    const hasEndEntityCert = certificates_analysis.some(a => a?.type === 'End-entity Certificate')
    const hasPrivateKey = certificates.some(cert => cert.type === 'private_key')
    const hasCACertificates = certificates_analysis.some(a => a?.type === 'Intermediate CA Certificate')
    const hasRootCA = certificates_analysis.some(a => a?.type === 'Root CA Certificate')

    setHasRequiredForLinux(hasEndEntityCert && hasPrivateKey)
    setHasRequiredForWindows(hasEndEntityCert && hasPrivateKey && hasCACertificates && hasRootCA)
    setHasAnyFiles(certificates.length > 0)
  }, [certificates])

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
      const newHeight = Math.max(250, Math.min(window.innerHeight * 0.8, dragStart.height + deltaY))
      setPanelSize({ width: newWidth, height: newHeight })
    }
  }

  const handleMouseUp = () => {
    setIsDragging(false)
    setIsResizing(false)
  }

  useEffect(() => {
    if (isDragging || isResizing) {
      const preventSelection = (e) => { e.preventDefault(); return false }

      document.addEventListener('mousemove', handleMouseMove, { passive: false })
      document.addEventListener('mouseup', handleMouseUp)
      document.addEventListener('selectstart', preventSelection)
      document.addEventListener('dragstart', preventSelection)

      document.body.style.webkitUserSelect = 'none'
      document.body.style.userSelect = 'none'

      return () => {
        document.removeEventListener('mousemove', handleMouseMove)
        document.removeEventListener('mouseup', handleMouseUp)
        document.removeEventListener('selectstart', preventSelection)
        document.removeEventListener('dragstart', preventSelection)
        document.body.style.webkitUserSelect = ''
        document.body.style.userSelect = ''
      }
    }
  }, [isDragging, isResizing, dragStart, panelPosition, panelSize])

  const handleClearAllFiles = async () => {
    if (window.confirm('Are you sure you want to clear all files? This action cannot be undone.')) {
      await clearAllFiles()
    }
  }

  const handleShowPKIBundle = () => {
    if (!isAuthenticated) {
      console.warn('PKI Bundle access requires authentication')
      return
    }
    setShowPKIBundle(true)
  }

  const handleClosePKIBundle = () => setShowPKIBundle(false)
  const handleShowAdvanced = () => setShowAdvanced(true)
  const handleCloseAdvanced = () => setShowAdvanced(false)

  return (
    <>
      <div
        ref={panelRef}
        className={`${styles.panel} ${isMinimized ? styles.minimized : ''}`}
        style={isMinimized ? {
          left: `${minimizedPosition.x}px`,
          top: `${minimizedPosition.y}px`,
          bottom: 'auto'
        } : {
          left: 0,
          top: 0,
          transform: `translate(${panelPosition.x}px, ${panelPosition.y}px)`,
          width: `${panelSize.width}px`,
          height: `${panelSize.height}px`
        }}
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
              <button
                className={`${styles.downloadButton} ${!hasRequiredForLinux ? styles.disabled : ''}`}
                disabled={!hasRequiredForLinux}
                title={hasRequiredForLinux ? "Download certificate bundle for Apache/Nginx" : "Certificate and private key required"}
              >
                <Monitor size={16} />
                Linux (Apache)
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
    </>
  )
}

export default FloatingPanel
