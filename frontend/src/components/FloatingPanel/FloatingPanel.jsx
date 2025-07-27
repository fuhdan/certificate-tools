import React, { useState, useEffect, useRef } from 'react'
import { 
  Settings, 
  Download, 
  Files, 
  Package, 
  Trash2, 
  Monitor, 
  Wrench,
  GripVertical 
} from 'lucide-react'
import styles from './FloatingPanel.module.css'
import ConnectionStatus from './ConnectionStatus'
import SystemMessages from './SystemMessages'
import FileManager from './FileManager'
import PKIBundleViewer from './PKIBundleViewer'
import AdvancedModal from './AdvancedModal'
import { useCertificates } from '../../contexts/CertificateContext'

const FloatingPanel = ({ isAuthenticated }) => {
  const { certificates, clearAllFiles } = useCertificates()
  const [showPKIBundle, setShowPKIBundle] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [hasRequiredForLinux, setHasRequiredForLinux] = useState(false)
  const [hasRequiredForWindows, setHasRequiredForWindows] = useState(false)
  const [hasAnyFiles, setHasAnyFiles] = useState(false)
  
  // Drag and resize functionality
  const panelRef = useRef(null)
  const [isDragging, setIsDragging] = useState(false)
  const [isResizing, setIsResizing] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  const [panelPosition, setPanelPosition] = useState({ x: 0, y: 0 })
  const [panelSize, setPanelSize] = useState({ width: 250, height: 400 })

  // Calculate requirements based on certificates
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
    
    console.log('Certificate requirements check:', {
      hasEndEntityCert,
      hasPrivateKey,
      hasCACertificates,
      hasRootCA,
      certificateTypes: certificates_analysis.map(a => a?.type)
    })
    
    // Linux (Apache) needs end-entity certificate + private key
    setHasRequiredForLinux(hasEndEntityCert && hasPrivateKey)
    
    // Windows (IIS/PKCS#12) needs: end-entity + private key + CA certificates + root CA
    setHasRequiredForWindows(hasEndEntityCert && hasPrivateKey && hasCACertificates && hasRootCA)
    
    // Advanced button: enable when any files are uploaded
    setHasAnyFiles(certificates.length > 0)
  }, [certificates])

  // Drag event handlers
  const handleMouseDown = (e) => {
    const target = e.target
    
    // Check if clicking on resize handle
    if (target.closest(`.${styles.resizeHandle}`)) {
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
    
    // Check if clicking on header for dragging (but not on buttons)
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
      
      // Keep panel within viewport bounds
      const maxX = window.innerWidth - panelSize.width
      const maxY = window.innerHeight - panelSize.height
      
      setPanelPosition({
        x: Math.max(0, Math.min(newX, maxX)),
        y: Math.max(0, Math.min(newY, maxY))
      })
    } else if (isResizing) {
      e.preventDefault()
      const deltaX = e.clientX - dragStart.x
      const deltaY = e.clientY - dragStart.y
      
      const newWidth = Math.max(200, Math.min(600, dragStart.width + deltaX))
      const newHeight = Math.max(250, Math.min(window.innerHeight * 0.8, dragStart.height + deltaY))
      
      setPanelSize({
        width: newWidth,
        height: newHeight
      })
    }
  }

  const handleMouseUp = () => {
    setIsDragging(false)
    setIsResizing(false)
  }

  // Add global event listeners for drag and resize
  useEffect(() => {
    if (isDragging || isResizing) {
      const preventSelection = (e) => {
        e.preventDefault()
        return false
      }
      
      document.addEventListener('mousemove', handleMouseMove, { passive: false })
      document.addEventListener('mouseup', handleMouseUp)
      document.addEventListener('selectstart', preventSelection)
      document.addEventListener('dragstart', preventSelection)
      
      // Safari-specific
      document.body.style.webkitUserSelect = 'none'
      document.body.style.userSelect = 'none'
      
      return () => {
        document.removeEventListener('mousemove', handleMouseMove)
        document.removeEventListener('mouseup', handleMouseUp)
        document.removeEventListener('selectstart', preventSelection)
        document.removeEventListener('dragstart', preventSelection)
        
        // Reset Safari styles
        document.body.style.webkitUserSelect = ''
        document.body.style.userSelect = ''
      }
    }
  }, [isDragging, isResizing, dragStart, panelPosition, panelSize])

  // Add test system message on component mount
  useEffect(() => {
    // Add a test message to demonstrate the system messages functionality
    const addTestMessage = () => {
      const event = new CustomEvent('systemMessage', {
        detail: {
          message: "Connection established successfully",
          type: 'info',
          id: Date.now()
        }
      })
      window.dispatchEvent(event)
    }
    
    // Add test message after a short delay
    const timer = setTimeout(addTestMessage, 1000)
    
    return () => clearTimeout(timer)
  }, [])

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

  const handleClosePKIBundle = () => {
    setShowPKIBundle(false)
  }

  const handleShowAdvanced = () => {
    setShowAdvanced(true)
  }

  const handleCloseAdvanced = () => {
    setShowAdvanced(false)
  }

  return (
    <>
      <div 
        ref={panelRef}
        className={styles.panel}
        style={{
          transform: `translate(${panelPosition.x}px, ${panelPosition.y}px)`,
          width: `${panelSize.width}px`,
          height: `${panelSize.height}px`,
          right: panelPosition.x === 0 && panelPosition.y === 0 ? '1rem' : 'auto',
          top: panelPosition.x === 0 && panelPosition.y === 0 ? '20%' : 'auto',
          left: panelPosition.x !== 0 || panelPosition.y !== 0 ? 0 : 'auto'
        }}
        onMouseDown={handleMouseDown}
      >
        <div className={styles.header}>
          <h3>System Panel</h3>
          <div className={styles.dragHandle}>
            <GripVertical size={16} />
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
              <button 
                className={styles.clearAllButton}
                onClick={handleClearAllFiles}
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
                title={hasRequiredForWindows ? "Download PKCS#12 bundle for Windows IIS" : "Full certificate chain required: end-entity certificate, private key, intermediate CA(s), and root CA"}
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
        
        {/* Resize handle */}
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