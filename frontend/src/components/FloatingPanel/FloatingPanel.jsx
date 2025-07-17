import React, { useState } from 'react'
import ConnectionStatus from './ConnectionStatus'
import SystemMessages from './SystemMessages'
import FileManager from './FileManager'
import PKIBundleViewer from './PKIBundleViewer'
import { Trash2, Package } from 'lucide-react'
import styles from './FloatingPanel.module.css'

const FloatingPanel = ({ isAuthenticated }) => {
  const [showPKIBundle, setShowPKIBundle] = useState(false)

  const clearAllFiles = () => {
    // Call the global clear function from FileUpload
    if (window.clearAllFiles) {
      window.clearAllFiles()
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

  return (
    <>
      <div className={styles.panel}>
        <div className={styles.header}>
          <h3>System Panel</h3>
        </div>
        <div className={styles.content}>
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
            onClick={clearAllFiles}
          >
            <Trash2 size={16} />
            Clear All Files
          </button>
          
          <FileManager />
        </div>
      </div>

      {showPKIBundle && isAuthenticated && (
        <PKIBundleViewer onClose={handleClosePKIBundle} />
      )}
    </>
  )
}

export default FloatingPanel
