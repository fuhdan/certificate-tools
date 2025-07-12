import React from 'react'
import ConnectionStatus from './ConnectionStatus'
import SystemMessages from './SystemMessages'
import FileManager from './FileManager'
import { Trash2 } from 'lucide-react'
import styles from './FloatingPanel.module.css'

const FloatingPanel = () => {
  const clearAllFiles = () => {
    // Call the global clear function from FileUpload
    if (window.clearAllFiles) {
      window.clearAllFiles()
    }
  }

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <h3>System Panel</h3>
      </div>
      <div className={styles.content}>
        <ConnectionStatus />
        
        <SystemMessages />
        
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
  )
}

export default FloatingPanel