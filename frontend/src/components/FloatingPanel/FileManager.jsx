import React, { useState, useEffect } from 'react'
import { Trash2 } from 'lucide-react'
import styles from './FloatingPanel.module.css'

const FileManager = () => {
  const [fileCount, setFileCount] = useState(0)

  // Listen for file uploads (you can connect this to your main file upload component)
  useEffect(() => {
    // This is a placeholder - you'd connect this to your actual file state
    const updateFileCount = () => {
      // Get file count from your upload component
      const uploadedFiles = document.querySelectorAll('[data-file-item]')
      setFileCount(uploadedFiles.length)
    }

    // Check periodically for file updates
    const interval = setInterval(updateFileCount, 1000)
    return () => clearInterval(interval)
  }, [])

  const clearAllFiles = () => {
    // This would trigger clearing files in the main upload component
    const clearButton = document.querySelector('[data-clear-all]')
    if (clearButton) {
      clearButton.click()
    }
  }

  return (
    <div className={styles.fileSection}>
      <div className={styles.sectionDivider}></div>
      <h4>File Manager</h4>
      <div className={styles.fileStats}>
        <span className={styles.fileCount}>Files: {fileCount}</span>
      </div>
      <button 
        className={styles.clearAllButton}
        onClick={clearAllFiles}
        disabled={fileCount === 0}
      >
        <Trash2 size={14} />
        Clear All
      </button>
    </div>
  )
}

export default FileManager