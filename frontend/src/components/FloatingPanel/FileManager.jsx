import React, { useState, useEffect } from 'react'
import { File, Trash2 } from 'lucide-react'
import styles from './FloatingPanel.module.css'

const FileManager = () => {
  const [files, setFiles] = useState([])

  useEffect(() => {
    // Initialize with any existing files
    if (window.uploadedFiles) {
      setFiles(window.uploadedFiles)
    }

    // Listen for file updates
    const handleFilesUpdated = (event) => {
      setFiles(event.detail.files)
    }

    window.addEventListener('filesUpdated', handleFilesUpdated)
    
    return () => {
      window.removeEventListener('filesUpdated', handleFilesUpdated)
    }
  }, [])

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getFileType = (type, isValid) => {
    if (!isValid && type !== 'Unknown') {
      return `${type} (Invalid)`
    }
    return type || 'Unknown'
  }

  const getTypeColor = (type, isValid) => {
    if (!isValid) return '#dc2626' // Red for invalid
    
    switch (type) {
      case 'Certificate':
        return '#1e40af' // Blue-700 - Primary certificates
      case 'CA Certificate':
        return '#1d4ed8' // Blue-600 - CA certificates (darker blue)
      case 'CSR':
        return '#3b82f6' // Blue-500 - Certificate requests (medium blue)
      case 'Certificate Chain':
        return '#2563eb' // Blue-600 - Certificate chains
      case 'Private Key':
        return '#dc2626' // Red-600 - Private keys (security)
      case 'Public Key':
        return '#059669' // Emerald-600 - Public keys
      default:
        return '#6b7280' // Gray-500 - Unknown types
    }
  }

  const deleteFile = async (fileId) => {
    if (window.deleteFile) {
      await window.deleteFile(fileId)
    }
  }

  if (files.length === 0) {
    return (
      <div className={styles.fileInfoSection}>
        <div className={styles.fileInfoCard}>
          <div className={styles.statusRow}>
            <span style={{ color: '#6b7280' }}>
              <File size={16} />
            </span>
            <span style={{ color: '#6b7280', fontWeight: '500' }}>
              No files uploaded
            </span>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.fileInfoSection}>
      <div className={styles.fileInfoCard}>
        <div className={styles.fileInfoHeader}>
          <File size={16} style={{ color: '#6b7280' }} />
          <span style={{ color: '#6b7280', fontWeight: '500' }}>
            Files: {files.length}
          </span>
        </div>
        
        <div className={styles.fileDetailsList}>
          {files.map((file, index) => (
            <div key={file.id} className={styles.fileDetail}>
              <div className={styles.fileHeader}>
                <span className={styles.fileNumber}>#{index + 1}</span>
                <button 
                  className={styles.deleteButton}
                  onClick={() => deleteFile(file.id)}
                  title="Delete file"
                >
                  <Trash2 size={12} />
                </button>
              </div>
              
              <div className={styles.fileDetailRow}>
                <span className={styles.fileDetailLabel}>Name:</span>
                <span className={styles.fileDetailValue}>{file.name}</span>
              </div>
              <div className={styles.fileDetailRow}>
                <span className={styles.fileDetailLabel}>Size:</span>
                <span className={styles.fileDetailValue}>{formatFileSize(file.size)}</span>
              </div>
              <div className={styles.fileDetailRow}>
                <span className={styles.fileDetailLabel}>Type:</span>
                <span 
                  className={styles.fileDetailValue}
                  style={{ color: getTypeColor(file.type, file.isValid) }}
                >
                  {getFileType(file.type, file.isValid)}
                </span>
              </div>
              <div className={styles.fileDetailRow}>
                <span className={styles.fileDetailLabel}>Format:</span>
                <span className={styles.fileDetailValue}>{file.format}</span>
              </div>
              {index < files.length - 1 && <div className={styles.fileDivider}></div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default FileManager