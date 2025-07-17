// frontend/src/components/FloatingPanel/FileManager.jsx
import React from 'react'
import { File, Trash2 } from 'lucide-react'
import { useCertificates } from '../../contexts/CertificateContext'
import styles from './FloatingPanel.module.css'

const FileManager = () => {
  const { certificates, deleteCertificate } = useCertificates()

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
        return '#dc2626' // Red-600 - Private keys (sensitive)
      default:
        return '#6b7280' // Gray-500 - Unknown/other types
    }
  }

  const handleDeleteFile = async (fileId) => {
    if (window.confirm('Are you sure you want to delete this certificate?')) {
      await deleteCertificate(fileId)
    }
  }

  if (certificates.length === 0) {
    return (
      <div className={styles.fileInfoSection}>
        <div className={styles.fileInfoCard}>
          <div className={styles.fileInfoHeader}>
            <File size={16} style={{ color: '#6b7280' }} />
            <span style={{ color: '#6b7280', fontWeight: '500' }}>
              No Files
            </span>
          </div>
          <p style={{ 
            margin: 0, 
            fontSize: '0.75rem', 
            color: '#9ca3af',
            textAlign: 'center' 
          }}>
            Upload certificates to get started
          </p>
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
            Files ({certificates.length})
          </span>
        </div>
        
        <div className={styles.fileDetailsList}>
          {certificates.map((file, index) => {
            const analysis = file.analysis || {}
            const type = analysis.type || 'Unknown'
            const isValid = file.success && analysis.isValid !== false
            const typeColor = getTypeColor(type, isValid)
            
            return (
              <div key={file.id || index} className={styles.fileDetail}>
                <div className={styles.fileHeader}>
                  <span className={styles.fileNumber}>#{index + 1}</span>
                  <button 
                    className={styles.deleteButton}
                    onClick={() => handleDeleteFile(file.id)}
                    title="Delete certificate"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                
                <div className={styles.fileDetailRow}>
                  <span className={styles.fileDetailLabel}>Name:</span>
                  <span className={styles.fileDetailValue}>
                    {file.filename || file.name}
                  </span>
                </div>
                
                <div className={styles.fileDetailRow}>
                  <span className={styles.fileDetailLabel}>Type:</span>
                  <span 
                    className={styles.fileDetailValue}
                    style={{ color: typeColor, fontWeight: '500' }}
                  >
                    {getFileType(type, isValid)}
                  </span>
                </div>
                
                {analysis.details?.subject?.commonName && (
                  <div className={styles.fileDetailRow}>
                    <span className={styles.fileDetailLabel}>CN:</span>
                    <span className={styles.fileDetailValue}>
                      {analysis.details.subject.commonName}
                    </span>
                  </div>
                )}
                
                {analysis.details?.validity?.daysUntilExpiry !== undefined && (
                  <div className={styles.fileDetailRow}>
                    <span className={styles.fileDetailLabel}>Expires:</span>
                    <span 
                      className={styles.fileDetailValue}
                      style={{ 
                        color: analysis.details.validity.daysUntilExpiry < 30 ? '#dc2626' : '#059669',
                        fontWeight: '500'
                      }}
                    >
                      {analysis.details.validity.daysUntilExpiry} days
                    </span>
                  </div>
                )}
                
                {analysis.keySize && (
                  <div className={styles.fileDetailRow}>
                    <span className={styles.fileDetailLabel}>Size:</span>
                    <span className={styles.fileDetailValue}>
                      {analysis.keySize} bits
                    </span>
                  </div>
                )}
                
                {index < certificates.length - 1 && (
                  <div className={styles.fileDivider} />
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default FileManager