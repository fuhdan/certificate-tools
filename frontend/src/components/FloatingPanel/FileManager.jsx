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

  const getCertificateType = (analysis) => {
    if (!analysis || !analysis.type) return 'Unknown'
    
    const type = analysis.type
    
    // Handle standardized types only
    switch (type) {
      case 'CSR':
        return 'CSR'
      case 'PrivateKey':
        return 'Private Key'
      case 'Certificate':
        return 'Certificate'
      case 'IssuingCA':
        return 'Issuing CA'
      case 'IntermediateCA':
        return 'Intermediate CA'
      case 'RootCA':
        return 'Root CA'
      case 'CertificateChain':
        return 'Certificate Chain'
      default:
        return type
    }
  }

  const hasPassword = (fileGroup) => {
    // Check if any certificate in the group was uploaded with a password
    // Use the backend-provided usedPassword flag
    const usedPassword = fileGroup.certificates.some(cert => 
      cert.analysis?.usedPassword === true
    )
    return usedPassword ? 'Yes' : 'No'
  }

  // Group certificates by filename (original uploaded file)
  const groupCertificatesByFile = () => {
    const groups = {}
    
    certificates.forEach(cert => {
      const filename = cert.filename || cert.name || 'Unknown'
      // Remove any suffix like " (Private Key)" or " (Certificate)" from filename
      const cleanFilename = filename.replace(/\s*\([^)]*\)$/, '')
      
      if (!groups[cleanFilename]) {
        groups[cleanFilename] = {
          filename: cleanFilename,
          totalSize: 0,
          certificates: [],
          format: 'PEM' // Default
        }
      }
      
      groups[cleanFilename].certificates.push(cert)
      // Use the actual file size from the first certificate's analysis
      if (cert.analysis?.size > 0) {
        groups[cleanFilename].totalSize = cert.analysis.size
      }
      // Set format based on any certificate in the group
      if (cert.analysis?.format === 'PKCS12') {
        groups[cleanFilename].format = 'PKCS12'
      }
    })
    
    return Object.values(groups)
  }

  const handleDeleteFile = async (fileId) => {
    if (window.confirm('Are you sure you want to delete this certificate component?')) {
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

  const fileGroups = groupCertificatesByFile()

  return (
    <div className={styles.fileInfoSection}>
      <div className={styles.fileInfoCard}>
        <div className={styles.fileInfoHeader}>
          <File size={16} style={{ color: '#6b7280' }} />
          <span style={{ color: '#6b7280', fontWeight: '500' }}>
            Files ({fileGroups.length})
          </span>
        </div>
        
        <div className={styles.fileDetailsList}>
          {fileGroups.map((fileGroup, groupIndex) => (
            <div key={fileGroup.filename} className={styles.fileContainer}>
              {/* File Header - Filename and Size */}
              <div className={styles.fileHeader}>
                <div className={styles.fileName}>
                  {fileGroup.filename}
                </div>
              </div>
              
              <div className={styles.fileInfo}>
                <div className={styles.fileSize}>
                  {formatFileSize(fileGroup.totalSize)}
                </div>
                
                <div className={styles.fileMetadata}>
                  <span>Password: {hasPassword(fileGroup)}</span>
                </div>
                
                <div className={styles.fileMetadata}>
                  <span>Format: {fileGroup.format}</span>
                </div>
              </div>
              
              {/* Certificate Types List */}
              <div className={styles.certificateTypesList}>
                {fileGroup.certificates.map((cert, certIndex) => {
                  const analysis = cert.analysis || {}
                  const certType = getCertificateType(analysis)
                  
                  return (
                    <div key={cert.id || certIndex} className={styles.certificateTypeItem}>
                      <span className={styles.certificateTypeLabel}>
                        Type: {certType}
                      </span>
                      
                      <button
                        className={styles.deleteTypeButton}
                        onClick={() => handleDeleteFile(cert.id)}
                        title={`Delete ${certType}`}
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  )
                })}
              </div>
              
              {/* Divider between file groups */}
              {groupIndex < fileGroups.length - 1 && (
                <div className={styles.fileGroupDivider} />
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default FileManager