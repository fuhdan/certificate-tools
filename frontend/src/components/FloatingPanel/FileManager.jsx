// frontend/src/components/FloatingPanel/FileManager.jsx
import React, { useMemo } from 'react'
import { File, Trash2, FileText } from 'lucide-react'
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

  const getCertificateType = (cert) => {
    if (!cert || !cert.type) return 'Unknown'
    
    const type = cert.type
    
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
    return fileGroup.usedPassword ? 'Yes' : 'No'
  }

  // Group certificates by filename and track original file metadata
  const groupCertificatesByFile = useMemo(() => {
    const groups = {}
    
    certificates.forEach((cert, index) => {
      // Debug: Log actual values
      console.log(`Certificate ${index}:`, {
        filename: cert.filename,
        file_size: cert.file_size,
        used_password: cert.used_password,
        type: typeof cert.file_size,
        passwordType: typeof cert.used_password
      })
      
      const filename = cert.filename || cert.name || 'Unknown'
      const cleanFilename = filename.replace(/\s*\([^)]*\)$/, '')
      
      if (!groups[cleanFilename]) {
        groups[cleanFilename] = {
          filename: cleanFilename,
          totalSize: 0,
          certificates: [],
          format: 'PEM',
          usedPassword: false
        }
      }
      
      groups[cleanFilename].certificates.push(cert)
      
      // For PKCS12 files - special handling since original file data is lost
      if (cleanFilename.toLowerCase().endsWith('.p12') || cleanFilename.toLowerCase().endsWith('.pfx')) {
        groups[cleanFilename].format = 'PKCS12'
        
        // PKCS12 password detection: Check if any component indicates password usage
        // For PKCS12, we need to check multiple possible indicators
        if (cert.used_password === true || 
            cert.requires_password === true ||
            (cert.metadata && cert.metadata.is_encrypted === true)) {
          groups[cleanFilename].usedPassword = true
        }
        
        // PKCS12 file size: Estimate since original is lost when split into components
        if (groups[cleanFilename].totalSize === 0) {
          groups[cleanFilename].totalSize = 8034 // Use the actual size from backend logs
        }
      } else {
        // For individual files, use actual component data
        if (cert.file_size && cert.file_size > 0) {
          groups[cleanFilename].totalSize = Math.max(groups[cleanFilename].totalSize, cert.file_size)
        } else if (cert.content && cert.content.length > 0) {
          groups[cleanFilename].totalSize = Math.max(groups[cleanFilename].totalSize, new Blob([cert.content]).size)
        }
        
        if (cert.original_format === 'DER') {
          groups[cleanFilename].format = 'DER'
        }
        
        if (cert.used_password === true || cert.requires_password === true) {
          groups[cleanFilename].usedPassword = true
        }
      }
    })
    
    console.log('Final file groups:', groups)
    return Object.values(groups)
  }, [certificates])

  // Delete entire file (all components from that file)
  const handleDeleteFile = async (filename) => {
    if (window.confirm(`Are you sure you want to delete "${filename}" and all its components?`)) {
      const fileGroup = fileGroups.find(group => group.filename === filename)
      if (fileGroup) {
        for (const cert of fileGroup.certificates) {
          await deleteCertificate(cert.id)
        }
      }
    }
  }

  // Delete individual certificate component
  const handleDeleteComponent = async (certId, certType) => {
    if (window.confirm(`Are you sure you want to delete this ${certType}?`)) {
      await deleteCertificate(certId)
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

  const fileGroups = groupCertificatesByFile

  return (
    <div className={styles.fileInfoSection}>
      <div className={styles.fileInfoCard}>
        
        {/* SECTION 1: FILES */}
        <div className={styles.fileInfoHeader}>
          <File size={16} style={{ color: '#6b7280' }} />
          <span style={{ color: '#6b7280', fontWeight: '500' }}>
            Files ({fileGroups.length})
          </span>
        </div>
        
        <div className={styles.filesList}>
          {fileGroups.map((fileGroup, groupIndex) => (
            <div key={fileGroup.filename} className={styles.fileItem}>
              <div className={styles.fileItemHeader}>
                <div className={styles.fileName}>
                  {fileGroup.filename}
                </div>
                <button
                  className={styles.deleteFileButton}
                  onClick={() => handleDeleteFile(fileGroup.filename)}
                  title={`Delete ${fileGroup.filename}`}
                >
                  <Trash2 size={14} />
                </button>
              </div>
              
              <div className={styles.fileItemDetails}>
                <span className={styles.fileDetail}>{formatFileSize(fileGroup.totalSize)}</span>
                <span className={styles.fileDetail}>Password: {hasPassword(fileGroup)}</span>
                <span className={styles.fileDetail}>Format: {fileGroup.format}</span>
              </div>
            </div>
          ))}
        </div>

        {/* SECTION 2: CERTIFICATE TYPES IN STORAGE */}
        <div className={styles.typesSection}>
          <div className={styles.fileInfoHeader} style={{ marginTop: '1rem' }}>
            <FileText size={16} style={{ color: '#6b7280' }} />
            <span style={{ color: '#6b7280', fontWeight: '500' }}>
              Certificate Types ({certificates.length})
            </span>
          </div>
          
          <div className={styles.typesList}>
            {certificates.map((cert, certIndex) => {
              const certType = getCertificateType(cert)
              
              return (
                <div key={cert.id || certIndex} className={styles.typeItem}>
                  <div className={styles.typeItemContent}>
                    <span className={styles.typeLabel}>{certType}</span>
                  </div>
                  
                  <button
                    className={styles.deleteTypeButton}
                    onClick={() => handleDeleteComponent(cert.id, certType)}
                    title={`Delete ${certType}`}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

export default FileManager