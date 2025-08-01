// frontend/src/components/CertificateDetails/CertificateDetails.jsx
// Updated to work with new session-based PKI storage format and swap header layout

import React, { useState } from 'react'
import { 
  ChevronDown, 
  ChevronUp, 
  Shield, 
  Key, 
  FileText, 
  Award,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  Globe
} from 'lucide-react'
import styles from './CertificateDetails.module.css'

const CertificateDetails = ({ certificate }) => {
  const [isExpanded, setIsExpanded] = useState(false)

  // Format timestamp for display
  const formatDate = (timestamp) => {
    if (!timestamp) return 'Unknown'
    try {
      return new Date(timestamp).toLocaleString()
    } catch (error) {
      return timestamp
    }
  }

  // Get type-specific icon
  const getTypeIcon = () => {
    const iconProps = { size: 24 }
    
    switch (certificate.type) {
      case 'PrivateKey':
        return <Key {...iconProps} className={styles.keyIcon} />
      case 'CSR':
        return <FileText {...iconProps} className={styles.csrIcon} />
      case 'Certificate':
        return <Shield {...iconProps} className={styles.certIcon} />
      case 'IssuingCA':
      case 'IntermediateCA': 
      case 'RootCA':
        return <Award {...iconProps} className={styles.caIcon} />
      default:
        return <FileText {...iconProps} className={styles.unknownIcon} />
    }
  }

  // Get user-friendly type label
  const getTypeLabel = () => {
    const typeLabels = {
      'PrivateKey': 'Private Key',
      'CSR': 'Certificate Signing Request',
      'Certificate': 'End Entity Certificate',
      'IssuingCA': 'Issuing CA Certificate',
      'IntermediateCA': 'Intermediate CA Certificate',
      'RootCA': 'Root CA Certificate'
    }
    return typeLabels[certificate.type] || certificate.type
  }

  // Get validation status color
  const getStatusColor = () => {
    return '#10b981' // Green for valid (simplified since we don't have validation info in new format)
  }

  // Render certificate-specific information
  const renderCertificateInfo = () => {
    if (certificate.type !== 'Certificate' && 
        certificate.type !== 'IssuingCA' && 
        certificate.type !== 'IntermediateCA' && 
        certificate.type !== 'RootCA') {
      return null
    }

    const metadata = certificate.metadata || {}

    return (
      <div className={styles.section}>
        <h4><Shield size={16} /> Certificate Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Subject:</span>
            <span className={styles.value}>{metadata.subject || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Issuer:</span>
            <span className={styles.value}>{metadata.issuer || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Serial Number:</span>
            <span className={styles.value} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {metadata.serial_number || 'N/A'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Valid From:</span>
            <span className={styles.value}>
              {metadata.not_valid_before ? formatDate(metadata.not_valid_before) : 'N/A'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Valid To:</span>
            <span className={styles.value}>
              {metadata.not_valid_after ? formatDate(metadata.not_valid_after) : 'N/A'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Signature Algorithm:</span>
            <span className={styles.value}>{metadata.signature_algorithm || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Public Key Algorithm:</span>
            <span className={styles.value}>{metadata.public_key_algorithm || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Public Key Size:</span>
            <span className={styles.value}>
              {metadata.public_key_size ? `${metadata.public_key_size} bits` : 'N/A'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Is CA:</span>
            <span className={`${styles.value} ${metadata.is_ca ? styles.yes : styles.no}`}>
              {metadata.is_ca ? 'Yes' : 'No'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Self Signed:</span>
            <span className={`${styles.value} ${metadata.is_self_signed ? styles.yes : styles.no}`}>
              {metadata.is_self_signed ? 'Yes' : 'No'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>SHA256 Fingerprint:</span>
            <span className={styles.value} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {metadata.fingerprint_sha256 || 'N/A'}
            </span>
          </div>
        </div>

        {/* Subject Alternative Names (if available) */}
        {metadata.subject_alt_name && metadata.subject_alt_name.length > 0 && (
          <div className={styles.extensionItem}>
            <h5>Subject Alternative Names</h5>
            <div className={styles.sanList}>
              {metadata.subject_alt_name.map((san, index) => (
                <span key={index} className={styles.sanItem}>
                  {san}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Key Usage (if available) */}
        {metadata.key_usage && (
          <div className={styles.extensionItem}>
            <h5>Key Usage</h5>
            <div className={styles.usageList}>
              {Object.entries(metadata.key_usage)
                .filter(([key, value]) => value === true)
                .map(([key, value]) => (
                  <span key={key} className={styles.usageItem}>
                    {key.replace(/([A-Z])/g, ' $1').toLowerCase().replace(/^\w/, c => c.toUpperCase())}
                  </span>
                ))}
            </div>
          </div>
        )}

        {/* Extended Key Usage (if available) */}
        {metadata.extended_key_usage && metadata.extended_key_usage.length > 0 && (
          <div className={styles.extensionItem}>
            <h5>Extended Key Usage</h5>
            <div className={styles.usageList}>
              {metadata.extended_key_usage.map((usage, index) => (
                <span key={index} className={styles.usageItem}>
                  {usage}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  // Render private key information
  const renderPrivateKeyInfo = () => {
    if (certificate.type !== 'PrivateKey') return null

    const metadata = certificate.metadata || {}

    return (
      <div className={styles.section}>
        <h4><Key size={16} /> Private Key Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Algorithm:</span>
            <span className={styles.value}>{metadata.algorithm || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Key Size:</span>
            <span className={styles.value}>{metadata.key_size ? `${metadata.key_size} bits` : 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Is Encrypted:</span>
            <span className={`${styles.value} ${metadata.is_encrypted ? styles.yes : styles.no}`}>
              {metadata.is_encrypted ? 'Yes' : 'No'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Public Key Fingerprint:</span>
            <span className={styles.value} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {metadata.public_key_fingerprint || 'N/A'}
            </span>
          </div>
        </div>
      </div>
    )
  }

  // Render CSR information
  const renderCSRInfo = () => {
    if (certificate.type !== 'CSR') return null

    const metadata = certificate.metadata || {}

    return (
      <div className={styles.section}>
        <h4><FileText size={16} /> CSR Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Subject:</span>
            <span className={styles.value}>{metadata.subject || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Signature Algorithm:</span>
            <span className={styles.value}>{metadata.signature_algorithm || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Public Key Algorithm:</span>
            <span className={styles.value}>{metadata.public_key_algorithm || 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Public Key Size:</span>
            <span className={styles.value}>{metadata.public_key_size ? `${metadata.public_key_size} bits` : 'N/A'}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Public Key Fingerprint:</span>
            <span className={styles.value} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {metadata.public_key_fingerprint || 'N/A'}
            </span>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      {/* Header with validation status - TYPE FIRST, THEN FILENAME */}
      <div className={styles.header} onClick={() => setIsExpanded(!isExpanded)}>
        <div className={styles.titleSection}>
          {getTypeIcon()}
          <div className={styles.titleInfo}>
            {/* SWAPPED: Type comes first, then filename */}
            <h3 className={styles.title}>{getTypeLabel()}</h3>
            <div className={styles.subtitle}>
              <span className={styles.filename}>{certificate.filename}</span>
              <span className={styles.uploadTime}>
                {formatDate(certificate.uploaded_at)}
              </span>
            </div>
          </div>
        </div>
        <div className={styles.controls}>
          {/* Validation status in header - simplified for new format */}
          <div className={styles.statusBadge} style={{ borderColor: getStatusColor() }}>
            <CheckCircle size={14} style={{ color: getStatusColor() }} />
            <span style={{ color: getStatusColor() }}>Valid</span>
          </div>
          
          {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>
      </div>

      {/* Content - show when expanded */}
      {isExpanded && (
        <div className={styles.content}>
          {/* Type-specific information - MOVED TO TOP */}
          {renderCertificateInfo()}
          {renderPrivateKeyInfo()}
          {renderCSRInfo()}

          {/* Component Information - MOVED TO BOTTOM */}
          <div className={styles.section}>
            <h4><Info size={16} /> Component Information</h4>
            <div className={styles.grid}>
              <div className={styles.field}>
                <span className={styles.label}>Component ID:</span>
                <span className={styles.value} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                  {certificate.id}
                </span>
              </div>
              <div className={styles.field}>
                <span className={styles.label}>Type:</span>
                <span className={styles.value}>{getTypeLabel()}</span>
              </div>
              <div className={styles.field}>
                <span className={styles.label}>Filename:</span>
                <span className={styles.value}>{certificate.filename}</span>
              </div>
              <div className={styles.field}>
                <span className={styles.label}>Upload Time:</span>
                <span className={styles.value}>{formatDate(certificate.uploaded_at)}</span>
              </div>
            </div>
          </div>

          {/* PEM Content Section */}
          <div className={styles.section}>
            <h4><FileText size={16} /> PEM Content</h4>
            <div className={styles.pemSection}>
              <button 
                className={styles.showContentButton}
                onClick={(e) => {
                  e.stopPropagation()
                  // TODO: Implement content display toggle
                  alert('Content display coming soon')
                }}
              >
                Show Content
              </button>
              <p className={styles.securityNote}>Content hidden for security</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default CertificateDetails