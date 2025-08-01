// frontend/src/components/CertificateDetails/CertificateDetails.jsx
// Updated to display missing metadata: days until expiry, expired status

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
  Globe,
  Clock,
  AlertCircle,
  Eye
} from 'lucide-react'
import styles from './CertificateDetails.module.css'

const CertificateDetails = ({ certificate }) => {
  const [isExpanded, setIsExpanded] = useState(true) // DEFAULT: Expanded
  const [showPemContent, setShowPemContent] = useState(false) // NEW: PEM content toggle

  // Format timestamp for display
  const formatDate = (timestamp) => {
    if (!timestamp) return 'Unknown'
    try {
      return new Date(timestamp).toLocaleString()
    } catch (error) {
      return timestamp
    }
  }

  // Format validity status with original validation icons (not eye)
  const formatValidityStatus = (metadata) => {
    if (!metadata.days_until_expiry && metadata.days_until_expiry !== 0) {
      return { text: 'Unknown', color: '#6b7280', icon: Info }
    }

    const days = metadata.days_until_expiry
    const isExpired = metadata.is_expired

    if (isExpired) {
      return { 
        text: 'Expired', 
        color: '#ef4444', 
        icon: XCircle 
      }
    }

    if (days <= 0) {
      return { 
        text: 'Expires today', 
        color: '#ef4444', 
        icon: AlertCircle 
      }
    }

    if (days <= 30) {
      return { 
        text: 'Expires soon', 
        color: '#f59e0b', 
        icon: AlertTriangle 
      }
    }

    if (days <= 90) {
      return { 
        text: 'Valid', 
        color: '#3b82f6', 
        icon: CheckCircle 
      }
    }

    return { 
      text: 'Valid', 
      color: '#10b981', 
      icon: CheckCircle 
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

  // Get validation status color - now uses validity status for certificates
  const getStatusColor = () => {
    if (certificate.type === 'Certificate' || 
        certificate.type === 'RootCA' || 
        certificate.type === 'IntermediateCA' || 
        certificate.type === 'IssuingCA') {
      const metadata = certificate.metadata || {}
      const validityStatus = formatValidityStatus(metadata)
      return validityStatus.color
    }
    return '#10b981' // Green for valid (simplified for non-certificates)
  }

  // Get status icon and text for header
  const getHeaderStatus = () => {
    if (certificate.type === 'Certificate' || 
        certificate.type === 'RootCA' || 
        certificate.type === 'IntermediateCA' || 
        certificate.type === 'IssuingCA') {
      const metadata = certificate.metadata || {}
      const validityStatus = formatValidityStatus(metadata)
      const StatusIcon = validityStatus.icon
      
      return {
        icon: <StatusIcon size={14} style={{ color: validityStatus.color }} />,
        text: validityStatus.text,
        color: validityStatus.color
      }
    }
    
    // Default for non-certificates
    return {
      icon: <CheckCircle size={14} style={{ color: '#10b981' }} />,
      text: 'Valid',
      color: '#10b981'
    }
  }

  // Render certificate-specific information
  const renderCertificateInfo = () => {
    if (certificate.type !== 'Certificate' && 
        certificate.type !== 'IssuingCA' && 
        certificate.type !== 'IntermediateCA' && 
        certificate.type !== 'RootCA') {
      return null
    }

    // Use direct metadata access (backend provides flattened metadata)
    const metadata = certificate.metadata || {}
    const validityStatus = formatValidityStatus(metadata)

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
          
          {/* FIXED: Validity Status - Remove eye icon from detailed section */}
          <div className={styles.field}>
            <span className={styles.label}>Validity Status:</span>
            <span className={styles.value} style={{ 
              color: validityStatus.color, 
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <validityStatus.icon size={16} />
              {validityStatus.text}
            </span>
          </div>

          {/* NEW: Days Until Expiry (separate field for clarity) */}
          {metadata.days_until_expiry !== undefined && (
            <div className={styles.field}>
              <span className={styles.label}>Days Until Expiry:</span>
              <span className={styles.value} style={{ 
                color: validityStatus.color, 
                fontWeight: '600' 
              }}>
                {metadata.is_expired ? 
                  `Expired ${Math.abs(metadata.days_until_expiry)} days ago` : 
                  `${metadata.days_until_expiry} days`
                }
              </span>
            </div>
          )}

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
          <div className={styles.field} style={{ gridColumn: '1 / -1' }}>
            <span className={styles.label}>SHA256 Fingerprint:</span>
            <span className={styles.value} style={{ 
              fontFamily: 'monospace', 
              fontSize: '0.8rem',
              wordBreak: 'keep-all',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              width: '100%',
              display: 'block',
              marginTop: '0.25rem'
            }}>
              {metadata.fingerprint_sha256 || 'N/A'}
            </span>
          </div>
        </div>

        {/* Subject Alternative Names - ONLY FOR END-ENTITY CERTIFICATES */}
        {certificate.type === 'Certificate' && metadata.subject_alt_name && metadata.subject_alt_name.length > 0 && (
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

        {/* DEBUG: Show SAN status for end-entity certificates only */}
        {certificate.type === 'Certificate' && (!metadata.subject_alt_name || metadata.subject_alt_name.length === 0) && (
          <div className={styles.extensionItem}>
            <h5>Subject Alternative Names</h5>
            <div className={styles.debugInfo}>
              <p style={{ color: '#ef4444', fontStyle: 'italic' }}>
                ⚠️ NO SAN DATA - End-entity certificates should have SANs
              </p>
              <details style={{ fontSize: '0.8rem', color: '#6b7280' }}>
                <summary>Certificate Debug Info</summary>
                <pre>{JSON.stringify({
                  certificate_type: certificate.type,
                  subject_cn: metadata.subject_common_name,
                  san_field: metadata.subject_alt_name,
                  is_ca: metadata.is_ca,
                  fingerprint: metadata.fingerprint_sha256?.substring(0, 16) + '...'
                }, null, 2)}</pre>
              </details>
            </div>
          </div>
        )}

        {/* CRITICAL BUG INDICATOR: CA certificates should NEVER have SANs */}
        {(certificate.type === 'RootCA' || certificate.type === 'IntermediateCA' || certificate.type === 'IssuingCA') && 
         metadata.subject_alt_name && metadata.subject_alt_name.length > 0 && (
          <div className={styles.extensionItem}>
            <h5>🚨 CRITICAL BUG: Subject Alternative Names Found on CA Certificate</h5>
            <div style={{ 
              color: '#dc2626', 
              fontWeight: 'bold', 
              padding: '1rem', 
              background: '#fef2f2', 
              border: '2px solid #fecaca', 
              borderRadius: '8px',
              marginBottom: '1rem'
            }}>
              <p>🚨 METADATA BUG DETECTED:</p>
              <p>CA certificates should NEVER have Subject Alternative Names.</p>
              <p>This indicates the backend is assigning the wrong certificate's metadata.</p>
              <details style={{ marginTop: '0.5rem' }}>
                <summary>Bug Details</summary>
                <pre>{JSON.stringify({
                  certificate_type: certificate.type,
                  subject_cn: metadata.subject_common_name,
                  incorrect_sans: metadata.subject_alt_name,
                  fingerprint: metadata.fingerprint_sha256
                }, null, 2)}</pre>
              </details>
            </div>
          </div>
        )}

        {/* Key Usage (if available) - FIXED: Only show TRUE values */}
        {metadata.key_usage && Object.keys(metadata.key_usage).length > 0 && (
          <div className={styles.extensionItem}>
            <h5>Key Usage</h5>
            <div className={styles.usageList}>
              {Object.entries(metadata.key_usage)
                .filter(([key, value]) => value === true)
                .map(([key, value]) => (
                  <span key={key} className={styles.usageItem}>
                    {key.replace(/([A-Z])/g, ' $1').toLowerCase().replace(/^\w/, c => c.toUpperCase()).replace(/_/g, ' ')}
                  </span>
                ))}
            </div>
            
            {/* DEBUG: Show all key usage for debugging */}
            <details style={{ fontSize: '0.8rem', color: '#6b7280', marginTop: '0.5rem' }}>
              <summary>Debug: All Key Usage Values</summary>
              <pre>{JSON.stringify(metadata.key_usage, null, 2)}</pre>
            </details>
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
          <div className={styles.field} style={{ gridColumn: '1 / -1' }}>
            <span className={styles.label}>Public Key Fingerprint:</span>
            <span className={styles.value} style={{ 
              fontFamily: 'monospace', 
              fontSize: '0.8rem',
              wordBreak: 'keep-all',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              width: '100%',
              display: 'block',
              marginTop: '0.25rem'
            }}>
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
            <span className={styles.value}>{metadata.public_key_size ? 
              `${metadata.public_key_size} bits` : 'N/A'}</span>
          </div>
          <div className={styles.field} style={{ gridColumn: '1 / -1' }}>
            <span className={styles.label}>Public Key Fingerprint:</span>
            <span className={styles.value} style={{ 
              fontFamily: 'monospace', 
              fontSize: '0.8rem',
              wordBreak: 'keep-all',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              width: '100%',
              display: 'block',
              marginTop: '0.25rem'
            }}>
              {metadata.public_key_fingerprint || 'N/A'}
            </span>
          </div>
        </div>
          
        {/* CSR Extensions */}
        {/* Subject Alternative Names - FOR CSRs */}
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
  
        {/* Key Usage for CSRs (if available) */}
        {metadata.key_usage && Object.keys(metadata.key_usage).length > 0 && (
          <div className={styles.extensionItem}>
            <h5>Key Usage</h5>
            <div className={styles.usageList}>
              {Object.entries(metadata.key_usage)
                .filter(([key, value]) => value === true)
                .map(([key, value]) => (
                  <span key={key} className={styles.usageItem}>
                    {key.replace(/([A-Z])/g, ' $1').toLowerCase().replace(/^\w/, c => c.toUpperCase()).replace(/_/g, ' ')}
                  </span>
                ))}
            </div>
          </div>
        )}
  
        {/* Extended Key Usage for CSRs (if available) */}
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
  
        {/* Basic Constraints for CSRs (if available) */}
        {metadata.basic_constraints && Object.keys(metadata.basic_constraints).length > 0 && (
          <div className={styles.extensionItem}>
            <h5>Basic Constraints</h5>
            <div className={styles.constraintsList}>
              {metadata.basic_constraints.is_ca !== undefined && (
                <span className={styles.constraintItem}>
                  CA: {metadata.basic_constraints.is_ca ? 'Yes' : 'No'}
                </span>
              )}
              {metadata.basic_constraints.path_length !== undefined && metadata.basic_constraints.path_length !== null && (
                <span className={styles.constraintItem}>
                  Path Length: {metadata.basic_constraints.path_length}
                </span>
              )}
            </div>
          </div>
        )}
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
          {/* Validation status in header - with eye icon for more details */}
          <div className={styles.statusBadge} style={{ borderColor: getStatusColor() }}>
            {(() => {
              const status = getHeaderStatus()
              return (
                <>
                  {status.icon}
                  <span style={{ color: status.color }}>{status.text}</span>
                  <Eye size={12} style={{ color: '#6b7280', marginLeft: '0.25rem' }} title="More details available" />
                </>
              )
            })()}
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
                  setShowPemContent(!showPemContent)
                }}
              >
                {showPemContent ? 'Hide Content' : 'Show Content'}
              </button>
              
              {showPemContent ? (
                <div className={styles.pemContent}>
                  <pre className={styles.pemText}>
                    {certificate.content || 'No PEM content available'}
                  </pre>
                </div>
              ) : (
                <p className={styles.securityNote}>Content hidden for security</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default CertificateDetails