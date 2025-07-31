// frontend/src/components/CertificateDetails/CertificateDetails.jsx
// Updated: Validation in header, no separate validation section, always expanded

import React, { useState } from 'react'
import { 
  Award, Key, FileText, User, Building, Calendar, 
  Shield, Hash, Eye, EyeOff, ChevronDown, ChevronUp,
  CheckCircle, XCircle, AlertTriangle, Info
} from 'lucide-react'
import styles from './CertificateDetails.module.css'

const CertificateDetails = ({ certificate }) => {
  const [isExpanded, setIsExpanded] = useState(true) // Default to expanded
  const [showSensitiveData, setShowSensitiveData] = useState(false)

  if (!certificate) {
    return null
  }

  const getTypeIcon = () => {
    if (certificate.has_certificate) {
      return certificate.certificate_info?.is_ca ? 
        <Building size={20} className={styles.caIcon} /> : 
        <Award size={20} className={styles.certIcon} />
    } else if (certificate.has_private_key) {
      return <Key size={20} className={styles.keyIcon} />
    } else if (certificate.has_csr) {
      return <FileText size={20} className={styles.csrIcon} />
    }
    return <Shield size={20} className={styles.unknownIcon} />
  }

  const getTypeLabel = () => {
    if (certificate.has_certificate) {
      if (certificate.certificate_info?.is_ca) {
        return certificate.certificate_info.is_self_signed ? 'Root CA' : 'Intermediate CA'
      }
      return 'End Entity Certificate'
    } else if (certificate.has_private_key && !certificate.has_certificate) {
      return 'Private Key'
    } else if (certificate.has_csr) {
      return 'Certificate Request (CSR)'
    }
    return 'Unknown Type'
  }

  const getStatusColor = () => {
    return certificate.is_valid ? '#10b981' : '#ef4444'
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A'
    try {
      return new Date(dateString).toLocaleString()
    } catch {
      return dateString
    }
  }

  const renderCertificateInfo = () => {
    if (!certificate.certificate_info) return null

    const info = certificate.certificate_info

    return (
      <>
        <div className={styles.section}>
          <h4><Award size={16} /> Certificate Information</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Subject:</span>
              <span className={styles.value}>{info.subject}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Issuer:</span>
              <span className={styles.value}>{info.issuer}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Serial Number:</span>
              <span className={styles.value} style={{ fontFamily: 'monospace' }}>
                {info.serial_number}
              </span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Valid From:</span>
              <span className={styles.value}>{formatDate(info.not_before)}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Valid Until:</span>
              <span className={styles.value}>{formatDate(info.not_after)}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Certificate Authority:</span>
              <span className={`${styles.value} ${info.is_ca ? styles.yes : styles.no}`}>
                {info.is_ca ? 'Yes' : 'No'}
              </span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Self-Signed:</span>
              <span className={`${styles.value} ${info.is_self_signed ? styles.yes : styles.no}`}>
                {info.is_self_signed ? 'Yes' : 'No'}
              </span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Version:</span>
              <span className={styles.value}>v{info.version}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Public Key Algorithm:</span>
              <span className={styles.value}>{info.public_key_algorithm}</span>
            </div>
            {info.public_key_size && (
              <div className={styles.field}>
                <span className={styles.label}>Key Size:</span>
                <span className={styles.value}>{info.public_key_size} bits</span>
              </div>
            )}
            <div className={styles.field}>
              <span className={styles.label}>Signature Algorithm:</span>
              <span className={styles.value}>{info.signature_algorithm}</span>
            </div>
          </div>
        </div>

        {/* Fingerprints */}
        <div className={styles.section}>
          <h4><Hash size={16} /> Fingerprints</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>SHA-256:</span>
              <span className={styles.value} style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {info.fingerprint_sha256}
              </span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>SHA-1:</span>
              <span className={styles.value} style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {info.fingerprint_sha1}
              </span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Public Key:</span>
              <span className={styles.value} style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {info.public_key_fingerprint}
              </span>
            </div>
          </div>
        </div>

        {/* Extensions */}
        {info.extensions && Object.keys(info.extensions).length > 0 && (
          <div className={styles.section}>
            <h4><Shield size={16} /> Extensions</h4>
            
            {/* Subject Alternative Names */}
            {info.extensions.subject_alt_name && info.extensions.subject_alt_name.length > 0 && (
              <div className={styles.extensionItem}>
                <h5>Subject Alternative Names</h5>
                <div className={styles.sanList}>
                  {info.extensions.subject_alt_name.map((san, index) => (
                    <span key={index} className={styles.sanItem}>
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Key Usage */}
            {info.extensions.key_usage && info.extensions.key_usage.length > 0 && (
              <div className={styles.extensionItem}>
                <h5>Key Usage</h5>
                <div className={styles.usageList}>
                  {info.extensions.key_usage.map((usage, index) => (
                    <span key={index} className={styles.usageItem}>
                      {usage}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Extended Key Usage */}
            {info.extensions.extended_key_usage && info.extensions.extended_key_usage.length > 0 && (
              <div className={styles.extensionItem}>
                <h5>Extended Key Usage</h5>
                <div className={styles.usageList}>
                  {info.extensions.extended_key_usage.map((usage, index) => (
                    <span key={index} className={styles.usageItem}>
                      {usage}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </>
    )
  }

  const renderPrivateKeyInfo = () => {
    if (!certificate.private_key_info) return null

    const info = certificate.private_key_info

    return (
      <div className={styles.section}>
        <h4><Key size={16} /> Private Key Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Algorithm:</span>
            <span className={styles.value}>{info.algorithm}</span>
          </div>
          {info.key_size && (
            <div className={styles.field}>
              <span className={styles.label}>Key Size:</span>
              <span className={styles.value}>{info.key_size} bits</span>
            </div>
          )}
          <div className={styles.field}>
            <span className={styles.label}>Encrypted:</span>
            <span className={`${styles.value} ${info.is_encrypted ? styles.yes : styles.no}`}>
              {info.is_encrypted ? 'Yes' : 'No'}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Public Key Fingerprint:</span>
            <span className={styles.value} style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
              {info.public_key_fingerprint}
            </span>
          </div>
        </div>
      </div>
    )
  }

  const renderCSRInfo = () => {
    if (!certificate.csr_info) return null

    const info = certificate.csr_info

    return (
      <>
        <div className={styles.section}>
          <h4><FileText size={16} /> Certificate Request Information</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Subject:</span>
              <span className={styles.value}>{info.subject}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Version:</span>
              <span className={styles.value}>v{info.version}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Public Key Algorithm:</span>
              <span className={styles.value}>{info.public_key_algorithm}</span>
            </div>
            {info.public_key_size && (
              <div className={styles.field}>
                <span className={styles.label}>Key Size:</span>
                <span className={styles.value}>{info.public_key_size} bits</span>
              </div>
            )}
            <div className={styles.field}>
              <span className={styles.label}>Signature Algorithm:</span>
              <span className={styles.value}>{info.signature_algorithm}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Public Key Fingerprint:</span>
              <span className={styles.value} style={{ fontFamily: 'monospace' }}>
                {info.public_key_fingerprint}
              </span>
            </div>
          </div>
        </div>

        {/* CSR Extensions */}
        {info.extensions && Object.keys(info.extensions).length > 0 && (
          <div className={styles.section}>
            <h4><Shield size={16} /> Requested Extensions</h4>
            
            {/* Subject Alternative Names */}
            {info.extensions.subject_alt_name && info.extensions.subject_alt_name.length > 0 && (
              <div className={styles.extensionItem}>
                <h5>Requested Subject Alternative Names</h5>
                <div className={styles.sanList}>
                  {info.extensions.subject_alt_name.map((san, index) => (
                    <span key={index} className={styles.sanItem}>
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </>
    )
  }

  return (
    <div className={styles.container}>
      {/* Header with validation status */}
      <div className={styles.header} onClick={() => setIsExpanded(!isExpanded)}>
        <div className={styles.titleSection}>
          {getTypeIcon()}
          <div className={styles.titleInfo}>
            <h3 className={styles.title}>{certificate.filename}</h3>
            <div className={styles.subtitle}>
              <span className={styles.type}>{getTypeLabel()}</span>
              <span className={styles.format}>({certificate.original_format})</span>
              {/* Bundle source indicator */}
              {certificate.is_bundle_component && (
                <span className={styles.bundleSource}>from {certificate.bundle_source}</span>
              )}
            </div>
          </div>
        </div>
        <div className={styles.controls}>
          {/* Validation status in header */}
          <div className={styles.statusBadge} style={{ borderColor: getStatusColor() }}>
            {certificate.is_valid ? (
              <CheckCircle size={14} style={{ color: getStatusColor() }} />
            ) : (
              <XCircle size={14} style={{ color: getStatusColor() }} />
            )}
            <span style={{ color: getStatusColor() }}>
              {certificate.is_valid ? 'Valid' : 'Invalid'}
            </span>
          </div>
          
          {/* Show validation errors count in header if any */}
          {certificate.validation_errors && certificate.validation_errors.length > 0 && (
            <div className={styles.errorCount}>
              <AlertTriangle size={14} style={{ color: '#ef4444' }} />
              <span style={{ color: '#ef4444', fontSize: '0.75rem' }}>
                {certificate.validation_errors.length} error{certificate.validation_errors.length > 1 ? 's' : ''}
              </span>
            </div>
          )}
          
          {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>
      </div>

      {/* Content - always show if expanded */}
      {isExpanded && (
        <div className={styles.content}>
          {/* File Information - Always expanded */}
          <div className={styles.section}>
            <h4><Info size={16} /> File Information</h4>
            <div className={styles.grid}>
              <div className={styles.field}>
                <span className={styles.label}>Filename:</span>
                <span className={styles.value}>{certificate.filename}</span>
              </div>
              <div className={styles.field}>
                <span className={styles.label}>Original Format:</span>
                <span className={styles.value}>{certificate.original_format}</span>
              </div>
              <div className={styles.field}>
                <span className={styles.label}>File Size:</span>
                <span className={styles.value}>{certificate.file_size} bytes</span>
              </div>
              <div className={styles.field}>
                <span className={styles.label}>Uploaded:</span>
                <span className={styles.value}>{formatDate(certificate.uploaded_at)}</span>
              </div>
              <div className={styles.field}>
                <span className={styles.label}>Used Password:</span>
                <span className={`${styles.value} ${certificate.used_password ? styles.yes : styles.no}`}>
                  {certificate.used_password ? 'Yes' : 'No'}
                </span>
              </div>
            </div>
          </div>

          {/* Content Summary - Always expanded */}
          <div className={styles.section}>
            <h4><Shield size={16} /> Content Summary</h4>
            <div className={styles.contentSummary}>
              <p>This section will show user-friendly validation information in a future update.</p>
            </div>
          </div>

          {/* Show validation errors if any - in content area */}
          {certificate.validation_errors && certificate.validation_errors.length > 0 && (
            <div className={styles.section}>
              <h4><AlertTriangle size={16} /> Validation Errors</h4>
              <div className={styles.errorList}>
                {certificate.validation_errors.map((error, index) => (
                  <div key={index} className={styles.errorItem}>
                    <AlertTriangle size={14} />
                    <span>{error}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Certificate Information */}
          {renderCertificateInfo()}

          {/* Private Key Information */}
          {renderPrivateKeyInfo()}

          {/* CSR Information */}
          {renderCSRInfo()}
        </div>
      )}
    </div>
  )
}

export default CertificateDetails