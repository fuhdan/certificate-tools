// frontend/src/components/CertificateDetails/CertificateDetails.jsx
// Updated for unified storage backend

import React, { useState } from 'react'
import { 
  Award, Key, FileText, User, Building, Calendar, 
  Shield, Hash, Eye, EyeOff, ChevronDown, ChevronUp,
  CheckCircle, XCircle, AlertTriangle, Info
} from 'lucide-react'
import styles from './CertificateDetails.module.css'

const CertificateDetails = ({ certificate }) => {
  const [isExpanded, setIsExpanded] = useState(false)
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
    return certificate.is_valid ? '#22c55e' : '#ef4444'
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'Not specified'
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
        {/* Subject Information */}
        <div className={styles.section}>
          <h4><User size={16} /> Subject Information</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Distinguished Name:</span>
              <span className={styles.value}>{info.subject}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Serial Number:</span>
              <span className={styles.value}>{info.serial_number}</span>
            </div>
          </div>
        </div>

        {/* Issuer Information */}
        <div className={styles.section}>
          <h4><Building size={16} /> Issuer Information</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Distinguished Name:</span>
              <span className={styles.value}>{info.issuer}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Self-Signed:</span>
              <span className={`${styles.value} ${info.is_self_signed ? styles.yes : styles.no}`}>
                {info.is_self_signed ? 'Yes' : 'No'}
              </span>
            </div>
          </div>
        </div>

        {/* Validity Period */}
        <div className={styles.section}>
          <h4><Calendar size={16} /> Validity Period</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Valid From:</span>
              <span className={styles.value}>{formatDate(info.not_valid_before)}</span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>Valid Until:</span>
              <span className={styles.value}>{formatDate(info.not_valid_after)}</span>
            </div>
          </div>
        </div>

        {/* Public Key Information */}
        <div className={styles.section}>
          <h4><Key size={16} /> Public Key</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Algorithm:</span>
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
              <span className={styles.label}>SHA-1:</span>
              <span className={styles.value} style={{ fontFamily: 'monospace' }}>
                {info.fingerprint_sha1}
              </span>
            </div>
            <div className={styles.field}>
              <span className={styles.label}>SHA-256:</span>
              <span className={styles.value} style={{ fontFamily: 'monospace' }}>
                {info.fingerprint_sha256}
              </span>
            </div>
          </div>
        </div>

        {/* Extensions */}
        {info.extensions && Object.keys(info.extensions).length > 0 && (
          <div className={styles.section}>
            <h4><Shield size={16} /> Extensions</h4>
            
            {/* Basic Constraints */}
            {info.extensions.basic_constraints && (
              <div className={styles.extensionItem}>
                <h5>Basic Constraints</h5>
                <div className={styles.grid}>
                  <div className={styles.field}>
                    <span className={styles.label}>Certificate Authority:</span>
                    <span className={`${styles.value} ${info.extensions.basic_constraints.ca ? styles.yes : styles.no}`}>
                      {info.extensions.basic_constraints.ca ? 'Yes' : 'No'}
                    </span>
                  </div>
                  {info.extensions.basic_constraints.path_length !== null && (
                    <div className={styles.field}>
                      <span className={styles.label}>Path Length:</span>
                      <span className={styles.value}>{info.extensions.basic_constraints.path_length}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Key Usage */}
            {info.extensions.key_usage && (
              <div className={styles.extensionItem}>
                <h5>Key Usage</h5>
                <div className={styles.usageList}>
                  {Object.entries(info.extensions.key_usage).map(([usage, enabled]) => 
                    enabled && (
                      <span key={usage} className={styles.usageItem}>
                        {usage.replace(/_/g, ' ')}
                      </span>
                    )
                  )}
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
            <span className={styles.value} style={{ fontFamily: 'monospace' }}>
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
          <h4><User size={16} /> CSR Subject Information</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Distinguished Name:</span>
              <span className={styles.value}>{info.subject}</span>
            </div>
          </div>
        </div>

        <div className={styles.section}>
          <h4><Key size={16} /> Public Key Information</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.label}>Algorithm:</span>
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

  const renderAdditionalCertificates = () => {
    if (!certificate.additional_certificates_info || certificate.additional_certificates_info.length === 0) {
      return null
    }

    return (
      <div className={styles.section}>
        <h4><Building size={16} /> Additional Certificates ({certificate.additional_certs_count})</h4>
        <div className={styles.additionalCerts}>
          {certificate.additional_certificates_info.map((certInfo, index) => (
            <div key={index} className={styles.additionalCert}>
              <div className={styles.certHeader}>
                <span className={styles.certIndex}>#{index + 1}</span>
                <span className={`${styles.certType} ${certInfo.is_ca ? styles.ca : styles.endEntity}`}>
                  {certInfo.is_ca ? (certInfo.is_self_signed ? 'Root CA' : 'Intermediate CA') : 'End Entity'}
                </span>
              </div>
              <div className={styles.certInfo}>
                <div className={styles.field}>
                  <span className={styles.label}>Subject:</span>
                  <span className={styles.value}>{certInfo.subject}</span>
                </div>
                <div className={styles.field}>
                  <span className={styles.label}>Issuer:</span>
                  <span className={styles.value}>{certInfo.issuer}</span>
                </div>
                <div className={styles.field}>
                  <span className={styles.label}>Fingerprint:</span>
                  <span className={styles.value} style={{ fontFamily: 'monospace' }}>
                    {certInfo.fingerprint_sha256}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      {/* Header */}
      <div className={styles.header} onClick={() => setIsExpanded(!isExpanded)}>
        <div className={styles.titleSection}>
          {getTypeIcon()}
          <div className={styles.titleInfo}>
            <h3 className={styles.title}>{certificate.filename}</h3>
            <div className={styles.subtitle}>
              <span className={styles.type}>{getTypeLabel()}</span>
              <span className={styles.format}>({certificate.original_format})</span>
            </div>
          </div>
        </div>
        <div className={styles.controls}>
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
          {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>
      </div>

      {/* Content */}
      {isExpanded && (
        <div className={styles.content}>
          {/* File Information */}
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

          {/* Content Summary */}
          <div className={styles.section}>
            <h4><Shield size={16} /> Content Summary</h4>
            <div className={styles.contentFlags}>
              <div className={`${styles.contentFlag} ${certificate.has_certificate ? styles.present : styles.absent}`}>
                <Award size={14} />
                <span>Certificate {certificate.has_certificate ? '✓' : '✗'}</span>
              </div>
              <div className={`${styles.contentFlag} ${certificate.has_private_key ? styles.present : styles.absent}`}>
                <Key size={14} />
                <span>Private Key {certificate.has_private_key ? '✓' : '✗'}</span>
              </div>
              <div className={`${styles.contentFlag} ${certificate.has_csr ? styles.present : styles.absent}`}>
                <FileText size={14} />
                <span>CSR {certificate.has_csr ? '✓' : '✗'}</span>
              </div>
              {certificate.additional_certs_count > 0 && (
                <div className={`${styles.contentFlag} ${styles.present}`}>
                  <Building size={14} />
                  <span>+{certificate.additional_certs_count} Additional</span>
                </div>
              )}
            </div>
          </div>

          {/* Validation Errors */}
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

          {/* Additional Certificates */}
          {renderAdditionalCertificates()}
        </div>
      )}
    </div>
  )
}

export default CertificateDetails