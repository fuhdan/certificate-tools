import React from 'react'
import { Shield, Key, FileText, Clock, User, Building } from 'lucide-react'
import styles from './CertificateDetails.module.css'

const CertificateDetails = ({ certificate }) => {
  // Safety checks
  if (!certificate) {
    return null
  }
  
  if (!certificate.analysis) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <h3>{certificate.filename || certificate.name}</h3>
          <p>Analysis data not available</p>
        </div>
      </div>
    )
  }
  
  if (!certificate.analysis.details) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <h3>{certificate.filename || certificate.name}</h3>
          <p>Detailed analysis not available. File type: {certificate.analysis.type}</p>
        </div>
      </div>
    )
  }

  const { analysis } = certificate
  const { details } = analysis

  const formatDate = (dateString) => {
    if (!dateString || dateString === 'N/A') return 'N/A'
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getTypeIcon = (type) => {
    switch (type) {
      case 'Certificate':
      case 'CA Certificate':
        return <Shield size={20} />
      case 'CSR':
        return <FileText size={20} />
      case 'Private Key':
        return <Key size={20} />
      default:
        return <FileText size={20} />
    }
  }

  const getEnhancedCertificateType = () => {
    const type = analysis.type || ''
    
    if (type === 'CSR') return { label: 'Certificate Signing Request', color: '#3b82f6' }
    if (type === 'Private Key') return { label: 'Private Key', color: '#dc2626' }
    if (type === 'Public Key') return { label: 'Public Key', color: '#059669' }
    if (type === 'Certificate Chain') return { label: 'Certificate Chain', color: '#2563eb' }
    
    // For certificates, determine specific type
    if (type === 'Certificate' || type === 'CA Certificate' || type === 'PKCS12 Certificate') {
      const isCA = details.extensions?.basicConstraints?.isCA || false
      const issuer = details.issuer?.commonName || ''
      const subject = details.subject?.commonName || ''
      
      if (!isCA) {
        return { label: 'End-Entity Certificate', color: '#1e40af' }
      } else {
        if (issuer === subject) {
          return { label: 'Root Certificate Authority', color: '#7c2d12' }
        } else {
          const subjectLower = subject.toLowerCase()
          if (subjectLower.includes('issuing') || subjectLower.includes('leaf')) {
            return { label: 'Issuing Certificate Authority', color: '#1d4ed8' }
          } else {
            return { label: 'Intermediate Certificate Authority', color: '#1e40af' }
          }
        }
      }
    }
    
    return { label: type, color: '#6b7280' }
  }

  const getTypeColor = (type) => {
    switch (type) {
      case 'Certificate':
        return '#1e40af'
      case 'CA Certificate':
        return '#1d4ed8'
      case 'CSR':
        return '#3b82f6'
      case 'Private Key':
        return '#dc2626'
      default:
        return '#6b7280'
    }
  }

  const renderCertificateDetails = () => (
    <>
      <div className={styles.section}>
        <h4><User size={16} /> Subject Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Common Name:</span>
            <span className={styles.value}>{details.subject.commonName}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Organization:</span>
            <span className={styles.value}>{details.subject.organization}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Organizational Unit:</span>
            <span className={styles.value}>{details.subject.organizationalUnit}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Country:</span>
            <span className={styles.value}>{details.subject.country}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>State:</span>
            <span className={styles.value}>{details.subject.state}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Locality:</span>
            <span className={styles.value}>{details.subject.locality}</span>
          </div>
        </div>
      </div>

      <div className={styles.section}>
        <h4><Building size={16} /> Issuer Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Common Name:</span>
            <span className={styles.value}>{details.issuer.commonName}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Organization:</span>
            <span className={styles.value}>{details.issuer.organization}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Country:</span>
            <span className={styles.value}>{details.issuer.country}</span>
          </div>
        </div>
      </div>

      <div className={styles.section}>
        <h4><Clock size={16} /> Validity Period</h4>
        <div className={styles.grid}>
          <div className={`${styles.field} ${!details.validity.isExpired ? styles.validDate : styles.expiredDate}`}>
            <span className={styles.label}>Valid From:</span>
            <span className={styles.value}>{formatDate(details.validity.notBefore)}</span>
          </div>
          <div className={`${styles.field} ${!details.validity.isExpired ? styles.validDate : styles.expiredDate}`}>
            <span className={styles.label}>Valid Until:</span>
            <span className={styles.value}>{formatDate(details.validity.notAfter)}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Days Until Expiry:</span>
            <span className={styles.value}>{details.validity.daysUntilExpiry}</span>
          </div>
        </div>
      </div>

      <div className={styles.section}>
        <h4><Key size={16} /> Public Key Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Algorithm:</span>
            <span className={styles.value}>{details.publicKey.algorithm}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Key Size:</span>
            <span className={styles.value}>{details.publicKey.keySize} bits</span>
          </div>
          {details.publicKey.exponent !== 'N/A' && (
            <div className={styles.field}>
              <span className={styles.label}>Exponent:</span>
              <span className={styles.value}>{details.publicKey.exponent}</span>
            </div>
          )}
        </div>
      </div>

      {details.extensions.subjectAltName && details.extensions.subjectAltName.length > 0 && (
        <div className={styles.section}>
          <h4>Subject Alternative Names</h4>
          <div className={styles.sanList}>
            {details.extensions.subjectAltName.map((san, index) => (
              <span key={index} className={styles.sanItem}>
                {san.typeName || `Type ${san.type}`}: {san.value}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Extended Key Usage section added here */}
      {details.extensions.extendedKeyUsage && details.extensions.extendedKeyUsage.length > 0 && (
        <div className={styles.section}>
          <h4>Extended Key Usage</h4>
          <div className={styles.grid}>
            {details.extensions.extendedKeyUsage.map((usage, index) => (
              <div key={index} className={styles.field}>
                <span className={styles.value}>{usage}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Key Usage section added here */}
      {details.extensions.keyUsage && (
        <div className={styles.section}>
          <h4>Key Usage</h4>
          <div className={styles.grid}>
            {Object.entries(details.extensions.keyUsage).map(([key, value]) => {
              if (typeof value === 'boolean' && value === true) {
                return (
                  <div key={key} className={styles.field}>
                    <span className={styles.value}>{key}</span>
                  </div>
                )
              }
              return null
            })}
          </div>
        </div>
      )}
    </>
  )

  const renderCSRDetails = () => (
    <>
      <div className={styles.section}>
        <h4><User size={16} /> Subject Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Common Name:</span>
            <span className={styles.value}>{details.subject.commonName}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Organization:</span>
            <span className={styles.value}>{details.subject.organization}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Organizational Unit:</span>
            <span className={styles.value}>{details.subject.organizationalUnit}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Country:</span>
            <span className={styles.value}>{details.subject.country}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>State/Province:</span>
            <span className={styles.value}>{details.subject.state}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Locality:</span>
            <span className={styles.value}>{details.subject.locality}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Email:</span>
            <span className={styles.value}>{details.subject.emailAddress}</span>
          </div>
        </div>
      </div>

      <div className={styles.section}>
        <h4><Key size={16} /> Public Key Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Algorithm:</span>
            <span className={styles.value}>{details.publicKey.algorithm}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Key Size:</span>
            <span className={styles.value}>{details.publicKey.keySize} bits</span>
          </div>
          {details.publicKey.exponent !== 'N/A' && (
            <div className={styles.field}>
              <span className={styles.label}>Exponent:</span>
              <span className={styles.value}>{details.publicKey.exponent}</span>
            </div>
          )}
          {details.publicKey.curve !== 'N/A' && (
            <div className={styles.field}>
              <span className={styles.label}>Curve:</span>
              <span className={styles.value}>{details.publicKey.curve}</span>
            </div>
          )}
        </div>
      </div>
      
      <div className={styles.section}>
        <h4><FileText size={16} /> Signature Information</h4>
        <div className={styles.grid}>
          <div className={styles.field}>
            <span className={styles.label}>Algorithm:</span>
            <span className={styles.value}>{details.signature.algorithm}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.label}>Hash Algorithm:</span>
            <span className={styles.value}>{details.signature.hashAlgorithm}</span>
          </div>
        </div>
      </div>

      {details.extensions.subjectAltName && details.extensions.subjectAltName.length > 0 && (
        <div className={styles.section}>
          <h4>Subject Alternative Names</h4>
          <div className={styles.sanList}>
            {details.extensions.subjectAltName.map((san, index) => (
              <span key={index} className={styles.sanItem}>
                {san.typeName || `Type ${san.type}`}: {san.value}
              </span>
            ))}
          </div>
        </div>
      )}

      {details.extensions.keyUsage && (
        <div className={styles.section}>
          <h4>Requested Key Usage</h4>
          <div className={styles.grid}>
            {Object.entries(details.extensions.keyUsage).map(([key, value]) => {
              if (typeof value === 'boolean' && value === true) {
                return (
                  <div key={key} className={styles.field}>
                    <span className={styles.value}>{key}</span>
                  </div>
                );
              }
              return null;
            })}
          </div>
        </div>
      )}

      {details.extensions.extendedKeyUsage && details.extensions.extendedKeyUsage.length > 0 && (
        <div className={styles.section}>
          <h4>Requested Extended Key Usage</h4>
          <div className={styles.grid}>
            {details.extensions.extendedKeyUsage.map((usage, index) => (
              <div key={index} className={styles.field}>
                <span className={styles.value}>{usage}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {details.version !== undefined && (
        <div className={styles.section}>
          <h4>CSR Version</h4>
          <div className={styles.grid}>
            <div className={styles.field}>
              <span className={styles.value}>Version {details.version}</span>
            </div>
          </div>
        </div>
      )}
    </>
  )

  const renderPrivateKeyDetails = () => (
    <div className={styles.section}>
      <h4><Key size={16} /> Private Key Information</h4>
      <div className={styles.grid}>
        <div className={styles.field}>
          <span className={styles.label}>Algorithm:</span>
          <span className={styles.value}>{details.algorithm}</span>
        </div>
        <div className={styles.field}>
          <span className={styles.label}>Key Size:</span>
          <span className={styles.value}>{details.keySize} bits</span>
        </div>
        {details.curve !== 'N/A' && (
          <div className={styles.field}>
            <span className={styles.label}>Curve:</span>
            <span className={styles.value}>{details.curve}</span>
          </div>
        )}
      </div>
    </div>
  )

  const enhancedType = getEnhancedCertificateType()

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.typeInfo}>
          <span style={{ color: enhancedType.color }}>
            {getTypeIcon(analysis.type)}
          </span>
          <h3>{certificate.filename}</h3>
          <span className={styles.typeLabel} style={{ backgroundColor: enhancedType.color }}>
            {enhancedType.label}
          </span>
        </div>
        <div className={styles.basicInfo}>
          <span>Format: {analysis.format}</span>
          <span>Size: {(analysis.size / 1024).toFixed(2)} KB</span>
        </div>
      </div>

      <div className={styles.content}>
        {analysis.type.includes('Certificate') && renderCertificateDetails()}
        {analysis.type === 'CSR' && renderCSRDetails()}
        {analysis.type === 'Private Key' && renderPrivateKeyDetails()}
      </div>
    </div>
  )
}

export default CertificateDetails
