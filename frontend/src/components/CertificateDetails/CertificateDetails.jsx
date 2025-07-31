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
      case 'IssuingCA':
      case 'IntermediateCA':
      case 'RootCA':
        return <Shield size={20} />
      case 'CSR':
        return <FileText size={20} />
      case 'PrivateKey':
        return <Key size={20} />
      default:
        return <FileText size={20} />
    }
  }

  const getEnhancedCertificateType = () => {
    const type = analysis.type || ''
    
    // Handle standardized types only
    switch (type) {
      case 'CSR':
        return { label: 'Certificate Signing Request', color: '#3b82f6' }
      case 'PrivateKey':
        return { label: 'Private Key', color: '#dc2626' }
      case 'Certificate':
        return { label: 'End-Entity Certificate', color: '#1e40af' }
      case 'IssuingCA':
        return { label: 'Issuing Certificate Authority', color: '#1d4ed8' }
      case 'IntermediateCA':
        return { label: 'Intermediate Certificate Authority', color: '#1e40af' }
      case 'RootCA':
        return { label: 'Root Certificate Authority', color: '#7c2d12' }
      case 'CertificateChain':
        return { label: 'Certificate Chain', color: '#2563eb' }
      default:
        return { label: type, color: '#6b7280' }
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
        {(analysis.type === 'Certificate' || 
          analysis.type === 'IssuingCA' || 
          analysis.type === 'IntermediateCA' || 
          analysis.type === 'RootCA') && renderCertificateDetails()}
        {analysis.type === 'CSR' && renderCSRDetails()}
        {analysis.type === 'PrivateKey' && renderPrivateKeyDetails()}
      </div>
    </div>
  )
}

export default CertificateDetails
