// frontend/src/components/ValidationPanel/ValidationPanel.jsx
import React, { useState, useEffect } from 'react'
import { Shield, CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronUp, Key, FileText, Eye, EyeOff } from 'lucide-react'
import api from '../../services/api'
import styles from './ValidationPanel.module.css'

const ValidationPanel = ({ certificates }) => {
  const [validations, setValidations] = useState([])
  const [isLoading, setIsLoading] = useState(false)
  const [isExpanded, setIsExpanded] = useState(false)
  const [showDetails, setShowDetails] = useState({})
  const [error, setError] = useState(null)

  useEffect(() => {
    if (certificates.length >= 2) {
      runValidations()
    } else {
      setValidations([])
    }
  }, [certificates])

  const runValidations = async () => {
    setIsLoading(true)
    setError(null)
    
    try {
      const response = await api.get('/validate')
      if (response.data.success) {
        setValidations(response.data.validations || [])
      }
    } catch (err) {
      console.error('Validation error:', err)
      setError('Failed to run validations')
    } finally {
      setIsLoading(false)
    }
  }

  const toggleDetails = (validationIndex) => {
    setShowDetails(prev => ({
      ...prev,
      [validationIndex]: !prev[validationIndex]
    }))
  }

  const getValidationIcon = (validation) => {
    if (validation.isValid) {
      return <CheckCircle size={20} className={styles.validIcon} />
    } else {
      return <XCircle size={20} className={styles.invalidIcon} />
    }
  }

  const getValidationTypeIcon = (validationType) => {
    if (validationType.includes('Private Key') && validationType.includes('CSR')) {
      return (
        <div className={styles.validationTypeIcons}>
          <Key size={16} />
          <span className={styles.arrow}>↔</span>
          <FileText size={16} />
        </div>
      )
    } else if (validationType.includes('CSR') && validationType.includes('Certificate')) {
      return (
        <div className={styles.validationTypeIcons}>
          <FileText size={16} />
          <span className={styles.arrow}>↔</span>
          <Shield size={16} />
        </div>
      )
    }
    return <Shield size={16} />
  }

  const getValidationFiles = (validation) => {
    const details = validation.details || {}
    
    if (details.privateKeyFile && details.csrFile) {
      return `${details.privateKeyFile} ↔ ${details.csrFile}`
    } else if (details.csrFile && details.certificateFile) {
      return `${details.csrFile} ↔ ${details.certificateFile}`
    } else if (details.files && details.files.length >= 2) {
      return `${details.files[0]} ↔ ${details.files[1]}`
    }
    return null
  }

  // Enhanced validation details renderer
  const renderValidationDetails = (validation) => {
    const details = validation.details || {}
    
    // For Certificate Chain validations, show cryptographic details
    if (validation.validationType === 'Certificate Chain' && details.signatureVerification) {
      return renderCertificateChainDetails(details)
    }

    // For other validation types, show existing details
    return renderStandardValidationDetails(validation)
  }

  const renderCertificateChainDetails = (details) => {
    const sigDetails = details.signatureVerification
    const nameChain = details.nameChaining
    
    return (
      <div className={styles.validationDetails}>
        <h4>Cryptographic Validation Details</h4>
        
        <div className={styles.detailSection}>
          <h5>🔐 Digital Signature Verification</h5>
          <div className={styles.detailGrid}>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Signature Verified:</span>
              <span className={`${styles.detailValue} ${sigDetails.verified ? styles.valid : styles.invalid}`}>
                {sigDetails.verified ? '✅ VERIFIED' : '❌ FAILED'}
              </span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Signature Algorithm:</span>
              <span className={styles.detailValue}>{sigDetails.algorithm}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Algorithm OID:</span>
              <span className={styles.detailValue}>{sigDetails.algorithmOID}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Issuer Public Key:</span>
              <span className={styles.detailValue}>
                {sigDetails.issuerPublicKeyAlgorithm} ({sigDetails.issuerKeySize} bits)
              </span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Signature Length:</span>
              <span className={styles.detailValue}>{sigDetails.signatureLength} bytes</span>
            </div>
          </div>
          {sigDetails.error && (
            <div className={styles.errorDetail}>
              <span className={styles.errorLabel}>Signature Error:</span>
              <span className={styles.errorValue}>{sigDetails.error}</span>
            </div>
          )}
        </div>

        <div className={styles.detailSection}>
          <h5>🔗 Certificate Name Chaining</h5>
          <div className={styles.detailGrid}>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>Name Chain Valid:</span>
              <span className={`${styles.detailValue} ${nameChain?.valid ? styles.valid : styles.invalid}`}>
                {nameChain?.valid ? '✅ VALID' : '❌ INVALID'}
              </span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>End Entity Issuer:</span>
              <span className={styles.detailValue}>{nameChain?.endEntityIssuer || 'N/A'}</span>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.detailLabel}>CA Subject:</span>
              <span className={styles.detailValue}>{nameChain?.caSubject || 'N/A'}</span>
            </div>
          </div>
        </div>

        {details.certificates && (
          <div className={styles.detailSection}>
            <h5>📋 Certificate Information</h5>
            <div className={styles.certificateChain}>
              {details.certificates.map((cert, index) => (
                <div key={index} className={styles.chainCertificate}>
                  <span className={styles.chainRole}>
                    {cert.isCA ? '🏛️ CA Certificate' : '📄 End Entity'}
                  </span>
                  <span className={styles.chainFile}>{cert.filename}</span>
                  <div className={styles.chainDetails}>
                    <span>Subject: {cert.subject}</span>
                    <span>Serial: {cert.serialNumber}</span>
                    <span>Valid: {new Date(cert.notBefore).toLocaleDateString()} - {new Date(cert.notAfter).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {details.keyIdentifiers && (
          <div className={styles.detailSection}>
            <h5>🔑 Key Identifiers</h5>
            <div className={styles.detailGrid}>
              {details.keyIdentifiers.endEntity?.subjectKeyId && (
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>End Entity Subject Key ID:</span>
                  <span className={styles.detailValue}>{details.keyIdentifiers.endEntity.subjectKeyId}</span>
                </div>
              )}
              {details.keyIdentifiers.endEntity?.authorityKeyId && (
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>End Entity Authority Key ID:</span>
                  <span className={styles.detailValue}>{details.keyIdentifiers.endEntity.authorityKeyId}</span>
                </div>
              )}
              {details.keyIdentifiers.issuingCA?.subjectKeyId && (
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>CA Subject Key ID:</span>
                  <span className={styles.detailValue}>{details.keyIdentifiers.issuingCA.subjectKeyId}</span>
                </div>
              )}
              {details.keyIdentifiers.keyIdMatch !== null && (
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>Key ID Match:</span>
                  <span className={`${styles.detailValue} ${details.keyIdentifiers.keyIdMatch ? styles.valid : styles.invalid}`}>
                    {details.keyIdentifiers.keyIdMatch ? '✅ MATCH' : '❌ NO MATCH'}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {details.validationSteps && (
          <div className={styles.detailSection}>
            <h5>📝 Validation Steps</h5>
            <div className={styles.validationSteps}>
              {details.validationSteps.map((step, index) => (
                <div key={index} className={styles.validationStep}>
                  <div className={styles.stepHeader}>
                    <span className={styles.stepName}>{step.step}</span>
                    <span className={`${styles.stepResult} ${step.result ? styles.valid : styles.invalid}`}>
                      {step.result ? '✅' : '❌'}
                    </span>
                  </div>
                  <div className={styles.stepDetails}>{step.details}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  const renderStandardValidationDetails = (validation) => {
    const details = validation.details || {}
    
    return (
      <div className={styles.validationDetails}>
        <h4>Validation Details</h4>
        
        {/* Render algorithm info */}
        {renderAlgorithmInfo(details)}
        
        {/* Render public key comparison */}
        {renderPublicKeyComparison(details.publicKeyComparison)}
        
        {/* Render legacy comparison format */}
        {details.comparison && (
          <div className={styles.comparisonSection}>
            <h5>Comparison</h5>
            {Object.entries(details.comparison).map(([key, comparison]) => (
              <div key={key} className={styles.comparisonItem}>
                <div className={styles.comparisonHeader}>
                  <span className={styles.comparisonLabel}>
                    {key.charAt(0).toUpperCase() + key.slice(1)}
                  </span>
                  <span className={`${styles.comparisonResult} ${comparison.match ? styles.match : styles.noMatch}`}>
                    {comparison.match ? <CheckCircle size={14} /> : <XCircle size={14} />}
                    {comparison.match ? 'Match' : 'No Match'}
                  </span>
                </div>
                {comparison.privateKey && comparison.csr && (
                  <div className={styles.comparisonValues}>
                    <div className={styles.valueRow}>
                      <span className={styles.valueLabel}>Private Key:</span>
                      <span className={styles.valueText}>{comparison.privateKey}</span>
                    </div>
                    <div className={styles.valueRow}>
                      <span className={styles.valueLabel}>CSR:</span>
                      <span className={styles.valueText}>{comparison.csr}</span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Render other standard details */}
        {renderFingerprint(details.fingerprint)}
        {renderSubjectComparison(details.subjectComparison)}
        {renderSanComparison(details.sanComparison)}
      </div>
    )
  }

  const renderAlgorithmInfo = (details) => {
    if (!details.algorithm) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>Algorithm Information</h5>
        <div className={styles.comparisonItem}>
          <div className={styles.comparisonHeader}>
            <span className={styles.comparisonLabel}>Algorithm</span>
            <span className={styles.comparisonResult}>{details.algorithm}</span>
          </div>
          {details.keySize && (
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>Key Size:</span>
              <span className={styles.valueText}>{details.keySize} bits</span>
            </div>
          )}
        </div>
      </div>
    )
  }

  const renderPublicKeyComparison = (comparison) => {
    if (!comparison) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>Public Key Comparison</h5>
        
        {comparison.directMatch !== undefined && (
          <div className={styles.comparisonItem}>
            <div className={styles.comparisonHeader}>
              <span className={styles.comparisonLabel}>Direct Match</span>
              <span className={`${styles.comparisonResult} ${comparison.directMatch ? styles.match : styles.noMatch}`}>
                {comparison.directMatch ? <CheckCircle size={14} /> : <XCircle size={14} />}
                {comparison.directMatch ? 'Match' : 'No Match'}
              </span>
            </div>
          </div>
        )}
        
        {comparison.fingerprintMatch !== undefined && (
          <div className={styles.comparisonItem}>
            <div className={styles.comparisonHeader}>
              <span className={styles.comparisonLabel}>Fingerprint Match</span>
              <span className={`${styles.comparisonResult} ${comparison.fingerprintMatch ? styles.match : styles.noMatch}`}>
                {comparison.fingerprintMatch ? <CheckCircle size={14} /> : <XCircle size={14} />}
                {comparison.fingerprintMatch ? 'Match' : 'No Match'}
              </span>
            </div>
          </div>
        )}
      </div>
    )
  }

  const renderFingerprint = (fingerprint) => {
    if (!fingerprint) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>Fingerprint</h5>
        <div className={styles.comparisonItem}>
          <div className={styles.valueRow}>
            <span className={styles.valueLabel}>SHA256:</span>
            <span className={styles.valueText}>{fingerprint}</span>
          </div>
        </div>
      </div>
    )
  }

  const renderSubjectComparison = (subjectComparison) => {
    if (!subjectComparison) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>Subject Comparison</h5>
        <div className={styles.comparisonItem}>
          <div className={styles.comparisonHeader}>
            <span className={styles.comparisonLabel}>Subject Match</span>
            <span className={`${styles.comparisonResult} ${subjectComparison.match ? styles.match : styles.noMatch}`}>
              {subjectComparison.match ? <CheckCircle size={14} /> : <XCircle size={14} />}
              {subjectComparison.match ? 'Match' : 'No Match'}
            </span>
          </div>
          <div className={styles.comparisonValues}>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>CSR Subject:</span>
              <span className={styles.valueText}>{subjectComparison.csr}</span>
            </div>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>Certificate Subject:</span>
              <span className={styles.valueText}>{subjectComparison.certificate}</span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  const renderSanComparison = (sanComparison) => {
    if (!sanComparison) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>Subject Alternative Names (SAN)</h5>
        <div className={styles.comparisonItem}>
          <div className={styles.comparisonHeader}>
            <span className={styles.comparisonLabel}>SAN Match</span>
            <span className={`${styles.comparisonResult} ${sanComparison.match ? styles.match : styles.noMatch}`}>
              {sanComparison.match ? <CheckCircle size={14} /> : <XCircle size={14} />}
              {sanComparison.match ? 'Match' : 'No Match'}
            </span>
          </div>
          <div className={styles.comparisonValues}>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>CSR SAN:</span>
              <span className={styles.valueText}>{sanComparison.csr?.join(', ') || 'None'}</span>
            </div>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>Certificate SAN:</span>
              <span className={styles.valueText}>{sanComparison.certificate?.join(', ') || 'None'}</span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  const hasValidations = validations.length > 0

  return (
    <div className={styles.container}>
      <div className={styles.header} onClick={() => setIsExpanded(!isExpanded)}>
        <div className={styles.titleSection}>
          <Shield size={24} className={styles.icon} />
          <h3>Validation Results</h3>
          {hasValidations && (
            <span className={styles.validationCount}>
              {validations.filter(v => v.isValid).length}/{validations.length} passed
            </span>
          )}
        </div>
        <div className={styles.controls}>
          {hasValidations && (
            <button onClick={(e) => { e.stopPropagation(); runValidations() }} className={styles.refreshButton}>
              Refresh
            </button>
          )}
          {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>
      </div>

      {isExpanded && (
        <div className={styles.content}>
          {error && (
            <div className={styles.errorMessage}>
              <AlertTriangle size={16} />
              {error}
            </div>
          )}

          {isLoading && !hasValidations && (
            <div className={styles.loadingMessage}>
              <div className={styles.spinner}></div>
              Running validation checks...
            </div>
          )}

          {!isLoading && !hasValidations && !error && (
            <div className={styles.noValidations}>
              <Shield size={32} className={styles.noValidationsIcon} />
              <p>No validation checks available</p>
              <small>Upload compatible certificates (e.g., private key + CSR) to see validations</small>
            </div>
          )}

          {hasValidations && (
            <div className={styles.validationsList}>
              {validations.map((validation, index) => (
                <div key={index} className={`${styles.validationItem} ${validation.isValid ? styles.valid : styles.invalid}`}>
                  <div className={styles.validationHeader}>
                    <div className={styles.validationInfo}>
                      {getValidationIcon(validation)}
                      {getValidationTypeIcon(validation.validationType)}
                      <div className={styles.validationText}>
                        <span className={styles.validationType}>{validation.validationType}</span>
                        {getValidationFiles(validation) && (
                          <span className={styles.validationFiles}>
                            {getValidationFiles(validation)}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className={styles.validationControls}>
                      <span className={`${styles.status} ${validation.isValid ? styles.validStatus : styles.invalidStatus}`}>
                        {validation.isValid ? 'MATCH' : 'NO MATCH'}
                      </span>
                      <button 
                        className={styles.detailsButton}
                        onClick={() => toggleDetails(index)}
                        title="Show/hide validation details"
                      >
                        {showDetails[index] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  {validation.error && (
                    <div className={styles.errorDetails}>
                      <AlertTriangle size={14} />
                      {validation.error}
                    </div>
                  )}

                  {showDetails[index] && (validation.details || validation.error) && renderValidationDetails(validation)}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default ValidationPanel