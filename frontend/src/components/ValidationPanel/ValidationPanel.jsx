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
    }
    return null
  }

  const renderPublicKeyComparison = (comparison) => {
    if (!comparison) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>Comparison</h5>
        
        {/* Direct Match */}
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
        
        {/* Fingerprint Match */}
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

        {/* Legacy format support for older validations */}
        {Object.entries(comparison).map(([key, comp]) => {
          // Skip the new format fields
          if (key === 'directMatch' || key === 'fingerprintMatch') return null
          
          return (
            <div key={key} className={styles.comparisonItem}>
              <div className={styles.comparisonHeader}>
                <span className={styles.comparisonLabel}>
                  {key === 'publicPoint' ? 'Public Point' : key.charAt(0).toUpperCase() + key.slice(1)}
                </span>
                <span className={`${styles.comparisonResult} ${comp.match ? styles.match : styles.noMatch}`}>
                  {comp.match ? <CheckCircle size={14} /> : <XCircle size={14} />}
                  {comp.match ? 'Match' : 'No Match'}
                </span>
              </div>
              
              {comp.details && (
                <div className={styles.comparisonDetails}>
                  <div className={styles.comparisonDetailItem}>
                    <strong>Expected:</strong> {comp.details.expected}
                  </div>
                  <div className={styles.comparisonDetailItem}>
                    <strong>Actual:</strong> {comp.details.actual}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    )
  }

  const renderFingerprint = (fingerprint) => {
    if (!fingerprint) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>Public Key Fingerprint (SHA256)</h5>
        <div className={styles.comparisonItem}>
          <div className={styles.comparisonHeader}>
            <span className={styles.comparisonLabel}>Fingerprint</span>
            <span className={`${styles.comparisonResult} ${fingerprint.match ? styles.match : styles.noMatch}`}>
              {fingerprint.match ? <CheckCircle size={14} /> : <XCircle size={14} />}
              {fingerprint.match ? 'Match' : 'No Match'}
            </span>
          </div>
          <div className={styles.comparisonValues}>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>CSR:</span>
              <span className={styles.valueText}>{fingerprint.csr}</span>
            </div>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>Certificate:</span>
              <span className={styles.valueText}>{fingerprint.certificate}</span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  const renderSubjectComparison = (subjectComparison) => {
    if (!subjectComparison || subjectComparison.match) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>⚠️ Subject Name Differences</h5>
        <div className={styles.comparisonItem}>
          <div className={styles.comparisonHeader}>
            <span className={styles.comparisonLabel}>Common Name</span>
            <span className={`${styles.comparisonResult} ${styles.noMatch}`}>
              <XCircle size={14} />
              Different
            </span>
          </div>
          <div className={styles.comparisonValues}>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>CSR:</span>
              <span className={styles.valueText}>{subjectComparison.commonName?.csr || 'N/A'}</span>
            </div>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>Certificate:</span>
              <span className={styles.valueText}>{subjectComparison.commonName?.certificate || 'N/A'}</span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  const renderSanComparison = (sanComparison) => {
    if (!sanComparison || sanComparison.match) return null

    return (
      <div className={styles.comparisonSection}>
        <h5>⚠️ Subject Alternative Name Differences</h5>
        <div className={styles.comparisonItem}>
          <div className={styles.comparisonValues}>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>CSR SANs:</span>
              <span className={styles.valueText}>
                {sanComparison.csr?.length > 0 ? sanComparison.csr.join(', ') : 'None'}
              </span>
            </div>
            <div className={styles.valueRow}>
              <span className={styles.valueLabel}>Certificate SANs:</span>
              <span className={styles.valueText}>
                {sanComparison.certificate?.length > 0 ? sanComparison.certificate.join(', ') : 'None'}
              </span>
            </div>
            {sanComparison.onlyInCsr?.length > 0 && (
              <div className={styles.valueRow}>
                <span className={styles.valueLabel}>Only in CSR:</span>
                <span className={styles.valueText}>{sanComparison.onlyInCsr.join(', ')}</span>
              </div>
            )}
            {sanComparison.onlyInCertificate?.length > 0 && (
              <div className={styles.valueRow}>
                <span className={styles.valueLabel}>Only in Certificate:</span>
                <span className={styles.valueText}>{sanComparison.onlyInCertificate.join(', ')}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    )
  }

  const hasValidations = validations.length > 0
  const validCount = validations.filter(v => v.isValid).length
  const invalidCount = validations.length - validCount

  if (certificates.length < 2) {
    return null // Don't show validation panel if less than 2 certificates
  }

  return (
    <div className={styles.container}>
      <div className={styles.header} onClick={() => setIsExpanded(!isExpanded)}>
        <div className={styles.titleSection}>
          <Shield size={24} className={styles.headerIcon} />
          <h3>Certificate Validation</h3>
          {hasValidations && (
            <div className={styles.statusBadges}>
              {validCount > 0 && (
                <span className={styles.validBadge}>
                  <CheckCircle size={14} />
                  {validCount} Valid
                </span>
              )}
              {invalidCount > 0 && (
                <span className={styles.invalidBadge}>
                  <XCircle size={14} />
                  {invalidCount} Invalid
                </span>
              )}
            </div>
          )}
        </div>
        <div className={styles.controls}>
          {isLoading && <div className={styles.spinner}></div>}
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

                  {showDetails[index] && validation.details && (
                    <div className={styles.validationDetails}>
                      <h4>Validation Details</h4>
                      
                      {/* Render public key comparison (legacy format for Private Key <-> CSR) */}
                      {validation.details.comparison && (
                        <div className={styles.comparisonSection}>
                          <h5>Comparison</h5>
                          {Object.entries(validation.details.comparison).map(([key, comparison]) => (
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
                              
                              {comparison.privateKey !== undefined && comparison.csr !== undefined && (
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

                              {comparison.x && comparison.y && (
                                <div className={styles.comparisonValues}>
                                  <div className={styles.valueRow}>
                                    <span className={styles.valueLabel}>X Coordinate:</span>
                                    <div className={styles.coordComparison}>
                                      <div className={styles.coordValue}>
                                        <span className={styles.coordLabel}>PK:</span>
                                        <span className={styles.valueText}>{comparison.x.privateKey}</span>
                                      </div>
                                      <div className={styles.coordValue}>
                                        <span className={styles.coordLabel}>CSR:</span>
                                        <span className={styles.valueText}>{comparison.x.csr}</span>
                                      </div>
                                      <span className={`${styles.coordResult} ${comparison.x.match ? styles.match : styles.noMatch}`}>
                                        {comparison.x.match ? '✓' : '✗'}
                                      </span>
                                    </div>
                                  </div>
                                  <div className={styles.valueRow}>
                                    <span className={styles.valueLabel}>Y Coordinate:</span>
                                    <div className={styles.coordComparison}>
                                      <div className={styles.coordValue}>
                                        <span className={styles.coordLabel}>PK:</span>
                                        <span className={styles.valueText}>{comparison.y.privateKey}</span>
                                      </div>
                                      <div className={styles.coordValue}>
                                        <span className={styles.coordLabel}>CSR:</span>
                                        <span className={styles.valueText}>{comparison.y.csr}</span>
                                      </div>
                                      <span className={`${styles.coordResult} ${comparison.y.match ? styles.match : styles.noMatch}`}>
                                        {comparison.y.match ? '✓' : '✗'}
                                      </span>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Render new format for CSR <-> Certificate */}
                      {renderPublicKeyComparison(validation.details.publicKeyComparison)}
                      {renderFingerprint(validation.details.fingerprint)}
                      {renderSubjectComparison(validation.details.subjectComparison)}
                      {renderSanComparison(validation.details.sanComparison)}
                    </div>
                  )}
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