// frontend/src/components/ValidationPanel/ValidationPanel.jsx
// Updated ValidationPanel for unified storage backend

import React, { useState, useEffect } from 'react'
import { 
  Shield, CheckCircle, XCircle, ChevronDown, ChevronUp, 
  AlertTriangle, Key, FileText, Award, Link2, Eye, EyeOff
} from 'lucide-react'
import styles from './ValidationPanel.module.css'

const ValidationPanel = ({ certificates = [], onValidationComplete }) => {
  const [validations, setValidations] = useState([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [isExpanded, setIsExpanded] = useState(true)
  const [showDetails, setShowDetails] = useState({})

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
      const response = await fetch('/validate', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (!response.ok) {
        throw new Error(`Validation failed: ${response.statusText}`)
      }

      const data = await response.json()
      
      if (!data.success) {
        throw new Error(data.message || 'Validation failed')
      }

      setValidations(data.validations || [])
      
      if (onValidationComplete) {
        onValidationComplete(data.validations || [])
      }
    } catch (err) {
      console.error('Validation error:', err)
      setError(err.message)
    } finally {
      setIsLoading(false)
    }
  }

  const toggleDetails = (index) => {
    setShowDetails(prev => ({
      ...prev,
      [index]: !prev[index]
    }))
  }

  const getValidationIcon = (validation) => {
    return validation.isValid ? (
      <CheckCircle size={20} className={styles.validIcon} />
    ) : (
      <XCircle size={20} className={styles.invalidIcon} />
    )
  }

  const getValidationTypeIcon = (validationType) => {
    const iconProps = { size: 18, className: styles.typeIcon }
    
    if (validationType.includes('Private Key')) {
      return <Key {...iconProps} />
    } else if (validationType.includes('CSR')) {
      return <FileText {...iconProps} />
    } else if (validationType.includes('Certificate')) {
      return <Award {...iconProps} />
    } else if (validationType.includes('Chain')) {
      return <Link2 {...iconProps} />
    }
    
    return <Shield {...iconProps} />
  }

  const formatValidationDescription = (validation) => {
    // Clean description - remove redundant parts if certificate1/certificate2 are shown
    let description = validation.description || ''
    
    // If we have certificate names, make description more concise
    if (validation.certificate1 && validation.certificate2) {
      return `${validation.certificate1} ↔ ${validation.certificate2}`
    } else if (validation.certificate1) {
      return validation.certificate1
    }
    
    return description
  }

  const renderValidationDetails = (validation) => {
    return (
      <div className={styles.validationDetails}>
        <div className={styles.detailsContent}>
          
          {/* Basic Information */}
          <div className={styles.basicInfo}>
            <div className={styles.infoRow}>
              <span className={styles.infoLabel}>Type:</span>
              <span className={styles.infoValue}>{validation.validationType}</span>
            </div>
            
            {validation.certificate1 && (
              <div className={styles.infoRow}>
                <span className={styles.infoLabel}>File 1:</span>
                <span className={styles.infoValue}>{validation.certificate1}</span>
              </div>
            )}
            
            {validation.certificate2 && (
              <div className={styles.infoRow}>
                <span className={styles.infoLabel}>File 2:</span>
                <span className={styles.infoValue}>{validation.certificate2}</span>
              </div>
            )}
            
            <div className={styles.infoRow}>
              <span className={styles.infoLabel}>Result:</span>
              <span className={`${styles.infoValue} ${validation.isValid ? styles.valid : styles.invalid}`}>
                {validation.isValid ? 'Valid Match' : 'No Match'}
              </span>
            </div>
            
            {validation.description && (
              <div className={styles.infoRow}>
                <span className={styles.infoLabel}>Description:</span>
                <span className={styles.infoValue}>{validation.description}</span>
              </div>
            )}
          </div>

          {/* Error Information */}
          {validation.error && (
            <div className={styles.errorSection}>
              <div className={styles.errorHeader}>
                <AlertTriangle size={16} />
                <span>Error Details</span>
              </div>
              <div className={styles.errorContent}>
                {validation.error}
              </div>
            </div>
          )}

          {/* Additional Details */}
          {validation.details && Object.keys(validation.details).length > 0 && (
            <div className={styles.detailsSection}>
              <div className={styles.detailsHeader}>
                <span>Technical Details</span>
              </div>
              <div className={styles.detailsGrid}>
                {Object.entries(validation.details).map(([key, value]) => (
                  <div key={key} className={styles.detailRow}>
                    <span className={styles.detailLabel}>{key}:</span>
                    <span className={styles.detailValue}>
                      {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    )
  }

  const hasValidations = validations.length > 0
  const validCount = validations.filter(v => v.isValid).length
  const invalidCount = validations.length - validCount

  // Don't show panel if less than 2 certificates
  if (certificates.length < 2) {
    return null
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
                <div 
                  key={index} 
                  className={`${styles.validationItem} ${validation.isValid ? styles.valid : styles.invalid}`}
                >
                  <div className={styles.validationHeader}>
                    <div className={styles.validationInfo}>
                      {getValidationIcon(validation)}
                      <div className={styles.validationTypeIcons}>
                        {getValidationTypeIcon(validation.validationType)}
                        {validation.certificate2 && <span className={styles.arrow}>↔</span>}
                      </div>
                      <div className={styles.validationText}>
                        <span className={styles.validationType}>{validation.validationType}</span>
                        <span className={styles.validationFiles}>
                          {formatValidationDescription(validation)}
                        </span>
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

                  {/* Error summary in header for invalid validations */}
                  {!validation.isValid && validation.error && (
                    <div className={styles.errorDetails}>
                      <AlertTriangle size={14} />
                      {validation.error}
                    </div>
                  )}

                  {/* Detailed view */}
                  {showDetails[index] && renderValidationDetails(validation)}
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