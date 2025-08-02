// frontend/src/components/ValidationPanel/ValidationPanel.jsx
// Fixed ValidationPanel for unified storage backend - no syntax errors

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
      setError(null)
    }
  }, [certificates])

  const runValidations = async () => {
    setIsLoading(true)
    setError(null)
    
    try {
      const response = await fetch('/validation/results', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (!response.ok) {
        throw new Error(`Validation failed: ${response.statusText}`)
      }

      const text = await response.text()
      let data
      
      try {
        data = JSON.parse(text)
      } catch (parseError) {
        console.error('JSON Parse Error:', parseError)
        console.error('Response text:', text)
        throw new Error('Invalid JSON response from server')
      }
      
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
    return validation.isValid ? 
      <CheckCircle size={20} className={styles.validIcon} /> : 
      <XCircle size={20} className={styles.invalidIcon} />
  }

  const getTypeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'private key':
      case 'privatekey':
        return <Key size={16} className={styles.typeIcon} />
      case 'csr':
      case 'certificate request':
        return <FileText size={16} className={styles.typeIcon} />
      case 'certificate':
      case 'ca certificate':
      case 'root ca':
      case 'intermediate ca':
      case 'issuing ca':
        return <Award size={16} className={styles.typeIcon} />
      default:
        return <Shield size={16} className={styles.typeIcon} />
    }
  }

  const renderValidationDetails = (validation) => {
    return (
      <div className={styles.validationDetails}>
        <div className={styles.detailsContent}>
          
          {/* Basic validation info */}
          <div className={styles.basicInfo}>
            <div className={styles.infoRow}>
              <span className={styles.infoLabel}>Type:</span>
              <span className={styles.infoValue}>{validation.type || 'Unknown'}</span>
            </div>
            <div className={styles.infoRow}>
              <span className={styles.infoLabel}>Status:</span>
              <span className={`${styles.infoValue} ${validation.isValid ? styles.valid : styles.invalid}`}>
                {validation.isValid ? 'Valid' : 'Invalid'}
              </span>
            </div>
            {validation.matchPercentage && (
              <div className={styles.infoRow}>
                <span className={styles.infoLabel}>Match:</span>
                <span className={styles.infoValue}>{validation.matchPercentage}%</span>
              </div>
            )}
          </div>

          {/* Error details */}
          {validation.error && (
            <div className={styles.errorSection}>
              <div className={styles.errorHeader}>
                <AlertTriangle size={16} />
                Error Details
              </div>
              <div className={styles.errorContent}>
                {validation.error}
              </div>
            </div>
          )}

          {/* Technical details */}
          {validation.details && (
            <div className={styles.detailsSection}>
              <div className={styles.detailsHeader}>Technical Details</div>
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

  if (certificates.length < 2) {
    return (
      <div className={styles.container}>
        <div className={styles.header} onClick={() => setIsExpanded(!isExpanded)}>
          <div className={styles.titleSection}>
            <Shield size={24} />
            <div className={styles.headerText}>
              <h3>Certificate Validation</h3>
              <p>Upload at least 2 certificates to see validation results</p>
            </div>
          </div>
          <div className={styles.expandButton}>
            {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
          </div>
        </div>

        {isExpanded && (
          <div className={styles.content}>
            <div className={styles.noValidations}>
              <Shield size={48} className={styles.noValidationsIcon} />
              <p>No validations available</p>
              <small>Upload certificates, private keys, or CSRs to see cryptographic validation results</small>
            </div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className={styles.container}>
      <div className={styles.header} onClick={() => setIsExpanded(!isExpanded)}>
        <div className={styles.titleSection}>
          <Shield size={24} />
          <div className={styles.headerText}>
            <h3>Certificate Validation</h3>
            {validations.length > 0 && (
              <p>{validations.length} validation{validations.length !== 1 ? 's' : ''} completed</p>
            )}
          </div>
        </div>

        <div className={styles.controls}>
          {validations.length > 0 && (
            <div className={styles.statusBadges}>
              <span className={`${styles.badge} ${styles.validBadge}`}>
                {validations.filter(v => v.isValid).length} Valid
              </span>
              <span className={`${styles.badge} ${styles.invalidBadge}`}>
                {validations.filter(v => !v.isValid).length} Invalid
              </span>
            </div>
          )}
          <div className={styles.expandButton}>
            {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
          </div>
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

          {isLoading && (
            <div className={styles.loadingMessage}>
              <div className={styles.spinner}></div>
              Running validations...
            </div>
          )}

          {!isLoading && !error && validations.length === 0 && (
            <div className={styles.noValidations}>
              <Shield size={48} className={styles.noValidationsIcon} />
              <p>No validation results</p>
              <small>Validation results will appear here once certificates are processed</small>
            </div>
          )}

          {validations.length > 0 && (
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
                        {getTypeIcon(validation.sourceType)}
                        <span className={styles.arrow}>→</span>
                        {getTypeIcon(validation.targetType)}
                      </div>

                      <div className={styles.validationText}>
                        <div className={styles.validationType}>
                          {validation.type || 'Unknown Validation'}
                        </div>
                        <div className={styles.validationFiles}>
                          {validation.sourceFile || 'Unknown'} → {validation.targetFile || 'Unknown'}
                        </div>
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