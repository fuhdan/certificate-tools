// Filter ONLY for actual PKI relationship validations
  const isValidPKIRelationship = (validation, key = '') => {
    const validationType = (validation.title || validation.validation_type || key || '').toLowerCase();
    
    // ONLY allow these specific PKI relationship validations
    const allowedTypes = [
      'private key',
      'certificate match',
      'csr',
      'chain',
      'ca match',
      'issuing',
      'intermediate',
      'root ca'
    ];
    
    // EXCLUDE these bullshit validations  
    const excludedTypes = [
      'expiry',
      'expired', 
      'date',
      'usage',
      'algorithm',
      'strength',
      'subject alternative',
      'san',
      'extension'
    ];
    
    // Must contain allowed type AND not contain excluded type
    const hasAllowedType = allowedTypes.some(type => validationType.includes(type));
    const hasExcludedType = excludedTypes.some(type => validationType.includes(type));
    
    return hasAllowedType && !hasExcludedType;
  };import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  CheckCircle, 
  AlertTriangle, 
  XCircle, 
  Key, 
  FileText, 
  Link, 
  Eye, 
  ChevronDown, 
  ChevronRight,
  Info,
  Loader2
} from 'lucide-react';
import styles from './ValidationPanel.module.css';
import { certificateAPI } from '../../services/api';

const ValidationPanel = ({ certificates = [], onValidationComplete }) => {
  const [validationResults, setValidationResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedValidations, setExpandedValidations] = useState(new Set());

  // Fetch validation results when certificates change
  useEffect(() => {
    if (certificates.length > 0) {
      fetchValidationResults();
    } else {
      setValidationResults(null);
      setError(null);
    }
  }, [certificates]);

  const fetchValidationResults = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      console.log('🔍 ValidationPanel: Fetching validation results...');
      const response = await certificateAPI.getCertificates();
      console.log('📥 ValidationPanel: Received certificates response:', response);
      
      if (response.success && response.validation_results) {
        console.log('📊 ValidationPanel: Found validation results:', response.validation_results);
        
        const backendResults = response.validation_results;
        
        // Filter out bullshit validations and process only PKI relationship validations
        let validations = [];
        
        if (backendResults.validations) {
          if (Array.isArray(backendResults.validations)) {
            validations = backendResults.validations
              .filter(validation => isValidPKIRelationship(validation))
              .map((validation, index) => ({
                isValid: validation.status === 'valid',
                validationType: validation.title || validation.validation_type || `Validation ${index + 1}`,
                description: validation.description || '',
                certificate1: validation.components_involved?.[0] || '',
                certificate2: validation.components_involved?.[1] || '',
                error: validation.error || null,
                details: validation.details || {}
              }));
          } else if (typeof backendResults.validations === 'object') {
            validations = Object.entries(backendResults.validations)
              .filter(([key, validation]) => isValidPKIRelationship(validation, key))
              .map(([key, validation]) => ({
                isValid: validation.status === 'valid',
                validationType: validation.title || formatValidationType(key),
                description: validation.description || '',
                certificate1: validation.components_involved?.[0] || '',
                certificate2: validation.components_involved?.[1] || '',
                error: validation.error || null,
                details: validation.details || {}
              }));
          }
        }
        
        setValidationResults({
          success: true,
          validations: validations,
          overall_status: backendResults.overall_status || 'unknown',
          total_validations: validations.length,
          passed_validations: validations.filter(v => v.isValid).length,
          failed_validations: validations.filter(v => !v.isValid).length
        });
        
        if (onValidationComplete) {
          onValidationComplete(validations);
        }
      } else {
        setValidationResults({
          success: true,
          validations: [],
          overall_status: 'unknown',
          total_validations: 0,
          passed_validations: 0,
          failed_validations: 0
        });
      }
    } catch (err) {
      console.error('💥 ValidationPanel: Error fetching validation results:', err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };



  const formatValidationType = (key) => {
    return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const getTypeIcon = (type) => {
    const typeStr = type?.toLowerCase() || '';
    
    if (typeStr.includes('private key') && typeStr.includes('certificate')) {
      return <Key size={18} className={styles.typeIconCrypto} />;
    }
    if (typeStr.includes('private key') && typeStr.includes('csr')) {
      return <Key size={18} className={styles.typeIconCrypto} />;
    }
    if (typeStr.includes('csr') && typeStr.includes('certificate')) {
      return <FileText size={18} className={styles.typeIconExtension} />;
    }
    if (typeStr.includes('chain') || typeStr.includes('ca')) {
      return <Link size={18} className={styles.typeIconChain} />;
    }
    return <Shield size={18} className={styles.typeIconSecurity} />;
  };

  const getConfidenceBadge = (confidence) => {
    const baseClasses = styles.confidenceBadge;
    const confidenceClasses = {
      high: styles.confidenceHigh,
      medium: styles.confidenceMedium,
      low: styles.confidenceLow
    };
    return `${baseClasses} ${confidenceClasses[confidence] || confidenceClasses.medium}`;
  };

  const getValidationConfidence = (validation) => {
    if (validation.details) {
      const details = validation.details;
      
      // High confidence: Cryptographic key matching validations
      if (details.modulus_match === true || details.exponent_match === true ||
          details.fingerprints_match === true || details.public_key_match === true) {
        return 'high';
      }
      
      // High confidence: Certificate chain validations
      if (details.all_signatures_valid === true || 
          details.trust_chain_complete === true ||
          details.signature_valid === true) {
        return 'high';
      }
      
      // Medium confidence: Partial matches or incomplete data
      if (details.partial_match === true || 
          Object.keys(details).length > 0) {
        return 'medium';
      }
    }
    
    // Low confidence: Failed validations or no details
    return validation.isValid ? 'medium' : 'low';
  };

  const toggleValidation = (validationId) => {
    const newExpanded = new Set(expandedValidations);
    if (newExpanded.has(validationId)) {
      newExpanded.delete(validationId);
    } else {
      newExpanded.add(validationId);
    }
    setExpandedValidations(newExpanded);
  };

  const renderValidationDetails = (validation) => {
    const details = validation.details || {};

    return (
      <div className={styles.detailsContainer}>
        <div className={styles.validationDetailsBox}>
          <h4 className={styles.validationDetailsTitle}>PKI Relationship Details</h4>
          
          {/* Basic validation info */}
          <div className={styles.basicInfoGrid}>
            <div className={styles.basicInfoItem}>
              <span className={styles.basicInfoLabel}>Validation Type:</span>
              <span className={styles.basicInfoValue}>{validation.validationType}</span>
            </div>
            <div className={styles.basicInfoItem}>
              <span className={styles.basicInfoLabel}>Result:</span>
              <span className={`${styles.basicInfoValue} ${validation.isValid ? styles.validText : styles.invalidText}`}>
                {validation.isValid ? 'MATCH' : 'NO MATCH'}
              </span>
            </div>
            {validation.certificate1 && (
              <div className={styles.basicInfoItem}>
                <span className={styles.basicInfoLabel}>Component 1:</span>
                <span className={styles.basicInfoValue}>{validation.certificate1}</span>
              </div>
            )}
            {validation.certificate2 && (
              <div className={styles.basicInfoItem}>
                <span className={styles.basicInfoLabel}>Component 2:</span>
                <span className={styles.basicInfoValue}>{validation.certificate2}</span>
              </div>
            )}
          </div>

          {/* Error information */}
          {validation.error && (
            <div className={styles.errorDetailsBox}>
              <h5 className={styles.errorDetailsTitle}>Validation Error</h5>
              <div className={styles.errorDetailsContent}>
                <AlertTriangle size={16} className={styles.errorDetailsIcon} />
                <span className={styles.errorDetailsText}>{validation.error}</span>
              </div>
            </div>
          )}

          {/* Cryptographic details */}
          {details && Object.keys(details).length > 0 && (
            <div className={styles.technicalDetailsBox}>
              <h5 className={styles.technicalDetailsTitle}>Cryptographic Analysis</h5>
              <div className={styles.technicalDetailsGrid}>
                {Object.entries(details).map(([key, value]) => (
                  <div key={key} className={styles.technicalDetailsItem}>
                    <span className={styles.technicalDetailsLabel}>{key}:</span>
                    <span className={styles.technicalDetailsValue}>
                      {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const getStatusIcon = (isValid) => {
    return isValid ? '✅' : '❌';
  };

  // Loading state
  if (isLoading) {
    return (
      <div className={styles.container}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingContent}>
            <Loader2 size={48} className={styles.loadingIcon} />
            <h3 className={styles.loadingTitle}>Validating PKI Relationships</h3>
            <p className={styles.loadingText}>Analyzing cryptographic component relationships...</p>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className={styles.container}>
        <div className={styles.errorContainer}>
          <div className={styles.errorContent}>
            <AlertTriangle size={48} className={styles.errorIcon} />
            <h3 className={styles.errorTitle}>PKI Validation Error</h3>
            <p className={styles.errorText}>{error}</p>
            <button 
              className={styles.retryButton}
              onClick={fetchValidationResults}
            >
              Retry Validation
            </button>
          </div>
        </div>
      </div>
    );
  }

  // No certificates uploaded
  if (certificates.length === 0) {
    return (
      <div className={styles.container}>
      </div>
    );
  }

  // No validation results yet
  if (!validationResults || !validationResults.validations || validationResults.validations.length === 0) {
    return (
      <div className={styles.container}>
        <div className={styles.noResultsContainer}>
          <div className={styles.noResultsContent}>
            <Shield size={48} className={styles.noResultsIcon} />
            <h3 className={styles.noResultsTitle}>No PKI Relationships Found</h3>
            <p className={styles.noResultsText}>
              {certificates.length === 1 
                ? "Single component uploaded. Upload related components (Private Key, CSR, Certificates, CAs) to validate PKI relationships."
                : "No cryptographic relationships detected between uploaded components."
              }
            </p>
          </div>
        </div>
      </div>
    );
  }

  const validationsArray = validationResults.validations || [];
  const totalValidations = validationsArray.length;
  const passedValidations = validationsArray.filter(v => v.isValid).length;
  const failedValidations = validationsArray.filter(v => !v.isValid).length;

  // PKI is valid if ALL relationship validations pass
  const pkiIsValid = totalValidations > 0 && failedValidations === 0;

  return (
    <div className={styles.container}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerTop}>
          <h2 className={styles.title}>
            <Shield size={24} className={styles.titleIcon} />
            <span>PKI Relationship Validation</span>
          </h2>
          <div className={styles.computedAt}>
            Analyzed: {new Date().toLocaleString()}
          </div>
        </div>

        {/* Overall Status */}
        <div className={styles.statusGrid}>
          <div className={styles.statusCard}>
            <div className={styles.statusNumber}>{totalValidations}</div>
            <div className={styles.statusLabel}>Relationships</div>
          </div>
          <div className={`${styles.statusCard} ${styles.statusCardPassed}`}>
            <div className={styles.statusNumber}>{passedValidations}</div>
            <div className={styles.statusLabel}>Valid</div>
          </div>
          <div className={`${styles.statusCard} ${styles.statusCardFailed}`}>
            <div className={styles.statusNumber}>{failedValidations}</div>
            <div className={styles.statusLabel}>Invalid</div>
          </div>
          <div className={`${styles.statusCard} ${styles.statusCardWarnings}`}>
            <div className={styles.statusNumber}>{Math.round((passedValidations/totalValidations)*100) || 0}%</div>
            <div className={styles.statusLabel}>Success Rate</div>
          </div>
        </div>

        {/* Overall Status Badge */}
        <div className={styles.overallStatusContainer}>
          <div className={`${styles.overallStatusBadge} ${
            pkiIsValid ? styles.overallStatusValid : styles.overallStatusInvalid
          }`}>
            {getStatusIcon(pkiIsValid)}
            <span>PKI {pkiIsValid ? 'Valid' : 'Invalid'}</span>
          </div>
        </div>
      </div>

      {/* Validation Details */}
      <div className={styles.content}>
        <div className={styles.validationsList}>
          {validationsArray.map((validation, index) => {
            const confidence = getValidationConfidence(validation);
            return (
              <div key={validation.validationId || index} className={styles.validationItem}>
                {/* Validation Header */}
                <div 
                  className={styles.validationHeader}
                  onClick={() => toggleValidation(validation.validationId || index)}
                >
                  <div className={styles.validationHeaderContent}>
                    {getTypeIcon(validation.validationType)}
                    <div className={styles.validationHeaderText}>
                      <h3 className={styles.validationTitle}>
                        {validation.validationType}
                      </h3>
                      <p className={styles.validationDescription}>
                        {validation.description || `Cryptographic relationship: ${validation.certificate1 || 'Component'} ↔ ${validation.certificate2 || 'Component'}`}
                      </p>
                    </div>
                  </div>
                  
                  <div className={styles.validationHeaderControls}>
                    <span className={getConfidenceBadge(confidence)}>
                      {confidence} confidence
                    </span>
                    {getStatusIcon(validation.isValid)}
                    {expandedValidations.has(validation.validationId || index) ? (
                      <ChevronDown size={20} className={styles.expandIcon} />
                    ) : (
                      <ChevronRight size={20} className={styles.expandIcon} />
                    )}
                  </div>
                </div>

                {/* Component Pills */}
                <div className={styles.componentPills}>
                  {validation.certificate1 && (
                    <span className={styles.componentPill}>
                      {validation.certificate1}
                    </span>
                  )}
                  {validation.certificate2 && (
                    <span className={styles.componentPill}>
                      {validation.certificate2}
                    </span>
                  )}
                </div>

                {/* Expanded Details */}
                {expandedValidations.has(validation.validationId || index) && (
                  <div className={styles.expandedDetails}>
                    {renderValidationDetails(validation)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Footer */}
      <div className={styles.footer}>
        <div className={styles.footerContent}>
          <span>PKI Validation Engine v2.0</span>
          <div className={styles.footerHint}>
            <Eye size={14} />
            <span>Click relationships to view cryptographic analysis</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ValidationPanel;