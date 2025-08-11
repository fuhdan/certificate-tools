import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  CheckCircle, 
  AlertTriangle, 
  XCircle, 
  Key, 
  FileText, 
  Link, 
  Clock, 
  Eye, 
  ChevronDown, 
  ChevronRight,
  Award,
  AlertCircle,
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
      // The validation results are already included in the certificates response
      const response = await certificateAPI.getCertificates();
      console.log('📥 ValidationPanel: Received certificates response:', response);
      
      if (response.success && response.validation_results) {
        console.log('📊 ValidationPanel: Found validation results:', response.validation_results);
        
        // Transform the backend validation results to frontend format
        const backendResults = response.validation_results;
        const validations = (backendResults.validations || []).map((validation, index) => ({
          isValid: validation.is_valid,
          validationType: validation.validation_type || `Validation ${index + 1}`,
          description: validation.description || '',
          certificate1: validation.certificate_1 || '',
          certificate2: validation.certificate_2 || '',
          error: validation.error || null,
          details: validation.details || {}
        }));
        
        setValidationResults({
          success: true,
          validations: validations,
          overall_status: backendResults.overall_status,
          total_validations: backendResults.total_validations,
          passed_validations: backendResults.passed_validations,
          failed_validations: backendResults.failed_validations
        });
        
        if (onValidationComplete) {
          onValidationComplete(validations);
        }
      } else {
        // No validation results available
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

  const getStatusIcon = (status, confidence = 'medium') => {
    const baseSize = 20;
    switch (status) {
      case 'valid':
      case true:
        return <CheckCircle size={baseSize} className={`${styles.statusIconValid} ${confidence === 'high' ? styles.highConfidence : ''}`} />;
      case 'warning': 
        return <AlertTriangle size={baseSize} className={styles.statusIconWarning} />;
      case 'invalid':
      case false:
        return <XCircle size={baseSize} className={styles.statusIconInvalid} />;
      default:
        return <AlertCircle size={baseSize} className={styles.statusIconDefault} />;
    }
  };

  const getTypeIcon = (type) => {
    // Map validation types from backend to icons
    if (type?.includes('Private Key') && type?.includes('Certificate')) {
      return <Key size={18} className={styles.typeIconCrypto} />;
    }
    if (type?.includes('Private Key') && type?.includes('CSR')) {
      return <Key size={18} className={styles.typeIconCrypto} />;
    }
    if (type?.includes('CSR') && type?.includes('Certificate')) {
      return <FileText size={18} className={styles.typeIconExtension} />;
    }
    if (type?.includes('Chain') || type?.includes('chain')) {
      return <Link size={18} className={styles.typeIconChain} />;
    }
    if (type?.includes('Algorithm') || type?.includes('Strength')) {
      return <Shield size={18} className={styles.typeIconSecurity} />;
    }
    return <Info size={18} className={styles.typeIconDefault} />;
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

  const toggleValidation = (validationId) => {
    const newExpanded = new Set(expandedValidations);
    if (newExpanded.has(validationId)) {
      newExpanded.delete(validationId);
    } else {
      newExpanded.add(validationId);
    }
    setExpandedValidations(newExpanded);
  };

  const formatFingerprint = (fingerprint) => {
    if (!fingerprint) return 'N/A';
    return fingerprint.match(/.{1,4}/g)?.join(' ') || fingerprint;
  };

  const renderValidationDetails = (validation) => {
    const details = validation.details || {};

    return (
      <div className={styles.detailsContainer}>
        <div className={styles.validationDetailsBox}>
          <h4 className={styles.validationDetailsTitle}>Validation Details</h4>
          
          {/* Basic validation info */}
          <div className={styles.basicInfoGrid}>
            <div className={styles.basicInfoItem}>
              <span className={styles.basicInfoLabel}>Validation Type:</span>
              <span className={styles.basicInfoValue}>{validation.validationType || validation.type || 'Unknown'}</span>
            </div>
            <div className={styles.basicInfoItem}>
              <span className={styles.basicInfoLabel}>Result:</span>
              <span className={`${styles.basicInfoValue} ${validation.isValid ? styles.validText : styles.invalidText}`}>
                {validation.isValid ? 'VALID' : 'INVALID'}
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
              <h5 className={styles.errorDetailsTitle}>Error Details</h5>
              <div className={styles.errorDetailsContent}>
                <AlertTriangle size={16} className={styles.errorDetailsIcon} />
                <span className={styles.errorDetailsText}>{validation.error}</span>
              </div>
            </div>
          )}

          {/* Technical details */}
          {details && Object.keys(details).length > 0 && (
            <div className={styles.technicalDetailsBox}>
              <h5 className={styles.technicalDetailsTitle}>Technical Details</h5>
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

  // Loading state
  if (isLoading) {
    return (
      <div className={styles.container}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingContent}>
            <Loader2 size={48} className={styles.loadingIcon} />
            <h3 className={styles.loadingTitle}>Running Validations</h3>
            <p className={styles.loadingText}>Analyzing cryptographic relationships...</p>
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
            <h3 className={styles.errorTitle}>Validation Error</h3>
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
  if (!validationResults || !validationResults.validations) {
    return (
      <div className={styles.container}>
        <div className={styles.noResultsContainer}>
          <div className={styles.noResultsContent}>
            <Shield size={48} className={styles.noResultsIcon} />
            <h3 className={styles.noResultsTitle}>No Validation Results</h3>
            <p className={styles.noResultsText}>
              {certificates.length === 1 
                ? "Single component uploaded. Upload related components to see cryptographic validations."
                : "No validation results available."
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
  const failedValidations = validationsArray.filter(v => !v.isValid && !v.error).length;
  const errorValidations = validationsArray.filter(v => v.error).length;

  return (
    <div className={styles.container}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerTop}>
          <h2 className={styles.title}>
            <Shield size={24} className={styles.titleIcon} />
            <span>PKI Validation Results</span>
          </h2>
          <div className={styles.computedAt}>
            Computed: {new Date().toLocaleString()}
          </div>
        </div>

        {/* Overall Status */}
        <div className={styles.statusGrid}>
          <div className={styles.statusCard}>
            <div className={styles.statusNumber}>{totalValidations}</div>
            <div className={styles.statusLabel}>Total Checks</div>
          </div>
          <div className={`${styles.statusCard} ${styles.statusCardPassed}`}>
            <div className={styles.statusNumber}>{passedValidations}</div>
            <div className={styles.statusLabel}>Passed</div>
          </div>
          <div className={`${styles.statusCard} ${styles.statusCardWarnings}`}>
            <div className={styles.statusNumber}>{errorValidations}</div>
            <div className={styles.statusLabel}>Warnings</div>
          </div>
          <div className={`${styles.statusCard} ${styles.statusCardFailed}`}>
            <div className={styles.statusNumber}>{failedValidations}</div>
            <div className={styles.statusLabel}>Failed</div>
          </div>
        </div>

        {/* Overall Status Badge */}
        <div className={styles.overallStatusContainer}>
          <div className={`${styles.overallStatusBadge} ${
            failedValidations === 0 ? styles.overallStatusValid :
            errorValidations > 0 ? styles.overallStatusWarning :
            styles.overallStatusInvalid
          }`}>
            {getStatusIcon(failedValidations === 0 ? 'valid' : 'invalid', 'high')}
            <span>PKI {failedValidations === 0 ? 'valid' : 'invalid'}</span>
          </div>
        </div>
      </div>

      {/* Validation Details */}
      <div className={styles.content}>
        <div className={styles.validationsList}>
          {validationsArray.map((validation, index) => (
            <div key={validation.validationId || index} className={styles.validationItem}>
              {/* Validation Header */}
              <div 
                className={styles.validationHeader}
                onClick={() => toggleValidation(validation.validationId || index)}
              >
                <div className={styles.validationHeaderContent}>
                  {getTypeIcon(validation.validationType || validation.type)}
                  <div className={styles.validationHeaderText}>
                    <h3 className={styles.validationTitle}>
                      {validation.validationType || validation.type || 'Unknown Validation'}
                    </h3>
                    <p className={styles.validationDescription}>
                      {validation.description || `${validation.certificate1 || 'Component'} → ${validation.certificate2 || 'Component'}`}
                    </p>
                  </div>
                </div>
                
                <div className={styles.validationHeaderControls}>
                  <span className={getConfidenceBadge('medium')}>
                    medium confidence
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
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className={styles.footer}>
        <div className={styles.footerContent}>
          <span>Validation Engine v2.0</span>
          <div className={styles.footerHint}>
            <Eye size={14} />
            <span>Click validations to view detailed analysis</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ValidationPanel;