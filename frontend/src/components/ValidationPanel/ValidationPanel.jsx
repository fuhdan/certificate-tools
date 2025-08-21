import React, { useState, useEffect } from 'react';
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

// Import comprehensive logging for validation panel
import {
  validationPanelError,
  validationPanelWarn,
  validationPanelInfo,
  validationPanelDebug,
  validationPanelLifecycle,
  validationPanelValidation,
  validationPanelFiltering,
  validationPanelPKI,
  validationPanelInteraction,
  validationPanelState,
  validationPanelRender,
  validationPanelAPI,
  validationPanelCryptography,
  validationPanelPerformance,
  validationPanelSecurity,
  time,
  timeEnd
} from '@/utils/logger'

const isValidPKIRelationship = (validation, key = '') => {
  time('ValidationPanel.pki_filter_check')
  
  const validationType = (validation.title || validation.validation_type || key || '').toLowerCase();
  
  validationPanelFiltering('PKI_RELATIONSHIP_CHECK', {
    input_count: 1,
    validation_type: validationType,
    validation_key: key
  })
  
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
  
  const isValid = hasAllowedType && !hasExcludedType;
  
  validationPanelFiltering('PKI_RELATIONSHIP_RESULT', {
    output_count: isValid ? 1 : 0,
    criteria: 'pki_relationships_only',
    has_allowed_type: hasAllowedType,
    has_excluded_type: hasExcludedType,
    allowed_types_matched: allowedTypes.filter(type => validationType.includes(type)),
    excluded_types_matched: excludedTypes.filter(type => validationType.includes(type))
  })
  
  timeEnd('ValidationPanel.pki_filter_check')
  return isValid;
};

const ValidationPanel = ({ certificates = [], onValidationComplete }) => {
  const [validationResults, setValidationResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedValidations, setExpandedValidations] = useState(new Set());

  // Log component lifecycle
  useEffect(() => {
    time('ValidationPanel.component_initialization')
    
    validationPanelLifecycle('COMPONENT_MOUNT', {
      initial_certificate_count: certificates?.length || 0,
      has_validation_callback: !!onValidationComplete,
      component_name: 'ValidationPanel'
    })

    timeEnd('ValidationPanel.component_initialization')

    return () => {
      validationPanelLifecycle('COMPONENT_UNMOUNT', {
        final_validation_results: !!validationResults,
        final_certificate_count: certificates?.length || 0,
        expanded_validations_count: expandedValidations.size
      })
    }
  }, [])

  // FIXED: Fetch validation results when certificates change (including deletions)
  useEffect(() => {
    time('ValidationPanel.certificate_change_handler')
    
    validationPanelState('CERTIFICATES_CHANGED', certificates, {
      certificate_count: certificates?.length || 0,
      certificate_filenames: certificates?.map(c => c.filename) || [],
      change_trigger: 'useEffect_dependency'
    })
    
    validationPanelInfo('🔄 ValidationPanel: Certificates changed:', certificates?.length, certificates?.map(c => c.filename));
    
    validationPanelValidation('VALIDATION_REFRESH_TRIGGERED', certificates, {
      trigger_reason: 'certificate_change',
      will_clear_results: true,
      will_fetch_new: true
    })
    
    validationPanelInfo('🔍 ValidationPanel: Fetching validation results...');
    setValidationResults(null);
    fetchValidationResults();

    timeEnd('ValidationPanel.certificate_change_handler')
  }, [certificates]);

  const fetchValidationResults = async () => {
    time('ValidationPanel.fetch_validation_results')
    
    validationPanelAPI('FETCH_START', {
      loading_state: true,
      error_cleared: true
    })

    setIsLoading(true);
    setError(null);
    
    try {
      validationPanelAPI('API_REQUEST_START', {
        endpoint: 'getCertificates',
        request_type: 'validation_results'
      })

      validationPanelInfo('🔍 ValidationPanel: Fetching validation results...');
      const response = await certificateAPI.getCertificates();
      
      validationPanelAPI('API_RESPONSE_RECEIVED', {
        success: response.success,
        has_validation_results: !!response.validation_results,
        response_keys: Object.keys(response)
      })

      validationPanelInfo('📥 ValidationPanel: Received certificates response:', response);
      
      if (response.success && response.validation_results) {
        time('ValidationPanel.process_validation_results')
        
        validationPanelValidation('BACKEND_RESULTS_RECEIVED', response.validation_results, {
          has_validations: !!response.validation_results.validations,
          overall_status: response.validation_results.overall_status
        })

        validationPanelInfo('📊 ValidationPanel: Found validation results:', response.validation_results);
        
        const backendResults = response.validation_results;
        
        // Filter out bullshit validations and process only PKI relationship validations
        let validations = [];
        
        if (backendResults.validations) {
          validationPanelFiltering('RAW_VALIDATIONS_PROCESSING', {
            input_count: Array.isArray(backendResults.validations) ? backendResults.validations.length : Object.keys(backendResults.validations).length,
            validation_type: Array.isArray(backendResults.validations) ? 'array' : 'object'
          })

          validationPanelInfo('🔍 Raw backend validations:', backendResults.validations);
          
          if (Array.isArray(backendResults.validations)) {
            validations = backendResults.validations
              .filter(validation => {
                const isValid = isValidPKIRelationship(validation)
                validationPanelFiltering('VALIDATION_FILTER_CHECK', {
                  validation_title: validation.title,
                  validation_type: validation.validation_type,
                  is_valid_pki: isValid
                })
                return isValid
              })
              .map((validation, index) => {
                validationPanelValidation('VALIDATION_PROCESSING', validation, {
                  processing_index: index,
                  validation_status: validation.status,
                  has_details: !!validation.details,
                  components_count: validation.components_involved?.length || 0
                })

                validationPanelInfo(`🔍 Processing validation ${index}:`, validation);
                validationPanelDebug(`🔍 Validation details (full object):`, JSON.stringify(validation.details, null, 2));
                
                return {
                  isValid: validation.status === 'valid',
                  validationType: validation.title || validation.validation_type || `Validation ${index + 1}`,
                  description: validation.description || '',
                  certificate1: validation.components_involved?.[0] || '',
                  certificate2: validation.components_involved?.[1] || '',
                  error: validation.error || null,
                  details: validation.details || {}
                };
              });
          } else if (typeof backendResults.validations === 'object') {
            validationPanelInfo('🔍 Raw backend validations (object):', backendResults.validations);
            validations = Object.entries(backendResults.validations)
              .filter(([key, validation]) => {
                const isValid = isValidPKIRelationship(validation, key)
                validationPanelFiltering('VALIDATION_OBJECT_FILTER_CHECK', {
                  validation_key: key,
                  validation_title: validation.title,
                  is_valid_pki: isValid
                })
                return isValid
              })
              .map(([key, validation]) => {
                validationPanelValidation('VALIDATION_OBJECT_PROCESSING', validation, {
                  validation_key: key,
                  validation_status: validation.status,
                  has_details: !!validation.details,
                  components_count: validation.components_involved?.length || 0
                })

                validationPanelInfo(`🔍 Processing validation ${key}:`, validation);
                validationPanelDebug(`🔍 Validation details (full object):`, JSON.stringify(validation.details, null, 2));
                
                return {
                  isValid: validation.status === 'valid',
                  validationType: validation.title || formatValidationType(key),
                  description: validation.description || '',
                  certificate1: validation.components_involved?.[0] || '',
                  certificate2: validation.components_involved?.[1] || '',
                  error: validation.error || null,
                  details: validation.details || {}
                };
              });
          }
        }
        
        const processedResults = {
          success: true,
          validations: validations,
          overall_status: backendResults.overall_status || 'unknown',
          total_validations: validations.length,
          passed_validations: validations.filter(v => v.isValid).length,
          failed_validations: validations.filter(v => !v.isValid).length
        }

        validationPanelValidation('VALIDATION_RESULTS_PROCESSED', processedResults, {
          processing_complete: true,
          success_rate: processedResults.passed_validations / processedResults.total_validations * 100 || 0
        })

        validationPanelPKI('PKI_ANALYSIS_COMPLETE', {
          is_valid: processedResults.failed_validations === 0 && processedResults.total_validations > 0,
          relationship_count: processedResults.total_validations,
          component_types: validations.map(v => v.validationType)
        })
        
        setValidationResults(processedResults);
        
        if (onValidationComplete) {
          validationPanelValidation('VALIDATION_CALLBACK_INVOKED', validations, {
            callback_provided: true,
            validation_count: validations.length
          })
          onValidationComplete(validations);
        }

        timeEnd('ValidationPanel.process_validation_results')
      } else {
        // FIXED: Clear validation results when no validation data is available
        validationPanelValidation('NO_VALIDATION_RESULTS', [], {
          clearing_results: true,
          response_success: response.success,
          has_validation_results: !!response.validation_results
        })

        validationPanelInfo('📊 ValidationPanel: No validation results found, clearing display');
        
        const emptyResults = {
          success: true,
          validations: [],
          overall_status: 'unknown',
          total_validations: 0,
          passed_validations: 0,
          failed_validations: 0
        }

        setValidationResults(emptyResults);
      }
    } catch (err) {
      validationPanelError('Error fetching validation results', {
        error_message: err.message,
        error_stack: err.stack,
        api_call_failed: true
      })

      console.error('💥 ValidationPanel: Error fetching validation results:', err);
      setError(err.message);
    } finally {
      validationPanelAPI('FETCH_COMPLETE', {
        loading_state: false,
        has_error: !!error
      })

      setIsLoading(false);
      timeEnd('ValidationPanel.fetch_validation_results')
    }
  };

  const formatValidationType = (key) => {
    const formatted = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    
    validationPanelDebug('Validation type formatted', {
      original_key: key,
      formatted_type: formatted
    })

    return formatted
  };

  const getTypeIcon = (type) => {
    const typeStr = type?.toLowerCase() || '';
    
    let icon
    let iconType

    if (typeStr.includes('private key') && typeStr.includes('certificate')) {
      icon = <Key size={18} className={styles.typeIconCrypto} />
      iconType = 'private_key_certificate'
    } else if (typeStr.includes('private key') && typeStr.includes('csr')) {
      icon = <Key size={18} className={styles.typeIconCrypto} />
      iconType = 'private_key_csr'
    } else if (typeStr.includes('csr') && typeStr.includes('certificate')) {
      icon = <FileText size={18} className={styles.typeIconExtension} />
      iconType = 'csr_certificate'
    } else if (typeStr.includes('chain') || typeStr.includes('ca')) {
      icon = <Link size={18} className={styles.typeIconChain} />
      iconType = 'chain_ca'
    } else {
      icon = <Shield size={18} className={styles.typeIconSecurity} />
      iconType = 'security_general'
    }

    validationPanelRender('TYPE_ICON_SELECTED', {
      validation_type: type,
      icon_type: iconType
    })

    return icon
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
    time('ValidationPanel.confidence_calculation')

    let confidence = 'medium'
    let confidenceFactors = []

    if (validation.details) {
      const details = validation.details;
      
      // High confidence: Cryptographic key matching validations
      if (details.modulus_match === true || details.exponent_match === true ||
          details.fingerprints_match === true || details.public_key_match === true) {
        confidence = 'high'
        confidenceFactors.push('cryptographic_match')
      }
      
      // High confidence: Certificate chain validations
      else if (details.all_signatures_valid === true || 
          details.trust_chain_complete === true ||
          details.signature_valid === true) {
        confidence = 'high'
        confidenceFactors.push('chain_validation')
      }
      
      // Medium confidence: Partial matches or incomplete data
      else if (details.partial_match === true || 
          Object.keys(details).length > 0) {
        confidence = 'medium'
        confidenceFactors.push('partial_data')
      }
    }
    
    // Low confidence: Failed validations or no details
    if (!validation.isValid) {
      confidence = 'low'
      confidenceFactors.push('validation_failed')
    }

    validationPanelSecurity('CONFIDENCE_CALCULATED', {
      level: confidence,
      validation_confidence: confidence,
      confidence_factors: confidenceFactors,
      has_details: !!validation.details,
      validation_valid: validation.isValid
    })

    timeEnd('ValidationPanel.confidence_calculation')
    return confidence
  };

  const toggleValidation = (validationId) => {
    validationPanelInteraction('VALIDATION_TOGGLE', {
      validation_id: validationId,
      current_expanded_count: expandedValidations.size,
      action: expandedValidations.has(validationId) ? 'collapse' : 'expand'
    })

    const newExpanded = new Set(expandedValidations);
    if (newExpanded.has(validationId)) {
      newExpanded.delete(validationId);
    } else {
      newExpanded.add(validationId);
    }
    
    validationPanelState('EXPANDED_VALIDATIONS_CHANGED', newExpanded, {
      expanded_count: newExpanded.size,
      validation_id: validationId
    })

    setExpandedValidations(newExpanded);
  };

  // Helper function to render fingerprint information using existing styles
  const renderFingerprintDetails = (fingerprintData) => {
    if (!fingerprintData || typeof fingerprintData !== 'object') return null;
    
    validationPanelCryptography('FINGERPRINT_RENDER', {
      fingerprint_matches: fingerprintData.match,
      has_csr: !!fingerprintData.csr,
      has_certificate: !!fingerprintData.certificate
    })
    
    return (
      <div className={styles.basicInfoGrid}>
        <div className={styles.basicInfoItem} style={{ gridColumn: '1 / -1', marginBottom: '0.5rem' }}>
          <span className={styles.basicInfoLabel} style={{ color: '#1e40af', fontWeight: 'bold' }}>
            Public Key Fingerprints (SHA256):
          </span>
        </div>
        {fingerprintData.csr && (
          <div className={styles.basicInfoItem}>
            <span className={styles.basicInfoLabel}>CSR:</span>
            <span className={`${styles.basicInfoValue} ${styles.technicalDetailsValue}`} style={{ fontFamily: 'Monaco, Menlo, monospace', fontSize: '0.8rem' }}>
              {fingerprintData.csr}
            </span>
          </div>
        )}
        {fingerprintData.certificate && (
          <div className={styles.basicInfoItem}>
            <span className={styles.basicInfoLabel}>Certificate:</span>
            <span className={`${styles.basicInfoValue} ${styles.technicalDetailsValue}`} style={{ fontFamily: 'Monaco, Menlo, monospace', fontSize: '0.8rem' }}>
              {fingerprintData.certificate}
            </span>
          </div>
        )}
        <div className={styles.basicInfoItem}>
          <span className={styles.basicInfoLabel}>Match:</span>
          <span className={`${styles.basicInfoValue} ${fingerprintData.match ? styles.validText : styles.invalidText}`} style={{ fontWeight: 'bold' }}>
            {fingerprintData.match ? '✅ Yes' : '❌ No'}
          </span>
        </div>
      </div>
    );
  };

  // Helper function to detect and render individual fingerprint fields  
  const renderIndividualFingerprints = (details, validationType) => {
    time('ValidationPanel.individual_fingerprints_render')
    
    validationPanelDebug('🔍 Checking for individual fingerprints in:', details);
    
    // Check if this validation has fingerprint data using specific patterns
    const fingerprintPairs = [];
    
    // Pattern 1: Private Key ↔ Certificate
    if (details.private_key_fingerprint && details.certificate_public_key_fingerprint) {
      validationPanelDebug('🔍 Found Private Key ↔ Certificate fingerprints:', details.private_key_fingerprint, details.certificate_public_key_fingerprint);
      fingerprintPairs.push({
        label1: 'Private Key',
        value1: details.private_key_fingerprint,
        label2: 'Certificate Public Key',
        value2: details.certificate_public_key_fingerprint,
        match: details.fingerprints_match
      });
    }
    
    // Pattern 2: Private Key ↔ CSR
    if (details.private_key_fingerprint && details.csr_public_key_fingerprint) {
      validationPanelDebug('🔍 Found Private Key ↔ CSR fingerprints:', details.private_key_fingerprint, details.csr_public_key_fingerprint);
      fingerprintPairs.push({
        label1: 'Private Key',
        value1: details.private_key_fingerprint,
        label2: 'CSR Public Key',
        value2: details.csr_public_key_fingerprint,
        match: details.fingerprints_match
      });
    }
    
    // Pattern 3: CSR ↔ Certificate
    if (details.csr_public_key_fingerprint && details.certificate_public_key_fingerprint) {
      validationPanelDebug('🔍 Found CSR ↔ Certificate fingerprints:', details.csr_public_key_fingerprint, details.certificate_public_key_fingerprint);
      fingerprintPairs.push({
        label1: 'CSR Public Key',
        value1: details.csr_public_key_fingerprint,
        label2: 'Certificate Public Key',
        value2: details.certificate_public_key_fingerprint,
        match: details.fingerprints_match
      });
    }

    validationPanelCryptography('INDIVIDUAL_FINGERPRINTS_PROCESSED', {
      fingerprint_pairs_found: fingerprintPairs.length,
      validation_type: validationType,
      patterns_detected: fingerprintPairs.map(p => `${p.label1}_to_${p.label2}`)
    })

    timeEnd('ValidationPanel.individual_fingerprints_render')
    
    if (fingerprintPairs.length === 0) return null;
    
    return fingerprintPairs.map((pair, index) => (
      <div key={index} className={styles.basicInfoGrid} style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(59, 130, 246, 0.05)', borderRadius: '8px' }}>
        <div className={styles.basicInfoItem} style={{ gridColumn: '1 / -1', marginBottom: '0.5rem' }}>
          <span className={styles.basicInfoLabel} style={{ color: '#1e40af', fontWeight: 'bold' }}>
            Public Key Fingerprints (SHA256):
          </span>
        </div>
        <div className={styles.basicInfoItem}>
          <span className={styles.basicInfoLabel}>{pair.label1}:</span>
          <span className={`${styles.basicInfoValue} ${styles.technicalDetailsValue}`} style={{ fontFamily: 'Monaco, Menlo, monospace', fontSize: '0.8rem' }}>
            {pair.value1}
          </span>
        </div>
        <div className={styles.basicInfoItem}>
          <span className={styles.basicInfoLabel}>{pair.label2}:</span>
          <span className={`${styles.basicInfoValue} ${styles.technicalDetailsValue}`} style={{ fontFamily: 'Monaco, Menlo, monospace', fontSize: '0.8rem' }}>
            {pair.value2}
          </span>
        </div>
        <div className={styles.basicInfoItem}>
          <span className={styles.basicInfoLabel}>Match:</span>
          <span className={`${styles.basicInfoValue} ${pair.match ? styles.validText : styles.invalidText}`} style={{ fontWeight: 'bold' }}>
            {pair.match ? '✅ Yes' : '❌ No'}
          </span>
        </div>
      </div>
    ));
  };

  // Helper function to render detailed value based on type using existing styles
  const renderDetailValue = (key, value) => {
    validationPanelDebug(`🔍 renderDetailValue called with key: "${key}", value:`, value, typeof value);
    
    validationPanelRender('DETAIL_VALUE_RENDER', {
      detail_key: key,
      value_type: typeof value,
      is_fingerprint_object: key === 'fingerprint' && typeof value === 'object'
    })
    
    if (key === 'fingerprint' && typeof value === 'object') {
      validationPanelDebug('🎯 Found fingerprint object!', value);
      return renderFingerprintDetails(value);
    }
    
    if (typeof value === 'object') {
      return (
        <pre style={{ 
          fontFamily: 'Monaco, Menlo, monospace', 
          fontSize: '0.8rem',
          background: 'rgba(0, 0, 0, 0.05)',
          padding: '0.5rem',
          borderRadius: '4px',
          margin: 0,
          overflowX: 'auto',
          whiteSpace: 'pre-wrap'
        }}>
          {JSON.stringify(value, null, 2)}
        </pre>
      );
    }
    
    return String(value);
  };

  const renderValidationDetails = (validation) => {
    time('ValidationPanel.validation_details_render')
    
    const details = validation.details || {};

    validationPanelRender('VALIDATION_DETAILS_RENDER', {
      validation_type: validation.validationType,
      has_details: Object.keys(details).length > 0,
      has_error: !!validation.error,
      detail_keys: Object.keys(details)
    })

    const detailsJSX = (
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
              
              {/* Check for individual fingerprint fields and render them specially */}
              {renderIndividualFingerprints(details, validation.validationType)}
              
              <div className={styles.technicalDetailsGrid}>
                {Object.entries(details)
                  .filter(([key, value]) => {
                    // Hide fingerprint fields since we render them specially above
                    if (key.includes('fingerprint') || key === 'fingerprints_match' || key === 'public_key_match') {
                      return false;
                    }
                    
                    // For Certificate ↔ CSR Match, exclude verbose subject/SAN fields since they're redundant
                    if (validation.validationType.includes('Certificate') && validation.validationType.includes('CSR')) {
                      const excludedFields = ['certificate_subject', 'csr_subject', 'certificate_sans', 'csr_sans'];
                      if (excludedFields.includes(key)) {
                        return false;
                      }
                    }
                    
                    return true;
                  })
                  .map(([key, value]) => {
                    validationPanelDebug(`🔍 Rendering detail: ${key}:`, value, typeof value);
                    return (
                      <div key={key} className={styles.technicalDetailsItem}>
                        <span className={styles.technicalDetailsLabel}>{key}:</span>
                        <span className={styles.technicalDetailsValue}>
                          {renderDetailValue(key, value)}
                        </span>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}
        </div>
      </div>
    );

    timeEnd('ValidationPanel.validation_details_render')
    return detailsJSX
  };

  const getStatusIcon = (isValid) => {
    return isValid ? '✅' : '❌';
  };

  // Log state changes
  useEffect(() => {
    validationPanelState('VALIDATION_RESULTS_CHANGED', validationResults, {
      has_results: !!validationResults,
      validation_count: validationResults?.validations?.length || 0,
      overall_status: validationResults?.overall_status
    })
  }, [validationResults])

  useEffect(() => {
    validationPanelState('LOADING_STATE_CHANGED', { isLoading }, {
      loading: isLoading
    })
  }, [isLoading])

  useEffect(() => {
    validationPanelState('ERROR_STATE_CHANGED', { error }, {
      has_error: !!error,
      error_message: error
    })
  }, [error])

  // Loading state
  if (isLoading) {
    validationPanelRender('LOADING_STATE_RENDER', {
      render_type: 'loading'
    })

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
  };

  // Error state
  if (error) {
    validationPanelRender('ERROR_STATE_RENDER', {
      render_type: 'error',
      error_message: error
    })

    return (
      <div className={styles.container}>
        <div className={styles.errorContainer}>
          <div className={styles.errorContent}>
            <AlertTriangle size={48} className={styles.errorIcon} />
            <h3 className={styles.errorTitle}>PKI Validation Error</h3>
            <p className={styles.errorText}>{error}</p>
            <button 
              className={styles.retryButton}
              onClick={() => {
                validationPanelInteraction('RETRY_BUTTON_CLICK', {
                  previous_error: error
                })
                fetchValidationResults()
              }}
            >
              Retry Validation
            </button>
          </div>
        </div>
      </div>
    );
  }

  // FIXED: No certificates uploaded - show appropriate empty state
  if (certificates.length === 0) {
    validationPanelRender('NO_CERTIFICATES_RENDER', {
      render_type: 'no_certificates',
      certificate_count: 0
    })

    return (
      <div className={styles.container}>
        <div className={styles.noResultsContainer}>
          <div className={styles.noResultsContent}>
            <Shield size={48} className={styles.noResultsIcon} />
            <h3 className={styles.noResultsTitle}>No PKI Components</h3>
            <p className={styles.noResultsText}>
              Upload PKI components (Private Keys, CSRs, Certificates, CAs) to validate cryptographic relationships.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // No validation results yet
  if (!validationResults || !validationResults.validations || validationResults.validations.length === 0) {
    validationPanelRender('NO_RESULTS_RENDER', {
      render_type: 'no_results',
      certificate_count: certificates.length,
      has_validation_results: !!validationResults
    })

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

  validationPanelPKI('PKI_STATUS_CALCULATED', {
    is_valid: pkiIsValid,
    relationship_count: totalValidations,
    passed_count: passedValidations,
    failed_count: failedValidations,
    success_rate: Math.round((passedValidations/totalValidations)*100) || 0
  })

  validationPanelRender('MAIN_VALIDATION_RENDER', {
    render_type: 'validation_panel',
    total_validations: totalValidations,
    pki_valid: pkiIsValid,
    expanded_validations: expandedValidations.size
  })

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
            const validationId = validation.validationId || index;
            
            validationPanelRender('VALIDATION_ITEM_RENDER', {
              validation_index: index,
              validation_type: validation.validationType,
              validation_valid: validation.isValid,
              confidence_level: confidence,
              is_expanded: expandedValidations.has(validationId)
            })

            return (
              <div key={validationId} className={styles.validationItem}>
                {/* Validation Header */}
                <div 
                  className={styles.validationHeader}
                  onClick={() => {
                    validationPanelInteraction('VALIDATION_HEADER_CLICK', {
                      validation_id: validationId,
                      validation_type: validation.validationType,
                      will_toggle: true
                    })
                    toggleValidation(validationId)
                  }}
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
                    {expandedValidations.has(validationId) ? (
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
                {expandedValidations.has(validationId) && (
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