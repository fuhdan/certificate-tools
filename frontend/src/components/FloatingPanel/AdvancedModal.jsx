// frontend/src/components/FloatingPanel/AdvancedModal.jsx
// ENHANCED WITH COMPREHENSIVE DOWNLOAD MODAL LOGGING

import React, { useState, useMemo, useEffect } from 'react'
import { X, Download, FileText, Key, Package, AlertCircle, CheckSquare, Square } from 'lucide-react'
import styles from './AdvancedModal.module.css'
import SecurePasswordModal from './SecurePasswordModal'
import { useCertificates } from '../../contexts/CertificateContext'
import { downloadAPI } from '../../services/api'

// Import comprehensive logging system
import {
  downloadModalError,
  downloadModalWarn,
  downloadModalInfo,
  downloadModalDebug,
  downloadModalLifecycle,
  downloadModalSelection,
  downloadModalFormat,
  downloadModalOperation,
  downloadModalRequirement,
  downloadModalQuickAction
} from '../../utils/logger'

const AdvancedModal = ({ onClose }) => {
  const { certificates } = useCertificates()
  
  // State for component and format selections
  const [selectedComponents, setSelectedComponents] = useState(new Set())
  const [formatSelections, setFormatSelections] = useState({})
  
  // State for download process
  const [isDownloading, setIsDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState(null)
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [downloadResult, setDownloadResult] = useState(null)

  const [pkcs7Format, setPkcs7Format] = useState('pem')
  const [pkcs12Format, setPkcs12Format] = useState('encrypted')

  // Component lifecycle logging
  useEffect(() => {
    downloadModalLifecycle('MOUNT', {
      certificates_count: certificates?.length || 0,
      has_certificates: !!certificates && certificates.length > 0
    })

    return () => {
      downloadModalLifecycle('UNMOUNT', {
        selected_components: selectedComponents.size,
        was_downloading: isDownloading,
        had_error: !!downloadError
      })
    }
  }, [])

  // Log state changes
  useEffect(() => {
    downloadModalSelection('COMPONENTS_CHANGED', {
      selected_count: selectedComponents.size,
      selected_ids: Array.from(selectedComponents),
      total_available: certificates?.length || 0
    })
  }, [selectedComponents])

  useEffect(() => {
    downloadModalFormat('FORMATS_CHANGED', {
      format_count: Object.keys(formatSelections).length,
      formats: formatSelections
    })
  }, [formatSelections])

  useEffect(() => {
    if (downloadError) {
      downloadModalError('Download error set', {
        error_message: downloadError
      })
    }
  }, [downloadError])

  useEffect(() => {
    downloadModalDebug('Download state changed', {
      is_downloading: isDownloading,
      has_error: !!downloadError,
      show_password_modal: showPasswordModal,
      has_download_result: !!downloadResult
    })
  }, [isDownloading, downloadError, showPasswordModal, downloadResult])

  // Get format options for component types
  const getFormatOptions = (componentType) => {
    downloadModalDebug('Getting format options', {
      component_type: componentType
    })

    if (componentType === 'PrivateKey') {
      return [
        { value: 'pem', label: 'PEM (Unencrypted)', description: 'Base64 encoded, unencrypted' },
        { value: 'der', label: 'DER (Unencrypted)', description: 'Binary encoded, unencrypted' },
        { value: 'pkcs8', label: 'PKCS#8 (Unencrypted)', description: 'Standard format, unencrypted' },
        { value: 'pkcs8_encrypted', label: 'PKCS#8 (Encrypted)', description: 'Password-protected PKCS#8' },
        { value: 'pem_encrypted', label: 'PEM (Encrypted)', description: 'Password-protected PEM' }
      ]
    } else if (componentType === 'CSR') {
      return [
        { value: 'pem', label: 'PEM', description: 'Base64 encoded text format' },
        { value: 'der', label: 'DER', description: 'Binary encoded format' }
      ]
    } else {
      // Certificates (all types)
      return [
        { value: 'pem', label: 'PEM', description: 'Base64 encoded text format' },
        { value: 'der', label: 'DER', description: 'Binary encoded format' }
      ]
    }
  }

  // Get icon for component type
  const getComponentIcon = (type) => {
    switch (type) {
      case 'PrivateKey':
        return <Key size={16} />
      case 'CSR':
        return <FileText size={16} />
      case 'Certificate':
      case 'RootCA':
      case 'IntermediateCA':
      case 'IssuingCA':
        return <Package size={16} />
      default:
        downloadModalWarn('Unknown component type for icon', {
          type,
          fallback_icon: 'FileText'
        })
        return <FileText size={16} />
    }
  }

  // Get component display name - Return component type names instead of filenames
  const getComponentDisplayName = (component) => {
    switch (component.type) {
      case 'Certificate':
        return 'Certificate'
      case 'CSR':
        return 'Certificate Signing Request'  
      case 'PrivateKey':
        return 'Private Key'
      case 'IssuingCA':
        return 'Issuing CA'
      case 'IntermediateCA':
        return 'Intermediate CA'
      case 'RootCA':
        return 'Root CA'
      default:
        downloadModalWarn('Unknown component type for display name', {
          type: component.type,
          fallback: component.type
        })
        return component.type
    }
  }

  // Handle component selection toggle
  const handleComponentToggle = (componentId) => {
    downloadModalSelection('TOGGLE_COMPONENT', {
      component_id: componentId,
      current_selected: selectedComponents.has(componentId),
      total_selected_before: selectedComponents.size
    })

    const newSelected = new Set(selectedComponents)
    if (newSelected.has(componentId)) {
      newSelected.delete(componentId)
      // Remove format selection when deselecting
      const newFormats = { ...formatSelections }
      delete newFormats[componentId]
      setFormatSelections(newFormats)

      downloadModalFormat('FORMAT_REMOVED', {
        component_id: componentId,
        remaining_formats: Object.keys(newFormats).length
      })
    } else {
      newSelected.add(componentId)
      // Set default format when selecting
      const component = certificates.find(c => c.id === componentId)
      if (component) {
        setFormatSelections(prev => ({
          ...prev,
          [componentId]: 'pem' // Default to PEM
        }))

        downloadModalFormat('FORMAT_SET_DEFAULT', {
          component_id: componentId,
          component_type: component.type,
          default_format: 'pem'
        })
      }
    }
    setSelectedComponents(newSelected)
  }

  // Handle format change for a component
  const handleFormatChange = (componentId, format) => {
    downloadModalFormat('FORMAT_CHANGED', {
      component_id: componentId,
      old_format: formatSelections[componentId],
      new_format: format
    })

    setFormatSelections(prev => ({
      ...prev,
      [componentId]: format
    }))
  }

  // Handle select all / deselect all
  const handleSelectAll = () => {
    const isSelectingAll = selectedComponents.size !== certificates.length

    downloadModalSelection('SELECT_ALL_TOGGLE', {
      action: isSelectingAll ? 'select_all' : 'deselect_all',
      current_selected: selectedComponents.size,
      total_available: certificates.length
    })

    if (selectedComponents.size === certificates.length) {
      // Deselect all
      setSelectedComponents(new Set())
      setFormatSelections({})
      downloadModalFormat('ALL_FORMATS_CLEARED', {
        cleared_count: Object.keys(formatSelections).length
      })
    } else {
      // Select all
      const allIds = certificates.map(c => c.id)
      setSelectedComponents(new Set(allIds))
      
      // Set default formats for all
      const defaultFormats = {}
      certificates.forEach(cert => {
        defaultFormats[cert.id] = 'pem'
      })
      setFormatSelections(defaultFormats)
      downloadModalFormat('ALL_FORMATS_SET_DEFAULT', {
        components_count: certificates.length,
        default_format: 'pem'
      })
    }
  }

  // Check bundle requirements
  const getBundleRequirements = () => {
    downloadModalRequirement('CHECKING_REQUIREMENTS', {
      certificates_count: certificates?.length || 0
    })

    const hasEndEntityCert = certificates.some(c => c.type === 'Certificate')
    const hasPrivateKey = certificates.some(c => c.type === 'PrivateKey')
    const hasCACerts = certificates.some(c => 
      c.type === 'RootCA' || c.type === 'IntermediateCA' || c.type === 'IssuingCA'
    )
    
    const requirements = {
      apache: {
        enabled: hasEndEntityCert && hasPrivateKey,
        tooltip: hasEndEntityCert && hasPrivateKey 
          ? "Download Apache/NGINX bundle" 
          : `Missing: ${!hasEndEntityCert ? 'End-entity Certificate' : ''} ${!hasPrivateKey ? 'Private Key' : ''}`.trim()
      },
      iis: {
        enabled: hasEndEntityCert && hasPrivateKey && hasCACerts,
        tooltip: hasEndEntityCert && hasPrivateKey && hasCACerts
          ? "Download IIS PKCS#12 bundle"
          : `Missing: ${!hasEndEntityCert ? 'End-entity Certificate' : ''} ${!hasPrivateKey ? 'Private Key' : ''} ${!hasCACerts ? 'CA Certificate Chain' : ''}`.trim()
      },
      pkcs7: {
        enabled: hasEndEntityCert && hasCACerts,
        tooltip: hasEndEntityCert && hasCACerts
          ? "Download PKCS#7 certificate chain"
          : `Missing: ${!hasEndEntityCert ? 'End-entity Certificate' : ''} ${!hasCACerts ? 'CA Certificates' : ''}`.trim()
      },
      pkcs12: {
        enabled: hasEndEntityCert && hasPrivateKey,
        tooltip: hasEndEntityCert && hasPrivateKey
          ? "Download PKCS#12 bundle with certificate and private key"
          : `Missing: ${!hasEndEntityCert ? 'End-entity Certificate' : ''} ${!hasPrivateKey ? 'Private Key' : ''}`.trim()
      },
      privateKey: {
        enabled: hasPrivateKey,
        tooltip: hasPrivateKey ? "Download private key" : "Missing: Private Key"
      },
      certificate: {
        enabled: hasEndEntityCert,
        tooltip: hasEndEntityCert ? "Download end-entity certificate" : "Missing: End-entity Certificate"
      },
      chain: {
        enabled: hasCACerts,
        tooltip: hasCACerts ? "Download CA certificate chain" : "Missing: CA Certificates"
      }
    }

    downloadModalRequirement('REQUIREMENTS_CALCULATED', {
      has_end_entity_cert: hasEndEntityCert,
      has_private_key: hasPrivateKey,
      has_ca_certs: hasCACerts,
      enabled_bundles: Object.entries(requirements).filter(([, req]) => req.enabled).map(([name]) => name)
    })
    
    return requirements
  }

  const bundleReqs = getBundleRequirements()

  // Check if all selected components have format selections
  const allFormatsSelected = useMemo(() => {
    const result = Array.from(selectedComponents).every(componentId => 
      formatSelections[componentId]
    )

    downloadModalFormat('FORMAT_VALIDATION', {
      all_formats_selected: result,
      selected_count: selectedComponents.size,
      formats_count: Object.keys(formatSelections).length
    })

    return result
  }, [selectedComponents, formatSelections])

  // Handle download
  const handleDownload = async () => {
    downloadModalOperation('DOWNLOAD_INITIATED', {
      selected_components: selectedComponents.size,
      has_formats: allFormatsSelected,
      download_config: {
        components: Array.from(selectedComponents),
        formats: formatSelections
      }
    })

    if (selectedComponents.size === 0) {
      const errorMsg = 'Please select at least one component to download'
      setDownloadError(errorMsg)
      downloadModalError('Download validation failed - no components', {
        selected_count: selectedComponents.size
      })
      return
    }

    if (!allFormatsSelected) {
      const errorMsg = 'Please select a format for all selected components'
      setDownloadError(errorMsg)
      downloadModalError('Download validation failed - missing formats', {
        selected_count: selectedComponents.size,
        formats_count: Object.keys(formatSelections).length
      })
      return
    }

    setIsDownloading(true)
    setDownloadError(null)

    try {
      // Prepare download configuration for unified API
      const downloadConfig = {
        components: Array.from(selectedComponents),
        formats: formatSelections,
        includeInstructions: false // Advanced downloads don't include instructions
      }

      downloadModalOperation('API_CALL_START', {
        config: downloadConfig
      })
      
      // Use unified download API
      const result = await downloadAPI.downloadCustomBundle(downloadConfig)

      downloadModalOperation('API_CALL_SUCCESS', {
        has_zip_password: !!result.zipPassword,
        has_encryption_password: !!result.encryptionPassword,
        bundle_type: result.bundleType
      })
      
      // Show password modal if we have passwords
      if (result.zipPassword) {
        setDownloadResult(result)
        setShowPasswordModal(true)
        downloadModalOperation('PASSWORD_MODAL_SHOWN', {
          bundle_type: result.bundleType
        })
      }
      
    } catch (error) {
      downloadModalError('Custom download failed', {
        error_message: error.message,
        error_stack: error.stack,
        selected_components: selectedComponents.size
      })
      setDownloadError(error.message || 'Download failed')
    } finally {
      setIsDownloading(false)
      downloadModalOperation('DOWNLOAD_COMPLETED', {
        success: !downloadError
      })
    }
  }

  const handlePasswordModalClose = () => {
    downloadModalLifecycle('PASSWORD_MODAL_CLOSED', {
      had_result: !!downloadResult
    })

    setShowPasswordModal(false)
    setDownloadResult(null)
    // Close the advanced modal after showing password
    onClose()
  }

  const handleOverlayClick = (e) => {
    if (e.target === e.currentTarget) {
      downloadModalLifecycle('OVERLAY_CLICK_CLOSE', {
        selected_components: selectedComponents.size
      })
      onClose()
    }
  }

  // Quick action handlers with logging
  const handleQuickAction = async (actionType, actionFn, config = {}) => {
    downloadModalQuickAction('QUICK_ACTION_START', {
      action_type: actionType,
      config
    })

    try {
      const result = await actionFn()
      
      downloadModalQuickAction('QUICK_ACTION_SUCCESS', {
        action_type: actionType,
        has_zip_password: !!result?.zipPassword
      })

      if (result?.zipPassword) {
        setDownloadResult(result)
        setShowPasswordModal(true)
      }
    } catch (error) {
      downloadModalError(`Quick action failed: ${actionType}`, {
        action_type: actionType,
        error_message: error.message,
        error_stack: error.stack
      })
    }
  }

  // Early return if no components
  if (!certificates || certificates.length === 0) {
    downloadModalWarn('No certificates available for download modal')
    
    return (
      <div className={styles.overlay} onClick={handleOverlayClick}>
        <div className={styles.modal}>
          <div className={styles.header}>
            <h2>Advanced Downloads</h2>
            <button onClick={onClose} className={styles.closeButton}>
              <X size={20} />
            </button>
          </div>
          <div className={styles.content}>
            <div className={styles.emptyState}>
              <AlertCircle size={48} />
              <p>No certificates available for download.</p>
              <p>Please upload some certificates first.</p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  downloadModalInfo('Rendering advanced modal', {
    certificates_count: certificates.length,
    selected_components: selectedComponents.size,
    is_downloading: isDownloading,
    has_error: !!downloadError
  })

  return (
    <>
      <div className={styles.overlay} onClick={handleOverlayClick}>
        <div className={styles.modal}>
          <div className={styles.header}>
            <h2>Advanced Downloads</h2>
            <button onClick={() => {
              downloadModalLifecycle('CLOSE_BUTTON_CLICKED')
              onClose()
            }} className={styles.closeButton}>
              <X size={20} />
            </button>
          </div>

          <div className={styles.content}>
            {/* Error Display */}
            {downloadError && (
              <div className={styles.errorMessage}>
                <AlertCircle size={16} />
                {downloadError}
              </div>
            )}

            {/* Component Selection Section */}
            <div className={styles.section}>
              <div className={styles.sectionHeader}>
                <h3>Select Components ({certificates.length} available)</h3>
                <button className={styles.selectAllButton} onClick={handleSelectAll}>
                  {selectedComponents.size === certificates.length ? (
                    <>
                      <CheckSquare size={16} />
                      Deselect All
                    </>
                  ) : (
                    <>
                      <Square size={16} />
                      Select All
                    </>
                  )}
                </button>
              </div>

              <div className={styles.componentList}>
                {certificates.map(component => {
                  const isSelected = selectedComponents.has(component.id)
                  const formatOptions = getFormatOptions(component.type)
                  
                  return (
                    <div key={component.id} className={styles.componentItem}>
                      {/* Component Selection */}
                      <div className={styles.componentHeader}>
                        <button
                          className={styles.selectButton}
                          onClick={() => handleComponentToggle(component.id)}
                        >
                          {isSelected ? <CheckSquare size={16} /> : <Square size={16} />}
                        </button>

                        <div className={styles.componentIcon}>
                          {getComponentIcon(component.type)}
                        </div>

                        <div className={styles.componentInfo}>
                          <div className={styles.componentName}>
                            {getComponentDisplayName(component)}
                          </div>
                          <div className={styles.componentDetails}>
                            <span className={styles.componentType}>{component.type}</span>
                          </div>
                        </div>
                      </div>

                      {/* Format Selection (only show if selected) */}
                      {isSelected && (
                        <div className={styles.formatSelection}>
                          <label className={styles.formatLabel}>Format:</label>
                          <select
                            value={formatSelections[component.id] || ''}
                            onChange={(e) => handleFormatChange(component.id, e.target.value)}
                            className={styles.formatSelect}
                          >
                            <option value="">Select format...</option>
                            {formatOptions.map(option => (
                              <option key={option.value} value={option.value}>
                                {option.label}
                              </option>
                            ))}
                          </select>
                          
                          {formatSelections[component.id] && (
                            <div className={styles.formatDescription}>
                              {formatOptions.find(opt => opt.value === formatSelections[component.id])?.description}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Quick Actions Section */}
            <div className={styles.section}>
              <h3>Quick Actions</h3>
              <p className={styles.sectionDescription}>
                Pre-configured downloads for common use cases.
              </p>

              <div className={styles.quickActions}>
                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.apache.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.apache.enabled && handleQuickAction('apache', () => downloadAPI.downloadApacheBundle(true))}
                  disabled={!bundleReqs.apache.enabled}
                  title={bundleReqs.apache.tooltip}
                >
                  <Package size={16} />
                  Apache/NGINX Bundle
                </button>
                
                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.iis.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.iis.enabled && handleQuickAction('iis', () => downloadAPI.downloadIISBundle(true))}
                  disabled={!bundleReqs.iis.enabled}
                  title={bundleReqs.iis.tooltip}
                >
                  <Package size={16} />
                  IIS Bundle
                </button>

                {/* PKCS7 Bundle with dropdown */}
                <div className={styles.splitButtonContainer}>
                  <button 
                    className={`${styles.quickActionButton} ${styles.splitButtonMain} ${!bundleReqs.pkcs7.enabled ? styles.disabled : ''}`}
                    onClick={() => {
                      if (bundleReqs.pkcs7.enabled) {
                        handleQuickAction('pkcs7', () => downloadAPI.downloadPKCS7Bundle(pkcs7Format), {
                          format: pkcs7Format
                        })
                      }
                    }}
                    disabled={!bundleReqs.pkcs7.enabled}
                    title={bundleReqs.pkcs7.tooltip}
                  >
                    <Package size={16} />
                    PKCS7 Bundle ({pkcs7Format.toUpperCase()})
                  </button>
                  
                  <div className={styles.splitButtonDropdown}>
                    <select 
                      className={styles.inlineDropdown}
                      value={pkcs7Format}
                      onChange={(e) => {
                        downloadModalFormat('PKCS7_FORMAT_CHANGED', {
                          old_format: pkcs7Format,
                          new_format: e.target.value
                        })
                        setPkcs7Format(e.target.value)
                      }}
                      disabled={!bundleReqs.pkcs7.enabled}
                    >
                      <option value="pem">PEM</option>
                      <option value="der">DER</option>
                    </select>
                  </div>
                </div>

                {/* PKCS12 Bundle with dropdown */}
                <div className={styles.splitButtonContainer}>
                  <button 
                    className={`${styles.quickActionButton} ${styles.splitButtonMain} ${!bundleReqs.pkcs12.enabled ? styles.disabled : ''}`}
                    onClick={() => {
                      if (bundleReqs.pkcs12.enabled) {
                        handleQuickAction('pkcs12', () => downloadAPI.downloadPKCS12Bundle(pkcs12Format), {
                          format: pkcs12Format
                        })
                      }
                    }}
                    disabled={!bundleReqs.pkcs12.enabled}
                    title={bundleReqs.pkcs12.tooltip}
                  >
                    <Package size={16} />
                    PKCS12 Bundle ({pkcs12Format === 'encrypted' ? 'Encrypted' : 'Unencrypted'})
                  </button>
                  
                  <div className={styles.splitButtonDropdown}>
                    <select 
                      className={styles.inlineDropdown}
                      value={pkcs12Format}
                      onChange={(e) => {
                        downloadModalFormat('PKCS12_FORMAT_CHANGED', {
                          old_format: pkcs12Format,
                          new_format: e.target.value
                        })
                        setPkcs12Format(e.target.value)
                      }}
                      disabled={!bundleReqs.pkcs12.enabled}
                    >
                      <option value="encrypted">Encrypted</option>
                      <option value="unencrypted">Unencrypted</option>
                    </select>
                  </div>
                </div>

                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.privateKey.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.privateKey.enabled && handleQuickAction('private_key', () => downloadAPI.downloadPrivateKey())}
                  disabled={!bundleReqs.privateKey.enabled}
                  title={bundleReqs.privateKey.tooltip}
                >
                  <FileText size={16} />
                  Private Key
                </button>

                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.certificate.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.certificate.enabled && handleQuickAction('certificate', () => downloadAPI.downloadCertificate())}
                  disabled={!bundleReqs.certificate.enabled}
                  title={bundleReqs.certificate.tooltip}
                >
                  <FileText size={16} />
                  Certificate
                </button>

                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.chain.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.chain.enabled && handleQuickAction('ca_chain', () => downloadAPI.downloadCAChain())}
                  disabled={!bundleReqs.chain.enabled}
                  title={bundleReqs.chain.tooltip}
                >
                  <FileText size={16} />
                  Chain
                </button>
              </div>
            </div>

            {/* Selection Summary */}
            <div className={styles.summary}>
              <h4>Download Summary</h4>
              {selectedComponents.size > 0 ? (
                <ul className={styles.summaryList}>
                  {Array.from(selectedComponents).map(componentId => {
                    const component = certificates.find(c => c.id === componentId)
                    return (
                      <li key={componentId} className={styles.summaryItem}>
                        {getComponentIcon(component.type)}
                        {getComponentDisplayName(component)} ({formatSelections[componentId] || 'No format selected'})
                      </li>
                    )
                  })}
                </ul>
              ) : (
                <p className={styles.noSelections}>No components selected</p>
              )}
            </div>
          </div>

          {/* Footer */}
          <div className={styles.footer}>
            <div className={styles.footerInfo}>
              {selectedComponents.size} component{selectedComponents.size !== 1 ? 's' : ''} selected
              {selectedComponents.size > 0 && !allFormatsSelected && (
                <span className={styles.warning}> • Select formats to continue</span>
              )}
            </div>
            
            <div className={styles.footerActions}>
              <button
                onClick={() => {
                  downloadModalLifecycle('CANCEL_CLICKED', {
                    selected_components: selectedComponents.size,
                    was_downloading: isDownloading
                  })
                  onClose()
                }}
                className={styles.cancelButton}
                disabled={isDownloading}
              >
                Cancel
              </button>
              <button
                onClick={handleDownload}
                disabled={selectedComponents.size === 0 || !allFormatsSelected || isDownloading}
                className={styles.downloadButton}
              >
                <Download size={16} />
                {isDownloading ? 'Creating Download...' : 'Download Selected'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Password Modal */}
      {showPasswordModal && downloadResult && (
        <SecurePasswordModal
          password={downloadResult.zipPassword}
          encryptionPassword={downloadResult.encryptionPassword}
          bundleType={downloadResult.bundleType}
          onClose={handlePasswordModalClose}
          onCopyComplete={() => {
            downloadModalInfo('Password copied from advanced download', {
              bundle_type: downloadResult.bundleType
            })
          }}
        />
      )}
    </>
  )
}

export default AdvancedModal