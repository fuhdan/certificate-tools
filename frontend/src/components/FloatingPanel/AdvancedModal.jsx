// frontend/src/components/FloatingPanel/AdvancedModal.jsx
// Complete rewrite - Advanced download functionality with component selection

import React, { useState, useMemo } from 'react'
import { X, Download, FileText, Key, Package, AlertCircle, CheckSquare, Square } from 'lucide-react'
import styles from './AdvancedModal.module.css'
import SecurePasswordModal from './SecurePasswordModal'
import { useCertificates } from '../../contexts/CertificateContext'
import { downloadAPI } from '../../services/api'

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

  // Get format options for component types
  const getFormatOptions = (componentType) => {
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
        return component.type
    }
  }

  // Handle component selection toggle
  const handleComponentToggle = (componentId) => {
    const newSelected = new Set(selectedComponents)
    if (newSelected.has(componentId)) {
      newSelected.delete(componentId)
      // Remove format selection when deselecting
      const newFormats = { ...formatSelections }
      delete newFormats[componentId]
      setFormatSelections(newFormats)
    } else {
      newSelected.add(componentId)
      // Set default format when selecting
      const component = certificates.find(c => c.id === componentId)
      if (component) {
        setFormatSelections(prev => ({
          ...prev,
          [componentId]: 'pem' // Default to PEM
        }))
      }
    }
    setSelectedComponents(newSelected)
  }

  // Handle format change for a component
  const handleFormatChange = (componentId, format) => {
    setFormatSelections(prev => ({
      ...prev,
      [componentId]: format
    }))
  }

  // Handle select all / deselect all
  const handleSelectAll = () => {
    if (selectedComponents.size === certificates.length) {
      // Deselect all
      setSelectedComponents(new Set())
      setFormatSelections({})
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
    }
  }

  // Check bundle requirements
  const getBundleRequirements = () => {
    const hasEndEntityCert = certificates.some(c => c.type === 'Certificate')
    const hasPrivateKey = certificates.some(c => c.type === 'PrivateKey')
    const hasCACerts = certificates.some(c => 
      c.type === 'RootCA' || c.type === 'IntermediateCA' || c.type === 'IssuingCA'
    )
    
    return {
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
      pkcs12: {  // ← ADD THIS
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
  }

  const bundleReqs = getBundleRequirements()
  // Check if all selected components have format selections
  const allFormatsSelected = useMemo(() => {
    return Array.from(selectedComponents).every(componentId => 
      formatSelections[componentId]
    )
  }, [selectedComponents, formatSelections])

  // Handle download
  const handleDownload = async () => {
    if (selectedComponents.size === 0) {
      setDownloadError('Please select at least one component to download')
      return
    }

    if (!allFormatsSelected) {
      setDownloadError('Please select a format for all selected components')
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

      console.log('Starting custom download with config:', downloadConfig)
      
      // Use unified download API
      const result = await downloadAPI.downloadCustomBundle(downloadConfig)

      console.log('Custom download completed:', result)
      
      // Show password modal if we have passwords
      if (result.zipPassword) {
        setDownloadResult(result)
        setShowPasswordModal(true)
      }
      
    } catch (error) {
      console.error('Custom download failed:', error)
      setDownloadError(error.message || 'Download failed')
    } finally {
      setIsDownloading(false)
    }
  }

  const handlePasswordModalClose = () => {
    setShowPasswordModal(false)
    setDownloadResult(null)
    // Close the advanced modal after showing password
    onClose()
  }

  const handleOverlayClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose()
    }
  }

  // Early return if no components
  if (!certificates || certificates.length === 0) {
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

  return (
    <>
      <div className={styles.overlay} onClick={handleOverlayClick}>
        <div className={styles.modal}>
          <div className={styles.header}>
            <h2>Advanced Downloads</h2>
            <button onClick={onClose} className={styles.closeButton}>
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
                  onClick={() => bundleReqs.apache.enabled && downloadAPI.downloadApacheBundle(true)}
                  disabled={!bundleReqs.apache.enabled}
                  title={bundleReqs.apache.tooltip}
                >
                  <Package size={16} />
                  Apache/NGINX Bundle
                </button>
                
                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.iis.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.iis.enabled && downloadAPI.downloadIISBundle(true)}
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
                    onClick={async () => {
                      if (bundleReqs.pkcs7.enabled) {
                        try {
                          const result = await downloadAPI.downloadPKCS7Bundle(pkcs7Format)
                          if (result.zipPassword) {
                            setDownloadResult(result)
                            setShowPasswordModal(true)
                          }
                        } catch (error) {
                          console.error('PKCS7 download failed:', error)
                        }
                      }
                    }}
                    disabled={!bundleReqs.pkcs7.enabled}
                    title={bundleReqs.pkcs7.tooltip}
                  >
                    <Package size={16} />
                    PKCS7 Bundle ({pkcs7Format.toUpperCase()}) {/* Shows selected format */}
                  </button>
                  
                  <div className={styles.splitButtonDropdown}>
                    <select 
                      className={styles.inlineDropdown}
                      value={pkcs7Format}
                      onChange={(e) => {
                        setPkcs7Format(e.target.value) // Just update the format, don't download
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
                    onClick={async () => {
                      if (bundleReqs.pkcs12.enabled) {
                        try {
                          const result = await downloadAPI.downloadPKCS12Bundle(pkcs12Format)
                          if (result.zipPassword) {
                            setDownloadResult(result)
                            setShowPasswordModal(true)
                          }
                        } catch (error) {
                          console.error('PKCS7 download failed:', error)
                        }
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
                        setPkcs12Format(e.target.value) // Just update the format, don't download
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
                  onClick={() => bundleReqs.privateKey.enabled && downloadAPI.downloadPrivateKey()}
                  disabled={!bundleReqs.privateKey.enabled}
                  title={bundleReqs.privateKey.tooltip}
                >
                  <FileText size={16} />
                  Private Key
                </button>

                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.certificate.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.certificate.enabled && downloadAPI.downloadCertificate()}
                  disabled={!bundleReqs.certificate.enabled}
                  title={bundleReqs.certificate.tooltip}
                >
                  <FileText size={16} />
                  Certificate
                </button>

                <button 
                  className={`${styles.quickActionButton} ${!bundleReqs.chain.enabled ? styles.disabled : ''}`}
                  onClick={() => bundleReqs.chain.enabled && downloadAPI.downloadCAChain()}
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
                onClick={onClose}
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
          bundleType={downloadResult.bundleType}  // ← ADD THIS LINE
          onClose={handlePasswordModalClose}
          onCopyComplete={() => {
            console.log('Password copied from advanced download')
          }}
        />
      )}
    </>
  )
}

export default AdvancedModal