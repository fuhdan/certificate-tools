// frontend/src/components/FloatingPanel/AdvancedModal.jsx
// Updated AdvancedModal with working API integration

import React, { useState, useMemo, useEffect } from 'react'
import { 
  X, 
  Download, 
  Shield, 
  Key, 
  FileText, 
  Award, 
  Lock,
  Package,
  CheckSquare,
  Square,
  AlertCircle,
  Loader
} from 'lucide-react'
import styles from './AdvancedModal.module.css'
import { useCertificates } from '../../contexts/CertificateContext'
import { advancedDownloadAPI } from '../../services/api'
import SecurePasswordModal from './SecurePasswordModal'

const AdvancedModal = ({ onClose }) => {
  const { components } = useCertificates()
  
  // Selection state
  const [selectedComponents, setSelectedComponents] = useState(new Set())
  
  // Format selections per component/group
  const [formatSelections, setFormatSelections] = useState({})
  
  // UI state
  const [isDownloading, setIsDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState(null)
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [downloadResult, setDownloadResult] = useState(null)

  // Check which bundle formats are selected (simple object access, no dependencies)
  const selectedBundles = {
    pkcs7: formatSelections['pkcs7_chain'] || null,
    pkcs12: formatSelections['pkcs12_bundle'] || null
  }

  // Get components that should be disabled based on bundle selections
  const disabledComponents = useMemo(() => {
    const disabled = new Set()
    
    if (!components) return disabled
    
    // If PKCS#7 is selected, disable certificates and CAs (they're in the bundle)
    if (selectedBundles.pkcs7) {
      components.forEach(comp => {
        if (['Certificate', 'RootCA', 'IntermediateCA', 'IssuingCA'].includes(comp.type)) {
          disabled.add(comp.id)
        }
      })
    }
    
    // If PKCS#12 is selected, disable certificates, CAs, and private keys (they're in the bundle)
    if (selectedBundles.pkcs12) {
      components.forEach(comp => {
        if (['Certificate', 'RootCA', 'IntermediateCA', 'IssuingCA', 'PrivateKey'].includes(comp.type)) {
          disabled.add(comp.id)
        }
      })
    }
    
    return disabled
  }, [components, formatSelections]) // Use formatSelections directly instead of selectedBundles

  // Auto-deselect disabled components
  useEffect(() => {
    if (disabledComponents.size > 0) {
      setSelectedComponents(prev => {
        const newSelected = new Set(prev)
        let hasChanges = false
        
        disabledComponents.forEach(id => {
          if (newSelected.has(id)) {
            newSelected.delete(id)
            hasChanges = true
          }
        })
        
        if (hasChanges) {
          // Clear format selections for disabled components
          setFormatSelections(prevFormats => {
            const updated = { ...prevFormats }
            disabledComponents.forEach(compId => {
              Object.keys(updated).forEach(key => {
                if (key.includes(compId)) {
                  delete updated[key]
                }
              })
            })
            return updated
          })
        }
        
        return hasChanges ? newSelected : prev
      })
    }
  }, [disabledComponents])

  // Get selected components
  const selectedComponentsArray = useMemo(() => {
    if (!components || components.length === 0) return []
    return components.filter(c => selectedComponents.has(c.id))
  }, [components, selectedComponents])

  // Analyze selected components to determine available format options
  const availableFormatGroups = useMemo(() => {
    const groups = []

    if (!components || !selectedComponentsArray) return groups

    const selectedPrivateKeys = selectedComponentsArray.filter(c => c.type === 'PrivateKey')
    const selectedCertificates = selectedComponentsArray.filter(c => 
      ['Certificate', 'RootCA', 'IntermediateCA', 'IssuingCA'].includes(c.type)
    )
    const selectedCSRs = selectedComponentsArray.filter(c => c.type === 'CSR')

    // Check what's available (not just selected) for bundle options
    const availablePrivateKeys = components.filter(c => c.type === 'PrivateKey')
    const availableEndEntityCerts = components.filter(c => c.type === 'Certificate')
    const availableCAs = components.filter(c => 
      ['RootCA', 'IntermediateCA', 'IssuingCA'].includes(c.type)
    )

    // Bundle options first (they affect individual selections)
    
    // PKCS#7 Chain (if we have end-entity cert + CA certs available)
    if (availableEndEntityCerts.length > 0 && availableCAs.length > 0) {
      groups.push({
        id: 'pkcs7_chain',
        title: 'PKCS#7 Certificate Chain',
        icon: <Package size={16} />,
        bundle: true,
        options: [
          { value: 'pem', label: 'PKCS#7 PEM', description: 'Certificate chain in PEM format' },
          { value: 'der', label: 'PKCS#7 DER', description: 'Certificate chain in DER format' }
        ]
      })
    }

    // PKCS#12 Bundle (if we have end-entity cert + private key available)
    if (availableEndEntityCerts.length > 0 && availablePrivateKeys.length > 0) {
      groups.push({
        id: 'pkcs12_bundle',
        title: 'PKCS#12 Bundle (Certificate + Chain + Private Key)',
        icon: <Lock size={16} />,
        bundle: true,
        options: [
          { value: 'encrypted', label: 'PKCS#12 (Encrypted)', description: 'Password-protected bundle' },
          { value: 'unencrypted', label: 'PKCS#12 (Unencrypted)', description: 'No password protection' }
        ]
      })
    }

    // Individual component formats (only for selected, non-disabled components)
    
    // Private Key formats (for each selected private key, if not disabled)
    selectedPrivateKeys.forEach(key => {
      if (!disabledComponents.has(key.id)) {
        groups.push({
          id: `privatekey_${key.id}`,
          title: `Private Key: ${key.filename}`,
          icon: <Key size={16} />,
          bundle: false,
          options: [
            { value: 'pem', label: 'PEM (Unencrypted)', description: 'Base64 encoded, unencrypted' },
            { value: 'der', label: 'DER (Unencrypted)', description: 'Binary encoded, unencrypted' },
            { value: 'pkcs8', label: 'PKCS#8 (Unencrypted)', description: 'Standard format, unencrypted' },
            { value: 'pkcs8_encrypted', label: 'PKCS#8 (Encrypted)', description: 'Password-protected PKCS#8' },
            { value: 'pem_encrypted', label: 'PEM (Encrypted)', description: 'Password-protected PEM' }
          ]
        })
      }
    })

    // CSR formats (for each selected CSR)
    selectedCSRs.forEach(csr => {
      groups.push({
        id: `csr_${csr.id}`,
        title: `CSR: ${csr.filename}`,
        icon: <FileText size={16} />,
        bundle: false,
        options: [
          { value: 'pem', label: 'PEM', description: 'Base64 encoded text format' },
          { value: 'der', label: 'DER', description: 'Binary encoded format' }
        ]
      })
    })

    // Certificate formats (for each selected certificate, if not disabled)
    selectedCertificates.forEach(cert => {
      if (!disabledComponents.has(cert.id)) {
        groups.push({
          id: `certificate_${cert.id}`,
          title: `Certificate: ${cert.filename}`,
          icon: cert.type === 'Certificate' ? <Shield size={16} /> : <Award size={16} />,
          bundle: false,
          options: [
            { value: 'pem', label: 'PEM', description: 'Base64 encoded text format' },
            { value: 'der', label: 'DER', description: 'Binary encoded format' }
          ]
        })
      }
    })

    return groups
  }, [selectedComponentsArray, components, disabledComponents])

  // Auto-set default PEM format for newly selected components
  useEffect(() => {
    if (!availableFormatGroups || availableFormatGroups.length === 0) return
    
    const updates = {}
    let hasUpdates = false
    
    availableFormatGroups.forEach(group => {
      if (!group.bundle && !formatSelections[group.id]) {
        updates[group.id] = 'pem' // Default to PEM
        hasUpdates = true
      }
    })
    
    if (hasUpdates) {
      setFormatSelections(prev => ({ ...prev, ...updates }))
    }
  }, [availableFormatGroups]) // Only depend on availableFormatGroups

  // Get icon for component type
  const getComponentIcon = (type) => {
    const iconProps = { size: 16 }
    switch (type) {
      case 'PrivateKey':
        return <Key {...iconProps} className={styles.keyIcon} />
      case 'CSR':
        return <FileText {...iconProps} className={styles.csrIcon} />
      case 'Certificate':
        return <Shield {...iconProps} className={styles.certIcon} />
      case 'IssuingCA':
      case 'IntermediateCA':
      case 'RootCA':
        return <Award {...iconProps} className={styles.caIcon} />
      default:
        return <FileText {...iconProps} className={styles.unknownIcon} />
    }
  }

  // Get component display name
  const getComponentDisplayName = (comp) => {
    if (comp.metadata?.subject_common_name) {
      return comp.metadata.subject_common_name
    }
    if (comp.metadata?.subject) {
      const cnMatch = comp.metadata.subject.match(/CN=([^,]+)/)
      if (cnMatch) return cnMatch[1]
    }
    return comp.filename
  }

  // Handle component selection
  const handleComponentSelect = (componentId) => {
    // Don't allow selecting disabled components
    if (disabledComponents.has(componentId)) return
    
    const newSelected = new Set(selectedComponents)
    if (newSelected.has(componentId)) {
      newSelected.delete(componentId)
      // Clear format selections for deselected components
      setFormatSelections(prev => {
        const updated = { ...prev }
        Object.keys(updated).forEach(key => {
          if (key.includes(componentId)) {
            delete updated[key]
          }
        })
        return updated
      })
    } else {
      newSelected.add(componentId)
    }
    setSelectedComponents(newSelected)
  }

  // Handle select/deselect all
  const handleSelectAll = () => {
    if (!components) return
    
    const availableComponents = components.filter(c => !disabledComponents.has(c.id))
    const allSelected = availableComponents.every(c => selectedComponents.has(c.id))
    
    if (allSelected) {
      // Deselect all
      setSelectedComponents(new Set())
      setFormatSelections({})
    } else {
      // Select all available
      setSelectedComponents(new Set(availableComponents.map(c => c.id)))
    }
  }

  // Handle format selection
  const handleFormatSelect = (groupId, format) => {
    setFormatSelections(prev => ({
      ...prev,
      [groupId]: format
    }))
  }

  // Handle bundle deselection
  const handleBundleDeselect = (bundleId) => {
    setFormatSelections(prev => {
      const updated = { ...prev }
      delete updated[bundleId]
      return updated
    })
  }

  // Check if we have any selections (components or bundles)
  const hasAnySelections = selectedComponents.size > 0 || selectedBundles.pkcs7 || selectedBundles.pkcs12

  // Check if all selected groups have formats chosen (including individual components)
  const allFormatsSelected = useMemo(() => {
    if (!availableFormatGroups || availableFormatGroups.length === 0) return false
    
    // Check individual component formats
    const individualGroups = availableFormatGroups.filter(group => !group.bundle)
    const individualFormatsSelected = individualGroups.every(group => formatSelections[group.id])
    
    // Check bundle formats
    const bundleGroups = availableFormatGroups.filter(group => group.bundle)
    const bundleFormatsSelected = bundleGroups.length === 0 || bundleGroups.some(group => formatSelections[group.id])
    
    // We need either all individual formats OR at least one bundle format
    return individualFormatsSelected || (bundleFormatsSelected && bundleGroups.some(group => formatSelections[group.id]))
  }, [availableFormatGroups, formatSelections])

  // Handle download
  const handleDownload = async () => {
    if (!hasAnySelections) {
      setDownloadError('Please select components or bundles to download')
      return
    }

    if (!allFormatsSelected) {
      setDownloadError('Please select a format for all selected items')
      return
    }

    setIsDownloading(true)
    setDownloadError(null)

    try {
      const downloadConfig = {
        component_ids: Array.from(selectedComponents),
        format_selections: formatSelections,
        bundles: selectedBundles
      }

      console.log('🚀 Starting advanced download with config:', downloadConfig)

      console.log('🚀 Starting advanced download with config:', downloadConfig)
      
      // Call the API
      const result = await advancedDownloadAPI.downloadAdvancedBundle(downloadConfig)
      
      console.log('✅ Download completed:', result)
      
      // Show password modal
      if (result.zipPassword) {
        setDownloadResult(result)
        setShowPasswordModal(true)
      }
      
    } catch (error) {
      console.error('❌ Download failed:', error)
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
  if (!components || components.length === 0) {
    return (
      <div className={styles.overlay} onClick={handleOverlayClick}>
        <div className={styles.modal}>
          <div className={styles.header}>
            <div className={styles.titleSection}>
              <Download size={24} className={styles.icon} />
              <h2>Advanced Download</h2>
            </div>
            <div className={styles.actions}>
              <button className={styles.closeButton} onClick={onClose}>
                <X size={20} />
              </button>
            </div>
          </div>
          <div className={styles.content}>
            <div className={styles.emptyState}>
              <FileText size={48} />
              <h3>No Components Available</h3>
              <p>Upload some certificates, keys, or CSRs first to download them.</p>
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
            <div className={styles.titleSection}>
              <Download size={24} className={styles.icon} />
              <h2>Advanced Download</h2>
            </div>
            <div className={styles.actions}>
              <button className={styles.closeButton} onClick={onClose}>
                <X size={20} />
              </button>
            </div>
          </div>

          <div className={styles.content}>
            {/* Security Notice */}
            <div className={styles.securityNotice}>
              <Lock size={18} />
              <div>
                <strong>Security First</strong>
                <p>All downloads are provided as password-protected ZIP files, regardless of format selected.</p>
              </div>
            </div>

            {/* Component Selection */}
            <div className={styles.section}>
              <div className={styles.sectionHeader}>
                <h3>Step 1: Select Components ({components.length} available)</h3>
                <button
                  className={styles.selectAllButton}
                  onClick={handleSelectAll}
                >
                  {components.filter(c => !disabledComponents.has(c.id)).every(c => selectedComponents.has(c.id)) ? 
                    <>
                      <CheckSquare size={16} />
                      Deselect All
                    </> : 
                    <>
                      <Square size={16} />
                      Select All
                    </>
                  }
                </button>
              </div>

              <div className={styles.componentList}>
                {components.map(comp => {
                  const isDisabled = disabledComponents.has(comp.id)
                  const isSelected = selectedComponents.has(comp.id)
                  
                  return (
                    <div key={comp.id} className={`${styles.componentItem} ${isDisabled ? styles.disabled : ''}`}>
                      <button
                        className={styles.selectButton}
                        onClick={() => handleComponentSelect(comp.id)}
                        disabled={isDisabled}
                        title={isDisabled ? 'This component is included in a selected bundle' : ''}
                      >
                        {isSelected ? <CheckSquare size={16} /> : <Square size={16} />}
                      </button>

                      <div className={styles.componentIcon}>
                        {getComponentIcon(comp.type)}
                      </div>

                      <div className={styles.componentInfo}>
                        <div className={styles.componentName}>
                          {getComponentDisplayName(comp)}
                          {isDisabled && <span className={styles.disabledNote}> (in bundle)</span>}
                        </div>
                        <div className={styles.componentDetails}>
                          <span className={styles.componentType}>{comp.type}</span>
                          <span className={styles.componentFilename}>{comp.filename}</span>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Format Selection - Show bundle options first, then individual formats */}
            {availableFormatGroups.length > 0 && (
              <div className={styles.section}>
                <div className={styles.sectionHeader}>
                  <h3>Step 2: Select Download Formats</h3>
                </div>

                <div className={styles.formatGroups}>
                  {availableFormatGroups.map(group => (
                    <div key={group.id} className={styles.formatGroup}>
                      <div className={styles.formatGroupHeader}>
                        {group.icon}
                        <span>{group.title}</span>
                        {group.bundle && formatSelections[group.id] && (
                          <button
                            className={styles.deselectBundle}
                            onClick={() => handleBundleDeselect(group.id)}
                            title="Remove bundle selection"
                          >
                            <X size={14} />
                          </button>
                        )}
                      </div>
                      
                      <div className={styles.formatOptions}>
                        {group.options.map(option => (
                          <label key={option.value} className={styles.formatOption}>
                            <input
                              type="radio"
                              name={group.id}
                              value={option.value}
                              checked={formatSelections[group.id] === option.value}
                              onChange={() => handleFormatSelect(group.id, option.value)}
                            />
                            <div className={styles.formatDetails}>
                              <div className={styles.formatLabel}>{option.label}</div>
                              <div className={styles.formatDescription}>{option.description}</div>
                            </div>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className={styles.footer}>
            {downloadError && (
              <div className={styles.error}>
                <AlertCircle size={16} />
                <span>{downloadError}</span>
              </div>
            )}

            <div className={styles.footerActions}>
              <div className={styles.selectedCount}>
                {selectedComponents.size} component{selectedComponents.size !== 1 ? 's' : ''} selected
                {(selectedBundles.pkcs7 || selectedBundles.pkcs12) && (
                  <span> • Bundle format selected</span>
                )}
                {hasAnySelections && !allFormatsSelected && (
                  <span> • Select formats to continue</span>
                )}
              </div>
              
              <div className={styles.actionButtons}>
                <button
                  className={styles.cancelButton}
                  onClick={onClose}
                  disabled={isDownloading}
                >
                  Cancel
                </button>
                <button
                  className={styles.downloadButton}
                  onClick={handleDownload}
                  disabled={isDownloading || !hasAnySelections || !allFormatsSelected}
                >
                  {isDownloading ? (
                    <>
                      <Loader size={16} className={styles.spinner} />
                      Preparing Download...
                    </>
                  ) : (
                    <>
                      <Download size={16} />
                      Download Encrypted ZIP
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Password Modal */}
      {showPasswordModal && downloadResult && (
        <SecurePasswordModal
          password={downloadResult.zipPassword}
          onClose={handlePasswordModalClose}
        />
      )}
    </>
  )
}

export default AdvancedModal