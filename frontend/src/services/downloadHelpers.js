import { downloadAPI, certificateAPI } from './api'

// Import existing download logging instead of creating new section
import {
  downloadError,
  downloadWarn,
  downloadInfo,
  downloadDebug,
  time,
  timeEnd
} from '../utils/logger'

/**
 * Helper functions for common download patterns using the unified custom endpoint
 * These provide a simple interface while using the powerful custom endpoint behind the scenes
 */

/**
 * Get component ID by type from current session
 */
async function getComponentIdByType(targetType) {
  time('DownloadHelpers.get_component_by_type')
  
  downloadDebug('Component search started', {
    helper_function: 'getComponentIdByType',
    target_type: targetType,
    search_method: 'by_type'
  })

  try {
    downloadDebug('API call for component discovery', {
      helper_context: 'getComponentIdByType',
      endpoint: 'getCertificates',
      purpose: 'component_discovery'
    })

    const apiResult = await certificateAPI.getCertificates()
    const component = apiResult.certificates.find(cert => cert.type === targetType)
    
    downloadDebug('Component search result', {
      helper_function: 'getComponentIdByType',
      target_type: targetType,
      component_id: component?.id,
      filename: component?.filename,
      found: !!component
    })

    if (component) {
      downloadDebug(`Found ${targetType} component: ${component.filename}`, {
        helper_context: 'getComponentIdByType',
        component_id: component.id,
        component_type: targetType
      })
    } else {
      downloadWarn(`No ${targetType} component found in session`, {
        helper_function: 'getComponentIdByType',
        target_type: targetType,
        available_types: apiResult.certificates.map(c => c.type),
        total_components: apiResult.certificates.length
      })
    }

    timeEnd('DownloadHelpers.get_component_by_type')
    return component?.id || null
  } catch (error) {
    downloadError(`Error finding ${targetType} component`, {
      helper_function: 'getComponentIdByType',
      error_message: error.message,
      target_type: targetType,
      search_method: 'by_type'
    })

    console.error(`Error finding ${targetType} component:`, error)
    timeEnd('DownloadHelpers.get_component_by_type')
    return null
  }
}

/**
 * Get CA component IDs from current session
 */
async function getCAComponentIds() {
  time('DownloadHelpers.get_ca_components')
  
  const caTypes = ['IssuingCA', 'IntermediateCA', 'RootCA']
  
  downloadDebug('CA component search started', {
    helper_function: 'getCAComponentIds',
    target_types: caTypes
  })

  try {
    downloadDebug('API call for CA discovery', {
      helper_context: 'getCAComponentIds',
      endpoint: 'getCertificates',
      purpose: 'ca_discovery'
    })

    const caResult = await certificateAPI.getCertificates()
    const caComponents = caResult.certificates.filter(cert => caTypes.includes(cert.type))
    const caIds = caComponents.map(cert => cert.id)
    
    downloadDebug('CA search result', {
      helper_function: 'getCAComponentIds',
      found_count: caComponents.length,
      ca_types_found: caComponents.map(c => c.type),
      ca_filenames: caComponents.map(c => c.filename)
    })

    downloadDebug(`Found ${caComponents.length} CA components`, {
      helper_context: 'getCAComponentIds',
      ca_components: caComponents.map(c => ({ type: c.type, filename: c.filename }))
    })

    timeEnd('DownloadHelpers.get_ca_components')
    return caIds
  } catch (error) {
    downloadError('Error finding CA components', {
      helper_function: 'getCAComponentIds',
      error_message: error.message,
      target_types: caTypes
    })

    console.error('Error finding CA components:', error)
    timeEnd('DownloadHelpers.get_ca_components')
    return []
  }
}

/**
 * Get all component IDs from current session  
 */
async function getAllComponentIds() {
  time('DownloadHelpers.get_all_components')
  
  downloadDebug('All components search started', {
    helper_function: 'getAllComponentIds'
  })

  try {
    downloadDebug('API call for all components discovery', {
      helper_context: 'getAllComponentIds',
      endpoint: 'getCertificates',
      purpose: 'all_components_discovery'
    })

    const allResult = await certificateAPI.getCertificates()
    const allIds = allResult.certificates.map(cert => cert.id)
    
    downloadDebug('All components search result', {
      helper_function: 'getAllComponentIds',
      found_count: allIds.length,
      component_types: allResult.certificates.map(c => c.type)
    })

    downloadDebug(`Found ${allIds.length} total components`, {
      helper_context: 'getAllComponentIds',
      components: allResult.certificates.map(c => ({ type: c.type, filename: c.filename }))
    })

    timeEnd('DownloadHelpers.get_all_components')
    return allIds
  } catch (error) {
    downloadError('Error getting all components', {
      helper_function: 'getAllComponentIds',
      error_message: error.message
    })

    console.error('Error getting all components:', error)
    timeEnd('DownloadHelpers.get_all_components')
    return []
  }
}

// ===== INDIVIDUAL COMPONENT DOWNLOAD HELPERS =====

/**
 * Download private key only
 * @param {string} format - Format for private key (pem, der, pkcs8, pkcs8_encrypted, pem_encrypted)
 * @param {boolean} encrypted - Whether to use encrypted format (convenience parameter)
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Download unencrypted PEM private key
 * await downloadPrivateKey('pem')
 * 
 * // Download encrypted PKCS#8 private key
 * await downloadPrivateKey('pkcs8_encrypted')
 * 
 * // Download encrypted PEM (convenience)
 * await downloadPrivateKey('pem', true)
 */
export async function downloadPrivateKey(format = 'pem', encrypted = false) {
  time('DownloadHelpers.download_private_key')
  
  downloadInfo('Private key download started', {
    helper_function: 'downloadPrivateKey',
    format: format,
    encrypted: encrypted
  })

  try {
    // Handle convenience encrypted parameter
    let finalFormat = format
    if (encrypted && format === 'pem') {
      finalFormat = 'pem_encrypted'
    } else if (encrypted && format === 'pkcs8') {
      finalFormat = 'pkcs8_encrypted'
    }

    downloadDebug('Encryption parameter processed', {
      helper_function: 'downloadPrivateKey',
      encrypted: encrypted || finalFormat.includes('encrypted'),
      original_format: format,
      final_format: finalFormat,
      format_security: finalFormat.includes('encrypted') ? 'encrypted' : 'plaintext'
    })

    const componentId = await getComponentIdByType('PrivateKey')
    if (!componentId) {
      downloadError('No private key found in session', {
        helper_function: 'downloadPrivateKey',
        error_type: 'component_not_found'
      })
      throw new Error('No private key found in session')
    }

    const config = {
      components: [componentId],
      formats: { [componentId]: finalFormat },
      includeInstructions: false
    }
    
    downloadDebug('Download configuration created', {
      helper_function: 'downloadPrivateKey',
      component_count: 1,
      bundle_type: 'single_private_key',
      config: config
    })

    downloadInfo('Downloading private key with helper:', config)
    
    downloadInfo('Starting private key download', {
      helper_function: 'downloadPrivateKey',
      endpoint: 'downloadCustomBundle',
      component_count: 1,
      download_type: 'private_key'
    })

    const result = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('Private key download completed', {
      helper_function: 'downloadPrivateKey',
      success: result.success,
      format: finalFormat,
      component_count: 1
    })

    timeEnd('DownloadHelpers.download_private_key')
    return result
  } catch (error) {
    downloadError('Error in downloadPrivateKey helper', {
      helper_function: 'downloadPrivateKey',
      error_message: error.message,
      error_stack: error.stack,
      format: format,
      encrypted: encrypted
    })

    console.error('Error in downloadPrivateKey helper:', error)
    timeEnd('DownloadHelpers.download_private_key')
    throw error
  }
}

/**
 * Download certificate only
 * @param {string} format - Format for certificate (pem, der)
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Download PEM certificate
 * await downloadCertificate('pem')
 * 
 * // Download DER certificate  
 * await downloadCertificate('der')
 */
export async function downloadCertificate(format = 'pem') {
  time('DownloadHelpers.download_certificate')
  
  downloadInfo('Certificate download started', {
    helper_function: 'downloadCertificate',
    format: format
  })

  try {
    const componentId = await getComponentIdByType('Certificate')
    if (!componentId) {
      downloadError('No certificate found in session', {
        helper_function: 'downloadCertificate',
        error_type: 'component_not_found'
      })
      throw new Error('No certificate found in session')
    }

    const config = {
      components: [componentId],
      formats: { [componentId]: format },
      includeInstructions: false
    }
    
    downloadDebug('Download configuration created', {
      helper_function: 'downloadCertificate',
      component_count: 1,
      bundle_type: 'single_certificate',
      config: config
    })

    downloadDebug('Downloading certificate with helper:', config)
    
    downloadInfo('Starting certificate download', {
      helper_function: 'downloadCertificate',
      endpoint: 'downloadCustomBundle',
      component_count: 1,
      download_type: 'certificate'
    })

    const result = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('Certificate download completed', {
      helper_function: 'downloadCertificate',
      success: result.success,
      format: format,
      component_count: 1
    })

    timeEnd('DownloadHelpers.download_certificate')
    return result
  } catch (error) {
    downloadError('Error in downloadCertificate helper', {
      helper_function: 'downloadCertificate',
      error_message: error.message,
      error_stack: error.stack,
      format: format
    })

    console.error('Error in downloadCertificate helper:', error)
    timeEnd('DownloadHelpers.download_certificate')
    throw error
  }
}

/**
 * Download CA certificate chain
 * @param {string} format - Format for CA certificates (pem, der)
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Download PEM CA chain
 * await downloadCAChain('pem')
 * 
 * // Download DER CA chain
 * await downloadCAChain('der')
 */
export async function downloadCAChain(format = 'pem') {
  time('DownloadHelpers.download_ca_chain')
  
  downloadInfo('CA chain download started', {
    helper_function: 'downloadCAChain',
    format: format
  })

  try {
    const componentIds = await getCAComponentIds()
    if (componentIds.length === 0) {
      downloadError('No CA certificates found in session', {
        helper_function: 'downloadCAChain',
        error_type: 'components_not_found'
      })
      throw new Error('No CA certificates found in session')
    }

    // Create format mapping for all CA components
    const formats = {}
    componentIds.forEach(id => {
      formats[id] = format
    })

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    downloadDebug('Download configuration created', {
      helper_function: 'downloadCAChain',
      component_count: componentIds.length,
      bundle_type: 'ca_chain',
      config: config
    })

    downloadDebug('Downloading CA chain with helper:', config)
    
    downloadInfo('Starting CA chain download', {
      helper_function: 'downloadCAChain',
      endpoint: 'downloadCustomBundle',
      component_count: componentIds.length,
      download_type: 'ca_chain'
    })

    const result = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('CA chain download completed', {
      helper_function: 'downloadCAChain',
      success: result.success,
      format: format,
      component_count: componentIds.length
    })

    timeEnd('DownloadHelpers.download_ca_chain')
    return result
  } catch (error) {
    downloadError('Error in downloadCAChain helper', {
      helper_function: 'downloadCAChain',
      error_message: error.message,
      error_stack: error.stack,
      format: format
    })

    console.error('Error in downloadCAChain helper:', error)
    timeEnd('DownloadHelpers.download_ca_chain')
    throw error
  }
}

// ===== ADVANCED DOWNLOAD HELPERS =====

/**
 * Download all components in session
 * @param {string} defaultFormat - Default format for all components (pem, der, etc.)
 * @param {Object} formatOverrides - Override formats for specific component types
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Download all components as PEM
 * await downloadAll('pem')
 * 
 * // Download all as PEM, but private key encrypted
 * await downloadAll('pem', { PrivateKey: 'pem_encrypted' })
 */
export async function downloadAll(defaultFormat = 'pem', formatOverrides = {}) {
  time('DownloadHelpers.download_all')
  
  downloadInfo('Download all components started', {
    helper_function: 'downloadAll',
    default_format: defaultFormat,
    format_overrides: Object.keys(formatOverrides)
  })

  try {
    downloadDebug('API call for download all discovery', {
      helper_context: 'downloadAll',
      endpoint: 'getCertificates',
      purpose: 'download_all_discovery'
    })

    const certificatesResult = await certificateAPI.getCertificates()
    const certificates = certificatesResult.certificates

    if (certificates.length === 0) {
      downloadError('No components found in session', {
        helper_function: 'downloadAll',
        error_type: 'no_components'
      })
      throw new Error('No components found in session')
    }

    const componentIds = certificates.map(cert => cert.id)
    const formats = {}

    // Apply formats based on component types
    certificates.forEach(cert => {
      const overrideFormat = formatOverrides[cert.type]
      formats[cert.id] = overrideFormat || defaultFormat
    })

    downloadDebug('Download all configuration created', {
      helper_function: 'downloadAll',
      component_count: componentIds.length,
      bundle_type: 'all_components',
      format_overrides_used: Object.keys(formatOverrides).length,
      config_summary: {
        components: componentIds.length,
        formats: Object.keys(formats).length
      }
    })

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    downloadDebug('Downloading all components with helper:', config)
    
    downloadInfo('Starting download all operation', {
      helper_function: 'downloadAll',
      endpoint: 'downloadCustomBundle',
      component_count: componentIds.length,
      download_type: 'all_components'
    })

    const downloadResult = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('Download all completed', {
      helper_function: 'downloadAll',
      success: downloadResult.success,
      component_count: componentIds.length,
      default_format: defaultFormat
    })

    timeEnd('DownloadHelpers.download_all')
    return downloadResult
  } catch (error) {
    downloadError('Error in downloadAll helper', {
      helper_function: 'downloadAll',
      error_message: error.message,
      error_stack: error.stack,
      default_format: defaultFormat
    })

    console.error('Error in downloadAll helper:', error)
    timeEnd('DownloadHelpers.download_all')
    throw error
  }
}

/**
 * Download specific components by their IDs
 * @param {string[]} componentIds - Array of component IDs to download
 * @param {Object} formats - Format mapping for each component
 * @param {boolean} includeInstructions - Whether to include installation instructions
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Download specific components
 * await downloadComponents(['id1', 'id2'], { id1: 'pem', id2: 'der' })
 */
export async function downloadComponents(componentIds, formats, includeInstructions = false) {
  time('DownloadHelpers.download_components')
  
  downloadInfo('Download specific components started', {
    helper_function: 'downloadComponents',
    component_count: componentIds?.length || 0,
    format_count: Object.keys(formats || {}).length,
    include_instructions: includeInstructions
  })

  try {
    if (!componentIds || componentIds.length === 0) {
      downloadError('No component IDs provided', {
        helper_function: 'downloadComponents',
        error_type: 'invalid_input'
      })
      throw new Error('No component IDs provided')
    }

    if (!formats || Object.keys(formats).length === 0) {
      downloadError('No format mappings provided', {
        helper_function: 'downloadComponents',
        error_type: 'invalid_input'
      })
      throw new Error('No format mappings provided')
    }

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: includeInstructions
    }
    
    downloadDebug('Download components configuration created', {
      helper_function: 'downloadComponents',
      component_count: componentIds.length,
      bundle_type: 'custom_components',
      config: config
    })

    downloadDebug('Downloading components with helper:', config)
    
    downloadInfo('Starting custom components download', {
      helper_function: 'downloadComponents',
      endpoint: 'downloadCustomBundle',
      component_count: componentIds.length,
      download_type: 'custom_components'
    })

    const result = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('Download components completed', {
      helper_function: 'downloadComponents',
      success: result.success,
      component_count: componentIds.length,
      include_instructions: includeInstructions
    })

    timeEnd('DownloadHelpers.download_components')
    return result
  } catch (error) {
    downloadError('Error in downloadComponents helper', {
      helper_function: 'downloadComponents',
      error_message: error.message,
      error_stack: error.stack,
      component_count: componentIds?.length || 0
    })

    console.error('Error in downloadComponents helper:', error)
    timeEnd('DownloadHelpers.download_components')
    throw error
  }
}

// ===== BUNDLE FORMAT HELPERS =====

/**
 * Create PKCS#7 bundle (certificate chain without private key)
 * @param {string} format - Format for PKCS7 (pem, der)
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Create PEM PKCS#7 bundle
 * await createPKCS7Bundle('pem')
 * 
 * // Create DER PKCS#7 bundle
 * await createPKCS7Bundle('der')
 */
export async function createPKCS7Bundle(format = 'pem') {
  time('DownloadHelpers.create_pkcs7_bundle')
  
  downloadInfo('PKCS#7 bundle creation started', {
    helper_function: 'createPKCS7Bundle',
    bundle_type: 'pkcs7',
    format: format
  })

  try {
    downloadDebug('API call for PKCS#7 bundle discovery', {
      helper_context: 'createPKCS7Bundle',
      endpoint: 'getCertificates',
      purpose: 'pkcs7_bundle_discovery'
    })

    const downloadAllResult = await certificateAPI.getCertificates()
    const certificates = downloadAllResult.certificates

    // Find certificate and CA certificates for PKCS7
    const certificate = certificates.find(cert => cert.type === 'Certificate')
    const caCerts = certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )

    if (!certificate) {
      downloadError('Certificate required for PKCS#7 bundle', {
        helper_function: 'createPKCS7Bundle',
        error_type: 'missing_certificate',
        available_types: certificates.map(c => c.type)
      })
      throw new Error('Certificate required for PKCS7 bundle')
    }

    // Build component list (certificate + CAs, no private key for PKCS7)
    const componentIds = [certificate.id, ...caCerts.map(ca => ca.id)]
    const formats = {}
    
    // Use special format key to request PKCS7 bundle creation
    formats['bundle_pkcs7'] = format
    
    downloadInfo('PKCS#7 bundle configuration', {
      helper_function: 'createPKCS7Bundle',
      bundle_type: 'pkcs7',
      component_count: componentIds.length,
      format: format,
      has_certificate: true,
      has_ca_chain: caCerts.length > 0,
      has_private_key: false
    })

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    downloadDebug('PKCS#7 bundle configuration created', {
      helper_function: 'createPKCS7Bundle',
      bundle_type: 'pkcs7',
      config: config
    })

    downloadDebug('Creating PKCS#7 bundle with helper:', config)
    
    downloadInfo('Starting PKCS#7 bundle download', {
      helper_function: 'createPKCS7Bundle',
      endpoint: 'downloadCustomBundle',
      component_count: componentIds.length,
      download_type: 'pkcs7_bundle'
    })

    const downloadResult = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('PKCS#7 bundle creation completed', {
      helper_function: 'createPKCS7Bundle',
      bundle_type: 'pkcs7',
      success: downloadResult.success,
      component_count: componentIds.length,
      format: format
    })

    timeEnd('DownloadHelpers.create_pkcs7_bundle')
    return downloadResult
  } catch (error) {
    downloadError('Error in createPKCS7Bundle helper', {
      helper_function: 'createPKCS7Bundle',
      error_message: error.message,
      error_stack: error.stack,
      format: format
    })

    console.error('Error in createPKCS7Bundle helper:', error)
    timeEnd('DownloadHelpers.create_pkcs7_bundle')
    throw error
  }
}

/**
 * Create PKCS#12 bundle (certificate + private key + CA chain)
 * @param {boolean} encrypted - Whether to encrypt the PKCS#12 bundle
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Create encrypted PKCS#12 bundle
 * await createPKCS12Bundle(true)
 * 
 * // Create unencrypted PKCS#12 bundle
 * await createPKCS12Bundle(false)
 */
export async function createPKCS12Bundle(encrypted = true) {
  time('DownloadHelpers.create_pkcs12_bundle')
  
  downloadInfo('PKCS#12 bundle creation started', {
    helper_function: 'createPKCS12Bundle',
    bundle_type: 'pkcs12',
    encrypted: encrypted
  })

  downloadDebug('PKCS#12 encryption configuration', {
    helper_function: 'createPKCS12Bundle',
    encrypted: encrypted,
    bundle_secured: encrypted,
    password_required: encrypted
  })

  try {
    downloadDebug('API call for PKCS#12 bundle discovery', {
      helper_context: 'createPKCS12Bundle',
      endpoint: 'getCertificates',
      purpose: 'pkcs12_bundle_discovery'
    })

    const pkcs7Result = await certificateAPI.getCertificates()
    const certificates = pkcs7Result.certificates

    // Find required components
    const certificate = certificates.find(cert => cert.type === 'Certificate')
    const privateKey = certificates.find(cert => cert.type === 'PrivateKey')
    
    if (!certificate) {
      downloadError('Certificate required for PKCS#12 bundle', {
        helper_function: 'createPKCS12Bundle',
        error_type: 'missing_certificate',
        available_types: certificates.map(c => c.type)
      })
      throw new Error('Certificate required for PKCS#12 bundle')
    }
    if (!privateKey) {
      downloadError('Private key required for PKCS#12 bundle', {
        helper_function: 'createPKCS12Bundle',
        error_type: 'missing_private_key',
        available_types: certificates.map(c => c.type)
      })
      throw new Error('Private key required for PKCS#12 bundle')
    }

    // Find CA certificates
    const caCerts = certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )

    // Build component list and formats
    const componentIds = [certificate.id, privateKey.id, ...caCerts.map(ca => ca.id)]
    const formats = {}
    
    // Use a special format key to request PKCS#12 bundle creation
    formats['bundle_pkcs12'] = encrypted ? 'encrypted' : 'unencrypted'
    
    downloadInfo('PKCS#12 bundle configuration', {
      helper_function: 'createPKCS12Bundle',
      bundle_type: 'pkcs12',
      component_count: componentIds.length,
      encrypted: encrypted,
      has_certificate: true,
      has_private_key: true,
      has_ca_chain: caCerts.length > 0
    })

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    downloadDebug('PKCS#12 bundle configuration created', {
      helper_function: 'createPKCS12Bundle',
      bundle_type: 'pkcs12',
      config: config
    })

    downloadDebug('Creating PKCS#12 bundle with helper:', config)
    
    downloadInfo('Starting PKCS#12 bundle download', {
      helper_function: 'createPKCS12Bundle',
      endpoint: 'downloadCustomBundle',
      component_count: componentIds.length,
      download_type: 'pkcs12_bundle'
    })

    const result = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('PKCS#12 bundle creation completed', {
      helper_function: 'createPKCS12Bundle',
      bundle_type: 'pkcs12',
      success: result.success,
      component_count: componentIds.length,
      encrypted: encrypted
    })

    timeEnd('DownloadHelpers.create_pkcs12_bundle')
    return result
  } catch (error) {
    downloadError('Error in createPKCS12Bundle helper', {
      helper_function: 'createPKCS12Bundle',
      error_message: error.message,
      error_stack: error.stack,
      encrypted: encrypted
    })

    console.error('Error in createPKCS12Bundle helper:', error)
    timeEnd('DownloadHelpers.create_pkcs12_bundle')
    throw error
  }
}

/**
 * Create certificate chain file (end-entity + CA certificates)
 * @param {string} format - Format for chain file (pem, der)
 * @returns {Promise<Object>} Download result
 * 
 * @example
 * // Create PEM certificate chain
 * await createCertificateChain('pem')
 */
export async function createCertificateChain(format = 'pem') {
  time('DownloadHelpers.create_certificate_chain')
  
  downloadInfo('Certificate chain creation started', {
    helper_function: 'createCertificateChain',
    bundle_type: 'certificate_chain',
    format: format
  })

  try {
    downloadDebug('API call for certificate chain discovery', {
      helper_context: 'createCertificateChain',
      endpoint: 'getCertificates',
      purpose: 'certificate_chain_discovery'
    })

    const pkcs12Result = await certificateAPI.getCertificates()
    const certificates = pkcs12Result.certificates

    // Find certificate and CA certificates
    const certificate = certificates.find(cert => cert.type === 'Certificate')
    const caCerts = certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )

    if (!certificate) {
      downloadError('Certificate required for certificate chain', {
        helper_function: 'createCertificateChain',
        error_type: 'missing_certificate',
        available_types: certificates.map(c => c.type)
      })
      throw new Error('Certificate required for certificate chain')
    }

    // Build component list (certificate first, then CAs)
    const componentIds = [certificate.id, ...caCerts.map(ca => ca.id)]
    const formats = {}
    
    // Use same format for all certificates
    componentIds.forEach(id => {
      formats[id] = format
    })

    downloadInfo('Certificate chain configuration', {
      helper_function: 'createCertificateChain',
      bundle_type: 'certificate_chain',
      component_count: componentIds.length,
      format: format,
      has_certificate: true,
      has_ca_chain: caCerts.length > 0,
      has_private_key: false
    })

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    downloadDebug('Certificate chain configuration created', {
      helper_function: 'createCertificateChain',
      bundle_type: 'certificate_chain',
      config: config
    })

    downloadDebug('Creating certificate chain with helper:', config)
    
    downloadInfo('Starting certificate chain download', {
      helper_function: 'createCertificateChain',
      endpoint: 'downloadCustomBundle',
      component_count: componentIds.length,
      download_type: 'certificate_chain'
    })

    const downloadResult = await downloadAPI.downloadCustomBundle(config)
    
    downloadInfo('Certificate chain creation completed', {
      helper_function: 'createCertificateChain',
      bundle_type: 'certificate_chain',
      success: downloadResult.success,
      component_count: componentIds.length,
      format: format
    })

    timeEnd('DownloadHelpers.create_certificate_chain')
    return downloadResult
  } catch (error) {
    downloadError('Error in createCertificateChain helper', {
      helper_function: 'createCertificateChain',
      error_message: error.message,
      error_stack: error.stack,
      format: format
    })

    console.error('Error in createCertificateChain helper:', error)
    timeEnd('DownloadHelpers.create_certificate_chain')
    throw error
  }
}

// ===== UTILITY HELPERS =====

/**
 * Get available components in current session
 * @returns {Promise<Object>} Component analysis
 * 
 * @example
 * const analysis = await getSessionAnalysis()
 * downloadDebug('Has private key:', analysis.hasPrivateKey)
 */
export async function getSessionAnalysis() {
  time('DownloadHelpers.get_session_analysis')
  
  downloadInfo('Session analysis started', {
    helper_function: 'getSessionAnalysis'
  })

  try {
    downloadDebug('API call for session analysis', {
      helper_context: 'getSessionAnalysis',
      endpoint: 'getCertificates',
      purpose: 'session_analysis'
    })

    const chainResult = await certificateAPI.getCertificates()
    const certificates = chainResult.certificates

    const analysis = {
      totalComponents: certificates.length,
      hasPrivateKey: certificates.some(cert => cert.type === 'PrivateKey'),
      hasCertificate: certificates.some(cert => cert.type === 'Certificate'), 
      hasCAChain: certificates.some(cert => ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)),
      hasCSR: certificates.some(cert => cert.type === 'CSR'),
      components: certificates.map(cert => ({
        id: cert.id,
        type: cert.type,
        filename: cert.filename
      })),
      canCreatePKCS12: certificates.some(cert => cert.type === 'Certificate') && 
                       certificates.some(cert => cert.type === 'PrivateKey'),
      canCreateChain: certificates.some(cert => cert.type === 'Certificate') &&
                     certificates.some(cert => ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type))
    }

    downloadInfo('Session analysis completed', {
      helper_function: 'getSessionAnalysis',
      total_components: analysis.totalComponents,
      has_private_key: analysis.hasPrivateKey,
      has_certificate: analysis.hasCertificate,
      has_ca_chain: analysis.hasCAChain,
      can_create_pkcs12: analysis.canCreatePKCS12,
      can_create_chain: analysis.canCreateChain
    })

    downloadDebug('Session analysis details', {
      helper_context: 'getSessionAnalysis',
      total_components: analysis.totalComponents,
      component_types: certificates.map(c => c.type),
      bundle_capabilities: {
        pkcs12: analysis.canCreatePKCS12,
        chain: analysis.canCreateChain
      }
    })

    timeEnd('DownloadHelpers.get_session_analysis')
    return analysis
  } catch (error) {
    downloadError('Error in getSessionAnalysis helper', {
      helper_function: 'getSessionAnalysis',
      error_message: error.message,
      error_stack: error.stack
    })

    console.error('Error in getSessionAnalysis helper:', error)
    
    const errorAnalysis = {
      totalComponents: 0,
      hasPrivateKey: false,
      hasCertificate: false,
      hasCAChain: false,
      hasCSR: false,
      components: [],
      canCreatePKCS12: false,
      canCreateChain: false
    }

    timeEnd('DownloadHelpers.get_session_analysis')
    return errorAnalysis
  }
}

/**
 * Validate download configuration before making request
 * @param {Object} config - Download configuration to validate
 * @returns {Promise<Object>} Validation result
 */
export async function validateDownloadConfig(config) {
  time('DownloadHelpers.validate_download_config')
  
  downloadDebug('Download configuration validation started', {
    helper_function: 'validateDownloadConfig',
    has_config: !!config,
    config_keys: config ? Object.keys(config) : []
  })

  try {
    const { components = [], formats = {} } = config
    
    if (components.length === 0) {
      const noComponentsResult = { valid: false, error: 'No components specified' }
      downloadWarn('Config validation failed: no components', {
        helper_function: 'validateDownloadConfig',
        failure_reason: 'no_components',
        validation_result: noComponentsResult
      })
      timeEnd('DownloadHelpers.validate_download_config')
      return noComponentsResult
    }

    // Check if all components have format specifications
    const missingFormats = components.filter(id => !formats[id])
    if (missingFormats.length > 0) {
      const missingFormatsResult = { 
        valid: false, 
        error: `Missing formats for components: ${missingFormats.join(', ')}` 
      }
      downloadWarn('Config validation failed: missing formats', {
        helper_function: 'validateDownloadConfig',
        failure_reason: 'missing_formats',
        missing_format_count: missingFormats.length,
        validation_result: missingFormatsResult
      })
      timeEnd('DownloadHelpers.validate_download_config')
      return missingFormatsResult
    }

    // Verify components exist in session
    downloadDebug('API call for config validation', {
      helper_context: 'validateDownloadConfig',
      endpoint: 'getCertificates',
      purpose: 'config_validation'
    })

    const validationApiResult = await certificateAPI.getCertificates()
    const sessionComponentIds = validationApiResult.certificates.map(cert => cert.id)
    const invalidComponents = components.filter(id => !sessionComponentIds.includes(id))
    
    if (invalidComponents.length > 0) {
      const invalidComponentsResult = {
        valid: false,
        error: `Invalid component IDs: ${invalidComponents.join(', ')}`
      }
      downloadWarn('Config validation failed: invalid component IDs', {
        helper_function: 'validateDownloadConfig',
        failure_reason: 'invalid_component_ids',
        invalid_component_count: invalidComponents.length,
        validation_result: invalidComponentsResult
      })
      timeEnd('DownloadHelpers.validate_download_config')
      return invalidComponentsResult
    }

    const successResult = { valid: true }
    downloadDebug('Config validation successful', {
      helper_function: 'validateDownloadConfig',
      components_count: components.length,
      formats_count: Object.keys(formats).length,
      validation_result: successResult
    })

    timeEnd('DownloadHelpers.validate_download_config')
    return successResult
  } catch (error) {
    const errorResult = { valid: false, error: error.message }
    downloadError('Error in validateDownloadConfig helper', {
      helper_function: 'validateDownloadConfig',
      error_message: error.message,
      error_stack: error.stack,
      validation_result: errorResult
    })

    timeEnd('DownloadHelpers.validate_download_config')
    return errorResult
  }
}

// Export all helper functions
export const downloadHelpers = {
  // Individual component downloads
  downloadPrivateKey,
  downloadCertificate,
  downloadCAChain,
  
  // Advanced downloads
  downloadAll,
  downloadComponents,
  
  // Bundle creation
  createPKCS7Bundle,
  createPKCS12Bundle,
  createCertificateChain,
  
  // Utilities
  getSessionAnalysis,
  validateDownloadConfig,
  
  // Component discovery
  getComponentIdByType,
  getCAComponentIds,
  getAllComponentIds
}