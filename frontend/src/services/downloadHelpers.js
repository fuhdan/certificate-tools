// frontend/src/services/downloadHelpers.js

import { downloadAPI, certificateAPI } from './api'

/**
 * Helper functions for common download patterns using the unified custom endpoint
 * These provide a simple interface while using the powerful custom endpoint behind the scenes
 */

/**
 * Get component ID by type from current session
 */
async function getComponentIdByType(targetType) {
  try {
    const result = await certificateAPI.getCertificates()
    const component = result.certificates.find(cert => cert.type === targetType)
    return component?.id || null
  } catch (error) {
    console.error(`Error finding ${targetType} component:`, error)
    return null
  }
}

/**
 * Get CA component IDs from current session
 */
async function getCAComponentIds() {
  try {
    const result = await certificateAPI.getCertificates()
    const caComponents = result.certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )
    return caComponents.map(cert => cert.id)
  } catch (error) {
    console.error('Error finding CA components:', error)
    return []
  }
}

/**
 * Get all component IDs from current session  
 */
async function getAllComponentIds() {
  try {
    const result = await certificateAPI.getCertificates()
    return result.certificates.map(cert => cert.id)
  } catch (error) {
    console.error('Error getting all components:', error)
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
  try {
    // Handle convenience encrypted parameter
    if (encrypted && format === 'pem') {
      format = 'pem_encrypted'
    } else if (encrypted && format === 'pkcs8') {
      format = 'pkcs8_encrypted'
    }

    const componentId = await getComponentIdByType('PrivateKey')
    if (!componentId) {
      throw new Error('No private key found in session')
    }

    const config = {
      components: [componentId],
      formats: { [componentId]: format },
      includeInstructions: false
    }
    
    console.log('Downloading private key with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in downloadPrivateKey helper:', error)
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
  try {
    const componentId = await getComponentIdByType('Certificate')
    if (!componentId) {
      throw new Error('No certificate found in session')
    }

    const config = {
      components: [componentId],
      formats: { [componentId]: format },
      includeInstructions: false
    }
    
    console.log('Downloading certificate with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in downloadCertificate helper:', error)
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
  try {
    const componentIds = await getCAComponentIds()
    if (componentIds.length === 0) {
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
    
    console.log('Downloading CA chain with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in downloadCAChain helper:', error)
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
  try {
    const result = await certificateAPI.getCertificates()
    const certificates = result.certificates

    if (certificates.length === 0) {
      throw new Error('No components found in session')
    }

    const componentIds = certificates.map(cert => cert.id)
    const formats = {}

    // Apply formats based on component types
    certificates.forEach(cert => {
      const overrideFormat = formatOverrides[cert.type]
      formats[cert.id] = overrideFormat || defaultFormat
    })

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    console.log('Downloading all components with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in downloadAll helper:', error)
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
  try {
    if (!componentIds || componentIds.length === 0) {
      throw new Error('No component IDs provided')
    }

    if (!formats || Object.keys(formats).length === 0) {
      throw new Error('No format mappings provided')
    }

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: includeInstructions
    }
    
    console.log('Downloading components with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in downloadComponents helper:', error)
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
  try {
    const result = await certificateAPI.getCertificates()
    const certificates = result.certificates

    // Find certificate and CA certificates for PKCS7
    const certificate = certificates.find(cert => cert.type === 'Certificate')
    const caCerts = certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )

    if (!certificate) {
      throw new Error('Certificate required for PKCS7 bundle')
    }

    // Build component list (certificate + CAs, no private key for PKCS7)
    const componentIds = [certificate.id, ...caCerts.map(ca => ca.id)]
    const formats = {}
    
    // Use special format key to request PKCS7 bundle creation
    formats['bundle_pkcs7'] = format
    
    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    console.log('Creating PKCS#7 bundle with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in createPKCS7Bundle helper:', error)
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
  try {
    const result = await certificateAPI.getCertificates()
    const certificates = result.certificates

    // Find required components
    const certificate = certificates.find(cert => cert.type === 'Certificate')
    const privateKey = certificates.find(cert => cert.type === 'PrivateKey')
    
    if (!certificate) {
      throw new Error('Certificate required for PKCS#12 bundle')
    }
    if (!privateKey) {
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
    
    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    console.log('Creating PKCS#12 bundle with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in createPKCS12Bundle helper:', error)
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
  try {
    const result = await certificateAPI.getCertificates()
    const certificates = result.certificates

    // Find certificate and CA certificates
    const certificate = certificates.find(cert => cert.type === 'Certificate')
    const caCerts = certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )

    if (!certificate) {
      throw new Error('Certificate required for certificate chain')
    }

    // Build component list (certificate first, then CAs)
    const componentIds = [certificate.id, ...caCerts.map(ca => ca.id)]
    const formats = {}
    
    // Use same format for all certificates
    componentIds.forEach(id => {
      formats[id] = format
    })

    const config = {
      components: componentIds,
      formats: formats,
      includeInstructions: false
    }
    
    console.log('Creating certificate chain with helper:', config)
    return await downloadAPI.downloadCustomBundle(config)
  } catch (error) {
    console.error('Error in createCertificateChain helper:', error)
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
 * console.log('Has private key:', analysis.hasPrivateKey)
 */
export async function getSessionAnalysis() {
  try {
    const result = await certificateAPI.getCertificates()
    const certificates = result.certificates

    return {
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
  } catch (error) {
    console.error('Error in getSessionAnalysis helper:', error)
    return {
      totalComponents: 0,
      hasPrivateKey: false,
      hasCertificate: false,
      hasCAChain: false,
      hasCSR: false,
      components: [],
      canCreatePKCS12: false,
      canCreateChain: false
    }
  }
}

/**
 * Validate download configuration before making request
 * @param {Object} config - Download configuration to validate
 * @returns {Promise<Object>} Validation result
 */
export async function validateDownloadConfig(config) {
  try {
    const { components = [], formats = {} } = config
    
    if (components.length === 0) {
      return { valid: false, error: 'No components specified' }
    }

    // Check if all components have format specifications
    const missingFormats = components.filter(id => !formats[id])
    if (missingFormats.length > 0) {
      return { 
        valid: false, 
        error: `Missing formats for components: ${missingFormats.join(', ')}` 
      }
    }

    // Verify components exist in session
    const result = await certificateAPI.getCertificates()
    const sessionComponentIds = result.certificates.map(cert => cert.id)
    const invalidComponents = components.filter(id => !sessionComponentIds.includes(id))
    
    if (invalidComponents.length > 0) {
      return {
        valid: false,
        error: `Invalid component IDs: ${invalidComponents.join(', ')}`
      }
    }

    return { valid: true }
  } catch (error) {
    return { valid: false, error: error.message }
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