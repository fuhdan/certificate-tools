// frontend/src/services/api.js
// STEP 3: Frontend Migration Complete - Individual components now use custom endpoint
// Removed individual component endpoints, replaced with custom endpoint calls

import axios from 'axios'
import { sessionManager } from './sessionManager'

// Create axios instance with base configuration
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000, // Increased for downloads
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor to add session ID and auth headers
api.interceptors.request.use(
  (config) => {
    // Add session ID to all requests
    const sessionId = sessionManager.getSessionId()
    if (sessionId) {
      config.headers['X-Session-ID'] = sessionId
    }

    // Add auth token if available
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`
    }

    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for unified error handling
api.interceptors.response.use(
  (response) => {
    return response
  },
  (error) => {
    // Handle authentication errors
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      delete api.defaults.headers.common['Authorization']
    }

    // Handle session-related errors
    if (error.response?.status === 400 && error.response?.data?.detail?.includes('session')) {
      sessionManager.generateNewSession()
    }

    return Promise.reject(error)
  }
)

/**
 * Map backend PKI component to frontend certificate object
 */
function mapPKIComponentToCertificate(component) {
  console.log('🗺️ Mapping component:', component)
  
  try {
    const metadata = component.metadata || {}
    console.log('🗺️ Component metadata:', metadata)
    
    // Base certificate object
    const certificate = {
      id: component.id,
      filename: component.filename,
      uploaded_at: component.uploaded_at,
      content: component.content,
      type: component.type,
      order: component.order,
      original_format: metadata.original_format,
      file_size: metadata.file_size,
      used_password: metadata.used_password,
      is_valid: true,
      validation_errors: [],
      metadata: metadata,
      
      // Component type flags
      has_certificate: component.type === 'Certificate',
      has_private_key: component.type === 'PrivateKey',
      has_csr: component.type === 'CSR',
      has_ca: ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(component.type)
    }
    
    // Add type-specific data based on component type
    if (component.type === 'Certificate' || ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(component.type)) {
      certificate.certificate_info = {
        subject: metadata.subject || 'N/A',
        issuer: metadata.issuer || 'N/A',
        serial_number: metadata.serial_number || 'N/A',
        not_valid_before: metadata.not_valid_before,
        not_valid_after: metadata.not_valid_after,
        is_expired: metadata.is_expired || false,
        days_until_expiry: metadata.days_until_expiry,
        is_ca: metadata.is_ca || false,
        is_self_signed: metadata.is_self_signed || false,
        fingerprint_sha256: metadata.fingerprint_sha256 || metadata.sha256_fingerprint,
        
        // Public key info
        public_key_algorithm: metadata.public_key_algorithm,
        public_key_size: metadata.public_key_size,
        public_key_size_detailed: metadata.public_key_size_detailed,
        public_key_exponent: metadata.public_key_exponent,
        public_key_curve: metadata.public_key_curve,
        
        // Extensions
        subject_alt_name: metadata.subject_alt_name || [],
        key_usage: metadata.key_usage || {},
        extended_key_usage: metadata.extended_key_usage || [],
        basic_constraints: metadata.basic_constraints || {}
      }
    }
    
    if (component.type === 'PrivateKey') {
      certificate.private_key_info = {
        algorithm: metadata.algorithm,
        key_size: metadata.key_size,
        is_encrypted: metadata.is_encrypted || false,
        fingerprint_sha256: metadata.fingerprint_sha256 || metadata.sha256_fingerprint
      }
    }
    
    if (component.type === 'CSR') {
      certificate.csr_info = {
        subject: metadata.subject || 'N/A',
        public_key_algorithm: metadata.public_key_algorithm,
        public_key_size: metadata.public_key_size,
        fingerprint_sha256: metadata.fingerprint_sha256 || metadata.sha256_fingerprint
      }
    }
    
    console.log('✅ Mapped certificate:', certificate)
    return certificate
    
  } catch (error) {
    console.error('💥 Error in mapPKIComponentToCertificate:', error)
    console.error('💥 Component that failed:', component)
    throw error
  }
}

// ===== HELPER FUNCTIONS FOR CUSTOM DOWNLOADS =====

/**
 * Get component ID by type from current session
 */
async function getComponentIdByType(targetType) {
  try {
    const certificates = await certificateAPI.getCertificates()
    const component = certificates.certificates.find(cert => cert.type === targetType)
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
    const certificates = await certificateAPI.getCertificates()
    const caComponents = certificates.certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )
    return caComponents.map(cert => cert.id)
  } catch (error) {
    console.error('Error finding CA components:', error)
    return []
  }
}

// ===== UNIFIED DOWNLOAD API =====
// All downloads now use the unified endpoint

export const downloadAPI = {
  /**
   * Download Apache server bundle
   * @param {boolean} includeInstructions - Whether to include installation guides
   */
  async downloadApacheBundle(includeInstructions = true) {
    try {
      const sessionId = sessionManager.getSessionId()
      const result = await this.downloadBundle('apache', {
        includeInstructions
      })
      
      console.log('Apache bundle downloaded successfully')
      return result
    } catch (error) {
      console.error('Error downloading Apache bundle:', error)
      throw new Error(error.response?.data?.detail || 'Apache download failed')
    }
  },

  /**
   * Download IIS server bundle
   * @param {boolean} includeInstructions - Whether to include installation guides
   */
  async downloadIISBundle(includeInstructions = true) {
    try {
      const sessionId = sessionManager.getSessionId()
      const result = await this.downloadBundle('iis', {
        includeInstructions
      })
      
      console.log('IIS bundle downloaded successfully')
      return result
    } catch (error) {
      console.error('Error downloading IIS bundle:', error)
      throw new Error(error.response?.data?.detail || 'IIS download failed')
    }
  },

  /**
   * Download Nginx server bundle
   * @param {boolean} includeInstructions - Whether to include installation guides
   */
  async downloadNginxBundle(includeInstructions = true) {
    try {
      const sessionId = sessionManager.getSessionId()
      const result = await this.downloadBundle('nginx', {
        includeInstructions
      })
      
      console.log('Nginx bundle downloaded successfully')
      return result
    } catch (error) {
      console.error('Error downloading Nginx bundle:', error)
      throw new Error(error.response?.data?.detail || 'Nginx download failed')
    }
  },

  /**
   * Download private key only - UPDATED: Now uses custom endpoint
   * @param {string} format - Format for private key (pem, der, pkcs8, pkcs8_encrypted, pem_encrypted)
   */
  async downloadPrivateKey(format = 'pem') {
    try {
      const componentId = await getComponentIdByType('PrivateKey')
      if (!componentId) {
        throw new Error('No private key found in session')
      }

      const config = {
        components: [componentId],
        formats: { [componentId]: format },
        includeInstructions: false
      }
      
      console.log('Downloading private key with custom endpoint:', config)
      const result = await this.downloadCustomBundle(config)
      
      console.log('Private key downloaded successfully')
      return result
    } catch (error) {
      console.error('Error downloading private key:', error)
      throw new Error(error.response?.data?.detail || 'Private key download failed')
    }
  },

  /**
   * Download certificate only - UPDATED: Now uses custom endpoint
   * @param {string} format - Format for certificate (pem, der)
   */
  async downloadCertificate(format = 'pem') {
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
      
      console.log('Downloading certificate with custom endpoint:', config)
      const result = await this.downloadCustomBundle(config)
      
      console.log('Certificate downloaded successfully')
      return result
    } catch (error) {
      console.error('Error downloading certificate:', error)
      throw new Error(error.response?.data?.detail || 'Certificate download failed')
    }
  },

  /**
   * Download CA certificate chain - UPDATED: Now uses custom endpoint
   * @param {string} format - Format for CA certificates (pem, der)
   */
  async downloadCAChain(format = 'pem') {
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
      
      console.log('Downloading CA chain with custom endpoint:', config)
      const result = await this.downloadCustomBundle(config)
      
      console.log('CA chain downloaded successfully')
      return result
    } catch (error) {
      console.error('Error downloading CA chain:', error)
      throw new Error(error.response?.data?.detail || 'CA chain download failed')
    }
  },

  /**
   * Download PKCS7 bundle - UPDATED: Now uses custom endpoint with chain creation
   * @param {string} format - Format for PKCS7 (pem, der)
   */
  async downloadPKCS7Bundle(format = 'pem') {
    try {
      // Get all certificate components (end-entity + CA certificates)
      const certificates = await certificateAPI.getCertificates()
      const certComponents = certificates.certificates.filter(cert => 
        cert.type === 'Certificate' || ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
      )
      
      if (certComponents.length === 0) {
        throw new Error('No certificates found for PKCS7 bundle')
      }

      // Create format mapping for all certificates
      const formats = {}
      certComponents.forEach(cert => {
        formats[cert.id] = format
      })

      // Use special bundle format key for PKCS7
      formats['bundle_pkcs7'] = format

      const config = {
        components: certComponents.map(cert => cert.id),
        formats: formats,
        includeInstructions: false
      }
      
      console.log('PKCS7 bundle downloaded successfully with custom endpoint')
      return await this.downloadCustomBundle(config)
    } catch (error) {
      console.error('Error downloading PKCS7 bundle:', error)
      throw new Error(error.response?.data?.detail || 'PKCS7 download failed')
    }
  },

  /**
   * Download PKCS12 bundle - UPDATED: Now uses custom endpoint with bundle creation
   * @param {string} encryption - Encryption type (encrypted, unencrypted)
   */
  async downloadPKCS12Bundle(encryption = 'encrypted') {
    try {
      // Get required components for PKCS12
      const certificates = await certificateAPI.getCertificates()
      const certificate = certificates.certificates.find(cert => cert.type === 'Certificate')
      const privateKey = certificates.certificates.find(cert => cert.type === 'PrivateKey')
      
      if (!certificate) {
        throw new Error('Certificate required for PKCS12 bundle')
      }
      if (!privateKey) {
        throw new Error('Private key required for PKCS12 bundle')
      }

      // Find CA certificates
      const caCerts = certificates.certificates.filter(cert => 
        ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
      )

      // Build component list and formats
      const componentIds = [certificate.id, privateKey.id, ...caCerts.map(ca => ca.id)]
      const formats = {}
      
      // Use special bundle format key for PKCS12
      formats['bundle_pkcs12'] = encryption

      const config = {
        components: componentIds,
        formats: formats,
        includeInstructions: false
      }
      
      console.log('PKCS12 bundle downloaded successfully with custom endpoint')
      return await this.downloadCustomBundle(config)
    } catch (error) {
      console.error('Error downloading PKCS12 bundle:', error)
      throw new Error(error.response?.data?.detail || 'PKCS12 download failed')
    }
  },

  /**
   * Download custom bundle with specific components and formats
   * @param {Object} config - Download configuration
   * @param {string[]} config.components - Array of component IDs
   * @param {Object} config.formats - Format selections for components
   * @param {boolean} config.includeInstructions - Whether to include instructions
   */
  async downloadCustomBundle(config) {
    try {
      const sessionId = sessionManager.getSessionId()
      const result = await this.downloadBundle('custom', config)
      
      console.log('Custom bundle downloaded successfully')
      return result
    } catch (error) {
      console.error('Error downloading custom bundle:', error)
      throw new Error(error.response?.data?.detail || 'Custom download failed')
    }
  },

  /**
   * Core download method - handles all bundle types
   * @param {string} bundleType - Type of bundle to download
   * @param {Object} options - Download options
   */
  async downloadBundle(bundleType, options = {}) {
    try {
      const sessionId = sessionManager.getSessionId()
      
      // Build query parameters
      const params = new URLSearchParams()
      
      if (options.includeInstructions !== undefined) {
        params.append('include_instructions', options.includeInstructions)
      }
      
      if (options.formats) {
        params.append('formats', JSON.stringify(options.formats))
      }
      
      if (options.components) {
        params.append('components', JSON.stringify(options.components))
      }
      
      const queryString = params.toString()
      const url = `/downloads/download/${bundleType}/${sessionId}${queryString ? '?' + queryString : ''}`
      
      console.log(`Downloading ${bundleType} bundle from:`, url)
      
      // Make API call
      const response = await api.post(url, {}, {
        responseType: 'blob',
        timeout: 60000, // 60 seconds for large downloads
      })

      console.log(`${bundleType} bundle response received:`, response.status, response.headers)

      // Extract passwords from response headers
      const zipPassword = response.headers['x-zip-password']
      const encryptionPassword = response.headers['x-encryption-password']
      
      // Create download filename from Content-Disposition header
      const contentDisposition = response.headers['content-disposition']
      let filename = `${bundleType}-bundle-${sessionId.substring(0, 8)}.zip`
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename=([^;]+)/)
        if (filenameMatch) {
          filename = filenameMatch[1].replace(/"/g, '')
        }
      }

      // Trigger download
      const blob = new Blob([response.data], { type: 'application/zip' })
      const downloadUrl = window.URL.createObjectURL(blob)
      
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      
      // Clean up
      window.URL.revokeObjectURL(downloadUrl)

      return {
        success: true,
        filename,
        zipPassword,
        encryptionPassword,
        bundleType
      }

    } catch (error) {
      console.error(`Error downloading ${bundleType} bundle:`, error)
      console.error('Error response:', error.response?.data)
      console.error('Error status:', error.response?.status)
      throw error
    }
  },

  /**
   * Get available bundle types for current session
   */
  async getAvailableBundleTypes() {
    try {
      const sessionId = sessionManager.getSessionId()
      const response = await api.get(`/downloads/bundle-types/${sessionId}`)
      return response.data
    } catch (error) {
      console.error('Error getting available bundle types:', error)
      throw new Error(error.response?.data?.detail || 'Failed to get available bundle types')
    }
  }
}

// ===== BACKWARD COMPATIBILITY WRAPPERS =====
// These maintain compatibility with existing frontend code

export const advancedDownloadAPI = {
  /**
   * Get available download formats for session components
   * @deprecated Use downloadAPI.getAvailableBundleTypes() instead
   */
  async getAvailableFormats() {
    try {
      const bundleTypes = await downloadAPI.getAvailableBundleTypes()
      
      // Convert new format to old format for compatibility
      return {
        success: true,
        session_id: bundleTypes.session_id,
        components: [], // Would need to be populated from session data
        bundle_options: bundleTypes.custom_available ? [
          { type: 'custom', name: 'Custom Selection', description: 'Select specific components and formats' }
        ] : [],
        message: "Use downloadAPI.getAvailableBundleTypes() for full information"
      }
    } catch (error) {
      console.error('Error getting available formats:', error)
      throw new Error(error.response?.data?.detail || 'Failed to get available formats')
    }
  },

  /**
   * Download advanced bundle with custom format selections
   * @deprecated Use downloadAPI.downloadCustomBundle() instead
   */
  async downloadAdvancedBundle(downloadConfig) {
    try {
      console.log('🔥 Advanced download (legacy) with config:', downloadConfig)
      
      // Convert legacy format to new format
      const config = {
        components: downloadConfig.component_ids || [],
        formats: downloadConfig.format_selections || {},
        includeInstructions: false // Advanced downloads typically don't include instructions
      }
      
      return await downloadAPI.downloadCustomBundle(config)
    } catch (error) {
      console.error('❌ Error in legacy advanced download:', error)
      throw error
    }
  }
}

// ===== CERTIFICATE API =====

export const certificateAPI = {
  async uploadCertificate(file, password = null) {
    try {
      const formData = new FormData()
      formData.append('file', file)  // Backend expects 'file' field name
      if (password) {
        formData.append('password', password)
      }

      const response = await api.post('/analyze-certificate', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      if (response.data.success) {
        return response.data
      }

      return response.data
    } catch (error) {
      // Check if this is a password requirement, not an actual error
      if (error.response?.status === 400 && error.response?.data?.requiresPassword) {
        // Return the password requirement response instead of throwing an error
        return error.response.data
      }
      
      console.error('Error uploading certificate:', error)
      throw new Error(error.response?.data?.detail || error.response?.data?.message || 'Upload failed')
    }
  },

  async getCertificates() {
    try {
      console.log('🔄 API: Getting certificates from /certificates endpoint...')
      const response = await api.get('/certificates')

      console.log('📥 API: Raw /certificates response:', response.data)
      console.log('📥 API: Components array:', response.data.components)
      console.log('📥 API: Components length:', response.data.components?.length)

      if (response.data.success && response.data.components) {
        console.log('🔄 API: Starting component mapping...')

        const certificates = response.data.components.map((component, index) => {
          console.log(`🔍 API: Mapping component ${index}:`, component)
          console.log(`🔍 API: Component keys:`, Object.keys(component))
          console.log(`🔍 API: Component type:`, component.type)
          console.log(`🔍 API: Component metadata:`, component.metadata)

          try {
            const mapped = mapPKIComponentToCertificate(component)
            console.log(`✅ API: Mapped component ${index}:`, mapped)
            console.log(`✅ API: Mapped component type:`, mapped?.type)
            return mapped
          } catch (mapError) {
            console.error(`💥 API: Mapping failed for component ${index}:`, mapError)
            return null
          }
        }).filter(cert => cert !== null) // Remove any failed mappings

        console.log('🎯 API: Final mapped certificates:', certificates)
        console.log('🎯 API: Final certificates count:', certificates.length)

        return {
          success: true,
          certificates: certificates,
          total: certificates.length
        }
      } else {
        console.log('❌ API: No components found or response unsuccessful')
        return {
          success: true,
          certificates: [],
          total: 0
        }
      }
    } catch (error) {
      console.error('💥 API: Error fetching certificates:', error)
      throw new Error(error.response?.data?.message || 'Failed to fetch certificates')
    }
  },

  async deleteCertificate(certificateId) {
    try {
      await api.delete(`/certificates/${certificateId}`)
      return { success: true }
    } catch (error) {
      console.error('Error deleting certificate:', error)
      throw new Error(error.response?.data?.message || 'Delete failed')
    }
  },

  async clearSession() {
    try {
      await api.post('/certificates/clear')
      return { success: true }
    } catch (error) {
      console.error('Error clearing session:', error)
      throw new Error(error.response?.data?.message || 'Clear session failed')
    }
  },

  async getValidationResults() {
    try {
      const response = await api.get('/validate')
      return response.data
    } catch (error) {
      console.error('Error fetching validation results:', error)
      throw new Error(error.response?.data?.message || 'Failed to fetch validation results')
    }
  }
}

// PKI Bundle API methods
export const pkiAPI = {
  async getPKIBundle() {
    try {
      const response = await api.get('/pki-bundle')
      return response.data
    } catch (error) {
      console.error('Error fetching PKI bundle:', error)
      throw new Error(error.response?.data?.message || 'Failed to fetch PKI bundle')
    }
  },

  async downloadPKIBundle(format = 'json', password) {
    try {
      const config = {
        params: { format },
        responseType: format === 'json' ? 'json' : 'blob'
      }
      
      if (password) {
        config.headers = { 'X-Archive-Password': password }
      }
      
      const response = await api.get('/pki-bundle/download', config)
      return response
    } catch (error) {
      console.error('Error downloading PKI bundle:', error)
      throw new Error(error.response?.data?.message || 'Download failed')
    }
  }
}

// Authentication API methods
export const authAPI = {
  async login(credentials) {
    const response = await api.post('/token', credentials, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
    return response.data
  },

  async getCurrentUser() {
    const response = await api.get('/users/me/')
    return response.data
  },

  async refreshToken(refreshToken) {
    const response = await api.post('/auth/refresh', { refresh_token: refreshToken })
    return response.data
  }
}

// Health check API
export const healthAPI = {
  async checkHealth() {
    const response = await api.get('/health')
    return response.data
  },

  async getStats() {
    const response = await api.get('/stats')
    return response.data
  }
}

export { mapPKIComponentToCertificate }
export default api