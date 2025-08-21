// frontend/src/services/api.js
// Clean API with proper logging system

import axios from 'axios'
import { 
  apiInfo, apiDebug, apiError, apiWarn,
  sessionInfo, sessionDebug, sessionWarn, sessionError, sessionTransition, sessionExpired, sessionCreated,
  cookieInfo, cookieDebug, cookieWarn, cookieStateChange,
  downloadInfo, downloadDebug, downloadError,
  time, timeEnd
} from '@/utils/logger'

// Helper function to log cookie information
function logCookieInfo(prefix) {
  const allCookies = document.cookie.split(';').reduce((cookies, cookie) => {
    const [name, value] = cookie.trim().split('=')
    cookies[name] = value
    return cookies
  }, {})
  
  const sessionToken = allCookies.session_token
  
  cookieDebug(`${prefix} Cookie State:`)
  cookieDebug(`   - Has session_token: ${!!sessionToken}`)
  if (sessionToken) {
    cookieDebug(`   - Token preview: ${sessionToken.substring(0, 20)}...${sessionToken.substring(sessionToken.length - 10)}`)
    cookieDebug(`   - Token length: ${sessionToken.length}`)
  }
  cookieDebug(`   - All cookies: ${Object.keys(allCookies).join(', ') || 'none'}`)
  
  return { allCookies, sessionToken }
}

// Helper function to detect session changes
let lastKnownSessionToken = null

function detectSessionChange(context) {
  const { sessionToken } = logCookieInfo(`SESSION CHECK - ${context}`)
  
  if (lastKnownSessionToken !== sessionToken) {
    if (lastKnownSessionToken === null) {
      sessionInfo(`Initial session detected: ${sessionToken ? sessionToken.substring(0, 20) + '...' : 'none'}`)
    } else if (sessionToken === null || sessionToken === undefined) {
      sessionError(`Session token LOST! Previous: ${lastKnownSessionToken.substring(0, 20)}...`)
      cookieStateChange('TOKEN_LOST')
    } else {
      sessionTransition(
        lastKnownSessionToken ? lastKnownSessionToken.substring(0, 20) + '...' : 'none',
        sessionToken.substring(0, 20) + '...',
        'TOKEN_CHANGED'
      )
      cookieStateChange('TOKEN_CHANGED')
    }
    lastKnownSessionToken = sessionToken
    return true
  }
  return false
}

// Create axios instance with base configuration
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true
})

// Request interceptor with clean logging
api.interceptors.request.use(
  (config) => {
    apiInfo(`${config.method?.toUpperCase()} ${config.url}`)
    
    // Check session state before request (debug only)
    const sessionChanged = detectSessionChange('PRE-REQUEST')
    if (sessionChanged) {
      sessionWarn(`Session change detected before ${config.method?.toUpperCase()} ${config.url}`)
    }
    
    // Log request timing (debug only)
    config.metadata = { startTime: Date.now() }
    
    return config
  },
  (error) => {
    apiError('Request error:', error)
    return Promise.reject(error)
  }
)

// Response interceptor with clean logging
api.interceptors.response.use(
  (response) => {
    // Calculate request duration (debug only)
    const duration = response.config.metadata ? Date.now() - response.config.metadata.startTime : 'unknown'
    
    apiDebug(`${response.status} ${response.config.method?.toUpperCase()} ${response.config.url} (${duration}ms)`)
    
    // Check for Set-Cookie headers in response (debug only)
    const setCookieHeader = response.headers['set-cookie'] || response.headers['Set-Cookie']
    if (setCookieHeader) {
      cookieInfo(`Server sent Set-Cookie header: ${setCookieHeader}`)
    }
    
    // Check session state after response (debug only)
    setTimeout(() => {
      const sessionChanged = detectSessionChange('POST-RESPONSE')
      if (sessionChanged) {
        sessionWarn(`Session changed after ${response.config.method?.toUpperCase()} ${response.config.url}`)
      }
    }, 100)
    
    return response
  },
  (error) => {
    const status = error.response?.status
    const url = error.config?.url
    const method = error.config?.method?.toUpperCase()
    
    apiError(`${status || 'NETWORK'} ${method} ${url}`)
    apiDebug('Error details:', error.response?.data)
    
    // Check if this might be session-related
    if (status === 401 || status === 403) {
      sessionError(`Potential session issue - ${status} error`)
      detectSessionChange('ERROR-RESPONSE')
    }
    
    // Check for Set-Cookie headers even in error responses (debug only)
    const setCookieHeader = error.response?.headers?.['set-cookie'] || error.response?.headers?.['Set-Cookie']
    if (setCookieHeader) {
      cookieWarn(`Server sent Set-Cookie in error response: ${setCookieHeader}`)
    }
    
    return Promise.reject(error)
  }
)

// Enhanced session monitoring - only in debug mode
if (import.meta.env.VITE_DEBUG === 'true' || localStorage.getItem('certificate_debug') === 'true') {
  // Check every 30 seconds
  setInterval(() => {
    detectSessionChange('PERIODIC-CHECK')
  }, 30000)

  // Monitor page visibility changes
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      sessionDebug('Page became visible - checking session')
      detectSessionChange('PAGE-VISIBLE')
    }
  })

  // Initialize session tracking
  setTimeout(() => {
    detectSessionChange('INITIAL-LOAD')
  }, 1000)
}

/**
 * Map backend PKI component to frontend certificate object
 */
function mapPKIComponentToCertificate(component) {
  apiDebug('Mapping component:', component)
  
  try {
    const metadata = component.metadata || {}
    
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
    
    apiDebug('Mapped certificate:', certificate)
    return certificate
    
  } catch (error) {
    apiError('Error in mapPKIComponentToCertificate:', error)
    apiError('Component that failed:', component)
    throw error
  }
}

// Helper functions for downloads
async function getComponentIdByType(targetType) {
  try {
    const certificates = await certificateAPI.getCertificates()
    const component = certificates.certificates.find(cert => cert.type === targetType)
    return component?.id || null
  } catch (error) {
    apiError(`Error finding ${targetType} component:`, error)
    return null
  }
}

async function getCAComponentIds() {
  try {
    const certificates = await certificateAPI.getCertificates()
    const caComponents = certificates.certificates.filter(cert => 
      ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
    )
    return caComponents.map(cert => cert.id)
  } catch (error) {
    apiError('Error finding CA components:', error)
    return []
  }
}

// Download API
export const downloadAPI = {
  async downloadApacheBundle(includeInstructions = true) {
    try {
      downloadInfo('Starting Apache bundle download')
      detectSessionChange('DOWNLOAD-START')
      
      const result = await this.downloadBundle('apache', {
        includeInstructions
      })
      
      downloadInfo('Apache bundle downloaded successfully')
      detectSessionChange('DOWNLOAD-SUCCESS')
      return result
    } catch (error) {
      downloadError('Apache bundle failed:', error)
      detectSessionChange('DOWNLOAD-ERROR')
      throw new Error(error.response?.data?.detail || 'Apache download failed')
    }
  },

  async downloadIISBundle(includeInstructions = true) {
    try {
      downloadInfo('Starting IIS bundle download')
      const result = await this.downloadBundle('iis', { includeInstructions })
      downloadInfo('IIS bundle downloaded successfully')
      return result
    } catch (error) {
      downloadError('IIS bundle failed:', error)
      throw new Error(error.response?.data?.detail || 'IIS download failed')
    }
  },

  async downloadNginxBundle(includeInstructions = true) {
    try {
      downloadInfo('Starting Nginx bundle download')
      const result = await this.downloadBundle('nginx', { includeInstructions })
      downloadInfo('Nginx bundle downloaded successfully')
      return result
    } catch (error) {
      downloadError('Nginx bundle failed:', error)
      throw new Error(error.response?.data?.detail || 'Nginx download failed')
    }
  },

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
      
      downloadDebug('Downloading private key with custom endpoint:', config)
      const result = await this.downloadCustomBundle(config)
      downloadInfo('Private key downloaded successfully')
      return result
    } catch (error) {
      downloadError('Error downloading private key:', error)
      throw new Error(error.response?.data?.detail || 'Private key download failed')
    }
  },

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
      
      downloadDebug('Downloading certificate with custom endpoint:', config)
      const result = await this.downloadCustomBundle(config)
      downloadInfo('Certificate downloaded successfully')
      return result
    } catch (error) {
      downloadError('Error downloading certificate:', error)
      throw new Error(error.response?.data?.detail || 'Certificate download failed')
    }
  },

  async downloadCAChain(format = 'pem') {
    try {
      const componentIds = await getCAComponentIds()
      if (componentIds.length === 0) {
        throw new Error('No CA certificates found in session')
      }

      const formats = {}
      componentIds.forEach(id => {
        formats[id] = format
      })

      const config = {
        components: componentIds,
        formats: formats,
        includeInstructions: false
      }
      
      downloadDebug('Downloading CA chain with custom endpoint:', config)
      const result = await this.downloadCustomBundle(config)
      downloadInfo('CA chain downloaded successfully')
      return result
    } catch (error) {
      downloadError('Error downloading CA chain:', error)
      throw new Error(error.response?.data?.detail || 'CA chain download failed')
    }
  },

  async downloadPKCS7Bundle(format = 'pem') {
    try {
      const certificates = await certificateAPI.getCertificates()
      const certComponents = certificates.certificates.filter(cert => 
        cert.type === 'Certificate' || ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
      )
      
      if (certComponents.length === 0) {
        throw new Error('No certificates found for PKCS7 bundle')
      }

      const formats = {}
      certComponents.forEach(cert => {
        formats[cert.id] = format
      })
      formats['bundle_pkcs7'] = format

      const config = {
        components: certComponents.map(cert => cert.id),
        formats: formats,
        includeInstructions: false
      }
      
      downloadInfo('PKCS7 bundle downloaded successfully')
      return await this.downloadCustomBundle(config)
    } catch (error) {
      downloadError('Error downloading PKCS7 bundle:', error)
      throw new Error(error.response?.data?.detail || 'PKCS7 download failed')
    }
  },

  async downloadPKCS12Bundle(encryption = 'encrypted') {
    try {
      const certificates = await certificateAPI.getCertificates()
      const certificate = certificates.certificates.find(cert => cert.type === 'Certificate')
      const privateKey = certificates.certificates.find(cert => cert.type === 'PrivateKey')
      
      if (!certificate) {
        throw new Error('Certificate required for PKCS12 bundle')
      }
      if (!privateKey) {
        throw new Error('Private key required for PKCS12 bundle')
      }

      const caCerts = certificates.certificates.filter(cert => 
        ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(cert.type)
      )

      const componentIds = [certificate.id, privateKey.id, ...caCerts.map(ca => ca.id)]
      const formats = {}
      formats['bundle_pkcs12'] = encryption

      const config = {
        components: componentIds,
        formats: formats,
        includeInstructions: false
      }
      
      downloadInfo('PKCS12 bundle downloaded successfully')
      return await this.downloadCustomBundle(config)
    } catch (error) {
      downloadError('Error downloading PKCS12 bundle:', error)
      throw new Error(error.response?.data?.detail || 'PKCS12 download failed')
    }
  },

  async downloadCustomBundle(config) {
    try {
      const result = await this.downloadBundle('custom', config)
      downloadInfo('Custom bundle downloaded successfully')
      return result
    } catch (error) {
      downloadError('Error downloading custom bundle:', error)
      throw new Error(error.response?.data?.detail || 'Custom download failed')
    }
  },

  async downloadBundle(bundleType, options = {}) {
    try {
      downloadInfo(`Starting ${bundleType} bundle download`)
      time(`download-${bundleType}`)
      detectSessionChange('DOWNLOAD-BUNDLE-START')
      
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
      const url = `/downloads/download/${bundleType}${queryString ? '?' + queryString : ''}`
      
      downloadDebug(`Download URL: ${url}`)
      
      const response = await api.post(url, {}, {
        responseType: 'blob',
        timeout: 60000,
      })

      downloadDebug(`Response: ${response.status}`, response.headers)
      detectSessionChange('DOWNLOAD-BUNDLE-SUCCESS')

      const zipPassword = response.headers['x-zip-password']
      const encryptionPassword = response.headers['x-encryption-password']
      
      const contentDisposition = response.headers['content-disposition']
      let filename = `${bundleType}-bundle.zip`
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename=([^;]+)/)
        if (filenameMatch) {
          filename = filenameMatch[1].replace(/"/g, '')
        }
      }

      const blob = new Blob([response.data], { type: 'application/zip' })
      const downloadUrl = window.URL.createObjectURL(blob)
      
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      
      window.URL.revokeObjectURL(downloadUrl)
      timeEnd(`download-${bundleType}`)

      return {
        success: true,
        filename,
        zipPassword,
        encryptionPassword,
        bundleType
      }

    } catch (error) {
      downloadError(`${bundleType} bundle failed:`, error)
      timeEnd(`download-${bundleType}`)
      detectSessionChange('DOWNLOAD-BUNDLE-ERROR')
      throw error
    }
  },

  async getAvailableBundleTypes() {
    try {
      const response = await api.get('/downloads/bundle-types')
      return response.data
    } catch (error) {
      downloadError('Error getting available bundle types:', error)
      throw new Error(error.response?.data?.detail || 'Failed to get available bundle types')
    }
  }
}

// Certificate API
export const certificateAPI = {
  async uploadCertificate(file, password = null) {
    try {
      apiInfo(`Starting certificate upload: ${file.name}`)
      time('upload-certificate')
      detectSessionChange('UPLOAD-START')
      
      const formData = new FormData()
      formData.append('file', file)
      if (password) {
        formData.append('password', password)
      }

      const response = await api.post('/analyze-certificate', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      apiInfo('Upload completed successfully')
      timeEnd('upload-certificate')
      detectSessionChange('UPLOAD-SUCCESS')

      return response.data.success ? response.data : response.data
    } catch (error) {
      apiError('Upload failed:', error)
      timeEnd('upload-certificate')
      detectSessionChange('UPLOAD-ERROR')
      
      if (error.response?.status === 400 && error.response?.data?.requiresPassword) {
        return error.response.data
      }
      
      throw new Error(error.response?.data?.detail || error.response?.data?.message || 'Upload failed')
    }
  },

  async getCertificates(options = {}) {
    try {
      apiInfo('Getting certificates from /certificates endpoint')
      time('get-certificates')
      detectSessionChange('GET-CERTIFICATES-START')
      
      const params = new URLSearchParams()
      if (options.include_validation) {
        params.append('include_validation', 'true')
      }
      if (options.include_chain_info) {
        params.append('include_chain_info', 'true')
      }
      
      const url = `/certificates${params.toString() ? '?' + params.toString() : ''}`
      apiDebug('Request URL:', url)
      
      const response = await api.get(url)

      apiDebug('Raw /certificates response:', response.data)
      apiDebug('Components array:', response.data.components)
      apiDebug('Components length:', response.data.components?.length)
      apiDebug('Validation results:', response.data.validation_results)
      
      timeEnd('get-certificates')
      detectSessionChange('GET-CERTIFICATES-SUCCESS')

      if (response.data.success && response.data.components) {
        apiDebug('Starting component mapping...')

        const certificates = response.data.components.map((component, index) => {
          apiDebug(`Mapping component ${index}:`, component)

          try {
            const mapped = mapPKIComponentToCertificate(component)
            apiDebug(`Mapped component ${index}:`, mapped)
            return mapped
          } catch (mapError) {
            apiError(`Mapping failed for component ${index}:`, mapError)
            return null
          }
        }).filter(cert => cert !== null)

        apiInfo(`Final mapped certificates: ${certificates.length}`)

        const result = {
          success: true,
          certificates: certificates,
          total: certificates.length
        }
        
        if (response.data.validation_results) {
          result.validation_results = response.data.validation_results
          apiDebug('Added validation results to response:', result.validation_results)
        }
        
        return result
      } else {
        apiInfo('No components found or response unsuccessful')
        return {
          success: true,
          certificates: [],
          total: 0
        }
      }
    } catch (error) {
      apiError('Error fetching certificates:', error)
      timeEnd('get-certificates')
      detectSessionChange('GET-CERTIFICATES-ERROR')
      throw new Error(error.response?.data?.message || 'Failed to fetch certificates')
    }
  },

  async deleteCertificate(certificateId) {
    try {
      apiInfo(`Deleting certificate: ${certificateId}`)
      detectSessionChange('DELETE-START')
      
      await api.delete(`/certificates/${certificateId}`)
      
      apiInfo('Certificate deleted successfully')
      detectSessionChange('DELETE-SUCCESS')
      return { success: true }
    } catch (error) {
      apiError('Error deleting certificate:', error)
      detectSessionChange('DELETE-ERROR')
      throw new Error(error.response?.data?.message || 'Delete failed')
    }
  },

  async clearSession() {
    try {
      apiInfo('Clearing session')
      detectSessionChange('CLEAR-START')
      
      await api.post('/certificates/clear')
      
      apiInfo('Session cleared successfully')
      detectSessionChange('CLEAR-SUCCESS')
      return { success: true }
    } catch (error) {
      apiError('Error clearing session:', error)
      detectSessionChange('CLEAR-ERROR')
      throw new Error(error.response?.data?.message || 'Clear session failed')
    }
  }
}

// Health check API
export const healthAPI = {
  async checkHealth() {
    try {
      apiDebug('Checking API health')
      const response = await api.get('/health')
      apiDebug('API health check successful')
      return response.data
    } catch (error) {
      apiError('API health check failed:', error)
      throw error
    }
  },

  async getStats() {
    try {
      apiDebug('Getting API stats')
      const response = await api.get('/stats')
      apiDebug('API stats retrieved successfully')
      return response.data
    } catch (error) {
      apiError('API stats failed:', error)
      throw error
    }
  }
}

// Session debugging utilities
export const sessionDebugUtils = {
  getCurrentSessionInfo() {
    return logCookieInfo('MANUAL-CHECK')
  },
  
  checkSessionNow() {
    return detectSessionChange('MANUAL-TRIGGER')
  },
  
  getLastKnownToken() {
    return lastKnownSessionToken
  },
  
  monitorSession(durationMinutes = 5) {
    sessionInfo(`Starting ${durationMinutes} minute session monitoring`)
    
    const startTime = Date.now()
    const endTime = startTime + (durationMinutes * 60 * 1000)
    
    const monitor = setInterval(() => {
      const currentTime = Date.now()
      const elapsed = Math.round((currentTime - startTime) / 1000)
      
      sessionDebug(`${elapsed}s elapsed - checking session`)
      const changed = detectSessionChange(`MONITOR-${elapsed}s`)
      
      if (changed) {
        sessionWarn(`Session change detected at ${elapsed}s!`)
      }
      
      if (currentTime >= endTime) {
        clearInterval(monitor)
        sessionInfo(`Monitoring complete after ${elapsed}s`)
      }
    }, 10000)
    
    return monitor
  },
  
  setupHourlySessionTest() {
    sessionInfo('Setting up hourly session behavior test')
    
    const hourlyCheck = setInterval(() => {
      const now = new Date()
      const minutes = now.getMinutes()
      
      if (minutes >= 55 || minutes <= 5) {
        sessionWarn(`Critical time check at ${now.toLocaleTimeString()}`)
        const changed = detectSessionChange(`HOURLY-${minutes}min`)
        
        if (changed) {
          sessionError(`Session changed at ${now.toLocaleTimeString()}!`)
        }
      }
    }, 30000)
    
    return hourlyCheck
  }
}

// Backward compatibility
export const advancedDownloadAPI = {
  async getAvailableFormats() {
    try {
      const bundleTypes = await downloadAPI.getAvailableBundleTypes()
      
      return {
        success: true,
        session_id: bundleTypes.session_id,
        components: [],
        bundle_options: bundleTypes.custom_available ? [
          { type: 'custom', name: 'Custom Selection', description: 'Select specific components and formats' }
        ] : [],
        message: "Use downloadAPI.getAvailableBundleTypes() for full information"
      }
    } catch (error) {
      downloadError('Error getting available formats:', error)
      throw new Error(error.response?.data?.detail || 'Failed to get available formats')
    }
  },

  async downloadAdvancedBundle(downloadConfig) {
    try {
      apiDebug('Advanced download (legacy) with config:', downloadConfig)
      
      const config = {
        components: downloadConfig.component_ids || [],
        formats: downloadConfig.format_selections || {},
        includeInstructions: false
      }
      
      return await downloadAPI.downloadCustomBundle(config)
    } catch (error) {
      downloadError('Error in legacy advanced download:', error)
      throw error
    }
  }
}

export { mapPKIComponentToCertificate }
export default api