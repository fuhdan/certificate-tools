// frontend/src/services/api.js
// Fixed API file with proper exports and data mapping

import axios from 'axios'
import { sessionManager } from './sessionManager'

// Create axios instance with base configuration
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
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
      // Regenerate session ID for session errors
      sessionManager.generateNewSession()
    }

    return Promise.reject(error)
  }
)

/**
 * Map backend PKI component to frontend certificate object
 * Updated to handle new flattened metadata from extractors
 */
function mapPKIComponentToCertificate(component) {
  const metadata = component.metadata || {}
  
  // Base certificate object - FIXED: Pass metadata directly through
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
    is_valid: true, // TODO: Get from validation
    validation_errors: [],
    
    // CRITICAL FIX: Pass ALL metadata directly through
    metadata: metadata,
    
    // Component type flags
    has_certificate: false,
    has_private_key: false,
    has_csr: false
  }

  // Map certificate data if it's a certificate component
  if (component.type === 'Certificate' || component.type === 'RootCA' || 
      component.type === 'IntermediateCA' || component.type === 'IssuingCA') {
    
    certificate.has_certificate = true
    certificate.certificate_info = {
      // Basic certificate info (backward compatibility)
      subject: metadata.subject,
      issuer: metadata.issuer,
      serial_number: metadata.serial_number,
      is_ca: metadata.is_ca,
      is_self_signed: metadata.is_self_signed,
      fingerprint_sha256: metadata.fingerprint_sha256,
      
      // Detailed subject fields (NEW)
      subject_common_name: metadata.subject_common_name,
      subject_organization: metadata.subject_organization,
      subject_organizational_unit: metadata.subject_organizational_unit,
      subject_country: metadata.subject_country,
      subject_state: metadata.subject_state,
      subject_locality: metadata.subject_locality,
      subject_email: metadata.subject_email,
      
      // Detailed issuer fields (NEW)
      issuer_common_name: metadata.issuer_common_name,
      issuer_organization: metadata.issuer_organization,
      issuer_organizational_unit: metadata.issuer_organizational_unit,
      issuer_country: metadata.issuer_country,
      issuer_state: metadata.issuer_state,
      issuer_locality: metadata.issuer_locality,
      issuer_email: metadata.issuer_email,
      
      // Validity information (NEW)
      not_valid_before: metadata.not_valid_before,
      not_valid_after: metadata.not_valid_after,
      is_expired: metadata.is_expired,
      days_until_expiry: metadata.days_until_expiry,
      
      // Signature and public key info (NEW)
      signature_algorithm: metadata.signature_algorithm,
      signature_algorithm_oid: metadata.signature_algorithm_oid,
      public_key_algorithm: metadata.public_key_algorithm,
      public_key_size: metadata.public_key_size,
      public_key_exponent: metadata.public_key_exponent,
      public_key_curve: metadata.public_key_curve,
      
      // Extensions (NEW flattened format)
      subject_alt_name: metadata.subject_alt_name || [],
      key_usage: metadata.key_usage || {},
      extended_key_usage: metadata.extended_key_usage || [],
      basic_constraints: metadata.basic_constraints || {},
      authority_key_identifier: metadata.authority_key_identifier,
      subject_key_identifier: metadata.subject_key_identifier
    }
  }

  // Map private key data if it's a private key component
  if (component.type === 'PrivateKey') {
    certificate.has_private_key = true
    certificate.private_key_info = {
      // Basic private key info (backward compatibility)
      algorithm: metadata.algorithm,
      key_size: metadata.key_size,
      is_encrypted: metadata.is_encrypted,
      public_key_fingerprint: metadata.public_key_fingerprint,
      
      // Algorithm-specific fields (NEW)
      rsa_exponent: metadata.rsa_exponent,
      rsa_modulus_bits: metadata.rsa_modulus_bits,
      ec_curve: metadata.ec_curve,
      ec_curve_oid: metadata.ec_curve_oid,
      ec_private_value_bits: metadata.ec_private_value_bits,
      ec_x_coord_bits: metadata.ec_x_coord_bits,
      ec_y_coord_bits: metadata.ec_y_coord_bits,
      dsa_p_bits: metadata.dsa_p_bits,
      dsa_q_bits: metadata.dsa_q_bits,
      dsa_g_bits: metadata.dsa_g_bits,
      dsa_y_bits: metadata.dsa_y_bits,
      curve: metadata.curve // For Ed25519/Ed448
    }
  }

  // Map CSR data if it's a CSR component
  if (component.type === 'CSR') {
    certificate.has_csr = true
    certificate.csr_info = {
      // Basic CSR info (backward compatibility)
      subject: metadata.subject,
      signature_algorithm: metadata.signature_algorithm,
      public_key_algorithm: metadata.public_key_algorithm,
      public_key_size: metadata.public_key_size,
      public_key_fingerprint: metadata.public_key_fingerprint,
      
      // Detailed subject fields (NEW)
      subject_common_name: metadata.subject_common_name,
      subject_organization: metadata.subject_organization,
      subject_organizational_unit: metadata.subject_organizational_unit,
      subject_country: metadata.subject_country,
      subject_state: metadata.subject_state,
      subject_locality: metadata.subject_locality,
      subject_email: metadata.subject_email,
      
      // Signature info (NEW)
      signature_algorithm_oid: metadata.signature_algorithm_oid,
      
      // Public key details (NEW)
      public_key_algorithm_detailed: metadata.public_key_algorithm_detailed,
      public_key_size_detailed: metadata.public_key_size_detailed,
      public_key_exponent: metadata.public_key_exponent,
      public_key_curve: metadata.public_key_curve,
      
      // Extensions (NEW flattened format)
      subject_alt_name: metadata.subject_alt_name || [],
      key_usage: metadata.key_usage || {},
      extended_key_usage: metadata.extended_key_usage || [],
      basic_constraints: metadata.basic_constraints || {}
    }
  }

  return certificate
}

// Certificate API methods
export const certificateAPI = {
  // Get all certificates for current session
  async getCertificates() {
    try {
      const sessionId = sessionManager.getSessionId()
      const response = await api.get(`/session/${sessionId}/components`)
      
      // Map each component to frontend certificate format
      const certificates = response.data.map(component => 
        mapPKIComponentToCertificate(component)
      )
      
      return {
        success: true,
        certificates: certificates,
        total: certificates.length
      }
    } catch (error) {
      console.error('Error fetching certificates:', error)
      throw new Error(error.response?.data?.message || 'Failed to fetch certificates')
    }
  },

  // Upload and analyze certificate
  async uploadCertificate(file, password = null) {
    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('session_id', sessionManager.getSessionId())
      if (password) {
        formData.append('password', password)
      }

      const response = await api.post('/analyze-certificate', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      // Refresh certificates after upload
      if (response.data.success) {
        return await this.getCertificates()
      }

      return response.data
    } catch (error) {
      console.error('Error uploading certificate:', error)
      throw new Error(error.response?.data?.message || 'Upload failed')
    }
  },

  // Delete certificate
  async deleteCertificate(certificateId) {
    try {
      const sessionId = sessionManager.getSessionId()
      await api.delete(`/session/${sessionId}/components/${certificateId}`)
      return { success: true }
    } catch (error) {
      console.error('Error deleting certificate:', error)
      throw new Error(error.response?.data?.message || 'Delete failed')
    }
  },

  // Clear session
  async clearSession() {
    try {
      const sessionId = sessionManager.getSessionId()
      await api.delete(`/session/${sessionId}`)
      return { success: true }
    } catch (error) {
      console.error('Error clearing session:', error)
      throw new Error(error.response?.data?.message || 'Clear session failed')
    }
  },

  // Get validation results
  async getValidationResults() {
    try {
      const sessionId = sessionManager.getSessionId()
      const response = await api.get(`/session/${sessionId}/validation`)
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
      const sessionId = sessionManager.getSessionId()
      const response = await api.get(`/pki-bundle?session_id=${sessionId}`)
      return response.data
    } catch (error) {
      console.error('Error fetching PKI bundle:', error)
      throw new Error(error.response?.data?.message || 'Failed to fetch PKI bundle')
    }
  },

  async downloadPKIBundle(format = 'json', password) {
    try {
      const sessionId = sessionManager.getSessionId()
      const config = {
        params: { session_id: sessionId, format },
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
    const response = await api.post('/auth/token', credentials, {
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

// Export the mapping function
export { mapPKIComponentToCertificate }

// Default export for backward compatibility
export default api