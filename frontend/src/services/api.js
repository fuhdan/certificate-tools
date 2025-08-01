// frontend/src/services/api.js
// FIXED: Updated to use sha256_fingerprint and correct endpoints

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
      sessionManager.generateNewSession()
    }

    return Promise.reject(error)
  }
)

/**
 * Map backend PKI component to frontend certificate object
 * FIXED: Use sha256_fingerprint instead of public_key_fingerprint
 */
function mapPKIComponentToCertificate(component) {
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
    has_certificate: false,
    has_private_key: false,
    has_csr: false
  }

  // Map certificate data if it's a certificate component
  if (component.type === 'Certificate' || component.type === 'RootCA' || 
      component.type === 'IntermediateCA' || component.type === 'IssuingCA') {
    
    certificate.has_certificate = true
    certificate.certificate_info = {
      subject: metadata.subject,
      issuer: metadata.issuer,
      serial_number: metadata.serial_number,
      is_ca: metadata.is_ca,
      is_self_signed: metadata.is_self_signed,
      fingerprint_sha256: metadata.fingerprint_sha256,
      
      // Detailed subject fields
      subject_common_name: metadata.subject_common_name,
      subject_organization: metadata.subject_organization,
      subject_organizational_unit: metadata.subject_organizational_unit,
      subject_country: metadata.subject_country,
      subject_state: metadata.subject_state,
      subject_locality: metadata.subject_locality,
      subject_email: metadata.subject_email,
      
      // Detailed issuer fields
      issuer_common_name: metadata.issuer_common_name,
      issuer_organization: metadata.issuer_organization,
      issuer_organizational_unit: metadata.issuer_organizational_unit,
      issuer_country: metadata.issuer_country,
      issuer_state: metadata.issuer_state,
      issuer_locality: metadata.issuer_locality,
      issuer_email: metadata.issuer_email,
      
      // Validity information
      not_valid_before: metadata.not_valid_before,
      not_valid_after: metadata.not_valid_after,
      is_expired: metadata.is_expired,
      days_until_expiry: metadata.days_until_expiry,
      
      // Signature and public key info
      signature_algorithm: metadata.signature_algorithm,
      signature_algorithm_oid: metadata.signature_algorithm_oid,
      public_key_algorithm: metadata.public_key_algorithm,
      public_key_size: metadata.public_key_size,
      public_key_exponent: metadata.public_key_exponent,
      public_key_curve: metadata.public_key_curve,
      
      // Extensions
      subject_alt_name: metadata.subject_alt_name || [],
      key_usage: metadata.key_usage || {},
      extended_key_usage: metadata.extended_key_usage || [],
      basic_constraints: metadata.basic_constraints || {},
      authority_key_identifier: metadata.authority_key_identifier,
      subject_key_identifier: metadata.subject_key_identifier
    }
  }

  // Map private key data
  if (component.type === 'PrivateKey') {
    certificate.has_private_key = true
    certificate.private_key_info = {
      algorithm: metadata.algorithm,
      key_size: metadata.key_size,
      is_encrypted: metadata.is_encrypted,
      // FIXED: Use sha256_fingerprint instead of public_key_fingerprint
      public_key_fingerprint: metadata.sha256_fingerprint,
      
      // Algorithm-specific fields
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
      curve: metadata.curve
    }
  }

  // Map CSR data
  if (component.type === 'CSR') {
    certificate.has_csr = true
    certificate.csr_info = {
      subject: metadata.subject,
      signature_algorithm: metadata.signature_algorithm,
      public_key_algorithm: metadata.public_key_algorithm,
      public_key_size: metadata.public_key_size,
      // FIXED: Use sha256_fingerprint instead of public_key_fingerprint
      public_key_fingerprint: metadata.sha256_fingerprint,
      
      // Detailed subject fields
      subject_common_name: metadata.subject_common_name,
      subject_organization: metadata.subject_organization,
      subject_organizational_unit: metadata.subject_organizational_unit,
      subject_country: metadata.subject_country,
      subject_state: metadata.subject_state,
      subject_locality: metadata.subject_locality,
      subject_email: metadata.subject_email,
      
      // Signature info
      signature_algorithm_oid: metadata.signature_algorithm_oid,
      
      // Public key details
      public_key_algorithm_detailed: metadata.public_key_algorithm_detailed,
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

  return certificate
}

// Certificate API methods
export const certificateAPI = {
  async getCertificates() {
    try {
      const response = await api.get('/certificates')
      
      if (response.data.success && response.data.components) {
        const certificates = response.data.components.map(component => 
          mapPKIComponentToCertificate(component)
        )
        
        return {
          success: true,
          certificates: certificates,
          total: certificates.length
        }
      } else {
        return {
          success: true,
          certificates: [],
          total: 0
        }
      }
    } catch (error) {
      console.error('Error fetching certificates:', error)
      throw new Error(error.response?.data?.message || 'Failed to fetch certificates')
    }
  },

  async uploadCertificate(file, password = null) {
    try {
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

      if (response.data.success) {
        return await this.getCertificates()
      }

      return response.data
    } catch (error) {
      // Check if this is a password requirement, not an actual error
      if (error.response?.status === 400 && error.response?.data?.requiresPassword) {
        // Return the password requirement response instead of throwing an error
        return error.response.data
      }
      
      console.error('Error uploading certificate:', error)
      throw new Error(error.response?.data?.message || 'Upload failed')
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