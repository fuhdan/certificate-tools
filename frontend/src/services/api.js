// frontend/src/services/api.js
// Updated for unified storage backend

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
      // Could trigger a logout event here
    }

    // Handle session-related errors
    if (error.response?.status === 400 && error.response?.data?.detail?.includes('session')) {
      // Regenerate session ID for session errors
      sessionManager.generateNewSession()
    }

    return Promise.reject(error)
  }
)

// Certificate API methods for unified backend
export const certificateAPI = {
  // Get all certificates for current session
  async getAllCertificates() {
    const response = await api.get('/certificates')
    return response.data
  },

  // Upload and analyze certificate
  async uploadCertificate(formData) {
    const response = await api.post('/analyze-certificate', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  },

  // Get specific certificate by ID
  async getCertificate(certificateId) {
    const response = await api.get(`/certificates/${certificateId}`)
    return response.data
  },

  // Delete specific certificate
  async deleteCertificate(certificateId) {
    const response = await api.delete(`/certificates/${certificateId}`)
    return response.data
  },

  // Clear all certificates in session
  async clearAllCertificates() {
    const response = await api.delete('/certificates')
    return response.data
  }
}

// Validation API methods
export const validationAPI = {
  // Get validation results for session
  async getValidationResults() {
    const response = await api.get('/validation/results')
    return response.data
  },

  // Trigger validation for session
  async triggerValidation() {
    const response = await api.post('/validation/validate')
    return response.data
  }
}

// PKI Bundle API methods (requires authentication)
export const pkiAPI = {
  // Get PKI bundle (requires auth)
  async getPKIBundle() {
    const response = await api.get('/pki-bundle')
    return response.data
  },

  // Download PKI bundle as file (requires auth)
  async downloadPKIBundle(password = null) {
    const config = {
      responseType: 'blob',
      headers: {}
    }
    
    if (password) {
      config.headers['X-Archive-Password'] = password
    }
    
    const response = await api.get('/pki-bundle/download', config)
    return response
  }
}

// Authentication API methods
export const authAPI = {
  // Login with credentials
  async login(credentials) {
    const response = await api.post('/auth/token', credentials, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
    return response.data
  },

  // Get current user info
  async getCurrentUser() {
    const response = await api.get('/users/me/')
    return response.data
  },

  // Refresh token (if implemented)
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

// Backward compatibility - maintain old API structure
api.get = async (url, config) => {
  const response = await api.request({ method: 'GET', url, ...config })
  return response
}

api.post = async (url, data, config) => {
  const response = await api.request({ method: 'POST', url, data, ...config })
  return response
}

api.delete = async (url, config) => {
  const response = await api.request({ method: 'DELETE', url, ...config })
  return response
}

api.put = async (url, data, config) => {
  const response = await api.request({ method: 'PUT', url, data, ...config })
  return response
}

export default api