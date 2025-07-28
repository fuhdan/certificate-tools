// frontend/src/services/api.js
import axios from 'axios'
import { sessionManager } from './sessionManager.js'

const api = axios.create({
  baseURL: '/api',
  timeout: 5000
})

// Request interceptor: Add session ID and auth headers
api.interceptors.request.use(
  (config) => {
    // Add session ID to every request
    const sessionId = sessionManager.getSessionId()
    if (sessionId) {
      config.headers['X-Session-ID'] = sessionId
    }
    
    // Preserve existing auth logic
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor: Handle session and auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle errors in order of precedence:
    
    // 1. Authentication errors (401) - highest priority
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      delete api.defaults.headers.common['Authorization']
      console.warn('Authentication expired')
      // Reload page to show login
      window.location.reload()
      return Promise.reject(error)
    }
    
    // 2. Session errors (400 with session message)
    if (error.response?.status === 400 && 
        error.response?.data?.detail?.includes('Invalid session')) {
      console.warn('Invalid session detected, renewing session')
      sessionManager.renewSession()
      
      // Optional: Retry the request with new session
      const originalRequest = error.config
      if (!originalRequest._retry) {
        originalRequest._retry = true
        originalRequest.headers['X-Session-ID'] = sessionManager.getSessionId()
        return api(originalRequest)
      }
    }
    
    return Promise.reject(error)
  }
)

// Development debugging (conditional)
if (import.meta.env.DEV) {
  api.interceptors.request.use((config) => {
    const sessionId = config.headers['X-Session-ID']
    if (sessionId) {
      console.log(`API Request [${sessionId.substring(0, 8)}...]: ${config.method?.toUpperCase()} ${config.url}`)
    }
    return config
  })
}

// Optional: Add session validation helper
export const validateSession = async () => {
  try {
    const response = await api.get('/health')
    return response.status === 200
  } catch (error) {
    console.warn('Session validation failed:', error.message)
    return false
  }
}

// Optional: Add session renewal helper
export const renewSessionAndRetry = async (failedRequest) => {
  sessionManager.renewSession()
  failedRequest.headers['X-Session-ID'] = sessionManager.getSessionId()
  return api(failedRequest)
}

export default api