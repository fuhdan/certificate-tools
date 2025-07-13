// frontend/src/services/api.js
import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 5000
})

// Add token to requests if available
api.interceptors.request.use(
  (config) => {
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

// Handle 401 responses (token expired)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('access_token')
      delete api.defaults.headers.common['Authorization']
      // Reload page to show login
      window.location.reload()
    }
    return Promise.reject(error)
  }
)

export default api