// frontend/src/components/Login/Login.jsx
import React, { useState } from 'react'
import { LogIn } from 'lucide-react'
import api from '../../services/api'
import styles from './Login.module.css'

const Login = ({ onLoginSuccess }) => {
  const [credentials, setCredentials] = useState({
    username: 'admin',
    password: 'admin123'
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    try {
      // Create FormData for OAuth2 password flow
      const formData = new FormData()
      formData.append('username', credentials.username)
      formData.append('password', credentials.password)

      const response = await api.post('/token', formData, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      })

      if (response.data.access_token) {
        // Store token in localStorage
        localStorage.setItem('access_token', response.data.access_token)
        
        // Set default authorization header for future requests
        api.defaults.headers.common['Authorization'] = `Bearer ${response.data.access_token}`
        
        onLoginSuccess()
      }
    } catch (error) {
      console.error('Login error:', error)
      setError(error.response?.data?.detail || 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleChange = (e) => {
    setCredentials({
      ...credentials,
      [e.target.name]: e.target.value
    })
  }

  return (
    <div className={styles.loginContainer}>
      <div className={styles.loginCard}>
        <div className={styles.loginHeader}>
          <LogIn size={32} className={styles.loginIcon} />
          <h2>Certificate Tools Login</h2>
          <p>Please sign in to continue</p>
        </div>

        <form onSubmit={handleSubmit} className={styles.loginForm}>
          <div className={styles.formGroup}>
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={credentials.username}
              onChange={handleChange}
              required
              disabled={isLoading}
            />
          </div>

          <div className={styles.formGroup}>
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={credentials.password}
              onChange={handleChange}
              required
              disabled={isLoading}
            />
          </div>

          {error && (
            <div className={styles.error}>
              {error}
            </div>
          )}

          <button 
            type="submit" 
            className={styles.loginButton}
            disabled={isLoading}
          >
            {isLoading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className={styles.defaultCreds}>
          <small>Default: admin / admin123</small>
        </div>
      </div>
    </div>
  )
}

export default Login