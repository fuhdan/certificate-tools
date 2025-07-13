// frontend/src/components/Header/Header.jsx
import React, { useState, useRef, useEffect } from 'react'
import { LogOut, LogIn, User, ChevronDown } from 'lucide-react'
import api from '../../services/api'
import styles from './Header.module.css'

const Header = ({ isAuthenticated, onLoginSuccess, onLogout, currentUser }) => {
  const [showLoginDropdown, setShowLoginDropdown] = useState(false)
  const [credentials, setCredentials] = useState({
    username: 'admin',
    password: 'admin123'
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const dropdownRef = useRef(null)

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setShowLoginDropdown(false)
        setError('')
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [])

  const handleLogin = async (e) => {
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
        
        // Close dropdown and notify parent
        setShowLoginDropdown(false)
        setError('')
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

  const toggleDropdown = () => {
    setShowLoginDropdown(!showLoginDropdown)
    setError('')
  }

  return (
    <header className={styles.header}>
      <div className={styles.logo}>
        <img src="./logo.png" alt="Certificate Tools" className={styles.logoImage} />
        <span className={styles.logoText}>Certificate Tools</span>
      </div>
      
      <div className={styles.authSection}>
        {isAuthenticated ? (
          <div className={styles.userMenu}>
            <div className={styles.userInfo}>
              <User size={16} />
              <span>{currentUser?.username || 'Admin'}</span>
            </div>
            <button 
              onClick={onLogout}
              className={styles.logoutButton}
              title="Logout"
            >
              <LogOut size={16} />
              Logout
            </button>
          </div>
        ) : (
          <div className={styles.loginContainer} ref={dropdownRef}>
            <button 
              onClick={toggleDropdown}
              className={styles.loginTrigger}
              title="Login"
            >
              <LogIn size={16} />
              Login
              <ChevronDown size={14} className={showLoginDropdown ? styles.chevronUp : ''} />
            </button>
            
            {showLoginDropdown && (
              <div className={styles.loginDropdown}>
                <div className={styles.dropdownHeader}>
                  <h3>Sign In</h3>
                </div>
                
                <form onSubmit={handleLogin} className={styles.loginForm}>
                  <div className={styles.formGroup}>
                    <input
                      type="text"
                      name="username"
                      placeholder="Username"
                      value={credentials.username}
                      onChange={handleChange}
                      required
                      disabled={isLoading}
                      className={styles.input}
                    />
                  </div>

                  <div className={styles.formGroup}>
                    <input
                      type="password"
                      name="password"
                      placeholder="Password"
                      value={credentials.password}
                      onChange={handleChange}
                      required
                      disabled={isLoading}
                      className={styles.input}
                    />
                  </div>

                  {error && (
                    <div className={styles.error}>
                      {error}
                    </div>
                  )}

                  <button 
                    type="submit" 
                    className={styles.submitButton}
                    disabled={isLoading}
                  >
                    {isLoading ? 'Signing in...' : 'Sign In'}
                  </button>
                </form>

                <div className={styles.defaultHint}>
                  <small>Default: admin / admin123</small>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  )
}

export default Header