// frontend/src/components/Layout/Layout.jsx
import React, { useState, useEffect } from 'react'
import Header from '../Header/Header'
import Footer from '../Footer/Footer'
import FloatingPanel from '../FloatingPanel/FloatingPanel'
import FileUpload from '../FileUpload/FileUpload'
import CertificateDetails from '../CertificateDetails/CertificateDetails'
import ValidationPanel from '../ValidationPanel/ValidationPanel'
import { CertificateProvider, useCertificates } from '../../contexts/CertificateContext'
import api from '../../services/api'
import styles from './Layout.module.css'

// Inner Layout component that uses the context
const LayoutContent = () => {
  const { certificates } = useCertificates()
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isCheckingAuth, setIsCheckingAuth] = useState(true)
  const [currentUser, setCurrentUser] = useState(null)

  // Check if user is already authenticated
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('access_token')
      if (token) {
        try {
          // Set the authorization header
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`
          
          // Test the token by making a request
          const response = await api.get('/users/me/')
          setIsAuthenticated(true)
          setCurrentUser(response.data)
        } catch (error) {
          // Token is invalid
          localStorage.removeItem('access_token')
          delete api.defaults.headers.common['Authorization']
          setIsAuthenticated(false)
          setCurrentUser(null)
        }
      }
      setIsCheckingAuth(false)
    }

    checkAuth()
  }, [])

  // Create sorted certificates for display
  const sortedCertificates = certificates.slice().sort((a, b) => {
    const typeA = a.analysis?.type || ''
    const typeB = b.analysis?.type || ''
    
    const typeOrder = {
      'Private Key': 1,
      'CSR': 2,
      'Certificate': 3,
      'CA Certificate': 4,
      'Certificate Chain': 5
    }
    
    return (typeOrder[typeA] || 999) - (typeOrder[typeB] || 999)
  })

  const handleLoginSuccess = async () => {
    setIsAuthenticated(true)
    
    // Get user info after successful login
    try {
      const response = await api.get('/users/me/')
      setCurrentUser(response.data)
    } catch (error) {
      console.error('Error getting user info:', error)
    }
  }

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    delete api.defaults.headers.common['Authorization']
    setIsAuthenticated(false)
    setCurrentUser(null)
  }

  // Show loading while checking authentication
  if (isCheckingAuth) {
    return (
      <div className={styles.loading}>
        <div className={styles.loadingSpinner}></div>
        <p>Loading...</p>
      </div>
    )
  }

  // Show main application with authentication-aware components
  return (
    <div className={styles.layout}>
      <Header 
        isAuthenticated={isAuthenticated}
        onLoginSuccess={handleLoginSuccess}
        onLogout={handleLogout}
        currentUser={currentUser}
      />
      <main className={styles.main}>
        <div className={styles.content}>
          <h1>Certificate Tools</h1>
          <p>Professional certificate management and conversion platform.</p>
          <FileUpload />
          
          {sortedCertificates.length > 0 && (
            <div className={styles.certificatesSection}>
              <h2>Certificate Analysis</h2>
              
              {/* Validation Panel - appears above certificate details */}
              <ValidationPanel 
                certificates={sortedCertificates}
              />
              
              {sortedCertificates.map((certificate) => (
                <CertificateDetails 
                  key={certificate.id} 
                  certificate={certificate} 
                />
              ))}
            </div>
          )}
        </div>
      </main>
      <FloatingPanel isAuthenticated={isAuthenticated} />
      <Footer />
    </div>
  )
}

// Main Layout component that provides the context
const Layout = () => {
  return (
    <CertificateProvider>
      <LayoutContent />
    </CertificateProvider>
  )
}

export default Layout