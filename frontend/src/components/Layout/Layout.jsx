// frontend/src/components/Layout/Layout.jsx
import React, { useState, useEffect } from 'react'
import Header from '../Header/Header'
import Footer from '../Footer/Footer'
import FloatingPanel from '../FloatingPanel/FloatingPanel'
import FileUpload from '../FileUpload/FileUpload'
import CertificateDetails from '../CertificateDetails/CertificateDetails'
import ValidationPanel from '../ValidationPanel/ValidationPanel'
import api from '../../services/api'
import styles from './Layout.module.css'

const Layout = () => {
  const [certificates, setCertificates] = useState([])
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

  // Listen for file updates from FileUpload component
  useEffect(() => {
    const handleFilesUpdated = (event) => {
      setCertificates(event.detail.files || [])
    }

    window.addEventListener('filesUpdated', handleFilesUpdated)
    
    return () => {
      window.removeEventListener('filesUpdated', handleFilesUpdated)
    }
  }, [])

  const getCertificateOrder = (certificate) => {
    const type = certificate.analysis?.type || ''
    const details = certificate.analysis?.details || {}
    
    // CSR = 1
    if (type === 'CSR') return 1
    
    // Private Key = 2  
    if (type === 'Private Key') return 2
    
    // For certificates, check if it's a CA
    if (type === 'Certificate' || type === 'CA Certificate' || type === 'PKCS12 Certificate') {
      const isCA = details.extensions?.basicConstraints?.isCA || false
      const issuer = details.issuer?.commonName || ''
      const subject = details.subject?.commonName || ''
      
      if (!isCA) {
        // End-entity certificate = 3
        return 3
      } else {
        // CA certificates - determine hierarchy
        if (issuer === subject) {
          // Self-signed = Root CA = 6
          return 6
        } else {
          // Check if it's an issuing CA (likely to issue end-entity certs)
          const subjectLower = subject.toLowerCase()
          if (subjectLower.includes('issuing') || subjectLower.includes('leaf')) {
            // Issuing CA = 4
            return 4
          } else {
            // Intermediate CA = 5
            return 5
          }
        }
      }
    }
    
    // Certificate Chain = 7 (after all individual certificates)
    if (type === 'Certificate Chain') return 7
    
    // Everything else = 8
    return 8
  }

  // Sort certificates according to the logical order
  const sortedCertificates = [...certificates].sort((a, b) => {
    const orderA = getCertificateOrder(a)
    const orderB = getCertificateOrder(b)
    
    if (orderA !== orderB) {
      return orderA - orderB
    }
    
    // If same order, sort by filename
    return (a.filename || '').localeCompare(b.filename || '')
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
    setCertificates([])
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
          <FileUpload isAuthenticated={isAuthenticated} />
          
          {sortedCertificates.length > 0 && isAuthenticated && (
            <div className={styles.certificatesSection}>
              <h2>Certificate Analysis</h2>
              
              {/* Validation Panel - appears above certificate details */}
              <ValidationPanel certificates={sortedCertificates} />
              
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
      {isAuthenticated && <FloatingPanel />}
      <Footer />
    </div>
  )
}

export default Layout