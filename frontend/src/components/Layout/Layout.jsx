// frontend/src/components/Layout/Layout.jsx
// Updated layout with fixed ValidationPanel - no mock data

import React, { useState, useEffect, useMemo } from 'react'
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

  // Helper function to determine certificate order in PKI hierarchy
  const getPKIOrder = (certificate) => {
    // 1. Private Key (standalone private key files)
    if (certificate.has_private_key && !certificate.has_certificate && !certificate.has_csr) {
      return 1
    }

    // 2. CSR (Certificate Signing Request - standalone)
    if (certificate.has_csr && !certificate.has_certificate && !certificate.has_private_key) {
      return 2
    }

    // 3. End-Entity Certificate (leaf certificate - not CA)
    if (certificate.has_certificate && certificate.certificate_info?.is_ca === false) {
      return 3
    }

    // 4. Intermediate CA Certificate (CA but not self-signed)
    if (certificate.has_certificate && certificate.certificate_info?.is_ca === true && !certificate.certificate_info?.is_self_signed) {
      return 4
    }

    // 5. Root CA Certificate (CA and self-signed)
    if (certificate.has_certificate && certificate.certificate_info?.is_ca === true && certificate.certificate_info?.is_self_signed) {
      return 5
    }

    // 6. Unknown/other components
    return 6
  }

  // Helper function to create properly sorted certificates
  const createSortedCertificates = (certs) => {
    if (!certs || certs.length === 0) return []

    return [...certs].sort((a, b) => {
      // Primary sort by PKI hierarchy order
      const orderA = getPKIOrder(a)
      const orderB = getPKIOrder(b)
      
      if (orderA !== orderB) {
        return orderA - orderB
      }

      // Secondary sort by filename for same-type components
      const filenameA = a.filename || ''
      const filenameB = b.filename || ''
      return filenameA.localeCompare(filenameB)
    })
  }

  // Login/logout handlers
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

  // Memoize the sorted certificates to avoid unnecessary recalculations
  const sortedCertificates = useMemo(() => {
    return createSortedCertificates(certificates)
  }, [certificates])

  if (isCheckingAuth) {
    return (
      <div className={styles.loadingContainer}>
        <div className={styles.loading}>
          <div className={styles.spinner}></div>
          <p>Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.layout}>
      <Header 
        isAuthenticated={isAuthenticated}
        onLoginSuccess={handleLoginSuccess}
        onLogout={handleLogout}
        currentUser={currentUser}
      />
      
      <main className={styles.main}>
        <div className={styles.container}>
          {/* File Upload Section */}
          <div className={styles.uploadSection}>
            <FileUpload />
          </div>
          
          {/* Certificate Details Section */}
          {sortedCertificates.length > 0 && (
            <div className={styles.certificatesSection}>
              <h2>Certificate Analysis</h2>
              <div className={styles.certificatesList}>
                {sortedCertificates.map(certificate => (
                  <CertificateDetails 
                    key={certificate.id} 
                    certificate={certificate} 
                  />
                ))}
              </div>
            </div>
          )}
          
          {/* ValidationPanel - Fixed with real API integration */}
          <ValidationPanel 
            certificates={sortedCertificates}
            onValidationComplete={(validations) => {
              console.log('Validation completed:', validations)
            }}
          />
        </div>
      </main>
      
      <Footer />
      
      {/* Floating System Panel */}
      <FloatingPanel 
        isAuthenticated={isAuthenticated}
        currentUser={currentUser}
      />
    </div>
  )
}

// Main Layout component with Context Provider
const Layout = () => {
  return (
    <CertificateProvider>
      <LayoutContent />
    </CertificateProvider>
  )
}

export default Layout