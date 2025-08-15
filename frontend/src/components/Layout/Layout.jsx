// frontend/src/components/Layout/Layout.jsx

import React, { useState, useEffect, useMemo } from 'react'
import { Helmet } from 'react-helmet' // NEW: ONLY THIS LINE ADDED
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
  // ADD: State for ValidationPanel toggle
  const [showValidationPanel, setShowValidationPanel] = useState(false)

  // NEW: ONLY ADDED THESE TWO DYNAMIC SEO FUNCTIONS
  const pageTitle = useMemo(() => {
    const certCount = Object.keys(certificates).length
    if (certCount === 0) {
      return 'SSL Certificate Tools - Professional Certificate Management & Analysis'
    }
    return `${certCount} Certificate${certCount > 1 ? 's' : ''} Analyzed - SSL Certificate Tools`
  }, [certificates])

  const metaDescription = useMemo(() => {
    const certCount = Object.keys(certificates).length
    if (certCount === 0) {
      return 'Upload and analyze SSL/TLS certificates, CSRs, and private keys. Professional certificate validation with detailed analysis and installation guides.'
    }
    return `Analyzing ${certCount} SSL certificate${certCount > 1 ? 's' : ''}. Professional certificate validation with detailed cryptographic analysis.`
  }, [certificates])

  // ADD: Handler for ValidationPanel toggle
  const handleToggleValidationPanel = (show) => {
    setShowValidationPanel(show)
    console.log('ValidationPanel visibility toggled:', show)
  }

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
      {/* NEW: ONLY ADDED THIS HELMET SECTION - NOTHING ELSE CHANGED */}
      <Helmet>
        <title>{pageTitle}</title>
        <meta name="description" content={metaDescription} />
        <meta name="keywords" content="SSL certificate analysis, TLS certificate validation, X.509 certificate parser, CSR analysis, private key validation, certificate chain verification, PKI tools" />
        <meta property="og:title" content={pageTitle} />
        <meta property="og:description" content={metaDescription} />
        <meta property="og:type" content="website" />
        <meta name="twitter:card" content="summary" />
        <meta name="twitter:title" content={pageTitle} />
        <meta name="twitter:description" content={metaDescription} />
      </Helmet>

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
          
          {/* ValidationPanel Section - POSITIONED CORRECTLY AFTER UPLOAD */}
          {showValidationPanel && (
            <div className={styles.validationSection}>
              <ValidationPanel 
                certificates={sortedCertificates}
                onValidationComplete={(validations) => {
                  console.log('Validation completed:', validations)
                }}
              />
            </div>
          )}
          
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
        </div>
      </main>
      
      <Footer />
      
      {/* Floating System Panel with ValidationPanel props */}
      <FloatingPanel 
        isAuthenticated={isAuthenticated}
        currentUser={currentUser}
        showValidationPanel={showValidationPanel}
        onToggleValidationPanel={handleToggleValidationPanel}
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