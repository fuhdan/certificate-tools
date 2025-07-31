// frontend/src/components/Layout/Layout.jsx
// Updated for unified storage backend

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
  // Updated for unified certificate model - proper PKI hierarchy
  const getPKIOrder = (certificate) => {
    // PKCS12/PKCS7 files should be expanded, not treated as single items
    // We look at what they CONTAIN, not the format
    
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

    // 6. PKCS12/PKCS7 bundles with multiple certificates (these should be processed to extract individual certs)
    if (certificate.original_format === 'PKCS12' || certificate.original_format === 'PKCS7') {
      return 6
    }

    // Default order for unknown types
    return 999
  }

  const createSortedCertificates = (certificates) => {
    // Cache the order calculations to avoid repeated computation
    const certificateOrders = new Map()
    
    const getSortOrder = (cert) => {
      const cacheKey = cert.id
      if (certificateOrders.has(cacheKey)) {
        return certificateOrders.get(cacheKey)
      }
      
      const order = getPKIOrder(cert)
      certificateOrders.set(cacheKey, order)
      return order
    }
    
    // Sort certificates by PKI hierarchy order
    return certificates.slice().sort((a, b) => {
      const orderA = getSortOrder(a)
      const orderB = getSortOrder(b)
      
      // Primary sort by PKI order
      if (orderA !== orderB) {
        return orderA - orderB
      }
      
      // Secondary sort by filename for consistent ordering
      const filenameA = a.filename || ''
      const filenameB = b.filename || ''
      return filenameA.localeCompare(filenameB)
    })
  }

  // Create sorted certificates for display using the unified model
  const sortedCertificates = useMemo(() => {
    return createSortedCertificates(certificates)
  }, [certificates])

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