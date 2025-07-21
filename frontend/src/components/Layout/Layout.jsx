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

  // Helper function to determine certificate order in PKI hierarchy
  const getCertificateOrder = (cert) => {
    const analysis = cert.analysis
    const type = analysis?.type
    const details = analysis?.details
    
    // 1. Private Key
    if (type === 'Private Key') {
      return 1
    }
    
    // 2. CSR
    if (type === 'CSR') {
      return 2
    }
    
    // 3. Certificate (End Entity) - not a CA
    if (type === 'Certificate' && !details?.extensions?.basicConstraints?.isCA) {
      return 3
    }
    
    // 4. Issuing CA 
    if (type === 'IssuingCA') {
      return 4
    }
    
    // 5. Intermediate CA
    if (type === 'IntermediateCA') {
      return 5
    }
    
    // 6. Root CA
    if (type === 'RootCA') {
      return 6
    }
    
    // Legacy CA Certificate types - determine by basic constraints
    if (type === 'CA Certificate' || (type === 'Certificate' && details?.extensions?.basicConstraints?.isCA)) {
      const subjectCN = details?.subject?.commonName || ''
      const issuerCN = details?.issuer?.commonName || ''
      
      // Root CA: self-signed (subject == issuer)
      if (subjectCN === issuerCN) {
        return 6
      }
      
      // Otherwise treat as intermediate
      return 5
    }
    
    // 7. Certificate Chain
    if (type === 'Certificate Chain') {
      return 7
    }
    
    // 8. Everything else
    return 8
  }

  // Create sorted certificates for display using the correct PKI hierarchy order
  const sortedCertificates = certificates.slice().sort((a, b) => {
    const typeA = a.analysis?.type || ''
    const typeB = b.analysis?.type || ''
    
    // DEBUG: Log what we're working with
    console.log('SORTING DEBUG:')
    console.log('Certificate A:', a.filename, 'Type:', typeA, 'isCA:', a.analysis?.details?.extensions?.basicConstraints?.isCA)
    console.log('Certificate B:', b.filename, 'Type:', typeB, 'isCA:', b.analysis?.details?.extensions?.basicConstraints?.isCA)
    
    // Special handling for Certificate type - check if it's End-Entity vs CA
    const getTypeOrder = (cert) => {
      const type = cert.analysis?.type || ''
      const isCA = cert.analysis?.details?.extensions?.basicConstraints?.isCA
      const filename = cert.filename || ''
      
      // Private Key
      if (type === 'Private Key') {
        console.log(`${filename} -> Order 1 (Private Key)`)
        return 1
      }
      
      // CSR
      if (type === 'CSR') {
        console.log(`${filename} -> Order 2 (CSR)`)
        return 2
      }
      
      // Certificate types - determine by isCA flag
      if (type === 'Certificate' || type === 'PKCS12 Certificate') {
        if (isCA === false || isCA === undefined) {
          console.log(`${filename} -> Order 3 (End-Entity Certificate, isCA: ${isCA})`)
          return 3 // End-Entity Certificate
        } else {
          // It's a CA certificate, check subject/issuer to determine type
          const subject = cert.analysis?.details?.subject?.commonName || ''
          const issuer = cert.analysis?.details?.issuer?.commonName || ''
          
          if (subject === issuer) {
            console.log(`${filename} -> Order 6 (Root CA, subject=issuer)`)
            return 6 // Root CA (self-signed)
          } else if (subject.includes('Issuing')) {
            console.log(`${filename} -> Order 4 (Issuing CA)`)
            return 4 // Issuing CA
          } else {
            console.log(`${filename} -> Order 5 (Intermediate CA)`)
            return 5 // Intermediate CA
          }
        }
      }
      
      // Specific types
      const typeOrder = {
        'IssuingCA': 4,
        'IntermediateCA': 5,
        'RootCA': 6,
        'CA Certificate': 7,
        'Certificate Chain': 8
      }
      
      const order = typeOrder[type] || 999
      console.log(`${filename} -> Order ${order} (${type})`)
      return order
    }
    
    const orderA = getTypeOrder(a)
    const orderB = getTypeOrder(b)
    
    console.log(`Final comparison: ${orderA} vs ${orderB}`)
    return orderA - orderB
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