import React, { useState, useEffect, useMemo } from 'react'
import { Helmet } from 'react-helmet'
import Header from '../Header/Header'
import Footer from '../Footer/Footer'
import FloatingPanel from '../FloatingPanel/FloatingPanel'
import FileUpload from '../FileUpload/FileUpload'
import CertificateDetails from '../CertificateDetails/CertificateDetails'
import ValidationPanel from '../ValidationPanel/ValidationPanel'
import { CertificateProvider, useCertificates } from '../../contexts/CertificateContext'
import api from '../../services/api'
import styles from './Layout.module.css'

// Import comprehensive logging for layout
import {
  layoutError,
  layoutInfo,
  layoutLifecycle,
  layoutAuth,
  layoutState,
  layoutCertificates,
  layoutSorting,
  layoutValidation,
  layoutSEO,
  layoutRender,
  layoutInteraction,
  time,
  timeEnd
} from '@/utils/logger'

// Inner Layout component that uses the context
const LayoutContent = () => {
  const { certificates } = useCertificates()
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isCheckingAuth, setIsCheckingAuth] = useState(true)
  const [currentUser, setCurrentUser] = useState(null)
  const [showValidationPanel, setShowValidationPanel] = useState(false)

  // Log component lifecycle
  useEffect(() => {
    time('Layout.component_initialization')
    
    layoutLifecycle('LAYOUT_CONTENT_MOUNT', {
      component_name: 'LayoutContent',
      initial_auth_state: isAuthenticated,
      initial_checking_auth: isCheckingAuth,
      initial_user: !!currentUser
    })

    timeEnd('Layout.component_initialization')

    return () => {
      layoutLifecycle('LAYOUT_CONTENT_UNMOUNT', {
        final_auth_state: isAuthenticated,
        final_user: !!currentUser,
        final_certificate_count: Object.keys(certificates).length
      })
    }
  }, [])

  // Dynamic SEO with logging
  const pageTitle = useMemo(() => {
    // FIXED: Add null check before Object.keys()
    if (!certificates || typeof certificates !== 'object') {
      return 'SSL Certificate Tools - Professional Certificate Management & Analysis'
    }
    
    const certCount = Object.keys(certificates).length
    if (certCount === 0) {
      return 'SSL Certificate Tools - Professional Certificate Management & Analysis'
    }
    return `${certCount} Certificate${certCount > 1 ? 's' : ''} Analyzed - SSL Certificate Tools`
  }, [certificates])

  // FIXED: Single metaDescription with both null checks AND logging
  const metaDescription = useMemo(() => {
    time('Layout.seo_description_generation')
    
    // Add null checks before Object.keys()
    if (!certificates || typeof certificates !== 'object') {
      const fallbackDescription = 'Upload and analyze SSL/TLS certificates, CSRs, and private keys. Professional certificate validation with detailed analysis and installation guides.'
      
      layoutSEO('META_DESCRIPTION_FALLBACK', { description: fallbackDescription, certificate_count: 0 }, {
        description_length: fallbackDescription.length,
        dynamic_description: false,
        reason: 'null_certificates'
      })
      
      timeEnd('Layout.seo_description_generation')
      return fallbackDescription
    }
    
    const certCount = Object.keys(certificates).length
    let description
    
    if (certCount === 0) {
      description = 'Upload and analyze SSL/TLS certificates, CSRs, and private keys. Professional certificate validation with detailed analysis and installation guides.'
    } else {
      description = `Analyzing ${certCount} SSL certificate${certCount > 1 ? 's' : ''}. Professional certificate validation with detailed cryptographic analysis.`
    }

    layoutSEO('META_DESCRIPTION_GENERATED', { description, certificate_count: certCount }, {
      description_length: description.length,
      dynamic_description: certCount > 0
    })

    timeEnd('Layout.seo_description_generation')
    return description
  }, [certificates])

  // ValidationPanel toggle handler with logging
  const handleToggleValidationPanel = (show) => {
    layoutInteraction('VALIDATION_PANEL_TOGGLE', {
      previous_state: showValidationPanel,
      new_state: show,
      trigger_source: 'floating_panel'
    })

    layoutValidation('PANEL_VISIBILITY_CHANGE', show, {
      visibility_changed: showValidationPanel !== show,
      // FIXED: Add null check
      certificate_count: (certificates && typeof certificates === 'object') ? Object.keys(certificates).length : 0
    })

    setShowValidationPanel(show)
    layoutInfo('ValidationPanel visibility toggled:', show)
  }

  // Authentication check with comprehensive logging
  useEffect(() => {
    const checkAuth = async () => {
      time('Layout.authentication_check')
      
      layoutAuth('AUTH_CHECK_START', false, {
        checking_auth: true,
        has_token: !!localStorage.getItem('access_token')
      })

      const token = localStorage.getItem('access_token')
      
      if (token) {
        try {
          layoutAuth('TOKEN_FOUND', false, {
            token_length: token.length,
            token_preview: `${token.substring(0, 10)}...${token.substring(token.length - 10)}`
          })

          // Set the authorization header
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`
          
          layoutAuth('API_HEADER_SET', false, {
            header_set: true
          })

          // Test the token by making a request
          const response = await api.get('/users/me/')
          
          layoutAuth('TOKEN_VALIDATION_SUCCESS', true, {
            user_id: response.data?.id,
            username: response.data?.username,
            user_email: response.data?.email
          })

          setIsAuthenticated(true)
          setCurrentUser(response.data)
          
        } catch (error) {
          layoutAuth('TOKEN_VALIDATION_FAILED', false, {
            error_message: error.message,
            error_status: error.response?.status,
            token_removed: true
          })

          // Token is invalid
          localStorage.removeItem('access_token')
          delete api.defaults.headers.common['Authorization']
          setIsAuthenticated(false)
          setCurrentUser(null)
        }
      } else {
        layoutAuth('NO_TOKEN_FOUND', false, {
          token_present: false
        })
      }
      
      setIsCheckingAuth(false)
      layoutAuth('AUTH_CHECK_COMPLETE', isAuthenticated, {
        checking_complete: true,
        final_auth_state: isAuthenticated
      })

      timeEnd('Layout.authentication_check')
    }

    checkAuth()
  }, [])

  // Helper function to determine certificate order in PKI hierarchy
  const getPKIOrder = (certificate) => {
    time('Layout.pki_order_calculation')
    
    let order
    let type

    // 1. Private Key (standalone private key files)
    if (certificate.has_private_key && !certificate.has_certificate && !certificate.has_csr) {
      order = 1
      type = 'private_key'
    }
    // 2. CSR (Certificate Signing Request - standalone)
    else if (certificate.has_csr && !certificate.has_certificate && !certificate.has_private_key) {
      order = 2
      type = 'csr'
    }
    // 3. End-Entity Certificate (leaf certificate - not CA)
    else if (certificate.has_certificate && certificate.certificate_info?.is_ca === false) {
      order = 3
      type = 'end_entity'
    }
    // 4. Intermediate CA Certificate (CA but not self-signed)
    else if (certificate.has_certificate && certificate.certificate_info?.is_ca === true && !certificate.certificate_info?.is_self_signed) {
      order = 4
      type = 'intermediate_ca'
    }
    // 5. Root CA Certificate (CA and self-signed)
    else if (certificate.has_certificate && certificate.certificate_info?.is_ca === true && certificate.certificate_info?.is_self_signed) {
      order = 5
      type = 'root_ca'
    }
    // 6. Unknown/other components
    else {
      order = 6
      type = 'unknown'
    }

    layoutSorting('PKI_ORDER_CALCULATED', {
      certificate_id: certificate.id,
      filename: certificate.filename,
      pki_order: order,
      certificate_type: type
    })

    timeEnd('Layout.pki_order_calculation')
    return order
  }

  // Helper function to create properly sorted certificates
  const createSortedCertificates = (certs) => {
    time('Layout.certificate_sorting')
    
    if (!certs || certs.length === 0) {
      layoutSorting('SORTING_SKIPPED', {
        reason: 'no_certificates',
        input_count: 0
      })
      timeEnd('Layout.certificate_sorting')
      return []
    }

    layoutSorting('SORTING_START', {
      input_count: certs.length,
      certificate_ids: certs.map(c => c.id)
    })

    const sorted = [...certs].sort((a, b) => {
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

    layoutSorting('SORTING_COMPLETE', {
      input_count: certs.length,
      output_count: sorted.length,
      sort_order: sorted.map(c => ({ id: c.id, filename: c.filename, order: getPKIOrder(c) }))
    })

    timeEnd('Layout.certificate_sorting')
    return sorted
  }

  // Login success handler with logging
  const handleLoginSuccess = async () => {
    time('Layout.login_success_handler')
    
    layoutAuth('LOGIN_SUCCESS_HANDLER', true, {
      handler_called: true
    })

    setIsAuthenticated(true)
    
    // Get user info after successful login
    try {
      const response = await api.get('/users/me/')
      
      layoutAuth('USER_INFO_RETRIEVED', true, {
        user_id: response.data?.id,
        username: response.data?.username,
        success: true
      })

      setCurrentUser(response.data)
    } catch (error) {
      layoutError('Error getting user info after login', {
        error_message: error.message,
        error_status: error.response?.status,
        login_success_but_user_info_failed: true
      })
    }

    timeEnd('Layout.login_success_handler')
  }

  // Logout handler with logging
  const handleLogout = () => {
    time('Layout.logout_handler')
    
    layoutAuth('LOGOUT_HANDLER', false, {
      previous_auth_state: isAuthenticated,
      had_user: !!currentUser
    })

    localStorage.removeItem('access_token')
    delete api.defaults.headers.common['Authorization']
    setIsAuthenticated(false)
    setCurrentUser(null)

    layoutAuth('LOGOUT_COMPLETE', false, {
      token_removed: true,
      header_cleared: true,
      user_cleared: true
    })

    timeEnd('Layout.logout_handler')
  }

  // Memoize the sorted certificates with logging
  const sortedCertificates = useMemo(() => {
    time('Layout.certificates_memoization')
    
    // FIXED: Add null check before Object.values()
    const certificatesArray = (certificates && typeof certificates === 'object') ? Object.values(certificates) : []
    
    layoutCertificates('CERTIFICATES_MEMOIZATION', certificatesArray, {
      memoization_trigger: 'certificates_change',
      input_certificate_count: certificatesArray.length
    })

    const sorted = createSortedCertificates(certificatesArray)
    
    layoutCertificates('SORTED_CERTIFICATES_READY', sorted, {
      output_certificate_count: sorted.length,
      processing_complete: true
    })

    timeEnd('Layout.certificates_memoization')
    return sorted
  }, [certificates])

  // Log state changes
  useEffect(() => {
    layoutState('AUTH_STATE_CHANGE', { isAuthenticated, isCheckingAuth }, {
      auth_changed: true,
      checking_auth: isCheckingAuth
    })
  }, [isAuthenticated, isCheckingAuth])

  useEffect(() => {
    layoutState('USER_STATE_CHANGE', currentUser || {}, {
      has_user: !!currentUser,
      user_id: currentUser?.id
    })
  }, [currentUser])

  useEffect(() => {
    layoutState('VALIDATION_PANEL_STATE_CHANGE', { showValidationPanel }, {
      panel_visible: showValidationPanel
    })
  }, [showValidationPanel])

  // Loading state with logging
  if (isCheckingAuth) {
    layoutRender('LOADING_STATE_RENDER', {
      render_type: 'loading',
      checking_auth: isCheckingAuth
    })

    return (
      <div className={styles.loadingContainer}>
        <div className={styles.loading}>
          <div className={styles.spinner}></div>
          <p>Loading...</p>
        </div>
      </div>
    )
  }

  // Main render with logging
  layoutRender('MAIN_LAYOUT_RENDER', {
    render_type: 'main_layout',
    is_authenticated: isAuthenticated,
    certificate_count: sortedCertificates.length,
    validation_panel_visible: showValidationPanel,
    has_user: !!currentUser
  })

  return (
    <div className={styles.layout}>
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
          
          {/* ValidationPanel Section */}
          {showValidationPanel && (
            <div className={styles.validationSection}>
              <ValidationPanel 
                certificates={sortedCertificates}
                onValidationComplete={(validations) => {
                  layoutValidation('VALIDATION_COMPLETE', true, {
                    validation_count: validations?.length || 0,
                    validation_results: validations
                  })
                  layoutInfo('Validation completed:', validations)
                }}
              />
            </div>
          )}
          
          {/* Certificate Details Section */}
          {sortedCertificates.length > 0 && (
            <div className={styles.certificatesSection}>
              <h2>Certificate Analysis</h2>
              <div className={styles.certificatesList}>
                {sortedCertificates.map((certificate, index) => {
                  layoutRender('CERTIFICATE_DETAILS_RENDER', {
                    certificate_id: certificate.id,
                    certificate_filename: certificate.filename,
                    render_index: index,
                    total_certificates: sortedCertificates.length
                  })

                  return (
                    <CertificateDetails 
                      key={certificate.id} 
                      certificate={certificate} 
                    />
                  )
                })}
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
  useEffect(() => {
    layoutLifecycle('LAYOUT_PROVIDER_MOUNT', {
      component_name: 'Layout',
      provider_initialized: true
    })

    return () => {
      layoutLifecycle('LAYOUT_CONTENT_UNMOUNT', {
        final_auth_state: isAuthenticated,
        final_user: !!currentUser,
        // FIXED: Add null check
        final_certificate_count: (certificates && typeof certificates === 'object') ? Object.keys(certificates).length : 0
      })
    }
  }, [])

  return (
    <CertificateProvider>
      <LayoutContent />
    </CertificateProvider>
  )
}

export default Layout