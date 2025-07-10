import React, { useState, useEffect } from 'react'
import Header from '../Header/Header'
import Footer from '../Footer/Footer'
import FloatingPanel from '../FloatingPanel/FloatingPanel'
import FileUpload from '../FileUpload/FileUpload'
import CertificateDetails from '../CertificateDetails/CertificateDetails'
import styles from './Layout.module.css'

const Layout = () => {
  const [certificates, setCertificates] = useState([])

  useEffect(() => {
    // Listen for file updates from FileUpload component
    const handleFilesUpdated = (event) => {
      setCertificates(event.detail.files || [])
    }

    window.addEventListener('filesUpdated', handleFilesUpdated)
    
    return () => {
      window.removeEventListener('filesUpdated', handleFilesUpdated)
    }
  }, [])

  return (
    <div className={styles.layout}>
      <Header />
      <main className={styles.main}>
        <div className={styles.content}>
          <h1>Certificate Tools</h1>
          <p>Professional certificate management and conversion platform.</p>
          <FileUpload />
          
          {certificates.length > 0 && (
            <div className={styles.certificatesSection}>
              <h2>Certificate Details</h2>
              {certificates.map((certificate) => (
                <CertificateDetails 
                  key={certificate.id} 
                  certificate={certificate} 
                />
              ))}
            </div>
          )}
        </div>
      </main>
      <FloatingPanel />
      <Footer />
    </div>
  )
}

export default Layout