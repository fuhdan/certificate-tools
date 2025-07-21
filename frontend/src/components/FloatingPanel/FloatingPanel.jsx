// frontend/src/components/FloatingPanel/FloatingPanel.jsx
import React, { useState, useEffect } from 'react'
import ConnectionStatus from './ConnectionStatus'
import SystemMessages from './SystemMessages'
import FileManager from './FileManager'
import PKIBundleViewer from './PKIBundleViewer'
import { Trash2, Package, Settings, Download, Files, Monitor } from 'lucide-react'
import { useCertificates } from '../../contexts/CertificateContext'
import styles from './FloatingPanel.module.css'

const FloatingPanel = ({ isAuthenticated }) => {
  const { clearAllFiles, certificates } = useCertificates()
  const [showPKIBundle, setShowPKIBundle] = useState(false)
  const [hasRequiredForLinux, setHasRequiredForLinux] = useState(false)
  const [hasRequiredForWindows, setHasRequiredForWindows] = useState(false)

  // Check if we have required files for different formats
  useEffect(() => {
    const certificates_analysis = certificates.map(cert => cert.analysis)
    
    // End-entity certificate (not a CA) - handle both 'Certificate' and 'PKCS12 Certificate' types
    const hasEndEntityCert = certificates_analysis.some(analysis => 
      (analysis?.type === 'Certificate' || analysis?.type === 'PKCS12 Certificate') && 
      (!analysis?.details?.extensions?.basicConstraints?.isCA || analysis?.details?.extensions?.basicConstraints?.isCA === false)
    )
    
    // Private key
    const hasPrivateKey = certificates_analysis.some(analysis => 
      analysis?.type === 'Private Key'
    )
    
    // Any CA certificate (intermediate or root)
    const hasCACertificates = certificates_analysis.some(analysis => 
      analysis?.type === 'CA Certificate' || 
      analysis?.type === 'IssuingCA' || 
      analysis?.type === 'IntermediateCA' || 
      analysis?.type === 'RootCA' ||
      (analysis?.type === 'Certificate' && analysis?.details?.extensions?.basicConstraints?.isCA === true)
    )
    
    // Root CA (self-signed where subject equals issuer)
    const hasRootCA = certificates_analysis.some(analysis => 
      (analysis?.type === 'RootCA') ||
      (analysis?.details?.subject?.commonName === analysis?.details?.issuer?.commonName &&
       analysis?.details?.extensions?.basicConstraints?.isCA === true)
    )
    
    console.log('Certificate Detection Debug:', {
      hasEndEntityCert,
      hasPrivateKey, 
      hasCACertificates,
      hasRootCA,
      certificateTypes: certificates_analysis.map(a => a?.type)
    })
    
    // Linux (Apache) needs end-entity certificate + private key
    setHasRequiredForLinux(hasEndEntityCert && hasPrivateKey)
    
    // Windows (IIS/PKCS#12) needs: end-entity + private key + CA certificates + root CA
    setHasRequiredForWindows(hasEndEntityCert && hasPrivateKey && hasCACertificates && hasRootCA)
  }, [certificates])

  // Add test system message on component mount
  useEffect(() => {
    // Add a test message to demonstrate the system messages functionality
    const addTestMessage = () => {
      const event = new CustomEvent('systemMessage', {
        detail: {
          message: "Connection established successfully",
          type: 'info',
          id: Date.now()
        }
      })
      window.dispatchEvent(event)
    }
    
    // Add test message after a short delay
    const timer = setTimeout(addTestMessage, 1000)
    
    return () => clearTimeout(timer)
  }, [])

  const handleClearAllFiles = async () => {
    if (window.confirm('Are you sure you want to clear all files? This action cannot be undone.')) {
      await clearAllFiles()
    }
  }

  const handleShowPKIBundle = () => {
    if (!isAuthenticated) {
      console.warn('PKI Bundle access requires authentication')
      return
    }
    setShowPKIBundle(true)
  }

  const handleClosePKIBundle = () => {
    setShowPKIBundle(false)
  }

  return (
    <>
      <div className={styles.panel}>
        <div className={styles.header}>
          <h3>System Panel</h3>
        </div>
        <div className={styles.content}>
          {/* General Section */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <Settings size={16} />
              <h4 className={styles.sectionTitle}>General</h4>
            </div>
            <div className={styles.sectionContent}>
              <ConnectionStatus />
              <SystemMessages />
              <button 
                className={`${styles.pkiBundleButton} ${!isAuthenticated ? styles.disabled : ''}`}
                onClick={handleShowPKIBundle}
                title={isAuthenticated ? "View PKI Bundle JSON" : "Login required to view PKI Bundle"}
                disabled={!isAuthenticated}
              >
                <Package size={16} />
                View PKI Bundle
              </button>
              <button 
                className={styles.clearAllButton}
                onClick={handleClearAllFiles}
              >
                <Trash2 size={16} />
                Clear All Files
              </button>
            </div>
          </div>

          {/* Download Section */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <Download size={16} />
              <h4 className={styles.sectionTitle}>Download</h4>
            </div>
            <div className={styles.sectionContent}>
              <button 
                className={`${styles.downloadButton} ${!hasRequiredForLinux ? styles.disabled : ''}`}
                disabled={!hasRequiredForLinux}
                title={hasRequiredForLinux ? "Download certificate bundle for Apache/Nginx" : "Certificate and private key required"}
              >
                <Monitor size={16} />
                Linux (Apache)
              </button>
              <button 
                className={`${styles.downloadButton} ${!hasRequiredForWindows ? styles.disabled : ''}`}
                disabled={!hasRequiredForWindows}
                title={hasRequiredForWindows ? "Download PKCS#12 bundle for Windows IIS" : "Full certificate chain required: end-entity certificate, private key, intermediate CA(s), and root CA"}
              >
                <Package size={16} />
                Windows (IIS)
              </button>
            </div>
          </div>

          {/* File Manager Section */}
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <Files size={16} />
              <h4 className={styles.sectionTitle}>File Manager</h4>
            </div>
            <div className={styles.sectionContent}>
              <FileManager />
            </div>
          </div>
        </div>
      </div>

      {showPKIBundle && isAuthenticated && (
        <PKIBundleViewer onClose={handleClosePKIBundle} />
      )}
    </>
  )
}

export default FloatingPanel