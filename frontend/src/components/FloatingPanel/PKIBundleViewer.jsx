// frontend/src/components/FloatingPanel/PKIBundleViewer.jsx
import React, { useState, useEffect } from 'react'
import { X, Package, Copy, Check, Download, AlertCircle } from 'lucide-react'
import api from '../../services/api'
import styles from './PKIBundleViewer.module.css'

const PKIBundleViewer = ({ onClose }) => {
  const [pkiBundle, setPkiBundle] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    fetchPKIBundle()
  }, [])

  const fetchPKIBundle = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // Get PKI bundle from the backend
      const response = await api.get('/pki-bundle')
      
      if (response.data.success && response.data.bundle) {
        setPkiBundle(response.data.bundle)
      } else {
        setError(response.data.message || 'No PKI bundle available')
      }
    } catch (err) {
      console.error('Error fetching PKI bundle:', err)
      if (err.response?.status === 404) {
        setError('No PKI bundle found. Upload certificates to generate a bundle.')
      } else {
        setError('Failed to load PKI bundle')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(pkiBundle, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy to clipboard:', err)
    }
  }

  const downloadBundle = () => {
    const blob = new Blob([JSON.stringify(pkiBundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'pki-bundle.json'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  const handleOverlayClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose()
    }
  }

  const formatJSON = (obj) => {
    return JSON.stringify(obj, null, 2)
  }

  return (
    <div className={styles.overlay} onClick={handleOverlayClick}>
      <div className={styles.modal}>
        <div className={styles.header}>
          <div className={styles.titleSection}>
            <Package size={24} className={styles.icon} />
            <h2>PKI Bundle JSON</h2>
          </div>
          <div className={styles.actions}>
            {pkiBundle && (
              <>
                <button 
                  className={styles.actionButton}
                  onClick={copyToClipboard}
                  title="Copy to clipboard"
                >
                  {copied ? <Check size={16} /> : <Copy size={16} />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
                <button 
                  className={styles.actionButton}
                  onClick={downloadBundle}
                  title="Download JSON file"
                >
                  <Download size={16} />
                  Download
                </button>
              </>
            )}
            <button 
              className={styles.closeButton}
              onClick={onClose}
              title="Close"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        <div className={styles.content}>
          {isLoading && (
            <div className={styles.loading}>
              <div className={styles.spinner}></div>
              <p>Loading PKI bundle...</p>
            </div>
          )}

          {error && (
            <div className={styles.error}>
              <AlertCircle size={20} />
              <p>{error}</p>
            </div>
          )}

          {pkiBundle && !isLoading && (
            <div className={styles.jsonContainer}>
              <div className={styles.summary}>
                <h3>Bundle Summary</h3>
                <div className={styles.summaryGrid}>
                  <div className={styles.summaryItem}>
                    <span className={styles.summaryLabel}>Version:</span>
                    <span className={styles.summaryValue}>{pkiBundle.version}</span>
                  </div>
                  <div className={styles.summaryItem}>
                    <span className={styles.summaryLabel}>Components:</span>
                    <span className={styles.summaryValue}>{pkiBundle.components?.length || 0}</span>
                  </div>
                  <div className={styles.summaryItem}>
                    <span className={styles.summaryLabel}>Generated:</span>
                    <span className={styles.summaryValue}>
                      {new Date(pkiBundle.generated).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              <div className={styles.jsonWrapper}>
                <pre className={styles.jsonContent}>
                  <code>{formatJSON(pkiBundle)}</code>
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default PKIBundleViewer