import React, { useState, useRef } from 'react'
import { Upload } from 'lucide-react'
import api from '../../services/api'
import styles from './FileUpload.module.css'

const FileUpload = () => {
  const [dragActive, setDragActive] = useState(false)
  const [files, setFiles] = useState([])
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const inputRef = useRef(null)

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true)
    } else if (e.type === "dragleave") {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(e.dataTransfer.files)
    }
  }

  const handleChange = (e) => {
    e.preventDefault()
    if (e.target.files && e.target.files[0]) {
      handleFiles(e.target.files)
    }
  }

  // Handle duplicate file decision (no longer needed - keeping for compatibility)
  const handleDuplicateDecision = async (action) => {
    // This function is no longer used since duplicates are auto-replaced
    setShowDuplicateModal(false)
    setDuplicateInfo(null)
    setIsAnalyzing(false)
  }

  // Refresh file list from backend
  const refreshFileList = async () => {
    try {
      const response = await api.get('/certificates')
      if (response.data.success) {
        const backendFiles = response.data.certificates.map(cert => ({
          id: cert.id,
          name: cert.filename,
          size: cert.analysis.size,
          type: cert.analysis.type,
          format: cert.analysis.format,
          isValid: cert.analysis.isValid,
          analyzed: true,
          analysis: cert.analysis,  // Include full analysis with details
          filename: cert.filename,  // Ensure filename is available
          uploadedAt: cert.uploadedAt
        }))
        
        setFiles(backendFiles)
        window.uploadedFiles = backendFiles
        
        window.dispatchEvent(new CustomEvent('filesUpdated', { 
          detail: { files: backendFiles } 
        }))
      }
    } catch (error) {
      console.error('Error refreshing file list:', error)
    }
  }

  const handleFiles = async (fileList) => {
    const fileArray = Array.from(fileList)
    setIsAnalyzing(true)
    
    for (const file of fileArray) {
      try {
        const formData = new FormData()
        formData.append('certificate', file)
        
        const response = await api.post('/analyze-certificate', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
        
        if (response.data.success) {
          if (response.data.isDuplicate && response.data.replaced) {
            // Certificate was automatically replaced - just refresh the list
            console.log(`Automatically replaced: ${response.data.replacedCertificate.filename} -> ${response.data.certificate.filename}`)
            await refreshFileList()
          } else {
            // New certificate added - refresh the list
            await refreshFileList()
          }
        }
      } catch (error) {
        console.error('Error analyzing file:', error)
      }
    }
    
    setIsAnalyzing(false)
  }

  const getFileFormat = (filename) => {
    const extension = filename.split('.').pop().toLowerCase()
    switch (extension) {
      case 'pem':
      case 'crt':
      case 'cer':
        return 'PEM'
      case 'der':
        return 'DER'
      case 'p12':
      case 'pfx':
        return 'PKCS12'
      case 'jks':
        return 'JKS'
      default:
        return extension.toUpperCase()
    }
  }

  const onButtonClick = () => {
    inputRef.current.click()
  }

  const clearAll = async () => {
    try {
      await api.delete('/certificates')
      await refreshFileList()
    } catch (error) {
      console.error('Error clearing files:', error)
    }
  }

  // Make clearAll function globally accessible and sync with backend
  React.useEffect(() => {
    window.clearAllFiles = clearAll
    
    // Function to delete individual file
    window.deleteFile = async (fileId) => {
      try {
        await api.delete(`/certificates/${fileId}`)
        await refreshFileList()
      } catch (error) {
        console.error('Error deleting file:', error)
      }
    }
    
    // Load existing files on component mount
    refreshFileList()
  }, [])

  return (
    <div className={styles.container}>
      <div 
        className={`${styles.dropZone} ${dragActive ? styles.dragActive : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={onButtonClick}
      >
        <input
          ref={inputRef}
          type="file"
          multiple
          onChange={handleChange}
          className={styles.hiddenInput}
          accept=".pem,.crt,.cer,.der,.p12,.pfx,.jks,.csr,.key"
        />
        
        <div className={styles.dropContent}>
          <Upload size={48} className={styles.uploadIcon} />
          <h3>{isAnalyzing ? 'Analyzing certificates...' : 'Drop certificate files here'}</h3>
          <p>{isAnalyzing ? 'Please wait while we analyze your files' : 'or click to select files'}</p>
          <span className={styles.supportedFormats}>
            Supported: PEM, DER, PKCS12, JKS, CSR
          </span>
        </div>
      </div>

      {files.length > 0 && (
        <div className={styles.uploadMessage}>
          <p>✅ {files.length} file(s) uploaded successfully</p>
          <p>View details in the System Panel →</p>
        </div>
      )}
    </div>
  )
}

export default FileUpload