import React, { useState, useRef } from 'react'
import { Upload, Key } from 'lucide-react'
import api from '../../services/api'
import styles from './FileUpload.module.css'

const FileUpload = () => {
  const [dragActive, setDragActive] = useState(false)
  const [files, setFiles] = useState([])
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [password, setPassword] = useState('')
  const [needsPassword, setNeedsPassword] = useState(false)
  const [passwordRequiredFiles, setPasswordRequiredFiles] = useState([])
  const inputRef = useRef(null)

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (needsPassword) return // Disable drag when password needed
    
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
    
    if (needsPassword) return // Disable drop when password needed
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(e.dataTransfer.files)
    }
  }

  const handleChange = (e) => {
    e.preventDefault()
    if (needsPassword) return // Disable file selection when password needed
    
    if (e.target.files && e.target.files[0]) {
      handleFiles(e.target.files)
    }
  }

  const handlePasswordChange = (e) => {
    const newPassword = e.target.value
    setPassword(newPassword)
    
    // If we have password-required files and a password, re-analyze them
    if (passwordRequiredFiles.length > 0 && newPassword) {
      reanalyzeFilesWithPassword(newPassword)
    }
  }

  const reanalyzeFilesWithPassword = async (pwd) => {
    setIsAnalyzing(true)
    
    let allSuccessful = true
    
    for (const file of passwordRequiredFiles) {
      try {
        const formData = new FormData()
        formData.append('certificate', file.fileObject)
        formData.append('password', pwd)
        
        const response = await api.post('/analyze-certificate', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
        
        if (response.data.success) {
          const analysis = response.data.certificate.analysis
          
          // Clear system messages if this is a successful private key upload
          if (response.data.clearSystemMessages) {
            window.dispatchEvent(new CustomEvent('clearSystemMessages'))
          }
          
          // Check if the file was successfully analyzed with valid details
          if (analysis.isValid && 
              !analysis.type.includes('Password Required') && 
              !analysis.type.includes('Invalid Password')) {
            await refreshFileList()
          } else {
            allSuccessful = false
          }
        } else if (response.data.isUnsupported) {
          // Handle unsupported files - show system message
          window.dispatchEvent(new CustomEvent('systemMessage', {
            detail: {
              message: response.data.message,
              type: 'warning',
              id: Date.now()
            }
          }))
          allSuccessful = false
        } else {
          allSuccessful = false
        }
      } catch (error) {
        console.error('Error re-analyzing with password:', error)
        allSuccessful = false
      }
    }
    
    // Only clear password requirement if ALL files were successfully analyzed
    if (allSuccessful) {
      setNeedsPassword(false)
      setPasswordRequiredFiles([])
      setPassword('')
    }
    
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
          analysis: cert.analysis,
          filename: cert.filename,
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
    
    const passwordRequiredFilesList = []
    
    for (const file of fileArray) {
      try {
        const formData = new FormData()
        formData.append('certificate', file)
        
        const response = await api.post('/analyze-certificate', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
        
        if (response.data.success) {
          const analysis = response.data.certificate.analysis
          
          // Clear system messages if this is a successful private key upload
          if (response.data.clearSystemMessages) {
            window.dispatchEvent(new CustomEvent('clearSystemMessages'))
          }
          
          // Check if file requires password
          if (analysis.type.includes('Password Required') || 
              analysis.type.includes('Invalid Password') ||
              (analysis.type.includes('PKCS12') && !analysis.isValid) ||
              (analysis.type.includes('Private Key') && analysis.type.includes('Password Required'))) {
            passwordRequiredFilesList.push({
              fileObject: file,
              filename: file.name,
              type: analysis.type
            })
          } else {
            await refreshFileList()
          }
        } else if (response.data.isUnsupported) {
          // Handle unsupported files - show system message instead of adding to list
          window.dispatchEvent(new CustomEvent('systemMessage', {
            detail: {
              message: response.data.message,
              type: 'warning',
              id: Date.now()
            }
          }))
        }
      } catch (error) {
        console.error('Error analyzing file:', error)
      }
    }
    
    if (passwordRequiredFilesList.length > 0) {
      setNeedsPassword(true)
      setPasswordRequiredFiles(passwordRequiredFilesList)
    }
    
    setIsAnalyzing(false)
  }

  const onButtonClick = () => {
    if (needsPassword) return // Disable click when password needed
    inputRef.current.click()
  }

  const clearAll = async () => {
    try {
      await api.delete('/certificates')
      await refreshFileList()
      setPassword('')
      setNeedsPassword(false)
      setPasswordRequiredFiles([])
      // Also clear system messages
      window.dispatchEvent(new CustomEvent('clearSystemMessages'))
    } catch (error) {
      console.error('Error clearing files:', error)
    }
  }

  // Make clearAll function globally accessible and sync with backend
  React.useEffect(() => {
    window.clearAllFiles = clearAll
    
    window.deleteFile = async (fileId) => {
      try {
        await api.delete(`/certificates/${fileId}`)
        await refreshFileList()
      } catch (error) {
        console.error('Error deleting file:', error)
      }
    }
    
    refreshFileList()
  }, [])

  return (
    <div className={styles.container}>
      <div 
        className={`${styles.dropZone} ${dragActive ? styles.dragActive : ''} ${needsPassword ? styles.disabled : ''}`}
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
          accept=".pem,.crt,.cer,.der,.p12,.pfx,.jks,.csr,.key,.p8,.pk8"
          disabled={needsPassword}
        />
        
        <div className={styles.dropContent}>
          <Upload size={48} className={styles.uploadIcon} />
          <h3>
            {isAnalyzing ? 'Analyzing certificates...' : 
             needsPassword ? 'Enter password to continue' : 
             'Drop certificate files here'}
          </h3>
          <p>
            {isAnalyzing ? 'Please wait while we analyze your files' : 
             needsPassword ? `Password required for: ${passwordRequiredFiles.map(f => f.filename).join(', ')}` : 
             'or click to select files'}
          </p>
          <span className={styles.supportedFormats}>
            Supported: PEM, DER, PKCS12, PKCS8, JKS, CSR
          </span>
        </div>
      </div>

      {/* Password field - only show when needed */}
      {needsPassword && (
        <div className={styles.passwordSection}>
          <div className={styles.passwordField}>
            <Key size={16} className={styles.keyIcon} />
            <input
              type="password"
              placeholder="Enter password for encrypted files"
              value={password}
              onChange={handlePasswordChange}
              className={styles.passwordInput}
              autoFocus
            />
          </div>
          <p className={styles.passwordHint}>
            Enter the correct password or click "Clear All Files" to start over.
          </p>
        </div>
      )}

      {files.length > 0 && !needsPassword && (
        <div className={styles.uploadMessage}>
          <p>✅ {files.length} file(s) uploaded successfully</p>
          <p>View details in the System Panel →</p>
        </div>
      )}
    </div>
  )
}

export default FileUpload