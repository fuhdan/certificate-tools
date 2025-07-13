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
          // Successfully analyzed with password
          await refreshFileList()
        } else if (response.data.requiresPassword) {
          // Still requires password (probably wrong password)
          allSuccessful = false
          console.log('Invalid password for:', file.filename)
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
      // Handle 401 authentication errors properly
      if (error.response && error.response.status === 401) {
        console.error('Authentication expired - please refresh the page')
        // Don't retry on 401 - just stop
        return
      }
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
          // Successfully analyzed without password
          if (response.data.isDuplicate && response.data.replaced) {
            console.log(`Automatically replaced: ${response.data.replacedCertificate.filename} -> ${response.data.certificate.filename}`)
          }
          await refreshFileList()
        } else if (response.data.requiresPassword) {
          // File requires password - add to password required list
          passwordRequiredFilesList.push({
            fileObject: file,
            filename: file.name,
            type: response.data.certificate?.analysis?.type || 'Encrypted File'
          })
          console.log('Password required for:', file.name)
        } else {
          console.error('Unexpected response:', response.data)
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
        if (error.response && error.response.status === 401) {
          console.error('Authentication expired - please refresh the page')
          return
        }
        console.error('Error deleting file:', error)
      }
    }
    
    // DON'T automatically refresh on mount - only when explicitly needed
    // refreshFileList()
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
          {needsPassword ? (
            <>
              <Key size={48} className={styles.lockIcon} />
              <h3>Enter password to continue</h3>
              <p>Password required for: {passwordRequiredFiles.map(f => f.filename).join(', ')}</p>
            </>
          ) : (
            <>
              <Upload size={48} className={styles.uploadIcon} />
              <h3>{isAnalyzing ? 'Analyzing certificates...' : 'Drop certificate files here'}</h3>
              <p>{isAnalyzing ? 'Please wait while we analyze your files' : 'or click to select files'}</p>
              <span className={styles.supportedFormats}>
                Supported: PEM, DER, PKCS12, PKCS8, JKS, CSR
              </span>
            </>
          )}
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