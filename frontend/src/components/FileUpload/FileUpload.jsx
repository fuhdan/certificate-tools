import React, { useState, useRef, useEffect } from 'react'
import { Upload, Key, AlertCircle } from 'lucide-react'
import api from '../../services/api'
import styles from './FileUpload.module.css'

const FileUpload = () => {
  const [dragActive, setDragActive] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [password, setPassword] = useState('')
  const [needsPassword, setNeedsPassword] = useState(false)
  const [passwordRequiredFiles, setPasswordRequiredFiles] = useState([])
  const [error, setError] = useState(null)
  const inputRef = useRef(null)

  // File validation
  const validateFile = (file) => {
    const errors = []
    
    // Size check (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
      errors.push('File too large (max 10MB)')
    }
    
    // Extension check
    const allowedExtensions = ['.pem', '.crt', '.cer', '.der', '.p12', '.pfx', '.jks', '.csr', '.key', '.p8', '.pk8']
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
    
    if (!allowedExtensions.includes(fileExtension)) {
      errors.push('Unsupported file type')
    }
    
    // Filename length check
    if (file.name.length > 255) {
      errors.push('Filename too long')
    }
    
    return errors
  }

  // Refresh file list from backend - NO AUTHENTICATION REQUIRED
  const refreshFiles = async () => {
    try {
      const response = await api.get('/certificates')
      if (response.data.success) {
        const files = response.data.certificates.map(cert => ({
          id: cert.id,
          name: cert.filename,
          success: true,
          analysis: cert.analysis,
          filename: cert.filename,
          uploadedAt: cert.uploadedAt
        }))
        
        // Update global state
        window.uploadedFiles = files
        window.dispatchEvent(new CustomEvent('filesUpdated', { detail: { files } }))
      }
    } catch (error) {
      // Only log error, don't show to user since this is background refresh
      console.error('Error refreshing files:', error)
    }
  }

  // Analyze single file - NO AUTHENTICATION REQUIRED
  const analyzeFile = async (file, password = null) => {
    const formData = new FormData()
    formData.append('certificate', file)
    if (password) {
      formData.append('password', password)
    }
    
    const response = await api.post('/analyze-certificate', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    
    return response.data
  }

  // Handle file selection/drop
  const handleFiles = async (fileList) => {
    const files = Array.from(fileList)
    setError(null)
    setIsAnalyzing(true)
    
    try {
      // Validate all files first
      const validationErrors = []
      files.forEach(file => {
        const errors = validateFile(file)
        if (errors.length > 0) {
          validationErrors.push(`${file.name}: ${errors.join(', ')}`)
        }
      })
      
      if (validationErrors.length > 0) {
        setError(`Validation failed:\n${validationErrors.join('\n')}`)
        return
      }
      
      // Process files
      const passwordRequired = []
      
      for (const file of files) {
        try {
          const result = await analyzeFile(file)
          
          if (result.success) {
            // File processed successfully
            console.log(`Successfully analyzed: ${file.name}`)
          } else if (result.requiresPassword) {
            // File needs password
            passwordRequired.push({
              fileObject: file,
              filename: file.name,
              type: result.certificate?.analysis?.type || 'Encrypted File'
            })
          } else {
            // Other error
            throw new Error(result.error || 'Analysis failed')
          }
        } catch (error) {
          console.error(`Error analyzing ${file.name}:`, error)
          setError(`Failed to analyze ${file.name}: ${error.message}`)
          return
        }
      }
      
      // Handle password-required files
      if (passwordRequired.length > 0) {
        setPasswordRequiredFiles(passwordRequired)
        setNeedsPassword(true)
      } else {
        // All files processed, refresh list
        await refreshFiles()
      }
      
    } catch (error) {
      console.error('Error handling files:', error)
      setError(`Upload failed: ${error.message}`)
    } finally {
      setIsAnalyzing(false)
    }
  }

  // Handle password submission
  const handlePasswordSubmit = async (passwordToUse = password) => {
    if (!passwordToUse.trim()) {
      setError('Please enter a password')
      return
    }
    
    setError(null)
    setIsAnalyzing(true)
    
    try {
      for (const fileInfo of passwordRequiredFiles) {
        const result = await analyzeFile(fileInfo.fileObject, passwordToUse)
        
        if (!result.success) {
          throw new Error(result.error || 'Invalid password')
        }
      }
      
      // Success - clear password state and refresh
      setPassword('')
      setNeedsPassword(false)
      setPasswordRequiredFiles([])
      await refreshFiles()
      
    } catch (error) {
      console.error('Error with password:', error)
      // Don't show password errors to user - just silently fail and let them try again
    } finally {
      setIsAnalyzing(false)
    }
  }

  // Clear all files - NO AUTHENTICATION REQUIRED
  const clearAllFiles = async () => {
    try {
      setError(null)
      await api.delete('/certificates')
      setPassword('')
      setNeedsPassword(false)
      setPasswordRequiredFiles([])
      await refreshFiles()
    } catch (error) {
      console.error('Error clearing files:', error)
      setError(`Clear failed: ${error.message}`)
    }
  }

  // Delete single file - NO AUTHENTICATION REQUIRED
  const deleteFile = async (fileId) => {
    try {
      setError(null)
      await api.delete(`/certificates/${fileId}`)
      await refreshFiles()
    } catch (error) {
      console.error('Error deleting file:', error)
      setError(`Delete failed: ${error.message}`)
    }
  }

  // Drag handlers
  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (!needsPassword) {
      setDragActive(true)
    }
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    if (needsPassword) return
    
    const files = e.dataTransfer.files
    if (files?.length > 0) {
      handleFiles(files)
    }
  }

  // File input change
  const handleInputChange = (e) => {
    if (needsPassword) return
    
    const files = e.target.files
    if (files?.length > 0) {
      handleFiles(files)
    }
  }

  // Button click
  const handleButtonClick = () => {
    if (needsPassword) return
    inputRef.current?.click()
  }

  // Password input change
  const handlePasswordChange = (e) => {
    const newPassword = e.target.value
    setPassword(newPassword)
    setError(null)
    
    // Auto-submit when password is entered
    if (passwordRequiredFiles.length > 0 && newPassword.trim()) {
      handlePasswordSubmit(newPassword)
    }
  }

  // Password form submit (not needed anymore but keeping for compatibility)
  const handlePasswordFormSubmit = (e) => {
    e.preventDefault()
    // This won't be called since we removed the form, but keeping it just in case
  }

  // Setup global functions and load initial files
  useEffect(() => {
    window.clearAllFiles = clearAllFiles
    window.deleteFile = deleteFile
    
    // Load initial files - but don't spam the server
    const loadFiles = async () => {
      try {
        await refreshFiles()
      } catch (error) {
        // Ignore errors on initial load
        console.log('Initial file load failed - this is normal')
      }
    }
    
    loadFiles()
  }, [])

  return (
    <div className={styles.container}>
      {/* Main upload area */}
      <div 
        className={`${styles.dropZone} ${dragActive ? styles.dragActive : ''} ${needsPassword ? styles.disabled : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleButtonClick}
      >
        <input
          ref={inputRef}
          type="file"
          multiple
          onChange={handleInputChange}
          className={styles.hiddenInput}
          accept=".pem,.crt,.cer,.der,.p12,.pfx,.jks,.csr,.key,.p8,.pk8"
          disabled={needsPassword}
        />
        
        <div className={styles.dropContent}>
          {needsPassword ? (
            <>
              <Key size={48} className={styles.lockIcon} />
              <h3>Password Required</h3>
              <p>Enter password for: {passwordRequiredFiles.map(f => f.filename).join(', ')}</p>
            </>
          ) : (
            <>
              <Upload size={48} className={styles.uploadIcon} />
              <h3>{isAnalyzing ? 'Analyzing certificates...' : 'Drop certificate files here'}</h3>
              <p>{isAnalyzing ? 'Please wait...' : 'or click to select files'}</p>
              <span className={styles.supportedFormats}>
                Supported: PEM, DER, PKCS12, PKCS8, JKS, CSR
              </span>
            </>
          )}
        </div>
      </div>

      {/* Error display */}
      {error && (
        <div className={styles.errorSection}>
          <div className={styles.errorMessage}>
            <AlertCircle size={16} className={styles.errorIcon} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Password form */}
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
              disabled={isAnalyzing}
            />
          </div>
          <p className={styles.passwordHint}>
            Enter the password - it will be checked automatically.
          </p>
        </div>
      )}
    </div>
  )
}

export default FileUpload
