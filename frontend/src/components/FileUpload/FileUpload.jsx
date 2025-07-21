// frontend/src/components/FileUpload/FileUpload.jsx
import React, { useState, useRef, useEffect } from 'react'
import { Upload, Key, AlertCircle } from 'lucide-react'
import { useCertificates } from '../../contexts/CertificateContext'
import styles from './FileUpload.module.css'

const FileUpload = () => {
  const {
    certificates,
    passwordState,
    addCertificate,
    refreshFiles,
    analyzeCertificate,
    updatePasswordState,
    clearError
  } = useCertificates()

  const [dragActive, setDragActive] = useState(false)
  const [error, setError] = useState(null)
  const inputRef = useRef(null)

  // Extract password state
  const { needsPassword, password, passwordRequiredFiles, isAnalyzing } = passwordState

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (window.passwordRetryTimeout) {
        clearTimeout(window.passwordRetryTimeout)
      }
    }
  }, [])

  // File validation
  const validateFile = (file) => {
    const errors = []
    
    // Size check (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
      errors.push('File too large (max 10MB)')
    }
    
    // Extension check
    const allowedExtensions = ['.pem', '.crt', '.cer', '.der', '.p12', '.pfx', '.jks', '.csr', '.key', '.p8', '.pk8', '.p7b', '.p7c', '.p7s', '.pkcs7', '.spc']
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

  // Handle file selection/drop
  const handleFiles = async (fileList, passwordOverride = null, silentMode = false) => {
    const files = Array.from(fileList)
    if (!silentMode) {
      setError(null)
      clearError() // Clear any global errors
    }
    updatePasswordState({ isAnalyzing: true })
    
    try {
      // Validate all files first (only if not in silent mode)
      if (!silentMode) {
        const validationErrors = []
        files.forEach(file => {
          const errors = validateFile(file)
          if (errors.length > 0) {
            validationErrors.push(`${file.name}: ${errors.join(', ')}`)
          }
        })
        
        if (validationErrors.length > 0) {
          setError(`Validation failed:\n${validationErrors.join('\n')}`)
          updatePasswordState({ isAnalyzing: false })
          return
        }
      }
      
      // Process each file
      const results = []
      const filesNeedingPassword = []
      const testPassword = passwordOverride || password
      
      for (const file of files) {
        try {
          const result = await analyzeCertificate(file, testPassword || null)
          
          if (result.success) {
            // Add to context state
            addCertificate({
              id: result.id || Date.now() + Math.random(),
              name: file.name,
              filename: file.name,
              success: true,
              analysis: result.analysis,
              uploadedAt: new Date().toISOString()
            })
            results.push(`✓ ${file.name}: Successfully analyzed`)
          } else {
            if (result.requiresPassword) {
              filesNeedingPassword.push(file)
            } else {
              if (!silentMode) {
                results.push(`✗ ${file.name}: ${result.error}`)
              }
            }
          }
        } catch (error) {
          if (error.response?.data?.requiresPassword) {
            filesNeedingPassword.push(file)
          } else {
            if (!silentMode) {
              results.push(`✗ ${file.name}: ${error.response?.data?.detail || error.message}`)
            }
          }
        }
      }
      
      // Handle password-protected files
      if (filesNeedingPassword.length > 0 && !silentMode) {
        updatePasswordState({
          passwordRequiredFiles: filesNeedingPassword,
          needsPassword: true
        })
      } else if (filesNeedingPassword.length === 0) {
        // Success! Clear password UI
        updatePasswordState({
          needsPassword: false,
          passwordRequiredFiles: [],
          password: ''
        })
        setError(null) // Clear any errors
        
        // Refresh the file list to ensure consistency
        await refreshFiles()
      }
      
      if (results.length > 0 && !silentMode) {
        console.log('File processing results:', results.join('\n'))
      }
      
    } catch (error) {
      if (!silentMode) {
        console.error('Error processing files:', error)
        setError(`Processing failed: ${error.message}`)
      }
    } finally {
      updatePasswordState({ isAnalyzing: false })
    }
  }

  // Handle password retry
  const handlePasswordRetry = async (passwordToTry = null) => {
    const testPassword = passwordToTry || password
    if (!testPassword.trim()) return
    
    // Check if we should still process (in case clear all was pressed)
    if (passwordRequiredFiles.length === 0) return
    
    // Try with the password - if it works, files will be processed normally
    await handleFiles(passwordRequiredFiles, testPassword, true)
  }

  // Drag and drop handlers
  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    
    if (isAnalyzing || needsPassword) return
    
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    if (isAnalyzing || needsPassword) return
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(e.dataTransfer.files)
    }
  }

  const handleChange = (e) => {
    e.preventDefault()
    if (isAnalyzing || needsPassword) return
    
    if (e.target.files && e.target.files[0]) {
      handleFiles(e.target.files)
    }
  }

  const openFileSelector = () => {
    if (!isAnalyzing && !needsPassword) {
      inputRef.current?.click()
    }
  }

  return (
    <div className={styles.container}>
      <div 
        className={`${styles.dropZone} ${dragActive ? styles.dragActive : ''} ${(isAnalyzing || needsPassword) ? styles.disabled : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={openFileSelector}
      >
        <input
          ref={inputRef}
          type="file"
          multiple
          accept=".pem,.crt,.cer,.der,.p12,.pfx,.jks,.csr,.key,.p8,.pk8,.p7b,.p7c,.p7s,.pkcs7,.spc"
          onChange={handleChange}
          className={styles.hiddenInput}
          disabled={isAnalyzing || needsPassword}
        />
        
        <div className={styles.dropContent}>
          {needsPassword ? (
            <>
              <Key size={48} className={styles.lockIcon} />
              <h3>Password Required</h3>
              <p>Enter password for protected files below</p>
            </>
          ) : isAnalyzing ? (
            <>
              <Key size={48} className={styles.lockIcon} />
              <h3>Analyzing Certificates...</h3>
              <p>Please wait while we process your files</p>
            </>
          ) : (
            <>
              <Upload size={48} className={styles.uploadIcon} />
              <h3>Upload Certificate Files</h3>
              <p>Drag and drop files here or click to browse</p>
            </>
          )}
          
          {!needsPassword && !isAnalyzing && (
            <div className={styles.supportedFormats}>
              Supports: PEM, CRT, CER, DER, P12, PFX, JKS, CSR, KEY, P8, PK8, P7B, P7C, P7S, PKCS7, SPC
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className={styles.errorSection}>
          <div className={styles.errorMessage}>
            <AlertCircle size={16} className={styles.errorIcon} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {needsPassword && (
        <div className={styles.passwordSection}>
          <div className={styles.passwordField}>
            <Key size={16} className={styles.keyIcon} />
            <input
              type="password"
              placeholder="Enter password for protected files"
              value={password}
              onChange={(e) => {
                const newPassword = e.target.value
                updatePasswordState({ password: newPassword })
                // Test immediately after each character (only if we still need password)
                if (newPassword.trim() && needsPassword && passwordRequiredFiles.length > 0) {
                  handlePasswordRetry(newPassword)
                }
              }}
              onKeyPress={(e) => e.key === 'Enter' && handlePasswordRetry()}
              className={styles.passwordInput}
              disabled={isAnalyzing}
              autoFocus
            />
          </div>
          <p className={styles.passwordHint}>
            Password tested automatically as you type
          </p>
        </div>
      )}
    </div>
  )
}

export default FileUpload