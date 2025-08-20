// frontend/src/components/FileUpload/FileUpload.jsx

import React, { useState, useRef, useEffect } from 'react'
import { Upload, Key, AlertCircle } from 'lucide-react'
import { useCertificates } from '../../contexts/CertificateContext'
import styles from './FileUpload.module.css'

// Import comprehensive logging system
import {
  uploadError,
  uploadWarn,
  uploadInfo,
  uploadDebug,
  uploadValidation,
  uploadLifecycle,
  uploadPassword,
  uploadInteraction,
  uploadResult,
  uploadBatch
} from '../../utils/logger'

const FileUpload = () => {
  const {
    certificates,
    passwordState,
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

  const passwordInputRef = useRef(null)

  // Component lifecycle logging
  useEffect(() => {
    uploadLifecycle('COMPONENT_MOUNT', [], {
      has_certificates: !!certificates,
      certificates_count: certificates?.length || 0,
      needs_password: needsPassword,
      is_analyzing: isAnalyzing
    })

    return () => {
      uploadLifecycle('COMPONENT_UNMOUNT', [])
      if (window.passwordRetryTimeout) {
        clearTimeout(window.passwordRetryTimeout)
        uploadDebug('Cleared password retry timeout on unmount')
      }
    }
  }, [])

  // Log password state changes
  useEffect(() => {
    if (needsPassword) {
      uploadPassword('PASSWORD_REQUIRED', {
        files_requiring_password: passwordRequiredFiles?.length || 0,
        has_password: !!password,
        password_length: password?.length || 0
      })
    }
  }, [needsPassword, passwordRequiredFiles, password])

  // File validation
  const validateFile = (file) => {
    uploadDebug(`Starting validation for file: ${file.name}`, {
      filename: file.name,
      size: file.size,
      type: file.type,
      last_modified: file.lastModified
    })

    const errors = []
    const details = {
      size: file.size,
      extension: file.name.toLowerCase().substring(file.name.lastIndexOf('.')),
      filename_length: file.name.length
    }
    
    // Size check (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
      errors.push('File too large (max 10MB)')
      uploadWarn(`File size validation failed: ${file.name}`, {
        size: file.size,
        max_size: 10 * 1024 * 1024
      })
    }
    
    // Extension check
    const allowedExtensions = ['.pem', '.crt', '.cer', '.der', '.p12', '.pfx', '.jks', '.csr', '.key', '.p8', '.pk8', '.p7b', '.p7c', '.p7s', '.pkcs7', '.spc']
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
    
    if (!allowedExtensions.includes(fileExtension)) {
      errors.push('Unsupported file type')
      uploadWarn(`File extension validation failed: ${file.name}`, {
        extension: fileExtension,
        allowed_extensions: allowedExtensions
      })
    }
    
    // Filename length check
    if (file.name.length > 255) {
      errors.push('Filename too long')
      uploadWarn(`Filename length validation failed: ${file.name}`, {
        length: file.name.length,
        max_length: 255
      })
    }

    const validationResult = {
      success: errors.length === 0,
      errors
    }

    uploadValidation(file.name, validationResult, details)
    
    return errors
  }

  // Handle file selection/drop
  const handleFiles = async (fileList, passwordOverride = null, silentMode = false) => {
    const files = Array.from(fileList)
    const startTime = Date.now()

    uploadLifecycle('FILES_RECEIVED', files, {
      files_count: files.length,
      password_override: !!passwordOverride,
      silent_mode: silentMode
    })

    if (!silentMode) {
      setError(null)
      clearError() // Clear any global errors
      uploadDebug('Cleared previous errors')
    }
    updatePasswordState({ isAnalyzing: true })
    
    try {
      // Validate all files first (only if not in silent mode)
      if (!silentMode) {
        uploadLifecycle('VALIDATION_START', files)
        const validationErrors = []
        files.forEach(file => {
          const errors = validateFile(file)
          if (errors.length > 0) {
            validationErrors.push(`${file.name}: ${errors.join(', ')}`)
          }
        })
        
        if (validationErrors.length > 0) {
          const errorMessage = `Validation failed:\n${validationErrors.join('\n')}`
          setError(errorMessage)
          updatePasswordState({ isAnalyzing: false })
          uploadError('File validation failed', {
            validation_errors: validationErrors,
            files_count: files.length
          })
          return
        }
        uploadLifecycle('VALIDATION_COMPLETE', files, { all_valid: true })
      }
      
      // Process each file
      const results = []
      const filesNeedingPassword = []
      const testPassword = passwordOverride || password
      
      uploadLifecycle('PROCESSING_START', files, {
        has_password: !!testPassword,
        password_length: testPassword?.length || 0
      })
      
      for (const [index, file] of files.entries()) {
        const fileStartTime = Date.now()
        uploadDebug(`Processing file ${index + 1}/${files.length}: ${file.name}`)

        try {
          uploadDebug(`Calling analyzeCertificate for: ${file.name}`, {
            filename: file.name,
            size: file.size,
            has_password: !!testPassword
          })

          const result = await analyzeCertificate(file, testPassword || null)
          const processingTime = Date.now() - fileStartTime

          uploadDebug(`analyzeCertificate completed for: ${file.name}`, {
            success: result.success,
            requires_password: result.requiresPassword,
            has_certificates: !!result.certificates,
            certificates_count: result.certificates?.length || 0,
            processing_time_ms: processingTime
          })
          
          if (result.success) {
            results.push(`✓ ${file.name}: Successfully analyzed`)
            uploadResult(file.name, result, {
              processing_time: processingTime,
              file_size: file.size
            })
            
            // DEBUG: Check if result already contains PKI components
            if (result.certificates && Array.isArray(result.certificates)) {
              uploadInfo(`File contains ${result.certificates.length} certificate(s): ${file.name}`)
              result.certificates.forEach((cert, idx) => {
                uploadDebug(`Certificate ${idx} details`, {
                  id: cert.id,
                  type: cert.type,
                  filename: cert.filename,
                  metadata_keys: Object.keys(cert.metadata || {})
                })
              })
            } else {
              uploadWarn(`File result does NOT contain certificates array: ${file.name}`)
            }
            
          } else {
            if (result.requiresPassword) {
              filesNeedingPassword.push(file)
              uploadPassword('FILE_REQUIRES_PASSWORD', {
                filename: file.name,
                files_requiring_password: filesNeedingPassword.length
              })
            } else {
              if (!silentMode) {
                results.push(`✗ ${file.name}: ${result.error}`)
                uploadResult(file.name, result, {
                  processing_time: processingTime,
                  file_size: file.size
                })
              }
            }
          }
        } catch (error) {
          const processingTime = Date.now() - fileStartTime
          uploadError(`Exception during file processing: ${file.name}`, {
            error_message: error.message,
            error_response: error.response?.data,
            processing_time_ms: processingTime
          })

          if (error.response?.data?.requiresPassword) {
            filesNeedingPassword.push(file)
            uploadPassword('EXCEPTION_REQUIRES_PASSWORD', {
              filename: file.name,
              error_details: error.response.data
            })
          } else {
            if (!silentMode) {
              results.push(`✗ ${file.name}: ${error.response?.data?.detail || error.message}`)
            }
          }
        }
      }
      
      // Handle password-protected files
      if (filesNeedingPassword.length > 0 && !silentMode) {
        uploadPassword('SETTING_PASSWORD_REQUIRED_STATE', {
          files_requiring_password: filesNeedingPassword.length,
          filenames: filesNeedingPassword.map(f => f.name)
        })
        updatePasswordState({
          passwordRequiredFiles: filesNeedingPassword,
          needsPassword: true
        })
      } else if (filesNeedingPassword.length === 0) {
        uploadLifecycle('ALL_FILES_PROCESSED', files, {
          successful_files: results.filter(r => r.startsWith('✓')).length,
          failed_files: results.filter(r => r.startsWith('✗')).length
        })
        
        // Success! Clear password UI
        updatePasswordState({
          needsPassword: false,
          passwordRequiredFiles: [],
          password: ''
        })
        setError(null) // Clear any errors
        
        // CRITICAL: Force refresh to ensure we get the latest PKI components
        try {
          uploadInfo('Calling refreshFiles() to get updated PKI components')
          await refreshFiles()
          uploadInfo('refreshFiles() completed successfully')
        } catch (refreshError) {
          uploadError('refreshFiles() failed after successful upload', {
            error: refreshError.message,
            stack: refreshError.stack
          })
          setError('Failed to refresh components after upload')
        }
      }
      
      // Log batch summary
      const totalTime = Date.now() - startTime
      const summary = {
        total_files: files.length,
        successful: results.filter(r => r.startsWith('✓')).length,
        failed: results.filter(r => r.startsWith('✗')).length,
        password_required: filesNeedingPassword.length,
        processing_time_ms: totalTime
      }
      uploadBatch(summary)
      
      if (results.length > 0 && !silentMode) {
        uploadInfo('File processing results summary', {
          results: results,
          total_files: files.length
        })
      }
      
    } catch (error) {
      uploadError('Critical error in handleFiles', {
        error_message: error.message,
        error_stack: error.stack,
        files_count: files.length,
        silent_mode: silentMode
      })
      if (!silentMode) {
        setError(`Processing failed: ${error.message}`)
      }
    } finally {
      updatePasswordState({ isAnalyzing: false })
      uploadLifecycle('PROCESSING_COMPLETE', files, {
        total_time_ms: Date.now() - startTime
      })
    }
  }

  // Handle password retry
  const handlePasswordRetry = async (passwordToTry = null) => {
    const testPassword = passwordToTry || password
    if (!testPassword.trim()) {
      uploadPassword('PASSWORD_RETRY_EMPTY', {
        password_length: testPassword.length
      })
      return
    }
    
    // Check if we should still process (in case clear all was pressed)
    if (passwordRequiredFiles.length === 0) {
      uploadPassword('PASSWORD_RETRY_NO_FILES', {
        password_length: testPassword.length
      })
      return
    }
    
    uploadPassword('PASSWORD_RETRY_ATTEMPT', {
      files_count: passwordRequiredFiles.length,
      password_length: testPassword.length,
      filenames: passwordRequiredFiles.map(f => f.name)
    })

    // Store the current focus state
    const hadFocus = passwordInputRef.current === document.activeElement
    
    // Try with the password - if it works, files will be processed normally
    await handleFiles(passwordRequiredFiles, testPassword, true)

    // Restore focus if the password field had focus before and still needs password
    if (hadFocus && needsPassword && passwordInputRef.current) {
      // Use setTimeout to ensure React has finished re-rendering
      setTimeout(() => {
        passwordInputRef.current?.focus()
        uploadDebug('Restored focus to password input after retry')
      }, 0)
    } 
  }

  // Drag and drop handlers
  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    
    if (isAnalyzing || needsPassword) {
      uploadInteraction('DRAG_BLOCKED', {
        event_type: e.type,
        is_analyzing: isAnalyzing,
        needs_password: needsPassword
      })
      return
    }
    
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
      uploadInteraction('DRAG_ENTER', { event_type: e.type })
    } else if (e.type === 'dragleave') {
      setDragActive(false)
      uploadInteraction('DRAG_LEAVE', { event_type: e.type })
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    uploadInteraction('DROP_EVENT', {
      files_count: e.dataTransfer.files?.length || 0,
      is_analyzing: isAnalyzing,
      needs_password: needsPassword
    })
    
    if (isAnalyzing || needsPassword) {
      uploadWarn('Drop event blocked - system is busy', {
        is_analyzing: isAnalyzing,
        needs_password: needsPassword
      })
      return
    }
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadInfo(`Files dropped: ${e.dataTransfer.files.length} files`)
      handleFiles(e.dataTransfer.files)
    }
  }

  const handleChange = (e) => {
    e.preventDefault()
    
    uploadInteraction('FILE_INPUT_CHANGE', {
      files_count: e.target.files?.length || 0,
      is_analyzing: isAnalyzing,
      needs_password: needsPassword
    })

    if (isAnalyzing || needsPassword) {
      uploadWarn('File input change blocked - system is busy', {
        is_analyzing: isAnalyzing,
        needs_password: needsPassword
      })
      return
    }
    
    if (e.target.files && e.target.files[0]) {
      uploadInfo(`Files selected via input: ${e.target.files.length} files`)
      handleFiles(e.target.files)
    }
  }

  const openFileSelector = () => {
    uploadInteraction('OPEN_FILE_SELECTOR', {
      is_analyzing: isAnalyzing,
      needs_password: needsPassword
    })

    if (!isAnalyzing && !needsPassword) {
      inputRef.current?.click()
      uploadDebug('File selector opened')
    } else {
      uploadWarn('File selector blocked - system is busy', {
        is_analyzing: isAnalyzing,
        needs_password: needsPassword
      })
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
              <p>Enter password for encrypted files below</p>
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
              ref={passwordInputRef}
              type="password"
              placeholder="Enter password for protected files"
              value={password}
              onChange={(e) => {
                const newPassword = e.target.value
                uploadPassword('PASSWORD_INPUT_CHANGE', {
                  password_length: newPassword.length,
                  has_value: !!newPassword.trim()
                })
                updatePasswordState({ password: newPassword })
                // Test immediately after each character (only if we still need password)
                if (newPassword.trim() && needsPassword && passwordRequiredFiles.length > 0) {
                  handlePasswordRetry(newPassword)
                }
              }}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  uploadInteraction('PASSWORD_ENTER_KEY', {
                    password_length: password.length
                  })
                  handlePasswordRetry()
                }
              }}
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