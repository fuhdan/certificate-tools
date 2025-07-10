import React, { useState, useRef } from 'react'
import { Upload, File } from 'lucide-react'
import styles from './FileUpload.module.css'

const FileUpload = () => {
  const [dragActive, setDragActive] = useState(false)
  const [files, setFiles] = useState([])
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

  const handleFiles = (fileList) => {
    const newFiles = Array.from(fileList).map(file => ({
      id: Date.now() + Math.random(),
      name: file.name,
      size: file.size,
      type: file.type,
      format: getFileFormat(file.name),
      file: file
    }))
    
    setFiles(prev => [...prev, ...newFiles])
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

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const onButtonClick = () => {
    inputRef.current.click()
  }

  const clearAll = () => {
    setFiles([])
  }

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
          accept=".pem,.crt,.cer,.der,.p12,.pfx,.jks"
        />
        
        <div className={styles.dropContent}>
          <Upload size={48} className={styles.uploadIcon} />
          <h3>Drop certificate files here</h3>
          <p>or click to select files</p>
          <span className={styles.supportedFormats}>
            Supported: PEM, DER, PKCS12, JKS
          </span>
        </div>
      </div>

      {files.length > 0 && (
        <div className={styles.filesSection}>
          <div className={styles.filesHeader}>
            <h4>Uploaded Files ({files.length})</h4>
            <button onClick={clearAll} className={styles.clearButton}>
              Clear All
            </button>
          </div>
          
          <div className={styles.filesList}>
            {files.map((file) => (
              <div key={file.id} className={styles.fileItem}>
                <div className={styles.fileIcon}>
                  <File size={20} />
                </div>
                <div className={styles.fileInfo}>
                  <div className={styles.fileName}>{file.name}</div>
                  <div className={styles.fileDetails}>
                    <span className={styles.fileSize}>{formatFileSize(file.size)}</span>
                    <span className={styles.fileFormat}>{file.format}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default FileUpload