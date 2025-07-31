// frontend/src/contexts/CertificateContext.jsx
// Updated for unified storage backend

import React, { createContext, useContext, useState, useCallback } from 'react'
import api from '../services/api'

const CertificateContext = createContext(null)

export const useCertificates = () => {
  const context = useContext(CertificateContext)
  if (!context) {
    throw new Error('useCertificates must be used within a CertificateProvider')
  }
  return context
}

export const CertificateProvider = ({ children }) => {
  const [certificates, setCertificates] = useState([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [passwordState, setPasswordState] = useState({
    needsPassword: false,
    password: '',
    passwordRequiredFiles: [],
    isAnalyzing: false
  })

  const refreshFiles = useCallback(async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const response = await api.get('/certificates')
      if (response.data.success) {
        // Map unified certificates to expected format
        const files = response.data.certificates.map(cert => ({
          // Core identity
          id: cert.id,
          filename: cert.filename,
          original_format: cert.original_format,
          uploaded_at: cert.uploaded_at,
          
          // File metadata
          file_size: cert.file_size,
          file_hash: cert.file_hash,
          content_hash: cert.content_hash,
          
          // Content flags
          has_certificate: cert.has_certificate,
          has_private_key: cert.has_private_key,
          has_csr: cert.has_csr,
          additional_certs_count: cert.additional_certs_count,
          
          // Pre-computed information
          certificate_info: cert.certificate_info,
          private_key_info: cert.private_key_info,
          csr_info: cert.csr_info,
          additional_certificates_info: cert.additional_certificates_info,
          
          // Validation
          is_valid: cert.is_valid,
          validation_errors: cert.validation_errors,
          
          // Legacy fields for compatibility (derived from unified model)
          name: cert.filename,
          success: cert.is_valid,
          uploadedAt: cert.uploaded_at
        }))
        
        setCertificates(files)
      }
    } catch (error) {
      console.error('Error refreshing files:', error)
      setError('Failed to refresh certificates')
    } finally {
      setIsLoading(false)
    }
  }, [])

  const addCertificate = useCallback((certificate) => {
    // Ensure certificate has unified model structure
    const unifiedCert = {
      id: certificate.id,
      filename: certificate.filename || certificate.name,
      original_format: certificate.original_format,
      uploaded_at: certificate.uploaded_at || certificate.uploadedAt,
      file_size: certificate.file_size,
      file_hash: certificate.file_hash,
      content_hash: certificate.content_hash,
      has_certificate: certificate.has_certificate || false,
      has_private_key: certificate.has_private_key || false,
      has_csr: certificate.has_csr || false,
      additional_certs_count: certificate.additional_certs_count || 0,
      certificate_info: certificate.certificate_info,
      private_key_info: certificate.private_key_info,
      csr_info: certificate.csr_info,
      additional_certificates_info: certificate.additional_certificates_info || [],
      is_valid: certificate.is_valid || certificate.success || true,
      validation_errors: certificate.validation_errors || [],
      // Legacy compatibility
      name: certificate.filename || certificate.name,
      success: certificate.is_valid || certificate.success || true,
      uploadedAt: certificate.uploaded_at || certificate.uploadedAt
    }
    
    setCertificates(prev => [...prev, unifiedCert])
  }, [])

  const updateCertificate = useCallback((certificateId, updates) => {
    setCertificates(prev => 
      prev.map(cert => 
        cert.id === certificateId 
          ? { ...cert, ...updates }
          : cert
      )
    )
  }, [])

  const deleteCertificate = useCallback(async (certificateId) => {
    try {
      setCertificates(prev => prev.filter(cert => cert.id !== certificateId))
      await api.delete(`/certificates/${certificateId}`)
    } catch (error) {
      console.error('Error deleting certificate:', error)
      setError('Failed to delete certificate')
      refreshFiles()
    }
  }, [refreshFiles])

  const clearAllFiles = useCallback(async () => {
    try {
      // IMMEDIATELY reset password state
      setPasswordState({
        needsPassword: false,
        password: '',
        passwordRequiredFiles: [],
        isAnalyzing: false
      })
      
      setCertificates([])
      await api.delete('/certificates')
    } catch (error) {
      console.error('Error clearing all files:', error)
      setError('Failed to clear all files')
      refreshFiles()
    }
  }, [refreshFiles])

  const analyzeCertificate = useCallback(async (file, password = null) => {
    const formData = new FormData()
    formData.append('certificate', file)
    if (password) {
      formData.append('password', password)
    }
    
    const response = await api.post('/analyze-certificate', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    
    return response.data
  }, [])

  const updatePasswordState = useCallback((updates) => {
    setPasswordState(prev => ({ ...prev, ...updates }))
  }, [])

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  const value = {
    certificates,
    isLoading,
    error,
    passwordState,
    refreshFiles,
    addCertificate,
    updateCertificate,
    deleteCertificate,
    clearAllFiles,
    analyzeCertificate,
    updatePasswordState,
    clearError
  }

  return (
    <CertificateContext.Provider value={value}>
      {children}
    </CertificateContext.Provider>
  )
}