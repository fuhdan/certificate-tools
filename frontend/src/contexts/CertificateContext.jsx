// frontend/src/contexts/CertificateContext.jsx
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
        const files = response.data.certificates.map(cert => ({
          id: cert.id,
          name: cert.filename,
          success: true,
          analysis: cert.analysis,
          filename: cert.filename,
          uploadedAt: cert.uploadedAt
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
    setCertificates(prev => [...prev, certificate])
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