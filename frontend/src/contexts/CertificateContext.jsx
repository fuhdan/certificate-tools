// frontend/src/contexts/CertificateContext.jsx
// Fixed to properly sort PKI components by their order field

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
  const [components, setComponents] = useState([])
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
        // Sort PKI components by their order field (backend provides the correct order)
        const sortedComponents = (response.data.components || []).sort((a, b) => {
          // Primary sort by order (PKI hierarchy)
          if (a.order !== b.order) {
            return a.order - b.order
          }
          
          // Secondary sort by filename for consistent display
          return (a.filename || '').localeCompare(b.filename || '')
        })
        
        setComponents(sortedComponents)
      }
    } catch (error) {
      console.error('Error refreshing files:', error)
      setError('Failed to refresh PKI components')
    } finally {
      setIsLoading(false)
    }
  }, [])

  const addComponent = useCallback((component) => {
    setComponents(prev => {
      const newComponents = [...prev, component]
      // Re-sort after adding new component
      return newComponents.sort((a, b) => {
        if (a.order !== b.order) {
          return a.order - b.order
        }
        return (a.filename || '').localeCompare(b.filename || '')
      })
    })
  }, [])

  const updateComponent = useCallback((componentId, updates) => {
    setComponents(prev => 
      prev.map(comp => 
        comp.id === componentId 
          ? { ...comp, ...updates }
          : comp
      )
    )
  }, [])

  const deleteComponent = useCallback(async (componentId) => {
    try {
      setComponents(prev => prev.filter(comp => comp.id !== componentId))
      await api.delete(`/certificates/${componentId}`)
    } catch (error) {
      console.error('Error deleting component:', error)
      setError('Failed to delete component')
      refreshFiles()
    }
  }, [refreshFiles])

  const clearAllFiles = useCallback(async () => {
    try {
      // Reset password state
      setPasswordState({
        needsPassword: false,
        password: '',
        passwordRequiredFiles: [],
        isAnalyzing: false
      })
      
      setComponents([])
      
      // Clear all components
      await api.post('/certificates/clear')
      
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

  // Helper functions for PKI components
  const getComponentsByType = useCallback((type) => {
    return components.filter(comp => comp.type === type)
  }, [components])

  const getOrderedComponents = useCallback(() => {
    // Components are already sorted by order
    return components
  }, [components])

  const hasPKIBundle = useCallback(() => {
    return components.length > 0
  }, [components])

  const getPKIStats = useCallback(() => {
    const stats = {
      total: components.length,
      byType: {},
      hasPrivateKey: false,
      hasCertificate: false,
      hasCSR: false,
      hasCA: false
    }

    components.forEach(comp => {
      // Count by type
      stats.byType[comp.type] = (stats.byType[comp.type] || 0) + 1
      
      // Set flags
      if (comp.type === 'PrivateKey') stats.hasPrivateKey = true
      if (comp.type === 'Certificate') stats.hasCertificate = true
      if (comp.type === 'CSR') stats.hasCSR = true
      if (['IssuingCA', 'IntermediateCA', 'RootCA'].includes(comp.type)) stats.hasCA = true
    })

    return stats
  }, [components])

  const value = {
    // Main state
    components,
    isLoading,
    error,
    passwordState,
    
    // Actions
    refreshFiles,
    addComponent,
    updateComponent,
    deleteComponent,
    clearAllFiles,
    analyzeCertificate,
    updatePasswordState,
    clearError,
    
    // PKI helpers
    getComponentsByType,
    getOrderedComponents,
    hasPKIBundle,
    getPKIStats,
    
    // Legacy compatibility (map to components for existing code)
    certificates: components,
    addCertificate: addComponent,
    updateCertificate: updateComponent,
    deleteCertificate: deleteComponent
  }

  return (
    <CertificateContext.Provider value={value}>
      {children}
    </CertificateContext.Provider>
  )
}