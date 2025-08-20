// frontend/src/contexts/CertificateContext.jsx
// Clean context with proper logging system

import React, { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { certificateAPI, sessionDebugUtils } from '../services/api'
import { 
  contextInfo, contextDebug, contextError, contextWarn,
  sessionInfo, sessionDebug, sessionWarn,
  time, timeEnd
} from '../utils/logger'

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
  
  // Session monitoring state
  const [sessionState, setSessionState] = useState({
    isMonitoring: false,
    lastSessionCheck: null,
    sessionChangeCount: 0,
    lastOperationTime: null
  })

  // Session monitoring effect
  useEffect(() => {
    contextInfo('CertificateProvider mounted - starting session monitoring')
    
    // Initialize session tracking
    const initialSession = sessionDebugUtils.getCurrentSessionInfo()
    setSessionState(prev => ({
      ...prev,
      lastSessionCheck: Date.now(),
      isMonitoring: true
    }))
    
    contextDebug('Initial session state:', initialSession)
    
    // Monitor session changes every 15 seconds (debug mode only)
    let sessionMonitor = null
    if (import.meta.env.VITE_DEBUG === 'true' || localStorage.getItem('certificate_debug') === 'true') {
      sessionMonitor = setInterval(() => {
        try {
          const changed = sessionDebugUtils.checkSessionNow()
          if (changed) {
            sessionWarn('Session change detected in provider!')
            setSessionState(prev => ({
              ...prev,
              sessionChangeCount: prev.sessionChangeCount + 1,
              lastSessionCheck: Date.now()
            }))
          }
        } catch (error) {
          contextError('Session monitoring error:', error)
        }
      }, 15000)
    }
    
    // Cleanup on unmount
    return () => {
      contextInfo('CertificateProvider unmounting - stopping session monitoring')
      if (sessionMonitor) {
        clearInterval(sessionMonitor)
      }
      setSessionState(prev => ({ ...prev, isMonitoring: false }))
    }
  }, [])

  // Track operation timing for session correlation
  const trackOperation = useCallback((operationName) => {
    const timestamp = Date.now()
    contextInfo(`Starting operation: ${operationName}`)
    
    setSessionState(prev => ({
      ...prev,
      lastOperationTime: timestamp
    }))
    
    return timestamp
  }, [])

  const refreshFiles = useCallback(async () => {
    const operationStart = trackOperation('refreshFiles')
    
    try {
      setIsLoading(true)
      setError(null)
      
      contextDebug('Refreshing files - checking session before API call')
      sessionDebugUtils.checkSessionNow()
      
      time('context-refresh-files')
      const result = await certificateAPI.getCertificates()
      timeEnd('context-refresh-files')
      
      contextDebug('Files refreshed - checking session after API call')
      sessionDebugUtils.checkSessionNow()
      
      if (result.success) {
        // Sort PKI components by their order field
        const sortedComponents = (result.certificates || []).sort((a, b) => {
          if (a.order !== b.order) {
            return a.order - b.order
          }
          return (a.filename || '').localeCompare(b.filename || '')
        })
        
        setComponents(sortedComponents)
        contextInfo(`Refresh successful: ${sortedComponents.length} components loaded`)
      }
    } catch (error) {
      contextError('Error refreshing files:', error)
      contextWarn('Checking session after refresh error')
      sessionDebugUtils.checkSessionNow()
      
      setError('Failed to refresh PKI components')
    } finally {
      setIsLoading(false)
      const operationEnd = Date.now()
      contextDebug(`refreshFiles completed in ${operationEnd - operationStart}ms`)
    }
  }, [trackOperation])

  const addComponent = useCallback((component) => {
    contextInfo(`Adding component: ${component.filename} (${component.type})`)
    
    setComponents(prev => {
      const newComponents = [...prev, component]
      const sorted = newComponents.sort((a, b) => {
        if (a.order !== b.order) {
          return a.order - b.order
        }
        return (a.filename || '').localeCompare(b.filename || '')
      })
      
      contextInfo(`Component added, total: ${sorted.length}`)
      return sorted
    })
  }, [])

  const updateComponent = useCallback((componentId, updates) => {
    contextDebug(`Updating component: ${componentId}`, updates)
    
    setComponents(prev => 
      prev.map(comp => 
        comp.id === componentId 
          ? { ...comp, ...updates }
          : comp
      )
    )
  }, [])

  const deleteComponent = useCallback(async (componentId) => {
    const operationStart = trackOperation(`deleteComponent-${componentId}`)
    
    try {
      contextInfo(`Deleting component: ${componentId}`)
      sessionDebugUtils.checkSessionNow()
      
      time('context-delete-component')
      await certificateAPI.deleteCertificate(componentId)
      timeEnd('context-delete-component')
      
      contextDebug('Component deleted - checking session')
      sessionDebugUtils.checkSessionNow()
      
      // Always refresh from server to ensure UI matches backend
      await refreshFiles()
      
      contextInfo('Delete operation completed')
      
    } catch (error) {
      contextError('Error deleting component:', error)
      sessionDebugUtils.checkSessionNow()
      setError('Failed to delete component')
    }
  }, [refreshFiles, trackOperation])

  const clearAllFiles = useCallback(async () => {
    const operationStart = trackOperation('clearAllFiles')
    
    try {
      contextInfo('Clearing all files')
      sessionDebugUtils.checkSessionNow()
      
      // Reset password state
      setPasswordState({
        needsPassword: false,
        password: '',
        passwordRequiredFiles: [],
        isAnalyzing: false
      })
      
      setComponents([])
      
      time('context-clear-session')
      await certificateAPI.clearSession()
      timeEnd('context-clear-session')
      
      contextInfo('All files cleared - checking session')
      sessionDebugUtils.checkSessionNow()
      
    } catch (error) {
      contextError('Error clearing all files:', error)
      sessionDebugUtils.checkSessionNow()
      setError('Failed to clear all files')
      refreshFiles()
    }
  }, [refreshFiles, trackOperation])

  const analyzeCertificate = useCallback(async (file, password = null) => {
    const operationStart = trackOperation(`analyzeCertificate-${file.name}`)
    
    try {
      contextInfo(`Analyzing certificate: ${file.name}`)
      contextDebug(`File size: ${file.size} bytes`)
      contextDebug(`Password provided: ${!!password}`)
      sessionDebugUtils.checkSessionNow()
      
      time('context-analyze-certificate')
      const result = await certificateAPI.uploadCertificate(file, password)
      timeEnd('context-analyze-certificate')
      
      contextDebug('Certificate analyzed - checking session')
      sessionDebugUtils.checkSessionNow()
      
      contextInfo(`Analysis result: ${result.success ? 'SUCCESS' : 'FAILED'}`)
      
      return result
    } catch (error) {
      contextError('Error analyzing certificate:', error)
      sessionDebugUtils.checkSessionNow()
      throw error
    }
  }, [trackOperation])

  const updatePasswordState = useCallback((updates) => {
    contextDebug('Updating password state:', updates)
    setPasswordState(prev => ({ ...prev, ...updates }))
  }, [])

  const clearError = useCallback(() => {
    contextDebug('Clearing error state')
    setError(null)
  }, [])

  // Helper functions for PKI components
  const getComponentsByType = useCallback((type) => {
    const filtered = components.filter(comp => comp.type === type)
    contextDebug(`getComponentsByType(${type}): ${filtered.length} components`)
    return filtered
  }, [components])

  const getOrderedComponents = useCallback(() => {
    contextDebug(`getOrderedComponents(): ${components.length} components`)
    return components
  }, [components])

  const hasPKIBundle = useCallback(() => {
    const hasBundle = components.length > 0
    contextDebug(`hasPKIBundle(): ${hasBundle}`)
    return hasBundle
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
      stats.byType[comp.type] = (stats.byType[comp.type] || 0) + 1
      
      if (comp.type === 'PrivateKey') stats.hasPrivateKey = true
      if (comp.type === 'Certificate') stats.hasCertificate = true
      if (comp.type === 'CSR') stats.hasCSR = true
      if (['IssuingCA', 'IntermediateCA', 'RootCA'].includes(comp.type)) stats.hasCA = true
    })

    contextDebug('PKI Stats:', stats)
    return stats
  }, [components])

  // Session debugging utilities for context
  const contextDebugUtils = useCallback(() => {
    contextInfo('=== CONTEXT DEBUG INFORMATION ===')
    
    contextInfo('Context State:')
    contextInfo(`   - Components: ${components.length}`)
    contextInfo(`   - Is Loading: ${isLoading}`)
    contextInfo(`   - Has Error: ${!!error}`)
    contextDebug('   - Password State:', passwordState)
    
    contextInfo('Session State:')
    contextInfo(`   - Is Monitoring: ${sessionState.isMonitoring}`)
    contextInfo(`   - Session Changes: ${sessionState.sessionChangeCount}`)
    contextInfo(`   - Last Check: ${sessionState.lastSessionCheck ? new Date(sessionState.lastSessionCheck).toLocaleTimeString() : 'never'}`)
    contextInfo(`   - Last Operation: ${sessionState.lastOperationTime ? new Date(sessionState.lastOperationTime).toLocaleTimeString() : 'never'}`)
    
    // Check current session
    sessionDebugUtils.getCurrentSessionInfo()
  }, [components, isLoading, error, passwordState, sessionState])

  const value = {
    // Main state
    components,
    isLoading,
    error,
    passwordState,
    
    // Session monitoring state
    sessionState,
    
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
    
    // Debug utilities
    contextDebugUtils,
    
    // Legacy compatibility
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