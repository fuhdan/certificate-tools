import React, { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { certificateAPI, sessionDebugUtils } from '../services/api'

// Import existing logging and comprehensive certificate context logging
import { 
  contextInfo, contextDebug, contextError, contextWarn,
  sessionInfo, sessionDebug, sessionWarn,
  certificateContextError,
  certificateContextWarn,
  certificateContextInfo,
  certificateContextDebug,
  certificateContextLifecycle,
  certificateContextState,
  certificateContextOperation,
  certificateContextComponent,
  certificateContextPassword,
  certificateContextSession,
  certificateContextAPI,
  certificateContextSorting,
  certificateContextStats,
  certificateContextPerformance,
  certificateContextSecurity,
  time, timeEnd
} from '../utils/logger'

const CertificateContext = createContext(null)

export const useCertificates = () => {
  const context = useContext(CertificateContext)
  if (!context) {
    certificateContextError('useCertificates called outside CertificateProvider', {
      error_type: 'context_usage_error',
      component_tree_issue: true
    })
    throw new Error('useCertificates must be used within a CertificateProvider')
  }
  
  certificateContextDebug('useCertificates hook accessed', {
    context_available: true,
    component_count: context.components?.length || 0
  })
  
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

  // Log component lifecycle
  useEffect(() => {
    time('CertificateContext.provider_initialization')
    
    certificateContextLifecycle('PROVIDER_MOUNT', {
      has_children: !!children,
      initial_component_count: 0,
      initial_loading_state: false,
      provider_name: 'CertificateProvider'
    })

    timeEnd('CertificateContext.provider_initialization')

    return () => {
      certificateContextLifecycle('PROVIDER_UNMOUNT', {
        final_component_count: components.length,
        final_loading_state: isLoading,
        final_error_state: !!error,
        session_monitoring_active: sessionState.isMonitoring
      })
    }
  }, [])

  // Session monitoring effect
  useEffect(() => {
    time('CertificateContext.session_monitoring_setup')
    
    contextInfo('CertificateProvider mounted - starting session monitoring')
    
    certificateContextSession('SESSION_MONITORING_START', {
      isMonitoring: false,
      lastSessionCheck: null,
      sessionChangeCount: 0
    }, {
      debug_mode: import.meta.env.VITE_DEBUG === 'true',
      local_debug: localStorage.getItem('certificate_debug') === 'true'
    })
    
    // Initialize session tracking
    const initialSession = sessionDebugUtils.getCurrentSessionInfo()
    
    const newSessionState = {
      lastSessionCheck: Date.now(),
      isMonitoring: true,
      sessionChangeCount: 0,
      lastOperationTime: null
    }
    
    setSessionState(prev => ({
      ...prev,
      ...newSessionState
    }))
    
    certificateContextSession('SESSION_STATE_INITIALIZED', newSessionState, {
      initial_session_info: initialSession
    })
    
    contextDebug('Initial session state:', initialSession)
    
    // Monitor session changes every 15 seconds (debug mode only)
    let sessionMonitor = null
    if (import.meta.env.VITE_DEBUG === 'true' || localStorage.getItem('certificate_debug') === 'true') {
      certificateContextSession('SESSION_MONITOR_ENABLED', {}, {
        monitor_interval: 15000,
        debug_mode_active: true
      })

      sessionMonitor = setInterval(() => {
        try {
          const changed = sessionDebugUtils.checkSessionNow()
          if (changed) {
            certificateContextSession('SESSION_CHANGE_DETECTED', {}, {
              change_source: 'periodic_monitor',
              monitor_interval: 15000
            })

            sessionWarn('Session change detected in provider!')
            setSessionState(prev => {
              const updated = {
                ...prev,
                sessionChangeCount: prev.sessionChangeCount + 1,
                lastSessionCheck: Date.now()
              }

              certificateContextState('SESSION_STATE_UPDATED', updated, {
                change_reason: 'session_change_detected',
                change_count: updated.sessionChangeCount
              })

              return updated
            })
          }
        } catch (error) {
          certificateContextError('Session monitoring error', {
            error_message: error.message,
            error_stack: error.stack,
            monitor_type: 'periodic_session_check'
          })
          contextError('Session monitoring error:', error)
        }
      }, 15000)
    } else {
      certificateContextSession('SESSION_MONITOR_DISABLED', {}, {
        debug_mode_active: false,
        reason: 'debug_mode_disabled'
      })
    }
    
    timeEnd('CertificateContext.session_monitoring_setup')
    
    // Cleanup on unmount
    return () => {
      time('CertificateContext.session_monitoring_cleanup')
      
      contextInfo('CertificateProvider unmounting - stopping session monitoring')
      
      certificateContextSession('SESSION_MONITORING_STOP', {
        isMonitoring: false
      }, {
        monitor_cleared: !!sessionMonitor,
        final_change_count: sessionState.sessionChangeCount
      })

      if (sessionMonitor) {
        clearInterval(sessionMonitor)
        certificateContextSession('SESSION_MONITOR_INTERVAL_CLEARED', {}, {
          interval_was_active: true
        })
      }
      
      setSessionState(prev => ({ ...prev, isMonitoring: false }))
      
      timeEnd('CertificateContext.session_monitoring_cleanup')
    }
  }, [])

  // Track operation timing for session correlation
  const trackOperation = useCallback((operationName) => {
    const timestamp = Date.now()
    
    certificateContextOperation('OPERATION_START', {
      operation_name: operationName,
      start_time: timestamp
    })

    contextInfo(`Starting operation: ${operationName}`)
    
    setSessionState(prev => {
      const updated = {
        ...prev,
        lastOperationTime: timestamp
      }

      certificateContextState('OPERATION_TIMESTAMP_UPDATED', updated, {
        operation_name: operationName,
        timestamp: timestamp
      })

      return updated
    })
    
    return timestamp
  }, [])

  // Log state changes
  useEffect(() => {
    certificateContextState('COMPONENTS_STATE_CHANGED', components, {
      component_count: components.length,
      component_types: components.reduce((acc, comp) => {
        acc[comp.type] = (acc[comp.type] || 0) + 1
        return acc
      }, {}),
      component_filenames: components.map(c => c.filename)
    })
  }, [components])

  useEffect(() => {
    certificateContextState('LOADING_STATE_CHANGED', { isLoading }, {
      loading: isLoading
    })
  }, [isLoading])

  useEffect(() => {
    certificateContextState('ERROR_STATE_CHANGED', { error }, {
      has_error: !!error,
      error_message: error
    })
  }, [error])

  useEffect(() => {
    certificateContextPassword('PASSWORD_STATE_CHANGED', passwordState, {
      needs_password: passwordState.needsPassword,
      has_password: !!passwordState.password,
      required_files_count: passwordState.passwordRequiredFiles.length,
      is_analyzing: passwordState.isAnalyzing
    })
  }, [passwordState])

  const refreshFiles = useCallback(async () => {
    const operationStart = trackOperation('refreshFiles')
    time('CertificateContext.refresh_files')
    
    try {
      certificateContextOperation('REFRESH_FILES_START', {
        operation_type: 'refresh',
        loading_state_will_change: true
      })

      setIsLoading(true)
      setError(null)
      
      certificateContextSecurity('SESSION_CHECK_BEFORE_REFRESH', {
        session_tracking: true,
        operation_type: 'refresh_files'
      })

      contextDebug('Refreshing files - checking session before API call')
      sessionDebugUtils.checkSessionNow()
      
      certificateContextAPI('API_CALL_START', {
        endpoint: 'getCertificates',
        operation: 'refresh_files'
      })

      const result = await certificateAPI.getCertificates()
      
      certificateContextAPI('API_RESPONSE_RECEIVED', {
        success: result.success,
        certificates_count: result.certificates?.length || 0,
        has_validation_results: !!result.validation_results
      })

      certificateContextSecurity('SESSION_CHECK_AFTER_REFRESH', {
        session_tracking: true,
        operation_type: 'refresh_files',
        api_success: result.success
      })

      contextDebug('Files refreshed - checking session after API call')
      sessionDebugUtils.checkSessionNow()
      
      if (result.success) {
        time('CertificateContext.component_sorting')
        
        // Sort PKI components by their order field
        const sortedComponents = (result.certificates || []).sort((a, b) => {
          if (a.order !== b.order) {
            return a.order - b.order
          }
          return (a.filename || '').localeCompare(b.filename || '')
        })
        
        certificateContextSorting('COMPONENTS_SORTED', {
          input_count: result.certificates?.length || 0,
          output_count: sortedComponents.length,
          criteria: 'order_then_filename'
        })

        timeEnd('CertificateContext.component_sorting')
        
        setComponents(sortedComponents)
        
        certificateContextOperation('REFRESH_FILES_SUCCESS', {
          operation_type: 'refresh',
          component_count: sortedComponents.length,
          success: true
        })

        contextInfo(`Refresh successful: ${sortedComponents.length} components loaded`)
      }
    } catch (error) {
      certificateContextError('Error refreshing files', {
        error_message: error.message,
        error_stack: error.stack,
        operation_type: 'refresh_files'
      })

      contextError('Error refreshing files:', error)
      
      certificateContextSecurity('SESSION_CHECK_AFTER_ERROR', {
        session_tracking: true,
        operation_type: 'refresh_files',
        error_occurred: true
      })

      contextWarn('Checking session after refresh error')
      sessionDebugUtils.checkSessionNow()
      
      setError('Failed to refresh PKI components')
    } finally {
      setIsLoading(false)
      const operationEnd = Date.now()
      
      certificateContextPerformance('REFRESH_FILES_COMPLETED', operationEnd - operationStart, {
        operation_duration: operationEnd - operationStart,
        operation_type: 'refresh_files'
      })

      contextDebug(`refreshFiles completed in ${operationEnd - operationStart}ms`)
      timeEnd('CertificateContext.refresh_files')
    }
  }, [trackOperation])

  const addComponent = useCallback((component) => {
    time('CertificateContext.add_component')
    
    certificateContextComponent('COMPONENT_ADD_START', component, {
      operation_type: 'add'
    })

    contextInfo(`Adding component: ${component.filename} (${component.type})`)
    
    setComponents(prev => {
      const newComponents = [...prev, component]
      
      certificateContextSorting('COMPONENT_SORT_ON_ADD', {
        input_count: newComponents.length,
        criteria: 'order_then_filename',
        new_component: component.filename
      })

      const sorted = newComponents.sort((a, b) => {
        if (a.order !== b.order) {
          return a.order - b.order
        }
        return (a.filename || '').localeCompare(b.filename || '')
      })
      
      certificateContextComponent('COMPONENT_ADD_COMPLETE', component, {
        operation_type: 'add',
        total_components: sorted.length,
        component_position: sorted.findIndex(c => c.id === component.id)
      })

      contextInfo(`Component added, total: ${sorted.length}`)
      
      timeEnd('CertificateContext.add_component')
      return sorted
    })
  }, [])

  const updateComponent = useCallback((componentId, updates) => {
    certificateContextComponent('COMPONENT_UPDATE_START', {
      id: componentId,
      updates: Object.keys(updates)
    }, {
      operation_type: 'update',
      update_fields: Object.keys(updates)
    })

    contextDebug(`Updating component: ${componentId}`, updates)
    
    setComponents(prev => {
      const updated = prev.map(comp => 
        comp.id === componentId 
          ? { ...comp, ...updates }
          : comp
      )

      certificateContextComponent('COMPONENT_UPDATE_COMPLETE', {
        id: componentId,
        updates: updates
      }, {
        operation_type: 'update',
        total_components: updated.length
      })

      return updated
    })
  }, [])

  const deleteComponent = useCallback(async (componentId) => {
    const operationStart = trackOperation(`deleteComponent-${componentId}`)
    time('CertificateContext.delete_component')
    
    try {
      certificateContextComponent('COMPONENT_DELETE_START', {
        id: componentId
      }, {
        operation_type: 'delete'
      })

      contextInfo(`Deleting component: ${componentId}`)
      
      certificateContextSecurity('SESSION_CHECK_BEFORE_DELETE', {
        session_tracking: true,
        operation_type: 'delete_component',
        component_id: componentId
      })

      sessionDebugUtils.checkSessionNow()
      
      certificateContextAPI('API_CALL_DELETE', {
        endpoint: 'deleteCertificate',
        component_id: componentId
      })

      await certificateAPI.deleteCertificate(componentId)
      
      certificateContextSecurity('SESSION_CHECK_AFTER_DELETE', {
        session_tracking: true,
        operation_type: 'delete_component',
        component_id: componentId,
        delete_success: true
      })

      contextDebug('Component deleted - checking session')
      sessionDebugUtils.checkSessionNow()
      
      // Always refresh from server to ensure UI matches backend
      await refreshFiles()
      
      certificateContextComponent('COMPONENT_DELETE_COMPLETE', {
        id: componentId
      }, {
        operation_type: 'delete',
        refresh_triggered: true
      })

      contextInfo('Delete operation completed')
      
    } catch (error) {
      certificateContextError('Error deleting component', {
        error_message: error.message,
        error_stack: error.stack,
        component_id: componentId,
        operation_type: 'delete_component'
      })

      contextError('Error deleting component:', error)
      sessionDebugUtils.checkSessionNow()
      setError('Failed to delete component')
    } finally {
      const operationEnd = Date.now()
      
      certificateContextPerformance('DELETE_COMPONENT_COMPLETED', operationEnd - operationStart, {
        operation_duration: operationEnd - operationStart,
        component_id: componentId
      })

      timeEnd('CertificateContext.delete_component')
    }
  }, [refreshFiles, trackOperation])

  const clearAllFiles = useCallback(async () => {
    const operationStart = trackOperation('clearAllFiles')
    time('CertificateContext.clear_all_files')
    
    try {
      certificateContextOperation('CLEAR_ALL_START', {
        operation_type: 'clear_all',
        current_component_count: components.length
      })

      contextInfo('Clearing all files')
      
      certificateContextSecurity('SESSION_CHECK_BEFORE_CLEAR', {
        session_tracking: true,
        operation_type: 'clear_all_files'
      })

      sessionDebugUtils.checkSessionNow()
      
      // Reset password state
      const clearedPasswordState = {
        needsPassword: false,
        password: '',
        passwordRequiredFiles: [],
        isAnalyzing: false
      }

      certificateContextPassword('PASSWORD_STATE_CLEARED', clearedPasswordState, {
        operation_type: 'clear_all'
      })

      setPasswordState(clearedPasswordState)
      
      setComponents([])
      
      certificateContextAPI('API_CALL_CLEAR_SESSION', {
        endpoint: 'clearSession',
        operation: 'clear_all_files'
      })

      await certificateAPI.clearSession()
      
      certificateContextSecurity('SESSION_CHECK_AFTER_CLEAR', {
        session_tracking: true,
        operation_type: 'clear_all_files',
        clear_success: true
      })

      contextInfo('All files cleared - checking session')
      sessionDebugUtils.checkSessionNow()
      
      certificateContextOperation('CLEAR_ALL_COMPLETE', {
        operation_type: 'clear_all',
        success: true
      })

    } catch (error) {
      certificateContextError('Error clearing all files', {
        error_message: error.message,
        error_stack: error.stack,
        operation_type: 'clear_all_files'
      })

      contextError('Error clearing all files:', error)
      sessionDebugUtils.checkSessionNow()
      setError('Failed to clear all files')
      refreshFiles()
    } finally {
      const operationEnd = Date.now()
      
      certificateContextPerformance('CLEAR_ALL_COMPLETED', operationEnd - operationStart, {
        operation_duration: operationEnd - operationStart
      })

      timeEnd('CertificateContext.clear_all_files')
    }
  }, [refreshFiles, trackOperation, components.length])

  const analyzeCertificate = useCallback(async (file, password = null) => {
    const operationStart = trackOperation(`analyzeCertificate-${file.name}`)
    time('CertificateContext.analyze_certificate')
    
    try {
      certificateContextOperation('ANALYZE_CERTIFICATE_START', {
        filename: file.name,
        file_size: file.size,
        has_password: !!password
      }, {
        operation_type: 'analyze_certificate'
      })

      contextInfo(`Analyzing certificate: ${file.name}`)
      contextDebug(`File size: ${file.size} bytes`)
      contextDebug(`Password provided: ${!!password}`)
      
      certificateContextSecurity('SESSION_CHECK_BEFORE_ANALYZE', {
        session_tracking: true,
        operation_type: 'analyze_certificate',
        filename: file.name,
        password_handling: !!password
      })

      sessionDebugUtils.checkSessionNow()
      
      certificateContextAPI('API_CALL_UPLOAD', {
        endpoint: 'uploadCertificate',
        filename: file.name,
        file_size: file.size,
        has_password: !!password
      })

      const result = await certificateAPI.uploadCertificate(file, password)
      
      certificateContextSecurity('SESSION_CHECK_AFTER_ANALYZE', {
        session_tracking: true,
        operation_type: 'analyze_certificate',
        filename: file.name,
        analysis_success: result.success
      })

      contextDebug('Certificate analyzed - checking session')
      sessionDebugUtils.checkSessionNow()
      
      certificateContextOperation('ANALYZE_CERTIFICATE_COMPLETE', {
        filename: file.name,
        success: result.success,
        has_certificate: result.certificate?.has_certificate,
        has_private_key: result.certificate?.has_private_key,
        has_csr: result.certificate?.has_csr
      }, {
        operation_type: 'analyze_certificate'
      })

      contextInfo(`Analysis result: ${result.success ? 'SUCCESS' : 'FAILED'}`)
      
      return result
    } catch (error) {
      certificateContextError('Error analyzing certificate', {
        error_message: error.message,
        error_stack: error.stack,
        filename: file.name,
        file_size: file.size,
        operation_type: 'analyze_certificate'
      })

      contextError('Error analyzing certificate:', error)
      sessionDebugUtils.checkSessionNow()
      throw error
    } finally {
      const operationEnd = Date.now()
      
      certificateContextPerformance('ANALYZE_CERTIFICATE_COMPLETED', operationEnd - operationStart, {
        operation_duration: operationEnd - operationStart,
        filename: file.name
      })

      timeEnd('CertificateContext.analyze_certificate')
    }
  }, [trackOperation])

  const updatePasswordState = useCallback((updates) => {
    certificateContextPassword('PASSWORD_STATE_UPDATE', updates, {
      update_keys: Object.keys(updates),
      operation_type: 'update_password_state'
    })

    contextDebug('Updating password state:', updates)
    setPasswordState(prev => ({ ...prev, ...updates }))
  }, [])

  const clearError = useCallback(() => {
    certificateContextState('ERROR_CLEARED', {
      error_was_present: !!error
    })

    contextDebug('Clearing error state')
    setError(null)
  }, [error])

  // Helper functions for PKI components
  const getComponentsByType = useCallback((type) => {
    const filtered = components.filter(comp => comp.type === type)
    
    certificateContextStats('COMPONENTS_BY_TYPE_QUERY', {
      requested_type: type,
      found_count: filtered.length,
      total_components: components.length
    })

    contextDebug(`getComponentsByType(${type}): ${filtered.length} components`)
    return filtered
  }, [components])

  const getOrderedComponents = useCallback(() => {
    certificateContextStats('ORDERED_COMPONENTS_QUERY', {
      component_count: components.length
    })

    contextDebug(`getOrderedComponents(): ${components.length} components`)
    return components
  }, [components])

  const hasPKIBundle = useCallback(() => {
    const hasBundle = components.length > 0
    
    certificateContextStats('PKI_BUNDLE_CHECK', {
      has_bundle: hasBundle,
      component_count: components.length
    })

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

    certificateContextStats('PKI_STATS_CALCULATED', stats, {
      calculation_complete: true
    })

    contextDebug('PKI Stats:', stats)
    return stats
  }, [components])

  // Session debugging utilities for context
  const contextDebugUtils = useCallback(() => {
    certificateContextLifecycle('DEBUG_UTILS_INVOKED', {
      component_count: components.length,
      is_loading: isLoading,
      has_error: !!error,
      session_monitoring: sessionState.isMonitoring
    })

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
    components: components || [],
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
    certificates: components || [],
    addCertificate: addComponent,
    updateCertificate: updateComponent,
    deleteCertificate: deleteComponent
  }

  certificateContextLifecycle('PROVIDER_VALUE_CREATED', {
    value_keys: Object.keys(value),
    component_count: components.length,
    state_summary: {
      loading: isLoading,
      error: !!error,
      passwordState: Object.keys(passwordState),
      sessionState: Object.keys(sessionState)
    }
  })

  return (
    <CertificateContext.Provider value={value}>
      {children}
    </CertificateContext.Provider>
  )
}