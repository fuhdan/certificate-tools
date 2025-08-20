// frontend/src/components/common/ConnectionStatus.jsx
// ENHANCED WITH COMPREHENSIVE CONNECTION-SPECIFIC LOGGING

import React, { useState, useEffect } from 'react'
import { Wifi, WifiOff, AlertCircle } from 'lucide-react'
import api from '../../services/api'
import styles from './FloatingPanel.module.css'

// Import comprehensive logging system
import {
  connectionError,
  connectionWarn,
  connectionInfo,
  connectionDebug,
  connectionLifecycle,
  connectionStatus,
  connectionHealthCheck
} from '../../utils/logger'

const ConnectionStatus = () => {
  const [status, setStatus] = useState('checking')
  const [lastChecked, setLastChecked] = useState(null)

  // Component lifecycle logging
  useEffect(() => {
    connectionLifecycle('MOUNT', {
      initial_status: status,
      has_last_checked: !!lastChecked
    })

    return () => {
      connectionLifecycle('UNMOUNT', {
        final_status: status,
        last_checked: lastChecked?.toISOString()
      })
    }
  }, [])

  // Log status changes
  useEffect(() => {
    connectionStatus('STATUS_CHANGED', {
      new_status: status,
      timestamp: new Date().toISOString(),
      last_checked: lastChecked?.toISOString()
    })
  }, [status])

  // Log when lastChecked changes
  useEffect(() => {
    if (lastChecked) {
      connectionHealthCheck('LAST_CHECKED_UPDATED', {
        timestamp: lastChecked.toISOString(),
        current_status: status
      })
    }
  }, [lastChecked])

  const checkConnection = async () => {
    const startTime = Date.now()
    
    connectionHealthCheck('CHECK_STARTED', {
      current_status: status,
      start_time: new Date().toISOString()
    })

    try {
      setStatus('checking')
      connectionStatus('STATUS_SET_CHECKING', {
        previous_status: status,
        reason: 'health_check_initiated'
      })

      connectionHealthCheck('API_CALL_START', {
        endpoint: '/health',
        start_time: startTime
      })

      const response = await api.get('/health')
      const responseTime = Date.now() - startTime

      connectionHealthCheck('API_CALL_SUCCESS', {
        response_time_ms: responseTime,
        response_status: response.status,
        response_data: response.data
      })

      if (response.data.status === 'online') {
        setStatus('connected')
        connectionStatus('STATUS_SET_CONNECTED', {
          response_time_ms: responseTime,
          backend_status: response.data.status
        })
      } else {
        setStatus('disconnected')
        connectionWarn('Backend reported non-online status', {
          backend_status: response.data.status,
          response_time_ms: responseTime,
          full_response: response.data
        })
      }
    } catch (error) {
      const responseTime = Date.now() - startTime
      
      connectionError('Health check failed', {
        error_message: error.message,
        error_code: error.code,
        error_response: error.response?.data,
        error_status: error.response?.status,
        response_time_ms: responseTime,
        network_error: !error.response
      })

      setStatus('disconnected')
      connectionStatus('STATUS_SET_DISCONNECTED', {
        reason: 'api_error',
        error_type: error.name,
        response_time_ms: responseTime
      })
    }
    
    const checkTime = new Date()
    setLastChecked(checkTime)
    
    connectionHealthCheck('CHECK_COMPLETED', {
      final_status: status,
      total_time_ms: Date.now() - startTime,
      check_time: checkTime.toISOString()
    })
  }

  useEffect(() => {
    connectionLifecycle('INITIAL_CHECK_START')
    checkConnection()
    
    connectionLifecycle('INTERVAL_SETUP', {
      interval_ms: 10000,
      check_frequency: 'every_10_seconds'
    })
    
    const interval = setInterval(() => {
      connectionHealthCheck('INTERVAL_TRIGGERED', {
        current_status: status,
        last_checked: lastChecked?.toISOString()
      })
      checkConnection()
    }, 10000) // Check every 10 seconds
    
    return () => {
      clearInterval(interval)
      connectionLifecycle('INTERVAL_CLEARED', {
        final_status: status
      })
    }
  }, [])

  const getStatusConfig = () => {
    connectionDebug('Getting status configuration', {
      current_status: status
    })

    switch (status) {
      case 'connected':
        return {
          icon: <Wifi size={16} />,
          text: 'Backend Online',
          color: 'green',
          bgColor: '#f0f9ff'
        }
      case 'disconnected':
        return {
          icon: <WifiOff size={16} />,
          text: 'Backend Offline',
          color: 'rgb(164, 0, 29)',
          bgColor: '#fef2f2'
        }
      case 'checking':
        return {
          icon: <AlertCircle size={16} />,
          text: 'Checking...',
          color: 'orange',
          bgColor: '#fffbeb'
        }
      default:
        connectionWarn('Unknown status type, using checking config', {
          unknown_status: status,
          fallback: 'checking'
        })
        return {
          icon: <AlertCircle size={16} />,
          text: 'Unknown Status',
          color: 'red',
          bgColor: '#fef2f2'
        }
    }
  }

  const config = getStatusConfig()

  connectionDebug('Rendering connection status', {
    status,
    last_checked: lastChecked?.toISOString(),
    config: {
      text: config.text,
      color: config.color,
      bgColor: config.bgColor
    }
  })

  return (
    <div className={styles.statusSection}>
      <div 
        className={styles.statusCard}
        style={{ 
          backgroundColor: config.bgColor,
          border: `1px solid ${config.color}`
        }}
      >
        <div className={styles.statusRow}>
          <span style={{ color: config.color }}>
            {config.icon}
          </span>
          <span style={{ color: config.color, fontWeight: '500' }}>
            {config.text}
          </span>
        </div>
        {lastChecked && (
          <div className={styles.lastChecked}>
            Last: {lastChecked.toLocaleTimeString()}
          </div>
        )}
      </div>
    </div>
  )
}

export default ConnectionStatus