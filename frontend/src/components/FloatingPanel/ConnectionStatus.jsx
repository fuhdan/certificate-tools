import React, { useState, useEffect } from 'react'
import { Wifi, WifiOff, AlertCircle } from 'lucide-react'
import api from '../../services/api'
import styles from './FloatingPanel.module.css'

const ConnectionStatus = () => {
  const [status, setStatus] = useState('checking')
  const [lastChecked, setLastChecked] = useState(null)

  const checkConnection = async () => {
    try {
      setStatus('checking')
      const response = await api.get('/health')
      if (response.data.status === 'online') {
        setStatus('connected')
      } else {
        setStatus('disconnected')
      }
    } catch (error) {
      setStatus('disconnected')
    }
    setLastChecked(new Date())
  }

  useEffect(() => {
    checkConnection()
    const interval = setInterval(checkConnection, 10000) // Check every 10 seconds
    return () => clearInterval(interval)
  }, [])

  const getStatusConfig = () => {
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
    }
  }

  const config = getStatusConfig()

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