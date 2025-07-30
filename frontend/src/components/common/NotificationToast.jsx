// frontend/src/components/common/NotificationToast.jsx
import React, { useEffect, useState } from 'react'
import { CheckCircle, XCircle, AlertCircle, Info, X } from 'lucide-react'
import styles from './NotificationToast.module.css'

const NotificationToast = ({ 
  type = 'info', 
  message, 
  duration = 5000, 
  onClose,
  show = false 
}) => {
  const [isVisible, setIsVisible] = useState(show)
  const [isExiting, setIsExiting] = useState(false)

  useEffect(() => {
    if (show) {
      setIsVisible(true)
      setIsExiting(false)
      
      if (duration > 0) {
        const timer = setTimeout(() => {
          handleClose()
        }, duration)
        
        return () => clearTimeout(timer)
      }
    }
  }, [show, duration])

  const handleClose = () => {
    setIsExiting(true)
    setTimeout(() => {
      setIsVisible(false)
      if (onClose) {
        onClose()
      }
    }, 300) // Animation duration
  }

  const getIcon = () => {
    switch (type) {
      case 'success':
        return <CheckCircle size={20} />
      case 'error':
        return <XCircle size={20} />
      case 'warning':
        return <AlertCircle size={20} />
      default:
        return <Info size={20} />
    }
  }

  if (!isVisible) return null

  return (
    <div className={`${styles.toast} ${styles[type]} ${isExiting ? styles.exiting : styles.entering}`}>
      <div className={styles.content}>
        <div className={styles.icon}>
          {getIcon()}
        </div>
        <div className={styles.message}>
          {message}
        </div>
        <button 
          className={styles.closeButton}
          onClick={handleClose}
          aria-label="Close notification"
        >
          <X size={16} />
        </button>
      </div>
    </div>
  )
}

export default NotificationToast