// frontend/src/components/common/NotificationToast.jsx
// ENHANCED WITH COMPREHENSIVE NOTIFICATION-SPECIFIC LOGGING

import React, { useEffect, useState } from 'react'
import { CheckCircle, XCircle, AlertCircle, Info, X } from 'lucide-react'
import styles from './NotificationToast.module.css'

// Import comprehensive logging system
import {
  notificationError,
  notificationWarn,
  notificationInfo,
  notificationDebug,
  notificationLifecycle,
  notificationDisplay,
  notificationTiming
} from '../../utils/logger'

const NotificationToast = ({
  type = 'info',
  message,
  duration = 5000,
  onClose,
  show = false
}) => {
  const [isVisible, setIsVisible] = useState(show)
  const [isExiting, setIsExiting] = useState(false)

  // Component lifecycle logging
  useEffect(() => {
    notificationLifecycle('MOUNT', {
      type,
      message: message?.substring(0, 100) + (message?.length > 100 ? '...' : ''),
      message_length: message?.length || 0,
      duration,
      show,
      has_close_callback: !!onClose
    })

    return () => {
      notificationLifecycle('UNMOUNT', {
        type,
        was_visible: isVisible,
        was_exiting: isExiting
      })
    }
  }, [])

  // Log prop changes
  useEffect(() => {
    notificationDisplay('PROPS_CHANGED', {
      type,
      message_length: message?.length || 0,
      duration,
      show,
      current_visible: isVisible,
      current_exiting: isExiting
    })
  }, [type, message, duration, show])

  useEffect(() => {
    if (show) {
      notificationLifecycle('SHOW', {
        type,
        message_preview: message?.substring(0, 50) + (message?.length > 50 ? '...' : ''),
        duration,
        was_visible: isVisible,
        was_exiting: isExiting
      })

      setIsVisible(true)
      setIsExiting(false)

      notificationDisplay('VISIBILITY_UPDATED', {
        type,
        is_visible: true,
        is_exiting: false
      })

      notificationTiming('VISIBILITY_SET_TRUE', {
        type,
        duration
      })

      if (duration > 0) {
        notificationTiming('AUTO_CLOSE_TIMER_SET', {
          type,
          duration_ms: duration
        })

        const timer = setTimeout(() => {
          notificationLifecycle('AUTO_CLOSE', {
            type,
            duration_ms: duration
          })
          handleClose()
        }, duration)

        return () => {
          clearTimeout(timer)
          notificationTiming('AUTO_CLOSE_TIMER_CLEARED', {
            type,
            duration_ms: duration
          })
        }
      } else {
        notificationWarn('No auto-close set - duration is zero or negative', {
          type,
          duration,
          reason: 'duration_zero_or_negative'
        })
      }
    }
  }, [show, duration])

  const handleClose = () => {
    notificationLifecycle('CLOSE_INITIATED', {
      type,
      trigger: 'manual_or_auto',
      current_visible: isVisible,
      current_exiting: isExiting
    })

    setIsExiting(true)
    notificationDisplay('EXIT_STATE_SET', {
      type,
      is_exiting: true
    })

    notificationTiming('EXIT_ANIMATION_STARTED', {
      type,
      animation_duration_ms: 300
    })

    setTimeout(() => {
      notificationTiming('EXIT_ANIMATION_COMPLETED', {
        type,
        animation_duration_ms: 300
      })

      setIsVisible(false)
      notificationDisplay('VISIBILITY_SET_FALSE', {
        type
      })

      notificationLifecycle('HIDDEN', {
        type
      })

      if (onClose) {
        notificationInfo('Executing close callback', {
          type,
          has_callback: true
        })
        try {
          onClose()
        } catch (error) {
          notificationError('Close callback execution failed', {
            type,
            error_message: error.message,
            error_stack: error.stack
          })
        }
      } else {
        notificationDebug('No close callback provided', {
          type,
          has_callback: false
        })
      }
    }, 300) // Animation duration
  }

  const getIcon = () => {
    notificationDebug('Getting icon for notification type', {
      type,
      available_types: ['success', 'error', 'warning', 'info']
    })

    switch (type) {
      case 'success':
        return <CheckCircle size={20} />
      case 'error':
        return <XCircle size={20} />
      case 'warning':
        return <AlertCircle size={20} />
      default:
        if (type !== 'info') {
          notificationError('Unknown notification type provided', {
            provided_type: type,
            fallback_type: 'info',
            available_types: ['success', 'error', 'warning', 'info']
          })
        }
        return <Info size={20} />
    }
  }

  // Early return logging
  if (!isVisible) {
    notificationDisplay('NOT_RENDERED', {
      type,
      reason: 'not_visible',
      show_prop: show,
      is_visible_state: isVisible
    })
    return null
  }

  // Render logging
  notificationDisplay('RENDERING', {
    type,
    message_length: message?.length || 0,
    is_visible: isVisible,
    is_exiting: isExiting,
    animation_state: isExiting ? 'exiting' : 'entering'
  })

  notificationInfo('Notification toast rendering', {
    type,
    message_length: message?.length || 0,
    is_visible: isVisible,
    is_exiting: isExiting
  })

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
          onClick={() => {
            notificationDisplay('CLOSE_BUTTON_CLICKED', {
              type,
              message_preview: message?.substring(0, 30) + (message?.length > 30 ? '...' : '')
            })
            notificationInfo('Close button clicked by user', {
              type,
              user_action: 'close_button_click'
            })
            handleClose()
          }}
          aria-label="Close notification"
        >
          <X size={16} />
        </button>
      </div>
    </div>
  )
}

export default NotificationToast