import React, { useState, useEffect } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import styles from './FloatingPanel.module.css'

// Import comprehensive logging for system messages
import {
  systemMessagesError,
  systemMessagesWarn,
  systemMessagesDebug,
  systemMessagesLifecycle,
  systemMessagesEvent,
  systemMessagesMessage,
  systemMessagesInteraction,
  systemMessagesState,
  systemMessagesListener,
  systemMessagesValidation,
  time,
  timeEnd
} from '@/utils/logger'

const SystemMessages = () => {
  const [messages, setMessages] = useState([])

  // Log component lifecycle
  useEffect(() => {
    time('SystemMessages.initialization')
    
    systemMessagesLifecycle('COMPONENT_MOUNT', {
      initial_message_count: 0,
      component_name: 'SystemMessages'
    })

    timeEnd('SystemMessages.initialization')

    // Cleanup logging
    return () => {
      systemMessagesLifecycle('COMPONENT_UNMOUNT', {
        final_message_count: messages.length,
        cleanup_completed: true
      })
    }
  }, [])

  useEffect(() => {
    time('SystemMessages.event_listeners_setup')

    // Listen for system messages
    const handleSystemMessage = (event) => {
      time('SystemMessages.handle_system_message')
      
      systemMessagesEvent('SYSTEM_MESSAGE_RECEIVED', {
        event_type: 'systemMessage',
        has_detail: !!event.detail,
        detail_keys: event.detail ? Object.keys(event.detail) : []
      })

      try {
        const { message, type = 'warning', id = Date.now() } = event.detail || {}
        
        // Validate incoming message
        const isValidMessage = message && typeof message === 'string' && message.trim().length > 0
        const isValidType = ['info', 'warning', 'error', 'success'].includes(type)
        const isValidId = id && (typeof id === 'number' || typeof id === 'string')

        systemMessagesValidation('INCOMING_MESSAGE_VALIDATION', isValidMessage && isValidType && isValidId, {
          message_length: message?.length || 0,
          message_type: type,
          message_id: id,
          is_valid_message: isValidMessage,
          is_valid_type: isValidType,
          is_valid_id: isValidId
        })

        if (!isValidMessage) {
          systemMessagesError('Invalid system message received', {
            message,
            message_type: typeof message,
            message_length: message?.length || 0,
            error_reason: 'empty_or_invalid_message'
          })
          timeEnd('SystemMessages.handle_system_message')
          return
        }

        if (!isValidType) {
          systemMessagesWarn('Unknown message type, defaulting to warning', {
            provided_type: type,
            default_type: 'warning',
            message_id: id
          })
        }

        const newMessage = { 
          id, 
          message: message.trim(), 
          type: isValidType ? type : 'warning', 
          timestamp: new Date() 
        }

        systemMessagesMessage('MESSAGE_ADDED', newMessage, {
          message_source: 'event_listener',
          timestamp: newMessage.timestamp.toISOString()
        })

        setMessages(prev => {
          const updatedMessages = [...prev, newMessage]
          
          systemMessagesState('MESSAGES_STATE_UPDATED', updatedMessages, {
            previous_count: prev.length,
            new_count: updatedMessages.length,
            added_message_id: newMessage.id,
            operation: 'add'
          })

          return updatedMessages
        })

      } catch (error) {
        systemMessagesError('Error processing system message event', {
          error_message: error.message,
          error_stack: error.stack,
          event_detail: event.detail
        })
      }

      timeEnd('SystemMessages.handle_system_message')
    }

    // Listen for clear messages
    const handleClearMessages = (event) => {
      time('SystemMessages.handle_clear_messages')
      
      systemMessagesEvent('CLEAR_MESSAGES_RECEIVED', {
        event_type: 'clearSystemMessages',
        current_message_count: messages.length
      })

      setMessages(prev => {
        systemMessagesState('MESSAGES_CLEARED', [], {
          previous_count: prev.length,
          cleared_count: prev.length,
          operation: 'clear_all'
        })

        systemMessagesMessage('ALL_MESSAGES_CLEARED', {}, {
          cleared_message_count: prev.length,
          clear_source: 'event_listener'
        })

        return []
      })

      timeEnd('SystemMessages.handle_clear_messages')
    }

    // Register event listeners
    systemMessagesListener('EVENT_LISTENERS_REGISTER', {
      events: ['systemMessage', 'clearSystemMessages'],
      handlers: ['handleSystemMessage', 'handleClearMessages']
    })

    window.addEventListener('systemMessage', handleSystemMessage)
    window.addEventListener('clearSystemMessages', handleClearMessages)
    
    timeEnd('SystemMessages.event_listeners_setup')
    
    return () => {
      time('SystemMessages.event_listeners_cleanup')
      
      systemMessagesListener('EVENT_LISTENERS_UNREGISTER', {
        events: ['systemMessage', 'clearSystemMessages'],
        cleanup_reason: 'component_unmount'
      })

      window.removeEventListener('systemMessage', handleSystemMessage)
      window.removeEventListener('clearSystemMessages', handleClearMessages)
      
      timeEnd('SystemMessages.event_listeners_cleanup')
    }
  }, [messages.length]) // Include messages.length for logging context

  const removeMessage = (id) => {
    time('SystemMessages.remove_message')
    
    systemMessagesInteraction('REMOVE_MESSAGE_CLICK', {
      message_id: id,
      current_message_count: messages.length,
      interaction_type: 'manual_dismiss'
    })

    const messageToRemove = messages.find(msg => msg.id === id)
    
    if (!messageToRemove) {
      systemMessagesError('Attempted to remove non-existent message', {
        attempted_id: id,
        available_ids: messages.map(m => m.id),
        message_count: messages.length
      })
      timeEnd('SystemMessages.remove_message')
      return
    }

    systemMessagesMessage('MESSAGE_REMOVED', messageToRemove, {
      removal_method: 'user_interaction',
      message_age_ms: Date.now() - messageToRemove.timestamp.getTime()
    })

    setMessages(prev => {
      const updatedMessages = prev.filter(msg => msg.id !== id)
      
      systemMessagesState('MESSAGE_STATE_UPDATED_REMOVE', updatedMessages, {
        previous_count: prev.length,
        new_count: updatedMessages.length,
        removed_message_id: id,
        operation: 'remove_single'
      })

      return updatedMessages
    })

    timeEnd('SystemMessages.remove_message')
  }

  // Log state changes
  useEffect(() => {
    if (messages.length > 0) {
      systemMessagesState('MESSAGES_STATE_CHANGE', messages, {
        total_messages: messages.length,
        message_types: messages.reduce((acc, msg) => {
          acc[msg.type] = (acc[msg.type] || 0) + 1
          return acc
        }, {}),
        oldest_message_age: messages.length > 0 
          ? Date.now() - Math.min(...messages.map(m => m.timestamp.getTime()))
          : 0
      })
    }
  }, [messages])

  // Early return logging
  if (messages.length === 0) {
    systemMessagesDebug('Component render skipped - no messages', {
      message_count: 0,
      render_result: 'null'
    })
    return null
  }

  // Render logging
  systemMessagesDebug('Component rendering with messages', {
    message_count: messages.length,
    message_types: messages.reduce((acc, msg) => {
      acc[msg.type] = (acc[msg.type] || 0) + 1
      return acc
    }, {}),
    render_result: 'system_messages_ui'
  })

  return (
    <div className={styles.systemMessagesSection}>
      <div className={styles.systemMessagesCard}>
        <div className={styles.systemMessagesHeader}>
          <AlertTriangle size={16} style={{ color: '#f59e0b' }} />
          <span style={{ color: '#f59e0b', fontWeight: '500' }}>
            System Messages
          </span>
        </div>
        
        <div className={styles.messagesList}>
          {messages.map((msg) => (
            <div key={msg.id} className={styles.messageItem}>
              <div className={styles.messageContent}>
                <span className={styles.messageText}>{msg.message}</span>
              </div>
              <button 
                className={styles.removeMessageButton}
                onClick={() => {
                  systemMessagesInteraction('DISMISS_BUTTON_CLICK', {
                    message_id: msg.id,
                    message_type: msg.type,
                    message_age_ms: Date.now() - msg.timestamp.getTime()
                  })
                  removeMessage(msg.id)
                }}
                title="Dismiss message"
              >
                <X size={12} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default SystemMessages