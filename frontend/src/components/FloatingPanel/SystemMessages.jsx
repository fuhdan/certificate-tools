import React, { useState, useEffect } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import styles from './FloatingPanel.module.css'

const SystemMessages = () => {
  const [messages, setMessages] = useState([])

  useEffect(() => {
    // Listen for system messages
    const handleSystemMessage = (event) => {
      const { message, type = 'warning', id = Date.now() } = event.detail
      setMessages(prev => [...prev, { id, message, type, timestamp: new Date() }])
    }

    // Listen for clear messages
    const handleClearMessages = () => {
      setMessages([])
    }

    window.addEventListener('systemMessage', handleSystemMessage)
    window.addEventListener('clearSystemMessages', handleClearMessages)
    
    return () => {
      window.removeEventListener('systemMessage', handleSystemMessage)
      window.removeEventListener('clearSystemMessages', handleClearMessages)
    }
  }, [])

  const removeMessage = (id) => {
    setMessages(prev => prev.filter(msg => msg.id !== id))
  }

  if (messages.length === 0) {
    return null
  }

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
                onClick={() => removeMessage(msg.id)}
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
