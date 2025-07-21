// frontend/src/components/FloatingPanel/AdvancedModal.jsx
import React from 'react'
import { X, Wrench } from 'lucide-react'
import styles from './AdvancedModal.module.css'

const AdvancedModal = ({ onClose }) => {
  return (
    <div className={styles.overlay}>
      <div className={styles.modal}>
        <div className={styles.header}>
          <div className={styles.titleSection}>
            <Wrench size={24} className={styles.icon} />
            <h2>Advanced Options</h2>
          </div>
          
          <div className={styles.actions}>
            <button 
              className={styles.closeButton}
              onClick={onClose}
              title="Close"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        <div className={styles.content}>
          <div className={styles.comingSoon}>
            <h3>Coming Soon</h3>
            <p>Advanced download and conversion options will be available here.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AdvancedModal