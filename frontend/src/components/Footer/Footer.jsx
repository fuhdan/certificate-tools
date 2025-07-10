import React, { useState } from 'react'
import styles from './Footer.module.css'

const Footer = () => {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <footer className={styles.footer}>
      <button 
        className={styles.trigger}
        onClick={() => setIsOpen(!isOpen)}
      >
        {isOpen ? '▼ NOTES ▼' : '▲ NOTES ▲'}
      </button>
      
      {isOpen && (
        <div className={styles.content}>
          <p>This is an empty website template.</p>
          <p>The floating panel shows backend connection status.</p>
        </div>
      )}
    </footer>
  )
}

export default Footer