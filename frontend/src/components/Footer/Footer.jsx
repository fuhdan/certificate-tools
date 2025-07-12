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
          <p>© 2025 Daniel’s Totally Legit Certificate Authority™. All rights reserved.<br />
This site uses TLS 1.3 because anything less is just insecure spaghetti code.<br />
Unauthorized access attempts will be ignored like your 10th failed login — but seriously, don’t try.<br />
Trust is established here by a Root CA, and shattered by expired certs and forgotten passwords.<br />
If you don’t understand this, please reboot your brain and try again.</p>
        </div>
      )}
    </footer>
  )
}

export default Footer