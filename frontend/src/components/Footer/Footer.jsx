import React, { useState, useEffect } from 'react'
import styles from './Footer.module.css'

const Footer = () => {
  const [isOpen, setIsOpen] = useState(false)
  const [text, setText] = useState('Loading…')

  useEffect(() => {
    fetch('/assets/footer.txt')
      .then(res => res.text())
      .then(data => setText(data))
      .catch(err => setText('Failed to load footer text.'))
  }, [])

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
          {text.split('\n').map((line, idx) => (
            <p key={idx}>{line}</p>
          ))}
        </div>
      )}
    </footer>
  )
}

export default Footer