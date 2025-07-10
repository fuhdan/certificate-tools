import React from 'react'
import ConnectionStatus from './ConnectionStatus'
import FileManager from './FileManager'
import styles from './FloatingPanel.module.css'

const FloatingPanel = () => {
  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <h3>System Panel</h3>
      </div>
      <div className={styles.content}>
        <ConnectionStatus />
        <FileManager />
      </div>
    </div>
  )
}

export default FloatingPanel