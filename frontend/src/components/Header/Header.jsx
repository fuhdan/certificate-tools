import React from 'react'
import styles from './Header.module.css'

const Header = () => {
  return (
    <header className={styles.header}>
      <div className={styles.logo}>
        <img src="./logo.png" alt="Certificate Tools" className={styles.logoImage} />
        <span className={styles.logoText}>Certificate Tools</span>
      </div>
      <div className={styles.user}>
        <button className={styles.userButton}>
          Administrator
        </button>
      </div>
    </header>
  )
}

export default Header