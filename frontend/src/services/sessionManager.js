/**
 * Session Manager for Certificate Generator
 * Provides automatic session isolation per browser tab using sessionStorage
 */
class SessionManager {
    constructor() {
        if (!this.isSessionStorageAvailable()) {
            console.warn('SessionStorage not available, using memory fallback')
            this.memoryStorage = new Map()
        }
        this.sessionId = this.getOrCreateSessionId()
        this.initializeSession()
    }
    
    initializeSession() {
        console.log(`Certificate session initialized: ${this.sessionId.substring(0, 8)}...`)
    }
    
    /**
     * Generate RFC 4122 version 4 UUID
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0
            const v = c === 'x' ? r : (r & 0x3 | 0x8)
            return v.toString(16)
        })
    }
    
    /**
     * Validate UUID format
     */
    isValidUUID(uuid) {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        return uuidRegex.test(uuid)
    }
    
    /**
     * Check if sessionStorage is available with fallback
     */
    isSessionStorageAvailable() {
        try {
            const test = '__session_test__'
            sessionStorage.setItem(test, test)
            sessionStorage.removeItem(test)
            return true
        } catch (e) {
            return false
        }
    }
    
    /**
     * Storage abstraction with fallback support
     */
    getStorageItem(key) {
        if (this.memoryStorage) {
            return this.memoryStorage.get(key)
        }
        return sessionStorage.getItem(key)
    }
    
    setStorageItem(key, value) {
        if (this.memoryStorage) {
            this.memoryStorage.set(key, value)
        } else {
            sessionStorage.setItem(key, value)
        }
    }
    
    removeStorageItem(key) {
        if (this.memoryStorage) {
            this.memoryStorage.delete(key)
        } else {
            sessionStorage.removeItem(key)
        }
    }
    
    /**
     * Get or create session ID with timestamp tracking
     */
    getOrCreateSessionId() {
        let sessionId = this.getStorageItem('certificate_session_id')
        
        if (!sessionId || !this.isValidUUID(sessionId)) {
            // Generate new session ID
            sessionId = this.generateUUID()
            this.setStorageItem('certificate_session_id', sessionId)
            this.setStorageItem('certificate_session_created', new Date().toISOString())
            console.log('New certificate session created:', sessionId.substring(0, 8) + '...')
        } else {
            console.log('Existing certificate session restored:', sessionId.substring(0, 8) + '...')
        }
        
        return sessionId
    }
    
    /**
     * Get current session ID
     */
    getSessionId() {
        return this.sessionId
    }
    
    /**
     * Generate new session (useful for "clear all" functionality)
     */
    renewSession() {
        this.sessionId = this.generateUUID()
        this.setStorageItem('certificate_session_id', this.sessionId)
        this.setStorageItem('certificate_session_created', new Date().toISOString())
        console.log('Certificate session renewed:', this.sessionId.substring(0, 8) + '...')
        return this.sessionId
    }
    
    /**
     * Clear session storage
     */
    clearSession() {
        this.removeStorageItem('certificate_session_id')
        this.removeStorageItem('certificate_session_created')
        this.sessionId = null
        console.log('Certificate session cleared')
    }
    
    /**
     * Check if session is active and valid
     */
    isSessionActive() {
        return this.sessionId !== null && this.isValidUUID(this.sessionId)
    }
    
    /**
     * Get session information for debugging
     */
    getSessionInfo() {
        return {
            sessionId: this.sessionId ? this.sessionId.substring(0, 8) + '...' : 'None',
            fullSessionId: this.sessionId,
            isActive: this.isSessionActive(),
            storageKey: 'certificate_session_id',
            createdAt: this.getStorageItem('certificate_session_created') || 'Unknown',
            storageType: this.memoryStorage ? 'Memory' : 'SessionStorage'
        }
    }
    
    /**
     * Debug session information
     */
    debugSession() {
        console.group('Certificate Session Debug')
        console.log('Session ID:', this.sessionId)
        console.log('Session Info:', this.getSessionInfo())
        console.log('Storage:', {
            certificate_session_id: this.getStorageItem('certificate_session_id'),
            certificate_session_created: this.getStorageItem('certificate_session_created')
        })
        console.groupEnd()
    }
}

// Create and export singleton instance
export const sessionManager = new SessionManager()

// Export class for testing if needed
export { SessionManager }

// Export helper functions for convenience
export const getSessionId = () => sessionManager.getSessionId()
export const renewSession = () => sessionManager.renewSession()
export const debugSession = () => sessionManager.debugSession()
export const getSessionInfo = () => sessionManager.getSessionInfo()
export const clearSession = () => sessionManager.clearSession()