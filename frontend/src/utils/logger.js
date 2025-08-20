// frontend/src/utils/logger.js
// Frontend logging system with configurable levels

class FrontendLogger {
  constructor() {
    // Get debug mode from environment or localStorage
    this.isDebugMode = this.getDebugMode()
    this.logLevel = this.getLogLevel()
    
    // Log levels (higher number = more verbose)
    this.levels = {
      ERROR: 0,
      WARN: 1, 
      INFO: 2,
      DEBUG: 3
    }
    
    // Initialize
    if (this.isDebugMode) {
      console.info('🐛 [LOGGER] Debug mode enabled - verbose logging active')
      console.info(`🐛 [LOGGER] Log level: ${this.logLevel}`)
    }
  }
  
  getDebugMode() {
    // Check multiple sources for debug mode
    const envDebug = import.meta.env.VITE_DEBUG === 'true'
    const localStorageDebug = localStorage.getItem('certificate_debug') === 'true'
    const urlDebug = new URLSearchParams(window.location.search).get('debug') === 'true'
    
    return envDebug || localStorageDebug || urlDebug
  }
  
  getLogLevel() {
    const envLevel = import.meta.env.VITE_LOG_LEVEL
    const localStorageLevel = localStorage.getItem('certificate_log_level')
    
    return localStorageLevel || envLevel || (this.isDebugMode ? 'DEBUG' : 'INFO')
  }
  
  shouldLog(level) {
    return this.levels[level] <= this.levels[this.logLevel]
  }
  
  // Core logging methods
  error(message, ...args) {
    if (this.shouldLog('ERROR')) {
      console.error(message, ...args)
    }
  }
  
  warn(message, ...args) {
    if (this.shouldLog('WARN')) {
      console.warn(message, ...args)
    }
  }
  
  info(message, ...args) {
    if (this.shouldLog('INFO')) {
      console.info(message, ...args)
    }
  }
  
  debug(message, ...args) {
    if (this.shouldLog('DEBUG')) {
      console.log(message, ...args)
    }
  }
  
  // Session-specific logging methods
  sessionError(message, ...args) {
    this.error(`🚨 [SESSION ERROR] ${message}`, ...args)
  }
  
  sessionWarn(message, ...args) {
    this.warn(`⚠️ [SESSION WARN] ${message}`, ...args)
  }
  
  sessionInfo(message, ...args) {
    this.info(`🔑 [SESSION] ${message}`, ...args)
  }
  
  sessionDebug(message, ...args) {
    this.debug(`🔍 [SESSION DEBUG] ${message}`, ...args)
  }
  
  // API-specific logging methods
  apiError(message, ...args) {
    this.error(`📡 [API ERROR] ${message}`, ...args)
  }
  
  apiWarn(message, ...args) {
    this.warn(`📡 [API WARN] ${message}`, ...args)
  }
  
  apiInfo(message, ...args) {
    this.info(`📡 [API] ${message}`, ...args)
  }
  
  apiDebug(message, ...args) {
    this.debug(`📡 [API DEBUG] ${message}`, ...args)
  }
  
  // Context-specific logging methods
  contextError(message, ...args) {
    this.error(`🎯 [CONTEXT ERROR] ${message}`, ...args)
  }
  
  contextWarn(message, ...args) {
    this.warn(`🎯 [CONTEXT WARN] ${message}`, ...args)
  }
  
  contextInfo(message, ...args) {
    this.info(`🎯 [CONTEXT] ${message}`, ...args)
  }
  
  contextDebug(message, ...args) {
    this.debug(`🎯 [CONTEXT DEBUG] ${message}`, ...args)
  }
  
  // Cookie-specific logging methods
  cookieError(message, ...args) {
    this.error(`🍪 [COOKIE ERROR] ${message}`, ...args)
  }
  
  cookieWarn(message, ...args) {
    this.warn(`🍪 [COOKIE WARN] ${message}`, ...args)
  }
  
  cookieInfo(message, ...args) {
    this.info(`🍪 [COOKIE] ${message}`, ...args)
  }
  
  cookieDebug(message, ...args) {
    this.debug(`🍪 [COOKIE DEBUG] ${message}`, ...args)
  }
  
  // Download-specific logging methods
  downloadError(message, ...args) {
    this.error(`🔽 [DOWNLOAD ERROR] ${message}`, ...args)
  }
  
  downloadWarn(message, ...args) {
    this.warn(`🔽 [DOWNLOAD WARN] ${message}`, ...args)
  }
  
  downloadInfo(message, ...args) {
    this.info(`🔽 [DOWNLOAD] ${message}`, ...args)
  }
  
  downloadDebug(message, ...args) {
    this.debug(`🔽 [DOWNLOAD DEBUG] ${message}`, ...args)
  }

  // Certificate analysis and validation logging
  certificateError(message, ...args) {
    this.error(`📜 [CERTIFICATE ERROR] ${message}`, ...args)
  }

  certificateWarn(message, ...args) {
    this.warn(`📜 [CERTIFICATE WARN] ${message}`, ...args)
  }

  certificateInfo(message, ...args) {
    this.info(`📜 [CERTIFICATE] ${message}`, ...args)
  }

  certificateDebug(message, ...args) {
    this.debug(`📜 [CERTIFICATE DEBUG] ${message}`, ...args)
  }

  // Certificate lifecycle logging
  certificateLifecycle(stage, certificateId, details = {}) {
    this.certificateInfo(`Lifecycle [${stage}] for certificate: ${certificateId}`, details)
  }

  // Certificate metadata logging with structured format
  certificateMetadata(certificateId, metadata, action = 'ANALYSIS') {
    this.certificateDebug(`[${action}] Certificate metadata for ${certificateId}:`, {
      id: certificateId,
      type: metadata.type,
      subject: metadata.subject,
      issuer: metadata.issuer,
      serial_number: metadata.serial_number,
      not_valid_before: metadata.not_valid_before,
      not_valid_after: metadata.not_valid_after,
      days_until_expiry: metadata.days_until_expiry,
      is_expired: metadata.is_expired,
      is_ca: metadata.is_ca,
      is_self_signed: metadata.is_self_signed,
      signature_algorithm: metadata.signature_algorithm,
      public_key_algorithm: metadata.public_key_algorithm,
      public_key_size: metadata.public_key_size,
      fingerprint_sha256: metadata.fingerprint_sha256
    })
  }

  // Certificate validity status logging
  certificateValidity(certificateId, validityInfo) {
    const { isExpired, daysUntilExpiry, status, color } = validityInfo
    
    if (isExpired) {
      this.certificateWarn(`Certificate ${certificateId} is EXPIRED (${Math.abs(daysUntilExpiry)} days ago)`, {
        id: certificateId,
        status,
        daysUntilExpiry,
        isExpired
      })
    } else if (daysUntilExpiry <= 30) {
      this.certificateWarn(`Certificate ${certificateId} expires SOON (${daysUntilExpiry} days)`, {
        id: certificateId,
        status,
        daysUntilExpiry,
        isExpired
      })
    } else {
      this.certificateInfo(`Certificate ${certificateId} is valid (${daysUntilExpiry} days remaining)`, {
        id: certificateId,
        status,
        daysUntilExpiry,
        isExpired
      })
    }
  }

  // Certificate extensions logging
  certificateExtensions(certificateId, extensions) {
    this.certificateDebug(`Extensions for certificate ${certificateId}:`, {
      id: certificateId,
      subject_alt_name: extensions.subject_alt_name || [],
      key_usage: extensions.key_usage || {},
      extended_key_usage: extensions.extended_key_usage || [],
      basic_constraints: extensions.basic_constraints || {}
    })
  }

  // Certificate validation errors and bugs
  certificateBug(bugType, certificateId, details) {
    this.certificateError(`🚨 CERTIFICATE BUG [${bugType}] in ${certificateId}:`, {
      bug_type: bugType,
      certificate_id: certificateId,
      details
    })
  }

  // Certificate user interactions
  certificateInteraction(action, certificateId, details = {}) {
    this.certificateInfo(`User interaction [${action}] for certificate: ${certificateId}`, {
      id: certificateId,
      action,
      ...details
    })
  }

  // Certificate security issues
  certificateSecurity(issueType, certificateId, issue) {
    this.certificateWarn(`Security issue [${issueType}] in certificate ${certificateId}:`, {
      issue_type: issueType,
      certificate_id: certificateId,
      issue,
      severity: issue.severity || 'medium',
      recommendation: issue.recommendation || 'Review certificate configuration'
    })
  }

  // File upload specific logging methods
  uploadError(message, ...args) {
    this.error(`📤 [UPLOAD ERROR] ${message}`, ...args)
  }

  uploadWarn(message, ...args) {
    this.warn(`📤 [UPLOAD WARN] ${message}`, ...args)
  }

  uploadInfo(message, ...args) {
    this.info(`📤 [UPLOAD] ${message}`, ...args)
  }

  uploadDebug(message, ...args) {
    this.debug(`📤 [UPLOAD DEBUG] ${message}`, ...args)
  }

  // File validation logging
  uploadValidation(filename, validationResult, details = {}) {
    if (validationResult.success) {
      this.uploadInfo(`File validation passed for: ${filename}`, {
        filename,
        size: details.size,
        extension: details.extension,
        ...details
      })
    } else {
      this.uploadWarn(`File validation failed for: ${filename}`, {
        filename,
        errors: validationResult.errors,
        size: details.size,
        extension: details.extension,
        ...details
      })
    }
  }

  // File processing lifecycle
  uploadLifecycle(stage, files, details = {}) {
    this.uploadInfo(`Upload lifecycle [${stage}] - ${files.length} file(s)`, {
      stage,
      file_count: files.length,
      filenames: files.map(f => f.name || f),
      ...details
    })
  }

  // Password handling logging
  uploadPassword(action, details = {}) {
    this.uploadInfo(`Password handling [${action}]`, {
      action,
      files_requiring_password: details.files_requiring_password || 0,
      has_password: !!details.password,
      password_length: details.password?.length || 0,
      retry_attempt: details.retry_attempt || 1
    })
  }

  // Drag and drop interaction logging
  uploadInteraction(action, details = {}) {
    this.uploadDebug(`User interaction [${action}]`, {
      action,
      is_analyzing: details.is_analyzing,
      needs_password: details.needs_password,
      files_count: details.files_count || 0
    })
  }

  // File processing results
  uploadResult(filename, result, details = {}) {
    if (result.success) {
      this.uploadInfo(`✅ File processing successful: ${filename}`, {
        filename,
        certificates_found: result.certificates?.length || 0,
        processing_time: details.processing_time,
        file_size: details.file_size
      })
    } else if (result.requiresPassword) {
      this.uploadWarn(`🔑 Password required for: ${filename}`, {
        filename,
        reason: 'encrypted_file'
      })
    } else {
      this.uploadError(`❌ File processing failed: ${filename}`, {
        filename,
        error: result.error,
        details: result.details
      })
    }
  }

  // Batch processing summary
  uploadBatch(summary) {
    this.uploadInfo(`Batch upload completed`, {
      total_files: summary.total_files,
      successful: summary.successful,
      failed: summary.failed,
      password_required: summary.password_required,
      processing_time_ms: summary.processing_time_ms
    })
  }

  // Context specific logging methods
  contextLifecycle(stage, details = {}) {
    this.contextInfo(`Context lifecycle [${stage}]`, {
      stage,
      ...details
    })
  }

  contextState(action, state, details = {}) {
    this.contextDebug(`Context state [${action}]`, {
      action,
      state_keys: Object.keys(state || {}),
      ...details
    })
  }

  contextAPI(action, details = {}) {
    this.contextInfo(`Context API [${action}]`, {
      action,
      ...details
    })
  }

  contextRefresh(action, results = {}) {
    this.contextInfo(`Context refresh [${action}]`, {
      action,
      certificates_count: results.certificates?.length || 0,
      success: results.success,
      ...results
    })
  }

  // Notification toast specific logging methods
  notificationError(message, ...args) {
    this.error(`🔔 [NOTIFICATION ERROR] ${message}`, ...args)
  }

  notificationWarn(message, ...args) {
    this.warn(`🔔 [NOTIFICATION WARN] ${message}`, ...args)
  }

  notificationInfo(message, ...args) {
    this.info(`🔔 [NOTIFICATION] ${message}`, ...args)
  }

  notificationDebug(message, ...args) {
    this.debug(`🔔 [NOTIFICATION DEBUG] ${message}`, ...args)
  }

  // Notification lifecycle logging
  notificationLifecycle(stage, details = {}) {
    this.notificationInfo(`Notification lifecycle [${stage}]`, {
      stage,
      ...details
    })
  }

  // Notification display and interaction logging
  notificationDisplay(action, details = {}) {
    this.notificationDebug(`Notification display [${action}]`, {
      action,
      ...details
    })
  }

  // Notification timing and animation logging
  notificationTiming(action, details = {}) {
    this.notificationDebug(`Notification timing [${action}]`, {
      action,
      ...details
    })
  }

  // Download modal specific logging methods
  downloadModalError(message, ...args) {
    this.error(`💾 [DOWNLOAD MODAL ERROR] ${message}`, ...args)
  }

  downloadModalWarn(message, ...args) {
    this.warn(`💾 [DOWNLOAD MODAL WARN] ${message}`, ...args)
  }

  downloadModalInfo(message, ...args) {
    this.info(`💾 [DOWNLOAD MODAL] ${message}`, ...args)
  }

  downloadModalDebug(message, ...args) {
    this.debug(`💾 [DOWNLOAD MODAL DEBUG] ${message}`, ...args)
  }

  // Download modal lifecycle logging
  downloadModalLifecycle(stage, details = {}) {
    this.downloadModalInfo(`Download modal lifecycle [${stage}]`, {
      stage,
      ...details
    })
  }

  // Component selection logging
  downloadModalSelection(action, details = {}) {
    this.downloadModalDebug(`Component selection [${action}]`, {
      action,
      ...details
    })
  }

  // Format selection logging
  downloadModalFormat(action, details = {}) {
    this.downloadModalDebug(`Format selection [${action}]`, {
      action,
      ...details
    })
  }

  // Download operation logging
  downloadModalOperation(action, details = {}) {
    this.downloadModalInfo(`Download operation [${action}]`, {
      action,
      ...details
    })
  }

  // Bundle requirement checking
  downloadModalRequirement(action, details = {}) {
    this.downloadModalDebug(`Bundle requirement [${action}]`, {
      action,
      ...details
    })
  }

  // Quick action logging
  downloadModalQuickAction(action, details = {}) {
    this.downloadModalInfo(`Quick action [${action}]`, {
      action,
      ...details
    })
  }

  // Connection status specific logging methods
  connectionError(message, ...args) {
    this.error(`📡 [CONNECTION ERROR] ${message}`, ...args)
  }

  connectionWarn(message, ...args) {
    this.warn(`📡 [CONNECTION WARN] ${message}`, ...args)
  }

  connectionInfo(message, ...args) {
    this.info(`📡 [CONNECTION] ${message}`, ...args)
  }

  connectionDebug(message, ...args) {
    this.debug(`📡 [CONNECTION DEBUG] ${message}`, ...args)
  }

  // Connection lifecycle logging
  connectionLifecycle(stage, details = {}) {
    this.connectionInfo(`Connection lifecycle [${stage}]`, {
      stage,
      ...details
    })
  }

  // Connection status change logging
  connectionStatus(action, details = {}) {
    this.connectionInfo(`Connection status [${action}]`, {
      action,
      ...details
    })
  }

  // Health check logging
  connectionHealthCheck(action, details = {}) {
    this.connectionDebug(`Health check [${action}]`, {
      action,
      ...details
    })
  }

  // File manager specific logging methods
  fileManagerError(message, ...args) {
    this.error(`📁 [FILE MANAGER ERROR] ${message}`, ...args)
  }

  fileManagerWarn(message, ...args) {
    this.warn(`📁 [FILE MANAGER WARN] ${message}`, ...args)
  }

  fileManagerInfo(message, ...args) {
    this.info(`📁 [FILE MANAGER] ${message}`, ...args)
  }

  fileManagerDebug(message, ...args) {
    this.debug(`📁 [FILE MANAGER DEBUG] ${message}`, ...args)
  }

  // File manager lifecycle logging
  fileManagerLifecycle(stage, details = {}) {
    this.fileManagerInfo(`File manager lifecycle [${stage}]`, {
      stage,
      ...details
    })
  }

  // File grouping and analysis logging
  fileManagerGrouping(action, details = {}) {
    this.fileManagerDebug(`File grouping [${action}]`, {
      action,
      ...details
    })
  }

  // File deletion logging
  fileManagerDeletion(action, details = {}) {
    this.fileManagerInfo(`File deletion [${action}]`, {
      action,
      ...details
    })
  }

  // File analysis and metadata logging
  fileManagerAnalysis(action, details = {}) {
    this.fileManagerDebug(`File analysis [${action}]`, {
      action,
      ...details
    })
  }

  // File size and format detection logging
  fileManagerFormat(action, details = {}) {
    this.fileManagerDebug(`Format detection [${action}]`, {
      action,
      ...details
    })
  }

  // FloatingPanel specific logging methods
  floatingPanelError(message, ...args) {
    this.error(`🏗️ [FLOATING PANEL ERROR] ${message}`, ...args)
  }

  floatingPanelWarn(message, ...args) {
    this.warn(`🏗️ [FLOATING PANEL WARN] ${message}`, ...args)
  }

  floatingPanelInfo(message, ...args) {
    this.info(`🏗️ [FLOATING PANEL] ${message}`, ...args)
  }

  floatingPanelDebug(message, ...args) {
    this.debug(`🏗️ [FLOATING PANEL DEBUG] ${message}`, ...args)
  }

  // Panel lifecycle logging
  floatingPanelLifecycle(stage, details = {}) {
    this.floatingPanelInfo(`Panel lifecycle [${stage}]`, {
      stage,
      ...details
    })
  }

  // Panel interaction logging
  floatingPanelInteraction(action, details = {}) {
    this.floatingPanelDebug(`User interaction [${action}]`, {
      action,
      ...details
    })
  }

  // Panel state changes
  floatingPanelState(action, state, details = {}) {
    this.floatingPanelDebug(`Panel state [${action}]`, {
      action,
      state_summary: typeof state === 'object' ? Object.keys(state) : state,
      ...details
    })
  }

  // Panel position and size tracking
  floatingPanelPosition(action, position, details = {}) {
    this.floatingPanelDebug(`Panel position [${action}]`, {
      action,
      x: position?.x,
      y: position?.y,
      width: position?.width,
      height: position?.height,
      ...details
    })
  }

  // Panel download operations
  floatingPanelDownload(action, details = {}) {
    this.floatingPanelInfo(`Download operation [${action}]`, {
      action,
      ...details
    })
  }

  // Panel validation toggle
  floatingPanelValidation(action, details = {}) {
    this.floatingPanelInfo(`Validation panel [${action}]`, {
      action,
      ...details
    })
  }

  // Panel modal operations
  floatingPanelModal(action, modalType, details = {}) {
    this.floatingPanelInfo(`Modal operation [${action}] - ${modalType}`, {
      action,
      modal_type: modalType,
      ...details
    })
  }

  // Panel file management
  floatingPanelFileManagement(action, details = {}) {
    this.floatingPanelInfo(`File management [${action}]`, {
      action,
      ...details
    })
  }

  // Panel performance tracking
  floatingPanelPerformance(action, timing, details = {}) {
    this.floatingPanelDebug(`Performance [${action}]`, {
      action,
      duration_ms: timing,
      ...details
    })
  }

  // Panel error handling
  floatingPanelErrorHandling(errorType, error, details = {}) {
    this.floatingPanelError(`Error handling [${errorType}]`, {
      error_type: errorType,
      error_message: error?.message || error,
      error_stack: error?.stack,
      ...details
    })
  }

  // Panel drag and resize operations
  floatingPanelDragResize(action, details = {}) {
    this.floatingPanelDebug(`Drag/Resize [${action}]`, {
      action,
      ...details
    })
  }

  // Panel certificate analysis integration
  floatingPanelCertificateAnalysis(action, details = {}) {
    this.floatingPanelDebug(`Certificate analysis [${action}]`, {
      action,
      ...details
    })
  }

  // SecurePasswordModal specific logging methods
  securePasswordModalError(message, ...args) {
    this.error(`🔐 [SECURE PASSWORD MODAL ERROR] ${message}`, ...args)
  }

  securePasswordModalWarn(message, ...args) {
    this.warn(`🔐 [SECURE PASSWORD MODAL WARN] ${message}`, ...args)
  }

  securePasswordModalInfo(message, ...args) {
    this.info(`🔐 [SECURE PASSWORD MODAL] ${message}`, ...args)
  }

  securePasswordModalDebug(message, ...args) {
    this.debug(`🔐 [SECURE PASSWORD MODAL DEBUG] ${message}`, ...args)
  }

  // Modal lifecycle logging
  securePasswordModalLifecycle(stage, details = {}) {
    this.securePasswordModalInfo(`Modal lifecycle [${stage}]`, {
      stage,
      ...details
    })
  }

  // Password security operations
  securePasswordModalSecurity(action, details = {}) {
    this.securePasswordModalInfo(`Security operation [${action}]`, {
      action,
      ...details
    })
  }

  // Copy operations logging
  securePasswordModalCopy(action, details = {}) {
    this.securePasswordModalInfo(`Copy operation [${action}]`, {
      action,
      ...details
    })
  }

  // User interactions
  securePasswordModalInteraction(action, details = {}) {
    this.securePasswordModalDebug(`User interaction [${action}]`, {
      action,
      ...details
    })
  }

  // Modal state changes
  securePasswordModalState(action, state, details = {}) {
    this.securePasswordModalDebug(`Modal state [${action}]`, {
      action,
      state_summary: typeof state === 'object' ? Object.keys(state) : state,
      ...details
    })
  }

  // Timer and auto-close operations
  securePasswordModalTimer(action, details = {}) {
    this.securePasswordModalDebug(`Timer operation [${action}]`, {
      action,
      ...details
    })
  }

  // Password visibility toggles
  securePasswordModalVisibility(action, details = {}) {
    this.securePasswordModalDebug(`Password visibility [${action}]`, {
      action,
      ...details
    })
  }

  // Clipboard operations with security focus
  securePasswordModalClipboard(action, details = {}) {
    this.securePasswordModalInfo(`Clipboard operation [${action}]`, {
      action,
      success: details.success,
      method_used: details.method_used,
      // Never log actual passwords for security
      password_type: details.password_type,
      password_length: details.password_length
    })
  }

  // Error handling for password operations
  securePasswordModalErrorHandling(errorType, error, details = {}) {
    this.securePasswordModalError(`Error handling [${errorType}]`, {
      error_type: errorType,
      error_message: error?.message || error,
      error_stack: error?.stack,
      ...details
    })
  }

  // Modal configuration and setup
  securePasswordModalConfig(action, config, details = {}) {
    this.securePasswordModalDebug(`Modal configuration [${action}]`, {
      action,
      is_dual_mode: config.isDualMode,
      bundle_type: config.bundleType,
      has_zip_password: config.hasZipPassword,
      has_encryption_password: config.hasEncryptionPassword,
      ...details
    })
  }

  // Performance tracking for modal operations
  securePasswordModalPerformance(action, timing, details = {}) {
    this.securePasswordModalDebug(`Performance [${action}]`, {
      action,
      duration_ms: timing,
      ...details
    })
  }
  
  // Control methods
  enableDebug() {
    localStorage.setItem('certificate_debug', 'true')
    this.isDebugMode = true
    this.logLevel = 'DEBUG'
    this.info('🐛 Debug mode enabled')
  }
  
  disableDebug() {
    localStorage.setItem('certificate_debug', 'false')
    this.isDebugMode = false
    this.logLevel = 'INFO'
    this.info('🐛 Debug mode disabled')
  }
  
  setLogLevel(level) {
    if (this.levels[level] !== undefined) {
      localStorage.setItem('certificate_log_level', level)
      this.logLevel = level
      this.info(`📊 Log level set to: ${level}`)
    } else {
      this.error(`❌ Invalid log level: ${level}. Valid levels: ${Object.keys(this.levels).join(', ')}`)
    }
  }
  
  getConfig() {
    return {
      isDebugMode: this.isDebugMode,
      logLevel: this.logLevel,
      availableLevels: Object.keys(this.levels)
    }
  }
  
  // Group logging for complex operations
  group(title) {
    if (this.shouldLog('DEBUG')) {
      console.group(title)
    }
  }
  
  groupEnd() {
    if (this.shouldLog('DEBUG')) {
      console.groupEnd()
    }
  }
  
  // Time logging for performance
  time(label) {
    if (this.shouldLog('DEBUG')) {
      console.time(label)
    }
  }
  
  timeEnd(label) {
    if (this.shouldLog('DEBUG')) {
      console.timeEnd(label)
    }
  }
  
  // Session transition logging (always shows as warning for visibility)
  sessionTransition(oldSession, newSession, reason) {
    this.sessionWarn(`Session transition: ${oldSession || 'none'} → ${newSession}`)
    if (reason) {
      this.sessionWarn(`Transition reason: ${reason}`)
    }
  }
  
  // Critical session events (always logged)
  sessionExpired(details) {
    this.sessionError(`JWT token expired! ${details}`)
  }
  
  sessionCreated(sessionId) {
    this.sessionInfo(`New session created: ${sessionId.substring(0, 8)}...`)
  }
  
  cookieStateChange(change) {
    this.cookieWarn(`Cookie state changed: ${change}`)
  }
}

// Create singleton instance
const logger = new FrontendLogger()

// Export convenience methods with proper binding
export const error = (...args) => logger.error(...args)
export const warn = (...args) => logger.warn(...args)
export const info = (...args) => logger.info(...args)
export const debug = (...args) => logger.debug(...args)
export const sessionError = (...args) => logger.sessionError(...args)
export const sessionWarn = (...args) => logger.sessionWarn(...args)
export const sessionInfo = (...args) => logger.sessionInfo(...args)
export const sessionDebug = (...args) => logger.sessionDebug(...args)
export const apiError = (...args) => logger.apiError(...args)
export const apiWarn = (...args) => logger.apiWarn(...args)
export const apiInfo = (...args) => logger.apiInfo(...args)
export const apiDebug = (...args) => logger.apiDebug(...args)
export const contextError = (...args) => logger.contextError(...args)
export const contextWarn = (...args) => logger.contextWarn(...args)
export const contextInfo = (...args) => logger.contextInfo(...args)
export const contextDebug = (...args) => logger.contextDebug(...args)
export const cookieError = (...args) => logger.cookieError(...args)
export const cookieWarn = (...args) => logger.cookieWarn(...args)
export const cookieInfo = (...args) => logger.cookieInfo(...args)
export const cookieDebug = (...args) => logger.cookieDebug(...args)
export const downloadError = (...args) => logger.downloadError(...args)
export const downloadWarn = (...args) => logger.downloadWarn(...args)
export const downloadInfo = (...args) => logger.downloadInfo(...args)
export const downloadDebug = (...args) => logger.downloadDebug(...args)
export const certificateError = (...args) => logger.certificateError(...args)
export const certificateWarn = (...args) => logger.certificateWarn(...args)
export const certificateInfo = (...args) => logger.certificateInfo(...args)
export const certificateDebug = (...args) => logger.certificateDebug(...args)
export const certificateLifecycle = (...args) => logger.certificateLifecycle(...args)
export const certificateMetadata = (...args) => logger.certificateMetadata(...args)
export const certificateValidity = (...args) => logger.certificateValidity(...args)
export const certificateExtensions = (...args) => logger.certificateExtensions(...args)
export const certificateBug = (...args) => logger.certificateBug(...args)
export const certificateInteraction = (...args) => logger.certificateInteraction(...args)
export const certificateSecurity = (...args) => logger.certificateSecurity(...args)
export const uploadError = (...args) => logger.uploadError(...args)
export const uploadWarn = (...args) => logger.uploadWarn(...args)
export const uploadInfo = (...args) => logger.uploadInfo(...args)
export const uploadDebug = (...args) => logger.uploadDebug(...args)
export const uploadValidation = (...args) => logger.uploadValidation(...args)
export const uploadLifecycle = (...args) => logger.uploadLifecycle(...args)
export const uploadPassword = (...args) => logger.uploadPassword(...args)
export const uploadInteraction = (...args) => logger.uploadInteraction(...args)
export const uploadResult = (...args) => logger.uploadResult(...args)
export const uploadBatch = (...args) => logger.uploadBatch(...args)
export const contextLifecycle = (...args) => logger.contextLifecycle(...args)
export const contextState = (...args) => logger.contextState(...args)
export const contextAPI = (...args) => logger.contextAPI(...args)
export const contextRefresh = (...args) => logger.contextRefresh(...args)
export const notificationError = (...args) => logger.notificationError(...args)
export const notificationWarn = (...args) => logger.notificationWarn(...args)
export const notificationInfo = (...args) => logger.notificationInfo(...args)
export const notificationDebug = (...args) => logger.notificationDebug(...args)
export const notificationLifecycle = (...args) => logger.notificationLifecycle(...args)
export const notificationDisplay = (...args) => logger.notificationDisplay(...args)
export const notificationTiming = (...args) => logger.notificationTiming(...args)
export const downloadModalError = (...args) => logger.downloadModalError(...args)
export const downloadModalWarn = (...args) => logger.downloadModalWarn(...args)
export const downloadModalInfo = (...args) => logger.downloadModalInfo(...args)
export const downloadModalDebug = (...args) => logger.downloadModalDebug(...args)
export const downloadModalLifecycle = (...args) => logger.downloadModalLifecycle(...args)
export const downloadModalSelection = (...args) => logger.downloadModalSelection(...args)
export const downloadModalFormat = (...args) => logger.downloadModalFormat(...args)
export const downloadModalOperation = (...args) => logger.downloadModalOperation(...args)
export const downloadModalRequirement = (...args) => logger.downloadModalRequirement(...args)
export const downloadModalQuickAction = (...args) => logger.downloadModalQuickAction(...args)
export const connectionError = (...args) => logger.connectionError(...args)
export const connectionWarn = (...args) => logger.connectionWarn(...args)
export const connectionInfo = (...args) => logger.connectionInfo(...args)
export const connectionDebug = (...args) => logger.connectionDebug(...args)
export const connectionLifecycle = (...args) => logger.connectionLifecycle(...args)
export const connectionStatus = (...args) => logger.connectionStatus(...args)
export const connectionHealthCheck = (...args) => logger.connectionHealthCheck(...args)
export const fileManagerError = (...args) => logger.fileManagerError(...args)
export const fileManagerWarn = (...args) => logger.fileManagerWarn(...args)
export const fileManagerInfo = (...args) => logger.fileManagerInfo(...args)
export const fileManagerDebug = (...args) => logger.fileManagerDebug(...args)
export const fileManagerLifecycle = (...args) => logger.fileManagerLifecycle(...args)
export const fileManagerGrouping = (...args) => logger.fileManagerGrouping(...args)
export const fileManagerDeletion = (...args) => logger.fileManagerDeletion(...args)
export const fileManagerAnalysis = (...args) => logger.fileManagerAnalysis(...args)
export const fileManagerFormat = (...args) => logger.fileManagerFormat(...args)
export const floatingPanelError = (...args) => logger.floatingPanelError(...args)
export const floatingPanelWarn = (...args) => logger.floatingPanelWarn(...args)
export const floatingPanelInfo = (...args) => logger.floatingPanelInfo(...args)
export const floatingPanelDebug = (...args) => logger.floatingPanelDebug(...args)
export const floatingPanelLifecycle = (...args) => logger.floatingPanelLifecycle(...args)
export const floatingPanelInteraction = (...args) => logger.floatingPanelInteraction(...args)
export const floatingPanelState = (...args) => logger.floatingPanelState(...args)
export const floatingPanelPosition = (...args) => logger.floatingPanelPosition(...args)
export const floatingPanelDownload = (...args) => logger.floatingPanelDownload(...args)
export const floatingPanelValidation = (...args) => logger.floatingPanelValidation(...args)
export const floatingPanelModal = (...args) => logger.floatingPanelModal(...args)
export const floatingPanelFileManagement = (...args) => logger.floatingPanelFileManagement(...args)
export const floatingPanelPerformance = (...args) => logger.floatingPanelPerformance(...args)
export const floatingPanelErrorHandling = (...args) => logger.floatingPanelErrorHandling(...args)
export const floatingPanelDragResize = (...args) => logger.floatingPanelDragResize(...args)
export const floatingPanelCertificateAnalysis = (...args) => logger.floatingPanelCertificateAnalysis(...args)
export const enableDebug = (...args) => logger.enableDebug(...args)
export const disableDebug = (...args) => logger.disableDebug(...args)
export const setLogLevel = (...args) => logger.setLogLevel(...args)
export const getConfig = (...args) => logger.getConfig(...args)
export const group = (...args) => logger.group(...args)
export const groupEnd = (...args) => logger.groupEnd(...args)
export const time = (...args) => logger.time(...args)
export const timeEnd = (...args) => logger.timeEnd(...args)
export const sessionTransition = (...args) => logger.sessionTransition(...args)
export const sessionExpired = (...args) => logger.sessionExpired(...args)
export const sessionCreated = (...args) => logger.sessionCreated(...args)
export const cookieStateChange = (...args) => logger.cookieStateChange(...args)
export const securePasswordModalError = (...args) => logger.securePasswordModalError(...args)
export const securePasswordModalWarn = (...args) => logger.securePasswordModalWarn(...args)
export const securePasswordModalInfo = (...args) => logger.securePasswordModalInfo(...args)
export const securePasswordModalDebug = (...args) => logger.securePasswordModalDebug(...args)
export const securePasswordModalLifecycle = (...args) => logger.securePasswordModalLifecycle(...args)
export const securePasswordModalSecurity = (...args) => logger.securePasswordModalSecurity(...args)
export const securePasswordModalCopy = (...args) => logger.securePasswordModalCopy(...args)
export const securePasswordModalInteraction = (...args) => logger.securePasswordModalInteraction(...args)
export const securePasswordModalState = (...args) => logger.securePasswordModalState(...args)
export const securePasswordModalTimer = (...args) => logger.securePasswordModalTimer(...args)
export const securePasswordModalVisibility = (...args) => logger.securePasswordModalVisibility(...args)
export const securePasswordModalClipboard = (...args) => logger.securePasswordModalClipboard(...args)
export const securePasswordModalErrorHandling = (...args) => logger.securePasswordModalErrorHandling(...args)
export const securePasswordModalConfig = (...args) => logger.securePasswordModalConfig(...args)
export const securePasswordModalPerformance = (...args) => logger.securePasswordModalPerformance(...args)

// Make logger available globally for debugging
if (typeof window !== 'undefined') {
  window.logger = {
    ...logger,
    // Convenience methods for console use
    enable: () => logger.enableDebug(),
    disable: () => logger.disableDebug(),
    level: (level) => logger.setLogLevel(level),
    config: () => logger.getConfig()
  }
  
  // Show logger availability
  if (logger.isDebugMode) {
    console.info('🐛 [LOGGER] Available as window.logger')
    console.info('🐛 [LOGGER] Try: logger.enable(), logger.disable(), logger.level("DEBUG")')
  }
}

export default logger