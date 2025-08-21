// frontend/src/utils/logger.js
// Frontend logging system with configurable global + per-section levels

class FrontendLogger {
  constructor() {
    // Known sections (used only for convenience & validation)
    this.sections = [
      'session',
      'api',
      'context',
      'cookie',
      'download',
      'certificate',
      'upload',
      'notification',
      'downloadModal',
      'connection',
      'fileManager',
      'floatingPanel',
      'securePasswordModal',
      'systemMessages',
      'layout',
      'validationPanel',
      'certificateContext'
    ]

    // Log levels (higher number = more verbose)
    this.levels = {
      ERROR: 0,
      WARN: 1,
      INFO: 2,
      DEBUG: 3
    }

    // Debug mode & global level
    this.isDebugMode = this.getDebugMode()
    this.logLevel = this.getLogLevel()

    // Section-specific overrides { [section]: 'ERROR'|'WARN'|'INFO'|'DEBUG' }
    this.sectionLogLevels = this.loadSectionLogLevels()

    // Initialize
    if (this.isDebugMode) {
      console.info('🐛 [LOGGER] Debug mode enabled - verbose logging active')
      console.info(`🐛 [LOGGER] Global log level: ${this.logLevel}`)
      console.info('🐛 [LOGGER] Section overrides:', this.sectionLogLevels)
    }
  }

  // --------------------------
  // Config helpers
  // --------------------------
  getDebugMode() {
    const envDebug = import.meta.env?.VITE_DEBUG === 'true'
    const localStorageDebug = localStorage.getItem('certificate_debug') === 'true'
    const urlDebug = new URLSearchParams(window.location.search).get('debug') === 'true'
    return envDebug || localStorageDebug || urlDebug
  }

  getLogLevel() {
    const envLevel = import.meta.env?.VITE_LOG_LEVEL
    const localStorageLevel = localStorage.getItem('certificate_log_level')
    const lvl = (localStorageLevel || envLevel || (this.isDebugMode ? 'DEBUG' : 'INFO'))
    return this.normalizeLevel(lvl)
  }

  normalizeLevel(level) {
    const up = String(level || '').toUpperCase()
    return this.levels[up] !== undefined ? up : 'INFO'
  }

  // --------------------------
  // Section overrides persistence
  // --------------------------
  loadSectionLogLevels() {
    try {
      const raw = localStorage.getItem('certificate_section_log_levels')
      const data = raw ? JSON.parse(raw) : {}
      // sanitize
      const cleaned = {}
      for (const [sec, lvl] of Object.entries(data)) {
        cleaned[sec] = this.normalizeLevel(lvl)
      }
      return cleaned
    } catch (e) {
      console.warn('⚠️ Failed to load section log levels:', e)
      return {}
    }
  }

  saveSectionLogLevels() {
    try {
      localStorage.setItem('certificate_section_log_levels', JSON.stringify(this.sectionLogLevels))
    } catch (e) {
      console.warn('⚠️ Failed to save section log levels:', e)
    }
  }

  enableSection(section, level = 'DEBUG') {
    const lvl = this.normalizeLevel(level)
    this.sectionLogLevels[section] = lvl
    this.saveSectionLogLevels()
    console.info(`🐛 [LOGGER] Enabled section "${section}" at level ${lvl}`)
  }

  setSectionLevel(section, level) {
    return this.enableSection(section, level)
  }

  disableSection(section) {
    if (this.sectionLogLevels[section] !== undefined) {
      delete this.sectionLogLevels[section]
      this.saveSectionLogLevels()
      console.info(`🐛 [LOGGER] Disabled section "${section}"`)
    }
  }

  clearSectionLevels() {
    this.sectionLogLevels = {}
    this.saveSectionLogLevels()
    console.info('🐛 [LOGGER] Cleared all section overrides')
  }

  getSectionConfig() {
    return { ...this.sectionLogLevels }
  }

  // --------------------------
  // Decision
  // --------------------------
  shouldLog(level, section = null) {
    const lvl = this.normalizeLevel(level)

    // Section override first
    if (section && this.sectionLogLevels[section]) {
      return this.levels[lvl] <= this.levels[this.sectionLogLevels[section]]
    }

    // Global fallback
    return this.levels[lvl] <= this.levels[this.logLevel]
  }

  // --------------------------
  // Low-level console
  // --------------------------
  sectionLog(section, level, message, ...args) {
    if (!this.shouldLog(level, section)) return
    switch (this.normalizeLevel(level)) {
      case 'ERROR': console.error(message, ...args); break
      case 'WARN':  console.warn(message, ...args);  break
      case 'INFO':  console.info(message, ...args);  break
      case 'DEBUG': console.log(message, ...args);    break
    }
  }

  // --------------------------
  // Core logging (global)
  // --------------------------
  error(message, ...args) {
    if (this.shouldLog('ERROR')) console.error(message, ...args)
  }
  warn(message, ...args) {
    if (this.shouldLog('WARN')) console.warn(message, ...args)
  }
  info(message, ...args) {
    if (this.shouldLog('INFO')) console.info(message, ...args)
  }
  debug(message, ...args) {
    if (this.shouldLog('DEBUG')) console.log(message, ...args)
  }

  // --------------------------
  // Session section methods
  // --------------------------
  sessionInfo(message, ...args) {
    this.sectionLog("session", "INFO", `👤 [SESSION] ${message}`, ...args)
  }
  sessionDebug(message, ...args) {
    this.sectionLog("session", "DEBUG", `👤 [SESSION DEBUG] ${message}`, ...args)
  }
  sessionWarn(message, ...args) {
    this.sectionLog("session", "WARN", `👤 [SESSION WARN] ${message}`, ...args)
  }
  sessionError(message, ...args) {
    this.sectionLog("session", "ERROR", `👤 [SESSION ERROR] ${message}`, ...args)
  }
  sessionTransition(message, ...args) {
    this.sectionLog("session", "INFO", `👤 [SESSION TRANSITION] ${message}`, ...args)
  }
  sessionExpired(message, ...args) {
    this.sectionLog("session", "WARN", `👤 [SESSION EXPIRED] ${message}`, ...args)
  }
  sessionCreated(message, ...args) {
    this.sectionLog("session", "INFO", `👤 [SESSION CREATED] ${message}`, ...args)
  }

  // --------------------------
  // API
  // --------------------------
  apiError(message, ...args)  { this.sectionLog('api', 'ERROR', `📡 [API ERROR] ${message}`, ...args) }
  apiWarn(message, ...args)   { this.sectionLog('api', 'WARN',  `📡 [API WARN] ${message}`, ...args) }
  apiInfo(message, ...args)   { this.sectionLog('api', 'INFO',  `📡 [API] ${message}`, ...args) }
  apiDebug(message, ...args)  { this.sectionLog('api', 'DEBUG', `📡 [API DEBUG] ${message}`, ...args) }

  // --------------------------
  // CONTEXT
  // --------------------------
  contextError(message, ...args) { this.sectionLog('context', 'ERROR', `🎯 [CONTEXT ERROR] ${message}`, ...args) }
  contextWarn(message, ...args)  { this.sectionLog('context', 'WARN',  `🎯 [CONTEXT WARN] ${message}`, ...args) }
  contextInfo(message, ...args)  { this.sectionLog('context', 'INFO',  `🎯 [CONTEXT] ${message}`, ...args) }
  contextDebug(message, ...args) { this.sectionLog('context', 'DEBUG', `🎯 [CONTEXT DEBUG] ${message}`, ...args) }

  contextLifecycle(stage, details = {}) {
    this.contextInfo(`Context lifecycle [${stage}]`, { stage, ...details })
  }
  contextState(action, state, details = {}) {
    const stateKeys = (state && typeof state === 'object') ? Object.keys(state) : []
    this.contextDebug(`Context state [${action}]`, { action, state_keys: Object.keys(state || {}), ...details })
  }
  contextAPI(action, details = {}) {
    this.contextInfo(`Context API [${action}]`, { action, ...details })
  }
  contextRefresh(action, results = {}) {
    this.contextInfo(`Context refresh [${action}]`, {
      action,
      certificates_count: results.certificates?.length || 0,
      success: results.success,
      ...results
    })
  }

  // --------------------------
  // Cookie section methods
  // --------------------------
  cookieInfo(message, ...args) {
    this.sectionLog("cookie", "INFO", `🍪 [COOKIE] ${message}`, ...args)
  }
  cookieDebug(message, ...args) {
    this.sectionLog("cookie", "DEBUG", `🍪 [COOKIE DEBUG] ${message}`, ...args)
  }
  cookieWarn(message, ...args) {
    this.sectionLog("cookie", "WARN", `🍪 [COOKIE WARN] ${message}`, ...args)
  }
  cookieError(message, ...args) {
    this.sectionLog("cookie", "ERROR", `🍪 [COOKIE ERROR] ${message}`, ...args)
  }
  cookieStateChange(message, ...args) {
    this.sectionLog("cookie", "INFO", `🍪 [COOKIE STATE CHANGE] ${message}`, ...args)
  }

  // --------------------------
  // DOWNLOAD
  // --------------------------
  downloadError(message, ...args) { this.sectionLog('download', 'ERROR', `🔽 [DOWNLOAD ERROR] ${message}`, ...args) }
  downloadWarn(message, ...args)  { this.sectionLog('download', 'WARN',  `🔽 [DOWNLOAD WARN] ${message}`, ...args) }
  downloadInfo(message, ...args)  { this.sectionLog('download', 'INFO',  `🔽 [DOWNLOAD] ${message}`, ...args) }
  downloadDebug(message, ...args) { this.sectionLog('download', 'DEBUG', `🔽 [DOWNLOAD DEBUG] ${message}`, ...args) }

  // --------------------------
  // CERTIFICATE
  // --------------------------
  certificateError(message, ...args) { this.sectionLog('certificate', 'ERROR', `📜 [CERTIFICATE ERROR] ${message}`, ...args) }
  certificateWarn(message, ...args)  { this.sectionLog('certificate', 'WARN',  `📜 [CERTIFICATE WARN] ${message}`, ...args) }
  certificateInfo(message, ...args)  { this.sectionLog('certificate', 'INFO',  `📜 [CERTIFICATE] ${message}`, ...args) }
  certificateDebug(message, ...args) { this.sectionLog('certificate', 'DEBUG', `📜 [CERTIFICATE DEBUG] ${message}`, ...args) }

  certificateLifecycle(stage, certificateId, details = {}) {
    this.certificateInfo(`Lifecycle [${stage}] for certificate: ${certificateId}`, details)
  }

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

  certificateValidity(certificateId, validityInfo) {
    const { isExpired, daysUntilExpiry, status } = validityInfo
    if (isExpired) {
      this.certificateWarn(`Certificate ${certificateId} is EXPIRED (${Math.abs(daysUntilExpiry)} days ago)`, {
        id: certificateId, status, daysUntilExpiry, isExpired
      })
    } else if (daysUntilExpiry <= 30) {
      this.certificateWarn(`Certificate ${certificateId} expires SOON (${daysUntilExpiry} days)`, {
        id: certificateId, status, daysUntilExpiry, isExpired
      })
    } else {
      this.certificateInfo(`Certificate ${certificateId} is valid (${daysUntilExpiry} days remaining)`, {
        id: certificateId, status, daysUntilExpiry, isExpired
      })
    }
  }

  certificateExtensions(certificateId, extensions) {
    this.certificateDebug(`Extensions for certificate ${certificateId}:`, {
      id: certificateId,
      subject_alt_name: extensions.subject_alt_name || [],
      key_usage: extensions.key_usage || {},
      extended_key_usage: extensions.extended_key_usage || [],
      basic_constraints: extensions.basic_constraints || {}
    })
  }

  certificateBug(bugType, certificateId, details) {
    this.certificateError(`🚨 CERTIFICATE BUG [${bugType}] in ${certificateId}:`, {
      bug_type: bugType, certificate_id: certificateId, details
    })
  }

  certificateInteraction(action, certificateId, details = {}) {
    this.certificateInfo(`User interaction [${action}] for certificate: ${certificateId}`, {
      id: certificateId, action, ...details
    })
  }

  certificateSecurity(issueType, certificateId, issue) {
    this.certificateWarn(`Security issue [${issueType}] in certificate ${certificateId}:`, {
      issue_type: issueType,
      certificate_id: certificateId,
      issue,
      severity: issue.severity || 'medium',
      recommendation: issue.recommendation || 'Review certificate configuration'
    })
  }

  // --------------------------
  // UPLOAD
  // --------------------------
  uploadError(message, ...args) { this.sectionLog('upload', 'ERROR', `📤 [UPLOAD ERROR] ${message}`, ...args) }
  uploadWarn(message, ...args)  { this.sectionLog('upload', 'WARN',  `📤 [UPLOAD WARN] ${message}`, ...args) }
  uploadInfo(message, ...args)  { this.sectionLog('upload', 'INFO',  `📤 [UPLOAD] ${message}`, ...args) }
  uploadDebug(message, ...args) { this.sectionLog('upload', 'DEBUG', `📤 [UPLOAD DEBUG] ${message}`, ...args) }

  uploadValidation(filename, validationResult, details = {}) {
    if (validationResult.success) {
      this.uploadInfo(`File validation passed for: ${filename}`, {
        filename, size: details.size, extension: details.extension, ...details
      })
    } else {
      this.uploadWarn(`File validation failed for: ${filename}`, {
        filename, errors: validationResult.errors, size: details.size, extension: details.extension, ...details
      })
    }
  }

  uploadLifecycle(stage, files, details = {}) {
    this.uploadInfo(`Upload lifecycle [${stage}] - ${files.length} file(s)`, {
      stage,
      file_count: files.length,
      filenames: files.map(f => f.name || f),
      ...details
    })
  }

  uploadPassword(action, details = {}) {
    this.uploadInfo(`Password handling [${action}]`, {
      action,
      files_requiring_password: details.files_requiring_password || 0,
      has_password: !!details.password,
      password_length: details.password?.length || 0,
      retry_attempt: details.retry_attempt || 1
    })
  }

  uploadInteraction(action, details = {}) {
    this.uploadDebug(`User interaction [${action}]`, {
      action,
      is_analyzing: details.is_analyzing,
      needs_password: details.needs_password,
      files_count: details.files_count || 0
    })
  }

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
        filename, reason: 'encrypted_file'
      })
    } else {
      this.uploadError(`❌ File processing failed: ${filename}`, {
        filename, error: result.error, details: result.details
      })
    }
  }

  uploadBatch(summary) {
    this.uploadInfo('Batch upload completed', {
      total_files: summary.total_files,
      successful: summary.successful,
      failed: summary.failed,
      password_required: summary.password_required,
      processing_time_ms: summary.processing_time_ms
    })
  }

  // --------------------------
  // NOTIFICATION
  // --------------------------
  notificationError(message, ...args) { this.sectionLog('notification', 'ERROR', `🔔 [NOTIFICATION ERROR] ${message}`, ...args) }
  notificationWarn(message, ...args)  { this.sectionLog('notification', 'WARN',  `🔔 [NOTIFICATION WARN] ${message}`, ...args) }
  notificationInfo(message, ...args)  { this.sectionLog('notification', 'INFO',  `🔔 [NOTIFICATION] ${message}`, ...args) }
  notificationDebug(message, ...args) { this.sectionLog('notification', 'DEBUG', `🔔 [NOTIFICATION DEBUG] ${message}`, ...args) }

  notificationLifecycle(stage, details = {}) {
    this.notificationInfo(`Notification lifecycle [${stage}]`, { stage, ...details })
  }
  notificationDisplay(action, details = {}) {
    this.notificationDebug(`Notification display [${action}]`, { action, ...details })
  }
  notificationTiming(action, details = {}) {
    this.notificationDebug(`Notification timing [${action}]`, { action, ...details })
  }

  // --------------------------
  // DOWNLOAD MODAL
  // --------------------------
  downloadModalError(message, ...args) { this.sectionLog('downloadModal', 'ERROR', `💾 [DOWNLOAD MODAL ERROR] ${message}`, ...args) }
  downloadModalWarn(message, ...args)  { this.sectionLog('downloadModal', 'WARN',  `💾 [DOWNLOAD MODAL WARN] ${message}`, ...args) }
  downloadModalInfo(message, ...args)  { this.sectionLog('downloadModal', 'INFO',  `💾 [DOWNLOAD MODAL] ${message}`, ...args) }
  downloadModalDebug(message, ...args) { this.sectionLog('downloadModal', 'DEBUG', `💾 [DOWNLOAD MODAL DEBUG] ${message}`, ...args) }

  downloadModalLifecycle(stage, details = {}) {
    this.downloadModalInfo(`Download modal lifecycle [${stage}]`, { stage, ...details })
  }
  downloadModalSelection(action, details = {}) {
    this.downloadModalDebug(`Component selection [${action}]`, { action, ...details })
  }
  downloadModalFormat(action, details = {}) {
    this.downloadModalDebug(`Format selection [${action}]`, { action, ...details })
  }
  downloadModalOperation(action, details = {}) {
    this.downloadModalInfo(`Download operation [${action}]`, { action, ...details })
  }
  downloadModalRequirement(action, details = {}) {
    this.downloadModalDebug(`Bundle requirement [${action}]`, { action, ...details })
  }
  downloadModalQuickAction(action, details = {}) {
    this.downloadModalInfo(`Quick action [${action}]`, { action, ...details })
  }

  // --------------------------
  // CONNECTION
  // --------------------------
  connectionError(message, ...args) { this.sectionLog('connection', 'ERROR', `📡 [CONNECTION ERROR] ${message}`, ...args) }
  connectionWarn(message, ...args)  { this.sectionLog('connection', 'WARN',  `📡 [CONNECTION WARN] ${message}`, ...args) }
  connectionInfo(message, ...args)  { this.sectionLog('connection', 'INFO',  `📡 [CONNECTION] ${message}`, ...args) }
  connectionDebug(message, ...args) { this.sectionLog('connection', 'DEBUG', `📡 [CONNECTION DEBUG] ${message}`, ...args) }

  connectionLifecycle(stage, details = {}) {
    this.connectionInfo(`Connection lifecycle [${stage}]`, { stage, ...details })
  }
  connectionStatus(action, details = {}) {
    this.connectionInfo(`Connection status [${action}]`, { action, ...details })
  }
  connectionHealthCheck(action, details = {}) {
    this.connectionDebug(`Health check [${action}]`, { action, ...details })
  }

  // --------------------------
  // FILE MANAGER
  // --------------------------
  fileManagerError(message, ...args) { this.sectionLog('fileManager', 'ERROR', `📁 [FILE MANAGER ERROR] ${message}`, ...args) }
  fileManagerWarn(message, ...args)  { this.sectionLog('fileManager', 'WARN',  `📁 [FILE MANAGER WARN] ${message}`, ...args) }
  fileManagerInfo(message, ...args)  { this.sectionLog('fileManager', 'INFO',  `📁 [FILE MANAGER] ${message}`, ...args) }
  fileManagerDebug(message, ...args) { this.sectionLog('fileManager', 'DEBUG', `📁 [FILE MANAGER DEBUG] ${message}`, ...args) }

  fileManagerLifecycle(stage, details = {}) {
    this.fileManagerInfo(`File manager lifecycle [${stage}]`, { stage, ...details })
  }
  fileManagerGrouping(action, details = {}) {
    this.fileManagerDebug(`File grouping [${action}]`, { action, ...details })
  }
  fileManagerDeletion(action, details = {}) {
    this.fileManagerInfo(`File deletion [${action}]`, { action, ...details })
  }
  fileManagerAnalysis(action, details = {}) {
    this.fileManagerDebug(`File analysis [${action}]`, { action, ...details })
  }
  fileManagerFormat(action, details = {}) {
    this.fileManagerDebug(`Format detection [${action}]`, { action, ...details })
  }

  // --------------------------
  // FLOATING PANEL
  // --------------------------
  floatingPanelError(message, ...args) { this.sectionLog('floatingPanel', 'ERROR', `🏗️ [FLOATING PANEL ERROR] ${message}`, ...args) }
  floatingPanelWarn(message, ...args)  { this.sectionLog('floatingPanel', 'WARN',  `🏗️ [FLOATING PANEL WARN] ${message}`, ...args) }
  floatingPanelInfo(message, ...args)  { this.sectionLog('floatingPanel', 'INFO',  `🏗️ [FLOATING PANEL] ${message}`, ...args) }
  floatingPanelDebug(message, ...args) { this.sectionLog('floatingPanel', 'DEBUG', `🏗️ [FLOATING PANEL DEBUG] ${message}`, ...args) }

  floatingPanelLifecycle(stage, details = {}) {
    this.floatingPanelInfo(`Panel lifecycle [${stage}]`, { stage, ...details })
  }
  floatingPanelInteraction(action, details = {}) {
    this.floatingPanelDebug(`User interaction [${action}]`, { action, ...details })
  }
  floatingPanelState(action, state, details = {}) {
    this.floatingPanelDebug(`Panel state [${action}]`, {
      action,
      state_summary: typeof state === 'object' ? Object.keys(state) : state,
      ...details
    })
  }
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
  floatingPanelDownload(action, details = {}) {
    this.floatingPanelInfo(`Download operation [${action}]`, { action, ...details })
  }
  floatingPanelValidation(action, details = {}) {
    this.floatingPanelInfo(`Validation panel [${action}]`, { action, ...details })
  }
  floatingPanelModal(action, modalType, details = {}) {
    this.floatingPanelInfo(`Modal operation [${action}] - ${modalType}`, {
      action, modal_type: modalType, ...details
    })
  }
  floatingPanelFileManagement(action, details = {}) {
    this.floatingPanelInfo(`File management [${action}]`, { action, ...details })
  }
  floatingPanelPerformance(action, timing, details = {}) {
    this.floatingPanelDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
  }
  floatingPanelErrorHandling(errorType, error, details = {}) {
    this.floatingPanelError(`Error handling [${errorType}]`, {
      error_type: errorType,
      error_message: error?.message || error,
      error_stack: error?.stack,
      ...details
    })
  }
  floatingPanelDragResize(action, details = {}) {
    this.floatingPanelDebug(`Drag/Resize [${action}]`, { action, ...details })
  }
  floatingPanelCertificateAnalysis(action, details = {}) {
    this.floatingPanelDebug(`Certificate analysis [${action}]`, { action, ...details })
  }

  // --------------------------
  // SECURE PASSWORD MODAL
  // --------------------------
  securePasswordModalError(message, ...args) { this.sectionLog('securePasswordModal', 'ERROR', `🔐 [SECURE PASSWORD MODAL ERROR] ${message}`, ...args) }
  securePasswordModalWarn(message, ...args)  { this.sectionLog('securePasswordModal', 'WARN',  `🔐 [SECURE PASSWORD MODAL WARN] ${message}`, ...args) }
  securePasswordModalInfo(message, ...args)  { this.sectionLog('securePasswordModal', 'INFO',  `🔐 [SECURE PASSWORD MODAL] ${message}`, ...args) }
  securePasswordModalDebug(message, ...args) { this.sectionLog('securePasswordModal', 'DEBUG', `🔐 [SECURE PASSWORD MODAL DEBUG] ${message}`, ...args) }

  securePasswordModalLifecycle(stage, details = {}) {
    this.securePasswordModalInfo(`Modal lifecycle [${stage}]`, { stage, ...details })
  }
  securePasswordModalSecurity(action, details = {}) {
    this.securePasswordModalInfo(`Security operation [${action}]`, { action, ...details })
  }
  securePasswordModalCopy(action, details = {}) {
    this.securePasswordModalInfo(`Copy operation [${action}]`, { action, ...details })
  }
  securePasswordModalInteraction(action, details = {}) {
    this.securePasswordModalDebug(`User interaction [${action}]`, { action, ...details })
  }
  securePasswordModalState(action, state, details = {}) {
    this.securePasswordModalDebug(`Modal state [${action}]`, {
      action,
      state_summary: typeof state === 'object' ? Object.keys(state) : state,
      ...details
    })
  }
  securePasswordModalTimer(action, details = {}) {
    this.securePasswordModalDebug(`Timer operation [${action}]`, { action, ...details })
  }
  securePasswordModalVisibility(action, details = {}) {
    this.securePasswordModalDebug(`Password visibility [${action}]`, { action, ...details })
  }
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
  securePasswordModalErrorHandling(errorType, error, details = {}) {
    this.securePasswordModalError(`Error handling [${errorType}]`, {
      error_type: errorType,
      error_message: error?.message || error,
      error_stack: error?.stack,
      ...details
    })
  }
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
  securePasswordModalPerformance(action, timing, details = {}) {
    this.securePasswordModalDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
  }

  // --------------------------
  // SYSTEM MESSAGES SECTION
  // --------------------------
  systemMessagesError(message, ...args) { 
    this.sectionLog('systemMessages', 'ERROR', `📢 [SYSTEM MESSAGES ERROR] ${message}`, ...args) 
  }
  systemMessagesWarn(message, ...args) { 
    this.sectionLog('systemMessages', 'WARN', `📢 [SYSTEM MESSAGES WARN] ${message}`, ...args) 
  }
  systemMessagesInfo(message, ...args) { 
    this.sectionLog('systemMessages', 'INFO', `📢 [SYSTEM MESSAGES] ${message}`, ...args) 
  }
  systemMessagesDebug(message, ...args) { 
    this.sectionLog('systemMessages', 'DEBUG', `📢 [SYSTEM MESSAGES DEBUG] ${message}`, ...args) 
  }

  // Specialized methods for system messages
  systemMessagesLifecycle(stage, details = {}) {
    this.systemMessagesInfo(`Lifecycle [${stage}]`, { stage, ...details })
  }
  systemMessagesEvent(eventType, details = {}) {
    this.systemMessagesInfo(`Event [${eventType}]`, { event_type: eventType, ...details })
  }
  systemMessagesMessage(action, messageData, details = {}) {
    this.systemMessagesInfo(`Message [${action}]`, { 
      action, 
      message_id: messageData?.id,
      message_type: messageData?.type,
      message_length: messageData?.message?.length || 0,
      ...details 
    })
  }
  systemMessagesInteraction(action, details = {}) {
    this.systemMessagesDebug(`User interaction [${action}]`, { action, ...details })
  }
  systemMessagesState(action, state, details = {}) {
    this.systemMessagesDebug(`State change [${action}]`, {
      action,
      message_count: Array.isArray(state) ? state.length : 0,
      state_summary: Array.isArray(state) ? `${state.length} messages` : typeof state,
      ...details
    })
  }
  systemMessagesListener(action, details = {}) {
    this.systemMessagesDebug(`Event listener [${action}]`, { action, ...details })
  }
  systemMessagesPerformance(action, timing, details = {}) {
    this.systemMessagesDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
  }
  systemMessagesValidation(action, validationResult, details = {}) {
    this.systemMessagesDebug(`Validation [${action}]`, { 
      action, 
      is_valid: validationResult,
      ...details 
    })
  }

  // --------------------------
  // LAYOUT SECTION
  // --------------------------
  layoutError(message, ...args) { 
    this.sectionLog('layout', 'ERROR', `🏗️ [LAYOUT ERROR] ${message}`, ...args) 
  }
  layoutWarn(message, ...args) { 
    this.sectionLog('layout', 'WARN', `🏗️ [LAYOUT WARN] ${message}`, ...args) 
  }
  layoutInfo(message, ...args) { 
    this.sectionLog('layout', 'INFO', `🏗️ [LAYOUT] ${message}`, ...args) 
  }
  layoutDebug(message, ...args) { 
    this.sectionLog('layout', 'DEBUG', `🏗️ [LAYOUT DEBUG] ${message}`, ...args) 
  }

  // Specialized methods for layout operations
  layoutLifecycle(stage, details = {}) {
    this.layoutInfo(`Lifecycle [${stage}]`, { stage, ...details })
  }
  layoutAuth(action, authState, details = {}) {
    this.layoutInfo(`Authentication [${action}]`, { 
      action, 
      is_authenticated: authState,
      has_user: !!details.user,
      ...details 
    })
  }
  layoutState(action, state, details = {}) {
    this.layoutDebug(`State change [${action}]`, {
      action,
      state_summary: typeof state === 'object' ? Object.keys(state) : state,
      ...details
    })
  }
  layoutCertificates(action, certificates, details = {}) {
    this.layoutInfo(`Certificates [${action}]`, { 
      action, 
      certificate_count: Array.isArray(certificates) ? certificates.length : 0,
      certificate_types: Array.isArray(certificates) ? certificates.reduce((acc, cert) => {
        const type = this.getCertificateType(cert)
        acc[type] = (acc[type] || 0) + 1
        return acc
      }, {}) : {},
      ...details 
    })
  }
  layoutSorting(action, sortDetails, details = {}) {
    this.layoutDebug(`Certificate sorting [${action}]`, { action, ...sortDetails, ...details })
  }
  layoutValidation(action, validationState, details = {}) {
    this.layoutInfo(`Validation panel [${action}]`, { 
      action, 
      validation_panel_visible: validationState,
      ...details 
    })
  }
  layoutSEO(action, seoData, details = {}) {
    this.layoutDebug(`SEO optimization [${action}]`, { 
      action, 
      page_title_length: seoData?.title?.length || 0,
      meta_description_length: seoData?.description?.length || 0,
      ...details 
    })
  }
  layoutPerformance(action, timing, details = {}) {
    this.layoutDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
  }
  layoutRender(action, renderData, details = {}) {
    this.layoutDebug(`Render [${action}]`, { action, ...renderData, ...details })
  }
  layoutInteraction(action, details = {}) {
    this.layoutDebug(`User interaction [${action}]`, { action, ...details })
  }

  // Helper method for certificate type classification
  getCertificateType(certificate) {
    if (!certificate) return 'unknown'
    
    if (certificate.has_private_key && !certificate.has_certificate && !certificate.has_csr) {
      return 'private_key'
    }
    if (certificate.has_csr && !certificate.has_certificate && !certificate.has_private_key) {
      return 'csr'
    }
    if (certificate.has_certificate && certificate.certificate_info?.is_ca === false) {
      return 'end_entity'
    }
    if (certificate.has_certificate && certificate.certificate_info?.is_ca === true && !certificate.certificate_info?.is_self_signed) {
      return 'intermediate_ca'
    }
    if (certificate.has_certificate && certificate.certificate_info?.is_ca === true && certificate.certificate_info?.is_self_signed) {
      return 'root_ca'
    }
    return 'unknown'
  }

  // --------------------------
  // VALIDATION PANEL SECTION
  // --------------------------
  validationPanelError(message, ...args) { 
    this.sectionLog('validationPanel', 'ERROR', `🔬 [VALIDATION PANEL ERROR] ${message}`, ...args) 
  }
  validationPanelWarn(message, ...args) { 
    this.sectionLog('validationPanel', 'WARN', `🔬 [VALIDATION PANEL WARN] ${message}`, ...args) 
  }
  validationPanelInfo(message, ...args) { 
    this.sectionLog('validationPanel', 'INFO', `🔬 [VALIDATION PANEL] ${message}`, ...args) 
  }
  validationPanelDebug(message, ...args) { 
    this.sectionLog('validationPanel', 'DEBUG', `🔬 [VALIDATION PANEL DEBUG] ${message}`, ...args) 
  }

  // Specialized methods for validation panel operations
  validationPanelLifecycle(stage, details = {}) {
    this.validationPanelInfo(`Lifecycle [${stage}]`, { stage, ...details })
  }
  
  validationPanelValidation(action, validationData, details = {}) {
    this.validationPanelInfo(`Validation [${action}]`, { 
      action, 
      validation_count: Array.isArray(validationData) ? validationData.length : 0,
      validation_success_rate: this.calculateValidationSuccessRate(validationData),
      ...details 
    })
  }

  validationPanelFiltering(action, filterData, details = {}) {
    this.validationPanelDebug(`Filtering [${action}]`, { 
      action, 
      input_count: filterData?.input_count || 0,
      output_count: filterData?.output_count || 0,
      filter_criteria: filterData?.criteria,
      ...details 
    })
  }

  validationPanelPKI(action, pkiData, details = {}) {
    this.validationPanelInfo(`PKI Analysis [${action}]`, { 
      action, 
      pki_valid: pkiData?.is_valid,
      relationship_count: pkiData?.relationship_count || 0,
      component_types: pkiData?.component_types,
      ...details 
    })
  }
  validationPanelInteraction(action, details = {}) {
    this.validationPanelDebug(`User interaction [${action}]`, { action, ...details })
  }

  validationPanelState(action, state, details = {}) {
    const stateKeys = (state && typeof state === 'object' && state !== null) ? Object.keys(state) : []
    this.validationPanelDebug(`State change [${action}]`, {
      action,
      state_summary: typeof state === 'object' ? stateKeys : state,
      ...details
    })
  }

  validationPanelRender(action, renderData, details = {}) {
    this.validationPanelDebug(`Render [${action}]`, { action, ...renderData, ...details })
  }

  validationPanelAPI(action, apiData, details = {}) {
    this.validationPanelInfo(`API operation [${action}]`, { 
      action, 
      success: apiData?.success,
      validation_results_present: !!apiData?.validation_results,
      ...details 
    })
  }

  validationPanelCryptography(action, cryptoData, details = {}) {
    this.validationPanelInfo(`Cryptographic analysis [${action}]`, { 
      action, 
      fingerprint_matches: cryptoData?.fingerprint_matches,
      key_matches: cryptoData?.key_matches,
      chain_valid: cryptoData?.chain_valid,
      ...details 
    })
  }

  validationPanelPerformance(action, timing, details = {}) {
    this.validationPanelDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
  }

  validationPanelSecurity(action, securityData, details = {}) {
    this.validationPanelInfo(`Security validation [${action}]`, { 
      action, 
      security_level: securityData?.level,
      validation_confidence: securityData?.confidence,
      ...details 
    })
  }

  // Helper method for validation success rate calculation
  calculateValidationSuccessRate(validationData) {
    if (!Array.isArray(validationData) || validationData.length === 0) return 0
    const successCount = validationData.filter(v => v.isValid || v.status === 'valid').length
    return Math.round((successCount / validationData.length) * 100)
  }

  // --------------------------
  // CERTIFICATE CONTEXT SECTION
  // --------------------------
  certificateContextError(message, ...args) { 
    this.sectionLog('certificateContext', 'ERROR', `📋 [CERTIFICATE CONTEXT ERROR] ${message}`, ...args) 
  }
  certificateContextWarn(message, ...args) { 
    this.sectionLog('certificateContext', 'WARN', `📋 [CERTIFICATE CONTEXT WARN] ${message}`, ...args) 
  }
  certificateContextInfo(message, ...args) { 
    this.sectionLog('certificateContext', 'INFO', `📋 [CERTIFICATE CONTEXT] ${message}`, ...args) 
  }
  certificateContextDebug(message, ...args) { 
    this.sectionLog('certificateContext', 'DEBUG', `📋 [CERTIFICATE CONTEXT DEBUG] ${message}`, ...args) 
  }

  // Specialized methods for certificate context operations
  certificateContextLifecycle(stage, details = {}) {
    this.certificateContextInfo(`Lifecycle [${stage}]`, { stage, ...details })
  }
  certificateContextState(action, state, details = {}) {
    this.certificateContextDebug(`State change [${action}]`, {
      action,
      state_summary: typeof state === 'object' ? Object.keys(state) : state,
      ...details
    })
  }
  certificateContextOperation(action, operationData, details = {}) {
    this.certificateContextInfo(`Operation [${action}]`, { 
      action, 
      operation_duration: operationData?.duration,
      operation_success: operationData?.success,
      component_count: operationData?.component_count,
      ...details 
    })
  }
  certificateContextComponent(action, componentData, details = {}) {
    this.certificateContextInfo(`Component [${action}]`, { 
      action, 
      component_id: componentData?.id,
      component_filename: componentData?.filename,
      component_type: componentData?.type,
      component_order: componentData?.order,
      ...details 
    })
  }
  certificateContextPassword(action, passwordData, details = {}) {
    this.certificateContextDebug(`Password handling [${action}]`, { 
      action, 
      needs_password: passwordData?.needsPassword,
      password_provided: passwordData?.password_provided,
      required_files_count: passwordData?.passwordRequiredFiles?.length || 0,
      is_analyzing: passwordData?.isAnalyzing,
      ...details 
    })
  }
  certificateContextSession(action, sessionData, details = {}) {
    this.certificateContextInfo(`Session monitoring [${action}]`, { 
      action, 
      is_monitoring: sessionData?.isMonitoring,
      session_changes: sessionData?.sessionChangeCount,
      last_check: sessionData?.lastSessionCheck,
      last_operation: sessionData?.lastOperationTime,
      ...details 
    })
  }
  certificateContextAPI(action, apiData, details = {}) {
    this.certificateContextInfo(`API operation [${action}]`, { 
      action, 
      api_success: apiData?.success,
      response_size: apiData?.certificates?.length || 0,
      has_validation_results: !!apiData?.validation_results,
      ...details 
    })
  }
  certificateContextSorting(action, sortData, details = {}) {
    this.certificateContextDebug(`Component sorting [${action}]`, { 
      action, 
      input_count: sortData?.input_count || 0,
      output_count: sortData?.output_count || 0,
      sort_criteria: sortData?.criteria,
      ...details 
    })
  }
  certificateContextStats(action, statsData, details = {}) {
    this.certificateContextDebug(`PKI statistics [${action}]`, { 
      action, 
      total_components: statsData?.total || 0,
      component_types: statsData?.byType,
      has_private_key: statsData?.hasPrivateKey,
      has_certificate: statsData?.hasCertificate,
      has_csr: statsData?.hasCSR,
      has_ca: statsData?.hasCA,
      ...details 
    })
  }
  certificateContextPerformance(action, timing, details = {}) {
    this.certificateContextDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
  }
  certificateContextSecurity(action, securityData, details = {}) {
    this.certificateContextInfo(`Security operation [${action}]`, { 
      action, 
      password_handling: securityData?.password_handling,
      session_tracking: securityData?.session_tracking,
      component_isolation: securityData?.component_isolation,
      ...details 
    })
  }

  // --------------------------
  // Global controls
  // --------------------------
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
    const lvl = this.normalizeLevel(level)
    localStorage.setItem('certificate_log_level', lvl)
    this.logLevel = lvl
    this.info(`📊 Log level set to: ${lvl}`)
  }

  getConfig() {
    return {
      isDebugMode: this.isDebugMode,
      logLevel: this.logLevel,
      availableLevels: Object.keys(this.levels),
      sections: [...this.sections],
      sectionLogLevels: this.getSectionConfig()
    }
  }

  // --------------------------
  // Grouping & timing (global DEBUG)
  // --------------------------
  group(title) { if (this.shouldLog('DEBUG')) console.group(title) }
  groupEnd() { if (this.shouldLog('DEBUG')) console.groupEnd() }
  time(label) { if (this.shouldLog('DEBUG')) console.time(label) }
  timeEnd(label) { if (this.shouldLog('DEBUG')) console.timeEnd(label) }
}

// Create singleton instance
const logger = new FrontendLogger()

// Export convenience methods with proper binding (backward-compatible)
export const error = (...args) => logger.error(...args)
export const warn = (...args) => logger.warn(...args)
export const info = (...args) => logger.info(...args)
export const debug = (...args) => logger.debug(...args)

export const sessionInfo = (...args) => logger.sessionInfo(...args)
export const sessionDebug = (...args) => logger.sessionDebug(...args)
export const sessionWarn = (...args) => logger.sessionWarn(...args)
export const sessionError = (...args) => logger.sessionError(...args)
export const sessionTransition = (...args) => logger.sessionTransition(...args)
export const sessionExpired = (...args) => logger.sessionExpired(...args)
export const sessionCreated = (...args) => logger.sessionCreated(...args)

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
export const cookieStateChange = (...args) => logger.cookieStateChange(...args)

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

export const systemMessagesError = (...args) => logger.systemMessagesError(...args)
export const systemMessagesWarn = (...args) => logger.systemMessagesWarn(...args)
export const systemMessagesInfo = (...args) => logger.systemMessagesInfo(...args)
export const systemMessagesDebug = (...args) => logger.systemMessagesDebug(...args)
export const systemMessagesLifecycle = (...args) => logger.systemMessagesLifecycle(...args)
export const systemMessagesEvent = (...args) => logger.systemMessagesEvent(...args)
export const systemMessagesMessage = (...args) => logger.systemMessagesMessage(...args)
export const systemMessagesInteraction = (...args) => logger.systemMessagesInteraction(...args)
export const systemMessagesState = (...args) => logger.systemMessagesState(...args)
export const systemMessagesListener = (...args) => logger.systemMessagesListener(...args)
export const systemMessagesPerformance = (...args) => logger.systemMessagesPerformance(...args)
export const systemMessagesValidation = (...args) => logger.systemMessagesValidation(...args)

export const layoutError = (...args) => logger.layoutError(...args)
export const layoutWarn = (...args) => logger.layoutWarn(...args)
export const layoutInfo = (...args) => logger.layoutInfo(...args)
export const layoutDebug = (...args) => logger.layoutDebug(...args)
export const layoutLifecycle = (...args) => logger.layoutLifecycle(...args)
export const layoutAuth = (...args) => logger.layoutAuth(...args)
export const layoutState = (...args) => logger.layoutState(...args)
export const layoutCertificates = (...args) => logger.layoutCertificates(...args)
export const layoutSorting = (...args) => logger.layoutSorting(...args)
export const layoutValidation = (...args) => logger.layoutValidation(...args)
export const layoutSEO = (...args) => logger.layoutSEO(...args)
export const layoutPerformance = (...args) => logger.layoutPerformance(...args)
export const layoutRender = (...args) => logger.layoutRender(...args)
export const layoutInteraction = (...args) => logger.layoutInteraction(...args)

export const validationPanelError = (...args) => logger.validationPanelError(...args)
export const validationPanelWarn = (...args) => logger.validationPanelWarn(...args)
export const validationPanelInfo = (...args) => logger.validationPanelInfo(...args)
export const validationPanelDebug = (...args) => logger.validationPanelDebug(...args)
export const validationPanelLifecycle = (...args) => logger.validationPanelLifecycle(...args)
export const validationPanelValidation = (...args) => logger.validationPanelValidation(...args)
export const validationPanelFiltering = (...args) => logger.validationPanelFiltering(...args)
export const validationPanelPKI = (...args) => logger.validationPanelPKI(...args)
export const validationPanelInteraction = (...args) => logger.validationPanelInteraction(...args)
export const validationPanelState = (...args) => logger.validationPanelState(...args)
export const validationPanelRender = (...args) => logger.validationPanelRender(...args)
export const validationPanelAPI = (...args) => logger.validationPanelAPI(...args)
export const validationPanelCryptography = (...args) => logger.validationPanelCryptography(...args)
export const validationPanelPerformance = (...args) => logger.validationPanelPerformance(...args)
export const validationPanelSecurity = (...args) => logger.validationPanelSecurity(...args)

export const certificateContextError = (...args) => logger.certificateContextError(...args)
export const certificateContextWarn = (...args) => logger.certificateContextWarn(...args)
export const certificateContextInfo = (...args) => logger.certificateContextInfo(...args)
export const certificateContextDebug = (...args) => logger.certificateContextDebug(...args)
export const certificateContextLifecycle = (...args) => logger.certificateContextLifecycle(...args)
export const certificateContextState = (...args) => logger.certificateContextState(...args)
export const certificateContextOperation = (...args) => logger.certificateContextOperation(...args)
export const certificateContextComponent = (...args) => logger.certificateContextComponent(...args)
export const certificateContextPassword = (...args) => logger.certificateContextPassword(...args)
export const certificateContextSession = (...args) => logger.certificateContextSession(...args)
export const certificateContextAPI = (...args) => logger.certificateContextAPI(...args)
export const certificateContextSorting = (...args) => logger.certificateContextSorting(...args)
export const certificateContextStats = (...args) => logger.certificateContextStats(...args)
export const certificateContextPerformance = (...args) => logger.certificateContextPerformance(...args)
export const certificateContextSecurity = (...args) => logger.certificateContextSecurity(...args)

// Global control exports
export const enableDebug = (...args) => logger.enableDebug(...args)
export const disableDebug = (...args) => logger.disableDebug(...args)
export const setLogLevel = (...args) => logger.setLogLevel(...args)
export const getConfig = (...args) => logger.getConfig(...args)
export const group = (...args) => logger.group(...args)
export const groupEnd = (...args) => logger.groupEnd(...args)
export const time = (...args) => logger.time(...args)
export const timeEnd = (...args) => logger.timeEnd(...args)

// Section control exports
export const enableSection = (...args) => logger.enableSection(...args)
export const disableSection = (...args) => logger.disableSection(...args)
export const setSectionLevel = (...args) => logger.setSectionLevel(...args)
export const getSectionConfig = (...args) => logger.getSectionConfig(...args)
export const clearSectionLevels = (...args) => logger.clearSectionLevels(...args)

// Make logger available globally for debugging
if (typeof window !== 'undefined') {
  window.logger = {
    ...logger,
    // Back-compat aliases
    enable: () => logger.enableDebug(),
    disable: () => logger.disableDebug(),
    level: (level) => logger.setLogLevel(level),

    // Section helpers
    enableSection: (section, level = 'DEBUG') => logger.enableSection(section, level),
    disableSection: (section) => logger.disableSection(section),
    sectionLevel: (section, level) => logger.setSectionLevel(section, level),
    sections: () => logger.getSectionConfig(),
    clearSections: () => logger.clearSectionLevels(),
    config: () => logger.getConfig(),

    // NEW: Display all available sections with current status
    availableSections: () => {
      const config = logger.getConfig()
      console.group('📋 Available Logger Sections')
      
      config.sections.forEach(section => {
        const currentLevel = config.sectionLogLevels[section] || `Global (${config.logLevel})`
        const emoji = config.sectionLogLevels[section] ? '🔧' : '🌐'
        console.log(`${emoji} ${section.padEnd(20)} → ${currentLevel}`)
      })
      
      console.groupEnd()
      console.log(`\n💡 Usage examples:`)
      console.log(`   logger.enableSection("fileManager")`)
      console.log(`   logger.enableSection("api", "WARN")`) 
      console.log(`   logger.disableSection("notification")`)
      
      return config.sections
    },

    // NEW: Enhanced help command
    help: () => {
      console.group('🚀 Logger Help')
      console.log('📊 Global Controls:')
      console.log('   logger.enable()           - Enable debug mode')
      console.log('   logger.disable()          - Disable debug mode') 
      console.log('   logger.level("INFO")      - Set global log level')
      console.log('')
      console.log('🎛️ Section Controls:')
      console.log('   logger.enableSection(section, level)  - Enable section logging')
      console.log('   logger.disableSection(section)        - Disable section override')
      console.log('   logger.sectionLevel(section, level)   - Set section level')
      console.log('')
      console.log('🔍 Information:')
      console.log('   logger.availableSections() - Show all available sections')
      console.log('   logger.sections()          - Show current section overrides')
      console.log('   logger.config()            - Show complete configuration')
      console.log('')
      console.log('📈 Levels: ERROR → WARN → INFO → DEBUG (increasing verbosity)')
      console.groupEnd()
      
      return 'Use logger.availableSections() to see all available sections'
    }
  }

  if (logger.isDebugMode) {
    console.info('🐛 [LOGGER] Available as window.logger')
    console.info('🐛 [LOGGER] Type logger.help() for usage guide')
    console.info('🐛 [LOGGER] Type logger.availableSections() to see all sections')
  }
}

export default logger