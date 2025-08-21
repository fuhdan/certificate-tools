# Frontend Logger

A comprehensive logging system for frontend applications with configurable global and per-section log levels.

## 🚀 Features

- **Multi-level logging**: ERROR, WARN, INFO, DEBUG
- **Section-based logging**: Independent log levels for different application areas
- **Persistent configuration**: Settings saved to localStorage
- **Runtime control**: Browser console interface for debugging
- **Performance optimized**: Logs are filtered before execution
- **Extensive section coverage**: Pre-defined sections for common application areas

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Technical Implementation](#technical-implementation)
- [Usage Examples](#usage-examples)
- [Section Management](#section-management)
- [Console Interface](#console-interface)
- [Adding New Sections](#adding-new-sections)
- [Configuration Options](#configuration-options)
- [Best Practices](#best-practices)

## 🚀 Quick Start

### Basic Import and Usage

```javascript
// Import specific loggers
import { info, debug, sessionInfo, apiError } from '@/utils/logger'

// Basic logging
info('Application started')
debug('Debug information', { data: 'example' })

// Section-specific logging
sessionInfo('User logged in', { userId: 123 })
apiError('API request failed', { endpoint: '/users', error })
```

### Enable Debug Mode

```javascript
// Via environment variable
VITE_DEBUG=true

// Via localStorage
localStorage.setItem('certificate_debug', 'true')

// Via URL parameter
https://yourapp.com?debug=true

// Via console
window.logger.enable()
```

## 🔧 Technical Implementation

### Core Architecture

```javascript
class FrontendLogger {
  constructor() {
    // Log levels (higher number = more verbose)
    this.levels = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3 }
    
    // Global configuration
    this.isDebugMode = this.getDebugMode()
    this.logLevel = this.getLogLevel()
    
    // Section-specific overrides
    this.sectionLogLevels = this.loadSectionLogLevels()
  }
}
```

### Decision Logic

The logger uses a hierarchical decision system:

1. **Section Override**: If a section has a specific log level, use it
2. **Global Fallback**: Otherwise, use the global log level
3. **Performance**: Logs are filtered before console output

```javascript
shouldLog(level, section = null) {
  const lvl = this.normalizeLevel(level)
  
  // Section override first
  if (section && this.sectionLogLevels[section]) {
    return this.levels[lvl] <= this.levels[this.sectionLogLevels[section]]
  }
  
  // Global fallback
  return this.levels[lvl] <= this.levels[this.logLevel]
}
```

### Persistence

Configuration is automatically persisted to localStorage:

- `certificate_debug`: Global debug mode (true/false)
- `certificate_log_level`: Global log level (ERROR|WARN|INFO|DEBUG)
- `certificate_section_log_levels`: Section-specific overrides (JSON object)

## 📖 Usage Examples

### Basic Logging

```javascript
import { error, warn, info, debug } from '@/utils/logger'

// Global logging
error('Critical error occurred')
warn('This is a warning')
info('Information message')
debug('Debug details', { context: 'data' })
```

### Section-Specific Logging

```javascript
import { 
  sessionInfo, sessionError,
  apiDebug, apiError,
  uploadInfo, uploadWarn
} from '@/utils/logger'

// Session management
sessionInfo('User authentication started')
sessionError('Login failed', { username, error })

// API operations
apiDebug('Making request', { method: 'POST', url: '/api/users' })
apiError('Request failed', { status: 500, response })

// File uploads
uploadInfo('File upload started', { filename: 'document.pdf' })
uploadWarn('Large file detected', { size: '50MB' })
```

### Specialized Section Methods

Each section provides specialized logging methods:

```javascript
// Session lifecycle
import { sessionTransition, sessionExpired, sessionCreated } from '@/utils/logger'

sessionCreated('New session initialized', { sessionId })
sessionTransition('State changed', { from: 'idle', to: 'active' })
sessionExpired('Session timeout', { duration: '30min' })

// Certificate operations
import { 
  certificateLifecycle, 
  certificateValidity, 
  certificateSecurity 
} from '@/utils/logger'

certificateLifecycle('Certificate loaded', { filename: 'cert.pem' })
certificateValidity('Validation completed', { isValid: true })
certificateSecurity('Security check', { algorithm: 'RSA-2048' })
```

## 🎛️ Section Management

### Available Sections

```javascript
const sections = [
  'session',              // User session management
  'api',                  // API communications
  'context',              // Application context
  'cookie',               // Cookie operations
  'download',             // File downloads
  'certificate',          // Certificate operations
  'upload',               // File uploads
  'notification',         // User notifications
  'downloadModal',        // Download modal interactions
  'connection',           // Network connections
  'fileManager',          // File management operations
  'floatingPanel',        // UI floating panels
  'securePasswordModal'   // Password modal operations
]
```

### Section Control

```javascript
import { 
  enableSection, 
  disableSection, 
  setSectionLevel,
  getSectionConfig,
  clearSectionLevels 
} from '@/utils/logger'

// Enable section with default DEBUG level
enableSection('fileManager')

// Enable section with specific level
enableSection('notification', 'WARN')

// Change existing section level
setSectionLevel('api', 'INFO')

// Disable section (falls back to global level)
disableSection('floatingPanel')

// Get current section configuration
const config = getSectionConfig()
console.log(config) // { fileManager: 'DEBUG', notification: 'WARN' }

// Clear all section overrides
clearSectionLevels()
```

## 🖥️ Console Interface

The logger is available globally as `window.logger` for runtime debugging:

### Quick Commands

```javascript
// Enable/disable debug mode
logger.enable()          // Enable global debug mode
logger.disable()         // Disable global debug mode

// Set global log level
logger.level('INFO')     // Set global level
logger.level('DEBUG')    // Set to debug level

// Section management
logger.enableSection('fileManager')                    // Enable section
logger.enableSection('notification', 'WARN')          // Enable with level
logger.disableSection('floatingPanel')                // Disable section
logger.sectionLevel('api', 'INFO')                    // Set section level

// Configuration inspection
logger.config()          // View complete configuration
logger.sections()        // View section overrides
logger.clearSections()   // Clear all section overrides
```

### View Available Sections

```javascript
// Display all available sections
logger.config().sections

// Or use this helper command
logger.availableSections = () => {
  const config = logger.config()
  console.group('📋 Available Logger Sections')
  config.sections.forEach(section => {
    const current = config.sectionLogLevels[section] || 'Global'
    console.log(`${section.padEnd(20)} → ${current}`)
  })
  console.groupEnd()
  return config.sections
}

// Usage
logger.availableSections()
```

### Debug Session Example

```javascript
// Start debugging session
logger.enable()

// Focus on specific areas
logger.enableSection('fileManager', 'DEBUG')
logger.enableSection('upload', 'INFO')
logger.disableSection('notification')

// Check configuration
logger.config()

// When done, cleanup
logger.clearSections()
logger.disable()
```

## ➕ Adding New Sections

### Step 1: Add Section to Configuration

```javascript
// In FrontendLogger constructor
this.sections = [
  'session',
  'api',
  // ... existing sections
  'newFeature',        // ← Add your new section
  'anotherSection'     // ← Add another section
]
```

### Step 2: Implement Section Methods

```javascript
// In FrontendLogger class
// --------------------------
// NEW FEATURE SECTION
// --------------------------
newFeatureError(message, ...args) { 
  this.sectionLog('newFeature', 'ERROR', `🎯 [NEW FEATURE ERROR] ${message}`, ...args) 
}
newFeatureWarn(message, ...args) { 
  this.sectionLog('newFeature', 'WARN', `🎯 [NEW FEATURE WARN] ${message}`, ...args) 
}
newFeatureInfo(message, ...args) { 
  this.sectionLog('newFeature', 'INFO', `🎯 [NEW FEATURE] ${message}`, ...args) 
}
newFeatureDebug(message, ...args) { 
  this.sectionLog('newFeature', 'DEBUG', `🎯 [NEW FEATURE DEBUG] ${message}`, ...args) 
}

// Specialized methods for the section
newFeatureLifecycle(stage, details = {}) {
  this.newFeatureInfo(`Lifecycle [${stage}]`, { stage, ...details })
}
newFeaturePerformance(action, timing, details = {}) {
  this.newFeatureDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
}
```

### Step 3: Export Methods

```javascript
// At the end of the file
export const newFeatureError = (...args) => logger.newFeatureError(...args)
export const newFeatureWarn = (...args) => logger.newFeatureWarn(...args)
export const newFeatureInfo = (...args) => logger.newFeatureInfo(...args)
export const newFeatureDebug = (...args) => logger.newFeatureDebug(...args)
export const newFeatureLifecycle = (...args) => logger.newFeatureLifecycle(...args)
export const newFeaturePerformance = (...args) => logger.newFeaturePerformance(...args)
```

### Step 4: Usage in Components

```javascript
import { 
  newFeatureInfo, 
  newFeatureError, 
  newFeatureLifecycle 
} from '@/utils/logger'

// In your component
newFeatureLifecycle('component_mounted', { componentName: 'MyComponent' })
newFeatureInfo('Feature activated', { userId: 123 })
newFeatureError('Operation failed', { error, context })
```

### Template for New Sections

```javascript
// TEMPLATE: Replace 'SECTION_NAME' with your section name
// --------------------------
// SECTION_NAME SECTION  
// --------------------------
sectionNameError(message, ...args) { 
  this.sectionLog('sectionName', 'ERROR', `🔥 [SECTION_NAME ERROR] ${message}`, ...args) 
}
sectionNameWarn(message, ...args) { 
  this.sectionLog('sectionName', 'WARN', `⚠️ [SECTION_NAME WARN] ${message}`, ...args) 
}
sectionNameInfo(message, ...args) { 
  this.sectionLog('sectionName', 'INFO', `ℹ️ [SECTION_NAME] ${message}`, ...args) 
}
sectionNameDebug(message, ...args) { 
  this.sectionLog('sectionName', 'DEBUG', `🐛 [SECTION_NAME DEBUG] ${message}`, ...args) 
}

// Specialized methods (customize as needed)
sectionNameLifecycle(stage, details = {}) {
  this.sectionNameInfo(`Lifecycle [${stage}]`, { stage, ...details })
}
sectionNameOperation(action, details = {}) {
  this.sectionNameDebug(`Operation [${action}]`, { action, ...details })
}
sectionNamePerformance(action, timing, details = {}) {
  this.sectionNameDebug(`Performance [${action}]`, { action, duration_ms: timing, ...details })
}

// Export template
export const sectionNameError = (...args) => logger.sectionNameError(...args)
export const sectionNameWarn = (...args) => logger.sectionNameWarn(...args)
export const sectionNameInfo = (...args) => logger.sectionNameInfo(...args)
export const sectionNameDebug = (...args) => logger.sectionNameDebug(...args)
export const sectionNameLifecycle = (...args) => logger.sectionNameLifecycle(...args)
export const sectionNameOperation = (...args) => logger.sectionNameOperation(...args)
export const sectionNamePerformance = (...args) => logger.sectionNamePerformance(...args)
```

## ⚙️ Configuration Options

### Environment Variables

```bash
# Enable debug mode
VITE_DEBUG=true

# Set global log level
VITE_LOG_LEVEL=DEBUG
```

### LocalStorage Configuration

```javascript
// Debug mode
localStorage.setItem('certificate_debug', 'true')

// Global log level
localStorage.setItem('certificate_log_level', 'INFO')

// Section overrides (JSON string)
localStorage.setItem('certificate_section_log_levels', JSON.stringify({
  fileManager: 'DEBUG',
  notification: 'WARN',
  api: 'INFO'
}))
```

### URL Parameters

```
https://yourapp.com?debug=true
```

### Programmatic Configuration

```javascript
import { setLogLevel, enableDebug, disableDebug } from '@/utils/logger'

// Set global level
setLogLevel('DEBUG')

// Enable/disable debug mode
enableDebug()
disableDebug()

// Get current configuration
import { getConfig } from '@/utils/logger'
const config = getConfig()
console.log(config)
```

## 🎯 Best Practices

### 1. Choose Appropriate Log Levels

```javascript
// ERROR: Critical issues that break functionality
sessionError('Authentication failed', { error, userId })

// WARN: Issues that might cause problems
uploadWarn('File size exceeds recommended limit', { size: '100MB' })

// INFO: Important state changes and user actions
certificateInfo('Certificate loaded successfully', { filename })

// DEBUG: Detailed information for debugging
apiDebug('Request details', { method, url, headers, body })
```

### 2. Include Contextual Information

```javascript
// Good: Include relevant context
fileManagerError('Delete operation failed', {
  filename: 'document.pdf',
  error: error.message,
  userId: currentUser.id,
  timestamp: new Date().toISOString()
})

// Avoid: Generic messages without context
fileManagerError('Something went wrong')
```

### 3. Use Section-Specific Methods

```javascript
// Good: Use specific section methods
uploadLifecycle('upload_started', { filename, size })
uploadValidation('file_type_check', { type: 'pdf', valid: true })

// Avoid: Generic logging for specific features
debug('Upload started')
info('File type is valid')
```

### 4. Performance Considerations

```javascript
// Good: Logger handles filtering efficiently
apiDebug('Expensive operation', () => {
  // This closure only executes if DEBUG level is active
  return {
    complexData: performExpensiveCalculation(),
    timestamp: Date.now()
  }
})

// The logger already handles this optimization internally
```

### 5. Development vs Production

```javascript
// Development: Enable specific debugging
if (import.meta.env.DEV) {
  logger.enableSection('fileManager', 'DEBUG')
  logger.enableSection('api', 'INFO')
}

// Production: Use conservative levels
if (import.meta.env.PROD) {
  logger.setLogLevel('WARN')
}
```

## 🔍 Debugging Workflows

### Issue Investigation

```javascript
// 1. Enable broad debugging
logger.enable()

// 2. Focus on problematic area
logger.enableSection('fileManager', 'DEBUG')
logger.enableSection('upload', 'DEBUG')

// 3. Reproduce issue and observe logs

// 4. Narrow down to specific component
logger.disableSection('fileManager')
// Keep only upload logging active

// 5. Clean up when done
logger.clearSections()
logger.disable()
```

### Performance Analysis

```javascript
// Enable performance logging for specific sections
logger.enableSection('api', 'DEBUG')
logger.enableSection('certificate', 'DEBUG')

// Look for performance-related log entries
// Performance logs include timing information
```

---

## 📝 License

This logger implementation is part of the Certificate Management System.

---

**Happy Logging! 🚀**

For questions or issues, please refer to the project documentation or create an issue in the project repository.