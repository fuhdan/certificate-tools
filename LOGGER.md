# Frontend Logger

A comprehensive logging system for frontend applications with configurable global and per-section log levels.

## 🚀 Features

- **Multi-level logging**: ERROR, WARN, INFO, DEBUG
- **Section-based logging**: Independent log levels for different application areas
- **Persistent configuration**: Settings saved to localStorage
- **Runtime control**: Browser console interface for debugging
- **Performance optimized**: Logs are filtered before execution
- **Extensive section coverage**: 17 pre-defined sections for common application areas
- **Docker/Production ready**: Environment variable support for containerized deployments

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Technical Implementation](#technical-implementation)
- [Usage Examples](#usage-examples)
- [Section Management](#section-management)
- [Console Interface](#console-interface)
- [Available Sections](#available-sections)
- [Adding New Sections](#adding-new-sections)
- [Configuration Options](#configuration-options)
- [Docker & Production](#docker--production)
- [Best Practices](#best-practices)
- [Debugging Workflows](#debugging-workflows)

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
// Via environment variable (Docker/Production)
VITE_DEBUG=true

// Via localStorage (Runtime)
localStorage.setItem('certificate_debug', 'true')

// Via URL parameter (Testing)
https://yourapp.com?debug=true

// Via console (Development)
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

1. **Console Override**: localStorage settings (highest priority)
2. **Debug Mode Default**: When VITE_DEBUG=true, defaults to DEBUG level
3. **Environment Variables**: VITE_LOG_LEVEL when debug mode is off
4. **Section Overrides**: Per-section level configuration
5. **Global Fallback**: Default INFO level

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

### Priority Order for Log Levels

```javascript
getLogLevel() {
  // 1. Console override always takes priority
  const localStorageLevel = localStorage.getItem('certificate_log_level')
  if (localStorageLevel) {
    return this.normalizeLevel(localStorageLevel)
  }
  
  // 2. Debug mode defaults to DEBUG level
  if (this.isDebugMode) {
    return 'DEBUG'
  }
  
  // 3. Environment variable when debug is off
  const envLevel = import.meta.env?.VITE_LOG_LEVEL
  if (envLevel && envLevel !== 'undefined') {
    return this.normalizeLevel(envLevel)
  }
  
  // 4. Final fallback
  return 'INFO'
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

### Performance Monitoring

```javascript
import { time, timeEnd } from '@/utils/logger'

// Built-in timing support
time('certificate-analysis')
// ... operations ...
timeEnd('certificate-analysis')

// Section-specific performance logging
import { certificateContextPerformance } from '@/utils/logger'
certificateContextPerformance('REFRESH_FILES_COMPLETED', 150, {
  operation_type: 'refresh_files'
})
```

## 🎛️ Section Management

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

// New helper commands
logger.help()            // Complete usage guide
logger.availableSections() // Show all sections with current status
```

### Enhanced Help System

```javascript
// Display complete usage guide
logger.help()

// Example output:
// 🚀 Logger Help
// 📊 Global Controls:
//    logger.enable()           - Enable debug mode
//    logger.disable()          - Disable debug mode
//    logger.level("INFO")      - Set global log level
//
// 🎛️ Section Controls:
//    logger.enableSection(section, level)  - Enable section logging
//    logger.disableSection(section)        - Disable section override
//    logger.sectionLevel(section, level)   - Set section level
//
// 🔍 Information:
//    logger.availableSections() - Show all available sections
//    logger.sections()          - Show current section overrides
//    logger.config()            - Show complete configuration
```

### View Available Sections

```javascript
// Display all available sections with current status
logger.availableSections()

// Example output:
// 📋 Available Logger Sections
// 🔧 fileManager        → DEBUG
// 🌐 notification       → Global (WARN)
// 🔧 api                → INFO
// 🌐 session            → Global (INFO)
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

## 📋 Available Sections

The current implementation includes **17 sections**:

| Section | Emoji | Description | Key Methods |
|---------|-------|-------------|-------------|
| `session` | 👤 | User session management | `sessionTransition`, `sessionExpired`, `sessionCreated` |
| `api` | 📡 | API communications | `apiInfo`, `apiError`, `apiDebug` |
| `context` | 🎯 | Application context | `contextLifecycle`, `contextState`, `contextAPI` |
| `cookie` | 🍪 | Cookie operations | `cookieStateChange`, `cookieInfo`, `cookieDebug` |
| `download` | 🔽 | File downloads | `downloadInfo`, `downloadError`, `downloadDebug` |
| `certificate` | 📜 | Certificate operations | `certificateLifecycle`, `certificateValidity`, `certificateSecurity` |
| `upload` | 📤 | File uploads | `uploadLifecycle`, `uploadValidation`, `uploadResult` |
| `notification` | 🔔 | User notifications | `notificationLifecycle`, `notificationDisplay`, `notificationTiming` |
| `downloadModal` | 💾 | Download modal interactions | `downloadModalLifecycle`, `downloadModalSelection`, `downloadModalOperation` |
| `connection` | 📡 | Network connections | `connectionLifecycle`, `connectionStatus`, `connectionHealthCheck` |
| `fileManager` | 📁 | File management operations | `fileManagerLifecycle`, `fileManagerGrouping`, `fileManagerDeletion` |
| `floatingPanel` | 🏗️ | UI floating panels | `floatingPanelLifecycle`, `floatingPanelInteraction`, `floatingPanelState` |
| `securePasswordModal` | 🔐 | Password modal operations | `securePasswordModalLifecycle`, `securePasswordModalSecurity`, `securePasswordModalClipboard` |
| `systemMessages` | 📢 | System message handling | `systemMessagesLifecycle`, `systemMessagesEvent`, `systemMessagesMessage` |
| `layout` | 🏗️ | Main layout operations | `layoutLifecycle`, `layoutAuth`, `layoutCertificates` |
| `validationPanel` | 🔬 | Certificate validation panel | `validationPanelValidation`, `validationPanelPKI`, `validationPanelCryptography` |
| `certificateContext` | 📋 | Certificate context provider | `certificateContextLifecycle`, `certificateContextOperation`, `certificateContextSession` |

### Section-Specific Usage Examples

#### Certificate Context
```javascript
import { 
  certificateContextLifecycle,
  certificateContextOperation,
  certificateContextSession,
  certificateContextStats 
} from '@/utils/logger'

certificateContextLifecycle('PROVIDER_MOUNT', { 
  has_children: true,
  initial_component_count: 0 
})

certificateContextOperation('REFRESH_FILES_START', {
  operation_type: 'refresh',
  loading_state_will_change: true
})

certificateContextStats('PKI_STATS_CALCULATED', {
  total: 5,
  byType: { Certificate: 1, PrivateKey: 1, IssuingCA: 1 },
  hasPrivateKey: true
})
```

#### Layout Section
```javascript
import { 
  layoutLifecycle,
  layoutAuth,
  layoutCertificates,
  layoutValidation,
  layoutPerformance 
} from '@/utils/logger'

layoutLifecycle('LAYOUT_MOUNT', { has_user: true })
layoutAuth('AUTH_CHECK_COMPLETE', { isAuthenticated: true })
layoutCertificates('CERTIFICATES_LOADED', certificates, { count: 5 })
layoutPerformance('RENDER_COMPLETE', 45, { component: 'MainLayout' })
```

#### Validation Panel
```javascript
import { 
  validationPanelValidation,
  validationPanelPKI,
  validationPanelCryptography,
  validationPanelSecurity 
} from '@/utils/logger'

validationPanelValidation('VALIDATION_START', validationData)
validationPanelPKI('PKI_ANALYSIS_COMPLETE', { is_valid: true })
validationPanelCryptography('FINGERPRINT_MATCH', { matches: 3 })
validationPanelSecurity('SECURITY_CHECK', { level: 'high', confidence: 95 })
```

#### System Messages
```javascript
import { 
  systemMessagesLifecycle,
  systemMessagesEvent,
  systemMessagesMessage,
  systemMessagesInteraction 
} from '@/utils/logger'

systemMessagesLifecycle('COMPONENT_MOUNT', { initial_message_count: 0 })
systemMessagesEvent('USER_NOTIFICATION', { type: 'success' })
systemMessagesMessage('MESSAGE_DISPLAYED', { id: 'msg-123', type: 'warning' })
systemMessagesInteraction('MESSAGE_DISMISSED', { id: 'msg-123' })
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
# Enable debug mode (highest priority in Docker/production)
VITE_DEBUG=true

# Set global log level (when debug mode is off)
VITE_LOG_LEVEL=DEBUG
```

### LocalStorage Configuration

```javascript
// Debug mode (overrides environment when set)
localStorage.setItem('certificate_debug', 'true')

// Global log level (overrides everything when set)
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

## 🐳 Docker & Production

### Docker Compose Configuration

```yaml
# docker-compose.yml
frontend:
  build: 
    context: ./frontend
    args:
      VITE_DEBUG: "true"      # Enable debug mode by default
      VITE_LOG_LEVEL: DEBUG   # Set debug level
  networks:
    - app-network
  restart: unless-stopped
```

### Dockerfile with Build Arguments

```dockerfile
FROM node:24-alpine AS builder

WORKDIR /app

# Accept build arguments for Vite environment variables
ARG VITE_API_URL=/api
ARG VITE_DEBUG=false
ARG VITE_LOG_LEVEL=INFO

# Set environment variables from build args
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_DEBUG=$VITE_DEBUG
ENV VITE_LOG_LEVEL=$VITE_LOG_LEVEL

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### Production Debugging

```javascript
// Enable specific debugging in production containers
logger.enableSection('certificateContext', 'DEBUG')
logger.enableSection('api', 'INFO')

// Monitor auto-refresh process
logger.enableSection('context', 'DEBUG')

// Focus on authentication issues
logger.enableSection('session', 'DEBUG')
logger.enableSection('cookie', 'DEBUG')
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

### 6. Certificate Context Integration

```javascript
// Complete certificate lifecycle logging
certificateContextLifecycle('PROVIDER_MOUNT', { 
  has_children: true,
  initial_component_count: 0 
})

certificateContextOperation('REFRESH_FILES_START', {
  operation_type: 'refresh',
  loading_state_will_change: true
})

certificateContextSession('SESSION_MONITORING_START', {
  is_monitoring: true,
  debug_mode: true
})
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

### Certificate Loading Issues

```javascript
// Debug certificate loading problems
logger.enableSection('certificateContext', 'DEBUG')
logger.enableSection('api', 'DEBUG')
logger.enableSection('session', 'DEBUG')

// Watch for these key log patterns:
// 📋 [CERTIFICATE CONTEXT] Lifecycle [PROVIDER_MOUNT]
// 🎯 [CONTEXT] CertificateProvider - triggering initial certificate refresh
// 📡 [API] GET /certificates
// 🎯 [CONTEXT] Initial refresh successful: X components loaded
```

### Session Management Debugging

```javascript
// Debug session/authentication issues
logger.enableSection('session', 'DEBUG')
logger.enableSection('cookie', 'DEBUG')
logger.enableSection('api', 'INFO')

// Key indicators to look for:
// 👤 [SESSION] Initial session detected: none/token
// 🍪 [COOKIE] Session token found/missing
// 📡 [API] Session change detected
```

### Performance Analysis

```javascript
// Enable performance logging for specific sections
logger.enableSection('api', 'DEBUG')
logger.enableSection('certificate', 'DEBUG')
logger.enableSection('certificateContext', 'DEBUG')

// Look for performance-related log entries:
// 📋 [CERTIFICATE CONTEXT] Performance [REFRESH_FILES_COMPLETED] 150ms
// 📡 [API DEBUG] 200 GET /certificates (70ms)
```

### Production Troubleshooting

```javascript
// Safe production debugging - minimal impact
logger.enableSection('connection', 'WARN')
logger.enableSection('session', 'INFO')
logger.enableSection('api', 'INFO')

// If more detail needed, temporarily enable:
logger.enableSection('certificateContext', 'DEBUG')
// Remember to disable after investigation:
logger.disableSection('certificateContext')
```

## 🎨 Emoji Reference

Each section uses distinctive emojis for easy identification in logs:

```
📋 [CERTIFICATE CONTEXT]     🎯 [CONTEXT]
📡 [API]                     👤 [SESSION]
🍪 [COOKIE]                  📤 [UPLOAD]
📁 [FILE MANAGER]            🏗️ [LAYOUT]
🔬 [VALIDATION PANEL]        📢 [SYSTEM MESSAGES]
🏗️ [FLOATING PANEL]         🔐 [SECURE PASSWORD MODAL]
🔽 [DOWNLOAD]                📜 [CERTIFICATE]
🔔 [NOTIFICATION]            📡 [CONNECTION]
💾 [DOWNLOAD MODAL]
```

---

## 📝 License

This logger implementation is part of the Certificate Management System.

---

**Happy Logging! 🚀**

For questions or issues, please refer to the project documentation or create an issue in the project repository.
