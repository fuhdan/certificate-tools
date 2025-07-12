const express = require('express')
const multer = require('multer')
const { analyzeCertificate } = require('../lib/certificateAnalyzer')
const CertificateStorage = require('../lib/certificateStorage')

const router = express.Router()

// Configure multer for file uploads
const storage = multer.memoryStorage()
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
})

// Certificate upload and analysis endpoint
router.post('/analyze-certificate', upload.single('certificate'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' })
    }
    
    // Get password from request body if provided
    const password = req.body.password || null
    
    const analysis = analyzeCertificate(req.file.buffer, req.file.originalname, password)
    
    // Handle unsupported PKCS#8 files - don't add to storage, just return message
    if (analysis.type === 'Private Key (Encrypted PKCS#8 - Not Supported)') {
      return res.json({
        success: false,
        isUnsupported: true,
        filename: req.file.originalname,
        message: `${req.file.originalname}: Encrypted binary PKCS#8 keys are not supported. Please convert to PEM format first using: openssl pkcs8 -in encrypted.p8 -out encrypted.pem`,
        timestamp: new Date().toISOString()
      })
    }
    
    // If this is a successfully decrypted private key, remove any "Password Required" versions
    if (analysis.type === 'Private Key' && analysis.isValid && password) {
      const allCerts = CertificateStorage.getAll()
      const passwordRequiredVersions = allCerts.filter(cert => 
        cert.analysis.type.includes('Password Required') && 
        cert.filename === req.file.originalname
      )
      
      // Remove password required versions of the same file
      passwordRequiredVersions.forEach(cert => {
        CertificateStorage.remove(cert.id)
        console.log(`Removed password required version: ${cert.filename}`)
      })
    }
    
    // Check for duplicates based on actual certificate content hash
    let existingCert = null
    
    if (analysis.hash) {
      existingCert = CertificateStorage.findByHash(analysis.hash)
    }
    
    const certificateData = {
      id: Date.now() + Math.random(),
      filename: req.file.originalname,
      analysis: analysis,
      uploadedAt: new Date().toISOString()
    }
    
    // Add main certificate/file
    let addedCertificates = []
    
    if (existingCert) {
      // Same certificate content - automatically replace the existing one
      const replacedCert = CertificateStorage.replace(existingCert, certificateData)
      addedCertificates.push(replacedCert)
    } else {
      // No duplicate, add to storage
      const newCert = CertificateStorage.add(certificateData)
      addedCertificates.push(newCert)
    }
    
    // Add additional items (like private keys from PKCS#12)
    if (analysis.additionalItems && analysis.additionalItems.length > 0) {
      analysis.additionalItems.forEach((item, index) => {
        // Check for existing duplicate of this additional item
        let existingAdditionalItem = null
        if (item.hash) {
          existingAdditionalItem = CertificateStorage.findByHash(item.hash)
        }
        
        const additionalData = {
          id: Date.now() + Math.random() + index,
          filename: `${req.file.originalname} (Private Key)`,
          analysis: item,
          uploadedAt: new Date().toISOString()
        }
        
        if (existingAdditionalItem) {
          // Replace existing private key
          const replacedItem = CertificateStorage.replace(existingAdditionalItem, additionalData)
          addedCertificates.push(replacedItem)
          console.log(`Replaced duplicate private key: ${existingAdditionalItem.filename} -> ${additionalData.filename}`)
        } else {
          // Add new private key
          const addedItem = CertificateStorage.add(additionalData)
          addedCertificates.push(addedItem)
        }
      })
    }
    
    // AFTER everything is processed, clean up any remaining "Password Required" versions
    if (analysis.type === 'Private Key' && analysis.isValid && password) {
      console.log(`Checking for cleanup of password required versions for: ${req.file.originalname}`)
      const allCertsAfter = CertificateStorage.getAll()
      console.log(`Total certificates after processing: ${allCertsAfter.length}`)
      
      const remainingPasswordRequired = allCertsAfter.filter(cert => {
        const isPasswordRequired = cert.analysis.type.includes('Password Required') || cert.analysis.type.includes('Invalid Password')
        const sameFilename = cert.filename === req.file.originalname
        console.log(`Cert: ${cert.filename}, Type: ${cert.analysis.type}, IsPasswordRequired: ${isPasswordRequired}, SameFilename: ${sameFilename}`)
        return isPasswordRequired && sameFilename
      })
      
      console.log(`Found ${remainingPasswordRequired.length} password required versions to clean up`)
      
      // Remove any remaining password required versions
      remainingPasswordRequired.forEach(cert => {
        CertificateStorage.remove(cert.id)
        console.log(`Cleaned up remaining password required version: ${cert.filename}`)
      })
    }
    
    if (existingCert) {
      res.json({
        success: true,
        isDuplicate: true,
        replaced: true,
        certificate: addedCertificates[0],
        additionalItems: addedCertificates.slice(1),
        replacedCertificate: existingCert,
        clearSystemMessages: analysis.type === 'Private Key' && analysis.isValid,
        message: `Automatically replaced ${existingCert.filename} with ${req.file.originalname} (identical content)`
      })
    } else {
      res.json({
        success: true,
        isDuplicate: false,
        certificate: addedCertificates[0],
        additionalItems: addedCertificates.slice(1),
        clearSystemMessages: analysis.type === 'Private Key' && analysis.isValid,
        timestamp: new Date().toISOString()
      })
    }
    
  } catch (error) {
    console.error('Certificate analysis error:', error)
    res.status(500).json({ 
      error: 'Failed to analyze certificate',
      details: error.message 
    })
  }
})

// Batch certificate analysis endpoint
router.post('/analyze-certificates', upload.array('certificates', 10), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' })
    }
    
    const password = req.body.password || null
    const results = req.files.map(file => {
      const analysis = analyzeCertificate(file.buffer, file.originalname, password)
      return {
        filename: file.originalname,
        analysis: analysis
      }
    })
    
    res.json({
      success: true,
      count: results.length,
      results: results,
      timestamp: new Date().toISOString()
    })
    
  } catch (error) {
    console.error('Batch certificate analysis error:', error)
    res.status(500).json({ 
      error: 'Failed to analyze certificates',
      details: error.message 
    })
  }
})

// Handle duplicate decision endpoint (now only for logging, auto-replace is done above)
router.post('/handle-duplicate', (req, res) => {
  // This endpoint is no longer needed since we auto-replace duplicates
  // But keeping it for backward compatibility
  res.json({
    success: true,
    message: 'Duplicates are now handled automatically by replacing identical certificates'
  })
})

// Get all uploaded certificates
router.get('/certificates', (req, res) => {
  res.json({
    success: true,
    certificates: CertificateStorage.getAll(),
    count: CertificateStorage.count()
  })
})

// Delete certificate endpoint
router.delete('/certificates/:id', (req, res) => {
  const { id } = req.params
  const removed = CertificateStorage.remove(id)
  
  if (removed) {
    res.json({
      success: true,
      message: 'Certificate deleted successfully'
    })
  } else {
    res.status(404).json({
      error: 'Certificate not found'
    })
  }
})

// Clear all certificates
router.delete('/certificates', (req, res) => {
  CertificateStorage.clear()
  res.json({
    success: true,
    message: 'All certificates cleared'
  })
})

// Future endpoints for certificate operations
router.post('/convert-certificate', upload.single('certificate'), (req, res) => {
  // TODO: Implement certificate format conversion
  res.json({ 
    message: 'Certificate conversion endpoint - Coming soon',
    targetFormat: req.body.targetFormat || 'PEM'
  })
})

router.post('/validate-certificate', upload.single('certificate'), (req, res) => {
  // TODO: Implement certificate validation
  res.json({ 
    message: 'Certificate validation endpoint - Coming soon'
  })
})

module.exports = router