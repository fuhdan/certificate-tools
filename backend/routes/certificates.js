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
    
    const analysis = analyzeCertificate(req.file.buffer, req.file.originalname)
    
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
    
    if (existingCert) {
      // Same certificate content - automatically replace the existing one
      const replacedCert = CertificateStorage.replace(existingCert, certificateData)
      
      res.json({
        success: true,
        isDuplicate: true,
        replaced: true,
        certificate: replacedCert,
        replacedCertificate: existingCert,
        message: `Automatically replaced ${existingCert.filename} with ${req.file.originalname} (identical content)`
      })
    } else {
      // No duplicate, add to storage
      const newCert = CertificateStorage.add(certificateData)
      
      res.json({
        success: true,
        isDuplicate: false,
        certificate: newCert,
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
    
    const results = req.files.map(file => {
      const analysis = analyzeCertificate(file.buffer, file.originalname)
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