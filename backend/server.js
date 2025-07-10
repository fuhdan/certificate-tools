const express = require('express')
const cors = require('cors')
const certificateRoutes = require('./routes/certificates')

const app = express()
const PORT = process.env.PORT || 8000

// Middleware
app.use(cors())
app.use(express.json())

// Simple health endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime())
  })
})

// Certificate routes
app.use('/', certificateRoutes)

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend running on port ${PORT}`)
  console.log('Certificate analysis endpoints available:')
  console.log('  POST /analyze-certificate')
  console.log('  POST /analyze-certificates')
  console.log('  GET /certificates')
  console.log('  DELETE /certificates/:id')
  console.log('  DELETE /certificates')
  console.log('  POST /convert-certificate (coming soon)')
  console.log('  POST /validate-certificate (coming soon)')
})