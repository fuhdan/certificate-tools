const crypto = require('crypto')
const forge = require('node-forge')

function getFileFormat(filename) {
  const extension = filename.split('.').pop().toLowerCase()
  switch (extension) {
    case 'pem':
    case 'crt':
    case 'cer':
      return 'PEM'
    case 'der':
      return 'DER'
    case 'p12':
    case 'pfx':
      return 'PKCS12'
    case 'jks':
      return 'JKS'
    case 'key':
      return 'Private Key'
    case 'csr':
      return 'CSR'
    default:
      return extension.toUpperCase()
  }
}

function analyzeCertificate(buffer, filename) {
  let certificateType = 'Unknown'
  let format = getFileFormat(filename)
  let isValid = false
  let certificateHash = null
  
  try {
    // Try to determine if this is a text (PEM) or binary (DER) file
    const content = buffer.toString('utf8')
    const isPEM = content.includes('-----BEGIN')
    
    if (isPEM) {
      // Handle PEM format
      if (content.includes('-----BEGIN CERTIFICATE-----')) {
        try {
          // Check if this is a certificate chain (multiple certificates)
          const certMatches = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)
          
          if (certMatches && certMatches.length > 1) {
            // Multiple certificates = certificate chain
            certificateType = 'Certificate Chain'
            isValid = true
            
            // Hash the entire chain content for comparison
            const chainContent = certMatches.join('').replace(/\s/g, '')
            certificateHash = crypto.createHash('sha256').update(chainContent).digest('hex')
            
          } else {
            // Single certificate
            const cert = forge.pki.certificateFromPem(content)
            certificateType = 'Certificate'
            isValid = true
            
            // Convert to DER for consistent comparison
            const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert))
            certificateHash = crypto.createHash('sha256').update(der.data, 'binary').digest('hex')
            
            // Check if it's a CA certificate
            const basicConstraints = cert.getExtension('basicConstraints')
            if (basicConstraints && basicConstraints.cA) {
              certificateType = 'CA Certificate'
            } else {
              certificateType = 'Certificate'
            }
          }
          
        } catch (err) {
          console.error('Error parsing PEM certificate:', err.message)
        }
        
      } else if (content.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
        try {
          const csr = forge.pki.certificationRequestFromPem(content)
          certificateType = 'CSR'
          isValid = true
          
          // Convert CSR to DER for comparison
          const der = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr))
          certificateHash = crypto.createHash('sha256').update(der.data, 'binary').digest('hex')
          
        } catch (err) {
          console.error('Error parsing PEM CSR:', err.message)
        }
        
      } else if (content.includes('-----BEGIN PRIVATE KEY-----') || 
                 content.includes('-----BEGIN RSA PRIVATE KEY-----') ||
                 content.includes('-----BEGIN EC PRIVATE KEY-----')) {
        try {
          // Parse the private key to get consistent representation
          let privateKey
          if (content.includes('-----BEGIN RSA PRIVATE KEY-----')) {
            privateKey = forge.pki.privateKeyFromPem(content)
          } else if (content.includes('-----BEGIN EC PRIVATE KEY-----')) {
            privateKey = forge.pki.privateKeyFromPem(content)
          } else {
            privateKey = forge.pki.privateKeyFromPem(content)
          }
          
          certificateType = 'Private Key'
          isValid = true
          
          // Convert to DER format for consistent comparison
          const der = forge.asn1.toDer(forge.pki.privateKeyToAsn1(privateKey))
          certificateHash = crypto.createHash('sha256').update(der.data, 'binary').digest('hex')
          
        } catch (err) {
          console.error('Error parsing PEM private key:', err.message)
          // Fallback: hash the cleaned PEM content
          const keyContent = content.replace(/\s/g, '')
          certificateHash = crypto.createHash('sha256').update(keyContent).digest('hex')
          certificateType = 'Private Key'
          isValid = true
        }
        
      } else if (content.includes('-----BEGIN PUBLIC KEY-----')) {
        certificateType = 'Public Key'
        isValid = true
        
        const keyContent = content.replace(/\s/g, '')
        certificateHash = crypto.createHash('sha256').update(keyContent).digest('hex')
      }
      
    } else {
      // Handle binary formats (DER, PKCS12, etc.)
      if (format === 'DER') {
        try {
          // First try to parse as DER certificate
          const asn1 = forge.asn1.fromDer(buffer.toString('binary'))
          
          try {
            const cert = forge.pki.certificateFromAsn1(asn1)
            certificateType = 'Certificate'
            isValid = true
            certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
            
            // Check if it's a CA certificate
            const basicConstraints = cert.getExtension('basicConstraints')
            if (basicConstraints && basicConstraints.cA) {
              certificateType = 'CA Certificate'
            } else {
              certificateType = 'Certificate'
            }
          } catch (certErr) {
            // Not a certificate, try parsing as private key
            try {
              const privateKey = forge.pki.privateKeyFromAsn1(asn1)
              certificateType = 'Private Key'
              isValid = true
              
              // Convert back to DER for consistent hash generation with PEM
              const der = forge.asn1.toDer(forge.pki.privateKeyToAsn1(privateKey))
              certificateHash = crypto.createHash('sha256').update(der.data, 'binary').digest('hex')
              
            } catch (keyErr) {
              // Not a private key either, try CSR
              try {
                const csr = forge.pki.certificationRequestFromAsn1(asn1)
                certificateType = 'CSR'
                isValid = true
                certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
              } catch (csrErr) {
                // Unknown DER format
                certificateType = 'Unknown DER'
                isValid = false
                certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
              }
            }
          }
          
        } catch (err) {
          console.error('Error parsing DER file:', err.message)
          // Fallback for binary files
          certificateType = 'Unknown Binary'
          isValid = false
          certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
        }
        
      } else if (format === 'PKCS12') {
        certificateType = 'PKCS12 Certificate'
        isValid = true
        certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
        
      } else {
        // Unknown binary format
        certificateType = 'Unknown Binary'
        certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
      }
    }
    
  } catch (error) {
    console.error('Error analyzing certificate:', error)
    // Fallback: just hash the entire file
    certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
  }
  
  return {
    type: certificateType,
    format: format,
    isValid: isValid,
    size: buffer.length,
    hash: certificateHash
  }
}

module.exports = {
  analyzeCertificate,
  getFileFormat
}