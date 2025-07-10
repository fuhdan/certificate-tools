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

// Map common OIDs to readable names
function getAlgorithmName(oid) {
  const oidMap = {
    // Signature algorithms
    '1.2.840.113549.1.1.5': 'SHA1withRSA',
    '1.2.840.113549.1.1.11': 'SHA256withRSA',
    '1.2.840.113549.1.1.12': 'SHA384withRSA',
    '1.2.840.113549.1.1.13': 'SHA512withRSA',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.4.3.2': 'ECDSA with SHA256',
    '1.2.840.10045.4.3.3': 'ECDSA with SHA384',
    '1.2.840.10045.4.3.4': 'ECDSA with SHA512',
    
    // Public key algorithms
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.10045.2.1': 'EC',
    
    // Hash algorithms
    '1.3.14.3.2.26': 'SHA1',
    '2.16.840.1.101.3.4.2.1': 'SHA256',
    '2.16.840.1.101.3.4.2.2': 'SHA384',
    '2.16.840.1.101.3.4.2.3': 'SHA512',
    
    // Elliptic curves
    '1.2.840.10045.3.1.7': 'P-256 (secp256r1)',
    '1.3.132.0.34': 'P-384 (secp384r1)',
    '1.3.132.0.35': 'P-521 (secp521r1)',
  };
  
  return oidMap[oid] || oid;
}

function extractCertificateDetails(cert) {
  const details = {
    subject: {},
    issuer: {},
    validity: {},
    extensions: {},
    publicKey: {},
    signature: {}
  }

  try {
    // Subject information
    details.subject = {
      commonName: cert.subject.getField('CN')?.value || 'N/A',
      organization: cert.subject.getField('O')?.value || 'N/A',
      organizationalUnit: cert.subject.getField('OU')?.value || 'N/A',
      country: cert.subject.getField('C')?.value || 'N/A',
      state: cert.subject.getField('ST')?.value || 'N/A',
      locality: cert.subject.getField('L')?.value || 'N/A',
      emailAddress: cert.subject.getField('emailAddress')?.value || 'N/A'
    }

    // Issuer information
    details.issuer = {
      commonName: cert.issuer.getField('CN')?.value || 'N/A',
      organization: cert.issuer.getField('O')?.value || 'N/A',
      organizationalUnit: cert.issuer.getField('OU')?.value || 'N/A',
      country: cert.issuer.getField('C')?.value || 'N/A'
    }

    // Validity period
    details.validity = {
      notBefore: cert.validity.notBefore.toISOString(),
      notAfter: cert.validity.notAfter.toISOString(),
      isExpired: new Date() > cert.validity.notAfter,
      daysUntilExpiry: Math.ceil((cert.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24))
    }

    // Serial number
    details.serialNumber = cert.serialNumber

    // Public key information
    details.publicKey = {
      algorithm: 'Unknown',
      keySize: 0,
      exponent: 'N/A'
    }

    if (cert.publicKey) {
      if (cert.publicKey.n) {
        // RSA key
        details.publicKey.algorithm = 'RSA'
        details.publicKey.keySize = cert.publicKey.n.bitLength()
        details.publicKey.exponent = cert.publicKey.e.toString()
      } else if (cert.publicKey.curve) {
        // EC key
        details.publicKey.algorithm = 'EC'
        details.publicKey.curve = cert.publicKey.curve || 'Unknown'
      }
    }

    // Signature algorithm
    details.signature = {
      algorithm: getAlgorithmName(cert.siginfo?.algorithmOid) || 'Unknown',
      algorithmOid: cert.siginfo?.algorithmOid || 'Unknown',
      hashAlgorithm: cert.md?.algorithm || 'Unknown'
    }

    // Extensions
    cert.extensions.forEach(ext => {
      switch (ext.name) {
        case 'basicConstraints':
          details.extensions.basicConstraints = {
            isCA: ext.cA || false,
            pathLength: ext.pathLenConstraint || 'N/A'
          }
          break
        case 'keyUsage':
          details.extensions.keyUsage = ext
          break
        case 'extKeyUsage':
          details.extensions.extendedKeyUsage = ext.usages || []
          break
        case 'subjectAltName':
          details.extensions.subjectAltName = ext.altNames?.map(alt => {
            let typeName = 'Unknown';
            let value = alt.value;
            
            switch (alt.type) {
              case 2:
                typeName = 'DNS';
                break;
              case 7:
                typeName = 'IP';
                // Handle IP address format
                if (typeof value === 'string' && value.length === 4) {
                  try {
                    // Convert binary IP to dotted decimal format
                    const bytes = [];
                    for (let i = 0; i < value.length; i++) {
                      bytes.push(value.charCodeAt(i));
                    }
                    value = bytes.join('.');
                  } catch (err) {
                    console.error('Error formatting IP address:', err);
                  }
                }
                break;
              case 1:
                typeName = 'Email';
                break;
              case 4:
                typeName = 'Directory Name';
                break;
              case 6:
                typeName = 'URI';
                break;
              default:
                typeName = `Type ${alt.type}`;
            }
            
            return {
              type: alt.type,
              typeName: typeName,
              value: value
            };
          }) || []
          break
        case 'authorityKeyIdentifier':
          details.extensions.authorityKeyIdentifier = ext.keyIdentifier || 'N/A'
          break
        case 'subjectKeyIdentifier':
          details.extensions.subjectKeyIdentifier = ext.subjectKeyIdentifier || 'N/A'
          break
      }
    })

  } catch (error) {
    console.error('Error extracting certificate details:', error)
  }

  return details
}

function extractCSRDetails(csr) {
  const details = {
    subject: {},
    publicKey: {},
    signature: {},
    extensions: {},
    attributes: []
  }

  try {
    // Subject information - extract all fields
    details.subject = {
      commonName: csr.subject.getField('CN')?.value || 'N/A',
      organization: csr.subject.getField('O')?.value || 'N/A',
      organizationalUnit: csr.subject.getField('OU')?.value || 'N/A',
      country: csr.subject.getField('C')?.value || 'N/A',
      state: csr.subject.getField('ST')?.value || 'N/A',
      locality: csr.subject.getField('L')?.value || 'N/A',
      emailAddress: csr.subject.getField('emailAddress')?.value || 'N/A'
    }

    // Extract all subject fields - including any non-standard ones
    details.subjectFull = [];
    if (csr.subject.attributes) {
      csr.subject.attributes.forEach(attr => {
        details.subjectFull.push({
          name: attr.name || attr.type,
          shortName: attr.shortName || '',
          value: attr.value
        });
      });
    }

    // Public key information
    details.publicKey = {
      algorithm: 'Unknown',
      keySize: 0,
      exponent: 'N/A',
      curve: 'N/A'
    }

    if (csr.publicKey) {
      if (csr.publicKey.n) {
        // RSA key
        details.publicKey.algorithm = 'RSA'
        details.publicKey.keySize = csr.publicKey.n.bitLength()
        details.publicKey.exponent = csr.publicKey.e.toString()
      } else if (csr.publicKey.curve) {
        // EC key
        details.publicKey.algorithm = 'EC'
        details.publicKey.curve = csr.publicKey.curve || 'Unknown'
      }
    }

    // Signature algorithm
    details.signature = {
      algorithm: csr.siginfo?.algorithmOid || 'Unknown',
      hashAlgorithm: csr.md?.algorithm || 'Unknown'
    }

    // Process attributes (extensions requested)
    if (csr.attributes) {
      for (let i = 0; i < csr.attributes.length; i++) {
        const attr = csr.attributes[i];
        
        // Look for the extension request attribute
        if (attr.name === 'extensionRequest' || attr.type === '1.2.840.113549.1.9.14') {
          // This is an extension request - extract the requested extensions
          if (attr.extensions) {
            // Process each requested extension
            attr.extensions.forEach(ext => {
              // Extract subject alternative names
              if (ext.name === 'subjectAltName' && ext.altNames) {
                details.extensions.subjectAltName = ext.altNames.map(alt => {
                  let typeName = 'Unknown';
                  let value = alt.value;
                  
                  switch (alt.type) {
                    case 2:
                      typeName = 'DNS';
                      break;
                    case 7:
                      typeName = 'IP';
                      // Handle IP address format
                      if (typeof value === 'string' && value.length === 4) {
                        try {
                          // Convert binary IP to dotted decimal format
                          const bytes = [];
                          for (let i = 0; i < value.length; i++) {
                            bytes.push(value.charCodeAt(i));
                          }
                          value = bytes.join('.');
                        } catch (err) {
                          console.error('Error formatting IP address:', err);
                        }
                      }
                      break;
                    case 1:
                      typeName = 'Email';
                      break;
                    case 4:
                      typeName = 'Directory Name';
                      break;
                    case 6:
                      typeName = 'URI';
                      break;
                    default:
                      typeName = `Type ${alt.type}`;
                  }
                  
                  return {
                    type: alt.type,
                    typeName: typeName,
                    value: value
                  };
                });
              } 
              // Extract basic constraints
              else if (ext.name === 'basicConstraints') {
                details.extensions.basicConstraints = {
                  isCA: ext.cA || false,
                  pathLength: ext.pathLenConstraint || 'N/A'
                };
              }
              // Extract key usage
              else if (ext.name === 'keyUsage') {
                details.extensions.keyUsage = ext;
              }
              // Extract extended key usage
              else if (ext.name === 'extKeyUsage') {
                details.extensions.extendedKeyUsage = ext.usages || [];
              }
              // Add other extensions
              else {
                // Create array if doesn't exist
                if (!details.extensions.other) {
                  details.extensions.other = [];
                }
                details.extensions.other.push({
                  name: ext.name || 'Unknown',
                  oid: ext.id || 'Unknown',
                  critical: ext.critical || false,
                  value: ext.value || 'N/A'
                });
              }
            });
          }
        } else {
          // Other attributes
          details.attributes.push({
            name: attr.name || 'Unknown',
            type: attr.type || 'Unknown',
            value: attr.value || 'N/A'
          });
        }
      }
    }

    // Add CSR version
    details.version = csr.version || 0;

  } catch (error) {
    console.error('Error extracting CSR details:', error)
  }

  return details
}

function extractPrivateKeyDetails(privateKey) {
  const details = {
    algorithm: 'Unknown',
    keySize: 0,
    exponent: 'N/A',
    curve: 'N/A'
  }

  try {
    if (privateKey.n) {
      // RSA key
      details.algorithm = 'RSA'
      details.keySize = privateKey.n.bitLength()
      details.exponent = privateKey.e?.toString() || 'N/A'
    } else if (privateKey.curve) {
      // EC key
      details.algorithm = 'EC'
      details.curve = privateKey.curve || 'Unknown'
    }
  } catch (error) {
    console.error('Error extracting private key details:', error)
  }

  return details
}
function analyzeCertificate(buffer, filename) {
  let certificateType = 'Unknown'
  let format = getFileFormat(filename)
  let isValid = false
  let certificateHash = null
  let details = null
  
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
            
            // Extract detailed information
            details = extractCertificateDetails(cert)
            
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
          
          // Extract detailed information
          details = extractCSRDetails(csr)
          
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
          
          // Extract detailed information
          details = extractPrivateKeyDetails(privateKey)
          
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
            
            // Extract detailed information
            details = extractCertificateDetails(cert)
            
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
              
              // Extract detailed information
              details = extractPrivateKeyDetails(privateKey)
              
            } catch (keyErr) {
              // Not a private key either, try CSR
              try {
                const csr = forge.pki.certificationRequestFromAsn1(asn1)
                certificateType = 'CSR'
                isValid = true
                certificateHash = crypto.createHash('sha256').update(buffer).digest('hex')
                
                // Extract detailed information
                details = extractCSRDetails(csr)
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
    hash: certificateHash,
    details: details
  }
}

module.exports = {
  analyzeCertificate,
  getFileFormat
}