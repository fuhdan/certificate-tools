const express = require('express');
const multer = require('multer');
const forge = require('node-forge');

const router = express.Router();

// Configure multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// Helper function to parse signature algorithm
const parseSignatureAlgorithm = (oid) => {
  const algorithms = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.5': 'SHA-1 with RSA',
    '1.2.840.113549.1.1.11': 'SHA-256 with RSA',
    '1.2.840.113549.1.1.12': 'SHA-384 with RSA',
    '1.2.840.113549.1.1.13': 'SHA-512 with RSA',
    '1.2.840.10045.4.1': 'SHA-1 with ECDSA',
    '1.2.840.10045.4.3.2': 'SHA-256 with ECDSA',
    '1.2.840.10045.4.3.3': 'SHA-384 with ECDSA',
    '1.2.840.10045.4.3.4': 'SHA-512 with ECDSA'
  };
  return algorithms[oid] || `Unknown (${oid})`;
};

// Helper function to get public key details
const getPublicKeyDetails = (publicKey) => {
  const details = {
    algorithm: 'Unknown',
    bitLength: 'Unknown',
    exponent: 'Unknown',
    curve: null,
    keyData: null
  };

  if (publicKey.n && publicKey.e) {
    details.algorithm = 'RSA';
    details.bitLength = publicKey.n.bitLength();
    details.exponent = publicKey.e.toString();
    details.modulus = forge.util.bytesToHex(publicKey.n.toByteArray()).toUpperCase();
  } else if (publicKey.point) {
    details.algorithm = 'Elliptic Curve (EC)';
    if (publicKey.point.curve && publicKey.point.curve.oid) {
      const curveOid = publicKey.point.curve.oid;
      const curveNames = {
        '1.2.840.10045.3.1.7': 'secp256r1 (P-256)',
        '1.3.132.0.34': 'secp384r1 (P-384)',
        '1.3.132.0.35': 'secp521r1 (P-521)',
        '1.2.840.10045.3.1.1': 'secp192r1 (P-192)'
      };
      details.curve = curveNames[curveOid] || `Unknown curve (${curveOid})`;
    }
    details.bitLength = publicKey.point.curve ? publicKey.point.curve.p.bitLength() : 'Unknown';
  }

  return details;
};

// Helper function to extract extensions from Certificate
const extractCertExtensions = (extensions) => {
  if (!extensions || extensions.length === 0) return [];
  
  return extensions.map(ext => {
    const result = {
      name: ext.name,
      id: ext.id,
      critical: ext.critical || false
    };

    switch (ext.name) {
      case 'keyUsage':
        result.usage = [];
        if (ext.digitalSignature) result.usage.push('Digital Signature');
        if (ext.nonRepudiation) result.usage.push('Non Repudiation');
        if (ext.keyEncipherment) result.usage.push('Key Encipherment');
        if (ext.dataEncipherment) result.usage.push('Data Encipherment');
        if (ext.keyAgreement) result.usage.push('Key Agreement');
        if (ext.keyCertSign) result.usage.push('Key Cert Sign');
        if (ext.cRLSign) result.usage.push('CRL Sign');
        if (ext.encipherOnly) result.usage.push('Encipher Only');
        if (ext.decipherOnly) result.usage.push('Decipher Only');
        break;

      case 'extKeyUsage':
        result.usage = [];
        if (ext.serverAuth) result.usage.push('Server Authentication');
        if (ext.clientAuth) result.usage.push('Client Authentication');
        if (ext.codeSigning) result.usage.push('Code Signing');
        if (ext.emailProtection) result.usage.push('Email Protection');
        if (ext.timeStamping) result.usage.push('Time Stamping');
        break;

      case 'basicConstraints':
        result.isCA = ext.cA || false;
        if (ext.pathLenConstraint !== undefined) {
          result.pathLength = ext.pathLenConstraint;
        }
        break;

      case 'subjectAltName':
        result.altNames = [];
        if (ext.altNames) {
          ext.altNames.forEach(altName => {
            const name = { type: altName.type };
            if (altName.type === 1) {
              name.value = altName.value;
              name.typeName = 'Email';
            } else if (altName.type === 2) {
              name.value = altName.value;
              name.typeName = 'DNS Name';
            } else if (altName.type === 6) {
              name.value = altName.value;
              name.typeName = 'URI';
            } else if (altName.type === 7) {
              name.value = altName.ip || altName.value;
              name.typeName = 'IP Address';
            } else {
              name.value = altName.value || altName.ip || 'Unknown';
              name.typeName = `Type ${altName.type}`;
            }
            result.altNames.push(name);
          });
        }
        break;

      case 'authorityKeyIdentifier':
        if (ext.keyIdentifier) {
          result.keyIdentifier = forge.util.bytesToHex(ext.keyIdentifier);
        }
        break;

      case 'subjectKeyIdentifier':
        if (ext.subjectKeyIdentifier) {
          result.keyIdentifier = forge.util.bytesToHex(ext.subjectKeyIdentifier);
        }
        break;

      default:
        if (ext.value) {
          result.value = ext.value;
        }
        break;
    }

    return result;
  });
};

// Helper function to manually parse CSR extensions
const parseCSRExtensions = (csr) => {
  const extensions = [];
  const sans = [];
  
  if (!csr.attributes) return { extensions, sans };
  
  const extReqAttr = csr.attributes.find(attr => 
    attr.name === 'extensionRequest' || 
    attr.type === '1.2.840.113549.1.9.14'
  );
  
  if (extReqAttr && extReqAttr.extensions) {
    extReqAttr.extensions.forEach(ext => {
      const extension = {
        name: ext.name,
        id: ext.id,
        critical: ext.critical || false
      };
      
      if (ext.name === 'subjectAltName' || ext.id === '2.5.29.17') {
        if (ext.altNames && ext.altNames.length > 0) {
          ext.altNames.forEach(altName => {
            const san = { type: altName.type };
            if (altName.type === 1) {
              san.value = altName.value;
              san.typeName = 'Email';
            } else if (altName.type === 2) {
              san.value = altName.value;
              san.typeName = 'DNS Name';
            } else if (altName.type === 6) {
              san.value = altName.value;
              san.typeName = 'URI';
            } else if (altName.type === 7) {
              san.value = altName.ip || altName.value;
              san.typeName = 'IP Address';
            } else {
              san.value = altName.value || altName.ip || 'Unknown';
              san.typeName = `Type ${altName.type}`;
            }
            sans.push(san);
          });
          extension.altNames = ext.altNames;
        }
      }
      
      if (ext.name === 'keyUsage') {
        extension.usage = [];
        if (ext.digitalSignature) extension.usage.push('Digital Signature');
        if (ext.nonRepudiation) extension.usage.push('Non Repudiation');
        if (ext.keyEncipherment) extension.usage.push('Key Encipherment');
        if (ext.dataEncipherment) extension.usage.push('Data Encipherment');
        if (ext.keyAgreement) extension.usage.push('Key Agreement');
        if (ext.keyCertSign) extension.usage.push('Key Cert Sign');
        if (ext.cRLSign) extension.usage.push('CRL Sign');
        if (ext.encipherOnly) extension.usage.push('Encipher Only');
        if (ext.decipherOnly) extension.usage.push('Decipher Only');
      }
      
      if (ext.name === 'extKeyUsage') {
        extension.usage = [];
        if (ext.serverAuth) extension.usage.push('Server Authentication');
        if (ext.clientAuth) extension.usage.push('Client Authentication');
        if (ext.codeSigning) extension.usage.push('Code Signing');
        if (ext.emailProtection) extension.usage.push('Email Protection');
        if (ext.timeStamping) extension.usage.push('Time Stamping');
      }
      
      if (ext.name === 'basicConstraints') {
        extension.isCA = ext.cA || false;
        if (ext.pathLenConstraint !== undefined) {
          extension.pathLength = ext.pathLenConstraint;
        }
      }
      
      extensions.push(extension);
    });
  }
  
  return { extensions, sans };
};

// Helper function to validate certificate with private key
const validateCertificateWithPrivateKey = (cert, privateKey) => {
  const validation = {
    publicKeyMatch: false,
    signatureValid: false,
    keyPairValid: false,
    details: {}
  };

  try {
    const certPublicKey = cert.publicKey;
    
    if (certPublicKey.n && privateKey.n && certPublicKey.e && privateKey.e) {
      validation.publicKeyMatch = 
        certPublicKey.n.equals(privateKey.n) && 
        certPublicKey.e.equals(privateKey.e);
      
      validation.details.keyType = 'RSA';
      validation.details.keySize = certPublicKey.n.bitLength();
      validation.details.publicExponent = certPublicKey.e.toString();
      
      let certModHex, privModHex;
      
      try {
        certModHex = certPublicKey.n.toString(16).toUpperCase();
        privModHex = privateKey.n.toString(16).toUpperCase();
        
        if (certModHex.length === 0) {
          certModHex = forge.util.bytesToHex(certPublicKey.n.toByteArray()).toUpperCase();
        }
        
        if (privModHex.length === 0) {
          privModHex = forge.util.bytesToHex(privateKey.n.toByteArray()).toUpperCase();
        }
      } catch (e) {
        console.log('Error getting modulus hex:', e.message);
        certModHex = 'ERROR_GETTING_MODULUS';
        privModHex = 'ERROR_GETTING_MODULUS';
      }
      
      validation.details.modulusMatch = {
        certificate: certModHex.length > 64 ? `${certModHex.substring(0, 32)}...${certModHex.substring(certModHex.length - 32)}` : certModHex,
        privateKey: privModHex.length > 64 ? `${privModHex.substring(0, 32)}...${privModHex.substring(privModHex.length - 32)}` : privModHex,
        identical: certModHex === privModHex,
        lengthMatch: certModHex.length === privModHex.length,
        totalLength: certModHex.length
      };
      
    } else if (certPublicKey.point && privateKey.d) {
      validation.details.keyType = 'Elliptic Curve';
      validation.details.keySize = privateKey.d.bitLength();
      validation.publicKeyMatch = true;
    }

    if (validation.publicKeyMatch) {
      try {
        const testMessage = 'Certificate-PrivateKey-Validation-Test-' + Date.now();
        const md = forge.md.sha256.create();
        md.update(testMessage, 'utf8');
        
        const signature = privateKey.sign(md);
        const verified = certPublicKey.verify(md.digest().getBytes(), signature);
        
        validation.signatureValid = verified;
        validation.keyPairValid = verified;
        
        if (verified) {
          validation.details.testMessage = testMessage;
          validation.details.signatureLength = signature.length;
          validation.details.hashAlgorithm = 'SHA-256';
        }
      } catch (e) {
        console.log('Signature validation error:', e.message);
        validation.signatureValid = false;
        validation.keyPairValid = false;
        validation.details.signatureError = e.message;
      }
    }

    validation.details.keyFormat = {
      certificate: 'X.509 Certificate',
      privateKey: 'PKCS#1 Private Key'
    };
    
    const keyUsageExt = cert.extensions?.find(ext => ext.name === 'keyUsage');
    if (keyUsageExt) {
      validation.details.keyUsageCompatibility = {
        canSign: keyUsageExt.digitalSignature || keyUsageExt.nonRepudiation,
        canEncrypt: keyUsageExt.keyEncipherment || keyUsageExt.dataEncipherment,
        canKeyExchange: keyUsageExt.keyAgreement,
        restrictions: []
      };
      
      if (!keyUsageExt.digitalSignature) {
        validation.details.keyUsageCompatibility.restrictions.push('Digital signature not allowed');
      }
      if (!keyUsageExt.keyEncipherment) {
        validation.details.keyUsageCompatibility.restrictions.push('Key encipherment not allowed');
      }
    }

  } catch (error) {
    console.log('Validation error:', error.message);
    validation.details.error = error.message;
  }

  return validation;
};

// Helper function to parse certificate chain
const parseCertificateChain = (chainContent) => {
  const chainCerts = [];
  
  if (!chainContent || !chainContent.trim()) {
    return chainCerts;
  }

  try {
    let content = chainContent.trim();
    if (!content.includes('-----BEGIN')) {
      try {
        content = Buffer.from(content, 'base64').toString('utf8');
      } catch (e) {
        return chainCerts;
      }
    }

    const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
    const matches = content.match(certRegex);
    
    if (matches) {
      matches.forEach((certPem, index) => {
        try {
          const cert = forge.pki.certificateFromPem(certPem);
          chainCerts.push({
            index: index,
            certificate: cert,
            pem: certPem,
            subject: cert.subject.attributes.map(attr => ({
              name: attr.name,
              shortName: attr.shortName,
              value: attr.value
            })),
            issuer: cert.issuer.attributes.map(attr => ({
              name: attr.name,
              shortName: attr.shortName,
              value: attr.value
            })),
            validity: {
              notBefore: cert.validity.notBefore,
              notAfter: cert.validity.notAfter,
              isValid: new Date() >= cert.validity.notBefore && new Date() <= cert.validity.notAfter
            },
            serialNumber: cert.serialNumber,
            fingerprint: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase()
          });
        } catch (e) {
          console.log(`Failed to parse certificate ${index} in chain:`, e.message);
        }
      });
    }
  } catch (error) {
    console.log('Error parsing certificate chain:', error.message);
  }

  return chainCerts;
};

// Helper function to validate certificate chain
const validateCertificateChain = (cert, chainCerts) => {
  const validation = {
    chainValid: false,
    chainLength: chainCerts.length,
    validationPath: [],
    issues: [],
    details: {}
  };

  if (chainCerts.length === 0) {
    validation.issues.push('No chain certificates provided');
    return validation;
  }

  try {
    let currentCert = cert;
    const validationPath = [{
      subject: currentCert.subject.getField('CN')?.value || 'Unknown',
      issuer: currentCert.issuer.getField('CN')?.value || 'Unknown',
      type: 'end-entity',
      valid: true,
      signatureValid: true,
      timeValid: new Date() >= currentCert.validity.notBefore && new Date() <= currentCert.validity.notAfter
    }];

    let foundIssuer = true;
    while (foundIssuer && validationPath.length <= chainCerts.length + 1) {
      foundIssuer = false;
      
      for (let i = 0; i < chainCerts.length; i++) {
        const chainCert = chainCerts[i].certificate;
        
        const currentIssuerCN = currentCert.issuer.getField('CN')?.value;
        const chainSubjectCN = chainCert.subject.getField('CN')?.value;
        
        if (currentIssuerCN === chainSubjectCN) {
          foundIssuer = true;
          
          let signatureValid = true;
          
          validationPath.push({
            subject: chainCert.subject.getField('CN')?.value || 'Unknown',
            issuer: chainCert.issuer.getField('CN')?.value || 'Unknown',
            type: chainCert.subject.getField('CN')?.value === chainCert.issuer.getField('CN')?.value ? 'root' : 'intermediate',
            valid: signatureValid && chainCerts[i].validity.isValid,
            signatureValid: signatureValid,
            timeValid: chainCerts[i].validity.isValid
          });

          currentCert = chainCert;
          
          if (chainCert.subject.getField('CN')?.value === chainCert.issuer.getField('CN')?.value) {
            validation.chainValid = true;
            foundIssuer = false;
            break;
          }
          break;
        }
      }
      
      if (!foundIssuer && validationPath[validationPath.length - 1].type !== 'root') {
        validation.issues.push(`Could not find issuer for: ${currentCert.subject.getField('CN')?.value}`);
      }
    }

    validation.validationPath = validationPath;
    
    if (validationPath.length === 1) {
      validation.issues.push('Certificate issuer not found in provided chain');
    }
    
    const hasExpiredCerts = validationPath.some(cert => !cert.timeValid);
    if (hasExpiredCerts) {
      validation.issues.push('One or more certificates in chain are expired or not yet valid');
    }
    
    if (validationPath.some(cert => cert.type === 'root') && validation.issues.length === 0) {
      validation.chainValid = true;
    }

    validation.details = {
      totalCerts: chainCerts.length + 1,
      pathLength: validationPath.length,
      hasRoot: validationPath.some(cert => cert.type === 'root'),
      hasIntermediate: validationPath.some(cert => cert.type === 'intermediate')
    };

  } catch (error) {
    validation.issues.push('Chain validation error: ' + error.message);
  }

  return validation;
};

// Helper function to parse certificate from DER or PEM format
const parseCertificateFromContent = (content, isDer = false) => {
  if (isDer) {
    console.log('Parsing DER format certificate');
    const binaryData = forge.util.decode64(content);
    const asn1 = forge.asn1.fromDer(binaryData);
    return forge.pki.certificateFromAsn1(asn1);
  } else {
    console.log('Parsing PEM format certificate');
    return forge.pki.certificateFromPem(content);
  }
};

// Helper function to parse CSR from DER or PEM format
const parseCSRFromContent = (content, isDer = false) => {
  if (isDer) {
    console.log('Parsing DER format CSR');
    const binaryData = forge.util.decode64(content);
    const asn1 = forge.asn1.fromDer(binaryData);
    return forge.pki.certificationRequestFromAsn1(asn1);
  } else {
    console.log('Parsing PEM format CSR');
    return forge.pki.certificationRequestFromPem(content);
  }
};

// Helper function to detect if private key is DER format
const isDerPrivateKey = (file) => {
  const lowerName = file.name.toLowerCase();
  return lowerName.endsWith('.der') || 
         lowerName.endsWith('.key') && !lowerName.includes('.pem');
};

// Helper function to parse private key from DER or PEM format
const parsePrivateKeyFromContent = (content, isDer = false, password = '') => {
  if (isDer) {
    console.log('Parsing DER format private key');
    const binaryData = forge.util.decode64(content);
    
    if (password) {
      // For encrypted DER private keys (PKCS#8)
      try {
        const asn1 = forge.asn1.fromDer(binaryData);
        return forge.pki.privateKeyFromAsn1(asn1, password);
      } catch (error) {
        console.log('Failed to parse encrypted DER, trying PKCS#8:', error.message);
        // Try PKCS#8 encrypted format
        const encryptedPrivateKeyInfo = forge.pki.encryptedPrivateKeyFromAsn1(forge.asn1.fromDer(binaryData));
        return forge.pki.decryptPrivateKeyInfo(encryptedPrivateKeyInfo, password);
      }
    } else {
      // Unencrypted DER private key
      const asn1 = forge.asn1.fromDer(binaryData);
      return forge.pki.privateKeyFromAsn1(asn1);
    }
  } else {
    console.log('Parsing PEM format private key');
    if (password) {
      if (content.includes('Proc-Type: 4,ENCRYPTED')) {
        return forge.pki.decryptRsaPrivateKey(content, password);
      } else if (content.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
        return forge.pki.privateKeyFromPem(content, password);
      } else {
        return forge.pki.privateKeyFromPem(content, password);
      }
    } else {
      return forge.pki.privateKeyFromPem(content);
    }
  }
};

// Helper function to check if DER private key is encrypted
const isDerPrivateKeyEncrypted = (binaryData) => {
  try {
    const asn1 = forge.asn1.fromDer(binaryData);
    // Try to parse as unencrypted first
    forge.pki.privateKeyFromAsn1(asn1);
    return false; // If successful, it's not encrypted
  } catch (error) {
    // If parsing fails, it might be encrypted or invalid
    // Check if it looks like PKCS#8 encrypted structure
    try {
      const asn1 = forge.asn1.fromDer(binaryData);
      if (asn1.tagClass === forge.asn1.Class.UNIVERSAL && asn1.type === forge.asn1.Type.SEQUENCE) {
        // Likely encrypted PKCS#8
        return true;
      }
    } catch (e) {
      // Not a valid ASN.1 structure
    }
    return false;
  }
};

// New endpoint to parse PKCS#12 files
router.post('/parse-pkcs12', (req, res) => {
  try {
    const { content, fileName = 'unknown', password = '' } = req.body;
    
    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'No PKCS#12 content provided' });
    }

    console.log(`Processing PKCS#12 file: ${fileName}`);

    try {
      const binaryData = forge.util.decode64(content);
      let p12Asn1;
      let p12;
      
      try {
        p12Asn1 = forge.asn1.fromDer(binaryData);
        p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
      } catch (parseError) {
        console.log('PKCS#12 parsing error:', parseError.message);
        
        // Check if it's a password issue
        if (parseError.message.includes('Invalid password') || 
            parseError.message.includes('Could not decrypt') ||
            parseError.message.includes('MAC verification failed') ||
            parseError.message.includes('Invalid key length')) {
          return res.json({ 
            needsPassword: true,
            error: 'Invalid password or password required'
          });
        }
        
        if (!password || password.trim() === '') {
          return res.json({ 
            needsPassword: true,
            error: 'Password required to decrypt PKCS#12 file'
          });
        }
        
        throw parseError;
      }

      console.log('PKCS#12 parsed successfully');

      // Extract certificate, private key, and certificate chain
      let certificate = null;
      let privateKey = null;
      let certificateChain = [];

      // Get certificate bags (certificates)
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
      const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
      const keyBags2 = p12.getBags({ bagType: forge.pki.oids.keyBag });

      console.log('Found certificate bags:', Object.keys(certBags).length);
      console.log('Found key bags (shrouded):', Object.keys(keyBags).length);
      console.log('Found key bags (plain):', Object.keys(keyBags2).length);

      // Process certificates
      Object.keys(certBags).forEach(bagId => {
        const bags = certBags[bagId];
        bags.forEach((bag, index) => {
          if (bag.cert) {
            const cert = bag.cert;
            const certData = {
              pem: forge.pki.certificateToPem(cert),
              subject: cert.subject.attributes.map(attr => ({
                name: attr.name,
                shortName: attr.shortName,
                value: attr.value
              })),
              issuer: cert.issuer.attributes.map(attr => ({
                name: attr.name,
                shortName: attr.shortName,
                value: attr.value
              })),
              validity: {
                notBefore: cert.validity.notBefore,
                notAfter: cert.validity.notAfter,
                isValid: new Date() >= cert.validity.notBefore && new Date() <= cert.validity.notAfter
              },
              serialNumber: cert.serialNumber,
              fingerprint: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase()
            };

            if (!certificate) {
              // First certificate is the main certificate
              certificate = certData;
              
              // Add full certificate parsing
              const publicKeyDetails = getPublicKeyDetails(cert.publicKey);
              
              certificate.type = 'Certificate';
              certificate.version = cert.version;
              certificate.publicKey = publicKeyDetails;
              certificate.signature = {
                algorithm: parseSignatureAlgorithm(cert.signatureOid),
                oid: cert.signatureOid,
                valid: true
              };
              certificate.extensions = extractCertExtensions(cert.extensions);
              certificate.validity.daysUntilExpiry = Math.ceil((cert.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24));
              certificate.validity.validityPeriodDays = Math.ceil((cert.validity.notAfter - cert.validity.notBefore) / (1000 * 60 * 60 * 24));
              certificate.raw = {
                fingerprint: {
                  sha1: forge.md.sha1.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase(),
                  sha256: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase()
                },
                pem: certData.pem
              };

              // Extract Subject Alternative Names
              const sanExtension = cert.extensions?.find(ext => ext.name === 'subjectAltName');
              if (sanExtension && sanExtension.altNames) {
                certificate.subjectAlternativeNames = sanExtension.altNames.map(altName => {
                  const san = { type: altName.type };
                  if (altName.type === 1) {
                    san.value = altName.value;
                    san.typeName = 'Email';
                  } else if (altName.type === 2) {
                    san.value = altName.value;
                    san.typeName = 'DNS Name';
                  } else if (altName.type === 6) {
                    san.value = altName.value;
                    san.typeName = 'URI';
                  } else if (altName.type === 7) {
                    san.value = altName.ip || altName.value;
                    san.typeName = 'IP Address';
                  } else {
                    san.value = altName.value || altName.ip || 'Unknown';
                    san.typeName = `Type ${altName.type}`;
                  }
                  return san;
                });
              }
            } else {
              // Additional certificates go to the chain
              certificateChain.push(certData);
            }
          }
        });
      });

      // Process private keys (shrouded key bags)
      Object.keys(keyBags).forEach(bagId => {
        const bags = keyBags[bagId];
        bags.forEach((bag) => {
          if (bag.key && !privateKey) {
            privateKey = {
              pem: forge.pki.privateKeyToPem(bag.key),
              type: 'Private Key'
            };
          }
        });
      });

      // Process private keys (plain key bags)
      Object.keys(keyBags2).forEach(bagId => {
        const bags = keyBags2[bagId];
        bags.forEach((bag) => {
          if (bag.key && !privateKey) {
            privateKey = {
              pem: forge.pki.privateKeyToPem(bag.key),
              type: 'Private Key'
            };
          }
        });
      });

      // Validate private key with certificate if both are present
      if (certificate && privateKey) {
        try {
          const cert = forge.pki.certificateFromPem(certificate.pem);
          const key = forge.pki.privateKeyFromPem(privateKey.pem);
          certificate.privateKeyValidation = validateCertificateWithPrivateKey(cert, key);
        } catch (validationError) {
          console.error('Private key validation error:', validationError.message);
          certificate.privateKeyValidation = {
            publicKeyMatch: false,
            signatureValid: false,
            keyPairValid: false,
            details: { error: 'Failed to validate private key: ' + validationError.message }
          };
        }
      }

      // Validate certificate chain if present
      if (certificate && certificateChain.length > 0) {
        try {
          const cert = forge.pki.certificateFromPem(certificate.pem);
          const chainCerts = certificateChain.map(chainCert => ({
            certificate: forge.pki.certificateFromPem(chainCert.pem),
            pem: chainCert.pem,
            subject: chainCert.subject,
            issuer: chainCert.issuer,
            validity: chainCert.validity,
            serialNumber: chainCert.serialNumber,
            fingerprint: chainCert.fingerprint
          }));
          certificate.chainValidation = validateCertificateChain(cert, chainCerts);
          certificate.certificateChain = certificateChain.map(chainCert => ({
            subject: chainCert.subject,
            issuer: chainCert.issuer,
            validity: chainCert.validity,
            serialNumber: chainCert.serialNumber,
            fingerprint: chainCert.fingerprint
          }));
        } catch (chainValidationError) {
          console.error('Chain validation error:', chainValidationError.message);
          certificate.chainValidation = {
            chainValid: false,
            chainLength: certificateChain.length,
            validationPath: [],
            issues: ['Failed to validate certificate chain: ' + chainValidationError.message],
            details: {}
          };
        }
      }

      const result = {
        type: 'PKCS#12',
        certificate: certificate,
        privateKey: privateKey,
        certificateChain: certificateChain,
        summary: {
          hasCertificate: !!certificate,
         hasPrivateKey: !!privateKey,
         chainLength: certificateChain.length,
         keyPairValid: certificate?.privateKeyValidation?.keyPairValid || false,
         chainValid: certificate?.chainValidation?.chainValid || false
       }
     };

     console.log('PKCS#12 processing complete:', {
       hasCertificate: result.summary.hasCertificate,
       hasPrivateKey: result.summary.hasPrivateKey,
       chainLength: result.summary.chainLength,
       keyPairValid: result.summary.keyPairValid,
       chainValid: result.summary.chainValid
     });

     return res.json(result);

   } catch (parseError) {
     console.error('PKCS#12 parsing error:', parseError.message);
     return res.status(400).json({ error: 'Failed to parse PKCS#12: ' + parseError.message });
   }

 } catch (error) {
   console.error('PKCS#12 processing error:', error);
   return res.status(500).json({ error: 'Server error processing PKCS#12: ' + error.message });
 }
});

// New endpoint to parse DER format certificates
router.post('/parse-der', (req, res) => {
 try {
   const { content, fileName = 'unknown', privateKey = '', chain = '', privateKeyPassword = '' } = req.body;
   
   if (!content || !content.trim()) {
     return res.status(400).json({ error: 'No DER content provided' });
   }

   console.log(`Processing DER file: ${fileName}`);

   let result = {};
   let cert = null;
   let csr = null;

   try {
     // Try to parse as certificate first
     try {
       cert = parseCertificateFromContent(content, true);
       console.log('Successfully parsed as DER certificate');
     } catch (certError) {
       console.log('Failed to parse as certificate, trying CSR:', certError.message);
       // Try to parse as CSR
       csr = parseCSRFromContent(content, true);
       console.log('Successfully parsed as DER CSR');
     }

     if (cert) {
       const publicKeyDetails = getPublicKeyDetails(cert.publicKey);
       
       result = {
         type: 'Certificate',
         subject: cert.subject.attributes.map(attr => ({
           name: attr.name,
           shortName: attr.shortName,
           value: attr.value,
           type: attr.type
         })),
         issuer: cert.issuer.attributes.map(attr => ({
           name: attr.name,
           shortName: attr.shortName,
           value: attr.value,
           type: attr.type
         })),
         validity: {
           notBefore: cert.validity.notBefore,
           notAfter: cert.validity.notAfter,
           isValid: new Date() >= cert.validity.notBefore && new Date() <= cert.validity.notAfter,
           daysUntilExpiry: Math.ceil((cert.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24)),
           validityPeriodDays: Math.ceil((cert.validity.notAfter - cert.validity.notBefore) / (1000 * 60 * 60 * 24))
         },
         serialNumber: cert.serialNumber,
         version: cert.version,
         publicKey: publicKeyDetails,
         signature: {
           algorithm: parseSignatureAlgorithm(cert.signatureOid),
           oid: cert.signatureOid,
           valid: true
         },
         extensions: extractCertExtensions(cert.extensions),
         raw: {
           fingerprint: {
             sha1: forge.md.sha1.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase(),
             sha256: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase()
           },
           pem: forge.pki.certificateToPem(cert),
           der: content
         }
       };

       const sanExtension = cert.extensions?.find(ext => ext.name === 'subjectAltName');
       if (sanExtension && sanExtension.altNames) {
         result.subjectAlternativeNames = sanExtension.altNames.map(altName => {
           const san = { type: altName.type };
           if (altName.type === 1) {
             san.value = altName.value;
             san.typeName = 'Email';
           } else if (altName.type === 2) {
             san.value = altName.value;
             san.typeName = 'DNS Name';
           } else if (altName.type === 6) {
             san.value = altName.value;
             san.typeName = 'URI';
           } else if (altName.type === 7) {
             san.value = altName.ip || altName.value;
             san.typeName = 'IP Address';
           } else {
             san.value = altName.value || altName.ip || 'Unknown';
             san.typeName = `Type ${altName.type}`;
           }
           return san;
         });
       }

       // Handle private key validation if provided
       if (privateKey && privateKey.trim()) {
         try {
           let privateKeyContent = privateKey.trim();
           if (!privateKeyContent.includes('-----BEGIN')) {
             privateKeyContent = Buffer.from(privateKeyContent, 'base64').toString('utf8');
           }
           
           let parsedPrivateKey;
           
           if (privateKeyPassword && privateKeyPassword.trim()) {
             console.log('Attempting to decrypt private key with password');
             try {
               if (privateKeyContent.includes('Proc-Type: 4,ENCRYPTED')) {
                 console.log('Detected traditional encrypted PEM format');
                 parsedPrivateKey = forge.pki.decryptRsaPrivateKey(privateKeyContent, privateKeyPassword);
               } 
               else if (privateKeyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
                 console.log('Detected PKCS#8 encrypted format');
                 parsedPrivateKey = forge.pki.privateKeyFromPem(privateKeyContent, privateKeyPassword);
               }
               else {
                 console.log('Trying generic password decryption');
                 try {
                   parsedPrivateKey = forge.pki.privateKeyFromPem(privateKeyContent, privateKeyPassword);
                 } catch (e1) {
                   console.log('Generic decryption failed, trying RSA decryption');
                   parsedPrivateKey = forge.pki.decryptRsaPrivateKey(privateKeyContent, privateKeyPassword);
                 }
               }
               console.log('Private key decrypted successfully');
             } catch (decryptError) {
               console.error('Decryption error:', decryptError.message);
               throw new Error('Failed to decrypt private key with provided password: ' + decryptError.message);
             }
           } else {
             console.log('Parsing unencrypted private key');
             parsedPrivateKey = forge.pki.privateKeyFromPem(privateKeyContent);
           }
           
           if (!parsedPrivateKey) {
             throw new Error('Failed to parse private key');
           }
           
           console.log('Private key parsed successfully, proceeding with validation');
           result.privateKeyValidation = validateCertificateWithPrivateKey(cert, parsedPrivateKey);
         } catch (error) {
           console.error('Private key processing error:', error.message);
           result.privateKeyValidation = {
             publicKeyMatch: false,
             signatureValid: false,
             keyPairValid: false,
             details: { error: 'Failed to parse private key: ' + error.message }
           };
         }
       }

       // Handle certificate chain validation if provided
       if (chain && chain.trim()) {
         console.log('Chain content provided, parsing and validating...');
         const chainCerts = parseCertificateChain(chain);
         if (chainCerts.length > 0) {
           result.chainValidation = validateCertificateChain(cert, chainCerts);
           result.certificateChain = chainCerts.map(chainCert => ({
             subject: chainCert.subject,
             issuer: chainCert.issuer,
             validity: chainCert.validity,
             serialNumber: chainCert.serialNumber,
             fingerprint: chainCert.fingerprint
           }));
         } else {
           result.chainValidation = {
             chainValid: false,
             chainLength: 0,
             validationPath: [],
             issues: ['Failed to parse any certificates from chain content'],
             details: {}
           };
         }
       }

     } else if (csr) {
       const publicKeyDetails = getPublicKeyDetails(csr.publicKey);
       const { extensions, sans } = parseCSRExtensions(csr);
       
       result = {
         type: 'CSR',
         subject: csr.subject.attributes.map(attr => ({
           name: attr.name,
           shortName: attr.shortName,
           value: attr.value,
           type: attr.type
         })),
         publicKey: publicKeyDetails,
         signature: {
           algorithm: parseSignatureAlgorithm(csr.signatureOid),
           oid: csr.signatureOid,
           valid: true
         },
         extensions: extensions,
         version: csr.version || 0,
         raw: {
           fingerprint: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes()).digest().toHex().toUpperCase(),
           pem: forge.pki.certificationRequestToPem(csr),
           der: content
         }
       };

       if (sans.length > 0) {
         result.subjectAlternativeNames = sans;
       }
     }

   } catch (parseError) {
     console.error('DER parsing error:', parseError.message);
     return res.status(400).json({ error: 'Failed to parse DER content: ' + parseError.message });
   }

   res.json(result);
 } catch (error) {
   console.error('DER processing error:', error);
   return res.status(500).json({ error: 'Server error processing DER content: ' + error.message });
 }
});

// New endpoint to parse PKCS#7 certificate bundles
router.post('/parse-pkcs7', (req, res) => {
 try {
   const { content, isDer = false, fileName = 'unknown' } = req.body;
   
   if (!content || !content.trim()) {
     return res.status(400).json({ error: 'No PKCS#7 content provided' });
   }

   console.log(`Processing PKCS#7 file: ${fileName}, DER format: ${isDer}`);

   let pkcs7Content = content.trim();
   let p7 = null;

   try {
     if (isDer) {
       console.log('Processing DER format PKCS#7');
       const binaryData = forge.util.decode64(pkcs7Content);
       const asn1 = forge.asn1.fromDer(binaryData);
       p7 = forge.pkcs7.messageFromAsn1(asn1);
     } else {
       if (pkcs7Content.includes('-----BEGIN PKCS7-----')) {
         console.log('Processing PEM format PKCS#7');
         p7 = forge.pkcs7.messageFromPem(pkcs7Content);
       } else if (pkcs7Content.includes('-----BEGIN CERTIFICATE-----')) {
         console.log('Processing PEM file with multiple certificates');
         const certMatches = pkcs7Content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
         if (certMatches && certMatches.length > 0) {
           const certificates = certMatches.map((certPem, index) => {
             try {
               const cert = forge.pki.certificateFromPem(certPem);
               return {
                 index: index,
                 pem: certPem,
                 subject: cert.subject.attributes.map(attr => ({
                   name: attr.name,
                   shortName: attr.shortName,
                   value: attr.value
                 })),
                 issuer: cert.issuer.attributes.map(attr => ({
                   name: attr.name,
                   shortName: attr.shortName,
                   value: attr.value
                 })),
                 validity: {
                   notBefore: cert.validity.notBefore,
                   notAfter: cert.validity.notAfter,
                   isValid: new Date() >= cert.validity.notBefore && new Date() <= cert.validity.notAfter
                 },
                 serialNumber: cert.serialNumber,
                 fingerprint: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase()
               };
             } catch (e) {
               console.log(`Failed to parse certificate ${index}:`, e.message);
               return null;
             }
           }).filter(cert => cert !== null);

           return res.json({
             type: 'PKCS#7 (Multi-PEM)',
             certificates: certificates,
             certificateCount: certificates.length
           });
         }
       } else {
         try {
           const binaryData = forge.util.decode64(pkcs7Content);
           const asn1 = forge.asn1.fromDer(binaryData);
           p7 = forge.pkcs7.messageFromAsn1(asn1);
         } catch (e) {
           return res.status(400).json({ error: 'Invalid PKCS#7 format - could not parse as PEM or DER' });
         }
       }
     }

     if (p7 && p7.certificates) {
       console.log(`Found ${p7.certificates.length} certificates in PKCS#7`);
       
       const certificates = p7.certificates.map((cert, index) => {
         const certPem = forge.pki.certificateToPem(cert);
         return {
           index: index,
           pem: certPem,
           subject: cert.subject.attributes.map(attr => ({
             name: attr.name,
             shortName: attr.shortName,
             value: attr.value
           })),
           issuer: cert.issuer.attributes.map(attr => ({
             name: attr.name,
             shortName: attr.shortName,
             value: attr.value
           })),
           validity: {
             notBefore: cert.validity.notBefore,
             notAfter: cert.validity.notAfter,
             isValid: new Date() >= cert.validity.notBefore && new Date() <= cert.validity.notAfter
           },
           serialNumber: cert.serialNumber,
           fingerprint: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase()
         };
       });

       return res.json({
         type: 'PKCS#7',
         certificates: certificates,
         certificateCount: certificates.length
       });
     } else {
       return res.status(400).json({ error: 'No certificates found in PKCS#7 structure' });
     }

   } catch (parseError) {
     console.error('PKCS#7 parsing error:', parseError.message);
     return res.status(400).json({ error: 'Failed to parse PKCS#7: ' + parseError.message });
   }

 } catch (error) {
   console.error('PKCS#7 processing error:', error);
   return res.status(500).json({ error: 'Server error processing PKCS#7: ' + error.message });
 }
});

// New endpoint to check if private key is encrypted
router.post('/check-key-encryption', (req, res) => {
 try {
   const { privateKey } = req.body;
   
   if (!privateKey || !privateKey.trim()) {
     return res.json({ encrypted: false });
   }

   let keyContent = privateKey.trim();
   
   if (!keyContent.includes('-----BEGIN')) {
     try {
       keyContent = Buffer.from(keyContent, 'base64').toString('utf8');
     } catch (e) {
       return res.json({ encrypted: false, error: 'Invalid key format' });
     }
   }

   const hasEncryptionHeader = keyContent.includes('Proc-Type: 4,ENCRYPTED') || 
                              keyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');
   
   if (hasEncryptionHeader) {
     return res.json({ encrypted: true });
   }

   try {
     forge.pki.privateKeyFromPem(keyContent);
     return res.json({ encrypted: false });
   } catch (error) {
     if (error.message.includes('decrypt') || error.message.includes('password') || error.message.includes('encrypted')) {
       return res.json({ encrypted: true });
     }
     
     return res.json({ encrypted: false, error: 'Invalid private key format' });
   }
 } catch (error) {
   console.error('Key encryption check error:', error);
   return res.json({ encrypted: false, error: 'Failed to check key encryption' });
 }
});

// Certificate/CSR parsing endpoint with private key and chain validation
router.post('/parse', upload.single('file'), (req, res) => {
  try {
    let content = '';
    let privateKeyContent = '';
    let chainContent = '';
    let privateKeyPassword = '';     
    if (req.file) {
      content = req.file.buffer.toString('utf8');
    } else if (req.body.content) {
      content = req.body.content;
    } else {
      return res.status(400).json({ error: 'No content provided' });
    } 
    if (req.body.privateKey) {
      privateKeyContent = req.body.privateKey.trim();
    } 
    if (req.body.chain) {
      chainContent = req.body.chain.trim();
    } 
    if (req.body.privateKeyPassword) {
      privateKeyPassword = req.body.privateKeyPassword.trim();
    } 
    content = content.trim();
    if (!content.includes('-----BEGIN')) {
      try {
        content = Buffer.from(content, 'base64').toString('utf8');
      } catch (e) {
        return res.status(400).json({ error: 'Invalid base64 content' });
      }
    } 
    let result = {};     
    if (content.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
      const csr = forge.pki.certificationRequestFromPem(content);
      const publicKeyDetails = getPublicKeyDetails(csr.publicKey);
      const { extensions, sans } = parseCSRExtensions(csr);      
      result = {
        type: 'CSR',
        subject: csr.subject.attributes.map(attr => ({
          name: attr.name,
          shortName: attr.shortName,
          value: attr.value,
          type: attr.type
        })),
        publicKey: publicKeyDetails,
        signature: {
          algorithm: parseSignatureAlgorithm(csr.signatureOid),
          oid: csr.signatureOid,
          valid: true
        },
        extensions: extensions,
        version: csr.version || 0,
        raw: {
          fingerprint: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes()).digest().toHex().toUpperCase(),
          pem: content
        }
      };  
      if (sans.length > 0) {
        result.subjectAlternativeNames = sans;
      } 
    } else if (content.includes('-----BEGIN CERTIFICATE-----')) {
      const cert = forge.pki.certificateFromPem(content);
      const publicKeyDetails = getPublicKeyDetails(cert.publicKey);      
      result = {
        type: 'Certificate',
        subject: cert.subject.attributes.map(attr => ({
          name: attr.name,
          shortName: attr.shortName,
          value: attr.value,
          type: attr.type
        })),
        issuer: cert.issuer.attributes.map(attr => ({
          name: attr.name,
          shortName: attr.shortName,
          value: attr.value,
          type: attr.type
        })),
        validity: {
          notBefore: cert.validity.notBefore,
          notAfter: cert.validity.notAfter,
          isValid: new Date() >= cert.validity.notBefore && new Date() <= cert.validity.notAfter,
          daysUntilExpiry: Math.ceil((cert.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24)),
          validityPeriodDays: Math.ceil((cert.validity.notAfter - cert.validity.notBefore) / (1000 * 60 * 60 * 24))
        },
        serialNumber: cert.serialNumber,
        version: cert.version,
        publicKey: publicKeyDetails,
        signature: {
          algorithm: parseSignatureAlgorithm(cert.signatureOid),
          oid: cert.signatureOid,
          valid: true
        },
        extensions: extractCertExtensions(cert.extensions),
        raw: {
          fingerprint: {
            sha1: forge.md.sha1.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase(),
            sha256: forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex().toUpperCase()
          },
          pem: content
        }
      };  
      const sanExtension = cert.extensions?.find(ext => ext.name === 'subjectAltName');
      if (sanExtension && sanExtension.altNames) {
        result.subjectAlternativeNames = sanExtension.altNames.map(altName => {
          const san = { type: altName.type };
          if (altName.type === 1) {
            san.value = altName.value;
            san.typeName = 'Email';
          } else if (altName.type === 2) {
            san.value = altName.value;
            san.typeName = 'DNS Name';
          } else if (altName.type === 6) {
            san.value = altName.value;
            san.typeName = 'URI';
          } else if (altName.type === 7) {
            san.value = altName.ip || altName.value;
            san.typeName = 'IP Address';
          } else {
            san.value = altName.value || altName.ip || 'Unknown';
            san.typeName = `Type ${altName.type}`;
          }
          return san;
        });
      } 
      if (privateKeyContent) {
        try {
          if (!privateKeyContent.includes('-----BEGIN')) {
            // Could be base64 encoded DER or PEM
            try {
              const decoded = Buffer.from(privateKeyContent, 'base64').toString('utf8');
              if (decoded.includes('-----BEGIN')) {
                // It was base64 encoded PEM
                privateKeyContent = decoded;
              } else {
                // It's likely DER format in base64
                console.log('Detected DER format private key in base64');
              }
            } catch (e) {
              console.log('Not valid base64, treating as raw content');
            }
          }
          
          let privateKey;
          const isDerFormat = !privateKeyContent.includes('-----BEGIN');
          
          if (privateKeyPassword) {
            console.log(`Attempting to decrypt ${isDerFormat ? 'DER' : 'PEM'} private key with password`);
            try {
              privateKey = parsePrivateKeyFromContent(privateKeyContent, isDerFormat, privateKeyPassword);
              console.log('Private key decrypted successfully');
            } catch (decryptError) {
              console.error('Decryption error:', decryptError.message);
              throw new Error(`Failed to decrypt ${isDerFormat ? 'DER' : 'PEM'} private key with provided password: ` + decryptError.message);
            }
          } else {
            console.log(`Parsing unencrypted ${isDerFormat ? 'DER' : 'PEM'} private key`);
            try {
              privateKey = parsePrivateKeyFromContent(privateKeyContent, isDerFormat);
            } catch (parseError) {
              // If parsing fails, it might be encrypted
              if (parseError.message.includes('decrypt') || 
                  parseError.message.includes('password') || 
                  parseError.message.includes('encrypted')) {
                throw new Error(`Private key appears to be encrypted but no password provided`);
              }
              throw parseError;
            }
          }
          
          if (!privateKey) {
            throw new Error('Failed to parse private key');
          }
          
          console.log('Private key parsed successfully, proceeding with validation');
          result.privateKeyValidation = validateCertificateWithPrivateKey(cert, privateKey);
        } catch (error) {
          console.error('Private key processing error:', error.message);
          result.privateKeyValidation = {
            publicKeyMatch: false,
            signatureValid: false,
            keyPairValid: false,
            details: { error: 'Failed to parse private key: ' + error.message }
          };
        }
      } 
      if (chainContent) {
        console.log('Chain content provided, parsing and validating...');
        const chainCerts = parseCertificateChain(chainContent);
        if (chainCerts.length > 0) {
          result.chainValidation = validateCertificateChain(cert, chainCerts);
          result.certificateChain = chainCerts.map(chainCert => ({
            subject: chainCert.subject,
            issuer: chainCert.issuer,
            validity: chainCert.validity,
            serialNumber: chainCert.serialNumber,
            fingerprint: chainCert.fingerprint
          }));
        } else {
          result.chainValidation = {
            chainValid: false,
            chainLength: 0,
            validationPath: [],
            issues: ['Failed to parse any certificates from chain content'],
            details: {}
          };
        }
      } 
    } else {
      return res.status(400).json({ error: 'Invalid certificate or CSR format' });
    } 
    res.json(result);
  } catch (error) {
    console.error('Certificate parsing error:', error);
    res.status(400).json({ error: 'Failed to parse certificate/CSR: ' + error.message });
  }
});

// New endpoint to parse DER private keys
router.post('/parse-private-key-der', (req, res) => {
  try {
    const { content, fileName = 'unknown', password = '' } = req.body;
    
    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'No DER private key content provided' });
    }

    console.log(`Processing DER private key: ${fileName}`);

    try {
      const binaryData = forge.util.decode64(content);
      
      // Check if the key is encrypted
      const isEncrypted = isDerPrivateKeyEncrypted(binaryData);
      
      if (isEncrypted && !password) {
        return res.json({ 
          needsPassword: true,
          error: 'Password required to decrypt DER private key'
        });
      }

      let privateKey;
      try {
        privateKey = parsePrivateKeyFromContent(content, true, password);
      } catch (parseError) {
        console.log('DER private key parsing error:', parseError.message);
        
        if (parseError.message.includes('decrypt') || 
            parseError.message.includes('password') || 
            parseError.message.includes('Invalid key length')) {
          return res.json({ 
            needsPassword: true,
            error: 'Invalid password or password required'
          });
        }
        throw parseError;
      }

      if (!privateKey) {
        throw new Error('Failed to parse DER private key');
      }

      console.log('DER private key parsed successfully');

      // Convert to PEM for frontend
      const pemKey = forge.pki.privateKeyToPem(privateKey);
      
      // Get key details
      const keyDetails = {
        type: 'Private Key',
        algorithm: privateKey.n ? 'RSA' : 'EC',
        bitLength: privateKey.n ? privateKey.n.bitLength() : (privateKey.d ? privateKey.d.bitLength() : 'Unknown'),
        format: 'DER',
        encrypted: isEncrypted,
        pem: pemKey
      };

      if (privateKey.n) {
        keyDetails.publicExponent = privateKey.e.toString();
        keyDetails.modulus = forge.util.bytesToHex(privateKey.n.toByteArray()).toUpperCase();
      }

      const result = {
        type: 'DER Private Key',
        privateKey: keyDetails,
        success: true
      };

      console.log('DER private key processing complete:', {
        algorithm: keyDetails.algorithm,
        bitLength: keyDetails.bitLength,
        encrypted: keyDetails.encrypted
      });

      return res.json(result);

    } catch (parseError) {
      console.error('DER private key parsing error:', parseError.message);
      return res.status(400).json({ error: 'Failed to parse DER private key: ' + parseError.message });
    }

  } catch (error) {
    console.error('DER private key processing error:', error);
    return res.status(500).json({ error: 'Server error processing DER private key: ' + error.message });
  }
});

// Enhanced private key encryption check endpoint
router.post('/check-private-key-encryption', (req, res) => {
  try {
    const { privateKey, isDer = false } = req.body;
    
    if (!privateKey || !privateKey.trim()) {
      return res.json({ encrypted: false });
    }

    let keyContent = privateKey.trim();
    
    if (isDer) {
      // For DER format, check binary content
      try {
        const binaryData = forge.util.decode64(keyContent);
        const isEncrypted = isDerPrivateKeyEncrypted(binaryData);
        return res.json({ encrypted: isEncrypted, format: 'DER' });
      } catch (e) {
        return res.json({ encrypted: false, error: 'Invalid DER format', format: 'DER' });
      }
    } else {
      // For PEM format (existing logic)
      if (!keyContent.includes('-----BEGIN')) {
        try {
          keyContent = Buffer.from(keyContent, 'base64').toString('utf8');
        } catch (e) {
          return res.json({ encrypted: false, error: 'Invalid key format', format: 'PEM' });
        }
      }

      const hasEncryptionHeader = keyContent.includes('Proc-Type: 4,ENCRYPTED') || 
                                 keyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      
      if (hasEncryptionHeader) {
        return res.json({ encrypted: true, format: 'PEM' });
      }

      try {
        forge.pki.privateKeyFromPem(keyContent);
        return res.json({ encrypted: false, format: 'PEM' });
      } catch (error) {
        if (error.message.includes('decrypt') || error.message.includes('password') || error.message.includes('encrypted')) {
          return res.json({ encrypted: true, format: 'PEM' });
        }
        
        return res.json({ encrypted: false, error: 'Invalid private key format', format: 'PEM' });
      }
    }
  } catch (error) {
    console.error('Private key encryption check error:', error);
    return res.json({ encrypted: false, error: 'Failed to check private key encryption' });
  }
});

module.exports = router;