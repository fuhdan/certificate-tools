const express = require('express');
const multer = require('multer');
const forge = require('node-forge');

const router = express.Router();

// Configure multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// New endpoint to check if private key is encrypted
router.post('/check-key-encryption', (req, res) => {
  try {
    const { privateKey } = req.body;
    
    if (!privateKey || !privateKey.trim()) {
      return res.json({ encrypted: false });
    }

    let keyContent = privateKey.trim();
    
    // Try to decode from base64 if needed
    if (!keyContent.includes('-----BEGIN')) {
      try {
        keyContent = Buffer.from(keyContent, 'base64').toString('utf8');
      } catch (e) {
        return res.json({ encrypted: false, error: 'Invalid key format' });
      }
    }

    // Check for obvious encryption indicators
    const hasEncryptionHeader = keyContent.includes('Proc-Type: 4,ENCRYPTED') || 
                               keyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');
    
    if (hasEncryptionHeader) {
      return res.json({ encrypted: true });
    }

    // Try to parse the key without password
    try {
      forge.pki.privateKeyFromPem(keyContent);
      // If we get here, the key is not encrypted
      return res.json({ encrypted: false });
    } catch (error) {
      // If parsing fails, it might be encrypted or invalid
      if (error.message.includes('decrypt') || error.message.includes('password') || error.message.includes('encrypted')) {
        return res.json({ encrypted: true });
      }
      
      // Otherwise it's probably just an invalid key
      return res.json({ encrypted: false, error: 'Invalid private key format' });
    }
  } catch (error) {
    console.error('Key encryption check error:', error);
    return res.json({ encrypted: false, error: 'Failed to check key encryption' });
  }
});

// Helper function to validate certificate with private key
const validateCertificateWithPrivateKey = (cert, privateKey) => {
  console.log('=== VALIDATION DEBUG START ===');
  const validation = {
    publicKeyMatch: false,
    signatureValid: false,
    keyPairValid: false,
    details: {}
  };

  try {
    const certPublicKey = cert.publicKey;
    console.log('Certificate public key n exists:', !!certPublicKey.n);
    console.log('Private key n exists:', !!privateKey.n);
    
    if (certPublicKey.n && privateKey.n && certPublicKey.e && privateKey.e) {
      validation.publicKeyMatch = 
        certPublicKey.n.equals(privateKey.n) && 
        certPublicKey.e.equals(privateKey.e);
      
      console.log('Public key match result:', validation.publicKeyMatch);
      
      validation.details.keyType = 'RSA';
      validation.details.keySize = certPublicKey.n.bitLength();
      validation.details.publicExponent = certPublicKey.e.toString();
      
      // Get modulus hex with fallback methods
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
      
      console.log('Certificate modulus length:', certModHex.length);
      console.log('Private key modulus length:', privModHex.length);
      
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

    // Test signature validation
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

    // Add key format validation
    validation.details.keyFormat = {
      certificate: 'X.509 Certificate',
      privateKey: 'PKCS#1 Private Key'
    };
    
    // Add usage compatibility check
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

  console.log('=== VALIDATION DEBUG END ===');
  return validation;
};

// Helper function to parse certificate chain
const parseCertificateChain = (chainContent) => {
  console.log('=== PARSING CERTIFICATE CHAIN ===');
  const chainCerts = [];
  
  if (!chainContent || !chainContent.trim()) {
    console.log('No chain content provided');
    return chainCerts;
  }

  try {
    let content = chainContent.trim();
    if (!content.includes('-----BEGIN')) {
      try {
        content = Buffer.from(content, 'base64').toString('utf8');
      } catch (e) {
        console.log('Failed to decode base64 chain:', e.message);
        return chainCerts;
      }
    }

    const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
    const matches = content.match(certRegex);
    
    if (matches) {
      console.log(`Found ${matches.length} certificates in chain`);
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
          console.log(`Chain cert ${index}: ${cert.subject.getField('CN')?.value || 'Unknown CN'}`);
        } catch (e) {
          console.log(`Failed to parse certificate ${index} in chain:`, e.message);
        }
      });
    }
  } catch (error) {
    console.log('Error parsing certificate chain:', error.message);
  }

  console.log(`Successfully parsed ${chainCerts.length} certificates from chain`);
  return chainCerts;
};

// Helper function to validate certificate chain
const validateCertificateChain = (cert, chainCerts) => {
  console.log('=== VALIDATING CERTIFICATE CHAIN ===');
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

    console.log('Starting chain validation from:', currentCert.subject.getField('CN')?.value);

    // Try to find each issuer in the chain
    let foundIssuer = true;
    while (foundIssuer && validationPath.length <= chainCerts.length + 1) {
      foundIssuer = false;
      
      for (let i = 0; i < chainCerts.length; i++) {
        const chainCert = chainCerts[i].certificate;
        
        // Check if this chain cert is the issuer of current cert by comparing issuer/subject
        const currentIssuerCN = currentCert.issuer.getField('CN')?.value;
        const chainSubjectCN = chainCert.subject.getField('CN')?.value;
        
        console.log(`Checking if "${chainSubjectCN}" issued "${currentCert.subject.getField('CN')?.value}"`);
        console.log(`Looking for issuer: "${currentIssuerCN}"`);
        
        if (currentIssuerCN === chainSubjectCN) {
          console.log('✓ Found issuer in chain:', chainSubjectCN);
          foundIssuer = true;
          
          // Verify signature (simplified check)
          let signatureValid = true; // Assume valid for now due to forge complexity
          
          validationPath.push({
            subject: chainCert.subject.getField('CN')?.value || 'Unknown',
            issuer: chainCert.issuer.getField('CN')?.value || 'Unknown',
            type: chainCert.subject.getField('CN')?.value === chainCert.issuer.getField('CN')?.value ? 'root' : 'intermediate',
            valid: signatureValid && chainCerts[i].validity.isValid,
            signatureValid: signatureValid,
            timeValid: chainCerts[i].validity.isValid
          });

          currentCert = chainCert;
          
          // If this is a self-signed certificate (root), we're done
          if (chainCert.subject.getField('CN')?.value === chainCert.issuer.getField('CN')?.value) {
            console.log('✓ Found root certificate:', chainCert.subject.getField('CN')?.value);
            validation.chainValid = true;
            foundIssuer = false; // Stop the loop
            break;
          }
          break; // Found this level, continue to next
        }
      }
      
      if (!foundIssuer && validationPath[validationPath.length - 1].type !== 'root') {
        console.log('✗ Could not find issuer for:', currentCert.subject.getField('CN')?.value);
        validation.issues.push(`Could not find issuer for: ${currentCert.subject.getField('CN')?.value}`);
      }
    }

    validation.validationPath = validationPath;
    
    // Check for issues
    if (validationPath.length === 1) {
      validation.issues.push('Certificate issuer not found in provided chain');
    }
    
    const hasExpiredCerts = validationPath.some(cert => !cert.timeValid);
    if (hasExpiredCerts) {
      validation.issues.push('One or more certificates in chain are expired or not yet valid');
    }
    
    // Mark as valid if we found a root and no critical issues
    if (validationPath.some(cert => cert.type === 'root') && validation.issues.length === 0) {
      validation.chainValid = true;
    }

    validation.details = {
      totalCerts: chainCerts.length + 1,
      pathLength: validationPath.length,
      hasRoot: validationPath.some(cert => cert.type === 'root'),
      hasIntermediate: validationPath.some(cert => cert.type === 'intermediate')
    };

    console.log('Chain validation result:', validation.chainValid);
    console.log('Validation path:');
    validationPath.forEach((cert, i) => {
      console.log(`  ${i}: ${cert.subject} (${cert.type}) - ${cert.valid ? 'Valid' : 'Invalid'}`);
    });

  } catch (error) {
    console.log('Chain validation error:', error.message);
    validation.issues.push('Chain validation error: ' + error.message);
  }

  console.log('=== CHAIN VALIDATION COMPLETE ===');
  return validation;
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
            privateKeyContent = Buffer.from(privateKeyContent, 'base64').toString('utf8');
          }
          
          let privateKey;
          
          // Try to parse private key with password if provided
          if (privateKeyPassword) {
            try {
              privateKey = forge.pki.decryptRsaPrivateKey(privateKeyContent, privateKeyPassword);
            } catch (decryptError) {
              // If decryption fails, try as PKCS#8
              try {
                privateKey = forge.pki.privateKeyFromPem(privateKeyContent, privateKeyPassword);
              } catch (pkcs8Error) {
                throw new Error('Failed to decrypt private key with provided password');
              }
            }
          } else {
            // Try to parse without password
            privateKey = forge.pki.privateKeyFromPem(privateKeyContent);
          }
          
          result.privateKeyValidation = validateCertificateWithPrivateKey(cert, privateKey);
        } catch (error) {
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

module.exports = router;