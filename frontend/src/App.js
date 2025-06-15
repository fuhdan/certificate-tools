import React, { useState, useEffect, useCallback } from 'react';
import StatusIndicator from './components/StatusIndicator';
import Header from './components/Header';
import InputSection from './components/InputSection';
import ResultsSection from './components/ResultsSection';
import { checkServerStatus, parseCertificate, parsePrivateKeyDer, checkPrivateKeyEncryption } from './services/api';

function App() {
  // State variables
  const [certContent, setCertContent] = useState('');
  const [privateKeyContent, setPrivateKeyContent] = useState('');
  const [chainContent, setChainContent] = useState('');
  const [privateKeyPassword, setPrivateKeyPassword] = useState('');
  const [pkcs12Password, setPkcs12Password] = useState('');
  const [showPkcs12PasswordInput, setShowPkcs12PasswordInput] = useState(false);
  const [pendingPkcs12Data, setPendingPkcs12Data] = useState(null);
  const [serverStatus, setServerStatus] = useState('checking');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [privateKeyDragOver, setPrivateKeyDragOver] = useState(false);
  const [chainDragOver, setChainDragOver] = useState(false);
  const [chainAutoDetected, setChainAutoDetected] = useState(false);
  const [privateKeyAutoDetected, setPrivateKeyAutoDetected] = useState(false);
  const [originalFileInfo, setOriginalFileInfo] = useState(null);
  const [certificateInfo, setCertificateInfo] = useState({
    type: 'none',
    format: 'none',
    source: 'none',
    fileName: null,
    fileSize: null,
    uploadedAt: null
  });
  const [privateKeyInfo, setPrivateKeyInfo] = useState({
    type: 'none',
    format: 'none',
    source: 'none',
    fileName: null,
    fileSize: null,
    uploadedAt: null,
    encrypted: false
  });
  const [chainInfo, setChainInfo] = useState({
    type: 'none',
    format: 'none',
    source: 'none',
    fileName: null,
    fileSize: null,
    uploadedAt: null,
    certificateCount: 0
  });
  const [showRawData, setShowRawData] = useState(false);
  const [exportResults, setExportResults] = useState(false);
  const [detailedValidation, setDetailedValidation] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);
  const [passwordAccepted, setPasswordAccepted] = useState(false);
  const [pkcs12PasswordAccepted, setPkcs12PasswordAccepted] = useState(false);
  const [pendingPrivateKeyData, setPendingPrivateKeyData] = useState(null);

  // Computed values
  const hasPrivateKey = privateKeyContent.trim().length > 0;
  const isCurrentPrivateKeyEncrypted = hasPrivateKey && (
                                                          privateKeyContent.includes('Proc-Type: 4,ENCRYPTED') || 
                                                          privateKeyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')
                                                        );
  const isDerKeyWaitingForPassword =  privateKeyInfo.format === 'der' &&
                                      (
                                        !!pendingPrivateKeyData || // We have pending DER data waiting for password
                                        (privateKeyInfo.encrypted && !passwordAccepted) // Key info shows encrypted and password not accepted
                                      );
  const isPrivateKeyEncrypted = isCurrentPrivateKeyEncrypted || isDerKeyWaitingForPassword;
  const showPrivateKeyInput = results && results.type === 'Certificate';
  const showPasswordInput = showPrivateKeyInput && 
                            isPrivateKeyEncrypted && 
                            !passwordAccepted && 
                            privateKeyInfo.source !== 'auto';
  const showChainInput = results && results.type === 'Certificate';
  const hasCertificateWithKey = results && results.type === 'Certificate' && hasPrivateKey;
  const shouldShowPkcs12PasswordInput = showPkcs12PasswordInput && !pkcs12PasswordAccepted;

  console.log('Password input state debug:', {
    hasPrivateKey,
    isCurrentPrivateKeyEncrypted,
    isDerKeyWaitingForPassword,
    isPrivateKeyEncrypted,
    showPrivateKeyInput,
    passwordAccepted,
    privateKeyInfoFormat: privateKeyInfo.format,
    privateKeyInfoEncrypted: privateKeyInfo.encrypted,
    privateKeyInfoSource: privateKeyInfo.source,
    hasPendingData: !!pendingPrivateKeyData,
    pendingDataFormat: pendingPrivateKeyData?.format,
    showPasswordInput,
    privateKeyContentLength: privateKeyContent.length
  });

  // Helper function: debounced processing function
  const debounce = (func, wait) => {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  };

  // Helper function: Determine file type and format
  const getFileTypeInfo = (file, detectedFormat = null) => {
    const fileName = file.name.toLowerCase();
    const fileSize = file.size;
    
    let fileType = 'Unknown';
    let format = detectedFormat || 'Unknown';
    let description = '';

    // Determine file type based on extension and detected format
    if (fileName.endsWith('.p12') || fileName.endsWith('.pfx') || fileName.endsWith('.pkcs12')) {
      fileType = 'PKCS#12';
      format = 'Binary';
      description = 'Password-protected certificate bundle';
    } else if (fileName.endsWith('.p7b') || fileName.endsWith('.p7c')) {
      fileType = 'PKCS#7';
      format = fileName.endsWith('.p7b') ? 'DER' : 'PEM';
      description = 'Certificate chain bundle';
    } else if (fileName.endsWith('.der') || fileName.endsWith('.cer')) {
      fileType = 'Certificate';
      format = 'DER';
      description = 'Binary encoded certificate';
    } else if (fileName.endsWith('.crt') || fileName.endsWith('.pem')) {
      fileType = 'Certificate';
      format = 'PEM';
      description = 'Text encoded certificate';
    } else if (fileName.endsWith('.csr')) {
      fileType = 'CSR';
      format = 'PEM';
      description = 'Certificate signing request';
    } else if (fileName.endsWith('.key')) {
      fileType = 'Private Key';
      format = 'PEM';
      description = 'Private key file';
    } else if (fileName.endsWith('.txt')) {
      // Try to detect from content if available
      if (detectedFormat) {
        fileType = detectedFormat.includes('PKCS') ? detectedFormat : 'Certificate';
        format = 'PEM';
        description = 'Text file containing certificate data';
      } else {
        fileType = 'Text File';
        format = 'PEM';
        description = 'Plain text certificate data';
      }
    }

    return {
      fileName: file.name,
      fileSize: fileSize,
      fileType: fileType,
      format: format,
      description: description,
      uploadedAt: new Date().toLocaleString()
    };
  };

  // Helper function: Check if file is PKCS#12 format
  const isPkcs12File = (file) => {
    const lowerName = file.name.toLowerCase();
    return lowerName.endsWith('.p12') || 
           lowerName.endsWith('.pfx') || 
           lowerName.endsWith('.pkcs12');
  };

  // Helper function: Check if file is likely DER private key
  const isDerPrivateKeyFile = (file) => {
    const lowerName = file.name.toLowerCase();
    return lowerName.endsWith('.der') || 
          (lowerName.endsWith('.key') && !lowerName.includes('.pem'));
  };

  // Helper function: Process certificate content
  const processCertificate = async (content, privateKey = '', chain = '', password = '') => {
    if (!content.trim()) {
      setResults(null);
      return;
    }

    setLoading(true);
    setError('');

    try {
      const data = await parseCertificate(content.trim(), privateKey.trim(), chain.trim(), password.trim());
      setResults(data);
      setError('');

      // Check if password was successful for PEM keys
      if (privateKey.trim() && password.trim() && data.privateKeyValidation) {
        if (data.privateKeyValidation.keyPairValid || 
            (data.privateKeyValidation.publicKeyMatch && data.privateKeyValidation.signatureValid)) {
          console.log('PEM private key password accepted');
          setPasswordAccepted(true);
        } else if (data.privateKeyValidation.details && 
                   data.privateKeyValidation.details.error && 
                   (data.privateKeyValidation.details.error.includes('password') ||
                    data.privateKeyValidation.details.error.includes('decrypt'))) {
          // Password error
          setPasswordAccepted(false);
        }
      }
    } catch (err) {
      setError(err.message);
      setResults(null);

      // Check if it's a password-related error for PEM keys
      if (privateKey.trim() && password.trim() && 
          (err.message.includes('password') || 
           err.message.includes('decrypt') || 
           err.message.includes('Invalid password'))) {
        setPasswordAccepted(false);
      }
    } finally {
      setLoading(false);
    }
  };

  // Helper function: Debounced version of processCertificate
  const debouncedProcess = useCallback(debounce((content, privateKey, chain, password) => {
    processCertificate(content, privateKey, chain, password);
  }, 500), []);

  //Helper function: Debounced version of processCertificate with password check
  const debouncedProcessWithPasswordCheck = useCallback(debounce(async (content, privateKey, chain, password) => {
    setLoading(true);
    setError('');
    
    try {
      const data = await parseCertificate(content.trim(), privateKey.trim(), chain.trim(), password.trim());
      setResults(data);
      setError('');

      // If we have private key validation results and no error, password was accepted
      if (data.privateKeyValidation && password.trim()) {
        if (data.privateKeyValidation.keyPairValid) {
          console.log('PEM private key password accepted');
          setPasswordAccepted(true);
        } else if (data.privateKeyValidation.details && 
                   data.privateKeyValidation.details.error && 
                   data.privateKeyValidation.details.error.includes('password')) {
          // Password error - keep showing password input
          setPasswordAccepted(false);
        } else {
          // Other validation error but password was accepted
          setPasswordAccepted(true);
        }
      }
    } catch (err) {
      setError(err.message);
      setResults(null);

      // Check if it's a password-related error
      if (err.message.includes('password') || 
          err.message.includes('decrypt') || 
          err.message.includes('Invalid password')) {
        setPasswordAccepted(false);
      }
    } finally {
      setLoading(false);
    }
  }, 500), []);

  // Check server status
  const updateServerStatus = useCallback(async () => {
    try {
      const isOnline = await checkServerStatus();
      setServerStatus(isOnline ? 'online' : 'offline');
    } catch (error) {
      setServerStatus('offline');
    }
  }, []);

  // Handle text input change
  const handleTextChange = (e) => {
    const value = e.target.value;

    // If new content is being pasted/typed and we have existing results, clear all first
    if (value.trim() && value !== certContent && results) {
      handleClearAll();
    }

    setCertContent(value);
    
    // Update certificate info for manual input
    if (value.trim()) {
      setCertificateInfoFromManual(value);
    } else {
      setCertificateInfo({
        type: 'none',
        format: 'none',
        source: 'none',
        fileName: null,
        fileSize: null,
        uploadedAt: null
      });
    }
    
    debouncedProcess(value, privateKeyContent, chainContent, privateKeyPassword);
  };

  // Handle private key text input change
  const handlePrivateKeyTextChange = (e) => {
    const value = e.target.value;
    setPrivateKeyContent(value);
    
    // Clear password states when manually entering new content
    setPrivateKeyPassword('');
    setPasswordAccepted(false);
    setPendingPrivateKeyData(null);
    
    // Update private key info for manual input
    if (value.trim()) {
      setPrivateKeyInfoFromManual(value);

      // Check if the new content is encrypted
      const isEncrypted = value.includes('Proc-Type: 4,ENCRYPTED') || 
                         value.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');

      // Only auto-process if the key is NOT encrypted
      if (certContent.trim() && !isEncrypted) {
        debouncedProcess(certContent, value, chainContent, '');
      }
      // If encrypted, don't auto-process - wait for password
    } else {
      setPrivateKeyInfo({
        type: 'none',
        format: 'none',
        source: 'none',
        fileName: null,
        fileSize: null,
        uploadedAt: null,
        encrypted: false
      });

      // If content is empty, process the certificate without private key
      if (certContent.trim()) {
        debouncedProcess(certContent, '', chainContent, '');
      }
    }
  };

  // Unified private key processing function
  const processPrivateKeyContent = async (content, fileName, format, password = '') => {
    setLoading(true);
    setError('');
    
    try {
      console.log('Processing private key:', {
        fileName: fileName,
        format: format,
        contentLength: content.length,
        hasPassword: password.length > 0
      });

      let data;
      if (format === 'der') {
        data = await parsePrivateKeyDer(content, fileName, password);

        console.log('DER processing result:', {
          needsPassword: data.needsPassword,
          hasError: !!data.error,
          success: !!data.privateKey
        });

      } else {
        // For PEM, use existing certificate parsing
        if (certContent.trim()) {
          await processCertificate(certContent, privateKeyContent, chainContent, password);
          setLoading(false);
          return;
        }
      }

      if (data && data.needsPassword && !password) {
        console.log('DER key needs password - showing password input');

        // Store the content and show password input
        setPendingPrivateKeyData({ content: content, fileName: fileName, format: format });
        setPasswordAccepted(false);

        // IMPORTANT: Update private key info to show it's encrypted and needs password
        setPrivateKeyInfo(prev => ({
          ...prev,
          encrypted: true, // Mark as encrypted
          type: 'encrypted' // Update type to show it's encrypted
        }));

        // Don't set any private key content yet - wait for password
        setPrivateKeyContent('');

        setLoading(false);
        return;
      }

      if (data && data.error && !data.needsPassword) {
        throw new Error(data.error);
      }

      // Success - password was correct or key wasn't encrypted
      console.log('DER key processed successfully');

      setPasswordAccepted(true);
      setPendingPrivateKeyData(null);
      setPrivateKeyPassword('');

      // Set the private key content as PEM (for DER files)
      if (data && data.privateKey && data.privateKey.pem) {
        setPrivateKeyContent(data.privateKey.pem);

        // Update private key info to show it's no longer encrypted
        setPrivateKeyInfo({
          type: data.privateKey.algorithm.toLowerCase(),
          format: 'der', // Keep original format for reference
          source: 'file',
          fileName: fileName,
          fileSize: data.privateKey.pem.length,
          uploadedAt: new Date().toLocaleString(),
          encrypted: false // No longer encrypted - successfully decrypted
        });

        // Re-process certificate with new private key (no password needed)
        if (certContent.trim()) {
          processCertificate(certContent, data.privateKey.pem, chainContent, '');
        }
      }

      setError('');

    } catch (err) {
      console.error('Private Key Error:', err.message);
      setError(`Failed to parse ${format.toUpperCase()} private key: ` + err.message);

      // If it's a password error, show password input
      if (err.message.includes('password') || err.message.includes('decrypt')) {
        console.log('DER key password error - showing password input');

        setPendingPrivateKeyData({ content: content, fileName: fileName, format: format });
        setPasswordAccepted(false);

        // Update private key info to show it's encrypted and needs password
        setPrivateKeyInfo(prev => ({
          ...prev,
          encrypted: true,
          type: 'encrypted'
        }));

        // Clear any private key content
        setPrivateKeyContent('');
      }
    } finally {
      setLoading(false);
    }
  };

  // Handle private key password input change
  const handlePrivateKeyPasswordChange = (e) => {
    const value = e.target.value;
    setPrivateKeyPassword(value);
    
    // If we have pending private key data (DER), try to process it
    if (pendingPrivateKeyData) {
      processPrivateKeyContent(
        pendingPrivateKeyData.content, 
        pendingPrivateKeyData.fileName, 
        pendingPrivateKeyData.format,
        value
      );
    } else if (certContent.trim() && privateKeyContent.trim()) {
      // For PEM keys, process immediately (no debounce for password changes)
      processCertificate(certContent, privateKeyContent, chainContent, value);
    }
  };

  // Handle PKCS#12 password input change
  const handlePkcs12PasswordChange = (e) => {
    const value = e.target.value;
    setPkcs12Password(value);
    
    // If we have pending PKCS#12 data, try to process it with the new password
    if (pendingPkcs12Data) {
      processPkcs12ContentWithPassword(pendingPkcs12Data.content, pendingPkcs12Data.fileName, value);
    }
  };

  // Handle chain text input change
  const handleChainTextChange = (e) => {
    const value = e.target.value;
    setChainContent(value);
    
    // Update chain info for manual input
    if (value.trim()) {
      setChainInfoFromManual(value);
    } else {
      setChainInfo({
        type: 'none',
        format: 'none',
        source: 'none',
        fileName: null,
        fileSize: null,
        uploadedAt: null,
        certificateCount: 0
      });
    }
    
    // Re-process certificate with new chain
    if (certContent.trim()) {
      debouncedProcess(certContent, privateKeyContent, value, privateKeyPassword);
    }
  };

  // Handle file drop
  const handleFileDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFile(files[0]);
    }
  };

  // Handle private key file drop
  const handlePrivateKeyFileDrop = (e) => {
    e.preventDefault();
    setPrivateKeyDragOver(false);
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handlePrivateKeyFile(files[0]);
    }
  };

  // Handle chain file drop
  const handleChainFileDrop = (e) => {
    e.preventDefault();
    setChainDragOver(false);
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleChainFile(files[0]);
    }
  };

  // Handle file input
  const handleFileInput = (e) => {
    if (e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  };

  // Handle private key file input
  const handlePrivateKeyFileInput = (e) => {
    if (e.target.files.length > 0) {
      handlePrivateKeyFile(e.target.files[0]);
    }
  };

  // Handle chain file input
  const handleChainFileInput = (e) => {
    if (e.target.files.length > 0) {
      handleChainFile(e.target.files[0]);
    }
  };

  // Check if file is likely DER format
  const isDerFile = (file) => {
    const lowerName = file.name.toLowerCase();
    return lowerName.endsWith('.der') || 
           lowerName.endsWith('.cer') || 
           lowerName.endsWith('.crt');
  };

  // Process dropped/selected file
  const handleFile = (file) => {
    console.log('Processing file:', file.name, 'Size:', file.size);
    
    // Clear all existing data when a new file is uploaded
    if (results || certContent.trim() || privateKeyContent.trim() || chainContent.trim()) {
      handleClearAll();
    }

    // Check if this is a PKCS#12 file first
    if (isPkcs12File(file)) {
      console.log('PKCS#12 format detected based on file extension');
      // Set certificate info for PKCS#12
      setCertificateInfo(detectCertificateInfo(file, null, 'PKCS#12'));

      const reader = new FileReader();
      reader.onload = (e) => {
        const arrayBuffer = e.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);
        const base64String = btoa(String.fromCharCode.apply(null, uint8Array));
        console.log('Converting PKCS#12 to base64 for processing');
        processPkcs12ContentWithPassword(base64String, file.name); // Use the correct function name
      };
      reader.readAsArrayBuffer(file);
      return;
    }

    // Check if this is likely a DER file
    if (isDerFile(file)) {
      console.log('DER format suspected based on file extension');
      // Set certificate info for DER
      setCertificateInfo(detectCertificateInfo(file, null, 'Certificate'));

      const reader = new FileReader();
      reader.onload = (e) => {
        const arrayBuffer = e.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);
        const base64String = btoa(String.fromCharCode.apply(null, uint8Array));
        console.log('Converting DER to base64 for processing');
        processContent(base64String, file.name, true); // true indicates DER format
      };
      reader.readAsArrayBuffer(file);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      console.log('File content loaded, length:', content.length);
      console.log('Content preview:', content.substring(0, 100));

      // Check if this is PKCS#7 format
      const isPkcs7Pem = content.includes('-----BEGIN PKCS7-----') || content.includes('-----BEGIN CERTIFICATE-----');
      const isPkcs7Der = !content.includes('-----BEGIN') && file.name.toLowerCase().endsWith('.p7b');

      if (isPkcs7Pem || isPkcs7Der) {
        console.log('PKCS#7 format detected, sending to backend for parsing');
        // Set certificate info for PKCS#7
        setCertificateInfo(detectCertificateInfo(file, content, 'PKCS#7'));
        // Send PKCS#7 content to backend for parsing
        processPkcs7Content(content, file.name);
        return;
      }

      // Check if this is a regular certificate chain (multiple certificates)
      const certMatches = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      const certCount = certMatches ? certMatches.length : 0;

      console.log('Detected certificates in file:', certCount);

      if (certCount > 1) {
        // This is a certificate chain - split it
        console.log('Certificate chain detected, splitting...');
        // Set certificate info for the main certificate
        setCertificateInfo(detectCertificateInfo(file, content, 'Certificate'));
        // Set chain info for auto-detected chain
        setChainInfo({
          ...detectChainInfo(file, content, true),
          certificateCount: certCount - 1 // Exclude the main certificate
        });

        const firstCert = certMatches[0];
        const chainCerts = certMatches.slice(1).join('\n');

        console.log('Setting first certificate as main cert');
        console.log('Setting remaining certificates as chain');

        setCertContent(firstCert);
        setChainContent(chainCerts);

        // Process with the split content
        processCertificate(firstCert, privateKeyContent, chainCerts, privateKeyPassword);
      } else {
        // Single certificate or CSR
        // Detect if it's a CSR or Certificate
        let detectedType = 'Certificate';
        if (content.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
          detectedType = 'CSR';
        }
        setCertificateInfo(detectCertificateInfo(file, content, detectedType));
        processContent(content, file.name);
      }
    };
    reader.onerror = (e) => {
      console.error('File reading error:', e);
      setError('Failed to read file');
    };

    // Read as text for PEM format, or as array buffer for potential DER format
    if (file.name.toLowerCase().endsWith('.p7b') || file.name.toLowerCase().endsWith('.p7c')) {
      reader.readAsArrayBuffer(file);
      reader.onload = (e) => {
        // Convert ArrayBuffer to base64 for backend processing
        const arrayBuffer = e.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);
        const base64String = btoa(String.fromCharCode.apply(null, uint8Array));
        console.log('PKCS#7 DER format detected, converting to base64');
        setCertificateInfo(detectCertificateInfo(file, null, 'PKCS#7'));
        processPkcs7Content(base64String, file.name, true); // true indicates DER format
      };
    } else {
      reader.readAsText(file);
    }
  };

  // Process PKCS#12 content
  const processPkcs12ContentWithPassword = async (base64Content, fileName, password = '') => {
    setLoading(true);
    setError('');
    
    try {
      console.log('API Request /api/parse-pkcs12:', {
        fileName: fileName,
        contentLength: base64Content.length,
        hasPassword: password.length > 0
      });

      const requestBody = { 
        content: base64Content,
        fileName: fileName,
        password: password
      };

      const response = await fetch(`${process.env.REACT_APP_API_URL || ''}/api/parse-pkcs12`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });

      const data = await response.json();

      console.log('API Response:', {
        status: response.status,
        needsPassword: data.needsPassword,
        type: data.type,
        hasCertificate: !!data.certificate,
        hasPrivateKey: !!data.privateKey,
        hasChain: data.certificateChain ? data.certificateChain.length : 0
      });

      if (data.needsPassword && !password) {
        // Store the content and show password input
        setPendingPkcs12Data({ content: base64Content, fileName: fileName });
        setShowPkcs12PasswordInput(true);
        setPkcs12PasswordAccepted(false);
        setLoading(false);
        return;
      }

      if (data.error) {
        throw new Error(data.error);
      }

      // Success - hide password input and clear pending data
      setShowPkcs12PasswordInput(false);
      setPkcs12PasswordAccepted(true);
      setPendingPkcs12Data(null);
      setPkcs12Password('');

      // Set the certificate content
      if (data.certificate && data.certificate.pem) {
        setCertContent(data.certificate.pem);
        setResults(data.certificate);

        // Update certificate info for PKCS#12
        setCertificateInfo({
          type: 'pkcs12',
          format: 'binary',
          source: 'file',
          fileName: fileName,
          fileSize: base64Content.length,
          uploadedAt: new Date().toLocaleString()
        });
      }

      // Set the private key content if available
      if (data.privateKey && data.privateKey.pem) {
        setPrivateKeyContent(data.privateKey.pem);
        setPrivateKeyAutoDetected(true);

        // Set private key info for auto-extracted key
        setPrivateKeyInfo({
          type: 'auto',
          format: 'pem',
          source: 'auto',
          fileName: fileName,
          fileSize: data.privateKey.pem.length,
          uploadedAt: new Date().toLocaleString(),
          encrypted: false // Already decrypted
        });

        // Clear any password states since key was auto-extracted
        setPrivateKeyPassword('');
        setPasswordAccepted(true);
      }

      // Set the certificate chain if available
      if (data.certificateChain && data.certificateChain.length > 0) {
        const chainPems = data.certificateChain.map(cert => cert.pem || 
          `-----BEGIN CERTIFICATE-----\n${cert.subject}\n-----END CERTIFICATE-----`).join('\n');
        setChainContent(chainPems);
        setChainAutoDetected(true);
        
        // Set chain info for auto-extracted chain
        setChainInfo({
          type: 'auto',
          format: 'pem',
          source: 'auto',
          fileName: fileName,
          fileSize: chainPems.length,
          uploadedAt: new Date().toLocaleString(),
          certificateCount: data.certificateChain.length
        });
      }

      // Log successful extraction summary
      console.log('PKCS#12 processing complete:', {
        hasCertificate: !!data.certificate,
        hasPrivateKey: !!data.privateKey,
        chainLength: data.certificateChain ? data.certificateChain.length : 0,
        keyPairValid: data.certificate?.privateKeyValidation?.keyPairValid || false,
        chainValid: data.certificate?.chainValidation?.chainValid || false
      });

      setError('');

    } catch (err) {
      console.error('PKCS#12 Error:', err.message);
      setError('Failed to parse PKCS#12 file: ' + err.message);

      // If it's a password error, show password input
      if (err.message.includes('password') || 
          err.message.includes('decrypt') || 
          err.message.includes('Invalid password') ||
          err.message.includes('MAC verification failed')) {
        setPendingPkcs12Data({ content: base64Content, fileName: fileName });
        setShowPkcs12PasswordInput(true);
        setPkcs12PasswordAccepted(false);
      }
    } finally {
      setLoading(false);
    }
  };

  // Process content (either PEM text or base64 DER)
  const processContent = (content, fileName, isDer = false) => {
    if (isDer) {
      console.log('Processing DER format certificate');
      // Send DER content to backend for parsing
      processDerCertificate(content, fileName);
    } else {
      setCertContent(content);
      processCertificate(content, privateKeyContent, chainContent, privateKeyPassword);
    }
  };

  // Process DER format certificate
  const processDerCertificate = async (base64Content, fileName) => {
    setLoading(true);
    setError('');
    
    try {
      console.log('API Request /api/parse-der:', {
        fileName: fileName,
        contentLength: base64Content.length
      });
      
      const requestBody = { 
        content: base64Content,
        fileName: fileName,
        privateKey: privateKeyContent.trim(),
        chain: chainContent.trim(),
        privateKeyPassword: privateKeyPassword.trim()
      };
      
      const response = await fetch(`${process.env.REACT_APP_API_URL || ''}/api/parse-der`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });
      
      const data = await response.json();
      
      console.log('API Response:', {
        status: response.status,
        type: data.type,
        subject: data.subject ? data.subject.find(attr => attr.shortName === 'CN')?.value || 'Unknown CN' : 'N/A'
      });
      
      if (data.error) {
        throw new Error(data.error);
      }
      
      // Set the results and convert DER to PEM for display
      setResults(data);
      if (data.raw && data.raw.pem) {
        setCertContent(data.raw.pem);
      }
      setError('');
      
    } catch (err) {
      console.error('DER Certificate Error:', err.message);
      setError('Failed to parse DER certificate: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Process dropped/selected private key file
  const handlePrivateKeyFile = (file) => {
    console.log('Processing private key file:', file.name, 'Size:', file.size);
    
    // Clear ALL password and encryption states when uploading new file
    setPrivateKeyPassword('');
    setPasswordAccepted(false);
    setPendingPrivateKeyData(null);
    setPrivateKeyContent(''); // Clear existing content
    
    // Check if this is a DER private key file
    if (isDerPrivateKeyFile(file)) {
      console.log('DER private key format detected based on file extension');

      // Set initial private key info for DER - assume it might be encrypted
      setPrivateKeyInfo({
        type: 'unknown',
        format: 'der',
        source: 'file',
        fileName: file.name,
        fileSize: file.size,
        uploadedAt: new Date().toLocaleString(),
        encrypted: false // Will be updated based on processing result
      });

      const reader = new FileReader();
      reader.onload = (e) => {
        const arrayBuffer = e.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);
        const base64String = btoa(String.fromCharCode.apply(null, uint8Array));
        console.log('Converting DER private key to base64 for processing');

        // Don't set privateKeyContent here - let processPrivateKeyContent handle it
        processPrivateKeyContent(base64String, file.name, 'der');
      };
      reader.readAsArrayBuffer(file);
      return;
    }

    // PEM processing (unchanged)
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      setPrivateKeyContent(content);

      // Set private key info for file upload
      setPrivateKeyInfo(detectPrivateKeyInfo(file, content, false));

      // Check if encrypted before auto-processing
      const isEncrypted = content.includes('Proc-Type: 4,ENCRYPTED') || 
                         content.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');

      // Only auto-process if not encrypted
      if (certContent.trim() && !isEncrypted) {
        processCertificate(certContent, content, chainContent, '');
      }
    };
    reader.readAsText(file);
  };

  // Process dropped/selected chain file
  const handleChainFile = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      setChainContent(content);
      
      // Set chain info for file upload
      setChainInfo(detectChainInfo(file, content, false));
      
      // Re-process certificate with new chain
      if (certContent.trim()) {
        processCertificate(certContent, privateKeyContent, content, privateKeyPassword);
      }
    };
    reader.readAsText(file);
  };

  // Drag handlers for certificate
  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  // Drag handlers for private key
  const handlePrivateKeyDragOver = (e) => {
    e.preventDefault();
    setPrivateKeyDragOver(true);
  };

  const handlePrivateKeyDragLeave = () => {
    setPrivateKeyDragOver(false);
  };

  // Drag handlers for chain
  const handleChainDragOver = (e) => {
    e.preventDefault();
    setChainDragOver(true);
  };

  const handleChainDragLeave = () => {
    setChainDragOver(false);
  };

  // Control panel functions
  const handleClearAll = () => {
    setCertContent('');
    setPrivateKeyContent('');
    setChainContent('');
    setPrivateKeyPassword('');
    setPkcs12Password('');
    setPasswordAccepted(false);
    setPkcs12PasswordAccepted(false);
    setShowPkcs12PasswordInput(false);
    setPendingPkcs12Data(null);
    setPendingPrivateKeyData(null);
    setChainAutoDetected(false);
    setPrivateKeyAutoDetected(false);
    setCertificateInfo({
      type: 'none',
      format: 'none',
      source: 'none',
      fileName: null,
      fileSize: null,
      uploadedAt: null
    });

    setPrivateKeyInfo({
      type: 'none',
      format: 'none',
      source: 'none',
      fileName: null,
      fileSize: null,
      uploadedAt: null,
      encrypted: false
    });

    setChainInfo({
      type: 'none',
      format: 'none',
      source: 'none',
      fileName: null,
      fileSize: null,
      uploadedAt: null,
      certificateCount: 0
    });

    setResults(null);
    setError('');
  };

  const handleDownloadReport = () => {
    if (!results) return;
    
    const report = {
      timestamp: new Date().toISOString(),
      type: results.type,
      subject: results.subject,
      ...(results.type === 'Certificate' && {
        issuer: results.issuer,
        validity: results.validity,
        serialNumber: results.serialNumber
      }),
      publicKey: results.publicKey,
      signature: results.signature,
      ...(results.subjectAlternativeNames && { sans: results.subjectAlternativeNames }),
      ...(results.extensions && { extensions: results.extensions }),
      ...(results.privateKeyValidation && { validation: results.privateKeyValidation }),
      // Include file tracking information
      fileInfo: {
        certificate: certificateInfo,
        privateKey: privateKeyInfo,
        chain: chainInfo
      },
      ...(showRawData && results.raw && { raw: results.raw })
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `certificate-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyDetails = async () => {
    if (!results) return;
    
    let text = `Certificate Analysis Report\n`;
    text += `Generated: ${new Date().toLocaleString()}\n\n`;
    text += `Type: ${results.type}\n`;
    
    // Add file information
    text += `\nFile Information:\n`;
    text += `  Certificate: ${certificateInfo.type} (${certificateInfo.format}, ${certificateInfo.source})\n`;
    if (privateKeyInfo.type !== 'none') {
      text += `  Private Key: ${privateKeyInfo.type} (${privateKeyInfo.format}, ${privateKeyInfo.source})\n`;
    }
    if (chainInfo.type !== 'none') {
      text += `  Chain: ${chainInfo.type} (${chainInfo.format}, ${chainInfo.source}, ${chainInfo.certificateCount} certs)\n`;
    }
    
    // Add subject info
    text += `\nSubject:\n`;
    results.subject.forEach(attr => {
      text += `  ${attr.shortName || attr.name}: ${attr.value}\n`;
    });
    
    // Add SANs if present
    if (results.subjectAlternativeNames) {
      text += `\nSubject Alternative Names:\n`;
      results.subjectAlternativeNames.forEach(san => {
        text += `  ${san.typeName}: ${san.value}\n`;
      });
    }
    
    // Add validation results if present
    if (results.privateKeyValidation) {
      text += `\nPrivate Key Validation:\n`;
      text += `  Public Key Match: ${results.privateKeyValidation.publicKeyMatch ? 'Valid' : 'Invalid'}\n`;
      text += `  Signature Valid: ${results.privateKeyValidation.signatureValid ? 'Valid' : 'Invalid'}\n`;
      text += `  Key Pair Valid: ${results.privateKeyValidation.keyPairValid ? 'Valid' : 'Invalid'}\n`;
    }
    
    try {
      // Try the modern clipboard API first
      await navigator.clipboard.writeText(text);
      console.log('Certificate details copied to clipboard');
    } catch (err) {
      // Fallback method for older browsers or when clipboard API fails
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';  // Prevent scrolling to bottom
      document.body.appendChild(textarea);
      textarea.select();
      
      try {
        document.execCommand('copy');
        console.log('Certificate details copied using fallback method');
      } catch (err) {
        console.error('Failed to copy text:', err);
      } finally {
        document.body.removeChild(textarea);
      }
    }
  };

  // Process PKCS#7 content
  const processPkcs7Content = async (content, fileName, isDer = false) => {
    setLoading(true);
    setError('');
    
    try {
      console.log('API Request /api/parse-pkcs7:', {
        fileName: fileName,
        isDer: isDer,
        contentLength: content.length
      });
      
      const requestBody = { 
        content: content,
        isDer: isDer,
        fileName: fileName
      };
      
      const response = await fetch(`${process.env.REACT_APP_API_URL || ''}/api/parse-pkcs7`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });
      
      const data = await response.json();
      
      console.log('API Response:', {
        status: response.status,
        type: data.type,
        certificateCount: data.certificateCount,
        certificates: data.certificates ? data.certificates.map(cert => 
          cert.subject.find(attr => attr.shortName === 'CN')?.value || 'Unknown CN'
        ) : []
      });
      
      if (data.error) {
        throw new Error(data.error);
      }
      
      if (data.certificates && data.certificates.length > 0) {
        // Set the first certificate as the main certificate
        const firstCert = data.certificates[0].pem;
        setCertContent(firstCert);
        
        if (data.certificates.length > 1) {
          // Set remaining certificates as chain
          const chainCerts = data.certificates.slice(1).map(cert => cert.pem).join('\n');
          setChainContent(chainCerts);
          // Set chain info for auto-extracted chain from PKCS#7
          setChainInfo({
            type: 'pkcs7',
            format: isDer ? 'der' : 'pem',
            source: 'auto',
            fileName: fileName,
            fileSize: chainCerts.length,
            uploadedAt: new Date().toLocaleString(),
            certificateCount: data.certificates.length - 1
          });
          
          // Process with split content
          processCertificate(firstCert, privateKeyContent, chainCerts, privateKeyPassword);
        } else {
          // Single certificate in PKCS#7
          processCertificate(firstCert, privateKeyContent, chainContent, privateKeyPassword);
        }
      } else {
        throw new Error('No certificates found in PKCS#7 file');
      }
      
    } catch (err) {
      console.error('PKCS#7 Error:', err.message);
      setError('Failed to parse PKCS#7 file: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const detectCertificateInfo = (file, content = null, detectedType = null) => {
    const fileName = file.name.toLowerCase();
    const fileSize = file.size;
    const uploadedAt = new Date().toLocaleString();
    
    let type = 'certificate';
    let format = 'pem';
    let source = 'file';

    // Determine type and format based on file extension and content
    if (fileName.endsWith('.p12') || fileName.endsWith('.pfx') || fileName.endsWith('.pkcs12')) {
      type = 'pkcs12';
      format = 'binary';
    } else if (fileName.endsWith('.p7b') || fileName.endsWith('.p7c')) {
      type = 'pkcs7';
      format = fileName.endsWith('.p7b') ? 'der' : 'pem';
    } else if (fileName.endsWith('.der') || fileName.endsWith('.cer')) {
      type = 'certificate';
      format = 'der';
    } else if (fileName.endsWith('.csr')) {
      type = 'csr';
      format = 'pem';
    } else if (content) {
      // Detect from content
      if (content.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
        type = 'csr';
      } else if (content.includes('-----BEGIN PKCS7-----')) {
        type = 'pkcs7';
      } else if (content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)?.length > 1) {
        type = 'chain';
      }
    }

    if (detectedType) {
      type = detectedType.toLowerCase();
    }

    return {
      type,
      format,
      source,
      fileName: file.name,
      fileSize,
      uploadedAt
    };
  };

  const detectPrivateKeyInfo = (file, content = null, isAuto = false) => {
    const fileName = file.name.toLowerCase();
    const fileSize = file.size;
    const uploadedAt = new Date().toLocaleString();
    
    let type = 'rsa'; // default assumption
    let format = 'pem';
    let source = isAuto ? 'auto' : 'file';
    let encrypted = false;

    // Detect format from file extension first
    if (fileName.endsWith('.der') || (fileName.endsWith('.key') && !fileName.includes('.pem'))) {
      format = 'der';
    }

    if (content && format === 'pem') {
      // Detect encryption for PEM
      encrypted = content.includes('Proc-Type: 4,ENCRYPTED') || 
                 content.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');

      // Detect type from PEM content
      if (content.includes('-----BEGIN EC PRIVATE KEY-----')) {
        type = 'ec';
        format = 'traditional';
      } else if (content.includes('-----BEGIN PRIVATE KEY-----')) {
        format = 'pkcs8';
      } else if (content.includes('-----BEGIN RSA PRIVATE KEY-----')) {
        type = 'rsa';
        format = 'traditional';
      } else if (content.includes('-----BEGIN DSA PRIVATE KEY-----')) {
        type = 'dsa';
        format = 'traditional';
      }

      if (encrypted) {
        type = 'encrypted';
      }
    } else if (format === 'der') {
      // For DER files, we'll detect encryption after trying to parse
      type = 'unknown'; // Will be determined after parsing
    }

    return {
      type,
      format,
      source,
      fileName: file.name,
      fileSize,
      uploadedAt,
      encrypted
    };
  };

  const detectChainInfo = (file, content = null, isAuto = false) => {
    const fileName = file.name.toLowerCase();
    const fileSize = file.size;
    const uploadedAt = new Date().toLocaleString();
    
    let type = 'chain';
    let format = 'pem';
    let source = isAuto ? 'auto' : 'file';
    let certificateCount = 0;

    if (fileName.endsWith('.p7b') || fileName.endsWith('.p7c')) {
      type = 'pkcs7';
      format = fileName.endsWith('.p7b') ? 'der' : 'pem';
    }

    if (content) {
      // Count certificates in chain
      const certMatches = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      certificateCount = certMatches ? certMatches.length : 0;
      
      if (certificateCount > 1) {
        type = 'chain';
      } else if (certificateCount === 1) {
        type = 'bundle';
      }
    }

    return {
      type,
      format,
      source,
      fileName: file.name,
      fileSize,
      uploadedAt,
      certificateCount
    };
  };

  // Updated function to set certificate info from manual input
  const setCertificateInfoFromManual = (content) => {
    let type = 'certificate';
    let format = 'pem';
    
    if (content.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
      type = 'csr';
    } else if (content.includes('-----BEGIN PKCS7-----')) {
      type = 'pkcs7';
    }

    setCertificateInfo({
      type,
      format,
      source: 'manual',
      fileName: null,
      fileSize: content.length,
      uploadedAt: new Date().toLocaleString()
    });
  };

  // Updated function to set private key info from manual input
  const setPrivateKeyInfoFromManual = (content) => {
    let type = 'rsa';
    let format = 'pem';
    let encrypted = false;

    if (content.includes('-----BEGIN EC PRIVATE KEY-----')) {
      type = 'ec';
      format = 'traditional';
    } else if (content.includes('-----BEGIN PRIVATE KEY-----')) {
      format = 'pkcs8';
    } else if (content.includes('-----BEGIN RSA PRIVATE KEY-----')) {
      type = 'rsa';
      format = 'traditional';
    } else if (content.includes('-----BEGIN DSA PRIVATE KEY-----')) {
      type = 'dsa';
      format = 'traditional';
    }

    encrypted = content.includes('Proc-Type: 4,ENCRYPTED') || 
               content.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');

    if (encrypted) {
      type = 'encrypted';
    }

    setPrivateKeyInfo({
      type,
      format,
      source: 'manual',
      fileName: null,
      fileSize: content.length,
      uploadedAt: new Date().toLocaleString(),
      encrypted
    });
  };

  // Updated function to set chain info from manual input
  const setChainInfoFromManual = (content) => {
    const certMatches = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    const certificateCount = certMatches ? certMatches.length : 0;
    
    let type = 'chain';
    if (certificateCount === 1) {
      type = 'bundle';
    } else if (certificateCount === 0) {
      type = 'none';
    }

    setChainInfo({
      type,
      format: 'pem',
      source: 'manual',
      fileName: null,
      fileSize: content.length,
      uploadedAt: new Date().toLocaleString(),
      certificateCount
    });
  };

  // Check status on mount and every 30 seconds
  useEffect(() => {
    updateServerStatus();
    const interval = setInterval(updateServerStatus, 30000);
    return () => clearInterval(interval);
  }, [updateServerStatus]);

  return (
    <div className="App">
      <div className="main-layout">
        <div className="content-area">
          <Header />
          
          <InputSection
            certContent={certContent}
            onTextChange={handleTextChange}
            dragOver={dragOver}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleFileDrop}
            onFileSelect={handleFileInput}
            privateKeyContent={privateKeyContent}
            onPrivateKeyTextChange={handlePrivateKeyTextChange}
            privateKeyDragOver={privateKeyDragOver}
            onPrivateKeyDragOver={handlePrivateKeyDragOver}
            onPrivateKeyDragLeave={handlePrivateKeyDragLeave}
            onPrivateKeyDrop={handlePrivateKeyFileDrop}
            onPrivateKeyFileSelect={handlePrivateKeyFileInput}
            showPrivateKeyInput={showPrivateKeyInput}
            privateKeyAutoDetected={privateKeyInfo.source === 'auto'}
            privateKeyPassword={privateKeyPassword}
            onPrivateKeyPasswordChange={handlePrivateKeyPasswordChange}
            showPasswordInput={showPasswordInput}
            privateKeyInfo={privateKeyInfo}
            chainContent={chainContent}
            onChainTextChange={handleChainTextChange}
            chainDragOver={chainDragOver}
            onChainDragOver={handleChainDragOver}
            onChainDragLeave={handleChainDragLeave}
            onChainDrop={handleChainFileDrop}
            onChainFileSelect={handleChainFileInput}
            showChainInput={showChainInput}
            chainAutoDetected={chainInfo.source === 'auto'}
            pkcs12Password={pkcs12Password}
            onPkcs12PasswordChange={handlePkcs12PasswordChange}
            showPkcs12PasswordInput={shouldShowPkcs12PasswordInput}
            results={results}
          />

          {(results || loading || error) && (
            <ResultsSection
              results={results}
              loading={loading}
              error={error}
              showRawData={showRawData}
              detailedValidation={detailedValidation}
            />
          )}
        </div>
        
        <div className="control-panel">
          <h3>Control Panel</h3>
          
          {/* Server Status */}
          <div className="control-section">
            <h4>Server Status</h4>
            <div className="server-status">
              <div className={`status-indicator-panel ${serverStatus}`}>
                <div className={`status-dot ${serverStatus}`}></div>
                <span>{serverStatus === 'online' ? 'Connected' : serverStatus === 'offline' ? 'Disconnected' : 'Checking...'}</span>
              </div>
            </div>
          </div>
          

          
          <div className="control-section">
            <h4>Display Options</h4>
            <div className="control-item">
              <label>
                <input 
                  type="checkbox" 
                  checked={showRawData}
                  onChange={(e) => setShowRawData(e.target.checked)}
                />
                Show Raw Data (PEM, Fingerprints)
              </label>
            </div>
            <div className="control-item">
              <label>
                <input 
                  type="checkbox" 
                  checked={exportResults}
                  onChange={(e) => setExportResults(e.target.checked)}
                />
                Auto-Export Results
              </label>
            </div>
            {hasCertificateWithKey && (
              <div className="control-item">
                <label>
                  <input 
                    type="checkbox" 
                    checked={detailedValidation}
                    onChange={(e) => setDetailedValidation(e.target.checked)}
                  />
                  Detailed Validation (Advanced Crypto Checks)
                </label>
              </div>
            )}
          </div>
          
          <div className="control-section">
            <h4>Actions</h4>
            {results && (
              <button 
                className="control-button" 
                onClick={handleDownloadReport}
                title="Download comprehensive JSON analysis report"
              >
                📄 Download Analysis Report
              </button>
            )}
            <button 
              className="control-button" 
              onClick={handleClearAll}
            >
              🗑️ Clear All
            </button>
            {results && (
              <button 
                className={`control-button ${copySuccess ? 'success' : ''}`}
                onClick={async () => {
                  await handleCopyDetails();
                  setCopySuccess(true);
                  setTimeout(() => setCopySuccess(false), 2000); // Reset after 2 seconds
                }}
                title="Copy formatted certificate details to clipboard"
              >
                {copySuccess ? '✅ Copied!' : '📋 Copy Summary'}
              </button>
            )}
          </div>
          
          {results && results.type === 'Certificate' && (() => {
            // Determine current format from the certificate info
            const currentFormat = certificateInfo.format;
            const isPemFormat = currentFormat === 'pem';
            const isDerFormat = currentFormat === 'der';
            const isBase64Format = currentFormat === 'binary';
            
            return (
              <div className="control-section">
                <h4>🔄 Convert Certificate</h4>
                {!isPemFormat && (
                  <button 
                    className="control-button conversion-button" 
                    title="Convert to PEM format (Base64 with headers)"
                  >
                    📝 To Certificate (PEM)
                  </button>
                )}
                {!isDerFormat && (
                  <button 
                    className="control-button conversion-button" 
                    title="Convert to DER format (Binary)"
                  >
                    🔗 To Certificate (DER)
                  </button>
                )}
                <button 
                  className="control-button conversion-button" 
                  title="Convert to PKCS#7 certificate chain"
                >
                  📦 To PKCS#7
                </button>
                {hasPrivateKey && (
                  <>
                    <button 
                      className="control-button conversion-button" 
                      title="Convert to PKCS#12 password-protected bundle"
                    >
                      🔐 To PKCS#12
                    </button>
                    <button 
                      className="control-button conversion-button" 
                      title="Convert to Java Keystore format"
                    >
                      ☕ To JKS
                    </button>
                  </>
                )}
                {!isBase64Format && (
                  <button 
                    className="control-button conversion-button" 
                    title="Convert to Base64 encoded certificate"
                  >
                    🔤 To Base64
                  </button>
                )}
                
                {/* Expanded Original File Info */}
                {certificateInfo.fileName && (
                  <div className="original-file-info">
                    <small>
                      <strong>Original:</strong>
                      <br />
                      <span className="file-details">
                        <strong>Filetype:</strong> {certificateInfo.type} ({certificateInfo.format})
                      </span>
                      {privateKeyInfo.type !== 'none' && (
                        <>
                          <span className="file-details">
                            <strong>Private Key:</strong> {privateKeyInfo.type} ({privateKeyInfo.format}, {privateKeyInfo.source})
                            {privateKeyInfo.encrypted && ' • Encrypted'}
                          </span>
                        </>
                      )}
                      {chainInfo.type !== 'none' && chainInfo.certificateCount > 0 && (
                        <>
                          <span className="file-details">
                            <strong>Chain:</strong> {chainInfo.type} ({chainInfo.format}, {chainInfo.source}) • {chainInfo.certificateCount} certs
                          </span>
                        </>
                      )}
                      <br />
                      <span className="file-details">
                        <strong>Filename:</strong> {certificateInfo.fileName}
                      </span>
                      <span className="file-details">
                        <strong>Filesize:</strong> {certificateInfo.fileSize ? (certificateInfo.fileSize / 1024).toFixed(1) + 'KB' : 'Unknown size'}
                      </span>
                      <span className="file-details">
                        <strong>Uploaded:</strong> {certificateInfo.uploadedAt}
                      </span>
                    </small>
                  </div>
                )}
              </div>
            );
          })()}
          
          {results && (
            <div className="control-section">
              <h4>Quick Info</h4>
              <div className="quick-info">
                <div className="info-item">
                  <span className="info-label">Type:</span>
                  <span className="info-value">{results.type}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Algorithm:</span>
                  <span className="info-value">{results.publicKey.algorithm}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Key Size:</span>
                  <span className="info-value">{results.publicKey.bitLength} bits</span>
                </div>
                {results.subjectAlternativeNames && (
                  <div className="info-item">
                    <span className="info-label">SANs:</span>
                    <span className="info-value">{results.subjectAlternativeNames.length}</span>
                  </div>
                )}
                {results.privateKeyValidation && (
                  <div className="info-item">
                    <span className="info-label">Key Match:</span>
                    <span className={`info-value ${results.privateKeyValidation.keyPairValid ? 'valid' : 'invalid'}`}>
                      {results.privateKeyValidation.keyPairValid ? '✅' : '❌'}
                    </span>
                  </div>
                )}
                {results.chainValidation && (
                  <div className="info-item">
                    <span className="info-label">Chain Valid:</span>
                    <span className={`info-value ${results.chainValidation.chainValid ? 'valid' : 'invalid'}`}>
                      {results.chainValidation.chainValid ? '✅' : '❌'}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;