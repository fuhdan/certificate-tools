import React, { useState, useEffect, useCallback } from 'react';
import StatusIndicator from './components/StatusIndicator';
import Header from './components/Header';
import InputSection from './components/InputSection';
import ResultsSection from './components/ResultsSection';
import { checkServerStatus, parseCertificate } from './services/api';

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
  const [chainAutoDetected, setChainAutoDetected] = useState(false); // Track if chain was auto-detected
  
  // NEW: Track original file information
  const [originalFileInfo, setOriginalFileInfo] = useState(null);

  // Control panel options
  const [showRawData, setShowRawData] = useState(false);
  const [exportResults, setExportResults] = useState(false);
  const [detailedValidation, setDetailedValidation] = useState(false);

  // Computed values - moved to the bottom to avoid initialization issues
  const hasPrivateKey = privateKeyContent.trim().length > 0;
  const isPrivateKeyEncrypted = hasPrivateKey && (
    privateKeyContent.includes('Proc-Type: 4,ENCRYPTED') || 
    privateKeyContent.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')
  );
  const showPrivateKeyInput = results && results.type === 'Certificate';
  const showPasswordInput = showPrivateKeyInput && hasPrivateKey && isPrivateKeyEncrypted;
  const showChainInput = results && results.type === 'Certificate'; // Always show for certificates
  const hasCertificateWithKey = results && results.type === 'Certificate' && hasPrivateKey;
  const hasAutoDetectedChain = chainAutoDetected && chainContent.trim().length > 0;

  // Check server status
  const updateServerStatus = useCallback(async () => {
    try {
      const isOnline = await checkServerStatus();
      setServerStatus(isOnline ? 'online' : 'offline');
    } catch (error) {
      setServerStatus('offline');
    }
  }, []);

  // Check status on mount and every 30 seconds
  useEffect(() => {
    updateServerStatus();
    const interval = setInterval(updateServerStatus, 30000);
    return () => clearInterval(interval);
  }, [updateServerStatus]);

  // Debounced processing function
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

  // Helper function to determine file type and format
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

  // Process certificate content with private key and chain
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
    } catch (err) {
      setError(err.message);
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  // Debounced version of processCertificate
  const debouncedProcess = useCallback(debounce((content, privateKey, chain, password) => {
    processCertificate(content, privateKey, chain, password);
  }, 500), []);

  // Handle text input change
  const handleTextChange = (e) => {
    const value = e.target.value;
    setCertContent(value);
    
    // Clear file info when manually typing
    if (originalFileInfo && value !== certContent) {
      setOriginalFileInfo(null);
    }
    
    debouncedProcess(value, privateKeyContent, chainContent, privateKeyPassword);
  };

  // Handle private key text input change
  const handlePrivateKeyTextChange = (e) => {
    const value = e.target.value;
    setPrivateKeyContent(value);
    
    // Re-process certificate with new private key
    if (certContent.trim()) {
      debouncedProcess(certContent, value, chainContent, privateKeyPassword);
    }
  };

  // Handle private key password input change
  const handlePrivateKeyPasswordChange = (e) => {
    const value = e.target.value;
    setPrivateKeyPassword(value);
    // Re-process certificate with new password
    if (certContent.trim() && privateKeyContent.trim()) {
      debouncedProcess(certContent, privateKeyContent, chainContent, value);
    }
  };

  // Handle PKCS#12 password input change
  const handlePkcs12PasswordChange = (e) => {
    const value = e.target.value;
    setPkcs12Password(value);
    
    // If we have pending PKCS#12 data, try to process it with the new password
    if (pendingPkcs12Data) {
      processPkcs12Content(pendingPkcs12Data.content, pendingPkcs12Data.fileName, value);
    }
  };

  // Handle chain text input change
  const handleChainTextChange = (e) => {
    const value = e.target.value;
    setChainContent(value);
    setChainAutoDetected(false); // Manual input, not auto-detected
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

  // Check if file is PKCS#12 format
  const isPkcs12File = (file) => {
    const lowerName = file.name.toLowerCase();
    return lowerName.endsWith('.p12') || 
           lowerName.endsWith('.pfx') || 
           lowerName.endsWith('.pkcs12');
  };

  // Process dropped/selected file
  const handleFile = (file) => {
    console.log('Processing file:', file.name, 'Size:', file.size);
    
    // Set original file info
    setOriginalFileInfo(getFileTypeInfo(file));
    
    // Check if this is a PKCS#12 file first
    if (isPkcs12File(file)) {
      console.log('PKCS#12 format detected based on file extension');
      // Update file info with detected format
      setOriginalFileInfo(getFileTypeInfo(file, 'PKCS#12'));
      
      const reader = new FileReader();
      reader.onload = (e) => {
        const arrayBuffer = e.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);
        const base64String = btoa(String.fromCharCode.apply(null, uint8Array));
        console.log('Converting PKCS#12 to base64 for processing');
        processPkcs12Content(base64String, file.name);
      };
      reader.readAsArrayBuffer(file);
      return;
    }
    
    const reader = new FileReader();
    
    // Check if this is likely a DER file
    if (isDerFile(file)) {
      console.log('DER format suspected based on file extension');
      // Update file info with detected format
      setOriginalFileInfo(getFileTypeInfo(file, 'Certificate'));
      
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
    reader.onload = (e) => {
      const content = e.target.result;
      console.log('File content loaded, length:', content.length);
      console.log('Content preview:', content.substring(0, 100));
      
      // Check if this is PKCS#7 format
      const isPkcs7Pem = content.includes('-----BEGIN PKCS7-----') || content.includes('-----BEGIN CERTIFICATE-----');
      const isPkcs7Der = !content.includes('-----BEGIN') && file.name.toLowerCase().endsWith('.p7b');
      
      if (isPkcs7Pem || isPkcs7Der) {
        console.log('PKCS#7 format detected, sending to backend for parsing');
        // Update file info with detected format
        setOriginalFileInfo(getFileTypeInfo(file, 'PKCS#7'));
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
        // Update file info with detected format
        setOriginalFileInfo(getFileTypeInfo(file, 'Certificate Chain'));
        
        const firstCert = certMatches[0];
        const chainCerts = certMatches.slice(1).join('\n');
        
        console.log('Setting first certificate as main cert');
        console.log('Setting remaining certificates as chain');
        
        setCertContent(firstCert);
        setChainContent(chainCerts);
        setChainAutoDetected(true); // Mark as auto-detected
        
        // Process with the split content
        processCertificate(firstCert, privateKeyContent, chainCerts, privateKeyPassword);
      } else {
        // Single certificate or CSR
        // Detect if it's a CSR or Certificate
        let detectedType = 'Certificate';
        if (content.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
          detectedType = 'CSR';
        }
        setOriginalFileInfo(getFileTypeInfo(file, detectedType));
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
        setOriginalFileInfo(getFileTypeInfo(file, 'PKCS#7'));
        processPkcs7Content(base64String, file.name, true); // true indicates DER format
      };
    } else {
      reader.readAsText(file);
    }
  };

  // Process PKCS#12 content
  const processPkcs12Content = async (base64Content, fileName, password = '') => {
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
        setLoading(false);
        return;
      }
      
      if (data.error) {
        throw new Error(data.error);
      }
      
      // Hide password input and clear pending data
      setShowPkcs12PasswordInput(false);
      setPendingPkcs12Data(null);
      setPkcs12Password('');
      
      // Set the certificate content
      if (data.certificate && data.certificate.pem) {
        setCertContent(data.certificate.pem);
        setResults(data.certificate);
      }
      
      // Set the private key content if available
      if (data.privateKey && data.privateKey.pem) {
        setPrivateKeyContent(data.privateKey.pem);
      }
      
      // Set the certificate chain if available
      if (data.certificateChain && data.certificateChain.length > 0) {
        const chainPems = data.certificateChain.map(cert => cert.pem).join('\n');
        setChainContent(chainPems);
        setChainAutoDetected(true);
      }
      
      setError('');
      
    } catch (err) {
      console.error('PKCS#12 Error:', err.message);
      setError('Failed to parse PKCS#12 file: ' + err.message);
      
      // If it's a password error, show password input
      if (err.message.includes('password') || err.message.includes('decrypt')) {
        setPendingPkcs12Data({ content: base64Content, fileName: fileName });
        setShowPkcs12PasswordInput(true);
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
      setChainAutoDetected(false);
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
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      setPrivateKeyContent(content);
      
      // Re-process certificate with new private key
      if (certContent.trim()) {
        processCertificate(certContent, content, chainContent, privateKeyPassword);
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
      setChainAutoDetected(false); // This is manually uploaded, not auto-detected
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

  // Control panel functions
  const handleClearAll = () => {
    setCertContent('');
    setPrivateKeyContent('');
    setChainContent('');
    setPrivateKeyPassword('');
    setPkcs12Password('');
    setShowPkcs12PasswordInput(false);
    setPendingPkcs12Data(null);
    setChainAutoDetected(false);
    setOriginalFileInfo(null); // Clear file info
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
      ...(originalFileInfo && { originalFile: originalFileInfo }),
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

  const handleCopyDetails = () => {
    if (!results) return;
    
    let text = `Certificate Analysis Report\n`;
    text += `Generated: ${new Date().toLocaleString()}\n\n`;
    text += `Type: ${results.type}\n`;
    
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
    
    navigator.clipboard.writeText(text).then(() => {
      // Could add a toast notification here
      console.log('Certificate details copied to clipboard');
    });
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
          setChainAutoDetected(true);
          
          // Process with split content
          processCertificate(firstCert, privateKeyContent, chainCerts, privateKeyPassword);
        } else {
          // Single certificate in PKCS#7
          setChainAutoDetected(false);
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
            privateKeyPassword={privateKeyPassword}
            onPrivateKeyPasswordChange={handlePrivateKeyPasswordChange}
            showPasswordInput={showPasswordInput}
            chainContent={chainContent}
            onChainTextChange={handleChainTextChange}
            chainDragOver={chainDragOver}
            onChainDragOver={handleChainDragOver}
            onChainDragLeave={handleChainDragLeave}
            onChainDrop={handleChainFileDrop}
            onChainFileSelect={handleChainFileInput}
            showChainInput={showChainInput}
            pkcs12Password={pkcs12Password}
            onPkcs12PasswordChange={handlePkcs12PasswordChange}
            showPkcs12PasswordInput={showPkcs12PasswordInput}
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
                className="control-button" 
                onClick={handleCopyDetails}
                title="Copy formatted certificate details to clipboard"
              >
                📋 Copy Summary
              </button>
            )}
          </div>
          
          {results && results.type === 'Certificate' && (() => {
            // Determine current format from the raw PEM data
            const rawPem = results.raw?.pem || '';
            const isPemFormat = rawPem.includes('-----BEGIN CERTIFICATE-----');
            const isDerFormat = !isPemFormat && rawPem.length > 0;
            const isBase64Format = !isPemFormat && !isDerFormat;
            
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
                
                {/* Original File Info */}
                {originalFileInfo && (
                  <div className="original-file-info">
                    <small>
                      <strong>Original:</strong> {originalFileInfo.fileType} ({originalFileInfo.format})
                      <br />
                      <span className="file-details">
                        {originalFileInfo.fileName} • {(originalFileInfo.fileSize / 1024).toFixed(1)}KB
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