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
  const [serverStatus, setServerStatus] = useState('checking');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [privateKeyDragOver, setPrivateKeyDragOver] = useState(false);
  const [chainDragOver, setChainDragOver] = useState(false);

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
  const showChainInput = showPrivateKeyInput && hasPrivateKey;
  const hasCertificateWithKey = results && results.type === 'Certificate' && hasPrivateKey;

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

  // Handle chain text input change
  const handleChainTextChange = (e) => {
    const value = e.target.value;
    setChainContent(value);
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

  // Process dropped/selected file
  const handleFile = (file) => {
    console.log('Processing file:', file.name, 'Size:', file.size);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      console.log('File content loaded, length:', content.length);
      console.log('Content preview:', content.substring(0, 100));
      setCertContent(content);
      processCertificate(content, privateKeyContent, chainContent, privateKeyPassword);
    };
    reader.onerror = (e) => {
      console.error('File reading error:', e);
      setError('Failed to read file');
    };
    reader.readAsText(file);
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
                    📝 To PEM
                  </button>
                )}
                {!isDerFormat && (
                  <button 
                    className="control-button conversion-button" 
                    title="Convert to DER format (Binary)"
                  >
                    🔗 To DER
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