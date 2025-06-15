import React from 'react';

const InputSection = ({ 
  certContent, 
  onTextChange, 
  dragOver, 
  onDragOver, 
  onDragLeave, 
  onDrop, 
  onFileSelect,
  // Private key props
  privateKeyContent,
  onPrivateKeyTextChange,
  privateKeyDragOver,
  onPrivateKeyDragOver,
  onPrivateKeyDragLeave,
  onPrivateKeyDrop,
  onPrivateKeyFileSelect,
  showPrivateKeyInput,
  privateKeyAutoDetected,
  // Password props
  privateKeyPassword,
  onPrivateKeyPasswordChange,
  showPasswordInput,
  // Chain props
  chainContent,
  onChainTextChange,
  chainDragOver,
  onChainDragOver,
  onChainDragLeave,
  onChainDrop,
  onChainFileSelect,
  showChainInput,
  chainAutoDetected,
  // PKCS#12 props
  pkcs12Password,
  onPkcs12PasswordChange,
  showPkcs12PasswordInput,
  // Results for showing PKCS#12 info
  results
}) => {
  // Check if private key was auto-detected
  const hasAutoDetectedPrivateKey = privateKeyAutoDetected && privateKeyContent.trim().length > 0;
  
  return (
    <div className="input-section">
      <div className="input-group">
        <label htmlFor="certInput">Certificate or Certificate Chain:</label>
        <textarea
          id="certInput"
          className="textarea"
          value={certContent}
          onChange={onTextChange}
          placeholder="Paste your certificate here, or upload a certificate/chain file below..."
        />
      </div>

      <div className="input-group">
        <label>Upload Certificate or Certificate Chain File:</label>
        <div
          className={`drop-zone ${dragOver ? 'dragover' : ''}`}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onDrop={onDrop}
          onClick={() => document.getElementById('fileInput').click()}
        >
          <div className="drop-icon">📄</div>
          <p><strong>Drop your certificate or certificate chain file here</strong></p>
          <p>Supports PEM (.pem, .crt), DER (.der, .cer), PKCS#7 (.p7b, .p7c), PKCS#12 (.p12, .pfx), or full certificate chains</p>
          <p style={{ fontSize: '0.8em', marginTop: '8px', opacity: 0.7 }}>
            💡 DER/PKCS#7/PKCS#12 and chain files will be automatically processed and converted
          </p>
        </div>
        <input
          type="file"
          id="fileInput"
          className="hidden-input"
          accept=".crt,.cer,.pem,.csr,.p7b,.p7c,.der,.p12,.pfx,.pkcs12,.txt"
          onChange={onFileSelect}
        />
      </div>

      {/* PKCS#12 Password Input - Show when PKCS#12 file needs password */}
      {showPkcs12PasswordInput && (
        <div className="input-group">
          <label htmlFor="pkcs12Password">🔐 PKCS#12 Password:</label>
          <input
            type="password"
            id="pkcs12Password"
            className="password-input"
            value={pkcs12Password}
            onChange={onPkcs12PasswordChange}
            placeholder="Enter password for PKCS#12 file..."
            autoFocus
          />
          <small className="password-hint">
            This PKCS#12 file is encrypted and requires a password to extract the certificate and private key.
          </small>
        </div>
      )}

      {/* Show info when private key was auto-detected */}
      {hasAutoDetectedPrivateKey && (
        <div className="input-group">
          <div className="private-key-detected-info">
            <div className="info-icon">✅</div>
            <div className="info-content">
              <strong>Private Key Auto-Detected!</strong>
              <p>Successfully extracted and loaded private key from the uploaded file. The private key has been automatically validated with the certificate.</p>
              {results && results.summary && results.summary.chainLength > 0 && (
                <p style={{ marginTop: '8px', fontSize: '0.9em', opacity: 0.8 }}>
                  Also found {results.summary.chainLength} certificate(s) in the chain.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Private Key Input - Only show for certificates that don't have auto-detected private key */}
      {showPrivateKeyInput && !hasAutoDetectedPrivateKey && (
        <>
          <div className="input-group">
            <label htmlFor="privateKeyInput">Private Key (Optional - for validation):</label>
            <textarea
              id="privateKeyInput"
              className="textarea"
              value={privateKeyContent}
              onChange={onPrivateKeyTextChange}
              placeholder="Paste your private key here to validate the certificate..."
            />
          </div>

          <div className="input-group">
            <label>Or upload private key file:</label>
            <div
              className={`drop-zone ${privateKeyDragOver ? 'dragover' : ''}`}
              onDragOver={onPrivateKeyDragOver}
              onDragLeave={onPrivateKeyDragLeave}
              onDrop={onPrivateKeyDrop}
              onClick={() => document.getElementById('privateKeyFileInput').click()}
            >
              <div className="drop-icon">🔑</div>
              <p><strong>Drop your private key file here</strong></p>
              <p>or click to browse</p>
            </div>
            <input
              type="file"
              id="privateKeyFileInput"
              className="hidden-input"
              accept=".key,.pem,.txt"
              onChange={onPrivateKeyFileSelect}
            />
          </div>

          {/* Password Input - Only show for encrypted private keys */}
          {showPasswordInput && (
            <div className="input-group">
              <label htmlFor="privateKeyPassword">🔐 Private Key Password:</label>
              <input
                type="password"
                id="privateKeyPassword"
                className="password-input"
                value={privateKeyPassword}
                onChange={onPrivateKeyPasswordChange}
                placeholder="Enter password for encrypted private key..."
              />
              <small className="password-hint">
                This private key is encrypted and requires a password to decrypt.
              </small>
            </div>
          )}
        </>
      )}

      {/* Certificate Chain Input - Always show for certificates, unless auto-detected */}
      {showChainInput && !chainAutoDetected && (
        <>
          <div className="input-group">
            <label htmlFor="chainInput">Certificate Chain (Optional - for chain validation):</label>
            <textarea
              id="chainInput"
              className="textarea"
              value={chainContent}
              onChange={onChainTextChange}
              placeholder="Paste your certificate chain (intermediate + root certificates) here to validate the chain..."
            />
          </div>

          <div className="input-group">
            <label>Or upload certificate chain file:</label>
            <div
              className={`drop-zone ${chainDragOver ? 'dragover' : ''}`}
              onDragOver={onChainDragOver}
              onDragLeave={onChainDragLeave}
              onDrop={onChainDrop}
              onClick={() => document.getElementById('chainFileInput').click()}
            >
              <div className="drop-icon">⛓️</div>
              <p><strong>Drop your certificate chain file here</strong></p>
              <p>or click to browse (.pem, .crt, .p7b)</p>
            </div>
            <input
              type="file"
              id="chainFileInput"
              className="hidden-input"
              accept=".pem,.crt,.cer,.p7b,.p7c,.txt"
              onChange={onChainFileSelect}
            />
          </div>
        </>
      )}

      {/* Show info when chain was auto-detected */}
      {chainAutoDetected && chainContent.trim().length > 0 && (
        <div className="input-group">
          <div className="chain-detected-info">
            <div className="info-icon">✅</div>
            <div className="info-content">
              <strong>Certificate Chain Auto-Detected!</strong>
              <p>Found multiple certificates in the uploaded file. The first certificate is being used as the end-entity certificate, and the remaining certificates are being validated as the certificate chain.</p>
              {!hasAutoDetectedPrivateKey && privateKeyContent.trim().length === 0 && (
                <p style={{ marginTop: '8px', fontSize: '0.9em', opacity: 0.8 }}>
                  Optionally upload a private key above for complete validation.
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default InputSection;