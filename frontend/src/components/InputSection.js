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
  showChainInput
}) => (
  <div className="input-section">
    <div className="input-group">
      <label htmlFor="certInput">Paste Certificate/CSR or upload file below:</label>
      <textarea
        id="certInput"
        className="textarea"
        value={certContent}
        onChange={onTextChange}
        placeholder="Paste your certificate or CSR here, or upload a file using the drop zone below..."
      />
    </div>

    <div className="input-group">
      <label>Or drop a certificate/CSR file:</label>
      <div
        className={`drop-zone ${dragOver ? 'dragover' : ''}`}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => document.getElementById('fileInput').click()}
      >
        <div className="drop-icon">📄</div>
        <p><strong>Drop your certificate or CSR file here</strong></p>
        <p>or click to browse</p>
      </div>
      <input
        type="file"
        id="fileInput"
        className="hidden-input"
        accept=".crt,.cer,.pem,.csr,.txt"
        onChange={onFileSelect}
      />
    </div>

    {/* Private Key Input - Only show for certificates */}
    {showPrivateKeyInput && (
      <>
        <div className="input-group">
          <label htmlFor="privateKeyInput">Paste Base64 Private Key (Optional):</label>
          <textarea
            id="privateKeyInput"
            className="textarea"
            value={privateKeyContent}
            onChange={onPrivateKeyTextChange}
            placeholder="Paste your base64 encoded private key here..."
          />
        </div>

        <div className="input-group">
          <label>Or drop a private key file:</label>
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

    {/* Certificate Chain Input - Only show for certificates with private key */}
    {showChainInput && (
      <>
        <div className="input-group">
          <label htmlFor="chainInput">Paste Certificate Chain (Optional):</label>
          <textarea
            id="chainInput"
            className="textarea"
            value={chainContent}
            onChange={onChainTextChange}
            placeholder="Paste your certificate chain (intermediate + root certificates) here..."
          />
        </div>

        <div className="input-group">
          <label>Or drop a certificate chain file:</label>
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
            accept=".pem,.crt,.cer,.p7b,.txt"
            onChange={onChainFileSelect}
          />
        </div>
      </>
    )}
  </div>
);

export default InputSection;