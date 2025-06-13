import React from 'react';

const CertificateTable = ({ data, showRawData = true, detailedValidation = true }) => {
  const renderChainValidationSection = () => {
    if (!data.chainValidation) return null;

    const chainVal = data.chainValidation;
    
    return (
      <div className="validation-section">
        <h3>⛓️ Certificate Chain Validation</h3>
        <div className="validation-item">
          <span className="validation-label">Chain Valid:</span>
          <span className={`validation-status ${chainVal.chainValid ? 'valid' : 'invalid'}`}>
            {chainVal.chainValid ? '✅ Valid' : '❌ Invalid'}
          </span>
        </div>
        <div className="validation-item">
          <span className="validation-label">Chain Length:</span>
          <span>{chainVal.chainLength} certificate(s) + end entity</span>
        </div>
        
        {chainVal.validationPath && chainVal.validationPath.length > 0 && (
          <>
            <div className="validation-item">
              <span className="validation-label">Validation Path:</span>
              <span></span>
            </div>
            {chainVal.validationPath.map((pathCert, index) => (
              <div key={`path-${index}`} className="validation-item" style={{ paddingLeft: '20px' }}>
                <span className="validation-label">{pathCert.type}:</span>
                <span style={{ 
                  color: pathCert.valid ? '#28a745' : '#dc3545',
                  fontFamily: 'monospace',
                  fontSize: '0.9em'
                }}>
                  {pathCert.subject} {pathCert.valid ? '✅' : '❌'}
                </span>
              </div>
            ))}
          </>
        )}
        
        {detailedValidation && chainVal.details && (
          <>
            <div className="validation-item">
              <span className="validation-label">Total Certificates:</span>
              <span>{chainVal.details.totalCerts}</span>
            </div>
            <div className="validation-item">
              <span className="validation-label">Has Root CA:</span>
              <span className={`validation-status ${chainVal.details.hasRoot ? 'valid' : 'invalid'}`}>
                {chainVal.details.hasRoot ? '✅ Yes' : '❌ No'}
              </span>
            </div>
            <div className="validation-item">
              <span className="validation-label">Has Intermediate:</span>
              <span className={`validation-status ${chainVal.details.hasIntermediate ? 'valid' : 'invalid'}`}>
                {chainVal.details.hasIntermediate ? '✅ Yes' : '❌ No'}
              </span>
            </div>
          </>
        )}
        
        {chainVal.issues && chainVal.issues.length > 0 && (
          <div className="validation-item">
            <span className="validation-label">Issues:</span>
            <span className="validation-status invalid">
              {chainVal.issues.join(', ')}
            </span>
          </div>
        )}
      </div>
    );
  };

  const renderValidationSection = () => {
    if (!data.privateKeyValidation) return null;

    const validation = data.privateKeyValidation;
    
    return (
      <div className="validation-section">
        <h3>🔐 Private Key Validation</h3>
        <div className="validation-item">
          <span className="validation-label">Public Key Match:</span>
          <span className={`validation-status ${validation.publicKeyMatch ? 'valid' : 'invalid'}`}>
            {validation.publicKeyMatch ? '✅ Valid' : '❌ Invalid'}
          </span>
        </div>
        <div className="validation-item">
          <span className="validation-label">Signature Validation:</span>
          <span className={`validation-status ${validation.signatureValid ? 'valid' : 'invalid'}`}>
            {validation.signatureValid ? '✅ Valid' : '❌ Invalid'}
          </span>
        </div>
        <div className="validation-item">
          <span className="validation-label">Key Pair Match:</span>
          <span className={`validation-status ${validation.keyPairValid ? 'valid' : 'invalid'}`}>
            {validation.keyPairValid ? '✅ Valid' : '❌ Invalid'}
          </span>
        </div>
        
        {detailedValidation && validation.details.keyType && (
          <>
            <div className="validation-item">
              <span className="validation-label">Key Type:</span>
              <span>{validation.details.keyType}</span>
            </div>
            <div className="validation-item">
              <span className="validation-label">Key Size:</span>
              <span>{validation.details.keySize} bits</span>
            </div>
            {validation.details.publicExponent && (
              <div className="validation-item">
                <span className="validation-label">Public Exponent:</span>
                <span>{validation.details.publicExponent}</span>
              </div>
            )}
            
            {validation.details.modulusMatch && (
              <>
                <div className="validation-item">
                  <span className="validation-label">Modulus Match:</span>
                  <span className={`validation-status ${validation.details.modulusMatch.identical ? 'valid' : 'invalid'}`}>
                    {validation.details.modulusMatch.identical ? '✅ Identical' : '❌ Different'}
                  </span>
                </div>
                <div className="validation-item">
                  <span className="validation-label">Modulus Length:</span>
                  <span>{validation.details.modulusMatch.totalLength / 2} bytes ({validation.details.modulusMatch.totalLength} hex chars)</span>
                </div>
                <div className="validation-item">
                  <span className="validation-label">Cert Modulus:</span>
                  <span style={{ 
                    fontFamily: 'monospace', 
                    fontSize: '0.75em',
                    wordBreak: 'break-all',
                    lineHeight: '1.2'
                  }}>
                    {validation.details.modulusMatch.certificate}
                  </span>
                </div>
                <div className="validation-item">
                  <span className="validation-label">Key Modulus:</span>
                  <span style={{ 
                    fontFamily: 'monospace', 
                    fontSize: '0.75em',
                    wordBreak: 'break-all',
                    lineHeight: '1.2',
                    color: validation.details.modulusMatch.identical ? '#28a745' : '#dc3545'
                  }}>
                    {validation.details.modulusMatch.privateKey}
                  </span>
                </div>
              </>
            )}
            
            {validation.details.testMessage && (
              <>
                <div className="validation-item">
                  <span className="validation-label">Test Signature:</span>
                  <span>{validation.details.signatureLength} bytes</span>
                </div>
                <div className="validation-item">
                  <span className="validation-label">Hash Algorithm:</span>
                  <span>{validation.details.hashAlgorithm}</span>
                </div>
              </>
            )}
            
            {validation.details.keyFormat && (
              <>
                <div className="validation-item">
                  <span className="validation-label">Certificate Format:</span>
                  <span>{validation.details.keyFormat.certificate}</span>
                </div>
                <div className="validation-item">
                  <span className="validation-label">Private Key Format:</span>
                  <span>{validation.details.keyFormat.privateKey}</span>
                </div>
              </>
            )}
            
            {validation.details.keyUsageCompatibility && (
              <>
                <div className="validation-item">
                  <span className="validation-label">Can Sign:</span>
                  <span className={`validation-status ${validation.details.keyUsageCompatibility.canSign ? 'valid' : 'invalid'}`}>
                    {validation.details.keyUsageCompatibility.canSign ? '✅ Yes' : '❌ No'}
                  </span>
                </div>
                <div className="validation-item">
                  <span className="validation-label">Can Encrypt:</span>
                  <span className={`validation-status ${validation.details.keyUsageCompatibility.canEncrypt ? 'valid' : 'invalid'}`}>
                    {validation.details.keyUsageCompatibility.canEncrypt ? '✅ Yes' : '❌ No'}
                  </span>
                </div>
                {validation.details.keyUsageCompatibility.restrictions.length > 0 && (
                  <div className="validation-item">
                    <span className="validation-label">Restrictions:</span>
                    <span className="validation-status invalid">
                      {validation.details.keyUsageCompatibility.restrictions.join(', ')}
                    </span>
                  </div>
                )}
              </>
            )}
          </>
        )}
        
        {validation.details.error && (
          <div className="validation-item">
            <span className="validation-label">Error:</span>
            <span className="validation-status invalid">{validation.details.error}</span>
          </div>
        )}
        
        {validation.details.signatureError && (
          <div className="validation-item">
            <span className="validation-label">Signature Error:</span>
            <span className="validation-status invalid">{validation.details.signatureError}</span>
          </div>
        )}
      </div>
    );
  };

  const renderTableRows = () => {
    const rows = [];

    // Type badge
    rows.push(
      <tr key="type">
        <td colSpan="2">
          <span className={`cert-type ${data.type.toLowerCase()}`}>
            {data.type}
          </span>
        </td>
      </tr>
    );

    // Version information
    if (data.version !== undefined) {
      rows.push(
        <tr key="version">
          <td>Version</td>
          <td>v{data.version + 1} (0x{data.version.toString(16)})</td>
        </tr>
      );
    }

    // Subject information
    rows.push(
      <tr key="subject-header">
        <td colSpan="2"><strong>Subject Information</strong></td>
      </tr>
    );
    
    data.subject.forEach((attr, index) => {
      rows.push(
        <tr key={`subject-${index}`}>
          <td>{attr.shortName || attr.name}</td>
          <td>{attr.value}</td>
        </tr>
      );
    });

    // Subject Alternative Names - ONLY show the main field, never from extensions
    if (data.subjectAlternativeNames && data.subjectAlternativeNames.length > 0) {
      rows.push(
        <tr key="san-header">
          <td colSpan="2"><strong>Subject Alternative Names (SANs)</strong></td>
        </tr>
      );
      
      data.subjectAlternativeNames.forEach((san, index) => {
        rows.push(
          <tr key={`san-${index}`}>
            <td style={{ paddingLeft: '20px' }}>{san.typeName || 'Unknown Type'}</td>
            <td>{san.value || 'No Value'}</td>
          </tr>
        );
      });
    }

    // Issuer information (certificates only)
    if (data.type === 'Certificate' && data.issuer) {
      rows.push(
        <tr key="issuer-header">
          <td colSpan="2"><strong>Issuer Information</strong></td>
        </tr>
      );
      
      data.issuer.forEach((attr, index) => {
        rows.push(
          <tr key={`issuer-${index}`}>
            <td>{attr.shortName || attr.name}</td>
            <td>{attr.value}</td>
          </tr>
        );
      });

      // Validity information
      rows.push(
        <tr key="validity-header">
          <td colSpan="2"><strong>Validity Information</strong></td>
        </tr>
      );
      
      rows.push(
        <tr key="valid-from">
          <td>Valid From</td>
          <td>{new Date(data.validity.notBefore).toLocaleString()}</td>
        </tr>
      );
      
      rows.push(
        <tr key="valid-until">
          <td>Valid Until</td>
          <td>{new Date(data.validity.notAfter).toLocaleString()}</td>
        </tr>
      );
      
      rows.push(
        <tr key="currently-valid">
          <td>Currently Valid</td>
          <td>
            {data.validity.isValid ? '✅ Yes' : '❌ No'}
            {data.validity.daysUntilExpiry > 0 && (
              <span style={{ marginLeft: '10px', fontSize: '0.9em', opacity: 0.8 }}>
                ({data.validity.daysUntilExpiry} days remaining)
              </span>
            )}
          </td>
        </tr>
      );

      if (data.validity.validityPeriodDays) {
        rows.push(
          <tr key="validity-period">
            <td>Validity Period</td>
            <td>{data.validity.validityPeriodDays} days</td>
          </tr>
        );
      }

      if (data.serialNumber) {
        rows.push(
          <tr key="serial">
            <td>Serial Number</td>
            <td>{data.serialNumber}</td>
          </tr>
        );
      }
    }

    // Public Key information
    rows.push(
      <tr key="pubkey-header">
        <td colSpan="2"><strong>Public Key Information</strong></td>
      </tr>
    );
    
    rows.push(
      <tr key="pubkey-algo">
        <td>Algorithm</td>
        <td>{data.publicKey.algorithm}</td>
      </tr>
    );
    
    rows.push(
      <tr key="pubkey-length">
        <td>Key Length</td>
        <td>{data.publicKey.bitLength} bits</td>
      </tr>
    );

    if (data.publicKey.exponent && data.publicKey.exponent !== 'Unknown') {
      rows.push(
        <tr key="pubkey-exponent">
          <td>Public Exponent</td>
          <td>{data.publicKey.exponent}</td>
        </tr>
      );
    }

    if (data.publicKey.curve) {
      rows.push(
        <tr key="pubkey-curve">
          <td>Curve</td>
          <td>{data.publicKey.curve}</td>
        </tr>
      );
    }

    if (data.publicKey.modulus) {
      rows.push(
        <tr key="pubkey-modulus">
          <td>Modulus</td>
          <td style={{ fontFamily: 'monospace', fontSize: '0.8em', wordBreak: 'break-all' }}>
            {data.publicKey.modulus}
          </td>
        </tr>
      );
    }

    // Signature information
    rows.push(
      <tr key="sig-header">
        <td colSpan="2"><strong>Signature Information</strong></td>
      </tr>
    );
    
    rows.push(
      <tr key="sig-algo">
        <td>Algorithm</td>
        <td>{data.signature.algorithm}</td>
      </tr>
    );

    if (data.signature.oid) {
      rows.push(
        <tr key="sig-oid">
          <td>Algorithm OID</td>
          <td>{data.signature.oid}</td>
        </tr>
      );
    }
    
    rows.push(
      <tr key="sig-valid">
        <td>Valid</td>
        <td>{data.signature.valid ? '✅ Yes' : '❌ No'}</td>
      </tr>
    );

    // Extensions - COMPLETELY EXCLUDE ANY SAN-related extensions
    if (data.extensions && data.extensions.length > 0) {
      // Filter out ALL possible SAN extension variations
      const nonSanExtensions = data.extensions.filter(ext => {
        const isSanExtension = 
          ext.name === 'subjectAltName' || 
          ext.name === 'subjectAlternativeName' ||
          ext.id === '2.5.29.17' ||
          (ext.altNames && ext.altNames.length > 0);
        
        return !isSanExtension;
      });
      
      if (nonSanExtensions.length > 0) {
        rows.push(
          <tr key="ext-header">
            <td colSpan="2"><strong>Extensions</strong></td>
          </tr>
        );

        nonSanExtensions.forEach((ext, index) => {
          rows.push(
            <tr key={`ext-${index}-name`}>
              <td>{ext.name}</td>
              <td>
                <div>
                  <strong>Critical:</strong> {ext.critical ? 'Yes' : 'No'}
                  {ext.id && <div><strong>OID:</strong> {ext.id}</div>}
                </div>
              </td>
            </tr>
          );

          if (ext.usage && ext.usage.length > 0) {
            rows.push(
              <tr key={`ext-${index}-usage`}>
                <td style={{ paddingLeft: '20px' }}>Usage</td>
                <td>{ext.usage.join(', ')}</td>
              </tr>
            );
          }

          if (ext.isCA !== undefined) {
            rows.push(
              <tr key={`ext-${index}-ca`}>
                <td style={{ paddingLeft: '20px' }}>Is CA</td>
                <td>{ext.isCA ? 'Yes' : 'No'}</td>
              </tr>
            );
          }

          if (ext.pathLength !== undefined) {
            rows.push(
              <tr key={`ext-${index}-path`}>
                <td style={{ paddingLeft: '20px' }}>Path Length</td>
                <td>{ext.pathLength}</td>
              </tr>
            );
          }

          if (ext.keyIdentifier) {
            rows.push(
              <tr key={`ext-${index}-keyid`}>
                <td style={{ paddingLeft: '20px' }}>Key Identifier</td>
                <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                  {ext.keyIdentifier}
                </td>
              </tr>
            );
          }

          if (ext.policies && ext.policies.length > 0) {
            rows.push(
              <tr key={`ext-${index}-policies`}>
                <td style={{ paddingLeft: '20px' }}>Policies</td>
                <td>{ext.policies.join(', ')}</td>
              </tr>
            );
          }

          if (ext.value && !ext.usage) {
            rows.push(
              <tr key={`ext-${index}-value`}>
                <td style={{ paddingLeft: '20px' }}>Value</td>
                <td style={{ fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all' }}>
                  {ext.value}
                </td>
              </tr>
            );
          }
        });
      }
    }

    // Fingerprints - only show if showRawData is enabled
    if (showRawData && data.raw && data.raw.fingerprint) {
      rows.push(
        <tr key="fingerprint-header">
          <td colSpan="2"><strong>Fingerprints</strong></td>
        </tr>
      );

      if (typeof data.raw.fingerprint === 'string') {
        rows.push(
          <tr key="fingerprint">
            <td>SHA-256</td>
            <td style={{ fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all' }}>
              {data.raw.fingerprint}
            </td>
          </tr>
        );
      } else {
        if (data.raw.fingerprint.sha1) {
          rows.push(
            <tr key="fingerprint-sha1">
              <td>SHA-1</td>
              <td style={{ fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all' }}>
                {data.raw.fingerprint.sha1}
              </td>
            </tr>
          );
        }
        if (data.raw.fingerprint.sha256) {
          rows.push(
            <tr key="fingerprint-sha256">
              <td>SHA-256</td>
              <td style={{ fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all' }}>
                {data.raw.fingerprint.sha256}
              </td>
            </tr>
          );
        }
      }
    }

    // Raw PEM data - only show if showRawData is enabled
    if (showRawData && data.raw && data.raw.pem) {
      rows.push(
        <tr key="raw-pem-header">
          <td colSpan="2"><strong>Raw PEM Data</strong></td>
        </tr>
      );
      rows.push(
        <tr key="raw-pem">
          <td>PEM Content</td>
          <td style={{ 
            fontFamily: 'monospace', 
            fontSize: '0.7em', 
            wordBreak: 'break-all',
            maxHeight: '200px',
            overflow: 'auto',
            whiteSpace: 'pre-wrap'
          }}>
            {data.raw.pem.substring(0, 500)}...
          </td>
        </tr>
      );
    }

    return rows;
  };

  return (
    <div>
      {renderValidationSection()}
      <table className="cert-table">
        <thead>
          <tr>
            <th>Property</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {renderTableRows()}
        </tbody>
      </table>
    </div>
  );
};

export default CertificateTable;