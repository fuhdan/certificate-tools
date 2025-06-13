import React from 'react';
import CertificateTable from './CertificateTable';

const ResultsSection = ({ results, loading, error, showRawData = true, detailedValidation = true }) => (
  <div className="results-section">
    <h2>Certificate Information</h2>
    
    {loading && (
      <div className="loading">
        <p>🔄 Processing...</p>
      </div>
    )}

    {error && (
      <div className="error">
        {error}
      </div>
    )}

    {results && (
      <CertificateTable 
        data={results} 
        showRawData={showRawData}
        detailedValidation={detailedValidation}
      />
    )}
  </div>
);

export default ResultsSection;