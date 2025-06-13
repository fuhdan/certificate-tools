import React from 'react';

const StatusIndicator = ({ status }) => (
  <div className="status-indicator">
    <div className={`status-dot ${status}`}></div>
    <span>{status === 'online' ? 'Online' : status === 'offline' ? 'Offline' : 'Checking...'}</span>
  </div>
);

export default StatusIndicator;