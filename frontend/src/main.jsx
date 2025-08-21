// NUCLEAR FIX: Make Object.keys/values/entries never crash on null
const originalObjectKeys = Object.keys;
const originalObjectValues = Object.values;
const originalObjectEntries = Object.entries;

Object.keys = function(obj) {
  if (obj === null || obj === undefined) {
    console.warn('Object.keys called with null/undefined:', obj, new Error().stack);
    return [];
  }
  return originalObjectKeys(obj);
};

Object.values = function(obj) {
  if (obj === null || obj === undefined) {
    console.warn('Object.values called with null/undefined:', obj, new Error().stack);
    return [];
  }
  return originalObjectValues(obj);
};

Object.entries = function(obj) {
  if (obj === null || obj === undefined) {
    console.warn('Object.entries called with null/undefined:', obj, new Error().stack);
    return [];
  }
  return originalObjectEntries(obj);
};

console.log('🛡️ Object.keys/values/entries patched to be null-safe');

import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(<App />)