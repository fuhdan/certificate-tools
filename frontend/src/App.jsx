// frontend/src/App.jsx
import React from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout/Layout'
import LandingPage from './components/LandingPage/LandingPage'

function App() {
  return (
    <Router>
      <Routes>
        {/* Landing page at root */}
        <Route path="/" element={<LandingPage />} />
        
        {/* Certificate analyzer app */}
        <Route path="/app" element={<Layout />} />
        
        {/* Catch-all route - redirect unknown paths to landing */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  )
}

export default App