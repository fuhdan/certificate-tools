// In-memory storage for uploaded certificates (in production, use database)
let uploadedCertificates = []

class CertificateStorage {
  static getAll() {
    return uploadedCertificates
  }

  static findById(id) {
    return uploadedCertificates.find(cert => cert.id == id)
  }

  static findByHash(hash) {
    return uploadedCertificates.find(cert => cert.analysis.hash === hash)
  }

  static add(certificateData) {
    uploadedCertificates.push(certificateData)
    console.log(`Added new certificate: ${certificateData.filename} (${certificateData.analysis.type}, hash: ${certificateData.analysis.hash?.substring(0, 8)}...)`)
    return certificateData
  }

  static replace(existingCert, newCertificateData) {
    const oldIndex = uploadedCertificates.findIndex(cert => cert.id === existingCert.id)
    if (oldIndex !== -1) {
      uploadedCertificates[oldIndex] = newCertificateData
      console.log(`Replaced duplicate certificate: ${existingCert.filename} -> ${newCertificateData.filename} (same content hash: ${newCertificateData.analysis.hash?.substring(0, 8)}...)`)
      return newCertificateData
    }
    return null
  }

  static remove(id) {
    const initialCount = uploadedCertificates.length
    uploadedCertificates = uploadedCertificates.filter(cert => cert.id != id)
    return uploadedCertificates.length < initialCount
  }

  static clear() {
    uploadedCertificates = []
    return true
  }

  static count() {
    return uploadedCertificates.length
  }
}

module.exports = CertificateStorage