# backend-fastapi/certificates/storage/__init__.py
# Clean storage module initialization - unified storage only

from .certificate_storage import CertificateStorage
from .unified_storage import unified_storage, UnifiedCertificateData, UnifiedStorageManager
from .crypto_access import CryptoObjectAccess

# Clean exports - no legacy compatibility
__all__ = [
    'CertificateStorage',          # Clean storage interface
    'unified_storage',             # Global unified storage instance
    'UnifiedCertificateData',      # Unified data model
    'UnifiedStorageManager',       # Unified storage manager class
    'CryptoObjectAccess',          # On-demand crypto object access
]