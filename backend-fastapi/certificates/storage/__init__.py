# backend-fastapi/certificates/storage/__init__.py
# Storage module initialization - unified interface

from .core import CertificateStorage
from .crypto_storage import CryptoObjectsStorage
from .hierarchy import HierarchyManager
from .pki_bundle import PKIBundleManager
from .utils import StorageUtils

# Export the main interface
__all__ = [
    'CertificateStorage',
    'CryptoObjectsStorage', 
    'HierarchyManager',
    'PKIBundleManager',
    'StorageUtils'
]

# For backward compatibility, maintain the original interface
# Import the main class so existing code continues to work:
# from certificates.storage import CertificateStorage
