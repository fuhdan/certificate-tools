# backend-fastapi/certificates/storage/pki_bundle.py
# PKI Bundle management - auto-generation and storage

import logging
import datetime
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# In-memory PKI bundle storage
current_pki_bundle: Dict[str, Any] = {}

class PKIBundleManager:
    """Manages automatic PKI bundle generation and storage"""
    
    @staticmethod
    def auto_generate_pki_bundle(uploaded_certificates: Optional[List[Dict[str, Any]]] = None):
        """Automatically generate and store PKI bundle when certificates change"""
        logger.info(f"=== AUTO-GENERATING PKI BUNDLE ===")
        
        try:
            # If certificates not provided, get them from storage
            if uploaded_certificates is None:
                # Import here to avoid circular import
                from .core import CertificateStorage
                all_certificates = CertificateStorage.get_all()
            else:
                # Sort the provided certificates
                from .hierarchy import HierarchyManager
                all_certificates = sorted(uploaded_certificates, key=lambda cert: (
                    HierarchyManager.get_certificate_order(cert),
                    cert.get('filename', '')
                ))
            
            if not all_certificates:
                logger.debug("No certificates found, clearing PKI bundle")
                PKIBundleManager.clear_pki_bundle()
                return
            
            # Generate the bundle
            bundle = PKIBundleManager._generate_pki_bundle_internal(all_certificates)
            
            # Store it in memory
            global current_pki_bundle
            current_pki_bundle = bundle
            
            logger.info(f"PKI bundle auto-generated with {len(bundle.get('components', []))} components")
            
            # Log bundle summary
            component_types = [comp.get('fileType') for comp in bundle.get('components', [])]
            type_counts = {}
            for comp_type in component_types:
                type_counts[comp_type] = type_counts.get(comp_type, 0) + 1
            
            logger.info(f"PKI bundle composition: {type_counts}")
            
        except Exception as e:
            logger.error(f"Error auto-generating PKI bundle: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
    
    @staticmethod
    def _generate_pki_bundle_internal(certificates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Internal PKI bundle generation"""
        logger.debug("=== GENERATING PKI BUNDLE ===")
        
        # Import here to avoid circular import
        from .crypto_storage import CryptoObjectsStorage
        
        bundle = {
            "version": "1.0",
            "generated": datetime.datetime.now().isoformat(),
            "description": "Complete PKI Bundle with PEM content and analysis details",
            "components": []
        }
        
        # Process each certificate
        for cert in certificates:
            cert_id = cert.get('id')
            analysis = cert.get('analysis', {})
            filename = cert.get('filename', 'unknown')
            
            # Get crypto objects
            if cert_id is not None:
                crypto_objects = CryptoObjectsStorage.get_crypto_objects(cert_id)
            else:
                logger.warning(f"Certificate {filename} has no ID, cannot retrieve crypto objects")
                crypto_objects = {}
            
            # Generate PEM content
            pem_content = PKIBundleManager._extract_pem_content(
                analysis.get('type'), 
                crypto_objects
            )
            
            if pem_content:
                component = {
                    "fileType": PKIBundleManager._normalize_file_type(analysis.get('type'), analysis.get('details')),
                    "file": pem_content,
                    "details": {
                        "name": filename,
                        "password": None,  # Not stored for security
                        "uploadedAt": cert.get('uploadedAt'),
                        "format": analysis.get('format'),
                        "isValid": analysis.get('isValid'),
                        "size": analysis.get('size'),
                        "analysis": analysis.get('details')
                    }
                }
                bundle["components"].append(component)
                logger.debug(f"Added {component['fileType']} to PKI bundle: {filename}")
        
        # Sort by PKI hierarchy
        bundle["components"] = PKIBundleManager._sort_by_hierarchy(bundle["components"])
        
        logger.info(f"PKI bundle generated with {len(bundle['components'])} components")
        return bundle
    
    @staticmethod
    def _extract_pem_content(cert_type: str, crypto_objects: Dict) -> Optional[str]:
        """Extract PEM content from crypto objects"""
        try:
            if cert_type == 'CSR' and 'csr' in crypto_objects:
                csr = crypto_objects['csr']
                return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                
            elif cert_type == 'Private Key' and 'private_key' in crypto_objects:
                private_key = crypto_objects['private_key']
                return private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
            elif 'Certificate' in cert_type and 'certificate' in crypto_objects:
                cert = crypto_objects['certificate']
                return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                
        except Exception as e:
            logger.error(f"Error extracting PEM for {cert_type}: {e}")
        return None
    
    @staticmethod
    def _normalize_file_type(cert_type: str, details: Optional[Dict] = None) -> str:
        if details is None:
            details = {}
        """Determine the correct PKI component type"""
        if cert_type == 'CSR':
            return 'CSR'
        elif cert_type == 'Private Key':
            return 'PrivateKey'
        elif 'Certificate' in cert_type:
            # Analyze if it's CA or end-entity
            if details:
                extensions = details.get('extensions', {})
                basic_constraints = extensions.get('basicConstraints', {})
                is_ca = basic_constraints.get('isCA', False)
                
                if not is_ca:
                    return 'Certificate'  # End-entity
                else:
                    subject = details.get('subject', {})
                    issuer = details.get('issuer', {})
                    subject_cn = subject.get('commonName', '')
                    issuer_cn = issuer.get('commonName', '')
                    
                    if subject_cn == issuer_cn:
                        return 'RootCA'
                    elif any(indicator in subject_cn.lower() for indicator in ['issuing', 'leaf']):
                        return 'IssuingCA'
                    else:
                        return 'IntermediateCA'
            return 'Certificate'
        else:
            return 'Unknown'
    
    @staticmethod
    def _sort_by_hierarchy(components: List[Dict]) -> List[Dict]:
        """Sort components by PKI hierarchy"""
        hierarchy_order = {
            'CSR': 1,
            'PrivateKey': 2,
            'Certificate': 3,
            'IssuingCA': 4,
            'IntermediateCA': 5,
            'RootCA': 6,
            'Unknown': 7
        }
        
        return sorted(components, key=lambda x: hierarchy_order.get(x['fileType'], 999))
    
    @staticmethod
    def clear_pki_bundle():
        """Clear the stored PKI bundle"""
        global current_pki_bundle
        current_pki_bundle = {}
        logger.debug("PKI bundle cleared")
    
    @staticmethod
    def get_pki_bundle() -> Dict[str, Any]:
        """Get the current PKI bundle"""
        return current_pki_bundle.copy() if current_pki_bundle else {}
    
    @staticmethod
    def has_pki_bundle() -> bool:
        """Check if PKI bundle exists"""
        return bool(current_pki_bundle and current_pki_bundle.get('components'))
    
    @staticmethod
    def validate_pki_bundle() -> Dict[str, Any]:
        """Validate PKI bundle completeness and structure"""
        validation = {
            "isComplete": False,
            "hasCSR": False,
            "hasPrivateKey": False,
            "hasCertificate": False,
            "hasIssuingCA": False,
            "hasRootCA": False,
            "intermediateCACount": 0,
            "issues": []
        }
        
        if not current_pki_bundle:
            validation["issues"].append("No PKI bundle exists")
            return validation
        
        component_types = [comp.get('fileType') for comp in current_pki_bundle.get('components', [])]
        
        validation["hasCSR"] = 'CSR' in component_types
        validation["hasPrivateKey"] = 'PrivateKey' in component_types
        validation["hasCertificate"] = 'Certificate' in component_types
        validation["hasIssuingCA"] = 'IssuingCA' in component_types
        validation["hasRootCA"] = 'RootCA' in component_types
        validation["intermediateCACount"] = component_types.count('IntermediateCA')
        
        # FIXED: PKI bundle is complete if we have at least one certificate
        # CSR is NOT required for bundle completeness
        if validation["hasCertificate"] or validation["hasIssuingCA"] or validation["hasRootCA"]:
            validation["isComplete"] = True
        
        # Only add issues for truly missing essential components
        if not validation["hasCertificate"] and not validation["hasIssuingCA"] and not validation["hasRootCA"]:
            validation["issues"].append("Missing certificates - upload at least one certificate")
        
        return validation