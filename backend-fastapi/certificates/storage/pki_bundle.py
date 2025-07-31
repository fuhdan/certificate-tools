# backend-fastapi/certificates/storage/pki_bundle.py
# Updated PKI Bundle management for unified PEM storage

import logging
import datetime
from typing import Dict, Any, List, Optional

from .unified_storage import unified_storage
from session_manager import SessionManager

logger = logging.getLogger(__name__)

class PKIBundleManager:
    """Manages PKI bundle generation from unified storage"""
    
    @staticmethod
    def auto_generate_pki_bundle(session_id: str, certificates: Optional[List] = None):
        """Automatically generate PKI bundle from unified storage"""
        logger.info(f"[{session_id}] Auto-generating PKI bundle from unified storage")
        
        try:
            # Get certificates from unified storage if not provided
            if certificates is None:
                unified_certs = unified_storage.get_all_certificates(session_id)
            else:
                # Convert API models to unified cert data if needed
                unified_certs = []
                for cert in certificates:
                    if hasattr(cert, 'id'):  # API model
                        unified_cert = unified_storage.get_certificate(cert.id, session_id)
                        if unified_cert:
                            unified_certs.append(unified_cert)
                    else:
                        # Already unified cert data
                        unified_certs.append(cert)
            
            if not unified_certs:
                logger.debug(f"[{session_id}] No certificates found, clearing PKI bundle")
                PKIBundleManager.clear_pki_bundle(session_id)
                return
            
            # Generate bundle from unified certificates
            bundle = PKIBundleManager._generate_pki_bundle_from_unified(unified_certs, session_id)
            
            # Store in session
            session_data = SessionManager.get_or_create_session(session_id)
            session_data["pki_bundle"] = bundle
            
            logger.info(f"[{session_id}] PKI bundle generated with {len(bundle.get('components', []))} components")
            
        except Exception as e:
            logger.error(f"[{session_id}] Error auto-generating PKI bundle: {e}")
    
    @staticmethod
    def _generate_pki_bundle_from_unified(unified_certs: List, session_id: str) -> Dict[str, Any]:
        """Generate PKI bundle from unified certificate data"""
        logger.debug(f"[{session_id}] Generating PKI bundle from {len(unified_certs)} unified certificates")
        
        bundle = {
            "version": "1.0",
            "generated": datetime.datetime.now().isoformat(),
            "description": "Complete PKI Bundle with PEM content and analysis details",
            "components": []
        }
        
        # Sort certificates by PKI hierarchy
        sorted_certs = sorted(unified_certs, key=lambda cert: (
            PKIBundleManager._get_cert_order(cert),
            cert.filename
        ))
        
        # Process each certificate
        for unified_cert in sorted_certs:
            # Add certificate component
            if unified_cert.certificate_pem:
                cert_component = PKIBundleManager._create_certificate_component(unified_cert)
                bundle["components"].append(cert_component)
            
            # Add private key component
            if unified_cert.private_key_pem:
                key_component = PKIBundleManager._create_private_key_component(unified_cert)
                bundle["components"].append(key_component)
            
            # Add CSR component
            if unified_cert.csr_pem:
                csr_component = PKIBundleManager._create_csr_component(unified_cert)
                bundle["components"].append(csr_component)
            
            # Add additional certificates
            for i, additional_cert_pem in enumerate(unified_cert.additional_certificates_pem):
                additional_component = PKIBundleManager._create_additional_certificate_component(
                    unified_cert, additional_cert_pem, i
                )
                bundle["components"].append(additional_component)
        
        logger.debug(f"[{session_id}] Bundle generated with {len(bundle['components'])} components")
        return bundle
    
    @staticmethod
    def _create_certificate_component(unified_cert) -> Dict[str, Any]:
        """Create certificate component for PKI bundle"""
        cert_info = unified_cert.certificate_info
        
        # Determine file type based on certificate properties
        if cert_info and cert_info.is_ca:
            if cert_info.is_self_signed:
                file_type = "RootCA"
            else:
                file_type = "IntermediateCA"
        else:
            file_type = "Certificate"
        
        return {
            "fileType": file_type,
            "file": unified_cert.certificate_pem,
            "details": {
                "name": unified_cert.filename,
                "password": None,
                "uploadedAt": unified_cert.uploaded_at,
                "format": unified_cert.original_format,
                "isValid": unified_cert.is_valid,
                "size": unified_cert.file_size,
                "analysis": {
                    "subject": cert_info.subject if cert_info else "",
                    "issuer": cert_info.issuer if cert_info else "",
                    "serialNumber": cert_info.serial_number if cert_info else "",
                    "notValidBefore": cert_info.not_valid_before if cert_info else "",
                    "notValidAfter": cert_info.not_valid_after if cert_info else "",
                    "signatureAlgorithm": cert_info.signature_algorithm if cert_info else "",
                    "publicKeyAlgorithm": cert_info.public_key_algorithm if cert_info else "",
                    "publicKeySize": cert_info.public_key_size if cert_info else None,
                    "isCA": cert_info.is_ca if cert_info else False,
                    "isSelfSigned": cert_info.is_self_signed if cert_info else False,
                    "fingerprint": {
                        "sha1": cert_info.fingerprint_sha1 if cert_info else "",
                        "sha256": cert_info.fingerprint_sha256 if cert_info else ""
                    },
                    "extensions": cert_info.extensions if cert_info else {}
                }
            }
        }
    
    @staticmethod
    def _create_private_key_component(unified_cert) -> Dict[str, Any]:
        """Create private key component for PKI bundle"""
        key_info = unified_cert.private_key_info
        
        return {
            "fileType": "PrivateKey",
            "file": unified_cert.private_key_pem,
            "details": {
                "name": f"{unified_cert.filename}_private_key",
                "password": None,
                "uploadedAt": unified_cert.uploaded_at,
                "format": "PEM",
                "isValid": unified_cert.is_valid,
                "analysis": {
                    "keyAlgorithm": key_info.algorithm if key_info else "",
                    "keySize": key_info.key_size if key_info else None,
                    "isEncrypted": key_info.is_encrypted if key_info else False
                }
            }
        }
    
    @staticmethod
    def _create_csr_component(unified_cert) -> Dict[str, Any]:
        """Create CSR component for PKI bundle"""
        csr_info = unified_cert.csr_info
        
        return {
            "fileType": "CSR",
            "file": unified_cert.csr_pem,
            "details": {
                "name": unified_cert.filename,
                "password": None,
                "uploadedAt": unified_cert.uploaded_at,
                "format": unified_cert.original_format,
                "isValid": unified_cert.is_valid,
                "analysis": {
                    "subject": csr_info.subject if csr_info else "",
                    "signatureAlgorithm": csr_info.signature_algorithm if csr_info else "",
                    "publicKeyAlgorithm": csr_info.public_key_algorithm if csr_info else "",
                    "publicKeySize": csr_info.public_key_size if csr_info else None,
                    "extensions": csr_info.extensions if csr_info else {}
                }
            }
        }
    
    @staticmethod
    def _create_additional_certificate_component(unified_cert, cert_pem: str, index: int) -> Dict[str, Any]:
        """Create component for additional certificate"""
        additional_cert_info = None
        if index < len(unified_cert.additional_certificates_info):
            additional_cert_info = unified_cert.additional_certificates_info[index]
        
        # Determine file type
        if additional_cert_info and additional_cert_info.is_ca:
            if additional_cert_info.is_self_signed:
                file_type = "RootCA"
            else:
                file_type = "IntermediateCA"
        else:
            file_type = "Certificate"
        
        return {
            "fileType": file_type,
            "file": cert_pem,
            "details": {
                "name": f"{unified_cert.filename}_additional_{index}",
                "password": None,
                "uploadedAt": unified_cert.uploaded_at,
                "format": "PEM",
                "isValid": True,
                "analysis": {
                    "subject": additional_cert_info.subject if additional_cert_info else "",
                    "issuer": additional_cert_info.issuer if additional_cert_info else "",
                    "serialNumber": additional_cert_info.serial_number if additional_cert_info else "",
                    "isCA": additional_cert_info.is_ca if additional_cert_info else False,
                    "isSelfSigned": additional_cert_info.is_self_signed if additional_cert_info else False,
                    "fingerprint": {
                        "sha256": additional_cert_info.fingerprint_sha256 if additional_cert_info else ""
                    }
                }
            }
        }
    
    @staticmethod
    def _get_cert_order(unified_cert) -> int:
        """Get certificate order for PKI hierarchy sorting"""
        # PKCS12/PKCS7 bundles first
        if unified_cert.original_format in ['PKCS12', 'PKCS7']:
            return 0
        
        # CA certificates
        if unified_cert.certificate_info and unified_cert.certificate_info.is_ca:
            return 1
        
        # Certificate chains
        if unified_cert.additional_certificates_pem:
            return 2
        
        # End entity certificates
        if unified_cert.certificate_pem:
            return 3
        
        # Private keys
        if unified_cert.private_key_pem:
            return 4
        
        # CSRs last
        if unified_cert.csr_pem:
            return 5
        
        return 6
    
    @staticmethod
    def get_pki_bundle(session_id: str) -> Dict[str, Any]:
        """Get the current PKI bundle for session"""
        session_data = SessionManager.get_or_create_session(session_id)
        return session_data.get("pki_bundle", {}).copy() if session_data.get("pki_bundle") else {}
    
    @staticmethod
    def has_pki_bundle(session_id: str) -> bool:
        """Check if PKI bundle exists in session"""
        session_data = SessionManager.get_or_create_session(session_id)
        pki_bundle = session_data.get("pki_bundle", {})
        return bool(pki_bundle and pki_bundle.get('components'))
    
    @staticmethod
    def clear_pki_bundle(session_id: str):
        """Clear PKI bundle from session"""
        session_data = SessionManager.get_or_create_session(session_id)
        if "pki_bundle" in session_data:
            del session_data["pki_bundle"]
            logger.debug(f"[{session_id}] PKI bundle cleared")
    
    @staticmethod
    def validate_pki_bundle(session_id: str) -> Dict[str, Any]:
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
        
        pki_bundle = PKIBundleManager.get_pki_bundle(session_id)
        if not pki_bundle:
            validation["issues"].append("No PKI bundle exists")
            return validation
        
        component_types = [comp.get('fileType') for comp in pki_bundle.get('components', [])]
        
        validation["hasCSR"] = 'CSR' in component_types
        validation["hasPrivateKey"] = 'PrivateKey' in component_types
        validation["hasCertificate"] = 'Certificate' in component_types
        validation["hasIssuingCA"] = 'IntermediateCA' in component_types
        validation["hasRootCA"] = 'RootCA' in component_types
        validation["intermediateCACount"] = component_types.count('IntermediateCA')
        
        # PKI bundle is complete if we have at least one certificate
        if validation["hasCertificate"] or validation["hasIssuingCA"] or validation["hasRootCA"]:
            validation["isComplete"] = True
        
        # Add issues for missing essential components
        if not validation["hasCertificate"] and not validation["hasIssuingCA"] and not validation["hasRootCA"]:
            validation["issues"].append("Missing certificates - upload at least one certificate")
        
        logger.debug(f"[{session_id}] PKI bundle validation: {validation}")
        return validation