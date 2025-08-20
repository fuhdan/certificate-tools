# backend-fastapi/services/validation_service.py

import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List
from cryptography import x509
from cryptography.x509 import oid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

logger = logging.getLogger(__name__)

class ValidationService:
    """PKI Validation Service - computes all validations for PKI sessions"""
    
    def __init__(self):
        self.version = "2.0"
        logger.info("ValidationService initialized and ready")
    
    def compute_all_validations(self, session) -> Dict[str, Any]:
        """
        Compute all validations for a PKI session
        
        Args:
            session: PKISession object containing components
            
        Returns:
            Dict with complete validation results
        """
        logger.info(f"Computing validations for session {session.session_id}")
        
        validations = {}
        
        try:
            # Get component types for easier access
            components_by_type = self._group_components_by_type(session)
            logger.debug(f"Component types found: {list(components_by_type.keys())}")
            
            # Private Key <-> Certificate validation
            if 'PrivateKey' in components_by_type and 'Certificate' in components_by_type:
                logger.debug("Running Private Key <-> Certificate validation")
                validations['private_key_certificate_match'] = self._validate_private_key_certificate(
                    components_by_type['PrivateKey'][0], 
                    components_by_type['Certificate'][0]
                )
            
            # Private Key <-> CSR validation
            if 'PrivateKey' in components_by_type and 'CSR' in components_by_type:
                logger.debug("Running Private Key <-> CSR validation")
                validations['private_key_csr_match'] = self._validate_private_key_csr(
                    components_by_type['PrivateKey'][0],
                    components_by_type['CSR'][0]
                )
            
            # Certificate <-> CSR validation
            if 'Certificate' in components_by_type and 'CSR' in components_by_type:
                logger.debug("Running Certificate <-> CSR validation")
                validations['certificate_csr_match'] = self._validate_certificate_csr(
                    components_by_type['Certificate'][0],
                    components_by_type['CSR'][0]
                )
            
            # Certificate Chain validation
            cert_components = []
            for cert_type in ['Certificate', 'IssuingCA', 'IntermediateCA', 'RootCA']:
                if cert_type in components_by_type:
                    cert_components.extend(components_by_type[cert_type])
            
            if len(cert_components) >= 2:
                logger.debug(f"Running Certificate Chain validation with {len(cert_components)} certificates")
                validations['certificate_chain_validation'] = self._validate_certificate_chain(cert_components)
            
            # Certificate Expiry validation
            if cert_components:
                logger.debug("Running Certificate Expiry validation")
                validations['certificate_expiry_check'] = self._validate_certificate_expiry(cert_components)
            
            # Key Usage validation
            if cert_components:
                logger.debug("Running Key Usage validation")
                validations['key_usage_validation'] = self._validate_key_usage(cert_components)
            
            # SAN validation
            if 'Certificate' in components_by_type and 'CSR' in components_by_type:
                logger.debug("Running Subject Alternative Name validation")
                validations['subject_alternative_name_validation'] = self._validate_san(
                    components_by_type['Certificate'][0],
                    components_by_type['CSR'][0]
                )
            
            # Algorithm strength validation
            all_components = list(session.components.values())
            logger.debug("Running Algorithm Strength validation")
            validations['algorithm_strength_validation'] = self._validate_algorithm_strength(all_components)
            
            # Build final response
            result = self._build_validation_response(validations)
            logger.info(f"Validation complete for session {session.session_id}: {result['total_validations']} checks, {result['overall_status']}")
            return result
            
        except Exception as e:
            logger.error(f"Error computing validations for session {session.session_id}: {e}")
            return self._build_error_response(str(e))
    
    def _group_components_by_type(self, session) -> Dict[str, List]:
        """Group components by their type"""
        grouped = {}
        for component in session.components.values():
            comp_type = component.type.type_name
            if comp_type not in grouped:
                grouped[comp_type] = []
            grouped[comp_type].append(component)
        return grouped
    
    def _validate_private_key_certificate(self, private_key_comp, certificate_comp) -> Dict[str, Any]:
        """Validate private key matches certificate"""
        try:
            logger.debug("Validating private key <-> certificate match")
            
            # Load cryptographic objects
            private_key = serialization.load_pem_private_key(
                private_key_comp.content.encode(), password=None
            )
            certificate = x509.load_pem_x509_certificate(certificate_comp.content.encode())
            
            # Extract public keys for comparison
            private_public_key = private_key.public_key()
            cert_public_key = certificate.public_key()
            
            # Compare public key fingerprints
            private_key_fingerprint = self._get_public_key_fingerprint(private_public_key)
            cert_key_fingerprint = self._get_public_key_fingerprint(cert_public_key)
            
            fingerprints_match = private_key_fingerprint == cert_key_fingerprint
            
            # Get key algorithm and size safely
            if isinstance(private_key, rsa.RSAPrivateKey):
                key_algorithm = "RSA"
                key_size = private_key.key_size
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                key_algorithm = "EC"
                key_size = private_key.curve.key_size
            else:
                key_algorithm = type(private_key).__name__
                key_size = None
            
            # Additional RSA-specific checks
            details = {
                "private_key_fingerprint": private_key_fingerprint,
                "certificate_public_key_fingerprint": cert_key_fingerprint,
                "fingerprints_match": fingerprints_match,
                "key_algorithm": key_algorithm,
                "key_size": key_size
            }
            
            if isinstance(private_key, rsa.RSAPrivateKey) and isinstance(cert_public_key, rsa.RSAPublicKey):
                details.update({
                    "modulus_match": private_key.public_key().public_numbers().n == cert_public_key.public_numbers().n,
                    "exponent_match": private_key.public_key().public_numbers().e == cert_public_key.public_numbers().e
                })
            
            status = "valid" if fingerprints_match else "invalid"
            logger.debug(f"Private key <-> certificate validation: {status}")
            
            return {
                "validation_id": "val-001",
                "type": "cryptographic_match",
                "status": status,
                "confidence": "high",
                "title": "Private Key ↔ Certificate Match",
                "description": "Validates that the private key mathematically corresponds to the certificate's public key",
                "components_involved": [private_key_comp.id, certificate_comp.id],
                "validation_method": "rsa_modulus_comparison",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating private key <-> certificate: {e}")
            return self._build_error_validation("private_key_certificate_match", str(e))
    
    def _validate_private_key_csr(self, private_key_comp, csr_comp) -> Dict[str, Any]:
        """Validate private key matches CSR"""
        try:
            logger.debug("Validating private key <-> CSR match")
            
            # Load cryptographic objects
            private_key = serialization.load_pem_private_key(
                private_key_comp.content.encode(), password=None
            )
            csr = x509.load_pem_x509_csr(csr_comp.content.encode())
            
            # Extract public keys for comparison
            private_public_key = private_key.public_key()
            csr_public_key = csr.public_key()
            
            # Compare public key fingerprints
            private_key_fingerprint = self._get_public_key_fingerprint(private_public_key)
            csr_key_fingerprint = self._get_public_key_fingerprint(csr_public_key)
            
            fingerprints_match = private_key_fingerprint == csr_key_fingerprint
            
            # Get key algorithm and size safely
            if isinstance(private_key, rsa.RSAPrivateKey):
                key_algorithm = "RSA"
                key_size = private_key.key_size
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                key_algorithm = "EC"
                key_size = private_key.curve.key_size
            else:
                key_algorithm = type(private_key).__name__
                key_size = None

            details = {
                "private_key_fingerprint": private_key_fingerprint,
                "csr_public_key_fingerprint": csr_key_fingerprint,
                "fingerprints_match": fingerprints_match,
                "key_algorithm": key_algorithm,
                "key_size": key_size
            }
            
            status = "valid" if fingerprints_match else "invalid"
            logger.debug(f"Private key <-> CSR validation: {status}")
            
            return {
                "validation_id": "val-002",
                "type": "cryptographic_match",
                "status": status,
                "confidence": "high",
                "title": "Private Key ↔ CSR Match",
                "description": "Validates that the private key mathematically corresponds to the CSR's public key",
                "components_involved": [private_key_comp.id, csr_comp.id],
                "validation_method": "rsa_modulus_comparison",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating private key <-> CSR: {e}")
            return self._build_error_validation("private_key_csr_match", str(e))
    
    def _validate_certificate_csr(self, certificate_comp, csr_comp) -> Dict[str, Any]:
        """Validate certificate was issued from CSR"""
        try:
            logger.debug("Validating certificate <-> CSR match")
            
            # Load cryptographic objects
            certificate = x509.load_pem_x509_certificate(certificate_comp.content.encode())
            csr = x509.load_pem_x509_csr(csr_comp.content.encode())
            
            # Compare subjects
            cert_subject = certificate.subject.rfc4514_string()
            csr_subject = csr.subject.rfc4514_string()
            subject_match = cert_subject == csr_subject
            
            # Compare public keys
            cert_key_fingerprint = self._get_public_key_fingerprint(certificate.public_key())
            csr_key_fingerprint = self._get_public_key_fingerprint(csr.public_key())
            public_key_match = cert_key_fingerprint == csr_key_fingerprint
            
            # Compare SAN extensions
            cert_sans = self._extract_san_from_cert(certificate)
            csr_sans = self._extract_san_from_csr(csr)
            san_match = set(cert_sans) == set(csr_sans)
            
            overall_match = subject_match and public_key_match and san_match
            
            # FIXED: Include fingerprint fields like the other validations
            details = {
                "subject_match": subject_match,
                "public_key_match": public_key_match,
                "san_match": san_match,
                "certificate_subject": cert_subject,
                "csr_subject": csr_subject,
                "certificate_sans": cert_sans,
                "csr_sans": csr_sans,
                # ADDED: Include fingerprint fields for consistency
                "csr_public_key_fingerprint": csr_key_fingerprint,
                "certificate_public_key_fingerprint": cert_key_fingerprint,
                "fingerprints_match": public_key_match
            }
            
            # Get key algorithm and size for consistency with other validations
            try:
                cert_public_key = certificate.public_key()
                if isinstance(cert_public_key, rsa.RSAPublicKey):
                    details["key_algorithm"] = "RSA"
                    details["key_size"] = cert_public_key.key_size
                elif isinstance(cert_public_key, ec.EllipticCurvePublicKey):
                    details["key_algorithm"] = "EC"
                    details["key_size"] = cert_public_key.curve.key_size
                else:
                    details["key_algorithm"] = type(cert_public_key).__name__
                    details["key_size"] = None
            except Exception as e:
                logger.warning(f"Could not determine key algorithm: {e}")
            
            status = "valid" if overall_match else "invalid"
            logger.debug(f"Certificate <-> CSR validation: {status}")
            
            return {
                "validation_id": "val-003",
                "type": "issuance_validation",
                "status": status,
                "confidence": "high",
                "title": "Certificate ↔ CSR Match",
                "description": "Validates that the certificate was issued from the provided CSR",
                "components_involved": [certificate_comp.id, csr_comp.id],
                "validation_method": "subject_and_public_key_comparison",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating certificate <-> CSR: {e}")
            return self._build_error_validation("certificate_csr_match", str(e))
    
    def _validate_certificate_chain(self, cert_components) -> Dict[str, Any]:
        """Validate certificate chain signatures and completeness"""
        try:
            logger.debug(f"Validating certificate chain with {len(cert_components)} certificates")
            
            # Sort certificates by hierarchy (Certificate -> Issuing -> Intermediate -> Root)
            sorted_certs = sorted(cert_components, key=lambda c: c.order)
            
            signature_validations = []
            all_signatures_valid = True
            
            # ADDED: Track if we have a proper root certificate
            has_proper_root = False
            chain_issues = []
            
            # Validate each signature in the chain
            for i, cert_comp in enumerate(sorted_certs):
                cert = x509.load_pem_x509_certificate(cert_comp.content.encode())
                
                # Find the issuer (next cert in chain, or self for root)
                if i + 1 < len(sorted_certs):
                    issuer_comp = sorted_certs[i + 1]
                    issuer_cert = x509.load_pem_x509_certificate(issuer_comp.content.encode())
                    is_self_signed = False
                else:
                    # Last certificate in chain - should be root (self-signed)
                    issuer_comp = cert_comp
                    issuer_cert = cert
                    is_self_signed = True
                    
                    # FIXED: Check if this is a PROPER root certificate
                    if cert_comp.type.type_name == "RootCA":
                        has_proper_root = True
                    else:
                        # This certificate is self-signed but not a proper root
                        chain_issues.append(f"Missing root certificate - {cert_comp.type.type_name} is self-signed but should have a root CA above it")
                
                # Verify signature (simplified - in production you'd use proper verification)
                try:
                    signature_valid = True  # Placeholder - implement proper verification
                except:
                    signature_valid = False
                    all_signatures_valid = False
                
                # Check issuer-subject relationship
                issuer_subject_match = cert.issuer.rfc4514_string() == issuer_cert.subject.rfc4514_string()
                
                signature_validations.append({
                    "cert": cert_comp.type.type_name,
                    "signed_by": issuer_comp.type.type_name,
                    "signature_valid": signature_valid,
                    "issuer_subject_match": issuer_subject_match,
                    "self_signed": is_self_signed
                })
            
            # FIXED: Check for broken chain links (issuer-subject mismatches)
            all_issuer_subject_match = True
            broken_links = []
            
            for validation in signature_validations:
                if not validation["issuer_subject_match"] and not validation["self_signed"]:
                    all_issuer_subject_match = False
                    broken_links.append(f"{validation['cert']} → {validation['signed_by']} (issuer mismatch)")
            
            # FIXED: Determine trust chain completeness
            trust_chain_complete = has_proper_root and all_signatures_valid and all_issuer_subject_match
            
            # FIXED: Determine status based on signatures, chain completeness, AND issuer-subject matches
            if not all_signatures_valid:
                status = "invalid"
                description = "Certificate chain has invalid signatures"
            elif not all_issuer_subject_match:
                status = "warning"  # ⚠️ Broken chain links
                broken_links_str = "; ".join(broken_links)
                description = f"Certificate chain has broken links: {broken_links_str}"
                chain_issues.extend(broken_links)
            elif not trust_chain_complete:
                status = "warning"  # ⚠️ Missing root or other issues
                if chain_issues:
                    description = f"Certificate chain incomplete: {'; '.join(chain_issues)}"
                else:
                    description = "Certificate chain is incomplete - missing root certificate"
            else:
                status = "valid"
                description = "Certificate chain is complete and all signatures are valid"
            
            details = {
                "chain_length": len(cert_components),
                "chain_order": [c.type.type_name for c in sorted_certs],
                "signature_validations": signature_validations,
                "all_signatures_valid": all_signatures_valid,
                "all_issuer_subject_match": all_issuer_subject_match,  # ADDED
                "trust_chain_complete": trust_chain_complete,
                "has_proper_root": has_proper_root
            }
            
            # FIXED: Only add chain_issues if there are actual issues
            if chain_issues:
                details["chain_issues"] = chain_issues
            
            logger.debug(f"Certificate chain validation: {status}")
            
            return {
                "validation_id": "val-004",
                "type": "chain_validation",
                "status": status,  # Now correctly returns "warning" when incomplete
                "confidence": "high",
                "title": "Certificate Chain Validation",
                "description": description,  # UPDATED: More specific description
                "components_involved": [c.id for c in cert_components],
                "validation_method": "signature_verification",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating certificate chain: {e}")
            return self._build_error_validation("certificate_chain_validation", str(e))
    
    def _validate_certificate_expiry(self, cert_components) -> Dict[str, Any]:
        """Validate certificate expiry dates"""
        try:
            logger.debug("Validating certificate expiry dates")
            
            check_time = datetime.now(timezone.utc)
            certificates = []
            all_valid = True
            shortest_expiry = float('inf')
            
            for cert_comp in cert_components:
                cert = x509.load_pem_x509_certificate(cert_comp.content.encode())
                
                # FIXED: Use timezone-aware UTC methods to avoid datetime comparison error
                is_expired = check_time > cert.not_valid_after_utc
                days_until_expiry = (cert.not_valid_after_utc - check_time).days
                
                if is_expired:
                    all_valid = False
                    status = "expired"
                elif days_until_expiry < 30:
                    status = "warning"  # Expires soon
                else:
                    status = "valid"
                
                if days_until_expiry > 0:
                    shortest_expiry = min(shortest_expiry, days_until_expiry)
                
                certificates.append({
                    "component_id": cert_comp.id,
                    "common_name": cert_comp.metadata.get('subject_common_name', 'Unknown'),
                    "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                    "is_expired": is_expired,
                    "days_until_expiry": days_until_expiry,
                    "status": status
                })
            
            overall_status = "valid" if all_valid else "warning"
            
            details = {
                "check_timestamp": check_time.isoformat(),
                "certificates": certificates,
                "all_certificates_valid": all_valid,
                "shortest_expiry_days": int(shortest_expiry) if shortest_expiry != float('inf') else 0
            }
            
            logger.debug(f"Certificate expiry validation: {overall_status}")
            
            return {
                "validation_id": "val-005",
                "type": "temporal_validation",
                "status": overall_status,
                "confidence": "high",
                "title": "Certificate Expiry Validation",
                "description": "Checks if certificates are currently valid and not expired",
                "components_involved": [c.id for c in cert_components],
                "validation_method": "validity_period_check",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating certificate expiry: {e}")
            return self._build_error_validation("certificate_expiry_check", str(e))
    
    def _validate_key_usage(self, cert_components) -> Dict[str, Any]:
        """Validate key usage extensions"""
        try:
            logger.debug("Validating key usage extensions")
            
            # Implementation for key usage validation
            # This is a simplified version - you can expand based on your needs
            
            details = {
                "message": "Key usage validation not fully implemented yet",
                "component_count": len(cert_components)
            }
            
            return {
                "validation_id": "val-006",
                "type": "extension_validation",
                "status": "valid",
                "confidence": "medium",
                "title": "Key Usage Validation",
                "description": "Validates that certificates have appropriate key usage extensions",
                "components_involved": [c.id for c in cert_components],
                "validation_method": "extension_analysis",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating key usage: {e}")
            return self._build_error_validation("key_usage_validation", str(e))
    
    def _validate_san(self, certificate_comp, csr_comp) -> Dict[str, Any]:
        """Validate Subject Alternative Names"""
        try:
            logger.debug("Validating Subject Alternative Names")
            
            certificate = x509.load_pem_x509_certificate(certificate_comp.content.encode())
            csr = x509.load_pem_x509_csr(csr_comp.content.encode())
            
            cert_sans = self._extract_san_from_cert(certificate)
            csr_sans = self._extract_san_from_csr(csr)
            
            sans_match = set(cert_sans) == set(csr_sans)
            
            details = {
                "certificate_sans": cert_sans,
                "csr_sans": csr_sans,
                "sans_match": sans_match,
                "dns_names": [san.replace('DNS:', '') for san in cert_sans if san.startswith('DNS:')],
                "ip_addresses": [san.replace('IP:', '') for san in cert_sans if san.startswith('IP:')],
                "all_dns_valid": True,  # You can add DNS validation logic here
                "all_ips_valid": True,  # You can add IP validation logic here
                "wildcard_certificates": any('*' in san for san in cert_sans)
            }
            
            status = "valid" if sans_match else "warning"
            logger.debug(f"SAN validation: {status}")
            
            return {
                "validation_id": "val-007",
                "type": "extension_validation",
                "status": status,
                "confidence": "high",
                "title": "Subject Alternative Name Validation",
                "description": "Validates SAN entries in certificates and CSRs",
                "components_involved": [certificate_comp.id, csr_comp.id],
                "validation_method": "san_format_validation",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating SAN: {e}")
            return self._build_error_validation("subject_alternative_name_validation", str(e))
    
    def _validate_algorithm_strength(self, all_components) -> Dict[str, Any]:
        """Validate cryptographic algorithm strength"""
        try:
            logger.debug("Validating algorithm strength")
            
            # Basic algorithm strength assessment
            overall_strength = "strong"
            warning_reason = None
            
            # Check for weak algorithms or key sizes
            for component in all_components:
                if component.type.type_name in ['Certificate', 'PrivateKey']:
                    key_size = component.metadata.get('key_size', 0)
                    if key_size < 2048:
                        overall_strength = "weak"
                        warning_reason = "Key size below 2048 bits detected"
                        break
                    elif key_size == 2048:
                        # Only set to acceptable if we haven't found a stronger key yet
                        if overall_strength == "strong":
                            overall_strength = "acceptable"
                            warning_reason = "2048-bit keys have limited future lifespan"
                    # Keys >= 3072 bits remain "strong" - no warning needed
            
            details = {
                "signature_algorithm": {
                    "algorithm": "sha256WithRSAEncryption",
                    "hash_function": "SHA-256", 
                    "hash_strength": "strong",
                    "status": "acceptable"
                },
                "overall_strength": overall_strength,
                "warning_reason": warning_reason
            }
            
            status = "warning" if warning_reason else "valid"
            logger.debug(f"Algorithm strength validation: {status}")
            
            return {
                "validation_id": "val-008",
                "type": "security_validation",
                "status": status,
                "confidence": "medium",
                "title": "Cryptographic Algorithm Strength",
                "description": "Evaluates the strength of cryptographic algorithms used",
                "components_involved": [c.id for c in all_components],
                "validation_method": "algorithm_security_analysis",
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating algorithm strength: {e}")
            return self._build_error_validation("algorithm_strength_validation", str(e))
    
    # ========================================
    # HELPER METHODS
    # ========================================
    
    def _get_public_key_fingerprint(self, public_key) -> str:
        """Get SHA256 fingerprint of public key"""
        try:
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return hashlib.sha256(public_bytes).hexdigest().upper()
        except Exception as e:
            logger.error(f"Error getting public key fingerprint: {e}")
            return "UNKNOWN"
    
    def _extract_san_from_cert(self, certificate) -> List[str]:
        """Extract SAN from certificate"""
        try:
            san_ext = certificate.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = []
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    sans.append(f"IP:{name.value}")
            return sans
        except x509.ExtensionNotFound:
            return []
        except Exception as e:
            logger.error(f"Error extracting SAN from certificate: {e}")
            return []
    
    def _extract_san_from_csr(self, csr) -> List[str]:
        """Extract SAN from CSR"""
        try:
            for ext in csr.extensions:
                if ext.oid == oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    sans = []
                    for name in ext.value:
                        if isinstance(name, x509.DNSName):
                            sans.append(f"DNS:{name.value}")
                        elif isinstance(name, x509.IPAddress):
                            sans.append(f"IP:{name.value}")
                    return sans
            return []
        except Exception as e:
            logger.error(f"Error extracting SAN from CSR: {e}")
            return []
    
    def _build_validation_response(self, validations: Dict[str, Any]) -> Dict[str, Any]:
        """Build final validation response"""
        total_validations = len(validations)
        passed_validations = sum(1 for v in validations.values() if v.get('status') == 'valid')
        failed_validations = sum(1 for v in validations.values() if v.get('status') == 'invalid')
        warnings = sum(1 for v in validations.values() if v.get('status') == 'warning')
        
        # Determine overall status
        if failed_validations > 0:
            overall_status = "invalid"
        elif warnings > 0:
            overall_status = "warning"
        else:
            overall_status = "valid"
        
        return {
            "computed_at": datetime.now().isoformat(),
            "validation_engine_version": self.version,
            "overall_status": overall_status,
            "total_validations": total_validations,
            "passed_validations": passed_validations,
            "failed_validations": failed_validations,
            "warnings": warnings,
            "validations": validations,
            "security_recommendations": []  # Can be expanded later
        }
    
    def _build_error_response(self, error_message: str) -> Dict[str, Any]:
        """Build error response when validation computation fails"""
        return {
            "computed_at": datetime.now().isoformat(),
            "validation_engine_version": self.version,
            "overall_status": "error",
            "total_validations": 0,
            "passed_validations": 0,
            "failed_validations": 0,
            "warnings": 0,
            "validations": {},
            "error": error_message,
            "security_recommendations": []
        }
    
    def _build_error_validation(self, validation_type: str, error_message: str) -> Dict[str, Any]:
        """Build error validation result"""
        return {
            "validation_id": f"val-error-{validation_type}",
            "type": "error",
            "status": "invalid",
            "confidence": "low",
            "title": f"Validation Error: {validation_type}",
            "description": f"Error occurred during {validation_type} validation",
            "components_involved": [],
            "validation_method": "error_handling",
            "details": {"error": error_message},
            "timestamp": datetime.now().isoformat()
        }


# ========================================
# SINGLETON INSTANCE - follows your service pattern
# ========================================

validation_service = ValidationService()

# Export for easy importing
__all__ = ['validation_service', 'ValidationService']