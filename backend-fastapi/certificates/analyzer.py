# certificates/analyzer.py
# Certificate analysis functions

import hashlib
import datetime
import logging
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)

def get_file_format(filename: str) -> str:
    """Determine file format from filename"""
    extension = filename.split('.')[-1].lower()
    format_map = {
        'pem': 'PEM',
        'crt': 'PEM',
        'cer': 'PEM',
        'der': 'DER',
        'p12': 'PKCS12',
        'pfx': 'PKCS12',
        'jks': 'JKS',
        'key': 'Private Key',
        'csr': 'CSR',
        'p8': 'PKCS8',
        'pk8': 'PKCS8'
    }
    return format_map.get(extension, extension.upper())

def extract_public_key_details(public_key) -> Dict[str, Any]:
    """Extract details from public key"""
    details = {
        "algorithm": "Unknown",
        "keySize": 0,
        "curve": "N/A"
    }
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            details["algorithm"] = "RSA"
            details["keySize"] = public_key.key_size
            details["exponent"] = str(public_key.public_numbers().e)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            details["algorithm"] = "EC"
            details["curve"] = public_key.curve.name
    except Exception as e:
        logger.warning(f"Error extracting public key details: {e}")
    
    return details

def extract_x509_details(cert: x509.Certificate) -> Dict[str, Any]:
    """Extract detailed information from X.509 certificate"""
    details = {
        "subject": {},
        "issuer": {},
        "validity": {},
        "publicKey": {},
        "signature": {},
        "extensions": {},
        "serialNumber": str(cert.serial_number)
    }
    
    try:
        # Subject information
        subject_attrs = {}
        for attribute in cert.subject:
            subject_attrs[attribute.oid._name] = attribute.value
        
        details["subject"] = {
            "commonName": subject_attrs.get("commonName", "N/A"),
            "organization": subject_attrs.get("organizationName", "N/A"),
            "organizationalUnit": subject_attrs.get("organizationalUnitName", "N/A"),
            "country": subject_attrs.get("countryName", "N/A"),
            "state": subject_attrs.get("stateOrProvinceName", "N/A"),
            "locality": subject_attrs.get("localityName", "N/A"),
            "emailAddress": subject_attrs.get("emailAddress", "N/A")
        }
        
        # Issuer information
        issuer_attrs = {}
        for attribute in cert.issuer:
            issuer_attrs[attribute.oid._name] = attribute.value
        
        details["issuer"] = {
            "commonName": issuer_attrs.get("commonName", "N/A"),
            "organization": issuer_attrs.get("organizationName", "N/A"),
            "organizationalUnit": issuer_attrs.get("organizationalUnitName", "N/A"),
            "country": issuer_attrs.get("countryName", "N/A")
        }
        
        # Validity period
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        is_expired = cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc)
        days_until_expiry = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days
        
        details["validity"] = {
            "notBefore": not_before,
            "notAfter": not_after,
            "isExpired": is_expired,
            "daysUntilExpiry": days_until_expiry
        }
        
        # Public key information
        public_key = cert.public_key()
        details["publicKey"] = extract_public_key_details(public_key)
        
        # Signature algorithm
        details["signature"] = {
            "algorithm": cert.signature_algorithm_oid._name,
            "algorithmOid": cert.signature_algorithm_oid.dotted_string
        }
        
        # Extensions
        extensions = {}
        for ext in cert.extensions:
            if isinstance(ext.value, x509.SubjectAlternativeName):
                san_list = []
                for name in ext.value:
                    if isinstance(name, x509.DNSName):
                        san_list.append({"type": 2, "typeName": "DNS", "value": name.value})
                    elif isinstance(name, x509.IPAddress):
                        san_list.append({"type": 7, "typeName": "IP", "value": str(name.value)})
                    elif isinstance(name, x509.RFC822Name):
                        san_list.append({"type": 1, "typeName": "Email", "value": name.value})
                extensions["subjectAltName"] = san_list
            elif isinstance(ext.value, x509.BasicConstraints):
                extensions["basicConstraints"] = {
                    "isCA": ext.value.ca,
                    "pathLength": ext.value.path_length
                }
            elif isinstance(ext.value, x509.KeyUsage):
                extensions["keyUsage"] = {
                    "digitalSignature": ext.value.digital_signature,
                    "keyEncipherment": ext.value.key_encipherment,
                    "keyAgreement": ext.value.key_agreement,
                    "keyCertSign": ext.value.key_cert_sign,
                    "crlSign": ext.value.crl_sign
                }
        
        details["extensions"] = extensions
        
    except Exception as e:
        logger.warning(f"Error extracting certificate details: {e}")
    
    return details

def extract_csr_details(csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
    """Extract details from CSR"""
    details = {
        "subject": {},
        "publicKey": {},
        "signature": {},
        "extensions": {}
    }
    
    try:
        # Subject information
        subject_attrs = {}
        for attribute in csr.subject:
            subject_attrs[attribute.oid._name] = attribute.value
        
        details["subject"] = {
            "commonName": subject_attrs.get("commonName", "N/A"),
            "organization": subject_attrs.get("organizationName", "N/A"),
            "organizationalUnit": subject_attrs.get("organizationalUnitName", "N/A"),
            "country": subject_attrs.get("countryName", "N/A"),
            "state": subject_attrs.get("stateOrProvinceName", "N/A"),
            "locality": subject_attrs.get("localityName", "N/A"),
            "emailAddress": subject_attrs.get("emailAddress", "N/A")
        }
        
        # Public key information
        public_key = csr.public_key()
        details["publicKey"] = extract_public_key_details(public_key)
        
        # Signature algorithm
        details["signature"] = {
            "algorithm": csr.signature_algorithm_oid._name,
            "algorithmOid": csr.signature_algorithm_oid.dotted_string
        }
        
    except Exception as e:
        logger.warning(f"Error extracting CSR details: {e}")
    
    return details

def extract_private_key_details(private_key) -> Dict[str, Any]:
    """Extract details from private key"""
    details = {
        "algorithm": "Unknown",
        "keySize": 0,
        "curve": "N/A"
    }
    
    try:
        if isinstance(private_key, rsa.RSAPrivateKey):
            details["algorithm"] = "RSA"
            details["keySize"] = private_key.key_size
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            details["algorithm"] = "EC"
            details["curve"] = private_key.curve.name
    except Exception as e:
        logger.warning(f"Error extracting private key details: {e}")
    
    return details

def generate_normalized_private_key_hash(private_key) -> str:
    """Generate a consistent hash for the same private key regardless of format or encryption"""
    try:
        # Always use the same normalization: DER + PKCS8 + No Encryption
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.info(f"Generated normalized hash: {hash_value} for private key (DER bytes length: {len(der_bytes)})")
        return hash_value
    except Exception as e:
        logger.error(f"Error generating normalized hash: {e}")
        fallback_hash = hashlib.sha256(str(private_key).encode()).hexdigest()
        logger.warning(f"Using fallback hash: {fallback_hash}")
        return fallback_hash

def generate_pkcs12_content_hash(cert, private_key, additional_certs) -> str:
    """Generate a consistent hash for PKCS12 content regardless of password protection"""
    try:
        hash_components = []
        
        # Hash the main certificate
        if cert:
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            hash_components.append(cert_der)
            logger.debug(f"Added main certificate to PKCS12 hash (DER length: {len(cert_der)})")
        
        # Hash the private key if present
        if private_key:
            key_der = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            hash_components.append(key_der)
            logger.debug(f"Added private key to PKCS12 hash (DER length: {len(key_der)})")
        
        # Hash additional certificates
        if additional_certs:
            for i, additional_cert in enumerate(additional_certs):
                if additional_cert:
                    additional_der = additional_cert.public_bytes(serialization.Encoding.DER)
                    hash_components.append(additional_der)
                    logger.debug(f"Added additional certificate {i} to PKCS12 hash (DER length: {len(additional_der)})")
        
        # Combine all components and hash
        if hash_components:
            combined_content = b''.join(sorted(hash_components))  # Sort for consistency
            content_hash = hashlib.sha256(combined_content).hexdigest()
            logger.info(f"Generated PKCS12 content hash: {content_hash} from {len(hash_components)} components")
            return content_hash
        else:
            # Fallback if no components found
            fallback_hash = hashlib.sha256(b'empty_pkcs12').hexdigest()
            logger.warning(f"No PKCS12 components found, using fallback hash: {fallback_hash}")
            return fallback_hash
            
    except Exception as e:
        logger.error(f"Error generating PKCS12 content hash: {e}")
        fallback_hash = hashlib.sha256(f"pkcs12_error_{str(e)}".encode()).hexdigest()
        return fallback_hash

def analyze_uploaded_certificate(file_content: bytes, filename: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Enhanced certificate analysis with password support"""
    analysis = {
        "type": "Unknown",
        "format": get_file_format(filename),
        "isValid": False,
        "size": len(file_content),
        "hash": hashlib.sha256(file_content).hexdigest(),
        "content_hash": None,
        "details": None,
        "requiresPassword": False
    }
    
    logger.info(f"Analyzing file: {filename}, size: {len(file_content)} bytes, format: {analysis['format']}")
    
    try:
        # Try to decode as text first
        try:
            content_str = file_content.decode('utf-8')
            is_pem = '-----BEGIN' in content_str
        except UnicodeDecodeError:
            content_str = None
            is_pem = False
        
        if is_pem and content_str:
            # Handle PEM format
            if '-----BEGIN CERTIFICATE-----' in content_str:
                # Check for certificate chain
                cert_blocks = content_str.count('-----BEGIN CERTIFICATE-----')
                if cert_blocks > 1:
                    analysis.update({
                        "type": "Certificate Chain",
                        "isValid": True,
                        "details": {"certificateCount": cert_blocks}
                    })
                    analysis["content_hash"] = hashlib.sha256(content_str.encode()).hexdigest()
                else:
                    # Single certificate
                    cert = x509.load_pem_x509_certificate(file_content)
                    
                    # Generate normalized hash from DER encoding
                    der_bytes = cert.public_bytes(serialization.Encoding.DER)
                    analysis["content_hash"] = hashlib.sha256(der_bytes).hexdigest()
                    
                    # Check if it's a CA certificate
                    try:
                        basic_constraints = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                        ).value
                        is_ca = basic_constraints.ca
                    except x509.ExtensionNotFound:
                        is_ca = False
                    
                    cert_type = "CA Certificate" if is_ca else "Certificate"
                    details = extract_x509_details(cert)
                    
                    analysis.update({
                        "type": cert_type,
                        "isValid": True,
                        "details": details
                    })
                    
            elif '-----BEGIN CERTIFICATE REQUEST-----' in content_str:
                csr = x509.load_pem_x509_csr(file_content)
                
                # Generate normalized hash from DER encoding
                der_bytes = csr.public_bytes(serialization.Encoding.DER)
                analysis["content_hash"] = hashlib.sha256(der_bytes).hexdigest()
                
                details = extract_csr_details(csr)
                analysis.update({
                    "type": "CSR",
                    "isValid": True,
                    "details": details
                })
                
            elif ('-----BEGIN PRIVATE KEY-----' in content_str or 
                  '-----BEGIN RSA PRIVATE KEY-----' in content_str or
                  '-----BEGIN EC PRIVATE KEY-----' in content_str or
                  '-----BEGIN ENCRYPTED PRIVATE KEY-----' in content_str):
                
                # Try to parse first, then check if it needs password
                try:
                    # Try to load the private key without password first
                    private_key = serialization.load_pem_private_key(file_content, password=None)
                    
                    # If we get here, it's unencrypted - use normalized hash
                    normalized_hash = generate_normalized_private_key_hash(private_key)
                    analysis["content_hash"] = normalized_hash
                    
                    details = extract_private_key_details(private_key)
                    logger.info(f"Successfully parsed unencrypted PEM private key, content_hash: {normalized_hash}")
                    analysis.update({
                        "type": "Private Key",
                        "isValid": True,
                        "details": details
                    })
                    
                except Exception as e:
                    # Failed to load without password - check if it's encrypted
                    error_str = str(e).lower()
                    if any(keyword in error_str for keyword in ['password', 'decrypt', 'encrypted', 'bad decrypt']):
                        # It's encrypted - check if password was provided
                        if not password:
                            analysis.update({
                                "type": "Private Key - Password Required",
                                "isValid": False,
                                "requiresPassword": True,
                                "details": {
                                    "algorithm": "Encrypted (password required)",
                                    "keySize": 0,
                                    "curve": "N/A",
                                    "encrypted": True,
                                    "requiresPassword": True
                                }
                            })
                            analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                        else:
                            # Password provided, try with password
                            try:
                                password_bytes = password.encode('utf-8')
                                private_key = serialization.load_pem_private_key(file_content, password=password_bytes)
                                
                                # Success with password - use normalized hash from decrypted key
                                normalized_hash = generate_normalized_private_key_hash(private_key)
                                analysis["content_hash"] = normalized_hash
                                
                                details = extract_private_key_details(private_key)
                                logger.info(f"Successfully decrypted PEM private key with password, content_hash: {normalized_hash}")
                                analysis.update({
                                    "type": "Private Key",
                                    "isValid": True,
                                    "details": details
                                })
                            except Exception as pwd_error:
                                # Wrong password
                                analysis.update({
                                    "type": "Private Key - Invalid Password",
                                    "isValid": False,
                                    "requiresPassword": True,
                                    "details": {
                                        "algorithm": "Encrypted (incorrect password)",
                                        "keySize": 0,
                                        "curve": "N/A",
                                        "encrypted": True,
                                        "requiresPassword": True
                                    }
                                })
                                analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                                logger.info(f"Invalid password for encrypted PEM private key")
                    else:
                        # Some other parsing error
                        analysis.update({
                            "type": "Private Key",
                            "isValid": False,
                            "error": str(e)
                        })
                        analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                        logger.info(f"PEM private key parsing failed: {e}")
                            
            elif '-----BEGIN PUBLIC KEY-----' in content_str:
                try:
                    public_key = serialization.load_pem_public_key(file_content)
                    
                    # Generate normalized hash from DER encoding
                    der_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    analysis["content_hash"] = hashlib.sha256(der_bytes).hexdigest()
                    
                    details = extract_public_key_details(public_key)
                    analysis.update({
                        "type": "Public Key",
                        "isValid": True,
                        "details": details
                    })
                except Exception as e:
                    analysis.update({
                        "type": "Public Key",
                        "isValid": False,
                        "error": str(e)
                    })
                    analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
        else:
            # Handle binary formats (DER, PKCS12, PKCS8, etc.)
            if analysis['format'] in ['DER', 'PKCS8']:
                try:
                    # First try to parse as DER certificate
                    try:
                        cert = x509.load_der_x509_certificate(file_content)
                        
                        # Generate normalized hash by re-encoding to DER format
                        der_bytes = cert.public_bytes(serialization.Encoding.DER)
                        analysis["content_hash"] = hashlib.sha256(der_bytes).hexdigest()
                        
                        details = extract_x509_details(cert)
                        
                        # Check if it's a CA certificate
                        try:
                            basic_constraints = cert.extensions.get_extension_for_oid(
                                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                            ).value
                            is_ca = basic_constraints.ca
                        except x509.ExtensionNotFound:
                            is_ca = False
                        
                        cert_type = "CA Certificate" if is_ca else "Certificate"
                        logger.info(f"Successfully parsed as DER {cert_type}")
                        analysis.update({
                            "type": cert_type,
                            "isValid": True,
                            "details": details
                        })
                    except Exception:
                        # Not a certificate, try parsing as CSR
                        try:
                            csr = x509.load_der_x509_csr(file_content)
                            
                            # Generate normalized hash by re-encoding to DER format
                            der_bytes = csr.public_bytes(serialization.Encoding.DER)
                            analysis["content_hash"] = hashlib.sha256(der_bytes).hexdigest()
                            
                            details = extract_csr_details(csr)
                            logger.info(f"Successfully parsed as DER CSR")
                            analysis.update({
                                "type": "CSR",
                                "isValid": True,
                                "details": details
                            })
                        except Exception:
                            # Not a CSR either, try private key
                            try:
                                # Try without password first
                                private_key = serialization.load_der_private_key(file_content, password=None)
                                
                                # Generate normalized hash
                                normalized_hash = generate_normalized_private_key_hash(private_key)
                                analysis["content_hash"] = normalized_hash
                                
                                details = extract_private_key_details(private_key)
                                logger.info(f"Successfully parsed as DER Private Key, content_hash: {normalized_hash}")
                                analysis.update({
                                    "type": "Private Key",
                                    "isValid": True,
                                    "details": details
                                })
                            except Exception as key_error:
                                # Check if it might be an encrypted DER/PKCS8 key
                                error_str = str(key_error).lower()
                                if any(keyword in error_str for keyword in ['encrypted', 'password', 'decrypt', 'bad decrypt']):
                                    logger.info(f"Detected encrypted DER private key")
                                    if password is None:
                                        analysis.update({
                                            "type": "Private Key - Password Required",
                                            "isValid": False,
                                            "requiresPassword": True,
                                            "details": {
                                                "algorithm": "Encrypted (password required)",
                                                "keySize": 0,
                                                "curve": "N/A",
                                                "encrypted": True,
                                                "format": "DER/PKCS8"
                                            }
                                        })
                                        analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                                    else:
                                        # Try with provided password
                                        try:
                                            password_bytes = password.encode('utf-8')
                                            private_key = serialization.load_der_private_key(file_content, password=password_bytes)
                                            
                                            # Success with password - use normalized hash
                                            normalized_hash = generate_normalized_private_key_hash(private_key)
                                            analysis["content_hash"] = normalized_hash
                                            
                                            details = extract_private_key_details(private_key)
                                            logger.info(f"Successfully decrypted DER Private Key with password, content_hash: {normalized_hash}")
                                            analysis.update({
                                                "type": "Private Key",
                                                "isValid": True,
                                                "details": details
                                            })
                                        except Exception as pwd_error:
                                            # Wrong password
                                            analysis.update({
                                                "type": "Private Key - Invalid Password",
                                                "isValid": False,
                                                "requiresPassword": True,
                                                "details": {
                                                    "algorithm": "Encrypted (incorrect password)",
                                                    "keySize": 0,
                                                    "curve": "N/A",
                                                    "encrypted": True,
                                                    "format": "DER/PKCS8"
                                                }
                                            })
                                            analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                                else:
                                    # Unknown DER format
                                    analysis.update({
                                        "type": "Unknown DER",
                                        "isValid": False
                                    })
                                    analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                                    
                except Exception as e:
                    logger.error(f"DER parsing error: {e}")
                    analysis.update({
                        "type": "Unknown Binary",
                        "isValid": False,
                        "error": str(e)
                    })
                    analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                    
            elif analysis['format'] == 'PKCS12':
                # Handle PKCS12 files - try without password first
                try:
                    # Try to parse PKCS12 without password first (many have no password)
                    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                        file_content, password=None
                    )
                    
                    # Success without password - generate normalized content hash
                    logger.info(f"Successfully parsed PKCS12 without password")
                    
                    # Always use the main certificate hash for duplicate detection
                    # This allows PKCS12 certificates to be detected as duplicates of standalone certificates
                    if cert:
                        # Use main certificate hash - same as standalone certificates
                        der_bytes = cert.public_bytes(serialization.Encoding.DER)
                        content_hash = hashlib.sha256(der_bytes).hexdigest()
                        logger.info(f"PKCS12 using main certificate hash for duplicate detection: {content_hash}")
                    else:
                        # No main certificate - use combined hash as fallback
                        content_hash = generate_pkcs12_content_hash(cert, private_key, additional_certs)
                        logger.info(f"PKCS12 no main certificate, using combined hash: {content_hash}")
                    
                    analysis.update({
                        "type": "PKCS12 Certificate",
                        "isValid": True
                    })
                    analysis["content_hash"] = content_hash
                    
                    # Extract certificate details if available
                    if cert:
                        details = extract_x509_details(cert)
                        analysis["details"] = details
                        
                except Exception as p12_err:
                    # Failed without password - check if it needs password
                    error_str = str(p12_err).lower()
                    logger.info(f"PKCS12 parsing without password failed: {p12_err}")
                    
                    if any(keyword in error_str for keyword in ['password', 'decrypt', 'invalid', 'mac', 'integrity']):
                        # It's password-protected - check if password was provided
                        if not password:
                            analysis.update({
                                "type": "PKCS12 Certificate - Password Required",
                                "isValid": False,
                                "requiresPassword": True,
                                "details": {
                                    "algorithm": "PKCS12 (password required)",
                                    "keySize": 0,
                                    "curve": "N/A",
                                    "encrypted": True,
                                    "requiresPassword": True
                                }
                            })
                            analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                        else:
                            # Password provided, try with password
                            try:
                                password_bytes = password.encode('utf-8')
                                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                                    file_content, password_bytes
                                )
                                
                                # Success with password - generate normalized content hash
                                logger.info(f"Successfully parsed PKCS12 with provided password")
                                
                                # Always use the main certificate hash for duplicate detection
                                if cert:
                                    # Use main certificate hash - same as standalone certificates
                                    der_bytes = cert.public_bytes(serialization.Encoding.DER)
                                    content_hash = hashlib.sha256(der_bytes).hexdigest()
                                    logger.info(f"PKCS12 using main certificate hash for duplicate detection: {content_hash}")
                                else:
                                    # No main certificate - use combined hash as fallback
                                    content_hash = generate_pkcs12_content_hash(cert, private_key, additional_certs)
                                    logger.info(f"PKCS12 no main certificate, using combined hash: {content_hash}")
                                
                                analysis.update({
                                    "type": "PKCS12 Certificate",
                                    "isValid": True
                                })
                                analysis["content_hash"] = content_hash
                                
                                # Extract certificate details if available
                                if cert:
                                    details = extract_x509_details(cert)
                                    analysis["details"] = details
                                    
                            except Exception as pwd_error:
                                # Wrong password
                                logger.info(f"PKCS12 parsing with provided password failed: {pwd_error}")
                                analysis.update({
                                    "type": "PKCS12 Certificate - Invalid Password",
                                    "isValid": False,
                                    "requiresPassword": True,
                                    "details": {
                                        "algorithm": "PKCS12 (incorrect password)",
                                        "keySize": 0,
                                        "curve": "N/A",
                                        "encrypted": True,
                                        "requiresPassword": True
                                    }
                                })
                                analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                    else:
                        # Some other PKCS12 parsing error (not password related)
                        logger.error(f"PKCS12 parsing failed with non-password error: {p12_err}")
                        analysis.update({
                            "type": "PKCS12 Certificate",
                            "isValid": False,
                            "error": str(p12_err)
                        })
                        analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
            else:
                # Unknown binary format
                analysis.update({
                    "type": "Unknown Binary",
                    "isValid": False
                })
                analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
                
    except Exception as e:
        logger.error(f"Certificate analysis error: {e}")
        analysis["error"] = str(e)
        # Ensure content_hash is set even on error
        if analysis["content_hash"] is None:
            analysis["content_hash"] = hashlib.sha256(file_content).hexdigest()
    
    # Only use file hash as fallback if content_hash is still None
    if analysis["content_hash"] is None:
        analysis["content_hash"] = analysis["hash"]
        logger.warning(f"Using file hash as fallback for content_hash: {analysis['hash']}")
    
    logger.info(f"Analysis complete: {analysis['type']}, content_hash: {analysis['content_hash']}, requiresPassword: {analysis['requiresPassword']}")
    return analysis