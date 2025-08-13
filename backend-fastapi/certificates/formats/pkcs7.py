# certificates/formats/pkcs7.py
# PKCS7 format analysis functions with comprehensive debugging

import logging
import re
import base64
from ..utils.hashing import generate_certificate_hash, generate_file_hash
from typing import Dict, Any, Optional, List
from cryptography import x509
from cryptography.x509 import oid

from ..extractors.certificate import extract_certificate_metadata

logger = logging.getLogger(__name__)

logger.debug("formats/pkcs7.py initialized")

def analyze_pkcs7(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze PKCS7 content - main entry point"""
    logger.info(f"=== PKCS7 ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"First 32 bytes (hex): {file_content[:32].hex()}")
    
    try:
        # Try to decode as text first for PEM format
        logger.debug("Attempting to decode PKCS7 content as UTF-8...")
        try:
            content_str = file_content.decode('utf-8')
            is_pem = '-----BEGIN' in content_str
            logger.debug(f"UTF-8 decode successful, content length: {len(content_str)} chars")
            logger.debug(f"Contains PEM markers: {is_pem}")
            
            if is_pem:
                logger.debug("PEM markers found in PKCS7 content:")
                for line in content_str.split('\n')[:10]:
                    if '-----' in line:
                        logger.debug(f"  PEM marker: {line.strip()}")
                        
        except UnicodeDecodeError as decode_err:
            content_str = None
            is_pem = False
            logger.debug(f"UTF-8 decode failed: {decode_err}. Treating as binary PKCS7.")
        
        if is_pem and content_str:
            logger.info("Routing to PEM PKCS7 analyzer...")
            # Handle PEM PKCS7
            return _analyze_pkcs7_pem(content_str, file_content)
        else:
            logger.info("Routing to DER PKCS7 analyzer...")
            # Handle DER PKCS7
            return _analyze_pkcs7_der(file_content)
            
    except Exception as e:
        logger.error(f"PKCS7 parsing failed: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "PKCS7 (Error)",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }

def _analyze_pkcs7_pem(content_str: str, file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM PKCS7 content"""
    logger.debug(f"Content string length: {len(content_str)} characters")
    
    try:
        certificates = []
        
        # Handle -----BEGIN PKCS7----- format
        logger.debug("Checking for -----BEGIN PKCS7----- format...")
        if '-----BEGIN PKCS7-----' in content_str:
            logger.debug("PKCS7 PEM block found")
            # Extract the base64 data between the markers
            pkcs7_match = re.search(
                r'-----BEGIN PKCS7-----\s*(.*?)\s*-----END PKCS7-----',
                content_str,
                re.DOTALL
            )
            
            if pkcs7_match:
                logger.debug("PKCS7 PEM block extracted successfully")
                # Decode the base64 PKCS7 data
                pkcs7_b64 = pkcs7_match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')
                logger.debug(f"Base64 PKCS7 data length: {len(pkcs7_b64)} chars")
                
                try:
                    pkcs7_der = base64.b64decode(pkcs7_b64)
                    logger.debug(f"Decoded PKCS7 DER length: {len(pkcs7_der)} bytes")
                    
                    # Extract certificates from the DER data
                    certificates = _extract_certificates_from_der(pkcs7_der)
                    logger.debug(f"Extracted {len(certificates)} certificates from PKCS7 DER")
                    
                except Exception as b64_err:
                    logger.error(f"Error decoding PKCS7 base64: {b64_err}")
        
        # Handle multiple -----BEGIN CERTIFICATE----- blocks (PKCS7-like)
        if not certificates:
            logger.debug("No PKCS7 block found, checking for multiple certificate blocks...")
            cert_blocks = re.findall(
                r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                content_str,
                re.DOTALL
            )
            
            logger.debug(f"Found {len(cert_blocks)} certificate blocks")
            
            if cert_blocks:
                for i, cert_block in enumerate(cert_blocks):
                    try:
                        logger.debug(f"Processing certificate block [{i}]...")
                        cert = x509.load_pem_x509_certificate(cert_block.encode())
                        certificates.append(cert)
                        logger.debug(f"Certificate [{i}] loaded successfully")
                    except Exception as cert_err:
                        logger.warning(f"Failed to parse certificate [{i}] in PKCS7: {cert_err}")
                        continue
        
        if certificates:
            logger.debug(f"Successfully extracted {len(certificates)} certificates from PEM PKCS7")
            return _process_certificate_chain(certificates, "PEM")
        else:
            logger.warning("No certificates found in PEM PKCS7 content")
            return {
                "type": "PKCS7 (No certificates found)",
                "isValid": False,
                "content_hash": generate_file_hash(file_content)
            }
            
    except Exception as e:
        logger.error(f"PEM PKCS7 parsing failed: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "PKCS7 (PEM Parse Error)",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }

def _analyze_pkcs7_der(file_content: bytes) -> Dict[str, Any]:
    """Analyze DER PKCS7 content"""
    logger.debug(f"=== DER PKCS7 ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"DER header analysis: {file_content[:16].hex()}")
    
    try:
        # Extract certificates from DER PKCS7 structure
        logger.debug("Attempting to extract certificates from DER PKCS7...")
        certificates = _extract_certificates_from_der(file_content)
        
        if certificates:
            logger.debug(f"Successfully extracted {len(certificates)} certificates from DER PKCS7")
            return _process_certificate_chain(certificates, "DER")
        else:
            logger.debug("No certificates found via PKCS7 parsing, trying single DER certificate fallback...")
            # Fallback: try to parse as single DER certificate
            try:
                cert = x509.load_der_x509_certificate(file_content)
                logger.debug("Successfully parsed as single DER certificate (PKCS7 fallback)")
                return _process_certificate_chain([cert], "DER")
            except Exception as fallback_err:
                logger.error(f"DER PKCS7 single certificate fallback failed: {fallback_err}")
                return {
                    "type": "PKCS7 (DER Parse Error)",
                    "isValid": False,
                    "content_hash": generate_file_hash(file_content),
                    "error": str(fallback_err)
                }
        
    except Exception as e:
        logger.error(f"DER PKCS7 parsing failed: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "PKCS7 (DER Error)",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }

def _process_certificate_chain(certificates: List, source_format: str) -> Dict[str, Any]:
    """Process a chain of certificates and return analysis result"""
    logger.debug(f"Processing {len(certificates)} certificates from {source_format} source")
    
    try:
        # Get the main certificate (first one)
        main_cert = certificates[0]
        logger.debug("Processing main certificate (first in chain)...")
        
        # Log main certificate details
        try:
            subject_cn = None
            for attribute in main_cert.subject:
                if attribute.oid._name == 'commonName':
                    subject_cn = attribute.value
                    break
            logger.debug(f"Main certificate subject CN: {subject_cn}")
            logger.debug(f"Main certificate serial: {main_cert.serial_number}")
        except Exception as cert_info_err:
            logger.debug(f"Error extracting main certificate info: {cert_info_err}")
        
        # Determine certificate type based on main certificate
        cert_type = _determine_certificate_type(main_cert)
        logger.debug(f"Main certificate type determined: {cert_type}")
        
        # Generate content hash from main certificate
        content_hash = generate_certificate_hash(main_cert)
        logger.debug(f"Main certificate hash: {content_hash[:16]}...")
        
        # Extract certificate metadata using new extractor
        logger.debug("Extracting main certificate metadata...")
        metadata = extract_certificate_metadata(main_cert)
        logger.debug(f"Main certificate metadata extracted, keys: {list(metadata.keys())}")
        
        result = {
            "type": cert_type,
            "isValid": True,
            "content_hash": content_hash,
            "details": metadata
        }
        
        # Add additional certificates if any
        if len(certificates) > 1:
            logger.debug(f"Processing {len(certificates) - 1} additional certificates...")
            additional_items = []
            
            for i, cert in enumerate(certificates[1:], 1):
                try:
                    logger.debug(f"Processing additional certificate [{i}]...")
                    
                    # Log additional certificate details
                    try:
                        subject_cn = None
                        for attribute in cert.subject:
                            if attribute.oid._name == 'commonName':
                                subject_cn = attribute.value
                                break
                        logger.debug(f"Additional cert [{i}] subject CN: {subject_cn}")
                    except Exception as add_cert_info_err:
                        logger.debug(f"Error extracting additional cert [{i}] info: {add_cert_info_err}")
                    
                    cert_hash = generate_certificate_hash(cert)
                    cert_metadata = extract_certificate_metadata(cert)
                    cert_type_additional = _determine_certificate_type(cert)
                    
                    logger.debug(f"Additional cert [{i}] hash: {cert_hash[:16]}...")
                    logger.debug(f"Additional cert [{i}] type: {cert_type_additional}")
                    
                    additional_items.append({
                        "type": cert_type_additional,
                        "format": "PKCS7",
                        "isValid": True,
                        "size": 0,
                        "content_hash": cert_hash,
                        "details": cert_metadata
                    })
                    logger.debug(f"Extracted additional certificate {i} from PKCS7")
                except Exception as cert_err:
                    logger.error(f"Error extracting additional certificate {i}: {cert_err}")
                    import traceback
                    logger.error(f"Additional cert extraction traceback: {traceback.format_exc()}")
            
            if additional_items:
                result["additional_items"] = additional_items
                logger.debug(f"Added {len(additional_items)} additional certificates to result")

        logger.debug(f"Successfully parsed {source_format} PKCS7 with {len(certificates)} certificates")
        return result
        
    except Exception as e:
        logger.error(f"Error processing certificate chain: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "PKCS7 (Processing Error)",
            "isValid": False,
            "content_hash": generate_file_hash(str(certificates).encode()),
            "error": str(e)
        }

def _extract_certificates_from_der(der_data: bytes) -> List:
    """Extract certificates from PKCS7 DER data"""
    logger.debug(f"=== DER CERTIFICATE EXTRACTION ===")
    logger.debug(f"DER data length: {len(der_data)} bytes")
    logger.debug(f"DER data header: {der_data[:32].hex()}")
    
    certificates = []
    
    try:
        # Look for certificate sequences (30 82 indicates SEQUENCE with long form)
        data_hex = der_data.hex()
        logger.debug(f"Searching for certificate patterns in {len(data_hex)} hex characters...")
        
        # Find potential certificate starts
        i = 0
        cert_count = 0
        
        while i < len(data_hex) - 8:
            if data_hex[i:i+4].lower() == '3082':
                logger.debug(f"Found potential certificate pattern at hex position {i}")
                try:
                    # Get the length (next 4 hex chars = 2 bytes)
                    length_hex = data_hex[i+4:i+8]
                    length = int(length_hex, 16)
                    logger.debug(f"Certificate length from header: {length} bytes")
                    
                    # Extract potential certificate
                    cert_start = i // 2  # Convert hex position to byte position
                    cert_length = length + 4  # Add the header length
                    
                    logger.debug(f"Extracting certificate: start={cert_start}, length={cert_length}")
                    
                    if cert_start + cert_length <= len(der_data):
                        cert_data = der_data[cert_start:cert_start + cert_length]
                        logger.debug(f"Extracted certificate data: {len(cert_data)} bytes")
                        
                        # Try to parse as certificate
                        try:
                            cert = x509.load_der_x509_certificate(cert_data)
                            certificates.append(cert)
                            cert_count += 1
                            
                            # Log certificate info
                            try:
                                subject_cn = None
                                for attribute in cert.subject:
                                    if attribute.oid._name == 'commonName':
                                        subject_cn = attribute.value
                                        break
                                logger.debug(f"Extracted certificate {cert_count} from PKCS7 DER: {subject_cn}")
                            except Exception as cert_info_err:
                                logger.debug(f"Extracted certificate {cert_count} from PKCS7 DER (info extraction failed)")
                            
                            # Skip past this certificate
                            i += cert_length * 2
                            continue
                            
                        except Exception as cert_parse_err:
                            logger.debug(f"Certificate parsing failed at position {cert_start}: {cert_parse_err}")
                            # Not a valid certificate, continue searching
                            pass
                    else:
                        logger.debug(f"Certificate would extend beyond data boundary")
                        
                except Exception as extract_err:
                    logger.debug(f"Error during certificate extraction: {extract_err}")
                    pass
            
            i += 2  # Move to next byte
        
        # Generate summary log
        additional_count = len(certificates) - 1 if len(certificates) > 1 else 0
        parts = [f"1 Certificate"]
        if additional_count > 0:
            parts.append(f"1 Chain ({additional_count} certs)")
        
        total = len(certificates)
        logger.info(f"PKCS7 extraction complete: {', '.join(parts)} ({total} total)")

        return certificates
        
    except Exception as e:
        logger.error(f"Error extracting certificates from PKCS7 DER: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return []

def _determine_certificate_type(cert) -> str:
    """Determine if certificate is CA or end-entity"""
    logger.debug("Determining certificate type (CA vs end-entity)...")
    
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        is_ca = basic_constraints.ca
        logger.debug(f"Basic Constraints found - CA: {is_ca}")
    except x509.ExtensionNotFound:
        is_ca = False
        logger.debug("No Basic Constraints extension found - assuming end-entity")
    except Exception as bc_err:
        logger.debug(f"Error checking Basic Constraints: {bc_err}")
        is_ca = False
    
    cert_type = "CA Certificate" if is_ca else "Certificate"
    logger.debug(f"Certificate type determined: {cert_type}")
    return cert_type