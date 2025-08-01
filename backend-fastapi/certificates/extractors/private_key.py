import logging
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.hazmat.primitives import serialization, hashes
import hashlib

logger = logging.getLogger(__name__)

logger.debug("extractors/private_key.py initialized")

def extract_private_key_metadata(private_key, is_encrypted: bool = False) -> Dict[str, Any]:
    """Extract flattened private key metadata for direct storage"""
    logger.info(f"=== PRIVATE KEY METADATA EXTRACTION ===")
    logger.debug(f"Private key object type: {type(private_key)}")
    logger.debug(f"Private key class name: {type(private_key).__name__}")
    
    # Calculate public key fingerprint
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_fingerprint = hashlib.sha256(public_bytes).hexdigest().upper()
    
    # Initialize flattened metadata with basic info
    metadata = {
        'algorithm': type(private_key).__name__.replace('PrivateKey', ''),
        'key_size': getattr(private_key, 'key_size', None),
        'is_encrypted': is_encrypted,
        'public_key_fingerprint': public_key_fingerprint
    }
    
    try:
        if isinstance(private_key, rsa.RSAPrivateKey):
            logger.debug("Processing RSA private key...")
            metadata['algorithm'] = "RSA"
            metadata['key_size'] = private_key.key_size
            
            # Extract RSA-specific details
            try:
                public_numbers = private_key.public_key().public_numbers()
                metadata['rsa_exponent'] = str(public_numbers.e)
                
                # Additional RSA debugging info
                logger.debug(f"RSA key size: {metadata['key_size']} bits")
                logger.debug(f"RSA public exponent: {metadata['rsa_exponent']}")
                
                # Log RSA key parameters (be careful with private info)
                private_numbers = private_key.private_numbers()
                modulus_bits = private_numbers.public_numbers.n.bit_length()
                metadata['rsa_modulus_bits'] = modulus_bits
                logger.debug(f"RSA modulus bit length: {modulus_bits}")
                logger.debug(f"RSA has p: {private_numbers.p is not None}")
                logger.debug(f"RSA has q: {private_numbers.q is not None}")
                
            except Exception as rsa_error:
                logger.error(f"Error extracting RSA details: {rsa_error}")
                
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            logger.debug("Processing EC private key...")
            metadata['algorithm'] = "EC"
            
            try:
                curve = private_key.curve
                metadata['ec_curve'] = curve.name
                metadata['key_size'] = curve.key_size
                
                logger.debug(f"EC curve name: {metadata['ec_curve']}")
                logger.debug(f"EC key size: {metadata['key_size']} bits")
                
                # Additional EC debugging info
                logger.debug(f"EC curve class: {type(curve).__name__}")
                curve_oid = getattr(curve, 'oid', None)
                if curve_oid is not None:
                    metadata['ec_curve_oid'] = curve_oid.dotted_string
                    logger.debug(f"EC curve OID: {metadata['ec_curve_oid']}")
                else:
                    logger.debug("EC curve has no OID attribute or OID is None")
                
                # Extract coordinate info safely
                try:
                    private_value_method = getattr(private_key, 'private_value', None)
                    if private_value_method is not None:
                        private_value = private_value_method()
                        metadata['ec_private_value_bits'] = private_value.bit_length()
                        logger.debug(f"EC private value bit length: {metadata['ec_private_value_bits']}")
                    else:
                        logger.debug("EC private key does not have private_value method")
                except Exception as pv_error:
                    logger.debug(f"Error accessing private_value(): {pv_error}")
                
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                metadata['ec_x_coord_bits'] = public_numbers.x.bit_length()
                metadata['ec_y_coord_bits'] = public_numbers.y.bit_length()
                logger.debug(f"EC public key X coordinate bit length: {metadata['ec_x_coord_bits']}")
                logger.debug(f"EC public key Y coordinate bit length: {metadata['ec_y_coord_bits']}")
                
            except Exception as ec_error:
                logger.error(f"Error extracting EC details: {ec_error}")
                
        elif isinstance(private_key, dsa.DSAPrivateKey):
            logger.debug("Processing DSA private key...")
            metadata['algorithm'] = "DSA"
            
            try:
                metadata['key_size'] = private_key.key_size
                logger.debug(f"DSA key size: {metadata['key_size']} bits")
                
                # Additional DSA debugging info
                private_numbers = private_key.private_numbers()
                public_numbers = private_numbers.public_numbers
                parameter_numbers = public_numbers.parameter_numbers
                
                metadata['dsa_p_bits'] = parameter_numbers.p.bit_length()
                metadata['dsa_q_bits'] = parameter_numbers.q.bit_length()
                metadata['dsa_g_bits'] = parameter_numbers.g.bit_length()
                metadata['dsa_y_bits'] = public_numbers.y.bit_length()
                
                logger.debug(f"DSA p bit length: {metadata['dsa_p_bits']}")
                logger.debug(f"DSA q bit length: {metadata['dsa_q_bits']}")
                logger.debug(f"DSA g bit length: {metadata['dsa_g_bits']}")
                logger.debug(f"DSA y bit length: {metadata['dsa_y_bits']}")
                
            except Exception as dsa_error:
                logger.error(f"Error extracting DSA details: {dsa_error}")
                
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            logger.debug("Processing Ed25519 private key...")
            metadata['algorithm'] = "Ed25519"
            metadata['key_size'] = 256  # Ed25519 is always 256 bits
            metadata['curve'] = "Ed25519"
            
            logger.debug("Ed25519 key processed (fixed 256-bit size)")
            
        elif isinstance(private_key, ed448.Ed448PrivateKey):
            logger.debug("Processing Ed448 private key...")
            metadata['algorithm'] = "Ed448"
            metadata['key_size'] = 448  # Ed448 is always 448 bits
            metadata['curve'] = "Ed448"
            
            logger.debug("Ed448 key processed (fixed 448-bit size)")
            
        else:
            logger.warning(f"Unknown private key type: {type(private_key)}")
            logger.warning(f"Private key attributes: {dir(private_key)}")
            
            # Try to extract basic info even for unknown types
            if hasattr(private_key, 'key_size'):
                try:
                    metadata['key_size'] = private_key.key_size
                    logger.debug(f"Unknown key type - extracted key size: {metadata['key_size']}")
                except Exception as size_error:
                    logger.error(f"Could not extract key size from unknown type: {size_error}")
            
            if hasattr(private_key, 'algorithm'):
                try:
                    metadata['algorithm'] = str(private_key.algorithm)
                    logger.debug(f"Unknown key type - extracted algorithm: {metadata['algorithm']}")
                except Exception as alg_error:
                    logger.error(f"Could not extract algorithm from unknown type: {alg_error}")
                    
    except Exception as e:
        logger.error(f"Error extracting private key details: {e}")
        logger.error(f"Private key object: {private_key}")
        logger.error(f"Private key type: {type(private_key)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Set error details
        metadata['error'] = str(e)
        metadata['algorithm'] = f"Error: {type(private_key).__name__}"
    
    logger.info(f"Private key metadata extraction complete")
    logger.debug(f"Final private key metadata: {metadata}")
    return metadata

def validate_private_key_consistency(private_key) -> Dict[str, Any]:
    """Validate private key internal consistency and log debugging info"""
    logger.debug(f"=== PRIVATE KEY VALIDATION ===")
    
    validation = {
        "isValid": False,
        "canSign": False,
        "canDerive": False,
        "hasPublicKey": False,
        "errors": []
    }
    
    try:
        # Test if we can extract public key
        try:
            public_key = private_key.public_key()
            validation["hasPublicKey"] = True
            logger.debug("Successfully extracted public key from private key")
        except Exception as pub_error:
            validation["errors"].append(f"Cannot extract public key: {pub_error}")
            logger.error(f"Cannot extract public key: {pub_error}")
        
        # Test signing capability (for signature algorithms)
        if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, dsa.DSAPrivateKey)):
            try:
                # Try to create a signature (don't actually sign, just check capability)
                test_data = b"test_signature_capability"
                
                if isinstance(private_key, rsa.RSAPrivateKey):
                    # Test RSA signing capability
                    from cryptography.hazmat.primitives.asymmetric import padding
                    signature = private_key.sign(test_data, padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ), hashes.SHA256())
                    validation["canSign"] = True
                    logger.debug(f"RSA signing test successful, signature length: {len(signature)}")
                    
                elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                    # Test EC signing capability  
                    signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))
                    validation["canSign"] = True
                    logger.debug(f"EC signing test successful, signature type: {type(signature)}")
                    
                elif isinstance(private_key, dsa.DSAPrivateKey):
                    # Test DSA signing capability
                    signature = private_key.sign(test_data, hashes.SHA256())
                    validation["canSign"] = True
                    logger.debug(f"DSA signing test successful, signature type: {type(signature)}")
                    
            except Exception as sign_error:
                validation["errors"].append(f"Cannot sign: {sign_error}")
                logger.error(f"Signing test failed: {sign_error}")
        
        # Test key derivation capability (for EC keys)
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            try:
                # Test if we can perform ECDH (key derivation)
                peer_public_key = private_key.public_key()  # Use own public key for test
                shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
                validation["canDerive"] = True
                logger.debug(f"EC key derivation test successful, shared key length: {len(shared_key)}")
            except Exception as derive_error:
                validation["errors"].append(f"Cannot derive keys: {derive_error}")
                logger.debug(f"Key derivation test failed (may be normal): {derive_error}")
        
        # Overall validation
        validation["isValid"] = (validation["hasPublicKey"] and 
                               (validation["canSign"] or validation["canDerive"]) and 
                               len(validation["errors"]) == 0)
        
        logger.debug(f"Private key validation result: {validation}")
        
    except Exception as val_error:
        logger.error(f"Private key validation error: {val_error}")
        validation["errors"].append(f"Validation error: {val_error}")
    
    return validation