from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uvicorn
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import base64

# Create FastAPI app
app = FastAPI(
    title="Certificate Tools API",
    description="A minimal API for certificate management tools",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    Returns the API status and current timestamp
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Certificate Tools API",
        "version": "1.0.0"
    }

@app.get("/")
async def root():
    """
    Root endpoint
    """
    return {
        "message": "Certificate Tools API",
        "docs": "/docs",
        "health": "/health",
        "upload": "/upload"
    }

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload and process certificate files (CSR, CRT, etc.)
    """
    print(f"Received file upload: {file.filename}")
    
    try:
        # Read file content
        content = await file.read()
        print(f"File size: {len(content)} bytes")
        
        # Try to determine file format and type
        file_info = {
            "filename": file.filename,
            "filetype": "Unknown",
            "fileformat": "Unknown",
            "certificate": {}
        }
        
        # Try to parse as PEM first
        try:
            # Check if it's a CSR
            if b'-----BEGIN CERTIFICATE REQUEST-----' in content:
                print("Detected CSR in PEM format")
                csr = x509.load_pem_x509_csr(content)
                file_info["filetype"] = "CSR"
                file_info["fileformat"] = "PEM"
                file_info["certificate"] = parse_csr_properties(csr)
                
            elif b'-----BEGIN CERTIFICATE-----' in content:
                print("Detected Certificate in PEM format")
                cert = x509.load_pem_x509_certificate(content)
                file_info["filetype"] = "Certificate"
                file_info["fileformat"] = "PEM"
                file_info["certificate"] = parse_certificate_properties(cert)
                
            else:
                print("No PEM headers found, trying DER format")
                # Try DER format
                try:
                    csr = x509.load_der_x509_csr(content)
                    file_info["filetype"] = "CSR"
                    file_info["fileformat"] = "DER"
                    file_info["certificate"] = parse_csr_properties(csr)
                    print("Successfully parsed as DER CSR")
                except:
                    try:
                        cert = x509.load_der_x509_certificate(content)
                        file_info["filetype"] = "Certificate" 
                        file_info["fileformat"] = "DER"
                        file_info["certificate"] = parse_certificate_properties(cert)
                        print("Successfully parsed as DER Certificate")
                    except Exception as der_error:
                        print(f"Failed to parse as DER: {der_error}")
                        file_info["fileformat"] = "Binary"
                        file_info["certificate"] = {"error": "Unable to parse certificate data"}
                        
        except Exception as parse_error:
            print(f"Parsing error: {parse_error}")
            file_info["certificate"] = {"parse_error": str(parse_error)}
            
        print(f"Returning file info: {file_info}")
        return file_info
        
    except Exception as e:
        print(f"Error processing file: {e}")
        raise HTTPException(status_code=400, detail=f"Error processing file: {str(e)}")

def parse_csr_properties(csr):
    """Parse CSR and extract all relevant properties"""
    properties = {}
    
    try:
        # Basic CSR information
        properties["Version"] = str(csr.version.value)
        
        # Subject information
        subject = csr.subject
        for attribute in subject:
            oid_name = get_oid_name(attribute.oid)
            properties[f"Subject.{oid_name}"] = attribute.value
            
        # Public key information
        public_key = csr.public_key()
        properties["Public Key Algorithm"] = public_key.__class__.__name__.replace('PublicKey', '')
        
        if hasattr(public_key, 'key_size'):
            properties["Key Size"] = f"{public_key.key_size} bits"
            
        # Signature algorithm
        properties["Signature Algorithm"] = csr.signature_algorithm_oid._name
        
        # Extensions
        try:
            extensions = csr.extensions
            for ext in extensions:
                ext_name = get_extension_name(ext.oid)
                properties[f"Extension.{ext_name}"] = str(ext.value)
                properties[f"Extension.{ext_name}.Critical"] = str(ext.critical)
        except:
            pass
            
        # Subject Alternative Names if present
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = []
            for name in san_ext.value:
                san_names.append(f"{name.__class__.__name__}: {name.value}")
            properties["Subject Alternative Names"] = ", ".join(san_names)
        except:
            pass
            
    except Exception as e:
        properties["parsing_error"] = str(e)
        
    return properties

def parse_certificate_properties(cert):
    """Parse certificate and extract all relevant properties"""
    properties = {}
    
    try:
        # Basic certificate information
        properties["Version"] = str(cert.version.value)
        properties["Serial Number"] = str(cert.serial_number)
        properties["Not Valid Before"] = cert.not_valid_before.isoformat()
        properties["Not Valid After"] = cert.not_valid_after.isoformat()
        
        # Subject information
        subject = cert.subject
        for attribute in subject:
            oid_name = get_oid_name(attribute.oid)
            properties[f"Subject.{oid_name}"] = attribute.value
            
        # Issuer information
        issuer = cert.issuer
        for attribute in issuer:
            oid_name = get_oid_name(attribute.oid)
            properties[f"Issuer.{oid_name}"] = attribute.value
            
        # Public key information
        public_key = cert.public_key()
        properties["Public Key Algorithm"] = public_key.__class__.__name__.replace('PublicKey', '')
        
        if hasattr(public_key, 'key_size'):
            properties["Key Size"] = f"{public_key.key_size} bits"
            
        # Signature algorithm
        properties["Signature Algorithm"] = cert.signature_algorithm_oid._name
        
        # Extensions
        try:
            extensions = cert.extensions
            for ext in extensions:
                ext_name = get_extension_name(ext.oid)
                properties[f"Extension.{ext_name}"] = str(ext.value)
                properties[f"Extension.{ext_name}.Critical"] = str(ext.critical)
        except:
            pass
            
    except Exception as e:
        properties["parsing_error"] = str(e)
        
    return properties

def get_oid_name(oid):
    """Get human-readable name for OID"""
    oid_map = {
        NameOID.COMMON_NAME: "Common Name",
        NameOID.COUNTRY_NAME: "Country",
        NameOID.LOCALITY_NAME: "Locality",
        NameOID.STATE_OR_PROVINCE_NAME: "State/Province",
        NameOID.ORGANIZATION_NAME: "Organization",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "Organizational Unit",
        NameOID.EMAIL_ADDRESS: "Email Address",
    }
    return oid_map.get(oid, str(oid))

def get_extension_name(oid):
    """Get human-readable name for extension OID"""
    ext_map = {
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "Subject Alternative Name",
        ExtensionOID.KEY_USAGE: "Key Usage",
        ExtensionOID.EXTENDED_KEY_USAGE: "Extended Key Usage",
        ExtensionOID.BASIC_CONSTRAINTS: "Basic Constraints",
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "Authority Key Identifier",
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: "Subject Key Identifier",
    }
    return ext_map.get(oid, str(oid))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)