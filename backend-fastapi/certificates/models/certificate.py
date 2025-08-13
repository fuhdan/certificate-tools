# backend-fastapi/certificates/models/certificate.py

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class CertificateInfoModel(BaseModel):
    """Certificate information model"""
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: Optional[int]
    is_ca: bool
    is_self_signed: bool
    fingerprint_sha1: str
    fingerprint_sha256: str
    extensions: Dict[str, Any] = Field(default_factory=dict)

class PrivateKeyInfoModel(BaseModel):
    """Private key information model"""
    algorithm: str
    key_size: Optional[int]
    is_encrypted: bool
    public_key_fingerprint: str

class CSRInfoModel(BaseModel):
    """CSR information model"""
    subject: str
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: Optional[int]
    public_key_fingerprint: str
    extensions: Dict[str, Any] = Field(default_factory=dict)

class UnifiedCertificateModel(BaseModel):
    """Unified certificate model for API responses"""
    
    # Identity
    id: str
    filename: str
    original_format: str
    uploaded_at: str
    
    # File metadata
    file_size: int
    file_hash: str
    content_hash: str
    
    # Content presence flags (don't expose PEM content in API)
    has_certificate: bool = False
    has_private_key: bool = False
    has_csr: bool = False
    additional_certs_count: int = 0
    
    # Pre-computed information
    certificate_info: Optional[CertificateInfoModel] = None
    private_key_info: Optional[PrivateKeyInfoModel] = None
    csr_info: Optional[CSRInfoModel] = None
    additional_certificates_info: List[CertificateInfoModel] = Field(default_factory=list)
    
    # Validation state
    is_valid: bool = False
    validation_errors: List[str] = Field(default_factory=list)
    requires_password: bool = False
    used_password: bool = False

class CertificateUploadRequest(BaseModel):
    """Certificate upload request model"""
    filename: str
    password: Optional[str] = None

class CertificateUploadResponse(BaseModel):
    """Certificate upload response model"""
    success: bool
    certificate: Optional[UnifiedCertificateModel] = None
    message: str
    errors: List[str] = Field(default_factory=list)

class SessionSummaryModel(BaseModel):
    """Session summary model"""
    exists: bool
    certificate_count: int = 0
    created_at: Optional[str] = None
    last_updated: Optional[str] = None
    certificates: List[UnifiedCertificateModel] = Field(default_factory=list)

class PEMExportModel(BaseModel):
    """PEM export model"""
    certificate_pem: Optional[str] = None
    private_key_pem: Optional[str] = None
    csr_pem: Optional[str] = None
    additional_certificates_pem: List[str] = Field(default_factory=list)

class PKIBundleModel(BaseModel):
    """PKI bundle model"""
    bundle_type: str  # "full_chain", "certificate_only", "private_key_only"
    components: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

# Conversion functions between storage and API models

def storage_to_api_model(storage_data) -> UnifiedCertificateModel:
    """Convert storage data to API model"""
    
    return UnifiedCertificateModel(
        id=storage_data.id,
        filename=storage_data.filename,
        original_format=storage_data.original_format,
        uploaded_at=storage_data.uploaded_at,
        file_size=storage_data.file_size,
        file_hash=storage_data.file_hash,
        content_hash=storage_data.content_hash,
        has_certificate=storage_data.certificate_pem is not None,
        has_private_key=storage_data.private_key_pem is not None,
        has_csr=storage_data.csr_pem is not None,
        additional_certs_count=len(storage_data.additional_certificates_pem),
        certificate_info=CertificateInfoModel(**storage_data.certificate_info.__dict__) if storage_data.certificate_info else None,
        private_key_info=PrivateKeyInfoModel(**storage_data.private_key_info.__dict__) if storage_data.private_key_info else None,
        csr_info=CSRInfoModel(**storage_data.csr_info.__dict__) if storage_data.csr_info else None,
        additional_certificates_info=[
            CertificateInfoModel(**info.__dict__) 
            for info in storage_data.additional_certificates_info
        ],
        is_valid=storage_data.is_valid,
        validation_errors=storage_data.validation_errors,
        requires_password=storage_data.requires_password,
        used_password=storage_data.used_password
    )

class ValidationDetailModel(BaseModel):
    """Individual validation details"""
    validation_id: str
    type: str  # cryptographic_match, chain_validation, etc.
    status: str  # valid, warning, invalid
    confidence: str  # high, medium, low
    title: str
    description: str
    components_involved: List[str] = Field(default_factory=list)
    validation_method: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str

class ValidationResultsModel(BaseModel):
    """Complete validation results for a session"""
    computed_at: str
    validation_engine_version: str = "2.0"
    overall_status: str  # valid, warning, invalid
    total_validations: int
    passed_validations: int
    failed_validations: int
    warnings: int
    validations: Dict[str, ValidationDetailModel] = Field(default_factory=dict)
    security_recommendations: List[Dict[str, Any]] = Field(default_factory=list)

def api_to_pem_export(storage_data) -> PEMExportModel:
    """Convert storage data to PEM export model"""
    
    return PEMExportModel(
        certificate_pem=storage_data.certificate_pem,
        private_key_pem=storage_data.private_key_pem,
        csr_pem=storage_data.csr_pem,
        additional_certificates_pem=storage_data.additional_certificates_pem
    )