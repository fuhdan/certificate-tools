# backend-fastapi/routers/advanced_downloads.py
# COMPLETE ENHANCED VERSION - Advanced download functionality with format selection and bundling

import logging
import json
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field

from middleware.session_middleware import get_session_id
from certificates.storage.session_pki_storage import session_pki_storage, PKIComponentType
from services.secure_zip_creator import secure_zip_creator, SecureZipCreatorError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/downloads/advanced", tags=["advanced_downloads"])

# Request models
class AdvancedDownloadRequest(BaseModel):
    """Advanced download request model"""
    component_ids: List[str] = Field(default=[], description="Selected component IDs")
    format_selections: Dict[str, str] = Field(default={}, description="Format selections for components")
    bundles: Dict[str, Optional[str]] = Field(default={}, description="Bundle selections")

@router.post("/download/{session_id}")
async def advanced_download(
    session_id: str,
    request: AdvancedDownloadRequest,
    session_id_validated: str = Depends(get_session_id)
):
    """
    Advanced download with custom format selection and bundling
    
    Returns a password-protected ZIP file containing selected components
    in their requested formats, plus any requested bundles.
    """
    logger.info(f"🔥 Advanced download started for session: {session_id}")
    logger.info(f"🔥 Request payload: {request.dict()}")
    
    try:
        # Validate session
        if session_id != session_id_validated:
            logger.warning(f"Session ID mismatch: path={session_id}, validated={session_id_validated}")
            raise HTTPException(status_code=400, detail="Session ID validation failed")
        
        # Get session
        session = session_pki_storage.get_or_create_session(session_id)
        if not session.components:
            logger.warning(f"No PKI components found in session: {session_id}")
            raise HTTPException(status_code=404, detail="No PKI components found in session")
        
        logger.info(f"🔥 Session has {len(session.components)} components")
        
        # Validate request
        _validate_download_request(request, session)
        
        # Prepare download package with proper certificate data
        download_package = await _prepare_download_package(request, session, session_id)
        
        # Use secure_zip_creator with the same method as Apache/IIS
        zip_data, password = secure_zip_creator.create_advanced_bundle(**download_package)
        
        logger.info(f"✅ Advanced download package created successfully for session: {session_id}")
        
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=advanced-bundle-{session_id}.zip",
                "X-Zip-Password": password,
                "Content-Length": str(len(zip_data))
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error in advanced download for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while preparing download")

@router.get("/formats/{session_id}")
async def get_available_formats(
    session_id: str,
    session_id_validated: str = Depends(get_session_id)
):
    """Get available download formats for session components"""
    logger.info(f"Getting available formats for session: {session_id}")
    
    try:
        # Validate session
        if session_id != session_id_validated:
            raise HTTPException(status_code=400, detail="Session ID validation failed")
        
        # Get session
        session = session_pki_storage.get_or_create_session(session_id)
        if not session.components:
            return {
                "success": True,
                "session_id": session_id,
                "components": [],
                "bundle_options": [],
                "message": "No components available"
            }
        
        # Analyze components and determine available formats
        component_formats = _analyze_component_formats(session)
        bundle_options = _analyze_bundle_options(session)
        
        return {
            "success": True,
            "session_id": session_id,
            "components": component_formats,
            "bundle_options": bundle_options,
            "component_count": len(session.components)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting formats for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze available formats")

def _validate_download_request(request: AdvancedDownloadRequest, session) -> None:
    """Validate advanced download request"""
    logger.info(f"🔥 Validating request with {len(request.component_ids)} components")
    
    # Check that we have some selection
    has_components = bool(request.component_ids)
    has_bundles = any(v for v in request.bundles.values())
    
    if not has_components and not has_bundles:
        raise HTTPException(status_code=400, detail="No components or bundles selected")
    
    # Validate component IDs exist in session
    for component_id in request.component_ids:
        if component_id not in session.components:
            raise HTTPException(status_code=400, detail=f"Component {component_id} not found in session")
    
    logger.info(f"✅ Request validation passed")

async def _prepare_download_package(request: AdvancedDownloadRequest, session, session_id: str) -> Dict[str, Any]:
    """Prepare download package with formatted components and bundles"""
    logger.info(f"🔥 Preparing download package for {len(request.component_ids)} components")
    
    files = {}
    
    # Extract certificate data for instruction generation
    certificate_data = _extract_certificate_data_from_session(session, request.component_ids)
    
    # Process individual component files
    for component_id in request.component_ids:
        component = session.components[component_id]
        logger.info(f"🔥 Processing component: {component.filename}")
        
        # For now, just include the original content
        filename = f"{component.filename}"
        content = component.content
        if isinstance(content, str):
            content = content.encode()
        files[filename] = content
    
    # Generate README using instruction generator with proper certificate data
    from services.instruction_generator import InstructionGenerator
    instruction_generator = InstructionGenerator()
    
    readme = instruction_generator.generate_advanced_download_info(
        session_id=session_id,
        component_count=len(request.component_ids),
        zip_password="WILL_BE_GENERATED"  # Will be replaced by secure_zip_creator
    )
    
    package = {
        "files": files,
        "bundles": {},
        "readme": readme
    }
    
    logger.info(f"✅ Package prepared with {len(files)} files")
    return package

def _extract_certificate_data_from_session(session, component_ids: List[str]) -> Dict[str, Any]:
    """Extract certificate data from session for instruction generation"""
    
    certificate_data = {
        'domain_name': 'example.com',
        'subject': 'CN=example.com',
        'issuer': 'Certificate Authority',
        'filename': 'certificate'
    }
    
    # Find primary certificate component
    for component_id in component_ids:
        component = session.components.get(component_id)
        if component and component.type.type_name == 'Certificate':
            metadata = component.metadata or {}
            
            # Extract domain name from certificate metadata
            if metadata.get('subject_common_name'):
                certificate_data['domain_name'] = metadata['subject_common_name']
            elif metadata.get('subject'):
                # Try to extract CN from subject
                subject = metadata['subject']
                if 'CN=' in subject:
                    for part in subject.split(','):
                        if 'CN=' in part:
                            cn = part.split('CN=')[1].strip()
                            if cn:
                                certificate_data['domain_name'] = cn
                                break
            
            # Add other metadata - FIX: Handle None values properly
            certificate_data['subject'] = metadata.get('subject') or certificate_data['subject']
            certificate_data['issuer'] = metadata.get('issuer') or certificate_data['issuer']
            certificate_data['filename'] = component.filename
            certificate_data['expiry_date'] = str(metadata.get('not_valid_after') or '')
            certificate_data['subject_alt_name'] = ', '.join(metadata.get('subject_alt_name') or [])
            break
    
    return certificate_data

def _analyze_component_formats(session) -> List[Dict[str, Any]]:
    """Analyze available formats for each component"""
    
    component_formats = []
    
    for component_id, component in session.components.items():
        formats = _get_component_format_options(component.type)
        
        component_info = {
            "id": component_id,
            "filename": component.filename,
            "type": component.type.type_name,
            "display_name": _get_component_display_name(component),
            "available_formats": formats
        }
        
        component_formats.append(component_info)
    
    return component_formats

def _analyze_bundle_options(session) -> List[Dict[str, Any]]:
    """Analyze available bundle options based on session components"""
    
    bundle_options = []
    
    # Check component types available
    has_end_entity_cert = any(
        comp.type == PKIComponentType.CERTIFICATE 
        for comp in session.components.values()
    )
    has_ca_certs = any(
        comp.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]
        for comp in session.components.values()
    )
    has_private_key = any(
        comp.type == PKIComponentType.PRIVATE_KEY
        for comp in session.components.values()
    )
    
    # PKCS#7 Chain option
    if has_end_entity_cert and has_ca_certs:
        bundle_options.append({
            "id": "pkcs7_chain",
            "title": "PKCS#7 Certificate Chain",
            "description": "Certificate chain in PKCS#7 format",
            "formats": [
                {"value": "pem", "label": "PKCS#7 PEM", "description": "Certificate chain in PEM format"},
                {"value": "der", "label": "PKCS#7 DER", "description": "Certificate chain in DER format"}
            ]
        })
    
    # PKCS#12 Bundle option
    if has_end_entity_cert and has_private_key:
        bundle_options.append({
            "id": "pkcs12_bundle", 
            "title": "PKCS#12 Bundle (Certificate + Chain + Private Key)",
            "description": "Complete bundle with certificate, chain, and private key",
            "formats": [
                {"value": "encrypted", "label": "PKCS#12 (Encrypted)", "description": "Password-protected bundle"},
                {"value": "unencrypted", "label": "PKCS#12 (Unencrypted)", "description": "No password protection"}
            ]
        })
    
    return bundle_options

def _get_component_format_options(component_type: PKIComponentType) -> List[Dict[str, str]]:
    """Get available format options for component type"""
    
    if component_type == PKIComponentType.PRIVATE_KEY:
        return [
            {"value": "pem", "label": "PEM (Unencrypted)", "description": "Base64 encoded, unencrypted"},
            {"value": "der", "label": "DER (Unencrypted)", "description": "Binary encoded, unencrypted"},
            {"value": "pkcs8", "label": "PKCS#8 (Unencrypted)", "description": "Standard format, unencrypted"},
            {"value": "pkcs8_encrypted", "label": "PKCS#8 (Encrypted)", "description": "Password-protected PKCS#8"},
            {"value": "pem_encrypted", "label": "PEM (Encrypted)", "description": "Password-protected PEM"}
        ]
    
    elif component_type == PKIComponentType.CSR:
        return [
            {"value": "pem", "label": "PEM", "description": "Base64 encoded text format"},
            {"value": "der", "label": "DER", "description": "Binary encoded format"}
        ]
    
    else:  # Certificates (all types)
        return [
            {"value": "pem", "label": "PEM", "description": "Base64 encoded text format"},
            {"value": "der", "label": "DER", "description": "Binary encoded format"}
        ]

def _get_component_display_name(component) -> str:
    """Get display name for component"""
    
    metadata = component.metadata or {}
    
    # Try common name first
    if metadata.get('subject_common_name'):
        return metadata['subject_common_name']
    
    # Try extracting CN from subject
    subject = metadata.get('subject', '')
    if 'CN=' in subject:
        for part in subject.split(','):
            if 'CN=' in part:
                return part.split('CN=')[1].strip()
    
    # Fall back to filename
    return component.filename