# backend-fastapi/routers/certificates.py
# Updated API endpoints for session-based PKI storage

import logging
import datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse

from auth.models import User
from auth.dependencies import get_current_active_user
from middleware.session_middleware import get_session_id
from certificates.analyzer import analyze_uploaded_certificate
from certificates.storage.session_pki_storage import session_pki_storage, PKIComponentType

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/analyze-certificate", tags=["certificates"])
async def analyze_certificate(
    file: UploadFile = File(...),
    password: str = Form(None),
    session_id: str = Depends(get_session_id)
):
    """Analyze uploaded certificate and store components in session"""
    
    filename = file.filename or "unknown_file"
    logger.info(f"[{session_id}] Analyzing certificate: {filename}")
    
    try:
        # Read file content
        file_content = await file.read()
        
        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        if len(file_content) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
        
        # Analyze and store components
        analysis_result = analyze_uploaded_certificate(
            file_content=file_content,
            filename=filename,
            password=password,
            session_id=session_id
        )
        
        logger.info(f"[{session_id}] Successfully analyzed: {filename}")
        
        return JSONResponse(
            status_code=201,
            content={
                "success": True,
                "message": f"Successfully analyzed {filename}",
                "analysis": analysis_result,
                "session_id": session_id
            }
        )
        
    except ValueError as ve:
        # Check if it's a password-related error
        error_message = str(ve)
        if "password required" in error_message.lower() or "password" in error_message.lower():
            logger.info(f"[{session_id}] Password required for {filename}")
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "requiresPassword": True,
                    "message": error_message,
                    "filename": filename,
                    "session_id": session_id
                }
            )
        else:
            logger.error(f"[{session_id}] Validation error for {filename}: {ve}")
            raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"[{session_id}] Analysis error for {filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.get("/certificates", tags=["certificates"])
def get_certificates(session_id: str = Depends(get_session_id)):
    """Get all PKI components for session in proper order"""
    
    logger.info(f"[{session_id}] Retrieving PKI components")
    
    try:
        # Get components from session storage - return as-is
        components = session_pki_storage.get_session_components(session_id)
        
        logger.info(f"[{session_id}] Retrieved {len(components)} PKI components")
        
        return {
            "success": True,
            "session_id": session_id,
            "components": components,  # Return PKI components directly
            "count": len(components),
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Error retrieving components: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve components: {str(e)}")

@router.get("/certificates/{component_id}", tags=["certificates"])
def get_certificate_component(
    component_id: str,
    session_id: str = Depends(get_session_id)
):
    """Get specific PKI component by ID"""
    
    logger.info(f"[{session_id}] Retrieving component: {component_id}")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        component = session.components.get(component_id)
        
        if not component:
            raise HTTPException(status_code=404, detail=f"Component {component_id} not found")
        
        return {
            "success": True,
            "component": component.to_dict(),
            "session_id": session_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Error retrieving component {component_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve component: {str(e)}")

@router.delete("/certificates/{component_id}", tags=["certificates"])
def delete_certificate_component(
    component_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Delete specific PKI component"""
    
    logger.info(f"[{session_id}] User '{current_user.username}' deleting component: {component_id}")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        if component_id not in session.components:
            raise HTTPException(status_code=404, detail=f"Component {component_id} not found")
        
        component = session.components[component_id]
        component_type = component.type.type_name
        
        success = session.remove_component(component_id)
        
        if success:
            logger.info(f"[{session_id}] Successfully deleted {component_type} component for user {current_user.username}")
            return {
                "success": True,
                "message": f"{component_type} component deleted successfully",
                "component_id": component_id
            }
        else:
            raise HTTPException(status_code=500, detail=f"Failed to delete component {component_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Component deletion error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete component: {str(e)}")

@router.post("/certificates/clear", tags=["certificates"])
def clear_all_components(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Clear all PKI components from session"""
    
    logger.info(f"[{session_id}] User '{current_user.username}' clearing all components")
    
    try:
        success = session_pki_storage.clear_session(session_id)
        
        if success:
            logger.info(f"[{session_id}] Successfully cleared all components for user {current_user.username}")
            return {
                "success": True,
                "message": "All PKI components cleared successfully",
                "session_id": session_id
            }
        else:
            logger.warning(f"[{session_id}] No components found to clear")
            return {
                "success": True,
                "message": "No components found to clear",
                "session_id": session_id
            }
        
    except Exception as e:
        logger.error(f"[{session_id}] Component clearing error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear components: {str(e)}")

@router.post("/certificates/replace/{component_id}", tags=["certificates"])
async def replace_component(
    component_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    file: UploadFile = File(...),
    password: str = Form(None),
    session_id: str = Depends(get_session_id)
):
    """Replace an existing PKI component with a new one"""
    
    filename = file.filename or "unknown_file"
    logger.info(f"[{session_id}] User '{current_user.username}' replacing component: {component_id}")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        if component_id not in session.components:
            raise HTTPException(status_code=404, detail=f"Component {component_id} not found")
        
        old_component = session.components[component_id]
        old_type = old_component.type
        
        # Read new file content
        file_content = await file.read()
        
        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        # For replacement, we temporarily analyze the new file to get its components
        temp_session_id = f"temp_{session_id}"
        analysis_result = analyze_uploaded_certificate(
            file_content=file_content,
            filename=filename,
            password=password,
            session_id=temp_session_id
        )
        
        # Get the temporary components
        temp_session = session_pki_storage.get_or_create_session(temp_session_id)
        temp_components = list(temp_session.components.values())
        
        # Find a component of the same type to replace with
        replacement_component = None
        for comp in temp_components:
            if comp.type == old_type:
                replacement_component = comp
                break
        
        if not replacement_component:
            # Clean up temp session
            session_pki_storage.clear_session(temp_session_id)
            raise HTTPException(
                status_code=400, 
                detail=f"No {old_type.type_name} found in uploaded file"
            )
        
        # Update the component with new content
        replacement_component.filename = filename
        replacement_component.uploaded_at = datetime.datetime.now().isoformat()
        
        # Replace in main session
        success = session.replace_component(component_id, replacement_component)
        
        # Clean up temp session
        session_pki_storage.clear_session(temp_session_id)
        
        if success:
            logger.info(f"[{session_id}] Successfully replaced {old_type.type_name} component")
            return {
                "success": True,
                "message": f"{old_type.type_name} component replaced successfully",
                "component_id": component_id,
                "new_filename": filename
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to replace component")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Component replacement error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to replace component: {str(e)}")

@router.get("/certificates/session-summary", tags=["certificates"])
def get_session_summary(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Get PKI session summary"""
    
    logger.info(f"[{session_id}] User '{current_user.username}' requesting session summary")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        # Count components by type
        component_counts = {}
        for component in session.components.values():
            type_name = component.type.type_name
            component_counts[type_name] = component_counts.get(type_name, 0) + 1
        
        # Check PKI completeness
        has_private_key = PKIComponentType.PRIVATE_KEY.type_name in component_counts
        has_certificate = PKIComponentType.CERTIFICATE.type_name in component_counts
        has_issuing_ca = PKIComponentType.ISSUING_CA.type_name in component_counts
        has_root_ca = PKIComponentType.ROOT_CA.type_name in component_counts
        
        is_complete_pki = has_certificate and (has_issuing_ca or has_root_ca)
        
        summary = {
            "success": True,
            "session_id": session_id,
            "created_at": session.created_at,
            "last_updated": session.last_updated,
            "total_components": len(session.components),
            "component_counts": component_counts,
            "pki_status": {
                "is_complete": is_complete_pki,
                "has_private_key": has_private_key,
                "has_certificate": has_certificate,
                "has_issuing_ca": has_issuing_ca,
                "has_root_ca": has_root_ca,
                "can_create_p12": has_certificate and has_private_key,
                "can_create_chain": has_certificate and (has_issuing_ca or has_root_ca)
            },
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        logger.debug(f"[{session_id}] Session summary generated for user {current_user.username}")
        return summary
        
    except Exception as e:
        logger.error(f"[{session_id}] Session summary error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get session summary: {str(e)}")

@router.get("/certificates/types", tags=["certificates"])
def get_available_component_types():
    """Get list of available PKI component types"""
    
    types = []
    for component_type in PKIComponentType:
        types.append({
            "type": component_type.type_name,
            "order": component_type.order,
            "description": _get_type_description(component_type)
        })
    
    return {
        "success": True,
        "component_types": sorted(types, key=lambda x: x["order"])
    }

def _get_type_description(component_type: PKIComponentType) -> str:
    """Get human-readable description for component type"""
    descriptions = {
        PKIComponentType.PRIVATE_KEY: "Private key for certificate encryption and signing",
        PKIComponentType.CSR: "Certificate Signing Request - request for certificate issuance",
        PKIComponentType.CERTIFICATE: "End-entity certificate for servers/clients",
        PKIComponentType.ISSUING_CA: "Certificate Authority that issued the end-entity certificate",
        PKIComponentType.INTERMEDIATE_CA: "Intermediate Certificate Authority in the chain",
        PKIComponentType.ROOT_CA: "Root Certificate Authority - top of the trust chain"
    }
    return descriptions.get(component_type, "PKI component")