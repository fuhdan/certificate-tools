# backend-fastapi/routers/certificates.py
# Enhanced API endpoints with smart chain management and deduplication

import logging
import datetime
from typing import Annotated, List, Dict, Any
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
    """Analyze uploaded certificate with smart chain management and deduplication"""
    
    filename = file.filename or "unknown_file"
    logger.info(f"[{session_id}] Analyzing certificate: {filename}")
    
    try:
        # Read file content
        file_content = await file.read()
        
        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        if len(file_content) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
        
        # Get current state before upload for comparison
        pre_upload_summary = session_pki_storage.get_chain_summary(session_id)
        pre_upload_count = pre_upload_summary.get('total_components', 0)
        
        # Analyze and store components with smart deduplication
        analysis_result = analyze_uploaded_certificate(
            file_content=file_content,
            filename=filename,
            password=password,
            session_id=session_id
        )
        
        # Get post-upload state
        post_upload_summary = session_pki_storage.get_chain_summary(session_id)
        post_upload_count = post_upload_summary.get('total_components', 0)
        
        # Determine what happened during upload
        components_added = len(analysis_result.get('component_ids', []))
        net_change = post_upload_count - pre_upload_count
        
        # Enhanced response with deduplication info
        response_data = {
            "success": True,
            "message": f"Successfully analyzed {filename}",
            "analysis": analysis_result,
            "session_id": session_id,
            "upload_summary": {
                "components_processed": components_added,
                "net_components_added": net_change,
                "total_components_before": pre_upload_count,
                "total_components_after": post_upload_count,
                "deduplication_occurred": components_added > net_change,
                "chains_before": len(pre_upload_summary.get('chains', {})),
                "chains_after": len(post_upload_summary.get('chains', {}))
            }
        }
        
        # Add specific messages based on what happened
        if net_change == 0 and components_added > 0:
            response_data["message"] += f" (replaced {components_added} existing components)"
        elif net_change < components_added:
            replaced_count = components_added - net_change
            response_data["message"] += f" (added {net_change}, replaced {replaced_count})"
        
        logger.info(f"[{session_id}] Successfully analyzed: {filename} - {response_data['message']}")
        
        return JSONResponse(
            status_code=201,
            content=response_data
        )
        
    except ValueError as ve:
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
def get_certificates(
    include_chain_info: bool = False,
    session_id: str = Depends(get_session_id)
):
    """Get all PKI components for session with optional chain information"""
    
    logger.info(f"[{session_id}] Retrieving PKI components")
    
    try:
        # Get components from session storage
        components = session_pki_storage.get_session_components(session_id)
        
        response_data = {
            "success": True,
            "session_id": session_id,
            "components": components,
            "count": len(components),
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        # Add chain information if requested
        if include_chain_info:
            chain_summary = session_pki_storage.get_chain_summary(session_id)
            response_data["chain_info"] = chain_summary
            
            # Add component type breakdown
            component_counts = session_pki_storage.get_component_count(session_id)
            response_data["component_breakdown"] = component_counts
        
        logger.info(f"[{session_id}] Retrieved {len(components)} PKI components")
        
        return response_data
        
    except Exception as e:
        logger.error(f"[{session_id}] Error retrieving components: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve components: {str(e)}")

@router.get("/certificates/chains", tags=["certificates"])
def get_certificate_chains(
    session_id: str = Depends(get_session_id)
):
    """Get detailed certificate chain information"""
    
    logger.info(f"[{session_id}] Requesting chain information")
    
    try:
        chain_summary = session_pki_storage.get_chain_summary(session_id)
        session = session_pki_storage.get_or_create_session(session_id)
        
        # Enhance chain info with component details
        enhanced_chains = {}
        for chain_id, chain_info in chain_summary.get('chains', {}).items():
            enhanced_chain = {
                "chain_id": chain_id,
                "component_count": chain_info['component_count'],
                "components": []
            }
            
            for comp_info in chain_info['components']:
                comp_id = comp_info['id']
                if comp_id in session.components:
                    component = session.components[comp_id]
                    enhanced_comp = {
                        **comp_info,
                        "subject": component.metadata.get('subject', 'N/A'),
                        "issuer": component.metadata.get('issuer', 'N/A'),
                        "valid_from": component.metadata.get('not_valid_before', 'N/A'),
                        "valid_to": component.metadata.get('not_valid_after', 'N/A'),
                        "fingerprint": component.metadata.get('fingerprint_sha256', 'N/A')[:16] + '...'
                    }
                    enhanced_chain['components'].append(enhanced_comp)
            
            enhanced_chains[chain_id] = enhanced_chain
        
        return {
            "success": True,
            "session_id": session_id,
            "total_chains": len(enhanced_chains),
            "chains": enhanced_chains,
            "orphaned_components": chain_summary.get('orphaned_components', []),
            "total_components": chain_summary.get('total_components', 0)
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Chain info error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get chain information: {str(e)}")

@router.get("/certificates/{component_id}", tags=["certificates"])
def get_certificate_component(
    component_id: str,
    include_related: bool = False,
    session_id: str = Depends(get_session_id)
):
    """Get specific PKI component by ID with optional related components"""
    
    logger.info(f"[{session_id}] Retrieving component: {component_id}")
    
    try:
        component = session_pki_storage.get_component_by_id(session_id, component_id)
        
        if not component:
            raise HTTPException(status_code=404, detail=f"Component {component_id} not found")
        
        response_data = {
            "success": True,
            "component": component.to_dict(),
            "session_id": session_id
        }
        
        # Add related components if requested
        if include_related and component.chain_id:
            session = session_pki_storage.get_or_create_session(session_id)
            related_components = []
            
            if component.chain_id in session.chains:
                for related_id in session.chains[component.chain_id]:
                    if related_id != component_id and related_id in session.components:
                        related_comp = session.components[related_id]
                        related_components.append({
                            "id": related_comp.id,
                            "type": related_comp.type.type_name,
                            "filename": related_comp.filename,
                            "subject": related_comp.metadata.get('subject', 'N/A')
                        })
            
            response_data["related_components"] = related_components
            response_data["chain_id"] = component.chain_id
        
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Error retrieving component {component_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve component: {str(e)}")

@router.delete("/certificates/{component_id}", tags=["certificates"])
def delete_certificate_component(
    component_id: str,
    session_id: str = Depends(get_session_id)
):
    """Delete specific PKI component"""
    
    logger.info(f"[{session_id}] Deleting component: {component_id}")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        if component_id not in session.components:
            raise HTTPException(status_code=404, detail=f"Component {component_id} not found")
        
        component = session.components[component_id]
        component_type = component.type.type_name
        chain_id = component.chain_id
        
        success = session.remove_component(component_id)
        
        if success:
            logger.info(f"[{session_id}] Successfully deleted {component_type} component: {component_id}")
            
            response_data = {
                "success": True,
                "message": f"{component_type} component deleted successfully",
                "component_id": component_id,
                "session_id": session_id
            }
            
            # Add chain impact information
            if chain_id:
                remaining_in_chain = len(session.chains.get(chain_id, set()))
                response_data["chain_impact"] = {
                    "chain_id": chain_id,
                    "remaining_components": remaining_in_chain,
                    "chain_empty": remaining_in_chain == 0
                }
            
            return response_data
        else:
            raise HTTPException(status_code=500, detail=f"Failed to delete component {component_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Component deletion error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete component: {str(e)}")

@router.delete("/certificates/chains/{chain_id}", tags=["certificates"])
def delete_certificate_chain(
    chain_id: str,
    session_id: str = Depends(get_session_id)
):
    """Delete an entire certificate chain"""
    
    logger.info(f"[{session_id}] Deleting chain: {chain_id}")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        if chain_id not in session.chains:
            raise HTTPException(status_code=404, detail=f"Chain {chain_id} not found")
        
        component_count = len(session.chains[chain_id])
        removed_count = session.remove_chain(chain_id)
        
        if removed_count > 0:
            logger.info(f"[{session_id}] Successfully deleted chain {chain_id}: {removed_count} components")
            return {
                "success": True,
                "message": f"Chain deleted successfully: {removed_count} components removed",
                "chain_id": chain_id,
                "removed_count": removed_count,
                "session_id": session_id
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to delete chain")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Chain deletion error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete chain: {str(e)}")

@router.post("/certificates/clear", tags=["certificates"])
def clear_all_components(
    session_id: str = Depends(get_session_id)
):
    """Clear all PKI components from session"""
    
    logger.info(f"[{session_id}] Clearing all components")
    
    try:
        # Get counts before clearing
        pre_clear_summary = session_pki_storage.get_chain_summary(session_id)
        component_count = pre_clear_summary.get('total_components', 0)
        chain_count = len(pre_clear_summary.get('chains', {}))
        
        success = session_pki_storage.clear_session(session_id)
        
        if success:
            logger.info(f"[{session_id}] Successfully cleared all components from session")
            return {
                "success": True,
                "message": f"All PKI components cleared successfully ({component_count} components, {chain_count} chains)",
                "cleared_components": component_count,
                "cleared_chains": chain_count,
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
    file: UploadFile = File(...),
    password: str = Form(None),
    session_id: str = Depends(get_session_id)
):
    """Replace an existing PKI component with a new one"""
    
    filename = file.filename or "unknown_file"
    logger.info(f"[{session_id}] Replacing component: {component_id}")
    
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
        
        # For replacement, we temporarily analyze the new file
        temp_session_id = f"temp_{session_id}_{datetime.datetime.now().timestamp()}"
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
                "new_filename": filename,
                "old_filename": old_component.filename,
                "component_type": old_type.type_name
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
    session_id: str = Depends(get_session_id)
):
    """Get comprehensive PKI session summary with enhanced chain information"""
    
    logger.info(f"[{session_id}] Requesting session summary")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        chain_summary = session_pki_storage.get_chain_summary(session_id)
        component_counts = session_pki_storage.get_component_count(session_id)
        
        # Check PKI completeness
        has_private_key = component_counts.get("PrivateKey", 0) > 0
        has_certificate = component_counts.get("Certificate", 0) > 0
        has_issuing_ca = component_counts.get("IssuingCA", 0) > 0
        has_intermediate_ca = component_counts.get("IntermediateCA", 0) > 0
        has_root_ca = component_counts.get("RootCA", 0) > 0
        has_csr = component_counts.get("CSR", 0) > 0
        
        is_complete_pki = has_certificate and (has_issuing_ca or has_root_ca)
        has_full_chain = has_certificate and has_issuing_ca and has_root_ca
        
        summary = {
            "success": True,
            "session_id": session_id,
            "created_at": session.created_at,
            "last_updated": session.last_updated,
            "total_components": len(session.components),
            "component_counts": component_counts,
            "chain_info": {
                "total_chains": len(chain_summary.get('chains', {})),
                "chains": chain_summary.get('chains', {}),
                "orphaned_components": len(chain_summary.get('orphaned_components', []))
            },
            "pki_status": {
                "is_complete": is_complete_pki,
                "has_full_chain": has_full_chain,
                "has_private_key": has_private_key,
                "has_certificate": has_certificate,
                "has_issuing_ca": has_issuing_ca,
                "has_intermediate_ca": has_intermediate_ca,
                "has_root_ca": has_root_ca,
                "has_csr": has_csr,
                "can_create_p12": has_certificate and has_private_key,
                "can_create_chain": has_certificate and (has_issuing_ca or has_root_ca),
                "can_create_full_bundle": has_certificate and has_private_key and has_issuing_ca and has_root_ca
            },
            "capabilities": {
                "pkcs12_export": has_certificate and has_private_key,
                "chain_export": has_certificate and (has_issuing_ca or has_root_ca),
                "full_pki_bundle": has_certificate and has_private_key and has_issuing_ca and has_root_ca,
                "certificate_validation": has_certificate,
                "chain_validation": is_complete_pki
            },
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        logger.debug(f"[{session_id}] Session summary generated successfully")
        return summary
        
    except Exception as e:
        logger.error(f"[{session_id}] Session summary error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get session summary: {str(e)}")

@router.get("/certificates/types", tags=["certificates"])
def get_available_component_types():
    """Get list of available PKI component types with descriptions"""
    
    types = []
    for component_type in PKIComponentType:
        types.append({
            "type": component_type.type_name,
            "order": component_type.order,
            "description": _get_type_description(component_type),
            "typical_extensions": _get_typical_extensions(component_type)
        })
    
    return {
        "success": True,
        "component_types": sorted(types, key=lambda x: x["order"]),
        "total_types": len(types)
    }

@router.get("/certificates/validation-status", tags=["certificates"])
def get_validation_status(
    session_id: str = Depends(get_session_id)
):
    """Get validation status for all components in session"""
    
    logger.info(f"[{session_id}] Requesting validation status")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        validation_results = []
        
        for component in session.components.values():
            # Basic validation based on metadata
            is_expired = component.metadata.get('is_expired', False)
            days_until_expiry = component.metadata.get('days_until_expiry')
            
            validation_status = {
                "component_id": component.id,
                "type": component.type.type_name,
                "filename": component.filename,
                "is_valid": not is_expired,
                "is_expired": is_expired,
                "days_until_expiry": days_until_expiry,
                "warnings": [],
                "errors": []
            }
            
            # Add warnings and errors
            if is_expired:
                validation_status["errors"].append("Certificate has expired")
            elif isinstance(days_until_expiry, (int, float)) and days_until_expiry < 30:
                validation_status["warnings"].append(f"Certificate expires in {days_until_expiry} days")
            
            validation_results.append(validation_status)
        
        overall_valid = all(result["is_valid"] for result in validation_results)
        
        return {
            "success": True,
            "session_id": session_id,
            "overall_status": "valid" if overall_valid else "invalid",
            "total_components": len(validation_results),
            "valid_components": sum(1 for r in validation_results if r["is_valid"]),
            "validation_results": validation_results,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Validation status error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get validation status: {str(e)}")

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

def _get_typical_extensions(component_type: PKIComponentType) -> List[str]:
    """Get typical file extensions for component type"""
    extensions = {
        PKIComponentType.PRIVATE_KEY: [".key", ".pem", ".p8", ".pk8"],
        PKIComponentType.CSR: [".csr", ".pem", ".req"],
        PKIComponentType.CERTIFICATE: [".crt", ".pem", ".cer", ".der"],
        PKIComponentType.ISSUING_CA: [".crt", ".pem", ".cer", ".der"],
        PKIComponentType.INTERMEDIATE_CA: [".crt", ".pem", ".cer", ".der"],
        PKIComponentType.ROOT_CA: [".crt", ".pem", ".cer", ".der"]
    }
    return extensions.get(component_type, [".pem"])