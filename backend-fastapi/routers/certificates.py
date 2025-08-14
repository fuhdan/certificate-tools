# backend-fastapi/routers/certificates.py
# Enhanced API endpoints with smart chain management and deduplication

import logging
import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse

import uuid
from config import settings
from certificates.analyzer import analyze_uploaded_certificate
from middleware.session_middleware import get_session_id
from certificates.analyzer import analyze_uploaded_certificate
from certificates.storage.session_pki_storage import session_pki_storage, PKIComponentType

logger = logging.getLogger(__name__)
router = APIRouter()

# Use MAX_FILE_SIZE from settings
MAX_FILE_SIZE = settings.MAX_FILE_SIZE

@router.post("/analyze-certificate")
async def analyze_certificate(
    file: UploadFile = File(...),
    password: str = Form(None),
    session_id_validated: str = Depends(get_session_id)
):
    """
    Analyze uploaded certificate file with enhanced password handling
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        # Read file content
        file_content = await file.read()
        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="Empty file")
        
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail=f"File too large (max {MAX_FILE_SIZE//1024//1024}MB)")
        
        logger.info(f"[{session_id_validated}] Analyzing certificate: {file.filename}")
        
        # FIXED: Use the correct function name from analyzer.py
        try:
            analysis_result = analyze_uploaded_certificate(
                file_content=file_content,
                filename=file.filename,
                password=password,
                session_id=session_id_validated
            )
            
            # FIXED: Handle the success/failure based on analyzer response format
            success = analysis_result.get("success", False)
            
            if not success:
                # Analysis failed - check if it's a password issue
                error_msg = analysis_result.get("message", "Unknown analysis error")
                if "password required" in error_msg.lower():
                    logger.info(f"[{session_id_validated}] Password required for {file.filename}")
                    return JSONResponse(
                        status_code=400,
                        content={
                            "success": False,
                            "requiresPassword": True,
                            "message": error_msg,
                            "filename": file.filename,
                            "analysis": analysis_result
                        }
                    )
                elif "invalid password" in error_msg.lower():
                    logger.info(f"[{session_id_validated}] Wrong password for {file.filename}")
                    return JSONResponse(
                        status_code=400,
                        content={
                            "success": False,
                            "requiresPassword": True,
                            "message": error_msg,
                            "filename": file.filename,
                            "analysis": analysis_result
                        }
                    )
                else:
                    # Other analysis error
                    logger.error(f"[{session_id_validated}] Analysis failed for {file.filename}: {error_msg}")
                    raise HTTPException(status_code=400, detail=error_msg)
                    
            else:
                # Success - file was processed successfully
                components_created = analysis_result.get("components_created", 0)
                logger.info(f"[{session_id_validated}] Successfully analyzed: {file.filename} ({components_created} components)")
                return {
                    "success": True,
                    "message": analysis_result.get("message", f"Certificate analyzed successfully: {file.filename}"),
                    "filename": file.filename,
                    "requiresPassword": False,
                    "analysis": analysis_result,
                    "id": analysis_result.get("session_id") or str(uuid.uuid4()),
                    "components_created": components_created
                }
                
        except ValueError as ve:
            # Handle password-related ValueErrors from analyzer
            error_msg = str(ve)
            if any(keyword in error_msg.lower() for keyword in ["password required", "password was not given"]):
                logger.info(f"[{session_id_validated}] Password required for {file.filename}")
                return JSONResponse(
                    status_code=400,
                    content={
                        "success": False,
                        "requiresPassword": True,
                        "message": error_msg,
                        "filename": file.filename
                    }
                )
            elif any(keyword in error_msg.lower() for keyword in ["invalid password", "wrong password", "decrypt"]):
                logger.info(f"[{session_id_validated}] Wrong password for {file.filename}")
                return JSONResponse(
                    status_code=400,
                    content={
                        "success": False,
                        "requiresPassword": True,
                        "message": error_msg,
                        "filename": file.filename
                    }
                )
            else:
                # Other ValueError
                logger.error(f"[{session_id_validated}] Analysis failed for {file.filename}: {error_msg}")
                raise HTTPException(status_code=400, detail=error_msg)
        except Exception as analysis_error:
            logger.error(f"[{session_id_validated}] Certificate analysis exception: {analysis_error}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=500, 
                detail=f"Analysis failed: {str(analysis_error)}"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id_validated}] Validation error for {file.filename if file else 'unknown'}: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/certificates", tags=["certificates"])
def get_certificates(
    include_chain_info: bool = False,
    session_id: str = Depends(get_session_id)
):
    """
    Get all PKI components for session with validation results always included
    
    MIGRATION COMPLETE: Validation results are now always included in this response.
    The separate /certificates/validation and /certificates/validation-status endpoints 
    have been removed as they were broken and redundant.
    """
    
    logger.info(f"[{session_id}] Retrieving PKI components with validation results")
    
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
        
        # ALWAYS include validation results (migration complete)
        validation_results = session_pki_storage.get_validation_results(session_id)
        if validation_results:
            response_data["validation_results"] = validation_results
            logger.info(f"[{session_id}] Included validation results: {validation_results.get('total_validations', 0)} checks")
        else:
            # Even if no validation results, include empty structure for consistency
            response_data["validation_results"] = {
                "computed_at": datetime.datetime.now().isoformat(),
                "validation_engine_version": "2.0",
                "overall_status": "valid",
                "total_validations": 0,
                "passed_validations": 0,
                "failed_validations": 0,
                "warnings": 0,
                "validations": {},
                "message": "No validation results available. Upload components to generate validations."
            }
            logger.info(f"[{session_id}] No validation results available")
        
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
        
        # FIXED: Use session_pki_storage.remove_component() instead of session_pki_storage.remove_component()
        # This ensures validation recomputation is triggered after deletion
        success = session_pki_storage.remove_component(session_id, component_id)
        
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
                # Get updated session after deletion for accurate chain count
                updated_session = session_pki_storage.get_or_create_session(session_id)
                remaining_in_chain = len(updated_session.chains.get(chain_id, set()))
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