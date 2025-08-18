# backend-fastapi/routers/downloads.py

import logging
import json
from typing import Optional
from fastapi import APIRouter, HTTPException, Response, Request, Query

from middleware.session_decorator import require_session
from services.download_service import download_service, BundleConfig, BundleType

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/downloads", tags=["downloads"])

@router.post("/download/{bundle_type}")
@require_session
async def download_bundle(
    request: Request,
    bundle_type: str,
    include_instructions: bool = Query(default=True, description="Include installation guides"),
    formats: Optional[str] = Query(default=None, description="JSON string of format selections"),
    components: Optional[str] = Query(default=None, description="JSON array of component IDs")
):
    """
    Unified download endpoint for server bundles + custom selections.
    
    Supported bundle types:
    - apache: Apache server bundle (cert + key + chain + guides)
    - iis: IIS server bundle (PKCS#12 + guides)  
    - nginx: Nginx server bundle (cert + key + chain + guides)
    - custom: Custom selection of components with format choices
    
    Examples:
    - POST /download/apache?include_instructions=true
    - POST /download/custom?components=["id1","id2"]&formats={"cert":"pem"}
    
    Args:
        bundle_type: Type of bundle to create
        include_instructions: Whether to include installation guides (server bundles only)
        formats: JSON string of format selections for components
        components: JSON array of specific component IDs to include
    
    Returns:
        Password-protected ZIP file with appropriate contents
    """
    # Get session ID from JWT cookie via decorator
    session_id = request.state.session_id
    
    logger.info(f"Unified download - type: {bundle_type}, session: {session_id}, instructions: {include_instructions}")
    
    try:
        # Validate bundle_type
        valid_types = ["apache", "iis", "nginx", "custom"]
        if bundle_type not in valid_types:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid bundle_type: {bundle_type}. Must be one of: {valid_types}"
            )
        
        # Parse optional JSON parameters
        parsed_formats = {}
        parsed_components = []
        
        if formats:
            try:
                parsed_formats = json.loads(formats)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid formats JSON")
        
        if components:
            try:
                parsed_components = json.loads(components)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid components JSON")
        
        # Map bundle_type to BundleType enum
        bundle_type_mapping = {
            "apache": BundleType.APACHE,
            "iis": BundleType.IIS,
            "nginx": BundleType.NGINX,
            "custom": BundleType.CUSTOM
        }
        
        # Create bundle configuration
        config = BundleConfig(
            bundle_type=bundle_type_mapping[bundle_type],
            format_selections=parsed_formats,
            component_selection=parsed_components
        )
        
        # Use unified download service
        zip_data, zip_password, bundle_password = await download_service.create_bundle(
            session_id=session_id,
            config=config,
            include_instructions=include_instructions
        )
        
        logger.info(f"Bundle created successfully - type: {bundle_type}, session: {session_id}")
        
        # Create appropriate filename based on bundle type
        filename = _get_bundle_filename(bundle_type, session_id)
        
        # Prepare response headers
        headers = {
            "Content-Disposition": f"attachment; filename={filename}",
            "X-Zip-Password": zip_password,
            "Content-Length": str(len(zip_data))
        }
        
        # Add bundle password for encrypted bundles
        if bundle_password:
            headers["X-Encryption-Password"] = bundle_password
        
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers=headers
        )
        
    except HTTPException as http_exc:
        raise http_exc
    
    except ValueError as e:
        logger.error(f"Value error creating {bundle_type} bundle for session {session_id}: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    
    except Exception as e:
        logger.error(f"Unexpected error creating {bundle_type} bundle for session {session_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while creating bundle"
        )


@router.get("/bundle-types")
@require_session
async def get_available_bundle_types(request: Request):
    """
    Get available bundle types for current session based on components present.
    
    This helps the frontend know which bundle types are possible to create.
    """
    # Get session ID from JWT cookie via decorator
    session_id = request.state.session_id
    
    try:
        # Use download service to analyze what's available
        available_info = download_service.get_available_bundle_types(session_id)
        
        # Check if custom bundles are available
        from certificates.storage.session_pki_storage import session_pki_storage
        session = session_pki_storage.get_or_create_session(session_id)
        
        # Custom is always available if we have components
        custom_available = bool(session.components)
        
        return {
            "session_id": session_id,
            "server_bundles": available_info["available_types"],
            "custom_available": custom_available,
            "requirements_met": available_info["requirements_met"],
            "component_summary": available_info["component_summary"]
        }
        
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Error getting bundle types for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze available bundle types")


def _get_bundle_filename(bundle_type: str, session_id: str) -> str:
    """Generate appropriate filename for bundle type"""
    filename_mapping = {
        "apache": f"apache-bundle-{session_id}.zip",
        "iis": f"iis-bundle-{session_id}.zip",
        "nginx": f"nginx-bundle-{session_id}.zip",
        "custom": f"custom-bundle-{session_id}.zip"
    }
    return filename_mapping.get(bundle_type, f"{bundle_type}-bundle-{session_id}.zip")