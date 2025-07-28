# routers/pki.py
# PKI bundle endpoints

import datetime
import logging
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from certificates.storage import CertificateStorage
from certificates.storage.pki_bundle import PKIBundleManager
from middleware.session_middleware import get_session_id
from auth.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/pki-bundle", tags=["pki"])
def get_pki_bundle(
    session_id: str = Depends(get_session_id),
    current_user: str = Depends(get_current_user)  # Add admin authentication
):
    """Get current PKI bundle - regenerates automatically if needed"""

    try:
        # Always get the latest certificates from storage
        all_certificates = CertificateStorage.get_all(session_id)
        
        if not all_certificates:
            return {
                "success": False,
                "message": "No certificates uploaded. Upload certificates to generate a bundle.",
                "bundle": None
            }
        
        # Force regeneration to ensure bundle includes ALL current certificates
        logger.info(f"[{session_id}] Admin {current_user} forcing PKI bundle regeneration for {len(all_certificates)} certificates")
        PKIBundleManager.auto_generate_pki_bundle(session_id, all_certificates)
        
        # Get the freshly generated bundle
        bundle = PKIBundleManager.get_pki_bundle(session_id)
        has_bundle = PKIBundleManager.has_pki_bundle(session_id)
        
        if not has_bundle or not bundle:
            return {
                "success": False,
                "message": "Failed to generate PKI bundle from uploaded certificates.",
                "bundle": None
            }
        
        logger.info(f"[{session_id}] Admin {current_user} retrieved PKI bundle with {len(bundle.get('components', []))} components")
        
        return {
            "success": True,
            "bundle": bundle,
            "timestamp": datetime.datetime.now().isoformat(),
            "session_info": {
                "has_bundle": has_bundle,
                "component_count": len(bundle.get('components', []))
            }
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] PKI bundle fetch error for admin {current_user}: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch PKI bundle: {str(e)}"
        )

@router.get("/pki-bundle/download", tags=["pki"])
def download_pki_bundle(
    session_id: str = Depends(get_session_id),
    current_user: str = Depends(get_current_user)  # Add admin authentication
):
    """Download PKI bundle as JSON file"""
    
    try:
        # Always get the latest certificates from storage
        all_certificates = CertificateStorage.get_all(session_id)
        
        if not all_certificates:
            raise HTTPException(
                status_code=404,
                detail="No certificates uploaded. Upload certificates to generate a bundle."
            )
        
        # Force regeneration to ensure bundle includes ALL current certificates
        PKIBundleManager.auto_generate_pki_bundle(session_id, all_certificates)
        
        # Get the freshly generated bundle
        bundle = PKIBundleManager.get_pki_bundle(session_id)
        
        if not bundle:
            raise HTTPException(
                status_code=500,
                detail="Failed to generate PKI bundle from uploaded certificates."
            )
        
        logger.info(f"[{session_id}] Admin {current_user} downloaded PKI bundle with {len(bundle.get('components', []))} components")
        
        # Return the bundle as a downloadable JSON response
        return JSONResponse(
            content=bundle,
            headers={
                "Content-Disposition": f"attachment; filename=pki-bundle-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] PKI bundle download error for admin {current_user}: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to download PKI bundle: {str(e)}"
        )

@router.get("/pki-bundle/validation", tags=["pki"])
def validate_pki_bundle(session_id: str = Depends(get_session_id)):
    """Validate PKI bundle completeness"""
    
    try:
        validation = PKIBundleManager.validate_pki_bundle(session_id)
        
        return {
            "success": True,
            "validation": validation,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"PKI bundle validation error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to validate PKI bundle: {str(e)}"
        )