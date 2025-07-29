#!/usr/bin/env python3
"""
Test the CWT-24 downloads endpoint
Run this while your FastAPI server is running
"""

import requests
import json
import tempfile
import pyzipper  # Changed from zipfile to pyzipper
import uuid
from pathlib import Path

# Configuration
API_BASE_URL = "http://localhost:8000"
TEST_SESSION_ID = "d7221ed6-8251-45bc-a8e2-5df055ab6133"

def get_auth_token():
    """Get JWT token for authenticated requests"""
    try:
        response = requests.post(f"{API_BASE_URL}/token", data={
            "username": "admin",
            "password": "admin123"
        })
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        print(f"❌ Failed to get auth token: {e}")
        return None

def test_downloads_endpoint():
    """Test the new downloads endpoint"""
    print("🌐 Testing CWT-24 Downloads Endpoint")
    print("=" * 50)
    
    # Get authentication token
    token = get_auth_token()
    if not token:
        return
    
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Session-ID": TEST_SESSION_ID
    }
    
    print(f"✅ Got auth token: {token[:20]}...")
    print(f"✅ Using session ID: {TEST_SESSION_ID}")
    
    # Test the downloads endpoint
    try:
        print("\n📦 Testing Apache bundle download...")
        
        response = requests.post(
            f"{API_BASE_URL}/api/downloads/apache/{TEST_SESSION_ID}",
            headers=headers
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type')}")
        print(f"Content-Length: {response.headers.get('Content-Length')}")
        
        if response.status_code == 200:
            # Get the ZIP password from headers
            zip_password = response.headers.get('X-Zip-Password')
            print(f"✅ ZIP Password: {zip_password}")
            
            if not zip_password:
                print("❌ No ZIP password in response headers")
                return
            
            # Save and test the ZIP file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                temp_file.write(response.content)
                temp_zip_path = temp_file.name
            
            print(f"✅ ZIP file saved to: {temp_zip_path}")
            print(f"✅ ZIP file size: {len(response.content):,} bytes")
            
            # Try to open the ZIP file with pyzipper
            try:
                with pyzipper.AESZipFile(temp_zip_path, 'r') as zip_ref:  # Changed to pyzipper.AESZipFile
                    zip_ref.setpassword(zip_password.encode('utf-8'))
                    files = zip_ref.namelist()
                    print(f"✅ ZIP contents: {files}")
                    
                    # Try to read one of the guide files
                    if 'APACHE_INSTALLATION_GUIDE.txt' in files:
                        guide_content = zip_ref.read('APACHE_INSTALLATION_GUIDE.txt').decode('utf-8')
                        print(f"✅ Apache guide preview: {guide_content[:100]}...")
                
            except Exception as e:
                print(f"❌ Failed to open ZIP: {e}")
            
            # Clean up
            Path(temp_zip_path).unlink()
            
        elif response.status_code == 404:
            print("⚠️  No certificates found in session (expected if session is empty)")
            print("💡 Upload some certificates first using the /api/certificates/upload endpoint")
            
        elif response.status_code == 400:
            print("⚠️  Session validation failed")
            print(f"Response: {response.text}")
            
        else:
            print(f"❌ Unexpected response: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"💥 Request failed: {e}")

def test_with_sample_certificate():
    """Test after uploading a sample certificate"""
    print("\n📋 Testing with sample certificate upload...")
    
    token = get_auth_token()
    if not token:
        return
    
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Session-ID": TEST_SESSION_ID
    }
    
    # Create a sample certificate file
    sample_cert = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAMpX8BjqE8qlMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST
UVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV
WXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX
YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
-----END CERTIFICATE-----"""
    
    try:
        # Upload sample certificate
        files = {
            'certificate': ('test_cert.crt', sample_cert, 'application/x-pem-file')
        }
        
        upload_response = requests.post(
            f"{API_BASE_URL}/api/certificates/upload",
            headers=headers,
            files=files
        )
        
        print(f"Upload Status: {upload_response.status_code}")
        
        if upload_response.status_code == 200:
            print("✅ Sample certificate uploaded successfully")
            
            # Now test the downloads endpoint
            test_downloads_endpoint()
        else:
            print(f"❌ Failed to upload certificate: {upload_response.text}")
            
    except Exception as e:
        print(f"💥 Upload test failed: {e}")

if __name__ == "__main__":
    print("Make sure your FastAPI server is running on http://localhost:8000")
    print("Starting endpoint tests...\n")
    
    test_downloads_endpoint()
    # test_with_sample_certificate()  # Uncomment to test with sample cert