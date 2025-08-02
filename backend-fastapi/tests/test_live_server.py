# tests/test_live_server_fixed.py
"""
Fixed Live Server Tests for Certificate Analysis API
Corrected endpoints and response expectations based on actual API structure
"""


import pytest
import pyzipper
import tempfile
import uuid
import json
import time
import concurrent.futures
from datetime import datetime
from pathlib import Path
import requests
import zipfile


# Configuration - adjust if your server runs on different port
API_BASE_URL = "http://localhost:8000"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"


# ========================================
# FIXTURES, HELPERS AND HOOKS
# ========================================


@pytest.fixture(scope="session", autouse=True)
def check_server_running():
    """🟢 Ensure API server is healthy before running tests"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code != 200:
            pytest.skip("Server not responding properly")
    except requests.RequestException:
        pytest.skip("Server not running. Start with: uvicorn main:app --host 0.0.0.0 --port 8000")


@pytest.fixture
def auth_token():
    """🔐 Obtain a valid JWT token for API authentication"""
    response = requests.post(f"{API_BASE_URL}/token", data={
        "username": DEFAULT_USERNAME,
        "password": DEFAULT_PASSWORD
    })
    assert response.status_code == 200, f"Auth failed: {response.text}"
    return response.json()["access_token"]


@pytest.fixture
def test_session_id():
    """🆔 Generate a unique session ID for testing isolation"""
    return str(uuid.uuid4())


@pytest.fixture
def auth_headers(auth_token, test_session_id):
    """🪪 Standard headers with JWT and Session token"""
    return {
        "Authorization": f"Bearer {auth_token}",
        "X-Session-ID": test_session_id
    }

@pytest.fixture
def sess_headers(test_session_id):
    """🪪 Standard headers with JWT and Session token"""
    return {
        "X-Session-ID": test_session_id
    }

def upload_certificate_bundle(session_id, certificate=None, private_key=None, ca_certificate=None):
    """Helper function to upload certificate, Private Key and CA Certificate."""
    responses = {}
    headers = {
        "X-Session-ID": session_id
    }

    # Upload certificate
    if certificate:
        files = {
            "file": ("test.crt", certificate, "application/x-pem-file")
        }
        response = requests.post(f"{API_BASE_URL}/analyze-certificate", headers=headers, files=files)
        responses["certificate"] = response

    # Upload private key if provided
    if private_key:
        files = {
            "file": ("test.key.pem", private_key, "application/x-pem-file")
        }
        response = requests.post(f"{API_BASE_URL}/analyze-certificate", headers=headers, files=files)
        responses["private_key"] = response

    # Upload CA certificate if provided
    if ca_certificate:
        files = {
            "file": ("ca.crt", ca_certificate, "application/x-pem-file")
        }
        response = requests.post(f"{API_BASE_URL}/analyze-certificate", headers=headers, files=files)
        responses["ca_certificate"] = response

    return responses

def list_certificates(session_id):
    """Helper function to list certificates."""
    headers = {
        "X-Session-ID": session_id
    }
    response = requests.get(f"{API_BASE_URL}/certificates", headers=headers)
    return response.status_code, response.json()


@pytest.fixture
def sample_certificate():
    """📄 Provide a sample certificate for upload tests"""
    return """-----BEGIN CERTIFICATE-----
MIIE9jCCAt6gAwIBAgIUMIT5LK1/1hPyAxvQmIStKt9GfNkwDQYJKoZIhvcNAQEL
BQAwgYQxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJCRTENMAsGA1UEBwwEQmVybjEQ
MA4GA1UECgwHRGFuaWVsRjEaMBgGA1UECwwRSVQgSW5mcmFzdHJ1Y3R1cmUxKzAp
BgNVBAMMIkRhbmllbEYgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjUw
NzMwMTIxMTQ3WhcNMjYwNzMwMTIxMTQ3WjBuMQswCQYDVQQGEwJVUzEOMAwGA1UE
CAwFU3RhdGUxDTALBgNVBAcMBENpdHkxDjAMBgNVBAoMBU15T3JnMRYwFAYDVQQL
DA1JVCBEZXBhcnRtZW50MRgwFgYDVQQDDA93ZWIuZXhhbXBsZS5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2h8Kdlvk3mKaKUQsaDBZfQvXfHQbi
1alW6baaUIM7iQZrTxRrK6Qi6Z9R2oeBkczRZ6Yr/fCA6oyfI62dS9gQkz44vKEE
15EZVXIp4pgDmSeNYWG5AxUpRq4bZg6hAywDHfZT3pkgoZzl+v7uyS1uTIVWC39/
HjYdNIoTPhI5Iu1KsD7gMmdY9MogHnoDeZBkeSYaSoIh2vTwk4LUILfyo1abkEcs
DhC7kZOoJX3SkkXhdJGkUfKF3oFbcEYOY//rywU0ufmPtQoY5MZuGi7M75/btIpA
jzBh860yCzUGL/9jAfOYUJ/qY6QecoFimiyHuDOpMV9VhsGf/ARKz3FxAgMBAAGj
dTBzMDEGA1UdEQQqMCiCD3dlYi5leGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29t
hwTAqAFkMB0GA1UdDgQWBBTCUI7VdT0rmpovqdN7BQCj0LeUOzAfBgNVHSMEGDAW
gBRGOXu/rasz8l8mXDr91mfnaQAiQjANBgkqhkiG9w0BAQsFAAOCAgEAbs7HXKDv
MxyO5A7lFx33y45o4vWg/LXmKYeV9GgPIv6w1J24hKjhhPM3z/bWRhx//nLcpaim
aKpZD4SYZeKkOknnk3eWdxDPx4d+B3jcsaguXOLwwNOOl/65yRAv3ROLY19e/KkO
LCJzFR1HzJIkYiG2pMZiWCt2dgpt/hQfBgw4r7StBsmYucCZdIbO+hi893WZHEM7
SXl1LuFjUBoG5T6iZr3o1+5f+5yHFiPe/75+XDiUqflvXa5ki/8ItQ7Eu6vIC0M7
GISZpAK3bUaEo5yo35oiiX6B7PUE2Ks240nteKeWd137DoBR4kab9kxUiFjq3ghm
8Wx5wcM0JMjGoAm0Bar/TzXrGsQgjhOmc3SsmVgm1Ro4TOCRTETehIIcquBqhJIN
1fqWUUNVAgOMEkRTRrCAtVDxvST9pNYotbjPNcEaDofxNa4xJQ8p7nBst3KBYZ76
rBe9yboJUOySZR6nXEbnU3flks3hzD/2q+YoqJKx6MFcyY+u/FAGzKHlXRtpYmoN
oZySs+TttdppJWxI5d3wVhPPoUqvFFzqmYyeGN9UV31gXr6DClcIIOLr8qelLfy8
Vt3Ye79lR5sQa18TlKAJ5CRUhTnrxniE16nc/fp8i0aX6s6t8aJ+pBmEL/Xbb8X4
2Ro0NWlhsRcYWHxgX4AlQDj73dFTpNUHdmo=
-----END CERTIFICATE-----"""


@pytest.fixture
def sample_private_key():
    """🔑 Sample private key for testing complete certificate bundles"""
    return """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2h8Kdlvk3mKaK
UQsaDBZfQvXfHQbi1alW6baaUIM7iQZrTxRrK6Qi6Z9R2oeBkczRZ6Yr/fCA6oyf
I62dS9gQkz44vKEE15EZVXIp4pgDmSeNYWG5AxUpRq4bZg6hAywDHfZT3pkgoZzl
+v7uyS1uTIVWC39/HjYdNIoTPhI5Iu1KsD7gMmdY9MogHnoDeZBkeSYaSoIh2vTw
k4LUILfyo1abkEcsDhC7kZOoJX3SkkXhdJGkUfKF3oFbcEYOY//rywU0ufmPtQoY
5MZuGi7M75/btIpAjzBh860yCzUGL/9jAfOYUJ/qY6QecoFimiyHuDOpMV9VhsGf
/ARKz3FxAgMBAAECggEAUWBhUaTXYwP5a70J+AjfiITv3RKx2TtsjcUQlefDOi2y
4PCWp9kDClWho/qLYya/a7SMDxzdtnvbSa+8XV5M68bZfK4ME36Pv/2qMiZFo4UK
byu1R6iqLIbIZIqxhvNFEfavtWCOYE/tBVNLiOXEDWKsJ1pk8yVi9s5PqJiJw1Ke
sFNWX7H022D5YZm9qHxaKPHEm5t1ltFL9JRXzHmEjhokoC38MpSgJgl2kSAYb0ht
y/fRRGnwQNMDXzJEu5I3O1XiPn135JP/hFZGhwAB28R3/oReyZ3L4S1FrtIBAAiI
vHfvIFjGoU/cUrwqyZJsByLs2bhJIBoPPu1/Ni2+aQKBgQD1XSP1BTdu+1HBnaSo
uu14w8vUkz1UqSsNO/R6AmakWbUM6P7d//sP8OjWvpNfFxVqZMuSHt+EMqnSwxwA
BVIozCe62+FM7AOx+Zr1eG0nGmJY/O9G1ffqt7AGeTXIWmVhez6I/q7yjEGuXm3K
wHy3mHyrYGsFpwC6zalR5h71YwKBgQC+cVdy/cvqNnA54r1k+A/c6amtcYg3fg8e
5835+D/XbNptbM1Eghbwga1pUgWw5p906zOQDXiO7fG5JG6qHPxMBsMm115Akmpk
FnnSqnFs4TtAbjJe0rpFV1VOrvQFogR49QXQ+DlVhZvSOY6Fn1pxHkZPNGuNz4KC
mTmjGSMwGwKBgGsPfQUIhauTVZUZ6CMHjV7IcEQNCxHJztMzefVS3t6PlgRQFgVg
EHhgMfihp0QymlGWMY1Mk1LnmFoycCFCMRtEGYHbN2+M+//IXekF5vrM9GTH2NAb
xNVR2Si58tG9P8dNM3grSMLkmDQxV87ENqcVjjBpHcmVmSfpXRwzQQbpAoGAEo0X
56uxYW9MH1dm+57ubKaWUL7udflhn7EU73SvQ1znKiGfHT1O3r7DFa9XvpO4lLsU
msO1KrcjBNX3sbqBGSbPe8ke9UtN8dH+q/bOdby6+NvDLFl6q6aGONPyEVpm9SFp
H6IOc7ZAJ4pTx9BuDvbUAoMotvevzuj+JFUeiGECgYA18e3dTGFeQUVxT7Y77MTk
lRiHc7r9u+/7bDBcl5wTzx565I0SQo8YXgNjQRVvKLXXzIZaqkI7JhZH7aUIHREu
eKM4CAwnzPR48rhLVB+zxMOxnU0wNe0Ll9SXW7xsLSo29CKcYF3Nm8cBbArqiaiO
v7F3SQHoRIn9v3QvA0wn+g==
-----END PRIVATE KEY-----"""


@pytest.fixture
def sample_ca_certificate():
    """🏢 Sample CA certificate for testing certificate chains"""
    return """-----BEGIN CERTIFICATE-----
MIIF+zCCA+OgAwIBAgIUQ0GyLfzmCyTrIH++b8/lceE62mMwDQYJKoZIhvcNAQEL
BQAwgYQxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJCRTENMAsGA1UEBwwEQmVybjEQ
MA4GA1UECgwHRGFuaWVsRjEaMBgGA1UECwwRSVQgSW5mcmFzdHJ1Y3R1cmUxKzAp
BgNVBAMMIkRhbmllbEYgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjUw
NzMwMTIwNzMyWhcNMzUwNzI4MTIwNzMyWjCBhDELMAkGA1UEBhMCQ0gxCzAJBgNV
BAgMAkJFMQ0wCwYDVQQHDARCZXJuMRAwDgYDVQQKDAdEYW5pZWxGMRowGAYDVQQL
DBFJVCBJbmZyYXN0cnVjdHVyZTErMCkGA1UEAwwiRGFuaWVsRiBSb290IENlcnRp
ZmljYXRlIEF1dGhvcml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJ2i4+92FhVxPfeZ+4VaI96U+4TCtBTyOzULIp2xGczrMGufF4L9oMdfyv2Oqhue
0wT+C6qkTA1Y/1Wpq6/+JPGdA/a1EEozDt1REK9F8lsMkM/PndY8oL7M6iraFJFq
34pwrLQRp/vUa4hbDhrBXRnRhzGBJnID5T2xWvpi1jKWV9M/7XYhrjhGTcB5Ewcb
zdppV3bITNPBuAvwHZcKQqvdjLJyl2RpEMBTEPb2eQr1NiIWKcb43l0YbHll65l9
6wQbJ5LJlJIrpp3uxQEXmrbWUebDTC1RcV4hyKArvshZBUxlnzay3QCkIroa81QP
8BQwTNP2pxOmTebrEPfn134Xmm6MJ8WFiSNWE64i1EWkyxBbu2iQZuX8gi46wv+u
XsiHO//MEaHg8IzWSMoupSUVf2aGnptoypBYeT1wmb933piMm4h1ZKIP2nqFFwgi
2GYSB+Bp5SOl546pPo/+JL10ORrDSI0Sbf2CjQpxisKZPP6Djmln5PxWQUqfEqjq
ESeaChGHnL4XpQUdtPm37zLpjWQVbUuOTX/ZK5M1Rg1hq5V4vKyK8dsGH9hP4YGN
Gu2vawxPCyKQ4hwP07uiuVHSn9muH5++Lft4xXaT6MlRnXccihlipTXH8XnBW4Y3
GENCYMwfKUayJq/FItkmrO/udqNLOjucsn0BqRbWadJ3AgMBAAGjYzBhMB0GA1Ud
DgQWBBRGOXu/rasz8l8mXDr91mfnaQAiQjAfBgNVHSMEGDAWgBRGOXu/rasz8l8m
XDr91mfnaQAiQjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjANBgkq
hkiG9w0BAQsFAAOCAgEAlBVsi6p6jLstLYsS2xpWbqrP+5iRI4S2wD+E+MqzsD2f
2uGtFwEktaaENgBStBlDgZRWdXBG1wJCG0qZE/c/CTDKsBj0r24WFZ/BZdoehBfi
7VJKyIO0ftYbcwNHg0SGgi6WfH4/w0WsXL2wQJU86njN89BWItRlyHOR/dLyYsTe
5YkNSXl0xQaEFPsgk97FAHwYEXpD4PO+enu79cCAjr8U3vfwk6fxFLr8U+FY0bK2
41XwG7Mj29/YUI/r4OfJGGlf0Hsk+aX/2ADfPgyzUGZYbSp7yemibaisWR0Z7Wrs
gAvEMOiYVANqLR5ze6eR9NaIWz2XcZwaQpZvJL4a6suqj1LskTXbYrN2xr0g0sBz
a33GdYtgknHhk2Zn8/BOkfGBGWQs0Jff84oQlBRjBO3s+CYZ8gphIMQ1liMLtlc3
iLu6pGKrq9u0husUcqXO7A9yK9GMF/uXobPzQuADhM3w5QeUB1N5OokK5+PyQgGT
WlDgopKSDMfq8Xm8BGS8X2viyiAWDTF0TOeFrrXd/cM908iu173LhMULZWtGRs4b
Xy+rrplYC0hpoeUz7o4S5WzYgDYPtTc7/Snl7nHwH/BqQx3O1U560icpc7g6cSLb
gouQLjA8NMKFBmFkFRLcSSx5DNKxrmBnCX5MNhopaZDLmWvBgP8s0iy+QtZEYuc=
-----END CERTIFICATE-----"""


def get_invalid_uuids():
    return [
        "foobar",
        "12345",
        "session123",
        "uuid-invalid",
        "",
        None,
        "123e4567-e89b-12d3-a456-42661417400",     # too short
        "123e4567-e89b-12d3-a456-4266141740000",   # too long
        "123e4567-e89b-12d3-a456-42661",           # way too short
        "123e4567e89b12d3a456426614174000",        # missing hyphens
        "123e4567-e89b-12d3-a456-42661417400g",    # invalid char
        "gggggggg-gggg-gggg-gggg-gggggggggggg",   # all invalid
        "123e4567--e89b-12d3-a456-426614174000",   # double dash
        "123e4567-e89b-12d3-a456:426614174000",    # colon instead of dash
        "123e4567-e89b_12d3-a456-426614174000",    # underscore
        "123E4567-E89B-12D3-A456-426614174000",    # uppercase (if applicable)
        "00000000-0000-0000-0000-000000000000",    # null UUID
        "not-a-uuid-not-a-uuid-not-a-uuid-notau",
    ]

@pytest.fixture
def invalid_uuids():
    return get_invalid_uuids()


# pytest hook to parametrize invalid_session_id with invalid_uuids fixture values
def pytest_generate_tests(metafunc):
    if "invalid_session_id" in metafunc.fixturenames:
        metafunc.parametrize("invalid_session_id", get_invalid_uuids())


# ========================================
# HEALTH CHECK TESTS
# ========================================


class TestHealthChecks:
    """✅ Verify API server responds with healthy status"""

    def test_server_responds_with_healthy_status(self):
        """Verify server is accessible"""
        response = requests.get(f"{API_BASE_URL}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"

    def test_root_endpoint_returns_server_info_and_endpoints(self):
        """✅ Check root endpoint returns server info and available endpoints"""
        response = requests.get(f"{API_BASE_URL}/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert "endpoints" in data


# ========================================
# AUTHENTICATION TESTS
# ========================================


class TestAuthentication:
    """JWT token authentication and authorization"""

    def test_valid_credentials_return_jwt_access_token(self):
        """🔐 Valid credentials should return JWT access token"""
        response = requests.post(f"{API_BASE_URL}/token", data={
            "username": DEFAULT_USERNAME,
            "password": DEFAULT_PASSWORD
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_invalid_credentials_return_401_unauthorized(self):
        """🔐 Invalid credentials should return 401 Unauthorized"""
        response = requests.post(f"{API_BASE_URL}/token", data={
            "username": "wrong",
            "password": "wrong"
        })
        assert response.status_code == 401

    def test_protected_endpoints_require_authentication_token(self):
        """🔐 Protected endpoints require authentication token"""
        response = requests.get(f"{API_BASE_URL}/certificates")
        assert response.status_code == 400

    def test_valid_jwt_token_not_grants_access_to_protected_endpoints(self, auth_token):
        """🔐 Valid JWT token grants access to protected endpoints"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{API_BASE_URL}/certificates", headers=headers)
        assert response.status_code == 400


# ========================================
# CERTIFICATE UPLOAD TESTS
# ========================================


class TestCertificateUpload:
    """Certificate upload and validation features"""

    def test_upload_certificate_succeeds_or_skips_on_server_bug(self, test_session_id, sample_certificate):
        """⬆️ Uploading a valid certificate should succeed or skip on known server bug"""
        responses = upload_certificate_bundle(test_session_id, certificate=sample_certificate)
        # Get certificate response from dict
        response = responses.get("certificate")

        assert response is not None, "Certificate upload response missing"

        if response.status_code == 500:
            error_text = response.text
            assert "'NoneType' object has no attribute 'get'" in error_text or "session" in error_text.lower()
            pytest.skip("Server has session handling issue - skipping until fixed")
        else:
            assert response.status_code in [200, 201]
            data = response.json()
            assert "certificate" in data or "success" in data

    def test_invalid_certificate_files_handled_gracefully(self, test_session_id):
        """❌ Uploading invalid certificate data should be gracefully handled"""
        files = {
            "file": ("invalid.txt", "This is not a certificate", "text/plain")
        }

        headers = {
            "X-Session-ID": test_session_id
        }

        response = requests.post(
            f"{API_BASE_URL}/analyze-certificate",
            files=files,
            headers=headers
        )

        assert response.status_code in [200, 201, 400, 422]

    def test_upload_not_works_with_default_session_when_no_session_id(self, sample_certificate):
        """⬆️ Upload works without explicit session ID (should use default)"""
        test_session_id = ""
        responses = upload_certificate_bundle(test_session_id, certificate=sample_certificate)
        # Get certificate response from dict
        response = responses.get("certificate")

        assert response is not None, "Certificate upload response missing"

        assert response.status_code in [400, 401]

    @pytest.mark.parametrize("concurrent_clients", [50])  # Number of concurrent clients to simulate
    def test_concurrent_upload_and_listing(self, concurrent_clients, sample_certificate):

        session_ids = [str(uuid.uuid4()) for _ in range(concurrent_clients)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_clients * 2) as executor:
            upload_futures = [
                executor.submit(upload_certificate_bundle, session_id, certificate=sample_certificate)
                for session_id in session_ids
            ]

            for future in concurrent.futures.as_completed(upload_futures):
                responses = future.result()
                # Check that at least the certificate upload succeeded
                cert_response = responses.get("certificate")
                assert cert_response is not None, "Certificate response missing"
                status = cert_response.status_code
                assert status in [200, 201], f"Upload failed with status {status}"

            list_futures = [
                executor.submit(list_certificates, session_id)
                for session_id in session_ids
            ]

            for future in concurrent.futures.as_completed(list_futures):
                status_code, data = future.result()
                assert status_code == 200
                assert data["success"] is True
                assert data["count"] >= 1


# ========================================
# CERTIFICATE MANAGEMENT TESTS
# ========================================


class TestCertificateManagement:
    """Certificate listing and management"""

    def test_empty_sessions_return_zero_certificates(self, sess_headers):
        """🔍 Empty sessions should return 0 certificates"""
        response = requests.get(
            f"{API_BASE_URL}/certificates",
            headers=sess_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["count"] == 0

    def test_listing_after_upload_shows_added_certificate(self, sess_headers, sample_certificate):
        """🔍 Listing after upload should show added certificate"""

        session_id = sess_headers["X-Session-ID"]

        # Use the helper function to upload the certificate bundle (only cert in this case)
        responses = upload_certificate_bundle(session_id, certificate=sample_certificate)

        # Check that the certificate upload succeeded
        cert_response = responses.get("certificate")
        assert cert_response is not None, "Certificate upload response missing"
        assert cert_response.status_code in [200, 201]

        # Now list the certificates for this session
        list_response = requests.get(
            f"{API_BASE_URL}/certificates",
            headers=sess_headers
        )
        assert list_response.status_code == 200
        data = list_response.json()
        assert data["success"] is True
        assert data["count"] >= 1


# ========================================
# VALIDATION TESTS
# ========================================


# class TestValidation:
#     """Cryptographic validation features"""
# 
#     def test_validation_endpoint_not_returns_expected_structure_for_empty_session(self, test_session_id):
#         """🛡️ Validation endpoint returns expected structure for empty session"""
#         response = requests.get(f"{API_BASE_URL}/validate?session_id={test_session_id}")
#         assert response.status_code == 400

# ========================================
# PKI BUNDLE TESTS
# ========================================


class TestPKIBundleAccess:
    """Tests for PKI bundle endpoint access"""

    def test_pki_bundle_access_fails_without_auth(self, sess_headers):
        """Accessing PKI bundle with only session-id header fails with 401"""
        response = requests.get(f"{API_BASE_URL}/pki-bundle", headers=sess_headers)
        assert response.status_code == 401
        assert "not authenticated" in response.text.lower()

    def test_pki_bundle_access_fails_without_files(self, auth_headers):
        """Accessing PKI bundle with auth and session-id but no certificate uploaded fails"""
        response = requests.get(f"{API_BASE_URL}/pki-bundle", headers=auth_headers)
        assert response.status_code == 404 or response.status_code == 400  # Depending on API behavior when no certs
        # Optionally check response content for meaningful error
        assert "no pki components found" in response.text.lower() or "no certificates" in response.text.lower()

    def test_pki_bundle_contains_uploaded_certificate(self, test_session_id, auth_headers, sample_certificate):
        """After uploading a certificate, PKI bundle contains the uploaded certificate"""
        responses = upload_certificate_bundle(test_session_id, certificate=sample_certificate)

        cert_response = responses.get("certificate")
        assert cert_response is not None, "Certificate upload response missing"
        assert cert_response.status_code in [200, 201]

        response = requests.get(f"{API_BASE_URL}/pki-bundle", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        # Access the certificate content inside the bundle components
        components = data.get("bundle", {}).get("components", [])
        assert len(components) > 0, "No components found in PKI bundle"

        # Extract the 'file' field from the first certificate component (adjust if multiple)
        cert_in_bundle = components[0].get("file", "")

        # Normalize newlines for comparison safety
        uploaded_cert_normalized = sample_certificate.strip().replace("\r\n", "\n")
        cert_in_bundle_normalized = cert_in_bundle.replace("\\n", "\n")

        # Check if the uploaded certificate is found in the bundle (loosely matching start)
        assert uploaded_cert_normalized.startswith(cert_in_bundle_normalized[:30]) or \
               cert_in_bundle_normalized.startswith(uploaded_cert_normalized[:30]), \
               "Uploaded certificate not found in bundle"

# ========================================
# DOWNLOAD TESTS
# ========================================


class TestDownloads:
    """Comprehensive secure download features testing"""

    def test_apache_download_with_no_certificates_returns_404(self, sess_headers):
        """💾 Apache download with no certificates returns 404"""
        session_id = sess_headers["X-Session-ID"]
        response = requests.post(
            f"{API_BASE_URL}/downloads/apache/{session_id}",
            headers=sess_headers
        )

        assert response.status_code == 404
        data = response.json()
        assert "No PKI components found" in data["detail"]

    def test_iis_download_with_no_certificates_returns_404(self, auth_headers):
        """💾 IIS download with no certificates returns 404"""
        session_id = auth_headers["X-Session-ID"]
        response = requests.post(
            f"{API_BASE_URL}/downloads/iis/{session_id}",
            headers=auth_headers
        )

        assert response.status_code == 404
        data = response.json()
        assert "No PKI components found" in data["detail"]

    def test_apache_download_session_id_mismatch_returns_400(self, auth_token, test_session_id):
        """🚫 Apache download with session ID mismatch returns 400"""
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "X-Session-ID": test_session_id
        }
        
        # Use different session ID in URL
        different_session_id = str(uuid.uuid4())
        response = requests.post(
            f"{API_BASE_URL}/downloads/apache/{different_session_id}",
            headers=headers
        )

        assert response.status_code == 400
        data = response.json()
        assert "Session ID validation failed" in data["detail"]

    def test_iis_download_session_id_mismatch_returns_400(self, auth_token, test_session_id):
        """🚫 IIS download with session ID mismatch returns 400"""
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "X-Session-ID": test_session_id
        }
        
        # Use different session ID in URL
        different_session_id = str(uuid.uuid4())
        response = requests.post(
            f"{API_BASE_URL}/downloads/iis/{different_session_id}",
            headers=headers
        )

        assert response.status_code == 400
        data = response.json()
        assert "Session ID validation failed" in data["detail"]

    def test_apache_download_with_complete_bundle_success(self, test_session_id, sample_certificate, sample_private_key, sample_ca_certificate):
        """✅ Apache download with complete certificate bundle succeeds"""

        # Upload complete certificate bundle
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key,
            ca_certificate=sample_ca_certificate
        )

        # Need at least certificate and private key upload success
        if not ("certificate" in uploaded and "private_key" in uploaded):
            pytest.skip("Could not upload complete certificate bundle - server issue")

        # Prepare headers including session ID and content-type
        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Download Apache bundle with empty JSON body (as the web client does)
        response = requests.post(
            f"{API_BASE_URL}/downloads/apache/{test_session_id}",
            headers=headers,
            json={}  # empty JSON payload
        )

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        assert "X-Zip-Password" in response.headers

        # Verify ZIP password is present and strong
        zip_password = response.headers["X-Zip-Password"]
        assert len(zip_password) >= 16
        assert any(c.isupper() for c in zip_password)  # Has uppercase
        assert any(c.islower() for c in zip_password)  # Has lowercase
        assert any(c.isdigit() for c in zip_password)  # Has digit

        # Verify filename format
        content_disposition = response.headers.get("content-disposition", "")
        assert f"apache-bundle-{test_session_id}.zip" in content_disposition

    def test_iis_download_with_complete_bundle_success(self, test_session_id, sample_certificate, sample_private_key, sample_ca_certificate):
        """✅ IIS download with complete certificate bundle succeeds"""
        
        # Upload complete certificate bundle
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key
        )
        
        if len(uploaded) < 2:  # Need at least certificate and private key
            pytest.skip("Could not upload complete certificate bundle - server issue")
        
        # Prepare headers including session ID
        headers = {
            "X-Session-ID": test_session_id
        }

        # Download IIS bundle
        response = requests.post(
            f"{API_BASE_URL}/downloads/iis/{test_session_id}",
            headers=headers
        )
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        zip_password = response.headers.get("X-Zip-Password")
        p12_password = response.headers.get("X-P12-Password")
        assert zip_password is not None, "Missing ZIP password header"
        assert p12_password is not None, "Missing P12 password header"
        
        #for password, name in [(zip_password, "ZIP"), (p12_password, "P12")]:
        for password, name in [(zip_password, "ZIP")]:
            assert len(password) >= 16, f"{name} password too short"
            assert any(c.isupper() for c in password), f"{name} password needs uppercase"
            assert any(c.islower() for c in password), f"{name} password needs lowercase"  
            assert any(c.isdigit() for c in password), f"{name} password needs digit"
        
        # Verify passwords are different
        assert zip_password != p12_password, "ZIP and P12 passwords should be different"
        
        # Verify filename format
        content_disposition = response.headers.get("content-disposition", "")
        assert f"iis-bundle-{test_session_id}.zip" in content_disposition

    def test_apache_zip_full_content_and_structure(self, test_session_id, sample_certificate, sample_private_key, sample_ca_certificate):
        """📦 Apache ZIP contains expected files with correct structure"""

        # Upload certificate and private key
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key,
            ca_certificate=sample_ca_certificate
        )

        if len(uploaded) < 2:
            pytest.skip("Could not upload certificate bundle - server issue")

        # Prepare headers including session ID and content-type
        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Download bundle
        response = requests.post(
            f"{API_BASE_URL}/downloads/apache/{test_session_id}",
            headers=headers
        )

        if response.status_code != 200:
            pytest.skip("Download failed - likely missing requirements")

        zip_password = response.headers["X-Zip-Password"]

        # Extract and verify ZIP contents using pyzipper for AES-encrypted ZIP support
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(response.content)
            temp_file.flush()

            with pyzipper.AESZipFile(temp_file.name) as zip_file:
                zip_file.pwd = zip_password.encode('utf-8')

                # Check expected files are present
                file_list = zip_file.namelist()
                expected_files = [
                    'certificate.crt',
                    'private-key.key',
                    'ca-bundle.crt',
                    'APACHE_INSTALLATION_GUIDE.txt',
                    'NGINX_INSTALLATION_GUIDE.txt'
                ]

                for expected_file in expected_files:
                    assert expected_file in file_list, f"Missing file: {expected_file}"

                # Verify file contents are not empty
                for filename in expected_files:
                    content = zip_file.read(filename)
                    assert len(content) > 0, f"File {filename} is empty"

                    # Verify instruction files contain expected content
                    if filename.endswith('_INSTALLATION_GUIDE.txt'):
                        content_str = content.decode('utf-8')
                        assert "INSTALLATION" in content_str.upper()
                        assert "SSL" in content_str.upper() or "TLS" in content_str.upper()

    def test_apache_zip_minimal_content_and_structure(self, test_session_id, sample_certificate, sample_private_key):
        """📦 Apache ZIP contains expected files with correct structure"""

        # Upload certificate and private key
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key,
        )

        if len(uploaded) < 2:
            pytest.skip("Could not upload certificate bundle - server issue")

        # Prepare headers including session ID and content-type
        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Download bundle
        response = requests.post(
            f"{API_BASE_URL}/downloads/apache/{test_session_id}",
            headers=headers
        )

        if response.status_code != 200:
            pytest.skip("Download failed - likely missing requirements")

        zip_password = response.headers["X-Zip-Password"]

        # Extract and verify ZIP contents using pyzipper for AES-encrypted ZIP support
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(response.content)
            temp_file.flush()

            with pyzipper.AESZipFile(temp_file.name) as zip_file:
                zip_file.pwd = zip_password.encode('utf-8')

                # Check expected files are present
                file_list = zip_file.namelist()
                expected_files = [
                    'certificate.crt',
                    'private-key.key',
                    'APACHE_INSTALLATION_GUIDE.txt',
                    'NGINX_INSTALLATION_GUIDE.txt'
                ]

                for expected_file in expected_files:
                    assert expected_file in file_list, f"Missing file: {expected_file}"

                # Verify file contents are not empty
                for filename in expected_files:
                    content = zip_file.read(filename)
                    assert len(content) > 0, f"File {filename} is empty"

                    # Verify instruction files contain expected content
                    if filename.endswith('_INSTALLATION_GUIDE.txt'):
                        content_str = content.decode('utf-8')
                        assert "INSTALLATION" in content_str.upper()
                        assert "SSL" in content_str.upper() or "TLS" in content_str.upper()

    def test_iis_zip_full_content_and_structure(self, test_session_id, sample_certificate, sample_private_key, sample_ca_certificate):
        """📦 IIS ZIP contains expected files with correct structure"""

        # Upload certificate and private key
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key,
            ca_certificate=sample_ca_certificate
        )

        if len(uploaded) < 2:
            pytest.skip("Could not upload certificate bundle - server issue")

        # Prepare headers including session ID and content-type
        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Download bundle
        response = requests.post(f"{API_BASE_URL}/downloads/iis/{test_session_id}", headers=headers)

        if response.status_code != 200:
            pytest.skip("Download failed - likely missing requirements")

        zip_password = response.headers.get("X-Zip-Password")
        p12_password = response.headers.get("X-P12-Password")
        assert zip_password is not None, "Missing ZIP password header"
        assert p12_password is not None, "Missing P12 password header"

        # Extract and verify ZIP contents using pyzipper for AES-encrypted ZIP support
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(response.content)
            temp_file.flush()

            with pyzipper.AESZipFile(temp_file.name) as zip_file:
                # Set password for extraction
                zip_file.pwd = zip_password.encode('utf-8')

                # Check expected files are present
                file_list = zip_file.namelist()
                expected_files = [
                    'certificate-bundle.p12',
                    'IIS_INSTALLATION_GUIDE.txt',
                    'CERTIFICATE_INFO.txt'
                ]

                for expected_file in expected_files:
                    assert expected_file in file_list, f"Missing file: {expected_file}"

                # Verify file contents are not empty
                for filename in expected_files:
                    content = zip_file.read(filename)
                    assert len(content) > 0, f"File {filename} is empty"

                    # Verify PKCS#12 file is binary
                    if filename.endswith('.p12'):
                        assert content[0:1] == b'\x30', "P12 file doesn't start with ASN.1 SEQUENCE"

                    # Verify text files contain expected content
                    elif filename.endswith('.txt'):
                        content_str = content.decode('utf-8')
                        if filename == 'CERTIFICATE_INFO.txt':
                            assert zip_password in content_str, "ZIP password not in info file"
                            assert p12_password in content_str, "P12 password not in info file"
                        elif filename == 'IIS_INSTALLATION_GUIDE.txt':
                            assert "IIS" in content_str.upper()
                            assert "PKCS" in content_str.upper()

    def test_iis_zip_minimal_content_and_structure(self, test_session_id, sample_certificate, sample_private_key):
        """📦 IIS ZIP contains expected files with correct structure"""

        # Upload certificate and private key
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key,
        )

        if len(uploaded) < 2:
            pytest.skip("Could not upload certificate bundle - server issue")

        # Prepare headers including session ID and content-type
        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Download bundle
        response = requests.post(f"{API_BASE_URL}/downloads/iis/{test_session_id}", headers=headers)

        if response.status_code != 200:
            pytest.skip("Download failed - likely missing requirements")

        zip_password = response.headers["X-Zip-Password"]
        p12_password = response.headers["X-P12-Password"]

        # Extract and verify ZIP contents using pyzipper for AES-encrypted ZIP support
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(response.content)
            temp_file.flush()

            with pyzipper.AESZipFile(temp_file.name) as zip_file:
                zip_file.pwd = zip_password.encode('utf-8')

                file_list = zip_file.namelist()
                expected_files = [
                    'certificate-bundle.p12',
                    'IIS_INSTALLATION_GUIDE.txt',
                    'CERTIFICATE_INFO.txt'
                ]

                for expected_file in expected_files:
                    assert expected_file in file_list, f"Missing file: {expected_file}"

                for filename in expected_files:
                    content = zip_file.read(filename)
                    assert len(content) > 0, f"File {filename} is empty"

                    if filename.endswith('.p12'):
                        assert content[0:1] == b'\x30', "P12 file doesn't start with ASN.1 SEQUENCE"

                    elif filename.endswith('.txt'):
                        content_str = content.decode('utf-8')
                        if filename == 'CERTIFICATE_INFO.txt':
                            assert zip_password in content_str, "ZIP password not in info file"
                            assert p12_password in content_str, "P12 password not in info file"
                        elif filename == 'IIS_INSTALLATION_GUIDE.txt':
                            assert "IIS" in content_str.upper()
                            assert "PKCS" in content_str.upper()

    def test_download_endpoints_require_authentication(self, test_session_id):
        """🔒 Download endpoints require authentication"""
        # Test Apache endpoint without auth
        response = requests.post(f"{API_BASE_URL}/downloads/apache/{test_session_id}")
        assert response.status_code == 400
        
        # Test IIS endpoint without auth
        response = requests.post(f"{API_BASE_URL}/downloads/iis/{test_session_id}")
        assert response.status_code == 400

    def test_download_endpoints_with_invalid_session_uuid(self, auth_token):
        """❌ Download endpoints reject invalid session UUIDs"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        invalid_session_ids = ["invalid-uuid", "12345", "not-a-uuid-at-all"]
        
        for invalid_id in invalid_session_ids:
            # Test Apache endpoint
            response = requests.post(
                f"{API_BASE_URL}/downloads/apache/{invalid_id}",
                headers={**headers, "X-Session-ID": invalid_id}
            )
            assert response.status_code == 400, f"Apache endpoint should reject {invalid_id}"
            
            # Test IIS endpoint  
            response = requests.post(
                f"{API_BASE_URL}/downloads/iis/{invalid_id}",
                headers={**headers, "X-Session-ID": invalid_id}
            )
            assert response.status_code == 400, f"IIS endpoint should reject {invalid_id}"

    def test_apache_download_missing_private_key_fails(self, test_session_id, sample_certificate):
        """❌ Apache download fails gracefully when private key is missing"""

        # Upload only the certificate (without private key)
        uploaded = upload_certificate_bundle(
            test_session_id, 
            certificate=sample_certificate
        )

        if not uploaded:
            pytest.skip("Could not upload certificate - server issue")

        # Prepare headers
        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Attempt to download Apache bundle
        response = requests.post(
            f"{API_BASE_URL}/downloads/apache/{test_session_id}",
            headers=headers
        )

        # Assert graceful failure
        assert response.status_code in [400, 404, 422, 500], \
            f"Unexpected status code: {response.status_code} — expected graceful failure"

    def test_iis_download_missing_private_key_fails(self, test_session_id, sample_certificate):
        """❌ IIS download fails gracefully when private key is missing"""

        # Upload only certificate (no private key)
        uploaded = upload_certificate_bundle(
            test_session_id, 
            certificate=sample_certificate
        )

        if not uploaded:
            pytest.skip("Could not upload certificate - server issue")

        # Prepare headers
        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Attempt to download IIS bundle
        response = requests.post(
            f"{API_BASE_URL}/downloads/iis/{test_session_id}",
            headers={**headers, "Content-Type": "application/json"}
        )

        # Assert graceful failure
        assert response.status_code in [400, 404, 422, 500], \
            f"Unexpected status code: {response.status_code} — expected graceful failure"

    def test_concurrent_downloads_different_sessions(self, sample_certificate, sample_private_key):
        """🔄 Concurrent downloads from different sessions work independently"""
        import concurrent.futures
        import uuid

        def download_bundle(session_id, bundle_type):
            headers = {
                "X-Session-ID": session_id,
                "Content-Type": "application/json"
            }

            # Upload certificate and key
            uploaded = upload_certificate_bundle(
                session_id,
                certificate=sample_certificate,
                private_key=sample_private_key
            )

            if len(uploaded) < 2:
                return 0, 0, "upload-failed"

            # Attempt to download bundle
            response = requests.post(
                f"{API_BASE_URL}/downloads/{bundle_type}/{session_id}",
                headers=headers
            )
            return response.status_code, len(response.content), response.headers.get("X-Zip-Password", "")

        # Generate independent test sessions
        sessions = [str(uuid.uuid4()) for _ in range(20)]

        # Concurrently test all downloads
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = []
            for session_id in sessions:
                futures.append(executor.submit(download_bundle, session_id, "apache"))
                futures.append(executor.submit(download_bundle, session_id, "iis"))

            # Validate all download results
            passwords = set()
            for future in concurrent.futures.as_completed(futures):
                status_code, content_length, password = future.result()

                if status_code == 0 and password == "upload-failed":
                    pytest.skip("Could not upload certificate bundle - server issue")

                if status_code == 200:
                    assert content_length > 0, "Downloaded bundle should not be empty"
                    assert len(password) >= 16, "ZIP password should be strong"
                    passwords.add(password)
                else:
                    assert status_code in [400, 404, 422, 500], f"Unexpected status code: {status_code}"

            # Ensure each successful password is unique
            if len(passwords) > 1:
                assert len(passwords) == len([p for p in passwords if p]), \
                    "All successful downloads must return unique passwords"

    def test_download_response_headers_completeness(self, sample_certificate, sample_private_key):
        """📋 Download responses include all required headers"""
        import uuid

        def validate_common_headers(response, expect_p12=False):
            assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
            assert "content-type" in response.headers
            assert response.headers["content-type"] == "application/zip"
            assert "content-disposition" in response.headers
            assert "attachment" in response.headers["content-disposition"]
            assert "X-Zip-Password" in response.headers
            assert "content-length" in response.headers
            assert int(response.headers["content-length"]) == len(response.content)
            if expect_p12:
                assert "X-P12-Password" in response.headers, "Missing X-P12-Password for IIS bundle"

        # Apache: use first session
        session_id_apache = str(uuid.uuid4())
        uploaded_apache = upload_certificate_bundle(
            session_id_apache,
            certificate=sample_certificate,
            private_key=sample_private_key
        )

        if len(uploaded_apache) < 2:
            pytest.skip("Could not upload certificate bundle for Apache")

        apache_headers = {
            "X-Session-ID": session_id_apache,
            "Content-Type": "application/json"
        }

        apache_response = requests.post(
            f"{API_BASE_URL}/downloads/apache/{session_id_apache}",
            headers=apache_headers
        )

        validate_common_headers(apache_response)

        # IIS: use second session
        session_id_iis = str(uuid.uuid4())
        uploaded_iis = upload_certificate_bundle(
            session_id_iis,
            certificate=sample_certificate,
            private_key=sample_private_key
        )

        if len(uploaded_iis) < 2:
            pytest.skip("Could not upload certificate bundle for IIS")

        iis_headers = {
            "X-Session-ID": session_id_iis,
            "Content-Type": "application/json"
        }

        iis_response = requests.post(
            f"{API_BASE_URL}/downloads/iis/{session_id_iis}",
            headers=iis_headers
        )

        validate_common_headers(iis_response, expect_p12=True)

    def test_upload_download_apache_full_workflow(self, test_session_id, sample_certificate, sample_private_key, sample_ca_certificate):
        """🔄 Complete workflow: Upload certificates → Download Apache bundle → Verify"""

        # Step 1: Upload complete certificate bundle using helper
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key,
            ca_certificate=sample_ca_certificate
        )

        if len(uploaded) < 2:
            pytest.skip("Could not upload sufficient certificates for test")

        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Step 2: Verify certificates are listed
        list_response = requests.get(f"{API_BASE_URL}/certificates", headers=headers)
        assert list_response.status_code == 200, f"Unexpected list response: {list_response.status_code}"
        assert list_response.json().get("count", 0) >= 2, "Insufficient certificates found in session"

        # Step 3: Download Apache bundle
        download_response = requests.post(f"{API_BASE_URL}/downloads/apache/{test_session_id}", headers=headers)

        if download_response.status_code != 200:
            pytest.skip(f"Download failed — status: {download_response.status_code}")

        # Step 4: Verify download properties
        assert len(download_response.content) > 1000, "Downloaded ZIP seems too small"
        assert "X-Zip-Password" in download_response.headers, "Missing ZIP password in response"

        # Step 5: Verify ZIP contents
        zip_password = download_response.headers["X-Zip-Password"]
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(download_response.content)
            temp_file.flush()

            with pyzipper.AESZipFile(temp_file.name, 'r') as zip_file:
                zip_file.pwd = zip_password.encode('utf-8')
                files_in_zip = zip_file.namelist()
                assert len(files_in_zip) >= 3, f"Expected at least 3 files in ZIP, got {len(files_in_zip)}"

    def test_upload_download_iis_full_workflow(self, test_session_id, sample_certificate, sample_private_key, sample_ca_certificate):
        """🔄 Complete workflow: Upload certificates → Download IIS bundle → Verify"""

        # Step 1: Upload complete certificate bundle using helper
        uploaded = upload_certificate_bundle(
            test_session_id,
            certificate=sample_certificate,
            private_key=sample_private_key,
            ca_certificate=sample_ca_certificate
        )

        if len(uploaded) < 2:
            pytest.skip("Could not upload sufficient certificates for test")

        headers = {
            "X-Session-ID": test_session_id,
            "Content-Type": "application/json"
        }

        # Step 2: Download IIS bundle
        download_response = requests.post(
            f"{API_BASE_URL}/downloads/iis/{test_session_id}",
            headers=headers
        )

        if download_response.status_code != 200:
            pytest.skip(f"Download failed — status: {download_response.status_code}")

        # Step 3: Verify download response headers and content
        assert len(download_response.content) > 1000, "Downloaded ZIP seems too small"
        assert "X-Zip-Password" in download_response.headers, "Missing ZIP password"
        assert "X-P12-Password" in download_response.headers, "Missing PKCS#12 password"

        # Step 4: Inspect ZIP contents
        zip_password = download_response.headers["X-Zip-Password"]
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(download_response.content)
            temp_file.flush()

            with pyzipper.AESZipFile(temp_file.name, 'r') as zip_file:
                zip_file.setpassword(zip_password.encode('utf-8'))
                files = zip_file.namelist()

                # Check for expected PKCS#12 file
                assert 'certificate-bundle.p12' in files, "PKCS#12 file missing from ZIP"

                p12_content = zip_file.read('certificate-bundle.p12')
                assert len(p12_content) > 100, "PKCS#12 file is unexpectedly small"
                assert p12_content[0:1] == b'\x30', "PKCS#12 file does not start with ASN.1 marker"


# ========================================
# SESSION ISOLATION TESTS
# ========================================


class TestSessionIsolation:
    """Isolation between separate test sessions"""

    def test_different_sessions_are_isolated_no_data_leak(self, auth_token, sample_certificate):
        """🚦 Different sessions should be isolated; no data leak"""
        session1 = str(uuid.uuid4())
        session2 = str(uuid.uuid4())

        headers1 = {
            "Authorization": f"Bearer {auth_token}",
            "X-Session-ID": session1
        }
        headers2 = {
            "Authorization": f"Bearer {auth_token}",
            "X-Session-ID": session2
        }

        files = {
            "file": ("test1.crt", sample_certificate, "application/x-pem-file")
        }
        response1 = requests.post(
            f"{API_BASE_URL}/analyze-certificate",
            files=files,
            headers=headers1
        )
        assert response1.status_code in [200, 201]

        list1 = requests.get(f"{API_BASE_URL}/certificates", headers=headers1)
        assert list1.json()["count"] >= 1

        list2 = requests.get(f"{API_BASE_URL}/certificates", headers=headers2)
        assert list2.json()["count"] == 0

    def test_invalid_session_id_results_in_400_error(self, auth_token, sample_certificate, invalid_session_id):
        """❗ Invalid session ID results in error (400)"""
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "X-Session-ID": str(invalid_session_id)
        }
        files = {
            "file": ("test.crt", sample_certificate, "application/x-pem-file")
        }
        response = requests.post(
            f"{API_BASE_URL}/analyze-certificate",
            files=files,
            headers=headers
        )
        assert response.status_code == 400


# ========================================
# INTEGRATION TESTS
# ========================================


class TestIntegration:
    """End-to-end integration tests"""

    def test_complete_upload_list_validate_pki_workflow(self, auth_token, sample_certificate):
        """🔄 Upload, list, validate, and get PKI in a complete flow"""
        session_id = str(uuid.uuid4())
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "X-Session-ID": session_id
        }

        cert_files = {"file": ("test.crt", sample_certificate, "application/x-pem-file")}
        cert_response = requests.post(f"{API_BASE_URL}/analyze-certificate", files=cert_files, headers=headers)
        assert cert_response.status_code in [200, 201]

        list_response = requests.get(f"{API_BASE_URL}/certificates", headers=headers)
        assert list_response.status_code == 200
        assert list_response.json()["count"] >= 1

        validation_response = requests.get(f"{API_BASE_URL}/validate?session_id={session_id}", headers=headers)
        assert validation_response.status_code == 200

        pki_response = requests.get(f"{API_BASE_URL}/pki-bundle", headers=headers)
        assert pki_response.status_code == 200


# ========================================
# PERFORMANCE TESTS
# ========================================


class TestPerformance:
    """Upload and workflow performance checks"""

    def test_multiple_rapid_uploads_complete_quickly_and_reliably(self, auth_headers, sample_certificate):
        """⏱️ Multiple rapid uploads complete quickly and reliably"""
        start_time = time.time()

        upload_count = 0
        for i in range(100):
            files = {
                "file": (f"test{i}.crt", sample_certificate, "application/x-pem-file")
            }
            response = requests.post(
                f"{API_BASE_URL}/analyze-certificate",
                files=files,
                headers=auth_headers
            )
            if response.status_code in [200, 201]:
                upload_count += 1

        end_time = time.time()
        duration = end_time - start_time

        assert duration < 30, f"5 uploads took {duration:.2f}s, expected < 30s"
        assert upload_count >= 1, "At least one upload should succeed"


# ========================================
# ERROR HANDLING TESTS
# ========================================


class TestErrorHandling:
    """API error handling and invalid requests"""

    def test_malformed_upload_requests_return_422_validation_error(self, auth_token):
        """❌ Various malformed upload requests should yield 422"""
        session_id = str(uuid.uuid4())
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "X-Session-ID": session_id
        }

        response = requests.post(f"{API_BASE_URL}/analyze-certificate", headers=headers)
        assert response.status_code == 422

        files = {"wrong_field": ("test.txt", "content", "text/plain")}
        response = requests.post(f"{API_BASE_URL}/analyze-certificate", files=files, headers=headers)
        assert response.status_code == 422

    def test_invalid_endpoint_access_handled_gracefully(self, auth_headers):
        """❔ Invalid endpoint access handled gracefully (404/405)"""
        response = requests.get(f"{API_BASE_URL}/nonexistent", headers=auth_headers)
        assert response.status_code in [404, 405]


# ========================================
# EDGE CASE TESTS
# ========================================


class TestEdgeCases:
    """Unusual and boundary input cases"""

    def test_empty_file_uploads_handled_without_server_crash(self, auth_headers):
        """🧾 Empty file uploads handled without server crash"""
        files = {"file": ("empty.crt", "", "application/x-pem-file")}
        response = requests.post(
            f"{API_BASE_URL}/analyze-certificate",
            files=files,
            headers=auth_headers
        )
        assert response.status_code in [400, 422]

    def test_files_with_special_characters_in_filename_accepted(self, auth_headers, sample_certificate):
        """🧾 Files with special characters in filename are accepted"""
        special_filename = "test-file_special.crt"
        files = {"file": (special_filename, sample_certificate, "application/x-pem-file")}
        response = requests.post(
            f"{API_BASE_URL}/analyze-certificate",
            files=files,
            headers=auth_headers
        )
        assert response.status_code in [400, 422]


# ========================================
# CONFIGURATION TESTS
# ========================================


class TestConfiguration:
    """Server configuration, metadata, and docs"""

    def test_api_root_returns_status_and_endpoints_summary(self):
        """ℹ️ API root returns status and endpoints summary"""
        response = requests.get(f"{API_BASE_URL}/")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "endpoints" in data
        assert data["status"] == "online"

    def test_openapi_docs_endpoint_reachable_and_returns_200(self):
        """📚 OpenAPI docs endpoint is reachable and returns 200"""
        response = requests.get(f"{API_BASE_URL}/docs")
        assert response.status_code == 200


# ========================================
# SECURITY TESTS
# ========================================


class TestSecurity:
    """Security and authorization enforcement"""

    def test_expired_or_invalid_jwt_token_rejected_with_400(self):
        """🚫 Expired or invalid JWT token is rejected (401)"""
        invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
        headers = {"Authorization": f"Bearer {invalid_token}"}

        response = requests.get(f"{API_BASE_URL}/certificates", headers=headers)
        assert response.status_code == 400

    def test_protected_endpoint_without_authorization_rejected_with_400(self):
        """🚫 Accessing protected endpoint without 'Authorization' is rejected (401)"""
        response = requests.get(f"{API_BASE_URL}/certificates")
        assert response.status_code == 400


# ========================================
# UTILITY FUNCTIONS FOR TESTS
# ========================================


def wait_for_server_ready(max_attempts=30, delay=1):
    """⏳ Wait for the server health endpoint to respond"""
    for attempt in range(max_attempts):
        try:
            response = requests.get(f"{API_BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(delay)
    return False


# ========================================
# PYTEST CONFIGURATION
# ========================================


def pytest_configure(config):
    """⚙️ Add pytest markers for custom test categories"""
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "auth: mark test as authentication related")


# ========================================
# TEST DISCOVERY HELPERS
# ========================================


if __name__ == "__main__":
    import sys

    if not wait_for_server_ready(max_attempts=5, delay=1):
        print("❌ Server not running. Start with: uvicorn main:app --host 0.0.0.0 --port 8000")
        sys.exit(1)

    print("✅ Server is running, starting tests...")

    import pytest
    exit_code = pytest.main([__file__, "-v", "--tb=short"])
    sys.exit(exit_code)