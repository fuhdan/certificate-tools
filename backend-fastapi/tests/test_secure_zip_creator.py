"""
Tests for SecureZipCreator service - Updated to use pyzipper
"""

import pytest
import pyzipper
import tempfile
import sys
import os

# Add the parent directory (backend-fastapi) to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.secure_zip_creator import (
    SecureZipCreator,
    ZipCreationError,
    PasswordGenerationError,
    ZipValidationError
)


class TestSecureZipCreator:
    """Test suite for SecureZipCreator service"""
    
    @pytest.fixture
    def zip_creator(self):
        """Create SecureZipCreator instance for testing"""
        return SecureZipCreator()
    
    @pytest.fixture
    def sample_files(self):
        """Sample files for testing"""
        return {
            'test.txt': b'Hello, World!',
            'data.json': b'{"test": "data"}',
            'readme.md': '# Test README\nThis is a test file.'
        }
    
    def test_password_generation_default_length(self, zip_creator):
        """Test password generation with default length"""
        password = zip_creator.generate_secure_password()
        
        assert len(password) == zip_creator.DEFAULT_PASSWORD_LENGTH
        assert any(c.islower() for c in password)  # Has lowercase
        assert any(c.isupper() for c in password)  # Has uppercase
        assert any(c.isdigit() for c in password)  # Has digit
        assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)  # Has special
    
    def test_password_generation_custom_length(self, zip_creator):
        """Test password generation with custom length"""
        length = 25
        password = zip_creator.generate_secure_password(length)
        
        assert len(password) == length
    
    def test_password_generation_minimum_length_error(self, zip_creator):
        """Test password generation fails with too short length"""
        with pytest.raises(PasswordGenerationError):
            zip_creator.generate_secure_password(10)
    
    def test_password_uniqueness(self, zip_creator):
        """Test that generated passwords are unique"""
        passwords = [zip_creator.generate_secure_password() for _ in range(10)]
        assert len(set(passwords)) == 10  # All unique
    
    def test_create_protected_zip_basic(self, zip_creator, sample_files):
        """Test basic ZIP creation with generated password"""
        zip_data, password = zip_creator.create_protected_zip(sample_files)
        
        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0
        assert isinstance(password, str)
        assert len(password) >= zip_creator.MIN_PASSWORD_LENGTH
    
    def test_create_protected_zip_custom_password(self, zip_creator, sample_files):
        """Test ZIP creation with custom password"""
        custom_password = "MySecurePassword123!"
        zip_data, password = zip_creator.create_protected_zip(sample_files, custom_password)
        
        assert password == custom_password
        assert isinstance(zip_data, bytes)
    
    def test_create_protected_zip_empty_files_error(self, zip_creator):
        """Test ZIP creation fails with empty files"""
        with pytest.raises(ZipCreationError):
            zip_creator.create_protected_zip({})
    
    def test_zip_validation_success(self, zip_creator, sample_files):
        """Test successful ZIP validation"""
        zip_data, password = zip_creator.create_protected_zip(sample_files)
        
        is_valid = zip_creator.validate_zip_integrity(zip_data, password)
        assert is_valid is True
    
    def test_zip_validation_wrong_password(self, zip_creator, sample_files):
        """Test ZIP validation with wrong password - should fail with AES encryption"""
        zip_data, _ = zip_creator.create_protected_zip(sample_files)
        
        # With pyzipper AES encryption: should properly fail with wrong password
        is_valid = zip_creator.validate_zip_integrity(zip_data, "wrongpassword")
        assert is_valid is False
    
    def test_zip_validation_empty_data_error(self, zip_creator):
        """Test ZIP validation fails with empty data"""
        with pytest.raises(ZipValidationError):
            zip_creator.validate_zip_integrity(b'', "password")
    
    def test_zip_validation_no_password_error(self, zip_creator):
        """Test ZIP validation fails without password"""
        with pytest.raises(ZipValidationError):
            zip_creator.validate_zip_integrity(b'data', '')
    
    def test_zip_content_integrity(self, zip_creator, sample_files):
        """Test that ZIP contains correct files with correct content"""
        zip_data, password = zip_creator.create_protected_zip(sample_files)
        
        # Extract and verify content using pyzipper
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(zip_data)
            temp_file.flush()
            
            with pyzipper.AESZipFile(temp_file.name, 'r') as zip_file:
                zip_file.setpassword(password.encode('utf-8'))
                
                # Check all files are present
                zip_files = zip_file.namelist()
                assert len(zip_files) == len(sample_files)
                
                for filename in sample_files:
                    assert filename in zip_files
                    
                    # Check content
                    extracted_content = zip_file.read(filename)
                    expected_content = sample_files[filename]
                    
                    if isinstance(expected_content, str):
                        expected_content = expected_content.encode('utf-8')
                    
                    assert extracted_content == expected_content
    
    def test_create_apache_bundle(self, zip_creator):
        """Test Apache bundle creation"""
        certificate = b'-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----'
        private_key = b'-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----'
        ca_bundle = b'-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----'
        apache_guide = "Apache installation guide"
        nginx_guide = "Nginx installation guide"
        
        zip_data, password = zip_creator.create_apache_bundle(
            certificate, private_key, ca_bundle, apache_guide, nginx_guide
        )
        
        assert isinstance(zip_data, bytes)
        assert len(password) >= zip_creator.MIN_PASSWORD_LENGTH
        
        # Verify ZIP contents using pyzipper
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(zip_data)
            temp_file.flush()
            
            with pyzipper.AESZipFile(temp_file.name, 'r') as zip_file:
                zip_file.setpassword(password.encode('utf-8'))
                files = zip_file.namelist()
                
                # Based on actual implementation using File Naming Service
                expected_files = [
                    'certificate.crt',        # get_standard_filename(CERTIFICATE, "PEM")
                    'private-key.pem',        # get_standard_filename(PRIVATE_KEY, "PEM") 
                    'ca-bundle.crt',          # Hardcoded CA bundle name
                    'APACHE_INSTALLATION_GUIDE.txt',
                    'NGINX_INSTALLATION_GUIDE.txt'
                ]
                
                for expected_file in expected_files:
                    assert expected_file in files
    
    def test_create_iis_bundle(self, zip_creator):
        """Test IIS bundle creation"""
        p12_bundle = b'PKCS12 bundle data'
        iis_guide = "IIS installation guide"
        
        zip_data, password = zip_creator.create_iis_bundle(
            p12_bundle, iis_guide
        )
        
        assert isinstance(zip_data, bytes)
        assert len(password) >= zip_creator.MIN_PASSWORD_LENGTH
        
        # Verify ZIP contents using pyzipper
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(zip_data)
            temp_file.flush()
            
            with pyzipper.AESZipFile(temp_file.name, 'r') as zip_file:
                zip_file.setpassword(password.encode('utf-8'))
                files = zip_file.namelist()
                
                # Based on actual implementation - IIS bundle only includes P12 and guide
                # No CERTIFICATE_INFO.txt is created by default
                expected_files = [
                    'certificate-bundle.p12',  # get_standard_filename(CERTIFICATE, "PKCS12")
                    'IIS_INSTALLATION_GUIDE.txt'
                ]
                
                for expected_file in expected_files:
                    assert expected_file in files
    
    def test_memory_usage_estimate(self, zip_creator, sample_files):
        """Test memory usage estimation"""
        estimate = zip_creator.get_memory_usage_estimate(sample_files)
        
        assert isinstance(estimate, int)
        assert estimate > 0
        
        # Should be reasonable estimate (not too small or too large)
        total_content_size = sum(
            len(content.encode('utf-8')) if isinstance(content, str) else len(content)
            for content in sample_files.values()
        )
        
        assert estimate >= total_content_size  # At least as big as content
        assert estimate <= total_content_size * 3  # Not unreasonably large
    
    def test_large_file_handling(self, zip_creator):
        """Test handling of larger files"""
        # Create a 1MB test file
        large_content = b'x' * (1024 * 1024)
        files = {'large_file.bin': large_content}
        
        zip_data, password = zip_creator.create_protected_zip(files)
        
        assert isinstance(zip_data, bytes)
        assert len(zip_data) < len(large_content)  # Should be compressed
        
        # Verify integrity
        is_valid = zip_creator.validate_zip_integrity(zip_data, password)
        assert is_valid is True


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
    
    def test_string_content_handling(self, zip_creator):
        """Test handling of string content (auto-conversion to bytes)"""
        files = {
            'text.txt': 'This is a string content',
            'unicode.txt': 'Unicode: 你好 🌟',
            'binary.bin': b'Binary content'
        }
        
        zip_data, password = zip_creator.create_protected_zip(files)
        
        # Verify all content types are handled correctly using pyzipper
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(zip_data)
            temp_file.flush()
            
            with pyzipper.AESZipFile(temp_file.name, 'r') as zip_file:
                zip_file.setpassword(password.encode('utf-8'))
                
                # Check text file
                text_content = zip_file.read('text.txt')
                assert text_content == b'This is a string content'
                
                # Check unicode file
                unicode_content = zip_file.read('unicode.txt')
                assert unicode_content == 'Unicode: 你好 🌟'.encode('utf-8')
                
                # Check binary file
                binary_content = zip_file.read('binary.bin')
                assert binary_content == b'Binary content'


# Performance tests
class TestSecureZipCreatorPerformance:
    """Performance tests for SecureZipCreator"""
    
    @pytest.fixture
    def zip_creator(self):
        return SecureZipCreator()
    
    def test_password_generation_performance(self, zip_creator):
        """Test password generation performance"""
        import time
        
        start_time = time.time()
        passwords = [zip_creator.generate_secure_password() for _ in range(100)]
        end_time = time.time()
        
        # Should generate 100 passwords in less than 1 second
        assert end_time - start_time < 1.0
        assert len(set(passwords)) == 100  # All unique
    
    def test_multiple_small_files_performance(self, zip_creator):
        """Test performance with many small files"""
        import time
        
        # Create 100 small files
        files = {f'file_{i}.txt': f'Content of file {i}' for i in range(100)}
        
        start_time = time.time()
        zip_data, password = zip_creator.create_protected_zip(files)
        end_time = time.time()
        
        # Should complete in reasonable time
        assert end_time - start_time < 5.0
        assert len(zip_data) > 0
        
        # Verify integrity
        is_valid = zip_creator.validate_zip_integrity(zip_data, password)
        assert is_valid is True