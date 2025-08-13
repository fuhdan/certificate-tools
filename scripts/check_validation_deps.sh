#!/bin/bash

# Validation Dependency Check Script
# This script searches for all references to the old validation system
# to determine what can be safely deleted

echo "🔍 VALIDATION DEPENDENCY CHECK REPORT"
echo "====================================="
echo ""

# Get the project root directory (parent of scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend-fastapi"

# Change to backend directory
cd "$BACKEND_DIR" 2>/dev/null || {
    echo "❌ Error: backend-fastapi directory not found at $BACKEND_DIR"
    echo "Expected project structure:"
    echo "  project-root/"
    echo "  ├── scripts/"
    echo "  └── backend-fastapi/"
    exit 1
}

echo "📁 Searching in: $(pwd)"
echo ""

# Function to search and report
search_and_report() {
    local search_term="$1"
    local description="$2"
    local results
    
    echo "🔍 Searching for: $description"
    echo "   Pattern: $search_term"
    
    results=$(grep -r "$search_term" . --include="*.py" 2>/dev/null | grep -v __pycache__ | grep -v "\.pyc")
    
    if [ -n "$results" ]; then
        echo "   ✅ FOUND:"
        echo "$results" | sed 's/^/      /'
    else
        echo "   ❌ NOT FOUND"
    fi
    echo ""
}

# Search for general validation imports
search_and_report "from.*validation" "General validation imports"
search_and_report "import.*validation" "Direct validation imports"

# Search for specific old validation components
search_and_report "ValidationResult" "ValidationResult model usage"
search_and_report "run_validations" "run_validations function calls"
search_and_report "CertificateValidator" "CertificateValidator class usage"

# Search for specific validation functions
search_and_report "validate_private_key_csr_match" "Private key <-> CSR validation"
search_and_report "validate_csr_certificate_match" "CSR <-> Certificate validation"
search_and_report "validate_private_key_certificate_match" "Private key <-> Certificate validation"
search_and_report "validate_certificate_chain" "Certificate chain validation"

# Search for validation module imports
search_and_report "certificates\.validation" "certificates.validation imports"
search_and_report "from certificates.validation" "From certificates.validation imports"

# Search for validation file references
search_and_report "private_key_csr" "private_key_csr module references"
search_and_report "csr_certificate" "csr_certificate module references"
search_and_report "private_key_cert" "private_key_cert module references"
search_and_report "chain_validation" "chain_validation module references"

echo "📊 SUMMARY"
echo "=========="
echo ""

# Count total references
total_refs=$(grep -r "ValidationResult\|run_validations\|CertificateValidator\|validate_.*_match\|validate_certificate_chain\|certificates\.validation" . --include="*.py" 2>/dev/null | grep -v __pycache__ | wc -l)

echo "Total references found: $total_refs"
echo ""

if [ "$total_refs" -eq 0 ]; then
    echo "✅ SAFE TO DELETE: No references to old validation system found"
    echo "   You can safely delete the entire certificates/validation/ directory"
elif [ "$total_refs" -lt 5 ]; then
    echo "⚠️  FEW REFERENCES: Only $total_refs references found"
    echo "   Review the specific files above and update them to use the new validation system"
    echo "   Then you can delete the certificates/validation/ directory"
else
    echo "❌ MANY REFERENCES: $total_refs references found"
    echo "   Significant refactoring needed before deletion"
    echo "   Consider gradual migration to the new validation system"
fi

echo ""
echo "📋 RECOMMENDATION"
echo "================"
echo ""

# Check if new validation service is being used
new_validation_refs=$(grep -r "validation_service" . --include="*.py" 2>/dev/null | grep -v __pycache__ | wc -l)

if [ "$new_validation_refs" -gt 0 ]; then
    echo "✅ New validation service is active ($new_validation_refs references found)"
    echo ""
    if [ "$total_refs" -eq 0 ]; then
        echo "🎯 ACTION: Delete certificates/validation/ directory completely"
    else
        echo "🎯 ACTION: Update remaining $total_refs references, then delete certificates/validation/"
    fi
else
    echo "⚠️  New validation service not found - check services/validation_service.py"
fi

echo ""
echo "🏁 Scan complete!"