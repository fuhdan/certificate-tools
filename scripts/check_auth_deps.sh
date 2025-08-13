#!/bin/bash

# Auth Dependency Check Script
# This script searches for all references to the auth system

echo "🔍 AUTH DEPENDENCY CHECK REPORT"
echo "==============================="
echo ""

# Get the project root directory (parent of scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend-fastapi"

# Change to backend directory
cd "$BACKEND_DIR" 2>/dev/null || {
    echo "❌ Error: backend-fastapi directory not found at $BACKEND_DIR"
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
    
    results=$(grep -r "$search_term" . --include="*.py" 2>/dev/null | grep -v __pycache__ | grep -v "\.pyc" | grep -v "auth/" || true)
    
    if [ -n "$results" ]; then
        echo "   ✅ FOUND:"
        echo "$results" | sed 's/^/      /'
    else
        echo "   ❌ NOT FOUND"
    fi
    echo ""
}

# Search for auth imports and usage
search_and_report "from.*auth" "Auth imports"
search_and_report "import.*auth" "Direct auth imports"
search_and_report "auth\." "Auth module usage"
search_and_report "User" "User model usage"
search_and_report "Depends.*auth" "Auth dependencies"
search_and_report "authenticate" "Authentication calls"
search_and_report "login" "Login functionality"
search_and_report "token" "Token usage"
search_and_report "jwt" "JWT usage"
search_and_report "Authorization" "Authorization headers"
search_and_report "Bearer" "Bearer token usage"

echo "📊 SUMMARY"
echo "=========="
echo ""

# Count total references outside auth directory
total_refs=$(grep -r "from.*auth\|import.*auth\|auth\.\|User\|authenticate\|login\|token\|jwt" . --include="*.py" 2>/dev/null | grep -v __pycache__ | grep -v "auth/" | wc -l)

echo "Total auth references found (outside auth/): $total_refs"
echo ""

if [ "$total_refs" -eq 0 ]; then
    echo "✅ SAFE TO DELETE: No external references to auth system found"
    echo "   You can safely delete the backend-fastapi/auth/ directory"
elif [ "$total_refs" -lt 5 ]; then
    echo "⚠️  FEW REFERENCES: Only $total_refs external references found"
    echo "   Review the specific files above and remove auth dependencies"
    echo "   Then you can delete the backend-fastapi/auth/ directory"
else
    echo "❌ MANY REFERENCES: $total_refs external references found"
    echo "   Auth system is actively used - keep the directory"
fi

echo ""
echo "📋 RECOMMENDATION"
echo "================"
echo ""

# Check what's in the auth directory
if [ -d "auth" ]; then
    echo "📂 Auth directory contents:"
    ls -la auth/ | sed 's/^/   /'
    echo ""
    
    # Quick check of main files that might use auth
    echo "🔍 Quick check of main application files:"
    
    # Check main.py
    if grep -q "auth" main.py 2>/dev/null; then
        echo "   ⚠️  main.py references auth"
    else
        echo "   ✅ main.py does NOT reference auth"
    fi
    
    # Check routers
    if [ -d "routers" ]; then
        auth_in_routers=$(grep -r "auth" routers/ --include="*.py" 2>/dev/null | wc -l)
        if [ "$auth_in_routers" -gt 0 ]; then
            echo "   ⚠️  routers/ contain $auth_in_routers auth references"
        else
            echo "   ✅ routers/ do NOT reference auth"
        fi
    fi
    
    echo ""
    
    if [ "$total_refs" -eq 0 ]; then
        echo "🎯 ACTION: Delete backend-fastapi/auth/ directory"
        echo "   The auth system appears to be unused"
    else
        echo "🎯 ACTION: Review auth usage before deciding"
        echo "   Check the references above to see if auth is needed"
    fi
else
    echo "📂 Auth directory not found - already deleted or doesn't exist"
fi

echo ""
echo "🏁 Auth scan complete!"