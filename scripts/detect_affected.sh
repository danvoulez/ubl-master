#!/bin/bash
# UBL Autopoietic Change Detection
# Intelligently detects what parts of the system are affected by changes

set -euo pipefail

# Default values
SCOPE="patch"
AFFECTED="core"
BREAKING="false"

# Get the base reference (main branch or previous commit)
if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
    BASE_REF="origin/main"
else
    # For pushes, compare with previous commit
    BASE_REF="HEAD~1"
fi

# Ensure we have the base ref available
if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
    echo "Warning: Cannot find base ref $BASE_REF, using HEAD~1"
    BASE_REF="HEAD~1"
fi

# Get changed files
CHANGED_FILES=$(git diff --name-only "$BASE_REF"...HEAD 2>/dev/null || echo "")

if [[ -z "$CHANGED_FILES" ]]; then
    echo "No changes detected"
    echo "affected=none"
    echo "breaking=false"
    echo "scope=none"
    exit 0
fi

echo "Changed files:"
echo "$CHANGED_FILES"

# Analyze scope of changes
analyze_scope() {
    local files="$1"
    local scope="patch"
    local affected="core"
    local breaking="false"

    # Check for breaking changes indicators
    if echo "$files" | grep -qE "(Cargo.toml|lib.rs|mod.rs)"; then
        scope="minor"

        # Check for API changes in public interfaces
        if git diff "$BASE_REF"...HEAD -- "*/lib.rs" "*/mod.rs" | grep -qE "^[-+].*pub (fn|struct|enum|trait|mod)"; then
            scope="major"
            breaking="true"
        fi
    fi

    # Determine affected components
    if echo "$files" | grep -q "^crates/ubl_runtime/"; then
        affected="runtime"
        if echo "$files" | grep -q "pipeline.rs"; then
            scope="minor"
        fi
    elif echo "$files" | grep -q "^crates/ubl_chipstore/"; then
        affected="chipstore"
    elif echo "$files" | grep -q "^crates/ubl_receipt/"; then
        affected="receipt"
    elif echo "$files" | grep -q "^services/ubl_gate/"; then
        affected="gateway"
    elif echo "$files" | grep -q "^crates/ubl_cli/"; then
        affected="cli"
    elif echo "$files" | grep -qE "^(\.github/|scripts/)"; then
        affected="infra"
        scope="patch"
    else
        affected="core"
    fi

    # Check for dependency changes
    if echo "$files" | grep -q "Cargo.lock"; then
        if [[ "$scope" == "patch" ]]; then
            scope="minor"
        fi
    fi

    # Check for version bumps in Cargo.toml
    if git diff "$BASE_REF"...HEAD -- "*/Cargo.toml" | grep -q "^+version"; then
        # Extract version change
        local version_change
        version_change=$(git diff "$BASE_REF"...HEAD -- "*/Cargo.toml" | grep "^+version" | head -1)
        if echo "$version_change" | grep -qE "\+.*[0-9]+\.[0-9]+\.0\""; then
            scope="major"
            breaking="true"
        elif echo "$version_change" | grep -qE "\+.*[0-9]+\.[1-9][0-9]*\.[0-9]+\""; then
            scope="minor"
        fi
    fi

    # Security-sensitive changes
    if echo "$files" | grep -qE "(crypto|auth|security|key)" || \
       git diff "$BASE_REF"...HEAD | grep -qiE "(password|secret|key|token|auth)"; then
        echo "Security-sensitive changes detected"
        if [[ "$scope" == "patch" ]]; then
            scope="minor"
        fi
    fi

    echo "affected=$affected"
    echo "breaking=$breaking"
    echo "scope=$scope"
}

# Run analysis
analyze_scope "$CHANGED_FILES"

# Additional context for debugging
echo ""
echo "=== Change Analysis Context ==="
echo "Base ref: $BASE_REF"
echo "Changed files count: $(echo "$CHANGED_FILES" | wc -l)"
echo "Commit range: $BASE_REF...HEAD"

# Show recent commits for context
echo ""
echo "=== Recent Commits ==="
git log --oneline "$BASE_REF"...HEAD | head -5