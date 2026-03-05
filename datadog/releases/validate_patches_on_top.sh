#!/bin/bash

set -e

# Source helper functions
source "$(dirname "$0")/helper.sh"

# Change to git root directory
change_to_git_root

# This script validates that any commits in a branch that differ from a reference branch
# are only applied at the top of the branch. This means:
# 1. There might be a point where the branch diverges from the reference branch
# 2. All commits after that divergence point should be unique to this branch

# Check arguments
if [ $# -lt 2 ]; then
    log_error "Usage: $0 <target_branch> <reference_branch>"
    log_error "Example: $0 v1.68.0-dd1 v1.68.0"
    exit 1
fi

TARGET_BRANCH=$1
REFERENCE_BRANCH=$2


# Function to validate branch commits
validate_branch() {
    local target_branch=$1
    local reference_branch=$2

    log "Validating patches on $target_branch against $reference_branch..."

    # Get all commits that are in our branch but not in the reference branch
    local cherry_output
    if ! cherry_output=$(git cherry -v $reference_branch $target_branch); then
        log_error "git cherry command failed!"
        log_error "Make sure both branches exist and are valid references."
        return 1
    fi

    log "Cherry Output"
    git cherry -v $reference_branch $target_branch

    # If there are no commits in our branch that aren't in the reference branch
    if [ -z "$cherry_output" ]; then
        log "No unique commits found - all commits are in $reference_branch"
        log "Current branch is identical to $reference_branch"
        return 0
    fi

    # Check if any '-' commit appears after a '+' commit
    # We want all unique commits ('+') to be at the top, with no interwoven commits ('-')
    local found_plus=false
    local found_minus_after_plus=false

    # Process the cherry output line by line - avoid pipe to prevent subshell issues
    while IFS= read -r line; do
        local prefix="${line:0:1}"

        if [ "$prefix" = "+" ]; then
            found_plus=true
        elif [ "$prefix" = "-" ] && [ "$found_plus" = true ]; then
            found_minus_after_plus=true
            break
        fi
    done < <(echo "$cherry_output")

    if [ "$found_minus_after_plus" = true ]; then
        log_error "Found cherry-picked commit after unique commit!"
        log_error "All cherry-picked commits should be before unique commits."
        log_error ""
        log_error "Cherry output:"
        git cherry -v $reference_branch $target_branch
        return 1
    fi

    log "Success: All cherry-picked commits are before unique commits"
    return 0
}

# Ensure upstream remote exists
ensure_upstream_remote
git fetch upstream

# Validate the branch
if ! validate_branch "$TARGET_BRANCH" "$REFERENCE_BRANCH"; then
    log_error "Validation failed! All commits in $TARGET_BRANCH should be applied on top of $REFERENCE_BRANCH"
    exit 1
fi

log "Validation successful!"
exit 0
