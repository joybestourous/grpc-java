#!/bin/bash

set -e

cd "$(git rev-parse --show-toplevel)"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <new_branch> <version>"
    echo "Error: Incorrect number of arguments."
    exit 1
fi

NEW_BRANCH=$1
VERSION=$2

echo "Completing rebase actions for branch $NEW_BRANCH with version $VERSION..."
git branch --force "$NEW_BRANCH" HEAD
git checkout "$NEW_BRANCH"

# Update build.gradle version now that rebase/branch update is complete
echo "Running version update..."
# Remove 'v' prefix if it exists from NEW_BRANCH and '-branch' suffix
version_no_prefix="${NEW_BRANCH#v}"
version_no_suffix="${version_no_prefix%-branch}"

sed -i '' "s/version = \"[^\"]*\" \/\/ CURRENT_GRPC_VERSION/version = \"${version_no_suffix}\" \/\/ CURRENT_GRPC_VERSION/" build.gradle
git add build.gradle
git commit -m "Update build.gradle to ${version_no_suffix}"

echo "Successfully completed post-rebase actions for $NEW_BRANCH."

exit 0
