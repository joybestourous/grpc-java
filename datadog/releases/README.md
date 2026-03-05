# Release Management

This directory contains scripts and documentation for managing our fork of
grpc-java, including keeping our patches up to date with upstream and creating
release branches.

## Prerequisites

- [GitHub CLI (`gh`)](https://cli.github.com/) installed and authenticated
- Git configured with write access to
  `git@github.com:DataDog/grpc-java-private.git`
- You have the following remotes setup in your git config

```
> git remote -v
origin  git@github.com:DataDog/grpc-java-private.git (fetch)
origin  git@github.com:DataDog/grpc-java-private.git (push)
upstream        git@github.com:grpc/grpc-java.git (fetch)
upstream        git@github.com:grpc/grpc-java.git (push)
```

## Branches

### master

Should always match the upstream `master` branch with only 1 DataDog commit
`Sync GitHub config from dd-master` on top. This branch provides visibility
into unreleased upstream changes.

### dd-master

**Should always match the latest upstream RELEASE TAG with all DataDog commits
on top.** This is the primary development branch. All DataDog patches are
developed and maintained here.

**Important:** dd-master tracks stable releases (e.g., `v1.68.0`), NOT
`upstream/master`. This ensures all DataDog patches are compatible with
released versions and can be cleanly rebased onto any release tag.

### dd-master-\<timestamp>

Working branches created when updating `dd-master` to a new upstream release.
These branches ensure DataDog changes can be rebased onto new releases.

### Version Branches

Branches with the format `v1.XX.X-ddX-branch` are DataDog release branches.
These should not be modified directly. They match the `v1.XX.X` upstream
release tag with all DataDog commits on top.

## Version Tagging and Consumption

Unlike the Go fork (which uses `go.mod` replace directives), grpc-java
consumers reference the fork by Maven coordinates. After a release branch is
created and tagged (e.g., `v1.68.0-dd1`), downstream projects update their
dependency declarations to reference the tag. The artifacts must be published
to an internal Maven/Artifactory registry before consumers can use them.

Tag format: `v1.XX.X-ddN` (e.g., `v1.68.0-dd1`)

## Development Philosophy

**Why dd-master tracks releases, not master:**

Our fork follows a release-based development model where `dd-master` tracks
the latest upstream **release tag** rather than `upstream/master`. By tracking
release tags, all DataDog patches are guaranteed to be compatible with the
current release and can be cleanly rebased onto any version tag.

**Implications:**

- ✅ All DataDog patches can be immediately released
- ✅ No dependency conflicts when creating release branches
- ✅ Clearer testing story (patches tested against stable releases)
- ✅ Doesn't pull in unreleased and perhaps unstable changes
- ⚠️ Need to rebase all patches when upstream releases (automated weekly)

## Workflows

### Adding Patches to the Fork

When adding new patches to our fork:

1. **Upstream Consideration**: For any patch that is not specifically related to
   the `datadog/` directory or `.github/`, check if there is an existing
   upstream issue or create one to discuss the change. This helps ensure our
   changes align with upstream's direction and may eventually be merged
   upstream.

2. **Sync with Upstream**: Before creating a new patch, ensure `dd-master` is
   up to date with the latest upstream release. If the automated sync workflow
   has not run recently, trigger it manually from the GitHub Actions tab.

3. **Create and Submit**: Create your patch branch from `dd-master`, make your
   changes, and submit a PR for review. Remember that `dd-master` tracks the
   latest upstream release tag, so your patches should not depend on unreleased
   upstream features.

4. **Merging/Rebasing your changes into dd-master**: If this is a new feature
   that you are bringing into dd-master, you can go ahead and squash merge your
   feature. However, if instead this is a modification of an existing patch,
   you should squash your changes into the existing patch that already exists.

   - Squash and merge your commit after approval so that we can distinguish
     between patches that are merged in and PRs that are closed.

   - Checkout dd-master locally, and run `git pull` so you have your merged
     commits.

   - Identify the commit which you want to merge your changes in. Let's say
     it's `ORIGINAL_COMMIT`

   - Run `git rebase -i $ORIGINAL_COMMIT^` and then move your commit so it's
     after the `ORIGINAL COMMIT` and then squash them together.

   - Run `git push --force`

### Automated Workflows (Recommended)

The repository uses GitHub Actions to automate most maintenance tasks. The
following workflows run automatically:

#### 1. Sync dd-master with Upstream (`.github/workflows/sync-dd-master.yml`)

**Schedule:** Runs weekly on Mondays at 7:00 UTC

**What it does:**

- Checks if a new upstream release is available
- Creates a timestamped branch (`dd-master-{timestamp}`)
- Attempts to automatically rebase DataDog patches onto the latest upstream
  release tag (e.g., `v1.68.0`)
- Creates a PR for review (either successful or for conflict resolution)

**After PR approval:** You must manually force push to dd-master:

```bash
git fetch origin dd-master-{timestamp}
git checkout dd-master
git reset --hard origin/dd-master-{timestamp}
git push origin dd-master --force
git push origin --delete dd-master-{timestamp}
git branch -d dd-master-{timestamp}
```

**Manual trigger:** You can also trigger this workflow manually from the GitHub
Actions tab.

#### 2. Auto-Detect New Releases (`.github/workflows/auto-detect-releases.yml`)

**Schedule:** Runs weekly on Tuesdays at 8:00 UTC (after dd-master sync)

**What it does:**

- Detects the latest upstream release from grpc/grpc-java
- Creates a version branch if it doesn't exist (e.g., `v1.68.0-branch`)
- Automatically triggers the create-release-branch workflow for new releases

**Note:** This workflow only creates releases for new upstream versions. To
create incremental DD releases with new patches (e.g., v1.68.0-dd2), manually
trigger the create-release-branch workflow.

#### 3. Create Release Branch (`.github/workflows/create-release-branch.yml`)

**Trigger:** Automatically triggered by auto-detect-releases, or manually via
GitHub Actions

**What it does:**

- Takes an upstream version as input (e.g., `v1.68.0`)
- Finds the next available dd number (`dd1`, `dd2`, etc.)
- Rebases DataDog patches onto the upstream release tag
- Updates the version in `build.gradle`
- Creates a release branch and tag

**On success:** The branch and tag are automatically created and pushed.
Downstream projects should be updated to consume the new tag from the internal
Maven registry.

**On conflict:** Follow the manual resolution steps printed in the job summary,
then run `./datadog/releases/complete_rebase_update.sh $NEW_BRANCH $VERSION`
to update `build.gradle` and commit, then push the branch and create the tag.

### Manual Conflict Resolution

When the automated workflows encounter rebase conflicts, follow the steps
printed in the GitHub Actions job summary. After resolving conflicts manually:

```bash
# After resolving conflicts and completing the rebase:
./datadog/releases/complete_rebase_update.sh $NEW_BRANCH $UPSTREAM_VERSION

# Push the branch and create the tag
git push origin $NEW_BRANCH --force
git tag -a $TAG_NAME -m "Version $TAG_NAME release"
git push origin $TAG_NAME
```

## Formatting

This file is formatted with [mdformat](https://github.com/hukkin/mdformat).

`mdformat ./datadog/releases/README.md --number --wrap 80`
