# GitHub Workflows

This directory contains GitHub Actions workflows for the OpenID Federation Resolver project.

## Workflow

### `docker-image.yml` - Docker Build & Push
- **Triggers**: Push to `main`, `dev` branches, tags, and pull requests
- **Features**:
  - Multi-architecture builds (AMD64, ARM64)
  - Automatic tagging based on branch/tag
  - GitHub Container Registry (ghcr.io) publishing
  - Build provenance attestation
  - GitHub Actions cache optimization
  - Pull request validation (build without push)

## Authentication

No extra repository secrets are required. The workflow authenticates to `ghcr.io` with `GITHUB_TOKEN` (`packages: write` is already granted).

## Workflow Features

### Build & Deployment
- ✅ **Multi-architecture Builds** (AMD64, ARM64)
- ✅ **Build Caching** (GitHub Actions cache)
- ✅ **Build Provenance** (SLSA attestations)
- ✅ **Smart Tagging** (branch names, semantic versions)

### Publishing & Tagging
- ✅ **Automatic Tagging** (branch names, semantic versions)
- ✅ **Latest Tag** (for main branch)
- ✅ **PR Builds** (build validation without publishing)
- ✅ **Metadata Labels** (build info, git refs)

## Usage

### For Development
- **Pull Requests**: Builds and validates only, no publishing
- **Development Branches**: Builds and publishes with branch name as tag  
- **Main Branch**: Builds and publishes with `latest` tag

### For Releases
- **Git Tags**: Create tags like `v1.0.0` for semantic versioning
- **Multiple Tags**: Automatically creates `v1.0.0`, `v1.0`, `v1` tags

### Example Docker Images

```bash
# Latest development build
docker pull ghcr.io/surf-openid-federation/openid-federation-resolver:latest

# Development branch
docker pull ghcr.io/surf-openid-federation/openid-federation-resolver:dev

# Specific version
docker pull ghcr.io/surf-openid-federation/openid-federation-resolver:v1.0.0
```

## Repository Configuration

The workflows are configured to only run on the main repository (`SURF-OpenID-Federation/OpenID-Federation-Resolver`) to prevent issues with forks. GHCR image names are lowercased automatically. After the first publish, set package visibility under **Packages** if you want public pulls.