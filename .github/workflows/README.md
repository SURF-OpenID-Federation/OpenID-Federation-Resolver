# GitHub Workflows

This directory contains GitHub Actions workflows for the OpenID Federation Resolver project.

## Workflows

### 1. `docker-image.yml` - Simple Docker Build & Push
- **Triggers**: Push to `main`, `dev` branches, tags, and pull requests
- **Features**:
  - Multi-architecture builds (AMD64, ARM64)
  - Automatic tagging based on branch/tag
  - Docker Hub publishing
  - Build provenance attestation
  - GitHub Actions cache optimization

### 2. `ci-cd.yml` - Comprehensive CI/CD Pipeline
- **Triggers**: Push to `main`, `dev` branches and pull requests
- **Features**:
  - **Testing**: Go tests, vet, staticcheck
  - **Security**: Gosec scanner, Trivy vulnerability scanning
  - **Building**: Multi-arch Docker builds with security scanning
  - **Publishing**: Docker Hub with metadata and attestations

## Required Secrets

To use these workflows, configure the following secrets in your GitHub repository:

1. **`DOCKERHUB_USERNAME`** - Your Docker Hub username
2. **`DOCKERHUB_TOKEN`** - Docker Hub access token (not password!)

### Setting up Docker Hub Access Token

1. Go to [Docker Hub Account Settings](https://hub.docker.com/settings/security)
2. Click "New Access Token"
3. Give it a name like "GitHub Actions - OpenID Federation Resolver"
4. Copy the generated token
5. Add it as `DOCKERHUB_TOKEN` secret in your GitHub repository

## Workflow Features

### Security & Quality
- ✅ **Go Static Analysis** (vet, staticcheck)
- ✅ **Security Scanning** (Gosec, Trivy)
- ✅ **Vulnerability Assessment** (Container and filesystem)
- ✅ **Build Provenance** (SLSA attestations)

### Performance & Efficiency
- ✅ **Multi-architecture Builds** (AMD64, ARM64)
- ✅ **Build Caching** (GitHub Actions cache)
- ✅ **Dependency Caching** (Go modules)
- ✅ **Parallel Jobs** (Testing, security, building)

### Publishing & Tagging
- ✅ **Automatic Tagging** (branch names, semantic versions)
- ✅ **Latest Tag** (for main branch)
- ✅ **PR Builds** (without publishing)
- ✅ **Metadata Labels** (build info, git refs)

## Usage

### For Development
- **Pull Requests**: Builds and tests only, no publishing
- **Feature Branches**: Builds and publishes with branch name as tag
- **Main Branch**: Builds and publishes with `latest` tag

### For Releases
- **Git Tags**: Create tags like `v1.0.0` for semantic versioning
- **Multiple Tags**: Automatically creates `v1.0.0`, `v1.0`, `v1` tags

### Example Docker Images

```bash
# Latest development build
docker pull harrykodden/openid-federation-resolver:latest

# Specific version
docker pull harrykodden/openid-federation-resolver:v1.0.0
```

## Repository Configuration

The workflows are configured to only run on the main repository (`HarryKodden/OpenID-Federation-Resolver`) to prevent issues with forks that don't have the required secrets configured.