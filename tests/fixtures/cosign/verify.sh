#!/bin/sh
# ZES test fixture (inert)
cosign verify ghcr.io/example/app:1.0.0
cosign verify --certificate-identity=https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com ghcr.io/example/app:1.0.0
cosign verify --key cosign.pub ghcr.io/example/app:1.0.0
