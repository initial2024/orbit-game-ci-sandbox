# Orbit Game CI Sandbox

Minimal, **public** and reproducible security-contract tests for the proposed game account-linking protocol.

This repository contains **only** a separately reviewed game-link issuer module, a synthetic testing adapter, test-only fixtures, and GitHub Actions configuration. It does not contain mailbox code, production database contents, user records, deployment tokens, private JWKs, or historic Git commits from the private services.

Passing sandbox CI is **supplemental evidence only**. It does not replace mandatory CI or release-security checks in the private main repository, nor authorize deploying the mail production service or enabling cloud save.

The sandbox is intended for GitHub standard hosted runners (`ubuntu-latest`). No deployment credentials are configured here.
