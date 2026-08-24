# Apex ACC Attestation Authority

This public repository is a deliberately minimal, owner-authorized signing authority for one bounded Apex Command Center TR-01D acceptance operation.

## Trust model

- The policy pins two non-reversible fingerprints for the exact Clerk development instance.
- The signing workflow runs in a protected GitHub Environment and performs a live read-only `GET /v1/instance` before signing.
- The workflow receives Clerk credentials only as encrypted Environment secrets and never prints or persists them.
- GitHub Actions OIDC and Sigstore Fulcio issue an ephemeral signing certificate. No long-lived private signing key is held by ACC Builder, Reviewer, Releaser, Harness or Caller.
- The Sigstore certificate identity must be exactly:
  `https://github.com/chrizzatsu/acc-attestation-authority/.github/workflows/sign-clerk-attestation.yml@refs/heads/main`
- The OIDC issuer must be exactly `https://token.actions.githubusercontent.com`.
- `main` is locked after initial setup. The scheduled first run requires protected-environment approval and signs only the locked policy/workflow.
- Release assets contain the canonical attestation JSON, Sigstore bundle, policy and SHA-256 manifest.

## Scope

The authority authorizes at most one temporary, non-customer, no-email, no-phone, no-invitation, no-notification principal for the exact development instance. Billing, plan, subscription, organization, database, CRM, MCP write/delete and external-send operations are forbidden. Cleanup and unchanged-state readback are mandatory.

## Verification

```bash
cosign verify-blob \
  --bundle clerk-instance-attestation-v1.sigstore.json \
  --certificate-identity 'https://github.com/chrizzatsu/acc-attestation-authority/.github/workflows/sign-clerk-attestation.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  clerk-instance-attestation-v1.json
sha256sum -c SHA256SUMS
```

The attestation is an owner-authorized, cryptographically bound operation policy plus live exact-instance/environment readback. It is not a general legal or billing guarantee and is invalid outside its stated operation, fingerprints, base SHA and validity window.
