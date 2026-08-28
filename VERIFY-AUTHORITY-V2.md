# Authority-v2 verification contract

## Pre-issuance candidate

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/verify_authority_v2.py
sha256sum -c AUTHORITY-V2-SHA256SUMS
```

The verifier pins policy/schema/authorization/Environment bytes, protected fingerprints and asset receipt, the exact Authority workflow, the sealed independent-review bootstrap workflow/validator hashes, the complete raw-byte checksum manifest and public privacy constraints.

The independent receipt binds the exact repository, base commit/tree, head commit/tree, sole parent, canonical diff SHA-256, complete ordered A/M/D/R path-object manifest, internal manifest, selected artifact hashes, protected-asset redactions and closures F1-F11. Because no documented GitHub release API establishes the exclusive publication transition F12 would need, the receipt carries the strictly separated activation-only decision: `review_outcome="ACTIVATION_ONLY"`, `approved=false`, `release_authorized=false`, closure `F12=false` recorded as an open-closure finding, and the distinct activation authorization, which is `activation_authorized=false` with `activation_findings=[{F8, F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE}]` at every state before `ready` and only becomes `activation_authorized=true` with `activation_findings=[]` once an external post-candidate review has authenticated. Closure `F8=false` is recorded as a second exact open finding (`F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE`) in every contract and receipt producible before the activation state is `ready`: F8 asserts an authenticated source chain, so it may close only once one exact authorized attempt-1 run head, tree, artifact, envelope and receipt digest are deterministically pinned by a later fresh ordinary non-merge direct-child candidate. The exporter, the independent validator and the Authority verifier each reject a closed F8 at any earlier activation state, and each reject an open F8 at `ready`. Activation authorization never implies final Authority approval and authorizes only the exact acc-releaser activation. Every open closure must appear exactly once in `findings`, and `findings_count` must equal their number. The bootstrap acquires it only from the fixed immutable artifact for protected task `t_c298fca4`; no dispatch receipt bytes are accepted. A real Sigstore bundle must authenticate those exact bytes to `chrizzatsu/acc-authority-independent-review/.github/workflows/review-authority-v2.yml@refs/heads/main` and the GitHub Actions OIDC issuer. Authority additionally reads back the independent run and hashes its workflow bytes against the sealed bootstrap. It then derives the live independent bootstrap commit and tree from authenticated canonical GitHub repository, run, job, commit and tree readback for the unique authorized attempt-1 reviewer run, binds the sealed workflow, validator and bootstrap-contract path-to-blob digests at that live head, and confirms the dispatched run and head against them. The sealed pre-live constants stay `null`, so they are never compared against and never become the binding.

Canonical diff bytes are SHA-256 over exact `LC_ALL=C` stdout:

```bash
git diff --binary --full-index --no-ext-diff --no-abbrev --find-renames=50% --src-prefix=a/ --dst-prefix=b/ <base> <head> --
```

## Sealed protected-source and independent-review chain

`protected-source-bootstrap-v2/` and `independent-review-bootstrap-v2/` contain only sealed bytes; neither repository is created, published or dispatched by this candidate. Each bootstrap contract pins the SHA-256 of every workflow, helper and validator byte it ships, and `reviewer-authorization-v2.json` seals both contracts in turn.

`independent-review-bootstrap-v2/bootstrap-contract.json` carries the single `authorized_source_run` object. It is `immutable-contract-pinned`, `caller_selectable: false`, `no_fallback: true`, and binds the source repository, run id and attempt 1, run head, source bootstrap commit and tree, source workflow path/SHA-256, source helper path/SHA-256, artifact name and content digest, envelope and receipt digests, reviewer task, Authority repository/head/tree, independent bootstrap commit and tree, and the certificate GitHub workflow SHA, which must equal the pinned independent bootstrap commit.

The review workflow declares no `workflow_dispatch` inputs. It rehashes its own checked-out workflow and validator, requires `github.sha` to equal the pinned bootstrap commit, reads the authorized run only from the contract, refetches the executed export workflow and helper at the pinned run head and rehashes them, and verifies the artifact, envelope and receipt digests before `cosign sign-blob`. It then requires the certificate GitHub workflow SHA to equal that same commit.

Authority-side, `scripts/verify_authority_v2.py` re-derives the only acceptable chain from the sealed contracts and requires the receipt's `source_execution_chain` plus the recomputed envelope/receipt digests to equal it exactly. Forged source or validator bytes carrying a real workflow identity, a substituted source run, a missing protected-source or independent-review bootstrap, and a certificate workflow-SHA mismatch all fail closed. The sealed contracts ship in `authorized_pending_evidence`: the reviewed repository, workflow, helper and validator blob bindings and exactly `run_attempt=1` are pinned, and every live identifier is derived at runtime from authenticated GitHub server state - the run's own `GITHUB_*` context plus documented authenticated commit projections the workflow writes to constant `authenticated/` paths. Nothing live is pre-pinned, so the sealed bytes execute without first needing evidence only running them can produce. The producer's emitted chain states which run made the bytes, and the authenticated run metadata must agree exactly. A later independently reviewed candidate may pin those identifiers; any sealed value that then contradicts the authenticated state fails closed. An `unavailable` contract still fails closed before any authorization, and the Authority's own issuance chain stays fail-closed until `ready`.

## Authenticated GitHub issuance

The separate releaser supplies exact candidate head/tree/diff, canonical review-receipt SHA-256, exact independent-review run ID, unique 64-hex nonce, tag and release name as attempt-1 dispatch inputs. Receipt and bundle bytes are downloaded, not supplied by the caller, and the protected-source run behind them is never caller-selectable. After independent `attestation` Environment approval, the workflow reads real GitHub REST run/job/approval objects and Actions OIDC claims. `scripts/collect_github_issuance_v2.py` validates closed field sets and strict integer-not-boolean IDs and validates the documented `environments`, `state` and `user` projection from the exact run-scoped approvals endpoint. Deployment/status IDs are deliberately absent; caller-settable `log_url` is irrelevant and rejected as an extra field.

The authenticated object binds:

- candidate head, tree and canonical diff SHA-256;
- independent review receipt SHA-256;
- nonce, immutable tag and release name;
- run id and attempt 1, and job id;
- independent approver, dispatch actor and `attestation` Environment;
- OIDC issuer, `sigstore` audience, subject, repository, workflow ref/SHA, git ref and event.

Every subject includes all of those fields plus the authenticated issuance SHA-256. Receipt authentication and validation, exact candidate/issuance recomputation and all three closed subject validations finish before the first `sign-blob`; signing uses only held verified snapshots. Replay, rerun, copy, cross-candidate and wrong identity reject. If a fixed protected GitHub claim ref already exists it is read only, and must carry canonical state binding nonce/issuance, draft ID, final tag/target/name/body, complete asset name/size/hash plan, plan digest, and immutable-release/ruleset guards.

## Signed-evidence verification

```bash
python3 scripts/verify_authority_v2.py \
  --release-dir /absolute/path/to/evidence \
  --reviewed-activation-sha '<exact-reviewed-40-hex-sha>' \
  --preissuance-review-receipt /absolute/path/to/canonical-reviewer-receipt.json \
  --preissuance-review-receipt-sha256 '<exact-review-receipt-64-hex-sha256>' \
  --github-issuance /absolute/path/to/github-issuance.json \
  --github-issuance-sha256 '<exact-issuance-64-hex-sha256>' \
  --cosign /absolute/path/to/pinned/cosign
```

For each case the verifier requires canonical subject bytes, the exact authenticated issuance, approved Cosign digest/build/platform, exact certificate identity and GitHub claims, one certificate chain and Rekor entry with inclusion proof, trusted `integratedTime`, correct freshness result and raw-byte manifest equality.

## Immutable publication

Publication is unavailable. Administration-read guard GETs and repository reads use unconfusable transports; an ordinary `GITHUB_TOKEN` cannot service the guard role, and the repository transport itself accepts only `GET` with no request body. No reviewed zero-spend guard App currently exists, so its contract is fail-closed `unavailable` with no fallback.

GitHub documents no durable server-owned pre-draft publication state, no atomic/versioned draft-assets-tag publish transition, no exhaustive inventory that excludes every competing writer and no exclusive/compare-and-swap/atomic release transition that binds the exact activation SHA and verified immutable asset snapshots against every authorized writer, so F12 and `release_authorized` stay false. No fallible publication write would therefore be exactly reconstructable. `publication-writer-exclusion-v2.json` accordingly declares `publication_writes_prohibited`, and `scripts/verify_publication_v2.py` contains no draft creation, asset upload, tag creation, durable claim, publish PATCH or delete at all. `PublicationService.publish` verifies the complete plan and then fails closed with zero requests. No unsupported `If-Match` CAS is used.

Documented HTTP 201 on Create a reference is the only creation; HTTP 409, HTTP 422, transport ambiguity and every other non-201 outcome are non-authoritative, so 422 is never unique already-exists proof. `classify_claim_readback` accepts only a nonce/issuance/plan-bearing annotated tag object with the exact tag-object SHA, object type, tag name, message, commit target and request identity; the actual reconciler resolves the claim through it, so direct commit refs, lightweight tags, object substitution, collisions, foreign nonce/issuance/plan and masked or ambiguous reads all reject.

A ref 404 becomes confirmed absence only through `_read_tag_ref_visibility`, a deterministic bounded exhaustive traversal of `/repos/{owner}/{repo}/git/matching-refs/tags/` at `per_page=100`, capped at 100 pages, by the same authenticated credential. Each page must be an authenticated HTTP 200 list whose every entry carries the exact `refs/tags/` prefix, each `rel="next"` target must be the same endpoint at exactly the following page with the same `per_page`, and the traversal must reach the documented last page and record explicit completion. A target that appears only on a later page, a duplicate, unparsable, foreign, non-monotonic or looping `Link` header, a page that fails to read, and a traversal that never terminates inside the bound all yield `readback_ambiguous`, which prohibits every retry and write progression. Every request is a read-only GET.

`PublicationService.reconcile` is read-only, exact and idempotent. It reads the immutable-release and exact-tag-ruleset guards, exhaustively lists releases over the documented paginated endpoint so drafts cannot hide, and resolves exactly one of `unpublished`, `unclaimed_draft`, `claimed_draft` or `published`, binding draft ID, durable claim, final tag, every downloaded asset hash, guards and the plan digest. The state matrix is strict: a mutable draft with a final tag present, or any other inconsistent combination, is rejected as irrecoverable partial state. Two or more releases on the tag, or a claim naming a different draft, reject.

For Environment policy, `protected_branches=true/custom_branch_policies=false` requires the documented deployment-branch-policies HTTP 404 and is never called main-only. An exact custom `main` policy at HTTP 200 is the sole main-only Environment mode. Independently, issuance always rejects any runtime ref other than `refs/heads/main`.

`scripts/verify_github_environment_v2.py` is read-only and opens no network connection, spawns no process and performs no GitHub write. It classifies the Environment read as `authenticated_present` (authenticated HTTP 200), `unauthenticated` (unauthenticated caller, 401 or 403), `masked_or_absent` (404 without proof), `confirmed_absent` or `unknown`. `confirmed_absent` requires far more than one 200 listing: `_is_authenticated_permission_proof` binds the proof to the target read through `_bound_target_request`, so the listing must carry the same `credential_identity` and `repository` as the target request and the target `request_path` must be exactly `/repos/{owner}/{repo}/environments/attestation`. The listing itself must then be a deterministic bounded exhaustive traversal of `/repos/{owner}/{repo}/environments` at `per_page=100`, capped at 100 pages: every page an authenticated HTTP 200 carrying the same credential identity on its exact deterministic page path `?per_page=100&page=N`, page numbers exactly sequential from 1, each `rel="next"` target the same endpoint at exactly the following page with the same `per_page`, every page that advertises a successor itself full, explicit completion reached inside the bound, one consistent `total_count` equal to the number of entries actually observed, no duplicate Environment, at least one Environment seen and the sealed Environment named nowhere. A missing or mismatched auth/request identity, an incomplete or unterminated traversal, a substituted or unadvertised page, a duplicate, unparsable, foreign, non-monotonic or looping `Link` header and inconsistent totals all yield `masked_or_absent`. The next link is parsed with `re` alone, so the module still imports no transport library. Only `authenticated_present` binds the sealed state in `github-environment-v2-contract.json`: HTTP 200, id `20467803126`, required `User` reviewer `chrizzatsu`, `prevent_self_review=true`, `protected_branches=true` and zero Environment secrets. Any live difference fails closed.

## F8 activation authorization and live evidence

`source-chain-activation-v2.json` carries only the *contract* for the external
activation review: `external_activation_review.state` is `unavailable`,
`receipt_sha256` is `null` and the package-level `activation_authorized` is
`false`. No candidate head, tree, trust digest or reviewer receipt digest is
pinned anywhere in the candidate, so the package cannot approve itself.

`scripts/verify_source_chain_activation_v2.py --activation-package ...` verifies
the package. `verify_external_activation_review(bytes, repository_root=...,
base_commit=..., receipt_sha256=...)` authenticates immutable external receipt
bytes produced only after this exact candidate exists. It requires canonical
exact JSON at the given digest, the literal `APPROVED` decision, an integer
(never boolean) zero finding count, `candidate_owned=false`,
`produced_after_candidate=true` and a reviewer repository that is not the
Authority repository, then recomputes every binding from the exact clean
checkout with Git: repository, base commit and tree, head commit and tree, sole
parent, canonical binary full-index diff SHA-256, the complete status-aware
changed-path manifest with modes, object ids and rename semantics, every
tracked path digest, the critical artifact digests and the current
`reviewer-authorization-v2.json` bytes. A dirty checkout, a non-direct-child
head, any mismatched binding, a self-reviewed receipt, or a candidate that
already contains the digest of its own later receipt all fail closed.

F8 is never a caller input, and neither is any capability that could reach it.
`scripts/pin_source_chain_activation_v2.py` exposes exactly one production
entry point, `derive_activation_closure(repository_root=ROOT)`. It accepts no
transport, no trust material, no evidence object, no closure flag and no run
identifier. There is no separate pinning step and no evidence token type to
construct: authentication and pinning are one indivisible operation whose
intermediates are local values, and it returns a pinned package only after
every proof has passed.

The Sigstore trust comes only from the candidate's own bytes: the official
`sigstore/root-signing` `targets/trusted_root.json` is vendored into
`reviewer-authorization-v2.json` and bound to its immutable source repository,
commit `ba3066c420970c13772ba0625f09f1ec97193116`, path and SHA-256
`6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`. The loader
re-derives every Fulcio root and Rekor key from those exact bytes, cross-checks
them against the sealed metadata index, and selects only the roots and the log
key valid at the Rekor integrated time. No runtime trust fetch exists.

The trusted time is bound to the authenticated timeline, not to a completion
instant. `created_at <= run_started_at <= updated_at` on the run and
`started_at <= completed_at` on the expected job must all be present, parsable
and monotonic, the job must have executed inside its own run, and the Rekor
`integratedTime` of both the external activation review bundle and the
protected-source receipt bundle must fall inside
`[max(run_started_at, job started_at), min(updated_at, job completed_at)]`.

Terminal activation state uses a later authority boundary. The inputless
`readback-authority-v2-activation.yml` workflow is triggered only by completion
of `review-authority-v2.yml`, then rejects the initial review dispatch and
accepts only the successful attempt-1 `workflow_run` activation on the exact
default-branch head. It obtains the completed run, exact activation job,
persisted cleanup step, final disabled workflow state and sole non-expired
generated artifact from authenticated GitHub API reads. The only semantic
runtime is the public linux/amd64 `python:3.13.7-slim` image pinned at OCI
manifest digest `sha256:2be5d3cb08aa616c6e38d922bd7072975166b2de772004f79ee1bae59fe983dc`.
The workflow starts `/usr/local/bin/python3 -I -B` by absolute path, fetches
the contract, workflow and verifier bytes at the immutable authenticated
`GITHUB_SHA`, checks their sealed hashes, and executes the verifier's stdlib
collector phase with an intentionally unusable `PATH`; ambient shell, `gh`,
`jq`, Git, archive tools and coreutils have no acceptance authority. The
downloaded archive is selected by canonical server id; its server digest, byte
size, archive SHA-256, closed member digest and exact `activation-record.json`
SHA-256 are recomputed before the collector writes anything signed. The public
Cosign v3.1.3 binary is downloaded from one constant release URL and checked
against its pinned linux/amd64 SHA-256 before every explicit-path execution.
The closed receipt is signed with Cosign v3.1.3 and the terminal verifier pins the collector's
`workflow_run` Fulcio identity, not the activation workflow identity. Its two
members are uploaded separately as
`authority-v2-closed-terminal-readback-t_c298fca4`.
That is the strictest interval that still proves the signature was produced
inside the exact run and job; an integration before the start or after the
successful completion is refused.

The transport is one fixed read-only client the operation instantiates itself,
with two explicit boundaries and no automatic redirect following. The
authenticated boundary is HTTPS to `api.github.com` with certificate
verification and a runtime token that is never logged or persisted. The
authorized runs are selected from exhaustive authenticated listings of the
sealed workflow, so an absent, additional or ambiguous run fails closed.

Immutable artifact bytes cross the second boundary, exactly as GitHub serves
them. `GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip` is read
with the canonical authenticated headers and redirects disabled, and must
answer the one documented redirect - never a direct `200` - carrying
`actions=read` permission provenance, the pinned API version and exactly one
`Location`. That target is validated before anything is dialled: absolute
HTTPS, no user information, port or fragment, a canonical non-traversing path,
a host inside the approved GitHub artifact storage origin class and a signed,
non-repeating query, or the read fails closed. The storage hop then carries no
`Authorization`, no API version and no GitHub header, accepts no further
redirect, requires an `application/zip` `200` from that exact URL and returns
bounded bytes only. Those untrusted bytes are bound back to the authenticated
artifact-list metadata - immutable numeric artifact id, non-expired, exact
name, size and GitHub SHA-256 digest - before the archive inventory and the
artifact, envelope and receipt bytes are recomputed. Unsafe or duplicated
archive member paths are refused.

The decision itself is never authored by this candidate. The candidate carries
only the schema, the binding requirements and the fail-closed verifier. The
independent reviewer writes the concrete decision to
`decisions/<authority head>.json` in its own repository after the exact
candidate exists, and `verify_kanban_review_v2.py --phase external-review`
authenticates those bytes against bindings it recomputes itself before copying
the decision verbatim into the receipt. A missing, malformed, non-canonical,
non-APPROVED, non-zero-finding, candidate-owned, pre-candidate, self-reviewed or
differently bound decision produces no receipt at all.

The decision must also have been delivered, not merely present. `--phase
decision-delivery` composes `authenticated/reviewer-decision-delivery.json`
from read-only GitHub GETs at constant paths, and the external-review phase
authenticates the reviewer writer identity, the exact internally derived
`decisions/<authority head>.json` path, the delivery commit, tree and blob
object name, the protected delivery branch and one independent readback of the
same immutable object before the decision counts at all. In the same way
`--phase server-objects` composes `authenticated/server-objects.json`, and the
external-review phase authenticates the canonical repository id, the exhaustive
terminated run and job paginations with their `rel="next"` Link closure, the
exact head and tree, every required path and blob rehashed from the
authenticated bytes, the canonical artifact id, name and recomputed content
digest and the exact token permission and API-version provenance. Only then may
`write_external_activation_review` run, and it seals the receipt `0444` and
reads the mode back before emitting its digest.

The Authority side has one real derived command line path:

```bash
python3 scripts/pin_source_chain_activation_v2.py --phase closure
```

It reads the sealed live evidence the activation lane drops beside the
Authority checkout in `acc-live-activation-evidence/`, authenticates the
exporter artifact, the external independent-review receipt against the exact
clean checkout and its Sigstore bundle against the pinned trust inside the
authenticated run and job window, derives F8 internally and hands the derived
package straight to the Authority boundary, which re-derives readiness and
binds it. The bound object is sealed `0444` as
`derived-activation-closure.json` and its digest is carried by the runner
state, the release checksum manifest and the final evidence manifest.
Unresolved or null evidence exits non-zero and prints nothing at all.

The Authority issuance lane closes the activation operationally: it downloads the
signed review and external activation review artifacts, confirms each against the
canonical server-returned artifact id and `sha256:` digest, assembles exactly the
sealed `acc-live-activation-evidence` inventory with the authenticated run and job
timeline, and invokes `--phase closure`. Missing, null or unresolved evidence exits
non-zero.

All live server provenance comes from raw `gh api -i` captures. Every status line,
header block, body and requested URL is recorded at a constant path, `rel="next"` is
followed until the server terminates the traversal, the canonical commit tree and
every required blob are fetched by object id and rehashed, and the artifact id and
archive digest are consumed exactly as returned. The external-review phase
recomputes the sealed document from those captures and refuses anything else.

Regenerated evidence is sealed immutable:

```bash
python3 scripts/build_authority_v2.py --emit-runner-state \
  --recovery-round "$ACC_RECOVERY_ROUND" --terminal-state completed \
  --runner-state-dir "$RUNTIME/runner-state"
```

The runner-state artifact derives the exact head, its tree and the reachable
commit count from the immutable checkout, records them beside the recovery
round and terminal state, and the directory is sealed to `0555` with `0444`
files whose modes are read back and whose digests are recomputed after sealing.

The complete final evidence set is sealed last, after every subject, every
Sigstore bundle and `AUTHORITY-V2-RELEASE-SHA256SUMS` exist:

```bash
python3 scripts/build_authority_v2.py --seal-final-evidence "$RUNTIME/dist" \
  --final-evidence-member AUTHORITY-V2-RELEASE-SHA256SUMS ...
```

It writes the post-seal manifest, seals the directory to `0555` with `0444`
files, reads both modes back and recomputes every digest from the sealed
bytes. Sealing earlier and appending a mutable artifact afterwards is refused.

The reviewer lane really produces what this side consumes: after the exact
candidate exists, `verify_kanban_review_v2.py --phase external-review`
recomputes every binding from the authenticated Authority checkout and writes
`external-activation-review-receipt.json` exclusively, and the workflow signs
it, verifies the certificate binds the pinned commit, and uploads
`authority-v2-external-activation-review-t_c298fca4` with the receipt and its
bundle.

The authorization is a derived transition, never a declaration. The shipped
candidate carries `external_activation_review.state = "unavailable"`,
`receipt_sha256 = null` and `activation_authorized = false`. Only
`derive_activation_closure` may set the state to `authenticated`, bind the
verified receipt digest and set `activation_authorized = true`, and only after
every proof above has passed.

### Readiness is derived, never declared

`scripts/verify_source_chain_activation_v2.py` never reads its readiness off a
candidate-owned `ready` flag. `derive_activation_readiness` computes F8, the
activation state and the activation authorization from exactly two independent
evidences: the *authenticated exporter evidence* (`exporter_evidence_state` -
the sealed protected-source bootstrap contract, which may only ever emit
pending evidence and never an authorization, together with the live producer
and reviewed-source bindings that only an executed authenticated exporter run
pins) and the *independent external closure evidence*
(`external_closure_evidence_state` - an authenticated, non-caller-selectable
external activation-review receipt digest). Every declared
`activation_state`, `f8_closed`, `activation_authorized`,
`repositories_created`, `workflows_written`, `runs_observed`,
`live_evidence_pinned` and external review `state` is then checked *against*
that derivation, so a forged flag can only contradict the evidence and fail
closed. `python3 scripts/verify_source_chain_activation_v2.py` reports the two
evidence sources it derived from.

The reachable transition is therefore exporter -> independent validator ->
Authority, and all three are exercised through their real command line entry
points. The independent validator's `external-review` phase resolves and
authenticates the canonical live repository, run, job, head, tree, path, blob
and artifact state, and `require_resolved_live_state` refuses any sealed null
or non-canonical identifier, *before* the external activation review receipt is
written.

Because no repository, run or artifact exists, the derivation cannot run and
`f8_closed` stays `false`.

### Candidate self-authorization

`verify_candidate_self_authorization` enforces exact cross-artifact
consistency: every candidate-owned member listed in
`CANDIDATE_OWNED_FALSE_MEMBERS` - across `authority-v2-policy.json` (both the
pre-issuance receipt contract and `issuance_state_at_candidate_handoff`), both
bootstrap contracts, `publication-writer-exclusion-v2.json` and
`source-chain-activation-v2.json` - must be literally `false` at handoff, and
every candidate-owned closure matrix must keep exactly F8 and F12 open. So at
candidate handoff `approved`, `activation_authorized` and `release_authorized`
are all `false`.

### Sigstore bundles

`scripts/sigstore_bundle_v03.py` is the single canonical parser for real Cosign
v3.1.3 Sigstore protobuf-JSON v0.3 bundles, shared by the live activation
pinning boundary and the Authority release boundary, so the two can never drift
apart.

The official Sigstore bundle format encodes the `VerificationMaterial`
protobuf `oneof content` **directly** as a member of `verificationMaterial`;
protobuf JSON never wraps a oneof in a literal `content` object. The parser
accepts exactly one canonical direct member:

* `verificationMaterial.certificate.rawBytes` - what a raw Cosign v3.1.3
  keyless `sign-blob --bundle` emits, carrying the Fulcio leaf and nothing
  else; or
* `verificationMaterial.x509CertificateChain.certificates[].rawBytes` - the
  leaf first, optionally followed by issuing intermediates.

Both normalise to one leaf plus zero or more *untrusted* intermediates, always
with `messageSignature.messageDigest`/`signature`. Rejected at both boundaries:
a literal nested `content` object, a `certificate` member beside a duplicated
`x509CertificateChain` (the bespoke direct-certificate-plus-chain shape), a
`publicKey` member, no content member at all, and any malformed member.
`tests/fixtures/cosign-v3.1.3-sigstore-v0.3-bundle.json` is the immutable
representative raw-Cosign fixture, in the direct `certificate` form, that both
boundaries are tested against.

The certificate path is validated by the established
`cryptography.x509.verification` RFC 5280 path-validation primitive against the
pinned Fulcio trust at the Rekor integrated time - issuer chaining and
signatures, BasicConstraints, CA `keyCertSign`, path length, maximum chain
depth, every certificate's validity window and any unrecognised critical
extension - plus a pinned end-entity contract (`digitalSignature` key usage,
`codeSigning` extended key usage, non-CA basic constraints, a subject
alternative name) and the exact identity, issuer, workflow SHA, ref and trigger
claims. The trust anchor and the issuing intermediates both come from the
pinned Sigstore trusted root vendored in `reviewer-authorization-v2.json`, so a
bundle is never required to carry a root, and anything a bundle does carry is
treated purely as a further untrusted candidate that can never become an
anchor. If that primitive or its dependency is unavailable the boundary fails
closed with an exact verification error. There is no permissive fallback.

## F12 exclusive publication

`publication-writer-exclusion-v2.json` seals the exact technical impossibility,
the authoritative documented semantics for every create-ref status together
with the explicit statement that none proves exclusivity, and the exhaustive
live authorized-writer proof as unavailable, including each attempted inventory
endpoint and why it is insufficient. `f12_closed` and `release_authorized` stay
`false` and every publication write stays prohibited.


Protected raw values remain private 0700/0600 runtime bytes and are deleted after issuance. No local/self-signed fallback, production/database/customer access, external send or spend is authorized by this repository.
