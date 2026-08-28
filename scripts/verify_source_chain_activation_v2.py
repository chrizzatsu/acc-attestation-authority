#!/usr/bin/env python3
"""Separately reviewable Authority-v2 source-chain activation package verifier.

F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE is closed by review, not by claim.
This module verifies only the activation-only package: it seals every already
reviewed `protected-source-bootstrap-v2` and `independent-review-bootstrap-v2`
byte individually, names the exact target repositories and their zero-spend,
disabled-by-default creation posture, and authorizes no repository creation,
workflow write, dispatch, issuance, signing, release or publication at all.

The package is reviewable before anything is created. While the repositories
and runs are absent it must report `activation_state: "unavailable"` and
`f8_closed: false`; only `scripts/pin_source_chain_activation_v2.py` may ever
bind real live activation evidence, and only for a later separate task.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ACTIVATION_PATH = ROOT / "source-chain-activation-v2.json"
TRUST_RECORD_PATH = "reviewer-authorization-v2.json"
CONTRACT = "acc-authority-v2-source-chain-activation"
FINDING = "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"
AUTHORITY_REPOSITORY = "chrizzatsu/acc-attestation-authority"
SOURCE_REPOSITORY = "chrizzatsu/acc-authority-protected-source"
INDEPENDENT_REPOSITORY = "chrizzatsu/acc-authority-independent-review"
TARGET_REPOSITORIES = tuple(sorted((SOURCE_REPOSITORY, INDEPENDENT_REPOSITORY)))
REPOSITORY_OWNER = "chrizzatsu"
SEALED_BYTE_ROLES = {
    "independent-review-bootstrap-v2/.github/workflows/readback-authority-v2-activation.yml":
        ("independent_activation_terminal_readback_workflow", INDEPENDENT_REPOSITORY),
    "independent-review-bootstrap-v2/.github/workflows/review-authority-v2.yml":
        ("independent_review_workflow", INDEPENDENT_REPOSITORY),
    "independent-review-bootstrap-v2/bootstrap-contract.json":
        ("independent_review_bootstrap_contract", INDEPENDENT_REPOSITORY),
    "independent-review-bootstrap-v2/scripts/verify_kanban_review_v2.py":
        ("independent_review_validator", INDEPENDENT_REPOSITORY),
    "protected-source-bootstrap-v2/.github/workflows/export-kanban-review-v2.yml":
        ("protected_source_workflow", SOURCE_REPOSITORY),
    "protected-source-bootstrap-v2/bootstrap-contract.json":
        ("protected_source_bootstrap_contract", SOURCE_REPOSITORY),
    "protected-source-bootstrap-v2/scripts/export_kanban_review_v2.py":
        ("protected_source_helper", SOURCE_REPOSITORY),
}
SEALED_BYTE_PATHS = tuple(sorted(SEALED_BYTE_ROLES))
SEALED_BYTE_KEYS = ("mutable", "path", "repository", "role", "sha256", "target_path")
AUTHORIZATION_KEYS = (
    "acc_releaser_activation", "authority_merge", "authority_v2_issuance",
    "customer_data_access", "database_access", "external_send",
    "product_access", "publication", "release", "repository_creation",
    "signing", "spend", "workflow_dispatch",
    "workflow_enable_before_authenticated_readback", "workflow_write",
)
# F8-ACTIVATION-AUTHORIZATION-SELF-PROHIBITED: the reviewed package carries an
# immutable pre-activation grant, so these must be true at every state or the
# named acc-releaser activation lane could never act at all.
REQUIRED_ACTIVATION_GRANTS = (
    "acc_releaser_activation", "repository_creation", "workflow_dispatch",
    "workflow_write",
)
# The activation package may never authorize any of these, at any state.
PERMANENTLY_UNAUTHORIZED = (
    "authority_merge", "authority_v2_issuance", "customer_data_access",
    "database_access", "external_send", "product_access", "publication",
    "release", "signing", "spend",
    "workflow_enable_before_authenticated_readback",
)
# `maximum_authorized_activation_attempts == 1` is a declaration; on its own it
# is exactly the defect the review found, because `GITHUB_RUN_ATTEMPT == 1`
# only blocks reruns of one run and never a second `workflow_dispatch` run id.
# The two flags below are the mechanism that makes the bound technical: the
# sealed workflow is disabled before any protected action runs, and additional
# run ids are excluded out of an exhaustively read-back server inventory before
# the lane touches anything protected.
PRE_ACTIVATION_AUTHORIZATION_KEYS = (
    "additional_run_ids_excluded_before_protected_actions",
    "authenticated_readback_required_before_enable",
    "authorized_decision_delivery", "authorized_lane",
    "authorized_run_attempt", "caller_selectable", "cleanup_required",
    "deterministic_later_fresh_direct_child_pinning_required",
    "exact_file_writes", "exact_repository_creation", "immutable",
    "lane_self_authorization_forbidden",
    "maximum_authorized_activation_attempts", "maximum_incremental_spend_eur",
    "reversible", "workflow_disabled_before_protected_actions",
    "workflows_disabled_until_authenticated_readback",
    "zero_spend_required",
)
PRE_ACTIVATION_TRUE_FLAGS = (
    "additional_run_ids_excluded_before_protected_actions",
    "authenticated_readback_required_before_enable", "cleanup_required",
    "deterministic_later_fresh_direct_child_pinning_required", "immutable",
    "lane_self_authorization_forbidden", "reversible",
    "workflow_disabled_before_protected_actions",
    "workflows_disabled_until_authenticated_readback", "zero_spend_required",
)
# The cleanup must really happen and really be read back, on the failure path
# as much as the success path, or the activation lane could leave the sealed
# workflow enabled and a further activation run dispatchable.
CLEANUP_KEYS = (
    "artifact_retention_days", "authenticated_disable_readback_required",
    "delete_runtime_bytes", "delete_temporary_checkouts",
    "disable_covers_failure_paths",
    "expected_workflow_state_after_activation", "no_persisted_raw_values",
    "workflow_disabled_after_activation",
)
CLEANUP_TRUE_FLAGS = (
    "authenticated_disable_readback_required", "delete_runtime_bytes",
    "delete_temporary_checkouts", "disable_covers_failure_paths",
    "no_persisted_raw_values", "workflow_disabled_after_activation",
)
DISABLED_WORKFLOW_STATE = "disabled_manually"
FILE_WRITE_KEYS = ("path", "repository", "sha256", "target_path")
# F8-INDEPENDENT-DECISION-DELIVERY-UNREACHABLE
#
# The immutable grant must reach the one sealed post-candidate path the
# independent reviewer really owns, so the decision this candidate can never
# author has somewhere authenticated to arrive.
DECISION_DELIVERY_PATH_TEMPLATE = "decisions/{authority_head_commit}.json"
DECISION_DELIVERY_BRANCH = "main"
DECISION_WRITER_LOGIN = "chrizzatsu"
DECISION_DELIVERY_KEYS = (
    "authenticated_readback_required", "branch", "branch_protection_required",
    "candidate_authored_decision_forbidden", "derived_path_only",
    "path_template", "produced_after_exact_candidate_required",
    "repository", "writer_login",
)
DECISION_DELIVERY_TRUE_FLAGS = (
    "authenticated_readback_required", "branch_protection_required",
    "candidate_authored_decision_forbidden", "derived_path_only",
    "produced_after_exact_candidate_required",
)
# The receipt must carry the authenticated delivery and canonical server
# objects it really depended on, never only a decision.
RECEIPT_DELIVERY_KEYS = (
    "blob_introduced_by_commit", "blob_sha", "branch", "branch_protected",
    "branch_protection_permission", "cas_capability_probe",
    "cas_capability_proven", "cas_expected_old_oid", "cas_primitive",
    "cas_ref", "commit_parent", "commit_sha", "commit_tree", "path",
    "race_readback_verified", "readback_verified", "repository",
    "repository_id", "writer_id", "writer_login",
)
DECISION_DELIVERY_CAS_PRIMITIVE = "git-receive-pack-expected-old-oid"
DECISION_DELIVERY_CAS_PROBE = "stale-lease-refused-and-honest-lease-applied"
DECISION_ADMINISTRATION_READ = "administration=read"
RECEIPT_SERVER_OBJECT_KEYS = (
    "artifact_content_sha256", "artifact_digest", "artifact_id",
    "artifact_name", "head_commit", "head_tree", "job_ids", "repository",
    "repository_id", "run_id", "tree_paths",
)
ARTIFACT_DIGEST_PREFIX = "sha256:"
MINIMUM_CANONICAL_ID = 1_000_000
MAXIMUM_CANONICAL_ID = 2 ** 63 - 1
MINIMUM_ID_ENTROPY = 4
AUTHORIZED_ACTIVATION_LANE = "acc-releaser"
POST_ACTIVATION_PROOF_KEYS = (
    "f8_true_requires_live_evidence", "live_evidence_pinned",
    "pinning_candidate_topology", "pinning_helper", "required_live_fields",
)
PINNING_HELPER_PATH = "scripts/pin_source_chain_activation_v2.py"
PINNING_CANDIDATE_TOPOLOGY = "fresh-ordinary-non-merge-direct-child"
TARGET_REPOSITORY_KEYS = (
    "admin_bypass_allowed", "branch_protection", "created", "default_branch",
    "default_branch_ref", "github_hosted_standard_runner_only",
    "maximum_incremental_spend_eur", "private", "repository_id",
    "repository_node_id", "visibility", "workflow_dispatch_authorized",
    "workflow_path", "workflow_state_on_creation", "workflows_enabled",
    "zero_spend_required",
)
BRANCH_PROTECTION = {
    "admin_bypass": False,
    "allow_deletions": False,
    "allow_force_pushes": False,
    "bypass_actors": [],
    "enforcement": "active",
    "ref_include": ["refs/heads/main"],
    "required_linear_history": True,
}
TARGET_WORKFLOW_PATHS = {
    SOURCE_REPOSITORY: ".github/workflows/export-kanban-review-v2.yml",
    INDEPENDENT_REPOSITORY: ".github/workflows/review-authority-v2.yml",
}
DISPATCH_KEYS = (
    "caller_selectable", "no_fallback", "ref", "repository", "run_attempt",
    "run_id", "selector", "trigger", "workflow_path",
)
PRODUCER_UNPINNED_FIELDS = (
    "artifact_content_sha256", "certificate_github_workflow_sha",
    "envelope_sha256", "review_receipt_sha256", "sigstore_bundle_sha256",
)
PRODUCER_KEYS = (
    "artifact_content_digest_algorithm", "artifact_content_sha256",
    "artifact_files", "artifact_name", "certificate_github_workflow_sha",
    "envelope_sha256", "immutable_actions_artifact_required",
    "review_receipt_sha256", "signed_artifact_files", "signed_artifact_name",
    "sigstore_bundle_required", "sigstore_bundle_sha256", "sigstore_identity",
    "sigstore_issuer",
)
REVIEWED_SOURCE_UNPINNED_FIELDS = (
    "authority_head_commit", "authority_head_tree",
    "independent_bootstrap_commit", "independent_bootstrap_tree",
    "source_bootstrap_commit", "source_bootstrap_tree",
)
REVIEWED_SOURCE_KEYS = tuple(sorted(
    (*REVIEWED_SOURCE_UNPINNED_FIELDS, "authority_repository", "trust_record")
))
READBACK_FIELDS = (
    "artifact_content_sha256", "certificate_github_workflow_sha",
    "envelope_sha256", "independent_bootstrap_commit",
    "independent_bootstrap_tree", "repository_id", "review_receipt_sha256",
    "run_attempt", "run_head_sha", "run_head_tree", "run_id",
    "source_bootstrap_commit", "source_bootstrap_tree",
)
# ---------------------------------------------------------------------------
# F8-EXACT-CANDIDATE-REVIEW-BINDING-STALE
#
# The candidate may define the receipt contract, but it may never contain its
# own approval, pin a sibling candidate's head/tree/trust constants, or
# precompute the digest of a receipt that can only exist afterwards. The
# activation authorization is therefore an *input*: immutable external
# independent-review receipt bytes, produced only after this exact candidate
# exists, verified byte for byte against the exact clean checkout.
# ---------------------------------------------------------------------------
EXTERNAL_REVIEW_RECEIPT_TYPE = (
    "acc-authority-v2-external-independent-activation-review"
)
EXTERNAL_REVIEW_DECISION = "APPROVED"
EXTERNAL_REVIEW_PROFILE = "acc-reviewer"
EXTERNAL_REVIEW_BINDING_KEYS = (
    "base_commit", "base_tree", "candidate_diff_sha256",
    "canonical_diff_sha256",
    "changed_path_manifest", "critical_artifact_sha256", "head_commit",
    "head_tree", "repository", "reviewer_authorization_path",
    "reviewer_authorization_sha256", "sole_parent", "tracked_paths_sha256",
)
EXTERNAL_REVIEW_DECISION_KEYS = (
    "activation_authorized", "candidate_owned", "decision", "decision_delivery",
    "findings", "findings_count", "produced_after_candidate", "receipt_type",
    "reviewer_profile", "reviewer_repository", "schema_version",
    "server_objects",
)
EXTERNAL_REVIEW_RECEIPT_KEYS = tuple(sorted(
    (*EXTERNAL_REVIEW_BINDING_KEYS, *EXTERNAL_REVIEW_DECISION_KEYS)
))
EXTERNAL_REVIEW_CONTRACT_KEYS = tuple(sorted((
    "artifact_files", "artifact_name",
    "candidate_authored_decision_forbidden",
    "candidate_owned_approval_forbidden",
    "decision_source",
    "circular_receipt_precomputation_forbidden",
    "produced_after_exact_candidate_required", "receipt_sha256",
    "receipt_type", "repository", "required_bindings", "required_decision",
    "required_findings_count", "required_reviewer_profile",
    "self_review_forbidden", "sigstore_bundle_required", "state",
    "verified_against_exact_checkout", "workflow_path",
)))
EXTERNAL_REVIEW_RECEIPT_MEMBER = "external-activation-review-receipt.json"
EXTERNAL_REVIEW_BUNDLE_MEMBER = "external-activation-review-receipt.sigstore.json"
EXTERNAL_REVIEW_UNAVAILABLE = "unavailable"
EXTERNAL_REVIEW_AUTHENTICATED = "authenticated"
EXTERNAL_REVIEW_STATES = (EXTERNAL_REVIEW_AUTHENTICATED, EXTERNAL_REVIEW_UNAVAILABLE)
# Only these two members move when an external review really authenticates;
# everything else in the contract is immutable across the transition.
EXTERNAL_REVIEW_TRANSITION_KEYS = ("receipt_sha256", "state")
CRITICAL_ARTIFACT_PATHS = (
    "AUTHORITY-V2-SHA256SUMS",
    "authority-v2-policy.json",
    "protected-asset-receipt-v2.json",
    "reviewer-authorization-v2.json",
    "schemas/authority-v2-subject.schema.json",
)
MANIFEST_ENTRY_KEYS = (
    "new_blob_oid", "new_mode", "new_path", "new_sha256", "old_blob_oid",
    "old_mode", "old_path", "old_sha256", "similarity", "status",
)
PACKAGE_KEYS = (
    "activation_authorized", "activation_state",
    "authorized_dispatch", "authorizes", "cleanup",
    "contract", "external_activation_review", "f8_closed", "finding",
    "generated_activation_evidence",
    "independent_activation_authorization_required",
    "independently_reviewable_before_repository_creation",
    "independently_reviewable_before_workflow_write", "no_fallback",
    "post_activation_proof", "pre_activation_authorization",
    "producer_bindings", "readback", "repositories_created", "reviewed_source",
    "runs_observed", "schema_version", "sealed_bytes",
    "supports_later_separate_acc_releaser_activation_task_only",
    "target_repositories", "terminal_readback", "unavailable_reason",
    "workflows_written",
)
ACTIVATION_STATES = ("ready", "unavailable")
TERMINAL_READBACK_KEYS = (
    "activation_artifact_files", "activation_artifact_name", "activation_job_name",
    "activation_record_digest_required", "activation_workflow_path",
    "artifact_archive_digest_recomputed", "artifact_content_digest_algorithm",
    "artifact_content_digest_recomputed", "artifact_exactly_one_non_expired",
    "caller_inputs", "cleanup_step_name", "closed_receipt_required",
    "collector_artifact_files", "collector_artifact_name",
    "collector_identity", "collector_job_name", "collector_verifier",
    "collector_workflow_path", "collector_workflow_sha256", "default_branch",
    "default_branch_ref", "exact_cosign_version", "fresh_provenance", "issuer",
    "no_repository_or_content_mutation",
    "permissions", "receipt_type", "recursion_forbidden", "repository",
    "run_attempt", "terminal_api_readback_required", "trigger",
    "trigger_workflow_name",
)
TERMINAL_COLLECTOR_PATH = (
    ".github/workflows/readback-authority-v2-activation.yml"
)
TERMINAL_COLLECTOR_SOURCE_PATH = (
    "independent-review-bootstrap-v2/" + TERMINAL_COLLECTOR_PATH
)
TERMINAL_COLLECTOR_IDENTITY = (
    f"https://github.com/{INDEPENDENT_REPOSITORY}/"
    f"{TERMINAL_COLLECTOR_PATH}@refs/heads/main"
)
TERMINAL_RECEIPT_TYPE = "acc-authority-v2-terminal-activation-readback"
TERMINAL_RUNTIME_DIGEST = (
    "sha256:2be5d3cb08aa616c6e38d922bd7072975166b2de772004f79ee1bae59fe983dc"
)
TERMINAL_RUNTIME_IMAGE = (
    "docker.io/library/python:3.13.7-slim@"
    + TERMINAL_RUNTIME_DIGEST
)
TERMINAL_RUNTIME_PATH = "/usr/local/bin"
TERMINAL_RUNTIME_EXECUTABLE = f"{TERMINAL_RUNTIME_PATH}/python3"
TERMINAL_RUNTIME_EXECUTABLES = ("python3",)
TERMINAL_COSIGN_DIGEST = (
    "sha256:4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
)
TERMINAL_COLLECTOR_MODE = (
    "digest-pinned-python-stdlib-no-authority-checkout"
)
TERMINAL_ARTIFACT_NAME = (
    "authority-v2-closed-terminal-readback-t_c298fca4"
)
GENERATED_ACTIVATION_ARTIFACT_NAME = (
    "authority-v2-generated-activation-evidence-t_c298fca4"
)
GENERATED_ACTIVATION_ARTIFACT_FILES = (
    "activation-record.json", "activation-subject.json",
    "canonical-binary-full-index.diff",
    "external-review/external-activation-review-receipt.json",
    "external-review/external-activation-review-receipt.sigstore.json",
    "generated-activation-evidence.sigstore.json",
    "name-status-find-renames-50.z", "raw-full-index-find-renames-50.z",
    "raw-provenance.json", "raw-status-authoritative.z",
    "raw/activation-jobs.json", "raw/activation-run.json",
    "raw/activation-runs.json", "raw/decision-commit.json",
    "raw/external-review-artifact.zip", "raw/review-artifacts.json",
    "raw/review-jobs.json", "raw/review-run.json",
    "raw/signed-review-artifact.zip", "raw/workflow-run-event.json",
    "raw/workflow-state-after.json", "raw/workflow-state-before.json",
    "raw/workflow-state-cleanup.json",
    "signed-review/kanban-review-envelope.json",
    "signed-review/preissuance-review-receipt.json",
    "signed-review/preissuance-review-receipt.sigstore.json",
)
GENERATED_ACTIVATION_JOB_NAME = "generated-activation-evidence"
ACTIVATION_CLEANUP_STEP_NAME = (
    "Reassert disabled state and delete ephemeral bytes"
)
GENERATED_ARTIFACT_CONTENT_DIGEST_ALGORITHM = (
    "sha256(acc-authority-v2-generated-activation-artifact\\0 || "
    "sorted(uint64be(len(name))||name||uint64be(len(bytes))||bytes))"
)
# ---------------------------------------------------------------------------
# F8-ACTIVATION-EVIDENCE-NOT-GENERATOR-BOUND
#
# The one activation this package may ever authorize is the *generation* of
# the Sigstore evidence that is missing, so the contract it carries binds the
# generator itself rather than a bundle shape: exact Cosign v3.1.3, through
# the Ed25519 / Rekor-v2 / RFC 3161 route, with the generator binary and the
# candidate identity bound to the exact output bytes. A "compatible",
# relabelled or static provenance satisfies none of it.
#
# Nothing here is an approval. Only a separately authorized releaser may
# perform that one reversible, zero-spend activation, only after an
# independent zero-finding activation review it does not author, and the
# generated bytes must then have a fresh independent review of their own
# before anything is approved. So the evidence state is `unavailable` and the
# authorization flags stay false.
# ---------------------------------------------------------------------------
GENERATED_EVIDENCE_KEYS = (
    "artifact_files", "authorized_lane", "builder_output_is_never_approval",
    "candidate_identity_binding_required", "evidence_state",
    "fabrication_prohibited", "generator", "generator_binary_digest_required",
    "generator_version",
    "independent_zero_finding_activation_review_required",
    "maximum_authorized_activation_attempts",
    "post_activation_independent_review_required", "rejected_evidence",
    "rekor_generation", "rekor_log_key_algorithm", "relabelling_prohibited",
    "reversible", "route",
    "self_authorization_forbidden", "signer_signature_algorithm",
    "substitution_prohibited", "timestamp", "zero_spend_required",
)
GENERATED_EVIDENCE_TRUE_FLAGS = (
    "builder_output_is_never_approval",
    "candidate_identity_binding_required", "fabrication_prohibited",
    "generator_binary_digest_required",
    "independent_zero_finding_activation_review_required",
    "post_activation_independent_review_required", "relabelling_prohibited",
    "reversible", "self_authorization_forbidden", "substitution_prohibited",
    "zero_spend_required",
)
GENERATED_EVIDENCE_EXACT = {
    "authorized_lane": "acc-releaser",
    "evidence_state": "unavailable",
    "generator": "cosign v3.1.3",
    "generator_version": "v3.1.3",
    "rekor_generation": "rekor-v2",
    # "ed25519" in the route name is the Rekor v2 transparency *log* key. The
    # signer is a Fulcio workload key on P-256, which is what the pinned
    # generator can actually produce and what the genuine in-repo Rekor-v2
    # vector really is.
    "rekor_log_key_algorithm": "PKIX_ED25519",
    "route": "cosign-v3.1.3-ed25519-rekor-v2-rfc3161",
    "signer_signature_algorithm": "ecdsa-p256-sha256",
    "timestamp": "rfc3161",
}
GENERATED_EVIDENCE_REJECTED = (
    "absent-evidence",
    "cosign-v3.1.3-ecdsa-hashedrekord-rekor-v1",
    "relabelled-provenance",
    "sigstore-java-conformance-vector",
    "static-or-compatible-provenance",
    "wrong-generator-version",
    "wrong-rekor-generation",
    "wrong-rekor-log-key-algorithm",
    "wrong-rfc3161-evidence",
    "wrong-signer-signature-algorithm",
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise SystemExit(message)


MANIFEST_NAME = "AUTHORITY-V2-SHA256SUMS"


def manifest_digest(repository_root, relative):
    """The digest the candidate's own sealed manifest pins for one path.

    The whole manifest is re-verified against the checkout first, so a single
    rewritten entry can never pass on its own.
    """
    manifest_path = Path(repository_root) / MANIFEST_NAME
    require(
        manifest_path.is_file() and not manifest_path.is_symlink(),
        "the candidate sealed manifest is absent or unsafe",
    )
    entries = {}
    for line in manifest_path.read_bytes().decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        require(match is not None, "the candidate sealed manifest is malformed")
        require(
            match.group(2) not in entries,
            "the candidate sealed manifest repeats a path",
        )
        entries[match.group(2)] = match.group(1)
    require(entries, "the candidate sealed manifest is empty")
    require(
        relative in entries,
        f"the candidate sealed manifest does not cover {relative}",
    )
    covered = Path(repository_root) / relative
    require(
        covered.is_file() and not covered.is_symlink(),
        f"the candidate sealed manifest covers an absent path: {relative}",
    )
    require(
        hashlib.sha256(covered.read_bytes()).hexdigest() == entries[relative],
        f"the candidate sealed manifest does not match the checkout: {relative}",
    )
    # The manifest itself is pinned by the Authority verifier against its own
    # sealed constant, so a candidate that rewrote both a file and its entry
    # is simply a different candidate and is rejected there.
    return entries[relative]


def _closed_json(data, label):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(
                type(key) is str and key not in result,
                f"{label} has a duplicate or non-string member",
            )
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit(f"{label} is not valid UTF-8 JSON") from error


def canonical_bytes(payload):
    """The single accepted on-disk encoding for the activation package."""
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _exact_keys(payload, keys, label):
    require(type(payload) is dict, f"{label} is malformed")
    require(tuple(sorted(payload)) == tuple(keys), f"{label} field set mismatch")
    return payload


def _bool(payload, field, expected, label):
    observed = payload.get(field)
    require(type(observed) is bool, f"{label} {field} is not a boolean")
    require(observed is expected, f"{label} {field} must be {expected}")


def _unpinned_or_hex(payload, field, pattern, activation_state, label):
    observed = payload.get(field)
    if activation_state == "unavailable":
        require(observed is None, f"{label} {field} must stay unpinned while inactive")
        return
    require(
        type(observed) is str and pattern.fullmatch(observed) is not None,
        f"{label} {field} is not an exact pinned digest",
    )


def _verify_sealed_bytes(package, root):
    sealed = package["sealed_bytes"]
    require(type(sealed) is list, "sealed byte inventory is malformed")
    observed_paths = []
    for entry in sealed:
        _exact_keys(entry, SEALED_BYTE_KEYS, "sealed byte entry")
        path = entry["path"]
        require(path in SEALED_BYTE_ROLES, f"unsealed bootstrap path: {path}")
        require(path not in observed_paths, f"duplicate sealed bootstrap path: {path}")
        observed_paths.append(path)
        role, repository = SEALED_BYTE_ROLES[path]
        require(entry["role"] == role, f"sealed byte role mismatch: {path}")
        require(entry["repository"] == repository, f"sealed byte repository mismatch: {path}")
        require(
            entry["target_path"] == path.split("/", 1)[1],
            f"sealed byte target path mismatch: {path}",
        )
        _bool(entry, "mutable", False, f"sealed byte {path}")
        digest = entry["sha256"]
        require(
            type(digest) is str and HEX64.fullmatch(digest) is not None,
            f"sealed byte digest is malformed: {path}",
        )
        file_path = Path(root) / path
        require(
            file_path.is_file() and not file_path.is_symlink(),
            f"sealed bootstrap byte is absent or unsafe: {path}",
        )
        require(
            hashlib.sha256(file_path.read_bytes()).hexdigest() == digest,
            f"sealed bootstrap byte changed: {path}",
        )
    require(tuple(observed_paths) == SEALED_BYTE_PATHS, "sealed byte inventory is incomplete")
    return {entry["path"]: entry["sha256"] for entry in sealed}


def _verify_trust_record(package, root, sealed):
    reviewed = _exact_keys(
        package["reviewed_source"], REVIEWED_SOURCE_KEYS, "reviewed source",
    )
    require(
        reviewed["authority_repository"] == AUTHORITY_REPOSITORY,
        "reviewed source authority repository mismatch",
    )
    record = _exact_keys(reviewed["trust_record"], ("path", "sha256"), "trust record")
    require(record["path"] == TRUST_RECORD_PATH, "trust record path mismatch")
    record_path = Path(root) / TRUST_RECORD_PATH
    require(
        record_path.is_file() and not record_path.is_symlink(),
        "trust record is absent or unsafe",
    )
    record_bytes = record_path.read_bytes()
    require(
        hashlib.sha256(record_bytes).hexdigest() == record["sha256"],
        "trust record digest mismatch",
    )
    trust = _closed_json(record_bytes, "trust record")
    require(type(trust) is dict, "trust record is malformed")
    independent = trust.get("bootstrap")
    protected = trust.get("protected_source_bootstrap")
    require(type(independent) is dict and type(protected) is dict, "trust record bootstrap members are absent")
    require(
        sealed["independent-review-bootstrap-v2/bootstrap-contract.json"]
        == independent.get("contract_sha256")
        and sealed[TERMINAL_COLLECTOR_SOURCE_PATH]
        == independent.get("collector_workflow_sha256")
        and sealed["independent-review-bootstrap-v2/.github/workflows/review-authority-v2.yml"]
        == independent.get("workflow_sha256")
        and sealed["independent-review-bootstrap-v2/scripts/verify_kanban_review_v2.py"]
        == independent.get("validator_sha256")
        and sealed["protected-source-bootstrap-v2/bootstrap-contract.json"]
        == protected.get("contract_sha256")
        and sealed["protected-source-bootstrap-v2/.github/workflows/export-kanban-review-v2.yml"]
        == protected.get("workflow_sha256")
        and sealed["protected-source-bootstrap-v2/scripts/export_kanban_review_v2.py"]
        == protected.get("helper_sha256"),
        "activation package does not seal the exact reviewed bootstrap bytes",
    )
    return reviewed


def _verify_target_repositories(package, activation_state):
    targets = package["target_repositories"]
    _exact_keys(targets, TARGET_REPOSITORIES, "target repository set")
    for name, target in targets.items():
        label = f"target repository {name}"
        _exact_keys(target, TARGET_REPOSITORY_KEYS, label)
        require(name.split("/")[0] == REPOSITORY_OWNER, f"{label} owner mismatch")
        require(target["visibility"] == "public", f"{label} visibility mismatch")
        _bool(target, "private", False, label)
        require(target["default_branch"] == "main", f"{label} default branch mismatch")
        require(
            target["default_branch_ref"] == "refs/heads/main",
            f"{label} default branch ref mismatch",
        )
        require(
            target["maximum_incremental_spend_eur"] == "0.00",
            f"{label} spend posture mismatch",
        )
        _bool(target, "zero_spend_required", True, label)
        _bool(target, "github_hosted_standard_runner_only", True, label)
        _bool(target, "admin_bypass_allowed", False, label)
        _bool(target, "workflows_enabled", False, label)
        _bool(target, "workflow_dispatch_authorized", False, label)
        require(
            target["workflow_state_on_creation"] == "disabled_manually",
            f"{label} workflow posture is not disabled by default",
        )
        require(
            target["workflow_path"] == TARGET_WORKFLOW_PATHS[name],
            f"{label} workflow path mismatch",
        )
        require(
            target["branch_protection"] == BRANCH_PROTECTION,
            f"{label} branch protection mismatch",
        )
        if activation_state == "unavailable":
            _bool(target, "created", False, label)
            require(
                target["repository_id"] is None
                and target["repository_node_id"] is None,
                f"{label} claims a live id while no repository exists",
            )
        else:
            _bool(target, "created", True, label)
            require(
                type(target["repository_id"]) is int
                and type(target["repository_id"]) is not bool
                and target["repository_id"] > 0
                and type(target["repository_node_id"]) is str
                and target["repository_node_id"] != "",
                f"{label} is missing a live immutable repository id",
            )


def _verify_dispatch(package, activation_state):
    dispatch = _exact_keys(
        package["authorized_dispatch"], DISPATCH_KEYS, "authorized dispatch",
    )
    _bool(dispatch, "caller_selectable", False, "authorized dispatch")
    _bool(dispatch, "no_fallback", True, "authorized dispatch")
    require(
        dispatch["selector"] == "immutable-contract-pinned",
        "authorized dispatch selector must not be caller selectable",
    )
    require(dispatch["ref"] == "refs/heads/main", "authorized dispatch ref mismatch")
    require(
        dispatch["trigger"] == "workflow_dispatch",
        "authorized dispatch trigger mismatch",
    )
    require(
        dispatch["repository"] == SOURCE_REPOSITORY
        and dispatch["workflow_path"] == TARGET_WORKFLOW_PATHS[SOURCE_REPOSITORY],
        "authorized dispatch workflow identity mismatch",
    )
    require(
        type(dispatch["run_attempt"]) is int
        and type(dispatch["run_attempt"]) is not bool
        and dispatch["run_attempt"] == 1,
        "authorized dispatch must pin attempt 1",
    )
    if activation_state == "unavailable":
        require(dispatch["run_id"] is None, "authorized dispatch claims a run that does not exist")
    else:
        require(
            type(dispatch["run_id"]) is int
            and type(dispatch["run_id"]) is not bool
            and dispatch["run_id"] > 0,
            "authorized dispatch is missing a live run id",
        )


def _verify_producer(package, activation_state):
    producer = _exact_keys(
        package["producer_bindings"], PRODUCER_KEYS, "producer bindings",
    )
    require(
        producer["artifact_name"] == "authority-v2-review-t_c298fca4"
        and producer["artifact_files"] == [
            "kanban-review-envelope.json", "preissuance-review-receipt.json",
        ]
        and producer["signed_artifact_name"] == "authority-v2-signed-review-t_c298fca4"
        and producer["signed_artifact_files"] == [
            "kanban-review-envelope.json",
            "preissuance-review-receipt.json",
            "preissuance-review-receipt.sigstore.json",
        ],
        "producer artifact binding mismatch",
    )
    _bool(producer, "immutable_actions_artifact_required", True, "producer bindings")
    _bool(producer, "sigstore_bundle_required", True, "producer bindings")
    require(
        producer["sigstore_identity"]
        == "https://github.com/chrizzatsu/acc-authority-independent-review/"
           ".github/workflows/review-authority-v2.yml@refs/heads/main"
        and producer["sigstore_issuer"] == "https://token.actions.githubusercontent.com",
        "producer Sigstore identity mismatch",
    )
    require(
        "sha256(acc-authority-v2-protected-source-artifact"
        in producer["artifact_content_digest_algorithm"],
        "producer artifact digest algorithm mismatch",
    )
    for field in PRODUCER_UNPINNED_FIELDS:
        pattern = HEX40 if field == "certificate_github_workflow_sha" else HEX64
        _unpinned_or_hex(producer, field, pattern, activation_state, "producer bindings")


def _verify_pre_activation_authorization(package, sealed):
    """The immutable grant: exactly this lane, these repositories, these bytes."""
    grant = _exact_keys(
        package["pre_activation_authorization"],
        PRE_ACTIVATION_AUTHORIZATION_KEYS,
        "pre-activation authorization",
    )
    label = "pre-activation authorization"
    require(
        grant["authorized_lane"] == AUTHORIZED_ACTIVATION_LANE,
        f"{label} names a lane other than {AUTHORIZED_ACTIVATION_LANE}",
    )
    for flag in PRE_ACTIVATION_TRUE_FLAGS:
        _bool(grant, flag, True, label)
    _bool(grant, "caller_selectable", False, label)
    require(
        type(grant["maximum_authorized_activation_attempts"]) is int
        and type(grant["maximum_authorized_activation_attempts"]) is not bool
        and grant["maximum_authorized_activation_attempts"] == 1,
        f"{label} must authorize at most one activation attempt",
    )
    require(
        type(grant["authorized_run_attempt"]) is int
        and type(grant["authorized_run_attempt"]) is not bool
        and grant["authorized_run_attempt"] == 1,
        f"{label} must pin attempt 1",
    )
    require(
        grant["maximum_incremental_spend_eur"] == "0.00",
        f"{label} spend posture mismatch",
    )
    require(
        grant["exact_repository_creation"] == sorted(TARGET_REPOSITORIES),
        f"{label} may create only the two exact named repositories",
    )
    _verify_authorized_decision_delivery(grant["authorized_decision_delivery"])
    writes = grant["exact_file_writes"]
    require(type(writes) is list, f"{label} file-write inventory is malformed")
    require(
        len(writes) == len(SEALED_BYTE_PATHS),
        f"{label} must write exactly the sealed bootstrap files",
    )
    observed = []
    for entry in writes:
        _exact_keys(entry, FILE_WRITE_KEYS, f"{label} file write")
        path = entry["path"]
        require(path in SEALED_BYTE_ROLES, f"{label} writes an unsealed path: {path}")
        require(path not in observed, f"{label} duplicates a write path: {path}")
        observed.append(path)
        role, repository = SEALED_BYTE_ROLES[path]
        require(entry["repository"] == repository, f"{label} repository mismatch: {path}")
        require(
            entry["target_path"] == path.split("/", 1)[1],
            f"{label} target path mismatch: {path}",
        )
        require(
            entry["sha256"] == sealed[path],
            f"{label} writes bytes that are not the sealed bytes: {path}",
        )
    require(
        tuple(observed) == SEALED_BYTE_PATHS,
        f"{label} file-write inventory is incomplete",
    )


def _canonical_identifier(value, label):
    """A real GitHub object id, never a small, round or caller-shaped number."""
    require(
        type(value) is int and type(value) is not bool
        and MINIMUM_CANONICAL_ID <= value <= MAXIMUM_CANONICAL_ID,
        f"{label} is not a canonical GitHub identifier",
    )
    require(
        len(set(str(value))) >= MINIMUM_ID_ENTROPY,
        f"{label} is a caller-shaped identifier",
    )
    return value


def _verify_authorized_decision_delivery(delivery):
    """The one sealed post-candidate path the independent reviewer owns."""
    label = "authorized reviewer decision delivery"
    _exact_keys(delivery, DECISION_DELIVERY_KEYS, label)
    require(
        delivery["path_template"] == DECISION_DELIVERY_PATH_TEMPLATE,
        f"{label} path template mismatch",
    )
    require(
        delivery["repository"] == INDEPENDENT_REPOSITORY
        and delivery["repository"] != AUTHORITY_REPOSITORY,
        f"{label} is not the independent reviewer's own repository",
    )
    require(
        delivery["branch"] == DECISION_DELIVERY_BRANCH,
        f"{label} delivery branch mismatch",
    )
    require(
        delivery["writer_login"] == DECISION_WRITER_LOGIN,
        f"{label} names no authorized reviewer writer identity",
    )
    for flag in DECISION_DELIVERY_TRUE_FLAGS:
        _bool(delivery, flag, True, label)
    return delivery


def _verify_receipt_decision_delivery(receipt, head_commit):
    """The receipt must bind the authenticated delivery, not just a decision."""
    label = "external review decision delivery"
    delivery = _exact_keys(receipt["decision_delivery"], RECEIPT_DELIVERY_KEYS, label)
    require(
        delivery["path"]
        == DECISION_DELIVERY_PATH_TEMPLATE.format(
            authority_head_commit=head_commit,
        ),
        f"{label} path is not the internally derived decision path",
    )
    require(
        delivery["repository"] == INDEPENDENT_REPOSITORY
        and delivery["repository"] != AUTHORITY_REPOSITORY,
        f"{label} is not the independent reviewer's own repository",
    )
    require(
        delivery["branch"] == DECISION_DELIVERY_BRANCH,
        f"{label} delivery branch mismatch",
    )
    require(
        delivery["writer_login"] == DECISION_WRITER_LOGIN,
        f"{label} writer identity mismatch",
    )
    _canonical_identifier(delivery["writer_id"], f"{label} writer id")
    _canonical_identifier(delivery["repository_id"], f"{label} repository id")
    for field in (
        "blob_introduced_by_commit", "branch_protected",
        "cas_capability_proven", "race_readback_verified",
        "readback_verified",
    ):
        _bool(delivery, field, True, label)
    require(
        delivery["branch_protection_permission"] == DECISION_ADMINISTRATION_READ,
        f"{label} branch protection carries no administration-read provenance",
    )
    for field in ("blob_sha", "commit_parent", "commit_sha", "commit_tree"):
        require(
            type(delivery[field]) is str
            and HEX40.fullmatch(delivery[field]) is not None,
            f"{label} {field} is not a canonical object name",
        )
    require(
        delivery["cas_expected_old_oid"] == delivery["commit_parent"]
        and delivery["cas_ref"] == "refs/heads/main"
        and delivery["cas_primitive"] == DECISION_DELIVERY_CAS_PRIMITIVE
        and delivery["cas_capability_probe"] == DECISION_DELIVERY_CAS_PROBE,
        f"{label} does not bind the expected-old-OID CAS and race readback",
    )
    return delivery


def _verify_receipt_server_objects(receipt):
    """The receipt must bind the canonical server objects it depended on."""
    label = "external review server objects"
    server = _exact_keys(
        receipt["server_objects"], RECEIPT_SERVER_OBJECT_KEYS, label,
    )
    require(
        server["repository"] == SOURCE_REPOSITORY
        and server["repository"] != AUTHORITY_REPOSITORY,
        f"{label} repository is not the protected source repository",
    )
    _canonical_identifier(server["repository_id"], f"{label} repository id")
    _canonical_identifier(server["artifact_id"], f"{label} artifact id")
    _canonical_identifier(server["run_id"], f"{label} run id")
    require(
        type(server["artifact_name"]) is str and server["artifact_name"],
        f"{label} artifact name is absent",
    )
    require(
        type(server["job_ids"]) is list and server["job_ids"]
        and server["job_ids"] == sorted(server["job_ids"])
        and len(set(server["job_ids"])) == len(server["job_ids"]),
        f"{label} job inventory is absent or repeats a job",
    )
    for identifier in server["job_ids"]:
        _canonical_identifier(identifier, f"{label} job id")
    for field in ("head_commit", "head_tree"):
        require(
            type(server[field]) is str
            and HEX40.fullmatch(server[field]) is not None,
            f"{label} {field} is not a canonical object name",
        )
    require(
        type(server["artifact_content_sha256"]) is str
        and HEX64.fullmatch(server["artifact_content_sha256"]) is not None,
        f"{label} artifact content digest is malformed",
    )
    require(
        type(server["artifact_digest"]) is str
        and server["artifact_digest"].startswith(ARTIFACT_DIGEST_PREFIX)
        and HEX64.fullmatch(
            server["artifact_digest"][len(ARTIFACT_DIGEST_PREFIX):]
        ) is not None,
        f"{label} server-returned artifact digest is malformed",
    )
    require(
        type(server["tree_paths"]) is list and server["tree_paths"]
        and server["tree_paths"] == sorted(server["tree_paths"])
        and len(set(server["tree_paths"])) == len(server["tree_paths"]),
        f"{label} tree membership is absent or repeats a path",
    )
    return server


def _verify_post_activation_proof(package, activation_state):
    """Post-activation proof is separate from the grant and needs live evidence."""
    proof = _exact_keys(
        package["post_activation_proof"],
        POST_ACTIVATION_PROOF_KEYS,
        "post-activation proof",
    )
    label = "post-activation proof"
    _bool(proof, "f8_true_requires_live_evidence", True, label)
    require(
        proof["pinning_helper"] == PINNING_HELPER_PATH,
        f"{label} pinning helper mismatch",
    )
    require(
        proof["pinning_candidate_topology"] == PINNING_CANDIDATE_TOPOLOGY,
        f"{label} pinning topology mismatch",
    )
    require(
        tuple(proof["required_live_fields"]) == READBACK_FIELDS,
        f"{label} required live field set mismatch",
    )
    require(type(proof["live_evidence_pinned"]) is bool,
            f"{label} live evidence flag is malformed")
    if activation_state == "unavailable":
        _bool(proof, "live_evidence_pinned", False, label)
    return proof


def _verify_live_evidence_is_complete(package):
    """Every live binding must really be pinned before F8 may ever be true."""
    for name, target in package["target_repositories"].items():
        require(
            type(target["repository_id"]) is int
            and type(target["repository_id"]) is not bool
            and target["repository_id"] > 0
            and type(target["repository_node_id"]) is str
            and target["repository_node_id"] != "",
            f"F8 closure requires a live repository id: {name}",
        )
    require(
        type(package["authorized_dispatch"]["run_id"]) is int
        and package["authorized_dispatch"]["run_id"] > 0,
        "F8 closure requires a live run id",
    )
    for field in PRODUCER_UNPINNED_FIELDS:
        require(
            package["producer_bindings"][field] is not None,
            f"F8 closure requires producer {field}",
        )
    for field in REVIEWED_SOURCE_UNPINNED_FIELDS:
        require(
            package["reviewed_source"][field] is not None,
            f"F8 closure requires reviewed source {field}",
        )


# ---------------------------------------------------------------------------
# Git-derived bindings of the exact checkout
# ---------------------------------------------------------------------------
def _git(repository_root, *arguments):
    try:
        return subprocess.run(
            ["git", "-C", str(repository_root), *arguments],
            check=True, capture_output=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(
            f"external review recomputation failed: {' '.join(arguments)}"
        ) from error


def _text(repository_root, *arguments):
    return _git(repository_root, *arguments).decode("utf-8").strip()


def _safe_path(raw):
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("changed path is not UTF-8") from error
    pure = PurePosixPath(decoded)
    require(
        decoded and not pure.is_absolute() and str(pure) == decoded
        and all(part not in ("", ".", "..") for part in pure.parts)
        and all(ord(character) >= 32 for character in decoded),
        "changed path is non-canonical",
    )
    return decoded


def _blob_sha256(repository_root, oid):
    return hashlib.sha256(
        _git(repository_root, "cat-file", "blob", oid)
    ).hexdigest()


def changed_path_manifest(repository_root, base_commit, head_commit):
    """The complete status-aware manifest, with modes, OIDs and renames."""
    raw = _git(
        repository_root, "diff", "--raw", "-z", "--full-index", "--no-ext-diff",
        "--no-abbrev", "--find-renames=50%", base_commit, head_commit, "--",
    )
    fields = raw.split(b"\0")
    require(fields[-1] == b"", "Git raw diff is not NUL terminated")
    fields.pop()
    header = re.compile(
        rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMDR])([0-9]{1,3})?"
    )
    entries = []
    index = 0
    while index < len(fields):
        match = header.fullmatch(fields[index])
        require(match is not None, "unsupported Git status in the reviewed diff")
        old_mode, new_mode, old_oid, new_oid, status_raw, score = match.groups()
        index += 1
        require(index < len(fields), "changed path missing from the Git raw diff")
        first = _safe_path(fields[index])
        index += 1
        status = status_raw.decode("ascii")
        if status == "R":
            require(index < len(fields) and score is not None,
                    "rename destination or similarity score is missing")
            second = _safe_path(fields[index])
            index += 1
            old_path, new_path = first, second
            similarity = int(score)
            require(50 <= similarity <= 100,
                    "rename similarity is outside the canonical threshold")
        else:
            require(score is None, "non-rename status carries a similarity score")
            old_path = None if status == "A" else first
            new_path = None if status == "D" else first
            similarity = None
        old_oid = old_oid.decode("ascii") if old_oid != b"0" * 40 else None
        new_oid = new_oid.decode("ascii") if new_oid != b"0" * 40 else None
        entries.append({
            "status": status,
            "similarity": similarity,
            "old_path": old_path,
            "new_path": new_path,
            "old_mode": old_mode.decode("ascii") if old_mode != b"000000" else None,
            "new_mode": new_mode.decode("ascii") if new_mode != b"000000" else None,
            "old_blob_oid": old_oid,
            "new_blob_oid": new_oid,
            "old_sha256": _blob_sha256(repository_root, old_oid) if old_oid else None,
            "new_sha256": _blob_sha256(repository_root, new_oid) if new_oid else None,
        })
    return entries


CANONICAL_CANDIDATE_DIFF_ARGUMENTS = {
    "canonical-binary-full-index.diff": ("--binary", "--full-index"),
    "name-status-find-renames-50.z": ("--name-status", "-z"),
    "raw-full-index-find-renames-50.z": ("--raw", "-z", "--full-index"),
    "raw-status-authoritative.z": ("--raw", "-z"),
}


def candidate_diff_streams(repository_root, base_commit, head_commit):
    """The four exact byte streams independently reviewed and later signed."""
    return {
        name: _git(
            repository_root, "diff", *leading, "--no-ext-diff", "--no-abbrev",
            "--find-renames=50%", "--src-prefix=a/", "--dst-prefix=b/",
            base_commit, head_commit, "--",
        )
        for name, leading in CANONICAL_CANDIDATE_DIFF_ARGUMENTS.items()
    }


def _tracked_paths(repository_root, head_commit):
    raw = _git(repository_root, "ls-tree", "-r", "-z", "--full-tree", head_commit)
    fields = [entry for entry in raw.split(b"\0") if entry]
    tracked = {}
    for entry in fields:
        meta, _, path_raw = entry.partition(b"\t")
        mode, kind, oid = meta.split(b" ")
        require(kind == b"blob", "reviewed tree carries a non-blob entry")
        require(re.fullmatch(rb"[0-7]{6}", mode) is not None,
                "reviewed tree entry mode is malformed")
        path = _safe_path(path_raw)
        require(path not in tracked, "reviewed tree has a duplicate path")
        tracked[path] = _blob_sha256(repository_root, oid.decode("ascii"))
    return tracked


def external_review_bindings(repository_root, base_commit, head_commit):
    """Every binding an external activation review must carry, from Git alone.

    The checkout must be exactly clean and the head must be an ordinary
    non-merge direct child of the base; anything else fails closed here rather
    than producing a binding an attacker could satisfy.
    """
    repository_root = Path(repository_root).resolve()
    require(
        type(base_commit) is str and HEX40.fullmatch(base_commit) is not None,
        "external review base commit is malformed",
    )
    require(
        type(head_commit) is str and HEX40.fullmatch(head_commit) is not None,
        "external review head commit is malformed",
    )
    require(
        _git(repository_root, "status", "--porcelain=v1", "-z",
             "--untracked-files=all") == b"",
        "the reviewed checkout is not exactly clean",
    )
    require(
        _text(repository_root, "rev-parse", "HEAD") == head_commit,
        "the reviewed checkout HEAD is not the reviewed head",
    )
    parents = _text(
        repository_root, "rev-list", "--parents", "-n", "1", head_commit,
    ).split()
    require(
        parents == [head_commit, base_commit],
        "the reviewed head is not an ordinary non-merge direct child of the base",
    )
    streams = candidate_diff_streams(
        repository_root, base_commit, head_commit,
    )
    diff = streams["canonical-binary-full-index.diff"]
    tracked = _tracked_paths(repository_root, head_commit)
    trust = tracked.get(TRUST_RECORD_PATH)
    require(
        type(trust) is str,
        f"the reviewed checkout does not track {TRUST_RECORD_PATH}",
    )
    return {
        "repository": AUTHORITY_REPOSITORY,
        "base_commit": base_commit,
        "base_tree": _text(repository_root, "rev-parse", f"{base_commit}^{{tree}}"),
        "head_commit": head_commit,
        "head_tree": _text(repository_root, "rev-parse", f"{head_commit}^{{tree}}"),
        "sole_parent": base_commit,
        "candidate_diff_sha256": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in streams.items()
        },
        "canonical_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "changed_path_manifest": changed_path_manifest(
            repository_root, base_commit, head_commit,
        ),
        "tracked_paths_sha256": tracked,
        "critical_artifact_sha256": {
            path: tracked[path]
            for path in CRITICAL_ARTIFACT_PATHS if path in tracked
        },
        "reviewer_authorization_path": TRUST_RECORD_PATH,
        "reviewer_authorization_sha256": trust,
    }


def _require_manifest_shape(entries):
    require(type(entries) is list and entries,
            "external review changed-path manifest is malformed")
    seen = set()
    for entry in entries:
        _exact_keys(entry, MANIFEST_ENTRY_KEYS, "external review manifest entry")
        require(entry["status"] in ("A", "M", "D", "R"),
                "external review manifest status is not modelled")
        for key in ("old_blob_oid", "new_blob_oid"):
            require(
                entry[key] is None
                or (type(entry[key]) is str
                    and HEX40.fullmatch(entry[key]) is not None),
                f"external review manifest {key} is malformed",
            )
        for key in ("old_sha256", "new_sha256"):
            require(
                entry[key] is None
                or (type(entry[key]) is str
                    and HEX64.fullmatch(entry[key]) is not None),
                f"external review manifest {key} is malformed",
            )
        for key in ("old_mode", "new_mode"):
            require(
                entry[key] is None
                or (type(entry[key]) is str
                    and re.fullmatch(r"[0-7]{6}", entry[key]) is not None),
                f"external review manifest {key} is malformed",
            )
        require(
            entry["similarity"] is None
            or (type(entry["similarity"]) is int
                and type(entry["similarity"]) is not bool),
            "external review manifest similarity is malformed",
        )
        paths = {value for value in (entry["old_path"], entry["new_path"]) if value}
        require(seen.isdisjoint(paths),
                "external review manifest repeats a changed path")
        seen.update(paths)


def _require_no_circular_precomputation(repository_root, head_commit, digest):
    """The candidate may not contain the digest of its own later receipt."""
    hits = subprocess.run(
        ["git", "-C", str(repository_root), "grep", "-l", "--fixed-strings",
         "-e", digest, head_commit, "--"],
        capture_output=True,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
    )
    require(
        hits.returncode == 1 and hits.stdout == b"",
        "the reviewed candidate precomputes its own external review receipt digest",
    )


def verify_external_activation_review(data, *, repository_root, base_commit,
                                      receipt_sha256):
    """Authenticate immutable external activation-review receipt bytes.

    The receipt is an input that can only exist after this exact candidate
    does. Every binding it carries is recomputed from the exact clean checkout,
    the decision must be a literal ``APPROVED`` with an integer zero finding
    count, and neither a candidate-owned nor a self-reviewed receipt is ever
    accepted. Only a receipt that survives all of this authorizes activation.
    """
    require(type(data) is bytes and data, "external review receipt bytes are required")
    require(
        type(receipt_sha256) is str and HEX64.fullmatch(receipt_sha256) is not None,
        "external review receipt digest is malformed",
    )
    require(
        hashlib.sha256(data).hexdigest() == receipt_sha256,
        "external review receipt digest mismatch",
    )
    receipt = _closed_json(data, "external review receipt")
    _exact_keys(receipt, EXTERNAL_REVIEW_RECEIPT_KEYS, "external review receipt")
    require(
        data == canonical_bytes(receipt),
        "external review receipt is not canonical exact JSON",
    )
    require(
        receipt["schema_version"] == 1
        and type(receipt["schema_version"]) is int
        and receipt["receipt_type"] == EXTERNAL_REVIEW_RECEIPT_TYPE,
        "external review receipt identity mismatch",
    )

    # --- strict decision: literal APPROVED, integer (never boolean) zero ---
    require(
        type(receipt["decision"]) is str
        and receipt["decision"] == EXTERNAL_REVIEW_DECISION,
        "external review decision is not the literal APPROVED decision",
    )
    require(
        type(receipt["findings"]) is list and receipt["findings"] == [],
        "external review receipt carries findings",
    )
    require(
        type(receipt["findings_count"]) is int
        and type(receipt["findings_count"]) is not bool
        and receipt["findings_count"] == 0,
        "external review finding count is not an integer zero",
    )
    require(
        receipt["activation_authorized"] is True,
        "external review receipt does not authorize the exact activation",
    )
    require(
        receipt["produced_after_candidate"] is True,
        "external review receipt does not attest it was produced after the candidate",
    )
    require(
        receipt["candidate_owned"] is False,
        "a candidate-owned external review receipt is never an approval",
    )
    require(
        receipt["reviewer_profile"] == EXTERNAL_REVIEW_PROFILE,
        "external review reviewer profile mismatch",
    )
    require(
        type(receipt["reviewer_repository"]) is str
        and receipt["reviewer_repository"] != AUTHORITY_REPOSITORY
        and receipt["reviewer_repository"] == INDEPENDENT_REPOSITORY,
        "external review receipt is self-reviewed by the candidate repository",
    )

    # --- every binding recomputed from the exact clean checkout -----------
    _require_manifest_shape(receipt["changed_path_manifest"])
    head_commit = receipt["head_commit"]
    require(
        type(head_commit) is str and HEX40.fullmatch(head_commit) is not None,
        "external review head commit is malformed",
    )
    derived = external_review_bindings(repository_root, base_commit, head_commit)
    for name in EXTERNAL_REVIEW_BINDING_KEYS:
        require(
            receipt[name] == derived[name],
            f"external review binding {name} does not match the exact checkout",
        )
    require(
        set(derived["critical_artifact_sha256"]) == set(CRITICAL_ARTIFACT_PATHS)
        or set(derived["critical_artifact_sha256"])
        == set(CRITICAL_ARTIFACT_PATHS) & set(derived["tracked_paths_sha256"]),
        "external review critical artifact inventory is incomplete",
    )
    _verify_receipt_decision_delivery(receipt, head_commit)
    _verify_receipt_server_objects(receipt)
    _require_no_circular_precomputation(
        Path(repository_root).resolve(), head_commit, receipt_sha256,
    )
    return {**receipt, "receipt_sha256": receipt_sha256}


def _verify_generated_activation_evidence(package):
    """The generator-bound activation contract, and never an approval.

    Every candidate-static value is pinned, every prohibition must be
    asserted, and the pre-activation evidence state must stay `unavailable`.
    Fresh bytes belong to the separate authenticated activation record; this
    package may not predeclare or relabel them as candidate-owned evidence.

    This contract governs the *evidence-generating* activation only. It is
    deliberately independent of the source-chain activation the rest of this
    package models: a source chain that legitimately reaches `ready` still
    holds no generated Sigstore evidence, and coupling the two would let one
    closure speak for the other.
    """
    label = "generated activation evidence contract"
    contract = _exact_keys(
        package["generated_activation_evidence"], GENERATED_EVIDENCE_KEYS,
        label,
    )
    for name in GENERATED_EVIDENCE_TRUE_FLAGS:
        _bool(contract, name, True, label)
    for name, value in sorted(GENERATED_EVIDENCE_EXACT.items()):
        require(
            contract[name] == value,
            f"{label} {name} is not the exact bound value {value!r}",
        )
    require(
        contract["artifact_files"]
        == list(GENERATED_ACTIVATION_ARTIFACT_FILES),
        f"{label} generated artifact inventory is open or reordered",
    )
    require(
        contract["maximum_authorized_activation_attempts"] == 1
        and type(contract["maximum_authorized_activation_attempts"]) is int
        and type(contract["maximum_authorized_activation_attempts"])
        is not bool,
        f"{label} authorizes more than the one reversible activation attempt",
    )
    require(
        tuple(contract["rejected_evidence"]) == GENERATED_EVIDENCE_REJECTED,
        f"{label} does not reject exactly the evidence classes it must",
    )
    return contract


def _verify_external_review_contract(package):
    """The candidate may only carry the contract, never the approval."""
    contract = _exact_keys(
        package["external_activation_review"],
        EXTERNAL_REVIEW_CONTRACT_KEYS,
        "external activation review contract",
    )
    label = "external activation review contract"
    require(
        contract["receipt_type"] == EXTERNAL_REVIEW_RECEIPT_TYPE,
        f"{label} receipt type mismatch",
    )
    require(
        contract["required_decision"] == EXTERNAL_REVIEW_DECISION
        and contract["required_reviewer_profile"] == EXTERNAL_REVIEW_PROFILE,
        f"{label} required decision mismatch",
    )
    require(
        type(contract["required_findings_count"]) is int
        and type(contract["required_findings_count"]) is not bool
        and contract["required_findings_count"] == 0,
        f"{label} required finding count is not an integer zero",
    )
    require(
        tuple(contract["required_bindings"]) == EXTERNAL_REVIEW_BINDING_KEYS,
        f"{label} required binding set mismatch",
    )
    require(
        type(contract["decision_source"]) is str and contract["decision_source"],
        f"{label} names no external decision source",
    )
    for flag in (
        "candidate_authored_decision_forbidden",
        "candidate_owned_approval_forbidden",
        "circular_receipt_precomputation_forbidden",
        "produced_after_exact_candidate_required",
        "self_review_forbidden",
        "verified_against_exact_checkout",
    ):
        _bool(contract, flag, True, label)
    require(
        contract["repository"] == INDEPENDENT_REPOSITORY
        and contract["workflow_path"]
        == TARGET_WORKFLOW_PATHS[INDEPENDENT_REPOSITORY],
        f"{label} names a repository or workflow that is not the reviewer",
    )
    require(
        contract["artifact_files"]
        == [EXTERNAL_REVIEW_RECEIPT_MEMBER, EXTERNAL_REVIEW_BUNDLE_MEMBER],
        f"{label} artifact member inventory mismatch",
    )
    require(
        type(contract["artifact_name"]) is str and contract["artifact_name"],
        f"{label} artifact name is absent",
    )
    _bool(contract, "sigstore_bundle_required", True, label)
    require(
        contract["state"] in EXTERNAL_REVIEW_STATES,
        f"{label} state is not a modelled review state",
    )
    if contract["state"] == EXTERNAL_REVIEW_UNAVAILABLE:
        require(
            contract["receipt_sha256"] is None,
            "the candidate may never precompute the later external review receipt",
        )
    else:
        require(
            type(contract["receipt_sha256"]) is str
            and HEX64.fullmatch(contract["receipt_sha256"]) is not None,
            f"{label} is authenticated but binds no exact receipt digest",
        )
    return contract


def _expected_terminal_readback_contract(collector_sha256, root):
    """The one post-completion collector the activation package seals."""
    validator_path = (
        Path(root) / "independent-review-bootstrap-v2" / "scripts"
        / "verify_kanban_review_v2.py"
    )
    require(
        validator_path.is_file() and not validator_path.is_symlink(),
        "terminal collector validator bytes are absent or unsafe",
    )
    validator_sha256 = hashlib.sha256(validator_path.read_bytes()).hexdigest()
    return {
        "activation_artifact_files": list(GENERATED_ACTIVATION_ARTIFACT_FILES),
        "activation_artifact_name": GENERATED_ACTIVATION_ARTIFACT_NAME,
        "activation_job_name": GENERATED_ACTIVATION_JOB_NAME,
        "activation_record_digest_required": True,
        "activation_workflow_path": TARGET_WORKFLOW_PATHS[INDEPENDENT_REPOSITORY],
        "artifact_archive_digest_recomputed": True,
        "artifact_content_digest_algorithm": (
            GENERATED_ARTIFACT_CONTENT_DIGEST_ALGORITHM
        ),
        "artifact_content_digest_recomputed": True,
        "artifact_exactly_one_non_expired": True,
        "caller_inputs": [],
        "cleanup_step_name": ACTIVATION_CLEANUP_STEP_NAME,
        "closed_receipt_required": True,
        "collector_artifact_files": [
            "terminal-activation-readback.json",
            "terminal-activation-readback.sigstore.json",
        ],
        "collector_artifact_name": TERMINAL_ARTIFACT_NAME,
        "collector_identity": TERMINAL_COLLECTOR_IDENTITY,
        "collector_job_name": "terminal-readback",
        "collector_verifier": {
            "ambient_execution_forbidden": True,
            "entrypoint": f"{TERMINAL_RUNTIME_EXECUTABLE} -I -B",
            "files": {
                "collector": f"sha256:{validator_sha256}",
                "cosign": TERMINAL_COSIGN_DIGEST,
                "python3": f"oci-manifest:{TERMINAL_RUNTIME_DIGEST}",
            },
            "head_tree_and_sole_parent_authenticated": True,
            "mode": TERMINAL_COLLECTOR_MODE,
            "repository": AUTHORITY_REPOSITORY,
            "runtime": {
                "executable_directory": TERMINAL_RUNTIME_PATH,
                "executables": list(TERMINAL_RUNTIME_EXECUTABLES),
                "image": TERMINAL_RUNTIME_IMAGE,
                "image_digest": TERMINAL_RUNTIME_DIGEST,
                "root_filesystem_read_only": True,
                "semantic_authority": "python-3.13.7-stdlib-only",
                "transitive_dependencies": (
                    "bound-by-oci-manifest-config-and-layer-digests"
                ),
            },
        },
        "collector_workflow_path": TERMINAL_COLLECTOR_PATH,
        "collector_workflow_sha256": collector_sha256,
        "default_branch": "main",
        "default_branch_ref": "refs/heads/main",
        "exact_cosign_version": "v3.1.3",
        "fresh_provenance": {
            "attestation_fields": [
                "generator", "generator_binary_sha256", "generator_platform",
                "generator_version", "rekor_generation",
                "rekor_log_key_algorithm", "route",
                "signer_signature_algorithm", "signing_window_end",
                "signing_window_start", "timestamp",
            ],
            "exact_fulcio_claims_required": True,
            "generator": "cosign v3.1.3",
            "generator_binary_sha256": (
                "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
            ),
            "generator_version": "v3.1.3",
            "pre_registered_bundle_digest_required": False,
            "rekor_generation": "rekor-v2",
            "rekor_log_key_algorithm": "PKIX_ED25519",
            "signer": "ecdsa-p256-sha256/Fulcio",
            "timestamp": "rfc3161",
        },
        "issuer": "https://token.actions.githubusercontent.com",
        "no_repository_or_content_mutation": True,
        "permissions": {
            "actions": "read",
            "contents": "read",
            "id-token": "write",
            "metadata": "read",
        },
        "receipt_type": TERMINAL_RECEIPT_TYPE,
        "recursion_forbidden": True,
        "repository": INDEPENDENT_REPOSITORY,
        "run_attempt": 1,
        "terminal_api_readback_required": True,
        "trigger": "workflow_run",
        "trigger_workflow_name": (
            "Sign exact protected Kanban Authority-v2 review"
        ),
    }


def _verify_terminal_readback_contract(package, sealed, root):
    """Bind the separate collector contract to its exact immutable bytes."""
    contract = _exact_keys(
        package["terminal_readback"], TERMINAL_READBACK_KEYS,
        "terminal activation readback contract",
    )
    collector_sha256 = sealed[TERMINAL_COLLECTOR_SOURCE_PATH]
    require(
        type(contract["run_attempt"]) is int
        and contract == _expected_terminal_readback_contract(
            collector_sha256, root,
        ),
        "terminal activation readback contract mismatch",
    )
    collector_path = Path(root) / TERMINAL_COLLECTOR_SOURCE_PATH
    require(
        collector_path.is_file() and not collector_path.is_symlink()
        and hashlib.sha256(collector_path.read_bytes()).hexdigest()
        == collector_sha256,
        "terminal activation collector bytes are absent or substituted",
    )
    bootstrap_path = Path(root) / (
        "independent-review-bootstrap-v2/bootstrap-contract.json"
    )
    bootstrap = _closed_json(
        bootstrap_path.read_bytes(), "independent review bootstrap contract",
    )
    require(
        bootstrap.get("terminal_readback") == contract,
        "terminal activation contract differs between source chain and bootstrap",
    )
    return contract


# ---------------------------------------------------------------------------
# F8-ACTIVATION-READINESS-CANDIDATE-DECLARED
#
# The reachable transition is exporter -> independent validator -> Authority.
# The Authority never reads its readiness off a candidate-owned `ready` flag.
# It derives readiness from two independent evidences, neither of which this
# candidate can author:
#
#   * authenticated exporter evidence - the sealed protected-source bootstrap
#     contract's own activation state, plus the live producer and reviewed
#     source bindings that only an executed, authenticated exporter run pins;
#   * independent external closure evidence - an authenticated,
#     non-caller-selectable external activation-review receipt digest produced
#     by the separate independent-review authority after this exact candidate.
#
# Every candidate-owned flag is then checked *against* that derivation, so a
# forged `activation_state`, `f8_closed`, `activation_authorized`,
# `live_evidence_pinned` or external review `state` can only contradict the
# evidence and fail closed. It can never manufacture readiness.
# ---------------------------------------------------------------------------
EXPORTER_EVIDENCE_SOURCE = "authenticated-exporter-evidence"
EXTERNAL_CLOSURE_EVIDENCE_SOURCE = "independent-external-closure-evidence"
ACTIVATION_EVIDENCE_SOURCES = (
    EXPORTER_EVIDENCE_SOURCE, EXTERNAL_CLOSURE_EVIDENCE_SOURCE,
)
SOURCE_BOOTSTRAP_CONTRACT_PATH = (
    "protected-source-bootstrap-v2/bootstrap-contract.json"
)
SOURCE_BOOTSTRAP_PENDING_STATE = "authorized_pending_evidence"
SOURCE_BOOTSTRAP_READY_STATE = "ready"
SOURCE_BOOTSTRAP_STATES = (
    SOURCE_BOOTSTRAP_PENDING_STATE, SOURCE_BOOTSTRAP_READY_STATE, "unavailable",
)


def exporter_evidence_state(package, root=ROOT):
    """The authenticated exporter side of the transition, from evidence only.

    The sealed exporter is a candidate-owned artifact, so it may only ever emit
    *pending* evidence. It is therefore never asked whether activation is
    authorized: it is asked only whether an authenticated run has really pinned
    every live producer and reviewed-source binding, and whether its own sealed
    activation state agrees. A contract that claims `ready` while any live
    binding is still unpinned is a contradiction and fails closed.
    """
    label = "sealed protected-source bootstrap contract"
    contract_path = Path(root) / SOURCE_BOOTSTRAP_CONTRACT_PATH
    require(
        contract_path.is_file() and not contract_path.is_symlink(),
        f"{label} is absent or unsafe",
    )
    contract = _closed_json(contract_path.read_bytes(), label)
    binding = contract.get("authority_binding")
    review = contract.get("protected_review_result")
    require(
        type(binding) is dict and type(review) is dict,
        "the sealed protected-source bootstrap contract members are malformed",
    )
    state = binding.get("activation_state")
    require(
        state in SOURCE_BOOTSTRAP_STATES
        and review.get("activation_state") == state,
        "the sealed exporter contract is not in a modelled activation state",
    )
    # The exporter is candidate owned, so it may only ever emit sealed pending
    # evidence: it can describe what an authenticated run would pin, and it can
    # never authorize the activation itself.
    require(
        review.get("activation_authorized") is False,
        "the candidate-owned exporter contract authorizes the activation, but "
        "sealed pending evidence may never carry an activation authorization",
    )
    require(
        state == SOURCE_BOOTSTRAP_PENDING_STATE,
        "the candidate-owned exporter contract must emit sealed pending "
        "evidence only",
    )
    producer = package["producer_bindings"]
    reviewed = package["reviewed_source"]
    pinned_fields = []
    for field in PRODUCER_UNPINNED_FIELDS:
        pattern = HEX40 if field == "certificate_github_workflow_sha" else HEX64
        pinned_fields.append(
            type(producer.get(field)) is str
            and pattern.fullmatch(producer[field]) is not None
        )
    for field in REVIEWED_SOURCE_UNPINNED_FIELDS:
        pinned_fields.append(
            type(reviewed.get(field)) is str
            and HEX40.fullmatch(reviewed[field]) is not None
        )
    pinned = all(pinned_fields)
    require(
        pinned or not any(pinned_fields),
        "the exporter evidence is partially pinned, so no authenticated run "
        "produced it",
    )
    return {
        "contract_activation_state": state,
        "pinned": pinned,
        "source": EXPORTER_EVIDENCE_SOURCE,
    }


def external_closure_evidence_state(external):
    """The independent, non-caller-selectable external closure evidence."""
    authenticated = external["state"] == EXTERNAL_REVIEW_AUTHENTICATED
    digest = external["receipt_sha256"]
    require(
        authenticated
        is (type(digest) is str and HEX64.fullmatch(digest) is not None),
        "the external closure evidence state contradicts its receipt digest",
    )
    return {
        "authenticated": authenticated,
        "receipt_sha256": digest,
        "source": EXTERNAL_CLOSURE_EVIDENCE_SOURCE,
    }


def derive_activation_readiness(*, exporter_pinned,
                                external_closure_authenticated):
    """F8 and the activation authorization, derived from both evidences only."""
    require(
        type(exporter_pinned) is bool
        and type(external_closure_authenticated) is bool,
        "activation readiness evidence is not literal boolean",
    )
    closed = exporter_pinned and external_closure_authenticated
    return {
        "activation_authorized": closed,
        "activation_state": "ready" if closed else "unavailable",
        "derived_from": list(ACTIVATION_EVIDENCE_SOURCES),
        "f8_closed": closed,
        "live_evidence_pinned": closed,
        "repositories_created": closed,
        "runs_observed": closed,
        "workflows_written": closed,
    }


def verify_activation_package(path=ACTIVATION_PATH, root=ROOT,
                              with_readiness=False):
    """Fail closed unless the activation-only package is exactly reviewable."""
    path = Path(path)
    require(
        path.is_file() and not path.is_symlink(),
        "source-chain activation package is absent or unsafe",
    )
    data = path.read_bytes()
    package = _closed_json(data, "source-chain activation package")
    _exact_keys(package, PACKAGE_KEYS, "source-chain activation package")
    require(
        data == canonical_bytes(package),
        "source-chain activation package is not canonical exact JSON",
    )
    require(
        package["schema_version"] == 1
        and package["contract"] == CONTRACT
        and package["finding"] == FINDING,
        "source-chain activation package identity mismatch",
    )
    activation_state = package["activation_state"]
    require(
        activation_state in ACTIVATION_STATES,
        "source-chain activation state is not a modelled state",
    )
    _bool(package, "no_fallback", True, "source-chain activation package")
    _bool(package, "independent_activation_authorization_required", True,
          "source-chain activation package")
    _bool(package, "independently_reviewable_before_repository_creation", True,
          "source-chain activation package")
    _bool(package, "independently_reviewable_before_workflow_write", True,
          "source-chain activation package")
    _bool(package, "supports_later_separate_acc_releaser_activation_task_only",
          True, "source-chain activation package")

    authorizes = _exact_keys(
        package["authorizes"], AUTHORIZATION_KEYS, "activation authorizations",
    )
    for name in AUTHORIZATION_KEYS:
        require(type(authorizes[name]) is bool, f"activation authorization {name} is not a boolean")
    for name in PERMANENTLY_UNAUTHORIZED:
        require(
            authorizes[name] is False,
            f"the activation package may never authorize {name}",
        )
    for name in REQUIRED_ACTIVATION_GRANTS:
        require(
            authorizes[name] is True,
            "the reviewed activation package must authorize the named "
            f"acc-releaser activation lane to {name}",
        )

    sealed = _verify_sealed_bytes(package, root)
    reviewed = _verify_trust_record(package, root, sealed)
    _verify_terminal_readback_contract(package, sealed, root)
    _verify_pre_activation_authorization(package, sealed)
    proof = _verify_post_activation_proof(package, activation_state)
    external = _verify_external_review_contract(package)
    _verify_generated_activation_evidence(package)
    _verify_target_repositories(package, activation_state)
    _verify_dispatch(package, activation_state)
    _verify_producer(package, activation_state)
    for field in REVIEWED_SOURCE_UNPINNED_FIELDS:
        _unpinned_or_hex(reviewed, field, HEX40, activation_state, "reviewed source")

    cleanup = _exact_keys(
        package["cleanup"], CLEANUP_KEYS, "activation cleanup contract",
    )
    for name in CLEANUP_TRUE_FLAGS:
        _bool(cleanup, name, True, "activation cleanup contract")
    require(cleanup["artifact_retention_days"] == 1, "activation artifact retention mismatch")
    require(
        cleanup["expected_workflow_state_after_activation"]
        == DISABLED_WORKFLOW_STATE,
        "the activation cleanup must leave the sealed workflow "
        f"{DISABLED_WORKFLOW_STATE}",
    )
    readback = _exact_keys(package["readback"], ("fields", "required"), "activation readback contract")
    _bool(readback, "required", True, "activation readback contract")
    require(
        tuple(readback["fields"]) == READBACK_FIELDS,
        "activation readback field set mismatch",
    )

    # ---------------------------------------------------------------------
    # The whole activation decision, derived from evidence and only then
    # compared with what this candidate declares. Nothing below reads a
    # candidate-owned flag as an input.
    # ---------------------------------------------------------------------
    exporter = exporter_evidence_state(package, root)
    closure = external_closure_evidence_state(external)
    derived = derive_activation_readiness(
        exporter_pinned=exporter["pinned"],
        external_closure_authenticated=closure["authenticated"],
    )
    for field in (
        "activation_authorized", "f8_closed", "repositories_created",
        "runs_observed", "workflows_written",
    ):
        require(
            type(package[field]) is bool,
            f"source-chain activation {field} is not literal boolean",
        )
        require(
            package[field] is derived[field],
            f"source-chain activation {field} contradicts the activation "
            "readiness derived from the authenticated exporter evidence and "
            "the independent external closure evidence",
        )
    require(
        activation_state == derived["activation_state"],
        "source-chain activation state contradicts the activation readiness "
        "derived from the authenticated exporter evidence and the independent "
        "external closure evidence",
    )
    require(
        proof["live_evidence_pinned"] is derived["live_evidence_pinned"],
        "pinned live activation evidence contradicts the derived readiness",
    )
    # The external closure evidence is not candidate-selectable: a candidate
    # that declares it authenticated while the authenticated exporter evidence
    # is absent is asserting evidence it cannot own.
    require(
        closure["authenticated"] is derived["f8_closed"],
        "the declared external closure evidence contradicts the activation "
        "readiness derived from the authenticated exporter evidence",
    )
    require(
        exporter["pinned"] is derived["f8_closed"],
        "the declared exporter evidence contradicts the derived activation "
        "readiness",
    )
    if derived["f8_closed"]:
        _verify_live_evidence_is_complete(package)
    else:
        require(
            type(package["unavailable_reason"]) is str
            and package["unavailable_reason"] != "",
            "inactive activation package must state its exact blocker",
        )
    package_readiness = dict(derived)

    if path == Path(root) / ACTIVATION_PATH.name:
        # The package is bound to the candidate's own sealed manifest rather
        # than to a second duplicated literal here: the manifest is
        # re-verified against the checkout, so a rewritten package or a
        # rewritten entry can never agree. The Authority verifier pins the
        # manifest itself against its own sealed constant.
        require(
            hashlib.sha256(data).hexdigest()
            == manifest_digest(root, ACTIVATION_PATH.name),
            "reviewed source-chain activation package hash mismatch",
        )
    if with_readiness:
        return package, package_readiness
    return package


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--activation-package", type=Path, default=ACTIVATION_PATH)
    args = parser.parse_args()
    package, readiness = verify_activation_package(
        path=args.activation_package, with_readiness=True,
    )
    print(json.dumps({
        "activation_authorized": readiness["activation_authorized"],
        "activation_state": readiness["activation_state"],
        "contract": CONTRACT,
        "derived_from": readiness["derived_from"],
        "f8_closed": readiness["f8_closed"],
        "finding": FINDING,
        "repositories_created": readiness["repositories_created"],
        "runs_observed": readiness["runs_observed"],
        "sealed_bytes": len(package["sealed_bytes"]),
        "verified": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
