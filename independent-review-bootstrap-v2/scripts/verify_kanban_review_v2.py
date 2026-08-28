#!/usr/bin/env python3
"""Authenticate one immutable protected Kanban result and every executed byte.

The authorized protected-source run is selected only by the sealed immutable
bootstrap contract. No caller input can choose, substitute or forge a path, a
run, an activation state, an artifact or a byte: every input is either a
constant path inside this sealed checkout, a file the workflow filled from an
authenticated GitHub read, or a value the Actions server itself set in the
environment. The only argument is the execution phase, which can never widen
what is checked.

The independent lane validates the same pre/post activation state as the
protected lane: it rehashes the authenticated protected-source bootstrap
contract at the pinned source head and requires its activation state and every
pinned binding to agree with this contract before any receipt is trusted.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ZIP_CREATOR_MSDOS = 0
ZIP_CREATOR_UNIX = 3
ZIP_NON_UNIX_CREATOR_SYSTEMS = frozenset((ZIP_CREATOR_MSDOS,))

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = "bootstrap-contract.json"
INDEPENDENT_WORKFLOW_PATH = ".github/workflows/review-authority-v2.yml"
INDEPENDENT_VALIDATOR_PATH = "scripts/verify_kanban_review_v2.py"
# Files the workflow fills only from authenticated, non-caller-selectable reads.
AUTHENTICATED_DIRECTORY = "authenticated"
INDEPENDENT_COMMIT_FILE = "authenticated/independent-commit.json"
SOURCE_RUN_FILE = "authenticated/source-run.json"
SOURCE_COMMIT_FILE = "authenticated/source-commit.json"
SOURCE_WORKFLOW_FILE = "authenticated/source-workflow.yml"
SOURCE_HELPER_FILE = "authenticated/source-helper.py"
SOURCE_CONTRACT_FILE = "authenticated/source-bootstrap-contract.json"
# Raw `gh api -i` captures: the exact status line, header block and body of
# every authenticated read, plus a sidecar recording the exact URL requested.
# Nothing about the live provenance is ever synthesised from these; every
# status, Link relation, permission header, page, tree entry, blob and
# artifact identifier the sealed document carries is read out of them.
RAW_DIRECTORY = "authenticated/raw"
RAW_REPOSITORY = "repository"
RAW_INSTALLATION = "installation"
RAW_RUN = "run"
RAW_COMMIT = "commit"
RAW_TREE = "tree"
RAW_RUNS_PREFIX = "runs"
RAW_JOBS_PREFIX = "jobs"
RAW_ARTIFACTS_PREFIX = "artifacts"
RAW_BLOB_PREFIX = "blob"
RAW_PROTECTION = "protection"
# The immutable artifact archive, downloaded by canonical server id.
ARTIFACT_ARCHIVE_FILE = "authenticated/artifact-archive.zip"
ARTIFACT_MEMBERS = (
    "kanban-review-envelope.json", "preissuance-review-receipt.json",
)
RAW_COLLECTIONS = (RAW_RUNS_PREFIX, RAW_JOBS_PREFIX, RAW_ARTIFACTS_PREFIX)
MAXIMUM_CAPTURED_PAGES = 100
PERMISSION_HEADER = "x-accepted-github-permissions"
API_VERSION_HEADER = "x-github-api-version-selected"
LINK_HEADER = "link"
REVIEWER_REPOSITORY_FILE = "authenticated/reviewer-repository.json"
REVIEWER_DECISION_COMMIT_FILE = "authenticated/reviewer-decision-commit.json"
REVIEWER_DECISION_PROTECTION_FILE = (
    "authenticated/reviewer-decision-branch-protection.json"
)
REVIEWER_DECISION_BLOB_FILE = "authenticated/reviewer-decision-blob.json"
REVIEWER_DECISION_READBACK_FILE = (
    "authenticated/reviewer-decision-readback.json"
)
ARTIFACT_DIRECTORY = "protected-review"
ENVELOPE_FILE = "protected-review/kanban-review-envelope.json"
RECEIPT_FILE = "protected-review/preissuance-review-receipt.json"
EXTERNAL_REVIEW_FILE = (
    "protected-review/external-activation-review-receipt.json"
)
EXTERNAL_REVIEW_RECEIPT_TYPE = (
    "acc-authority-v2-external-independent-activation-review"
)
# The candidate defines only what an acceptable reviewer decision must look
# like. It never authors, defaults or synthesizes one: the concrete decision
# bytes are a separate immutable artifact the independent reviewer writes to
# `decisions/<authority head>.json` only after that exact candidate exists.
REVIEWER_DECISION_TYPE = "acc-authority-v2-independent-reviewer-decision"
REVIEWER_DECISION_DIRECTORY = "decisions"
REVIEWER_AUTHORED_DECISION_DIRECTORY = "reviewer-authored-decisions"
# F8-INDEPENDENT-DECISION-DELIVERY-UNREACHABLE
#
# A decision file lying in the checkout proves nothing: anything able to write
# the lane could place one. The decision is authorized only when the sealed
# delivery evidence - filled exclusively from authenticated read-only GitHub
# reads at constant paths - proves who wrote it, that it sits at the exact
# path this lane derives for itself, that the delivery commit, tree and blob
# are the authenticated ones, that the delivery branch is protected, and that
# an independent readback reproduces the exact bytes on disk.
DECISION_DELIVERY_FILE = "authenticated/reviewer-decision-delivery.json"
DECISION_DELIVERY_OPERATION_FILE = (
    "authenticated/reviewer-decision-delivery-operation.json"
)
DECISION_DELIVERY_KEYS = (
    "blob", "branch_protection", "commit", "operation", "readback",
    "repository",
)
DELIVERY_OPERATION_KEYS = (
    "author", "blob_sha", "cas_capability_probe", "cas_capability_proven",
    "cas_expected_old_oid", "cas_primitive", "cas_ref", "changed_paths",
    "commit_parent", "commit_sha", "commit_tree", "committer",
    "parent_tree", "path", "readback_decision_sha256",
    "signature_verified", "signed_payload_sha256",
)
DECISION_DELIVERY_BRANCH = "main"
DECISION_WRITER_LOGIN = "chrizzatsu"
DECISION_WRITER_TYPE = "User"
DECISION_BLOB_KEYS = (
    "content", "encoding", "path", "sha", "size", "type", "url",
)
DECISION_READBACK_KEYS = ("content", "encoding", "path", "ref", "sha", "size")
DECISION_COMMIT_KEYS = (
    "author", "committer", "files", "parents", "sha", "tree", "verification",
)
DECISION_COMMIT_FILE_KEYS = ("filename", "sha", "status")
# The delivery commit must really have introduced or changed the exact derived
# decision path. Authenticating only the commit author proves who made *a*
# commit, never who wrote *this* blob.
DECISION_INTRODUCING_STATUSES = ("added", "modified")
DECISION_ACTOR_KEYS = ("id", "login", "type")
DECISION_REPOSITORY_KEYS = (
    "default_branch", "full_name", "id", "node_id", "private", "visibility",
)
BRANCH_PROTECTION_KEYS = (
    "allow_deletions", "allow_force_pushes", "authenticated_status", "enabled",
    "endpoint_requirement", "enforce_admins", "required_signatures", "url",
)
# Reading branch protection is an administration-scoped read. The delivery
# evidence must carry the server's own statement that the credential which
# performed it really held administration read, so a protection block that was
# never authenticated at the right scope can never stand in for one that was.
ADMINISTRATION_READ = "administration=read"
BRANCH_PROTECTION_ENABLED = ("enforce_admins", "required_signatures")
BRANCH_PROTECTION_DISABLED = ("allow_deletions", "allow_force_pushes")
REQUIRED_DECISION = "APPROVED"
REQUIRED_FINDINGS_COUNT = 0
REVIEWER_DECISION_KEYS = tuple(sorted((
    "activation_authorized", "base_commit", "canonical_diff_sha256",
    "candidate_owned", "decision", "document_type", "findings",
    "findings_count", "head_commit", "head_tree", "produced_after_candidate",
    "repository", "reviewer_authorization_sha256", "reviewer_profile",
    "reviewer_repository", "schema_version", "sole_parent",
)))
REVIEWER_DECISION_BOUND_FIELDS = (
    "base_commit", "canonical_diff_sha256", "head_commit", "head_tree",
    "repository", "reviewer_authorization_sha256", "sole_parent",
)
REVIEWER_DECISION_COPIED_FIELDS = (
    "activation_authorized", "candidate_owned", "decision", "findings",
    "findings_count", "produced_after_candidate", "reviewer_profile",
    "reviewer_repository",
)
REVIEWER_PROFILE = "acc-reviewer"
INDEPENDENT_REPOSITORY = "chrizzatsu/acc-authority-independent-review"
TRUST_RECORD_PATH = "reviewer-authorization-v2.json"
# F8-EXTERNAL-REVIEW-LIVE-AUTHENTICATION-INCOMPLETE
#
# Before a receipt may exist, the canonical repository identity, the
# exhaustively paginated run and job inventories with their Link closure, the
# exact head and tree, every required path and blob, the artifact id, name and
# recomputed digest and the token permission provenance must all authenticate
# from sealed read-only GitHub responses at a constant path.
SERVER_OBJECTS_FILE = "authenticated/server-objects.json"
SERVER_OBJECTS_KEYS = (
    "api_version", "artifacts", "head", "jobs", "repository", "token", "tree",
    "workflow_runs",
)
GITHUB_API_VERSION = "2022-11-28"
GITHUB_API_ROOT = "https://api.github.com"
SERVER_PAGE_KEYS = (
    "count", "link", "page", "per_page", "status", "total_count",
)
SERVER_PAGE_STATUS = 200
SERVER_PER_PAGE = 100
SERVER_REPOSITORY_KEYS = ("default_branch", "full_name", "id", "node_id")
SERVER_TOKEN_KEYS = (
    "account_login", "app_id", "app_slug", "endpoint_requirements",
    "grant_record_sha256", "installation_id", "installation_settings_url",
    "issuer", "permissions", "repositories", "repository_selection",
    "target_type", "token_issuance_endpoint",
)
REQUIRED_TOKEN_PERMISSIONS = {
    "actions": "read", "contents": "read", "metadata": "read",
}
REQUIRED_TOKEN_SELECTION = "selected"
# Only read levels may ever be granted to this lane. `metadata` is the
# documented read-only level GitHub publishes for the metadata scope.
READ_ONLY_GRANT_LEVELS = ("read",)
SERVER_JOB_KEYS = (
    "completed_at", "conclusion", "head_sha", "id", "name", "run_attempt",
    "run_id", "started_at", "status",
)
SERVER_ARTIFACT_KEYS = (
    "digest", "expired", "id", "name", "node_id", "size_in_bytes",
    "workflow_run",
)
SERVER_TREE_ENTRY_KEYS = ("blob_sha", "mode", "path", "sha256", "size")
SERVER_HEAD_KEYS = ("commit", "tree")
SOURCE_JOB_NAME = "export"
SOURCE_BOOTSTRAP_CONTRACT = "bootstrap-contract.json"
BLOB_MODE = "100644"
ARTIFACT_DIGEST_PREFIX = "sha256:"
MINIMUM_DIGEST_ENTROPY = 8
# Regenerated evidence is sealed read-only and its mode is read back.
SEALED_FILE_MODE = 0o444
# A caller-shaped identifier is a small, round or low-entropy number; a real
# GitHub object id is neither.
MINIMUM_CANONICAL_ID = 1_000_000
MAXIMUM_CANONICAL_ID = 2 ** 63 - 1
MINIMUM_ID_ENTROPY = 4
LINK_NEXT = 'rel="next"'
TERMINAL_COLLECTOR_PHASE = "terminal-readback-collector"
PHASES = (
    "bootstrap", "select", "server-objects", "chain", "deliver-decision",
    "deliver-commit",
    "decision-delivery", "external-review", TERMINAL_COLLECTOR_PHASE,
)
RUNS_PER_PAGE = 100
# The authorized run set is never a fixed page count: it comes from the one
# exhaustively captured traversal that terminates only where the server itself
# advertises no further page, and selection and receipt consume that same set.
MAX_AUTHORIZED_RUN_SET = RUNS_PER_PAGE * MAXIMUM_CAPTURED_PAGES
BRANCH_REF_PREFIX = "refs/heads/"
SOURCE_REF = "refs/heads/main"
SOURCE_TRIGGER = "workflow_dispatch"
RUN_SET_LABEL = "authorized protected-source run set"

AUTHORITY_COMMIT_FILE = "authenticated/authority-commit.json"
AUTHORITY_CHECKOUT = "authenticated/authority-checkout"
AUTHORITY_REMOTES = (
    "https://github.com/chrizzatsu/acc-attestation-authority",
    "https://github.com/chrizzatsu/acc-attestation-authority.git",
    "git@github.com:chrizzatsu/acc-attestation-authority.git",
    "ssh://git@github.com/chrizzatsu/acc-attestation-authority.git",
)
CRITICAL_ARTIFACT_PATHS = (
    "AUTHORITY-V2-SHA256SUMS",
    "authority-v2-policy.json",
    "protected-asset-receipt-v2.json",
    "reviewer-authorization-v2.json",
    "schemas/authority-v2-subject.schema.json",
)
CANDIDATE_FIELDS = {
    "artifact_sha256", "base_commit", "base_tree", "canonical_diff_sha256",
    "changed_path_manifest", "head_commit", "head_tree",
    "internal_manifest", "repository", "sole_parent",
}
INTERNAL_MANIFEST_PATH = "AUTHORITY-V2-SHA256SUMS"
AUTHORITY_REPOSITORY = "chrizzatsu/acc-attestation-authority"
UNAVAILABLE = "unavailable"
AUTHORIZED_PENDING_EVIDENCE = "authorized_pending_evidence"
READY = "ready"
AUTHORIZED_STATES = (AUTHORIZED_PENDING_EVIDENCE, READY)
LIVE_HEX40_FIELDS = (
    "authority_head_commit", "authority_head_tree",
    "certificate_github_workflow_sha", "independent_bootstrap_commit",
    "independent_bootstrap_tree", "run_head_sha", "source_bootstrap_commit",
    "source_bootstrap_tree",
)
LIVE_HEX64_FIELDS = (
    "artifact_content_sha256", "envelope_sha256", "review_receipt_sha256",
)
REVIEWED_HEX64_FIELDS = (
    "independent_validator_sha256", "independent_workflow_sha256",
    "source_helper_sha256", "source_workflow_sha256",
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TASK_ID = "t_c298fca4"
SOURCE_REPOSITORY = "chrizzatsu/acc-authority-protected-source"
SOURCE_WORKFLOW = ".github/workflows/export-kanban-review-v2.yml"
SOURCE_HELPER = "scripts/export_kanban_review_v2.py"
SOURCE_ARTIFACT = "authority-v2-review-t_c298fca4"
REQUIRED_SOURCE_PATHS = tuple(sorted(
    (SOURCE_WORKFLOW, SOURCE_HELPER, SOURCE_BOOTSTRAP_CONTRACT)
))
INDEPENDENT_WORKFLOW = ".github/workflows/review-authority-v2.yml"
INDEPENDENT_TERMINAL_COLLECTOR = (
    ".github/workflows/readback-authority-v2-activation.yml"
)
INDEPENDENT_VALIDATOR = "scripts/verify_kanban_review_v2.py"
TERMINAL_RUNTIME_DIGEST = (
    "sha256:2be5d3cb08aa616c6e38d922bd7072975166b2de772004f79ee1bae59fe983dc"
)
TERMINAL_RUNTIME_IMAGE = (
    "docker.io/library/python:3.13.7-slim@"
    + TERMINAL_RUNTIME_DIGEST
)
TERMINAL_RUNTIME_PATH = "/usr/local/bin"
TERMINAL_RUNTIME_EXECUTABLE = f"{TERMINAL_RUNTIME_PATH}/python3"
TERMINAL_RUNTIME_VERSION = (3, 13, 7)
TERMINAL_RUNTIME_EXECUTABLES = ("python3",)
TERMINAL_COSIGN_DIGEST = (
    "sha256:4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
)
TERMINAL_COSIGN_URL = (
    "https://github.com/sigstore/cosign/releases/download/v3.1.3/"
    "cosign-linux-amd64"
)
TERMINAL_COLLECTOR_MODE = (
    "digest-pinned-python-stdlib-no-authority-checkout"
)
TERMINAL_ACTIVATION_WORKFLOW_NAME = (
    "Sign exact protected Kanban Authority-v2 review"
)
TERMINAL_ACTIVATION_JOB_NAME = "generated-activation-evidence"
TERMINAL_ACTIVATION_ARTIFACT_NAME = (
    "authority-v2-generated-activation-evidence-t_c298fca4"
)
TERMINAL_CLEANUP_STEP_NAME = (
    "Reassert disabled state and delete ephemeral bytes"
)
TERMINAL_COLLECTOR_JOB_NAME = "terminal-readback"
TERMINAL_OUTPUT_MEMBERS = (
    "terminal-activation-readback.json",
    "terminal-activation-readback.sigstore.json",
)
TERMINAL_MAXIMUM_JSON_BYTES = 16 * 1024 * 1024
TERMINAL_MAXIMUM_ARTIFACT_BYTES = 64 * 1024 * 1024
TERMINAL_MAXIMUM_MEMBER_BYTES = 8 * 1024 * 1024
TERMINAL_MAXIMUM_COSIGN_BYTES = 256 * 1024 * 1024
TERMINAL_ARTIFACT_STORAGE_HOST_SUFFIXES = (
    ".blob.core.windows.net", ".actions.githubusercontent.com",
)
TERMINAL_SECRET_PATTERN = re.compile(
    rb"(?ix)([\"']?authorization[\"']?\s*[:=]\s*[\"']?\s*"
    rb"(?:bearer|basic)\s+[A-Za-z0-9._~+:/=-]+|"
    rb"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    rb"-----BEGIN[ ](?:[A-Z0-9]+[ ])*PRIVATE[ ]KEY-----|"
    rb"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    rb"[\"']?aws[\s_.-]*(?:access[\s_.-]*key[\s_.-]*id|"
    rb"secret[\s_.-]*access[\s_.-]*key|session[\s_.-]*token)"
    rb"[\"']?\s*[:=]\s*[\"']?\s*[A-Za-z0-9_./+=-]{16,})"
)
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
TERMINAL_ACTIVATION_ARTIFACT_FILES = (
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
TERMINAL_VERIFIER_PATHS = (
    "scripts/pin_source_chain_activation_v2.py",
    "scripts/sigstore_bundle_v03.py",
    "scripts/verify_source_chain_activation_v2.py",
)
RECEIPT_FIELDS = {
    "schema_version", "receipt_type", "reviewer_profile", "review_outcome",
    "approved", "findings_count", "findings", "release_authorized",
    "activation_authorized", "activation_findings", "candidate",
    "protected_identity_asset", "closure_matrix", "classifications",
    "source_execution_chain",
}
# F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE forces the final Authority decision.
REVIEW_OUTCOME = "ACTIVATION_ONLY"
FINAL_APPROVED = False
FINAL_RELEASE_AUTHORIZED = False
CLOSURE_KEYS = {f"F{number}" for number in range(1, 13)}
CLOSED_CLOSURES = tuple(f"F{number}" for number in range(1, 12))
OPEN_CLOSURES = ("F12",)
# F8 asserts that the authenticated source chain really exists. It stays open
# beside F12 until the activation state is `ready`, so no receipt producible
# before deterministically pinned live evidence can ever claim it.
LIVE_EVIDENCE_CLOSURE = "F8"
LIVE_EVIDENCE_FINDING = "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"
PREACTIVATION_OPEN_CLOSURES = (*OPEN_CLOSURES, LIVE_EVIDENCE_CLOSURE)
PREACTIVATION_CLOSED_CLOSURES = tuple(
    name for name in sorted(CLOSURE_KEYS)
    if name not in PREACTIVATION_OPEN_CLOSURES
)


def required_closures(state):
    """The exact closed/open partition this activation state may carry."""
    if state == READY:
        return CLOSED_CLOSURES, OPEN_CLOSURES
    return PREACTIVATION_CLOSED_CLOSURES, PREACTIVATION_OPEN_CLOSURES
FINDING_KEYS = ("closure", "finding")
ACTIVATION_FINDING = {
    "closure": LIVE_EVIDENCE_CLOSURE,
    "finding": LIVE_EVIDENCE_FINDING,
}
CHAIN_FIELDS = {
    "artifact_content_sha256", "authority_head_commit", "authority_head_tree",
    "authority_repository", "certificate_github_workflow_sha", "envelope_sha256",
    "independent_bootstrap_commit", "independent_bootstrap_tree",
    "independent_validator_sha256", "independent_workflow_sha256",
    "review_receipt_sha256", "reviewer_task_id", "run_attempt", "run_head_sha",
    "run_id", "source_bootstrap_commit", "source_bootstrap_tree",
    "source_helper_path", "source_helper_sha256", "source_repository",
    "source_workflow_path", "source_workflow_sha256",
}
SELF_REFERENTIAL_CHAIN_FIELDS = {
    "artifact_content_sha256", "envelope_sha256", "review_receipt_sha256",
}
RECEIPT_CHAIN_FIELDS = CHAIN_FIELDS - SELF_REFERENTIAL_CHAIN_FIELDS


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def _zip_member_type_is_regular(info):
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if info.create_system == ZIP_CREATOR_UNIX:
        return file_type == stat.S_IFREG
    if info.create_system in ZIP_NON_UNIX_CREATOR_SYSTEMS:
        return file_type in (0, stat.S_IFREG)
    return False


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def closed_json(data, label):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(type(key) is str and key not in result, f"{label} duplicate member")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit(f"{label} is not valid UTF-8 JSON") from error


def artifact_content_sha256(members):
    digest = hashlib.sha256(b"acc-authority-v2-protected-source-artifact\0")
    for name in sorted(members):
        encoded = name.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(members[name]).to_bytes(8, "big"))
        digest.update(members[name])
    return digest.hexdigest()


def expected_page_lengths(total):
    """The exact per-page counts a complete terminated pagination returns."""
    full, remainder = divmod(total, RUNS_PER_PAGE)
    lengths = [RUNS_PER_PAGE] * full
    if remainder or not lengths:
        lengths.append(remainder)
    return lengths


def complete_workflow_run_set(pages, label=RUN_SET_LABEL):
    """Every run of the sealed workflow, from an exhaustive bounded pagination.

    A truncated page, pages that disagree about the total, a run repeated on a
    later page and a run set larger than the bound are all refused, so the
    authorized run may only be chosen out of a provably complete set. Nothing
    here is caller selectable: the pages are constant-path files the workflow
    fills from authenticated reads.
    """
    require(
        type(pages) is list and pages
        and len(pages) <= MAXIMUM_CAPTURED_PAGES,
        f"{label} is not an exhaustively captured page set",
    )
    totals = set()
    lengths = []
    runs = []
    for number, page in enumerate(pages, start=1):
        require(type(page) is dict, f"{label} page {number} is malformed")
        total = page.get("total_count")
        require(
            type(total) is int and type(total) is not bool and total >= 0,
            f"{label} page {number} total count is absent or malformed",
        )
        entries = page.get("workflow_runs")
        require(type(entries) is list, f"{label} page {number} run list is malformed")
        totals.add(total)
        lengths.append(len(entries))
        runs.extend(entries)
    require(len(totals) == 1, f"{label} pages disagree about the run total")
    total = totals.pop()
    require(
        total <= MAX_AUTHORIZED_RUN_SET,
        f"{label} is larger than the bounded authorized pagination",
    )
    require(
        lengths == expected_page_lengths(total),
        f"{label} pagination is incomplete or collides on a later page",
    )
    identifiers = []
    for entry in runs:
        require(type(entry) is dict, f"{label} run entry is malformed")
        identifier = entry.get("id")
        require(
            type(identifier) is int and type(identifier) is not bool and identifier > 0,
            f"{label} run id is absent or malformed",
        )
        identifiers.append(identifier)
    require(
        len(set(identifiers)) == len(identifiers),
        f"{label} pagination repeats a run across pages",
    )
    return runs


def sealed_head_branch(ref, label=RUN_SET_LABEL):
    require(
        type(ref) is str and ref.startswith(BRANCH_REF_PREFIX)
        and len(ref) > len(BRANCH_REF_PREFIX),
        f"{label} sealed ref is not a branch ref",
    )
    return ref[len(BRANCH_REF_PREFIX):]


def sole_authorized_run(runs, run, head_sha, label=RUN_SET_LABEL):
    """Exactly one authorized attempt-1 run for the sealed workflow/ref/head.

    `head_sha` is None only while no live head is known yet, in which case the
    head is taken from the sole run the authenticated server reports. The run
    set must still hold exactly one run either way, so a second attempt-1
    `workflow_dispatch` and a later inserted successful run both fail closed
    instead of silently replacing the selected run and artifact chain.
    """
    head_branch = sealed_head_branch(SOURCE_REF, label)
    matching = [
        entry for entry in runs
        if entry.get("path") == run["source_workflow_path"]
        and type(entry.get("head_repository")) is dict
        and entry["head_repository"].get("full_name") == run["source_repository"]
        and entry.get("event") == SOURCE_TRIGGER
        and entry.get("head_branch") == head_branch
        and entry.get("run_attempt") == 1
        and (head_sha is None or entry.get("head_sha") == head_sha)
    ]
    require(
        len(matching) == 1,
        f"{label} must hold exactly one authorized attempt-1 run for the sealed "
        f"workflow, ref and head, but holds {len(matching)}, so the authorized "
        "protected-source run is additional or ambiguous",
    )
    require(
        len(runs) == 1,
        f"{label} holds {len(runs)} runs of the sealed workflow, so the "
        "authorized protected-source run is additional or ambiguous",
    )
    observed = matching[0]
    observed_head = observed.get("head_sha")
    require(
        type(observed_head) is str and HEX40.fullmatch(observed_head) is not None,
        f"{label} run head is absent or malformed",
    )
    sealed_id = run.get("run_id")
    require(
        sealed_id is None or sealed_id == observed["id"],
        f"{label} contradicts the sealed authorized run id",
    )
    sealed_head = run.get("run_head_sha")
    require(
        sealed_head is None or sealed_head == observed_head,
        f"{label} contradicts the sealed authorized run head",
    )
    return observed


def captured_workflow_run_pages(root):
    """The one exhaustively captured workflow-run traversal, as page bodies.

    Selection and receipt creation consume exactly this set, so the run the
    lane selects can never differ from the run the receipt binds.
    """
    endpoint = (
        f"{GITHUB_API_ROOT}/repos/{SOURCE_REPOSITORY}/actions/workflows"
        f"/{PurePosixPath(SOURCE_WORKFLOW).name}/runs"
    )
    return [
        page["capture"]["json"]
        for page in _captured_collection(
            root, RAW_RUNS_PREFIX, endpoint, RUN_SET_LABEL,
        )
    ]


def select_authorized_run(run, pages):
    """Select the sole authorized protected-source run, server-read only."""
    return sole_authorized_run(complete_workflow_run_set(pages), run, None)


# ---------------------------------------------------------------------------
# The independent lane re-derives the complete Authority candidate binding for
# itself, from the authenticated checkout the workflow materialised at a
# constant path. It never accepts the producer's word for the repository, the
# base, the head, the tree, the sole parent, the canonical binary full-index
# diff, the status-aware changed-path manifest with its modes, object ids and
# rename semantics, the tracked internal manifest or the critical artifacts.
# ---------------------------------------------------------------------------
def _git(root, *arguments):
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments], check=True, capture_output=True,
            env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(
            f"authenticated Authority checkout read failed: {' '.join(arguments)}"
        ) from error


def _git_text(root, *arguments):
    return _git(root, *arguments).decode("utf-8").strip()


def _candidate_path(raw):
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("Authority changed path is not UTF-8") from error
    pure = PurePosixPath(decoded)
    require(
        decoded and not pure.is_absolute() and str(pure) == decoded
        and all(part not in ("", ".", "..") for part in pure.parts)
        and all(ord(character) >= 32 for character in decoded),
        "Authority changed path is non-canonical",
    )
    return decoded


def candidate_changed_path_manifest(root, base, head):
    """Every changed path with status, similarity, modes, object ids and digests."""
    fields = _git(
        root, "diff", "--raw", "-z", "--full-index", "--no-ext-diff",
        "--no-abbrev", "--find-renames=50%", base, head, "--",
    ).split(b"\0")
    require(fields[-1] == b"", "Authority raw diff is not NUL terminated")
    fields.pop()
    header = re.compile(
        rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMDR])([0-9]{1,3})?"
    )
    entries = []
    index = 0
    while index < len(fields):
        match = header.fullmatch(fields[index])
        require(match is not None, "unsupported Git status in the Authority diff")
        old_mode, new_mode, old_oid, new_oid, status_raw, score = match.groups()
        index += 1
        require(index < len(fields), "Authority changed path is missing")
        first = _candidate_path(fields[index])
        index += 1
        status = status_raw.decode("ascii")
        if status == "R":
            require(index < len(fields) and score is not None,
                    "Authority rename destination or similarity is missing")
            second = _candidate_path(fields[index])
            index += 1
            old_path, new_path, similarity = first, second, int(score)
            require(50 <= similarity <= 100,
                    "Authority rename similarity is outside the canonical threshold")
        else:
            require(score is None, "Authority non-rename status carries a similarity")
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
            "old_sha256": hashlib.sha256(
                _git(root, "cat-file", "blob", old_oid)).hexdigest() if old_oid else None,
            "new_sha256": hashlib.sha256(
                _git(root, "cat-file", "blob", new_oid)).hexdigest() if new_oid else None,
        })
    return entries


CANONICAL_CANDIDATE_DIFF_ARGUMENTS = {
    "canonical-binary-full-index.diff": ("--binary", "--full-index"),
    "name-status-find-renames-50.z": ("--name-status", "-z"),
    "raw-full-index-find-renames-50.z": ("--raw", "-z", "--full-index"),
    "raw-status-authoritative.z": ("--raw", "-z"),
}


def candidate_diff_streams(root, base, head):
    """The four exact byte streams sealed into the external review."""
    return {
        name: _git(
            root, "diff", *leading, "--no-ext-diff", "--no-abbrev",
            "--find-renames=50%",
            "--src-prefix=a/", "--dst-prefix=b/", base, head, "--",
        )
        for name, leading in CANONICAL_CANDIDATE_DIFF_ARGUMENTS.items()
    }


def derive_candidate_binding(root, run):
    """Recompute the complete Authority candidate contract independently."""
    checkout = Path(root) / AUTHORITY_CHECKOUT
    require(
        checkout.is_dir() and not checkout.is_symlink(),
        "the authenticated Authority checkout is absent or unsafe",
    )
    base = run.get("authority_base_commit")
    base_tree = run.get("authority_base_tree")
    require(
        type(base) is str and HEX40.fullmatch(base) is not None
        and type(base_tree) is str and HEX40.fullmatch(base_tree) is not None,
        "the sealed contract does not pin the reviewed Authority base",
    )
    head = run["authority_head_commit"]
    require(
        _git_text(checkout, "remote", "get-url", "origin") in AUTHORITY_REMOTES,
        "Authority checkout origin identity mismatch",
    )
    require(
        _git(checkout, "status", "--porcelain=v1", "-z",
             "--untracked-files=all") == b"",
        "the authenticated Authority checkout is not exactly clean",
    )
    require(
        _git_text(checkout, "rev-parse", "HEAD") == head,
        "the authenticated Authority checkout is not at the authorized head",
    )
    require(
        _git_text(checkout, "rev-parse", f"{head}^{{tree}}")
        == run["authority_head_tree"],
        "the authenticated Authority checkout tree contradicts the authorized run",
    )
    require(
        _git_text(checkout, "rev-parse", f"{base}^{{tree}}") == base_tree,
        "the authenticated Authority base tree contradicts the sealed contract",
    )
    require(
        _git_text(checkout, "rev-list", "--parents", "-n", "1", head).split()
        == [head, base],
        "the Authority candidate is not an ordinary non-merge direct child",
    )
    streams = candidate_diff_streams(checkout, base, head)
    diff = streams["canonical-binary-full-index.diff"]
    manifest = candidate_changed_path_manifest(checkout, base, head)
    touched = set()
    for entry in manifest:
        paths = {value for value in (entry["old_path"], entry["new_path"]) if value}
        require(touched.isdisjoint(paths),
                "Authority changed-path manifest repeats a path")
        touched.update(paths)
    require(
        any(entry["new_path"] == INTERNAL_MANIFEST_PATH for entry in manifest),
        "the Authority candidate does not cover its own checksum manifest",
    )
    internal = _git(checkout, "show", f"{head}:{INTERNAL_MANIFEST_PATH}")
    try:
        internal_text = internal.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("Authority internal manifest is not UTF-8") from error
    require(internal_text.endswith("\n"),
            "Authority internal manifest lacks its final newline")
    return {
        "repository": AUTHORITY_REPOSITORY,
        "base_commit": base,
        "base_tree": base_tree,
        "head_commit": head,
        "head_tree": run["authority_head_tree"],
        "sole_parent": base,
        "candidate_diff_sha256": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in streams.items()
        },
        "canonical_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "changed_path_manifest": manifest,
        "internal_manifest": internal_text,
        "artifact_sha256": {
            path: hashlib.sha256(
                _git(checkout, "show", f"{head}:{path}")).hexdigest()
            for path in CRITICAL_ARTIFACT_PATHS
        },
    }


def authenticate_candidate_binding(root, run, candidate):
    """Fail closed unless the receipt carries exactly the derived binding."""
    require(type(candidate) is dict, "review candidate malformed")
    require(
        set(candidate) == CANDIDATE_FIELDS,
        "review candidate contract field set mismatch",
    )
    derived = derive_candidate_binding(root, run)
    for name in sorted(CANDIDATE_FIELDS):
        require(
            candidate[name] == derived[name],
            f"review candidate {name} is not the independently derived value",
        )
    return derived


def verify_terminal_readback_contract(contract):
    """Bind the only post-completion collector and its closed receipt lane."""
    terminal = contract.get("terminal_readback")
    require(type(terminal) is dict, "terminal readback contract is absent")
    require(
        tuple(sorted(terminal)) == tuple(sorted(TERMINAL_READBACK_KEYS)),
        "terminal readback contract field set mismatch",
    )
    collector = read_bytes(
        ROOT / INDEPENDENT_TERMINAL_COLLECTOR,
        "terminal readback collector workflow",
    )
    expected_identity = (
        f"https://github.com/{INDEPENDENT_REPOSITORY}/"
        f"{INDEPENDENT_TERMINAL_COLLECTOR}@refs/heads/main"
    )
    require(
        terminal["repository"] == INDEPENDENT_REPOSITORY
        and terminal["activation_workflow_path"] == INDEPENDENT_WORKFLOW
        and terminal["collector_workflow_path"] == INDEPENDENT_TERMINAL_COLLECTOR
        and terminal["collector_workflow_sha256"]
        == hashlib.sha256(collector).hexdigest()
        and terminal["collector_identity"] == expected_identity
        and terminal["trigger"] == "workflow_run"
        and type(terminal["run_attempt"]) is int
        and terminal["run_attempt"] == 1
        and terminal["caller_inputs"] == []
        and terminal["permissions"] == {
            "actions": "read", "contents": "read", "id-token": "write",
            "metadata": "read",
        },
        "terminal readback collector identity or permission mismatch",
    )
    verifier = terminal["collector_verifier"]
    validator = contract.get("validator")
    validator_sha256 = (
        validator.get("sha256") if type(validator) is dict else None
    )
    require(
        type(validator_sha256) is str
        and HEX64.fullmatch(validator_sha256) is not None,
        "terminal collector validator digest is absent",
    )
    expected_files = {
        "collector": f"sha256:{validator_sha256}",
        "cosign": TERMINAL_COSIGN_DIGEST,
        "python3": f"oci-manifest:{TERMINAL_RUNTIME_DIGEST}",
    }
    expected_runtime = {
        "executable_directory": TERMINAL_RUNTIME_PATH,
        "executables": list(TERMINAL_RUNTIME_EXECUTABLES),
        "image": TERMINAL_RUNTIME_IMAGE,
        "image_digest": TERMINAL_RUNTIME_DIGEST,
        "root_filesystem_read_only": True,
        "semantic_authority": "python-3.13.7-stdlib-only",
        "transitive_dependencies": (
            "bound-by-oci-manifest-config-and-layer-digests"
        ),
    }
    require(
        type(verifier) is dict
        and tuple(sorted(verifier)) == (
            "ambient_execution_forbidden", "entrypoint", "files",
            "head_tree_and_sole_parent_authenticated", "mode", "repository",
            "runtime",
        )
        and verifier["ambient_execution_forbidden"] is True
        and verifier["head_tree_and_sole_parent_authenticated"] is True
        and verifier["entrypoint"] == (
            f"{TERMINAL_RUNTIME_EXECUTABLE} -I -B"
        )
        and verifier["mode"] == TERMINAL_COLLECTOR_MODE
        and verifier["repository"] == AUTHORITY_REPOSITORY
        and type(verifier["files"]) is dict
        and verifier["files"] == expected_files
        and verifier["runtime"] == expected_runtime,
        "terminal collector verifier bytes are open or malformed",
    )
    require(
        terminal["activation_artifact_files"]
        == list(TERMINAL_ACTIVATION_ARTIFACT_FILES),
        "terminal generated artifact inventory is open or reordered",
    )
    fresh = terminal["fresh_provenance"]
    require(
        type(fresh) is dict
        and tuple(sorted(fresh)) == (
            "attestation_fields", "exact_fulcio_claims_required", "generator",
            "generator_binary_sha256", "generator_version",
            "pre_registered_bundle_digest_required", "rekor_generation",
            "rekor_log_key_algorithm", "signer", "timestamp",
        )
        and fresh["attestation_fields"] == [
            "generator", "generator_binary_sha256", "generator_platform",
            "generator_version", "rekor_generation",
            "rekor_log_key_algorithm", "route",
            "signer_signature_algorithm", "signing_window_end",
            "signing_window_start", "timestamp",
        ]
        and fresh.get("generator") == "cosign v3.1.3"
        and fresh.get("generator_version") == "v3.1.3"
        and fresh.get("generator_binary_sha256")
        == "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
        and fresh.get("rekor_generation") == "rekor-v2"
        and fresh.get("rekor_log_key_algorithm") == "PKIX_ED25519"
        and fresh.get("signer") == "ecdsa-p256-sha256/Fulcio"
        and fresh.get("timestamp") == "rfc3161"
        and fresh.get("exact_fulcio_claims_required") is True
        and fresh.get("pre_registered_bundle_digest_required") is False,
        "terminal fresh provenance contract is substituted",
    )
    for field in (
        "activation_record_digest_required", "artifact_archive_digest_recomputed",
        "artifact_content_digest_recomputed",
        "artifact_exactly_one_non_expired", "closed_receipt_required",
        "no_repository_or_content_mutation", "recursion_forbidden",
        "terminal_api_readback_required",
    ):
        require(terminal[field] is True, f"terminal readback {field} must be true")
    return terminal


def require_terminal_python_runtime(
        contract, *, executable=None, version=None, environment=None):
    """Accept only the OCI-bound interpreter; PATH has no authority."""
    verify_terminal_readback_contract(contract)
    observed_executable = sys.executable if executable is None else executable
    observed_version = sys.version_info[:3] if version is None else version
    observed_environment = os.environ if environment is None else environment
    require(
        observed_executable == TERMINAL_RUNTIME_EXECUTABLE,
        "terminal collector interpreter path mismatch",
    )
    require(
        tuple(observed_version) == TERMINAL_RUNTIME_VERSION,
        "terminal collector interpreter version mismatch",
    )
    require(type(observed_environment) is dict,
            "terminal collector environment is malformed")
    return True


def _terminal_value(payload, path, label):
    value = payload
    for member in path:
        require(type(value) is dict and member in value,
                f"{label} is absent")
        value = value[member]
    return value


def _terminal_positive_integer(value, label):
    require(type(value) is int and value > 0, f"{label} is not a positive integer")
    return value


def _terminal_environment_integer(environment, name):
    value = environment.get(name, "")
    require(re.fullmatch(r"[1-9][0-9]*", value) is not None,
            f"{name} is not a positive integer")
    return int(value)


def _terminal_epoch(value, label):
    require(type(value) is str and value.endswith("Z"),
            f"{label} is not a UTC timestamp")
    try:
        moment = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SystemExit(f"{label} is not a UTC timestamp") from error
    seconds = int(moment.timestamp())
    return _terminal_positive_integer(seconds, label)


def _terminal_write(path, data, label, mode=0o600):
    require(type(data) is bytes and data, f"{label} is empty")
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.exists() and not path.is_symlink(), f"{label} already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if path.exists() and not path.is_symlink():
            path.unlink()
        raise
    return path


def _terminal_response_bytes(request, maximum, label):
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            require(response.status == 200, f"{label} returned HTTP {response.status}")
            data = response.read(maximum + 1)
    except (urllib.error.URLError, TimeoutError) as error:
        raise SystemExit(f"{label} authenticated read failed") from error
    require(0 < len(data) <= maximum, f"{label} response size is invalid")
    return data


class _TerminalRefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Never carry an authenticated header across an implicit redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _terminal_exchange(request, maximum, label):
    opener = urllib.request.build_opener(_TerminalRefuseRedirects())
    try:
        response = opener.open(request, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, TimeoutError) as error:
        raise SystemExit(f"{label} read failed") from error
    try:
        data = response.read(maximum + 1)
        status = response.status
        headers = tuple(response.headers.items())
    finally:
        response.close()
    require(len(data) <= maximum, f"{label} response exceeds its size bound")
    return status, headers, data


def _terminal_api_request(path, token):
    require(type(path) is str and path.startswith("repos/") and ".." not in path,
            "terminal API path is unsafe")
    require(type(token) is str and token, "terminal API credential is absent")
    return urllib.request.Request(
        f"{GITHUB_API_ROOT}/{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "acc-authority-v2-terminal-collector",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
        method="GET",
    )


def _terminal_api_bytes(path, token, maximum=TERMINAL_MAXIMUM_JSON_BYTES):
    request = _terminal_api_request(path, token)
    status, _headers, data = _terminal_exchange(
        request, maximum, "terminal GitHub API",
    )
    require(status == 200 and data, f"terminal GitHub API returned HTTP {status}")
    return data


def _terminal_api_json(path, token, label):
    return closed_json(_terminal_api_bytes(path, token), label)


def _terminal_capture_json(raw_root, name, path, token, label):
    data = _terminal_api_bytes(path, token)
    payload = closed_json(data, label)
    _terminal_write(raw_root / name, canonical(payload), label)
    return payload


def _terminal_expected_page_lengths(total):
    full, remainder = divmod(total, 100)
    lengths = [100] * full
    if remainder or not lengths:
        lengths.append(remainder)
    return lengths


def _terminal_paginated_capture(raw_root, name, path, collection, token):
    pages = []
    expected_total = None
    for page_number in range(1, 101):
        payload = _terminal_api_json(
            f"{path}{'&' if '?' in path else '?'}per_page=100&page={page_number}",
            token,
            f"terminal {collection} page",
        )
        require(type(payload) is dict and set(payload) == {"total_count", collection},
                f"terminal {collection} page shape mismatch")
        total = payload["total_count"]
        require(type(total) is int and total >= 0,
                f"terminal {collection} total_count is malformed")
        expected_total = total if expected_total is None else expected_total
        require(total == expected_total,
                f"terminal {collection} pagination changed during capture")
        pages.append(payload)
        lengths = _terminal_expected_page_lengths(expected_total)
        if page_number == len(lengths):
            require([len(page[collection]) for page in pages] == lengths,
                    f"terminal {collection} pagination is incomplete")
            break
    else:
        require(False, f"terminal {collection} pagination exceeded its bound")
    _terminal_write(raw_root / name, canonical(pages), f"terminal {collection} pages")
    return pages


def _terminal_flatten(pages, collection, label):
    flattened = []
    for page in pages:
        values = page.get(collection) if type(page) is dict else None
        require(type(values) is list, f"{label} collection is malformed")
        flattened.extend(values)
    return flattened


def _terminal_require_environment(environment):
    activation_run_id = _terminal_environment_integer(environment, "ACTIVATION_RUN_ID")
    collector_run_id = _terminal_environment_integer(environment, "GITHUB_RUN_ID")
    require(environment.get("ACTIVATION_RUN_ATTEMPT") == "1"
            and environment.get("GITHUB_RUN_ATTEMPT") == "1",
            "terminal collector run attempt mismatch")
    head = environment.get("ACTIVATION_HEAD_SHA", "")
    require(HEX40.fullmatch(head) is not None and environment.get("GITHUB_SHA") == head,
            "terminal collector head mismatch")
    require(environment.get("GITHUB_REPOSITORY") == INDEPENDENT_REPOSITORY
            and environment.get("GITHUB_EVENT_NAME") == "workflow_run"
            and environment.get("GITHUB_REF") == "refs/heads/main",
            "terminal collector server environment mismatch")
    return activation_run_id, collector_run_id, head


def _terminal_prepare_root(environment):
    workspace = Path(environment.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink(),
            "terminal collector workspace is absent or unsafe")
    root = workspace / "terminal"
    require(not root.exists() and not root.is_symlink(),
            "terminal collector root already exists")
    for child in (root / "raw", root / "artifact", root / "output"):
        child.mkdir(mode=0o700, parents=True, exist_ok=False)
    return root


def _terminal_repository_facts(raw_root, token, repository, head):
    repo = _terminal_capture_json(
        raw_root, "repository.json", f"repos/{repository}", token,
        "terminal repository",
    )
    repository_id = _terminal_positive_integer(repo.get("id"), "repository id")
    require(repo.get("full_name") == repository and repo.get("default_branch") == "main",
            "terminal repository identity mismatch")
    branch = _terminal_capture_json(
        raw_root, "default-branch-commit.json", f"repos/{repository}/commits/main",
        token, "terminal default branch commit",
    )
    require(branch.get("sha") == head, "terminal default branch head mismatch")
    return repository_id


def _terminal_workflow_facts(raw_root, token, repository):
    workflow = _terminal_capture_json(
        raw_root, "activation-workflow.json",
        f"repos/{repository}/actions/workflows/review-authority-v2.yml",
        token, "terminal activation workflow",
    )
    workflow_id = _terminal_positive_integer(workflow.get("id"), "workflow id")
    require(workflow.get("path") == INDEPENDENT_WORKFLOW
            and workflow.get("name") == TERMINAL_ACTIVATION_WORKFLOW_NAME
            and workflow.get("state") == "disabled_manually",
            "terminal activation workflow state mismatch")
    return workflow_id


def _terminal_authenticate_activation_run(
        run, event, *, run_id, repository_id, workflow_id, repository, head):
    expected = {
        "id": run_id, "run_attempt": 1, "event": "workflow_run",
        "status": "completed", "conclusion": "success",
        "path": INDEPENDENT_WORKFLOW, "name": TERMINAL_ACTIVATION_WORKFLOW_NAME,
        "head_sha": head, "head_branch": "main", "workflow_id": workflow_id,
    }
    require(all(run.get(key) == value for key, value in expected.items())
            and _terminal_value(run, ("repository", "full_name"), "run repository")
            == repository
            and _terminal_value(run, ("repository", "id"), "run repository id")
            == repository_id
            and _terminal_value(run, ("head_repository", "full_name"),
                               "run head repository") == repository
            and _terminal_value(run, ("head_repository", "id"),
                               "run head repository id") == repository_id,
            "terminal activation run mismatch")
    event_run = _terminal_value(event, ("workflow_run",), "workflow_run event")
    for key in ("id", "run_attempt", "event", "status", "conclusion", "path",
                "head_sha", "head_branch", "workflow_id"):
        require(event_run.get(key) == expected[key], f"terminal event {key} mismatch")
    require(_terminal_value(event_run, ("repository", "full_name"),
                            "event repository") == repository
            and _terminal_value(event_run, ("head_repository", "full_name"),
                               "event head repository") == repository
            and _terminal_value(event, ("repository", "full_name"),
                               "event root repository") == repository,
            "terminal workflow_run repository mismatch")


def _terminal_select_activation_job(jobs, run_id, head):
    matches = [job for job in jobs if type(job) is dict
               and job.get("name") == TERMINAL_ACTIVATION_JOB_NAME]
    require(len(matches) == 1, "terminal activation job is not unique")
    job = matches[0]
    job_id = _terminal_positive_integer(job.get("id"), "activation job id")
    require(job.get("run_id") == run_id and job.get("run_attempt") == 1
            and job.get("head_sha") == head and job.get("status") == "completed"
            and job.get("conclusion") == "success",
            "terminal activation job mismatch")
    started = _terminal_epoch(job.get("started_at"), "activation job start")
    completed = _terminal_epoch(job.get("completed_at"), "activation job completion")
    require(started <= completed, "terminal activation job timeline is inverted")
    cleanup = [step for step in job.get("steps", []) if type(step) is dict
               and step.get("name") == TERMINAL_CLEANUP_STEP_NAME]
    require(len(cleanup) == 1, "terminal cleanup step is not unique")
    number = _terminal_positive_integer(cleanup[0].get("number"), "cleanup step number")
    require(cleanup[0].get("status") == "completed"
            and cleanup[0].get("conclusion") == "success",
            "terminal cleanup step did not succeed")
    return job, job_id, started, completed, number


def _terminal_select_artifact(
        artifacts, run_id, repository_id, repository, head):
    matches = [artifact for artifact in artifacts if type(artifact) is dict
               and artifact.get("name") == TERMINAL_ACTIVATION_ARTIFACT_NAME
               and artifact.get("expired") is False]
    require(len(matches) == 1, "terminal activation artifact is not unique")
    artifact = matches[0]
    artifact_id = _terminal_positive_integer(artifact.get("id"), "artifact id")
    url = f"{GITHUB_API_ROOT}/repos/{repository}/actions/artifacts/{artifact_id}"
    workflow_run = artifact.get("workflow_run")
    require(type(workflow_run) is dict
            and workflow_run.get("id") == run_id
            and workflow_run.get("repository_id") == repository_id
            and workflow_run.get("head_repository_id") == repository_id
            and workflow_run.get("head_sha") == head
            and workflow_run.get("head_branch") == "main"
            and artifact.get("url") == url
            and artifact.get("archive_download_url") == f"{url}/zip",
            "terminal activation artifact provenance mismatch")
    digest = artifact.get("digest")
    size = artifact.get("size_in_bytes")
    require(type(digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
            "terminal activation artifact digest is malformed")
    _terminal_positive_integer(size, "artifact size")
    return artifact, artifact_id, digest, size


def _terminal_collect_activation_facts(root, contract, environment, token):
    raw = root / "raw"
    run_id, collector_run_id, head = _terminal_require_environment(environment)
    event_path = Path(environment.get("GITHUB_EVENT_PATH", ""))
    require(event_path.is_file() and not event_path.is_symlink(),
            "terminal workflow_run event is absent or unsafe")
    event_data = event_path.read_bytes()
    require(0 < len(event_data) <= TERMINAL_MAXIMUM_JSON_BYTES,
            "terminal workflow_run event size is invalid")
    event = closed_json(event_data, "terminal workflow_run event")
    _terminal_write(raw / "workflow-run-event.json", canonical(event),
                    "terminal workflow_run event")
    repository = environment["GITHUB_REPOSITORY"]
    repository_id = _terminal_repository_facts(raw, token, repository, head)
    workflow_id = _terminal_workflow_facts(raw, token, repository)
    run = _terminal_capture_json(
        raw, "activation-run.json", f"repos/{repository}/actions/runs/{run_id}",
        token, "terminal activation run",
    )
    job_pages = _terminal_paginated_capture(
        raw, "activation-jobs.json",
        f"repos/{repository}/actions/runs/{run_id}/attempts/1/jobs",
        "jobs", token,
    )
    artifact_pages = _terminal_paginated_capture(
        raw, "activation-artifacts.json",
        f"repos/{repository}/actions/runs/{run_id}/artifacts",
        "artifacts", token,
    )
    _terminal_authenticate_activation_run(
        run, event, run_id=run_id, repository_id=repository_id,
        workflow_id=workflow_id, repository=repository, head=head,
    )
    job = _terminal_select_activation_job(
        _terminal_flatten(job_pages, "jobs", "activation jobs"), run_id, head,
    )
    artifact = _terminal_select_artifact(
        _terminal_flatten(artifact_pages, "artifacts", "activation artifacts"),
        run_id, repository_id, repository, head,
    )
    return {
        "artifact": artifact, "collector_run_id": collector_run_id,
        "contract": contract, "head": head, "job": job,
        "repository": repository, "repository_id": repository_id,
        "run": run, "run_id": run_id, "workflow_id": workflow_id,
    }


def _terminal_safe_zip_member(info, expected, observed, destination=None):
    name = info.filename
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise SystemExit("terminal artifact member name is not ASCII") from error
    require(name and "\x00" not in name and "\\" not in name
            and not name.startswith("/"),
            "terminal artifact member is unsafe or unexpected")
    segments = name.split("/")
    require(all(part not in ("", ".", "..") for part in segments),
            "terminal artifact member is unsafe or unexpected")
    normalized = unicodedata.normalize(
        "NFC", PurePosixPath(*segments).as_posix(),
    )
    require(normalized == name and "/" not in normalized and encoded
            and not info.is_dir()
            and _zip_member_type_is_regular(info)
            and info.flag_bits & 1 == 0,
            "terminal artifact member is unsafe or unexpected")
    require(name in expected,
            "terminal artifact member inventory carries an additional member")
    require(name not in observed,
            "terminal artifact repeats an archive member path")
    require(type(info.file_size) is int and type(info.file_size) is not bool
            and 0 <= info.file_size <= TERMINAL_MAXIMUM_MEMBER_BYTES,
            "terminal artifact member exceeds its size bound")
    if destination is not None:
        destination = Path(destination)
        require(destination.is_dir() and not destination.is_symlink(),
                "terminal artifact extraction root is unsafe")
        root = destination.resolve()
        require((root / normalized).resolve().parent == root,
                "terminal artifact member escapes its extraction root")
    return name


def _terminal_validated_zip_infos(archive, expected, destination=None):
    expected = tuple(sorted(expected))
    require(expected and len(expected) == len(set(expected)),
            "terminal artifact expected inventory is malformed")
    infos = archive.infolist()
    observed = {}
    total = 0
    for info in infos:
        name = _terminal_safe_zip_member(
            info, expected, observed, destination,
        )
        total += info.file_size
        require(total <= TERMINAL_MAXIMUM_ARTIFACT_BYTES,
                "terminal artifact exceeds its uncompressed size bound")
        observed[name] = info
    require(tuple(sorted(observed)) == expected,
            "terminal artifact inventory mismatch")
    return tuple((name, observed[name]) for name in expected), total


def _terminal_read_validated_zip(archive, expected, destination=None):
    infos, total = _terminal_validated_zip_infos(
        archive, expected, destination,
    )
    members = {}
    for name, info in infos:
        data = archive.read(info)
        require(len(data) == info.file_size,
                "terminal artifact member size mismatch")
        members[name] = data
    return members, total


def _terminal_generated_content_digest(members):
    digest = hashlib.sha256(b"acc-authority-v2-generated-activation-artifact\0")
    for name in sorted(members):
        encoded = name.encode("ascii")
        data = members[name]
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _terminal_extract_artifact(root, archive, expected_members):
    expected = tuple(sorted(expected_members))
    members = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as artifact_zip:
            members, total = _terminal_read_validated_zip(
                artifact_zip, expected, root / "artifact",
            )
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as error:
        raise SystemExit("terminal activation artifact is not a safe ZIP") from error
    for name in expected:
        _terminal_write(root / "artifact" / name, members[name],
                        f"terminal artifact member {name}")
    return members, total


def _terminal_storage_target(location):
    require(type(location) is str and location == location.strip(),
            "terminal artifact redirect target is absent or malformed")
    try:
        parsed = urllib.parse.urlsplit(location)
        port = parsed.port
    except ValueError as error:
        raise SystemExit("terminal artifact redirect target is malformed") from error
    host = parsed.hostname
    require(parsed.scheme == "https" and parsed.netloc
            and parsed.fragment == "" and type(host) is str and host
            and not host.endswith(".") and port is None and parsed.netloc == host,
            "terminal artifact redirect authority is not canonical HTTPS")
    require(any(host.endswith(suffix) and len(host) > len(suffix)
                for suffix in TERMINAL_ARTIFACT_STORAGE_HOST_SUFFIXES),
            "terminal artifact redirect is not approved GitHub storage")
    require(parsed.path.startswith("/") and len(parsed.path) > 1
            and ".." not in parsed.path and parsed.query,
            "terminal artifact redirect target is not immutable and canonical")
    try:
        parameters = urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True, strict_parsing=True,
        )
    except ValueError as error:
        raise SystemExit("terminal artifact redirect query is malformed") from error
    require(all(len(values) == 1 for values in parameters.values())
            and len(parameters.get("sig", [""])[0]) >= 16,
            "terminal artifact redirect carries no unique download signature")
    return location


def _terminal_download_artifact(path, token):
    request = _terminal_api_request(path, token)
    status, headers, _body = _terminal_exchange(
        request, TERMINAL_MAXIMUM_JSON_BYTES, "terminal artifact redirect",
    )
    locations = [value for name, value in headers if name.lower() == "location"]
    require(status == 302 and len(locations) == 1,
            "terminal artifact endpoint did not return one redirect")
    target = _terminal_storage_target(locations[0])
    storage_request = urllib.request.Request(
        target,
        headers={"Accept": "application/zip",
                 "User-Agent": "acc-authority-v2-terminal-collector"},
        method="GET",
    )
    forbidden = ("authorization", "x-github-api-version", "cookie")
    require(all(name.lower() not in forbidden
                and not name.lower().startswith("x-github")
                for name, _value in storage_request.header_items()),
            "terminal artifact storage request carries a credential")
    storage_status, _headers, archive = _terminal_exchange(
        storage_request, TERMINAL_MAXIMUM_ARTIFACT_BYTES,
        "terminal artifact storage",
    )
    require(storage_status == 200 and archive,
            f"terminal artifact storage returned HTTP {storage_status}")
    return archive


def _terminal_archive_identity(root, facts, token):
    artifact, artifact_id, digest, size = facts["artifact"]
    archive = _terminal_download_artifact(
        f"repos/{facts['repository']}/actions/artifacts/{artifact_id}/zip",
        token,
    )
    require(len(archive) == size, "terminal artifact archive size mismatch")
    archive_sha256 = hashlib.sha256(archive).hexdigest()
    require(f"sha256:{archive_sha256}" == digest,
            "terminal artifact archive digest mismatch")
    _terminal_write(root / "raw" / "generated-activation-artifact.zip", archive,
                    "terminal activation artifact archive")
    expected = facts["contract"]["generated_activation_evidence"]["artifact_files"]
    require(type(expected) is list and expected == sorted(expected),
            "terminal expected artifact inventory is malformed")
    members, total = _terminal_extract_artifact(root, archive, expected)
    record_digest = hashlib.sha256(members["activation-record.json"]).hexdigest()
    identity = {
        "activation_record_sha256": record_digest,
        "archive_sha256": archive_sha256,
        "content_sha256": _terminal_generated_content_digest(members),
        "file_count": len(members),
        "total_uncompressed_bytes": total,
    }
    _terminal_write(root / "raw" / "archive-identity.json", canonical(identity),
                    "terminal archive identity")
    return identity, members


def _terminal_authority_topology(root, facts, members, token):
    record = closed_json(members["activation-record.json"], "activation record")
    head = _terminal_value(record, ("candidate", "head"), "Authority head")
    tree = _terminal_value(record, ("candidate", "tree"), "Authority tree")
    require(type(head) is str and HEX40.fullmatch(head) is not None
            and type(tree) is str and HEX40.fullmatch(tree) is not None,
            "terminal Authority candidate identity is malformed")
    base = _terminal_value(
        facts["contract"], ("authorized_source_run", "authority_base_commit"),
        "authorized Authority base",
    )
    require(type(base) is str and HEX40.fullmatch(base) is not None,
            "authorized Authority base is malformed")
    commit = _terminal_capture_json(
        root / "raw", "authority-verifier-commit.json",
        f"repos/{AUTHORITY_REPOSITORY}/commits/{head}", token,
        "terminal Authority verifier commit",
    )
    parents = commit.get("parents")
    require(commit.get("sha") == head
            and _terminal_value(commit, ("commit", "tree", "sha"),
                               "Authority commit tree") == tree
            and type(parents) is list and len(parents) == 1,
            "terminal Authority candidate topology mismatch")
    parent = parents[0]
    expected_url = f"{GITHUB_API_ROOT}/repos/{AUTHORITY_REPOSITORY}/commits/{base}"
    require(type(parent) is dict and set(parent) == {"html_url", "sha", "url"}
            and parent.get("sha") == base and parent.get("url") == expected_url
            and parent.get("html_url")
            == f"https://github.com/{AUTHORITY_REPOSITORY}/commit/{base}",
            "terminal Authority candidate sole parent mismatch")
    return record


def _terminal_authenticate_activation_record(root, record, facts, identity):
    provenance = record.get("run_provenance")
    job_id = facts["job"][1]
    expected = {
        "run_id": facts["run_id"], "run_attempt": 1, "job_id": job_id,
        "job_name": TERMINAL_ACTIVATION_JOB_NAME, "sha": facts["head"],
        "activation_head_sha": facts["head"], "decision_sha": facts["head"],
    }
    require(type(provenance) is dict
            and all(provenance.get(key) == value for key, value in expected.items()),
            "terminal activation record provenance mismatch")
    record_path = root / "artifact" / "activation-record.json"
    require(hashlib.sha256(record_path.read_bytes()).hexdigest()
            == identity["activation_record_sha256"],
            "terminal activation record digest mismatch")


def _terminal_public_bytes(url, maximum, label):
    require(url == TERMINAL_COSIGN_URL, "terminal public dependency URL mismatch")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream",
                 "User-Agent": "acc-authority-v2-terminal-collector"},
        method="GET",
    )
    return _terminal_response_bytes(request, maximum, label)


def _terminal_install_cosign(environment):
    temporary = Path("/tmp")
    require(temporary.is_absolute() and temporary.is_dir()
            and not temporary.is_symlink(),
            "terminal temporary directory is absent or unsafe")
    directory = temporary / "authority-v2-cosign-v3.1.3"
    require(not directory.exists() and not directory.is_symlink(),
            "terminal Cosign directory already exists")
    directory.mkdir(mode=0o700)
    data = _terminal_public_bytes(
        TERMINAL_COSIGN_URL, TERMINAL_MAXIMUM_COSIGN_BYTES,
        "Cosign v3.1.3 release binary",
    )
    require(f"sha256:{hashlib.sha256(data).hexdigest()}" == TERMINAL_COSIGN_DIGEST,
            "Cosign v3.1.3 release binary digest mismatch")
    path = _terminal_write(directory / "cosign", data, "Cosign v3.1.3 binary",
                           mode=0o500)
    require(path.stat().st_mode & 0o777 == 0o500, "Cosign mode mismatch")
    return path


def _terminal_require_cosign(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(),
            "terminal Cosign binary is absent or unsafe")
    data = path.read_bytes()
    require(f"sha256:{hashlib.sha256(data).hexdigest()}" == TERMINAL_COSIGN_DIGEST,
            "terminal Cosign binary changed before execution")


def _terminal_run_cosign(path, arguments, environment):
    _terminal_require_cosign(path)
    home = Path(path).parent / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    cosign_environment = {
        **environment,
        "HOME": str(home),
        "PATH": "/authority-v2-no-ambient-tools",
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_CONFIG_HOME": str(home / "config"),
    }
    try:
        completed = subprocess.run(
            [str(path), *arguments], env=cosign_environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=300, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit("exact Cosign v3.1.3 execution failed") from error
    require(completed.returncode == 0, "exact Cosign v3.1.3 rejected its operation")


def _terminal_collector_facts(root, facts, token):
    repository = facts["repository"]
    run_id = facts["collector_run_id"]
    run = _terminal_capture_json(
        root / "raw", "collector-run.json",
        f"repos/{repository}/actions/runs/{run_id}", token,
        "terminal collector run",
    )
    pages = _terminal_paginated_capture(
        root / "raw", "collector-jobs.json",
        f"repos/{repository}/actions/runs/{run_id}/attempts/1/jobs",
        "jobs", token,
    )
    expected = {
        "id": run_id, "run_attempt": 1, "event": "workflow_run",
        "path": INDEPENDENT_TERMINAL_COLLECTOR, "head_branch": "main",
        "head_sha": facts["head"],
    }
    require(all(run.get(key) == value for key, value in expected.items())
            and _terminal_value(run, ("repository", "full_name"),
                               "collector repository") == repository
            and _terminal_value(run, ("head_repository", "full_name"),
                               "collector head repository") == repository,
            "terminal collector run mismatch")
    jobs = _terminal_flatten(pages, "jobs", "collector jobs")
    matches = [job for job in jobs if type(job) is dict
               and job.get("name") == TERMINAL_COLLECTOR_JOB_NAME]
    require(len(matches) == 1, "terminal collector job is not unique")
    job = matches[0]
    job_id = _terminal_positive_integer(job.get("id"), "collector job id")
    require(job.get("run_id") == run_id and job.get("run_attempt") == 1
            and job.get("head_sha") == facts["head"],
            "terminal collector job mismatch")
    started = _terminal_epoch(job.get("started_at"), "collector job start")
    signing_end = int(time.time()) + 300
    require(started <= signing_end and signing_end - started <= 86400,
            "terminal collector signing window is invalid")
    return job_id, started, signing_end


def _terminal_receipt(facts, identity, collector):
    artifact, artifact_id, digest, size = facts["artifact"]
    _job, job_id, started, completed, cleanup_number = facts["job"]
    collector_job_id, signing_start, signing_end = collector
    return {
        "activation_record_sha256": identity["activation_record_sha256"],
        "artifact": {
            "activation_record_sha256": identity["activation_record_sha256"],
            "archive_download_url": artifact["archive_download_url"],
            "archive_sha256": identity["archive_sha256"],
            "content_sha256": identity["content_sha256"],
            "digest": digest,
            "expired": False,
            "head_sha": facts["head"],
            "id": artifact_id,
            "matching_count": 1,
            "name": TERMINAL_ACTIVATION_ARTIFACT_NAME,
            "run_id": facts["run_id"],
            "size_in_bytes": size,
            "url": artifact["url"],
        },
        "attestation": {
            "generator": "cosign v3.1.3",
            "generator_binary_sha256": TERMINAL_COSIGN_DIGEST.removeprefix("sha256:"),
            "generator_platform": "linux/amd64",
            "generator_version": "v3.1.3",
            "rekor_generation": "rekor-v2",
            "rekor_log_key_algorithm": "PKIX_ED25519",
            "route": "cosign-v3.1.3-ed25519-rekor-v2-rfc3161",
            "signer_signature_algorithm": "ecdsa-p256-sha256",
            "signing_window_end": signing_end,
            "signing_window_start": signing_start,
            "timestamp": "rfc3161",
        },
        "cleanup": {
            "conclusion": "success",
            "number": cleanup_number,
            "path": INDEPENDENT_WORKFLOW,
            "result": "success",
            "state": "disabled_manually",
            "status": "completed",
            "step_name": TERMINAL_CLEANUP_STEP_NAME,
            "workflow_id": facts["workflow_id"],
        },
        "collector": {
            "event": "workflow_run",
            "job_id": collector_job_id,
            "ref": "refs/heads/main",
            "repository": facts["repository"],
            "run_attempt": 1,
            "run_id": facts["collector_run_id"],
            "sha": facts["head"],
            "workflow_path": INDEPENDENT_TERMINAL_COLLECTOR,
        },
        "contract": {
            "activation_artifact_name": TERMINAL_ACTIVATION_ARTIFACT_NAME,
            "activation_job_name": TERMINAL_ACTIVATION_JOB_NAME,
            "activation_workflow_path": INDEPENDENT_WORKFLOW,
            "artifact_content_digest_algorithm": (
                "sha256(acc-authority-v2-generated-activation-artifact\\0 || "
                "sorted(uint64be(len(name))||name||uint64be(len(bytes))||bytes))"
            ),
            "collector_workflow_path": INDEPENDENT_TERMINAL_COLLECTOR,
            "default_branch": "main",
            "default_branch_ref": "refs/heads/main",
            "repository": facts["repository"],
            "run_attempt": 1,
            "trigger_event": "workflow_run",
        },
        "job": {
            "completed_at": completed,
            "conclusion": "success",
            "head_sha": facts["head"],
            "id": job_id,
            "name": TERMINAL_ACTIVATION_JOB_NAME,
            "run_attempt": 1,
            "run_id": facts["run_id"],
            "started_at": started,
            "status": "completed",
        },
        "record_type": "acc-authority-v2-terminal-activation-readback",
        "run": {
            "conclusion": "success",
            "event": "workflow_run",
            "head_branch": "main",
            "head_sha": facts["head"],
            "id": facts["run_id"],
            "path": INDEPENDENT_WORKFLOW,
            "repository_id": facts["repository_id"],
            "run_attempt": 1,
            "status": "completed",
            "workflow_id": facts["workflow_id"],
        },
    }


def _terminal_sign_receipt(root, facts, identity, collector, cosign, environment):
    receipt_path = root / "output" / TERMINAL_OUTPUT_MEMBERS[0]
    bundle_path = root / "output" / TERMINAL_OUTPUT_MEMBERS[1]
    _terminal_write(receipt_path, canonical(_terminal_receipt(facts, identity, collector)),
                    "terminal activation receipt")
    _terminal_run_cosign(
        cosign,
        ["sign-blob", "--yes", "--signing-algorithm",
         "ecdsa-sha2-256-nistp256", "--bundle", str(bundle_path),
         str(receipt_path)],
        environment,
    )
    require(bundle_path.is_file() and not bundle_path.is_symlink()
            and 0 < bundle_path.stat().st_size <= TERMINAL_MAXIMUM_JSON_BYTES,
            "terminal Sigstore bundle is absent or unsafe")
    _terminal_run_cosign(
        cosign,
        ["verify-blob", "--bundle", str(bundle_path),
         "--certificate-identity",
         (f"https://github.com/{INDEPENDENT_REPOSITORY}/"
          f"{INDEPENDENT_TERMINAL_COLLECTOR}@refs/heads/main"),
         "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
         "--certificate-github-workflow-repository", INDEPENDENT_REPOSITORY,
         "--certificate-github-workflow-ref", "refs/heads/main",
         "--certificate-github-workflow-sha", facts["head"],
         "--certificate-github-workflow-trigger", "workflow_run",
         str(receipt_path)],
        environment,
    )


def _terminal_require_output_inventory(output_root):
    require(output_root.is_dir() and not output_root.is_symlink(),
            "terminal output root is absent or unsafe")
    observed = []
    for member in output_root.iterdir():
        require(member.name in TERMINAL_OUTPUT_MEMBERS,
                "unexpected terminal output member")
        require(member.is_file() and not member.is_symlink(),
                "terminal output member is not a regular file")
        data = member.read_bytes()
        require(data and TERMINAL_SECRET_PATTERN.search(data) is None,
                "secret-bearing terminal output member")
        member.chmod(0o444)
        require(stat.S_IMODE(member.stat().st_mode) == 0o444,
                "terminal output member mode mismatch")
        observed.append(member.name)
    require(tuple(sorted(observed)) == TERMINAL_OUTPUT_MEMBERS,
            "terminal output inventory is incomplete")
    output_root.chmod(0o555)
    require(stat.S_IMODE(output_root.stat().st_mode) == 0o555,
            "terminal output directory mode mismatch")


def collect_terminal_readback(contract, environment=None):
    """Collect and sign terminal facts with Python stdlib as sole authority."""
    observed_environment = dict(os.environ if environment is None else environment)
    require_terminal_python_runtime(contract, environment=observed_environment)
    token = observed_environment.get("GITHUB_TOKEN", "")
    root = _terminal_prepare_root(observed_environment)
    facts = _terminal_collect_activation_facts(
        root, contract, observed_environment, token,
    )
    identity, members = _terminal_archive_identity(root, facts, token)
    record = _terminal_authority_topology(root, facts, members, token)
    _terminal_authenticate_activation_record(root, record, facts, identity)
    cosign = _terminal_install_cosign(observed_environment)
    collector = _terminal_collector_facts(root, facts, token)
    _terminal_sign_receipt(
        root, facts, identity, collector, cosign, observed_environment,
    )
    _terminal_require_output_inventory(root / "output")
    return {"terminal_readback_collected": True}


def authorized_source_run(contract):
    require(
        type(contract) is dict
        and contract.get("contract") == "acc-authority-v2-independent-review-bootstrap",
        "independent review bootstrap contract identity mismatch",
    )
    verify_terminal_readback_contract(contract)
    run = contract.get("authorized_source_run")
    require(type(run) is dict, "authorized protected-source run is absent")
    require(
        run.get("selector") == "immutable-contract-pinned"
        and run.get("caller_selectable") is False
        and run.get("no_fallback") is True,
        "authorized protected-source run must not be caller selectable",
    )
    state = run.get("activation_state")
    require(state in AUTHORIZED_STATES,
            "authorized protected-source run is unavailable")
    if state == AUTHORIZED_PENDING_EVIDENCE:
        for key in (*LIVE_HEX40_FIELDS, *LIVE_HEX64_FIELDS, "run_id"):
            require(run.get(key) is None,
                    f"authorized protected-source run pre-pins live evidence {key}")
    else:
        for key in LIVE_HEX40_FIELDS:
            require(type(run.get(key)) is str and HEX40.fullmatch(run[key]) is not None,
                    f"authorized protected-source run {key} is unpinned")
        for key in LIVE_HEX64_FIELDS:
            require(type(run.get(key)) is str and HEX64.fullmatch(run[key]) is not None,
                    f"authorized protected-source run {key} is unpinned")
        require(type(run.get("run_id")) is int and type(run["run_id"]) is not bool
                and run["run_id"] > 0,
                "authorized protected-source run id is malformed")
    for key in REVIEWED_HEX64_FIELDS:
        require(type(run.get(key)) is str and HEX64.fullmatch(run[key]) is not None,
                f"reviewed protected-source blob binding {key} is unpinned")
    require(
        type(run.get("authority_base_commit")) is str
        and HEX40.fullmatch(run["authority_base_commit"]) is not None
        and type(run.get("authority_base_tree")) is str
        and HEX40.fullmatch(run["authority_base_tree"]) is not None,
        "authorized protected-source run does not pin the reviewed Authority base",
    )
    require(run.get("run_attempt") == 1, "authorized protected-source run attempt mismatch")
    require(run.get("source_repository") == SOURCE_REPOSITORY
            and run.get("source_workflow_path") == SOURCE_WORKFLOW
            and run.get("source_helper_path") == SOURCE_HELPER
            and run.get("artifact_name") == SOURCE_ARTIFACT
            and run.get("reviewer_task_id") == TASK_ID,
            "authorized protected-source run identity mismatch")
    return run


def resolve_live_run(run, *, bootstrap_commit, bootstrap_tree,
                     source_run_metadata, source_run_pages, source_commit,
                     authority_commit, envelope_data, receipt_data):
    """Bind every live identifier from authenticated server state, not from a caller.

    A sealed value that a later exact pinning already fixed must equal the
    authenticated value; a value still unpinned is supplied by this run's
    authenticated GitHub server state. Nothing here is caller selectable.
    """
    require(type(source_run_metadata) is dict,
            "protected-source run metadata is malformed")
    # The producer's own emitted chain states which run made these bytes. The
    # authenticated run metadata must agree with it exactly, so substituting a
    # different run, attempt or head can never be reconciled.
    produced = closed_json(receipt_data, "protected review receipt")
    require(type(produced) is dict, "protected review receipt is malformed")
    produced_chain = produced.get("source_execution_chain")
    require(type(produced_chain) is dict,
            "protected review receipt carries no source execution chain")
    run_id = produced_chain.get("run_id")
    head_sha = produced_chain.get("run_head_sha")
    require(type(run_id) is int and type(run_id) is not bool and run_id > 0,
            "produced protected-source run id is malformed")
    require(type(head_sha) is str and HEX40.fullmatch(head_sha) is not None,
            "produced protected-source run head is malformed")
    require(produced_chain.get("run_attempt") == 1,
            "produced protected-source run is not attempt 1")
    require(source_run_metadata.get("id") == run_id,
            "authenticated run metadata is not the run that produced these bytes")
    require(source_run_metadata.get("run_attempt") == 1,
            "authenticated protected-source run is not attempt 1")
    require(source_run_metadata.get("head_sha") == head_sha,
            "authenticated run head is not the head that produced these bytes")
    observed = sole_authorized_run(
        complete_workflow_run_set(source_run_pages), run, head_sha,
    )
    require(observed["id"] == run_id,
            "the only authorized protected-source run is not the run that "
            "produced these bytes")

    def commit_pair(payload, label):
        require(type(payload) is dict, f"{label} is malformed")
        sha = payload.get("sha")
        tree = payload.get("tree")
        require(type(sha) is str and HEX40.fullmatch(sha) is not None,
                f"{label} commit SHA is malformed")
        require(type(tree) is dict, f"{label} tree object is absent")
        tree_sha = tree.get("sha")
        require(type(tree_sha) is str and HEX40.fullmatch(tree_sha) is not None,
                f"{label} tree SHA is malformed")
        return sha, tree_sha

    source_sha, source_tree = commit_pair(source_commit, "authenticated source commit")
    authority_sha, authority_tree = commit_pair(
        authority_commit, "authenticated Authority candidate commit",
    )
    require(type(bootstrap_commit) is str
            and HEX40.fullmatch(bootstrap_commit) is not None
            and type(bootstrap_tree) is str
            and HEX40.fullmatch(bootstrap_tree) is not None,
            "authenticated independent bootstrap commit or tree is malformed")
    require(source_sha == head_sha,
            "authenticated source commit is not the authenticated run head")
    receipt_sha256 = hashlib.sha256(receipt_data).hexdigest()
    envelope_sha256 = hashlib.sha256(envelope_data).hexdigest()
    derived = {
        "artifact_content_sha256": artifact_content_sha256({
            "kanban-review-envelope.json": envelope_data,
            "preissuance-review-receipt.json": receipt_data,
        }),
        "authority_head_commit": authority_sha,
        "authority_head_tree": authority_tree,
        "certificate_github_workflow_sha": bootstrap_commit,
        "envelope_sha256": envelope_sha256,
        "independent_bootstrap_commit": bootstrap_commit,
        "independent_bootstrap_tree": bootstrap_tree,
        "review_receipt_sha256": receipt_sha256,
        "run_head_sha": head_sha,
        "run_id": run_id,
        "source_bootstrap_commit": source_sha,
        "source_bootstrap_tree": source_tree,
    }
    for field, value in derived.items():
        sealed = run.get(field)
        require(sealed is None or sealed == value,
                f"sealed {field} contradicts the authenticated server state")
    live = dict(run)
    live.update(derived)
    require(
        live["certificate_github_workflow_sha"] == live["independent_bootstrap_commit"],
        "certificate workflow SHA must equal the authenticated independent bootstrap commit",
    )
    require(live["source_bootstrap_commit"] == live["run_head_sha"],
            "source bootstrap commit must equal the authenticated run head SHA")
    return live


def verify_source_contract_state(contract, run, source_contract_data):
    """The protected lane must be in exactly the same activation state.

    The authenticated protected-source bootstrap contract is rehashed against
    the sealed digest, then every pinned binding and the activation state
    itself must agree with this contract. A null/ready contradiction on either
    side fails closed.
    """
    protected = contract.get("protected_source")
    require(type(protected) is dict, "protected source binding is absent")
    require(
        hashlib.sha256(source_contract_data).hexdigest()
        == protected.get("bootstrap_contract_sha256"),
        "authenticated protected-source bootstrap contract bytes are not the sealed bytes",
    )
    source_contract = closed_json(
        source_contract_data, "authenticated protected-source bootstrap contract",
    )
    require(
        type(source_contract) is dict
        and source_contract.get("contract")
        == "acc-authority-v2-protected-source-bootstrap",
        "authenticated protected-source bootstrap contract identity mismatch",
    )
    require(
        source_contract.get("repository") == run["source_repository"]
        and source_contract.get("workflow", {}).get("path")
        == run["source_workflow_path"]
        and source_contract.get("helper", {}).get("path")
        == run["source_helper_path"]
        and source_contract.get("workflow", {}).get("sha256")
        == run["source_workflow_sha256"]
        and source_contract.get("helper", {}).get("sha256")
        == run["source_helper_sha256"]
        and source_contract.get("reviewer_task_id") == run["reviewer_task_id"]
        and source_contract.get("artifact", {}).get("name") == run["artifact_name"],
        "authenticated protected-source bootstrap contract identity binding mismatch",
    )
    binding = source_contract.get("authority_binding")
    review = source_contract.get("protected_review_result")
    require(type(binding) is dict and type(review) is dict,
            "authenticated protected-source contract members are malformed")
    state = binding.get("activation_state")
    require(
        state in AUTHORIZED_STATES and review.get("activation_state") == state,
        "authenticated protected-source contract is not in an authorized state",
    )
    require(
        source_contract.get("repository_created") is (state == READY)
        and source_contract.get("workflow_dispatched") is (state == READY),
        "authenticated protected-source posture contradicts its activation state",
    )
    require(
        binding.get("authorized_run_attempt") == 1,
        "authenticated protected-source contract does not authorize attempt 1",
    )
    for field in (
        "independent_validator_sha256", "independent_workflow_sha256",
    ):
        require(
            binding.get(field) == run[field],
            f"authenticated protected-source binding {field} mismatch",
        )
    for field in (
        "authority_head_commit", "authority_head_tree",
        "independent_bootstrap_commit", "independent_bootstrap_tree",
        "source_bootstrap_commit", "source_bootstrap_tree",
    ):
        sealed = binding.get(field)
        require(
            sealed is None or sealed == run[field],
            f"authenticated protected-source binding {field} mismatch",
        )
    return source_contract


def expected_chain(run):
    return {
        "artifact_content_sha256": run["artifact_content_sha256"],
        "authority_head_commit": run["authority_head_commit"],
        "authority_head_tree": run["authority_head_tree"],
        "authority_repository": run["authority_repository"],
        "certificate_github_workflow_sha": run["certificate_github_workflow_sha"],
        "envelope_sha256": run["envelope_sha256"],
        "independent_bootstrap_commit": run["independent_bootstrap_commit"],
        "independent_bootstrap_tree": run["independent_bootstrap_tree"],
        "independent_validator_sha256": run["independent_validator_sha256"],
        "independent_workflow_sha256": run["independent_workflow_sha256"],
        "review_receipt_sha256": run["review_receipt_sha256"],
        "reviewer_task_id": run["reviewer_task_id"],
        "run_attempt": run["run_attempt"],
        "run_head_sha": run["run_head_sha"],
        "run_id": run["run_id"],
        "source_bootstrap_commit": run["source_bootstrap_commit"],
        "source_bootstrap_tree": run["source_bootstrap_tree"],
        "source_helper_path": run["source_helper_path"],
        "source_helper_sha256": run["source_helper_sha256"],
        "source_repository": run["source_repository"],
        "source_workflow_path": run["source_workflow_path"],
        "source_workflow_sha256": run["source_workflow_sha256"],
    }


def verify_reviewed_bootstrap_blobs(run, workflow_data, validator_data):
    """The reviewed independent blob bindings, checkable before any live run."""
    require(hashlib.sha256(workflow_data).hexdigest() == run["independent_workflow_sha256"],
            "executed independent review workflow bytes differ from the sealed bootstrap")
    require(hashlib.sha256(validator_data).hexdigest() == run["independent_validator_sha256"],
            "executed independent review validator bytes differ from the sealed bootstrap")


def verify_bootstrap_bytes(run, workflow_data, validator_data, bootstrap_commit, bootstrap_tree):
    require(hashlib.sha256(workflow_data).hexdigest() == run["independent_workflow_sha256"],
            "executed independent review workflow bytes differ from the sealed bootstrap")
    require(hashlib.sha256(validator_data).hexdigest() == run["independent_validator_sha256"],
            "executed independent review validator bytes differ from the sealed bootstrap")
    require(type(bootstrap_commit) is str and bootstrap_commit == run["independent_bootstrap_commit"],
            "this run head is not the pinned independent bootstrap commit")
    require(type(bootstrap_tree) is str and HEX40.fullmatch(bootstrap_tree) is not None,
            "bootstrap tree SHA is missing or malformed")
    require(bootstrap_tree == run["independent_bootstrap_tree"],
            "authenticated bootstrap tree does not match the pinned independent bootstrap tree")


def verify_source_bytes(run, metadata, workflow_data, helper_data, source_commit_data):
    require(type(metadata) is dict, "protected-source run metadata is malformed")
    require(metadata.get("id") == run["run_id"]
            and metadata.get("run_attempt") == run["run_attempt"]
            and metadata.get("head_sha") == run["run_head_sha"]
            and metadata.get("path") == run["source_workflow_path"]
            and metadata.get("event") == "workflow_dispatch"
            and metadata.get("head_branch") == "main"
            and metadata.get("conclusion") == "success",
            "observed protected-source run is not the contract-pinned authorized run")
    head_repository = metadata.get("head_repository")
    require(type(head_repository) is dict
            and head_repository.get("full_name") == run["source_repository"],
            "protected-source run repository mismatch")
    require(hashlib.sha256(workflow_data).hexdigest() == run["source_workflow_sha256"],
            "executed protected-source workflow bytes differ from the sealed bootstrap")
    require(hashlib.sha256(helper_data).hexdigest() == run["source_helper_sha256"],
            "executed protected-source helper bytes differ from the sealed bootstrap")
    require(type(source_commit_data) is dict, "source commit data is required for tree verification")
    authenticated_sha = source_commit_data.get("sha")
    require(type(authenticated_sha) is str and HEX40.fullmatch(authenticated_sha) is not None,
            "source commit data SHA is missing or malformed")
    require(authenticated_sha == run["run_head_sha"],
            "authenticated source commit SHA does not match the pinned run head")
    source_tree_obj = source_commit_data.get("tree")
    require(type(source_tree_obj) is dict, "source commit data tree object is missing")
    source_tree = source_tree_obj.get("sha")
    require(type(source_tree) is str and HEX40.fullmatch(source_tree) is not None,
            "source commit data tree SHA is missing or malformed")
    require(source_tree == run["source_bootstrap_tree"],
            "authenticated source tree does not match the pinned source bootstrap tree")


def verify_activation_only_decision(receipt, state):
    """Re-derive the only decision the sealed chain may carry at this state.

    Final Authority approval and release authorization stay false and closure
    F12 stays open. A receipt asserting `release_authorized=true` or a closed
    F12 while exclusive publication is unavailable is a contradiction and
    rejects, and so is a receipt closing F8 before the activation state is
    `ready` with every live field pinned. The strictly distinct activation-only
    decision authorizes nothing beyond the exact acc-releaser activation.
    """
    closed_closures, open_closures = required_closures(state)
    require(
        receipt.get("review_outcome") == REVIEW_OUTCOME,
        "review outcome is not the activation-only decision",
    )
    require(
        receipt.get("approved") is FINAL_APPROVED
        and receipt.get("release_authorized") is FINAL_RELEASE_AUTHORIZED,
        "review result claims final Authority approval or release authorization",
    )
    closure = receipt.get("closure_matrix")
    require(
        type(closure) is dict and set(closure) == CLOSURE_KEYS
        and all(type(value) is bool for value in closure.values()),
        "review closure matrix mismatch",
    )
    for name in closed_closures:
        require(closure[name] is True, f"review closure {name} is not closed")
    for name in open_closures:
        require(
            closure[name] is False,
            f"review closure {name} may not be closed at activation state {state}",
        )
    findings = receipt.get("findings")
    require(
        type(findings) is list and findings,
        "review result must record its open closures as findings",
    )
    observed = []
    for entry in findings:
        require(
            type(entry) is dict and tuple(sorted(entry)) == FINDING_KEYS,
            "review finding is malformed",
        )
        require(
            type(entry["finding"]) is str and entry["finding"],
            "review finding text is absent",
        )
        observed.append(entry["closure"])
    require(
        sorted(observed) == sorted(name for name, value in closure.items() if not value),
        "review findings do not match the open closures exactly",
    )
    require(
        type(receipt.get("findings_count")) is int
        and type(receipt.get("findings_count")) is not bool
        and receipt["findings_count"] == len(findings),
        "review findings count mismatch",
    )
    if state == READY:
        require(
            receipt.get("activation_authorized") is True,
            "review result does not authorize the exact activation",
        )
        require(
            type(receipt.get("activation_findings")) is list
            and receipt["activation_findings"] == [],
            "review activation findings must be exactly zero",
        )
    else:
        require(
            receipt.get("activation_authorized") is False,
            "a pre-activation receipt may never authorize the activation",
        )
        require(
            receipt.get("activation_findings") == [ACTIVATION_FINDING],
            "a pre-activation receipt must record the exact activation finding",
        )


# ---------------------------------------------------------------------------
# The external post-candidate activation review this lane produces
#
# Only after the exact Authority candidate exists can a reviewer bind it. The
# reviewer recomputes every binding from the authenticated Authority checkout,
# records a literal APPROVED decision with an integer zero finding count, and
# emits canonical immutable bytes the Authority side re-verifies against the
# exact clean checkout before any activation is authorized.
# ---------------------------------------------------------------------------
def _tracked_paths(checkout, head):
    raw = _git(checkout, "ls-tree", "-r", "-z", "--full-tree", head)
    tracked = {}
    for entry in (item for item in raw.split(b"\0") if item):
        meta, _, path_raw = entry.partition(b"\t")
        mode, kind, oid = meta.split(b" ")
        require(kind == b"blob", "reviewed tree carries a non-blob entry")
        require(re.fullmatch(rb"[0-7]{6}", mode) is not None,
                "reviewed tree entry mode is malformed")
        path = _candidate_path(path_raw)
        require(path not in tracked, "reviewed tree has a duplicate path")
        tracked[path] = hashlib.sha256(
            _git(checkout, "cat-file", "blob", oid.decode("ascii"))
        ).hexdigest()
    return tracked


# Every canonical live identifier the external activation review depends on.
# The sealed contract leaves each of them null before a run exists, so carrying
# a sealed null head or tree into a receipt is exactly the failure this guard
# refuses.
RESOLVED_LIVE_HEX40_FIELDS = (
    "authority_head_commit", "authority_head_tree", "certificate_github_workflow_sha",
    "independent_bootstrap_commit", "independent_bootstrap_tree", "run_head_sha",
    "source_bootstrap_commit", "source_bootstrap_tree",
)
RESOLVED_LIVE_HEX64_FIELDS = (
    "artifact_content_sha256", "envelope_sha256", "review_receipt_sha256",
)


def require_resolved_live_state(live):
    """Refuse any unresolved or sealed-null live state before a receipt exists.

    The external activation review binds the canonical live repository, run,
    job, head, tree, path, blob and artifact state. Every one of those must
    already have been resolved from authenticated GitHub server state and
    verified; a value that is still the sealed null placeholder, or that is not
    a canonical identifier, can never be written into a receipt.
    """
    require(type(live) is dict, "resolved live activation state is malformed")
    for field in RESOLVED_LIVE_HEX40_FIELDS:
        value = live.get(field)
        require(
            value is not None,
            f"the external activation review may not carry sealed null {field}",
        )
        require(
            type(value) is str and HEX40.fullmatch(value) is not None,
            f"resolved live {field} is not a canonical object name",
        )
    for field in RESOLVED_LIVE_HEX64_FIELDS:
        value = live.get(field)
        require(
            value is not None,
            f"the external activation review may not carry sealed null {field}",
        )
        require(
            type(value) is str and HEX64.fullmatch(value) is not None,
            f"resolved live {field} is not a canonical digest",
        )
    run_id = live.get("run_id")
    require(
        type(run_id) is int and type(run_id) is not bool and run_id > 0,
        "the external activation review may not carry an unresolved run id",
    )
    require(
        live.get("run_attempt") == 1,
        "the external activation review may only bind the authorized attempt 1",
    )
    for field, expected in (
        ("source_repository", SOURCE_REPOSITORY),
        ("source_workflow_path", SOURCE_WORKFLOW),
        ("source_helper_path", SOURCE_HELPER),
        ("artifact_name", SOURCE_ARTIFACT),
        ("authority_repository", AUTHORITY_REPOSITORY),
    ):
        require(
            live.get(field) == expected,
            f"resolved live {field} is not the sealed canonical value",
        )
    return live


def external_review_bindings(root, run):
    """Every binding the external activation review must carry, from Git alone."""
    derived = derive_candidate_binding(root, run)
    checkout = Path(root) / AUTHORITY_CHECKOUT
    tracked = _tracked_paths(checkout, derived["head_commit"])
    trust = tracked.get(TRUST_RECORD_PATH)
    require(
        type(trust) is str,
        f"the reviewed checkout does not track {TRUST_RECORD_PATH}",
    )
    return {
        "base_commit": derived["base_commit"],
        "base_tree": derived["base_tree"],
        "candidate_diff_sha256": derived["candidate_diff_sha256"],
        "canonical_diff_sha256": derived["canonical_diff_sha256"],
        "changed_path_manifest": derived["changed_path_manifest"],
        "critical_artifact_sha256": {
            path: tracked[path]
            for path in CRITICAL_ARTIFACT_PATHS if path in tracked
        },
        "head_commit": derived["head_commit"],
        "head_tree": derived["head_tree"],
        "repository": AUTHORITY_REPOSITORY,
        "reviewer_authorization_path": TRUST_RECORD_PATH,
        "reviewer_authorization_sha256": trust,
        "sole_parent": derived["sole_parent"],
        "tracked_paths_sha256": tracked,
    }


# ---------------------------------------------------------------------------
# Canonical server-object hygiene shared by the delivery and provenance checks
# ---------------------------------------------------------------------------
def _exact_members(payload, keys, label):
    require(
        type(payload) is dict and tuple(sorted(payload)) == tuple(sorted(keys)),
        f"{label} field set mismatch",
    )
    return payload


def _required_members(payload, keys, label):
    """Every consumed field must be present; real extra fields are fine.

    Real GitHub bodies carry many more fields than any one lane consumes, and
    the set grows over time. Refusing a genuine response for carrying its own
    documented fields is not a security property - it just means the lane can
    never run against the real API. What must never be relaxed is the other
    direction: every field this lane goes on to read has to be there.
    """
    require(type(payload) is dict and payload, f"{label} body is malformed")
    missing = [key for key in sorted(keys) if key not in payload]
    require(
        not missing,
        f"{label} omits required field(s): {', '.join(missing)}",
    )
    return payload


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


def _git_blob_oid(data):
    """The Git object name of a blob, recomputed rather than believed."""
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _positive_int(value, label):
    require(
        type(value) is int and type(value) is not bool and value > 0,
        f"{label} is absent or malformed",
    )
    return value


def _decoded_content(payload, label):
    """Decode one authenticated contents read and recompute its object name."""
    require(payload["encoding"] == "base64", f"{label} encoding is not base64")
    content = payload["content"]
    require(type(content) is str and content, f"{label} content is absent")
    try:
        data = base64.b64decode(content, validate=True)
    except ValueError as error:
        raise SystemExit(f"{label} content is not exact base64") from error
    require(
        base64.b64encode(data).decode("ascii") == content,
        f"{label} content is not canonical base64",
    )
    sha = payload["sha"]
    require(
        type(sha) is str and HEX40.fullmatch(sha) is not None,
        f"{label} blob object name is malformed",
    )
    require(
        _git_blob_oid(data) == sha,
        f"{label} blob object name is not the Git object name of its bytes",
    )
    size = payload["size"]
    require(
        type(size) is int and type(size) is not bool and size == len(data),
        f"{label} size does not match its bytes",
    )
    return data, sha


def authenticate_decision_delivery(root, bindings, run, decision_data):
    """Authenticate the sealed post-candidate reviewer decision delivery.

    A decision file lying in the checkout proves nothing. This authenticates
    the writer identity, the exact path this lane derived for itself, the
    delivery commit, tree and blob, the protection of the delivery branch and
    an independent readback that reproduces the exact bytes on disk. Every
    input is a constant path the workflow filled from an authenticated
    read-only GitHub read; none of it is caller selectable.
    """
    label = "reviewer decision delivery"
    document = closed_json(
        read_bytes(Path(root) / DECISION_DELIVERY_FILE, label), label,
    )
    _exact_members(document, DECISION_DELIVERY_KEYS, label)
    operation = _exact_members(
        document["operation"], DELIVERY_OPERATION_KEYS,
        f"{label} operation",
    )
    # The path is derived here, never read out of the evidence.
    derived_path = (
        f"{REVIEWER_DECISION_DIRECTORY}/{bindings['head_commit']}.json"
    )

    # --- the reviewer's own repository, canonically identified -----------
    repository = _exact_members(
        document["repository"], DECISION_REPOSITORY_KEYS, f"{label} repository",
    )
    require(
        repository["full_name"] == INDEPENDENT_REPOSITORY
        and repository["full_name"] != AUTHORITY_REPOSITORY,
        f"{label} is not the independent reviewer's own repository",
    )
    repository_id = _canonical_identifier(
        repository["id"], f"{label} repository id",
    )
    require(
        type(repository["node_id"]) is str and repository["node_id"],
        f"{label} repository node id is absent",
    )
    require(
        repository["default_branch"] == DECISION_DELIVERY_BRANCH,
        f"{label} default branch is not the protected delivery branch",
    )
    # The activation package and the pinning helper both pin this repository
    # as a public, non-archived reviewer repository; requiring the opposite
    # here would make the delivery path unreachable in production.
    require(
        repository["private"] is False and repository["visibility"] == "public",
        f"{label} repository posture is not the sealed reviewer posture",
    )

    # --- the writer, authenticated as the real reviewer identity ---------
    bootstrap_commit = run.get("independent_bootstrap_commit")
    bootstrap_tree = run.get("independent_bootstrap_tree")
    require(
        type(bootstrap_commit) is str
        and HEX40.fullmatch(bootstrap_commit) is not None
        and type(bootstrap_tree) is str
        and HEX40.fullmatch(bootstrap_tree) is not None,
        f"{label} cannot bind an unresolved independent bootstrap head",
    )
    commit = _exact_members(
        document["commit"], DECISION_COMMIT_KEYS, f"{label} commit",
    )
    # The delivery commit is a NEW commit (child of the bootstrap commit),
    # not the bootstrap commit itself. Its SHA and tree come from the
    # evidence; the parent relationship is what binds it to the bootstrap.
    delivery_sha = commit["sha"]
    require(
        type(delivery_sha) is str
        and HEX40.fullmatch(delivery_sha) is not None
        and delivery_sha != bootstrap_commit,
        f"{label} delivery commit is absent or is the bootstrap commit itself",
    )
    tree = commit["tree"]
    delivery_tree = tree.get("sha") if type(tree) is dict else None
    require(
        type(tree) is dict and tuple(sorted(tree)) == ("sha",)
        and type(delivery_tree) is str
        and HEX40.fullmatch(delivery_tree) is not None,
        f"{label} delivery commit tree is malformed",
    )
    writers = []
    for role in ("author", "committer"):
        actor = _exact_members(
            commit[role], DECISION_ACTOR_KEYS, f"{label} {role}",
        )
        require(
            actor["login"] == DECISION_WRITER_LOGIN,
            f"{label} {role} is not the authorized independent reviewer",
        )
        require(
            actor["type"] == DECISION_WRITER_TYPE,
            f"{label} {role} is not a real reviewer identity",
        )
        writers.append(_canonical_identifier(actor["id"], f"{label} {role} id"))
    require(len(set(writers)) == 1, f"{label} author and committer disagree")
    verification = commit["verification"]
    require(
        type(verification) is dict
        and verification.get("verified") is True
        and verification.get("reason") == "valid",
        f"{label} commit signature is not verified",
    )
    parents = commit["parents"]
    require(
        type(parents) is list
        and len(parents) == 1
        and type(parents[0]) is str
        and HEX40.fullmatch(parents[0]) is not None
        and parents[0] == bootstrap_commit,
        f"{label} delivery commit sole parent is not the authenticated "
        "bootstrap commit",
    )

    # --- the delivery branch really is protected -------------------------
    protection = _exact_members(
        document["branch_protection"], BRANCH_PROTECTION_KEYS,
        f"{label} branch protection",
    )
    require(
        protection["url"] == f"{GITHUB_API_ROOT}/repos/{INDEPENDENT_REPOSITORY}"
        f"/branches/{DECISION_DELIVERY_BRANCH}/protection",
        f"{label} branch protection was read for another repository or branch",
    )
    require(
        protection["enabled"] is True,
        f"{label} branch is not protected",
    )
    # The branch-protection endpoint is administration scoped: GitHub answers
    # a credential without administration read with 404, never with the
    # protection block. The authenticated HTTP 200 the composition required is
    # therefore the real proof that the reading credential held that grant.
    # The endpoint requirement header is recorded beside it as what the
    # endpoint asks for, never as the grant itself.
    require(
        protection["authenticated_status"] == SERVER_PAGE_STATUS,
        f"{label} branch protection was not an authenticated "
        f"HTTP {SERVER_PAGE_STATUS} administration-scoped read",
    )
    require(
        type(protection["endpoint_requirement"]) is str
        and ADMINISTRATION_READ in [
            element.strip()
            for element in re.split(r"[;,]", protection["endpoint_requirement"])
        ],
        f"{label} branch protection endpoint requirement is not "
        f"{ADMINISTRATION_READ}",
    )
    for field in BRANCH_PROTECTION_ENABLED:
        member = protection[field]
        require(
            type(member) is dict and member.get("enabled") is True,
            f"{label} branch protection does not enforce {field}",
        )
    for field in BRANCH_PROTECTION_DISABLED:
        member = protection[field]
        require(
            type(member) is dict and member.get("enabled") is False,
            f"{label} branch protection still permits {field}",
        )

    # --- the delivered blob, at exactly the derived path ------------------
    blob = _exact_members(document["blob"], DECISION_BLOB_KEYS, f"{label} blob")
    require(blob["type"] == "file", f"{label} blob is not a regular file")
    require(
        blob["path"] == derived_path,
        f"{label} blob is not at the internally derived decision path",
    )
    require(
        blob["url"] == f"{GITHUB_API_ROOT}/repos/{INDEPENDENT_REPOSITORY}"
        f"/contents/{derived_path}?ref={delivery_sha}",
        f"{label} blob was not read at the authenticated delivery commit",
    )
    delivered, blob_sha = _decoded_content(blob, f"{label} blob")
    require(
        delivered == decision_data,
        f"{label} blob is not the decision bytes this lane read",
    )
    # The authenticated writer must really have introduced or changed exactly
    # this blob at exactly this path in exactly this commit. Authenticating
    # the commit author alone proves nothing about who wrote the decision.
    files = commit["files"]
    require(type(files) is list and files, f"{label} commit changes no file")
    # The complete parent-to-commit difference, not a sample of it: a delivery
    # that also touched a workflow, a validator or any other path is refused
    # outright rather than accepted because the decision path happens to be
    # among its changes.
    require(
        len(files) == 1,
        f"{label} commit does not change exactly one path: it changes "
        f"{len(files)}",
    )
    introduced = []
    for entry in files:
        _exact_members(entry, DECISION_COMMIT_FILE_KEYS, f"{label} commit file")
        if entry["filename"] != derived_path:
            continue
        require(
            entry["status"] in DECISION_INTRODUCING_STATUSES,
            f"{label} commit did not introduce or change the decision path",
        )
        require(
            entry["sha"] == blob_sha,
            f"{label} commit did not write the delivered decision blob",
        )
        introduced.append(entry)
    require(
        len(introduced) == 1,
        f"{label} commit does not carry exactly one change to the internally "
        "derived decision path",
    )

    # --- one independent readback of the same immutable object -----------
    readback = _exact_members(
        document["readback"], DECISION_READBACK_KEYS, f"{label} readback",
    )
    require(
        readback["path"] == derived_path,
        f"{label} readback is not at the internally derived decision path",
    )
    require(
        readback["ref"] == delivery_sha,
        f"{label} readback was not taken at the authenticated delivery commit",
    )
    reread, readback_sha = _decoded_content(readback, f"{label} readback")
    require(
        readback_sha == blob_sha and reread == decision_data,
        f"{label} readback does not reproduce the exact delivered bytes",
    )
    require(
        operation["cas_expected_old_oid"] == parents[0]
        and operation["commit_parent"] == parents[0]
        and operation["commit_sha"] == delivery_sha
        and operation["commit_tree"] == delivery_tree
        and operation["blob_sha"] == blob_sha
        and operation["path"] == derived_path
        and operation["changed_paths"] == [derived_path]
        and operation["readback_decision_sha256"]
        == hashlib.sha256(reread).hexdigest()
        and operation["cas_ref"] == DELIVERY_TARGET_REF
        and operation["cas_primitive"] == DELIVERY_CAS_PRIMITIVE
        and operation["cas_capability_proven"] is True
        and operation["cas_capability_probe"] == DELIVERY_CAS_CAPABILITY_PROBE
        and operation["signature_verified"] is True,
        f"{label} expected-old-OID CAS operation or race readback mismatch",
    )
    return {
        "blob_sha": blob_sha,
        "branch": DECISION_DELIVERY_BRANCH,
        "branch_protected": True,
        "branch_protection_permission": ADMINISTRATION_READ,
        "blob_introduced_by_commit": True,
        "commit_parent": parents[0],
        "commit_sha": delivery_sha,
        "commit_tree": delivery_tree,
        "cas_capability_probe": operation["cas_capability_probe"],
        "cas_capability_proven": True,
        "cas_expected_old_oid": operation["cas_expected_old_oid"],
        "cas_primitive": operation["cas_primitive"],
        "cas_ref": operation["cas_ref"],
        "path": derived_path,
        "readback_verified": True,
        "race_readback_verified": True,
        "repository": INDEPENDENT_REPOSITORY,
        "repository_id": repository_id,
        "writer_id": writers[0],
        "writer_login": DECISION_WRITER_LOGIN,
    }


# ---------------------------------------------------------------------------
# Raw authenticated GitHub captures
#
# `gh api -i` writes the exact status line, header block and body of one
# authenticated read. The workflow records every such read at a constant path
# together with the exact URL it requested, and follows `rel="next"` until the
# server itself terminates the traversal. Everything the sealed server-object
# document carries is then read out of those captures: no status, Link
# relation, permission header, page, tree entry, blob or artifact identifier
# is ever invented locally.
# ---------------------------------------------------------------------------
def _parse_http_capture(data, label):
    """Split one raw `gh api -i` capture into status, headers and body."""
    require(type(data) is bytes and data, f"{label} capture is empty")
    normalised = data.replace(b"\r\n", b"\n")
    separator = normalised.find(b"\n\n")
    require(separator > 0, f"{label} capture carries no header block")
    head = normalised[:separator].decode("utf-8", "replace").split("\n")
    body = normalised[separator + 2:]
    status_line = head[0]
    match = re.fullmatch(r"HTTP/[0-9.]+ (\d{3})(?: .*)?", status_line.strip())
    require(match is not None, f"{label} capture has no HTTP status line")
    headers = {}
    for line in head[1:]:
        name, colon, value = line.partition(":")
        require(colon, f"{label} capture header line is malformed")
        name = name.strip().lower()
        value = value.strip()
        # GitHub may repeat a header; keep every value, joined as sent.
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return {"status": int(match.group(1)), "headers": headers, "body": body}


def _link_relations(headers, label):
    """Every `rel=` target the server advertised on this exact response."""
    raw = headers.get(LINK_HEADER)
    if raw is None:
        return {}
    relations = {}
    for element in raw.split(","):
        match = re.fullmatch(
            r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"\s*', element,
        )
        require(
            match is not None,
            f"{label} Link header element is unparsable",
        )
        target, relation = match.group(1), match.group(2)
        require(
            relation not in relations,
            f"{label} Link header repeats rel=\"{relation}\"",
        )
        relations[relation] = target
    return relations


def _read_capture(root, name, label, *, canonical_url=None):
    """One raw capture, bound only to server-attested provenance.

    The workflow never states which URL it requested: a self-written sidecar
    would be exactly the caller-shaped provenance this lane refuses. A
    single-object read is bound to the canonical `url` the payload itself
    carries; a collection page is bound to the internally derived first page
    and thereafter only to the `rel="next"` the previous page advertised.
    """
    root = Path(root)
    capture = _parse_http_capture(
        read_bytes(root / RAW_DIRECTORY / f"{name}.http", f"{label} capture"),
        label,
    )
    require(
        capture["status"] == SERVER_PAGE_STATUS,
        f"{label} is not an authenticated HTTP {SERVER_PAGE_STATUS} read",
    )
    require(
        capture["headers"].get(API_VERSION_HEADER) == GITHUB_API_VERSION,
        f"{label} carries no exact GitHub API version provenance",
    )
    # No authenticated read may ever have been performed with a write grant.
    _require_read_only_permission(capture, label)
    capture["json"] = closed_json(capture["body"], label)
    if canonical_url is not None:
        observed = capture["json"].get("url") if type(capture["json"]) is dict \
            else None
        require(
            observed == canonical_url,
            f"{label} payload does not carry its canonical endpoint",
        )
        capture["url"] = canonical_url
    return capture


def _require_read_only_permission(capture, label):
    """Refuse any read the server says required a write grant."""
    raw = capture["headers"].get(PERMISSION_HEADER)
    if raw is None:
        return
    for element in re.split(r"[;,]", raw):
        element = element.strip()
        if not element:
            continue
        match = re.fullmatch(r"([a-z_]+)=([a-z]+)", element)
        require(match is not None, f"{label} permission provenance is unparsable")
        require(
            match.group(2) in ("read", "metadata"),
            f"{label} was performed with a {match.group(2)} grant, which this "
            "read-only lane may never hold",
        )


def _captured_collection(root, prefix, endpoint, label):
    """An exhaustive traversal proved terminated by the server's own headers.

    Page one must be the exact internally derived canonical endpoint. Every
    later page must be precisely the target the previous page advertised as
    `rel="next"`, and the traversal ends only where the server advertises no
    next page at all. A missing capture, an omitted page, an unadvertised
    page, a non-200 status or an absent Link header mid-traversal all fail
    closed.
    """
    first = f"{endpoint}?per_page={SERVER_PER_PAGE}&page=1"
    pages = []
    expected_url = first
    number = 1
    while True:
        page_label = f"{label} page {number}"
        capture = _read_capture(root, f"{prefix}-page-{number}", page_label)
        capture["url"] = expected_url
        relations = _link_relations(capture["headers"], page_label)
        for relation, target in relations.items():
            require(
                target.startswith(f"{endpoint}?"),
                f"{page_label} advertises a foreign rel=\"{relation}\" target",
            )
        if number > 1:
            require(
                relations.get("prev") is not None
                and relations.get("first") == first,
                f"{page_label} does not link back to the traversal it belongs to",
            )
        pages.append({"capture": capture, "relations": relations})
        following = relations.get("next")
        if following is None:
            break
        require(
            number < MAXIMUM_CAPTURED_PAGES,
            f"{label} pagination exceeded the authenticated bound",
        )
        require(
            following == f"{endpoint}?per_page={SERVER_PER_PAGE}"
                        f"&page={number + 1}",
            f"{page_label} advertises a substituted next page",
        )
        expected_url = following
        number += 1
    # A page beyond the server-advertised termination is an unadvertised read.
    require(
        not (Path(root) / RAW_DIRECTORY / f"{prefix}-page-{number + 1}.http"
             ).exists(),
        f"{label} captured a page the server never advertised",
    )
    return pages


def _collection_pages(pages, key, label):
    """The sealed page provenance and entries, read out of the captures."""
    totals = set()
    entries = []
    sealed = []
    for index, page in enumerate(pages, start=1):
        payload = page["capture"]["json"]
        require(type(payload) is dict, f"{label} page {index} body is malformed")
        items = payload.get(key)
        require(
            type(items) is list, f"{label} page {index} collection is malformed",
        )
        total = payload.get("total_count")
        require(
            type(total) is int and type(total) is not bool and total >= 0,
            f"{label} page {index} total is absent or malformed",
        )
        totals.add(total)
        entries.extend(items)
        sealed.append({
            "count": len(items),
            "link": page["capture"]["headers"].get(LINK_HEADER),
            "page": index,
            "per_page": SERVER_PER_PAGE,
            "status": page["capture"]["status"],
            "total_count": total,
        })
    require(len(totals) == 1, f"{label} pages disagree about the total")
    total = totals.pop()
    require(
        total == len(entries),
        f"{label} traversal did not return every advertised entry",
    )
    return sealed, entries, total


def _endpoint_requirements(captures, label):
    """What the server said each endpoint *requires*, never what a token holds.

    `x-accepted-github-permissions` documents the permission an endpoint
    accepts. It is recorded here as exactly that - an endpoint requirement -
    and is never read as provenance for the grants the credential actually
    holds. The grants come only from the authenticated installation readback.
    """
    requirements = {}
    for capture in captures:
        raw = capture["headers"].get(PERMISSION_HEADER)
        require(
            type(raw) is str and raw,
            f"{label} carries no {PERMISSION_HEADER} endpoint requirement",
        )
        for element in re.split(r"[;,]", raw):
            element = element.strip()
            if not element:
                continue
            match = re.fullmatch(r"([a-z_]+)=([a-z]+)", element)
            require(
                match is not None,
                f"{label} endpoint requirement is unparsable",
            )
            requirements.setdefault(match.group(1), set()).add(match.group(2))
    return {
        scope: sorted(levels) for scope, levels in sorted(requirements.items())
    }


CREDENTIAL_GRANT_CONTRACT_KEY = "authorized_credential_grant_contract"
CREDENTIAL_GRANT_CONTRACT_KEYS = (
    "artifact_capture_path", "candidate_supplied_bytes_forbidden",
    "endpoint_requirement_headers_are_not_grants", "endpoint_template",
    "installation_id", "issuer_prefix", "maximum_age_seconds", "permissions",
    "record_sha256", "repositories", "repository_selection",
    "required_permissions", "required_repository",
    "required_repository_selection", "required_status", "runtime_binding",
    "state",
)
CREDENTIAL_GRANT_UNAVAILABLE = "unavailable"
CREDENTIAL_RECORD_KEYS = (
    "access_tokens_url", "account", "app_id", "app_slug", "html_url", "id",
    "permissions", "repositories_url", "repository_selection", "target_type",
)
# The documented installation settings URL. A GitHub *installation* object's
# `html_url` is the settings page of the account the App is installed on, not
# the App's own `https://github.com/apps/{slug}` page. Requiring the App page
# there was a defect twice over: no real installation record ever carries it,
# and it would have accepted any installation of that App on any account,
# which is exactly the binding this lane exists to make exact.
ORGANIZATION_INSTALLATION_URL = (
    "https://github.com/organizations/{account}/settings/installations"
    "/{installation_id}"
)
USER_INSTALLATION_URL = "https://github.com/settings/installations/{installation_id}"
INSTALLATION_TARGET_TYPES = ("Organization", "User")
# The App's own page. This is the one place `https://github.com/apps/{slug}`
# is correct: it names the App, and only `GET /app` may establish it.
APP_PAGE_PREFIX = "https://github.com/apps/"
INSTALLATION_ACCOUNT_KEYS = ("id", "login", "node_id", "type")
# The freshly minted App JWT the runtime chain authenticates with. The token
# bytes are never persisted anywhere - only the window they were valid for, so
# an expired, not-yet-valid or foreign-App credential chain fails closed.
RUNTIME_APP_JWT_FILE = f"{AUTHENTICATED_DIRECTORY}/runtime-app-jwt.json"
RUNTIME_APP_JWT_KEYS = ("app_client_id", "expires_at", "issued_at")
# GitHub refuses an App JWT whose lifetime exceeds ten minutes.
MAXIMUM_APP_JWT_LIFETIME_SECONDS = 600
# No record in this lane may ever carry credential material under any
# documented name.
RUNTIME_APP_JWT_FORBIDDEN_KEYS = (
    "jwt", "pem", "private-key", "private_key", "token",
)
RAW_INSTALLATION_GRANT = "installation-grant"
# The two remaining reads of the very chain that issues the runtime token: the
# App itself, and the installation that actually covers the repository this
# runtime credential reads. Both are documented read-only GETs and neither
# ever carries a token.
RAW_APP = "app"
RAW_REPOSITORY_INSTALLATION = "repository-installation"
APP_RECORD_KEYS = ("client_id", "html_url", "id", "permissions", "slug")
INSTALLATION_RECORD_KEYS = (
    "access_tokens_url", "account", "app_id", "app_slug", "html_url", "id",
    "permissions", "repositories_url", "repository_selection", "target_type",
)
DATE_HEADER = "date"
HTTP_DATE = re.compile(
    r"[A-Z][a-z]{2}, (\d{2}) ([A-Z][a-z]{2}) (\d{4}) "
    r"(\d{2}):(\d{2}):(\d{2}) GMT"
)
HTTP_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)


def _http_date_seconds(value, label):
    match = HTTP_DATE.fullmatch(value if type(value) is str else "")
    require(match is not None, f"{label} is not a canonical HTTP date")
    day, month, year, hour, minute, second = match.groups()
    require(month in HTTP_MONTHS, f"{label} month is not canonical")
    import calendar
    return calendar.timegm((
        int(year), HTTP_MONTHS.index(month) + 1, int(day),
        int(hour), int(minute), int(second), 0, 0, 0,
    ))


def _installation_account(document, label):
    """The exact account object an installation record names."""
    account = document.get("account")
    require(type(account) is dict, f"{label} names no installation account")
    _required_members(account, INSTALLATION_ACCOUNT_KEYS, f"{label} account")
    login = account["login"]
    require(
        type(login) is str and login,
        f"{label} installation account publishes no login",
    )
    account_type = account["type"]
    require(
        account_type in INSTALLATION_TARGET_TYPES,
        f"{label} installation account type is not a documented account type",
    )
    _canonical_identifier(account["id"], f"{label} installation account id")
    require(
        type(account["node_id"]) is str and account["node_id"],
        f"{label} installation account node id is absent",
    )
    return {"login": login, "type": account_type}


def _installation_settings_url(target_type, account, installation_id, label):
    """The documented settings URL of exactly this installation.

    Organization installations are administered under the organization's own
    settings; user installations under the account's. Either way the URL names
    the *installation*, by account and by id, so it can never be satisfied by
    a different installation of the same App.
    """
    require(
        target_type in INSTALLATION_TARGET_TYPES,
        f"{label} installation target type is not a documented target type",
    )
    require(
        target_type == account["type"],
        f"{label} installation target type contradicts its own account",
    )
    if target_type == "Organization":
        return ORGANIZATION_INSTALLATION_URL.format(
            account=account["login"], installation_id=installation_id,
        )
    return USER_INSTALLATION_URL.format(installation_id=installation_id)


def authenticated_app_identity(root, label):
    """The App this runtime chain really authenticated as, from `GET /app`.

    The App identity is never taken from an installation record, a workflow
    variable or a contract: it is read back from the endpoint that answers
    only for the credential actually presented. Everything downstream - the
    installation, the grant, the issuance and the inventory - is then required
    to name exactly this App.
    """
    app = _required_members(
        _read_capture(root, RAW_APP, label)["json"], APP_RECORD_KEYS, label,
    )
    app_id = _positive_int(app["id"], f"{label} App id")
    require(
        len(set(str(app_id))) >= MINIMUM_ID_ENTROPY,
        f"{label} App id is a caller-shaped identifier",
    )
    slug = app["slug"]
    require(type(slug) is str and slug, f"{label} App publishes no slug")
    client_id = app["client_id"]
    require(
        type(client_id) is str and client_id,
        f"{label} App publishes no client id",
    )
    html_url = app["html_url"]
    require(
        html_url == f"{APP_PAGE_PREFIX}{slug}",
        f"{label} App page does not name the slug its own record identifies",
    )
    declared = app["permissions"]
    require(
        type(declared) is dict and declared,
        f"{label} App declares no permissions",
    )
    for scope, level in REQUIRED_TOKEN_PERMISSIONS.items():
        require(
            declared.get(scope) == level,
            f"{label} App does not declare the required {scope}={level}",
        )
    return {
        "app_id": app_id,
        "app_slug": slug,
        "client_id": client_id,
        "html_url": html_url,
        "permissions": dict(declared),
    }


def authenticated_app_jwt_claims(root, app, *, captured_at, label):
    """The window the freshly minted App JWT was valid for, and nothing else.

    The workflow mints a short-lived App JWT for this run alone, from the
    reviewed App private-key chain, and never writes the token anywhere. What
    it does record is the claim window, so this lane can require that the
    credential the captures were taken with really was this App's, really was
    already valid, and really had not expired at the instant the server
    recorded the read. An expired, not-yet-valid, over-long or foreign-App
    window fails closed; a record that carries credential material at all is
    refused outright.
    """
    path = Path(root) / RUNTIME_APP_JWT_FILE
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} record is absent or unsafe: {RUNTIME_APP_JWT_FILE}",
    )
    document = closed_json(read_bytes(path, label), label)
    for forbidden in RUNTIME_APP_JWT_FORBIDDEN_KEYS:
        require(
            forbidden not in document,
            f"{label} record carries credential material: {forbidden}",
        )
    _exact_members(document, RUNTIME_APP_JWT_KEYS, label)
    require(
        document["app_client_id"] == app["client_id"],
        f"{label} was minted for another App than the one this chain "
        "authenticated as",
    )
    issued = document["issued_at"]
    expires = document["expires_at"]
    for name, value in (("issued_at", issued), ("expires_at", expires)):
        require(
            type(value) is int and type(value) is not bool and value > 0,
            f"{label} {name} is not an exact instant",
        )
    require(
        issued < expires,
        f"{label} expires no later than it was issued",
    )
    require(
        expires - issued <= MAXIMUM_APP_JWT_LIFETIME_SECONDS,
        f"{label} lifetime exceeds the documented maximum of "
        f"{MAXIMUM_APP_JWT_LIFETIME_SECONDS} seconds",
    )
    require(
        type(captured_at) is int and type(captured_at) is not bool,
        f"{label} cannot be bound to an unauthenticated capture instant",
    )
    require(
        issued <= captured_at,
        f"{label} was not yet valid when the server recorded this read",
    )
    require(
        captured_at <= expires,
        f"{label} had already expired when the server recorded this read",
    )
    return {
        "app_client_id": document["app_client_id"],
        "expires_at": expires,
        "issued_at": issued,
    }


def authenticated_credential_grant(root, contract, *, run_started, app):
    """Authenticate the external immutable installation grant record.

    The candidate supplies no grant evidence at all: it defines only the
    contract this record must satisfy, and its default state is explicitly
    unavailable. The exact bytes come only from the production lane, as the
    raw captured response of an authenticated GET on the canonical
    `/app/installations/{installation_id}` endpoint. Everything is read out of
    that response - issuer, installation id, the actual permissions, the
    repository selection and the response freshness - and an absent,
    placeholder, substituted, stale, future-dated, foreign-issuer,
    foreign-installation or under-privileged record fails closed.
    `x-accepted-github-permissions` remains an endpoint requirement only and
    is never read here.
    """
    label = "external installation grant record"
    terms = contract.get(CREDENTIAL_GRANT_CONTRACT_KEY)
    require(type(terms) is dict, f"{label} contract is absent")
    _exact_members(terms, CREDENTIAL_GRANT_CONTRACT_KEYS, f"{label} contract")
    require(
        terms["state"] == CREDENTIAL_GRANT_UNAVAILABLE,
        f"{label} contract must ship unavailable and carry no grant evidence",
    )
    for field in ("installation_id", "permissions", "record_sha256",
                  "repositories", "repository_selection"):
        require(
            terms[field] is None,
            f"{label} contract carries candidate-supplied {field}",
        )
    require(
        terms["candidate_supplied_bytes_forbidden"] is True
        and terms["endpoint_requirement_headers_are_not_grants"] is True,
        f"{label} contract does not forbid candidate-supplied grant evidence",
    )
    require(
        terms["required_permissions"] == REQUIRED_TOKEN_PERMISSIONS
        and terms["required_repository"] == SOURCE_REPOSITORY
        and terms["required_repository_selection"] == REQUIRED_TOKEN_SELECTION,
        f"{label} contract requirements are not the sealed requirements",
    )

    path = Path(root) / RAW_DIRECTORY / f"{RAW_INSTALLATION_GRANT}.http"
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} artifact is absent or unsafe: {terms['artifact_capture_path']}",
    )
    capture = _parse_http_capture(path.read_bytes(), label)
    require(
        capture["status"] == terms["required_status"],
        f"{label} is not an authenticated HTTP {terms['required_status']} read",
    )
    _require_read_only_permission(capture, label)
    document = closed_json(capture["body"], f"{label} body")
    _required_members(document, CREDENTIAL_RECORD_KEYS, f"{label} body")

    installation_id = _canonical_identifier(
        document["id"], f"{label} installation id",
    )
    # The App identity comes from the authenticated `GET /app` chain, never
    # from the installation record describing itself.
    require(
        document["app_slug"] == app["app_slug"],
        f"{label} names another App than the one this chain authenticated as",
    )
    # GitHub App ids are legitimately small, so only the installation id
    # carries the canonical-identifier floor; the App id must still be a real
    # positive server identifier rather than a round placeholder.
    app_id = _positive_int(document["app_id"], f"{label} app id")
    require(
        len(set(str(app_id))) >= MINIMUM_ID_ENTROPY,
        f"{label} app id is a caller-shaped identifier",
    )
    require(
        app_id == app["app_id"],
        f"{label} names another App id than the one this chain "
        "authenticated as",
    )
    issuer = app["html_url"]
    account = _installation_account(document, label)
    # A user installation settings URL carries only the installation id, so
    # the account itself is bound here instead of being inferred from a URL:
    # an installation that covers the required repository can only be on the
    # account that owns it, and the sealed contract names that repository.
    require(
        account["login"] == terms["required_repository"].split("/", 1)[0],
        f"{label} installation is not on the account that owns the required "
        "protected source repository",
    )
    target_type = document["target_type"]
    settings_url = _installation_settings_url(
        target_type, account, installation_id, label,
    )
    require(
        document["html_url"] == settings_url,
        f"{label} is not the documented settings URL of this exact "
        "installation",
    )

    permissions = document["permissions"]
    require(
        type(permissions) is dict and permissions,
        f"{label} publishes no permissions",
    )
    for scope, level in sorted(permissions.items()):
        require(
            type(scope) is str and level in READ_ONLY_GRANT_LEVELS,
            f"{label} holds a {level} grant on {scope}, which this read-only "
            "lane may never hold",
        )
    for scope, level in REQUIRED_TOKEN_PERMISSIONS.items():
        require(
            permissions.get(scope) == level,
            f"{label} does not grant the required {scope}={level}",
        )
    selection = document["repository_selection"]
    require(
        selection == terms["required_repository_selection"],
        f"{label} is not restricted to the selected repository",
    )

    # Freshness, from the server's own response date.
    recorded = _http_date_seconds(
        capture["headers"].get(DATE_HEADER), f"{label} response date",
    )
    require(
        type(run_started) is int and type(run_started) is not bool
        and run_started > 0,
        f"{label} cannot be aged against an unauthenticated run start",
    )
    # The grant read is performed *by this run*, so the server recorded it at
    # or after the run started. Requiring it to precede the run could never be
    # satisfied by a real capture; requiring it to precede the run start is
    # what a replayed record from an earlier run would look like.
    require(
        recorded >= run_started,
        f"{label} was recorded before the run that performs it started",
    )
    require(
        recorded - run_started <= terms["maximum_age_seconds"],
        f"{label} is stale for this run",
    )
    # The record names its own token issuance and runtime readback endpoints.
    # They are carried out of here verbatim so the runtime chain can require
    # the installation that covers this repository to name exactly the same
    # two endpoints, rather than merely to look similar.
    return {
        "access_tokens_url": document["access_tokens_url"],
        "account_login": account["login"],
        "app_id": app_id,
        "app_slug": document["app_slug"],
        "installation_id": installation_id,
        "installation_settings_url": settings_url,
        "issuer": issuer,
        "issuer_prefix": terms["issuer_prefix"],
        "permissions": dict(permissions),
        "record_sha256": hashlib.sha256(capture["body"]).hexdigest(),
        "recorded_at": recorded,
        "repositories_url": document["repositories_url"],
        "repository_selection": selection,
        "target_type": target_type,
    }


def authenticated_runtime_token_chain(root, grant, app, label):
    """The App and installation that issue the very token this run is using.

    The grant record alone states what an installation was granted; on its own
    it says nothing about the credential actually in use. These two documented
    read-only GETs close exactly that gap from the same authenticated App
    chain: `/app` names the issuing App and its declared permissions, and
    `/repos/{source}/installation` names the installation that really covers
    the repository this runtime token reads, together with its own canonical
    token-issuance endpoint and its own runtime repositories endpoint. Both
    must be exactly the endpoints the grant record itself names, so the grant,
    the issuance and the runtime readback are one chain. Neither read ever
    carries a token. A foreign App, a foreign installation, a different
    permission set, a different selection or a substituted endpoint all fail
    closed.
    """
    app_id, slug = app["app_id"], app["app_slug"]
    require(
        app_id == grant["app_id"] and slug == grant["app_slug"],
        f"{label} App is not the App the authenticated grant record names",
    )

    record = _required_members(
        _read_capture(
            root, RAW_REPOSITORY_INSTALLATION,
            f"{label} repository installation",
        )["json"],
        INSTALLATION_RECORD_KEYS, f"{label} repository installation",
    )
    require(
        _canonical_identifier(
            record["id"], f"{label} repository installation id",
        ) == grant["installation_id"],
        f"{label} repository is not covered by the granted installation",
    )
    require(
        record["app_id"] == app_id and record["app_slug"] == slug,
        f"{label} repository installation is not this App's installation",
    )
    record_account = _installation_account(record, f"{label} repository installation")
    require(
        record_account["login"] == grant["account_login"],
        f"{label} repository installation is on another account than the "
        "authenticated grant record covers",
    )
    require(
        record["target_type"] == grant["target_type"],
        f"{label} repository installation target type drift",
    )
    require(
        record["html_url"] == grant["installation_settings_url"]
        == _installation_settings_url(
            record["target_type"], record_account, grant["installation_id"],
            f"{label} repository installation",
        ),
        f"{label} repository installation is not the documented settings URL "
        "of the granted installation",
    )
    require(
        record["permissions"] == grant["permissions"],
        f"{label} repository installation permissions contradict the "
        "authenticated grant record",
    )
    require(
        record["repository_selection"] == grant["repository_selection"],
        f"{label} repository installation selection contradicts the "
        "authenticated grant record",
    )
    issuance = (
        f"{GITHUB_API_ROOT}/app/installations"
        f"/{grant['installation_id']}/access_tokens"
    )
    readback = f"{GITHUB_API_ROOT}/installation/repositories"
    require(
        record["access_tokens_url"] == issuance
        and grant["access_tokens_url"] == issuance,
        f"{label} token issuance endpoint is not the canonical endpoint of "
        "the granted installation",
    )
    require(
        record["repositories_url"] == readback
        and grant["repositories_url"] == readback,
        f"{label} runtime repositories endpoint is not the canonical "
        "endpoint the exhaustive inventory was read from",
    )
    return {
        "account_login": grant["account_login"],
        "app_id": app_id,
        "app_slug": slug,
        "installation_settings_url": grant["installation_settings_url"],
        "target_type": grant["target_type"],
        "token_issuance_endpoint": issuance,
    }


# ---------------------------------------------------------------------------
# F8-CREDENTIAL-GRANT-NOT-BOUND-TO-RUNTIME-TOKEN
#
# The grant record and the App chain both describe an *installation*. Neither
# says anything about the credential this run is actually holding. The pinned
# `actions/create-github-app-token` step publishes exactly that missing fact:
# `app-slug` and `installation-id` are outputs of the very issuance that
# minted the runtime token, so consuming them binds the grant, the issuance
# chain and the credential in use into one statement instead of two
# independent claims that merely look alike.
# ---------------------------------------------------------------------------
RUNTIME_TOKEN_GRANT_FILE = f"{AUTHENTICATED_DIRECTORY}/runtime-token-grant.json"
RUNTIME_TOKEN_GRANT_KEYS = ("app_slug", "installation_id")
# The token itself is a credential and must never reach the filesystem, so the
# record is refused outright if it carries one under any documented name.
RUNTIME_TOKEN_FORBIDDEN_KEYS = ("token", "expires_at", "private-key",
                                "private_key")


def authenticated_runtime_token_issuance(root, grant, chain, label):
    """Bind the runtime credential's own issuance outputs to the grant chain.

    The record is written by the workflow from the pinned token action's own
    `app-slug` and `installation-id` outputs - the issuance that produced the
    token this run is using. Both must be exactly the App slug and the
    installation the authenticated grant record and the issuance chain name,
    so a grant for one installation can never authorise a token minted by
    another. The record may carry nothing else, and above all never the token.
    """
    path = Path(root) / RUNTIME_TOKEN_GRANT_FILE
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} record is absent or unsafe: {RUNTIME_TOKEN_GRANT_FILE}",
    )
    document = closed_json(read_bytes(path, label), label)
    for forbidden in RUNTIME_TOKEN_FORBIDDEN_KEYS:
        require(
            forbidden not in document,
            f"{label} record carries credential material: {forbidden}",
        )
    _exact_members(document, RUNTIME_TOKEN_GRANT_KEYS, label)
    installation_id = _canonical_identifier(
        document["installation_id"], f"{label} installation id",
    )
    slug = document["app_slug"]
    require(type(slug) is str and slug, f"{label} record publishes no App slug")
    require(
        installation_id == grant["installation_id"],
        f"{label} minted a token for another installation than the one the "
        "authenticated grant record covers",
    )
    require(
        slug == grant["app_slug"] and slug == chain["app_slug"],
        f"{label} minted a token for another App than the one the "
        "authenticated issuance chain names",
    )
    # The canonical issuance endpoint of the installation that really minted
    # this token, so the grant, the chain and the credential are one chain.
    require(
        chain["token_issuance_endpoint"]
        == f"{GITHUB_API_ROOT}/app/installations/{installation_id}"
           "/access_tokens",
        f"{label} issuance endpoint is not the canonical endpoint of the "
        "installation that minted this runtime token",
    )
    return {
        "account_login": chain["account_login"],
        "app_id": chain["app_id"],
        "app_slug": slug,
        "installation_id": installation_id,
        "installation_settings_url": chain["installation_settings_url"],
        "target_type": chain["target_type"],
        "token_issuance_endpoint": chain["token_issuance_endpoint"],
    }


INVENTORY_ENTRY_KEYS = ("full_name", "id", "node_id")


def bind_runtime_credential(grant, *, selection, repositories, chain,
                            repository_identity):
    """Bind the external grant record to the credential this run is using.

    The runtime readback publishes the repository selection and the exhaustive
    inventory. The selection must be the one the same authenticated issuance
    chain states, and every inventory entry must identify the protected source
    repository by exactly the canonical numeric id, full name and node id the
    authenticated repository read returned - so a substituted, extra, omitted
    or partially identified repository fails closed.
    """
    label = "runtime credential binding"
    require(
        selection == grant["repository_selection"],
        f"{label} repository selection contradicts the authenticated grant",
    )
    require(
        type(repositories) is list and len(repositories) == 1,
        f"{label} inventory is not exactly the protected source repository",
    )
    entry = repositories[0]
    require(type(entry) is dict, f"{label} inventory entry is malformed")
    _exact_members(entry, INVENTORY_ENTRY_KEYS, f"{label} inventory entry")
    require(
        entry.get("full_name") == SOURCE_REPOSITORY,
        f"{label} inventory names a foreign repository",
    )
    repository_id = _canonical_identifier(
        entry.get("id"), f"{label} repository id",
    )
    # The inventory the runtime credential returned must be the very
    # repository the authenticated repository read identified, by canonical
    # numeric id and by node id, never merely by a matching name.
    require(
        repository_id == repository_identity["id"]
        and entry["node_id"] == repository_identity["node_id"]
        and entry["full_name"] == repository_identity["full_name"],
        f"{label} inventory is not the authenticated protected source "
        "repository object",
    )
    return {
        **grant,
        **chain,
        "repositories": [
            {"full_name": SOURCE_REPOSITORY, "id": repository_id},
        ],
    }


def _authenticated_run_start(root, label):
    """The authenticated instant this run began, from the server's own body."""
    metadata = closed_json(
        read_bytes(Path(root) / SOURCE_RUN_FILE, label), label,
    )
    started = metadata.get("run_started_at")
    require(
        type(started) is str and started,
        f"{label} publishes no authenticated start instant",
    )
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z", started,
    )
    require(match is not None, f"{label} start instant is not canonical UTC")
    import calendar
    return calendar.timegm(
        tuple(int(part) for part in match.groups()) + (0, 0, 0)
    )


def _runtime_installation_readback(pages, repositories, label):
    """What the authenticated runtime readback itself publishes, and only that.

    It publishes the repository selection and the exhaustive inventory - by
    canonical numeric id and full name - and never grants.
    """
    require(
        all(type(item) is dict for item in repositories),
        f"{label} repository inventory is malformed",
    )
    selections = {
        page["capture"]["json"].get("repository_selection") for page in pages
    }
    require(
        len(selections) == 1,
        f"{label} pages disagree about the repository selection",
    )
    return selections.pop(), list(repositories)


def _require_artifact_archive(root, artifact, live, label):
    """Recompute size and digest over the archive bytes actually obtained.

    The artifact is downloaded by its canonical server id, and the server's own
    `size_in_bytes` and `sha256:` digest are recomputed over exactly those
    bytes. A digest that is merely well formed, or an archive that is not the
    one the server described, can never reach a receipt. The archive members
    are then recomputed to the exact artifact content digest this lane derived
    for itself, so the download and the exported bytes are one chain.
    """
    path = Path(root) / ARTIFACT_ARCHIVE_FILE
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} artifact archive is absent or unsafe",
    )
    data = path.read_bytes()
    require(
        len(data) == artifact["size_in_bytes"],
        f"{label} artifact archive size does not match the authenticated size",
    )
    require(
        artifact["digest"] == ARTIFACT_DIGEST_PREFIX
        + hashlib.sha256(data).hexdigest(),
        f"{label} artifact archive bytes do not match the server digest",
    )
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members, _ = _terminal_read_validated_zip(
                archive, ARTIFACT_MEMBERS,
            )
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as error:
        raise SystemExit(
            f"{label} artifact archive is not a readable archive"
        ) from error
    require(
        artifact_content_sha256(members) == live["artifact_content_sha256"],
        f"{label} artifact archive does not carry the exported review bytes",
    )


def _derive_server_objects(root):
    """Derive the whole sealed document from the raw captures, deterministically.

    This is a pure function of the captured bytes, so composition and
    authentication can recompute it independently and any locally invented
    field is impossible by construction.
    """
    root = Path(root)
    label = "authenticated GitHub server objects"
    repository_capture = _read_capture(
        root, RAW_REPOSITORY, f"{label} repository",
        canonical_url=f"{GITHUB_API_ROOT}/repos/{SOURCE_REPOSITORY}",
    )
    repository_body = repository_capture["json"]
    require(type(repository_body) is dict, f"{label} repository body is malformed")
    full_name = repository_body.get("full_name")
    require(
        full_name == SOURCE_REPOSITORY,
        f"{label} repository is not the protected source repository",
    )

    run_capture = _read_capture(root, RAW_RUN, f"{label} run")
    run_body = run_capture["json"]
    require(type(run_body) is dict, f"{label} run body is malformed")
    run_id = _positive_int(run_body.get("id"), f"{label} run id")
    require(
        run_body.get("url")
        == f"{GITHUB_API_ROOT}/repos/{full_name}/actions/runs/{run_id}",
        f"{label} run was not read from its canonical endpoint",
    )
    head_sha = run_body.get("head_sha")
    require(
        type(head_sha) is str and HEX40.fullmatch(head_sha) is not None,
        f"{label} run head is malformed",
    )

    commit_capture = _read_capture(
        root, RAW_COMMIT, f"{label} commit",
        canonical_url=f"{GITHUB_API_ROOT}/repos/{full_name}"
                      f"/git/commits/{head_sha}",
    )
    commit_body = commit_capture["json"]
    tree_sha = _member(commit_body, ("tree", "sha"), f"{label} commit tree")
    require(
        type(tree_sha) is str and HEX40.fullmatch(tree_sha) is not None,
        f"{label} commit tree is malformed",
    )

    workflow_name = PurePosixPath(SOURCE_WORKFLOW).name
    endpoints = {
        RAW_RUNS_PREFIX: (
            f"{GITHUB_API_ROOT}/repos/{full_name}/actions/workflows"
            f"/{workflow_name}/runs", "workflow_runs", f"{label} workflow run",
        ),
        RAW_JOBS_PREFIX: (
            f"{GITHUB_API_ROOT}/repos/{full_name}/actions/runs/{run_id}/jobs",
            "jobs", f"{label} job",
        ),
        RAW_ARTIFACTS_PREFIX: (
            f"{GITHUB_API_ROOT}/repos/{full_name}/actions/runs/{run_id}"
            "/artifacts", "artifacts", f"{label} artifact",
        ),
    }
    collected = {}
    permission_captures = [repository_capture, run_capture, commit_capture]
    for prefix, (endpoint, key, collection_label) in endpoints.items():
        pages = _captured_collection(root, prefix, endpoint, collection_label)
        permission_captures.extend(page["capture"] for page in pages)
        collected[prefix] = _collection_pages(pages, key, collection_label)

    tree_capture = _read_capture(
        root, RAW_TREE, f"{label} tree",
        canonical_url=f"{GITHUB_API_ROOT}/repos/{full_name}"
                      f"/git/trees/{tree_sha}",
    )
    tree_body = tree_capture["json"]
    require(type(tree_body) is dict, f"{label} tree body is malformed")
    require(
        tree_body.get("sha") == tree_sha,
        f"{label} tree is not the authenticated commit tree",
    )
    require(
        tree_body.get("truncated") is False,
        f"{label} tree read is truncated",
    )
    permission_captures.append(tree_capture)
    server_tree = {}
    for entry in tree_body.get("tree") or []:
        require(type(entry) is dict, f"{label} tree entry is malformed")
        if entry.get("path") in REQUIRED_SOURCE_PATHS:
            server_tree[entry["path"]] = entry

    tree_entries = []
    for index, path in enumerate(REQUIRED_SOURCE_PATHS, start=1):
        entry = server_tree.get(path)
        require(
            entry is not None,
            f"{label} tree does not carry the required path: {path}",
        )
        require(
            entry.get("type") == "blob" and entry.get("mode") == BLOB_MODE,
            f"{label} tree entry is not a regular blob: {path}",
        )
        blob_sha = entry.get("sha")
        require(
            type(blob_sha) is str and HEX40.fullmatch(blob_sha) is not None,
            f"{label} tree entry object name is malformed: {path}",
        )
        blob_label = f"{label} blob {path}"
        blob_capture = _read_capture(
            root, f"{RAW_BLOB_PREFIX}-{index}", blob_label,
            canonical_url=f"{GITHUB_API_ROOT}/repos/{full_name}"
                          f"/git/blobs/{blob_sha}",
        )
        permission_captures.append(blob_capture)
        blob_body = blob_capture["json"]
        require(type(blob_body) is dict, f"{blob_label} body is malformed")
        require(
            blob_body.get("sha") == blob_sha,
            f"{blob_label} is not the object the tree names",
        )
        data, _ = _decoded_content(
            {
                "content": re.sub(r"\s+", "", str(blob_body.get("content", ""))),
                "encoding": blob_body.get("encoding"),
                "sha": blob_sha,
                "size": blob_body.get("size"),
            },
            blob_label,
        )
        tree_entries.append({
            "blob_sha": blob_sha,
            "mode": entry["mode"],
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        })

    # The installation's repository selection is read exhaustively at the full
    # page size and its own `total_count` is enforced, so a second selected
    # repository can never hide on a page that was never requested.
    installation_endpoint = f"{GITHUB_API_ROOT}/installation/repositories"
    installation_pages = _captured_collection(
        root, RAW_INSTALLATION, installation_endpoint, f"{label} installation",
    )
    permission_captures.extend(page["capture"] for page in installation_pages)
    _, repositories, installation_total = _collection_pages(
        installation_pages, "repositories", f"{label} installation",
    )
    require(
        installation_total == len(repositories),
        f"{label} installation inventory is incomplete",
    )
    # The grants come only from the sealed, reviewer-authenticated record; the
    # runtime readback binds it to the credential actually in use.
    contract = closed_json(
        read_bytes(root / CONTRACT_PATH, "independent review bootstrap contract"),
        "independent review bootstrap contract",
    )
    run_started = _authenticated_run_start(root, f"{label} run")
    # The App this runtime chain really authenticated as, before anything is
    # allowed to describe it.
    app = authenticated_app_identity(root, f"{label} App")
    grant = authenticated_credential_grant(
        root, contract, run_started=run_started, app=app,
    )
    # The freshly minted App JWT really covered the instant the server
    # recorded the grant read; its bytes were never persisted.
    app_jwt = authenticated_app_jwt_claims(
        root, app, captured_at=grant["recorded_at"], label=f"{label} App JWT",
    )
    observed_selection, observed_repositories = _runtime_installation_readback(
        installation_pages, repositories, f"{label} installation",
    )
    chain = authenticated_runtime_token_chain(
        root, grant, app, f"{label} installation",
    )
    # The credential this run is really holding, from the pinned token
    # action's own issuance outputs. Everything downstream binds to this.
    issuance = authenticated_runtime_token_issuance(
        root, grant, chain, f"{label} runtime token issuance",
    )
    chain = {**chain, **issuance}
    permission_captures.append(
        _read_capture(root, RAW_APP, f"{label} installation App"),
    )
    permission_captures.append(
        _read_capture(
            root, RAW_REPOSITORY_INSTALLATION,
            f"{label} installation repository installation",
        ),
    )
    bound = bind_runtime_credential(
        grant, selection=observed_selection,
        repositories=observed_repositories, chain=chain,
        repository_identity={
            key: _member(repository_body, (key,), f"{label} repository {key}")
            for key in ("full_name", "id", "node_id")
        },
    )
    installation_id = bound["installation_id"]
    grants = bound["permissions"]
    selection = bound["repository_selection"]


    runs_pages, _, _ = collected[RAW_RUNS_PREFIX]
    jobs_pages, job_entries, _ = collected[RAW_JOBS_PREFIX]
    artifact_pages, artifact_entries, _ = collected[RAW_ARTIFACTS_PREFIX]
    return {
        "api_version": GITHUB_API_VERSION,
        "artifacts": {
            "entries": [
                {
                    "digest": entry.get("digest"),
                    "expired": entry.get("expired"),
                    "id": entry.get("id"),
                    "name": entry.get("name"),
                    "node_id": entry.get("node_id"),
                    "size_in_bytes": entry.get("size_in_bytes"),
                    "workflow_run": {
                        "id": _member(
                            entry, ("workflow_run", "id"),
                            f"{label} artifact run",
                        ),
                    },
                }
                for entry in artifact_entries
                if entry.get("name") == SOURCE_ARTIFACT
            ],
            "pages": artifact_pages,
        },
        "head": {"commit": head_sha, "tree": tree_sha},
        "jobs": {
            "entries": [
                {
                    key: _member(entry, (key,), f"{label} job {key}")
                    for key in SERVER_JOB_KEYS
                }
                for entry in job_entries
            ],
            "pages": jobs_pages,
        },
        "repository": {
            key: _member(repository_body, (key,), f"{label} repository {key}")
            for key in SERVER_REPOSITORY_KEYS
        },
        "token": {
            # What each endpoint required, recorded as exactly that.
            "endpoint_requirements": _endpoint_requirements(
                permission_captures, label,
            ),
            # The exact sealed grant record the external reviewer
            # authenticated before this lane ever ran.
            "account_login": bound["account_login"],
            "app_id": bound["app_id"],
            "app_slug": bound["app_slug"],
            "grant_record_sha256": bound["record_sha256"],
            "installation_id": installation_id,
            "installation_settings_url": bound["installation_settings_url"],
            "issuer": bound["issuer"],
            "permissions": grants,
            "repositories": bound["repositories"],
            "repository_selection": selection,
            "target_type": bound["target_type"],
            "token_issuance_endpoint": bound["token_issuance_endpoint"],
        },
        "tree": {"entries": tree_entries, "truncated": False},
        "workflow_runs": {"pages": runs_pages},
    }


def _expected_server_page_lengths(total):
    """The exact minimal page lengths a terminated pagination must return."""
    full, remainder = divmod(total, SERVER_PER_PAGE)
    lengths = [SERVER_PER_PAGE] * full
    if remainder or not lengths:
        lengths.append(remainder)
    return lengths


def _authenticated_pages(pages, label, endpoint, expected_counts=None):
    """Exhaustive, terminated pagination provenance for one collection.

    Every page is an authenticated HTTP 200 read at its exact deterministic
    page path, each advertised ``rel="next"`` names exactly the following page
    at the same page size, the last page closes the traversal, all pages agree
    on one total, and the observed per-page counts must be exactly the counts
    a complete traversal produces.
    """
    require(type(pages) is list and pages, f"{label} pagination is absent")
    totals = set()
    observed = []
    for index, page in enumerate(pages, start=1):
        _exact_members(page, SERVER_PAGE_KEYS, f"{label} page {index}")
        require(
            page["status"] == SERVER_PAGE_STATUS,
            f"{label} page {index} is not an authenticated HTTP 200 read",
        )
        require(
            page["page"] == index and type(page["page"]) is int
            and type(page["page"]) is not bool,
            f"{label} pagination is not monotonic at page {index}",
        )
        require(
            page["per_page"] == SERVER_PER_PAGE,
            f"{label} page {index} was not read at the exact page size",
        )
        count = page["count"]
        require(
            type(count) is int and type(count) is not bool
            and 0 <= count <= SERVER_PER_PAGE,
            f"{label} page {index} entry count is malformed",
        )
        total = page["total_count"]
        require(
            type(total) is int and type(total) is not bool and total >= 0,
            f"{label} page {index} total is malformed",
        )
        totals.add(total)
        link = page["link"]
        require(
            link is None or type(link) is str,
            f"{label} page {index} Link provenance is malformed",
        )
        relations = _link_relations(
            {} if link is None else {LINK_HEADER: link}, f"{label} page {index}",
        )
        following = relations.get("next")
        if index == len(pages):
            require(
                following is None,
                f"{label} pagination never reaches its Link closure",
            )
        else:
            require(
                following == f"{endpoint}?per_page={SERVER_PER_PAGE}"
                             f"&page={index + 1}",
                f"{label} page {index} Link header does not advertise the "
                "exact next page",
            )
        observed.append(count)
    require(len(totals) == 1, f"{label} pages disagree about the total")
    total = totals.pop()
    expected = (
        _expected_server_page_lengths(total)
        if expected_counts is None else list(expected_counts)
    )
    require(
        observed == expected,
        f"{label} pagination is incomplete, substituted or unadvertised",
    )
    return total


def authenticate_server_objects(root, live):
    """Authenticate every canonical server object a receipt would depend on.

    Nothing here is caller selectable and nothing is believed on shape alone:
    the repository is identified by its canonical numeric id, the run and job
    inventories come from exhaustive terminated paginations with Link closure,
    the head and tree are the authenticated ones, every required path and blob
    is rehashed to its Git object name and content digest from the exact
    authenticated bytes, and the artifact digest must equal the artifact
    content digest this lane recomputed for itself.
    """
    label = "authenticated GitHub server objects"
    root = Path(root)
    data = read_bytes(root / SERVER_OBJECTS_FILE, label)
    document = closed_json(data, label)
    _exact_members(document, SERVER_OBJECTS_KEYS, label)
    # Receipt creation depends directly on the raw captured responses: the
    # sealed document must be exactly what those captures deterministically
    # produce, so an invented status, Link relation, permission, page, tree
    # entry, blob or artifact identifier can never survive here.
    recomposed = _derive_server_objects(root)
    require(
        document == recomposed,
        f"{label} do not match the raw authenticated GitHub captures",
    )
    require(
        data == json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
        f"{label} document is not canonical exact JSON",
    )
    require(
        document["api_version"] == GITHUB_API_VERSION,
        f"{label} carry no exact GitHub API version provenance",
    )

    # --- token permission provenance --------------------------------------
    token = _exact_members(document["token"], SERVER_TOKEN_KEYS, f"{label} token")
    require(
        type(token["permissions"]) is dict
        and token["permissions"] == REQUIRED_TOKEN_PERMISSIONS,
        f"{label} token permission provenance mismatch",
    )
    require(
        token["repository_selection"] == REQUIRED_TOKEN_SELECTION,
        f"{label} token is not restricted to the selected repository",
    )
    require(
        type(token["repositories"]) is list and len(token["repositories"]) == 1
        and type(token["repositories"][0]) is dict
        and token["repositories"][0].get("full_name")
        == live["source_repository"]
        and type(token["repositories"][0].get("id")) is int,
        f"{label} token does not name exactly the protected source repository "
        "by canonical numeric id and full name",
    )
    require(
        type(token["grant_record_sha256"]) is str
        and HEX64.fullmatch(token["grant_record_sha256"]) is not None,
        f"{label} token carries no authenticated grant record digest",
    )
    require(
        type(token["issuer"]) is str
        and token["issuer"].startswith("https://github.com/apps/"),
        f"{label} token names no authenticated issuing App",
    )
    # The App identity and the canonical token issuance endpoint are the same
    # authenticated chain the runtime credential was issued through.
    require(
        type(token["app_slug"]) is str and token["app_slug"]
        and token["issuer"] == f"https://github.com/apps/{token['app_slug']}",
        f"{label} token issuer does not name the authenticated App slug",
    )
    require(
        type(token["app_id"]) is int and type(token["app_id"]) is not bool
        and token["app_id"] > 0,
        f"{label} token names no authenticated App id",
    )
    require(
        token["token_issuance_endpoint"]
        == f"{GITHUB_API_ROOT}/app/installations"
           f"/{token['installation_id']}/access_tokens",
        f"{label} token issuance endpoint is not the canonical endpoint of "
        "the authenticated installation",
    )
    # The exact installation, named the way GitHub names it: by account and by
    # id, on the documented settings URL of that account's installations.
    require(
        type(token["account_login"]) is str and token["account_login"],
        f"{label} token names no installation account",
    )
    require(
        token["target_type"] in INSTALLATION_TARGET_TYPES,
        f"{label} token installation target type is not a documented type",
    )
    require(
        token["installation_settings_url"] == _installation_settings_url(
            token["target_type"],
            {"login": token["account_login"], "type": token["target_type"]},
            token["installation_id"], f"{label} token",
        ),
        f"{label} token installation settings URL is not the documented URL "
        "of this exact installation",
    )

    # --- canonical repository identity ------------------------------------
    repository = _exact_members(
        document["repository"], SERVER_REPOSITORY_KEYS, f"{label} repository",
    )
    require(
        repository["full_name"] == live["source_repository"]
        and repository["full_name"] != AUTHORITY_REPOSITORY,
        f"{label} repository is not the protected source repository",
    )
    repository_id = _canonical_identifier(
        repository["id"], f"{label} repository id",
    )
    require(
        type(repository["node_id"]) is str and repository["node_id"],
        f"{label} repository node id is absent",
    )
    require(
        repository["default_branch"] == sealed_head_branch(SOURCE_REF),
        f"{label} repository default branch mismatch",
    )

    full_name = repository["full_name"]
    workflow_name = PurePosixPath(live["source_workflow_path"]).name
    runs_endpoint = (
        f"{GITHUB_API_ROOT}/repos/{full_name}/actions/workflows"
        f"/{workflow_name}/runs"
    )
    run_id = live["run_id"]
    jobs_endpoint = (
        f"{GITHUB_API_ROOT}/repos/{full_name}/actions/runs/{run_id}/jobs"
    )
    artifacts_endpoint = (
        f"{GITHUB_API_ROOT}/repos/{full_name}/actions/runs/{run_id}/artifacts"
    )

    # --- exhaustive workflow run pagination, cross-read with the pages ----
    runs = document["workflow_runs"]
    require(
        type(runs) is dict and tuple(sorted(runs)) == ("pages",),
        f"{label} workflow run provenance is malformed",
    )
    # The traversal is proved complete by the server's own Link relations in
    # the raw captures; the sealed pages must be exactly that traversal.
    run_total = _authenticated_pages(
        runs["pages"], f"{label} workflow run", runs_endpoint,
    )
    require(
        run_total >= 1,
        f"{label} workflow run traversal observed no authorized run",
    )

    # --- exhaustive job pagination, every job of the authorized run -------
    jobs = document["jobs"]
    require(
        type(jobs) is dict and tuple(sorted(jobs)) == ("entries", "pages"),
        f"{label} job provenance is malformed",
    )
    job_entries = jobs["entries"]
    require(
        type(job_entries) is list and job_entries,
        f"{label} job inventory is empty",
    )
    job_total = _authenticated_pages(
        jobs["pages"], f"{label} job", jobs_endpoint,
    )
    require(
        job_total == len(job_entries),
        f"{label} job pagination total contradicts the job inventory",
    )
    job_ids = []
    job_names = []
    for entry in job_entries:
        _exact_members(entry, SERVER_JOB_KEYS, f"{label} job")
        job_ids.append(_canonical_identifier(entry["id"], f"{label} job id"))
        require(
            entry["run_id"] == run_id,
            f"{label} job does not belong to the authorized run",
        )
        require(
            entry["run_attempt"] == 1 and type(entry["run_attempt"]) is int
            and type(entry["run_attempt"]) is not bool,
            f"{label} job is not the authorized attempt 1",
        )
        require(
            entry["status"] == "completed" and entry["conclusion"] == "success",
            f"{label} job did not complete successfully",
        )
        require(
            entry["head_sha"] == live["run_head_sha"],
            f"{label} job head is not the authenticated run head",
        )
        for field in ("started_at", "completed_at"):
            require(
                type(entry[field]) is str and entry[field],
                f"{label} job {field} is absent",
            )
        job_names.append(entry["name"])
    require(
        len(set(job_ids)) == len(job_ids),
        f"{label} job pagination repeats a job",
    )
    require(
        job_names.count(SOURCE_JOB_NAME) == 1,
        f"{label} do not hold exactly one authorized {SOURCE_JOB_NAME} job",
    )

    # --- the exact authenticated head and tree ----------------------------
    head = _exact_members(document["head"], SERVER_HEAD_KEYS, f"{label} head")
    require(
        head["commit"] == live["run_head_sha"],
        f"{label} head commit is not the authenticated run head",
    )
    require(
        head["tree"] == live["source_bootstrap_tree"],
        f"{label} head tree is not the authenticated run head tree",
    )

    # --- every required path and blob, rehashed from authenticated bytes --
    sealed_blobs = {
        SOURCE_WORKFLOW: read_bytes(
            root / SOURCE_WORKFLOW_FILE, "executed protected-source workflow",
        ),
        SOURCE_HELPER: read_bytes(
            root / SOURCE_HELPER_FILE, "executed protected-source helper",
        ),
        SOURCE_BOOTSTRAP_CONTRACT: read_bytes(
            root / SOURCE_CONTRACT_FILE,
            "authenticated protected-source bootstrap contract",
        ),
    }
    tree = document["tree"]
    require(
        type(tree) is dict and tuple(sorted(tree)) == ("entries", "truncated"),
        f"{label} tree provenance is malformed",
    )
    require(tree["truncated"] is False, f"{label} tree read is truncated")
    require(type(tree["entries"]) is list, f"{label} tree entries are malformed")
    observed_paths = []
    for entry in tree["entries"]:
        _exact_members(entry, SERVER_TREE_ENTRY_KEYS, f"{label} tree entry")
        path = entry["path"]
        require(
            path in sealed_blobs, f"{label} tree names an unsealed path: {path}",
        )
        require(
            path not in observed_paths, f"{label} tree repeats a path: {path}",
        )
        observed_paths.append(path)
        data = sealed_blobs[path]
        require(
            entry["mode"] == BLOB_MODE,
            f"{label} tree entry is not a regular blob: {path}",
        )
        require(
            entry["blob_sha"] == _git_blob_oid(data),
            f"{label} tree entry object name is not the authenticated blob: {path}",
        )
        require(
            entry["sha256"] == hashlib.sha256(data).hexdigest(),
            f"{label} tree entry digest is not the authenticated blob digest: {path}",
        )
        require(
            entry["size"] == len(data),
            f"{label} tree entry size mismatch: {path}",
        )
    require(
        sorted(observed_paths) == sorted(sealed_blobs),
        f"{label} tree membership is incomplete",
    )

    # --- the immutable artifact, by canonical id, name and digest ---------
    artifacts = document["artifacts"]
    require(
        type(artifacts) is dict
        and tuple(sorted(artifacts)) == ("entries", "pages"),
        f"{label} artifact provenance is malformed",
    )
    artifact_entries = artifacts["entries"]
    require(
        type(artifact_entries) is list and len(artifact_entries) == 1,
        f"{label} artifact inventory is not the sole authorized artifact",
    )
    artifact_total = _authenticated_pages(
        artifacts["pages"], f"{label} artifact", artifacts_endpoint,
    )
    require(
        artifact_total == len(artifact_entries),
        f"{label} artifact pagination total contradicts the inventory",
    )
    artifact = _exact_members(
        artifact_entries[0], SERVER_ARTIFACT_KEYS, f"{label} artifact",
    )
    _require_artifact_archive(root, artifact, live, label)
    artifact_id = _canonical_identifier(
        artifact["id"], f"{label} artifact id",
    )
    require(
        artifact["name"] == live["artifact_name"],
        f"{label} artifact is not the sealed authorized artifact",
    )
    require(artifact["expired"] is False, f"{label} artifact is expired")
    require(
        type(artifact["node_id"]) is str and artifact["node_id"],
        f"{label} artifact node id is absent",
    )
    _positive_int(artifact["size_in_bytes"], f"{label} artifact size")
    reference = artifact["workflow_run"]
    require(
        type(reference) is dict and reference.get("id") == run_id,
        f"{label} artifact does not belong to the authorized run",
    )
    # The server-returned archive digest is consumed verbatim: it is real
    # provenance, never a locally computed stand-in. A placeholder or
    # low-entropy digest is refused, and the member-wise artifact content
    # digest this lane recomputed for itself is bound separately below.
    digest = artifact["digest"]
    require(
        type(digest) is str and digest.startswith(ARTIFACT_DIGEST_PREFIX)
        and HEX64.fullmatch(digest[len(ARTIFACT_DIGEST_PREFIX):]) is not None,
        f"{label} artifact digest is not a canonical server-returned digest",
    )
    require(
        len(set(digest[len(ARTIFACT_DIGEST_PREFIX):])) >= MINIMUM_DIGEST_ENTROPY,
        f"{label} artifact digest is a placeholder",
    )
    require(
        type(live["artifact_content_sha256"]) is str
        and HEX64.fullmatch(live["artifact_content_sha256"]) is not None,
        f"{label} artifact content digest was not recomputed",
    )
    return {
        "artifact_content_sha256": live["artifact_content_sha256"],
        "artifact_digest": digest,
        "artifact_id": artifact_id,
        "artifact_name": artifact["name"],
        "head_commit": head["commit"],
        "head_tree": head["tree"],
        "job_ids": sorted(job_ids),
        "repository": full_name,
        "repository_id": repository_id,
        "run_id": run_id,
        "tree_paths": sorted(observed_paths),
    }


def read_reviewer_decision(root, bindings, run):
    """Authenticate the independent reviewer's own decision bytes.

    The bytes are not part of this candidate: the reviewer writes them at
    `decisions/<authority head>.json`, a path that cannot even be named before
    the exact candidate exists. This lane only authenticates them, and only
    once the sealed delivery evidence has proved the writer identity, the
    derived path, the delivery commit, tree and blob, the branch protection
    and an independent readback. It never formulates, defaults or repairs a
    decision, and a decision that is absent, undelivered, malformed,
    contradictory, candidate-owned or bound to a different candidate leaves
    the activation unauthorized.
    """
    path = (
        Path(root) / REVIEWER_DECISION_DIRECTORY
        / f'{bindings["head_commit"]}.json'
    )
    require(
        path.is_file() and not path.is_symlink(),
        "no independent reviewer decision exists for this exact candidate, so "
        "the activation stays unauthorized",
    )
    data = path.read_bytes()
    require(data, "the independent reviewer decision is empty")
    delivery = authenticate_decision_delivery(root, bindings, run, data)
    decision = closed_json(data, "independent reviewer decision")
    require(
        type(decision) is dict
        and tuple(sorted(decision)) == REVIEWER_DECISION_KEYS,
        "the independent reviewer decision field set mismatch",
    )
    require(
        data == json.dumps(decision, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
        "the independent reviewer decision is not canonical exact JSON",
    )
    require(
        decision["schema_version"] == 1
        and type(decision["schema_version"]) is int
        and decision["document_type"] == REVIEWER_DECISION_TYPE,
        "the independent reviewer decision identity mismatch",
    )

    # --- the strict decision, accepted only when it is really present ---
    require(
        type(decision["decision"]) is str
        and decision["decision"] == REQUIRED_DECISION,
        "the independent reviewer did not approve this exact candidate",
    )
    require(
        type(decision["findings"]) is list and decision["findings"] == [],
        "the independent reviewer recorded findings against this candidate",
    )
    require(
        type(decision["findings_count"]) is int
        and type(decision["findings_count"]) is not bool
        and decision["findings_count"] == REQUIRED_FINDINGS_COUNT,
        "the independent reviewer finding count is not an integer zero",
    )
    require(
        decision["activation_authorized"] is True,
        "the independent reviewer decision does not authorize the activation",
    )
    require(
        decision["candidate_owned"] is False,
        "a candidate-owned decision is never an independent review",
    )
    require(
        decision["produced_after_candidate"] is True,
        "the decision does not attest it was produced after the candidate",
    )
    require(
        decision["reviewer_profile"] == REVIEWER_PROFILE,
        "the independent reviewer profile mismatch",
    )
    require(
        type(decision["reviewer_repository"]) is str
        and decision["reviewer_repository"] == INDEPENDENT_REPOSITORY
        and decision["reviewer_repository"] != AUTHORITY_REPOSITORY,
        "the decision is self-reviewed by the candidate repository",
    )

    # --- every binding recomputed here, never taken from the decision ---
    for field in REVIEWER_DECISION_BOUND_FIELDS:
        require(
            decision[field] == bindings[field],
            f"the independent reviewer decision {field} is not this candidate",
        )
    return decision, delivery


def build_external_activation_review(root, run):
    """Package the reviewer's authenticated decision, never author one.

    The receipt exists only once every canonical server object and the sealed
    reviewer decision delivery have authenticated, and it binds both.
    """
    bindings = external_review_bindings(root, run)
    decision, delivery = read_reviewer_decision(root, bindings, run)
    server_objects = authenticate_server_objects(root, run)
    receipt = dict(bindings)
    for field in REVIEWER_DECISION_COPIED_FIELDS:
        receipt[field] = decision[field]
    receipt["decision_delivery"] = delivery
    receipt["server_objects"] = server_objects
    receipt["receipt_type"] = EXTERNAL_REVIEW_RECEIPT_TYPE
    receipt["schema_version"] = 1
    return json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def write_external_activation_review(root, run):
    """Write the receipt exclusively, then seal it read-only and read back.

    A pre-planted file fails closed. Once written the receipt is sealed to
    `0444`, its mode is read back from the filesystem and its digest is
    recomputed from the sealed bytes, so the emitted digest is the digest of
    the immutable artifact rather than of what was intended to be written.
    """
    directory = Path(root) / ARTIFACT_DIRECTORY
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = build_external_activation_review(root, run)
    path = Path(root) / EXTERNAL_REVIEW_FILE
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise SystemExit(
            "the external activation review receipt already exists or is unsafe"
        ) from error
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, SEALED_FILE_MODE)
    observed = os.stat(path).st_mode & 0o777
    require(
        observed == SEALED_FILE_MODE,
        "the external activation review receipt did not seal read-only",
    )
    sealed = path.read_bytes()
    require(
        sealed == data,
        "the sealed external activation review receipt is not the written bytes",
    )
    return {
        "mode": format(observed, "04o"),
        "sealed": True,
        "sha256": hashlib.sha256(sealed).hexdigest(),
        "size": len(sealed),
    }


# ---------------------------------------------------------------------------
# Composition of the sealed evidence documents
#
# These phases never decide anything. They only rearrange bytes the workflow
# already obtained from authenticated read-only GitHub GETs at constant paths,
# and recompute digests from the authenticated blobs on disk. The
# external-review phase then re-authenticates every value independently, so a
# composition that invented a value could only contradict the lane and fail
# closed.
# ---------------------------------------------------------------------------
def _member(payload, path, label):
    for key in path:
        require(type(payload) is dict, f"{label} is malformed")
        require(key in payload, f"{label} is absent")
        payload = payload[key]
    return payload


def _write_sealed_document(path, document, label):
    """Write one composed evidence document exclusively and seal it 0444."""
    data = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise SystemExit(f"{label} already exists or is unsafe") from error
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, SEALED_FILE_MODE)
    observed = os.stat(path).st_mode & 0o777
    require(observed == SEALED_FILE_MODE, f"{label} did not seal read-only")
    sealed = path.read_bytes()
    require(sealed == data, f"{label} sealed bytes are not the written bytes")
    return {
        "mode": format(observed, "04o"),
        "sealed": True,
        "sha256": hashlib.sha256(sealed).hexdigest(),
    }


def compose_server_objects(root):
    """Seal the canonical server-object evidence derived from the raw captures.

    This decides nothing and invents nothing. Every value is a deterministic
    function of the raw `gh api -i` captures the workflow recorded, so the
    external-review phase can recompute the same document independently and
    refuse any document that is not exactly what those captures produce.
    """
    root = Path(root)
    return _write_sealed_document(
        root / SERVER_OBJECTS_FILE,
        _derive_server_objects(root),
        "authenticated GitHub server objects document",
    )



def resolve_authorized_candidate_head(run, authority_commit):
    """Bind the authorized Authority head from the authenticated server read.

    The sealed contract leaves the head and tree null until an authorized run
    has executed, so the delivery phase resolves them from exactly the
    authenticated Authority commit the workflow reads, and a sealed pin, once
    present, must equal it. Nothing here is caller selectable, and the exact
    head the checkout must sit at is still the one this resolution returns.
    """
    require(type(authority_commit) is dict,
            "authenticated Authority commit is malformed")
    head = authority_commit.get("sha")
    tree = authority_commit.get("tree")
    require(type(tree) is dict, "authenticated Authority commit tree is absent")
    head_tree = tree.get("sha")
    require(
        type(head) is str and HEX40.fullmatch(head) is not None
        and type(head_tree) is str and HEX40.fullmatch(head_tree) is not None,
        "authenticated Authority head or tree is malformed",
    )
    derived = {"authority_head_commit": head, "authority_head_tree": head_tree}
    for field, value in derived.items():
        sealed = run.get(field)
        require(sealed is None or sealed == value,
                f"sealed {field} contradicts the authenticated server state")
    resolved = dict(run)
    resolved.update(derived)
    return resolved


def deliver_reviewer_decision(root, run):
    """Deliver the reviewer's own authored decision; never author one.

    This is the production delivery step, and it composes no verdict. The
    independent reviewer authors the decision in their own repository, at
    `reviewer-authored-decisions/<authority head>.json` — a path that cannot
    even be named before this exact candidate exists. This lane re-derives
    every binding from the authenticated Authority checkout, requires the
    authored bytes to bind exactly this candidate, and publishes those exact
    bytes at the derived delivery path. Every verdict field stays the
    reviewer's alone: a decision this lane could compose for itself would
    authorize nothing, so an absent, malformed, non-canonical or
    foreign-candidate artifact leaves the activation unauthorized.

    The workflow step that follows creates a signed, reviewer-owned commit
    over exactly that path and pushes it with a fail-closed CAS.
    """
    root = Path(root)
    bindings = external_review_bindings(root, run)
    head = bindings["head_commit"]
    authored = read_bytes(
        root / REVIEWER_AUTHORED_DECISION_DIRECTORY / f"{head}.json",
        "independent reviewer authored decision",
    )
    require(authored, "the independent reviewer authored decision is empty")
    document = closed_json(authored, "independent reviewer authored decision")
    require(
        type(document) is dict
        and tuple(sorted(document)) == REVIEWER_DECISION_KEYS,
        "the independent reviewer authored decision field set mismatch",
    )
    require(
        authored
        == json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        "the independent reviewer authored decision is not canonical exact JSON",
    )
    require(
        document["document_type"] == REVIEWER_DECISION_TYPE
        and type(document["schema_version"]) is int
        and document["schema_version"] == 1,
        "the independent reviewer authored decision identity mismatch",
    )
    for field in REVIEWER_DECISION_BOUND_FIELDS:
        require(
            document[field] == bindings[field],
            f"the authored reviewer decision {field} is not this candidate",
        )
    path = root / REVIEWER_DECISION_DIRECTORY / f"{head}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise SystemExit(
            "the reviewer decision already exists or is unsafe"
        ) from error
    try:
        os.write(descriptor, authored)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "decision_path": str(path.relative_to(root)),
        "head_commit": head,
        "sha256": hashlib.sha256(authored).hexdigest(),
    }


# ---------------------------------------------------------------------------
# F8-INDEPENDENT-DECISION-DELIVERY-STILL-NONPRODUCTION
#
# The decision must reach the lane as a real, reviewer-owned, server-verifiable
# signed commit: one created through the documented Git Data API, signed with a
# key only the independent reviewer holds, introducing exactly one path, and
# installed by an atomic expected-head compare-and-swap. Everything below is
# that mechanism. It composes no verdict and it never believes a value it did
# not recompute: the blob object name, the complete parent-to-commit tree
# difference and the sole parent are all derived here, and the server's own
# signature verification is required rather than assumed.
# ---------------------------------------------------------------------------
DELIVERY_BLOB_MODE = "100644"
DELIVERY_REF_PATH = f"heads/{DECISION_DELIVERY_BRANCH}"
DELIVERY_TARGET_REF = f"refs/{DELIVERY_REF_PATH}"
DELIVERY_CREATE_KEYS = ("parents", "sha", "tree", "verification")
# The atomic primitive, on the target reference itself.
#
# GitHub's REST reference-update endpoint takes `sha` and `force` and no
# expected-old-OID at all, so no REST call can be a compare-and-swap on the
# reference it rewrites. A *side* reference created by `POST /git/refs` is
# atomic, but it is a different reference: nothing about creating it
# constrains what `refs/heads/main` holds at the instant it is rewritten.
#
# The Git wire protocol is the one GitHub-reachable primitive that does. A
# push update command is `<old-oid> <new-oid> <ref>`, and the receiving side
# applies it inside a reference transaction that fails unless the reference
# still holds exactly `<old-oid>`. `--force-with-lease=<ref>:<oid>` states
# that expectation explicitly rather than inferring it from a remote-tracking
# ref, so the old OID this lane read for itself is the old OID the server
# enforces. If the primitive is unavailable for any reason - no `git`, no
# reachable remote, a refused push - the delivery fails closed and the target
# reference is never touched.
DELIVERY_CAS_PRIMITIVE = "git-receive-pack-expected-old-oid"
# Using the primitive is not the same as proving it is in force. A `git` or a
# transport that accepts the update command but drops its old-OID precondition
# would install the decision straight over a racing writer, and would only be
# found out once the target reference had already been rewritten. So the
# capability is demonstrated first, in a scratch repository, against a real
# `git receive-pack`: a push whose update command states an OID the reference
# does not hold must be refused, and a push that states the OID it really
# holds must be applied. Both halves, or the delivery reports the capability
# unproven and touches nothing.
DELIVERY_CAS_CAPABILITY_PROBE = "stale-lease-refused-and-honest-lease-applied"
DELIVERY_CAS_PROOF_BRANCH = "main"
DELIVERY_CAS_PROOF_REF = f"refs/heads/{DELIVERY_CAS_PROOF_BRANCH}"
DELIVERY_CAS_PROOF_IDENTITY = {
    "GIT_AUTHOR_NAME": "acc-cas-capability-proof",
    "GIT_AUTHOR_EMAIL": "acc-cas-capability-proof@localhost",
    "GIT_AUTHOR_DATE": "@0 +0000",
    "GIT_COMMITTER_NAME": "acc-cas-capability-proof",
    "GIT_COMMITTER_EMAIL": "acc-cas-capability-proof@localhost",
    "GIT_COMMITTER_DATE": "@0 +0000",
}
DELIVERY_REMOTE_TEMPLATE = "https://github.com/{repository}.git"
# The push credential travels in the environment, never in argv.
DELIVERY_PUSH_TIMEOUT_SECONDS = 120
PGP_SIGNATURE_HEADER = "-----BEGIN PGP SIGNATURE-----"
# The identity the signed commit object carries is never a constant of this
# lane. GitHub verifies a commit signature against the *committer* address and
# reports `verified` only for an address the signing key has registered and
# verified on the account, so a placeholder address could never produce a
# verified delivery at all. The identity is read back from the authenticated
# account and from the registered key that is about to sign, and the exact
# same bytes are both signed and sent.
REVIEWER_ACCOUNT_ENDPOINT = "/user"
REVIEWER_GPG_KEYS_ENDPOINT = "/user/gpg_keys"
GPG_LONG_KEY_ID = re.compile(r"[0-9A-F]{16}")
DELIVERY_IDENTITY_KEYS = ("date", "email", "name")
# The commit object timestamp form this lane emits. It carries no local zone:
# the instant is recorded in UTC, so the signed bytes and the request object
# are two renderings of exactly one moment.
DELIVERY_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DELIVERY_UTC_OFFSET = "+0000"


def _api_path(suffix):
    return f"/repos/{INDEPENDENT_REPOSITORY}{suffix}"


def _github_git_data_transport(token):
    """The production transport: the documented Git Data endpoints, nothing else.

    It is constructed here rather than accepted from a caller, so no caller can
    substitute a transport that reaches an undocumented or write-wider
    endpoint. The delivery lane below is the only user.
    """
    import urllib.error
    import urllib.request

    def request(method, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        target = urllib.request.Request(
            f"{GITHUB_API_ROOT}{path}", data=body, method=method,
        )
        target.add_header("Accept", "application/vnd.github+json")
        target.add_header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        target.add_header("Authorization", f"Bearer {token}")
        if body is not None:
            target.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(target) as answer:
                return json.loads(answer.read())
        except urllib.error.HTTPError as error:
            # The status is part of the answer: a 422 on the claim reference
            # is the compare-and-swap being lost, not a transport failure.
            raise SystemExit(
                f"reviewer decision delivery {method} {path} was refused: "
                f"HTTP {error.code}"
            ) from error
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise SystemExit(
                f"reviewer decision delivery {method} {path} failed"
            ) from error

    return request


def _reviewer_commit_signature(payload, *, signing_key, label):
    """The reviewer's own detached OpenPGP signature over the commit object.

    The REST create-commit `signature` field is documented as the *PGP*
    signature of the commit, which GitHub writes into the created commit's
    `gpgsig` header and then verifies against the keys the signing identity
    has registered. An SSH signature is a different format and does not
    belong in that field, so this lane produces a real ASCII-armored OpenPGP
    detached signature and nothing else. The key is the independent
    reviewer's alone: this lane can produce a signature but can never make the
    server accept one, because the created commit is kept only if GitHub
    itself reports a verified signature.
    """
    require(
        signing_key is not None,
        f"{label} has no reviewer-owned signing key",
    )
    home = Path(signing_key)
    require(
        home.is_dir() and not home.is_symlink(),
        f"{label} reviewer signing keyring is absent or unsafe",
    )
    with tempfile.TemporaryDirectory() as workspace:
        target = Path(workspace) / "commit"
        target.write_bytes(payload)
        signature = Path(workspace) / "commit.asc"
        try:
            completed = subprocess.run(
                ["gpg", "--batch", "--quiet", "--yes", "--homedir", str(home),
                 "--passphrase", "", "--armor", "--detach-sign",
                 "--output", str(signature), str(target)],
                capture_output=True,
            )
        except OSError as error:
            raise SystemExit(f"{label} could not sign the commit") from error
        require(
            completed.returncode == 0,
            f"{label} could not sign the commit object",
        )
        require(signature.is_file(), f"{label} produced no signature")
        armored = signature.read_text(encoding="utf-8")
    require(
        armored.startswith(PGP_SIGNATURE_HEADER),
        f"{label} did not produce an OpenPGP signature",
    )
    return armored


def _reviewer_signing_key_id(signing_key, label):
    """The long key id of the one secret key this keyring holds.

    It is read from the keyring that is about to sign, so the registered
    account key required below is the key that really produces the signature
    rather than some other key that merely exists on the account.
    """
    home = Path(signing_key) if signing_key is not None else None
    require(
        home is not None and home.is_dir() and not home.is_symlink(),
        f"{label} reviewer signing keyring is absent or unsafe",
    )
    try:
        completed = subprocess.run(
            ["gpg", "--batch", "--quiet", "--homedir", str(home),
             "--list-secret-keys", "--with-colons"],
            capture_output=True,
        )
    except OSError as error:
        raise SystemExit(
            f"{label} could not read the reviewer signing keyring"
        ) from error
    require(
        completed.returncode == 0,
        f"{label} could not read the reviewer signing keyring",
    )
    identifiers = [
        line.split(":")[4]
        for line in completed.stdout.decode("utf-8", "replace").splitlines()
        if line.startswith("sec:") and len(line.split(":")) > 4
    ]
    require(
        len(identifiers) == 1
        and GPG_LONG_KEY_ID.fullmatch(identifiers[0]) is not None,
        f"{label} reviewer keyring does not hold exactly one signing key",
    )
    return identifiers[0]


def _reviewer_verified_identity(transport, *, signing_key, signing_identity,
                                label):
    """The reviewer identity GitHub itself will accept, read back from GitHub.

    Two authenticated reads, both documented and both read-only. `GET /user`
    names the account this credential really is - which must be the expected
    decision writer, so the delivery is attributed to the reviewer and to
    nobody else. `GET /user/gpg_keys` names the OpenPGP keys that account has
    registered, and the key that is about to sign must be exactly one of them,
    usable, unrevoked, and carrying exactly one verified address. That address
    is the only address a commit this key signs can be verified under, so it
    is the address the signed bytes carry. An unregistered key, a revoked or
    non-signing key, an unverified address and an ambiguous address all fail
    closed here rather than producing an unverifiable delivery.
    """
    account = transport("GET", REVIEWER_ACCOUNT_ENDPOINT)
    require(
        type(account) is dict,
        f"{label} authenticated account read is malformed",
    )
    require(
        account.get("login") == signing_identity,
        f"{label} authenticated account is not the expected decision writer",
    )
    name = account.get("name")
    require(
        type(name) is str and name,
        f"{label} authenticated account publishes no reviewer name",
    )
    key_id = _reviewer_signing_key_id(signing_key, label)
    keys = transport("GET", REVIEWER_GPG_KEYS_ENDPOINT)
    require(
        type(keys) is list and keys,
        f"{label} authenticated account registers no OpenPGP key",
    )
    matching = [
        key for key in keys
        if type(key) is dict and key.get("key_id") == key_id
    ]
    require(
        len(matching) == 1,
        f"{label} signing key is not a single registered account key",
    )
    key = matching[0]
    require(
        key.get("can_sign") is True and key.get("revoked") is False,
        f"{label} registered signing key is revoked or cannot sign",
    )
    addresses = sorted({
        entry["email"] for entry in key.get("emails") or []
        if type(entry) is dict and entry.get("verified") is True
        and type(entry.get("email")) is str and entry["email"]
    })
    require(
        len(addresses) == 1,
        f"{label} registered signing key carries no single verified address",
    )
    return {"email": addresses[0], "name": name}


def _delivery_identity(reviewer, seconds, label):
    """One author/committer object: exactly one instant, two renderings."""
    require(
        type(seconds) is int and type(seconds) is not bool and seconds > 0,
        f"{label} delivery instant is malformed",
    )
    moment = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    identity = {
        "date": moment.strftime(DELIVERY_DATE_FORMAT),
        "email": reviewer["email"],
        "name": reviewer["name"],
    }
    require(
        tuple(sorted(identity)) == DELIVERY_IDENTITY_KEYS
        and all(type(value) is str and value for value in identity.values()),
        f"{label} commit identity is malformed",
    )
    return identity


def _git_identity_bytes(identity):
    """The exact `name <email> seconds +0000` bytes the commit object holds."""
    moment = datetime.datetime.strptime(
        identity["date"], DELIVERY_DATE_FORMAT,
    ).replace(tzinfo=datetime.timezone.utc)
    return (
        f"{identity['name']} <{identity['email']}> "
        f"{int(moment.timestamp())} {DELIVERY_UTC_OFFSET}"
    )


def _git_commit_oid(unsigned, signature):
    """The object name of the signed commit, recomputed from the signed bytes.

    Git stores the signature as a `gpgsig` header with continuation lines
    indented by one space. Recomputing the object name from the exact payload
    the reviewer signed plus the exact armor that was sent proves the sha the
    server returned really is that commit, rather than a different object
    reported alongside a valid-looking signature.
    """
    payload = _signed_commit_object(unsigned, signature)
    return hashlib.sha1(
        b"commit " + str(len(payload)).encode("ascii") + b"\0" + payload,
    ).hexdigest()


def _delivery_tree_entries(transport, tree_sha, label):
    """The complete recursive tree, refused outright if it was truncated."""
    document = transport(
        "GET", _api_path(f"/git/trees/{tree_sha}?recursive=1"),
    )
    require(type(document) is dict, f"{label} tree read is malformed")
    require(
        document.get("sha") == tree_sha,
        f"{label} tree read is not the tree that was asked for",
    )
    require(
        document.get("truncated") is False,
        f"{label} tree read is truncated, so it is not the complete tree",
    )
    entries = {}
    for entry in document.get("tree") or []:
        require(type(entry) is dict, f"{label} tree entry is malformed")
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        require(
            type(path) is str and path and path not in entries,
            f"{label} tree repeats or omits a path",
        )
        entries[path] = (entry.get("mode"), entry.get("sha"))
    return entries


def _delivery_remote(token):
    """The reviewer's own repository, over HTTPS, with the token in the env."""
    remote = DELIVERY_REMOTE_TEMPLATE.format(repository=INDEPENDENT_REPOSITORY)
    header = base64.b64encode(
        f"x-access-token:{token}".encode("utf-8"),
    ).decode("ascii")
    environment = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {header}",
    }
    return remote, environment


def _git_delivery(workspace, *arguments, label, environment=None, stdin=None):
    """One Git command in the reviewer's own repository, or a closed failure."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(workspace), *arguments],
            capture_output=True, input=stdin, env=environment,
            timeout=DELIVERY_PUSH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit(
            f"{label} has no compare-and-swap primitive available: "
            f"git {arguments[0]} could not be run"
        ) from error
    require(
        completed.returncode == 0,
        f"{label} compare-and-swap primitive failed: git {arguments[0]}",
    )
    return completed.stdout


def _compose_delivery_objects(workspace, *, decision, path, parent_tree,
                              tree_sha, commit_object, commit_sha, label):
    """Compose the exact delivery objects in the reviewer's own repository.

    The push protocol can only send objects this repository actually holds,
    and the commit the Git Data API created is unreachable until a reference
    points at it, so it cannot be fetched back. The identical objects are
    therefore composed here from the parent tree this lane already read, and
    every one of them must carry exactly the object name the server already
    reported. A single disagreement fails closed before any reference is
    touched: nothing is pushed that the server has not already accepted and
    verified under this reviewer's own signature.
    """
    workspace = Path(workspace)
    index = workspace / ".git" / "acc-decision-delivery-index"
    environment = {**os.environ, "GIT_INDEX_FILE": str(index)}
    try:
        blob = _git_delivery(
            workspace, "hash-object", "-t", "blob", "-w", "--stdin",
            stdin=decision, label=label,
        ).decode("ascii").strip()
        require(
            blob == _git_blob_oid(decision),
            f"{label} composed blob is not the object name of the decision",
        )
        _git_delivery(
            workspace, "read-tree", parent_tree,
            environment=environment, label=label,
        )
        _git_delivery(
            workspace, "update-index", "--add", "--cacheinfo",
            f"{DELIVERY_BLOB_MODE},{blob},{path}",
            environment=environment, label=label,
        )
        composed_tree = _git_delivery(
            workspace, "write-tree", environment=environment, label=label,
        ).decode("ascii").strip()
        require(
            composed_tree == tree_sha,
            f"{label} composed tree is not the delivery tree the server built",
        )
        composed_commit = _git_delivery(
            workspace, "hash-object", "-t", "commit", "-w", "--stdin",
            stdin=commit_object, label=label,
        ).decode("ascii").strip()
        require(
            composed_commit == commit_sha,
            f"{label} composed commit is not the delivery commit the server "
            "created",
        )
    finally:
        try:
            index.unlink()
        except OSError:
            pass


def _cas_probe(*arguments, environment, label):
    """One probe command, or a closed refusal to claim the capability."""
    try:
        return subprocess.run(
            ["git", *arguments], capture_output=True, input=b"",
            env=environment, timeout=DELIVERY_PUSH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit(
            f"{label} compare-and-swap capability could not be proven: "
            f"git {arguments[0]} could not be run"
        ) from error


def _prove_cas_capability(environment, *, label):
    """Prove the expected-old-OID primitive before any target ref is touched.

    Everything here happens inside a scratch repository this function creates
    and removes; no remote, no network and no reference outside it is
    involved. A reference is created holding one commit, and a second commit
    is pushed at it twice through a real `git receive-pack`:

      * once with an update command that states an old OID the reference does
        *not* hold. The receiving side's reference transaction must refuse it,
        and the reference must still hold what it held. Without the
        precondition this push is an ordinary fast-forward and would be
        applied - which is exactly the failure this proof exists to catch.
      * once with an update command that states the OID the reference really
        holds, which must be applied.

    Both halves must hold. If either cannot be demonstrated - no `git`, no
    `receive-pack`, or a lease that is not enforced - the capability is not
    proven, the caller fails closed and the target reference is never touched.
    Demonstrating it *after* the delivery push would be no proof at all.
    """
    environment = {**environment, **DELIVERY_CAS_PROOF_IDENTITY}
    with tempfile.TemporaryDirectory(prefix="acc-cas-capability-") as scratch:
        origin = Path(scratch) / "origin.git"
        work = Path(scratch) / "work"
        for arguments in (
            ("init", "--bare", "--quiet", f"--initial-branch={DELIVERY_CAS_PROOF_BRANCH}", str(origin)),
            ("init", "--quiet", f"--initial-branch={DELIVERY_CAS_PROOF_BRANCH}", str(work)),
        ):
            require(
                _cas_probe(*arguments, environment=environment,
                           label=label).returncode == 0,
                f"{label} compare-and-swap capability could not be proven: "
                f"the scratch repository could not be created",
            )

        def probe(*arguments):
            return _cas_probe(
                "-C", str(work), *arguments,
                environment=environment, label=label,
            )

        empty = probe("mktree")
        require(
            empty.returncode == 0,
            f"{label} compare-and-swap capability could not be proven: "
            f"the scratch tree could not be composed",
        )
        tree = empty.stdout.decode("ascii").strip()
        commits = []
        for parent in ((), ("-p", None)):
            arguments = ["commit-tree", tree, "-m", f"cas-proof-{len(commits)}"]
            if parent:
                arguments = [
                    "commit-tree", tree, "-p", commits[0], "-m",
                    f"cas-proof-{len(commits)}",
                ]
            composed = probe(*arguments)
            require(
                composed.returncode == 0,
                f"{label} compare-and-swap capability could not be proven: "
                f"the scratch commit could not be composed",
            )
            commits.append(composed.stdout.decode("ascii").strip())
        held, offered = commits
        require(
            probe("update-ref", DELIVERY_CAS_PROOF_REF, held).returncode == 0
            and probe(
                "push", "--quiet", str(origin),
                f"{held}:{DELIVERY_CAS_PROOF_REF}",
            ).returncode == 0,
            f"{label} compare-and-swap capability could not be proven: "
            f"the scratch reference could not be established",
        )

        def scratch_head():
            read = _cas_probe(
                "-C", str(origin), "rev-parse", DELIVERY_CAS_PROOF_REF,
                environment=environment, label=label,
            )
            require(
                read.returncode == 0,
                f"{label} compare-and-swap capability could not be proven: "
                f"the scratch reference could not be read back",
            )
            return read.stdout.decode("ascii").strip()

        require(
            scratch_head() == held,
            f"{label} compare-and-swap capability could not be proven: "
            f"the scratch reference does not hold the commit it was set to",
        )
        # The stale half. The offered commit is a child of what the reference
        # holds, so without the old-OID precondition this is a plain
        # fast-forward and is applied. It must be refused instead.
        stale = probe(
            "push", "--atomic", "--porcelain",
            f"--force-with-lease={DELIVERY_CAS_PROOF_REF}:{offered}",
            str(origin), f"{offered}:{DELIVERY_CAS_PROOF_REF}",
        )
        require(
            stale.returncode != 0 and scratch_head() == held,
            f"{label} compare-and-swap capability could not be proven: an "
            f"update command stating an old OID the reference does not hold "
            f"was not refused, so no expected-old-OID precondition is in "
            f"force and no reference may be mutated under it",
        )
        # The honest half: the same primitive must still install a real move.
        honest = probe(
            "push", "--atomic", "--porcelain",
            f"--force-with-lease={DELIVERY_CAS_PROOF_REF}:{held}",
            str(origin), f"{offered}:{DELIVERY_CAS_PROOF_REF}",
        )
        require(
            honest.returncode == 0 and scratch_head() == offered,
            f"{label} compare-and-swap capability could not be proven: the "
            f"primitive refused an update command stating the OID the "
            f"reference really holds",
        )
    return {
        "cas_capability_probe": DELIVERY_CAS_CAPABILITY_PROBE,
        "cas_capability_proven": True,
    }


def _install_delivery_commit(workspace, *, remote, environment, commit_sha,
                             expected_head, label):
    """Move the target reference under its expected old OID, or fail closed.

    This is the compare-and-swap, and it is performed on the target reference
    itself. `--force-with-lease=<ref>:<oid>` puts the expected old OID into
    the push update command, and the receiving side applies that command in a
    reference transaction that refuses it unless the reference still holds
    exactly that OID - including against a writer that lands after the pack
    arrives and before the transaction commits. There is no side reference,
    and no REST reference write happens at all.
    """
    # The capability first, before a single byte goes at the target: a
    # primitive that is not proven to enforce the old OID may not be used to
    # rewrite anything.
    capability = _prove_cas_capability(environment, label=label)
    lease = f"--force-with-lease={DELIVERY_TARGET_REF}:{expected_head}"
    try:
        completed = subprocess.run(
            ["git", "-C", str(workspace), "push", "--atomic", "--porcelain",
             lease, remote, f"{commit_sha}:{DELIVERY_TARGET_REF}"],
            capture_output=True, env=environment,
            timeout=DELIVERY_PUSH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit(
            f"{label} has no compare-and-swap primitive available: the "
            "expected-old-OID push could not be run"
        ) from error
    answer = completed.stdout.decode("utf-8", "replace")
    require(
        completed.returncode == 0,
        f"{label} expected-old-head compare-and-swap was refused by the "
        f"server: the target reference did not hold {expected_head}",
    )
    # `--porcelain` reports one `<flag>\t<src>:<dst>\t<summary>` line per
    # reference. A blank flag is a fast-forward and `*` is a created
    # reference; `!` is a refusal and `=` means the reference already held
    # this commit, which is a claim this lane never gets to make about a
    # commit it has just created. Only a real move is an installation.
    installed = [
        line.split("\t") for line in answer.splitlines()
        if line.count("\t") == 2
        and line.split("\t")[1].endswith(f":{DELIVERY_TARGET_REF}")
    ]
    require(
        len(installed) == 1,
        f"{label} expected-old-head compare-and-swap did not report exactly "
        f"one update of {DELIVERY_TARGET_REF}",
    )
    flag, reference, summary = installed[0]
    require(
        flag.strip() in ("", "*")
        and reference == f"{commit_sha}:{DELIVERY_TARGET_REF}",
        f"{label} expected-old-head compare-and-swap did not install the "
        f"delivery commit on the target reference: {flag.strip() or ' '} "
        f"{summary}",
    )
    return {
        **capability,
        "cas_expected_old_oid": expected_head,
        "cas_primitive": DELIVERY_CAS_PRIMITIVE,
        "cas_ref": DELIVERY_TARGET_REF,
    }


def _signed_commit_object(unsigned, signature):
    """The exact signed commit object bytes, as Git stores them."""
    head, _, message = unsigned.decode("utf-8").partition("\n\n")
    indented = signature.rstrip("\n").replace("\n", "\n ")
    return f"{head}\ngpgsig {indented}\n\n{message}".encode("utf-8")


def deliver_decision_commit(*, decision, head_commit, expected_head,
                            transport=None, signing_key=None,
                            signing_identity=DECISION_WRITER_LOGIN,
                            workspace=None, remote=None):
    """Deliver the reviewer's decision as one signed, CAS-installed commit.

    The path is derived here from the exact candidate head and is never read
    out of any evidence. The blob object name is recomputed locally and must
    equal the one the server returns. The commit carries exactly one parent -
    the expected head this lane read for itself - and the server must report a
    verified signature. The ref is then moved by an atomic fast-forward-only
    compare-and-swap, so a branch that moved after the head was read fails
    closed instead of overwriting another writer. Finally the complete
    parent-to-commit tree difference is recomputed and must be exactly the one
    derived decision path.
    """
    label = "reviewer decision delivery"
    require(
        type(decision) is bytes and decision,
        f"{label} carries no decision bytes",
    )
    require(
        type(head_commit) is str and HEX40.fullmatch(head_commit) is not None,
        f"{label} candidate head is malformed",
    )
    require(
        type(expected_head) is str
        and HEX40.fullmatch(expected_head) is not None,
        f"{label} expected head is malformed",
    )
    token = os.environ.get("GH_TOKEN", "")
    if transport is None:
        transport = _github_git_data_transport(token)
    # The reviewer's own checkout, and the reviewer's own repository. Both are
    # derived here rather than accepted from evidence, so no caller can point
    # the compare-and-swap at another repository or another working tree.
    workspace = ROOT if workspace is None else Path(workspace)
    require(
        (workspace / ".git").exists(),
        f"{label} has no reviewer repository to compose the delivery in",
    )
    if remote is None:
        remote, environment = _delivery_remote(token)
    else:
        environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    path = f"{REVIEWER_DECISION_DIRECTORY}/{head_commit}.json"

    # --- the reviewer identity, read back from GitHub, never assumed ------
    reviewer = _reviewer_verified_identity(
        transport, signing_key=signing_key,
        signing_identity=signing_identity, label=label,
    )
    # One instant, captured once, rendered into the signed bytes and into the
    # request object alike. `time.time()` is read exactly here so the two can
    # never describe different moments.
    identity = _delivery_identity(reviewer, int(time.time()), label)

    # --- the expected head, read from the server, never from a caller -----
    reference = transport("GET", _api_path(f"/git/ref/{DELIVERY_REF_PATH}"))
    require(
        type(reference) is dict
        and _member(reference, ("object", "sha"), f"{label} reference")
        == expected_head,
        f"{label} expected head is not the head the delivery branch carries",
    )

    # --- the decision blob, recomputed before it is believed --------------
    created = transport("POST", _api_path("/git/blobs"), {
        "content": base64.b64encode(decision).decode("ascii"),
        "encoding": "base64",
    })
    blob_sha = created.get("sha") if type(created) is dict else None
    require(
        blob_sha == _git_blob_oid(decision),
        f"{label} blob is not the object name of the decision bytes",
    )

    # The parent tree is the tree of the expected head, read through the same
    # complete-tree path the delivery tree is read through, so the difference
    # below is computed over two comparable complete trees.
    parent_tree_sha = _delivery_parent_tree(transport, expected_head, label)
    parent_entries = _delivery_tree_entries(
        transport, parent_tree_sha, f"{label} parent",
    )

    # --- the delivery tree, built from the parent tree plus one entry -----
    tree = transport("POST", _api_path("/git/trees"), {
        "base_tree": parent_tree_sha,
        "tree": [{
            "mode": DELIVERY_BLOB_MODE, "path": path,
            "sha": blob_sha, "type": "blob",
        }],
    })
    tree_sha = tree.get("sha") if type(tree) is dict else None
    require(
        type(tree_sha) is str and HEX40.fullmatch(tree_sha) is not None,
        f"{label} delivery tree is malformed",
    )

    # --- the reviewer's own OpenPGP signature over the exact commit -------
    message = f"deliver: reviewer decision for {head_commit}"
    unsigned = _unsigned_commit_object(
        tree_sha, [expected_head], message, identity,
    )
    signature = _reviewer_commit_signature(
        unsigned, signing_key=signing_key, label=label,
    )
    # The author and committer are *sent*, not left to the server. An omitted
    # author is filled in by GitHub from the authenticated identity and from
    # its own clock, which is by construction not the object the reviewer
    # signed, so the signature could never verify. These are the exact same
    # bytes that were signed a moment ago.
    commit = transport("POST", _api_path("/git/commits"), {
        "author": dict(identity),
        "committer": dict(identity),
        "message": message,
        "parents": [expected_head],
        "signature": signature,
        "tree": tree_sha,
    })
    require(type(commit) is dict, f"{label} commit creation is malformed")
    commit_sha = commit.get("sha")
    require(
        type(commit_sha) is str and HEX40.fullmatch(commit_sha) is not None
        and commit_sha != expected_head,
        f"{label} delivery commit is malformed or is the expected head",
    )
    parents = [
        entry.get("sha") for entry in commit.get("parents") or []
        if type(entry) is dict
    ]
    require(
        parents == [expected_head],
        f"{label} delivery commit sole parent is not the expected head",
    )
    require(
        _member(commit, ("tree", "sha"), f"{label} commit tree") == tree_sha,
        f"{label} delivery commit does not carry the delivery tree",
    )

    # --- the signed author and committer bytes ----------------------------
    # The server returns author and committer as structured objects. Both must
    # be exactly the identity that was signed, and the signed payload the
    # server echoes must be exactly the object bytes this lane produced - so
    # a commit reported beside a valid signature over different bytes fails.
    for role in ("author", "committer"):
        observed = commit.get(role)
        require(
            type(observed) is dict
            and {key: observed.get(key) for key in identity} == identity,
            f"{label} delivery commit {role} is not the signed {role} bytes",
        )
    verification = commit.get("verification")
    require(
        type(verification) is dict
        and verification.get("verified") is True
        and verification.get("reason") == "valid",
        f"{label} commit signature is not verified by the server",
    )
    require(
        verification.get("signature") == signature,
        f"{label} commit does not carry the signature this reviewer produced",
    )
    require(
        type(verification.get("payload")) is str
        and verification["payload"].encode("utf-8") == unsigned,
        f"{label} verified payload is not the commit object that was signed",
    )
    # The object name, recomputed from the signed payload and the signature.
    require(
        _git_commit_oid(unsigned, signature) == commit_sha,
        f"{label} delivery commit is not the object name of the signed bytes",
    )

    # --- the complete parent-to-commit difference, before the ref moves ---
    delivery_entries = _delivery_tree_entries(
        transport, tree_sha, f"{label} delivery",
    )
    changed = sorted(
        name for name in set(parent_entries) | set(delivery_entries)
        if parent_entries.get(name) != delivery_entries.get(name)
    )
    require(
        changed == [path],
        f"{label} commit does not change exactly one path: "
        f"{', '.join(changed) or 'nothing'}",
    )
    require(
        delivery_entries[path] == (DELIVERY_BLOB_MODE, blob_sha),
        f"{label} delivery tree does not carry the delivered decision blob",
    )

    # --- the expected-old-OID compare-and-swap on the target reference ----
    # Composed locally first, because the push protocol can only send objects
    # this repository holds and the API-created commit is still unreachable.
    # Every composed object name must equal the one the server reported.
    _compose_delivery_objects(
        workspace, decision=decision, path=path, parent_tree=parent_tree_sha,
        tree_sha=tree_sha,
        commit_object=_signed_commit_object(unsigned, signature),
        commit_sha=commit_sha, label=label,
    )
    # The claim is stated on the target reference itself, in the push update
    # command, and the server's reference transaction enforces it.
    installation = _install_delivery_commit(
        workspace, remote=remote, environment=environment,
        commit_sha=commit_sha, expected_head=expected_head, label=label,
    )

    # --- the race read-back: ref, commit, tree and path -------------------
    # Everything above describes what was sent. This reads back what the
    # server now actually holds, so a writer that landed between the update
    # and this read is caught instead of being reported as a success.
    observed_ref = transport("GET", _api_path(f"/git/ref/{DELIVERY_REF_PATH}"))
    require(
        _member(observed_ref, ("object", "sha"), f"{label} read back reference")
        == commit_sha,
        f"{label} delivery branch does not read back as the delivery commit",
    )
    observed_commit = transport(
        "GET", _api_path(f"/git/commits/{commit_sha}"),
    )
    require(
        type(observed_commit) is dict
        and observed_commit.get("sha") == commit_sha
        and [
            entry.get("sha") for entry in observed_commit.get("parents") or []
            if type(entry) is dict
        ] == [expected_head]
        and _member(
            observed_commit, ("tree", "sha"), f"{label} read back commit tree",
        ) == tree_sha,
        f"{label} delivery commit does not read back as the commit installed",
    )
    observed_entries = _delivery_tree_entries(
        transport, tree_sha, f"{label} read back",
    )
    require(
        observed_entries == delivery_entries
        and observed_entries.get(path) == (DELIVERY_BLOB_MODE, blob_sha),
        f"{label} delivery tree does not read back as the tree installed",
    )
    content = transport(
        "GET", _api_path(f"/contents/{path}?ref={commit_sha}"),
    )
    require(
        type(content) is dict and content.get("path") == path
        and content.get("sha") == blob_sha
        and content.get("encoding") == "base64",
        f"{label} delivered path does not read back at the delivery commit",
    )
    try:
        readback = base64.b64decode(content.get("content") or "", validate=False)
    except (ValueError, TypeError) as error:
        raise SystemExit(f"{label} read back path is malformed") from error
    require(
        readback == decision,
        f"{label} read back path is not the decision bytes that were delivered",
    )
    return {
        **installation,
        "author": identity,
        "blob_sha": blob_sha,
        "changed_paths": changed,
        "commit_parent": expected_head,
        "commit_sha": commit_sha,
        "commit_tree": tree_sha,
        "committer": identity,
        "parent_tree": parent_tree_sha,
        "path": path,
        "readback_decision_sha256": hashlib.sha256(readback).hexdigest(),
        "signature_verified": True,
        "signed_payload_sha256": hashlib.sha256(unsigned).hexdigest(),
    }


REVIEWER_SIGNING_KEY_VARIABLE = "ACC_REVIEWER_SIGNING_KEY"
DELIVERY_EXPECTED_HEAD_VARIABLE = "GITHUB_SHA"


def _expected_delivery_head():
    """The exact head this run was checked out at, and nothing else.

    It is the compare-and-swap expectation: the delivery may install its
    commit only while the delivery branch still carries exactly this commit.
    """
    head = os.environ.get(DELIVERY_EXPECTED_HEAD_VARIABLE, "")
    require(
        HEX40.fullmatch(head) is not None,
        "the reviewer decision delivery has no authenticated expected head",
    )
    return head


def _delivery_parent_tree(transport, expected_head, label):
    """The tree of the expected head, from the server's own commit object."""
    commit = transport("GET", _api_path(f"/git/commits/{expected_head}"))
    tree_sha = _member(commit, ("tree", "sha"), f"{label} parent commit")
    require(
        type(tree_sha) is str and HEX40.fullmatch(tree_sha) is not None,
        f"{label} parent commit tree is malformed",
    )
    return tree_sha


def _unsigned_commit_object(tree, parents, message, identity):
    """The exact commit object bytes the reviewer signs, with no signature.

    The author and committer bytes are rendered from the very identity object
    that is sent in the create-commit request, so what is signed and what is
    asked for can never be two different things.
    """
    rendered = _git_identity_bytes(identity)
    lines = [f"tree {tree}"]
    lines += [f"parent {parent}" for parent in parents]
    lines.append(f"author {rendered}")
    lines.append(f"committer {rendered}")
    return ("\n".join(lines) + "\n\n" + message + "\n").encode("utf-8")


def compose_decision_delivery(root, bootstrap_commit, bootstrap_tree):
    """Compose the sealed reviewer decision delivery evidence."""
    root = Path(root)
    label = "reviewer decision delivery"
    authority_commit = closed_json(
        read_bytes(root / AUTHORITY_COMMIT_FILE,
                   "authenticated Authority commit"),
        "authenticated Authority commit",
    )
    head_commit = _member(
        authority_commit, ("sha",), "authenticated Authority head",
    )
    require(
        type(head_commit) is str and HEX40.fullmatch(head_commit) is not None,
        "authenticated Authority head is malformed",
    )
    derived_path = f"{REVIEWER_DECISION_DIRECTORY}/{head_commit}.json"
    repository = closed_json(
        read_bytes(root / REVIEWER_REPOSITORY_FILE, f"{label} repository"),
        f"{label} repository",
    )
    commit = closed_json(
        read_bytes(root / REVIEWER_DECISION_COMMIT_FILE, f"{label} commit"),
        f"{label} commit",
    )
    # The protection read is captured raw so the server's own scope statement
    # travels with it; a bare JSON body could never prove it was performed
    # with an administration-read credential.
    protection_capture = _read_capture(
        root, RAW_PROTECTION, f"{label} branch protection",
    )
    protection = protection_capture["json"]
    protection_permission = protection_capture["headers"].get(
        PERMISSION_HEADER, "",
    )
    blob = closed_json(
        read_bytes(root / REVIEWER_DECISION_BLOB_FILE, f"{label} blob"),
        f"{label} blob",
    )
    readback = closed_json(
        read_bytes(root / REVIEWER_DECISION_READBACK_FILE, f"{label} readback"),
        f"{label} readback",
    )
    operation = closed_json(
        read_bytes(
            root / DECISION_DELIVERY_OPERATION_FILE,
            f"{label} operation",
        ),
        f"{label} operation",
    )
    _exact_members(operation, DELIVERY_OPERATION_KEYS, f"{label} operation")
    protection_url = (
        f"{GITHUB_API_ROOT}/repos/{INDEPENDENT_REPOSITORY}"
        f"/branches/{DECISION_DELIVERY_BRANCH}/protection"
    )
    require(
        _member(protection, ("url",), f"{label} branch protection url")
        == protection_url,
        f"{label} branch protection was read for another repository or branch",
    )
    # The delivery commit SHA comes from the evidence itself, not from
    # GITHUB_SHA. The workflow fetches the delivery commit's API data after
    # the CAS push; the compose function reads it here.
    delivery_sha = _member(commit, ("sha",), f"{label} delivery commit sha")
    require(
        type(delivery_sha) is str
        and HEX40.fullmatch(delivery_sha) is not None,
        f"{label} delivery commit sha is malformed",
    )
    require(
        operation["cas_expected_old_oid"] == bootstrap_commit
        and operation["commit_parent"] == bootstrap_commit
        and operation["commit_sha"] == delivery_sha
        and operation["commit_tree"]
        == _member(commit, ("commit", "tree", "sha"), f"{label} tree")
        and operation["blob_sha"] == _member(blob, ("sha",), f"{label} blob")
        and operation["path"] == derived_path
        and operation["changed_paths"] == [derived_path]
        and operation["cas_ref"] == DELIVERY_TARGET_REF
        and operation["cas_primitive"] == DELIVERY_CAS_PRIMITIVE
        and operation["cas_capability_proven"] is True
        and operation["cas_capability_probe"] == DELIVERY_CAS_CAPABILITY_PROBE
        and operation["signature_verified"] is True,
        f"{label} operation does not bind the expected-old-OID CAS and its "
        "server readback",
    )
    blob_url = (
        f"{GITHUB_API_ROOT}/repos/{INDEPENDENT_REPOSITORY}"
        f"/contents/{derived_path}?ref={delivery_sha}"
    )

    def actor(role):
        return {
            key: _member(commit, (role, key), f"{label} {role} {key}")
            for key in DECISION_ACTOR_KEYS
        }

    document = {
        "blob": {
            "content": _member(blob, ("content",), f"{label} blob content"),
            "encoding": _member(blob, ("encoding",), f"{label} blob encoding"),
            "path": derived_path,
            "sha": _member(blob, ("sha",), f"{label} blob sha"),
            "size": _member(blob, ("size",), f"{label} blob size"),
            "type": _member(blob, ("type",), f"{label} blob type"),
            "url": blob_url,
        },
        "branch_protection": {
            "allow_deletions": {
                "enabled": _member(
                    protection, ("allow_deletions", "enabled"),
                    f"{label} allow_deletions",
                ),
            },
            "allow_force_pushes": {
                "enabled": _member(
                    protection, ("allow_force_pushes", "enabled"),
                    f"{label} allow_force_pushes",
                ),
            },
            "enabled": True,
            "enforce_admins": {
                "enabled": _member(
                    protection, ("enforce_admins", "enabled"),
                    f"{label} enforce_admins",
                ),
            },
            "required_signatures": {
                "enabled": _member(
                    protection, ("required_signatures", "enabled"),
                    f"{label} required_signatures",
                ),
            },
            "authenticated_status": protection_capture["status"],
            "endpoint_requirement": protection_permission,
            "url": protection_url,
        },
        "commit": {
            "author": actor("author"),
            "committer": actor("committer"),
            "files": [
                {
                    key: _member(entry, (key,), f"{label} commit file {key}")
                    for key in DECISION_COMMIT_FILE_KEYS
                }
                for entry in _member(commit, ("files",), f"{label} commit files")
            ],
            "parents": [
                _member(parent, ("sha",), f"{label} commit parent")
                for parent in _member(
                    commit, ("parents",), f"{label} commit parents",
                )
            ],
            "sha": _member(commit, ("sha",), f"{label} commit sha"),
            "tree": {
                "sha": _member(
                    commit, ("commit", "tree", "sha"), f"{label} commit tree",
                ),
            },
            "verification": {
                "reason": _member(
                    commit, ("commit", "verification", "reason"),
                    f"{label} verification reason",
                ),
                "verified": _member(
                    commit, ("commit", "verification", "verified"),
                    f"{label} verification",
                ),
            },
        },
        "operation": operation,
        "readback": {
            "content": _member(
                readback, ("content",), f"{label} readback content",
            ),
            "encoding": _member(
                readback, ("encoding",), f"{label} readback encoding",
            ),
            "path": derived_path,
            "ref": delivery_sha,
            "sha": _member(readback, ("sha",), f"{label} readback sha"),
            "size": _member(readback, ("size",), f"{label} readback size"),
        },
        "repository": {
            key: _member(repository, (key,), f"{label} repository {key}")
            for key in DECISION_REPOSITORY_KEYS
        },
    }
    # The delivery commit is a NEW commit whose sole parent is the bootstrap
    # commit (GITHUB_SHA). Its tree includes the decision file, so it differs
    # from the bootstrap tree. Validate the parent relationship instead.
    require(
        document["commit"]["parents"] == [bootstrap_commit],
        f"{label} delivery commit sole parent is not the authenticated "
        "bootstrap commit",
    )
    return _write_sealed_document(
        root / DECISION_DELIVERY_FILE, document, f"{label} document",
    )


def verify(run, envelope_data, receipt_data, root=ROOT):
    receipt_sha256 = hashlib.sha256(receipt_data).hexdigest()
    envelope_sha256 = hashlib.sha256(envelope_data).hexdigest()
    require(receipt_sha256 == run["review_receipt_sha256"],
            "protected review receipt digest is not the authorized digest")
    require(envelope_sha256 == run["envelope_sha256"],
            "protected Kanban envelope digest is not the authorized digest")
    artifact_sha256 = artifact_content_sha256({
        "kanban-review-envelope.json": envelope_data,
        "preissuance-review-receipt.json": receipt_data,
    })
    require(artifact_sha256 == run["artifact_content_sha256"],
            "protected artifact content digest mismatch")

    receipt = closed_json(receipt_data, "review receipt")
    require(receipt_data == canonical(receipt), "review receipt is not canonical exact bytes")
    require(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS,
            "review receipt field set mismatch")
    require(
        type(receipt["schema_version"]) is int and receipt["schema_version"] == 2
        and receipt["receipt_type"] == "acc-authority-v2-preissuance-independent-review"
        and receipt["reviewer_profile"] == "acc-reviewer",
        "review receipt identity mismatch",
    )
    verify_activation_only_decision(receipt, run.get("activation_state"))
    chain = receipt["source_execution_chain"]
    require(type(chain) is dict and set(chain) == RECEIPT_CHAIN_FIELDS,
            "review receipt source execution chain field set mismatch")
    full_chain = {**chain, "artifact_content_sha256": artifact_sha256,
                  "envelope_sha256": envelope_sha256,
                  "review_receipt_sha256": receipt_sha256}
    require(full_chain == expected_chain(run),
            "review receipt source execution chain binding mismatch")
    observed_candidate = receipt["candidate"]
    require(type(observed_candidate) is dict, "review candidate malformed")
    require(observed_candidate.get("head_commit") == run["authority_head_commit"]
            and observed_candidate.get("head_tree") == run["authority_head_tree"],
            "review candidate is not the authorized Authority head")
    authenticate_candidate_binding(root, run, observed_candidate)

    envelope = closed_json(envelope_data, "Kanban review envelope")
    require(envelope_data == canonical(envelope),
            "Kanban review envelope is not canonical exact bytes")
    require(envelope == {
        "schema_version": 2,
        "task_id": TASK_ID,
        "source_repository": run["source_repository"],
        "source_workflow": run["source_workflow_path"],
        "source_workflow_sha256": run["source_workflow_sha256"],
        "source_helper": run["source_helper_path"],
        "source_helper_sha256": run["source_helper_sha256"],
        "source_run_id": run["run_id"],
        "source_run_attempt": run["run_attempt"],
        "source_run_head_sha": run["run_head_sha"],
        "artifact_name": run["artifact_name"],
        "review_receipt_sha256": receipt_sha256,
        "immutable": True,
    }, "Kanban review envelope binding mismatch")
    return {
        "activation_authorized": receipt["activation_authorized"],
        "release_authorized": FINAL_RELEASE_AUTHORIZED,
        "review_receipt_sha256": receipt_sha256,
        "source_verified": True,
    }


def read_bytes(path, label):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"{label} is absent or unsafe")
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(
        description="Authenticate the sealed protected Kanban review. Only the "
                    "execution phase is selectable; every path, run, state, "
                    "artifact and byte comes from the sealed contract, an "
                    "authenticated read or the Actions server environment.",
    )
    parser.add_argument("--phase", choices=PHASES, required=True)
    arguments = parser.parse_args()
    contract = closed_json(
        read_bytes(ROOT / CONTRACT_PATH, "independent review bootstrap contract"),
        "independent review bootstrap contract",
    )
    run = authorized_source_run(contract)

    if arguments.phase == TERMINAL_COLLECTOR_PHASE:
        print(json.dumps(collect_terminal_readback(contract), sort_keys=True))
        return

    bootstrap_commit = os.environ.get("GITHUB_SHA", "")
    require(HEX40.fullmatch(bootstrap_commit) is not None,
            "authenticated independent bootstrap commit is absent")
    independent_commit = closed_json(
        read_bytes(ROOT / INDEPENDENT_COMMIT_FILE, "authenticated independent commit"),
        "authenticated independent commit",
    )
    require(type(independent_commit) is dict
            and independent_commit.get("sha") == bootstrap_commit,
            "authenticated independent commit is not this run head")
    commit_tree = independent_commit.get("tree")
    require(type(commit_tree) is dict, "authenticated independent commit tree is absent")
    bootstrap_tree = commit_tree.get("sha")

    if arguments.phase == "bootstrap":
        verify_reviewed_bootstrap_blobs(
            run,
            read_bytes(ROOT / INDEPENDENT_WORKFLOW_PATH,
                       "executed independent review workflow"),
            read_bytes(ROOT / INDEPENDENT_VALIDATOR_PATH,
                       "executed independent review validator"),
        )
        print(json.dumps({"bootstrap_verified": True,
                          "bootstrap_commit": bootstrap_commit},
                         sort_keys=True))
        return

    if arguments.phase == "server-objects":
        sealed = compose_server_objects(ROOT)
        print(json.dumps({"server_objects_mode": sealed["mode"],
                          "server_objects_sealed": sealed["sealed"],
                          "server_objects_sha256": sealed["sha256"]},
                         sort_keys=True))
        return

    if arguments.phase == "deliver-decision":
        # The delivery phase runs after the authenticated Authority commit has
        # been read, exactly as the workflow's own AUTHORITY_HEAD does; the
        # sealed contract still pins the reviewed base and, once a run exists,
        # the head itself.
        resolved = resolve_authorized_candidate_head(
            run,
            closed_json(
                read_bytes(ROOT / AUTHORITY_COMMIT_FILE,
                           "authenticated Authority commit"),
                "authenticated Authority commit",
            ),
        )
        result = deliver_reviewer_decision(ROOT, resolved)
        print(json.dumps(result, sort_keys=True))
        return

    if arguments.phase == "deliver-commit":
        # The one phase that installs anything. The bytes the reviewer
        # authored and `--phase deliver-decision` published are turned into a
        # real, reviewer-owned, server-verified signed commit that introduces
        # exactly the derived decision path, through an atomic expected-head
        # compare-and-swap. It is kept apart from every composing phase
        # precisely because it is the only one that constructs a transport.
        head = resolve_authorized_candidate_head(
            run,
            closed_json(
                read_bytes(ROOT / AUTHORITY_COMMIT_FILE,
                           "authenticated Authority commit"),
                "authenticated Authority commit",
            ),
        )
        path = ROOT / REVIEWER_DECISION_DIRECTORY / f"{head}.json"
        delivered = deliver_decision_commit(
            decision=read_bytes(path, "published reviewer decision"),
            head_commit=head,
            expected_head=_expected_delivery_head(),
            signing_key=os.environ.get(REVIEWER_SIGNING_KEY_VARIABLE),
        )
        print(json.dumps(delivered, sort_keys=True))
        return

    if arguments.phase == "decision-delivery":
        sealed = compose_decision_delivery(
            ROOT, bootstrap_commit, bootstrap_tree,
        )
        print(json.dumps({"decision_delivery_mode": sealed["mode"],
                          "decision_delivery_sealed": sealed["sealed"],
                          "decision_delivery_sha256": sealed["sha256"]},
                         sort_keys=True))
        return

    source_run_pages = captured_workflow_run_pages(ROOT)
    if arguments.phase == "select":
        selected = select_authorized_run(run, source_run_pages)
        print(json.dumps({"source_run_id": selected["id"],
                          "source_run_head_sha": selected["head_sha"]},
                         sort_keys=True))
        return

    source_contract_data = read_bytes(
        ROOT / SOURCE_CONTRACT_FILE, "authenticated protected-source bootstrap contract",
    )
    source_run_metadata = closed_json(
        read_bytes(ROOT / SOURCE_RUN_FILE, "protected-source run metadata"),
        "protected-source run metadata",
    )
    source_commit = closed_json(
        read_bytes(ROOT / SOURCE_COMMIT_FILE, "source commit data"),
        "source commit data",
    )
    authority_commit = closed_json(
        read_bytes(ROOT / AUTHORITY_COMMIT_FILE, "authenticated Authority commit"),
        "authenticated Authority commit",
    )
    envelope_data = read_bytes(ROOT / ENVELOPE_FILE, "protected Kanban envelope")
    receipt_data = read_bytes(ROOT / RECEIPT_FILE, "protected review receipt")
    live = resolve_live_run(
        run,
        bootstrap_commit=bootstrap_commit,
        bootstrap_tree=bootstrap_tree,
        source_run_metadata=source_run_metadata,
        source_run_pages=source_run_pages,
        source_commit=source_commit,
        authority_commit=authority_commit,
        envelope_data=envelope_data,
        receipt_data=receipt_data,
    )
    verify_bootstrap_bytes(
        live,
        read_bytes(ROOT / INDEPENDENT_WORKFLOW_PATH,
                   "executed independent review workflow"),
        read_bytes(ROOT / INDEPENDENT_VALIDATOR_PATH,
                   "executed independent review validator"),
        bootstrap_commit,
        bootstrap_tree,
    )
    verify_source_contract_state(contract, live, source_contract_data)
    verify_source_bytes(
        live,
        source_run_metadata,
        read_bytes(ROOT / SOURCE_WORKFLOW_FILE, "executed protected-source workflow"),
        read_bytes(ROOT / SOURCE_HELPER_FILE, "executed protected-source helper"),
        source_commit,
    )
    result = verify(live, envelope_data, receipt_data)
    if arguments.phase == "external-review":
        # Only now, with every live identifier resolved from authenticated
        # server state and every executed byte verified, may a receipt exist.
        require_resolved_live_state(live)
        sealing = write_external_activation_review(ROOT, live)
        print(json.dumps({
            "external_review_receipt_mode": sealing["mode"],
            "external_review_receipt_sha256": sealing["sha256"],
            "external_review_sealed": sealing["sealed"],
            "external_review_written": True,
        }, sort_keys=True))
        return
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
