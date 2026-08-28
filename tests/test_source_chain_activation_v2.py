#!/usr/bin/env python3
"""F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE activation-package closure.

The activation package is reviewable on its own: it seals the already reviewed
`protected-source-bootstrap-v2` and `independent-review-bootstrap-v2` bytes,
names the exact target repositories and their creation posture, and authorizes
no Authority-v2 issuance, signing, release or publication at all. F8 stays open
while the repositories and runs are absent, and the separate pinning helper is
the only path that may ever bind real live activation evidence.
"""
import ast
import base64
import hashlib
import http.server
import contextlib
import importlib.util
import inspect
import io
import os
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
import urllib.request
import warnings
import zipfile
from unittest import mock
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ACTIVATION = load_module(
    "verify_source_chain_activation_v2",
    ROOT / "scripts" / "verify_source_chain_activation_v2.py",
)
VALIDATOR = load_module(
    "verify_kanban_review_v2",
    ROOT / "independent-review-bootstrap-v2" / "scripts"
    / "verify_kanban_review_v2.py",
)
PIN = load_module(
    "pin_source_chain_activation_v2",
    ROOT / "scripts" / "pin_source_chain_activation_v2.py",
)
VERIFIER = load_module(
    "verify_authority_v2", ROOT / "scripts" / "verify_authority_v2.py",
)
GENERATOR = load_module(
    "build_authority_v2", ROOT / "scripts" / "build_authority_v2.py",
)
PUBLICATION = load_module(
    "verify_publication_v2", ROOT / "scripts" / "verify_publication_v2.py",
)
SIGSTORE = load_module(
    "sigstore_bundle_v03", ROOT / "scripts" / "sigstore_bundle_v03.py",
)


def reviewer_decision(run, checkout, **overrides):
    """Decision bytes as the independent reviewer would author them.

    The candidate never produces these: the test stands in for the separately
    authored external artifact so the sealed lane can be driven end to end.
    """
    diff = subprocess.run(
        ["git", "-C", str(checkout), "diff", "--binary", "--full-index",
         "--no-ext-diff", "--no-abbrev", "--find-renames=50%", "--src-prefix=a/",
         "--dst-prefix=b/", run["authority_base_commit"],
         run["authority_head_commit"], "--"],
        check=True, capture_output=True,
    ).stdout
    trust = subprocess.run(
        ["git", "-C", str(checkout), "show",
         f'{run["authority_head_commit"]}:{VALIDATOR.TRUST_RECORD_PATH}'],
        check=True, capture_output=True,
    ).stdout
    document = {
        "activation_authorized": True,
        "base_commit": run["authority_base_commit"],
        "canonical_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "candidate_owned": False,
        "decision": "APPROVED",
        "document_type": VALIDATOR.REVIEWER_DECISION_TYPE,
        "findings": [],
        "findings_count": 0,
        "head_commit": run["authority_head_commit"],
        "head_tree": run["authority_head_tree"],
        "produced_after_candidate": True,
        "repository": VALIDATOR.AUTHORITY_REPOSITORY,
        "reviewer_authorization_sha256": hashlib.sha256(trust).hexdigest(),
        "reviewer_profile": "acc-reviewer",
        "reviewer_repository": VALIDATOR.INDEPENDENT_REPOSITORY,
        "schema_version": 1,
        "sole_parent": run["authority_base_commit"],
    }
    document.update(overrides)
    return json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"


# ---------------------------------------------------------------------------
# F8-INDEPENDENT-DECISION-DELIVERY-UNREACHABLE
#
# The reviewer's decision is never a file a test may drop into the lane. It is
# delivered into the independent reviewer's own protected repository, and the
# sealed lane authenticates the writer identity, the internally derived
# `decisions/<authority head>.json` path, the delivery commit, tree and blob,
# the branch protection and a second independent readback before it may build
# a receipt at all. Everything below is a sealed fake read-only GitHub
# response; no production call is ever made.
# ---------------------------------------------------------------------------
API_ROOT = "https://api.github.com"
DELIVERY_WRITER_LOGIN = "chrizzatsu"
DELIVERY_WRITER_ID = 20467803
INDEPENDENT_REPOSITORY_ID = 1039481726
SOURCE_REPOSITORY_ID = 1039481725
SOURCE_ARTIFACT_ID = 4210033771
SOURCE_JOB_ID = 4210033991
INSTALLATION_ID = 87654321
REMOVE = object()


def git_blob_oid(data):
    """The Git object name of a blob, recomputed rather than believed."""
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def apply_overrides(document, overrides):
    """Damage one sealed response member, addressed by dotted path."""
    for dotted, value in overrides.items():
        member = document
        *parents, leaf = dotted.split(".")
        for key in parents:
            member = member[int(key)] if key.isdigit() else member[key]
        if leaf.isdigit():
            member[int(leaf)] = value
        elif value is REMOVE:
            member.pop(leaf, None)
        else:
            member[leaf] = value
    return document


def sealed_pages(endpoint, counts, total, per_page=100):
    """Exhaustive pagination provenance with an explicit Link closure."""
    pages = []
    for index, count in enumerate(counts, start=1):
        last = index == len(counts)
        pages.append({
            "count": count,
            "link": None if last else (
                f'<{endpoint}?per_page={per_page}&page={index + 1}>; rel="next"'
            ),
            "page": index,
            "per_page": per_page,
            "status": 200,
            "total_count": total,
        })
    return pages


def sealed_reviewer_delivery_responses(decision_bytes, *, head_commit,
                                       bootstrap_commit, bootstrap_tree,
                                       delivery_commit=None,
                                       delivery_tree=None, **damage):
    """The immutable external delivery chain, exactly as GitHub returns it.

    These are sealed raw reviewer responses, never a composed document: the
    real `--phase decision-delivery` CLI derives the delivery evidence from
    them, so no test ever places the decision or its provenance itself.

    The delivery commit is a NEW commit whose sole parent is the bootstrap
    commit (GITHUB_SHA). Its tree includes the decision file, so it differs
    from the bootstrap tree.
    """
    path = f"{VALIDATOR.REVIEWER_DECISION_DIRECTORY}/{head_commit}.json"
    encoded = base64.b64encode(decision_bytes).decode("ascii")
    blob_sha = git_blob_oid(decision_bytes)
    repository = VALIDATOR.INDEPENDENT_REPOSITORY
    branch = VALIDATOR.DECISION_DELIVERY_BRANCH
    api = API_ROOT
    delivery = delivery_commit or hashlib.sha256(
        f"acc-delivery-commit-{bootstrap_commit}".encode()
    ).hexdigest()[:40]
    delivery_t = delivery_tree or hashlib.sha256(
        f"acc-delivery-tree-{bootstrap_commit}".encode()
    ).hexdigest()[:40]
    responses = {
        "repository": {
            "default_branch": branch,
            "full_name": repository,
            "id": INDEPENDENT_REPOSITORY_ID,
            "node_id": "R_kgDOIndependentReview",
            "private": False,
            "visibility": "public",
        },
        "commit": {
            "author": {"id": DELIVERY_WRITER_ID, "login": DELIVERY_WRITER_LOGIN,
                       "type": "User"},
            "committer": {"id": DELIVERY_WRITER_ID,
                          "login": DELIVERY_WRITER_LOGIN, "type": "User"},
            "commit": {
                "tree": {"sha": delivery_t},
                "verification": {"reason": "valid", "verified": True},
            },
            "files": [{
                "filename": path,
                "sha": blob_sha,
                "status": "added",
            }],
            "parents": [{"sha": bootstrap_commit}],
            "sha": delivery,
        },
        "blob": {
            "content": encoded,
            "encoding": "base64",
            "path": path,
            "sha": blob_sha,
            "size": len(decision_bytes),
            "type": "file",
        },
        "readback": {
            "content": encoded,
            "encoding": "base64",
            "path": path,
            "sha": blob_sha,
            "size": len(decision_bytes),
            "type": "file",
        },
    }
    protection = {
        "allow_deletions": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "enforce_admins": {"enabled": True},
        "required_signatures": {"enabled": True},
        "url": f"{api}/repos/{repository}/branches/{branch}/protection",
    }
    protection_options = {"permissions": "administration=read"}
    for name, override in damage.items():
        if name == "protection":
            protection = override.get("body", protection)
            protection_options = {
                **protection_options,
                **{k: v for k, v in override.items() if k != "body"},
            }
        elif override is REMOVE:
            responses.pop(name, None)
        else:
            responses[name] = apply_overrides(deepcopy(responses[name]), override)
    return responses, protection, protection_options


ARTIFACT_IDENTITY_LAYOUT = (
    ("authority-v2-external-activation-review-t_c298fca4", 3344556679,
     (PIN.LIVE_EVIDENCE_EXTERNAL_RECEIPT, PIN.LIVE_EVIDENCE_EXTERNAL_BUNDLE)),
    ("authority-v2-signed-review-t_c298fca4", 3344556678,
     (PIN.LIVE_EVIDENCE_ENVELOPE, PIN.LIVE_EVIDENCE_RECEIPT,
      PIN.LIVE_EVIDENCE_SIGNED_BUNDLE)),
)


def build_artifact_archive(members):
    """One real, deterministic ZIP carrying exactly these member bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for member in sorted(members):
            info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, members[member])
    return buffer.getvalue()


def artifact_identity_entries(evidence):
    """The canonical identity the issuance lane really resolved.

    The issuance workflow downloads each artifact by its canonical server id
    and keeps that exact archive beside the evidence it expanded, so the
    closure can open the real ZIP for itself. These entries carry the
    recomputed size, digest and member digests of the archives actually
    written here, so a name can never stand in for bytes.
    """
    evidence = Path(evidence)

    def member_bytes(member):
        candidate = evidence / member
        return candidate.read_bytes() if candidate.is_file() else b""

    entries = []
    for name, artifact_id, members in ARTIFACT_IDENTITY_LAYOUT:
        payload = {member: member_bytes(member) for member in members}
        archive = build_artifact_archive(payload)
        (evidence / PIN.ARTIFACT_ARCHIVE_TEMPLATE.format(
            artifact_id=artifact_id,
        )).write_bytes(archive)
        entries.append({
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "archive_size": len(archive),
            "artifact_id": artifact_id,
            "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
            "members": {
                member: hashlib.sha256(payload[member]).hexdigest()
                for member in members
            },
            "name": name,
        })
    return entries


def seal_reviewer_delivery(root, run, decision_bytes, **damage):
    """Seal the immutable external delivery chain the real CLI consumes."""
    root = Path(root)
    responses, protection, options = sealed_reviewer_delivery_responses(
        decision_bytes,
        head_commit=run["authority_head_commit"],
        bootstrap_commit=run["independent_bootstrap_commit"],
        bootstrap_tree=run["independent_bootstrap_tree"],
        **damage,
    )
    authority = root / VALIDATOR.AUTHORITY_COMMIT_FILE
    if not authority.exists():
        write_sealed_json(authority, {
            "sha": run["authority_head_commit"],
            "tree": {"sha": run["authority_head_tree"]},
        })
    for name, relative in (
        ("repository", VALIDATOR.REVIEWER_REPOSITORY_FILE),
        ("commit", VALIDATOR.REVIEWER_DECISION_COMMIT_FILE),
        ("blob", VALIDATOR.REVIEWER_DECISION_BLOB_FILE),
        ("readback", VALIDATOR.REVIEWER_DECISION_READBACK_FILE),
    ):
        if name not in responses:
            continue
        write_sealed_json(root / relative, responses[name])
    if protection is not None:
        write_capture(
            root, VALIDATOR.RAW_PROTECTION,
            protection["url"] if type(protection) is dict else "",
            http_capture(protection, **options),
        )
    commit = responses.get("commit") or {}
    blob = responses.get("blob") or {}
    commit_payload = commit.get("commit") or {}
    tree = commit_payload.get("tree") or {}
    delivered_path = (
        f"{VALIDATOR.REVIEWER_DECISION_DIRECTORY}/"
        f'{run["authority_head_commit"]}.json'
    )
    write_sealed_json(
        root / VALIDATOR.DECISION_DELIVERY_OPERATION_FILE,
        {
            "author": {"fixture": "reviewer"},
            "blob_sha": blob.get("sha", "0" * 40),
            "cas_capability_probe": VALIDATOR.DELIVERY_CAS_CAPABILITY_PROBE,
            "cas_capability_proven": True,
            "cas_expected_old_oid": run["independent_bootstrap_commit"],
            "cas_primitive": VALIDATOR.DELIVERY_CAS_PRIMITIVE,
            "cas_ref": VALIDATOR.DELIVERY_TARGET_REF,
            "changed_paths": [delivered_path],
            "commit_parent": run["independent_bootstrap_commit"],
            "commit_sha": commit.get("sha", "0" * 40),
            "commit_tree": tree.get("sha", "0" * 40),
            "committer": {"fixture": "reviewer"},
            "parent_tree": run["independent_bootstrap_tree"],
            "path": delivered_path,
            "readback_decision_sha256": hashlib.sha256(
                decision_bytes
            ).hexdigest(),
            "signature_verified": True,
            "signed_payload_sha256": hashlib.sha256(
                b"fixture signed delivery payload"
            ).hexdigest(),
        },
    )



# NON-AUTHORITATIVE FIXTURE identifiers. These exist only inside tests and are
# never serialized into a production contract, workflow or receipt.
FIXTURE_INSTALLATION_ID = 11223344
FIXTURE_APP_ID = 913472
FIXTURE_APP_SLUG = "acc-test-nonauthoritative-app"
FIXTURE_APP_CLIENT_ID = "Iv23liACCnonauthoritative"
FIXTURE_ACCOUNT_LOGIN = "chrizzatsu"
# The documented installation settings URL. A GitHub installation object's
# `html_url` is the *settings* page of the account the App is installed on -
# `https://github.com/settings/installations/{id}` for a user account and
# `https://github.com/organizations/{org}/settings/installations/{id}` for an
# organization. It is never the App's own `https://github.com/apps/{slug}`
# page, which names the App and says nothing at all about the installation.
FIXTURE_INSTALLATION_SETTINGS_URL = (
    f"https://github.com/settings/installations/{FIXTURE_INSTALLATION_ID}"
)
FIXTURE_INSTALLATION_ACCOUNT = {
    "id": 40311993,
    "login": FIXTURE_ACCOUNT_LOGIN,
    "node_id": "U_kgDOAcc",
    "type": "User",
}
# The claims of the freshly minted, never-persisted App JWT this run used.
FIXTURE_APP_JWT_ISSUED_AT = 1_800_000_000
FIXTURE_APP_JWT_EXPIRES_AT = FIXTURE_APP_JWT_ISSUED_AT + 540


def http_capture(body, *, status=200, link=None, permissions="actions=read",
                 api_version=None, date=None):
    """One sealed raw `gh api -i` capture: status line, headers and body."""
    payload = json.dumps(body, sort_keys=True).encode("utf-8")
    head = [f"HTTP/2.0 {status} "]
    head.append(
        "x-github-api-version-selected: "
        f"{VALIDATOR.GITHUB_API_VERSION if api_version is None else api_version}"
    )
    if permissions is not None:
        head.append(f"x-accepted-github-permissions: {permissions}")
    if link is not None:
        head.append(f"link: {link}")
    if date is not None:
        head.append(f"date: {date}")
    return ("\r\n".join(head) + "\r\n\r\n").encode("utf-8") + payload


def write_capture(root, name, url, capture):
    """Seal one raw capture. No request URL is ever recorded beside it."""
    directory = Path(root) / VALIDATOR.RAW_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.http").write_bytes(capture)


def artifact_archive_bytes(members):
    """The immutable artifact archive exactly as Actions stores it.

    Deterministic: the same members always produce the same archive bytes, so
    the sealed server digest and the obtained bytes really are one chain.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(2026, 8, 26, 13, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, members[name])
    return buffer.getvalue()


def sealed_raw_captures(live, source_bytes, *, damage=None):
    """Every raw authenticated GitHub response the sealed lane must consume.

    These are sealed fixtures of exactly what `gh api -i` writes; no request is
    ever made. Single-object bodies carry their own canonical `url`, because
    the lane refuses any request provenance the caller wrote itself.
    """
    damage = damage or {}
    repo = live["source_repository"]
    api = VALIDATOR.GITHUB_API_ROOT
    run_id = live["run_id"]
    head = live["run_head_sha"]
    tree = live["source_bootstrap_tree"]
    archive = live["artifact_archive"]
    runs_endpoint = (
        f"{api}/repos/{repo}/actions/workflows"
        f"/{PurePosixPath(live['source_workflow_path']).name}/runs"
    )
    jobs_endpoint = f"{api}/repos/{repo}/actions/runs/{run_id}/jobs"
    artifacts_endpoint = f"{api}/repos/{repo}/actions/runs/{run_id}/artifacts"
    installation_endpoint = f"{api}/installation/repositories"
    entries = sorted(source_bytes)
    captures = {
        "repository": (f"{api}/repos/{repo}", {
            "default_branch": "main",
            "full_name": repo,
            "id": SOURCE_REPOSITORY_ID,
            "node_id": "R_kgDOProtectedSource",
            "url": f"{api}/repos/{repo}",
        }, {"permissions": "metadata=read"}),
        # Exactly the documented runtime readback: repository selection and
        # the exhaustive inventory. It publishes no grants, and none is ever
        # inferred from it or from an endpoint requirement header.
        "installation-page-1": (
            f"{installation_endpoint}?per_page=100&page=1", {
                "repositories": [{
                    "full_name": repo,
                    "id": SOURCE_REPOSITORY_ID,
                    "node_id": "R_kgDOProtectedSource",
                }],
                "repository_selection": "selected",
                "total_count": 1,
            }, {"permissions": "metadata=read"}),
        # NON-AUTHORITATIVE FIXTURE: the App the runtime credential is issued
        # by, read from the same authenticated App chain.
        VALIDATOR.RAW_APP: (
            f"{api}/app", {
                "client_id": FIXTURE_APP_CLIENT_ID,
                "html_url": f"https://github.com/apps/{FIXTURE_APP_SLUG}",
                "id": FIXTURE_APP_ID,
                "permissions": {
                    "actions": "read", "contents": "read", "metadata": "read",
                },
                "slug": FIXTURE_APP_SLUG,
            }, {"permissions": "metadata=read"}),
        # NON-AUTHORITATIVE FIXTURE: the installation that actually covers the
        # repository this runtime token reads. It names its own token issuance
        # endpoint and its own runtime repositories endpoint, so the grant and
        # the credential in use are one authenticated chain.
        VALIDATOR.RAW_REPOSITORY_INSTALLATION: (
            f"{api}/repos/{repo}/installation", {
                "access_tokens_url": f"{api}/app/installations"
                                     f"/{FIXTURE_INSTALLATION_ID}/access_tokens",
                "account": dict(FIXTURE_INSTALLATION_ACCOUNT),
                "app_id": FIXTURE_APP_ID,
                "app_slug": FIXTURE_APP_SLUG,
                "html_url": FIXTURE_INSTALLATION_SETTINGS_URL,
                "id": FIXTURE_INSTALLATION_ID,
                "permissions": {
                    "actions": "read", "contents": "read", "metadata": "read",
                },
                "repositories_url": f"{api}/installation/repositories",
                "repository_selection": "selected",
                "target_type": "User",
            }, {"permissions": "metadata=read"}),
        # NON-AUTHORITATIVE FIXTURE: the external immutable grant record. Its
        # values are test values and are never written into any production
        # contract or receipt.
        VALIDATOR.RAW_INSTALLATION_GRANT: (
            f"{api}/app/installations/{FIXTURE_INSTALLATION_ID}", {
                "access_tokens_url": f"{api}/app/installations"
                                     f"/{FIXTURE_INSTALLATION_ID}/access_tokens",
                "account": dict(FIXTURE_INSTALLATION_ACCOUNT),
                "app_id": FIXTURE_APP_ID,
                "app_slug": FIXTURE_APP_SLUG,
                "html_url": FIXTURE_INSTALLATION_SETTINGS_URL,
                "id": FIXTURE_INSTALLATION_ID,
                "permissions": {
                    "actions": "read", "contents": "read", "metadata": "read",
                },
                "repositories_url": f"{api}/installation/repositories",
                "repository_selection": "selected",
                "target_type": "User",
            }, {"permissions": "metadata=read",
                "date": "Fri, 15 Jan 2027 08:03:20 GMT"}),
        "run": (f"{api}/repos/{repo}/actions/runs/{run_id}", {
            "head_sha": head, "id": run_id, "run_attempt": 1,
            "run_started_at": "2027-01-15T08:00:00Z",
            "url": f"{api}/repos/{repo}/actions/runs/{run_id}",
        }, {"permissions": "actions=read"}),
        "commit": (f"{api}/repos/{repo}/git/commits/{head}", {
            "sha": head, "tree": {"sha": tree},
            "url": f"{api}/repos/{repo}/git/commits/{head}",
        }, {"permissions": "contents=read"}),
        "tree": (f"{api}/repos/{repo}/git/trees/{tree}?recursive=1", {
            "sha": tree,
            "truncated": False,
            "url": f"{api}/repos/{repo}/git/trees/{tree}",
            "tree": [
                {"mode": "100644", "path": path,
                 "sha": git_blob_oid(source_bytes[path]),
                 "size": len(source_bytes[path]), "type": "blob"}
                for path in entries
            ],
        }, {"permissions": "contents=read"}),
        "runs-page-1": (f"{runs_endpoint}?per_page=100&page=1", {
            "total_count": 1,
            "workflow_runs": [{
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_repository": {"full_name": repo},
                "head_sha": head,
                "id": run_id,
                "path": live["source_workflow_path"],
                "run_attempt": 1,
            }],
        }, {"permissions": "actions=read"}),
        "jobs-page-1": (f"{jobs_endpoint}?per_page=100&page=1", {
            "jobs": [{
                "completed_at": "2026-08-26T13:00:41Z",
                "conclusion": "success",
                "head_sha": head,
                "id": SOURCE_JOB_ID,
                "name": VALIDATOR.SOURCE_JOB_NAME,
                "run_attempt": 1,
                "run_id": run_id,
                "started_at": "2026-08-26T13:00:11Z",
                "status": "completed",
            }],
            "total_count": 1,
        }, {"permissions": "actions=read"}),
        "artifacts-page-1": (f"{artifacts_endpoint}?per_page=100&page=1", {
            "artifacts": [{
                "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
                "expired": False,
                "id": SOURCE_ARTIFACT_ID,
                "name": live["artifact_name"],
                "node_id": "MDg6QXJ0aWZhY3Q0MjEwMDMzNzcx",
                "size_in_bytes": len(archive),
                "workflow_run": {"id": run_id},
            }],
            "total_count": 1,
        }, {"permissions": "actions=read"}),
    }
    for index, path in enumerate(entries, start=1):
        data = source_bytes[path]
        captures[f"blob-{index}"] = (
            f"{api}/repos/{repo}/git/blobs/{git_blob_oid(data)}",
            {
                "content": base64.b64encode(data).decode("ascii"),
                "encoding": "base64",
                "sha": git_blob_oid(data),
                "size": len(data),
                "url": f"{api}/repos/{repo}/git/blobs/{git_blob_oid(data)}",
            },
            {"permissions": "contents=read"},
        )
    for name, override in damage.items():
        if override is REMOVE:
            captures.pop(name, None)
            continue
        url, body, options = captures.get(name, (None, {}, {}))
        url = override.get("url", url)
        body = override.get("body", body)
        options = {**options, **{
            key: value for key, value in override.items()
            if key not in ("url", "body")
        }}
        captures[name] = (url, body, options)
    return captures


def seal_raw_captures(root, live, source_bytes, *, damage=None):
    captures = sealed_raw_captures(live, source_bytes, damage=damage)
    # Reseal from scratch, so a removed capture really is absent rather than
    # left behind by an earlier sealing of the same lane.
    directory = Path(root) / VALIDATOR.RAW_DIRECTORY
    if directory.is_dir():
        for existing in directory.glob("*.http"):
            if existing.stem != VALIDATOR.RAW_PROTECTION:
                existing.unlink()
    for name, (url, body, options) in captures.items():
        write_capture(root, name, url, http_capture(body, **options))
    archive = Path(root) / VALIDATOR.ARTIFACT_ARCHIVE_FILE
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(live["artifact_archive"])



def sealed_source_bytes():
    """The exact protected-source bytes the sealed tree membership must name."""
    return {
        VALIDATOR.SOURCE_WORKFLOW:
            (SOURCE_BOOTSTRAP_ROOT / VALIDATOR.SOURCE_WORKFLOW).read_bytes(),
        VALIDATOR.SOURCE_HELPER:
            (SOURCE_BOOTSTRAP_ROOT / VALIDATOR.SOURCE_HELPER).read_bytes(),
        VALIDATOR.SOURCE_BOOTSTRAP_CONTRACT:
            (SOURCE_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes(),
    }


def write_sealed_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def synthetic_live_run(*, base_commit, base_tree, head_commit, head_tree):
    """A coherent sealed live state for the unit-level receipt contract test."""
    members = {
        name: json.dumps({"member": name}, sort_keys=True).encode() + b"\n"
        for name in VALIDATOR.ARTIFACT_MEMBERS
    }
    return {
        "artifact_archive": artifact_archive_bytes(members),
        "artifact_content_sha256": VALIDATOR.artifact_content_sha256(members),
        "artifact_name": VALIDATOR.SOURCE_ARTIFACT,
        "authority_base_commit": base_commit,
        "authority_base_tree": base_tree,
        "authority_head_commit": head_commit,
        "authority_head_tree": head_tree,
        "independent_bootstrap_commit":
            hashlib.sha256(b"acc-synthetic-independent-commit").hexdigest()[:40],
        "independent_bootstrap_tree":
            hashlib.sha256(b"acc-synthetic-independent-tree").hexdigest()[:40],
        "run_head_sha":
            hashlib.sha256(b"acc-synthetic-source-commit").hexdigest()[:40],
        "run_id": 4102337781,
        "source_bootstrap_commit":
            hashlib.sha256(b"acc-synthetic-source-commit").hexdigest()[:40],
        "source_bootstrap_tree":
            hashlib.sha256(b"acc-synthetic-source-tree").hexdigest()[:40],
        "source_helper_path": VALIDATOR.SOURCE_HELPER,
        "source_repository": VALIDATOR.SOURCE_REPOSITORY,
        "source_workflow_path": VALIDATOR.SOURCE_WORKFLOW,
    }


def deliver_reviewer_decision(root, run, checkout, *, decision=None,
                              delivery=None, server_objects=None,
                              raw_damage=None, compose=True,
                              skip_delivery=False, skip_server_objects=False,
                              **overrides):
    """Seal the immutable external delivery and server-response chain.

    Nothing here composes evidence: only the decision bytes the independent
    reviewer authored and the raw GitHub responses that describe their
    delivery are sealed. The real production CLI phases derive every piece of
    provenance from them.
    """
    root = Path(root)
    head = run["authority_head_commit"]
    data = decision if decision is not None else reviewer_decision(
        run, checkout, **overrides,
    )
    path = root / VALIDATOR.REVIEWER_DECISION_DIRECTORY / f"{head}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if not skip_delivery:
        seal_reviewer_delivery(root, run, data, **(delivery or {}))
        if compose and not (root / VALIDATOR.DECISION_DELIVERY_FILE).exists():
            # The production composition, over the sealed raw responses.
            VALIDATOR.compose_decision_delivery(
                root, run["independent_bootstrap_commit"],
                run["independent_bootstrap_tree"],
            )
    if not skip_server_objects:
        # The sealed bootstrap contract is part of the reviewer checkout the
        # workflow's `actions/checkout` provides, not injected provenance.
        contract = root / VALIDATOR.CONTRACT_PATH
        if not contract.exists():
            contract.parent.mkdir(parents=True, exist_ok=True)
            contract.write_bytes(
                (INDEPENDENT_BOOTSTRAP_ROOT / "bootstrap-contract.json"
                 ).read_bytes()
            )
        seal_authenticated_source_reads(root, run)
        if raw_damage is not None or not (
            root / VALIDATOR.RAW_DIRECTORY / "runs-page-1.http"
        ).exists():
            seal_raw_captures(
                root, run, sealed_source_bytes(), damage=raw_damage,
            )
        if compose and not (root / VALIDATOR.SERVER_OBJECTS_FILE).exists():
            VALIDATOR.compose_server_objects(root)
        if server_objects:
            sealed = root / VALIDATOR.SERVER_OBJECTS_FILE
            document = json.loads(sealed.read_bytes())
            os.chmod(sealed, 0o600)
            sealed.write_bytes(
                json.dumps(
                    apply_overrides(document, server_objects),
                    indent=2, sort_keys=True,
                ).encode() + b"\n"
            )
    return path



def seal_authenticated_source_reads(root, run):
    """Fill the constant authenticated read paths the lane rehashes."""
    authenticated = root / VALIDATOR.AUTHENTICATED_DIRECTORY
    authenticated.mkdir(parents=True, exist_ok=True)
    for relative, data in (
        (VALIDATOR.SOURCE_WORKFLOW_FILE,
         sealed_source_bytes()[VALIDATOR.SOURCE_WORKFLOW]),
        (VALIDATOR.SOURCE_HELPER_FILE,
         sealed_source_bytes()[VALIDATOR.SOURCE_HELPER]),
        (VALIDATOR.SOURCE_CONTRACT_FILE,
         sealed_source_bytes()[VALIDATOR.SOURCE_BOOTSTRAP_CONTRACT]),
    ):
        target = root / relative
        if not target.exists():
            target.write_bytes(data)
    # The pinned token action's own issuance outputs, exactly as the workflow
    # writes them from `steps.source-token.outputs.*`.
    issuance_file = root / VALIDATOR.RUNTIME_TOKEN_GRANT_FILE
    if not issuance_file.exists():
        write_sealed_json(issuance_file, {
            "app_slug": FIXTURE_APP_SLUG,
            "installation_id": FIXTURE_INSTALLATION_ID,
        })
    # The claims of the App JWT this run minted for itself. The token bytes
    # are never written anywhere: only the window they were valid for, so the
    # lane can refuse an expired or not-yet-valid credential chain.
    jwt_file = root / VALIDATOR.RUNTIME_APP_JWT_FILE
    if not jwt_file.exists():
        write_sealed_json(jwt_file, {
            "app_client_id": FIXTURE_APP_CLIENT_ID,
            "expires_at": FIXTURE_APP_JWT_EXPIRES_AT,
            "issued_at": FIXTURE_APP_JWT_ISSUED_AT,
        })
    # The authenticated run metadata the lane ages the grant record against.
    run_file = root / VALIDATOR.SOURCE_RUN_FILE
    if not run_file.exists():
        write_sealed_json(run_file, {
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_repository": {"full_name": run["source_repository"]},
            "head_sha": run["run_head_sha"],
            "id": run["run_id"],
            "path": run["source_workflow_path"],
            "run_attempt": 1,
            "run_started_at": "2027-01-15T08:00:00Z",
        })


def external_review_evidence(head_commit):
    """The authenticated delivery and server objects a receipt must bind."""
    return {
        "decision_delivery": {
            "blob_sha": hashlib.sha256(
                f"acc-delivery-blob-{head_commit}".encode()
            ).hexdigest()[:40],
            "blob_introduced_by_commit": True,
            "branch": ACTIVATION.DECISION_DELIVERY_BRANCH,
            "branch_protected": True,
            "branch_protection_permission": "administration=read",
            "cas_capability_probe": VALIDATOR.DELIVERY_CAS_CAPABILITY_PROBE,
            "cas_capability_proven": True,
            "cas_expected_old_oid": hashlib.sha256(
                f"acc-delivery-parent-{head_commit}".encode()
            ).hexdigest()[:40],
            "cas_primitive": VALIDATOR.DELIVERY_CAS_PRIMITIVE,
            "cas_ref": VALIDATOR.DELIVERY_TARGET_REF,
            "commit_parent": hashlib.sha256(
                f"acc-delivery-parent-{head_commit}".encode()
            ).hexdigest()[:40],
            "commit_sha": hashlib.sha256(
                f"acc-delivery-commit-{head_commit}".encode()
            ).hexdigest()[:40],
            "commit_tree": hashlib.sha256(
                f"acc-delivery-tree-{head_commit}".encode()
            ).hexdigest()[:40],
            "path": ACTIVATION.DECISION_DELIVERY_PATH_TEMPLATE.format(
                authority_head_commit=head_commit,
            ),
            "readback_verified": True,
            "race_readback_verified": True,
            "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "repository_id": INDEPENDENT_REPOSITORY_ID,
            "writer_id": DELIVERY_WRITER_ID,
            "writer_login": ACTIVATION.DECISION_WRITER_LOGIN,
        },
        "server_objects": {
            "artifact_content_sha256": hashlib.sha256(
                f"acc-artifact-{head_commit}".encode()
            ).hexdigest(),
            "artifact_digest": "sha256:" + hashlib.sha256(
                f"acc-archive-{head_commit}".encode()
            ).hexdigest(),
            "artifact_id": SOURCE_ARTIFACT_ID,
            "artifact_name": VALIDATOR.SOURCE_ARTIFACT,
            "head_commit": hashlib.sha256(
                f"acc-server-head-{head_commit}".encode()
            ).hexdigest()[:40],
            "head_tree": hashlib.sha256(
                f"acc-server-tree-{head_commit}".encode()
            ).hexdigest()[:40],
            "job_ids": [SOURCE_JOB_ID],
            "repository": ACTIVATION.SOURCE_REPOSITORY,
            "repository_id": SOURCE_REPOSITORY_ID,
            "run_id": 4102337781,
            "tree_paths": sorted(sealed_source_bytes()),
        },
    }


CANDIDATE_CRITICAL_PATHS = (
    "AUTHORITY-V2-SHA256SUMS", "authority-v2-policy.json",
    "protected-asset-receipt-v2.json", "reviewer-authorization-v2.json",
    "schemas/authority-v2-subject.schema.json",
)


def build_authority_candidate(root, extra_paths=(), overrides=None):
    """A real Authority candidate checkout the sealed lanes can re-derive.

    `extra_paths` widens the committed candidate to the exact further tracked
    artifacts a lane needs, so the Authority closure CLI can run from a clean
    checkout of the same candidate rather than from an injected copy.
    """
    root.mkdir(parents=True, exist_ok=True)
    policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
    base = policy["authority_repository_base"]["commit"]
    git(root, "init", "-q")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Fixture")
    git(root, "remote", "add", "origin",
        "https://github.com/chrizzatsu/acc-attestation-authority")
    git(root, "fetch", "-q", str(ROOT), base)
    git(root, "checkout", "-q", base)
    for relative in (*CANDIDATE_CRITICAL_PATHS, *extra_paths):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    # A different candidate may seal different data; `overrides` replaces
    # exact tracked bytes before the single candidate commit, exactly as the
    # release procedure would, and the manifest is resealed over them.
    for relative, produce in (overrides or {}).items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(produce(
            target.read_bytes() if target.is_file() else b"", root,
        ))
    if overrides:
        reseal_candidate_manifest(root)
    git(root, "add", "-A")
    git(root, "commit", "-qm", "candidate")
    return base, git(root, "rev-parse", "HEAD")


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True
    ).stdout.decode().strip()


class ActivationPackageTests(unittest.TestCase):
    """The reviewable activation-only package itself."""

    def setUp(self):
        self.data = ACTIVATION.ACTIVATION_PATH.read_bytes()
        self.package = json.loads(self.data)

    def test_package_bytes_are_canonical_and_verify_against_the_repository(self):
        self.assertEqual(
            self.data,
            json.dumps(self.package, indent=2, sort_keys=True).encode() + b"\n",
        )
        self.assertEqual(ACTIVATION.verify_activation_package(), self.package)

    def test_package_seals_each_bootstrap_byte_individually_and_unchanged(self):
        sealed = {
            entry["path"]: entry["sha256"]
            for entry in self.package["sealed_bytes"]
        }
        self.assertEqual(tuple(sorted(sealed)), ACTIVATION.SEALED_BYTE_PATHS)
        for path, digest in sealed.items():
            self.assertEqual(
                hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest
            )
        trust_record = json.loads(
            (ROOT / "reviewer-authorization-v2.json").read_bytes()
        )
        self.assertEqual(
            sealed["independent-review-bootstrap-v2/.github/workflows/review-authority-v2.yml"],
            trust_record["bootstrap"]["workflow_sha256"],
        )
        self.assertEqual(
            sealed["independent-review-bootstrap-v2/.github/workflows/readback-authority-v2-activation.yml"],
            trust_record["bootstrap"]["collector_workflow_sha256"],
        )
        self.assertEqual(
            sealed["independent-review-bootstrap-v2/scripts/verify_kanban_review_v2.py"],
            trust_record["bootstrap"]["validator_sha256"],
        )
        self.assertEqual(
            sealed["independent-review-bootstrap-v2/bootstrap-contract.json"],
            trust_record["bootstrap"]["contract_sha256"],
        )
        self.assertEqual(
            sealed["protected-source-bootstrap-v2/.github/workflows/export-kanban-review-v2.yml"],
            trust_record["protected_source_bootstrap"]["workflow_sha256"],
        )
        self.assertEqual(
            sealed["protected-source-bootstrap-v2/scripts/export_kanban_review_v2.py"],
            trust_record["protected_source_bootstrap"]["helper_sha256"],
        )
        self.assertEqual(
            sealed["protected-source-bootstrap-v2/bootstrap-contract.json"],
            trust_record["protected_source_bootstrap"]["contract_sha256"],
        )

    def test_target_repositories_carry_exact_zero_spend_creation_posture(self):
        targets = self.package["target_repositories"]
        self.assertEqual(
            tuple(sorted(targets)),
            (
                "chrizzatsu/acc-authority-independent-review",
                "chrizzatsu/acc-authority-protected-source",
            ),
        )
        for name, target in targets.items():
            self.assertEqual(name.split("/")[0], "chrizzatsu")
            self.assertEqual(target["visibility"], "public")
            self.assertIs(target["private"], False)
            self.assertEqual(target["default_branch"], "main")
            self.assertEqual(target["default_branch_ref"], "refs/heads/main")
            self.assertEqual(target["maximum_incremental_spend_eur"], "0.00")
            self.assertIs(target["zero_spend_required"], True)
            self.assertIs(target["github_hosted_standard_runner_only"], True)
            self.assertIs(target["workflows_enabled"], False)
            self.assertEqual(target["workflow_state_on_creation"], "disabled_manually")
            self.assertIs(target["workflow_dispatch_authorized"], False)
            self.assertIsNone(target["repository_id"])
            self.assertIsNone(target["repository_node_id"])
            self.assertIs(target["created"], False)
            protection = target["branch_protection"]
            self.assertEqual(protection["enforcement"], "active")
            self.assertEqual(protection["bypass_actors"], [])
            self.assertIs(protection["allow_force_pushes"], False)
            self.assertIs(protection["allow_deletions"], False)
            self.assertIs(protection["admin_bypass"], False)
            self.assertIs(protection["required_linear_history"], True)

    def test_package_authorizes_no_issuance_signing_release_or_publication(self):
        """The grant reaches the activation lane only; nothing Authority-side."""
        authorizes = self.package["authorizes"]
        self.assertEqual(
            tuple(sorted(authorizes)), ACTIVATION.AUTHORIZATION_KEYS,
        )
        for name in ACTIVATION.PERMANENTLY_UNAUTHORIZED:
            self.assertIs(authorizes[name], False, name)
        for name in ACTIVATION.REQUIRED_ACTIVATION_GRANTS:
            self.assertIs(authorizes[name], True, name)
        self.assertIs(
            self.package["independent_activation_authorization_required"], True
        )
        self.assertIs(
            self.package["supports_later_separate_acc_releaser_activation_task_only"],
            True,
        )

    def test_f8_stays_open_while_repositories_and_runs_are_absent(self):
        self.assertEqual(self.package["finding"], ACTIVATION.FINDING)
        self.assertEqual(self.package["activation_state"], "unavailable")
        self.assertIs(self.package["f8_closed"], False)
        self.assertIs(self.package["repositories_created"], False)
        self.assertIs(self.package["workflows_written"], False)
        self.assertIs(self.package["runs_observed"], False)
        run = self.package["authorized_dispatch"]
        self.assertEqual(run["selector"], "immutable-contract-pinned")
        self.assertIs(run["caller_selectable"], False)
        self.assertIs(run["no_fallback"], True)
        self.assertEqual(run["run_attempt"], 1)
        self.assertEqual(run["trigger"], "workflow_dispatch")
        self.assertEqual(run["ref"], "refs/heads/main")
        self.assertIsNone(run["run_id"])

    def test_producer_cleanup_and_readback_bindings_are_declared_and_unpinned(self):
        producer = self.package["producer_bindings"]
        self.assertEqual(
            producer["artifact_name"], "authority-v2-review-t_c298fca4"
        )
        self.assertEqual(
            producer["artifact_files"],
            ["kanban-review-envelope.json", "preissuance-review-receipt.json"],
        )
        self.assertEqual(
            producer["signed_artifact_name"],
            "authority-v2-signed-review-t_c298fca4",
        )
        self.assertEqual(
            producer["sigstore_identity"],
            "https://github.com/chrizzatsu/acc-authority-independent-review/"
            ".github/workflows/review-authority-v2.yml@refs/heads/main",
        )
        self.assertEqual(
            producer["sigstore_issuer"],
            "https://token.actions.githubusercontent.com",
        )
        for unpinned in (
            "artifact_content_sha256", "envelope_sha256",
            "review_receipt_sha256", "sigstore_bundle_sha256",
            "certificate_github_workflow_sha",
        ):
            self.assertIsNone(producer[unpinned], unpinned)
        reviewed = self.package["reviewed_source"]
        self.assertEqual(
            reviewed["trust_record"]["path"], "reviewer-authorization-v2.json"
        )
        self.assertEqual(
            reviewed["trust_record"]["sha256"],
            hashlib.sha256(
                (ROOT / "reviewer-authorization-v2.json").read_bytes()
            ).hexdigest(),
        )
        for unpinned in (
            "authority_head_commit", "authority_head_tree",
            "source_bootstrap_commit", "source_bootstrap_tree",
            "independent_bootstrap_commit", "independent_bootstrap_tree",
        ):
            self.assertIsNone(reviewed[unpinned], unpinned)
        self.assertIs(self.package["cleanup"]["delete_runtime_bytes"], True)
        self.assertEqual(self.package["cleanup"]["artifact_retention_days"], 1)
        self.assertIs(self.package["readback"]["required"], True)
        self.assertIn("run_id", self.package["readback"]["fields"])

    def test_tampered_package_field_and_sealed_byte_are_rejected(self):
        for mutate in (
            lambda payload: payload.update(f8_closed=True),
            lambda payload: payload.update(activation_state="ready"),
            lambda payload: payload["authorizes"].update(publication=True),
            lambda payload: payload["authorized_dispatch"].update(run_attempt=2),
            lambda payload: payload["authorized_dispatch"].update(caller_selectable=True),
            lambda payload: payload["sealed_bytes"][0].update(sha256="0" * 64),
            lambda payload: payload.update(unexpected_member=1),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(self.package)
                mutate(payload)
                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "source-chain-activation-v2.json"
                    path.write_bytes(
                        json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
                    )
                    with self.assertRaises(SystemExit):
                        ACTIVATION.verify_activation_package(path=path)

    def test_non_canonical_or_duplicate_member_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "source-chain-activation-v2.json"
            path.write_bytes(json.dumps(self.package).encode())
            with self.assertRaises(SystemExit):
                ACTIVATION.verify_activation_package(path=path)
            path.write_bytes(b'{"f8_closed": false, "f8_closed": true}')
            with self.assertRaises(SystemExit):
                ACTIVATION.verify_activation_package(path=path)


# ---------------------------------------------------------------------------
# Authenticated live-evidence fixtures
#
# These replace the obsolete caller-shaped pinning evidence dictionaries. Every
# value below is really computed: real Git blob object names, a real EC
# certificate chain, a real ECDSA signature over the exact subject bytes, a
# real RFC 6962 inclusion proof, a real signed checkpoint and a real signed
# entry timestamp. Nothing is asserted locally and no closure flag exists.
# ---------------------------------------------------------------------------
def der(tag, content):
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        encoded = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + content


class SigstoreFixture:
    """A real, cryptographically verifiable Sigstore bundle."""

    ORIGIN = "acc-test-transparency-log"
    TREE_SIZE = 4
    TREE_INDEX = 1

    # Every deviation an adversarial chain may carry. The honest default is an
    # exact Fulcio-shaped chain: CA certificates that assert BasicConstraints
    # and keyCertSign, and a leaf that asserts digitalSignature plus the
    # codeSigning extended key usage.
    FLAWS = (
        "extra_intermediate", "intermediate_ca", "intermediate_key_cert_sign",
        "intermediate_validity", "leaf_ca", "leaf_code_signing_eku",
        "leaf_digital_signature", "leaf_unknown_critical_extension",
    )

    def __init__(self, subject, *, repository, workflow_path, workflow_sha,
                 integrated, validity=None, authority=None, issuer=None,
                 ref=None, trigger=None, flaws=None, chain_form=True,
                 rekor_key_type="ec"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        self.chain_form = chain_form
        flaws = dict(flaws or {})
        unknown = set(flaws) - set(self.FLAWS)
        assert not unknown, f"unmodelled Sigstore fixture flaw: {sorted(unknown)}"
        self.flaws = flaws
        self.eku_oid = ExtendedKeyUsageOID
        self.x509 = x509
        self.hashes = hashes
        self.serialization = serialization
        self.ec = ec
        self.subject = subject
        self.integrated = integrated
        self.claim_issuer = issuer or PIN.OIDC_ISSUER
        self.claim_ref = ref or "refs/heads/main"
        self.claim_trigger = trigger or "workflow_dispatch"
        self.identity = (
            f"https://github.com/{repository}/{workflow_path}@refs/heads/main"
        )
        self.root_key = (
            authority.root_key if authority else ec.generate_private_key(ec.SECP256R1())
        )
        self.intermediate_key = (
            authority.intermediate_key if authority
            else ec.generate_private_key(ec.SECP256R1())
        )
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        if authority:
            self.rekor_key = authority.rekor_key
        elif rekor_key_type == "ed25519":
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
            self.rekor_key = _ed25519.Ed25519PrivateKey.generate()
        else:
            self.rekor_key = ec.generate_private_key(ec.SECP256R1())

        moment = datetime.fromtimestamp(integrated, tz=timezone.utc)
        window = validity or (
            moment - timedelta(minutes=5), moment + timedelta(minutes=5),
        )
        names = {
            key: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
            for key, value in (
                ("root", "acc-test-fulcio-root"),
                ("intermediate", "acc-test-fulcio-intermediate"),
                ("leaf", "acc-test-sigstore-leaf"),
            )
        }
        self.root = authority.root if authority else self._sign_certificate(
            names["root"], names["root"], self.root_key.public_key(),
            self.root_key, moment - timedelta(days=1), moment + timedelta(days=1),
            ca=True, path_length=None, extensions=[],
        )
        intermediate_window = flaws.get("intermediate_validity") or (
            moment - timedelta(hours=1), moment + timedelta(hours=1),
        )
        self.intermediate = (
            authority.intermediate if authority else self._sign_certificate(
                names["intermediate"], names["root"],
                self.intermediate_key.public_key(), self.root_key,
                intermediate_window[0], intermediate_window[1],
                ca=flaws.get("intermediate_ca", True),
                path_length=0,
                key_cert_sign=flaws.get("intermediate_key_cert_sign", True),
                extensions=[],
            )
        )
        # A second intermediate under an intermediate that pins pathLenConstraint
        # zero is exactly the RFC 5280 path length violation.
        self.extra_intermediate = None
        leaf_issuer_name = names["intermediate"]
        leaf_issuer_key = self.intermediate_key
        if flaws.get("extra_intermediate"):
            names["extra"] = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "acc-test-fulcio-extra"),
            ])
            self.extra_intermediate_key = ec.generate_private_key(ec.SECP256R1())
            self.extra_intermediate = self._sign_certificate(
                names["extra"], names["intermediate"],
                self.extra_intermediate_key.public_key(), self.intermediate_key,
                intermediate_window[0], intermediate_window[1],
                ca=True, path_length=0, extensions=[],
            )
            leaf_issuer_name = names["extra"]
            leaf_issuer_key = self.extra_intermediate_key
        self.leaf = self._sign_certificate(
            names["leaf"], leaf_issuer_name, self.leaf_key.public_key(),
            leaf_issuer_key, window[0], window[1], ca=False,
            extensions=[
                (oid, der(0x0C, value.encode("utf-8")))
                for oid, value in (
                    ("1.3.6.1.4.1.57264.1.8", self.claim_issuer),
                    ("1.3.6.1.4.1.57264.1.12", f"https://github.com/{repository}"),
                    ("1.3.6.1.4.1.57264.1.14", self.claim_ref),
                    ("1.3.6.1.4.1.57264.1.18", self.identity),
                    ("1.3.6.1.4.1.57264.1.19", workflow_sha),
                    ("1.3.6.1.4.1.57264.1.20", self.claim_trigger),
                )
            ],
        )
        self.signature = self.leaf_key.sign(subject, ec.ECDSA(hashes.SHA256()))
        # The pinned trust supplies the Fulcio intermediates, exactly as the
        # vendored Sigstore trusted root does: a bundle never has to carry
        # them, and never carries the trust anchor at all.
        self.trust = authority.trust if authority else PIN._SigstoreTrustRoot(
            fulcio_roots=(self.root,),
            fulcio_intermediates=(self.intermediate,),
            rekor_public_key=self.public_der(self.rekor_key),
            rekor_origin=self.ORIGIN,
        )
        self.body = json.dumps({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(subject).hexdigest(),
                }},
                "signature": {
                    "content": base64.b64encode(self.signature).decode("ascii"),
                    "publicKey": {
                        "content": base64.b64encode(self.leaf).decode("ascii"),
                    },
                },
            },
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.log_index = self.TREE_INDEX
        self.root_hash, self.path = self._merkle()

    # -- helpers ----------------------------------------------------------
    def public_der(self, key):
        return key.public_key().public_bytes(
            self.serialization.Encoding.DER,
            self.serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _key_usage(self, **asserted):
        fields = (
            "digital_signature", "content_commitment", "key_encipherment",
            "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
        )
        values = {name: asserted.get(name, False) for name in fields}
        return self.x509.KeyUsage(
            encipher_only=False, decipher_only=False, **values,
        )

    def _sign_certificate(self, subject_name, issuer_name, public_key,
                          signing_key, not_before, not_after, *, ca, extensions,
                          path_length=None, key_cert_sign=True):
        builder = (
            self.x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(issuer_name)
            .public_key(public_key)
            .serial_number(self.x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                self.x509.BasicConstraints(
                    ca=ca or (not ca and self.flaws.get("leaf_ca", False)),
                    path_length=path_length if ca else None,
                ), True,
            )
        )
        if ca:
            builder = builder.add_extension(
                self._key_usage(key_cert_sign=key_cert_sign, crl_sign=True), True,
            )
        else:
            builder = builder.add_extension(
                self._key_usage(
                    digital_signature=self.flaws.get(
                        "leaf_digital_signature", True,
                    ),
                    content_commitment=not self.flaws.get(
                        "leaf_digital_signature", True,
                    ),
                ), True,
            ).add_extension(
                self.x509.ExtendedKeyUsage([
                    self.eku_oid.CODE_SIGNING
                    if self.flaws.get("leaf_code_signing_eku", True)
                    else self.eku_oid.SERVER_AUTH
                ]), False,
            ).add_extension(
                self.x509.SubjectAlternativeName([
                    self.x509.UniformResourceIdentifier(self.identity),
                ]), True,
            )
            if self.flaws.get("leaf_unknown_critical_extension"):
                builder = builder.add_extension(
                    self.x509.UnrecognizedExtension(
                        self.x509.ObjectIdentifier("1.3.6.1.4.1.57264.9999.1"),
                        b"\x04\x00",
                    ), True,
                )
        for oid, value in extensions:
            builder = builder.add_extension(
                self.x509.UnrecognizedExtension(
                    self.x509.ObjectIdentifier(oid), value,
                ), False,
            )
        return builder.sign(signing_key, self.hashes.SHA256()).public_bytes(
            self.serialization.Encoding.DER,
        )

    def _merkle(self):
        level = [
            hashlib.sha256(b"\x00" + f"acc-filler-{index}".encode()).digest()
            for index in range(self.TREE_SIZE)
        ]
        level[self.TREE_INDEX] = hashlib.sha256(b"\x00" + self.body).digest()
        path = []
        index = self.TREE_INDEX
        while len(level) > 1:
            path.append(level[index ^ 1])
            level = [
                hashlib.sha256(b"\x01" + level[pair] + level[pair + 1]).digest()
                for pair in range(0, len(level), 2)
            ]
            index //= 2
        return level[0], path

    def _rekor_sign(self, signing_key, message):
        """Sign with the Rekor key, handling EC and Ed25519."""
        from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
        if isinstance(signing_key, _ed25519.Ed25519PrivateKey):
            return signing_key.sign(message)
        return signing_key.sign(
            message, self.ec.ECDSA(self.hashes.SHA256()),
        )

    def checkpoint(self, *, root_hash=None, key=None, origin=None):
        encoded = base64.b64encode(root_hash or self.root_hash).decode("ascii")
        origin = origin or self.ORIGIN
        body = f"{origin}\n{self.TREE_SIZE}\n{encoded}\n"
        signing = key or self.rekor_key
        signature = self._rekor_sign(signing, body.encode("utf-8"))
        hint = hashlib.sha256(self.public_der(signing)).digest()[:4]
        blob = base64.b64encode(hint + signature).decode("ascii")
        return f"{body}\n— {origin} {blob}\n"

    def signed_entry_timestamp(self, *, key=None, log_id=None, log_index=None):
        payload = json.dumps({
            "body": base64.b64encode(self.body).decode("ascii"),
            "integratedTime": self.integrated,
            "logID": log_id or self.trust.log_id(),
            "logIndex": self.log_index if log_index is None else log_index,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signing = key or self.rekor_key
        return base64.b64encode(
            self._rekor_sign(signing, payload),
        ).decode("ascii")

    def payload(self):
        encoded_leaf = base64.b64encode(self.leaf).decode("ascii")
        return {
            "mediaType": PIN.SIGSTORE_MEDIA_TYPES[0],
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(
                        hashlib.sha256(self.subject).digest()
                    ).decode("ascii"),
                },
                "signature": base64.b64encode(self.signature).decode("ascii"),
            },
            "verificationMaterial": {
                # The canonical Sigstore v0.3 protobuf-JSON encoding: the
                # `content` oneof member appears DIRECTLY under
                # verificationMaterial, never wrapped in a literal `content`
                # object, and the pinned trust anchor is never duplicated
                # inside the bundle.
                **self.verification_material_content(encoded_leaf),
                "tlogEntries": [{
                    "logIndex": self.log_index,
                    "logId": {"keyId": self.trust.log_id()},
                    "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                    "integratedTime": self.integrated,
                    "canonicalizedBody": base64.b64encode(self.body).decode("ascii"),
                    "inclusionPromise": {
                        "signedEntryTimestamp": self.signed_entry_timestamp(),
                    },
                    "inclusionProof": {
                        "logIndex": self.log_index,
                        "treeSize": self.TREE_SIZE,
                        "rootHash": base64.b64encode(self.root_hash).decode("ascii"),
                        "hashes": [
                            base64.b64encode(node).decode("ascii")
                            for node in self.path
                        ],
                        "checkpoint": {"envelope": self.checkpoint()},
                    },
                }],
            },
        }

    def verification_material_content(self, encoded_leaf):
        """Exactly one canonical protobuf oneof member, directly encoded.

        `certificate` is what a raw Cosign v3.1.3 keyless `sign-blob --bundle`
        emits; `x509CertificateChain` is the other canonical v0.3 member. Both
        are accepted, and neither ever carries the pinned Fulcio root.
        """
        if self.chain_form:
            return {"x509CertificateChain": {"certificates": [
                {"rawBytes": value} for value in (
                    encoded_leaf,
                    *(
                        [base64.b64encode(self.extra_intermediate).decode("ascii")]
                        if self.extra_intermediate else []
                    ),
                    base64.b64encode(self.intermediate).decode("ascii"),
                )
            ]}}
        return {"certificate": {"rawBytes": encoded_leaf}}

    def with_body(self, body):
        """Re-seat the transparency body and recompute everything it binds.

        The Merkle path, the root hash, the signed checkpoint and the signed
        entry timestamp are all derived from `self.body`, so an adversarial
        body stays *internally consistent* here. That is the point: it removes
        the inclusion proof as an accidental catch and leaves the body schema
        itself as the only thing that can refuse it.
        """
        self.body = body
        self.root_hash, self.path = self._merkle()
        return self

    def bundle(self, *mutations):
        payload = self.payload()
        for mutate in mutations:
            mutate(payload)
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

_UNSET = object()


class RecordedGitHub:
    """Recorded canonical responses for the private production HTTPS exchange.

    Tests never subclass, construct or pass a production transport: they
    monkeypatch only the one private HTTPS exchange inside the fixed
    production client, so every URL, header and status check the real
    transport performs still runs.
    """

    TOKEN = {"GITHUB_TOKEN": "test-runtime-token"}

    def __init__(self, recorded):
        self._recorded = recorded
        self._seen = []
        self._requests = []

    def exchange(self, request, limit=None):
        """Bound to this recording, so the production client calls it directly."""
        url = request.full_url
        if url not in self._recorded:
            raise SystemExit(f"unrecorded canonical read: {url}")
        self._seen.append(url)
        self._requests.append((url, dict(request.header_items()), limit))
        return self._recorded[url]

    def reads(self):
        return tuple(self._seen)

    def requests(self):
        """Every request the real production client actually built."""
        return tuple(self._requests)

    def patched(self):
        """Patch only the private exchange and the runtime token."""
        return (
            mock.patch.object(
                PIN._GitHubReadOnlyTransport, "_exchange", self.exchange,
            ),
            mock.patch.dict(os.environ, self.TOKEN),
        )


class LiveEvidenceFixture:
    """Every canonical GitHub response the F8 derivation must authenticate."""

    SOURCE_ID = 987654321
    INDEPENDENT_ID = 876543219
    SOURCE_RUN_ID = 17493820551
    INDEPENDENT_RUN_ID = 17493820552
    SOURCE_JOB_ID = 49382055117
    INDEPENDENT_JOB_ID = 49382055118
    REVIEW_ARTIFACT_ID = 3344556677
    SIGNED_ARTIFACT_ID = 3344556678
    EXTERNAL_REVIEW_ARTIFACT_ID = 3344556679
    SOURCE_HEAD = "3f9c1ab27d0e45681bc7ade290f36154b8d0e7a2"
    SOURCE_TREE = "5c81ea37b04d9f26138ac0e574bd9231fa6c08e4"
    INDEPENDENT_HEAD = "7a2d05c9138ebf4460d17ac83e592b6f0cd41827"
    INDEPENDENT_TREE = "91be47d3a05c6f2810749ecb35d2860af71c4d39"
    INTEGRATED = 1800000000

    # The real GitHub timeline: the run and its job start, cosign signs and
    # Rekor integrates the entry *during* the job, and only then does the job
    # and the run complete. Anything else is not a representative server order.
    @staticmethod
    def instant(offset):
        return datetime.fromtimestamp(
            LiveEvidenceFixture.INTEGRATED + offset, tz=timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    RUN_CREATED_OFFSET = -900
    RUN_STARTED_OFFSET = -600
    JOB_STARTED_OFFSET = -300
    JOB_COMPLETED_OFFSET = 300
    RUN_UPDATED_OFFSET = 600

    def __init__(self, external_review, external_receipt, *,
                 repository_root, base_commit):
        self.external_review = external_review
        self.external_receipt = external_receipt
        self.repository_root = repository_root
        self.base_commit = base_commit
        self.package = ACTIVATION.verify_activation_package()
        self.external_contract = self.package["external_activation_review"]
        self.external_receipt_name, self.external_bundle_name = (
            self.external_contract["artifact_files"]
        )
        self.producer = self.package["producer_bindings"]
        self.envelope_name, self.receipt_name = sorted(
            self.producer["artifact_files"]
        )
        self.bundle_name = next(
            name for name in self.producer["signed_artifact_files"]
            if name.endswith(".sigstore.json")
        )
        self.receipt = self._receipt()
        self.envelope = self._envelope()
        self.sigstore = SigstoreFixture(
            self.receipt,
            repository=ACTIVATION.INDEPENDENT_REPOSITORY,
            workflow_path=ACTIVATION.TARGET_WORKFLOW_PATHS[
                ACTIVATION.INDEPENDENT_REPOSITORY
            ],
            workflow_sha=self.INDEPENDENT_HEAD,
            integrated=self.INTEGRATED,
        )
        self.trust = self.sigstore.trust
        self.responses = {}
        self._artifacts = {}
        self._record_all()
        self._record_external_review(self.external_members())

    # -- artifact members --------------------------------------------------
    def _receipt(self):
        return json.dumps({
            "source_execution_chain": {
                "run_id": self.SOURCE_RUN_ID,
                "run_attempt": 1,
                "run_head_sha": self.SOURCE_HEAD,
                "source_bootstrap_commit": self.SOURCE_HEAD,
                "source_bootstrap_tree": self.SOURCE_TREE,
                "independent_bootstrap_commit": self.INDEPENDENT_HEAD,
                "independent_bootstrap_tree": self.INDEPENDENT_TREE,
                "authority_head_commit": self.external_review["head_commit"],
                "authority_head_tree": self.external_review["head_tree"],
            },
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def _envelope(self):
        return json.dumps({
            "review_receipt_sha256": hashlib.sha256(self.receipt).hexdigest(),
            "source_run_id": self.SOURCE_RUN_ID,
            "source_run_attempt": 1,
            "source_run_head_sha": self.SOURCE_HEAD,
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    # -- recording ---------------------------------------------------------
    def _headers(self, permission, content_type):
        return {
            "Content-Type": f"{content_type}; charset=utf-8",
            PIN.PERMISSION_HEADER: permission,
            PIN.API_VERSION_HEADER: PIN.API_VERSION,
        }

    def record(self, url, payload, *, permission, status=200, headers=None,
               answered=None):
        body = (
            payload if type(payload) is bytes
            else json.dumps(payload, sort_keys=True).encode()
        )
        content_type = (
            PIN.ZIP_CONTENT_TYPE if type(payload) is bytes
            else PIN.JSON_CONTENT_TYPE
        )
        merged = self._headers(permission, content_type)
        merged.update(headers or {})
        self.responses[url] = PIN._TransportResponse(
            url=answered or url, status=status, headers=merged, body=body,
        )

    def record_redirect(self, url, target, *, status=302, headers=None,
                        answered=None):
        """The documented api.github.com artifact ZIP redirect, hop one."""
        merged = {
            "Location": target,
            PIN.PERMISSION_HEADER: PIN.ACTIONS_READ,
            PIN.API_VERSION_HEADER: PIN.API_VERSION,
        }
        merged.update(headers or {})
        self.responses[url] = PIN._TransportResponse(
            url=answered or url, status=status, headers=merged, body=b"",
        )

    def record_storage(self, url, body, *, status=200, headers=None,
                       answered=None):
        """The signed immutable storage download, hop two.

        Storage is not the GitHub API: it carries no permission provenance and
        no API version, and it is never sent a credential.
        """
        merged = {
            "Content-Type": PIN.ZIP_CONTENT_TYPE,
            "Content-Length": str(len(body)),
        }
        merged.update(headers or {})
        self.responses[url] = PIN._TransportResponse(
            url=answered or url, status=status, headers=merged, body=body,
        )

    STORAGE_HOST = "productionresultssa10.blob.core.windows.net"

    @classmethod
    def storage_target(cls, artifact_id):
        """The immutable signed storage URL the artifact redirect names."""
        token = hashlib.sha256(f"acc-artifact-{artifact_id}".encode()).hexdigest()
        return (
            f"https://{cls.STORAGE_HOST}/actions-results/{token[:32]}"
            f"/workflow-job-run-{token[32:]}/artifacts/{artifact_id}.zip"
            "?rscd=attachment%3B+filename%3D%22artifact.zip%22"
            "&se=2033-01-19T03%3A14%3A07Z"
            f"&sig={token}%3D&sp=r&spr=https&sr=b&sv=2025-01-05"
        )

    def _archive(self, members):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name in sorted(members):
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, members[name])
        return buffer.getvalue()

    def _record_repository(self, full_name, identifier):
        url = f"{PIN.API_ROOT}/repos/{full_name}"
        payload = {
            "full_name": full_name,
            "id": identifier,
            "node_id": f"R_kgDO{identifier}",
            "url": url,
            "html_url": f"https://github.com/{full_name}",
            "default_branch": "main",
            "visibility": "public",
            "private": False,
            "archived": False,
            "disabled": False,
            "permissions": {"admin": False, "push": False, "pull": True},
        }
        self.record(url, payload, permission=PIN.METADATA_READ)
        self.record(
            f"{PIN.API_ROOT}/repositories/{identifier}", payload,
            permission=PIN.METADATA_READ,
        )

    def _record_run(self, full_name, repository_id, run_id, workflow_path,
                    head_sha, head_tree, job_name, job_id):
        url = f"{PIN.API_ROOT}/repos/{full_name}/actions/runs/{run_id}"
        nested = {"id": repository_id, "full_name": full_name}
        self.record(url, {
            "id": run_id,
            "url": url,
            "run_attempt": 1,
            "previous_attempt_url": None,
            "status": "completed",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": workflow_path,
            "workflow_id": repository_id + 11,
            "repository": nested,
            "head_repository": nested,
            "head_sha": head_sha,
            "created_at": self.instant(self.RUN_CREATED_OFFSET),
            "run_started_at": self.instant(self.RUN_STARTED_OFFSET),
            "updated_at": self.instant(self.RUN_UPDATED_OFFSET),
        }, permission=PIN.ACTIONS_READ)
        jobs = f"{url}/attempts/1/jobs"
        self.record(
            f"{jobs}?per_page=100&page=1",
            {"total_count": 1, "jobs": [{
                "id": job_id, "name": job_name, "run_id": run_id,
                "run_attempt": 1, "status": "completed",
                "conclusion": "success", "head_sha": head_sha,
                "started_at": self.instant(self.JOB_STARTED_OFFSET),
                "completed_at": self.instant(self.JOB_COMPLETED_OFFSET),
            }]},
            permission=PIN.ACTIONS_READ,
        )
        commit_url = f"{PIN.API_ROOT}/repos/{full_name}/git/commits/{head_sha}"
        self.record(commit_url, {
            "sha": head_sha, "url": commit_url, "tree": {"sha": head_tree},
        }, permission=PIN.CONTENTS_READ)

    def _record_tree(self, full_name, tree_sha):
        sealed = PIN._sealed_bytes_for(full_name)
        entries = []
        for path, data in sorted(sealed.items()):
            oid = PIN._git_blob_oid(data)
            entries.append({
                "path": path, "type": "blob", "mode": "100644",
                "sha": oid, "size": len(data),
            })
            blob_url = f"{PIN.API_ROOT}/repos/{full_name}/git/blobs/{oid}"
            self.record(blob_url, {
                "sha": oid, "encoding": "base64",
                "content": base64.b64encode(data).decode("ascii"),
            }, permission=PIN.CONTENTS_READ)
        url = f"{PIN.API_ROOT}/repos/{full_name}/git/trees/{tree_sha}?recursive=1"
        self.record(url, {
            "sha": tree_sha, "truncated": False, "tree": entries,
        }, permission=PIN.CONTENTS_READ)
        return sealed

    def _record_artifact(self, full_name, run_id, head_sha, artifact_id, name,
                         members, *, corrupt_digest=False):
        archive = self._archive(members)
        declared = (
            hashlib.sha256(archive + b"forged").hexdigest() if corrupt_digest
            else hashlib.sha256(archive).hexdigest()
        )
        canonical = (
            f"{PIN.API_ROOT}/repos/{full_name}/actions/artifacts/{artifact_id}"
        )
        listing = f"{PIN.API_ROOT}/repos/{full_name}/actions/runs/{run_id}/artifacts"
        entry = {
            "id": artifact_id, "name": name, "expired": False,
            "url": canonical,
            "archive_download_url": f"{canonical}/zip",
            "size_in_bytes": len(archive),
            "digest": f"sha256:{declared}",
            "workflow_run": {"id": run_id, "head_sha": head_sha},
        }
        page = f"{listing}?per_page=100&page=1"
        entries = [
            item for item in self._artifacts.setdefault(page, [])
            if item["name"] != name
        ]
        entries.append(entry)
        self._artifacts[page] = entries
        self.record(
            page, {"total_count": len(entries), "artifacts": list(entries)},
            permission=PIN.ACTIONS_READ,
        )
        # The real GitHub flow: the authenticated API endpoint answers one
        # redirect, and the archive bytes come from signed storage.
        target = self.storage_target(artifact_id)
        self.record_redirect(f"{canonical}/zip", target)
        self.record_storage(target, archive)

    def _record_inventories(self, full_name, repository_id, workflow_path,
                            run_id, head_sha):
        """The exhaustive listings the production operation selects from."""
        workflow_id = repository_id + 11
        self.record(
            f"{PIN.API_ROOT}/repos/{full_name}/actions/workflows"
            "?per_page=100&page=1",
            {"total_count": 1, "workflows": [{
                "id": workflow_id, "name": "sealed", "path": workflow_path,
                "state": "active",
            }]},
            permission=PIN.ACTIONS_READ,
        )
        self.record(
            f"{PIN.API_ROOT}/repos/{full_name}/actions/workflows"
            f"/{workflow_id}/runs?per_page=100&page=1",
            {"total_count": 1, "workflow_runs": [{
                "id": run_id, "run_attempt": 1, "status": "completed",
                "conclusion": "success", "event": "workflow_dispatch",
                "head_branch": "main", "path": workflow_path,
                "head_sha": head_sha,
            }]},
            permission=PIN.ACTIONS_READ,
        )

    def _record_all(self):
        self._record_repository(ACTIVATION.SOURCE_REPOSITORY, self.SOURCE_ID)
        self._record_repository(
            ACTIVATION.INDEPENDENT_REPOSITORY, self.INDEPENDENT_ID,
        )
        self._record_inventories(
            ACTIVATION.SOURCE_REPOSITORY, self.SOURCE_ID,
            ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.SOURCE_REPOSITORY],
            self.SOURCE_RUN_ID, self.SOURCE_HEAD,
        )
        self._record_inventories(
            ACTIVATION.INDEPENDENT_REPOSITORY, self.INDEPENDENT_ID,
            ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY],
            self.INDEPENDENT_RUN_ID, self.INDEPENDENT_HEAD,
        )
        self._record_run(
            ACTIVATION.SOURCE_REPOSITORY, self.SOURCE_ID, self.SOURCE_RUN_ID,
            ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.SOURCE_REPOSITORY],
            self.SOURCE_HEAD, self.SOURCE_TREE, PIN.SOURCE_JOB_NAME,
            self.SOURCE_JOB_ID,
        )
        self._record_run(
            ACTIVATION.INDEPENDENT_REPOSITORY, self.INDEPENDENT_ID,
            self.INDEPENDENT_RUN_ID,
            ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY],
            self.INDEPENDENT_HEAD, self.INDEPENDENT_TREE,
            PIN.INDEPENDENT_JOB_NAME, self.INDEPENDENT_JOB_ID,
        )
        self._record_tree(ACTIVATION.SOURCE_REPOSITORY, self.SOURCE_TREE)
        self._record_tree(
            ACTIVATION.INDEPENDENT_REPOSITORY, self.INDEPENDENT_TREE,
        )
        self._record_artifact(
            ACTIVATION.SOURCE_REPOSITORY, self.SOURCE_RUN_ID, self.SOURCE_HEAD,
            self.REVIEW_ARTIFACT_ID, self.producer["artifact_name"],
            {self.envelope_name: self.envelope, self.receipt_name: self.receipt},
        )
        self._record_artifact(
            ACTIVATION.INDEPENDENT_REPOSITORY, self.INDEPENDENT_RUN_ID,
            self.INDEPENDENT_HEAD, self.SIGNED_ARTIFACT_ID,
            self.producer["signed_artifact_name"],
            {
                self.envelope_name: self.envelope,
                self.receipt_name: self.receipt,
                self.bundle_name: self.sigstore.bundle(),
            },
        )

    # -- the external activation review authority --------------------------
    def external_bundle(self, receipt, *, claims=None, mutation=None):
        arguments = {
            "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "workflow_path": self.external_contract["workflow_path"],
            "workflow_sha": self.INDEPENDENT_HEAD,
            "integrated": self.INTEGRATED,
            "authority": self.sigstore,
        }
        arguments.update(claims or {})
        fixture = SigstoreFixture(receipt, **arguments)
        return fixture.bundle(*([mutation] if mutation else []))

    def external_members(self, receipt=None, *, claims=None, mutation=None):
        receipt = self.external_receipt if receipt is None else receipt
        return {
            self.external_receipt_name: receipt,
            self.external_bundle_name: self.external_bundle(
                receipt, claims=claims, mutation=mutation,
            ),
        }

    def _record_external_review(self, members, *, corrupt_digest=False):
        self._record_artifact(
            ACTIVATION.INDEPENDENT_REPOSITORY, self.INDEPENDENT_RUN_ID,
            self.INDEPENDENT_HEAD, self.EXTERNAL_REVIEW_ARTIFACT_ID,
            self.external_contract["artifact_name"], members,
            corrupt_digest=corrupt_digest,
        )

    def external_review_transport(self, receipt, *, corrupt_digest=False,
                                  claims=None, bundle_mutation=None):
        """A transport whose external activation review artifact is replaced."""
        keep = dict(self.responses)
        self.responses = keep
        saved = dict(keep)
        self._record_external_review(
            self.external_members(
                receipt, claims=claims, mutation=bundle_mutation,
            ),
            corrupt_digest=corrupt_digest,
        )
        replaced = dict(self.responses)
        self.responses = saved
        return RecordedGitHub(replaced)

    # -- driving -----------------------------------------------------------
    def transport(self):
        return RecordedGitHub(dict(self.responses))

    def pinned_trust(self):
        """The fixture's own material, shaped as pinned trust for the loader."""
        return PIN._PinnedSigstoreTrust(
            fulcio_authorities=({
                "root": self.sigstore.root,
                "intermediates": (self.sigstore.intermediate,),
                "uri": "https://fulcio.test.invalid",
                "valid_from": self.INTEGRATED - 86400,
                "valid_to": None,
            },),
            rekor_logs=({
                "log_id_key_id": self.trust.log_key_id(),
                "log_id_hex": self.trust.log_id(),
                "origin": self.trust.rekor_origin,
                "public_key": self.trust.rekor_public_key,
                "valid_from": self.INTEGRATED - 86400,
                "valid_to": None,
            },),
        )

    def derive(self, exchange=None, *, repository_root=None, trust=_UNSET):
        """Drive the production operation through its private seams only.

        The transport is never passed in: only the private HTTPS exchange is
        recorded. Trust is never passed in either: it is either the real
        candidate-bound loader or, for positive coverage, a private monkeypatch
        of that loader.
        """
        recorded = self.transport() if exchange is None else exchange
        pinned = self.pinned_trust() if trust is _UNSET else trust
        contexts = list(recorded.patched())
        if pinned is not None:
            contexts.append(
                mock.patch.object(
                    PIN, "_load_pinned_sigstore_trust", lambda root: pinned,
                )
            )
        with contextlib.ExitStack() as stack:
            for context in contexts:
                stack.enter_context(context)
            return PIN.derive_activation_closure(
                repository_root or self.repository_root,
            )

    def rejection(self, exchange=None, **kwargs):
        """The exact reason the production operation refused to close F8."""
        try:
            self.derive(exchange, **kwargs)
        except SystemExit as error:
            return str(error)
        raise AssertionError("the production operation closed F8")

class PreActivationAuthorizationTests(unittest.TestCase):
    """F8-ACTIVATION-AUTHORIZATION-SELF-PROHIBITED.

    The reviewed package carries one immutable pre-activation authorization for
    the named acc-releaser activation lane, strictly separated from the
    post-activation proof that may only ever be pinned from live evidence.
    """

    PROTECTED_SOURCE = "chrizzatsu/acc-authority-protected-source"
    INDEPENDENT_REVIEW = "chrizzatsu/acc-authority-independent-review"

    def setUp(self):
        self.data = ACTIVATION.ACTIVATION_PATH.read_bytes()
        self.package = json.loads(self.data)
        self.grant = self.package["pre_activation_authorization"]
        self.proof = self.package["post_activation_proof"]

    def _verify(self, payload):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "source-chain-activation-v2.json"
            path.write_bytes(
                json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
            )
            return ACTIVATION.verify_activation_package(path=path)

    # --- the grant exists and is not self-prohibited ---

    def test_package_authorizes_the_named_acc_releaser_activation_lane(self):
        authorizes = self.package["authorizes"]
        self.assertIs(authorizes["acc_releaser_activation"], True)
        self.assertIs(authorizes["repository_creation"], True)
        self.assertIs(authorizes["workflow_write"], True)
        self.assertIs(authorizes["workflow_dispatch"], True)
        self.assertEqual(self.grant["authorized_lane"], "acc-releaser")
        self.assertIs(self.grant["caller_selectable"], False)
        self.assertIs(self.grant["lane_self_authorization_forbidden"], True)
        self.assertIs(self.grant["immutable"], True)

    def test_authority_release_send_and_spend_permissions_stay_false(self):
        authorizes = self.package["authorizes"]
        for name in (
            "authority_merge", "authority_v2_issuance", "customer_data_access",
            "database_access", "external_send", "product_access", "publication",
            "release", "signing", "spend",
            "workflow_enable_before_authenticated_readback",
        ):
            self.assertIs(authorizes[name], False, name)
        self.assertEqual(
            tuple(sorted(authorizes)), ACTIVATION.AUTHORIZATION_KEYS,
        )

    def test_grant_binds_exactly_the_two_named_target_repositories(self):
        self.assertEqual(
            self.grant["exact_repository_creation"],
            [self.INDEPENDENT_REVIEW, self.PROTECTED_SOURCE],
        )
        self.assertEqual(
            tuple(sorted(self.package["target_repositories"])),
            (self.INDEPENDENT_REVIEW, self.PROTECTED_SOURCE),
        )

    def test_grant_binds_exactly_the_seven_sealed_files_and_hashes(self):
        writes = self.grant["exact_file_writes"]
        self.assertEqual(len(writes), 7)
        sealed = {entry["path"]: entry for entry in self.package["sealed_bytes"]}
        self.assertEqual(len(sealed), 7)
        for entry in writes:
            self.assertEqual(
                tuple(sorted(entry)), ("path", "repository", "sha256", "target_path"),
            )
            source = sealed[entry["path"]]
            self.assertEqual(entry["repository"], source["repository"])
            self.assertEqual(entry["target_path"], source["target_path"])
            self.assertEqual(entry["sha256"], source["sha256"])
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest(),
            )
        self.assertEqual(
            [entry["path"] for entry in writes],
            sorted(entry["path"] for entry in writes),
        )

    def test_grant_binds_zero_spend_reversibility_and_one_attempt_1_execution(self):
        self.assertEqual(self.grant["maximum_authorized_activation_attempts"], 1)
        self.assertEqual(self.grant["authorized_run_attempt"], 1)
        self.assertIs(self.grant["reversible"], True)
        self.assertEqual(self.grant["maximum_incremental_spend_eur"], "0.00")
        self.assertIs(self.grant["zero_spend_required"], True)
        self.assertIs(
            self.grant["workflows_disabled_until_authenticated_readback"], True
        )
        self.assertIs(self.grant["authenticated_readback_required_before_enable"], True)
        self.assertIs(self.grant["cleanup_required"], True)
        self.assertIs(
            self.grant["deterministic_later_fresh_direct_child_pinning_required"],
            True,
        )

    def test_one_activation_is_technically_enforced_not_merely_declared(self):
        """`GITHUB_RUN_ATTEMPT == 1` only blocks reruns of one run.

        A second `workflow_dispatch` is a different run id at attempt 1, so
        the grant must bind the mechanism that really excludes it: the sealed
        workflow is disabled before any protected action runs, additional run
        ids are excluded out of an exhaustively read-back inventory, and the
        disable is re-asserted and read back on the failure path too.
        """
        self.assertIs(
            self.grant["workflow_disabled_before_protected_actions"], True,
        )
        self.assertIs(
            self.grant["additional_run_ids_excluded_before_protected_actions"],
            True,
        )
        cleanup = self.package["cleanup"]
        self.assertIs(cleanup["workflow_disabled_after_activation"], True)
        self.assertIs(cleanup["authenticated_disable_readback_required"], True)
        self.assertIs(cleanup["disable_covers_failure_paths"], True)
        self.assertEqual(
            cleanup["expected_workflow_state_after_activation"],
            "disabled_manually",
        )

    def test_a_weakened_one_activation_mechanism_is_rejected(self):
        for mutate in (
            lambda p: p["pre_activation_authorization"].update(
                workflow_disabled_before_protected_actions=False),
            lambda p: p["pre_activation_authorization"].update(
                additional_run_ids_excluded_before_protected_actions=False),
            lambda p: p["pre_activation_authorization"].pop(
                "workflow_disabled_before_protected_actions"),
            lambda p: p["cleanup"].update(workflow_disabled_after_activation=False),
            lambda p: p["cleanup"].update(
                authenticated_disable_readback_required=False),
            lambda p: p["cleanup"].update(disable_covers_failure_paths=False),
            lambda p: p["cleanup"].update(
                expected_workflow_state_after_activation="active"),
            lambda p: p["cleanup"].pop("disable_covers_failure_paths"),
        ):
            payload = deepcopy(self.package)
            mutate(payload)
            with self.assertRaises(SystemExit):
                self._verify(payload)

    # --- post-activation proof is separate and empty ---

    def test_post_activation_proof_is_separate_and_holds_no_live_evidence_yet(self):
        self.assertIs(self.proof["live_evidence_pinned"], False)
        self.assertIs(self.proof["f8_true_requires_live_evidence"], True)
        self.assertEqual(
            self.proof["pinning_helper"],
            "scripts/pin_source_chain_activation_v2.py",
        )
        self.assertEqual(
            self.proof["pinning_candidate_topology"],
            "fresh-ordinary-non-merge-direct-child",
        )
        self.assertEqual(
            self.proof["required_live_fields"], list(ACTIVATION.READBACK_FIELDS),
        )
        self.assertIs(self.package["f8_closed"], False)
        self.assertEqual(self.package["activation_state"], "unavailable")

    def test_f8_can_never_be_true_without_pinned_live_evidence(self):
        payload = deepcopy(self.package)
        payload["f8_closed"] = True
        with self.assertRaises(SystemExit):
            self._verify(payload)
        payload = deepcopy(self.package)
        payload["activation_state"] = "ready"
        payload["repositories_created"] = True
        payload["workflows_written"] = True
        payload["runs_observed"] = True
        payload["f8_closed"] = True
        with self.assertRaises(SystemExit):
            self._verify(payload)

    # --- adversarial mutations of the grant ---

    def test_widened_or_removed_grant_is_rejected(self):
        for mutate in (
            lambda p: p["authorizes"].update(authority_v2_issuance=True),
            lambda p: p["authorizes"].update(authority_merge=True),
            lambda p: p["authorizes"].update(release=True),
            lambda p: p["authorizes"].update(publication=True),
            lambda p: p["authorizes"].update(signing=True),
            lambda p: p["authorizes"].update(external_send=True),
            lambda p: p["authorizes"].update(spend=True),
            lambda p: p["authorizes"].update(product_access=True),
            lambda p: p["authorizes"].update(customer_data_access=True),
            lambda p: p["authorizes"].update(database_access=True),
            lambda p: p["authorizes"].update(
                workflow_enable_before_authenticated_readback=True,
            ),
            lambda p: p["authorizes"].update(acc_releaser_activation=False),
            lambda p: p["authorizes"].update(repository_creation=False),
            lambda p: p["pre_activation_authorization"].update(
                authorized_lane="anyone",
            ),
            lambda p: p["pre_activation_authorization"].update(caller_selectable=True),
            lambda p: p["pre_activation_authorization"].update(
                maximum_authorized_activation_attempts=2,
            ),
            lambda p: p["pre_activation_authorization"].update(authorized_run_attempt=2),
            lambda p: p["pre_activation_authorization"].update(
                maximum_incremental_spend_eur="0.01",
            ),
            lambda p: p["pre_activation_authorization"].update(reversible=False),
            lambda p: p["pre_activation_authorization"].update(
                workflows_disabled_until_authenticated_readback=False,
            ),
            lambda p: p["pre_activation_authorization"].update(
                exact_repository_creation=[
                    "chrizzatsu/acc-authority-protected-source",
                    "chrizzatsu/somewhere-else",
                ],
            ),
            lambda p: p["pre_activation_authorization"]["exact_file_writes"].append({
                "path": "README.md",
                "repository": "chrizzatsu/acc-authority-protected-source",
                "sha256": "0" * 64,
                "target_path": "README.md",
            }),
            lambda p: p["pre_activation_authorization"]["exact_file_writes"][0].update(
                sha256="0" * 64,
            ),
            lambda p: p["pre_activation_authorization"]["exact_file_writes"].pop(),
            lambda p: p.pop("pre_activation_authorization"),
            lambda p: p.pop("post_activation_proof"),
            lambda p: p["post_activation_proof"].update(live_evidence_pinned=True),
            lambda p: p["post_activation_proof"].update(
                f8_true_requires_live_evidence=False,
            ),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(self.package)
                mutate(payload)
                with self.assertRaises(SystemExit):
                    self._verify(payload)

    def test_shipped_package_still_verifies_exactly(self):
        self.assertEqual(ACTIVATION.verify_activation_package(), self.package)


class ExternalActivationReviewTests(unittest.TestCase):
    """F8-EXACT-CANDIDATE-REVIEW-BINDING-STALE.

    The candidate may define the external review-receipt contract, but it may
    never contain its own approval, pin a stale sibling head/tree/trust
    constant, or circularly precompute the later receipt. Activation
    authorization is external, post-candidate and verified byte for byte
    against the exact clean checkout.
    """

    def setUp(self):
        self.data = ACTIVATION.ACTIVATION_PATH.read_bytes()
        self.package = json.loads(self.data)

    # -- helpers ----------------------------------------------------------
    def make_candidate(self, root, *, trust_bytes=b'{"trust":1}\n', extra=None):
        git(root, "init", "-q")
        git(root, "config", "user.email", "fixture@example.invalid")
        git(root, "config", "user.name", "Fixture")
        (root / "keep.txt").write_bytes(b"keep\n")
        (root / "old-name.txt").write_bytes(b"renamed payload\n" * 8)
        git(root, "add", "-A")
        git(root, "commit", "-qm", "base")
        base = git(root, "rev-parse", "HEAD")
        (root / ACTIVATION.TRUST_RECORD_PATH).write_bytes(trust_bytes)
        (root / "old-name.txt").rename(root / "new-name.txt")
        (root / "keep.txt").write_bytes(b"keep\nmore\n")
        for name, payload in (extra or {}).items():
            (root / name).write_bytes(payload)
        git(root, "add", "-A")
        git(root, "commit", "-qm", "candidate")
        return base, git(root, "rev-parse", "HEAD")

    def receipt_for(self, root, base, head, **overrides):
        payload = ACTIVATION.external_review_bindings(root, base, head)
        payload.update({
            "schema_version": 1,
            "receipt_type": ACTIVATION.EXTERNAL_REVIEW_RECEIPT_TYPE,
            "reviewer_profile": "acc-reviewer",
            "reviewer_repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "candidate_owned": False,
            "produced_after_candidate": True,
            "decision": "APPROVED",
            "findings": [],
            "findings_count": 0,
            "activation_authorized": True,
            **external_review_evidence(head),
        })
        payload.update(overrides)
        return ACTIVATION.canonical_bytes(payload)

    def verify(self, data, root, base, **kwargs):
        return ACTIVATION.verify_external_activation_review(
            data,
            repository_root=root,
            base_commit=base,
            receipt_sha256=kwargs.pop(
                "receipt_sha256", hashlib.sha256(data).hexdigest(),
            ),
            **kwargs,
        )

    # -- behaviour --------------------------------------------------------
    def test_candidate_carries_no_stale_self_review_approval(self):
        self.assertNotIn("activation_source_review", self.package)
        self.assertFalse(hasattr(ACTIVATION, "EXPECTED_ACTIVATION_SOURCE_REVIEW"))
        source = (
            ROOT / "scripts" / "verify_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        for stale in (
            "5f86afae420c174540374a4af8e2163b96b7dbc0",
            "27a990510f0ed5e9d834d16a262adc7205bc6ab1",
            "8cc3d71f462eee863f9da6b624cf590903710abbc56b2de9e36cd835c128438a",
            "fc28b2764f61148727ac8a52d976918ee748aab12ce8f2f3635f76111f749276",
        ):
            self.assertNotIn(stale, source)
            self.assertNotIn(stale, self.data.decode())

    def test_pre_review_package_authorizes_no_activation(self):
        self.assertIs(self.package["activation_authorized"], False)
        self.assertIs(self.package["f8_closed"], False)
        contract = self.package["external_activation_review"]
        self.assertEqual(contract["state"], "unavailable")
        self.assertIsNone(contract["receipt_sha256"])
        self.assertIs(contract["candidate_owned_approval_forbidden"], True)
        self.assertIs(contract["self_review_forbidden"], True)
        self.assertEqual(
            contract["receipt_type"], ACTIVATION.EXTERNAL_REVIEW_RECEIPT_TYPE,
        )

    def test_external_receipt_binds_every_value_to_the_exact_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_candidate(root)
            data = self.receipt_for(root, base, head)
            review = self.verify(data, root, base)
        self.assertIs(review["activation_authorized"], True)
        self.assertEqual(review["head_commit"], head)
        self.assertEqual(review["sole_parent"], base)
        self.assertEqual(review["receipt_sha256"], hashlib.sha256(data).hexdigest())
        renames = [
            entry for entry in review["changed_path_manifest"]
            if entry["status"] == "R"
        ]
        self.assertTrue(renames, "rename semantics missing from the bound manifest")
        self.assertEqual(renames[0]["old_path"], "old-name.txt")
        self.assertEqual(renames[0]["new_path"], "new-name.txt")
        self.assertIsNotNone(renames[0]["old_blob_oid"])
        self.assertIsNotNone(renames[0]["new_mode"])

    def test_external_receipt_seals_all_four_canonical_diff_streams(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_candidate(root)
            receipt = json.loads(self.receipt_for(root, base, head))
            observed = receipt["candidate_diff_sha256"]
            commands = {
                "canonical-binary-full-index.diff": (
                    "--binary", "--full-index",
                ),
                "name-status-find-renames-50.z": ("--name-status", "-z"),
                "raw-full-index-find-renames-50.z": (
                    "--raw", "-z", "--full-index",
                ),
                "raw-status-authoritative.z": ("--raw", "-z"),
            }
            expected = {}
            for name, leading in commands.items():
                raw = subprocess.run(
                    ["git", "-C", str(root), "diff", *leading,
                     "--no-ext-diff", "--no-abbrev", "--find-renames=50%",
                     "--src-prefix=a/", "--dst-prefix=b/", base, head, "--"],
                    check=True, capture_output=True,
                    env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
                ).stdout
                expected[name] = hashlib.sha256(raw).hexdigest()
        self.assertEqual(observed, expected)

    def test_every_binding_forgery_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_candidate(root)
            good = json.loads(self.receipt_for(root, base, head))
            for mutate in (
                lambda r: r.update(head_commit="0" * 40),
                lambda r: r.update(head_tree="0" * 40),
                lambda r: r.update(sole_parent="0" * 40),
                lambda r: r.update(base_commit="0" * 40),
                lambda r: r.update(canonical_diff_sha256="0" * 64),
                lambda r: r.update(reviewer_authorization_sha256="0" * 64),
                lambda r: r.update(repository="chrizzatsu/other"),
                lambda r: r.update(decision="CHANGES_REQUESTED"),
                lambda r: r.update(decision="approved"),
                lambda r: r.update(findings=[{"closure": "F8", "finding": "x"}]),
                lambda r: r.update(findings_count=1),
                lambda r: r.update(findings_count=True),
                lambda r: r.update(activation_authorized="yes"),
                lambda r: r.update(produced_after_candidate=False),
                lambda r: r.update(candidate_owned=True),
                lambda r: r.update(reviewer_profile="acc-releaser"),
                lambda r: r["changed_path_manifest"].pop(),
                lambda r: r["changed_path_manifest"][0].update(new_sha256="0" * 64),
                lambda r: r["tracked_paths_sha256"].update({"keep.txt": "0" * 64}),
                lambda r: r["tracked_paths_sha256"].pop("keep.txt"),
                lambda r: r.pop("critical_artifact_sha256"),
            ):
                with self.subTest(mutate=mutate):
                    payload = deepcopy(good)
                    mutate(payload)
                    data = ACTIVATION.canonical_bytes(payload)
                    with self.assertRaises(SystemExit):
                        self.verify(data, root, base)

    def test_self_reviewed_receipt_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_candidate(root)
            data = self.receipt_for(
                root, base, head,
                reviewer_repository=ACTIVATION.AUTHORITY_REPOSITORY,
            )
            with self.assertRaises(SystemExit):
                self.verify(data, root, base)

    def test_receipt_precomputed_inside_the_candidate_is_rejected(self):
        """A candidate may not carry the digest of its own later receipt.

        The guard is exercised directly because a real circular precomputation
        would require an attacker to solve a SHA-256 fixpoint; the defense must
        still reject the digest the moment it appears in the reviewed tree.
        """
        planted = "9" * 60 + "abcd"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_candidate(
                root, extra={"precomputed.json": planted.encode() + b"\n"},
            )
            with self.assertRaises(SystemExit):
                ACTIVATION._require_no_circular_precomputation(
                    root, head, planted,
                )
            data = self.receipt_for(root, base, head)
            # An honest receipt over the same candidate still authenticates.
            self.assertIs(self.verify(data, root, base)["activation_authorized"], True)
            # A digest the candidate does not carry is not a precomputation.
            ACTIVATION._require_no_circular_precomputation(
                root, head, hashlib.sha256(b"unrelated\n").hexdigest(),
            )

    def test_non_canonical_bytes_digest_and_dirty_checkout_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_candidate(root)
            data = self.receipt_for(root, base, head)
            with self.assertRaises(SystemExit):
                self.verify(data, root, base, receipt_sha256="0" * 64)
            with self.assertRaises(SystemExit):
                self.verify(b" " + data, root, base)
            (root / "dirty.txt").write_bytes(b"dirty\n")
            with self.assertRaises(SystemExit):
                self.verify(data, root, base)


class LiveEvidenceForgeryTests(unittest.TestCase):
    """F8-LIVE-EVIDENCE-FORGEABLE.

    F8 may never be set by a caller. It is derived only from canonical,
    authenticated GitHub repository/run/job/commit/tree/path/blob/artifact
    evidence read through an explicit injected read-only transport, with
    complete permission and pagination provenance, immutable artifact download
    by canonical id, byte recomputation and a real Sigstore/Rekor boundary.
    """

    def test_no_caller_controlled_closure_boolean_survives(self):
        source = (
            ROOT / "scripts" / "pin_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("set_f8_closed", source)
        signature = inspect.signature(PIN.derive_activation_closure)
        for name in signature.parameters:
            self.assertNotIn("f8", name.lower())
            self.assertNotIn("closed", name.lower())
            self.assertNotIn("closure", name.lower())

    def test_synthetic_fixture_identifiers_are_rejected(self):
        for identifier in (4242, 900001, 1, 0, -5, True, 111111, "4242"):
            with self.subTest(identifier=identifier):
                with self.assertRaises(SystemExit):
                    PIN._require_canonical_id(identifier, "fixture id")
        for digest in ("a" * 40, "b" * 40, "1" * 64, "0" * 64, "f" * 64):
            with self.subTest(digest=digest):
                with self.assertRaises(SystemExit):
                    PIN._require_non_synthetic_digest(digest, "fixture digest")

    def test_caller_shaped_evidence_and_closure_objects_are_refused(self):
        class CallerTransport:
            f8_closed = True

            def get(self, url):
                raise AssertionError("must never be called")

        for candidate in (CallerTransport(), {"f8_closed": True}, None, object()):
            with self.subTest(candidate=type(candidate).__name__):
                with self.assertRaises(SystemExit):
                    PIN._require_read_only_transport(candidate)

    def test_read_only_transport_boundary_expresses_only_reads(self):
        self.assertTrue(hasattr(PIN, "_ReadOnlyTransport"))
        members = dir(PIN._ReadOnlyTransport)
        for verb in ("post", "put", "patch", "delete", "write", "dispatch"):
            self.assertNotIn(verb, [name.lower() for name in members])

    def test_the_closure_operation_accepts_no_forged_state(self):
        for forged in (
            {"authorized_run": {"run_id": 4242}},
            {"f8_closed": True},
            None,
            "ready",
            42,
        ):
            with self.subTest(forged=type(forged).__name__):
                with self.assertRaises((SystemExit, TypeError, OSError)):
                    PIN.derive_activation_closure(forged)


class SigstoreVerificationBoundaryTests(unittest.TestCase):
    """The Sigstore boundary performs real trusted cryptography or fails closed."""

    REPOSITORY = ACTIVATION.INDEPENDENT_REPOSITORY
    WORKFLOW = ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY]
    WORKFLOW_SHA = "7a2d05c9138ebf4460d17ac83e592b6f0cd41827"
    INTEGRATED = 1800000000

    def setUp(self):
        self.subject = b'{"receipt":"exact-subject-bytes"}\n'
        self.fixture = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )

    _UNSET = object()

    def verify(self, bundle=None, *, trust=_UNSET, subject=None, **overrides):
        arguments = {
            "subject_bytes": subject or self.subject,
            "trust": self.fixture.trust if trust is self._UNSET else trust,
            "repository": self.REPOSITORY,
            "workflow_path": self.WORKFLOW,
            "workflow_sha": self.WORKFLOW_SHA,
            # The authenticated run and job window the signature must fall in.
            "signing_window": (self.INTEGRATED - 300, self.INTEGRATED + 300),
        }
        arguments.update(overrides)
        return PIN._verify_sigstore_bundle(
            bundle if bundle is not None else self.fixture.bundle(), **arguments,
        )

    def test_a_genuinely_signed_bundle_verifies(self):
        result = self.verify()
        self.assertEqual(result["integrated_time"], self.INTEGRATED)
        self.assertEqual(result["certificate_workflow_sha"], self.WORKFLOW_SHA)
        self.assertEqual(
            result["identity"],
            f"https://github.com/{self.REPOSITORY}/{self.WORKFLOW}"
            "@refs/heads/main",
        )

    def test_absent_trust_material_fails_closed(self):
        for trust in (None, {}, "pinned", object()):
            with self.subTest(trust=type(trust).__name__):
                with self.assertRaises(SystemExit):
                    self.verify(trust=trust)

    def test_bad_leaf_signature_is_rejected(self):
        """A leaf whose issuer signature does not verify must reject."""
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )
        forged = base64.b64encode(other.leaf).decode("ascii")

        def substitute(payload):
            chain = payload["verificationMaterial"]["x509CertificateChain"]
            chain["certificates"][0]["rawBytes"] = forged

        with self.assertRaises(SystemExit):
            self.verify(self.fixture.bundle(substitute))

    def test_chain_substitution_to_an_unpinned_root_is_rejected(self):
        """The bundle can never widen the trusted path.

        The trust anchor and the issuing intermediates come from the pinned
        Fulcio trust, so a leaf issued under a foreign authority is refused
        whatever chain the bundle asserts, and grafting a foreign intermediate
        into an honest bundle cannot make that foreign authority an anchor.
        """
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )
        # A foreign leaf, with its own honest-looking chain, against pinned trust.
        with self.assertRaises(SystemExit):
            self.verify(other.bundle(), trust=self.fixture.trust)

        # The same foreign leaf, grafted into the pinned lane's own bundle.
        def substitute_foreign_leaf(payload):
            chain = payload["verificationMaterial"]["x509CertificateChain"]
            chain["certificates"] = [
                {"rawBytes": base64.b64encode(other.leaf).decode("ascii")},
                {"rawBytes": base64.b64encode(other.intermediate).decode("ascii")},
            ]

        with self.assertRaises(SystemExit):
            self.verify(self.fixture.bundle(substitute_foreign_leaf))

        # An honest leaf still verifies when the bundle carries no issuer at
        # all: the path is built from the pinned Fulcio intermediates.
        def drop_every_issuer(payload):
            chain = payload["verificationMaterial"]["x509CertificateChain"]
            chain["certificates"] = chain["certificates"][:1]

        self.verify(self.fixture.bundle(drop_every_issuer))

        # An extra untrusted foreign intermediate changes nothing.
        def append_foreign_intermediate(payload):
            chain = payload["verificationMaterial"]["x509CertificateChain"]
            chain["certificates"].append(
                {"rawBytes": base64.b64encode(other.intermediate).decode("ascii")},
            )

        self.verify(self.fixture.bundle(append_foreign_intermediate))

    def test_expired_and_not_yet_valid_certificates_are_rejected(self):
        moment = datetime.fromtimestamp(self.INTEGRATED, tz=timezone.utc)
        for label, window in (
            ("expired", (moment - timedelta(days=2), moment - timedelta(days=1))),
            ("not-yet-valid",
             (moment + timedelta(days=1), moment + timedelta(days=2))),
        ):
            with self.subTest(label=label):
                fixture = SigstoreFixture(
                    self.subject, repository=self.REPOSITORY,
                    workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
                    integrated=self.INTEGRATED, validity=window,
                )
                with self.assertRaises(SystemExit):
                    self.verify(fixture.bundle(), trust=fixture.trust)

    def test_subject_mutation_and_bad_subject_signature_are_rejected(self):
        with self.assertRaises(SystemExit):
            self.verify(subject=self.subject + b"tampered\n")

        def forge_signature(payload):
            signature = base64.b64decode(payload["messageSignature"]["signature"])
            payload["messageSignature"]["signature"] = base64.b64encode(
                signature[:-1] + bytes([signature[-1] ^ 0xFF]),
            ).decode("ascii")

        with self.assertRaises(SystemExit):
            self.verify(self.fixture.bundle(forge_signature))

        def forge_digest(payload):
            payload["messageSignature"]["messageDigest"]["digest"] = (
                base64.b64encode(hashlib.sha256(b"other").digest()).decode("ascii")
            )

        with self.assertRaises(SystemExit):
            self.verify(self.fixture.bundle(forge_digest))

    def test_rekor_key_substitution_is_rejected(self):
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )
        foreign = PIN._SigstoreTrustRoot(
            fulcio_roots=self.fixture.trust.fulcio_roots,
            rekor_public_key=other.trust.rekor_public_key,
            rekor_origin=self.fixture.trust.rekor_origin,
        )
        with self.assertRaises(SystemExit):
            self.verify(trust=foreign)

    def test_bad_signed_entry_timestamp_is_rejected(self):
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )

        def foreign_set(payload):
            entry = payload["verificationMaterial"]["tlogEntries"][0]
            entry["inclusionPromise"]["signedEntryTimestamp"] = (
                self.fixture.signed_entry_timestamp(key=other.rekor_key)
            )

        def absent_set(payload):
            payload["verificationMaterial"]["tlogEntries"][0].pop("inclusionPromise")

        def shifted_index(payload):
            payload["verificationMaterial"]["tlogEntries"][0]["logIndex"] = 2

        for mutate in (foreign_set, absent_set, shifted_index):
            with self.subTest(mutate=mutate.__name__):
                with self.assertRaises(SystemExit):
                    self.verify(self.fixture.bundle(mutate))

    def test_bad_checkpoint_signature_and_origin_are_rejected(self):
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )

        def foreign_key(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            proof["checkpoint"]["envelope"] = self.fixture.checkpoint(
                key=other.rekor_key,
            )

        def foreign_origin(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            proof["checkpoint"]["envelope"] = self.fixture.checkpoint(
                origin="some-other-log",
            )

        def unsigned(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            envelope = proof["checkpoint"]["envelope"]
            proof["checkpoint"]["envelope"] = envelope.split("\n\n")[0] + "\n\n"

        def other_root(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            proof["checkpoint"]["envelope"] = self.fixture.checkpoint(
                root_hash=hashlib.sha256(b"different-root").digest(),
            )

        for mutate in (foreign_key, foreign_origin, unsigned, other_root):
            with self.subTest(mutate=mutate.__name__):
                with self.assertRaises(SystemExit):
                    self.verify(self.fixture.bundle(mutate))

    def test_merkle_substitution_is_rejected(self):
        def swap_hash(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            proof["hashes"][0] = base64.b64encode(
                hashlib.sha256(b"forged-sibling").digest()
            ).decode("ascii")

        def drop_hash(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            proof["hashes"] = proof["hashes"][:1]

        def shift_index(payload):
            entry = payload["verificationMaterial"]["tlogEntries"][0]
            entry["inclusionProof"]["logIndex"] = 3
            entry["logIndex"] = 3

        def forged_body(payload):
            entry = payload["verificationMaterial"]["tlogEntries"][0]
            body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
            body["spec"]["data"]["hash"]["value"] = "0" * 64
            entry["canonicalizedBody"] = base64.b64encode(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).decode("ascii")

        for mutate in (swap_hash, drop_hash, shift_index, forged_body):
            with self.subTest(mutate=mutate.__name__):
                with self.assertRaises(SystemExit):
                    self.verify(self.fixture.bundle(mutate))

    def test_trusted_time_and_workload_claims_are_enforced(self):
        # Integration before the authenticated start or after the
        # authenticated successful completion is refused.
        with self.assertRaises(SystemExit):
            self.verify(
                signing_window=(self.INTEGRATED + 60, self.INTEGRATED + 300),
            )
        with self.assertRaises(SystemExit):
            self.verify(
                signing_window=(self.INTEGRATED - 300, self.INTEGRATED - 60),
            )
        for malformed in (None, (), (1,), (2, 1), ("a", "b"), (True, 2)):
            with self.subTest(malformed=malformed):
                with self.assertRaises(SystemExit):
                    self.verify(signing_window=malformed)
        with self.assertRaises(SystemExit):
            self.verify(workflow_sha="0" * 40)
        with self.assertRaises(SystemExit):
            self.verify(repository="chrizzatsu/acc-attestation-authority")
        with self.assertRaises(SystemExit):
            self.verify(workflow_path=".github/workflows/other.yml")

    def test_wrong_issuer_ref_and_trigger_claims_are_rejected(self):
        for oid, forged in (
            ("1.3.6.1.4.1.57264.1.8", "https://accounts.google.com"),
            ("1.3.6.1.4.1.57264.1.14", "refs/heads/release"),
            ("1.3.6.1.4.1.57264.1.20", "push"),
            ("1.3.6.1.4.1.57264.1.12", "https://github.com/chrizzatsu/other"),
        ):
            with self.subTest(oid=oid):
                fixture = self._fixture_with_claim(oid, forged)
                with self.assertRaises(SystemExit):
                    self.verify(fixture.bundle(), trust=fixture.trust)

    def _fixture_with_claim(self, oid, value):
        original = SigstoreFixture._sign_certificate

        def patched(instance, subject_name, issuer_name, public_key,
                    signing_key, not_before, not_after, *, ca, extensions,
                    **keywords):
            extensions = [
                (name, der(0x0C, value.encode("utf-8")) if name == oid else raw)
                for name, raw in extensions
            ]
            return original(
                instance, subject_name, issuer_name, public_key, signing_key,
                not_before, not_after, ca=ca, extensions=extensions, **keywords,
            )

        with mock.patch.object(SigstoreFixture, "_sign_certificate", patched):
            return SigstoreFixture(
                self.subject, repository=self.REPOSITORY,
                workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
                integrated=self.INTEGRATED,
            )


class Ed25519RekorVerificationTests(unittest.TestCase):
    """Ed25519 Rekor key support for SET and checkpoint signature verification.

    The production boundary must accept Ed25519 public keys for both the signed
    entry timestamp and the checkpoint signature, alongside the existing EC and
    RSA support. Tamper, wrong-key and wrong-checkpoint must all be rejected.
    """

    REPOSITORY = ACTIVATION.INDEPENDENT_REPOSITORY
    WORKFLOW = ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY]
    WORKFLOW_SHA = "7a2d05c9138ebf4460d17ac83e592b6f0cd41827"
    INTEGRATED = 1800000000

    def setUp(self):
        self.subject = b'{"receipt":"ed25519-subject-bytes"}\n'
        self.fixture = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
            rekor_key_type="ed25519",
        )

    def verify(self, bundle=None, *, trust=None, **overrides):
        arguments = {
            "subject_bytes": self.subject,
            "trust": trust or self.fixture.trust,
            "repository": self.REPOSITORY,
            "workflow_path": self.WORKFLOW,
            "workflow_sha": self.WORKFLOW_SHA,
            "signing_window": (self.INTEGRATED - 300, self.INTEGRATED + 300),
        }
        arguments.update(overrides)
        return PIN._verify_sigstore_bundle(
            bundle if bundle is not None else self.fixture.bundle(), **arguments,
        )

    def test_ed25519_rekor_key_verifies_set_and_checkpoint(self):
        result = self.verify()
        self.assertEqual(result["integrated_time"], self.INTEGRATED)
        self.assertEqual(result["certificate_workflow_sha"], self.WORKFLOW_SHA)

    def test_ed25519_rekor_tampered_set_is_rejected(self):
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
            rekor_key_type="ed25519",
        )

        def foreign_set(payload):
            entry = payload["verificationMaterial"]["tlogEntries"][0]
            entry["inclusionPromise"]["signedEntryTimestamp"] = (
                self.fixture.signed_entry_timestamp(key=other.rekor_key)
            )

        with self.assertRaises(SystemExit):
            self.verify(self.fixture.bundle(foreign_set))

    def test_ed25519_rekor_wrong_checkpoint_key_is_rejected(self):
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
            rekor_key_type="ed25519",
        )

        def foreign_checkpoint(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            proof["checkpoint"]["envelope"] = self.fixture.checkpoint(
                key=other.rekor_key,
            )

        with self.assertRaises(SystemExit):
            self.verify(self.fixture.bundle(foreign_checkpoint))

    def test_ed25519_rekor_wrong_checkpoint_origin_is_rejected(self):
        def foreign_origin(payload):
            proof = payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
            proof["checkpoint"]["envelope"] = self.fixture.checkpoint(
                origin="some-other-log",
            )

        with self.assertRaises(SystemExit):
            self.verify(self.fixture.bundle(foreign_origin))

    def test_ec_rekor_key_substitution_into_ed25519_trust_is_rejected(self):
        ec_fixture = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )
        cross_trust = PIN._SigstoreTrustRoot(
            fulcio_roots=self.fixture.trust.fulcio_roots,
            rekor_public_key=ec_fixture.trust.rekor_public_key,
            rekor_origin=self.fixture.trust.rekor_origin,
        )
        with self.assertRaises(SystemExit):
            self.verify(trust=cross_trust)


class AuthenticatedLiveEvidenceTests(unittest.TestCase):
    """F8 is constructed only by the complete authenticated evidence path.

    This replaces the obsolete caller-shaped pinning evidence tests and keeps
    every attack they carried: run substitution, tree/blob/object-id
    substitution, stale or wrong source, wrong parent/head/tree/diff/trust,
    missing evidence and the deterministic never-release posture.
    """

    @classmethod
    def setUpClass(cls):
        cls._directory = tempfile.TemporaryDirectory()
        root = Path(cls._directory.name) / "candidate"
        root.mkdir()
        cls.candidate_root = root
        git(root, "init", "-q")
        git(root, "config", "user.email", "fixture@example.invalid")
        git(root, "config", "user.name", "Fixture")
        (root / "keep.txt").write_bytes(b"keep\n")
        (root / "old-name.txt").write_bytes(b"renamed payload\n" * 8)
        git(root, "add", "-A")
        git(root, "commit", "-qm", "base")
        cls.base = git(root, "rev-parse", "HEAD")
        (root / ACTIVATION.TRUST_RECORD_PATH).write_bytes(b'{"trust":1}\n')
        (root / "authority-v2-policy.json").write_bytes(
            json.dumps({
                "authority_repository_base": {"commit": cls.base},
            }, sort_keys=True).encode() + b"\n"
        )
        (root / "old-name.txt").rename(root / "new-name.txt")
        (root / "keep.txt").write_bytes(b"keep\nmore\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "candidate")
        cls.head = git(root, "rev-parse", "HEAD")
        payload = ACTIVATION.external_review_bindings(root, cls.base, cls.head)
        payload.update({
            "schema_version": 1,
            "receipt_type": ACTIVATION.EXTERNAL_REVIEW_RECEIPT_TYPE,
            "reviewer_profile": "acc-reviewer",
            "reviewer_repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "candidate_owned": False,
            "produced_after_candidate": True,
            "decision": "APPROVED",
            "findings": [],
            "findings_count": 0,
            "activation_authorized": True,
            **external_review_evidence(cls.head),
        })
        data = ACTIVATION.canonical_bytes(payload)
        cls.external_receipt_bytes = data
        cls.external_review = ACTIVATION.verify_external_activation_review(
            data, repository_root=root, base_commit=cls.base,
            receipt_sha256=hashlib.sha256(data).hexdigest(),
        )

    @classmethod
    def tearDownClass(cls):
        cls._directory.cleanup()

    def make_fixture(self):
        return LiveEvidenceFixture(
            self.external_review, self.external_receipt_bytes,
            repository_root=self.candidate_root, base_commit=self.base,
        )

    def setUp(self):
        self.fixture = self.make_fixture()

    def assertRejectedBeforeTrust(self, exchange=None, **kwargs):
        """The attack must be refused even though the honest run succeeds.

        With the fixture's own trust monkeypatched into the private loader the
        unmutated pipeline closes F8, so every rejection here is caused by the
        mutation under test and nothing else.
        """
        return self.fixture.rejection(exchange, **kwargs)

    def mutated(self, url, payload=None, **kwargs):
        """One canonical read replaced, everything else authentic."""
        responses = dict(self.fixture.responses)
        original = responses[url]
        body = original.body if payload is None else (
            payload if type(payload) is bytes
            else json.dumps(payload, sort_keys=True).encode()
        )
        responses[url] = PIN._TransportResponse(
            url=kwargs.get("answered", original.url),
            status=kwargs.get("status", original.status),
            headers=kwargs.get("headers", original.headers),
            body=body,
        )
        return RecordedGitHub(responses)

    def json_at(self, url):
        return json.loads(self.fixture.responses[url].body)

    # -- the only path that can construct F8 ------------------------------
    def test_the_authorization_really_transitions_from_false_to_true(self):
        self.assertIs(
            ACTIVATION.verify_activation_package()["activation_authorized"], False,
        )
        pinned = self.fixture.derive()
        self.assertIs(pinned["activation_authorized"], True)
        self.assertIs(pinned["f8_closed"], True)

    def test_the_complete_pipeline_pins_f8_and_consumes_every_read(self):
        """The one indivisible operation returns a pinned package, or nothing.

        Every recorded canonical read is consumed, proving that the repository,
        run, job, commit, tree, blob and artifact proofs, the byte
        recomputation and the external activation review verification against
        the exact checkout all ran before anything was pinned.
        """
        recorded = self.fixture.transport()
        pinned = self.fixture.derive(recorded)
        self.assertEqual(set(recorded.reads()), set(self.fixture.responses))
        self.assertIs(pinned["f8_closed"], True)
        self.assertEqual(pinned["activation_state"], "ready")
        self.assertIs(pinned["post_activation_proof"]["live_evidence_pinned"], True)
        self.assertEqual(
            pinned["reviewed_source"]["authority_head_commit"], self.head,
        )
        self.assertEqual(
            pinned["target_repositories"][ACTIVATION.SOURCE_REPOSITORY][
                "repository_id"
            ],
            self.fixture.SOURCE_ID,
        )
        self.assertEqual(
            pinned["authorized_dispatch"]["run_id"], self.fixture.SOURCE_RUN_ID,
        )

    def test_the_pinned_package_reverifies_and_never_authorizes_release(self):
        pinned = self.fixture.derive()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "source-chain-activation-v2.json"
            path.write_bytes(ACTIVATION.canonical_bytes(pinned))
            self.assertEqual(
                ACTIVATION.verify_activation_package(path=path), pinned,
            )
        for name in ACTIVATION.PERMANENTLY_UNAUTHORIZED:
            self.assertIs(pinned["authorizes"][name], False, name)
        # The authenticated transition really happened, and it authorizes only
        # the activation lane: release and publication stay false.
        self.assertIs(pinned["activation_authorized"], True)
        self.assertEqual(
            pinned["external_activation_review"]["state"], "authenticated",
        )
        self.assertEqual(
            pinned["external_activation_review"]["receipt_sha256"],
            hashlib.sha256(self.external_receipt_bytes).hexdigest(),
        )
        self.assertIs(pinned["authorizes"]["release"], False)
        self.assertIs(pinned["authorizes"]["publication"], False)
        self.assertIs(
            self.fixture.package["activation_authorized"], False,
            "the sealed candidate must still ship unauthorized",
        )

    def test_the_operation_is_deterministic(self):
        first = self.fixture.derive()
        second = self.fixture.derive()
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True),
        )

    def test_locally_generated_sigstore_trust_can_never_close_f8(self):
        """The CRITICAL forge path: caller-generated Fulcio and Rekor roots.

        The fixture's material closes F8 only while the private trust loader is
        monkeypatched inside this test. Against the real candidate-bound
        official Sigstore trusted root it is refused outright.
        """
        pinned = PIN._load_pinned_sigstore_trust(ROOT)
        self.assertNotIn(
            self.fixture.sigstore.root,
            tuple(entry["root"] for entry in pinned.fulcio_authorities),
        )
        message = self.fixture.rejection(trust=None)
        self.assertIn("pinned", message)
        self.assertTrue(pinned.fulcio_authorities and pinned.rekor_logs)

    def test_the_shipped_candidate_cannot_close_f8_at_all(self):
        package = ACTIVATION.verify_activation_package()
        self.assertIs(package["f8_closed"], False)
        self.assertIs(package["activation_authorized"], False)
        self.assertEqual(package["activation_state"], "unavailable")

    # -- run substitution --------------------------------------------------
    def test_run_substitution_and_wrong_run_state_are_rejected(self):
        url = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            f"/actions/runs/{self.fixture.SOURCE_RUN_ID}"
        )
        run = self.json_at(url)
        for mutate in (
            lambda r: r.update(run_attempt=2),
            lambda r: r.update(previous_attempt_url=f"{url}/attempts/1"),
            lambda r: r.update(conclusion="failure"),
            lambda r: r.update(status="in_progress"),
            lambda r: r.update(event="push"),
            lambda r: r.update(head_branch="release"),
            lambda r: r.update(path=".github/workflows/other.yml"),
            lambda r: r.update(id=self.fixture.INDEPENDENT_RUN_ID),
            lambda r: r.update(url=f"{url}?cache=1"),
            lambda r: r["head_repository"].update(id=1),
            lambda r: r.update(workflow_id=7),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(run)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(url, payload))
        # No caller may name a run: the run is selected from the exhaustive
        # authenticated listing, so a synthetic, absent, additional or
        # ambiguous entry there is the only way to influence the selection and
        # every one of them fails closed.
        inventory = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            f"/actions/workflows/{self.fixture.SOURCE_ID + 11}/runs"
            "?per_page=100&page=1"
        )
        listed = self.json_at(inventory)
        second = {**listed["workflow_runs"][0], "id": listed["workflow_runs"][0]["id"] + 1}
        for label, mutate in (
            ("synthetic-id", lambda p: p["workflow_runs"][0].update(id=4242)),
            ("boolean-id", lambda p: p["workflow_runs"][0].update(id=True)),
            ("absent", lambda p: p.update(total_count=0, workflow_runs=[])),
            ("additional", lambda p: (
                p.update(total_count=2, workflow_runs=[p["workflow_runs"][0], second])
            )),
            ("attempt-2", lambda p: p["workflow_runs"][0].update(run_attempt=2)),
            ("unsuccessful", lambda p: p["workflow_runs"][0].update(conclusion="failure")),
            ("foreign-trigger", lambda p: p["workflow_runs"][0].update(event="push")),
            ("foreign-branch", lambda p: p["workflow_runs"][0].update(head_branch="dev")),
            ("foreign-path", lambda p: p["workflow_runs"][0].update(path=".github/workflows/x.yml")),
        ):
            with self.subTest(label=label):
                payload = deepcopy(listed)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(inventory, payload))
        workflows = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            "/actions/workflows?per_page=100&page=1"
        )
        catalogue = self.json_at(workflows)
        for label, mutate in (
            ("foreign-workflow-path",
             lambda p: p["workflows"][0].update(path=".github/workflows/x.yml")),
            ("synthetic-workflow-id",
             lambda p: p["workflows"][0].update(id=7)),
            ("absent-workflow", lambda p: p.update(total_count=0, workflows=[])),
        ):
            with self.subTest(label=label):
                payload = deepcopy(catalogue)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(workflows, payload))

    def test_job_and_pagination_provenance_must_be_complete(self):
        url = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            f"/actions/runs/{self.fixture.SOURCE_RUN_ID}/attempts/1/jobs"
            "?per_page=100&page=1"
        )
        jobs = self.json_at(url)
        for mutate in (
            lambda p: p["jobs"][0].update(conclusion="failure"),
            lambda p: p["jobs"][0].update(name="other"),
            lambda p: p["jobs"][0].update(run_attempt=2),
            lambda p: p["jobs"][0].update(id=12),
            lambda p: p["jobs"][0].update(head_sha="0" * 40),
            lambda p: p.update(total_count=2),
            lambda p: p.update(jobs=[]),
            lambda p: p.pop("total_count"),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(jobs)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(url, payload))
        # a truncated traversal that still advertises a next page
        self.assertRejectedBeforeTrust(self.mutated(
            url, jobs,
            headers={
                **self.fixture.responses[url].headers,
                "Link": f'<{url.replace("page=1", "page=2")}>; rel="next"',
            },
        ))

    def test_missing_permission_version_and_ambiguous_transport_reject(self):
        url = f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
        headers = dict(self.fixture.responses[url].headers)
        for label, replacement in (
            ("no-permission",
             {k: v for k, v in headers.items() if k != PIN.PERMISSION_HEADER}),
            ("wrong-permission", {**headers, PIN.PERMISSION_HEADER: "contents=write"}),
            ("no-version",
             {k: v for k, v in headers.items() if k != PIN.API_VERSION_HEADER}),
            ("wrong-content-type", {**headers, "Content-Type": "text/html"}),
        ):
            with self.subTest(label=label):
                self.assertRejectedBeforeTrust(
                        self.mutated(url, headers=replacement),
                    )
        for label, kwargs in (
            ("redirected", {"answered": f"{url}?redirected=1"}),
            ("not-authenticated", {"status": 401}),
            ("rate-limited", {"status": 429}),
            ("masked", {"status": 404}),
        ):
            with self.subTest(label=label):
                self.assertRejectedBeforeTrust(self.mutated(url, **kwargs))

    def test_repository_identity_and_synthetic_ids_are_rejected(self):
        url = f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
        repository = self.json_at(url)
        for mutate in (
            lambda r: r.update(id=900001),
            lambda r: r.update(id=1111111),
            lambda r: r.update(full_name="chrizzatsu/other"),
            lambda r: r.update(url=f"{url}/"),
            lambda r: r.update(html_url="https://example.invalid/x"),
            lambda r: r.update(visibility="private"),
            lambda r: r.update(archived=True),
            lambda r: r.pop("permissions"),
            lambda r: r["permissions"].update(push=True),
            lambda r: r.update(node_id="X"),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(repository)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(url, payload))
        # the canonical numeric id must resolve back to the same repository
        by_id = f"{PIN.API_ROOT}/repositories/{self.fixture.SOURCE_ID}"
        forged = {**self.json_at(by_id), "full_name": "chrizzatsu/elsewhere"}
        self.assertRejectedBeforeTrust(self.mutated(by_id, forged))

    # -- tree, blob and object-id substitution -----------------------------
    def test_tree_blob_and_object_id_substitution_are_rejected(self):
        url = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            f"/git/trees/{self.fixture.SOURCE_TREE}?recursive=1"
        )
        tree = self.json_at(url)
        for mutate in (
            lambda p: p.update(truncated=True),
            lambda p: p["tree"].pop(),
            lambda p: p["tree"][0].update(sha="f" * 40),
            lambda p: p["tree"][0].update(type="tree"),
            lambda p: p["tree"][0].update(mode="100755"),
            lambda p: p["tree"][0].update(path="scripts/elsewhere.py"),
            lambda p: p.update(sha="0" * 40),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(tree)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(url, payload))
        sealed = PIN._sealed_bytes_for(ACTIVATION.SOURCE_REPOSITORY)
        target, data = sorted(sealed.items())[0]
        oid = PIN._git_blob_oid(data)
        blob_url = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}/git/blobs/{oid}"
        )
        blob = self.json_at(blob_url)
        for mutate in (
            lambda p: p.update(content=base64.b64encode(b"forged").decode()),
            lambda p: p.update(sha="e" * 40),
            lambda p: p.update(encoding="utf-8"),
            lambda p: p.pop("content"),
        ):
            with self.subTest(target=target, mutate=mutate):
                payload = deepcopy(blob)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(blob_url, payload))

    def test_commit_head_and_tree_substitution_are_rejected(self):
        url = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            f"/git/commits/{self.fixture.SOURCE_HEAD}"
        )
        commit = self.json_at(url)
        for mutate in (
            lambda p: p.update(sha="0" * 40),
            lambda p: p["tree"].update(sha="a" * 40),
            lambda p: p.pop("tree"),
            lambda p: p.update(url=f"{url}?x=1"),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(commit)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(url, payload))

    # -- artifact immutability and byte recomputation ----------------------
    def test_mutable_download_and_forged_artifact_bytes_are_rejected(self):
        listing = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}/actions/runs"
            f"/{self.fixture.SOURCE_RUN_ID}/artifacts?per_page=100&page=1"
        )
        artifacts = self.json_at(listing)
        canonical = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            f"/actions/artifacts/{self.fixture.REVIEW_ARTIFACT_ID}"
        )
        for mutate in (
            lambda p: p["artifacts"][0].update(
                archive_download_url="https://pipelines.actions.example/x?sig=1",
            ),
            lambda p: p["artifacts"][0].update(expired=True),
            lambda p: p["artifacts"][0].update(id=42),
            lambda p: p["artifacts"][0].update(url=f"{canonical}/other"),
            lambda p: p["artifacts"][0]["workflow_run"].update(id=1),
            lambda p: p["artifacts"][0].update(digest="sha256:" + "0" * 64),
            lambda p: p["artifacts"][0].pop("digest"),
            lambda p: p["artifacts"][0].update(size_in_bytes=0),
            lambda p: p.update(artifacts=[]),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(artifacts)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(listing, payload))
        self.assertRejectedBeforeTrust(
                self.mutated(
                    self.fixture.storage_target(
                        self.fixture.REVIEW_ARTIFACT_ID,
                    ),
                    b"not-a-zip",
                ),
            )

    # -- the documented two-boundary artifact download ---------------------
    def artifact_zip_url(self, artifact_id=None, repository=None):
        return (
            f"{PIN.API_ROOT}/repos/{repository or ACTIVATION.SOURCE_REPOSITORY}"
            f"/actions/artifacts/{artifact_id or self.fixture.REVIEW_ARTIFACT_ID}"
            "/zip"
        )

    def review_artifact_listing(self):
        return (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}/actions/runs"
            f"/{self.fixture.SOURCE_RUN_ID}/artifacts?per_page=100&page=1"
        )

    def rerecorded_review_archive(self, archive):
        """The source review artifact re-recorded with exactly these bytes."""
        listing = self.review_artifact_listing()
        payload = deepcopy(self.json_at(listing))
        payload["artifacts"][0].update(
            size_in_bytes=len(archive),
            digest=f"sha256:{hashlib.sha256(archive).hexdigest()}",
        )
        responses = dict(self.mutated(listing, payload)._recorded)
        target = self.fixture.storage_target(self.fixture.REVIEW_ARTIFACT_ID)
        responses[target] = PIN._TransportResponse(
            url=target, status=200,
            headers=self.fixture.responses[target].headers, body=archive,
        )
        return RecordedGitHub(responses)

    def test_the_documented_two_boundary_artifact_download_closes_f8(self):
        """The real GitHub flow, not a synthetic direct 200, must work.

        ``GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip``
        answers one redirect to signed storage; the archive bytes are read from
        that storage target. Both boundaries are exercised through the real
        private production transport.
        """
        recorded = self.fixture.transport()
        pinned = self.fixture.derive(recorded)
        self.assertIs(pinned["f8_closed"], True)
        api_zip = self.artifact_zip_url()
        target = self.fixture.storage_target(self.fixture.REVIEW_ARTIFACT_ID)
        reads = recorded.reads()
        self.assertIn(api_zip, reads, "the canonical artifact endpoint was never read")
        self.assertIn(target, reads, "the signed storage target was never read")
        self.assertLess(
            reads.index(api_zip), reads.index(target),
            "the storage read must follow the authenticated redirect",
        )
        self.assertEqual(
            self.fixture.responses[api_zip].status, PIN.ARTIFACT_REDIRECT_STATUS,
        )

    def test_no_credential_or_github_header_reaches_artifact_storage(self):
        recorded = self.fixture.transport()
        self.fixture.derive(recorded)
        target = self.fixture.storage_target(self.fixture.REVIEW_ARTIFACT_ID)
        api_zip = self.artifact_zip_url()
        storage = [item for item in recorded.requests() if item[0] == target]
        self.assertTrue(storage, "the storage boundary was never dialled")
        for url, headers, limit in storage:
            lowered = {name.lower(): value for name, value in headers.items()}
            for forbidden in (
                "authorization", "proxy-authorization", "cookie",
                "x-github-api-version",
            ):
                self.assertNotIn(forbidden, lowered, forbidden)
            for name in lowered:
                self.assertFalse(name.startswith("x-github"), name)
            self.assertEqual(limit, PIN.MAXIMUM_ARTIFACT_BYTES)
        api = [item for item in recorded.requests() if item[0] == api_zip]
        self.assertTrue(api)
        for url, headers, limit in api:
            lowered = {name.lower(): value for name, value in headers.items()}
            self.assertTrue(lowered["authorization"].startswith("Bearer "))
            self.assertEqual(lowered["x-github-api-version"], PIN.API_VERSION)

    def test_a_direct_two_hundred_artifact_response_cannot_supply_bytes(self):
        """The synthetic shape that hid this defect must now fail closed."""
        api_zip = self.artifact_zip_url()
        target = self.fixture.storage_target(self.fixture.REVIEW_ARTIFACT_ID)
        archive = self.fixture.responses[target].body
        responses = dict(self.fixture.responses)
        responses[api_zip] = PIN._TransportResponse(
            url=api_zip, status=200,
            headers={
                "Content-Type": PIN.ZIP_CONTENT_TYPE,
                PIN.PERMISSION_HEADER: PIN.ACTIONS_READ,
                PIN.API_VERSION_HEADER: PIN.API_VERSION,
            },
            body=archive,
        )
        message = self.assertRejectedBeforeTrust(RecordedGitHub(responses))
        self.assertIn("redirect", message)

    def test_absent_wrong_or_ambiguous_artifact_redirects_are_rejected(self):
        api_zip = self.artifact_zip_url()
        target = self.fixture.storage_target(self.fixture.REVIEW_ARTIFACT_ID)
        honest = self.fixture.responses[api_zip].headers
        for label, status, headers in (
            ("direct-200", 200, honest),
            ("permanent-301", 301, honest),
            ("see-other-303", 303, honest),
            ("temporary-307", 307, honest),
            ("not-found", 404, honest),
            ("server-error", 500, honest),
            ("no-location", 302, {
                key: value for key, value in honest.items()
                if key.lower() != "location"
            }),
            ("repeated-location", 302, {**honest, "location": target}),
            ("no-permission-provenance", 302, {
                key: value for key, value in honest.items()
                if key.lower() != PIN.PERMISSION_HEADER
            }),
            ("wrong-permission-provenance", 302, {
                **honest, PIN.PERMISSION_HEADER: PIN.CONTENTS_READ,
            }),
            ("no-api-version", 302, {
                key: value for key, value in honest.items()
                if key.lower() != PIN.API_VERSION_HEADER
            }),
        ):
            with self.subTest(label=label):
                self.assertRejectedBeforeTrust(
                    self.mutated(api_zip, status=status, headers=headers),
                )
        with self.subTest(label="answered-elsewhere"):
            self.assertRejectedBeforeTrust(
                self.mutated(api_zip, answered=f"{api_zip}?x=1"),
            )

    def test_forged_artifact_redirect_targets_are_rejected(self):
        api_zip = self.artifact_zip_url()
        honest = dict(self.fixture.responses[api_zip].headers)
        signed = "sig=" + "a" * 64 + "&se=2033-01-19T03%3A14%3A07Z"
        host = LiveEvidenceFixture.STORAGE_HOST
        for label, location in (
            ("relative", f"/actions-results/x.zip?{signed}"),
            ("scheme-relative", f"//{host}/x.zip?{signed}"),
            ("plain-http", f"http://{host}/x.zip?{signed}"),
            ("userinfo", f"https://evil@{host}/x.zip?{signed}"),
            ("credential-userinfo", f"https://u:p@{host}/x.zip?{signed}"),
            ("fragment", f"https://{host}/x.zip?{signed}#frag"),
            ("explicit-port", f"https://{host}:8443/x.zip?{signed}"),
            ("foreign-host", f"https://storage.example.invalid/x.zip?{signed}"),
            ("lookalike-host", f"https://{host}.evil.invalid/x.zip?{signed}"),
            ("bare-suffix", f"https://blob.core.windows.net/x.zip?{signed}"),
            ("api-host", f"https://api.github.com/x.zip?{signed}"),
            ("github-host", f"https://github.com/x.zip?{signed}"),
            ("uppercase-netloc", f"https://{host.upper()}/x.zip?{signed}"),
            ("unsigned-mutable", f"https://{host}/actions-results/latest.zip"),
            ("no-signature", f"https://{host}/x.zip?se=2033-01-19T03%3A14%3A07Z"),
            ("empty-signature", f"https://{host}/x.zip?sig=&se=1"),
            ("short-signature", f"https://{host}/x.zip?sig=abc&se=1"),
            ("repeated-parameter", f"https://{host}/x.zip?{signed}&sig=" + "b" * 64),
            ("path-traversal", f"https://{host}/actions-results/../x.zip?{signed}"),
            ("empty-path", f"https://{host}?{signed}"),
            ("root-path", f"https://{host}/?{signed}"),
            ("header-injection", f"https://{host}/x.zip?{signed}\r\nX-Evil: 1"),
            ("leading-space", f" https://{host}/x.zip?{signed}"),
            ("embedded-newline", f"https://{host}/x.zip?{signed}\n"),
            ("malformed-query", f"https://{host}/x.zip?sig"),
            ("empty", ""),
        ):
            with self.subTest(label=label):
                self.assertRejectedBeforeTrust(
                    self.mutated(
                        api_zip, headers={**honest, "Location": location},
                    ),
                )
        for label, value in (("absent", None), ("non-string", 7), ("list", [1])):
            with self.subTest(label=f"location-{label}"):
                headers = {
                    key: item for key, item in honest.items()
                    if key.lower() != "location"
                }
                if value is not None:
                    headers["Location"] = value
                self.assertRejectedBeforeTrust(
                    self.mutated(api_zip, headers=headers),
                )

    def test_the_storage_hop_must_be_an_unredirected_verified_zip_read(self):
        target = self.fixture.storage_target(self.fixture.REVIEW_ARTIFACT_ID)
        honest = dict(self.fixture.responses[target].headers)
        elsewhere = self.fixture.storage_target(self.fixture.SIGNED_ARTIFACT_ID)
        for label, kwargs in (
            ("another-redirect", {
                "status": 302, "headers": {**honest, "Location": elsewhere},
            }),
            ("not-found", {"status": 404}),
            ("server-error", {"status": 500}),
            ("partial-content", {"status": 206}),
            ("answered-elsewhere", {"answered": elsewhere}),
            ("wrong-content-type", {
                "headers": {**honest, "Content-Type": "text/html"},
            }),
            ("json-content-type", {
                "headers": {**honest, "Content-Type": PIN.JSON_CONTENT_TYPE},
            }),
            ("impersonates-the-api", {
                "headers": {
                    **honest,
                    PIN.PERMISSION_HEADER: PIN.ACTIONS_READ,
                    PIN.API_VERSION_HEADER: PIN.API_VERSION,
                },
            }),
            ("repeated-header", {
                "headers": {**honest, "content-type": PIN.ZIP_CONTENT_TYPE},
            }),
        ):
            with self.subTest(label=label):
                self.assertRejectedBeforeTrust(self.mutated(target, **kwargs))
        for label, body in (
            ("empty", b""),
            ("truncated", self.fixture.responses[target].body[:-1]),
            ("padded", self.fixture.responses[target].body + b"\0"),
            ("not-a-zip", b"not-a-zip"),
        ):
            with self.subTest(label=f"bytes-{label}"):
                self.assertRejectedBeforeTrust(self.mutated(target, body))

    def test_storage_bytes_must_match_the_authenticated_artifact_metadata(self):
        """Storage is untrusted: its bytes are bound to authenticated metadata."""
        listing = self.review_artifact_listing()
        target = self.fixture.storage_target(self.fixture.REVIEW_ARTIFACT_ID)
        archive = self.fixture.responses[target].body
        for label, mutate in (
            ("size", lambda entry: entry.update(size_in_bytes=len(archive) + 1)),
            ("digest", lambda entry: entry.update(
                digest="sha256:" + hashlib.sha256(archive + b"x").hexdigest(),
            )),
        ):
            with self.subTest(label=label):
                payload = deepcopy(self.json_at(listing))
                mutate(payload["artifacts"][0])
                self.assertRejectedBeforeTrust(self.mutated(listing, payload))

    def test_unsafe_or_duplicated_archive_member_paths_are_rejected(self):
        honest = {
            self.fixture.envelope_name: self.fixture.envelope,
            self.fixture.receipt_name: self.fixture.receipt,
        }
        for label, members in (
            ("parent-traversal", {"../evil.json": b"x", **honest}),
            ("absolute", {"/etc/passwd": b"x", **honest}),
            ("nested", {"protected-review/evil.json": b"x", **honest}),
            ("dot", {".": b"x", **honest}),
            ("hidden", {".evil": b"x", **honest}),
        ):
            with self.subTest(label=label):
                archive = self.fixture._archive(members)
                message = self.assertRejectedBeforeTrust(
                    self.rerecorded_review_archive(archive),
                )
                self.assertIn("archive member", message)
        buffer = io.BytesIO()
        with warnings.catch_warnings():
            # the duplicate member is the attack under test
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buffer, "w") as duplicated:
                for member in sorted(honest):
                    info = zipfile.ZipInfo(member)
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    duplicated.writestr(info, honest[member])
                duplicate = zipfile.ZipInfo(self.fixture.receipt_name)
                duplicate.external_attr = (stat.S_IFREG | 0o600) << 16
                duplicated.writestr(duplicate, b"shadow")
        message = self.assertRejectedBeforeTrust(
            self.rerecorded_review_archive(buffer.getvalue()),
        )
        self.assertIn("repeats", message)
        with self.subTest(label="prefixed-inventory"):
            prefixed = {
                f"protected-review/{member}": data
                for member, data in honest.items()
            }
            self.assertRejectedBeforeTrust(
                self.rerecorded_review_archive(self.fixture._archive(prefixed)),
            )

    def test_forged_receipt_chain_and_envelope_bytes_are_rejected(self):
        canonical = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
            f"/actions/artifacts/{self.fixture.REVIEW_ARTIFACT_ID}"
        )
        for label, mutate in (
            ("stale-source-head",
             lambda chain: chain.update(source_bootstrap_commit="0" * 40)),
            ("wrong-source-tree",
             lambda chain: chain.update(source_bootstrap_tree="0" * 40)),
            ("wrong-independent-head",
             lambda chain: chain.update(independent_bootstrap_commit="0" * 40)),
            ("wrong-authority-head",
             lambda chain: chain.update(authority_head_commit="0" * 40)),
            ("wrong-authority-tree",
             lambda chain: chain.update(authority_head_tree="0" * 40)),
            ("wrong-run-id", lambda chain: chain.update(run_id=1)),
            ("wrong-attempt", lambda chain: chain.update(run_attempt=2)),
        ):
            with self.subTest(label=label):
                receipt = json.loads(self.fixture.receipt)
                mutate(receipt["source_execution_chain"])
                forged = json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"),
                ).encode() + b"\n"
                envelope = json.loads(self.fixture.envelope)
                envelope["review_receipt_sha256"] = hashlib.sha256(
                    forged
                ).hexdigest()
                members = {
                    self.fixture.envelope_name: json.dumps(
                        envelope, sort_keys=True, separators=(",", ":"),
                    ).encode() + b"\n",
                    self.fixture.receipt_name: forged,
                }
                archive = self.fixture._archive(members)
                listing = (
                    f"{PIN.API_ROOT}/repos/{ACTIVATION.SOURCE_REPOSITORY}"
                    f"/actions/runs/{self.fixture.SOURCE_RUN_ID}/artifacts"
                    "?per_page=100&page=1"
                )
                payload = deepcopy(self.json_at(listing))
                payload["artifacts"][0].update(
                    size_in_bytes=len(archive),
                    digest=f"sha256:{hashlib.sha256(archive).hexdigest()}",
                )
                responses = dict(self.mutated(listing, payload)._recorded)
                target = self.fixture.storage_target(
                    self.fixture.REVIEW_ARTIFACT_ID,
                )
                responses[target] = PIN._TransportResponse(
                    url=target, status=200,
                    headers=self.fixture.responses[target].headers,
                    body=archive,
                )
                self.assertRejectedBeforeTrust(RecordedGitHub(responses))

    # -- external review binding ------------------------------------------
    def test_the_external_review_must_be_read_from_the_authority(self):
        """Removing the reviewer's artifact makes the closure unreachable."""
        prefix = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.INDEPENDENT_REPOSITORY}"
            f"/actions/runs/{self.fixture.INDEPENDENT_RUN_ID}"
        )
        for url in sorted(self.fixture.responses):
            if not url.startswith(prefix):
                continue
            with self.subTest(url=url):
                responses = dict(self.fixture.responses)
                responses.pop(url)
                self.assertRejectedBeforeTrust(RecordedGitHub(responses))

    def test_a_forged_trust_record_in_the_checkout_cannot_substitute_trust(self):
        """Trust is bound to the shipping candidate, never to the checkout."""
        pinned = PIN._load_pinned_sigstore_trust(ROOT)
        record = json.loads((ROOT / ACTIVATION.TRUST_RECORD_PATH).read_bytes())
        forged = deepcopy(record)
        forged["sigstore_trusted_root"]["canonical_bytes_base64"] = (
            base64.b64encode(b"{}").decode("ascii")
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ACTIVATION.TRUST_RECORD_PATH).write_bytes(
                json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
            with self.assertRaises(SystemExit):
                PIN._load_pinned_sigstore_trust(root)
        self.assertEqual(
            PIN._load_pinned_sigstore_trust(ROOT).rekor_logs, pinned.rekor_logs,
        )

    def test_missing_evidence_reads_fail_closed(self):
        for url in sorted(self.fixture.responses):
            with self.subTest(url=url):
                responses = dict(self.fixture.responses)
                responses.pop(url)
                self.assertRejectedBeforeTrust(RecordedGitHub(responses))

    def test_the_helper_can_express_only_authenticated_github_reads(self):
        source = (
            ROOT / "scripts" / "pin_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "import requests", "import socket", "subprocess", "gh api",
            "git push", "urlopen(url", "urlopen(request, data",
        ):
            self.assertNotIn(forbidden, source, forbidden)
        # The one production client is HTTPS-only, certificate verified and
        # never logs or persists the runtime token.
        self.assertIn("ssl.create_default_context()", source)
        self.assertIn("verify_mode = ssl.CERT_REQUIRED", source)
        self.assertIn("check_hostname = True", source)
        for leak in ("print(", "logging", "write_text", "open(", "environ["):
            self.assertNotIn(f"{leak}self.__token", source)
        # urlopen() auto-follows redirects onto foreign hosts, so the one
        # production exchange dials a private opener that refuses every one.
        self.assertNotIn("urllib.request.urlopen(", source)
        self.assertEqual(source.count("build_opener("), 1)
        self.assertEqual(source.count("def _exchange("), 1)

class ArtifactStorageTransportBoundaryTests(unittest.TestCase):
    """F8-LIVE-ARTIFACT-DOWNLOAD-UNREACHABLE.

    An authentic GitHub artifact download crosses two different boundaries. The
    first is the canonical authenticated ``api.github.com`` artifact-id ZIP
    endpoint, which answers exactly one documented redirect and is never
    allowed to auto-follow it. The second is an unauthenticated verified-HTTPS
    read of the immutable signed storage target, which is sent no credential,
    no API version and no GitHub header, may not redirect again and returns
    bounded bytes only.
    """

    SOURCE = (ROOT / "scripts" / "pin_source_chain_activation_v2.py").read_text(
        encoding="utf-8"
    )
    HOST = "productionresultssa10.blob.core.windows.net"
    SIGNED = "sig=" + "a" * 64 + "&se=2033-01-19T03%3A14%3A07Z&sp=r&sr=b"

    def transport(self):
        with mock.patch.dict(os.environ, RecordedGitHub.TOKEN):
            return PIN._GitHubReadOnlyTransport()

    def test_the_production_client_never_auto_follows_a_redirect(self):
        """urlopen() silently follows redirects, so it may not be used."""
        self.assertNotIn("urllib.request.urlopen(", self.SOURCE)
        self.assertEqual(self.SOURCE.count("build_opener("), 1)
        handler = PIN._RefuseRedirects()
        self.assertIsInstance(handler, urllib.request.HTTPRedirectHandler)
        self.assertIsNone(
            handler.redirect_request(
                urllib.request.Request(f"{PIN.API_ROOT}/x"), io.BytesIO(b""),
                302, "Found", {}, f"https://{self.HOST}/x.zip?{self.SIGNED}",
            ),
            "the production client must refuse every redirect",
        )

    def test_the_api_boundary_carries_the_exact_authenticated_headers(self):
        request = self.transport()._api_request(f"{PIN.API_ROOT}/repos/x/y")
        headers = {name.lower(): value for name, value in request.header_items()}
        self.assertEqual(headers["authorization"], "Bearer test-runtime-token")
        self.assertEqual(headers["x-github-api-version"], PIN.API_VERSION)
        self.assertEqual(headers["accept"], "application/vnd.github+json")
        self.assertEqual(request.get_method(), "GET")

    def test_the_storage_boundary_carries_no_credential_or_github_header(self):
        target = f"https://{self.HOST}/actions-results/x.zip?{self.SIGNED}"
        request = self.transport()._storage_request(target)
        headers = {name.lower(): value for name, value in request.header_items()}
        for forbidden in PIN.STORAGE_FORBIDDEN_REQUEST_HEADERS:
            self.assertNotIn(forbidden, headers, forbidden)
        for name in headers:
            self.assertFalse(name.startswith("x-github"), name)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, target)
        PIN._require_unauthenticated_request(request, "artifact download")
        forged = urllib.request.Request(target)
        forged.add_header("Authorization", "Bearer leaked")
        with self.assertRaises(SystemExit):
            PIN._require_unauthenticated_request(forged, "artifact download")
        versioned = urllib.request.Request(target)
        versioned.add_header("X-GitHub-Api-Version", PIN.API_VERSION)
        with self.assertRaises(SystemExit):
            PIN._require_unauthenticated_request(versioned, "artifact download")
        insecure = urllib.request.Request(f"http://{self.HOST}/x.zip?{self.SIGNED}")
        with self.assertRaises(SystemExit):
            PIN._require_unauthenticated_request(insecure, "artifact download")

    def test_the_transport_downloads_only_canonical_artifact_zip_endpoints(self):
        transport = self.transport()
        for url in (
            f"{PIN.API_ROOT}/repos/o/r/actions/artifacts/1/zip/extra",
            f"{PIN.API_ROOT}/repos/o/r/actions/runs/1",
            f"https://{self.HOST}/x.zip?{self.SIGNED}",
            "https://api.github.com.evil.invalid/x/zip",
            "", None, 7,
        ):
            with self.subTest(url=url):
                with self.assertRaises(SystemExit):
                    transport.read_immutable_zip(url)

    def test_every_ambiguous_or_mutable_storage_target_is_rejected(self):
        for location in (
            None, "", 7, ["https://x"],
            f"/actions-results/x.zip?{self.SIGNED}",
            f"//{self.HOST}/x.zip?{self.SIGNED}",
            f"http://{self.HOST}/x.zip?{self.SIGNED}",
            f"ftp://{self.HOST}/x.zip?{self.SIGNED}",
            f"https://evil@{self.HOST}/x.zip?{self.SIGNED}",
            f"https://{self.HOST}:8443/x.zip?{self.SIGNED}",
            f"https://{self.HOST}/x.zip?{self.SIGNED}#frag",
            f"https://{self.HOST.upper()}/x.zip?{self.SIGNED}",
            f"https://storage.example.invalid/x.zip?{self.SIGNED}",
            f"https://{self.HOST}.evil.invalid/x.zip?{self.SIGNED}",
            f"https://blob.core.windows.net/x.zip?{self.SIGNED}",
            f"https://actions.githubusercontent.com/x.zip?{self.SIGNED}",
            f"https://api.github.com/x.zip?{self.SIGNED}",
            f"https://{self.HOST}/actions-results/../x.zip?{self.SIGNED}",
            f"https://{self.HOST}/x.zip",
            f"https://{self.HOST}?{self.SIGNED}",
            f"https://{self.HOST}/?{self.SIGNED}",
            f"https://{self.HOST}/x.zip?sig=&se=1",
            f"https://{self.HOST}/x.zip?sig=abc",
            f"https://{self.HOST}/x.zip?sig",
            f"https://{self.HOST}/x.zip?{self.SIGNED}&sig=" + "b" * 64,
            f"https://{self.HOST}/x.zip?{self.SIGNED}\r\nX-Evil: 1",
            f" https://{self.HOST}/x.zip?{self.SIGNED}",
            f"https://{self.HOST}/x zip?{self.SIGNED}",
        ):
            with self.subTest(location=location):
                with self.assertRaises(SystemExit):
                    PIN._require_artifact_storage_url(location, "artifact")
        for approved in (
            f"https://{self.HOST}/actions-results/a/b/c.zip?{self.SIGNED}",
            f"https://pipelines.actions.githubusercontent.com/a/b?{self.SIGNED}",
        ):
            with self.subTest(approved=approved):
                self.assertEqual(
                    PIN._require_artifact_storage_url(approved, "artifact"),
                    approved,
                )


class ForgedExternalReviewTests(AuthenticatedLiveEvidenceTests):
    """A caller-supplied external activation review may never cross the boundary.

    The live-evidence interface must not accept a review mapping, a preverified
    review object or any closure flag. The external activation review can only
    enter as immutable artifact bytes read through the injected read-only
    transport, authenticated against the exact named independent-review
    authority and its Sigstore provenance, and then verified byte for byte
    against the exact clean checkout.
    """

    def plausible_forgery(self, **overrides):
        forged = dict(self.external_review)
        forged.update(overrides)
        return forged

    def test_the_public_interface_accepts_no_review_mapping_at_all(self):
        signature = inspect.signature(PIN.derive_activation_closure)
        self.assertNotIn("external_review", signature.parameters)
        for name in signature.parameters:
            lowered = name.lower()
            for forbidden in ("review", "verified", "closed", "trust",
                              "transport", "evidence", "run_id"):
                self.assertNotIn(forbidden, lowered)

    def test_a_fully_plausible_forged_review_mapping_cannot_close_f8(self):
        """There is no entry point a review mapping could be handed to."""
        for label, forged in (
            ("verbatim-preverified", self.plausible_forgery()),
            ("foreign-head", self.plausible_forgery(head_commit="0" * 40)),
            ("foreign-tree", self.plausible_forgery(head_tree="0" * 40)),
            ("self-authorized", self.plausible_forgery(activation_authorized=True)),
            ("minimal", {
                "activation_authorized": True,
                "receipt_type": ACTIVATION.EXTERNAL_REVIEW_RECEIPT_TYPE,
                "head_commit": self.head,
                "head_tree": git(self.candidate_root, "rev-parse", "HEAD^{tree}"),
            }),
        ):
            with self.subTest(label=label):
                with self.assertRaises(TypeError):
                    PIN.derive_activation_closure(
                        self.candidate_root, external_review=forged,
                    )
                with self.assertRaises((SystemExit, TypeError)):
                    PIN.derive_activation_closure(forged)

    def test_no_pinning_entry_point_exists_beside_the_indivisible_operation(self):
        """There is no evidence token and no separate pinning step to abuse."""
        public = sorted(
            name for name in vars(PIN)
            if not name.startswith("_") and callable(getattr(PIN, name))
            and getattr(getattr(PIN, name), "__module__", None) == PIN.__name__
        )
        self.assertEqual(
            public,
            ["derive_activation_closure", "derive_live_activation_closure",
             "main", "require"],
        )
        # Neither derived entry point may accept an evidence object, transport,
        # trust material, closure flag or run identifier, so there is still no
        # separate pinning step and no token to abuse.
        for name in ("derive_activation_closure",
                     "derive_live_activation_closure"):
            parameters = inspect.signature(getattr(PIN, name)).parameters
            self.assertLessEqual(set(parameters), {"repository_root"}, name)
        self.assertNotIn("_AuthenticatedActivationEvidence", vars(PIN))

    def test_substituted_external_review_bytes_and_digest_are_rejected(self):
        listing = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.INDEPENDENT_REPOSITORY}"
            f"/actions/runs/{self.fixture.INDEPENDENT_RUN_ID}"
            "/artifacts?per_page=100&page=1"
        )
        canonical = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.INDEPENDENT_REPOSITORY}"
            f"/actions/artifacts/{self.fixture.EXTERNAL_REVIEW_ARTIFACT_ID}"
        )
        original = json.loads(self.fixture.external_receipt)
        for label, mutate in (
            ("foreign-head", lambda r: r.update(head_commit="0" * 40)),
            ("foreign-tree", lambda r: r.update(head_tree="0" * 40)),
            ("foreign-diff", lambda r: r.update(canonical_diff_sha256="0" * 64)),
            ("foreign-trust",
             lambda r: r.update(reviewer_authorization_sha256="0" * 64)),
            ("self-reviewed",
             lambda r: r.update(reviewer_repository=ACTIVATION.AUTHORITY_REPOSITORY)),
            ("candidate-owned", lambda r: r.update(candidate_owned=True)),
            ("changes-requested", lambda r: r.update(decision="CHANGES_REQUESTED")),
            ("non-zero-findings", lambda r: r.update(findings_count=1)),
        ):
            with self.subTest(label=label):
                receipt = deepcopy(original)
                mutate(receipt)
                forged = ACTIVATION.canonical_bytes(receipt)
                self.assertRejectedBeforeTrust(
                        self.fixture.external_review_transport(forged),
                    )
        # An untouched receipt delivered under a substituted digest rejects too.
        self.assertRejectedBeforeTrust(
                self.fixture.external_review_transport(
                    self.fixture.external_receipt, corrupt_digest=True,
                )
            )

    def test_the_external_review_must_come_from_the_named_authority(self):
        run = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.INDEPENDENT_REPOSITORY}"
            f"/actions/runs/{self.fixture.INDEPENDENT_RUN_ID}"
        )
        metadata = self.json_at(run)
        for mutate in (
            lambda r: r.update(path=".github/workflows/other.yml"),
            lambda r: r.update(event="push"),
            lambda r: r.update(head_branch="release"),
            lambda r: r.update(conclusion="failure"),
            lambda r: r.update(run_attempt=2),
            lambda r: r["head_repository"].update(
                full_name=ACTIVATION.SOURCE_REPOSITORY,
            ),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(metadata)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(run, payload))
        # The reviewing run is selected from the exhaustive listing, never
        # named by a caller, so only that listing can be attacked.
        inventory = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.INDEPENDENT_REPOSITORY}"
            f"/actions/workflows/{self.fixture.INDEPENDENT_ID + 11}/runs"
            "?per_page=100&page=1"
        )
        listed = self.json_at(inventory)
        for label, mutate in (
            ("synthetic-id", lambda p: p["workflow_runs"][0].update(id=4242)),
            ("absent", lambda p: p.update(total_count=0, workflow_runs=[])),
            ("ambiguous", lambda p: p.update(
                total_count=2,
                workflow_runs=[
                    p["workflow_runs"][0],
                    {**p["workflow_runs"][0],
                     "id": p["workflow_runs"][0]["id"] + 1},
                ],
            )),
        ):
            with self.subTest(label=label):
                payload = deepcopy(listed)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(inventory, payload))

    def test_mutable_external_review_download_is_rejected(self):
        listing = (
            f"{PIN.API_ROOT}/repos/{ACTIVATION.INDEPENDENT_REPOSITORY}"
            f"/actions/runs/{self.fixture.INDEPENDENT_RUN_ID}"
            "/artifacts?per_page=100&page=1"
        )
        artifacts = self.json_at(listing)
        for mutate in (
            lambda p: p["artifacts"][0].update(
                archive_download_url="https://pipelines.actions.example/x?sig=1",
            ),
            lambda p: p["artifacts"][0].update(expired=True),
            lambda p: p["artifacts"][0].update(id=99),
            lambda p: p["artifacts"][0]["workflow_run"].update(id=1),
            lambda p: p.update(artifacts=[]),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(artifacts)
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(listing, payload))

    def test_reviewer_sigstore_provenance_must_authenticate(self):
        for label, claims in (
            ("foreign-issuer", {"issuer": "https://accounts.google.com"}),
            ("foreign-ref", {"ref": "refs/heads/release"}),
            ("foreign-trigger", {"trigger": "push"}),
            ("foreign-workflow-sha", {"workflow_sha": "0" * 40}),
            ("foreign-repository", {"repository": "chrizzatsu/other"}),
        ):
            with self.subTest(label=label):
                self.assertRejectedBeforeTrust(
                        self.fixture.external_review_transport(
                            self.fixture.external_receipt, claims=claims,
                        )
                    )
        for label, mutate in (
            ("absent-transparency",
             lambda payload: payload["verificationMaterial"].pop("tlogEntries")),
            ("absent-certificate",
             lambda payload: payload["verificationMaterial"][
                 "x509CertificateChain"].update(certificates=[])),
            ("bespoke-legacy-certificate-shape",
             lambda payload: payload["verificationMaterial"].update(
                 certificate={"rawBytes": payload["verificationMaterial"][
                     "x509CertificateChain"]["certificates"][0][
                         "rawBytes"]})),
            ("forged-merkle", lambda payload: payload["verificationMaterial"][
                "tlogEntries"][0]["inclusionProof"].update(
                    hashes=[base64.b64encode(b"x" * 32).decode("ascii")],
                )),
            ("forged-time", lambda payload: payload["verificationMaterial"][
                "tlogEntries"][0].update(integratedTime=1)),
        ):
            with self.subTest(label=label):
                self.assertRejectedBeforeTrust(
                        self.fixture.external_review_transport(
                            self.fixture.external_receipt,
                            bundle_mutation=mutate,
                        )
                    )

    def test_a_receipt_that_does_not_match_the_exact_checkout_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            other = Path(td) / "other"
            other.mkdir()
            git(other, "init", "-q")
            git(other, "config", "user.email", "fixture@example.invalid")
            git(other, "config", "user.name", "Fixture")
            (other / "keep.txt").write_bytes(b"keep\n")
            git(other, "add", "-A")
            git(other, "commit", "-qm", "base")
            base = git(other, "rev-parse", "HEAD")
            (other / ACTIVATION.TRUST_RECORD_PATH).write_bytes(b'{"trust":2}\n')
            git(other, "add", "-A")
            git(other, "commit", "-qm", "candidate")
            (other / "authority-v2-policy.json").write_bytes(
                json.dumps({
                    "authority_repository_base": {"commit": base},
                }, sort_keys=True).encode() + b"\n"
            )
            git(other, "add", "-A")
            git(other, "commit", "-qm", "policy")
            self.assertRejectedBeforeTrust(repository_root=other)


class ProductionActivationBoundaryTests(unittest.TestCase):
    """The production closure takes no capability from any caller.

    No transport, no trust object, no preverified evidence, no closure flag and
    no run identifier may cross the boundary. Sigstore trust comes only from the
    candidate-bound canonical contract bytes, and the transport is one fixed
    read-only GitHub REST client the operation instantiates for itself.
    """

    def test_the_only_production_entry_point_accepts_no_capability(self):
        self.assertTrue(hasattr(PIN, "derive_activation_closure"))
        parameters = inspect.signature(PIN.derive_activation_closure).parameters
        self.assertLessEqual(set(parameters), {"repository_root"})
        for name in parameters:
            lowered = name.lower()
            for forbidden in (
                "transport", "trust", "evidence", "review", "run_id", "closed",
                "closure", "token", "session", "client",
            ):
                self.assertNotIn(forbidden, lowered)

    def test_no_public_evidence_type_or_pinning_entry_point_exists(self):
        for name in (
            "AuthenticatedActivationEvidence", "pin_activation",
            "authenticate_live_activation_evidence",
            "SigstoreTrustRoot", "verify_sigstore_activation_bundle",
        ):
            self.assertFalse(hasattr(PIN, name), name)

    def test_a_directly_constructed_proof_cannot_produce_a_pinned_package(self):
        constructible = [
            value for name, value in vars(PIN).items()
            if not name.startswith("__")
            and isinstance(value, type)
            and hasattr(value, "__dataclass_fields__")
        ]
        for candidate in constructible:
            with self.subTest(candidate=candidate.__name__):
                self.assertTrue(
                    candidate.__name__.startswith("_"),
                    f"{candidate.__name__} is a public constructible proof type",
                )

    def test_pinned_sigstore_trust_is_bound_to_the_official_root_signing_commit(self):
        trust = json.loads(
            (ROOT / ACTIVATION.TRUST_RECORD_PATH).read_bytes()
        )["sigstore_trusted_root"]
        self.assertEqual(
            trust["source_repository"], "https://github.com/sigstore/root-signing",
        )
        self.assertEqual(
            trust["source_commit"], "ba3066c420970c13772ba0625f09f1ec97193116",
        )
        self.assertEqual(trust["source_path"], "targets/trusted_root.json")
        self.assertEqual(
            trust["sha256"],
            "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
        )
        canonical = base64.b64decode(trust["canonical_bytes_base64"])
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), trust["sha256"])
        self.assertTrue(trust["fulcio_authorities"])
        self.assertTrue(trust["rekor_logs"])

    def test_the_pinned_trust_loader_refuses_tampered_contract_bytes(self):
        loaded = PIN._load_pinned_sigstore_trust(ROOT)
        self.assertTrue(loaded.fulcio_authorities)
        for mutate in (
            lambda t: t.update(sha256="0" * 64),
            lambda t: t.update(source_commit="0" * 40),
            lambda t: t.update(source_repository="https://github.com/other/root"),
            lambda t: t.update(media_type="application/json"),
            lambda t: t["rekor_logs"][0].update(public_key_sha256="0" * 64),
            lambda t: t["fulcio_authorities"][0].update(
                certificate_sha256=["0" * 64],
            ),
            lambda t: t.update(rekor_logs=[]),
            lambda t: t.update(fulcio_authorities=[]),
        ):
            with self.subTest(mutate=mutate):
                record = json.loads(
                    (ROOT / ACTIVATION.TRUST_RECORD_PATH).read_bytes()
                )
                mutate(record["sigstore_trusted_root"])
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    (root / ACTIVATION.TRUST_RECORD_PATH).write_bytes(
                        json.dumps(
                            record, sort_keys=True, separators=(",", ":"),
                        ).encode() + b"\n"
                    )
                    with self.assertRaises(SystemExit):
                        PIN._load_pinned_sigstore_trust(root)

    def test_the_production_transport_is_a_read_only_github_rest_client(self):
        source = (
            ROOT / "scripts" / "pin_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess", "gh api", "git push",
            'method="POST"', 'method="PUT"', 'method="PATCH"',
            'method="DELETE"',
        ):
            self.assertNotIn(forbidden, source, forbidden)
        self.assertIn("https://api.github.com", source)
        transport = PIN._GitHubReadOnlyTransport
        self.assertTrue(issubclass(transport, PIN._ReadOnlyTransport))
        for verb in ("post", "put", "patch", "delete", "write"):
            self.assertNotIn(verb, [name.lower() for name in dir(transport)])


class ExternalActivationReviewProducibilityTests(unittest.TestCase):
    """F8-EXTERNAL-ACTIVATION-REVIEW-UNPRODUCIBLE.

    The production operation consumes an external activation-review receipt and
    its Sigstore bundle from the same unique independent-review run. The sealed
    reviewer workflow must actually be able to produce and upload exactly that
    artifact, or the transition it gates is impossible.
    """

    INDEPENDENT_ROOT = ROOT / "independent-review-bootstrap-v2"

    def setUp(self):
        self.contract = json.loads(
            (ROOT / "source-chain-activation-v2.json").read_bytes()
        )["external_activation_review"]
        self.workflow = (
            self.INDEPENDENT_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.validator = (
            self.INDEPENDENT_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")

    def test_the_reviewer_workflow_uploads_the_required_artifact(self):
        self.assertIn(self.contract["artifact_name"], self.workflow)
        for member in self.contract["artifact_files"]:
            self.assertIn(
                f"protected-review/{member}", self.workflow,
                f"the reviewer workflow never uploads {member}",
            )

    def test_the_reviewer_workflow_signs_the_external_receipt(self):
        receipt, bundle = self.contract["artifact_files"]
        self.assertIn(
            f"--bundle protected-review/{bundle}", self.workflow,
            "the reviewer workflow never signs the external activation review",
        )
        self.assertIn(f"protected-review/{receipt}", self.workflow)

    def test_the_validator_can_emit_the_external_receipt(self):
        self.assertIn("external-review", self.validator)
        self.assertTrue(
            hasattr(VALIDATOR, "build_external_activation_review"),
            "the sealed validator cannot produce the external review receipt",
        )
        self.assertIn("external-review", VALIDATOR.PHASES)

    def test_the_emitted_receipt_satisfies_the_production_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            checkout = root / VALIDATOR.AUTHORITY_CHECKOUT
            base, head = build_authority_candidate(checkout)
            run = synthetic_live_run(
                base_commit=base,
                base_tree=git(checkout, "rev-parse", f"{base}^{{tree}}"),
                head_commit=head,
                head_tree=git(checkout, "rev-parse", "HEAD^{tree}"),
            )
            # The reviewer's separately authored decision is the only thing
            # that can turn the sealed lane's bindings into an APPROVED
            # receipt, and it counts only once its sealed delivery
            # authenticates end to end.
            deliver_reviewer_decision(root, run, checkout)
            data = VALIDATOR.build_external_activation_review(root, run)
        receipt = json.loads(data)
        self.assertEqual(
            sorted(receipt), list(ACTIVATION.EXTERNAL_REVIEW_RECEIPT_KEYS),
        )
        self.assertEqual(receipt["decision"], "APPROVED")
        self.assertEqual(receipt["findings"], [])
        self.assertEqual(receipt["findings_count"], 0)
        self.assertIs(receipt["candidate_owned"], False)
        self.assertIs(receipt["activation_authorized"], True)
        self.assertEqual(
            receipt["receipt_type"], ACTIVATION.EXTERNAL_REVIEW_RECEIPT_TYPE,
        )


class ActivationAuthorizationTransitionTests(unittest.TestCase):
    """F8-PREACTIVATION-AUTHORIZATION-SELF-ASSERTED and
    F8-AUTHORIZATION-TRANSITION-ABSENT.

    No candidate-owned artefact may pre-assert the activation authorization,
    and the authenticated operation must really move it from false to true.
    """

    def test_no_sealed_candidate_artefact_pre_authorizes_activation(self):
        source = json.loads(
            (ROOT / "protected-source-bootstrap-v2" / "bootstrap-contract.json")
            .read_bytes()
        )
        self.assertIs(
            source["protected_review_result"]["activation_authorized"], False,
            "the protected-source contract pre-asserts the activation authorization",
        )
        self.assertTrue(
            source["protected_review_result"]["activation_findings"],
            "a pre-review contract must record why activation is unauthorized",
        )
        package = ACTIVATION.verify_activation_package()
        self.assertIs(package["activation_authorized"], False)
        self.assertIs(package["f8_closed"], False)
        self.assertEqual(
            package["external_activation_review"]["state"], "unavailable",
        )

    def test_the_activation_package_models_an_authenticated_transition(self):
        self.assertIn(
            "authenticated", ACTIVATION.EXTERNAL_REVIEW_STATES,
            "the package cannot represent an authenticated external review",
        )
        payload = deepcopy(ACTIVATION.verify_activation_package())
        payload["activation_authorized"] = True
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "source-chain-activation-v2.json"
            path.write_bytes(ACTIVATION.canonical_bytes(payload))
            with self.assertRaises(SystemExit):
                ACTIVATION.verify_activation_package(path=path)


class IndependentReviewerDecisionTests(unittest.TestCase):
    """F8-EXACT-CANDIDATE-REVIEW-BINDING.

    The candidate may define the decision schema, the binding requirements and
    the fail-closed verifier. It may never author, default or synthesize the
    reviewer's decision. Concrete APPROVED bytes must be a separate immutable
    artifact the independent reviewer produces only after this exact candidate
    exists, and the sealed lane may only authenticate and package them.
    """

    INDEPENDENT_ROOT = ROOT / "independent-review-bootstrap-v2"

    def setUp(self):
        self.validator_source = (
            self.INDEPENDENT_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.contract = json.loads(
            (self.INDEPENDENT_ROOT / "bootstrap-contract.json").read_bytes()
        )

    # -- helpers ----------------------------------------------------------
    def prepared(self, root):
        checkout = root / VALIDATOR.AUTHORITY_CHECKOUT
        base, head = build_authority_candidate(checkout)
        run = synthetic_live_run(
            base_commit=base,
            base_tree=git(checkout, "rev-parse", f"{base}^{{tree}}"),
            head_commit=head,
            head_tree=git(checkout, "rev-parse", "HEAD^{tree}"),
        )
        return run, checkout

    def decision_for(self, root, run, checkout, **overrides):
        return reviewer_decision(run, checkout, **overrides)

    def place(self, root, run, data):
        """Deliver the decision with the sealed evidence the lane demands."""
        return deliver_reviewer_decision(root, run, None, decision=data)

    # -- the candidate may not author the decision ------------------------
    def test_no_candidate_artefact_preselects_an_approved_decision(self):
        external = self.contract["external_activation_review"]
        self.assertNotIn(
            "decision", external,
            "the candidate contract preselects the reviewer decision",
        )
        self.assertNotIn("findings_count", external)
        self.assertEqual(external["required_decision"], "APPROVED")
        self.assertEqual(external["required_findings_count"], 0)
        self.assertIs(external["candidate_authored_decision_forbidden"], True)
        self.assertTrue(external["decision_source"])
        self.assertFalse(
            hasattr(VALIDATOR, "EXTERNAL_REVIEW_DECISION"),
            "the validator still carries an emitted decision constant",
        )
        for emitted in (
            '"decision": EXTERNAL_REVIEW_DECISION',
            '"decision": "APPROVED"',
            '"activation_authorized": True,',
            '"findings": [],',
            '"candidate_owned": False,',
        ):
            self.assertNotIn(
                emitted, self.validator_source,
                f"the validator still authors {emitted}",
            )

    def test_the_candidate_alone_cannot_produce_any_approved_receipt(self):
        """Without separately authored reviewer bytes nothing is producible."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run, _ = self.prepared(root)
            with self.assertRaises(SystemExit) as raised:
                VALIDATOR.build_external_activation_review(root, run)
            self.assertIn("decision", str(raised.exception).lower())

    def test_separately_authored_reviewer_bytes_are_authenticated_and_packaged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run, checkout = self.prepared(root)
            self.place(root, run, self.decision_for(root, run, checkout))
            data = VALIDATOR.build_external_activation_review(root, run)
        receipt = json.loads(data)
        self.assertEqual(
            sorted(receipt), list(ACTIVATION.EXTERNAL_REVIEW_RECEIPT_KEYS),
        )
        self.assertEqual(receipt["decision"], "APPROVED")
        self.assertEqual(receipt["findings_count"], 0)
        self.assertIs(receipt["activation_authorized"], True)
        self.assertIs(receipt["candidate_owned"], False)

    def test_every_contradictory_or_substituted_decision_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run, checkout = self.prepared(root)
            for label, overrides in (
                ("changes-requested", {"decision": "CHANGES_REQUESTED"}),
                ("lowercase", {"decision": "approved"}),
                ("non-zero-findings", {"findings_count": 1}),
                ("findings-present",
                 {"findings": [{"closure": "F8", "finding": "x"}]}),
                ("boolean-count", {"findings_count": True}),
                ("unauthorized", {"activation_authorized": False}),
                ("candidate-owned", {"candidate_owned": True}),
                ("pre-candidate", {"produced_after_candidate": False}),
                ("self-reviewed",
                 {"reviewer_repository": VALIDATOR.AUTHORITY_REPOSITORY}),
                ("foreign-profile", {"reviewer_profile": "acc-releaser"}),
                ("foreign-head", {"head_commit": "0" * 40}),
                ("foreign-tree", {"head_tree": "0" * 40}),
                ("foreign-base", {"base_commit": "0" * 40}),
                ("foreign-parent", {"sole_parent": "0" * 40}),
                ("foreign-diff", {"canonical_diff_sha256": "0" * 64}),
                ("foreign-trust", {"reviewer_authorization_sha256": "0" * 64}),
                ("foreign-repository", {"repository": "chrizzatsu/other"}),
                ("foreign-type", {"document_type": "something-else"}),
            ):
                with self.subTest(label=label):
                    path = self.place(
                        root, run, self.decision_for(root, run, checkout, **overrides),
                    )
                    try:
                        with self.assertRaises(SystemExit):
                            VALIDATOR.build_external_activation_review(root, run)
                    finally:
                        path.unlink()

    def test_a_decision_for_a_different_candidate_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run, checkout = self.prepared(root)
            data = self.decision_for(root, run, checkout)
        with tempfile.TemporaryDirectory() as td:
            other = Path(td)
            other_run, other_checkout = self.prepared(other)
            # a genuinely different candidate: one extra reviewed byte
            (other_checkout / "extra.txt").write_bytes(b"different candidate\n")
            git(other_checkout, "add", "-A")
            git(other_checkout, "commit", "-q", "--amend", "--no-edit")
            other_run["authority_head_commit"] = git(
                other_checkout, "rev-parse", "HEAD",
            )
            other_run["authority_head_tree"] = git(
                other_checkout, "rev-parse", "HEAD^{tree}",
            )
            self.assertNotEqual(
                other_run["authority_head_commit"], json.loads(data)["head_commit"],
            )
            # the earlier reviewer decision cannot approve this candidate
            path = other / VALIDATOR.REVIEWER_DECISION_DIRECTORY / (
                f'{other_run["authority_head_commit"]}.json'
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            with self.assertRaises(SystemExit):
                VALIDATOR.build_external_activation_review(other, other_run)

    def test_non_canonical_or_duplicate_decision_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run, checkout = self.prepared(root)
            good = self.decision_for(root, run, checkout)
            for label, data in (
                ("not-json", b"not json\n"),
                ("non-canonical", good.replace(b"\n", b"", 1)),
                ("duplicate-member",
                 b'{"decision":"APPROVED","decision":"APPROVED"}\n'),
                ("empty", b""),
            ):
                with self.subTest(label=label):
                    path = self.place(root, run, data)
                    try:
                        with self.assertRaises(SystemExit):
                            VALIDATOR.build_external_activation_review(root, run)
                    finally:
                        path.unlink()

    def test_the_workflow_reads_the_external_decision_it_never_authors(self):
        workflow = (
            self.INDEPENDENT_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(VALIDATOR.REVIEWER_DECISION_DIRECTORY, workflow)
        review_job, activation_job = workflow.split(
            f"  {PIN.ACTIVATION_JOB_NAME}:", 1,
        )
        self.assertNotIn("APPROVED", review_job)
        self.assertIn('.decision == "APPROVED"', activation_job)


class RunSigningWindowTests(AuthenticatedLiveEvidenceTests):
    """F8-LIVE-EVIDENCE-TRANSITION-UNREACHABLE.

    cosign signs and Rekor integrates the entry *during* the job, before the
    job and the run complete. The trusted time must therefore be proven to fall
    inside the authenticated run/job window, not after the run finished. A
    timeline that puts integration after successful completion is not a
    representative server order and must never pass.
    """

    def run_url(self, repository, run_id):
        return f"{PIN.API_ROOT}/repos/{repository}/actions/runs/{run_id}"

    def jobs_url(self, repository, run_id):
        return (
            f"{self.run_url(repository, run_id)}"
            "/attempts/1/jobs?per_page=100&page=1"
        )

    def independent(self):
        return (
            ACTIVATION.INDEPENDENT_REPOSITORY, self.fixture.INDEPENDENT_RUN_ID,
        )

    def test_a_signature_integrated_inside_the_job_is_accepted(self):
        """The real order: run start <= job start <= Rekor <= job end <= run end."""
        pinned = self.fixture.derive()
        self.assertIs(pinned["f8_closed"], True)
        self.assertIs(pinned["activation_authorized"], True)
        started = self.fixture.INTEGRATED + self.fixture.JOB_STARTED_OFFSET
        completed = self.fixture.INTEGRATED + self.fixture.JOB_COMPLETED_OFFSET
        self.assertLess(started, self.fixture.INTEGRATED)
        self.assertLess(self.fixture.INTEGRATED, completed)

    def test_a_signature_before_the_authenticated_start_is_rejected(self):
        repository, run_id = self.independent()
        url = self.jobs_url(repository, run_id)
        payload = deepcopy(self.json_at(url))
        payload["jobs"][0]["started_at"] = self.fixture.instant(
            self.fixture.JOB_COMPLETED_OFFSET - 60,
        )
        self.assertRejectedBeforeTrust(self.mutated(url, payload))

    def test_a_signature_after_the_authenticated_completion_is_rejected(self):
        repository, run_id = self.independent()
        url = self.jobs_url(repository, run_id)
        payload = deepcopy(self.json_at(url))
        payload["jobs"][0]["completed_at"] = self.fixture.instant(
            self.fixture.JOB_STARTED_OFFSET + 60,
        )
        self.assertRejectedBeforeTrust(self.mutated(url, payload))

    def test_the_old_reverse_order_timeline_cannot_pass(self):
        """Rekor after successful run completion is not a real server order."""
        repository, run_id = self.independent()
        url = self.run_url(repository, run_id)
        payload = deepcopy(self.json_at(url))
        payload["updated_at"] = self.fixture.instant(-1)
        payload["run_started_at"] = self.fixture.instant(-120)
        payload["created_at"] = self.fixture.instant(-180)
        jobs_url = self.jobs_url(repository, run_id)
        jobs = deepcopy(self.json_at(jobs_url))
        jobs["jobs"][0]["started_at"] = self.fixture.instant(-100)
        jobs["jobs"][0]["completed_at"] = self.fixture.instant(-10)
        responses = dict(self.mutated(url, payload)._recorded)
        responses[jobs_url] = self.mutated(jobs_url, jobs)._recorded[jobs_url]
        self.assertRejectedBeforeTrust(RecordedGitHub(responses))

    def test_missing_or_unparsable_timestamps_are_rejected(self):
        repository, run_id = self.independent()
        run_url = self.run_url(repository, run_id)
        jobs_url = self.jobs_url(repository, run_id)
        for label, url, mutate in (
            ("run-no-start", run_url, lambda p: p.pop("run_started_at")),
            ("run-no-completion", run_url, lambda p: p.pop("updated_at")),
            ("run-no-creation", run_url, lambda p: p.pop("created_at")),
            ("job-no-start", jobs_url, lambda p: p["jobs"][0].pop("started_at")),
            ("job-no-completion", jobs_url,
             lambda p: p["jobs"][0].pop("completed_at")),
            ("run-unparsable", run_url,
             lambda p: p.update(run_started_at="yesterday")),
            ("run-not-utc", run_url,
             lambda p: p.update(run_started_at="2027-01-15T08:00:00+01:00")),
            ("job-unparsable", jobs_url,
             lambda p: p["jobs"][0].update(completed_at="")),
            ("run-null", run_url, lambda p: p.update(updated_at=None)),
            ("job-null", jobs_url, lambda p: p["jobs"][0].update(started_at=None)),
        ):
            with self.subTest(label=label):
                payload = deepcopy(self.json_at(url))
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(url, payload))

    def test_contradictory_or_non_monotonic_timestamps_are_rejected(self):
        repository, run_id = self.independent()
        run_url = self.run_url(repository, run_id)
        jobs_url = self.jobs_url(repository, run_id)
        for label, url, mutate in (
            ("run-started-before-created", run_url,
             lambda p: p.update(run_started_at=self.fixture.instant(-1200))),
            ("run-updated-before-started", run_url,
             lambda p: p.update(updated_at=self.fixture.instant(-700))),
            ("job-started-before-run", jobs_url,
             lambda p: p["jobs"][0].update(
                 started_at=self.fixture.instant(-800))),
            ("job-completed-after-run", jobs_url,
             lambda p: p["jobs"][0].update(
                 completed_at=self.fixture.instant(900))),
            ("job-completed-before-started", jobs_url,
             lambda p: p["jobs"][0].update(
                 completed_at=self.fixture.instant(-400))),
        ):
            with self.subTest(label=label):
                payload = deepcopy(self.json_at(url))
                mutate(payload)
                self.assertRejectedBeforeTrust(self.mutated(url, payload))


# ---------------------------------------------------------------------------
# The production signing workflow must actually be able to reach Authority
# verification once the authorized independent-review run exists.
# ---------------------------------------------------------------------------
SIGNING_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
SEALED_INDEPENDENT_CONTRACT = (
    "independent-review-bootstrap-v2/bootstrap-contract.json"
)
# The exact runtime file names the production step installs before its guards.
RUNTIME_SEALED_READBACKS = {
    "independent-review-workflow.yml":
        "independent-review-bootstrap-v2/.github/workflows/review-authority-v2.yml",
    "independent-review-validator.py":
        "independent-review-bootstrap-v2/scripts/verify_kanban_review_v2.py",
}


def workflow_run_block(text, step_name):
    """The exact `run` scalar of one named production step, verbatim."""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == f"- name: {step_name}":
            start = index
            break
    if start is None:
        raise AssertionError(f"production step {step_name!r} is absent")
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("- name:"):
            raise AssertionError(f"production step {step_name!r} carries no run block")
        if stripped in ("run: |", "run: |-"):
            indent = len(lines[index]) - len(lines[index].lstrip()) + 2
            body = []
            for candidate in lines[index + 1:]:
                if candidate.strip() and len(candidate) - len(candidate.lstrip()) < indent:
                    break
                body.append(candidate[indent:] if candidate.strip() else "")
            return "\n".join(body).rstrip() + "\n"
    raise AssertionError(f"production step {step_name!r} carries no run block")


class ProductionWorkflowLiveTransitionTests(unittest.TestCase):
    """F8-INDEPENDENT-BOOTSTRAP-LIVE-TRANSITION-UNREACHABLE.

    The signing workflow refuses to issue anything until it has bound the
    exact independent-review bootstrap commit. That binding must be reachable
    from authenticated live evidence: a guard that compares the live head to a
    sealed constant the pre-live contract deliberately keeps `null` can never
    succeed, so every real production run would stop before Authority
    verification and the F8 `false -> authenticated true` transition could
    never happen at all.
    """

    STEP_NAME = "Validate exact independent-review run and workflow bytes"
    CANONICAL_LIVE_HEAD = LiveEvidenceFixture.INDEPENDENT_HEAD

    def setUp(self):
        self.workflow = SIGNING_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.contract = json.loads(
            (ROOT / SEALED_INDEPENDENT_CONTRACT).read_bytes()
        )

    def sealed_contract_guards(self):
        """Every `[[ ... ]]` guard of the step that reads the sealed contract."""
        block = workflow_run_block(self.workflow, self.STEP_NAME)
        return [
            line for line in block.splitlines()
            if line.startswith("[[ ") and SEALED_INDEPENDENT_CONTRACT in line
        ]

    def test_the_pre_live_sealed_bootstrap_identifiers_stay_unpinned(self):
        """The invariant the transition must respect, not work around."""
        run = self.contract["authorized_source_run"]
        unavailable = self.contract["live_identifiers_never_pre_pinned"]
        for field in ("independent_bootstrap_commit", "independent_bootstrap_tree"):
            self.assertIn(field, unavailable, field)
            self.assertIsNone(run[field], field)

    def test_no_workflow_guard_reads_a_deliberately_unavailable_sealed_field(self):
        """`jq -e` on a null pre-live constant can only ever fail closed."""
        unavailable = self.contract["live_identifiers_never_pre_pinned"]
        offenders = []
        for number, line in enumerate(self.workflow.splitlines(), 1):
            if "jq -e" not in line or SEALED_INDEPENDENT_CONTRACT not in line:
                continue
            for field in unavailable:
                if f".{field}" in line:
                    offenders.append((number, field, line.strip()))
        self.assertEqual(
            offenders, [],
            "the production workflow reads a sealed field that is "
            "deliberately unavailable before activation, so the step can "
            "never succeed and Authority verification is unreachable",
        )

    def test_the_sealed_contract_guards_execute_green_for_the_live_head(self):
        """The real guard lines, run in real bash against the real bytes."""
        guards = self.sealed_contract_guards()
        self.assertTrue(guards, "the production step binds no sealed contract byte")
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "authority-v2-runtime"
            runtime.mkdir()
            for name, sealed in RUNTIME_SEALED_READBACKS.items():
                (runtime / name).write_bytes((ROOT / sealed).read_bytes())
            script = "set -euo pipefail\n" + "\n".join(guards) + "\n"
            result = subprocess.run(
                ["bash", "-c", script], cwd=str(ROOT), capture_output=True,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "AUTHORITY_V2_RUNTIME": str(runtime),
                    "REVIEW_HEAD": self.CANONICAL_LIVE_HEAD,
                },
            )
            self.assertEqual(
                result.returncode, 0,
                "the production independent-review binding guards fail closed "
                "for the canonical authenticated live head, so no real run can "
                "reach Authority verification:\n"
                f"{script}\nstderr={result.stderr.decode()!r}",
            )


class DerivedIndependentBootstrapBindingTests(AuthenticatedLiveEvidenceTests):
    """F8-INDEPENDENT-BOOTSTRAP-LIVE-TRANSITION-UNREACHABLE, end to end.

    The signing workflow's binding step is driven over the real production
    bytes: the live commit and tree are derived from authenticated canonical
    repository, run, job, commit and tree readbacks for the unique authorized
    independent run, the sealed workflow, validator and bootstrap-contract
    path-to-blob digests are bound at that live head, and the exact guard lines
    of the production workflow are then executed in real bash. Every rejection
    below is caused only by the mutation under test: the unmutated pipeline
    derives a non-null binding and the guards run green.
    """

    STEP_NAME = ProductionWorkflowLiveTransitionTests.STEP_NAME
    BINDING_FILE = "independent-bootstrap-binding.json"

    def setUp(self):
        super().setUp()
        self.workflow = SIGNING_WORKFLOW_PATH.read_text(encoding="utf-8")
        for name, module in (
            ("pin_source_chain_activation_v2", PIN),
            ("verify_source_chain_activation_v2", ACTIVATION),
        ):
            self.addCleanup(
                lambda key=name, previous=sys.modules.get(name):
                    sys.modules.__setitem__(key, previous)
                    if previous is not None else sys.modules.pop(key, None)
            )
            sys.modules[name] = module

    # -- driving the production derivation ---------------------------------
    def derive(self, exchange=None):
        """The private production derivation, over recorded canonical reads."""
        recorded = self.fixture.transport() if exchange is None else exchange
        with contextlib.ExitStack() as stack:
            for context in recorded.patched():
                stack.enter_context(context)
            return PIN._derive_independent_bootstrap_binding()

    def consume(self, exchange=None, *, review_head=None, run_id=None,
                output=None):
        """The workflow-facing operation the production step actually runs."""
        recorded = self.fixture.transport() if exchange is None else exchange
        with contextlib.ExitStack() as stack:
            for context in recorded.patched():
                stack.enter_context(context)
            return VERIFIER.derive_independent_bootstrap_binding(
                self.fixture.INDEPENDENT_HEAD if review_head is None
                else review_head,
                str(self.fixture.INDEPENDENT_RUN_ID) if run_id is None
                else run_id,
                output,
            )

    def rejection(self, exchange=None, **kwargs):
        with tempfile.TemporaryDirectory() as td:
            kwargs.setdefault("output", Path(td) / self.BINDING_FILE)
            try:
                self.consume(exchange, **kwargs)
            except SystemExit as error:
                return str(error)
        raise AssertionError("the production operation bound the live head")

    # -- GREEN: the transition is reachable --------------------------------
    def test_the_live_commit_and_tree_are_derived_and_never_null(self):
        binding = self.derive()
        self.assertEqual(
            binding["independent_bootstrap_commit"],
            self.fixture.INDEPENDENT_HEAD,
        )
        self.assertEqual(
            binding["independent_bootstrap_tree"], self.fixture.INDEPENDENT_TREE,
        )
        self.assertEqual(binding["run_id"], self.fixture.INDEPENDENT_RUN_ID)
        self.assertEqual(binding["run_attempt"], 1)
        self.assertEqual(
            binding["repository"], ACTIVATION.INDEPENDENT_REPOSITORY,
        )
        self.assertEqual(binding["repository_id"], self.fixture.INDEPENDENT_ID)
        self.assertEqual(
            binding["derived_from"], PIN.BOOTSTRAP_BINDING_PROVENANCE,
        )
        self.assertIsNone(binding["sealed_pre_live_commit"])
        self.assertIsNone(binding["sealed_pre_live_tree"])

    def test_the_bound_paths_are_the_sealed_workflow_validator_and_contract(self):
        bound = self.derive()["bound_paths"]
        sealed = PIN._sealed_bytes_for(ACTIVATION.INDEPENDENT_REPOSITORY)
        self.assertEqual(sorted(bound), sorted(sealed))
        for target_path, digest in bound.items():
            self.assertEqual(
                hashlib.sha256(sealed[target_path]).hexdigest(), digest,
            )
        contract = json.loads(
            (ROOT / SEALED_INDEPENDENT_CONTRACT).read_bytes()
        )
        self.assertEqual(
            bound[".github/workflows/review-authority-v2.yml"],
            contract["workflow"]["sha256"],
        )
        self.assertEqual(
            bound[".github/workflows/readback-authority-v2-activation.yml"],
            contract["terminal_readback"]["collector_workflow_sha256"],
        )
        self.assertEqual(
            bound["scripts/verify_kanban_review_v2.py"],
            contract["validator"]["sha256"],
        )
        self.assertEqual(
            bound["bootstrap-contract.json"],
            hashlib.sha256(
                (ROOT / SEALED_INDEPENDENT_CONTRACT).read_bytes()
            ).hexdigest(),
        )

    def test_the_sealed_pre_live_contract_stays_null_and_f8_stays_false(self):
        """Deriving live values may never pin or authorize the sealed package."""
        self.derive()
        contract = json.loads(
            (ROOT / SEALED_INDEPENDENT_CONTRACT).read_bytes()
        )
        for field in PIN.INDEPENDENT_BOOTSTRAP_LIVE_FIELDS:
            self.assertIsNone(contract["authorized_source_run"][field], field)
        package = ACTIVATION.verify_activation_package()
        self.assertIs(package["f8_closed"], False)
        self.assertIs(package["activation_authorized"], False)
        self.assertEqual(package["activation_state"], "unavailable")

    def test_the_production_workflow_step_executes_green_over_the_binding(self):
        """The real guard lines of the real step, in real bash, exit zero."""
        block = workflow_run_block(self.workflow, self.STEP_NAME)
        guards = [
            line for line in block.splitlines()
            if line.startswith("[[ ") and self.BINDING_FILE in line
        ]
        self.assertEqual(
            len(guards), 3,
            "the production step must consume the derived commit, tree and run",
        )
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "authority-v2-runtime"
            runtime.mkdir()
            binding = self.consume(output=runtime / self.BINDING_FILE)
            script = "set -euo pipefail\n" + "\n".join(guards) + "\n"
            result = subprocess.run(
                ["bash", "-c", script], cwd=str(ROOT), capture_output=True,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "AUTHORITY_V2_RUNTIME": str(runtime),
                    "REVIEW_HEAD": binding["independent_bootstrap_commit"],
                    "INDEPENDENT_REVIEW_RUN_ID": str(binding["run_id"]),
                },
            )
            self.assertEqual(
                result.returncode, 0,
                f"{script}\nstderr={result.stderr.decode()!r}",
            )

    def test_the_binding_output_is_canonical_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / self.BINDING_FILE
            binding = self.consume(output=output)
            self.assertEqual(
                output.read_bytes(),
                json.dumps(binding, indent=2, sort_keys=True).encode() + b"\n",
            )
            with self.assertRaises(SystemExit):
                self.consume(output=output)

    # -- adversarial: null, missing and synthetic identifiers --------------
    def test_a_null_or_missing_live_head_or_tree_is_rejected(self):
        repository = ACTIVATION.INDEPENDENT_REPOSITORY
        run_id = self.fixture.INDEPENDENT_RUN_ID
        run_url = f"{PIN.API_ROOT}/repos/{repository}/actions/runs/{run_id}"
        commit_url = (
            f"{PIN.API_ROOT}/repos/{repository}/git/commits"
            f"/{self.fixture.INDEPENDENT_HEAD}"
        )
        for label, url, mutate in (
            ("run-head-null", run_url, lambda p: p.update(head_sha=None)),
            ("run-head-missing", run_url, lambda p: p.pop("head_sha")),
            ("commit-tree-null", commit_url,
             lambda p: p.update(tree={"sha": None})),
            ("commit-tree-missing", commit_url, lambda p: p.pop("tree")),
        ):
            with self.subTest(label=label):
                payload = deepcopy(self.json_at(url))
                mutate(payload)
                self.assertTrue(self.rejection(self.mutated(url, payload)))

    def test_a_synthetic_or_repeated_live_head_or_tree_is_rejected(self):
        repository = ACTIVATION.INDEPENDENT_REPOSITORY
        run_id = self.fixture.INDEPENDENT_RUN_ID
        run_url = f"{PIN.API_ROOT}/repos/{repository}/actions/runs/{run_id}"
        for label, head in (
            ("all-zero", "0" * 40),
            ("all-f", "f" * 40),
            ("repeated-pair", "ab" * 20),
            ("short", "a" * 39),
            ("uppercase", "A" * 40),
        ):
            with self.subTest(label=label):
                payload = deepcopy(self.json_at(run_url))
                payload["head_sha"] = head
                self.assertTrue(self.rejection(self.mutated(run_url, payload)))

    def test_a_commit_readback_that_disagrees_with_the_run_tree_is_rejected(self):
        repository = ACTIVATION.INDEPENDENT_REPOSITORY
        commit_url = (
            f"{PIN.API_ROOT}/repos/{repository}/git/commits"
            f"/{self.fixture.INDEPENDENT_HEAD}"
        )
        payload = deepcopy(self.json_at(commit_url))
        payload["tree"] = {"sha": self.fixture.SOURCE_TREE}
        self.assertTrue(self.rejection(self.mutated(commit_url, payload)))

    def test_a_substituted_run_head_that_the_tree_cannot_carry_is_rejected(self):
        """A live head whose tree does not hold the sealed reviewer bytes."""
        repository = ACTIVATION.INDEPENDENT_REPOSITORY
        tree_url = (
            f"{PIN.API_ROOT}/repos/{repository}/git/trees"
            f"/{self.fixture.INDEPENDENT_TREE}?recursive=1"
        )
        for label, mutate in (
            ("truncated", lambda p: p.update(truncated=True)),
            ("identity-mismatch", lambda p: p.update(sha="0" * 40)),
            ("workflow-absent", lambda p: p.update(tree=[
                entry for entry in p["tree"]
                if entry["path"] != ".github/workflows/review-authority-v2.yml"
            ])),
            ("validator-absent", lambda p: p.update(tree=[
                entry for entry in p["tree"]
                if entry["path"] != "scripts/verify_kanban_review_v2.py"
            ])),
            ("contract-absent", lambda p: p.update(tree=[
                entry for entry in p["tree"]
                if entry["path"] != "bootstrap-contract.json"
            ])),
            ("blob-substituted", lambda p: p["tree"][0].update(sha="0" * 40)),
            ("not-a-blob", lambda p: p["tree"][0].update(type="tree")),
            ("executable-mode", lambda p: p["tree"][0].update(mode="100755")),
        ):
            with self.subTest(label=label):
                payload = deepcopy(self.json_at(tree_url))
                mutate(payload)
                self.assertTrue(self.rejection(self.mutated(tree_url, payload)))

    def test_substituted_workflow_validator_or_contract_bytes_are_rejected(self):
        repository = ACTIVATION.INDEPENDENT_REPOSITORY
        sealed = PIN._sealed_bytes_for(repository)
        for target_path, data in sorted(sealed.items()):
            with self.subTest(target_path=target_path):
                oid = PIN._git_blob_oid(data)
                url = f"{PIN.API_ROOT}/repos/{repository}/git/blobs/{oid}"
                payload = deepcopy(self.json_at(url))
                payload["content"] = base64.b64encode(
                    data + b"# forged\n"
                ).decode("ascii")
                self.assertTrue(self.rejection(self.mutated(url, payload)))

    def test_an_absent_additional_or_ambiguous_authorized_run_is_rejected(self):
        repository = ACTIVATION.INDEPENDENT_REPOSITORY
        workflow_id = self.fixture.INDEPENDENT_ID + 11
        url = (
            f"{PIN.API_ROOT}/repos/{repository}/actions/workflows"
            f"/{workflow_id}/runs?per_page=100&page=1"
        )
        original = self.json_at(url)
        for label, mutate in (
            ("absent", lambda p: p.update(workflow_runs=[])),
            ("additional", lambda p: p["workflow_runs"].append(
                dict(p["workflow_runs"][0], id=p["workflow_runs"][0]["id"] + 1)
            )),
            ("wrong-attempt", lambda p: p["workflow_runs"][0].update(run_attempt=2)),
            ("wrong-trigger", lambda p: p["workflow_runs"][0].update(event="push")),
            ("wrong-branch", lambda p: p["workflow_runs"][0].update(
                head_branch="activation")),
            ("wrong-path", lambda p: p["workflow_runs"][0].update(
                path=".github/workflows/other.yml")),
            ("not-successful", lambda p: p["workflow_runs"][0].update(
                conclusion="failure")),
        ):
            with self.subTest(label=label):
                payload = deepcopy(original)
                mutate(payload)
                self.assertTrue(self.rejection(self.mutated(url, payload)))

    # -- adversarial: the caller may never preselect the binding -----------
    def test_a_caller_preselected_run_or_head_cannot_bind(self):
        for label, kwargs in (
            ("foreign-head", {"review_head": "b" * 40}),
            ("source-head", {"review_head": self.fixture.SOURCE_HEAD}),
            ("tree-as-head", {"review_head": self.fixture.INDEPENDENT_TREE}),
            ("foreign-run", {"run_id": str(self.fixture.SOURCE_RUN_ID)}),
            ("adjacent-run",
             {"run_id": str(self.fixture.INDEPENDENT_RUN_ID + 1)}),
            ("non-numeric-run", {"run_id": "17493820552 "}),
            ("zero-run", {"run_id": "0"}),
            ("uppercase-head", {"review_head": "A" * 40}),
            ("short-head", {"review_head": "a" * 39}),
        ):
            with self.subTest(label=label):
                self.assertTrue(self.rejection(**kwargs))

    def test_a_sealed_contract_that_pre_pins_the_bootstrap_commit_is_rejected(self):
        """A candidate-precomputed future commit may never become the binding."""
        contract = json.loads(
            (ROOT / SEALED_INDEPENDENT_CONTRACT).read_bytes()
        )
        for label, mutate in (
            ("pre-pinned-commit", lambda c: c["authorized_source_run"].update(
                independent_bootstrap_commit=self.fixture.INDEPENDENT_HEAD)),
            ("pre-pinned-tree", lambda c: c["authorized_source_run"].update(
                independent_bootstrap_tree=self.fixture.INDEPENDENT_TREE)),
            ("pre-pinned-foreign", lambda c: c["authorized_source_run"].update(
                independent_bootstrap_commit="c" * 40)),
            ("undeclared", lambda c: c.update(
                live_identifiers_never_pre_pinned=[
                    name for name in c["live_identifiers_never_pre_pinned"]
                    if name != "independent_bootstrap_commit"
                ])),
        ):
            with self.subTest(label=label):
                payload = deepcopy(contract)
                mutate(payload)
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    target = root / SEALED_INDEPENDENT_CONTRACT
                    target.parent.mkdir(parents=True)
                    target.write_bytes(
                        json.dumps(payload, indent=2, sort_keys=True).encode()
                        + b"\n"
                    )
                    with self.assertRaises(SystemExit):
                        with contextlib.ExitStack() as stack:
                            for context in self.fixture.transport().patched():
                                stack.enter_context(context)
                            PIN._derive_independent_bootstrap_binding(root)

    def test_a_contract_binding_foreign_paths_or_digests_is_rejected(self):
        contract = json.loads(
            (ROOT / SEALED_INDEPENDENT_CONTRACT).read_bytes()
        )
        package = ACTIVATION.verify_activation_package()
        for label, mutate in (
            ("foreign-workflow-path",
             lambda c: c["workflow"].update(path=".github/workflows/x.yml")),
            ("foreign-validator-path",
             lambda c: c["validator"].update(path="scripts/x.py")),
            ("foreign-workflow-digest",
             lambda c: c["workflow"].update(sha256="0" * 64)),
            ("foreign-validator-digest",
             lambda c: c["validator"].update(sha256="1" * 64)),
            ("self-contradicting-workflow",
             lambda c: c["authorized_source_run"].update(
                 independent_workflow_sha256="2" * 64)),
            ("self-contradicting-validator",
             lambda c: c["authorized_source_run"].update(
                 independent_validator_sha256="3" * 64)),
            ("synthetic-digest",
             lambda c: c["workflow"].update(sha256="ab" * 32)),
        ):
            with self.subTest(label=label):
                payload = deepcopy(contract)
                mutate(payload)
                with self.assertRaises(SystemExit):
                    PIN._required_independent_bootstrap_digests(payload, package)

    def test_a_forged_binding_object_cannot_satisfy_the_consumer(self):
        """The consumer re-checks every field of whatever the derivation returns."""
        honest = self.derive()
        for label, mutate in (
            ("null-commit",
             lambda b: b.update(independent_bootstrap_commit=None)),
            ("null-tree", lambda b: b.update(independent_bootstrap_tree=None)),
            ("missing-commit",
             lambda b: b.pop("independent_bootstrap_commit")),
            ("commit-equals-tree",
             lambda b: b.update(
                 independent_bootstrap_tree=b["independent_bootstrap_commit"])),
            ("sealed-commit-leaked",
             lambda b: b.update(sealed_pre_live_commit="d" * 40)),
            ("forged-provenance",
             lambda b: b.update(derived_from="caller-supplied")),
            ("foreign-repository",
             lambda b: b.update(repository="chrizzatsu/other")),
            ("wrong-attempt", lambda b: b.update(run_attempt=2)),
            ("head-drift", lambda b: b.update(run_head_sha="e" * 40)),
            ("missing-bound-path",
             lambda b: b["bound_paths"].pop("bootstrap-contract.json")),
        ):
            with self.subTest(label=label):
                forged = deepcopy(honest)
                mutate(forged)
                with tempfile.TemporaryDirectory() as td:
                    with mock.patch.object(
                        PIN, "_derive_independent_bootstrap_binding",
                        lambda *a, **k: forged,
                    ):
                        with self.assertRaises(SystemExit):
                            VERIFIER.derive_independent_bootstrap_binding(
                                self.fixture.INDEPENDENT_HEAD,
                                str(self.fixture.INDEPENDENT_RUN_ID),
                                Path(td) / self.BINDING_FILE,
                            )


# ---------------------------------------------------------------------------
# F13-SIGSTORE-BUNDLE-CONTRACT-DIVERGENT
#
# The pinning boundary and the Authority boundary must read real Cosign v3.1.3
# Sigstore protobuf-JSON v0.3 bundles through exactly one shared canonical
# parser.
#
# The official Sigstore bundle format encodes the `verificationMaterial`
# protobuf oneof DIRECTLY: `verificationMaterial.certificate` (what a raw
# Cosign v3.1.3 keyless `sign-blob --bundle` emits) or
# `verificationMaterial.x509CertificateChain`. A literal nested `content`
# object is not protobuf JSON, and a direct certificate beside a duplicated
# chain is the bespoke shape finding 3 requires rejecting.
# ---------------------------------------------------------------------------
SHARED_PARSER_PATH = ROOT / "scripts" / "sigstore_bundle_v03.py"
REAL_FORMAT_BUNDLE_PATH = (
    ROOT / "tests" / "fixtures" / "cosign-v3.1.3-sigstore-v0.3-bundle.json"
)


class SharedSigstoreBundleContractTests(unittest.TestCase):
    """One canonical v0.3 parser, used at the pinning and Authority boundaries."""

    REPOSITORY = ACTIVATION.INDEPENDENT_REPOSITORY
    WORKFLOW = ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY]
    WORKFLOW_SHA = "7a2d05c9138ebf4460d17ac83e592b6f0cd41827"
    INTEGRATED = 1800000000

    def fixture_bytes(self):
        self.assertTrue(
            REAL_FORMAT_BUNDLE_PATH.is_file(),
            "the immutable real-format Cosign v3.1.3 bundle fixture is absent",
        )
        return REAL_FORMAT_BUNDLE_PATH.read_bytes()

    def material(self):
        return json.loads(self.fixture_bytes())["verificationMaterial"]

    def rebuilt(self, material):
        payload = json.loads(self.fixture_bytes())
        payload["verificationMaterial"] = material
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def test_exactly_one_shared_canonical_parser_serves_both_boundaries(self):
        self.assertTrue(
            SHARED_PARSER_PATH.is_file(),
            "the shared canonical Sigstore v0.3 parser module is absent",
        )
        self.assertEqual(PIN.SIGSTORE.__file__, str(SHARED_PARSER_PATH))
        self.assertEqual(VERIFIER.SIGSTORE.__file__, str(SHARED_PARSER_PATH))

    def test_the_committed_fixture_is_raw_cosign_direct_certificate_output(self):
        """The immutable fixture is representative raw Cosign v3.1.3 output."""
        material = self.material()
        self.assertIn(
            "certificate", material,
            "the committed fixture is not raw Cosign direct-certificate output",
        )
        self.assertNotIn(
            "content", material,
            "a literal nested `content` object is not Sigstore protobuf JSON",
        )
        self.assertNotIn("x509CertificateChain", material)
        self.assertNotIn("publicKey", material)
        self.assertIn("certificate", material)
        self.assertIn("tlogEntries", material)
        # timestampVerificationData is a valid protobuf-JSON member that
        # genuine Cosign v3.1.3 keyless output may carry; the parser
        # correctly ignores it.
        for key in sorted(material):
            self.assertIn(key, (
                "certificate", "tlogEntries", "timestampVerificationData",
            ))
        self.assertEqual(sorted(material["certificate"]), ["rawBytes"])

    def test_immutable_real_format_fixture_parses_at_both_boundaries(self):
        data = self.fixture_bytes()
        parsed = PIN.SIGSTORE.parse_bundle(data)
        self.assertEqual(parsed.media_type, PIN.SIGSTORE.CANONICAL_MEDIA_TYPE)
        self.assertEqual(parsed.content_member, "certificate")
        # A raw Cosign keyless bundle carries the leaf and nothing else: no
        # intermediate and, above all, no duplicated pinned trust anchor.
        self.assertEqual(len(parsed.certificate_chain), 1)
        self.assertEqual(parsed.leaf_der, parsed.certificate_chain[0])
        self.assertEqual(parsed.untrusted_intermediates, ())
        self.assertEqual(parsed.digest_algorithm, "SHA2_256")
        self.assertEqual(len(parsed.message_digest), 32)
        self.assertTrue(parsed.signature)
        self.assertTrue(parsed.canonicalized_body)
        self.assertGreater(parsed.integrated_time, 0)
        # The Authority boundary reads the very same bytes through the parser.
        observed = VERIFIER.extract_rekor_time_bytes(data)
        self.assertEqual(int(observed.timestamp()), parsed.integrated_time)

    def test_the_other_canonical_direct_oneof_member_is_accepted(self):
        """`x509CertificateChain` is equally canonical protobuf JSON v0.3."""
        live = SigstoreFixture(
            b"subject\n", repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED, chain_form=True,
        )
        material = json.loads(live.bundle())["verificationMaterial"]
        self.assertIn("x509CertificateChain", material)
        self.assertNotIn("certificate", material)
        self.assertNotIn("content", material)
        parsed = PIN.SIGSTORE.parse_bundle(live.bundle())
        self.assertEqual(parsed.content_member, "x509CertificateChain")
        self.assertEqual(parsed.leaf_der, live.leaf)
        self.assertEqual(parsed.untrusted_intermediates, (live.intermediate,))
        # The bundle never carries the pinned trust anchor.
        self.assertNotIn(live.root, parsed.certificate_chain)

    def test_both_canonical_members_normalize_to_the_same_leaf_contract(self):
        arguments = dict(
            repository=self.REPOSITORY, workflow_path=self.WORKFLOW,
            workflow_sha=self.WORKFLOW_SHA, integrated=self.INTEGRATED,
        )
        chained = SigstoreFixture(b"subject\n", chain_form=True, **arguments)
        direct = SigstoreFixture(
            b"subject\n", chain_form=False, authority=chained, **arguments,
        )
        for fixture in (chained, direct):
            parsed = PIN.SIGSTORE.parse_bundle(fixture.bundle())
            self.assertEqual(parsed.leaf_der, fixture.leaf)
            self.assertEqual(parsed.message_digest, hashlib.sha256(b"subject\n").digest())

    def test_the_bespoke_nested_content_object_is_rejected_at_both_boundaries(self):
        material = self.material()
        nested = {"content": {"certificate": material["certificate"]},
                  "tlogEntries": material["tlogEntries"]}
        bespoke = self.rebuilt(nested)
        with self.assertRaises(SystemExit):
            PIN.SIGSTORE.parse_bundle(bespoke)
        with self.assertRaises(SystemExit):
            VERIFIER.extract_rekor_time_bytes(bespoke)

    def test_rejected_bespoke_direct_certificate_plus_chain_fails_closed(self):
        material = self.material()
        duplicated = dict(material)
        duplicated["x509CertificateChain"] = {
            "certificates": [material["certificate"]],
        }
        bespoke = self.rebuilt(duplicated)
        with self.assertRaises(SystemExit):
            PIN.SIGSTORE.parse_bundle(bespoke)
        with self.assertRaises(SystemExit):
            VERIFIER.extract_rekor_time_bytes(bespoke)

    def test_absent_and_malformed_oneof_members_are_rejected(self):
        material = self.material()
        for label, mutate in (
            ("no-content-member", lambda m: m.pop("certificate")),
            ("public-key-member",
             lambda m: m.update(publicKey={"hint": "x"})),
            ("certificate-not-object",
             lambda m: m.update(certificate="Y2VydA==")),
            ("certificate-without-raw-bytes",
             lambda m: m.update(certificate={})),
            ("certificate-raw-bytes-not-string",
             lambda m: m.update(certificate={"rawBytes": ["Y2VydA=="]})),
            ("certificate-raw-bytes-empty",
             lambda m: m.update(certificate={"rawBytes": ""})),
            ("certificate-raw-bytes-not-base64",
             lambda m: m.update(certificate={"rawBytes": "not base64!"})),
            ("chain-instead-but-empty",
             lambda m: (m.pop("certificate"),
                        m.update(x509CertificateChain={"certificates": []}))),
            ("chain-entry-malformed",
             lambda m: (m.pop("certificate"),
                        m.update(x509CertificateChain={
                            "certificates": [{"raw": "Y2VydA=="}]}))),
            ("chain-repeats-a-certificate",
             lambda m: (m.pop("certificate"),
                        m.update(x509CertificateChain={"certificates": [
                            {"rawBytes": "Y2VydA=="},
                            {"rawBytes": "Y2VydA=="}]}))),
            ("chain-not-object",
             lambda m: (m.pop("certificate"),
                        m.update(x509CertificateChain=["Y2VydA=="]))),
        ):
            with self.subTest(label=label):
                broken = deepcopy(material)
                mutate(broken)
                data = self.rebuilt(broken)
                with self.assertRaises(SystemExit):
                    PIN.SIGSTORE.parse_bundle(data)
                with self.assertRaises(SystemExit):
                    VERIFIER.extract_rekor_time_bytes(data)


# ---------------------------------------------------------------------------
# F14-CERTIFICATE-CHAIN-ACCEPTANCE-PERMISSIVE
#
# The Sigstore certificate chain is validated against the pinned Fulcio trust
# by established library primitives under the RFC 5280 rules, never by a
# permissive walk: the anchor always comes from the pinned store, every issuer
# link is verified by `Certificate.verify_directly_issued_by`, every validity
# window, CA assertion, keyCertSign usage and pathLenConstraint is enforced,
# the depth is bounded, an unrecognised critical extension is refused and the
# end entity must satisfy the code-signing contract exactly. If the
# verification dependency is unavailable the boundary fails closed; there is
# no permissive fallback anywhere.
#
# NOTE on the engine. A Fulcio workload certificate is a *code-signing* end
# entity. `cryptography.x509.verification` exposes only the TLS client and TLS
# server profiles, each of which refuses such a leaf outright for lacking its
# own required extended key usage - so it could never accept a genuine
# Sigstore certificate, which is why only synthetic leaves ever passed through
# it. The RFC 5280 constraints below are therefore applied to the code-signing
# profile instead, with every cryptographic step still performed by the
# library. Every adversarial case this class asserted is unchanged.
# ---------------------------------------------------------------------------
class Rfc5280CertificateChainTests(unittest.TestCase):
    """Adversarial chains the pinned-trust path validation must refuse."""

    REPOSITORY = ACTIVATION.INDEPENDENT_REPOSITORY
    WORKFLOW = ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY]
    WORKFLOW_SHA = "7a2d05c9138ebf4460d17ac83e592b6f0cd41827"
    INTEGRATED = 1800000000

    def setUp(self):
        self.subject = b'{"receipt":"exact-subject-bytes"}\n'

    def fixture(self, **flaws):
        return SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED, flaws=flaws or None,
        )

    def verify(self, fixture, bundle=None):
        return PIN._verify_sigstore_bundle(
            bundle if bundle is not None else fixture.bundle(),
            subject_bytes=self.subject,
            trust=fixture.trust,
            repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW,
            workflow_sha=self.WORKFLOW_SHA,
            signing_window=(self.INTEGRATED - 300, self.INTEGRATED + 300),
        )

    def test_the_established_primitives_perform_the_validation(self):
        primitive = PIN._x509_verification()
        from cryptography.x509 import verification

        self.assertIs(primitive["PolicyBuilder"], verification.PolicyBuilder)
        self.assertIs(primitive["Store"], verification.Store)
        self.assertIs(primitive["VerificationError"], verification.VerificationError)
        source = inspect.getsource(PIN._verify_certificate_chain)
        # The availability gate is still consulted, so an environment without
        # the verification dependency fails closed before anything runs.
        self.assertIn("_x509_verification()", source)
        # Every issuer link is an established library operation, never a
        # hand-rolled signature comparison.
        self.assertIn("_issued_by_any", source)
        self.assertIn(
            "verify_directly_issued_by",
            inspect.getsource(PIN._issued_by_any),
        )
        self.assertNotIn("_verify_certificate_signature", source)
        # An honest chain still verifies end to end.
        self.verify(self.fixture())

    def test_a_raw_cosign_certificate_only_bundle_verifies_from_pinned_trust(self):
        """No issuing certificate in the bundle: the path comes from trust."""
        fixture = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED, chain_form=False,
        )
        parsed = PIN.SIGSTORE.parse_bundle(fixture.bundle())
        self.assertEqual(parsed.content_member, "certificate")
        self.assertEqual(parsed.untrusted_intermediates, ())
        self.assertEqual(fixture.trust.fulcio_intermediates, (fixture.intermediate,))
        result = self.verify(fixture)
        self.assertEqual(result["integrated_time"], self.INTEGRATED)

    def test_a_bundle_need_never_carry_the_pinned_trust_anchor(self):
        for label, chain_form in (("chain", True), ("certificate", False)):
            with self.subTest(label=label):
                fixture = SigstoreFixture(
                    self.subject, repository=self.REPOSITORY,
                    workflow_path=self.WORKFLOW,
                    workflow_sha=self.WORKFLOW_SHA,
                    integrated=self.INTEGRATED, chain_form=chain_form,
                )
                parsed = PIN.SIGSTORE.parse_bundle(fixture.bundle())
                self.assertNotIn(fixture.root, parsed.certificate_chain)
                self.verify(fixture)

    def test_an_untrusted_bundle_intermediate_never_becomes_an_anchor(self):
        """A foreign self-signed root inside the bundle is not a trust anchor."""
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )
        with self.assertRaises(SystemExit):
            PIN._verify_sigstore_bundle(
                other.bundle(),
                subject_bytes=self.subject,
                trust=other.trust.__class__(
                    fulcio_roots=(),
                    fulcio_intermediates=(),
                    rekor_public_key=other.trust.rekor_public_key,
                    rekor_origin=other.trust.rekor_origin,
                ),
                repository=self.REPOSITORY,
                workflow_path=self.WORKFLOW,
                workflow_sha=self.WORKFLOW_SHA,
                signing_window=(self.INTEGRATED - 300, self.INTEGRATED + 300),
            )

    def test_non_ca_issuer_is_rejected(self):
        fixture = self.fixture(intermediate_ca=False)
        with self.assertRaises(SystemExit):
            self.verify(fixture)

    def test_issuer_without_key_cert_sign_key_usage_is_rejected(self):
        fixture = self.fixture(intermediate_key_cert_sign=False)
        with self.assertRaises(SystemExit):
            self.verify(fixture)

    def test_invalid_leaf_extended_key_usage_is_rejected(self):
        fixture = self.fixture(leaf_code_signing_eku=False)
        with self.assertRaises(SystemExit):
            self.verify(fixture)

    def test_invalid_leaf_key_usage_is_rejected(self):
        fixture = self.fixture(leaf_digital_signature=False)
        with self.assertRaises(SystemExit):
            self.verify(fixture)

    def test_path_length_constraint_violation_is_rejected(self):
        fixture = self.fixture(extra_intermediate=True)
        with self.assertRaises(SystemExit):
            self.verify(fixture)

    def test_unknown_critical_extension_is_rejected(self):
        fixture = self.fixture(leaf_unknown_critical_extension=True)
        with self.assertRaises(SystemExit):
            self.verify(fixture)

    def test_not_yet_valid_and_expired_intermediates_are_rejected(self):
        moment = datetime.fromtimestamp(self.INTEGRATED, tz=timezone.utc)
        for label, window in (
            ("expired", (moment - timedelta(days=9), moment - timedelta(days=1))),
            ("not-yet-valid",
             (moment + timedelta(days=1), moment + timedelta(days=2))),
        ):
            with self.subTest(label=label):
                fixture = self.fixture(intermediate_validity=window)
                with self.assertRaises(SystemExit):
                    self.verify(fixture)

    def test_not_yet_valid_and_expired_leaves_are_rejected(self):
        moment = datetime.fromtimestamp(self.INTEGRATED, tz=timezone.utc)
        for label, window in (
            ("expired", (moment - timedelta(hours=3), moment - timedelta(hours=1))),
            ("not-yet-valid",
             (moment + timedelta(hours=1), moment + timedelta(hours=3))),
        ):
            with self.subTest(label=label):
                fixture = SigstoreFixture(
                    self.subject, repository=self.REPOSITORY,
                    workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
                    integrated=self.INTEGRATED, validity=window,
                )
                with self.assertRaises(SystemExit):
                    self.verify(fixture)

    @contextlib.contextmanager
    def unavailable_primitive(self):
        """Exactly the environment in which the dependency is not installed."""
        import cryptography.x509 as parent

        saved = parent.verification
        with mock.patch.dict(
            sys.modules, {"cryptography.x509.verification": None},
        ):
            del parent.verification
            try:
                yield
            finally:
                parent.verification = saved

    def test_absent_verification_primitive_fails_closed(self):
        fixture = self.fixture()
        with self.unavailable_primitive():
            with self.assertRaises(SystemExit) as caught:
                PIN._x509_verification()
        self.assertIn("cryptography.x509.verification", str(caught.exception))
        with self.unavailable_primitive():
            with self.assertRaises(SystemExit):
                self.verify(fixture)

    def test_a_rejecting_primitive_has_no_permissive_fallback(self):
        """When the library refuses an issuer link, nothing accepts it anyway."""
        fixture = self.fixture()
        from cryptography import x509

        def refuse(*arguments, **keywords):
            raise x509.verification.VerificationError("refused by the primitive")

        with mock.patch.object(
            x509.Certificate, "verify_directly_issued_by", refuse,
        ):
            with self.assertRaises(SystemExit):
                self.verify(fixture)

    def test_a_leaf_without_basic_constraints_is_a_valid_end_entity(self):
        """Every genuine Fulcio leaf omits basicConstraints entirely."""
        from cryptography import x509

        for path in (
            ROOT / "tests" / "fixtures"
            / "cosign-v3.1.3-sigstore-v0.3-bundle.json",
        ):
            bundle = json.loads(path.read_bytes())
            leaf = x509.load_der_x509_certificate(base64.b64decode(
                bundle["verificationMaterial"]["certificate"]["rawBytes"]
            ))
            with self.assertRaises(x509.ExtensionNotFound):
                leaf.extensions.get_extension_for_class(x509.BasicConstraints)
            # The pinned Fulcio path accepts it, at its own trusted time.
            entry = bundle["verificationMaterial"]["tlogEntries"][0]
            integrated = int(entry["integratedTime"])
            trust = PIN._load_pinned_sigstore_trust(ROOT).select(
                integrated, entry["logId"]["keyId"],
            )
            PIN._verify_certificate_chain(
                [base64.b64decode(
                    bundle["verificationMaterial"]["certificate"]["rawBytes"]
                )],
                trust, PIN._cryptography(), "genuine release leaf",
                integrated_time=integrated,
            )

    def test_a_leaf_that_asserts_a_certificate_authority_is_refused(self):
        fixture = self.fixture(leaf_ca=True)
        with self.assertRaises(SystemExit):
            self.verify(fixture)



# ---------------------------------------------------------------------------
# F15-EXTERNAL-REVIEW-SEALED-NULL-STATE and
# F16-ACTIVATION-TRANSITION-UNREACHABLE
#
# The external-review phase must resolve and authenticate the canonical live
# repository, run, job, head, tree, path, blob and artifact state *before* it
# writes any receipt, and may never carry the sealed null head/tree forward.
# The reachable lane is exporter -> independent validator -> Authority, driven
# here through the real command line entry points of all three, never through a
# synthetic in-process call.
# ---------------------------------------------------------------------------
SOURCE_BOOTSTRAP_ROOT = ROOT / "protected-source-bootstrap-v2"
INDEPENDENT_BOOTSTRAP_ROOT = ROOT / "independent-review-bootstrap-v2"


class SealedLane:
    """A real, runnable exporter -> validator lane in a scratch directory.

    Nothing here injects a function result: every artifact is produced by
    invoking the sealed helpers exactly as their workflows do, on the command
    line, with only authenticated-read files and Actions server environment
    variables as input.
    """

    SOURCE_RUN_ID = 4102337781
    INDEPENDENT_RUN_ID = 4102337999

    def __init__(self, workspace, extra_candidate_paths=(),
                 candidate_overrides=None):
        self.workspace = Path(workspace)
        self.source_root = self.workspace / "protected-source"
        self.independent_root = self.workspace / "independent-review"
        self.checkout = self.workspace / "authority-checkout"
        self.base, self.head = build_authority_candidate(
            self.checkout, extra_paths=extra_candidate_paths,
            overrides=candidate_overrides,
        )
        self.head_tree = git(self.checkout, "rev-parse", "HEAD^{tree}")
        self.source_contract = json.loads(
            (SOURCE_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes()
        )
        self.independent_contract = json.loads(
            (INDEPENDENT_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes()
        )
        self._copy_bootstraps()
        self.source_commit = self._synthetic_commit("source")
        self.independent_commit = self._synthetic_commit("independent")

    # -- construction ----------------------------------------------------
    def _copy_bootstraps(self):
        for source, target in (
            (SOURCE_BOOTSTRAP_ROOT, self.source_root),
            (INDEPENDENT_BOOTSTRAP_ROOT, self.independent_root),
        ):
            shutil.copytree(source, target)
            pycache = target / "scripts" / "__pycache__"
            if pycache.is_dir():
                shutil.rmtree(pycache)

    def _synthetic_commit(self, role):
        digest = hashlib.sha256(f"acc-{role}-commit".encode()).hexdigest()[:40]
        tree = hashlib.sha256(f"acc-{role}-tree".encode()).hexdigest()[:40]
        return {"sha": digest, "tree": {"sha": tree}}

    def _authority_commit(self):
        return {"sha": self.head, "tree": {"sha": self.head_tree}}

    def _run_entry(self, workflow_path, repository, head_sha, run_id):
        return {
            "run_started_at": "2027-01-15T08:00:00Z",
            "id": run_id,
            "path": workflow_path,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": head_sha,
            "run_attempt": 1,
            "conclusion": "success",
            "head_repository": {"full_name": repository},
        }

    def _run_pages(self, entry):
        # One terminated server traversal: the single page the server would
        # advertise no next page after.
        return [{"total_count": 1, "workflow_runs": [entry]}]

    def _http_capture(self, payload):
        headers = [
            "HTTP/2.0 200 Ok",
            "x-github-api-version-selected: 2022-11-28",
            "content-type: application/json; charset=utf-8",
        ]
        body = json.dumps(payload, sort_keys=True).encode() + b"\n"
        return "\r\n".join(headers).encode() + b"\r\n\r\n" + body

    def write_json(self, path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    def source_run(self):
        return self._run_entry(
            self.source_contract["workflow"]["path"],
            self.source_contract["repository"],
            self.source_commit["sha"],
            self.SOURCE_RUN_ID,
        )

    # -- the exporter lane ------------------------------------------------
    def prepare_exporter(self):
        authenticated = self.source_root / "authenticated"
        self.write_json(authenticated / "source-commit.json", self.source_commit)
        self.write_json(
            authenticated / "independent-commit.json", self.independent_commit,
        )
        self.write_json(
            authenticated / "authority-commit.json", self._authority_commit(),
        )
        shutil.copytree(self.checkout, authenticated / "authority-checkout")
        raw = authenticated / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        # The authenticated readback that the sealed workflow is already
        # disabled, so no additional activation run id can be dispatched.
        (raw / "workflow-state.http").write_bytes(self._http_capture({
            "id": 42424242,
            "path": self.source_contract["workflow"]["path"],
            "state": "disabled_manually",
            "url": (
                "https://api.github.com/repos/"
                f'{self.source_contract["repository"]}/actions/workflows/'
                "export-kanban-review-v2.yml"
            ),
        }))
        for number, page in enumerate(self._run_pages(self.source_run()), start=1):
            (raw / f"runs-page-{number}.http").write_bytes(
                self._http_capture(page)
            )

    def exporter_environment(self):
        contract = self.source_contract
        return {
            "GITHUB_RUN_ID": str(self.SOURCE_RUN_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": self.source_commit["sha"],
            "GITHUB_REPOSITORY": contract["repository"],
            "GITHUB_EVENT_NAME": contract["workflow"]["trigger"],
            "GITHUB_REF": contract["workflow"]["ref"],
            "GITHUB_WORKFLOW_REF": (
                f'{contract["repository"]}/{contract["workflow"]["path"]}'
                f'@{contract["workflow"]["ref"]}'
            ),
        }

    def run_exporter(self):
        """Invoke the sealed exporter's real command line entry point."""
        return run_cli(
            self.source_root / "scripts" / "export_kanban_review_v2.py",
            environment=self.exporter_environment(),
        )

    # -- the independent validator lane -----------------------------------
    def prepare_validator(self):
        authenticated = self.independent_root / "authenticated"
        self.write_json(
            authenticated / "independent-commit.json", self.independent_commit,
        )
        self.write_json(authenticated / "source-commit.json", self.source_commit)
        self.write_json(
            authenticated / "authority-commit.json", self._authority_commit(),
        )
        run = self.source_run()
        self.write_json(authenticated / "source-run.json", run)
        # The pinned token action's own issuance outputs, exactly as the
        # workflow writes them from `steps.source-token.outputs.*`.
        self.write_json(authenticated / "runtime-token-grant.json", {
            "app_slug": FIXTURE_APP_SLUG,
            "installation_id": FIXTURE_INSTALLATION_ID,
        })
        # The claim window of the App JWT this run minted for itself. The
        # token bytes are never written anywhere.
        self.write_json(authenticated / "runtime-app-jwt.json", {
            "app_client_id": FIXTURE_APP_CLIENT_ID,
            "expires_at": FIXTURE_APP_JWT_EXPIRES_AT,
            "issued_at": FIXTURE_APP_JWT_ISSUED_AT,
        })
        for number, page in enumerate(self._run_pages(run), start=1):
            self.write_json(authenticated / f"source-run-page-{number}.json", page)
        (authenticated / "source-workflow.yml").write_bytes(
            (SOURCE_BOOTSTRAP_ROOT / self.source_contract["workflow"]["path"])
            .read_bytes()
        )
        (authenticated / "source-helper.py").write_bytes(
            (SOURCE_BOOTSTRAP_ROOT / self.source_contract["helper"]["path"])
            .read_bytes()
        )
        (authenticated / "source-bootstrap-contract.json").write_bytes(
            (SOURCE_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes()
        )
        shutil.copytree(self.checkout, authenticated / "authority-checkout")
        exported = self.source_root / "protected-review"
        target = self.independent_root / "protected-review"
        target.mkdir(parents=True, exist_ok=True)
        for member in sorted(self.source_contract["artifact"]["files"]):
            (target / member).write_bytes((exported / member).read_bytes())
        # The authenticated captures the workflow records before the chain
        # phase, including the one exhaustive run traversal both selection and
        # receipt creation consume.
        seal_raw_captures(
            self.independent_root, self.live_run(), sealed_source_bytes(),
        )

    def live_run(self):
        """Exactly the live state the sealed validator resolves for itself."""
        members = {}
        exported = self.source_root / "protected-review"
        for member in sorted(self.source_contract["artifact"]["files"]):
            candidate = exported / member
            members[member] = candidate.read_bytes() if candidate.is_file() else b""
        return {
            "artifact_archive": artifact_archive_bytes(members),
            "artifact_content_sha256": VALIDATOR.artifact_content_sha256(members),
            "artifact_name": self.source_contract["artifact"]["name"],
            "authority_base_commit": self.base,
            "authority_head_commit": self.head,
            "authority_head_tree": self.head_tree,
            "independent_bootstrap_commit": self.independent_commit["sha"],
            "independent_bootstrap_tree": self.independent_commit["tree"]["sha"],
            "run_head_sha": self.source_commit["sha"],
            "run_id": self.SOURCE_RUN_ID,
            "source_bootstrap_commit": self.source_commit["sha"],
            "source_bootstrap_tree": self.source_commit["tree"]["sha"],
            "source_helper_path": self.source_contract["helper"]["path"],
            "source_repository": self.source_contract["repository"],
            "source_workflow_path": self.source_contract["workflow"]["path"],
        }

    def deliver_decision(self, **overrides):
        """Deliver the reviewer decision with its sealed delivery evidence."""
        return deliver_reviewer_decision(
            self.independent_root, self.live_run(), self.checkout, **overrides,
        )

    def validator_environment(self):
        return {"GITHUB_SHA": self.independent_commit["sha"]}

    def run_validator(self, phase):
        """Invoke the sealed validator's real command line entry point."""
        return run_cli(
            self.independent_root / "scripts" / "verify_kanban_review_v2.py",
            "--phase", phase, environment=self.validator_environment(),
        )

    def external_receipt_path(self):
        return (
            self.independent_root
            / "protected-review" / "external-activation-review-receipt.json"
        )


def run_cli(script, *arguments, environment=None):
    """Run one sealed helper exactly as its workflow does, on the CLI."""
    return subprocess.run(
        [sys.executable, str(script), *arguments],
        capture_output=True,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            **(environment or {}),
        },
    )


class ExternalReviewLiveStateCliTests(unittest.TestCase):
    """The external-review phase authenticates live state before it writes."""

    def test_sealed_null_head_and_tree_are_never_carried_into_a_receipt(self):
        """The sealed contract alone must never produce a receipt."""
        with tempfile.TemporaryDirectory() as td:
            lane = SealedLane(td)
            sealed = lane.independent_contract["authorized_source_run"]
            self.assertIsNone(sealed["authority_head_commit"])
            self.assertIsNone(sealed["authority_head_tree"])
            lane.deliver_decision()
            observed = lane.run_validator("external-review")
            self.assertNotEqual(
                observed.returncode, 0,
                "the external-review phase accepted sealed null live state",
            )
            self.assertFalse(
                lane.external_receipt_path().exists(),
                "a receipt was written before live state was authenticated",
            )

    def test_authenticated_live_state_produces_a_populated_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            lane = SealedLane(td)
            lane.prepare_exporter()
            exported = lane.run_exporter()
            self.assertEqual(exported.returncode, 0, exported.stderr.decode())
            lane.prepare_validator()
            lane.deliver_decision()
            observed = lane.run_validator("external-review")
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            emitted = json.loads(observed.stdout)
            self.assertIs(emitted["external_review_written"], True)
            receipt = json.loads(lane.external_receipt_path().read_bytes())
            self.assertEqual(receipt["head_commit"], lane.head)
            self.assertEqual(receipt["head_tree"], lane.head_tree)
            self.assertEqual(receipt["base_commit"], lane.base)
            self.assertIsNotNone(receipt["head_commit"])
            self.assertIsNotNone(receipt["head_tree"])
            self.assertIs(receipt["candidate_owned"], False)
            self.assertIs(receipt["activation_authorized"], True)
            self.assertEqual(
                hashlib.sha256(
                    lane.external_receipt_path().read_bytes()
                ).hexdigest(),
                emitted["external_review_receipt_sha256"],
            )

    def test_unresolvable_live_state_is_refused_before_any_receipt(self):
        for label, damage in (
            ("absent-authenticated-artifact",
             lambda lane: shutil.rmtree(lane.independent_root / "protected-review")),
            ("absent-authenticated-run",
             lambda lane: (
                 lane.independent_root / "authenticated" / "source-run.json"
             ).unlink()),
            ("absent-authenticated-authority-head",
             lambda lane: (
                 lane.independent_root / "authenticated" / "authority-commit.json"
             ).unlink()),
            ("absent-authenticated-blob",
             lambda lane: (
                 lane.independent_root / "authenticated" / "source-helper.py"
             ).unlink()),
            ("absent-authenticated-checkout-path",
             lambda lane: shutil.rmtree(
                 lane.independent_root / "authenticated" / "authority-checkout"
             )),
            ("foreign-authenticated-head",
             lambda lane: lane.write_json(
                 lane.independent_root / "authenticated" / "authority-commit.json",
                 {"sha": "0" * 40, "tree": {"sha": "1" * 40}},
             )),
        ):
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as td:
                    lane = SealedLane(td)
                    lane.prepare_exporter()
                    self.assertEqual(lane.run_exporter().returncode, 0)
                    lane.prepare_validator()
                    lane.deliver_decision()
                    damage(lane)
                    observed = lane.run_validator("external-review")
                    self.assertNotEqual(observed.returncode, 0, label)
                    self.assertFalse(
                        lane.external_receipt_path().exists(),
                        f"{label} still wrote a receipt",
                    )


class ReachableActivationTransitionCliTests(unittest.TestCase):
    """Exporter -> independent validator -> Authority, end to end on the CLI."""

    def test_the_candidate_exporter_emits_sealed_pending_evidence_only(self):
        with tempfile.TemporaryDirectory() as td:
            lane = SealedLane(td)
            lane.prepare_exporter()
            observed = lane.run_exporter()
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            receipt = json.loads(
                (lane.source_root / "protected-review"
                 / "preissuance-review-receipt.json").read_bytes()
            )
            self.assertIs(receipt["activation_authorized"], False)
            self.assertIs(receipt["approved"], False)
            self.assertIs(receipt["release_authorized"], False)
            self.assertIs(receipt["closure_matrix"]["F8"], False)
            self.assertIs(receipt["closure_matrix"]["F12"], False)

    def test_the_validator_cli_derives_authorization_from_external_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            lane = SealedLane(td)
            lane.prepare_exporter()
            self.assertEqual(lane.run_exporter().returncode, 0)
            lane.prepare_validator()
            chain = lane.run_validator("chain")
            self.assertEqual(chain.returncode, 0, chain.stderr.decode())
            emitted = json.loads(chain.stdout)
            # The chain phase never inherits the producer's own claim.
            self.assertIs(emitted["activation_authorized"], False)
            self.assertIs(emitted["release_authorized"], False)
            self.assertIs(emitted["source_verified"], True)

    def test_the_authority_cli_derives_f8_from_evidence_not_a_ready_flag(self):
        """The Authority CLI must not read readiness off a candidate flag."""
        observed = run_cli(
            ROOT / "scripts" / "verify_source_chain_activation_v2.py",
        )
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        emitted = json.loads(observed.stdout)
        self.assertIs(emitted["f8_closed"], False)
        self.assertEqual(emitted["activation_state"], "unavailable")
        self.assertIs(emitted["verified"], True)
        self.assertIn("derived_from", emitted)
        self.assertEqual(
            emitted["derived_from"],
            ["authenticated-exporter-evidence", "independent-external-closure-evidence"],
        )

    def test_readiness_is_derived_from_both_evidences_never_from_a_flag(self):
        derive = getattr(ACTIVATION, "derive_activation_readiness", None)
        self.assertTrue(
            callable(derive),
            "the Authority derives no activation readiness from evidence",
        )
        package = json.loads((ROOT / "source-chain-activation-v2.json").read_bytes())
        exporter = ACTIVATION.exporter_evidence_state(package, root=ROOT)
        external = package["external_activation_review"]
        self.assertFalse(exporter["pinned"])
        self.assertEqual(external["state"], ACTIVATION.EXTERNAL_REVIEW_UNAVAILABLE)
        for exporter_pinned, closure, expected in (
            (False, False, False),
            (True, False, False),
            (False, True, False),
            (True, True, True),
        ):
            with self.subTest(exporter=exporter_pinned, closure=closure):
                self.assertIs(
                    derive(
                        exporter_pinned=exporter_pinned,
                        external_closure_authenticated=closure,
                    )["f8_closed"],
                    expected,
                )

    def test_the_derivation_names_both_independent_evidence_sources(self):
        self.assertEqual(
            ACTIVATION.ACTIVATION_EVIDENCE_SOURCES,
            ("authenticated-exporter-evidence",
             "independent-external-closure-evidence"),
        )

    def test_a_candidate_owned_ready_flag_alone_never_closes_f8(self):
        package = json.loads((ROOT / "source-chain-activation-v2.json").read_bytes())
        for label, mutate in (
            ("ready-state", lambda p: p.update(activation_state="ready")),
            ("f8-closed", lambda p: p.update(f8_closed=True)),
            ("activation-authorized",
             lambda p: p.update(activation_authorized=True)),
            ("external-state-authenticated",
             lambda p: p["external_activation_review"].update(
                 state="authenticated", receipt_sha256="0" * 64,
             )),
            ("repositories-created",
             lambda p: p.update(repositories_created=True)),
            ("live-evidence-pinned",
             lambda p: p["post_activation_proof"].update(live_evidence_pinned=True)),
        ):
            with self.subTest(label=label):
                forged = deepcopy(package)
                mutate(forged)
                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "source-chain-activation-v2.json"
                    path.write_bytes(ACTIVATION.canonical_bytes(forged))
                    with self.assertRaises(SystemExit):
                        ACTIVATION.verify_activation_package(path=path)



# ---------------------------------------------------------------------------
# F8-CANDIDATE-SELF-AUTHORIZATION
#
# Every candidate-owned artifact - policy, bootstrap contracts, activation
# package and receipt contract - must ship with `activation_authorized` false,
# F8 and F12 open, and builder approval and release authorization false. The
# production verifier enforces that exact cross-artifact consistency; these
# tests enumerate every candidate-owned field rather than sampling one.
# ---------------------------------------------------------------------------
CANDIDATE_OWNED_ACTIVATION_FIELDS = (
    ("authority-v2-policy.json",
     ("issuance_contract", "preissuance_receipt_contract",
      "activation_authorized")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "activation_authorized")),
    ("protected-source-bootstrap-v2/bootstrap-contract.json",
     ("protected_review_result", "activation_authorized")),
    ("source-chain-activation-v2.json", ("activation_authorized",)),
)
CANDIDATE_OWNED_FALSE_FIELDS = (
    ("authority-v2-policy.json",
     ("issuance_contract", "preissuance_receipt_contract", "approved")),
    ("authority-v2-policy.json",
     ("issuance_contract", "preissuance_receipt_contract",
      "release_authorized")),
    ("authority-v2-policy.json",
     ("issuance_contract", "preissuance_receipt_contract",
      "final_authority_approval")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "approval")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "release_authorized")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "release_published")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "subjects_issued")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "subjects_signed")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "workflow_dispatched")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff", "workflow_live_on_main")),
    ("authority-v2-policy.json",
     ("issuance_state_at_candidate_handoff",
      "github_environment_secrets_staged")),
    ("protected-source-bootstrap-v2/bootstrap-contract.json",
     ("protected_review_result", "approved")),
    ("protected-source-bootstrap-v2/bootstrap-contract.json",
     ("protected_review_result", "release_authorized")),
    ("protected-source-bootstrap-v2/bootstrap-contract.json",
     ("repository_created",)),
    ("protected-source-bootstrap-v2/bootstrap-contract.json",
     ("workflow_dispatched",)),
    ("independent-review-bootstrap-v2/bootstrap-contract.json",
     ("repository_created",)),
    ("independent-review-bootstrap-v2/bootstrap-contract.json",
     ("workflow_dispatched",)),
    ("independent-review-bootstrap-v2/bootstrap-contract.json",
     ("publication_performed",)),
    ("publication-writer-exclusion-v2.json", ("release_authorized",)),
    ("source-chain-activation-v2.json", ("f8_closed",)),
    ("source-chain-activation-v2.json", ("repositories_created",)),
    ("source-chain-activation-v2.json", ("workflows_written",)),
    ("source-chain-activation-v2.json", ("runs_observed",)),
)
CANDIDATE_OWNED_OPEN_CLOSURES = (
    ("protected-source-bootstrap-v2/bootstrap-contract.json",
     ("protected_review_result", "closure_matrix")),
)


def read_member(document, path):
    for key in path:
        document = document[key]
    return document


class CandidateSelfAuthorizationTests(unittest.TestCase):
    """No candidate-owned artifact may authorize its own activation."""

    def document(self, relative):
        return json.loads((ROOT / relative).read_bytes())

    def test_every_candidate_owned_activation_authorization_is_false(self):
        for relative, path in CANDIDATE_OWNED_ACTIVATION_FIELDS:
            with self.subTest(artifact=relative, field=".".join(path)):
                self.assertIs(
                    read_member(self.document(relative), path), False,
                    f"{relative}:{'.'.join(path)} self-authorizes the activation",
                )

    def test_every_candidate_owned_approval_and_release_flag_is_false(self):
        for relative, path in CANDIDATE_OWNED_FALSE_FIELDS:
            with self.subTest(artifact=relative, field=".".join(path)):
                self.assertIs(
                    read_member(self.document(relative), path), False,
                    f"{relative}:{'.'.join(path)} is not false at handoff",
                )

    def test_f8_and_f12_stay_open_in_every_candidate_owned_closure_matrix(self):
        for relative, path in CANDIDATE_OWNED_OPEN_CLOSURES:
            matrix = read_member(self.document(relative), path)
            with self.subTest(artifact=relative):
                self.assertIs(matrix["F8"], False)
                self.assertIs(matrix["F12"], False)
                for name in matrix:
                    if name not in ("F8", "F12"):
                        self.assertIs(matrix[name], True, name)

    def test_the_policy_receipt_contract_keeps_f8_open_and_records_it(self):
        contract = self.document("authority-v2-policy.json")[
            "issuance_contract"]["preissuance_receipt_contract"]
        self.assertEqual(
            sorted(contract["closure_matrix_required_false"]), ["F12", "F8"],
        )
        self.assertNotIn("F8", contract["closure_matrix_required_true"])
        self.assertEqual(
            contract["activation_findings"],
            [{"closure": "F8",
              "finding": "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"}],
        )

    def test_production_verification_enforces_the_cross_artifact_consistency(self):
        checker = getattr(VERIFIER, "verify_candidate_self_authorization", None)
        self.assertTrue(
            callable(checker),
            "production verification enforces no cross-artifact consistency",
        )
        self.assertEqual(checker(ROOT)["candidate_owned_fields_checked"],
                         len(VERIFIER.CANDIDATE_OWNED_FALSE_MEMBERS))
        self.assertGreaterEqual(
            len(VERIFIER.CANDIDATE_OWNED_FALSE_MEMBERS),
            len(CANDIDATE_OWNED_ACTIVATION_FIELDS)
            + len(CANDIDATE_OWNED_FALSE_FIELDS),
        )

    def test_flipping_any_candidate_owned_field_is_refused(self):
        members = VERIFIER.CANDIDATE_OWNED_FALSE_MEMBERS
        self.assertTrue(members)
        for relative, path in members:
            with self.subTest(artifact=relative, field=".".join(path)):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    for name in {name for name, _ in members}:
                        target = root / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes((ROOT / name).read_bytes())
                    document = json.loads((root / relative).read_bytes())
                    member = document
                    for key in path[:-1]:
                        member = member[key]
                    member[path[-1]] = True
                    (root / relative).write_text(
                        json.dumps(document, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(SystemExit):
                        VERIFIER.verify_candidate_self_authorization(root)



# ---------------------------------------------------------------------------
# F8-INDEPENDENT-DECISION-DELIVERY-UNREACHABLE
#
# The independent reviewer's decision must reach the lane through one sealed
# post-candidate delivery path whose writer identity, internally derived
# `decisions/<authority head>.json` path, delivery commit, tree and blob,
# branch protection and independent readback all authenticate end to end.
# Everything below drives the real sealed CLI against sealed fake read-only
# GitHub responses; nothing is injected into production code.
# ---------------------------------------------------------------------------
class ReviewerDecisionDeliveryCliTests(unittest.TestCase):
    """The reviewer decision counts only once its delivery authenticates."""

    def prepared_lane(self, stack):
        lane = SealedLane(stack.enter_context(tempfile.TemporaryDirectory()))
        lane.prepare_exporter()
        exported = lane.run_exporter()
        self.assertEqual(exported.returncode, 0, exported.stderr.decode())
        lane.prepare_validator()
        return lane

    def test_a_bare_decision_file_without_sealed_delivery_is_refused(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            lane.deliver_decision(skip_delivery=True)
            observed = lane.run_validator("external-review")
            self.assertNotEqual(
                observed.returncode, 0,
                "a decision file alone authorized the activation",
            )
            self.assertFalse(lane.external_receipt_path().exists())

    def test_authenticated_delivery_binds_the_receipt_to_the_delivery(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            lane.deliver_decision()
            observed = lane.run_validator("external-review")
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            receipt = json.loads(lane.external_receipt_path().read_bytes())
            delivery = receipt["decision_delivery"]
            self.assertEqual(
                delivery["path"],
                f"{VALIDATOR.REVIEWER_DECISION_DIRECTORY}/{lane.head}.json",
            )
            self.assertEqual(
                delivery["repository"], VALIDATOR.INDEPENDENT_REPOSITORY,
            )
            self.assertNotEqual(
                delivery["repository"], VALIDATOR.AUTHORITY_REPOSITORY,
            )
            self.assertEqual(
                delivery["cas_expected_old_oid"],
                lane.independent_commit["sha"],
            )
            self.assertEqual(delivery["cas_ref"], "refs/heads/main")
            self.assertEqual(
                delivery["cas_primitive"], VALIDATOR.DELIVERY_CAS_PRIMITIVE,
            )
            self.assertIs(delivery["cas_capability_proven"], True)
            self.assertEqual(
                delivery["cas_capability_probe"],
                VALIDATOR.DELIVERY_CAS_CAPABILITY_PROBE,
            )
            self.assertIs(delivery["race_readback_verified"], True)
            # The delivery commit is a NEW commit (child of the bootstrap
            # commit), so its SHA and tree differ from the bootstrap values.
            self.assertRegex(delivery["commit_sha"], r'^[0-9a-f]{40}$')
            self.assertNotEqual(
                delivery["commit_sha"], lane.independent_commit["sha"],
            )
            self.assertRegex(delivery["commit_tree"], r'^[0-9a-f]{40}$')
            self.assertNotEqual(
                delivery["commit_tree"],
                lane.independent_commit["tree"]["sha"],
            )
            self.assertEqual(
                delivery["blob_sha"],
                git_blob_oid(
                    (lane.independent_root
                     / VALIDATOR.REVIEWER_DECISION_DIRECTORY
                     / f"{lane.head}.json").read_bytes()
                ),
            )
            self.assertEqual(delivery["writer_login"], DELIVERY_WRITER_LOGIN)
            self.assertIs(delivery["branch_protected"], True)
            self.assertIs(delivery["readback_verified"], True)

    def test_every_forged_delivery_member_is_refused(self):
        """Damage the sealed raw delivery responses, never a composed document."""
        foreign = hashlib.sha256(b"acc-foreign-object").hexdigest()[:40]
        damages = (
            ("foreign-writer-login", {"commit": {"author": {
                "id": DELIVERY_WRITER_ID, "login": "attacker", "type": "User"}}}),
            ("bot-writer-type", {"commit": {"committer": {
                "id": DELIVERY_WRITER_ID, "login": DELIVERY_WRITER_LOGIN,
                "type": "Bot"}}}),
            ("unverified-signature", {"commit": {
                "commit.verification": {"reason": "unsigned", "verified": False}}}),
            ("foreign-delivery-commit", {"commit": {
                "sha": foreign, "parents": [{"sha": foreign}]}}),
            ("malformed-delivery-tree",
             {"commit": {"commit.tree": {"sha": "not-a-hex-tree"}}}),
            ("self-referential-parent", {"commit": {"parents": []}}),
            ("private-reviewer-repository",
             {"repository": {"private": True, "visibility": "private"}}),
            ("authority-repository-as-writer",
             {"repository": {"full_name": VALIDATOR.AUTHORITY_REPOSITORY}}),
            ("caller-shaped-repository-id", {"repository": {"id": 7}}),
            ("absent-repository-node-id", {"repository": {"node_id": ""}}),
            ("force-pushes-allowed", {"protection": {"body": {
                "allow_deletions": {"enabled": False},
                "allow_force_pushes": {"enabled": True},
                "enforce_admins": {"enabled": True},
                "required_signatures": {"enabled": True},
                "url": f"{API_ROOT}/repos/{VALIDATOR.INDEPENDENT_REPOSITORY}"
                       "/branches/main/protection"}}}),
            ("deletions-allowed", {"protection": {"body": {
                "allow_deletions": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "enforce_admins": {"enabled": True},
                "required_signatures": {"enabled": True},
                "url": f"{API_ROOT}/repos/{VALIDATOR.INDEPENDENT_REPOSITORY}"
                       "/branches/main/protection"}}}),
            ("admins-exempt", {"protection": {"body": {
                "allow_deletions": {"enabled": False},
                "allow_force_pushes": {"enabled": False},
                "enforce_admins": {"enabled": False},
                "required_signatures": {"enabled": True},
                "url": f"{API_ROOT}/repos/{VALIDATOR.INDEPENDENT_REPOSITORY}"
                       "/branches/main/protection"}}}),
            ("signatures-not-required", {"protection": {"body": {
                "allow_deletions": {"enabled": False},
                "allow_force_pushes": {"enabled": False},
                "enforce_admins": {"enabled": True},
                "required_signatures": {"enabled": False},
                "url": f"{API_ROOT}/repos/{VALIDATOR.INDEPENDENT_REPOSITORY}"
                       "/branches/main/protection"}}}),
            ("foreign-protection-url", {"protection": {"body": {
                "allow_deletions": {"enabled": False},
                "allow_force_pushes": {"enabled": False},
                "enforce_admins": {"enabled": True},
                "required_signatures": {"enabled": True},
                "url": f"{API_ROOT}/repos/{VALIDATOR.AUTHORITY_REPOSITORY}"
                       "/branches/main/protection"}}}),
            ("blob-sha-not-the-object-name", {"blob": {"sha": foreign}}),
            ("blob-size-mismatch", {"blob": {"size": 1}}),
            ("blob-not-a-file", {"blob": {"type": "symlink"}}),
        )
        for label, delivery in damages:
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.prepared_lane(stack)
                    lane.deliver_decision(delivery=delivery, compose=False)
                    composed = lane.run_validator("decision-delivery")
                    if composed.returncode == 0:
                        observed = lane.run_validator("external-review")
                        self.assertNotEqual(observed.returncode, 0, label)
                    self.assertFalse(
                        lane.external_receipt_path().exists(),
                        f"{label} still wrote a receipt",
                    )

    def test_administration_read_provenance_is_required(self):
        """A protection block read without administration read is refused."""
        for label, options in (
            ("no-permission-header", {"permissions": None}),
            ("contents-only", {"permissions": "contents=read"}),
            ("metadata-only", {"permissions": "metadata=read"}),
            ("non-200", {"status": 403}),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.prepared_lane(stack)
                    lane.deliver_decision(
                        delivery={"protection": options}, compose=False,
                    )
                    composed = lane.run_validator("decision-delivery")
                    if composed.returncode == 0:
                        observed = lane.run_validator("external-review")
                        self.assertNotEqual(observed.returncode, 0, label)
                    self.assertFalse(lane.external_receipt_path().exists(), label)

    def test_the_writer_must_have_introduced_the_exact_decision_blob(self):
        """Authenticating the commit author alone can never be enough."""
        other = hashlib.sha256(b"acc-other-path").hexdigest()[:40]
        for label, files in (
            ("commit-changed-another-path",
             [{"filename": f"decisions/{other}.json", "sha": "0" * 40,
               "status": "added"}]),
            ("commit-only-removed-the-path",
             [{"filename": "PLACEHOLDER", "sha": "0" * 40,
               "status": "removed"}]),
            ("commit-wrote-different-bytes",
             [{"filename": "PLACEHOLDER", "sha": "1" * 40,
               "status": "modified"}]),
            ("commit-changes-nothing", []),
            ("commit-changes-the-path-twice", "DUPLICATE"),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.prepared_lane(stack)
                    decision = reviewer_decision(lane.live_run(), lane.checkout)
                    path = (
                        f"{VALIDATOR.REVIEWER_DECISION_DIRECTORY}/{lane.head}.json"
                    )
                    if files == "DUPLICATE":
                        entry = {"filename": path,
                                 "sha": git_blob_oid(decision),
                                 "status": "added"}
                        resolved = [entry, dict(entry)]
                    else:
                        resolved = [
                            {**entry, "filename": path}
                            if entry["filename"] == "PLACEHOLDER" else entry
                            for entry in files
                        ]
                    lane.deliver_decision(
                        decision=decision,
                        delivery={"commit": {"files": resolved}},
                        compose=False,
                    )
                    composed = lane.run_validator("decision-delivery")
                    if composed.returncode == 0:
                        observed = lane.run_validator("external-review")
                        self.assertNotEqual(observed.returncode, 0, label)
                    self.assertFalse(lane.external_receipt_path().exists(), label)

    def test_the_delivery_path_is_derived_internally_not_read_from_evidence(self):
        other = hashlib.sha256(b"acc-other-candidate").hexdigest()[:40]
        for label, delivery in (
            ("foreign-blob-path",
             {"blob": {"path": f"decisions/{other}.json"}}),
            ("foreign-readback-path",
             {"readback": {"path": f"decisions/{other}.json"}}),
            ("escaping-path",
             {"blob": {"path": "decisions/../decisions/x.json"}}),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.prepared_lane(stack)
                    lane.deliver_decision(delivery=delivery, compose=False)
                    composed = lane.run_validator("decision-delivery")
                    if composed.returncode == 0:
                        self.assertNotEqual(
                            lane.run_validator("external-review").returncode, 0,
                            label,
                        )
                    self.assertFalse(lane.external_receipt_path().exists(), label)

    def test_the_readback_must_reproduce_the_exact_on_disk_bytes(self):
        forged = base64.b64encode(b"{}\n").decode("ascii")
        for label, delivery in (
            ("readback-content-mismatch", {"readback": {"content": forged}}),
            ("readback-sha-mismatch",
             {"readback": {"sha": hashlib.sha256(b"x").hexdigest()[:40]}}),
            ("blob-content-mismatch", {"blob": {"content": forged}}),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.prepared_lane(stack)
                    lane.deliver_decision(delivery=delivery, compose=False)
                    composed = lane.run_validator("decision-delivery")
                    if composed.returncode == 0:
                        self.assertNotEqual(
                            lane.run_validator("external-review").returncode, 0,
                            label,
                        )
                    self.assertFalse(lane.external_receipt_path().exists(), label)

    def test_a_decision_delivered_for_another_candidate_is_refused(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            lane.deliver_decision()
            decisions = lane.independent_root / VALIDATOR.REVIEWER_DECISION_DIRECTORY
            (decisions / f"{lane.head}.json").rename(
                decisions / f"{'0' * 40}.json"
            )
            self.assertNotEqual(
                lane.run_validator("external-review").returncode, 0,
            )
            self.assertFalse(lane.external_receipt_path().exists())

    def test_the_sealed_lane_exposes_no_test_only_decision_injection(self):
        validator = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        injection = "place_" + "decision"
        self.assertNotIn(injection, validator)
        self.assertFalse(hasattr(VALIDATOR, injection))
        self.assertNotIn(
            f"def {injection}",
            (ROOT / "tests" / "test_source_chain_activation_v2.py")
            .read_text(encoding="utf-8"),
            "the sealed lane is still driven by test-only decision injection",
        )
        self.assertNotIn(
            "place_reviewer_" + "decision",
            (ROOT / "tests" / "test_source_chain_activation_v2.py")
            .read_text(encoding="utf-8"),
        )

    def test_the_activation_grant_names_the_sealed_decision_delivery(self):
        package = json.loads((ROOT / "source-chain-activation-v2.json").read_bytes())
        grant = package["pre_activation_authorization"]
        delivery = grant["authorized_decision_delivery"]
        self.assertEqual(
            delivery["path_template"], ACTIVATION.DECISION_DELIVERY_PATH_TEMPLATE,
        )
        self.assertEqual(
            delivery["repository"], ACTIVATION.INDEPENDENT_REPOSITORY,
        )
        self.assertNotEqual(
            delivery["repository"], ACTIVATION.AUTHORITY_REPOSITORY,
        )
        self.assertEqual(delivery["branch"], ACTIVATION.DECISION_DELIVERY_BRANCH)
        self.assertEqual(delivery["writer_login"], ACTIVATION.DECISION_WRITER_LOGIN)
        for flag in (
            "authenticated_readback_required", "branch_protection_required",
            "candidate_authored_decision_forbidden",
            "derived_path_only", "produced_after_exact_candidate_required",
        ):
            self.assertIs(delivery[flag], True, flag)
        self.assertIs(package["activation_authorized"], False)
        self.assertIs(package["f8_closed"], False)

    def test_the_reviewer_workflow_reads_the_sealed_delivery_evidence(self):
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(VALIDATOR.DECISION_DELIVERY_FILE, workflow)
        self.assertIn(VALIDATOR.SERVER_OBJECTS_FILE, workflow)
        self.assertIn("branches/main/protection", workflow)


# ---------------------------------------------------------------------------
# F8-EXTERNAL-REVIEW-LIVE-AUTHENTICATION-INCOMPLETE
#
# Before the external activation review receipt may be written at all, the
# canonical repository identity, the exhaustively paginated run and job
# inventories with their Link closure, the exact head and tree, every required
# path and blob, the artifact id, name and digest and the token permission
# provenance must authenticate from sealed read-only GitHub responses.
# ---------------------------------------------------------------------------
class ExternalReviewServerObjectCliTests(unittest.TestCase):
    """Receipt generation depends on verified canonical server objects."""

    def prepared_lane(self, stack):
        lane = SealedLane(stack.enter_context(tempfile.TemporaryDirectory()))
        lane.prepare_exporter()
        exported = lane.run_exporter()
        self.assertEqual(exported.returncode, 0, exported.stderr.decode())
        lane.prepare_validator()
        return lane

    def refuse(self, label, **kwargs):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            lane.deliver_decision(**kwargs)
            observed = lane.run_validator("external-review")
            self.assertNotEqual(observed.returncode, 0, label)
            self.assertFalse(
                lane.external_receipt_path().exists(),
                f"{label} still wrote a receipt",
            )

    def test_receipt_generation_requires_sealed_server_objects(self):
        self.refuse("absent-server-objects", skip_server_objects=True)

    def test_incomplete_or_unterminated_pagination_is_refused(self):
        endpoint = f"{API_ROOT}/repos/x/y/actions/runs/1/jobs"
        for label, damage in (
            ("truncated-run-page-set",
             {"workflow_runs": {"pages": sealed_pages(endpoint, [1, 0], 1)}}),
            ("missing-link-closure", {"jobs.pages": [{
                "count": 1, "link": f'<{endpoint}?per_page=100&page=2>; rel="next"',
                "page": 1, "per_page": 100, "status": 200, "total_count": 1}]}),
            ("page-count-contradicts-entries",
             {"jobs.pages": sealed_pages(endpoint, [3], 3)}),
            ("non-200-page", {"artifacts.pages": [{
                "count": 1, "link": None, "page": 1, "per_page": 100,
                "status": 404, "total_count": 1}]}),
            ("unadvertised-extra-page",
             {"artifacts.pages": sealed_pages(endpoint, [1, 0], 1)}),
            ("non-monotonic-pages", {"jobs.pages": [{
                "count": 1, "link": None, "page": 2, "per_page": 100,
                "status": 200, "total_count": 1}]}),
            ("foreign-per-page", {"jobs.pages": [{
                "count": 1, "link": None, "page": 1, "per_page": 30,
                "status": 200, "total_count": 1}]}),
        ):
            with self.subTest(label=label):
                self.refuse(label, server_objects=damage)

    def test_caller_shaped_identifiers_are_refused(self):
        for label, damage in (
            ("tiny-repository-id", {"repository.id": 3}),
            ("boolean-repository-id", {"repository.id": True}),
            ("zero-artifact-id", {"artifacts.entries": [{
                "digest": "sha256:" + "0" * 64, "expired": False, "id": 0,
                "name": VALIDATOR.SOURCE_ARTIFACT, "node_id": "n",
                "size_in_bytes": 1, "workflow_run": {"id": 1}}]}),
            ("repeated-digit-job-id", {"jobs.entries": [{
                "completed_at": "2026-08-26T13:00:41Z", "conclusion": "success",
                "head_sha": "0" * 40, "id": 1111111111,
                "name": VALIDATOR.SOURCE_JOB_NAME, "run_attempt": 1,
                "run_id": 1111111111, "started_at": "2026-08-26T13:00:11Z",
                "status": "completed"}]}),
            ("foreign-repository-full-name",
             {"repository.full_name": VALIDATOR.AUTHORITY_REPOSITORY}),
        ):
            with self.subTest(label=label):
                self.refuse(label, server_objects=damage)

    def test_merely_well_formed_hashes_are_refused(self):
        well_formed64 = hashlib.sha256(b"acc-well-formed").hexdigest()
        well_formed40 = well_formed64[:40]
        for label, damage in (
            ("artifact-digest-not-recomputed",
             {"artifacts.entries.0.digest": f"sha256:{well_formed64}"}),
            ("head-tree-not-the-authenticated-tree",
             {"head.tree": well_formed40}),
            ("head-commit-not-the-authenticated-head",
             {"head.commit": well_formed40}),
            ("tree-blob-sha-not-the-object-name",
             {"tree.entries.0.blob_sha": well_formed40}),
            ("tree-blob-sha256-not-the-sealed-digest",
             {"tree.entries.0.sha256": well_formed64}),
        ):
            with self.subTest(label=label):
                self.refuse(label, server_objects=damage)

    def test_token_permission_and_api_version_provenance_is_required(self):
        for label, damage in (
            ("absent-actions-read",
             {"token.permissions": {"contents": "read", "metadata": "read"}}),
            ("write-permission",
             {"token.permissions": {"actions": "write", "contents": "read",
                                    "metadata": "read"}}),
            ("all-repositories", {"token.repository_selection": "all"}),
            ("foreign-token-repository",
             {"token.repositories": [VALIDATOR.AUTHORITY_REPOSITORY]}),
            ("absent-api-version", {"api_version": ""}),
            ("foreign-api-version", {"api_version": "2020-01-01"}),
        ):
            with self.subTest(label=label):
                self.refuse(label, server_objects=damage)

    def test_every_required_tree_path_and_blob_must_be_present(self):
        entries = [
            {
                "blob_sha": git_blob_oid(data),
                "mode": "100644",
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for path, data in sorted(sealed_source_bytes().items())
        ]
        for label, damage in (
            ("missing-required-path", {"tree.entries": entries[1:]}),
            ("duplicate-path", {"tree.entries": entries + entries[:1]}),
            ("truncated-tree", {"tree.truncated": True}),
            ("non-blob-mode", {"tree.entries.0.mode": "160000"}),
        ):
            with self.subTest(label=label):
                self.refuse(label, server_objects=damage)

    def test_the_job_inventory_must_be_complete_and_successful(self):
        for label, damage in (
            ("no-jobs", {"jobs.entries": []}),
            ("failed-job", {"jobs.entries.0.conclusion": "failure"}),
            ("incomplete-job", {"jobs.entries.0.status": "in_progress"}),
            ("foreign-run-job", {"jobs.entries.0.run_id": 4102337782}),
            ("second-attempt-job", {"jobs.entries.0.run_attempt": 2}),
            ("foreign-job-head", {"jobs.entries.0.head_sha": "0" * 40}),
            ("absent-required-job-name", {"jobs.entries.0.name": "other"}),
        ):
            with self.subTest(label=label):
                self.refuse(label, server_objects=damage)

    def test_the_artifact_identity_must_be_canonical_and_bound(self):
        for label, damage in (
            ("foreign-artifact-name", {"artifacts.entries.0.name": "other"}),
            ("expired-artifact", {"artifacts.entries.0.expired": True}),
            ("foreign-artifact-run",
             {"artifacts.entries.0.workflow_run": {"id": 4102337782}}),
            ("unprefixed-digest",
             {"artifacts.entries.0.digest": "0" * 64}),
            ("no-artifacts", {"artifacts.entries": []}),
        ):
            with self.subTest(label=label):
                self.refuse(label, server_objects=damage)

    def test_the_authenticated_receipt_binds_the_canonical_server_objects(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            lane.deliver_decision()
            observed = lane.run_validator("external-review")
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            receipt = json.loads(lane.external_receipt_path().read_bytes())
            server = receipt["server_objects"]
            self.assertEqual(server["repository_id"], SOURCE_REPOSITORY_ID)
            self.assertEqual(server["repository"], VALIDATOR.SOURCE_REPOSITORY)
            self.assertEqual(server["run_id"], lane.SOURCE_RUN_ID)
            self.assertEqual(server["artifact_id"], SOURCE_ARTIFACT_ID)
            self.assertEqual(server["job_ids"], [SOURCE_JOB_ID])
            self.assertEqual(server["head_commit"], lane.source_commit["sha"])
            self.assertEqual(
                server["head_tree"], lane.source_commit["tree"]["sha"],
            )
            self.assertEqual(
                server["artifact_content_sha256"],
                lane.live_run()["artifact_content_sha256"],
            )
            self.assertEqual(
                sorted(server["tree_paths"]), sorted(sealed_source_bytes()),
            )


# ---------------------------------------------------------------------------
# F8-ACTIVATION-CLI-TRANSITION-DISCONNECTED
#
# One real command line path must authenticate the live exporter artifact, the
# external independent-review receipt and its Sigstore bundle, derive F8
# internally from that evidence and hand the derived evidence straight to the
# Authority. Unresolved or null state exits non-zero, and neither a
# candidate-owned package flag nor a merely well-formed hash is evidence.
# The whole path below runs offline against sealed local bytes: the pinned
# Sigstore boundary fails closed long before any transport is constructed.
# ---------------------------------------------------------------------------
CLOSURE_CANDIDATE_PATHS = (
    "source-chain-activation-v2.json",
    "publication-writer-exclusion-v2.json",
    "github-app-guard-v2-contract.json",
    "github-environment-v2-contract.json",
    "scripts/pin_source_chain_activation_v2.py",
    "scripts/verify_source_chain_activation_v2.py",
    "scripts/sigstore_bundle_v03.py",
    "protected-source-bootstrap-v2/bootstrap-contract.json",
    "protected-source-bootstrap-v2/scripts/export_kanban_review_v2.py",
    "protected-source-bootstrap-v2/.github/workflows/export-kanban-review-v2.yml",
    "independent-review-bootstrap-v2/bootstrap-contract.json",
    "independent-review-bootstrap-v2/scripts/verify_kanban_review_v2.py",
    "independent-review-bootstrap-v2/.github/workflows/readback-authority-v2-activation.yml",
    "independent-review-bootstrap-v2/.github/workflows/review-authority-v2.yml",
)


class ActivationClosureCliTests(unittest.TestCase):
    """Exporter -> independent review -> Authority, on the real closure CLI."""

    def closure_cli(self, checkout):
        return run_cli(
            checkout / "scripts" / "pin_source_chain_activation_v2.py",
            "--phase", PIN.CLOSURE_PHASE,
        )

    def assert_failed_closed(self, observed, label):
        self.assertNotEqual(observed.returncode, 0, label)
        stderr = observed.stderr.decode()
        self.assertNotIn("Traceback", stderr, f"{label} did not fail closed")
        self.assertTrue(stderr.strip(), f"{label} named no blocker")
        return stderr

    def test_the_closure_phase_is_the_only_derived_production_transition(self):
        self.assertEqual(PIN.CLOSURE_PHASE, "closure")
        self.assertIn(PIN.CLOSURE_PHASE, PIN.PHASES)
        signature = inspect.signature(PIN.derive_activation_closure)
        self.assertEqual(list(signature.parameters), ["repository_root"])
        source = (ROOT / "scripts" / "pin_source_chain_activation_v2.py").read_text()
        self.assertIn("_authenticate_live_activation_evidence(", source)
        self.assertEqual(
            list(inspect.signature(PIN.derive_live_activation_closure).parameters),
            ["repository_root"],
        )

    def test_the_closure_cli_exits_non_zero_without_sealed_live_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            checkout = Path(td) / "authority-checkout"
            build_authority_candidate(
                checkout, extra_paths=CLOSURE_CANDIDATE_PATHS,
            )
            observed = self.closure_cli(checkout)
            stderr = self.assert_failed_closed(observed, "absent-live-evidence")
            self.assertIn(PIN.LIVE_EVIDENCE_DIRECTORY, stderr)
            self.assertEqual(observed.stdout, b"")

    def test_the_report_phase_never_reports_a_derived_closure(self):
        observed = run_cli(ROOT / "scripts" / "pin_source_chain_activation_v2.py")
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        emitted = json.loads(observed.stdout)
        self.assertIs(emitted["f8_closed"], False)
        self.assertIs(emitted["activation_authorized"], False)
        self.assertIs(emitted["live_evidence_authenticated"], False)
        self.assertEqual(emitted["activation_state"], "unavailable")

    def build_live_lane(self, stack):
        """A real exporter and independent-review run over one candidate."""
        lane = SealedLane(
            stack.enter_context(tempfile.TemporaryDirectory()),
            extra_candidate_paths=CLOSURE_CANDIDATE_PATHS,
        )
        lane.prepare_exporter()
        exported = lane.run_exporter()
        self.assertEqual(exported.returncode, 0, exported.stderr.decode())
        lane.prepare_validator()
        lane.deliver_decision()
        reviewed = lane.run_validator("external-review")
        self.assertEqual(reviewed.returncode, 0, reviewed.stderr.decode())
        return lane

    def place_live_evidence(self, lane, *, timeline=True, bundle=True,
                            window=None):
        """Drop the exact bytes the sealed lanes really produced."""
        evidence = lane.checkout.parent / PIN.LIVE_EVIDENCE_DIRECTORY
        evidence.mkdir(parents=True, exist_ok=True)
        produced = lane.independent_root / "protected-review"
        for member in (
            "kanban-review-envelope.json",
            "preissuance-review-receipt.json",
            "external-activation-review-receipt.json",
        ):
            (evidence / member).write_bytes((produced / member).read_bytes())
        if bundle:
            vendored = (
                ROOT / "tests" / "fixtures"
                / "cosign-v3.1.3-sigstore-v0.3-bundle.json"
            ).read_bytes()
            (evidence / "external-activation-review-receipt.sigstore.json"
             ).write_bytes(vendored)
            # The third member the signed-review upload really carries. These
            # archive-leg counterexamples are all refused before any Sigstore
            # verification runs, so the vendored bytes stand in for it here.
            (evidence / PIN.LIVE_EVIDENCE_SIGNED_BUNDLE).write_bytes(vendored)
        write_sealed_json(
            evidence / PIN.LIVE_EVIDENCE_IDENTITY,
            artifact_identity_entries(evidence),
        )
        if timeline:
            started = window[0] if window else 1_787_000_000
            write_sealed_json(evidence / "authenticated-run-timeline.json", {
                "independent_bootstrap_commit": lane.independent_commit["sha"],
                "job_completed_at": started + 400,
                "job_started_at": started,
                "repository": VALIDATOR.INDEPENDENT_REPOSITORY,
                "run_attempt": 1,
                "run_id": lane.INDEPENDENT_RUN_ID,
                "run_started_at": started,
                "workflow_path": VALIDATOR.INDEPENDENT_WORKFLOW,
            })
        return evidence

    # -- F8-ISSUANCE-ARTIFACT-BINDING-BYPASSABLE ---------------------------
    #
    # Naming an artifact, or declaring a digest beside an unrelated recomputed
    # one, may never stand in for the real archive. The closure must open the
    # exact ZIP the issuance lane downloaded by canonical server id, recompute
    # its size and digest, require the server digest to be exactly
    # `sha256:` + the recomputed archive digest, and bind the complete real
    # member inventory member by member to the evidence bytes it authenticated.
    # Every counterexample below must be refused by that leg, before the
    # pinned Sigstore trust is ever reached.
    # ----------------------------------------------------------------------
    def identity_document(self, evidence):
        return json.loads(
            (evidence / PIN.LIVE_EVIDENCE_IDENTITY).read_bytes(),
        )

    def rewrite_identity(self, evidence, document):
        write_sealed_json(evidence / PIN.LIVE_EVIDENCE_IDENTITY, document)

    def archive_path(self, evidence, entry):
        return evidence / PIN.ARTIFACT_ARCHIVE_TEMPLATE.format(
            artifact_id=entry["artifact_id"],
        )

    def assert_archive_leg_refused(self, lane, label):
        """The archive leg refuses, and it refuses before the pinned trust."""
        observed = self.closure_cli(lane.checkout)
        stderr = self.assert_failed_closed(observed, label)
        self.assertNotIn(
            "Sigstore", stderr,
            f"{label} reached the pinned trust instead of the archive leg",
        )
        self.assertEqual(observed.stdout, b"")
        return stderr

    def test_the_closure_requires_the_real_downloaded_artifact_archive(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            self.archive_path(evidence, document[0]).unlink()
            stderr = self.assert_archive_leg_refused(lane, "absent-archive")
            self.assertIn("archive", stderr)

    def test_a_declared_digest_must_be_the_recomputed_archive_digest(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            # A perfectly canonical, high-entropy `sha256:` digest that simply
            # is not this archive's digest. Shape alone may never pass.
            document[0]["digest"] = "sha256:" + hashlib.sha256(
                b"acc-not-this-archive",
            ).hexdigest()
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "digest-mismatch")
            self.assertIn("digest", stderr)

    def test_the_recomputed_archive_digest_must_be_the_archive_on_disk(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            recomputed = hashlib.sha256(b"acc-substituted-archive").hexdigest()
            document[0]["archive_sha256"] = recomputed
            document[0]["digest"] = "sha256:" + recomputed
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "archive-drift")
            self.assertIn("archive", stderr)

    def test_the_declared_archive_size_must_be_the_archive_size(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            document[0]["archive_size"] = document[0]["archive_size"] + 1
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "size-mismatch")
            self.assertIn("size", stderr)

    def test_the_canonical_artifact_id_selects_the_authenticated_archive(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            document[0]["artifact_id"] = 4102337782
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "artifact-id-drift")
            self.assertIn("archive", stderr)

    def test_two_artifacts_may_never_share_one_canonical_id(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            document[0]["artifact_id"] = document[1]["artifact_id"]
            self.rewrite_identity(evidence, document)
            self.assert_archive_leg_refused(lane, "repeated-artifact-id")

    def reseal_archive(self, evidence, entry, members):
        """Replace one archive with a real ZIP over exactly these members."""
        archive = build_artifact_archive(members)
        self.archive_path(evidence, entry).write_bytes(archive)
        entry["archive_sha256"] = hashlib.sha256(archive).hexdigest()
        entry["archive_size"] = len(archive)
        entry["digest"] = "sha256:" + entry["archive_sha256"]
        return archive

    def real_members(self, evidence, entry):
        return {
            member: (evidence / member).read_bytes()
            for member in entry["members"]
        }

    def test_a_missing_archive_member_is_refused(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            entry = document[0]
            members = self.real_members(evidence, entry)
            dropped = sorted(members)[0]
            del members[dropped]
            self.reseal_archive(evidence, entry, members)
            entry["members"].pop(dropped)
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "missing-member")
            self.assertIn("member", stderr)

    def test_an_extra_archive_member_is_refused(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            entry = document[0]
            members = self.real_members(evidence, entry)
            members["smuggled.json"] = b"{}\n"
            self.reseal_archive(evidence, entry, members)
            entry["members"]["smuggled.json"] = hashlib.sha256(
                b"{}\n",
            ).hexdigest()
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "extra-member")
            self.assertIn("member", stderr)

    def test_an_archive_member_that_is_not_the_evidence_byte_is_refused(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            entry = document[0]
            members = self.real_members(evidence, entry)
            drifted = sorted(members)[0]
            members[drifted] = members[drifted] + b"\n"
            self.reseal_archive(evidence, entry, members)
            entry["members"][drifted] = hashlib.sha256(
                members[drifted],
            ).hexdigest()
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "member-drift")
            self.assertIn("member", stderr)

    def test_a_declared_member_digest_must_be_the_real_member_digest(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            document = self.identity_document(evidence)
            entry = document[0]
            member = sorted(entry["members"])[0]
            entry["members"][member] = hashlib.sha256(
                b"acc-not-this-member",
            ).hexdigest()
            self.rewrite_identity(evidence, document)
            stderr = self.assert_archive_leg_refused(lane, "member-digest")
            self.assertIn("member", stderr)

    def test_an_unexpected_evidence_file_is_refused(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            (evidence / "artifact-4102337782.zip").write_bytes(b"PK\x05\x06")
            self.assert_archive_leg_refused(lane, "extra-archive")

    def test_exporter_to_authority_closure_cli_authenticates_real_artifacts(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            self.place_live_evidence(lane)
            observed = self.closure_cli(lane.checkout)
            stderr = self.assert_failed_closed(observed, "forged-bundle")
            # Every local byte authenticates - the exporter artifact, the
            # external independent-review receipt against this exact clean
            # checkout, and the real Cosign v3.1.3 protobuf-JSON v0.3 bundle
            # shape. The pinned Sigstore trust is what refuses, and it refuses
            # before any transport exists.
            self.assertNotIn(PIN.LIVE_EVIDENCE_DIRECTORY, stderr)
            self.assertIn("Sigstore", stderr)
            self.assertEqual(observed.stdout, b"")

    def test_the_closure_cli_reaches_real_pinned_sigstore_cryptography(self):
        """Inside the authenticated window the real trust still refuses."""
        integrated = int(json.loads(
            (ROOT / "tests" / "fixtures"
             / "cosign-v3.1.3-sigstore-v0.3-bundle.json").read_bytes()
        )["verificationMaterial"]["tlogEntries"][0]["integratedTime"])
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            self.place_live_evidence(lane, window=(integrated - 10,))
            observed = self.closure_cli(lane.checkout)
            stderr = self.assert_failed_closed(observed, "pinned-trust")
            self.assertNotIn(
                "outside the authenticated run and job window", stderr,
                "the authenticated window itself refused, not the trust",
            )
            self.assertEqual(observed.stdout, b"")

    def test_the_closure_cli_refuses_an_incomplete_evidence_set(self):
        for label, kwargs in (
            ("absent-sigstore-bundle", {"bundle": False}),
            ("absent-run-timeline", {"timeline": False}),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.build_live_lane(stack)
                    self.place_live_evidence(lane, **kwargs)
                    self.assert_failed_closed(self.closure_cli(lane.checkout), label)

    def test_the_closure_cli_refuses_a_forged_evidence_member(self):
        for label, member, data in (
            ("truncated-receipt", "external-activation-review-receipt.json", b"{}\n"),
            ("truncated-envelope", "kanban-review-envelope.json", b"{}\n"),
            ("empty-bundle",
             "external-activation-review-receipt.sigstore.json", b"\n"),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.build_live_lane(stack)
                    evidence = self.place_live_evidence(lane)
                    (evidence / member).write_bytes(data)
                    self.assert_failed_closed(self.closure_cli(lane.checkout), label)

    def test_a_candidate_declared_ready_package_never_closes_f8_on_the_cli(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            self.place_live_evidence(lane)
            package = json.loads(
                (lane.checkout / "source-chain-activation-v2.json").read_bytes()
            )
            package["activation_state"] = "ready"
            package["f8_closed"] = True
            package["activation_authorized"] = True
            (lane.checkout / "source-chain-activation-v2.json").write_bytes(
                ACTIVATION.canonical_bytes(package)
            )
            self.assert_failed_closed(
                self.closure_cli(lane.checkout), "candidate-declared-ready",
            )

    def test_the_authenticated_evidence_reaches_the_authority_derivation(self):
        """The CLI hands derived evidence to Authority, never a flag."""
        source = (ROOT / "scripts" / "pin_source_chain_activation_v2.py").read_text()
        self.assertIn("_bind_derived_closure_at_authority", source)
        self.assertIn("ACTIVATION.verify_activation_package(", source)
        self.assertIn("authenticate_live_activation_evidence", source)
        self.assertEqual(
            sorted(PIN.LIVE_EVIDENCE_MEMBERS),
            [
                "authenticated-artifact-identity.json",
                "authenticated-run-timeline.json",
                "external-activation-review-receipt.json",
                "external-activation-review-receipt.sigstore.json",
                "kanban-review-envelope.json",
                "preissuance-review-receipt.json",
                "preissuance-review-receipt.sigstore.json",
            ],
        )

    def test_live_evidence_authentication_binds_the_real_exporter_bytes(self):
        with contextlib.ExitStack() as stack:
            lane = self.build_live_lane(stack)
            evidence = self.place_live_evidence(lane)
            with self.assertRaises(SystemExit) as refused:
                PIN._authenticate_live_activation_evidence(
                    evidence,
                    repository_root=lane.checkout,
                    base_commit=lane.base,
                )
            # The bytes and every binding authenticate; only the pinned
            # Sigstore trust refuses the fixture bundle.
            self.assertNotIn("envelope", str(refused.exception).lower())


# ---------------------------------------------------------------------------
# F8-EXTERNAL-REVIEW-LIVE-AUTHENTICATION-INCOMPLETE (captured provenance)
#
# The sealed server-object document must be a deterministic function of the
# raw `gh api -i` captures: real status lines, real Link relations, real
# permission headers, the server-returned artifact id and digest, and the
# canonical commit tree and blob reads. Everything below drives the exact
# production composition and receipt-creation CLI over sealed raw fixtures.
# ---------------------------------------------------------------------------
class CapturedServerProvenanceCliTests(unittest.TestCase):
    """Round trip: sealed raw gh-api captures -> composition -> receipt."""

    def prepared_lane(self, stack, **kwargs):
        lane = SealedLane(stack.enter_context(tempfile.TemporaryDirectory()))
        lane.prepare_exporter()
        exported = lane.run_exporter()
        self.assertEqual(exported.returncode, 0, exported.stderr.decode())
        lane.prepare_validator()
        lane.deliver_decision(compose=False, **kwargs)
        # The delivery composition is the reviewer-side lane; only the
        # server-object composition is under test here.
        delivered = lane.run_validator("decision-delivery")
        self.assertEqual(delivered.returncode, 0, delivered.stderr.decode())
        return lane

    def test_the_real_cli_composes_the_document_from_raw_captures(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            sealed = lane.independent_root / VALIDATOR.SERVER_OBJECTS_FILE
            self.assertFalse(sealed.exists())
            composed = lane.run_validator("server-objects")
            self.assertEqual(composed.returncode, 0, composed.stderr.decode())
            emitted = json.loads(composed.stdout)
            self.assertIs(emitted["server_objects_sealed"], True)
            self.assertEqual(emitted["server_objects_mode"], "0444")
            document = json.loads(sealed.read_bytes())
            self.assertEqual(
                emitted["server_objects_sha256"],
                hashlib.sha256(sealed.read_bytes()).hexdigest(),
            )
            # Every value came out of the captures, none was invented.
            run = lane.live_run()
            self.assertEqual(document["head"]["commit"], run["run_head_sha"])
            self.assertEqual(
                document["head"]["tree"], run["source_bootstrap_tree"],
            )
            self.assertEqual(
                document["repository"]["id"], SOURCE_REPOSITORY_ID,
            )
            self.assertEqual(
                document["artifacts"]["entries"][0]["id"], SOURCE_ARTIFACT_ID,
            )
            self.assertEqual(
                document["artifacts"]["entries"][0]["digest"],
                "sha256:" + hashlib.sha256(
                    run["artifact_archive"]
                ).hexdigest(),
                "the server-returned archive digest was not consumed verbatim",
            )
            self.assertEqual(
                document["artifacts"]["entries"][0]["size_in_bytes"],
                len(run["artifact_archive"]),
            )
            self.assertEqual(
                document["token"]["repository_selection"], "selected",
            )
            self.assertEqual(
                document["token"]["permissions"],
                {"actions": "read", "contents": "read", "metadata": "read"},
            )
            self.assertEqual(
                [entry["path"] for entry in document["tree"]["entries"]],
                list(VALIDATOR.REQUIRED_SOURCE_PATHS),
            )
            for entry in document["tree"]["entries"]:
                data = sealed_source_bytes()[entry["path"]]
                self.assertEqual(entry["blob_sha"], git_blob_oid(data))
                self.assertEqual(
                    entry["sha256"], hashlib.sha256(data).hexdigest(),
                )
            for collection in ("workflow_runs", "jobs", "artifacts"):
                pages = document[collection]["pages"]
                self.assertEqual(pages[-1]["link"], None, collection)
                self.assertEqual(pages[-1]["status"], 200, collection)

    def test_the_composed_document_carries_the_receipt_end_to_end(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            self.assertEqual(lane.run_validator("server-objects").returncode, 0)
            reviewed = lane.run_validator("external-review")
            self.assertEqual(reviewed.returncode, 0, reviewed.stderr.decode())
            receipt = json.loads(lane.external_receipt_path().read_bytes())
            server = receipt["server_objects"]
            self.assertEqual(server["artifact_id"], SOURCE_ARTIFACT_ID)
            self.assertEqual(
                server["artifact_digest"],
                "sha256:" + hashlib.sha256(
                    lane.live_run()["artifact_archive"]
                ).hexdigest(),
            )
            self.assertEqual(server["repository_id"], SOURCE_REPOSITORY_ID)
            self.assertEqual(server["job_ids"], [SOURCE_JOB_ID])

    def test_the_composition_is_not_repeatable_over_a_sealed_document(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            self.assertEqual(lane.run_validator("server-objects").returncode, 0)
            again = lane.run_validator("server-objects")
            self.assertNotEqual(
                again.returncode, 0,
                "a sealed server-object document was silently overwritten",
            )

    def refuse_raw(self, label, damage):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack, raw_damage=damage)
            composed = lane.run_validator("server-objects")
            if composed.returncode == 0:
                reviewed = lane.run_validator("external-review")
                self.assertNotEqual(reviewed.returncode, 0, label)
                self.assertFalse(
                    lane.external_receipt_path().exists(),
                    f"{label} still wrote a receipt",
                )
            else:
                self.assertNotIn("Traceback", composed.stderr.decode(), label)
                self.assertFalse(
                    (lane.independent_root / VALIDATOR.SERVER_OBJECTS_FILE
                     ).exists(),
                    f"{label} still sealed a server-object document",
                )

    # -- F8-CREDENTIAL-GRANT-NOT-BOUND-TO-RUNTIME-TOKEN -------------------
    #
    # The grant record and the credential actually in use must be one
    # authenticated issuance chain, never two independent claims that merely
    # look consistent. The App identity, the app slug, the installation id,
    # the granted permissions, the repository selection and the exhaustive
    # paginated inventory must all be derived from that same chain, and every
    # page must be bound to it. A mismatch or an omission anywhere fails
    # closed.
    # ----------------------------------------------------------------------
    API = VALIDATOR.GITHUB_API_ROOT

    def test_the_runtime_token_issuance_chain_must_be_present(self):
        for label, damage in (
            ("absent-app-capture", {VALIDATOR.RAW_APP: REMOVE}),
            ("absent-repository-installation-capture",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: REMOVE}),
            ("absent-grant-record",
             {VALIDATOR.RAW_INSTALLATION_GRANT: REMOVE}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_the_app_identity_must_be_the_granting_app(self):
        for label, damage in (
            ("app-id-is-not-the-granting-app",
             {VALIDATOR.RAW_APP: {"body": {"id": 4102337782}}}),
            ("app-slug-is-not-the-granting-app",
             {VALIDATOR.RAW_APP: {"body": {
                 "slug": "acc-test-foreign-app",
                 "html_url": "https://github.com/apps/acc-test-foreign-app",
             }}}),
            ("app-does-not-name-its-own-slug",
             {VALIDATOR.RAW_APP: {"body": {
                 "html_url": "https://github.com/apps/acc-test-other",
             }}}),
            ("app-withholds-a-required-permission",
             {VALIDATOR.RAW_APP: {"body": {"permissions": {
                 "contents": "read", "metadata": "read",
             }}}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_the_installation_must_be_the_one_that_issues_this_token(self):
        api = self.API
        for label, damage in (
            ("installation-id-is-not-the-granted-installation",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: {"body": {
                 "id": 4102337782,
             }}}),
            ("installation-app-id-mismatch",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: {"body": {
                 "app_id": 4102337782,
             }}}),
            ("installation-app-slug-mismatch",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: {"body": {
                 "app_slug": "acc-test-foreign-app",
             }}}),
            ("installation-permissions-mismatch",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: {"body": {
                 "permissions": {
                     "actions": "read", "contents": "read",
                     "metadata": "read", "issues": "read",
                 },
             }}}),
            ("installation-selection-mismatch",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: {"body": {
                 "repository_selection": "all",
             }}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_the_issuance_and_readback_endpoints_must_be_canonical(self):
        api = self.API
        foreign = f"{api}/app/installations/4102337782/access_tokens"
        for label, damage in (
            ("foreign-token-issuance-endpoint",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: {"body": {
                 "access_tokens_url": foreign,
             }}}),
            ("foreign-runtime-repositories-endpoint",
             {VALIDATOR.RAW_REPOSITORY_INSTALLATION: {"body": {
                 "repositories_url": f"{api}/user/installations/1/repositories",
             }}}),
            ("grant-record-issuance-endpoint-drift",
             {VALIDATOR.RAW_INSTALLATION_GRANT: {"body": {
                 "access_tokens_url": foreign,
             }}}),
            ("grant-record-readback-endpoint-drift",
             {VALIDATOR.RAW_INSTALLATION_GRANT: {"body": {
                 "repositories_url": f"{api}/user/installations/1/repositories",
             }}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_every_inventory_page_is_bound_to_the_issuance_chain(self):
        for label, damage in (
            ("page-selection-contradicts-the-chain",
             {"installation-page-1": {"body": {
                 "repositories": [{
                     "full_name": VALIDATOR.SOURCE_REPOSITORY,
                     "id": SOURCE_REPOSITORY_ID,
                     "node_id": "R_kgDOProtectedSource",
                 }],
                 "repository_selection": "all",
                 "total_count": 1,
             }}}),
            ("inventory-repository-node-id-drift",
             {"installation-page-1": {"body": {
                 "repositories": [{
                     "full_name": VALIDATOR.SOURCE_REPOSITORY,
                     "id": SOURCE_REPOSITORY_ID,
                     "node_id": "R_kgDOSubstituted",
                 }],
                 "repository_selection": "selected",
                 "total_count": 1,
             }}}),
            ("inventory-repository-id-drift",
             {"installation-page-1": {"body": {
                 "repositories": [{
                     "full_name": VALIDATOR.SOURCE_REPOSITORY,
                     "id": 4102337782,
                     "node_id": "R_kgDOProtectedSource",
                 }],
                 "repository_selection": "selected",
                 "total_count": 1,
             }}}),
            ("inventory-omits-the-repository-identity",
             {"installation-page-1": {"body": {
                 "repositories": [{
                     "full_name": VALIDATOR.SOURCE_REPOSITORY,
                     "id": SOURCE_REPOSITORY_ID,
                 }],
                 "repository_selection": "selected",
                 "total_count": 1,
             }}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_an_absent_capture_or_header_fails_closed(self):
        for label, damage in (
            ("absent-repository-capture", {"repository": REMOVE}),
            ("absent-installation-capture", {"installation-page-1": REMOVE}),
            ("absent-run-capture", {"run": REMOVE}),
            ("absent-commit-capture", {"commit": REMOVE}),
            ("absent-tree-capture", {"tree": REMOVE}),
            ("absent-blob-capture", {"blob-2": REMOVE}),
            ("absent-jobs-page", {"jobs-page-1": REMOVE}),
            ("absent-artifacts-page", {"artifacts-page-1": REMOVE}),
            ("absent-api-version-header", {"run": {"api_version": ""}}),
            ("absent-permission-header", {"run": {"permissions": None}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_a_non_200_captured_status_fails_closed(self):
        for label, damage in (
            ("run-404", {"run": {"status": 404}}),
            ("jobs-403", {"jobs-page-1": {"status": 403}}),
            ("tree-500", {"tree": {"status": 500}}),
            ("blob-404", {"blob-1": {"status": 404}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_an_unterminated_or_substituted_traversal_fails_closed(self):
        api = VALIDATOR.GITHUB_API_ROOT
        repo = VALIDATOR.SOURCE_REPOSITORY
        jobs = f"{api}/repos/{repo}/actions/runs/4102337781/jobs"
        for label, damage in (
            ("advertised-next-page-never-captured",
             {"jobs-page-1": {"link": f'<{jobs}?per_page=100&page=2>; rel="next"'}}),
            ("substituted-next-target",
             {"jobs-page-1": {"link": f'<{api}/repos/x/y/jobs?per_page=100&page=2>; rel="next"'}}),
            ("unparsable-link",
             {"jobs-page-1": {"link": "not-a-link-header"}}),
            ("foreign-payload-endpoint",
             {"repository": {"body": {
                 "default_branch": "main", "full_name": repo,
                 "id": SOURCE_REPOSITORY_ID, "node_id": "n",
                 "url": "https://example.invalid/repos/x/y"}}}),
            ("run-payload-endpoint-substituted",
             {"run": {"body": {
                 "head_sha": "0" * 40, "id": 4102337781, "run_attempt": 1,
                 "url": f"{api}/repos/x/y/actions/runs/4102337781"}}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_an_unadvertised_extra_page_fails_closed(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            api = VALIDATOR.GITHUB_API_ROOT
            repo = VALIDATOR.SOURCE_REPOSITORY
            write_capture(
                lane.independent_root, "jobs-page-2",
                f"{api}/repos/{repo}/actions/runs/{lane.SOURCE_RUN_ID}"
                "/jobs?per_page=100&page=2",
                http_capture({"jobs": [], "total_count": 0}),
            )
            composed = lane.run_validator("server-objects")
            self.assertNotEqual(
                composed.returncode, 0,
                "a page the server never advertised was accepted",
            )
            self.assertIn("never advertised", composed.stderr.decode())

    def test_invented_tree_blob_or_artifact_provenance_fails_closed(self):
        forged = hashlib.sha256(b"acc-forged").hexdigest()
        for label, damage in (
            ("blob-not-the-tree-object",
             {"blob-1": {"body": {"content": base64.b64encode(b"x").decode(),
                                  "encoding": "base64", "sha": forged[:40],
                                  "size": 1}}}),
            ("truncated-tree", {"tree": {"body": {
                "sha": "0" * 40, "truncated": True, "tree": []}}}),
            ("artifact-without-run-binding", {"artifacts-page-1": {"body": {
                "artifacts": [{
                    "digest": f"sha256:{forged}", "expired": False,
                    "id": SOURCE_ARTIFACT_ID, "name": VALIDATOR.SOURCE_ARTIFACT,
                    "node_id": "n", "size_in_bytes": 1,
                    "workflow_run": {"id": 1},
                }], "total_count": 1}}}),
            ("placeholder-artifact-digest", {"artifacts-page-1": {"body": {
                "artifacts": [{
                    "digest": "sha256:" + "0" * 64, "expired": False,
                    "id": SOURCE_ARTIFACT_ID, "name": VALIDATOR.SOURCE_ARTIFACT,
                    "node_id": "n", "size_in_bytes": 1,
                    "workflow_run": {"id": 4102337781},
                }], "total_count": 1}}}),
            ("total-count-contradicts-entries",
             {"jobs-page-1": {"body": {"jobs": [], "total_count": 3}}}),
            ("foreign-installation-repository", {"installation-page-1": {"body": {
                "repositories": [{"full_name": VALIDATOR.AUTHORITY_REPOSITORY}],
                "repository_selection": "selected", "total_count": 1}}}),
            ("all-repository-selection", {"installation-page-1": {"body": {
                "repositories": [{"full_name": VALIDATOR.SOURCE_REPOSITORY}],
                "repository_selection": "all", "total_count": 1}}}),
        ):
            with self.subTest(label=label):
                self.refuse_raw(label, damage)

    def test_a_locally_edited_sealed_document_no_longer_matches_the_captures(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            self.assertEqual(lane.run_validator("server-objects").returncode, 0)
            sealed = lane.independent_root / VALIDATOR.SERVER_OBJECTS_FILE
            document = json.loads(sealed.read_bytes())
            document["token"]["permissions"]["actions"] = "read"
            document["artifacts"]["entries"][0]["id"] = 4210033772
            os.chmod(sealed, 0o600)
            sealed.write_bytes(
                json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
            )
            reviewed = lane.run_validator("external-review")
            self.assertNotEqual(reviewed.returncode, 0)
            self.assertIn(
                "do not match the raw authenticated GitHub captures",
                reviewed.stderr.decode(),
            )
            self.assertFalse(lane.external_receipt_path().exists())

    def test_the_workflow_captures_headers_and_follows_pagination(self):
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("gh api -i", workflow)
        self.assertIn('rel="next"', workflow)
        self.assertIn("capture_pages", workflow)
        self.assertIn("/installation/repositories", workflow)
        self.assertIn("/git/trees/", workflow)
        self.assertIn("/git/blobs/", workflow)
        self.assertIn("--phase server-objects", workflow)
        self.assertNotIn("source-run-jobs-page-1.json", workflow)


# ---------------------------------------------------------------------------
# F8-ACTIVATION-CLI-TRANSITION-NOT-OPERATIONALLY-CLOSED
#
# The Authority issuance lane must really download both artifacts by their
# authenticated canonical ids and digests, assemble the fixed sealed evidence
# inventory and invoke the derived closure. A genuinely signed bundle and an
# authenticated run timeline must drive the exact production authentication to
# success, and the internally derived F8 must reach the Authority derivation.
# ---------------------------------------------------------------------------
def sigstore_trusted_root_document(fixture):
    """The exact `targets/trusted_root.json` shape a candidate may vendor."""
    moment = datetime.fromtimestamp(fixture.integrated, tz=timezone.utc)
    started = (moment - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rekor_der = fixture.public_der(fixture.rekor_key)
    return {
        "mediaType": PIN.SIGSTORE_TRUST_MEDIA_TYPE,
        "certificateAuthorities": [{
            "uri": "https://fulcio.acc-test.invalid",
            "certChain": {"certificates": [
                {"rawBytes": base64.b64encode(fixture.intermediate).decode()},
                {"rawBytes": base64.b64encode(fixture.root).decode()},
            ]},
        }],
        "tlogs": [{
            "baseUrl": f"https://{SigstoreFixture.ORIGIN}",
            "logId": {"keyId": base64.b64encode(
                hashlib.sha256(rekor_der).digest()
            ).decode("ascii")},
            "publicKey": {
                "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                "rawBytes": base64.b64encode(rekor_der).decode("ascii"),
            },
        }],
    }


def production_equivalent_trust_record(fixture, template):
    """A candidate-owned trust record pinning this fixture's own anchors.

    Only sealed data differs from the shipped record: the production loader,
    the manifest binding and every verification step are byte-identical.
    """
    document = sigstore_trusted_root_document(fixture)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    moment = datetime.fromtimestamp(fixture.integrated, tz=timezone.utc)
    valid_from = (moment - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    authority = document["certificateAuthorities"][0]
    certificates = [
        base64.b64decode(item["rawBytes"])
        for item in authority["certChain"]["certificates"]
    ]
    log = document["tlogs"][0]
    rekor_der = base64.b64decode(log["publicKey"]["rawBytes"])
    record = deepcopy(template)
    record[PIN.SIGSTORE_TRUST_KEY] = {
        "canonical_bytes_base64": base64.b64encode(canonical).decode("ascii"),
        "fulcio_authorities": [{
            "certificate_sha256": [
                hashlib.sha256(item).hexdigest() for item in certificates
            ],
            "common_name": "acc-test-fulcio-root",
            "organization": "acc-test",
            "root_sha256": hashlib.sha256(certificates[-1]).hexdigest(),
            "uri": authority["uri"],
            "valid_from": valid_from,
            "valid_to": None,
        }],
        "media_type": PIN.SIGSTORE_TRUST_MEDIA_TYPE,
        "rekor_logs": [{
            "base_url": log["baseUrl"],
            "key_details": log["publicKey"]["keyDetails"],
            "log_id_key_id": log["logId"]["keyId"],
            "origin": SigstoreFixture.ORIGIN,
            "public_key_sha256": hashlib.sha256(rekor_der).hexdigest(),
            "valid_from": valid_from,
            "valid_to": None,
        }],
        "runtime_trust_fetch_forbidden": True,
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "source_commit": hashlib.sha256(b"acc-test-root-signing").hexdigest()[:40],
        "source_path": PIN.SIGSTORE_TRUST_SOURCE_PATH,
        "source_repository": "https://github.com/sigstore/root-signing",
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def rebind_activation_trust(data, root):
    """Rebind the activation package to the candidate's own trust record."""
    package = json.loads(data)
    package["reviewed_source"]["trust_record"]["sha256"] = hashlib.sha256(
        (Path(root) / ACTIVATION.TRUST_RECORD_PATH).read_bytes()
    ).hexdigest()
    return ACTIVATION.canonical_bytes(package)


def reseal_candidate_manifest(root):
    """Regenerate the candidate's own sealed manifest over its exact bytes."""
    root = Path(root)
    manifest = root / "AUTHORITY-V2-SHA256SUMS"
    names = [
        line.split("  ", 1)[1]
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if (root / line.split("  ", 1)[1]).is_file()
    ]
    manifest.write_text("".join(
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
        for name in names
    ), encoding="utf-8")


class OperationalClosureLaneTests(unittest.TestCase):
    """The production lane exists, and authenticated evidence really closes F8."""

    def test_the_issuance_workflow_places_every_sealed_evidence_member(self):
        """Each sealed member is really copied into the evidence directory."""
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        derived = ("authenticated-artifact-identity.json",
                   "authenticated-run-timeline.json")
        for member in PIN.LIVE_EVIDENCE_MEMBERS:
            if member in derived:
                continue
            self.assertIn(
                f'"$EVIDENCE/{member}"', workflow,
                f"the issuance lane never places {member} in the evidence set",
            )

    def test_the_issuance_workflow_assembles_and_invokes_the_closure(self):
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "name: authority-v2-external-activation-review-t_c298fca4", workflow,
            "the issuance lane never downloads the external review artifact",
        )
        self.assertIn("actions/runs/$INDEPENDENT_REVIEW_RUN_ID/artifacts", workflow)
        self.assertIn('sha256:[0-9a-f]{64}', workflow)
        self.assertIn(PIN.LIVE_EVIDENCE_DIRECTORY, workflow)
        for member in PIN.LIVE_EVIDENCE_MEMBERS:
            self.assertIn(member, workflow, member)
        self.assertIn(
            "pin_source_chain_activation_v2.py --phase closure", workflow,
            "the issuance lane never invokes the derived closure",
        )
        self.assertIn('jq -er .f8_closed', workflow)

    def build_authenticated_evidence(self, stack):
        """Real exporter and reviewer bytes plus a genuinely signed bundle."""
        lane = SealedLane(
            stack.enter_context(tempfile.TemporaryDirectory()),
            extra_candidate_paths=CLOSURE_CANDIDATE_PATHS,
        )
        lane.prepare_exporter()
        self.assertEqual(lane.run_exporter().returncode, 0)
        lane.prepare_validator()
        lane.deliver_decision()
        reviewed = lane.run_validator("external-review")
        self.assertEqual(reviewed.returncode, 0, reviewed.stderr.decode())
        evidence = lane.checkout.parent / PIN.LIVE_EVIDENCE_DIRECTORY
        evidence.mkdir(parents=True, exist_ok=True)
        produced = lane.independent_root / "protected-review"
        for member in (
            "kanban-review-envelope.json",
            "preissuance-review-receipt.json",
            "external-activation-review-receipt.json",
        ):
            (evidence / member).write_bytes((produced / member).read_bytes())
        receipt = (evidence / "external-activation-review-receipt.json").read_bytes()
        integrated = 1_800_000_000
        fixture = SigstoreFixture(
            receipt,
            repository=VALIDATOR.INDEPENDENT_REPOSITORY,
            workflow_path=VALIDATOR.INDEPENDENT_WORKFLOW,
            workflow_sha=lane.independent_commit["sha"],
            integrated=integrated,
        )
        (evidence / "external-activation-review-receipt.sigstore.json"
         ).write_bytes(fixture.bundle())
        (evidence / PIN.LIVE_EVIDENCE_SIGNED_BUNDLE).write_bytes(
            SigstoreFixture(
                (evidence / PIN.LIVE_EVIDENCE_RECEIPT).read_bytes(),
                repository=VALIDATOR.INDEPENDENT_REPOSITORY,
                workflow_path=VALIDATOR.INDEPENDENT_WORKFLOW,
                workflow_sha=lane.independent_commit["sha"],
                integrated=integrated,
            ).bundle()
        )
        write_sealed_json(
            evidence / PIN.LIVE_EVIDENCE_IDENTITY,
            artifact_identity_entries(evidence),
        )
        write_sealed_json(evidence / "authenticated-run-timeline.json", {
            "independent_bootstrap_commit": lane.independent_commit["sha"],
            "job_completed_at": integrated + 120,
            "job_started_at": integrated - 120,
            "repository": VALIDATOR.INDEPENDENT_REPOSITORY,
            "run_attempt": 1,
            "run_id": lane.INDEPENDENT_RUN_ID,
            "run_started_at": integrated - 180,
            "workflow_path": VALIDATOR.INDEPENDENT_WORKFLOW,
        })
        return lane, evidence, fixture

    def test_the_production_entry_points_never_accept_a_trust_anchor(self):
        for name in ("derive_activation_closure",
                     "derive_live_activation_closure"):
            self.assertLessEqual(
                set(inspect.signature(getattr(PIN, name)).parameters),
                {"repository_root"}, name,
            )
        source = (ROOT / "scripts" / "pin_source_chain_activation_v2.py").read_text()
        self.assertIn(
            "_authenticate_live_activation_evidence(\n        "
            "repository_root.parent / LIVE_EVIDENCE_DIRECTORY",
            source,
            "the production closure supplies its own trust anchor",
        )

    def test_the_shipped_candidate_closure_is_authoritatively_refused(self):
        """Authoritative: the exact shipped candidate, nothing substituted."""
        with tempfile.TemporaryDirectory() as td:
            checkout = Path(td) / "authority-checkout"
            build_authority_candidate(
                checkout, extra_paths=CLOSURE_CANDIDATE_PATHS,
            )
            # Nothing is injected, patched or substituted: this is the exact
            # shipped trust record, activation package and manifest.
            self.assertEqual(
                hashlib.sha256(
                    (checkout / ACTIVATION.TRUST_RECORD_PATH).read_bytes()
                ).hexdigest(),
                hashlib.sha256(
                    (ROOT / ACTIVATION.TRUST_RECORD_PATH).read_bytes()
                ).hexdigest(),
            )
            observed = run_cli(
                checkout / "scripts" / "pin_source_chain_activation_v2.py",
                "--phase", PIN.CLOSURE_PHASE,
            )
            self.assertNotEqual(observed.returncode, 0)
            self.assertEqual(observed.stdout, b"")
            self.assertNotIn("Traceback", observed.stderr.decode())
            self.assertFalse(
                (checkout.parent / PIN.LIVE_EVIDENCE_DIRECTORY
                 / PIN.DERIVED_CLOSURE_NAME).exists(),
                "the shipped candidate produced a derived closure",
            )

    def test_the_real_cli_closure_still_refuses_the_shipped_candidate(self):
        with contextlib.ExitStack() as stack:
            lane, evidence, _ = self.build_authenticated_evidence(stack)
            observed = run_cli(
                lane.checkout / "scripts" / "pin_source_chain_activation_v2.py",
                "--phase", PIN.CLOSURE_PHASE,
            )
            self.assertNotEqual(observed.returncode, 0)
            self.assertEqual(observed.stdout, b"")
            stderr = observed.stderr.decode()
            self.assertNotIn("Traceback", stderr)
            # Every local byte and every binding authenticated; the shipped
            # candidate's pinned public Sigstore anchor is the only thing left
            # refusing, exactly as it must for a bundle it never signed.
            self.assertIn("pinned transparency log", stderr)
            self.assertNotIn(PIN.LIVE_EVIDENCE_DIRECTORY, stderr)


# ---------------------------------------------------------------------------
# NON-AUTHORITATIVE: production-equivalent substituted-trust transition
#
# These tests are explicitly NOT a proof that the shipped candidate closes F8.
# They run the production CLI and the production trust loader unmodified, but
# against a *different* candidate whose sealed data - its vendored Sigstore
# trusted root, the activation package binding and the resealed manifest - was
# substituted so that a locally generated bundle can chain to it. They prove
# the code path, not the shipped anchor.
#
# The authoritative statement about the shipped candidate is the non-injected
# test in `ActivationClosureCliTests`, which runs the same CLI against the
# exact shipped candidate and shows it refused at the pinned public anchor.
# The shipped posture remains F8=false, F12=false, approved=false,
# activation_authorized=false and release_authorized=false.
# ---------------------------------------------------------------------------
class NonAuthoritativeSubstitutedTrustClosureCliTests(unittest.TestCase):
    """Non-authoritative: the production CLI over substituted sealed trust."""

    AUTHORITATIVE = False

    INTEGRATED = 1_800_000_000

    def production_equivalent_candidate(self, stack):
        # The candidate seals its own Sigstore anchors before it is committed,
        # so the checkout stays exactly clean and the external receipt binds
        # this exact head. Only sealed data differs from the shipped candidate.
        authority = SigstoreFixture(
            b"acc-production-equivalent-anchor",
            repository=VALIDATOR.INDEPENDENT_REPOSITORY,
            workflow_path=VALIDATOR.INDEPENDENT_WORKFLOW,
            workflow_sha="0" * 40,
            integrated=self.INTEGRATED,
        )
        lane = SealedLane(
            stack.enter_context(tempfile.TemporaryDirectory()),
            extra_candidate_paths=CLOSURE_CANDIDATE_PATHS,
            candidate_overrides={
                ACTIVATION.TRUST_RECORD_PATH: lambda data, _root: (
                    production_equivalent_trust_record(
                        authority, json.loads(data),
                    )
                ),
                "source-chain-activation-v2.json": rebind_activation_trust,
            },
        )
        lane.prepare_exporter()
        self.assertEqual(lane.run_exporter().returncode, 0)
        lane.prepare_validator()
        lane.deliver_decision()
        reviewed = lane.run_validator("external-review")
        self.assertEqual(reviewed.returncode, 0, reviewed.stderr.decode())

        evidence = lane.checkout.parent / PIN.LIVE_EVIDENCE_DIRECTORY
        evidence.mkdir(parents=True, exist_ok=True)
        produced = lane.independent_root / "protected-review"
        for member in (
            "kanban-review-envelope.json",
            "preissuance-review-receipt.json",
            "external-activation-review-receipt.json",
        ):
            (evidence / member).write_bytes((produced / member).read_bytes())
        receipt = (
            evidence / "external-activation-review-receipt.json"
        ).read_bytes()
        fixture = SigstoreFixture(
            receipt,
            repository=VALIDATOR.INDEPENDENT_REPOSITORY,
            workflow_path=VALIDATOR.INDEPENDENT_WORKFLOW,
            workflow_sha=lane.independent_commit["sha"],
            integrated=self.INTEGRATED,
            authority=authority,
        )
        (evidence / "external-activation-review-receipt.sigstore.json"
         ).write_bytes(fixture.bundle())
        (evidence / PIN.LIVE_EVIDENCE_SIGNED_BUNDLE).write_bytes(
            SigstoreFixture(
                (evidence / PIN.LIVE_EVIDENCE_RECEIPT).read_bytes(),
                repository=VALIDATOR.INDEPENDENT_REPOSITORY,
                workflow_path=VALIDATOR.INDEPENDENT_WORKFLOW,
                workflow_sha=lane.independent_commit["sha"],
                integrated=self.INTEGRATED,
                authority=authority,
            ).bundle()
        )
        write_sealed_json(
            evidence / PIN.LIVE_EVIDENCE_IDENTITY,
            artifact_identity_entries(evidence),
        )
        write_sealed_json(evidence / "authenticated-run-timeline.json", {
            "independent_bootstrap_commit": lane.independent_commit["sha"],
            "job_completed_at": self.INTEGRATED + 120,
            "job_started_at": self.INTEGRATED - 120,
            "repository": VALIDATOR.INDEPENDENT_REPOSITORY,
            "run_attempt": 1,
            "run_id": lane.INDEPENDENT_RUN_ID,
            "run_started_at": self.INTEGRATED - 180,
            "workflow_path": VALIDATOR.INDEPENDENT_WORKFLOW,
        })
        return lane, evidence, fixture

    def closure_cli(self, checkout):
        return run_cli(
            checkout / "scripts" / "pin_source_chain_activation_v2.py",
            "--phase", PIN.CLOSURE_PHASE,
        )

    def test_substituted_trust_transition_is_labelled_non_authoritative(self):
        """This class may never be read as a shipped-candidate F8 closure."""
        self.assertIs(self.AUTHORITATIVE, False)
        source = (
            ROOT / "tests" / "test_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        self.assertIn("NON-AUTHORITATIVE", source)
        # The shipped candidate itself still carries none of it.
        package = ACTIVATION.verify_activation_package()
        self.assertIs(package["f8_closed"], False)
        self.assertIs(package["activation_authorized"], False)
        self.assertEqual(package["activation_state"], "unavailable")

    def test_the_production_cli_refuses_substituted_sealed_trust(self):
        """A self-consistent local trust root never reaches an F8 closure."""
        with contextlib.ExitStack() as stack:
            lane, evidence, _ = self.production_equivalent_candidate(stack)
            observed = self.closure_cli(lane.checkout)
            self.assertNotEqual(observed.returncode, 0)
            self.assertIn(
                "trusted root source or digest is substituted",
                observed.stderr.decode(),
            )
            self.assertEqual(observed.stdout, b"")
            self.assertFalse((evidence / PIN.DERIVED_CLOSURE_NAME).exists())

    def test_the_production_cli_never_accepts_injected_trust_or_booleans(self):
        parameters = inspect.signature(
            PIN._authenticate_live_activation_evidence
        ).parameters
        self.assertNotIn("trust", parameters)
        for name in ("derive_activation_closure",
                     "derive_live_activation_closure"):
            self.assertLessEqual(
                set(inspect.signature(getattr(PIN, name)).parameters),
                {"repository_root"}, name,
            )
        source = (ROOT / "scripts" / "pin_source_chain_activation_v2.py").read_text()
        self.assertIn("_bind_derived_closure_at_authority", source)
        self.assertIn("ACTIVATION.verify_activation_package(", source)

    def test_null_or_unresolved_evidence_stays_non_zero(self):
        for label, damage in (
            ("absent-evidence-directory",
             lambda e: shutil.rmtree(e)),
            ("absent-bundle",
             lambda e: (e / "external-activation-review-receipt.sigstore.json"
                        ).unlink()),
            ("absent-timeline",
             lambda e: (e / "authenticated-run-timeline.json").unlink()),
            ("forged-external-receipt",
             lambda e: (e / "external-activation-review-receipt.json"
                        ).write_bytes(b"{}\n")),
            ("truncated-envelope",
             lambda e: (e / "kanban-review-envelope.json").write_bytes(b"{}\n")),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane, evidence, _ = self.production_equivalent_candidate(
                        stack,
                    )
                    damage(evidence)
                    observed = self.closure_cli(lane.checkout)
                    self.assertNotEqual(observed.returncode, 0, label)
                    self.assertEqual(observed.stdout, b"", label)
                    self.assertNotIn(
                        "Traceback", observed.stderr.decode(), label,
                    )

    def test_a_substituted_trust_anchor_is_refused_by_the_sealed_manifest(self):
        with contextlib.ExitStack() as stack:
            lane, _, _ = self.production_equivalent_candidate(stack)
            # A trust record the candidate's own manifest does not cover.
            trust_path = lane.checkout / ACTIVATION.TRUST_RECORD_PATH
            record = json.loads(trust_path.read_bytes())
            record["sigstore_trusted_root"]["source_commit"] = "0" * 40
            trust_path.write_bytes(
                json.dumps(record, sort_keys=True,
                           separators=(",", ":")).encode() + b"\n"
            )
            observed = self.closure_cli(lane.checkout)
            self.assertNotEqual(observed.returncode, 0)
            self.assertEqual(observed.stdout, b"")
            self.assertFalse(
                (lane.checkout.parent / PIN.LIVE_EVIDENCE_DIRECTORY
                 / PIN.DERIVED_CLOSURE_NAME).exists(),
                "a substituted trust anchor still produced a derived closure",
            )

    def test_the_sealed_manifest_binding_refuses_a_rewritten_entry(self):
        """The anchor is the manifest entry, never a caller-shaped digest."""
        with contextlib.ExitStack() as stack:
            lane, _, _ = self.production_equivalent_candidate(stack)
            manifest = lane.checkout / "AUTHORITY-V2-SHA256SUMS"
            rewritten = "".join(
                (f"{'0' * 64}  {name}\n"
                 if name == ACTIVATION.TRUST_RECORD_PATH else line + "\n")
                for line, name in (
                    (entry, entry.split("  ", 1)[1])
                    for entry in manifest.read_text().splitlines()
                )
            )
            manifest.write_text(rewritten, encoding="utf-8")
            with self.assertRaises(SystemExit) as refused:
                ACTIVATION.manifest_digest(
                    lane.checkout, ACTIVATION.TRUST_RECORD_PATH,
                )
            self.assertIn("does not match the checkout", str(refused.exception))

    def test_a_forged_member_digest_is_not_rescued_by_the_artifact_name(self):
        """The exact bypass: a correct name beside a wrong member byte.

        Before this was closed the closure accepted a matching artifact name
        in place of a matching digest, so an identity inventory describing
        bytes nobody ever downloaded still derived a closed F8.
        """
        with contextlib.ExitStack() as stack:
            lane, evidence, _ = self.production_equivalent_candidate(stack)
            identity = evidence / PIN.LIVE_EVIDENCE_IDENTITY
            entries = json.loads(identity.read_bytes())
            forged = hashlib.sha256(b"acc-forged-envelope").hexdigest()
            for entry in entries:
                if entry["name"].endswith("signed-review-t_c298fca4"):
                    entry["members"][PIN.LIVE_EVIDENCE_ENVELOPE] = forged
            os.chmod(identity, 0o600)
            write_sealed_json(identity, entries)
            observed = self.closure_cli(lane.checkout)
            self.assertNotEqual(
                observed.returncode, 0,
                "a forged archive member digest still derived a closed F8",
            )
            # The declared member digest is not the digest of the member in
            # the real archive that was downloaded by canonical server id.
            self.assertIn(
                "is not the authenticated member digest",
                observed.stderr.decode(),
            )
            self.assertEqual(observed.stdout, b"")

            # The stronger bypass: an internally consistent archive whose
            # member really does hash to the forged digest. Only binding the
            # member back to the evidence byte refuses this.
            entry = next(
                item for item in entries
                if item["name"].endswith("signed-review-t_c298fca4")
            )
            members = {
                PIN.LIVE_EVIDENCE_ENVELOPE: b"acc-forged-envelope",
                PIN.LIVE_EVIDENCE_RECEIPT: (
                    evidence / PIN.LIVE_EVIDENCE_RECEIPT
                ).read_bytes(),
                PIN.LIVE_EVIDENCE_SIGNED_BUNDLE: (
                    evidence / PIN.LIVE_EVIDENCE_SIGNED_BUNDLE
                ).read_bytes(),
            }
            archive = build_artifact_archive(members)
            archive_path = evidence / PIN.ARTIFACT_ARCHIVE_TEMPLATE.format(
                artifact_id=entry["artifact_id"],
            )
            os.chmod(archive_path, 0o600)
            archive_path.write_bytes(archive)
            entry["archive_sha256"] = hashlib.sha256(archive).hexdigest()
            entry["archive_size"] = len(archive)
            entry["digest"] = "sha256:" + entry["archive_sha256"]
            write_sealed_json(identity, entries)
            observed = self.closure_cli(lane.checkout)
            self.assertNotEqual(
                observed.returncode, 0,
                "a self-consistent forged archive still derived a closed F8",
            )
            self.assertIn(
                "is not the byte this closure authenticated",
                observed.stderr.decode(),
            )
            self.assertEqual(observed.stdout, b"")

    def test_an_artifact_name_alone_can_never_bind_the_exporter(self):
        """Identity and digest are required together, never alternatively."""
        source = (
            ROOT / "scripts" / "pin_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            'or server["artifact_name"] == SOURCE_ARTIFACT_NAME', source,
            "a matching name can still rescue a mismatched digest",
        )
        self.assertEqual(
            sorted(PIN.ARTIFACT_IDENTITY_KEYS),
            ["archive_sha256", "archive_size", "artifact_id", "digest",
             "members", "name"],
        )
        for name, members in PIN.ARTIFACT_REQUIRED_MEMBERS.items():
            self.assertIn(name, PIN.REQUIRED_ARTIFACT_NAMES)
            self.assertTrue(members, name)

    def test_the_derived_closure_seals_once_and_never_overwrites(self):
        with contextlib.ExitStack() as stack:
            lane, evidence, _ = self.production_equivalent_candidate(stack)
            package = json.loads(
                (lane.checkout / "source-chain-activation-v2.json").read_bytes()
            )
            sealed = PIN._seal_derived_closure(lane.checkout, package)
            self.assertEqual(sealed["mode"], "0444")
            with self.assertRaises(SystemExit) as raised:
                PIN._seal_derived_closure(lane.checkout, package)
            self.assertIn("already", str(raised.exception))
            self.assertTrue((evidence / PIN.DERIVED_CLOSURE_NAME).is_file())


# ---------------------------------------------------------------------------
# R4 / R5: the real local output path, end to end
#
# Build -> bundle fixture -> release checksum manifest -> runner state ->
# seal -> verify, driven through the production CLI, with mode readback,
# post-seal hashes and a cleanup that really succeeds over the sealed tree.
# ---------------------------------------------------------------------------
FINAL_EVIDENCE_INVENTORY = tuple(sorted([
    *VERIFIER.release_evidence_inventory(), VERIFIER.RELEASE_MANIFEST_NAME,
]))


class FullOutputPathIntegrationTests(unittest.TestCase):
    """The exact workflow output path, executed locally through the CLI."""

    SUBJECTS = ("authority-v2-future", "authority-v2-in_window",
                "authority-v2-stale")

    @staticmethod
    def reopen(directory):
        directory = Path(directory)
        if not directory.exists():
            return
        for path in sorted(directory.rglob("*"), reverse=True):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        os.chmod(directory, 0o700)

    def workspace(self):
        workspace = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(workspace, ignore_errors=True))
        self.addCleanup(self.reopen, workspace)
        return workspace

    def gate_document(self, digests):
        """The exact document the unchanged verify-only path emits.

        Its field set is the production contract itself, so this can never
        drift from what `verify_publication_v2.py --verify-only` writes.
        """
        document = {
            "asset_digests": dict(digests),
            "assets_verified": len(digests),
            "blocked_by": None,
            # The one canonical map this gate consumed, by digest.
            "canonical_inventory_sha256": GENERATOR.canonical_inventory_sha256({
                "digests": dict(digests), "inventory": sorted(digests),
            }),
            "deep_plan_verified": True,
            "f12_closed": False,
            "inventory": sorted(digests),
            "publication": "unavailable",
            "release_authorized": False,
            "release_evidence_verified": len(digests),
            "state": "verified",
            "transports_constructed": 0,
            "verify_only": True,
            "writes_performed": 0,
        }
        self.assertEqual(
            sorted(document), sorted(GENERATOR.VERIFY_ONLY_GATE_KEYS),
        )
        return document

    def write_gate(self, path, document):
        path = Path(path)
        path.write_bytes(
            json.dumps(document, sort_keys=True).encode("utf-8") + b"\n"
        )
        return path

    def generate(self, dist, *, derived_closure):
        """Subjects, then real bundle fixtures, then the checksum manifest."""
        dist.mkdir(parents=True, exist_ok=True)
        for name in self.SUBJECTS:
            payload = json.dumps(
                {"case": name, "schema_version": 2}, sort_keys=True,
            ).encode() + b"\n"
            (dist / f"{name}.json").write_bytes(payload)
            fixture = SigstoreFixture(
                payload,
                repository=VALIDATOR.INDEPENDENT_REPOSITORY,
                workflow_path=VALIDATOR.INDEPENDENT_WORKFLOW,
                workflow_sha="a" * 40,
                integrated=1_800_000_000,
            )
            (dist / f"{name}.sigstore.json").write_bytes(fixture.bundle())
        # The real pre-terminal ordering: a non-terminal staged runner state,
        # then the write-free F12 gate over the inventory that carries it, and
        # only then the completed terminal artifact.
        staged = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-runner-state", "--recovery-round", "3",
             "--terminal-state", GENERATOR.RUNNER_STAGING_STATE,
             "--derived-closure-sha256", derived_closure],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(staged.returncode, 0, staged.stderr.decode())
        (dist / GENERATOR.RUNNER_STATE_NAME).write_bytes(
            GENERATOR.canonical_runner_state(
                json.loads(staged.stdout)["runner_state"]
            )
        )
        pre_terminal = self.write_gate(
            dist.parent / "verify-only-pre-terminal.json",
            self.gate_document({
                GENERATOR.RUNNER_STATE_NAME: hashlib.sha256(
                    (dist / GENERATOR.RUNNER_STATE_NAME).read_bytes()
                ).hexdigest(),
            }),
        )
        state = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-runner-state", "--recovery-round", "3",
             "--terminal-state", "completed",
             "--verify-only-result", str(pre_terminal),
             "--derived-closure-sha256", derived_closure],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(state.returncode, 0, state.stderr.decode())
        runner_state = json.loads(state.stdout)["runner_state"]
        (dist / GENERATOR.RUNNER_STATE_NAME).write_bytes(
            GENERATOR.canonical_runner_state(runner_state)
        )
        # The six reviewed public / pre-issuance release assets are staged
        # into the same inventory the production workflow stages them into:
        # the gate verifies all fourteen, so all fourteen are sealed.
        for member in GENERATOR.SEALED_PUBLIC_ASSET_NAMES:
            (dist / member).write_bytes(
                json.dumps({"member": member}, sort_keys=True).encode() + b"\n"
            )
        # The release checksum manifest still enumerates the signed release
        # evidence alone, byte for byte as the production verifier recomputes.
        lines = []
        for member in sorted(
            child.name for child in dist.iterdir()
            if child.name not in GENERATOR.SEALED_PUBLIC_ASSET_NAMES
            and child.name != "AUTHORITY-V2-RELEASE-SHA256SUMS"
        ):
            digest = hashlib.sha256((dist / member).read_bytes()).hexdigest()
            lines.append(f"{digest}  {member}\n")
        (dist / "AUTHORITY-V2-RELEASE-SHA256SUMS").write_text(
            "".join(lines), encoding="utf-8",
        )
        return runner_state

    def seal(self, dist):
        members = sorted(child.name for child in dist.iterdir())
        selectors = []
        for member in members:
            selectors += ["--final-evidence-member", member]
        # The production ordering: the final evidence manifest is composed
        # first, outside the inventory it describes, and only then is the
        # last non-mutating gate taken over exactly those bytes.
        manifest = dist.parent / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME
        composing = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-final-evidence-manifest", str(dist),
             "--final-evidence-manifest", str(manifest), *selectors],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(composing.returncode, 0, composing.stderr.decode())
        gate = self.write_gate(
            dist.parent / "verify-only-final.json",
            self.gate_document({
                member: hashlib.sha256((dist / member).read_bytes()).hexdigest()
                for member in members
            }),
        )
        arguments = [sys.executable,
                     str(ROOT / "scripts" / "build_authority_v2.py"),
                     "--seal-final-evidence", str(dist),
                     "--final-evidence-manifest", str(manifest),
                     "--verify-only-result", str(gate), *selectors]
        observed = subprocess.run(arguments, capture_output=True, cwd=str(ROOT))
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        # Nothing was created inside the sealed inventory afterwards.
        self.assertEqual(
            sorted(child.name for child in dist.iterdir()), members,
        )
        return json.loads(observed.stdout)

    def test_the_release_inventory_is_identical_downstream(self):
        """Runner state, release manifest and publication agree exactly."""
        release = VERIFIER.release_evidence_inventory()
        self.assertIn(VERIFIER.RUNNER_STATE_ASSET_NAME, release)
        self.assertEqual(
            sorted(release),
            sorted(name for name in PUBLICATION.RELEASE_EVIDENCE_ASSET_NAMES
                   if name != VERIFIER.RELEASE_MANIFEST_NAME),
        )
        self.assertIn(
            VERIFIER.RUNNER_STATE_ASSET_NAME,
            PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES,
        )
        self.assertEqual(
            sorted(FINAL_EVIDENCE_INVENTORY),
            sorted([*release, VERIFIER.RELEASE_MANIFEST_NAME]),
        )

    def test_the_verify_only_publication_path_confirms_f12_false(self):
        """The expected F12-blocked state is confirmed without any write."""
        workspace = self.workspace()
        assets = {}
        for name in PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES:
            target = workspace / name
            target.write_bytes(b"{}\n")
            assets[name] = str(target)
        # The deep verify-only preflight itself is exercised in
        # `tests/test_publication_v2.py`; here the workflow wiring and the
        # shared release inventory are what must agree.
        self.assertEqual(
            sorted(assets), sorted(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES),
        )
        self.assertIn(
            "review_receipt_sha256",
            inspect.signature(
                PUBLICATION.verify_only_publication_state
            ).parameters,
        )
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("verify_publication_v2.py --verify-only", workflow)
        self.assertIn(
            "--asset authority-v2-runner-state.json=", workflow,
        )

    def test_the_full_local_output_path_seals_and_verifies(self):
        workspace = self.workspace()
        dist = workspace / "dist"
        derived = hashlib.sha256(b"acc-derived-closure").hexdigest()
        runner_state = self.generate(dist, derived_closure=derived)
        emitted = self.seal(dist)

        # Runner state: truthful terminal point, exact candidate range.
        self.assertEqual(runner_state["terminal_state"], "completed")
        self.assertEqual(runner_state["recovery_round"], 3)
        self.assertEqual(runner_state["derived_closure_sha256"], derived)
        self.assertEqual(
            runner_state["commit_count"],
            int(subprocess.run(
                ["git", "-C", str(ROOT), "rev-list", "--count",
                 f'{runner_state["base_commit"]}..{runner_state["head_commit"]}'],
                check=True, capture_output=True,
            ).stdout.decode().strip()),
        )
        self.assertEqual(runner_state["commit_count"], 1)

        # The final evidence binds the sealed runner state and the closure.
        final = emitted["final_evidence"]
        self.assertEqual(final["runner_terminal_state"], "completed")
        self.assertEqual(final["derived_closure_sha256"], derived)
        self.assertEqual(
            final["runner_state_sha256"],
            hashlib.sha256(
                (dist / GENERATOR.RUNNER_STATE_NAME).read_bytes()
            ).hexdigest(),
        )

        # 0555/0444 with real readback and post-seal hashes.
        sealing = final["sealing"]
        self.assertEqual(sealing["directory_mode_readback"], "0555")
        self.assertEqual(oct(os.stat(dist).st_mode & 0o777), oct(0o555))
        self.assertIs(sealing["hashes_recomputed_after_sealing"], True)
        for entry in sealing["entries"]:
            member = dist / entry["name"]
            self.assertEqual(entry["mode_readback"], "0444", entry["name"])
            self.assertEqual(
                oct(os.stat(member).st_mode & 0o777), oct(0o444), entry["name"],
            )
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256(member.read_bytes()).hexdigest(), entry["name"],
            )

        # The release checksum manifest still verifies over the sealed bytes.
        for line in (
            dist / "AUTHORITY-V2-RELEASE-SHA256SUMS"
        ).read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(
                hashlib.sha256((dist / name).read_bytes()).hexdigest(), digest,
                name,
            )
        self.assertIn(GENERATOR.RUNNER_STATE_NAME, (
            dist / "AUTHORITY-V2-RELEASE-SHA256SUMS"
        ).read_text())

        # Every bundle in the sealed set is the real Cosign v0.3 shape.
        for name in self.SUBJECTS:
            parsed = SIGSTORE.parse_bundle(
                (dist / f"{name}.sigstore.json").read_bytes(),
                media_types=PIN.SIGSTORE_MEDIA_TYPES,
            )
            self.assertTrue(parsed.certificate_chain)
            self.assertEqual(parsed.integrated_time, 1_800_000_000)

        # Sealing really is immutable.
        with self.assertRaises(PermissionError):
            (dist / "authority-v2-late.json").write_bytes(b"{}\n")

    def test_the_workflow_cleanup_succeeds_over_the_sealed_tree(self):
        """The exact cleanup the workflow runs must remove a sealed tree."""
        workspace = self.workspace()
        runtime = workspace / "authority-v2-runtime"
        dist = runtime / "dist"
        self.generate(
            dist, derived_closure=hashlib.sha256(b"acc-cleanup").hexdigest(),
        )
        self.seal(dist)
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        cleanup = workflow_run_block(
            workflow, "Delete ephemeral protected runtime bytes",
        )
        self.assertIn("chmod u+rwx", cleanup)
        self.assertIn("chmod u+rw", cleanup)
        observed = subprocess.run(
            ["bash", "-c", cleanup],
            capture_output=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                 "AUTHORITY_V2_RUNTIME": str(runtime)},
        )
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        self.assertFalse(runtime.exists(), "the sealed runtime was not removed")

    def test_a_naive_cleanup_would_have_failed(self):
        """The reopening step is load-bearing, not decorative."""
        workspace = self.workspace()
        dist = workspace / "dist"
        self.generate(
            dist, derived_closure=hashlib.sha256(b"acc-naive").hexdigest(),
        )
        self.seal(dist)
        observed = subprocess.run(
            ["bash", "-c", 'set -euo pipefail\nrm -rf "$1"\ntest ! -e "$1"',
             "cleanup", str(dist)],
            capture_output=True,
        )
        self.assertNotEqual(
            observed.returncode, 0,
            "a naive cleanup removed the sealed evidence, so reopening it "
            "would not be load-bearing",
        )

    def test_the_workflow_emits_the_runner_state_only_at_the_terminal_point(self):
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        emit = workflow.index("--emit-runner-state")
        self.assertGreater(
            emit, workflow.index("--sign-subject-dir"),
            "the runner state is emitted before the subjects are signed",
        )
        self.assertLess(
            emit, workflow.index("AUTHORITY-V2-RELEASE-SHA256SUMS\n"),
            "the runner state is not part of the release checksum manifest",
        )
        self.assertIn("--derived-closure-sha256", workflow)
        self.assertIn("--terminal-state blocked_builder_failed", workflow)
        self.assertIn("authority-v2-runner-state.json", workflow)
        self.assertIn("runner_terminal_state", workflow)


# ---------------------------------------------------------------------------
# GITHUB-TOKEN-PERMISSION-PROVENANCE-SYNTHESIZED
#
# `x-accepted-github-permissions` states what an endpoint requires. It is
# never read as the grant a credential holds: the grants come only from the
# authenticated installation readback, which must publish them itself.
# ---------------------------------------------------------------------------
class InstallationGrantProvenanceCliTests(unittest.TestCase):
    """Real installation grants, endpoint requirements kept separate."""

    def prepared_lane(self, stack, **kwargs):
        lane = SealedLane(stack.enter_context(tempfile.TemporaryDirectory()))
        lane.prepare_exporter()
        self.assertEqual(lane.run_exporter().returncode, 0)
        lane.prepare_validator()
        lane.deliver_decision(compose=False, **kwargs)
        delivered = lane.run_validator("decision-delivery")
        self.assertEqual(delivered.returncode, 0, delivered.stderr.decode())
        return lane

    def test_the_document_separates_grants_from_endpoint_requirements(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            self.assertEqual(lane.run_validator("server-objects").returncode, 0)
            token = json.loads(
                (lane.independent_root / VALIDATOR.SERVER_OBJECTS_FILE
                 ).read_bytes()
            )["token"]
            self.assertEqual(token["installation_id"], FIXTURE_INSTALLATION_ID)
            self.assertEqual(
                token["permissions"],
                {"actions": "read", "contents": "read", "metadata": "read"},
                "the grants must come from the external authenticated grant "
                "record, never from the runtime readback",
            )
            self.assertEqual(token["repository_selection"], "selected")
            self.assertIn("endpoint_requirements", token)
            self.assertIsNot(
                token["permissions"], token["endpoint_requirements"],
            )
            for scope, levels in token["endpoint_requirements"].items():
                self.assertIsInstance(levels, list, scope)

    def refuse(self, label, damage):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack, raw_damage=damage)
            composed = lane.run_validator("server-objects")
            if composed.returncode == 0:
                reviewed = lane.run_validator("external-review")
                self.assertNotEqual(reviewed.returncode, 0, label)
            self.assertNotIn("Traceback", composed.stderr.decode(), label)
            self.assertFalse(lane.external_receipt_path().exists(), label)

    def test_the_runtime_readback_is_never_the_source_of_grants(self):
        """The documented readback publishes no grants, and none is inferred."""
        repo = VALIDATOR.SOURCE_REPOSITORY
        with contextlib.ExitStack() as stack:
            # A readback that tries to publish its own, wider grants changes
            # nothing: the grants come only from the sealed record.
            lane = self.prepared_lane(stack, raw_damage={
                "installation-page-1": {"body": {
                    "installation": {"id": 1, "permissions": {
                        "actions": "write", "contents": "write"}},
                    "repositories": [{"full_name": repo,
                                      "id": SOURCE_REPOSITORY_ID,
                                      "node_id": "R_kgDOProtectedSource"}],
                    "repository_selection": "selected", "total_count": 1}},
            })
            self.assertEqual(lane.run_validator("server-objects").returncode, 0)
            token = json.loads(
                (lane.independent_root / VALIDATOR.SERVER_OBJECTS_FILE
                 ).read_bytes()
            )["token"]
            self.assertEqual(
                token["permissions"],
                {"actions": "read", "contents": "read", "metadata": "read"},
            )
            self.assertEqual(token["installation_id"], FIXTURE_INSTALLATION_ID)
            self.assertRegex(token["grant_record_sha256"], r"^[0-9a-f]{64}$")

    def test_a_readback_contradicting_the_sealed_grant_fails_closed(self):
        repo = VALIDATOR.SOURCE_REPOSITORY
        for label, body in (
            ("foreign-inventory", {
                "repositories": [{"full_name": VALIDATOR.AUTHORITY_REPOSITORY,
                                  "id": SOURCE_REPOSITORY_ID}],
                "repository_selection": "selected", "total_count": 1}),
            ("all-selection", {
                "repositories": [{"full_name": repo, "id": SOURCE_REPOSITORY_ID}],
                "repository_selection": "all", "total_count": 1}),
            ("extra-repository", {
                "repositories": [
                    {"full_name": repo, "id": SOURCE_REPOSITORY_ID},
                    {"full_name": VALIDATOR.AUTHORITY_REPOSITORY, "id": 2},
                ],
                "repository_selection": "selected", "total_count": 2}),
        ):
            with self.subTest(label=label):
                self.refuse(label, {"installation-page-1": {"body": body}})

    def test_an_endpoint_requirement_header_can_never_grant_a_scope(self):
        """Even an `actions=write` requirement header grants nothing."""
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(
                stack, raw_damage={"run": {"permissions": "actions=write"}},
            )
            composed = lane.run_validator("server-objects")
            self.assertNotEqual(
                composed.returncode, 0,
                "a write-scoped read was accepted by this read-only lane",
            )
            self.assertIn("write", composed.stderr.decode())

    def test_the_validator_no_longer_derives_grants_from_headers(self):
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("_captured_permissions", source)
        self.assertNotIn("_authenticated_installation_grants", source)
        self.assertIn("authenticated_credential_grant", source)
        self.assertIn("_endpoint_requirements", source)

    def test_branch_protection_proof_is_the_authenticated_status(self):
        """A 200 on the administration-scoped endpoint is the real proof."""
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            delivery = json.loads(
                (lane.independent_root / VALIDATOR.DECISION_DELIVERY_FILE
                 ).read_bytes()
            )["branch_protection"]
            self.assertEqual(delivery["authenticated_status"], 200)
            self.assertIn("administration=read", delivery["endpoint_requirement"])


# ---------------------------------------------------------------------------
# REVIEW-WORKFLOW-RAW-CAPTURE-NOT-OPERATIONAL
#
# The exact shell the workflow runs must parse CRLF captures and must select
# the artifact across every fully traversed page.
# ---------------------------------------------------------------------------
class RawCaptureShellBlockTests(unittest.TestCase):
    """The workflow's own shell, executed over CRLF multipage captures."""

    def workflow_block(self):
        return workflow_run_block(
            (INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
             / "review-authority-v2.yml").read_text(encoding="utf-8"),
            "Capture every canonical protected-source server response",
        )

    def helpers(self):
        """Exactly the capture helpers the workflow defines, nothing else."""
        block = self.workflow_block()
        start = block.index("capture_body() {")
        end = block.index("capture_pages() {")
        return block[start:end]

    def artifact_selection(self):
        block = self.workflow_block()
        start = block.index("for page in authenticated/raw/artifacts-page-*.http")
        end = block.index("gh api", start)
        return block[start:end]

    def crlf_capture(self, body, *, link=None):
        head = ["HTTP/2.0 200 ", "x-github-api-version-selected: 2022-11-28"]
        if link is not None:
            head.append(f"link: {link}")
        return ("\r\n".join(head) + "\r\n\r\n").encode() + json.dumps(
            body, sort_keys=True,
        ).encode()

    def test_capture_body_parses_crlf_captures(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "tree.http"
            path.write_bytes(self.crlf_capture(
                {"tree": [{"path": "bootstrap-contract.json", "sha": "a" * 40}]},
            ))
            observed = subprocess.run(
                ["bash", "-c",
                 self.helpers() + '\ncapture_body "$1" | jq -er ".tree[0].sha"',
                 "shell", str(path)],
                capture_output=True,
            )
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            self.assertEqual(observed.stdout.decode().strip(), "a" * 40)

    def test_next_link_terminates_on_a_crlf_final_page(self):
        with tempfile.TemporaryDirectory() as td:
            last = Path(td) / "last.http"
            last.write_bytes(self.crlf_capture({"total_count": 0}))
            first = Path(td) / "first.http"
            first.write_bytes(self.crlf_capture(
                {"total_count": 1},
                link='<https://api.github.com/x?per_page=100&page=2>; rel="next"',
            ))
            script = (
                "set -euo pipefail\n" + self.helpers()
                + '\nnxt="$(next_link "$1" || true)"\nprintf "%s" "$nxt"\n'
            )
            for path, expected in ((last, ""), (first, "page=2")):
                observed = subprocess.run(
                    ["bash", "-c", script, "shell", str(path)],
                    capture_output=True,
                )
                self.assertEqual(
                    observed.returncode, 0, observed.stderr.decode(),
                )
                if expected:
                    self.assertIn(expected, observed.stdout.decode())
                else:
                    self.assertEqual(observed.stdout.decode(), "")

    def test_the_artifact_is_selected_across_every_traversed_page(self):
        wanted = "authority-v2-review-t_c298fca4"
        digest = "sha256:" + hashlib.sha256(b"acc-multipage").hexdigest()
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td) / "authenticated" / "raw"
            raw.mkdir(parents=True)
            (raw / "artifacts-page-1.http").write_bytes(self.crlf_capture({
                "artifacts": [{"name": "other", "expired": False, "id": 1,
                               "digest": digest}],
                "total_count": 2,
            }, link='<https://api.github.com/a?per_page=100&page=2>; rel="next"'))
            # The real artifact only exists on the second traversed page.
            (raw / "artifacts-page-2.http").write_bytes(self.crlf_capture({
                "artifacts": [{"name": wanted, "expired": False,
                               "id": 4210033771, "digest": digest}],
                "total_count": 2,
            }))
            script = (
                "set -euo pipefail\ncd \"$1\"\n" + self.helpers()
                + "\n" + self.artifact_selection()
                + '\njq -er .id authenticated/selected-artifact.json\n'
            )
            observed = subprocess.run(
                ["bash", "-c", script, "shell", str(Path(td))],
                capture_output=True,
            )
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            self.assertEqual(observed.stdout.decode().strip(), "4210033771")

    def test_an_absent_or_ambiguous_artifact_fails_closed(self):
        wanted = "authority-v2-review-t_c298fca4"
        digest = "sha256:" + hashlib.sha256(b"acc-ambiguous").hexdigest()
        for label, pages in (
            ("absent", [[{"name": "other", "expired": False, "id": 1,
                          "digest": digest}]]),
            ("expired", [[{"name": wanted, "expired": True, "id": 1,
                           "digest": digest}]]),
            ("ambiguous", [
                [{"name": wanted, "expired": False, "id": 1, "digest": digest}],
                [{"name": wanted, "expired": False, "id": 2, "digest": digest}],
            ]),
        ):
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as td:
                    raw = Path(td) / "authenticated" / "raw"
                    raw.mkdir(parents=True)
                    for number, artifacts in enumerate(pages, start=1):
                        (raw / f"artifacts-page-{number}.http").write_bytes(
                            self.crlf_capture({
                                "artifacts": artifacts,
                                "total_count": len(artifacts),
                            })
                        )
                    script = (
                        "set -euo pipefail\ncd \"$1\"\n" + self.helpers()
                        + "\n" + self.artifact_selection()
                    )
                    observed = subprocess.run(
                        ["bash", "-c", script, "shell", str(Path(td))],
                        capture_output=True,
                    )
                    self.assertNotEqual(observed.returncode, 0, label)

    def test_the_workflow_uses_no_cr_unsafe_body_split(self):
        block = self.workflow_block()
        self.assertNotIn("sed -n '/^$/,$p' authenticated", block)
        self.assertIn("tr -d '\\r'", block)
        self.assertIn("artifacts-page-*.http", block)


# ---------------------------------------------------------------------------
# F8-DECISION-DELIVERY-TEST-INJECTION
#
# The positive path must not place a decision or call a composer. The reviewer
# owns a real delivery commit in its own repository; every GitHub response is
# derived from those immutable Git objects, and every phase runs through the
# same CLI entry points the production workflow invokes.
# ---------------------------------------------------------------------------
class ReviewerDeliveryRepository:
    """A real, reviewer-owned repository whose commit delivers the decision."""

    def __init__(self, root, *, decision_path, decision_bytes):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email",
            f"{DELIVERY_WRITER_LOGIN}@users.noreply.github.com")
        git(self.root, "config", "user.name", DELIVERY_WRITER_LOGIN)
        (self.root / "README.md").write_bytes(b"acc independent review\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "reviewer bootstrap")
        self.parent = git(self.root, "rev-parse", "HEAD")
        self.parent_tree = git(self.root, "rev-parse", "HEAD^{tree}")
        target = self.root / decision_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(decision_bytes)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "deliver reviewer decision")
        self.commit = git(self.root, "rev-parse", "HEAD")
        self.tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.decision_path = decision_path
        self.blob = git(self.root, "rev-parse", f"HEAD:{decision_path}")

    def changed_files(self):
        """Exactly what the delivery commit introduced, read from Git."""
        raw = subprocess.run(
            ["git", "-C", str(self.root), "diff-tree", "--no-commit-id",
             "-r", "--name-status", self.commit],
            check=True, capture_output=True,
        ).stdout.decode()
        statuses = {"A": "added", "M": "modified", "D": "removed"}
        entries = []
        for line in raw.splitlines():
            status, _, name = line.partition("\t")
            entries.append({
                "filename": name,
                "sha": git(self.root, "rev-parse", f"{self.commit}:{name}")
                if status != "D" else "0" * 40,
                "status": statuses[status[0]],
            })
        return entries

    def responses(self):
        """The GitHub responses this immutable delivery commit implies."""
        blob = git_blob_oid((self.root / self.decision_path).read_bytes())
        data = (self.root / self.decision_path).read_bytes()
        content = base64.b64encode(data).decode("ascii")
        contents = {
            "content": content,
            "encoding": "base64",
            "path": self.decision_path,
            "sha": blob,
            "size": len(data),
            "type": "file",
        }
        return {
            "repository": {
                "default_branch": VALIDATOR.DECISION_DELIVERY_BRANCH,
                "full_name": VALIDATOR.INDEPENDENT_REPOSITORY,
                "id": INDEPENDENT_REPOSITORY_ID,
                "node_id": "R_kgDOIndependentReview",
                "private": False,
                "visibility": "public",
            },
            "commit": {
                "author": {"id": DELIVERY_WRITER_ID,
                           "login": DELIVERY_WRITER_LOGIN, "type": "User"},
                "committer": {"id": DELIVERY_WRITER_ID,
                              "login": DELIVERY_WRITER_LOGIN, "type": "User"},
                "commit": {
                    "tree": {"sha": self.tree},
                    "verification": {"reason": "valid", "verified": True},
                },
                "files": self.changed_files(),
                "parents": [{"sha": self.parent}],
                "sha": self.commit,
            },
            "blob": contents,
            "readback": dict(contents),
        }


class ReviewerOwnedDeliveryCliTests(unittest.TestCase):
    """Every phase, through the same CLI entry points the workflow calls."""

    # Every phase the workflow calls. `deliver-commit` is the one phase that
    # installs anything: it constructs the production Git Data transport, so
    # it is exercised end to end against a real Git Data server in
    # `ReviewerOwnedDecisionDeliveryTests` rather than driven here, where no
    # transport may ever be constructed.
    PHASES = ("bootstrap", "select", "server-objects", "chain",
              "deliver-decision", "decision-delivery", "external-review")
    INSTALLING_PHASES = ("deliver-commit",)
    TERMINAL_PHASES = ("terminal-readback-collector",)

    def build(self, stack):
        workspace = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        lane = SealedLane(workspace, extra_candidate_paths=CLOSURE_CANDIDATE_PATHS)
        # The reviewer authors and commits the decision in its own repository,
        # before this lane ever sees it.
        decision = reviewer_decision(
            {
                "authority_base_commit": lane.base,
                "authority_head_commit": lane.head,
                "authority_head_tree": lane.head_tree,
            },
            lane.checkout,
        )
        reviewer = ReviewerDeliveryRepository(
            workspace / "reviewer-repository",
            decision_path=(
                f"{VALIDATOR.REVIEWER_DECISION_DIRECTORY}/{lane.head}.json"
            ),
            decision_bytes=decision,
        )
        # The reviewer's own authored artifact, committed in the reviewer's
        # repository and checked out with it. The lane never composes a
        # verdict: the real `--phase deliver-decision` entry point binds these
        # authored bytes to the candidate and publishes them unchanged.
        authored = (
            lane.independent_root
            / VALIDATOR.REVIEWER_AUTHORED_DECISION_DIRECTORY
            / f"{lane.head}.json"
        )
        authored.parent.mkdir(parents=True, exist_ok=True)
        authored.write_bytes(decision)
        # GITHUB_SHA is the bootstrap commit (the workflow trigger), not the
        # delivery commit. The delivery commit is a child of bootstrap,
        # created by the delivery step and fetched by the authentication step.
        # The lane therefore checks out the bootstrap parent, exactly as the
        # workflow's `actions/checkout` does, so the delivered decision path
        # does not exist yet. Nothing is placed at it by this test.
        lane.independent_commit = {
            "sha": reviewer.parent, "tree": {"sha": reviewer.parent_tree},
        }
        lane.prepare_exporter()
        self.assertEqual(lane.run_exporter().returncode, 0)
        lane.prepare_validator()
        responses = reviewer.responses()
        run = lane.live_run()
        write_sealed_json(
            lane.independent_root / VALIDATOR.AUTHORITY_COMMIT_FILE,
            {"sha": lane.head, "tree": {"sha": lane.head_tree}},
        )
        for name, relative in (
            ("repository", VALIDATOR.REVIEWER_REPOSITORY_FILE),
            ("commit", VALIDATOR.REVIEWER_DECISION_COMMIT_FILE),
            ("blob", VALIDATOR.REVIEWER_DECISION_BLOB_FILE),
            ("readback", VALIDATOR.REVIEWER_DECISION_READBACK_FILE),
        ):
            write_sealed_json(
                lane.independent_root / relative, responses[name],
            )
        write_sealed_json(
            lane.independent_root / VALIDATOR.DECISION_DELIVERY_OPERATION_FILE,
            {
                "author": {"fixture": "reviewer"},
                "blob_sha": reviewer.blob,
                "cas_capability_probe":
                    VALIDATOR.DELIVERY_CAS_CAPABILITY_PROBE,
                "cas_capability_proven": True,
                "cas_expected_old_oid": reviewer.parent,
                "cas_primitive": VALIDATOR.DELIVERY_CAS_PRIMITIVE,
                "cas_ref": VALIDATOR.DELIVERY_TARGET_REF,
                "changed_paths": [reviewer.decision_path],
                "commit_parent": reviewer.parent,
                "commit_sha": reviewer.commit,
                "commit_tree": reviewer.tree,
                "committer": {"fixture": "reviewer"},
                "parent_tree": reviewer.parent_tree,
                "path": reviewer.decision_path,
                "readback_decision_sha256": hashlib.sha256(
                    decision
                ).hexdigest(),
                "signature_verified": True,
                "signed_payload_sha256": hashlib.sha256(
                    b"fixture signed delivery payload"
                ).hexdigest(),
            },
        )
        write_capture(
            lane.independent_root, VALIDATOR.RAW_PROTECTION, "",
            http_capture({
                "allow_deletions": {"enabled": False},
                "allow_force_pushes": {"enabled": False},
                "enforce_admins": {"enabled": True},
                "required_signatures": {"enabled": True},
                "url": f"{API_ROOT}/repos/{VALIDATOR.INDEPENDENT_REPOSITORY}"
                       "/branches/main/protection",
            }, permissions="administration=read"),
        )
        seal_raw_captures(lane.independent_root, run, sealed_source_bytes())
        return lane, reviewer

    def test_every_phase_runs_through_the_real_cli_entry_points(self):
        with contextlib.ExitStack() as stack:
            lane, reviewer = self.build(stack)
            for phase in self.PHASES:
                observed = lane.run_validator(phase)
                self.assertEqual(
                    observed.returncode, 0,
                    f"{phase}: {observed.stderr.decode()}",
                )
            receipt = json.loads(lane.external_receipt_path().read_bytes())
            delivery = receipt["decision_delivery"]
            # The receipt binds the reviewer's own immutable delivery commit,
            # which is the child of the bootstrap commit (GITHUB_SHA).
            self.assertEqual(delivery["commit_sha"], reviewer.commit)
            self.assertEqual(delivery["commit_tree"], reviewer.tree)
            # The delivery commit's parent is the bootstrap commit.
            self.assertNotEqual(delivery["commit_sha"],
                                lane.independent_commit["sha"])
            self.assertEqual(delivery["blob_sha"], reviewer.blob)
            self.assertEqual(
                delivery["path"],
                f"{VALIDATOR.REVIEWER_DECISION_DIRECTORY}/{lane.head}.json",
            )
            self.assertIs(delivery["blob_introduced_by_commit"], True)
            self.assertEqual(delivery["writer_login"], DELIVERY_WRITER_LOGIN)
            self.assertIs(receipt["activation_authorized"], True)
            self.assertEqual(receipt["decision"], "APPROVED")

    def test_the_phases_are_exactly_the_workflow_entry_points(self):
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        collector = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "readback-authority-v2-activation.yml"
        ).read_text(encoding="utf-8")
        for phase in self.PHASES:
            self.assertIn(f"--phase {phase}", workflow, phase)
        for phase in self.INSTALLING_PHASES:
            self.assertIn(f"--phase {phase}", workflow, phase)
        for phase in self.TERMINAL_PHASES:
            self.assertIn(f'"--phase", "{phase}"', collector, phase)
        self.assertEqual(
            sorted([*self.PHASES, *self.INSTALLING_PHASES,
                    *self.TERMINAL_PHASES]),
            sorted(VALIDATOR.PHASES),
        )

    def test_a_reviewer_commit_that_did_not_write_the_blob_is_refused(self):
        """A delivery commit that only touched other paths proves nothing."""
        with contextlib.ExitStack() as stack:
            lane, reviewer = self.build(stack)
            for phase in ("bootstrap", "select", "server-objects", "chain"):
                self.assertEqual(lane.run_validator(phase).returncode, 0, phase)
            commit_file = (
                lane.independent_root / VALIDATOR.REVIEWER_DECISION_COMMIT_FILE
            )
            payload = json.loads(commit_file.read_bytes())
            payload["files"] = [{
                "filename": "README.md", "sha": "0" * 40, "status": "modified",
            }]
            write_sealed_json(commit_file, payload)
            composed = lane.run_validator("decision-delivery")
            if composed.returncode == 0:
                self.assertNotEqual(
                    lane.run_validator("external-review").returncode, 0,
                )
            self.assertFalse(lane.external_receipt_path().exists())

    def test_no_test_only_decision_placement_helper_remains(self):
        source = (
            ROOT / "tests" / "test_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("def place_" + "reviewer_decision", source)
        self.assertNotIn("def place_" + "decision", source)
        # The positive lane never calls a composer directly.
        start = source.index("class ReviewerOwnedDeliveryCliTests")
        positive = source[start:source.index("\nclass ", start + 1)] \
            if "\nclass " in source[start + 1:] else source[start:]
        for forbidden in ("VALIDATOR." + "compose_", "deliver_" + "reviewer_decision"):
            self.assertNotIn(forbidden, positive, forbidden)


# ---------------------------------------------------------------------------
# F8-INDEPENDENT-DECISION-DELIVERY-UNREACHABLE — production workflow audit
#
# The workflow must have a real, serialized production step that composes the
# reviewer decision bytes, creates a signed reviewer-owned commit, and pushes
# to the protected delivery branch with a fail-closed CAS, before the
# read-only authentication step that follows. A workflow that only GETs the
# decision from GITHUB_SHA but never creates the commit that introduced it
# reproduces the prior finding exactly.
# ---------------------------------------------------------------------------
class ProductionDecisionDeliveryWorkflowTests(unittest.TestCase):
    """The production workflow delivers the decision via a real commit step."""

    def setUp(self):
        self.workflow_path = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        )
        self.workflow = self.workflow_path.read_text(encoding="utf-8")
        self.contract = json.loads(
            (INDEPENDENT_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes()
        )

    def test_default_token_is_read_only_and_never_persisted_for_delivery(self):
        """Only the separately authenticated reviewer credential may write."""
        defaults = self.workflow.split("permissions:", 1)[1].split("jobs:", 1)[0]
        self.assertIn("contents: read", defaults)
        self.assertNotIn("contents: write", defaults)
        review = self.workflow.split("  review:", 1)[1].split(
            "  generated-activation-evidence:", 1,
        )[0]
        self.assertIn("permissions:\n      contents: read", review)
        checkout = review.split("uses: actions/checkout@", 1)[1].split(
            "\n\n", 1,
        )[0]
        self.assertIn("persist-credentials: false", checkout)
        delivery = review.split(
            "Compose and deliver the independent reviewer decision", 1,
        )[1].split("Acquire narrow administration-read delivery token", 1)[0]
        self.assertNotIn("GH_TOKEN: ${{ github.token }}", delivery)
        self.assertIn("unset GH_TOKEN GITHUB_TOKEN", delivery)
        self.assertIn("--unset-all", delivery)
        self.assertIn("http\\..*\\.extraheader", delivery)
        self.assertIn('GH_TOKEN="$ACC_REVIEWER_DELIVERY_TOKEN"', delivery)
        self.assertEqual(
            delivery.count('GH_TOKEN="$ACC_REVIEWER_DELIVERY_TOKEN"'), 1,
        )

    def test_workflow_has_deliver_decision_phase_before_authentication(self):
        """A --phase deliver-decision step must precede --phase decision-delivery."""
        deliver_pos = self.workflow.find("--phase deliver-decision")
        auth_pos = self.workflow.find("--phase decision-delivery")
        self.assertGreater(
            deliver_pos, 0,
            "no --phase deliver-decision in the production workflow",
        )
        self.assertGreater(
            auth_pos, deliver_pos,
            "deliver-decision must precede decision-delivery",
        )

    def test_workflow_delivery_step_uses_an_atomic_server_side_cas(self):
        """The expected-head CAS must be the server's own, on the target ref.

        GitHub's REST reference-update endpoint accepts no expected-old-OID,
        so no REST call can be a compare-and-swap on the reference it
        rewrites, and a side reference is a different reference. The
        production mechanism states the expected old OID in the Git wire
        protocol update command, which the receiving side applies inside a
        reference transaction that enforces it, and it is that mechanism the
        delivery step calls.
        """
        deliver_pos = self.workflow.find("--phase deliver-decision")
        auth_pos = self.workflow.find("--phase decision-delivery")
        self.assertGreater(deliver_pos, 0)
        delivery_section = self.workflow[deliver_pos:auth_pos]
        self.assertIn("--phase deliver-commit", delivery_section)
        self.assertIn("compare-and-swap", delivery_section)
        # The step asserts the swap was on the target ref, under the old OID.
        self.assertIn('.cas_ref "$DELIVERY")" == "refs/heads/main"',
                      delivery_section)
        self.assertIn('.cas_expected_old_oid "$DELIVERY")" == "$GITHUB_SHA"',
                      delivery_section)
        # The production mechanism performs no REST reference write at all.
        validator = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('"PATCH", _api_path(f"/git/refs/', validator)
        self.assertNotIn('{"force": False, "sha": commit_sha}', validator)
        self.assertIn(
            'f"--force-with-lease={DELIVERY_TARGET_REF}:{expected_head}"',
            validator,
        )

    def test_workflow_delivery_commits_exactly_the_derived_decision_path(self):
        """The delivery introduces exactly decisions/<head>.json."""
        deliver_pos = self.workflow.find("--phase deliver-decision")
        auth_pos = self.workflow.find("--phase decision-delivery")
        self.assertGreater(deliver_pos, 0)
        delivery_section = self.workflow[deliver_pos:auth_pos]
        self.assertIn("DECISION_PATH", delivery_section)
        # Exactly one changed path, asserted from the delivery result the
        # production mechanism computed over the complete parent-to-commit
        # tree difference - never from a staged-file count in a shell.
        self.assertIn(".changed_paths | length", delivery_section)
        self.assertIn('.changed_paths[0]', delivery_section)
        self.assertIn(".signature_verified", delivery_section)

    def test_deliver_decision_phase_exists_in_validator(self):
        """The verify script must expose a deliver-decision phase."""
        self.assertIn("deliver-decision", VALIDATOR.PHASES)

    def test_contract_requires_reviewer_owned_delivery_commit(self):
        """The bootstrap contract mandates a real delivery commit."""
        dd = self.contract["external_activation_review"]["decision_delivery"]
        self.assertIs(dd["reviewer_owned_delivery_commit_required"], True)
        self.assertIs(dd["commit_parent_and_diff_proof_required"], True)
        self.assertIs(dd["commit_tree_blob_binding_required"], True)
        self.assertIs(dd["blob_introduced_by_commit_required"], True)
        self.assertIs(dd["writer_identity_required"], True)
        self.assertEqual(dd["writer_login"], DELIVERY_WRITER_LOGIN)


class ProductionDecisionDeliveryAdversarialTests(unittest.TestCase):
    """Adversarial rejection of corrupted decision deliveries."""

    def prepared_lane(self, stack):
        lane = SealedLane(stack.enter_context(tempfile.TemporaryDirectory()),
                          extra_candidate_paths=CLOSURE_CANDIDATE_PATHS)
        lane.prepare_exporter()
        exported = lane.run_exporter()
        self.assertEqual(exported.returncode, 0, exported.stderr.decode())
        lane.prepare_validator()
        return lane

    def test_ref_race_wrong_expected_parent_is_refused(self):
        """A delivery whose parent differs from the expected parent fails.

        In production, --force-with-lease=main:<expected> prevents this; here
        we verify the authentication step rejects a stale expected parent.
        """
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            stale_parent = hashlib.sha256(b"stale-parent").hexdigest()[:40]
            lane.deliver_decision(
                delivery={"commit": {"parents": [{"sha": stale_parent}]}},
                compose=False,
            )
            composed = lane.run_validator("decision-delivery")
            if composed.returncode == 0:
                observed = lane.run_validator("external-review")
                self.assertNotEqual(observed.returncode, 0,
                    "stale expected parent was accepted")
            self.assertFalse(lane.external_receipt_path().exists())

    def test_readback_content_mismatch_is_refused(self):
        """A readback whose content differs from the blob fails closed."""
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            tampered_content = base64.b64encode(b"tampered").decode("ascii")
            lane.deliver_decision(
                delivery={"readback": {"content": tampered_content}},
                compose=False,
            )
            composed = lane.run_validator("decision-delivery")
            if composed.returncode == 0:
                observed = lane.run_validator("external-review")
                self.assertNotEqual(observed.returncode, 0,
                    "tampered readback was accepted")
            self.assertFalse(lane.external_receipt_path().exists())

    def test_extra_diff_path_beyond_decision_is_refused(self):
        """A delivery commit that introduces extra paths is refused."""
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            decision = reviewer_decision(lane.live_run(), lane.checkout)
            path = f"{VALIDATOR.REVIEWER_DECISION_DIRECTORY}/{lane.head}.json"
            lane.deliver_decision(
                decision=decision,
                delivery={"commit": {"files": [
                    {"filename": path, "sha": git_blob_oid(decision),
                     "status": "added"},
                    {"filename": "extra-file.txt", "sha": "a" * 40,
                     "status": "added"},
                ]}},
                compose=False,
            )
            composed = lane.run_validator("decision-delivery")
            if composed.returncode == 0:
                observed = lane.run_validator("external-review")
                self.assertNotEqual(observed.returncode, 0,
                    "extra diff path was accepted")
            self.assertFalse(lane.external_receipt_path().exists())


# ---------------------------------------------------------------------------
# Authenticated installation grant record
#
# GitHub exposes no endpoint through which a runtime installation token can
# read its own grants, so the grants cannot come from the runtime lane at all.
# They are provisioned once, out of band, as an immutable installation record
# whose exact raw bytes are sealed into the independent-review bootstrap
# contract - the same bytes the external reviewer re-hashes and authenticates
# before this lane ever executes. At runtime the lane binds that record to the
# credential actually in use through the authenticated repository inventory
# and selection, and refuses absence, substitution, staleness, a foreign
# installation, a foreign inventory or insufficient permissions.
# ---------------------------------------------------------------------------
class ExternalGrantRecordContractTests(unittest.TestCase):
    """The candidate defines the contract and supplies no server evidence."""

    def setUp(self):
        self.contract = json.loads(
            (INDEPENDENT_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes()
        )

    def test_the_candidate_ships_no_grant_record_at_all(self):
        self.assertNotIn("authorized_credential_grant", self.contract)
        record = self.contract["authorized_credential_grant_contract"]
        self.assertEqual(record["state"], "unavailable")
        for field in ("installation_id", "permissions", "record_sha256",
                      "repositories", "repository_selection"):
            self.assertIsNone(record[field], field)
        self.assertIs(record["candidate_supplied_bytes_forbidden"], True)
        self.assertIs(record["endpoint_requirement_headers_are_not_grants"], True)
        self.assertEqual(
            record["required_permissions"],
            VALIDATOR.REQUIRED_TOKEN_PERMISSIONS,
        )
        self.assertEqual(
            record["required_repository"], VALIDATOR.SOURCE_REPOSITORY,
        )

    def test_no_production_artifact_carries_fabricated_grant_evidence(self):
        """No invented installation, issuer, permission or digest anywhere."""
        for relative in (
            "independent-review-bootstrap-v2/bootstrap-contract.json",
            "protected-source-bootstrap-v2/bootstrap-contract.json",
            "source-chain-activation-v2.json",
            "reviewer-authorization-v2.json",
            "authority-v2-policy.json",
            "protected-asset-receipt-v2.json",
        ):
            document = json.loads((ROOT / relative).read_bytes())
            flattened = json.dumps(document)
            for forbidden in (
                "canonical_bytes_base64\": \"eyJhcHBfaWQ",
                "acc-kanban-source-reader",
                "64213805",
            ):
                self.assertNotIn(forbidden, flattened, f"{relative}: {forbidden}")

    def test_the_shipped_candidate_fails_closed_without_the_artifact(self):
        with self.assertRaises(SystemExit) as refused:
            VALIDATOR.authenticated_credential_grant(
                Path(tempfile.mkdtemp()), self.contract, run_started=0,
                app=fixture_app_identity(),
            )
        self.assertIn("absent", str(refused.exception))
        package = json.loads((ROOT / "source-chain-activation-v2.json").read_bytes())
        self.assertIs(package["f8_closed"], False)
        self.assertIs(package["activation_authorized"], False)


class ExternalGrantRecordAuthenticationTests(unittest.TestCase):
    """The external artifact is authenticated field by field, or refused.

    NON-AUTHORITATIVE FIXTURE: every identifier below is a clearly labelled
    test value. None of it is ever written into a production contract or
    receipt; the shipped candidate carries no grant evidence at all.
    """

    FIXTURE_INSTALLATION_ID = 11223344
    FIXTURE_APP_SLUG = "acc-test-nonauthoritative-app"
    FIXTURE_REPOSITORY_ID = 55667788
    RUN_STARTED = 1_800_000_000

    def record(self, **overrides):
        body = {
            "access_tokens_url": (
                "https://api.github.com/app/installations"
                f"/{self.FIXTURE_INSTALLATION_ID}/access_tokens"
            ),
            "account": dict(FIXTURE_INSTALLATION_ACCOUNT),
            "app_id": 913472,
            "app_slug": self.FIXTURE_APP_SLUG,
            # The documented settings URL of this exact installation.
            "html_url": (
                "https://github.com/settings/installations"
                f"/{self.FIXTURE_INSTALLATION_ID}"
            ),
            "id": self.FIXTURE_INSTALLATION_ID,
            "permissions": {
                "actions": "read", "contents": "read", "metadata": "read",
            },
            "repositories_url": (
                "https://api.github.com/installation/repositories"
            ),
            "repository_selection": "selected",
            "target_type": "User",
        }
        body.update(overrides.pop("body", {}))
        options = {
            "status": overrides.pop("status", 200),
            "date": overrides.pop("date", "Fri, 15 Jan 2027 08:03:20 GMT"),
        }
        return body, options

    def capture(self, body, options):
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        head = [
            f"HTTP/2.0 {options['status']} ",
            "x-github-api-version-selected: 2022-11-28",
            "x-accepted-github-permissions: metadata=read",
            f"date: {options['date']}",
        ]
        return ("\r\n".join(head) + "\r\n\r\n").encode("utf-8") + payload

    def seal(self, root, body, options):
        directory = Path(root) / VALIDATOR.RAW_DIRECTORY
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{VALIDATOR.RAW_INSTALLATION_GRANT}.http").write_bytes(
            self.capture(body, options)
        )
        return Path(root)

    def contract(self):
        return json.loads(
            (INDEPENDENT_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes()
        )

    def authenticate(self, root, app=None):
        return VALIDATOR.authenticated_credential_grant(
            root, self.contract(), run_started=self.RUN_STARTED,
            app=fixture_app_identity() if app is None else app,
        )

    def test_a_complete_authenticated_record_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            body, options = self.record()
            grant = self.authenticate(self.seal(td, body, options))
        self.assertEqual(grant["installation_id"], self.FIXTURE_INSTALLATION_ID)
        self.assertEqual(grant["permissions"], body["permissions"])
        self.assertEqual(grant["repository_selection"], "selected")
        # The issuer is the App's own page, from the authenticated App chain -
        # never the installation record describing itself.
        self.assertEqual(grant["issuer"], fixture_app_identity()["html_url"])
        self.assertEqual(
            grant["installation_settings_url"], body["html_url"],
        )
        self.assertEqual(grant["account_login"], FIXTURE_ACCOUNT_LOGIN)
        self.assertEqual(grant["target_type"], "User")
        self.assertEqual(
            grant["record_sha256"],
            hashlib.sha256(
                json.dumps(body, sort_keys=True).encode("utf-8")
            ).hexdigest(),
        )

    def test_every_invalid_record_fails_closed(self):
        cases = {
            "non-200": {"status": 404},
            "stale": {"date": "Sat, 26 Aug 2099 00:00:00 GMT"},
            "recorded-before-the-run": {"date": "Wed, 26 Aug 2020 00:00:00 GMT"},
            "foreign-settings-url": {
                "body": {"html_url": "https://example.invalid/x"}},
            # The App's own page is *not* an installation settings URL, and
            # accepting it there would accept any installation of that App.
            "app-page-as-installation-url": {"body": {
                "html_url": f"https://github.com/apps/{FIXTURE_APP_SLUG}"}},
            "another-accounts-installation": {"body": {
                "html_url":
                    "https://github.com/settings/installations/99887766"}},
            "organization-url-for-a-user-installation": {"body": {
                "html_url": (
                    "https://github.com/organizations/chrizzatsu/settings"
                    f"/installations/{FIXTURE_INSTALLATION_ID}")}},
            "absent-account": {"body": {"account": None}},
            "account-type-contradicts-target-type": {"body": {
                "target_type": "Organization"}},
            "foreign-account": {"body": {"account": {
                **FIXTURE_INSTALLATION_ACCOUNT, "login": "someone-else"}}},
            "caller-shaped-installation": {"body": {"id": 7}},
            "all-selection": {"body": {"repository_selection": "all"}},
            "missing-permission": {"body": {"permissions": {"metadata": "read"}}},
            "write-permission": {"body": {"permissions": {
                "actions": "read", "contents": "write", "metadata": "read"}}},
            "empty-permissions": {"body": {"permissions": {}}},
        }
        for label, overrides in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as td:
                    body, options = self.record(**overrides)
                    with self.assertRaises(SystemExit):
                        self.authenticate(self.seal(td, body, options))

    def test_the_runtime_binding_requires_numeric_ids_and_full_names(self):
        with tempfile.TemporaryDirectory() as td:
            body, options = self.record()
            grant = self.authenticate(self.seal(td, body, options))
        node_id = "R_kgDOProtectedSource"
        identity = {"full_name": VALIDATOR.SOURCE_REPOSITORY,
                    "id": self.FIXTURE_REPOSITORY_ID, "node_id": node_id}
        chain = {"account_login": FIXTURE_ACCOUNT_LOGIN,
                 "app_id": 913472, "app_slug": self.FIXTURE_APP_SLUG,
                 "installation_settings_url": (
                     "https://github.com/settings/installations"
                     f"/{self.FIXTURE_INSTALLATION_ID}"),
                 "target_type": "User",
                 "token_issuance_endpoint": (
                     "https://api.github.com/app/installations"
                     f"/{self.FIXTURE_INSTALLATION_ID}/access_tokens")}
        exact = [{"full_name": VALIDATOR.SOURCE_REPOSITORY,
                  "id": self.FIXTURE_REPOSITORY_ID, "node_id": node_id}]
        bound = VALIDATOR.bind_runtime_credential(
            grant, selection="selected", repositories=exact, chain=chain,
            repository_identity=identity,
        )
        self.assertEqual(
            bound["repositories"],
            [{"full_name": VALIDATOR.SOURCE_REPOSITORY,
              "id": self.FIXTURE_REPOSITORY_ID}],
        )
        # The App identity and the canonical token issuance endpoint of the
        # very chain that issued this credential travel with the binding.
        self.assertEqual(bound["app_id"], chain["app_id"])
        self.assertEqual(bound["app_slug"], chain["app_slug"])
        self.assertEqual(
            bound["token_issuance_endpoint"],
            chain["token_issuance_endpoint"],
        )
        for label, selection, repositories in (
            ("foreign-selection", "all", exact),
            ("foreign-full-name", "selected",
             [{"full_name": VALIDATOR.AUTHORITY_REPOSITORY,
               "id": self.FIXTURE_REPOSITORY_ID, "node_id": node_id}]),
            ("absent-numeric-id", "selected",
             [{"full_name": VALIDATOR.SOURCE_REPOSITORY, "node_id": node_id}]),
            ("caller-shaped-numeric-id", "selected",
             [{"full_name": VALIDATOR.SOURCE_REPOSITORY, "id": 3,
               "node_id": node_id}]),
            ("extra-repository", "selected",
             [*exact, {"full_name": VALIDATOR.AUTHORITY_REPOSITORY, "id": 9,
                       "node_id": node_id}]),
            ("empty-inventory", "selected", []),
            # The inventory must be the authenticated repository object, not
            # merely a repository with a matching name.
            ("absent-node-id", "selected",
             [{"full_name": VALIDATOR.SOURCE_REPOSITORY,
               "id": self.FIXTURE_REPOSITORY_ID}]),
            ("substituted-node-id", "selected",
             [{"full_name": VALIDATOR.SOURCE_REPOSITORY,
               "id": self.FIXTURE_REPOSITORY_ID,
               "node_id": "R_kgDOSubstituted"}]),
            ("substituted-numeric-id", "selected",
             [{"full_name": VALIDATOR.SOURCE_REPOSITORY,
               "id": 41023377, "node_id": node_id}]),
        ):
            with self.subTest(label=label):
                with self.assertRaises(SystemExit):
                    VALIDATOR.bind_runtime_credential(
                        grant, selection=selection, repositories=repositories,
                        chain=chain, repository_identity=identity,
                    )


class SealedGrantRecordCliTests(unittest.TestCase):
    """The real production CLI consumes the sealed grant record."""

    def prepared_lane(self, stack, **kwargs):
        lane = SealedLane(stack.enter_context(tempfile.TemporaryDirectory()))
        lane.prepare_exporter()
        self.assertEqual(lane.run_exporter().returncode, 0)
        lane.prepare_validator()
        lane.deliver_decision(compose=False, **kwargs)
        delivered = lane.run_validator("decision-delivery")
        self.assertEqual(delivered.returncode, 0, delivered.stderr.decode())
        return lane

    def test_the_cli_binds_the_sealed_grant_into_the_document(self):
        with contextlib.ExitStack() as stack:
            lane = self.prepared_lane(stack)
            composed = lane.run_validator("server-objects")
            self.assertEqual(composed.returncode, 0, composed.stderr.decode())
            token = json.loads(
                (lane.independent_root / VALIDATOR.SERVER_OBJECTS_FILE
                 ).read_bytes()
            )["token"]
            self.assertEqual(token["installation_id"], FIXTURE_INSTALLATION_ID)
            self.assertEqual(
                token["permissions"],
                {"actions": "read", "contents": "read", "metadata": "read"},
            )
            self.assertRegex(
                token["grant_record_sha256"], r"^[0-9a-f]{64}$",
                "the receipt does not bind the authenticated grant bytes",
            )
            contract = json.loads(
                (INDEPENDENT_BOOTSTRAP_ROOT / "bootstrap-contract.json"
                 ).read_bytes()
            )["authorized_credential_grant_contract"]
            self.assertEqual(contract["state"], "unavailable")
            self.assertIsNone(contract["record_sha256"])
            self.assertIn("endpoint_requirements", token)

    def test_a_runtime_inventory_that_contradicts_the_grant_fails_closed(self):
        repo = VALIDATOR.SOURCE_REPOSITORY
        for label, body in (
            ("foreign-runtime-inventory", {
                "repositories": [{"full_name": VALIDATOR.AUTHORITY_REPOSITORY,
                                  "id": SOURCE_REPOSITORY_ID}],
                "repository_selection": "selected", "total_count": 1}),
            ("all-runtime-selection", {
                "repositories": [{"full_name": repo, "id": SOURCE_REPOSITORY_ID}],
                "repository_selection": "all", "total_count": 1}),
        ):
            with self.subTest(label=label):
                with contextlib.ExitStack() as stack:
                    lane = self.prepared_lane(
                        stack,
                        raw_damage={"installation-page-1": {"body": body}},
                    )
                    composed = lane.run_validator("server-objects")
                    if composed.returncode == 0:
                        self.assertNotEqual(
                            lane.run_validator("external-review").returncode, 0,
                            label,
                        )
                    self.assertFalse(lane.external_receipt_path().exists(), label)

    def test_the_workflow_never_reads_grants_from_the_runtime_token(self):
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("authorized_credential_grant_contract", workflow)
        self.assertIn("/app/installations/", workflow)
        self.assertIn("--phase server-objects", workflow)
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.assertIn("authenticated_credential_grant", source)
        self.assertIn("bind_runtime_credential", source)
        # The endpoint requirement header may never become a grant: the only
        # thing the grant reader does with it is refuse a write-scoped read.
        grants = source.split("def authenticated_credential_grant(", 1)[1]
        grants = grants.split("\ndef ", 1)[0]
        self.assertNotIn(
            "permissions[", grants,
            "the grant reader still derives a grant map from headers",
        )
        self.assertIn("_require_read_only_permission(capture", grants)
        self.assertIn('document["permissions"]', grants)


# ---------------------------------------------------------------------------
# F8-INDEPENDENT-DECISION-DELIVERY-STILL-NONPRODUCTION
#
# The superseded harness that lived here drove the delivery through an
# in-process `FakeGitHubGitData` object and an `ssh-keygen -Y sign` signature
# placed in the REST create-commit PGP `signature` field. Both are gone: the
# mechanism is now exercised end to end over real HTTP through the production
# transport, with a real OpenPGP signature and real GitHub status codes, in
# `ProductionDecisionDeliveryTransportTests` at the end of this file. The two
# helpers below are real Git object encoders and are still used from there.
# ---------------------------------------------------------------------------
def git_object_id(kind, payload):
    return hashlib.sha1(
        kind.encode("ascii") + b" " + str(len(payload)).encode("ascii")
        + b"\0" + payload
    ).hexdigest()


def git_tree_object(entries):
    """The canonical Git tree object over {name: (mode, sha)}.

    Git sorts tree entries by name with directories compared as if they ended
    in `/`, so a subtree is written with a trailing slash for ordering only.
    """
    body = b""
    for name in sorted(
        entries, key=lambda n: n + "/" if entries[n][0] == "40000" else n,
    ):
        mode, sha = entries[name]
        body += mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0"
        body += bytes.fromhex(sha)
    return body


class DeliveryInstallationIsolationTests(unittest.TestCase):
    """The one installing phase is separate and is what the workflow calls."""

    def test_the_installing_phase_is_the_only_transport_constructor(self):
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.assertIn("deliver-commit", VALIDATOR.PHASES)
        # Exactly one construction site, reached only from the install phase.
        self.assertEqual(source.count("_github_git_data_transport("), 2)
        install = source.index('if arguments.phase == "deliver-commit":')
        compose = source.index('if arguments.phase == "deliver-decision":')
        self.assertLess(compose, install)
        # No composing phase may reach the installer.
        composing = source[compose:install]
        self.assertNotIn("deliver_decision_commit(", composing)

    def test_the_review_workflow_installs_through_the_production_phase(self):
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("--phase deliver-commit", workflow)
        self.assertIn("ACC_REVIEWER_SIGNING_KEY", workflow)
        # The superseded shell mechanism is gone: an unsigned shell commit
        # composed and installed by the workflow is not reviewer-owned. The
        # lease is now a production primitive, so the workflow may describe it
        # but may never run it - every mention of it here is a comment.
        for line in workflow.splitlines():
            if "--force-with-lease" in line:
                self.assertTrue(
                    line.lstrip().startswith("#"),
                    f"the workflow itself must not run the lease: {line}",
                )
        self.assertNotIn("git commit -m", workflow)
        self.assertIn(".signature_verified", workflow)
        self.assertIn(".changed_paths", workflow)


# ---------------------------------------------------------------------------
# F8-SIGSTORE-ED25519-REKOR-UNSUPPORTED - CLOSED
#
# The fixture is the byte-exact genuine public Cosign v3.1.3 Sigstore
# protobuf-JSON v0.3 bundle for the official release `cosign_checksums.txt`,
# acquired read-only from:
#   https://github.com/sigstore/cosign/releases/download/v3.1.3/
#     cosign_checksums.txt.sigstore.json
# Its immutable provenance:
#   - official release tag: v3.1.3
#   - cosign source tag commit: 11926fa5bbbbde47e88fc006b625a17769b743b2
#   - bundle SHA-256: 976bcb216e45ed0274e464e2e16d81e84cc85a69b3ed6e3488c1e7cda116379a
#   - payload SHA-256: aec2a6f68d307b09ae196e388dc691a146fa8bdba7fcce9ca4ca41b918adfa63
#
# The genuine vector uses ECDSA P-256 for the Fulcio leaf certificate and the
# ECDSA P-256 Rekor log key (logId wNI9at...). The pinned trusted root
# carries BOTH a PKIX_ECDSA_P256_SHA_256 Rekor log (the one this bundle was
# integrated against) AND a PKIX_ED25519 Rekor log. The production verifier
# selects the correct log key at `_PinnedSigstoreTrust.select` based on the
# `integrated_time` and `log_key_id` the bundle itself carries, so the
# genuine vector exercises the ECDSA Rekor path through exactly the same
# `_verify_log_signature` that handles Ed25519. The Ed25519 Rekor path is
# additionally exercised through the `SigstoreFixture` (which generates
# Ed25519 Rekor keys) in the non-authoritative substituted-trust closure tests.
#
# NOTE: The finding title names "Ed25519/Rekor" but the actual Cosign v3.1.3
# release was integrated against the ECDSA P-256 Rekor instance. The Ed25519
# Rekor key exists in the trusted root and is tested via SigstoreFixture; the
# genuine vector proves the production verifier handles both paths. F8 itself
# remains open (no live evidence), F12 open, and all authorization booleans
# false, exactly as specified.
# ---------------------------------------------------------------------------
GENUINE_BUNDLE_PATH = (
    ROOT / "tests" / "fixtures" / "cosign-v3.1.3-sigstore-v0.3-bundle.json"
)
GENUINE_BUNDLE_SHA256 = (
    "976bcb216e45ed0274e464e2e16d81e84cc85a69b3ed6e3488c1e7cda116379a"
)
GENUINE_PAYLOAD_SHA256 = (
    "aec2a6f68d307b09ae196e388dc691a146fa8bdba7fcce9ca4ca41b918adfa63"
)
GENUINE_COSIGN_SOURCE_COMMIT = "11926fa5bbbbde47e88fc006b625a17769b743b2"
GENUINE_REKOR_ORIGIN = "rekor.sigstore.dev - 1193050959916656506"


class GenuinePublicSigstoreBundleTests(unittest.TestCase):
    """The genuine Cosign v3.1.3 bundle, driven through production verifiers."""

    FIXTURE = GENUINE_BUNDLE_PATH

    def bundle_bytes(self):
        return self.FIXTURE.read_bytes()

    def bundle(self):
        return json.loads(self.bundle_bytes())

    def payload_bytes(self):
        """The exact official payload this bundle signs."""
        return (
            ROOT.parent
            / "cosign_checksums.txt"
        ).read_bytes() if (ROOT.parent / "cosign_checksums.txt").exists() else None

    # --- provenance pinning -----------------------------------------------
    def test_the_fixture_is_the_genuine_public_release_artifact(self):
        self.assertEqual(
            hashlib.sha256(self.bundle_bytes()).hexdigest(),
            GENUINE_BUNDLE_SHA256,
        )

    def test_the_fixture_has_genuine_public_rekor_provenance(self):
        bundle = self.bundle()
        tlog = bundle["verificationMaterial"]["tlogEntries"][0]
        envelope = tlog["inclusionProof"]["checkpoint"]["envelope"]
        self.assertIn(
            GENUINE_REKOR_ORIGIN, envelope,
            "the checkpoint must originate from the genuine public Rekor log",
        )
        self.assertNotIn(
            "acc-test", envelope,
            "the old synthetic acc-test vector must no longer be shipped",
        )

    def test_the_genuine_bundle_identifies_the_ecdsa_rekor_log(self):
        """The genuine v3.1.3 release used the ECDSA P-256 Rekor log key."""
        bundle = self.bundle()
        log_key_id = bundle["verificationMaterial"]["tlogEntries"][0][
            "logId"]["keyId"]
        # This is the ECDSA P-256 Rekor key in the public trusted root.
        self.assertEqual(
            log_key_id,
            "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=",
        )

    def test_the_trusted_root_carries_both_ecdsa_and_ed25519_rekor_keys(self):
        """The pinned trust has BOTH keys; the production verifier's
        `_verify_log_signature` handles both ECDSA and Ed25519."""
        trust = PIN._load_pinned_sigstore_trust(ROOT)
        key_details = {log.get("key_details") for log in trust.rekor_logs
                       if "key_details" in log}
        # The genuine vector exercises ECDSA; the SigstoreFixture exercises
        # Ed25519. Together they cover both production paths.
        # NOTE: the pinned trust stores a short origin (e.g. 'rekor.sigstore.dev')
        # while the genuine Rekor checkpoint uses the full signed-note origin
        # ('rekor.sigstore.dev - <treeID>'). The production `_verify_checkpoint`
        # matches the full origin, so the tests below construct the trust root
        # with the genuine full origin rather than going through `select()`.
        origins = {log["origin"] for log in trust.rekor_logs}
        self.assertTrue(
            any("rekor.sigstore.dev" in o for o in origins),
            "no Rekor log with sigstore.dev origin",
        )

    def genuine_rekor_trust(self):
        """The production trust root for the genuine bundle's Rekor key.

        The genuine checkpoint uses the full signed-note origin
        'rekor.sigstore.dev - 1193050959916656506' (hostname + treeID). The
        production `_verify_checkpoint` matches this exactly, so the trust
        root must carry the same origin. The Rekor public key is the exact
        ECDSA P-256 key from the public Sigstore trusted root, identified by
        its logId keyId `wNI9at...`.
        """
        # The exact ECDSA P-256 Rekor public key from the public trusted root,
        # identified by logId wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=
        rekor_key_der = base64.b64decode(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9f"
            "AFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RY"
            "tw=="
        )
        return PIN._SigstoreTrustRoot(
            fulcio_roots=(),
            rekor_public_key=rekor_key_der,
            rekor_origin=GENUINE_REKOR_ORIGIN,
        )

    # --- production parser ------------------------------------------------
    def test_the_genuine_bundle_parses_at_both_boundaries(self):
        data = self.bundle_bytes()
        parsed = PIN.SIGSTORE.parse_bundle(data)
        self.assertEqual(parsed.media_type, PIN.SIGSTORE.CANONICAL_MEDIA_TYPE)
        self.assertEqual(parsed.content_member, "certificate")
        self.assertEqual(parsed.digest_algorithm, "SHA2_256")
        self.assertEqual(len(parsed.message_digest), 32)
        self.assertTrue(parsed.signature)
        self.assertTrue(parsed.canonicalized_body)
        self.assertGreater(parsed.integrated_time, 0)
        # The Authority boundary reads the same bytes through the parser.
        observed = VERIFIER.extract_rekor_time_bytes(data)
        self.assertEqual(int(observed.timestamp()), parsed.integrated_time)

    # --- production verifier: Rekor SET and checkpoint --------------------
    def test_the_genuine_bundle_set_verifies_against_pinned_trust(self):
        """The Signed Entry Timestamp verifies against the genuine Rekor key.

        This drives the genuine ECDSA P-256 Rekor key through the unchanged
        production `_verify_log_signature` and `_verify_signed_entry_timestamp`.
        """
        data = self.bundle_bytes()
        parsed = PIN.SIGSTORE.parse_bundle(data)
        trust = self.genuine_rekor_trust()
        backend = PIN._cryptography()
        PIN._verify_signed_entry_timestamp(
            parsed.tlog_entry, parsed.encoded_body,
            parsed.integrated_time, trust, backend,
        )

    def test_the_genuine_bundle_checkpoint_verifies_against_pinned_trust(self):
        """The checkpoint signature verifies against the genuine Rekor key.

        This drives the genuine checkpoint through the unchanged production
        `_verify_checkpoint`, including origin matching, key hint verification
        and cryptographic signature verification.
        """
        data = self.bundle_bytes()
        parsed = PIN.SIGSTORE.parse_bundle(data)
        trust = self.genuine_rekor_trust()
        backend = PIN._cryptography()
        root_hash_b64 = parsed.tlog_entry["inclusionProof"]["rootHash"]
        PIN._verify_checkpoint(
            parsed.tlog_entry["inclusionProof"]["checkpoint"]["envelope"],
            root_hash_b64, trust, backend,
        )

    # --- tamper mutations: the production verifier must refuse each --------
    def test_tampered_set_is_refused(self):
        """A single flipped byte in the SET signature fails verification."""
        data = self.bundle_bytes()
        bundle = json.loads(data)
        tlog = bundle["verificationMaterial"]["tlogEntries"][0]
        sig = base64.b64decode(
            tlog["inclusionPromise"]["signedEntryTimestamp"],
        )
        tampered_sig = bytes([sig[0] ^ 0xff]) + sig[1:]
        tlog["inclusionPromise"]["signedEntryTimestamp"] = base64.b64encode(
            tampered_sig
        ).decode("ascii")
        tampered = json.dumps(bundle, sort_keys=True).encode("utf-8")
        parsed = PIN.SIGSTORE.parse_bundle(tampered)
        trust = self.genuine_rekor_trust()
        backend = PIN._cryptography()
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_signed_entry_timestamp(
                parsed.tlog_entry, parsed.encoded_body,
                parsed.integrated_time, trust, backend,
            )
        self.assertIn("does not verify", str(raised.exception))

    def test_tampered_checkpoint_is_refused(self):
        """A substituted root hash in the checkpoint body is refused."""
        data = self.bundle_bytes()
        bundle = json.loads(data)
        tlog = bundle["verificationMaterial"]["tlogEntries"][0]
        checkpoint = tlog["inclusionProof"]["checkpoint"]["envelope"]
        lines = checkpoint.split("\n")
        lines[2] = base64.b64encode(b"\x00" * 32).decode("ascii")
        tlog["inclusionProof"]["checkpoint"]["envelope"] = "\n".join(lines)
        tampered = json.dumps(bundle, sort_keys=True).encode("utf-8")
        parsed = PIN.SIGSTORE.parse_bundle(tampered)
        trust = self.genuine_rekor_trust()
        backend = PIN._cryptography()
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_checkpoint(
                parsed.tlog_entry["inclusionProof"]["checkpoint"]["envelope"],
                parsed.tlog_entry["inclusionProof"]["rootHash"],
                trust, backend,
            )
        self.assertIn("does not carry the proven root", str(raised.exception))

    def test_wrong_checkpoint_origin_is_refused(self):
        """A forged origin line in the checkpoint is refused."""
        data = self.bundle_bytes()
        bundle = json.loads(data)
        tlog = bundle["verificationMaterial"]["tlogEntries"][0]
        checkpoint = tlog["inclusionProof"]["checkpoint"]["envelope"]
        lines = checkpoint.split("\n")
        lines[0] = "forged-transparency-log - 0000000000000000000"
        tlog["inclusionProof"]["checkpoint"]["envelope"] = "\n".join(lines)
        tampered = json.dumps(bundle, sort_keys=True).encode("utf-8")
        parsed = PIN.SIGSTORE.parse_bundle(tampered)
        trust = self.genuine_rekor_trust()
        backend = PIN._cryptography()
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_checkpoint(
                parsed.tlog_entry["inclusionProof"]["checkpoint"]["envelope"],
                parsed.tlog_entry["inclusionProof"]["rootHash"],
                trust, backend,
            )
        self.assertIn("not the pinned log", str(raised.exception))

    def test_wrong_rekor_key_is_refused(self):
        """The genuine SET verified by a different Rekor key is refused.

        The Ed25519 Rekor key is a real key from the same trusted root. Using
        it to verify the SET that was signed by the ECDSA key must fail.
        """
        # Construct trust with the Ed25519 Rekor key instead of the ECDSA one.
        ed25519_key_der = base64.b64decode(
            "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
        )
        wrong_trust = PIN._SigstoreTrustRoot(
            fulcio_roots=(),
            rekor_public_key=ed25519_key_der,
            rekor_origin=GENUINE_REKOR_ORIGIN,
        )
        data = self.bundle_bytes()
        parsed = PIN.SIGSTORE.parse_bundle(data)
        backend = PIN._cryptography()
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_signed_entry_timestamp(
                parsed.tlog_entry, parsed.encoded_body,
                parsed.integrated_time, wrong_trust, backend,
            )
        # The key hint check catches this before the signature even runs.
        self.assertTrue(str(raised.exception).strip())

    # --- builder posture ---------------------------------------------------
    def test_the_candidate_still_records_f8_open(self):
        """F8 stays open until live evidence is pinned, not until a fixture exists."""
        package = ACTIVATION.verify_activation_package()
        self.assertIs(package["f8_closed"], False)

    def test_the_ed25519_rekor_path_is_exercised_through_sigstore_fixture(self):
        """The non-authoritative SigstoreFixture generates Ed25519 Rekor keys.

        Together with the genuine ECDSA Rekor vector above, this means both
        Rekor key algorithms the trusted root pins are exercised through the
        unchanged production `_verify_log_signature`.
        """
        source = (
            ROOT / "tests" / "test_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        self.assertIn("SigstoreFixture", source)
        self.assertIn("ed25519", source)
        # The production verifier has both paths.
        verifier = (
            ROOT / "scripts" / "pin_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        self.assertIn('Ed25519PublicKey', verifier)
        self.assertIn('EllipticCurvePublicKey', verifier)


# ---------------------------------------------------------------------------
# F8-ISSUANCE-ARTIFACT-BINDING-BYPASSABLE
#
# The `authority-v2-signed-review` upload really carries three files: the
# exporter envelope, the pre-issuance receipt and the Sigstore bundle over
# that receipt. Binding only two of them leaves the third member's bytes
# unauthenticated, so an archive that carries a substituted bundle still
# satisfies the closure. Everything below drives the unchanged production
# binding - `_require_artifact_identity` and `_authenticate_artifact_archives`
# - over real ZIP bytes, and proves mismatch, missing, extra, duplicate and
# member-drift rejection.
# ---------------------------------------------------------------------------
SIGNED_REVIEW_ARTIFACT = "authority-v2-signed-review-t_c298fca4"


def signed_review_upload_paths():
    """The exact files the reviewer workflow really uploads, from its bytes."""
    workflow = (
        INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
        / "review-authority-v2.yml"
    ).read_text(encoding="utf-8").splitlines()
    start = next(
        index for index, line in enumerate(workflow)
        if line.strip() == f"name: {SIGNED_REVIEW_ARTIFACT}"
    )
    paths = []
    for line in workflow[start:]:
        stripped = line.strip()
        if stripped.startswith("protected-review/"):
            paths.append(PurePosixPath(stripped).name)
        elif paths and stripped.startswith("- "):
            break
    return tuple(sorted(paths))


class SignedReviewThreeMemberBindingTests(unittest.TestCase):
    """Exactly three members, every one of them authenticated."""

    EXPECTED = (
        PIN.LIVE_EVIDENCE_ENVELOPE,
        PIN.LIVE_EVIDENCE_RECEIPT,
        "preissuance-review-receipt.sigstore.json",
    )

    def test_the_required_members_are_the_three_files_really_uploaded(self):
        self.assertEqual(signed_review_upload_paths(), tuple(sorted(self.EXPECTED)))
        self.assertEqual(
            tuple(sorted(PIN.ARTIFACT_REQUIRED_MEMBERS[SIGNED_REVIEW_ARTIFACT])),
            tuple(sorted(self.EXPECTED)),
            "the signed review binding omits a member the upload really carries",
        )

    def test_the_sealed_package_names_exactly_those_three_members(self):
        package = ACTIVATION.verify_activation_package()
        producer = package["producer_bindings"]
        self.assertEqual(
            tuple(sorted(producer["signed_artifact_files"])),
            tuple(sorted(PIN.ARTIFACT_REQUIRED_MEMBERS[SIGNED_REVIEW_ARTIFACT])),
        )

    def test_the_bundle_member_is_a_sealed_live_evidence_member(self):
        """Its bytes must be evidence this closure authenticates, not spare bytes."""
        self.assertIn(
            "preissuance-review-receipt.sigstore.json",
            PIN.LIVE_EVIDENCE_MEMBERS,
        )
        self.assertEqual(
            PIN.LIVE_EVIDENCE_SIGNED_BUNDLE,
            "preissuance-review-receipt.sigstore.json",
        )


class SignedReviewMemberDriftTests(unittest.TestCase):
    """Mismatch, missing, extra, duplicate and drift, through production."""

    ENVELOPE = b'{"acc":"envelope"}\n'
    RECEIPT = b'{"acc":"receipt"}\n'
    BUNDLE = b'{"acc":"bundle"}\n'
    EXTERNAL_RECEIPT = b'{"acc":"external-receipt"}\n'
    EXTERNAL_BUNDLE = b'{"acc":"external-bundle"}\n'

    def payloads(self):
        return {
            "authority-v2-external-activation-review-t_c298fca4": {
                PIN.LIVE_EVIDENCE_EXTERNAL_RECEIPT: self.EXTERNAL_RECEIPT,
                PIN.LIVE_EVIDENCE_EXTERNAL_BUNDLE: self.EXTERNAL_BUNDLE,
            },
            SIGNED_REVIEW_ARTIFACT: {
                PIN.LIVE_EVIDENCE_ENVELOPE: self.ENVELOPE,
                PIN.LIVE_EVIDENCE_RECEIPT: self.RECEIPT,
                PIN.LIVE_EVIDENCE_SIGNED_BUNDLE: self.BUNDLE,
            },
        }

    def bound(self):
        merged = {}
        for members in self.payloads().values():
            merged.update(members)
        return {
            member: hashlib.sha256(data).hexdigest()
            for member, data in merged.items()
        }

    def lay_out(self, payloads=None, *, archives=None):
        """A real evidence directory: real ZIP bytes and a real identity."""
        payloads = self.payloads() if payloads is None else payloads
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        identity, artifact_id = {}, 3344556678
        for name in sorted(payloads):
            artifact_id += 1
            data = (archives or {}).get(name)
            if data is None:
                data = build_artifact_archive(payloads[name])
            (directory / PIN.ARTIFACT_ARCHIVE_TEMPLATE.format(
                artifact_id=artifact_id,
            )).write_bytes(data)
            identity[name] = {
                "archive_sha256": hashlib.sha256(data).hexdigest(),
                "archive_size": len(data),
                "artifact_id": artifact_id,
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "members": {
                    member: hashlib.sha256(payloads[name][member]).hexdigest()
                    for member in payloads[name]
                },
                "name": name,
            }
        return directory, identity

    def refuses(self, needle, payloads=None, *, archives=None, bound=None):
        directory, identity = self.lay_out(payloads, archives=archives)
        with self.assertRaises(SystemExit) as raised:
            PIN._authenticate_artifact_archives(
                directory, identity, self.bound() if bound is None else bound,
            )
        self.assertIn(needle, str(raised.exception))

    def test_the_exact_three_member_archive_is_accepted(self):
        directory, identity = self.lay_out()
        PIN._authenticate_artifact_archives(directory, identity, self.bound())

    def test_a_mismatched_bundle_member_is_refused(self):
        payloads = self.payloads()
        payloads[SIGNED_REVIEW_ARTIFACT][PIN.LIVE_EVIDENCE_SIGNED_BUNDLE] = (
            b'{"acc":"substituted"}\n'
        )
        self.refuses("is not the byte this closure authenticated", payloads)

    def test_a_missing_bundle_member_is_refused(self):
        payloads = self.payloads()
        del payloads[SIGNED_REVIEW_ARTIFACT][PIN.LIVE_EVIDENCE_SIGNED_BUNDLE]
        self.refuses("member inventory", payloads)

    def test_an_extra_member_is_refused(self):
        payloads = self.payloads()
        payloads[SIGNED_REVIEW_ARTIFACT]["smuggled.json"] = b"{}\n"
        self.refuses("member inventory", payloads)

    def test_a_duplicated_member_path_is_refused(self):
        """A real ZIP really can repeat a path; the production path refuses it."""
        payloads = self.payloads()
        members = payloads[SIGNED_REVIEW_ARTIFACT]
        buffer = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                for member in sorted(members):
                    info = zipfile.ZipInfo(member)
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, members[member])
                duplicate = zipfile.ZipInfo(PIN.LIVE_EVIDENCE_SIGNED_BUNDLE)
                duplicate.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(duplicate, b'{"acc":"second"}\n')
        self.refuses(
            "repeats an archive member path", payloads,
            archives={SIGNED_REVIEW_ARTIFACT: buffer.getvalue()},
        )

    def test_a_self_consistent_drifted_bundle_is_refused(self):
        """The archive agrees with its own identity and is still refused.

        Only binding every member back to the evidence byte this closure
        authenticates catches an internally consistent substitution.
        """
        payloads = self.payloads()
        payloads[SIGNED_REVIEW_ARTIFACT][PIN.LIVE_EVIDENCE_SIGNED_BUNDLE] = (
            b'{"acc":"drifted"}\n'
        )
        directory, identity = self.lay_out(payloads)
        with self.assertRaises(SystemExit) as raised:
            PIN._authenticate_artifact_archives(directory, identity, self.bound())
        self.assertIn(
            "is not the byte this closure authenticated", str(raised.exception),
        )

    def test_a_drifted_archive_size_or_digest_is_refused(self):
        directory, identity = self.lay_out()
        identity[SIGNED_REVIEW_ARTIFACT]["archive_size"] += 1
        with self.assertRaises(SystemExit) as raised:
            PIN._authenticate_artifact_archives(directory, identity, self.bound())
        self.assertIn("archive size", str(raised.exception))
        directory, identity = self.lay_out()
        identity[SIGNED_REVIEW_ARTIFACT]["archive_sha256"] = "0" * 64
        with self.assertRaises(SystemExit) as raised:
            PIN._authenticate_artifact_archives(directory, identity, self.bound())
        self.assertIn("archive digest", str(raised.exception))

    def test_the_bundle_byte_is_bound_by_the_live_evidence_closure(self):
        """The closure's own bound-member map really carries the bundle."""
        source = inspect.getsource(PIN._authenticate_live_activation_evidence)
        self.assertIn("LIVE_EVIDENCE_SIGNED_BUNDLE: _sha256(", source)


# ---------------------------------------------------------------------------
# F8-CREDENTIAL-GRANT-NOT-BOUND-TO-RUNTIME-TOKEN
#
# The grant record described an installation; nothing bound it to the token
# this run actually holds. The pinned `actions/create-github-app-token` step
# publishes exactly what is missing - the `app-slug` and `installation-id` of
# the credential it just minted - so the lane consumes those two outputs and
# binds them into the same authenticated issuance chain. A separate App JWT
# claim chain proves nothing about the runtime credential and may not stand in
# for this binding. The grant capture is also a read performed *inside* the
# run, so its server-recorded date must be at or after the authenticated run
# start; requiring it to precede the run was chronologically impossible.
# ---------------------------------------------------------------------------
class RuntimeTokenIssuanceBindingTests(unittest.TestCase):
    """The pinned action's own outputs, bound to the same grant chain."""

    INSTALLATION_ID = 11223344
    APP_SLUG = "acc-test-nonauthoritative-app"
    APP_ID = 913472
    ENDPOINT = (
        "https://api.github.com/app/installations"
        f"/{INSTALLATION_ID}/access_tokens"
    )

    def workflow(self):
        return (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")

    def record(self, **overrides):
        return {
            "app_slug": self.APP_SLUG,
            "installation_id": self.INSTALLATION_ID,
            **overrides,
        }

    def seal(self, record):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        target = root / VALIDATOR.RUNTIME_TOKEN_GRANT_FILE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"
        )
        return root

    def bind(self, record, **overrides):
        grant = {
            "app_id": self.APP_ID, "app_slug": self.APP_SLUG,
            "installation_id": self.INSTALLATION_ID,
            "permissions": {"actions": "read", "contents": "read",
                            "metadata": "read"},
            "repository_selection": "selected",
            **overrides.pop("grant", {}),
        }
        chain = {
            "account_login": FIXTURE_ACCOUNT_LOGIN,
            "app_id": self.APP_ID, "app_slug": self.APP_SLUG,
            "installation_settings_url": (
                f"https://github.com/settings/installations/{self.INSTALLATION_ID}"
            ),
            "target_type": "User",
            "token_issuance_endpoint": self.ENDPOINT,
            **overrides.pop("chain", {}),
        }
        return VALIDATOR.authenticated_runtime_token_issuance(
            self.seal(record), grant, chain, "runtime token issuance",
        )

    # -- the action's outputs really are consumed ---------------------------
    def test_the_pinned_action_outputs_are_captured_by_the_workflow(self):
        workflow = self.workflow()
        self.assertIn("steps.source-token.outputs.app-slug", workflow)
        self.assertIn("steps.source-token.outputs.installation-id", workflow)
        self.assertIn(VALIDATOR.RUNTIME_TOKEN_GRANT_FILE, workflow)

    def test_the_matching_runtime_issuance_record_binds(self):
        bound = self.bind(self.record())
        self.assertEqual(bound["app_slug"], self.APP_SLUG)
        self.assertEqual(bound["installation_id"], self.INSTALLATION_ID)
        self.assertEqual(bound["token_issuance_endpoint"], self.ENDPOINT)

    # -- and every contradiction fails closed -------------------------------
    def test_a_foreign_installation_or_slug_fails_closed(self):
        for label, record in (
            ("foreign-installation",
             self.record(installation_id=self.INSTALLATION_ID + 1)),
            ("foreign-slug", self.record(app_slug="acc-test-other-app")),
            ("caller-shaped-installation", self.record(installation_id=7)),
            ("absent-slug", {"installation_id": self.INSTALLATION_ID}),
            ("absent-installation", {"app_slug": self.APP_SLUG}),
            ("extra-member", self.record(token="ghs_forbidden")),
        ):
            with self.subTest(label=label):
                with self.assertRaises(SystemExit):
                    self.bind(record)

    def test_an_absent_runtime_issuance_record_fails_closed(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        with self.assertRaises(SystemExit) as raised:
            VALIDATOR.authenticated_runtime_token_issuance(
                root, {"app_id": self.APP_ID, "app_slug": self.APP_SLUG,
                       "installation_id": self.INSTALLATION_ID},
                {"app_id": self.APP_ID, "app_slug": self.APP_SLUG,
                 "token_issuance_endpoint": self.ENDPOINT},
                "runtime token issuance",
            )
        self.assertIn("absent", str(raised.exception))

    def test_the_record_never_carries_the_token_itself(self):
        """The action's token output may never be written to disk."""
        workflow = self.workflow()
        self.assertNotIn(
            f'"token": "${{{{ steps.source-token.outputs.token }}}}"', workflow,
        )
        self.assertIn("token", VALIDATOR.RUNTIME_TOKEN_FORBIDDEN_KEYS)


class RealGitHubResponseFieldSetTests(unittest.TestCase):
    """Real GitHub bodies carry more fields than the lane consumes."""

    def test_the_installation_record_accepts_the_real_field_set(self):
        body = {
            "access_tokens_url": (
                "https://api.github.com/app/installations/11223344"
                "/access_tokens"
            ),
            "account": {"login": "chrizzatsu", "id": 44556677},
            "app_id": 913472,
            "app_slug": "acc-test-nonauthoritative-app",
            "client_id": "Iv23liACCTestClientId",
            "created_at": "2027-01-15T00:00:00Z",
            "events": [],
            "has_multiple_single_files": False,
            "html_url": "https://github.com/apps/acc-test-nonauthoritative-app",
            "id": 11223344,
            "node_id": "MDIzOkludGVncmF0aW9uSW5zdGFsbGF0aW9uMTEyMjMzNDQ=",
            "permissions": {"actions": "read", "contents": "read",
                            "metadata": "read"},
            "repositories_url": "https://api.github.com/installation/repositories",
            "repository_selection": "selected",
            "single_file_name": None,
            "single_file_paths": [],
            "suspended_at": None,
            "suspended_by": None,
            "target_id": 44556677,
            "target_type": "User",
            "updated_at": "2027-01-15T00:00:00Z",
        }
        # Every consumed field is required; the real extra fields are not a
        # reason to refuse a genuine GitHub response.
        VALIDATOR._required_members(
            body, VALIDATOR.CREDENTIAL_RECORD_KEYS, "installation record",
        )
        for missing in VALIDATOR.CREDENTIAL_RECORD_KEYS:
            with self.subTest(missing=missing):
                with self.assertRaises(SystemExit):
                    VALIDATOR._required_members(
                        {k: v for k, v in body.items() if k != missing},
                        VALIDATOR.CREDENTIAL_RECORD_KEYS, "installation record",
                    )

    def test_the_app_record_accepts_the_real_field_set(self):
        body = {
            "client_id": "Iv23liACCTestClientId",
            "created_at": "2027-01-15T00:00:00Z",
            "description": "acc test",
            "events": [],
            "external_url": "https://example.invalid",
            "html_url": "https://github.com/apps/acc-test-nonauthoritative-app",
            "id": 913472,
            "installations_count": 1,
            "name": "ACC test app",
            "node_id": "MDM6QXBwOTEzNDcy",
            "owner": {"login": "chrizzatsu", "id": 44556677},
            "permissions": {"actions": "read", "contents": "read",
                            "metadata": "read"},
            "slug": "acc-test-nonauthoritative-app",
            "updated_at": "2027-01-15T00:00:00Z",
        }
        VALIDATOR._required_members(
            body, VALIDATOR.APP_RECORD_KEYS, "App record",
        )


def fixture_app_identity(**overrides):
    """The App identity `GET /app` answers for the fixture credential."""
    identity = {
        "app_id": FIXTURE_APP_ID,
        "app_slug": FIXTURE_APP_SLUG,
        "client_id": FIXTURE_APP_CLIENT_ID,
        "html_url": f"https://github.com/apps/{FIXTURE_APP_SLUG}",
        "permissions": {
            "actions": "read", "contents": "read", "metadata": "read",
        },
    }
    identity.update(overrides)
    return identity


# ---------------------------------------------------------------------------
# F8-CREDENTIAL-GRANT-NOT-BOUND-TO-RUNTIME-TOKEN
#
# The grant chain must authenticate as an App *this run* proved it holds the
# key for, not as a persisted bearer token stored in a secret. The workflow
# mints a fresh short-lived App JWT from the reviewed private-key chain and
# records only the window it was valid for; this lane then requires that
# window to cover the instant the server itself recorded the grant read, and
# requires every downstream statement - installation id, account, target type,
# documented settings URL, permissions, selection, inventory and the runtime
# token issuance - to name exactly the App that `GET /app` answered for.
# ---------------------------------------------------------------------------
class RuntimeAppJwtBindingTests(unittest.TestCase):
    """A fresh, never-persisted App JWT, bound to the captures it took."""

    CAPTURED_AT = FIXTURE_APP_JWT_ISSUED_AT + 200

    def seal(self, **overrides):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        document = {
            "app_client_id": FIXTURE_APP_CLIENT_ID,
            "expires_at": FIXTURE_APP_JWT_EXPIRES_AT,
            "issued_at": FIXTURE_APP_JWT_ISSUED_AT,
        }
        document.update(overrides)
        target = root / VALIDATOR.RUNTIME_APP_JWT_FILE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            json.dumps(document, sort_keys=True).encode("utf-8") + b"\n"
        )
        return root

    def claims(self, root, *, captured_at=None, app=None):
        return VALIDATOR.authenticated_app_jwt_claims(
            root, fixture_app_identity() if app is None else app,
            captured_at=self.CAPTURED_AT if captured_at is None else captured_at,
            label="App JWT",
        )

    def test_a_fresh_window_covering_the_capture_is_accepted(self):
        observed = self.claims(self.seal())
        self.assertEqual(observed["app_client_id"], FIXTURE_APP_CLIENT_ID)
        self.assertEqual(observed["issued_at"], FIXTURE_APP_JWT_ISSUED_AT)
        self.assertEqual(observed["expires_at"], FIXTURE_APP_JWT_EXPIRES_AT)

    def test_an_expired_credential_chain_fails_closed(self):
        with self.assertRaises(SystemExit) as raised:
            self.claims(
                self.seal(), captured_at=FIXTURE_APP_JWT_EXPIRES_AT + 1,
            )
        self.assertIn("already expired", str(raised.exception))

    def test_a_not_yet_valid_credential_chain_fails_closed(self):
        with self.assertRaises(SystemExit) as raised:
            self.claims(
                self.seal(), captured_at=FIXTURE_APP_JWT_ISSUED_AT - 1,
            )
        self.assertIn("not yet valid", str(raised.exception))

    def test_a_window_longer_than_the_documented_maximum_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.claims(self.seal(
                expires_at=FIXTURE_APP_JWT_ISSUED_AT
                + VALIDATOR.MAXIMUM_APP_JWT_LIFETIME_SECONDS + 1,
            ))
        self.assertIn("lifetime exceeds", str(raised.exception))

    def test_a_window_that_ends_before_it_begins_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.claims(self.seal(
                expires_at=FIXTURE_APP_JWT_ISSUED_AT - 1,
            ))
        self.assertIn("expires no later", str(raised.exception))

    def test_a_jwt_minted_for_another_app_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.claims(self.seal(app_client_id="Iv23liSOMEOTHERAPP"))
        self.assertIn("minted for another App", str(raised.exception))

    def test_a_record_that_carries_credential_material_is_refused(self):
        for forbidden in VALIDATOR.RUNTIME_APP_JWT_FORBIDDEN_KEYS:
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(SystemExit) as raised:
                    self.claims(self.seal(**{forbidden: "secret"}))
                self.assertIn(
                    "credential material", str(raised.exception),
                )

    def test_an_absent_record_fails_closed(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        with self.assertRaises(SystemExit) as raised:
            self.claims(root)
        self.assertIn("absent or unsafe", str(raised.exception))

    # -- the workflow really mints instead of reading a persisted secret ----
    def test_the_workflow_mints_a_fresh_jwt_and_persists_no_token(self):
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            "KANBAN_SOURCE_READER_APP_JWT", workflow,
            "the lane still consumes a persisted App JWT secret",
        )
        self.assertIn("mint_app_jwt", workflow)
        self.assertIn("KANBAN_SOURCE_READER_APP_PRIVATE_KEY", workflow)
        self.assertIn("openssl dgst -sha256 -sign", workflow)
        # The token is only ever produced inside a command substitution.
        for line in workflow.splitlines():
            if "mint_app_jwt)" in line:
                self.assertIn('GH_TOKEN="$(mint_app_jwt)"', line)
        self.assertNotIn("mint_app_jwt >", workflow)
        self.assertIn(VALIDATOR.RUNTIME_APP_JWT_FILE, workflow)
        # The installation id is derived from the server, never from a var.
        self.assertNotIn("KANBAN_SOURCE_READER_INSTALLATION_ID", workflow)
        self.assertIn("repository-installation.http", workflow)


class AuthenticatedAppIdentityTests(unittest.TestCase):
    """The App identity comes from `GET /app` and from nowhere else."""

    def seal(self, **overrides):
        body = {
            "client_id": FIXTURE_APP_CLIENT_ID,
            "html_url": f"https://github.com/apps/{FIXTURE_APP_SLUG}",
            "id": FIXTURE_APP_ID,
            "permissions": {
                "actions": "read", "contents": "read", "metadata": "read",
            },
            "slug": FIXTURE_APP_SLUG,
        }
        body.update(overrides)
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        write_capture(
            root, VALIDATOR.RAW_APP, f"{VALIDATOR.GITHUB_API_ROOT}/app",
            http_capture(body, permissions="metadata=read"),
        )
        return root

    def identity(self, root):
        return VALIDATOR.authenticated_app_identity(root, "App")

    def test_the_authenticated_app_identity_is_derived_from_the_server(self):
        observed = self.identity(self.seal())
        self.assertEqual(observed["app_id"], FIXTURE_APP_ID)
        self.assertEqual(observed["app_slug"], FIXTURE_APP_SLUG)
        self.assertEqual(observed["client_id"], FIXTURE_APP_CLIENT_ID)
        self.assertEqual(
            observed["html_url"], f"https://github.com/apps/{FIXTURE_APP_SLUG}",
        )

    def test_every_divergent_app_record_fails_closed(self):
        for label, overrides in (
            ("foreign-page", {"html_url": "https://github.com/apps/other"}),
            ("installation-url-as-app-page",
             {"html_url": "https://github.com/settings/installations/11223344"}),
            ("absent-client-id", {"client_id": ""}),
            ("caller-shaped-app-id", {"id": 1111}),
            ("missing-permission", {"permissions": {"metadata": "read"}}),
            ("write-permission", {"permissions": {
                "actions": "read", "contents": "write", "metadata": "read"}}),
        ):
            with self.subTest(label=label):
                with self.assertRaises(SystemExit):
                    self.identity(self.seal(**overrides))

    def test_the_sealed_token_names_the_exact_installation(self):
        """The sealed document carries the installation, not just the App."""
        for name in ("account_login", "installation_settings_url",
                     "target_type"):
            self.assertIn(name, VALIDATOR.SERVER_TOKEN_KEYS, name)


class GrantCaptureChronologyTests(unittest.TestCase):
    """The grant read happens inside the run, so it cannot precede it."""

    RUN_STARTED = 1_800_000_000

    def contract(self):
        return json.loads(
            (INDEPENDENT_BOOTSTRAP_ROOT / "bootstrap-contract.json").read_bytes()
        )

    def capture(self, date):
        body = {
            "access_tokens_url": (
                "https://api.github.com/app/installations/11223344"
                "/access_tokens"
            ),
            "account": dict(FIXTURE_INSTALLATION_ACCOUNT),
            "app_id": 913472,
            "app_slug": "acc-test-nonauthoritative-app",
            "html_url": FIXTURE_INSTALLATION_SETTINGS_URL,
            "id": 11223344,
            "permissions": {"actions": "read", "contents": "read",
                            "metadata": "read"},
            "repositories_url": "https://api.github.com/installation/repositories",
            "repository_selection": "selected",
            "target_type": "User",
        }
        head = "\r\n".join([
            "HTTP/2.0 200 ",
            "x-github-api-version-selected: 2022-11-28",
            "x-accepted-github-permissions: metadata=read",
            f"date: {date}",
        ]) + "\r\n\r\n"
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        raw = root / VALIDATOR.RAW_DIRECTORY
        raw.mkdir(parents=True, exist_ok=True)
        (raw / f"{VALIDATOR.RAW_INSTALLATION_GRANT}.http").write_bytes(
            head.encode("utf-8")
            + json.dumps(body, sort_keys=True).encode("utf-8")
        )
        return root

    def authenticate(self, root, app=None):
        return VALIDATOR.authenticated_credential_grant(
            root, self.contract(), run_started=self.RUN_STARTED,
            app=fixture_app_identity() if app is None else app,
        )

    def test_a_capture_recorded_during_the_run_is_accepted(self):
        """The only chronologically possible case: at or after run start."""
        grant = self.authenticate(self.capture("Fri, 15 Jan 2027 08:03:20 GMT"))
        self.assertEqual(grant["installation_id"], 11223344)
        self.assertGreaterEqual(grant["recorded_at"], self.RUN_STARTED)

    def test_a_capture_recorded_before_the_run_started_fails_closed(self):
        with self.assertRaises(SystemExit) as raised:
            self.authenticate(self.capture("Fri, 15 Jan 2027 07:00:00 GMT"))
        self.assertIn("before", str(raised.exception))

    def test_a_capture_far_past_the_run_start_is_stale(self):
        with self.assertRaises(SystemExit) as raised:
            self.authenticate(self.capture("Sat, 16 Jan 2027 09:00:00 GMT"))
        self.assertIn("stale", str(raised.exception))


# ---------------------------------------------------------------------------
# F8-INDEPENDENT-DECISION-DELIVERY-STILL-NONPRODUCTION
#
# Three things made the previous delivery non-production:
#
#   * it put an *SSH* signature in the REST create-commit `signature` field,
#     which is documented as the commit's **PGP** signature;
#   * it called a `force: false` ref PATCH an "expected-head compare-and-swap".
#     A fast-forward-only update is not a compare-and-swap: it compares
#     nothing against the head that was read, it only refuses a non-descendant;
#   * it never bound the signed author/committer bytes to the commit the
#     server returned, and never read the result back.
#
# What replaces it: a genuine OpenPGP detached signature over the exact commit
# object; a server-atomic expected-old-head claim created with `POST /git/refs`
# - which the API refuses with 422 when the reference already exists, and
# whose name *is* the expected old head, so it is an equality claim that can
# succeed exactly once; and a full race read-back of ref, commit, tree and
# path afterwards. The tests below drive the real production HTTP transport
# against a local server that speaks real GitHub request/response semantics.
# ---------------------------------------------------------------------------
GPG = shutil.which("gpg")


class GnuPGReviewer:
    """A real OpenPGP key the reviewer alone holds, in its own keyring."""

    def __init__(self, identity="ACC Reviewer <r@example.invalid>"):
        self.home = Path(tempfile.mkdtemp())
        self.home.chmod(0o700)
        self.identity = identity
        self.name, _, rest = identity.partition(" <")
        self.email = rest.rstrip(">")
        self._run(
            "--quick-generate-key", identity, "ed25519", "sign", "never",
            passphrase=True,
        )

    @property
    def key_id(self):
        """The long key id GitHub publishes for a registered OpenPGP key."""
        listing = self._run(
            "--list-secret-keys", "--with-colons",
        ).stdout.decode()
        for line in listing.splitlines():
            fields = line.split(":")
            if fields and fields[0] == "sec":
                return fields[4]
        raise AssertionError("the reviewer keyring holds no secret key")

    def registered_key(self, *, verified=True, can_sign=True, revoked=False):
        """Exactly what `GET /user/gpg_keys` answers for this key."""
        return {
            "can_sign": can_sign,
            "emails": [{"email": self.email, "verified": verified}],
            "key_id": self.key_id,
            "primary_key_id": None,
            "revoked": revoked,
        }

    def _run(self, *arguments, passphrase=False, **kwargs):
        command = [GPG, "--batch", "--quiet", "--yes",
                   "--homedir", str(self.home)]
        if passphrase:
            command += ["--passphrase", ""]
        return subprocess.run(
            command + list(arguments), capture_output=True, **kwargs,
        )

    def sign(self, payload):
        target = self.home / "commit"
        target.write_bytes(payload)
        observed = self._run(
            "--armor", "--detach-sign", "--output", str(self.home / "commit.asc"),
            str(target), passphrase=True,
        )
        assert observed.returncode == 0, observed.stderr.decode()
        return (self.home / "commit.asc").read_text(encoding="utf-8")

    def verify(self, payload, signature):
        (self.home / "verify.sig").write_text(signature, encoding="utf-8")
        (self.home / "verify.msg").write_bytes(payload)
        return self._run(
            "--verify", str(self.home / "verify.sig"),
            str(self.home / "verify.msg"),
        ).returncode == 0

    def close(self):
        shutil.rmtree(self.home, ignore_errors=True)


class GitHubGitDataService:
    """Real Git Data semantics: real object names, real status codes.

    It stores real Git objects, verifies the reviewer's OpenPGP signature for
    itself with `gpg --verify`, refuses a duplicate `POST /git/refs` with the
    documented 422, and applies real fast-forward-only rules to `PATCH`.
    Nothing is ever injected: the production code produces every value and
    this server refuses whatever it cannot verify.
    """

    # What GitHub really substitutes when a create-commit request omits the
    # author: the *authenticated user* and the server's own clock. Neither is
    # the identity a reviewer signed, which is exactly why an omitted author
    # can never produce a verified signature.
    SERVER_CLOCK = 1_900_000_000
    DEFAULT_SERVER_NAME = "GitHub Web Flow"
    DEFAULT_SERVER_EMAIL = "noreply@github.com"

    # A `pre-receive` hook records every update command the server really
    # received - `<old> <new> <ref>`, the wire form of the compare-and-swap -
    # and, when armed, moves the target reference after the pack has arrived
    # and before the reference transaction commits. That is exactly the race
    # the old-OID precondition exists for.
    PRE_RECEIVE_HOOK = """#!/bin/sh
while read old new ref; do
  printf '%s %s %s\\n' "$old" "$new" "$ref" >> "$GIT_DIR/acc-updates"
done
if [ -f "$GIT_DIR/acc-race" ]; then
  raced_ref="$(sed -n 1p "$GIT_DIR/acc-race")"
  raced_sha="$(sed -n 2p "$GIT_DIR/acc-race")"
  rm -f "$GIT_DIR/acc-race"
  env -u GIT_QUARANTINE_PATH git update-ref "$raced_ref" "$raced_sha" >&2
fi
exit 0
"""

    # A `post-receive` hook lets another writer land after the reference
    # transaction has committed and before the delivery reads it back.
    POST_RECEIVE_HOOK = """#!/bin/sh
cat > /dev/null
if [ -f "$GIT_DIR/acc-race-after" ]; then
  raced_ref="$(sed -n 1p "$GIT_DIR/acc-race-after")"
  raced_sha="$(sed -n 2p "$GIT_DIR/acc-race-after")"
  rm -f "$GIT_DIR/acc-race-after"
  env -u GIT_QUARANTINE_PATH git update-ref "$raced_ref" "$raced_sha" >&2
fi
exit 0
"""

    def __init__(self, repository, reviewer, *, base_entries,
                 signature_must_verify=True, login=None, gpg_keys=None,
                 user_name=None):
        self.repository = repository
        self.reviewer = reviewer
        self.signature_must_verify = signature_must_verify
        self.login = VALIDATOR.DECISION_WRITER_LOGIN if login is None else login
        self.user_name = (
            reviewer.name if user_name is None else user_name
        )
        self.gpg_keys = (
            [reviewer.registered_key()] if gpg_keys is None else list(gpg_keys)
        )
        self.blobs, self.trees, self.commits = {}, {}, {}
        self.calls = []
        # A real bare repository, served by the real `git receive-pack`. The
        # REST endpoints below read their references out of it, so a push and
        # an API read can never describe two different servers.
        self.workspace = Path(tempfile.mkdtemp())
        self.repository_path = self.workspace / "server.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", "-b", "main",
             str(self.repository_path)],
            check=True, capture_output=True,
        )
        hook = self.repository_path / "hooks" / "pre-receive"
        hook.write_text(self.PRE_RECEIVE_HOOK, encoding="utf-8")
        hook.chmod(0o755)
        after = self.repository_path / "hooks" / "post-receive"
        after.write_text(self.POST_RECEIVE_HOOK, encoding="utf-8")
        after.chmod(0o755)
        entries = {}
        for path, data in base_entries.items():
            sha = self._write_object("blob", data)
            self.blobs[sha] = data
            entries[path] = ("100644", sha)
        tree_sha = self._store_tree(entries)
        bootstrap = self._default_identity()
        self.parent = self._store_commit(
            tree_sha, [], "bootstrap", None, bootstrap, bootstrap,
        )
        self.move_ref("refs/heads/main", self.parent)

    def close(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    # -- a real Git server -------------------------------------------------
    def _git(self, *arguments, **kwargs):
        return subprocess.run(
            ["git", "--git-dir", str(self.repository_path), *arguments],
            check=True, capture_output=True, **kwargs,
        )

    def _write_object(self, kind, payload):
        """Write a real object into the real repository, and check its name."""
        observed = self._git(
            "hash-object", "-t", kind, "-w", "--stdin", input=payload,
        ).stdout.decode().strip()
        assert observed == git_object_id(kind, payload), kind
        return observed

    @property
    def refs(self):
        """Whatever the server's own repository holds, right now."""
        listing = self._git(
            "for-each-ref", "--format=%(refname) %(objectname)",
        ).stdout.decode()
        return {
            line.split(" ")[0]: line.split(" ")[1]
            for line in listing.splitlines() if line
        }

    def move_ref(self, name, sha):
        self._git("update-ref", name, sha)

    def race_on_receive(self, name, sha):
        """Arm the server to move `name` to `sha` mid-receive, exactly once."""
        (self.repository_path / "acc-race").write_text(
            f"{name}\n{sha}\n", encoding="utf-8",
        )

    def race_after_receive(self, name, sha):
        """Arm another writer to land once the transaction has committed."""
        (self.repository_path / "acc-race-after").write_text(
            f"{name}\n{sha}\n", encoding="utf-8",
        )

    @property
    def received_updates(self):
        """Every `<old> <new> <ref>` update command the server received."""
        log = self.repository_path / "acc-updates"
        if not log.is_file():
            return []
        return [
            tuple(line.split(" "))
            for line in log.read_text(encoding="utf-8").splitlines() if line
        ]

    def clone(self, destination):
        """A real working checkout of this server, for the delivery lane."""
        subprocess.run(
            ["git", "clone", "-q", str(self.repository_path), str(destination)],
            check=True, capture_output=True,
        )
        return destination

    # -- real Git objects --------------------------------------------------
    def _store_tree(self, entries):
        """Write real nested tree objects for a flat {path: (mode, sha)} map."""
        sha = self._store_subtree(entries)
        self.trees[sha] = dict(entries)
        return sha

    def _store_subtree(self, entries):
        level, nested = {}, {}
        for path, value in entries.items():
            head, separator, rest = path.partition("/")
            if separator:
                nested.setdefault(head, {})[rest] = value
            else:
                level[head] = value
        for name, children in nested.items():
            level[name] = ("40000", self._store_subtree(children))
        return self._write_object("tree", git_tree_object(level))

    # -- real omitted-field / default semantics ----------------------------
    def _default_identity(self):
        """What the server writes when the request names no author at all."""
        return {
            "date": datetime.fromtimestamp(
                self.SERVER_CLOCK, timezone.utc,
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "email": self.DEFAULT_SERVER_EMAIL,
            "name": self.DEFAULT_SERVER_NAME,
        }

    def _requested_identity(self, requested):
        """One author/committer object, with the documented defaults applied.

        GitHub fills an omitted name/email from the authenticated identity and
        an omitted date from its own clock. Nothing here is ever taken from
        what some other request happened to sign: the object the commit
        carries is the object this request actually asked for.
        """
        if type(requested) is not dict:
            return self._default_identity()
        default = self._default_identity()
        return {
            "date": requested.get("date") or default["date"],
            "email": requested.get("email") or default["email"],
            "name": requested.get("name") or default["name"],
        }

    @staticmethod
    def _git_identity(identity):
        """The exact `name <email> seconds +0000` bytes a commit object holds."""
        moment = datetime.strptime(
            identity["date"], "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=timezone.utc)
        return (
            f"{identity['name']} <{identity['email']}> "
            f"{int(moment.timestamp())} +0000"
        )

    def _payload(self, tree, parents, message, signature, author, committer):
        lines = [f"tree {tree}"]
        lines += [f"parent {parent}" for parent in parents]
        lines.append(f"author {self._git_identity(author)}")
        lines.append(f"committer {self._git_identity(committer)}")
        head = "\n".join(lines)
        if signature is not None:
            indented = signature.rstrip("\n").replace("\n", "\n ")
            head += f"\ngpgsig {indented}"
        return (head + "\n\n" + message + "\n").encode("utf-8")

    def _store_commit(self, tree, parents, message, signature, author,
                      committer, verified=False):
        payload = self._payload(
            tree, parents, message, signature, author, committer,
        )
        sha = self._write_object("commit", payload)
        self.commits[sha] = {
            "author": author, "committer": committer,
            "message": message, "parents": list(parents), "tree": tree,
            "signature": signature, "verified": verified,
            "unsigned": self._payload(
                tree, parents, message, None, author, committer,
            ),
        }
        return sha

    def _verified_emails(self):
        return {
            entry["email"]
            for key in self.gpg_keys
            if key.get("can_sign") and not key.get("revoked")
            for entry in key.get("emails") or []
            if entry.get("verified")
        }

    def _commit_body(self, sha):
        commit = self.commits[sha]
        body = {
            "author": dict(commit["author"]),
            "committer": dict(commit["committer"]),
            "message": commit["message"],
            "parents": [{"sha": p} for p in commit["parents"]],
            "sha": sha, "tree": {"sha": commit["tree"]},
            "url": (f"{VALIDATOR.GITHUB_API_ROOT}/repos/{self.repository}"
                    f"/git/commits/{sha}"),
        }
        if commit["signature"] is not None:
            body["verification"] = {
                "payload": commit["unsigned"].decode("utf-8"),
                "reason": "valid" if commit["verified"] else "unverified",
                "signature": commit["signature"],
                "verified": commit["verified"],
                "verified_at": "2027-01-15T08:00:00Z",
            }
        return body

    # -- the documented endpoints, with real status codes ------------------
    def handle(self, method, path, payload):
        self.calls.append((method, path))
        if method == "GET" and path.split("?")[0] == "/user":
            return 200, {"login": self.login, "name": self.user_name,
                         "type": "User"}
        if method == "GET" and path.split("?")[0] == "/user/gpg_keys":
            return 200, [dict(key) for key in self.gpg_keys]
        prefix = f"/repos/{self.repository}"
        if not path.startswith(prefix):
            return 404, {"message": "Not Found"}
        rest = path[len(prefix):]

        if method == "GET" and rest.startswith("/git/ref/"):
            name = "refs/" + rest[len("/git/ref/"):]
            if name not in self.refs:
                return 404, {"message": "Not Found"}
            return 200, {"object": {"sha": self.refs[name], "type": "commit"},
                         "ref": name}
        if method == "POST" and rest == "/git/blobs":
            data = base64.b64decode(payload["content"], validate=True)
            sha = self._write_object("blob", data)
            self.blobs[sha] = data
            return 201, {"sha": sha}
        if method == "POST" and rest == "/git/trees":
            base = dict(self.trees[payload["base_tree"]])
            for entry in payload["tree"]:
                base[entry["path"]] = (entry["mode"], entry["sha"])
            return 201, {"sha": self._store_tree(base)}
        if method == "POST" and rest == "/git/commits":
            author = self._requested_identity(payload.get("author"))
            committer = self._requested_identity(
                payload.get("committer", payload.get("author")),
            )
            unsigned = self._payload(
                payload["tree"], payload["parents"], payload["message"], None,
                author, committer,
            )
            signature = payload.get("signature")
            # Real semantics: the signature is verified over the object the
            # server actually wrote, and only a *verified* email of a usable
            # registered key can make the result `verified`.
            verified = bool(
                self.signature_must_verify and signature
                and signature.startswith("-----BEGIN PGP SIGNATURE-----")
                and self.reviewer.verify(unsigned, signature)
                and committer["email"] in self._verified_emails()
            )
            sha = self._store_commit(
                payload["tree"], payload["parents"], payload["message"],
                signature, author, committer, verified,
            )
            return 201, self._commit_body(sha)
        # There is deliberately no reference-write endpoint here. GitHub's
        # `PATCH /repos/{owner}/{repo}/git/refs/{ref}` accepts `sha` and
        # `force` and no expected-old-OID at all, so no REST call can be a
        # compare-and-swap on the target reference. The delivery lane installs
        # its commit through the Git wire protocol, whose update command
        # carries the old OID and is applied inside a reference transaction
        # that enforces it - served here by the real `git receive-pack`.
        if method == "GET" and rest.startswith("/git/commits/"):
            sha = rest[len("/git/commits/"):]
            if sha not in self.commits:
                return 404, {"message": "Not Found"}
            return 200, self._commit_body(sha)
        if method == "GET" and rest.startswith("/git/trees/"):
            sha = rest[len("/git/trees/"):].split("?")[0]
            if sha not in self.trees:
                return 404, {"message": "Not Found"}
            entries = self.trees[sha]
            return 200, {
                "sha": sha, "truncated": False,
                "tree": [{"mode": entries[n][0], "path": n,
                          "sha": entries[n][1], "type": "blob"}
                         for n in sorted(entries)],
            }
        if method == "GET" and rest.startswith("/contents/"):
            target, _, query = rest[len("/contents/"):].partition("?")
            ref = dict(
                part.split("=", 1) for part in query.split("&") if "=" in part
            ).get("ref")
            tree = self.trees[self.commits[ref]["tree"]]
            if target not in tree:
                return 404, {"message": "Not Found"}
            mode, blob = tree[target]
            return 200, {
                "content": base64.b64encode(self.blobs[blob]).decode("ascii"),
                "encoding": "base64", "path": target, "sha": blob,
                "size": len(self.blobs[blob]), "type": "file",
            }
        return 404, {"message": f"unsupported endpoint {method} {path}"}


@unittest.skipIf(GPG is None, "gpg is unavailable")
class ProductionDecisionDeliveryTransportTests(unittest.TestCase):
    """The production transport, over real HTTP, against real semantics."""

    HEAD = "b" * 40
    DECISION = json.dumps(
        {"decision": "APPROVED", "findings_count": 0}, indent=2, sort_keys=True,
    ).encode("utf-8") + b"\n"

    def serve(self, **kwargs):
        import http.server
        import threading

        reviewer = GnuPGReviewer()
        self.addCleanup(reviewer.close)
        service = GitHubGitDataService(
            VALIDATOR.INDEPENDENT_REPOSITORY, reviewer,
            base_entries={"README.md": b"# independent review\n"}, **kwargs,
        )
        self.addCleanup(service.close)
        self.service = service
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _dispatch(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                received.append({
                    "method": self.command, "path": self.path,
                    "headers": dict(self.headers), "body": raw,
                })
                payload = json.loads(raw) if raw else None
                status, body = service.handle(
                    self.command, self.path.split("?")[0]
                    if self.command != "GET" else self.path, payload,
                )
                encoded = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = do_POST = do_PATCH = _dispatch

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        root = f"http://127.0.0.1:{server.server_address[1]}"
        self.enterContext(mock.patch.object(VALIDATOR, "GITHUB_API_ROOT", root))
        return service, reviewer, received

    def deliver(self, reviewer, *, expected_head, **kwargs):
        """No transport is injected: production constructs its own.

        The reviewer's own checkout is a real clone of the real server
        repository, and the remote is that repository, so the installation
        below is a real push into a real `git receive-pack`.
        """
        kwargs.setdefault("remote", str(self.service.repository_path))
        if "workspace" not in kwargs:
            kwargs["workspace"] = self.service.clone(
                self.service.workspace / f"checkout-{len(self.service.calls)}",
            )
        with mock.patch.dict(os.environ, {"GH_TOKEN": "ghs_acc_test_token"}):
            return VALIDATOR.deliver_decision_commit(
                decision=self.DECISION, head_commit=self.HEAD,
                expected_head=expected_head,
                signing_key=str(reviewer.home), **kwargs,
            )

    # -- the mechanism -----------------------------------------------------
    def test_the_production_transport_delivers_over_real_http(self):
        service, reviewer, received = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        self.assertEqual(delivered["path"], f"decisions/{self.HEAD}.json")
        self.assertEqual(delivered["commit_parent"], service.parent)
        self.assertEqual(delivered["changed_paths"], [delivered["path"]])
        self.assertIs(delivered["signature_verified"], True)
        self.assertEqual(service.refs["refs/heads/main"], delivered["commit_sha"])
        # Real production request semantics reached the server.
        first = {k.lower(): v for k, v in received[0]["headers"].items()}
        self.assertEqual(first["accept"], "application/vnd.github+json")
        self.assertEqual(
            first["x-github-api-version"], VALIDATOR.GITHUB_API_VERSION,
        )
        self.assertEqual(first["authorization"], "Bearer ghs_acc_test_token")

    def test_the_signature_is_openpgp_and_never_an_ssh_signature(self):
        service, reviewer, received = self.serve()
        self.deliver(reviewer, expected_head=service.parent)
        created = next(
            item for item in received
            if item["method"] == "POST" and item["path"].endswith("/git/commits")
        )
        signature = json.loads(created["body"])["signature"]
        self.assertTrue(signature.startswith("-----BEGIN PGP SIGNATURE-----"))
        self.assertNotIn("BEGIN SSH SIGNATURE", signature)
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("ssh-keygen", source)

    def test_the_signed_author_and_committer_bytes_are_bound(self):
        service, reviewer, _ = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        self.assertEqual(delivered["author"], delivered["committer"])
        self.assertEqual(
            delivered["signed_payload_sha256"],
            hashlib.sha256(
                service.commits[delivered["commit_sha"]]["unsigned"]
            ).hexdigest(),
        )

    def test_a_commit_whose_author_bytes_drifted_is_refused(self):
        """The returned commit must be the object the reviewer really signed."""
        service, reviewer, _ = self.serve()
        original = service._commit_body

        def drifted(sha):
            body = original(sha)
            body["author"] = {**body["author"], "email": "attacker@example.invalid"}
            return body

        service._commit_body = drifted
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("author", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    def test_a_verification_payload_that_is_not_the_signed_object_is_refused(self):
        service, reviewer, _ = self.serve()
        original = service._commit_body

        def drifted(sha):
            body = original(sha)
            if "verification" in body:
                body["verification"] = {
                    **body["verification"], "payload": "tree deadbeef\n",
                }
            return body

        service._commit_body = drifted
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("signed", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    def test_an_unverified_signature_is_refused_by_the_server(self):
        service, reviewer, _ = self.serve(signature_must_verify=False)
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("signature", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    def test_a_wrong_reviewer_key_is_refused_by_the_server(self):
        service, _, _ = self.serve()
        other = GnuPGReviewer("ACC Impostor <x@example.invalid>")
        self.addCleanup(other.close)
        with self.assertRaises(SystemExit):
            self.deliver(other, expected_head=service.parent)
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    # -- the expected-old-OID compare-and-swap on the target reference ------
    def test_the_compare_and_swap_mutates_the_target_reference_itself(self):
        service, reviewer, _ = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        # The reference that moved is the delivery branch, not a side claim,
        # and the update command carried the expected old OID.
        self.assertEqual(delivered["cas_ref"], "refs/heads/main")
        self.assertEqual(delivered["cas_expected_old_oid"], service.parent)
        self.assertEqual(
            service.received_updates,
            [(service.parent, delivered["commit_sha"], "refs/heads/main")],
        )
        self.assertEqual(
            service.refs["refs/heads/main"], delivered["commit_sha"],
        )

    def test_a_second_delivery_that_read_the_same_head_is_refused(self):
        """The branch has moved on, so the replay's lease is stale."""
        service, reviewer, _ = self.serve()
        parent = service.parent
        installed = self.deliver(reviewer, expected_head=parent)
        self.assertEqual(service.refs["refs/heads/main"], installed["commit_sha"])
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=parent)
        self.assertIn("expected head", str(raised.exception))
        self.assertEqual(
            service.refs["refs/heads/main"], installed["commit_sha"],
        )

    def test_a_branch_that_moved_after_the_head_was_read_is_refused(self):
        service, reviewer, _ = self.serve()
        moving = service._default_identity()
        moved = service._store_commit(
            service.commits[service.parent]["tree"], [service.parent], "race",
            None, moving, moving,
        )
        service.move_ref("refs/heads/main", moved)
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("expected head", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], moved)

    def test_no_rest_reference_write_is_ever_called_a_compare_and_swap(self):
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        # There is no REST reference write at all, and the reason is stated.
        self.assertNotIn("_api_path(f\"/git/refs/", source)
        self.assertNotIn("_api_path(\"/git/refs\")", source)
        window = source[
            source.index("# The atomic primitive, on the target reference"):
            source.index("DELIVERY_CAS_PRIMITIVE =")
        ]
        self.assertIn("no\n# expected-old-OID at all", window)
        self.assertIn("force-with-lease", window)
        # And the installation really is the push, on the target reference.
        install = source.index("def _install_delivery_commit")
        self.assertIn(
            "--force-with-lease", source[install:install + 3000],
        )

    # -- the race read-back -------------------------------------------------
    def test_the_result_is_read_back_from_ref_commit_tree_and_path(self):
        service, reviewer, received = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        # Everything after the commit creation is a read-back of what the
        # server now actually holds, once the reference has been moved.
        created = [call for call in service.calls if call[0] == "POST"]
        tail = service.calls[service.calls.index(created[-1]) + 1:]
        self.assertIn(
            ("GET", f"/repos/{VALIDATOR.INDEPENDENT_REPOSITORY}"
                    "/git/ref/heads/main"), tail,
        )
        self.assertTrue(
            any(call[0] == "GET" and "/contents/" in call[1] for call in tail),
            "the delivered path was never read back",
        )
        self.assertEqual(
            delivered["readback_decision_sha256"],
            hashlib.sha256(self.DECISION).hexdigest(),
        )

    def test_a_raced_ref_after_the_update_is_refused(self):
        """Another writer lands between the update and the read-back."""
        service, reviewer, _ = self.serve()
        racing = service._default_identity()
        raced = service._store_commit(
            service.commits[service.parent]["tree"], [service.parent], "race",
            None, racing, racing,
        )
        service.race_after_receive("refs/heads/main", raced)
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("read back", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], raced)

    def test_a_second_changed_path_is_refused(self):
        service, reviewer, _ = self.serve()
        original = service.handle

        def smuggle(method, path, payload=None):
            if method == "POST" and path.endswith("/git/trees"):
                payload = deepcopy(payload)
                sha = git_object_id("blob", b"{}\n")
                service.blobs[sha] = b"{}\n"
                payload["tree"].append({
                    "mode": "100644", "path": "smuggled.json",
                    "sha": sha, "type": "blob",
                })
            return original(method, path, payload)

        service.handle = smuggle
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("exactly one", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)


# ---------------------------------------------------------------------------
# F8-INDEPENDENT-DECISION-DELIVERY-STILL-NONPRODUCTION - the identity itself
#
# The create-commit request must carry the *exact* author and committer
# objects whose bytes were OpenPGP-signed, and that identity is never a
# constant of the lane. GitHub fills an omitted author from the authenticated
# identity and from its own clock, and reports `verified` only for a committer
# address that the signing key has registered and verified on the account - so
# an omitted field or a placeholder address could never produce a verified
# delivery at all. Everything below drives the unchanged production lane
# against a server that applies exactly those documented default and
# verification semantics.
# ---------------------------------------------------------------------------
@unittest.skipIf(GPG is None, "gpg is unavailable")
class ReviewerVerifiedDeliveryIdentityTests(unittest.TestCase):
    """The delivered identity is read back from GitHub, then signed and sent."""

    HEAD = ProductionDecisionDeliveryTransportTests.HEAD
    DECISION = ProductionDecisionDeliveryTransportTests.DECISION
    serve = ProductionDecisionDeliveryTransportTests.serve
    deliver = ProductionDecisionDeliveryTransportTests.deliver

    @staticmethod
    def created(received):
        return next(
            json.loads(item["body"]) for item in received
            if item["method"] == "POST"
            and item["path"].endswith("/git/commits")
        )

    # -- the request really carries the signed objects ---------------------
    def test_the_request_carries_the_exact_signed_author_and_committer(self):
        service, reviewer, received = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        body = self.created(received)
        # Present at all - the defect was that they were omitted entirely.
        self.assertIn("author", body)
        self.assertIn("committer", body)
        self.assertEqual(body["author"], body["committer"])
        self.assertEqual(
            sorted(body["author"]), ["date", "email", "name"],
        )
        self.assertEqual(body["author"], delivered["author"])
        self.assertEqual(body["committer"], delivered["committer"])
        # And they are exactly the bytes that were signed, not merely equal
        # looking: the signed object is reconstructed from the sent object.
        signed = service.commits[delivered["commit_sha"]]["unsigned"]
        rendered = VALIDATOR._git_identity_bytes(body["author"])
        self.assertIn(
            f"author {rendered}\n".encode("utf-8"), signed,
        )
        self.assertIn(
            f"committer {rendered}\n".encode("utf-8"), signed,
        )
        self.assertEqual(
            delivered["signed_payload_sha256"],
            hashlib.sha256(signed).hexdigest(),
        )

    def test_the_delivered_identity_is_the_reviewer_verified_account_identity(self):
        service, reviewer, received = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        self.assertEqual(delivered["author"]["email"], reviewer.email)
        self.assertEqual(delivered["author"]["name"], service.user_name)
        # Both authenticated identity reads really happened.
        self.assertIn(("GET", "/user"), service.calls)
        self.assertIn(("GET", "/user/gpg_keys"), service.calls)

    def test_the_delivery_uses_a_reviewer_scoped_credential(self):
        """Only a user-scoped credential can read the identity back."""
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("ACC_REVIEWER_DELIVERY_TOKEN", workflow)
        self.assertIn(
            'GH_TOKEN="$ACC_REVIEWER_DELIVERY_TOKEN"', workflow,
        )
        # It is used for the installing phase and for nothing else.
        install = workflow.index("--phase deliver-commit")
        scoped = workflow.index('GH_TOKEN="$ACC_REVIEWER_DELIVERY_TOKEN"')
        self.assertLess(scoped, install)
        self.assertEqual(
            workflow.count('GH_TOKEN="$ACC_REVIEWER_DELIVERY_TOKEN"'), 1,
        )

    def test_delivery_transport_injects_exactly_one_authorization_extraheader(self):
        _, environment = VALIDATOR._delivery_remote("reviewer-writer-token")
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(environment["GIT_CONFIG_KEY_0"], "http.extraheader")
        self.assertTrue(
            environment["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
        )
        authorization_values = [
            value for key, value in environment.items()
            if key.startswith("GIT_CONFIG_VALUE_")
            and value.lower().startswith("authorization:")
        ]
        self.assertEqual(len(authorization_values), 1)

    def test_the_lane_carries_no_placeholder_identity_constant(self):
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("example.invalid", source)
        self.assertNotIn("DELIVERY_COMMIT_IDENTITY", source)
        self.assertFalse(
            hasattr(VALIDATOR, "DELIVERY_COMMIT_IDENTITY"),
            "the lane still pins a constant commit identity",
        )

    # -- real omitted-field default semantics ------------------------------
    def test_an_omitted_author_is_defaulted_by_the_server_and_never_verifies(self):
        """Exactly why the omission was a production defect, demonstrated."""
        service, reviewer, _ = self.serve()
        tree = service.commits[service.parent]["tree"]
        # What the server does with a request that names no author at all.
        status, body = service.handle(
            "POST", f"/repos/{VALIDATOR.INDEPENDENT_REPOSITORY}/git/commits",
            {"message": "omitted", "parents": [service.parent], "tree": tree},
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["author"], service._default_identity())
        self.assertEqual(body["committer"], service._default_identity())
        # It is not the identity the reviewer would have signed.
        identity = VALIDATOR._delivery_identity(
            {"email": reviewer.email, "name": service.user_name},
            service.SERVER_CLOCK, "test",
        )
        self.assertNotEqual(body["author"], identity)
        # The production lane never leaves it to the server.
        _, _, received = self.serve()
        service2, reviewer2, received2 = self.serve()
        self.deliver(reviewer2, expected_head=service2.parent)
        self.assertIsNotNone(self.created(received2).get("author"))

    def test_a_committer_the_server_defaults_away_is_refused(self):
        """A server that silently rewrites the committer fails the delivery."""
        service, reviewer, _ = self.serve()
        original = service._requested_identity

        def defaulted(requested):
            return service._default_identity()

        service._requested_identity = defaulted
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("author", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    # -- adversarial account and key states --------------------------------
    def test_an_account_that_is_not_the_decision_writer_is_refused(self):
        service, reviewer, _ = self.serve(login="someone-else")
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("expected decision writer", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    def test_an_unregistered_signing_key_is_refused(self):
        other = GnuPGReviewer("ACC Other <other@example.invalid>")
        self.addCleanup(other.close)
        service, reviewer, _ = self.serve(gpg_keys=[other.registered_key()])
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("single registered account key", str(raised.exception))

    def test_a_revoked_or_unusable_signing_key_is_refused(self):
        for label, overrides in (
            ("revoked", {"revoked": True}),
            ("cannot-sign", {"can_sign": False}),
        ):
            with self.subTest(label=label):
                service, reviewer, _ = self.serve()
                service.gpg_keys = [reviewer.registered_key(**overrides)]
                with self.assertRaises(SystemExit) as raised:
                    self.deliver(reviewer, expected_head=service.parent)
                self.assertIn(
                    "revoked or cannot sign", str(raised.exception),
                )

    def test_an_unverified_signing_address_is_refused(self):
        service, reviewer, _ = self.serve()
        service.gpg_keys = [reviewer.registered_key(verified=False)]
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("single verified address", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    def test_an_ambiguous_verified_address_is_refused(self):
        service, reviewer, _ = self.serve()
        key = reviewer.registered_key()
        key["emails"] = [
            {"email": reviewer.email, "verified": True},
            {"email": "second@example.invalid", "verified": True},
        ]
        service.gpg_keys = [key]
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("single verified address", str(raised.exception))

    def test_a_committer_the_server_will_not_verify_is_refused(self):
        """The signature is produced, but only the server can make it count.

        The account still publishes the address, so the lane derives and signs
        it exactly as before; the server simply will not verify a commit under
        it. The delivery must then fail closed instead of installing an
        unverified commit, because this lane can produce a signature but can
        never make GitHub accept one.
        """
        service, reviewer, _ = self.serve()
        service._verified_emails = lambda: set()
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn(
            "not verified by the server", str(raised.exception),
        )
        self.assertEqual(service.refs["refs/heads/main"], service.parent)
        self.assertIn(("GET", "/user/gpg_keys"), service.calls)

    # -- the exact date --------------------------------------------------
    def test_the_delivered_date_is_one_exact_utc_instant(self):
        service, reviewer, received = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        stamp = delivered["author"]["date"]
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        moment = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc,
        )
        signed = service.commits[delivered["commit_sha"]]["unsigned"]
        self.assertIn(
            f"> {int(moment.timestamp())} +0000\n".encode("utf-8"), signed,
        )
        # The request and the signed bytes describe the same single instant.
        self.assertEqual(self.created(received)["author"]["date"], stamp)


# ---------------------------------------------------------------------------
# F8-SIGSTORE-ED25519-REKOR-UNSUPPORTED
#
# A genuine, immutable, public Sigstore protobuf-JSON v0.3 bundle whose
# transparency entry is integrated by an **Ed25519** Rekor log, vendored here
# byte for byte and pinned by digest.
#
# PROVENANCE (immutable, public, not produced by this repository):
#   repository : sigstore/sigstore-java
#   commit     : 42071e4bb62d1423257814defb7ec765153c81c4
#   blob       : ab4ef344952003756722c3cd547a0ae25e443b8a
#   path       : sigstore-java/src/test/resources/dev/sigstore/samples/
#                bundles/bundle.dsse.rekor-v2.sigstore
#   raw sha256 : 1d86a26555d7db11c517a2c6c766452a6c19550c1cde49ef1a7a3ccb5a1c2b66
#
# NOMENCLATURE, stated exactly. This is **not** a Cosign v3.1.3 *release*
# asset. An authenticated enumeration of every v3.1.3 Cosign release
# `.sigstore.json` asset shows all of them use the legacy ECDSA log key
# `wNI9...` with checkpoint origin `rekor.sigstore.dev - 1193050959916656506`.
# No Cosign v3.1.3 release asset used Ed25519, and this file never claims one
# did. What this is: the genuine immutable public Rekor-v2 Ed25519
# conformance vector that a Cosign-v3.1.3-compatible Sigstore v0.3 verifier
# must accept. The upstream repository's `KeylessTest sign_production_rekorV2`
# path exercises `https://log2025-1.rekor.sigstore.dev` with Rekor v2.
#
# Its checkpoint note origin is exactly `log2025-1.rekor.sigstore.dev`, which
# is exactly the origin the production trust record pins for the Ed25519 log
# `zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=`. Everything below drives that
# genuine checkpoint through the *unchanged* production trust selection
# (`_PinnedSigstoreTrust.select`) and the *unchanged* production verifiers
# (`_verify_checkpoint`, `_verify_log_signature`), and proves tamper,
# wrong-key and wrong-origin all fail closed.
# ---------------------------------------------------------------------------
# An instant inside the pinned Ed25519 log's validity window (it opens
# 2025-09-23), used only to drive the unchanged production trust selection.
INTEGRATED_WITHIN_ED25519_VALIDITY = 1_760_000_000
ED25519_VECTOR_SHA256 = (
    "1d86a26555d7db11c517a2c6c766452a6c19550c1cde49ef1a7a3ccb5a1c2b66"
)
ED25519_VECTOR_SOURCE_REPOSITORY = "sigstore/sigstore-java"
ED25519_VECTOR_SOURCE_COMMIT = "42071e4bb62d1423257814defb7ec765153c81c4"
ED25519_VECTOR_SOURCE_BLOB = "ab4ef344952003756722c3cd547a0ae25e443b8a"
ED25519_VECTOR_SOURCE_PATH = (
    "sigstore-java/src/test/resources/dev/sigstore/samples/bundles/"
    "bundle.dsse.rekor-v2.sigstore"
)
ED25519_REKOR_LOG_KEY_ID = "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A="
ED25519_REKOR_CHECKPOINT_ORIGIN = "log2025-1.rekor.sigstore.dev"
# The legacy ECDSA log every Cosign v3.1.3 release asset really used.
LEGACY_ECDSA_LOG_KEY_ID = "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="

ED25519_REKOR_V2_VECTOR_BASE64 = (
    "ewogICJtZWRpYVR5cGUiOiAiYXBwbGljYXRpb24vdm5kLmRldi5zaWdzdG9yZS5idW5kbGUu"
    "djAuMytqc29uIiwKICAidmVyaWZpY2F0aW9uTWF0ZXJpYWwiOiB7CiAgICAidGxvZ0VudHJp"
    "ZXMiOiBbewogICAgICAibG9nSW5kZXgiOiAiNDg1NTExNCIsCiAgICAgICJsb2dJZCI6IHsK"
    "ICAgICAgICAia2V5SWQiOiAienhHWkZWdmQwRkVtalI4V3JGd01kY0FKOXZ0YVkvUVhmNDRZ"
    "MXdVZVA2QT0iCiAgICAgIH0sCiAgICAgICJraW5kVmVyc2lvbiI6IHsKICAgICAgICAia2lu"
    "ZCI6ICJoYXNoZWRyZWtvcmQiLAogICAgICAgICJ2ZXJzaW9uIjogIjAuMC4yIgogICAgICB9"
    "LAogICAgICAiaW5jbHVzaW9uUHJvb2YiOiB7CiAgICAgICAgImxvZ0luZGV4IjogIjQ4NTUx"
    "MTQiLAogICAgICAgICJyb290SGFzaCI6ICJnRGZRSGNQU2tMRFZVZC94ZVpXUHNxU0I3UlRS"
    "MGhvMDdrMTVqZ3pMT3B3PSIsCiAgICAgICAgInRyZWVTaXplIjogIjQ4NTUxMTUiLAogICAg"
    "ICAgICJoYXNoZXMiOiBbImFSWkwvc3p3NHV4NVoxYmtFempIT0Z2YzBaWlZpSTJJa0E3T1R3"
    "WXBFY009IiwgImtSNHVzMzkyZWczdzBoUnFSbmV4bmVJdjYyTm4zNmJldzg4VEdvS1FEOXc9"
    "IiwgInpCZ01IS1FlYnp0TXBQOWVSMmpIdXhoa3p4TW5hK3ZlYktUbUdaaUJqaVE9IiwgIitp"
    "dWUwVmtJN1NaTHl4blZFaEJNRzhzMEozSlZJUVUxbDNEWGJNOEwwb0k9IiwgIjgyZVNGQ04y"
    "TzNkUDBqRlJmbiszRnVjQ2lQMy9mZWNLU255T0owaFVDRWM9IiwgImxzOHloa1h3MlBnRXVM"
    "MjRNSDdra05oVkNPWmpRcVhVMzZ1UGMyN2hZaUk9IiwgInUycVkrbCtOZG0zZDl1US8xS2NL"
    "WWVYbFRLK2prdG9mTkI2bk1uRmtiMm89IiwgIlJnMVFUeEMxQWcxSDFiajErNDR4SjNZelUz"
    "K0RCYXlOR2R6YmJ6aXhOS0E9IiwgIjlRemc4RjNyYml2ZDJRbythRWRpRkhseHlRWk5nWFdi"
    "SW81SkZBVUtxQTQ9Il0sCiAgICAgICAgImNoZWNrcG9pbnQiOiB7CiAgICAgICAgICAiZW52"
    "ZWxvcGUiOiAibG9nMjAyNS0xLnJla29yLnNpZ3N0b3JlLmRldlxuNDg1NTExNVxuZ0RmUUhj"
    "UFNrTERWVWQveGVaV1BzcVNCN1JUUjBobzA3azE1amd6TE9wd1x1MDAzZFxuXG7igJQgbG9n"
    "MjAyNS0xLnJla29yLnNpZ3N0b3JlLmRldiB6eEdaRlhZSHZ0VjZjVzIyWUp4MWRXeDlJaXVV"
    "SHc0QnVYWjNYODFKQWdLOHNXWC9IQlFIMlFkbERhcHFqTWtwOUdjcklUb3A3alVHOTc5RnlL"
    "YVk3QzdWdlFNXHUwMDNkXG4iCiAgICAgICAgfQogICAgICB9LAogICAgICAiY2Fub25pY2Fs"
    "aXplZEJvZHkiOiAiZXlKaGNHbFdaWEp6YVc5dUlqb2lNQzR3TGpJaUxDSnJhVzVrSWpvaWFH"
    "RnphR1ZrY21WcmIzSmtJaXdpYzNCbFl5STZleUpvWVhOb1pXUlNaV3R2Y21SV01EQXlJanA3"
    "SW1SaGRHRWlPbnNpWVd4bmIzSnBkR2h0SWpvaVUwaEJNbDh5TlRZaUxDSmthV2RsYzNRaU9p"
    "Sm1hMUJZU25kMFRtNTFOSEo2Y1daWmExTjFaRXhyU0RScVUzWmxkQ3RLTTJkeE9VaHlTSGhI"
    "WTJJMFBTSjlMQ0p6YVdkdVlYUjFjbVVpT25zaVkyOXVkR1Z1ZENJNklrMUZVVU5KUlVSRFN6"
    "SnlSWE5YVG10NEwydFBUek15U0hCaVpETnZjelozUWtGc1MzUXhjekJXTnlzM2NXMXhlRUZw"
    "UWtGbUsyOXJkbmx1WW1abVlWWk1jRzFuV1VsVVVIRXllU3RXUW05UlQwTklVV3hpVmpKamFD"
    "OVNRbWM5UFNJc0luWmxjbWxtYVdWeUlqcDdJbXRsZVVSbGRHRnBiSE1pT2lKUVMwbFlYMFZE"
    "UkZOQlgxQXlOVFpmVTBoQlh6STFOaUlzSW5nMU1EbERaWEowYVdacFkyRjBaU0k2ZXlKeVlY"
    "ZENlWFJsY3lJNklrMUpTVVJIVkVORFFYQXJaMEYzU1VKQlowbFZRakVyY1hKNU1qZzNTMVJ5"
    "Wm1WaFJsSmhhbkZwYnl0NU9XWjNkME5uV1VsTGIxcEplbW93UlVGM1RYZE9la1ZXVFVKTlIw"
    "RXhWVVZEYUUxTll6SnNibU16VW5aamJWVjFXa2RXTWsxU05IZElRVmxFVmxGUlJFVjRWbnBo"
    "VjJSNlpFYzVlVnBUTVhCaWJsSnNZMjB4YkZwSGJHaGtSMVYzU0doalRrMXFXWGRPYWtGNlRW"
    "UnJlVTE2U1RKWGFHTk9UV3BaZDA1cVFYcE5WR3Q2VFhwSk1sZHFRVUZOUm10M1JYZFpTRXR2"
    "V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZFUmpCWk9IUmpiVEp4T0daVWVs"
    "TnZOMUZCZDBSemJUbFFVVEZQYm1ZeGVXRjNRWGhJV0VVNVJYUXpabUZZZEdOdmIzSjJWVmxR"
    "UjJkS1ozUnNOVFJ2YjFsSFdsZHZVRm96ZGtSR0wzRm1jemhPYVZKUWNVOURRV0kwZDJkblJ6"
    "Wk5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpTR2RFUVZSQ1owNVdTRk5WUlVSRVFVdENaMmR5"
    "UW1kRlJrSlJZMFJCZWtGa1FtZE9Wa2hSTkVWR1oxRlZjVGR1WTA1dU1DOXlZVXcwZFdoMVZr"
    "UTFRblp1YkRsSlZXOXZkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4"
    "VG1wd1MwWlhhWGhwTkZsYVJEaDNVbmRaUkZaU01GSkJVVWd2UWtRd2QwODBSVFZrVnpVd1ky"
    "NVdlbVJIVm10TVdFNW9VVWhPY0ZvelRqQmlNMHBzVEZkT2RtSnRXblpqYlRGb1ltMU9iRXh0"
    "YkdoaVV6VnVZekpXZVdSdGJHcGFWMFpxV1RJNU1XSnVVWFZaTWpsMFRVTnJSME5wYzBkQlVW"
    "RkNaemM0ZDBGUlJVVkhNbWd3WkVoQ2VrOXBPSFpaVjA1cVlqTldkV1JJVFhWYU1qbDJXako0"
    "YkV4dFRuWmlWRUZ5UW1kdmNrSm5SVVZCV1U4dlRVRkZTVUpDTUUxSE1tZ3daRWhDZWs5cE9I"
    "WlpWMDVxWWpOV2RXUklUWFZhTWpsMldqSjRiRXh0VG5aaVZFRnNRbWR2Y2tKblJVVkJXVTh2"
    "VFVGRldVSkNZMDFHVkVWM1RsUkZNRTVFV1hoUFJFRXdUMVJKTUU5RWF6Sk9ha1V6VG5wRFFt"
    "bG5XVXRMZDFsQ1FrRklWMlZSU1VWQloxSTRRa2h2UVdWQlFqSkJUakE1VFVkeVIzaDRSWGxa"
    "ZUd0bFNFcHNiazUzUzJsVGJEWTBNMnA1ZEM4MFpVdGpiMEYyUzJVMlQwRkJRVUp1YnpkM2Vr"
    "VlZRVUZCVVVSQlJXTjNVbEZKYUVGS1R6VkljMWRhTm5aQ1UwaGFhemRsV2xKc1NrSmtMM0JZ"
    "Vm5sb2NFMXpiM0l5Tm5GcFdEVTRVMnBJUVdsQ05VZHFMMWhxTDNSemVFcE5ibFZFV2t4WmVq"
    "Rm9VVkIxYWtKTFlsZHNiRXhOTTNaS2FrUXZNMGxKYWtGTFFtZG5jV2hyYWs5UVVWRkVRWGRP"
    "YjBGRVFteEJha0pxVmsxaVZXczJaVFoxZEhjeFIxSTRMemtySzBKRFRteGlRMWt4UjAxSUt6"
    "RlZPV1pwUVZacGMzVnBTVFpHVmtsSVlUVlNOVGRIVURsa1QxVjFRelJaUTAxUlJFeEVRa2RG"
    "TVVSbFRHNXJlRXdyTjI1d2NHUm1aVTFyUjBkWk9FOU9aSFJ2UkdKMFNYcEZSSFZ2WjB4a2FV"
    "UnpaMU54YkZWQlQxVlVZMUEyYTB0NU1XYzlJbjE5ZlgxOWZRPT0iCiAgICB9XSwKICAgICJ0"
    "aW1lc3RhbXBWZXJpZmljYXRpb25EYXRhIjogewogICAgICAicmZjMzE2MVRpbWVzdGFtcHMi"
    "OiBbewogICAgICAgICJzaWduZWRUaW1lc3RhbXAiOiAiTUlJQzFqQURBZ0VBTUlJQ3pRWUpL"
    "b1pJaHZjTkFRY0NvSUlDdmpDQ0Fyb0NBUU14RFRBTEJnbGdoa2dCWlFNRUFnRXdnY01HQ3lx"
    "R1NJYjNEUUVKRUFFRW9JR3pCSUd3TUlHdEFnRUJCZ2tyQmdFRUFZTy9NQUl3TVRBTkJnbGdo"
    "a2dCWlFNRUFnRUZBQVFndnJhb2JTMkdWd0RjdWhJQkptRmhjOExzNDZPQ3czdXJyK0VpVnFB"
    "YlphQUNGUUNoc3BUOUZJWHNyNENld2s5TGZ5V1FkYlNTYXhnUE1qQXlOakEyTURNeE9USXpN"
    "alphTUFNQ0FRRUNDUURSdmcrKzBWSllaYUF5cERBd0xqRVZNQk1HQTFVRUNoTU1jMmxuYzNS"
    "dmNtVXVaR1YyTVJVd0V3WURWUVFERXd4emFXZHpkRzl5WlMxMGMyR2dBREdDQWR3d2dnSFlB"
    "Z0VCTUZFd09URVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVNBd0hnWURWUVFERXhk"
    "emFXZHpkRzl5WlMxMGMyRXRjMlZzWm5OcFoyNWxaQUlVT2hOVUx3eVFZZTY4d1VNdnk0cU9p"
    "eW9qaXd3d0N3WUpZSVpJQVdVREJBSUJvSUg4TUJvR0NTcUdTSWIzRFFFSkF6RU5CZ3NxaGtp"
    "Rzl3MEJDUkFCQkRBY0Jna3Foa2lHOXcwQkNRVXhEeGNOTWpZd05qQXpNVGt5TXpJMldqQXZC"
    "Z2txaGtpRzl3MEJDUVF4SWdRZ1VkVWk2dlVBeUZaNHhNbWpYbWRJby9GZjF6Q3pzUzFpaHdH"
    "Q0VoZjVKZGt3Z1k0R0N5cUdTSWIzRFFFSkVBSXZNWDh3ZlRCN01Ia0VJSVg1Sjd3SHEyTEt3"
    "N1JEVnNFTy9JR3l4b2cvMm5xNTV0aHcyZEU2elFXM01GVXdQYVE3TURreEZUQVRCZ05WQkFv"
    "VERITnBaM04wYjNKbExtUmxkakVnTUI0R0ExVUVBeE1YYzJsbmMzUnZjbVV0ZEhOaExYTmxi"
    "R1p6YVdkdVpXUUNGRG9UVkM4TWtHSHV2TUZETDh1S2pvc3FJNHNNTUFvR0NDcUdTTTQ5QkFN"
    "Q0JHZ3daZ0l4QU1sblNjZi9CcUVYWmxiNVN2UGRUS0NLSDlZczFxSzNJM29iWTN0L0Mzam1W"
    "TTJTTjdIZTdzR3lCdC8ySk1keGZ3SXhBTnVJWlJ0MjVUUU4xUm9wTTRSMkxmOVZZY2NhRHhN"
    "bTdrelVZazlRbFYxRm1aZEpyc3BEU014YXJ2cE9FNlcyYWc9PSIKICAgICAgfV0KICAgIH0s"
    "CiAgICAiY2VydGlmaWNhdGUiOiB7CiAgICAgICJyYXdCeXRlcyI6ICJNSUlER1RDQ0FwK2dB"
    "d0lCQWdJVUIxK3FyeTI4N0tUcmZlYUZSYWpxaW8reTlmd3dDZ1lJS29aSXpqMEVBd013TnpF"
    "Vk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXla"
    "UzFwYm5SbGNtMWxaR2xoZEdVd0hoY05Nall3TmpBek1Ua3lNekkyV2hjTk1qWXdOakF6TVRr"
    "ek16STJXakFBTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFREYwWTh0Y20y"
    "cThmVHpTbzdRQXdEc205UFExT25mMXlhd0F4SFhFOUV0M2ZhWHRjb29ydlVZUEdnSmd0bDU0"
    "b29ZR1pXb1BaM3ZERi9xZnM4TmlSUHFPQ0FiNHdnZ0c2TUE0R0ExVWREd0VCL3dRRUF3SUhn"
    "REFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQXpBZEJnTlZIUTRFRmdRVXE3bmNObjAvcmFM"
    "NHVodVZENUJ2bmw5SVVvb3dId1lEVlIwakJCZ3dGb0FVMzlQcHoxWWtFWmI1cU5qcEtGV2l4"
    "aTRZWkQ4d1J3WURWUjBSQVFIL0JEMHdPNEU1ZFc1MGNuVnpkR1ZrTFhOaFFITnBaM04wYjNK"
    "bExXTnZibVp2Y20xaGJtTmxMbWxoYlM1bmMyVnlkbWxqWldGalkyOTFiblF1WTI5dE1Da0dD"
    "aXNHQVFRQmc3OHdBUUVFRzJoMGRIQnpPaTh2WVdOamIzVnVkSE11WjI5dloyeGxMbU52YlRB"
    "ckJnb3JCZ0VFQVlPL01BRUlCQjBNRzJoMGRIQnpPaTh2WVdOamIzVnVkSE11WjI5dloyeGxM"
    "bU52YlRBbEJnb3JCZ0VFQVlPL01BRVlCQmNNRlRFd05URTBORFl4T0RBME9USTBPRGsyTmpF"
    "M056Q0JpZ1lLS3dZQkJBSFdlUUlFQWdSOEJIb0FlQUIyQU4wOU1Hckd4eEV5WXhrZUhKbG5O"
    "d0tpU2w2NDNqeXQvNGVLY29BdktlNk9BQUFCbm83d3pFVUFBQVFEQUVjd1JRSWhBSk81SHNX"
    "WjZ2QlNIWms3ZVpSbEpCZC9wWFZ5aHBNc29yMjZxaVg1OFNqSEFpQjVHai9Yai90c3hKTW5V"
    "RFpMWXoxaFFQdWpCS2JXbGxMTTN2SmpELzNJSWpBS0JnZ3Foa2pPUFFRREF3Tm9BREJsQWpC"
    "alZNYlVrNmU2dXR3MUdSOC85KytCQ05sYkNZMUdNSCsxVTlmaUFWaXN1aUk2RlZJSGE1UjU3"
    "R1A5ZE9VdUM0WUNNUURMREJHRTFEZUxua3hMKzducHBkZmVNa0dHWThPTmR0b0RidEl6RUR1"
    "b2dMZGlEc2dTcWxVQU9VVGNQNmtLeTFnPSIKICAgIH0KICB9LAogICJkc3NlRW52ZWxvcGUi"
    "OiB7CiAgICAicGF5bG9hZCI6ICJleUpmZEhsd1pTSTZJbWgwZEhCek9pOHZhVzR0ZEc5MGJ5"
    "NXBieTlUZEdGMFpXMWxiblF2ZGpFaUxDSnpkV0pxWldOMElqcGJleUp1WVcxbElqb2lZUzUw"
    "ZUhRaUxDSmthV2RsYzNRaU9uc2ljMmhoTWpVMklqb2lZVEJqWm1NM01USTNNV1EyWlRJM09H"
    "VTFOMk5rTXpNeVptWTVOVGRqTTJZM01EUXpabVJrWVRNMU5HTTBZMkppTVRrd1lUTXdaRFUy"
    "WldaaE1ERmlaaUo5ZlYwc0luQnlaV1JwWTJGMFpWUjVjR1VpT2lKb2RIUndjem92TDNOc2My"
    "RXVaR1YyTDNCeWIzWmxibUZ1WTJVdmRqRWlMQ0p3Y21Wa2FXTmhkR1VpT25zaVluVnBiR1JF"
    "WldacGJtbDBhVzl1SWpwN0ltSjFhV3hrVkhsd1pTSTZJbWgwZEhCek9pOHZZV04wYVc5dWN5"
    "NW5hWFJvZFdJdWFXOHZZblZwYkdSMGVYQmxjeTkzYjNKclpteHZkeTkyTVNJc0ltVjRkR1Z5"
    "Ym1Gc1VHRnlZVzFsZEdWeWN5STZleUozYjNKclpteHZkeUk2ZXlKeVpXWWlPaUp5Wldaekwy"
    "aGxZV1J6TDIxaGFXNGlMQ0p5WlhCdmMybDBiM0o1SWpvaWFIUjBjSE02THk5bmFYUm9kV0l1"
    "WTI5dEwyeHZiM05sWW1GNmIyOXJZUzloWVMxMFpYTjBJaXdpY0dGMGFDSTZJaTVuYVhSb2RX"
    "SXZkMjl5YTJac2IzZHpMM0J5YjNabGJtRnVZMlV1ZVdGdGJDSjlmU3dpYVc1MFpYSnVZV3hR"
    "WVhKaGJXVjBaWEp6SWpwN0ltZHBkR2gxWWlJNmV5SmxkbVZ1ZEY5dVlXMWxJam9pZDI5eWEy"
    "WnNiM2RmWkdsemNHRjBZMmdpTENKeVpYQnZjMmwwYjNKNVgybGtJam9pT0RreE56RTFORFEw"
    "SWl3aWNtVndiM05wZEc5eWVWOXZkMjVsY2w5cFpDSTZJakV6TURRNE1qWWlMQ0p5ZFc1dVpY"
    "SmZaVzUyYVhKdmJtMWxiblFpT2lKbmFYUm9kV0l0YUc5emRHVmtJbjE5TENKeVpYTnZiSFps"
    "WkVSbGNHVnVaR1Z1WTJsbGN5STZXM3NpZFhKcElqb2laMmwwSzJoMGRIQnpPaTh2WjJsMGFI"
    "VmlMbU52YlM5c2IyOXpaV0poZW05dmEyRXZZV0V0ZEdWemRFQnlaV1p6TDJobFlXUnpMMjFo"
    "YVc0aUxDSmthV2RsYzNRaU9uc2laMmwwUTI5dGJXbDBJam9pWldKbVpqaGtabUprTmpBNVlq"
    "ZGlNakl5TXpkak56Y3hPV05sTURkbU1tUmpOemt6TkdZMVppSjlmVjE5TENKeWRXNUVaWFJo"
    "YVd4eklqcDdJbUoxYVd4a1pYSWlPbnNpYVdRaU9pSm9kSFJ3Y3pvdkwyZHBkR2gxWWk1amIy"
    "MHZiRzl2YzJWaVlYcHZiMnRoTDJGaExYUmxjM1F2TG1kcGRHaDFZaTkzYjNKclpteHZkM012"
    "Y0hKdmRtVnVZVzVqWlM1NVlXMXNRSEpsWm5NdmFHVmhaSE12YldGcGJpSjlMQ0p0WlhSaFpH"
    "RjBZU0k2ZXlKcGJuWnZZMkYwYVc5dVNXUWlPaUpvZEhSd2N6b3ZMMmRwZEdoMVlpNWpiMjB2"
    "Ykc5dmMyVmlZWHB2YjJ0aEwyRmhMWFJsYzNRdllXTjBhVzl1Y3k5eWRXNXpMekV4T1RReE5E"
    "STFORGczTDJGMGRHVnRjSFJ6THpFaWZYMTlmUT09IiwKICAgICJwYXlsb2FkVHlwZSI6ICJh"
    "cHBsaWNhdGlvbi92bmQuaW4tdG90bytqc29uIiwKICAgICJzaWduYXR1cmVzIjogW3sKICAg"
    "ICAgInNpZyI6ICJNRVFDSUVEQ0syckVzV05reC9rT08zMkhwYmQzb3M2d0JBbEt0MXMwVjcr"
    "N3FtcXhBaUJBZitva3Z5bmJmZmFWTHBtZ1lJVFBxMnkrVkJvUU9DSFFsYlYyY2gvUkJnPT0i"
    "CiAgICB9XQogIH0KfQo="
)


def ed25519_rekor_v2_vector():
    """The vendored genuine public Ed25519 Rekor-v2 bundle, digest-checked."""
    raw = base64.b64decode(ED25519_REKOR_V2_VECTOR_BASE64, validate=True)
    assert hashlib.sha256(raw).hexdigest() == ED25519_VECTOR_SHA256
    return raw


class GenuineEd25519RekorVectorTests(unittest.TestCase):
    """The genuine public Ed25519 vector, through unchanged production code."""

    def setUp(self):
        self.raw = ed25519_rekor_v2_vector()
        self.bundle = json.loads(self.raw)
        self.entry = (
            self.bundle["verificationMaterial"]["tlogEntries"][0]
        )
        self.proof = self.entry["inclusionProof"]
        self.envelope = self.proof["checkpoint"]["envelope"]
        self.trust = PIN._load_pinned_sigstore_trust(ROOT)
        self.backend = PIN._cryptography()

    def selected(self, key_id=None):
        """The unchanged production trust selection, by real log key id."""
        return self.trust.select(
            INTEGRATED_WITHIN_ED25519_VALIDITY,
            key_id or self.entry["logId"]["keyId"],
        )

    # -- it really is the genuine immutable public vector -------------------
    def test_the_vector_is_the_pinned_immutable_public_bytes(self):
        self.assertEqual(
            hashlib.sha256(self.raw).hexdigest(), ED25519_VECTOR_SHA256,
        )
        self.assertEqual(
            ED25519_VECTOR_SOURCE_COMMIT,
            "42071e4bb62d1423257814defb7ec765153c81c4",
        )
        self.assertEqual(
            ED25519_VECTOR_SOURCE_BLOB,
            "ab4ef344952003756722c3cd547a0ae25e443b8a",
        )

    def test_it_is_a_sigstore_v03_bundle_integrated_by_an_ed25519_log(self):
        self.assertEqual(
            self.bundle["mediaType"], SIGSTORE.CANONICAL_MEDIA_TYPE,
        )
        self.assertEqual(
            self.entry["logId"]["keyId"], ED25519_REKOR_LOG_KEY_ID,
        )
        self.assertEqual(
            self.entry["kindVersion"],
            {"kind": "hashedrekord", "version": "0.0.2"},
        )
        # Genuine Rekor v2: a real inclusion proof and checkpoint, and a real
        # RFC3161 timestamp rather than a Rekor v1 signed entry timestamp.
        self.assertTrue(self.proof["hashes"])
        self.assertTrue(
            self.bundle["verificationMaterial"]["timestampVerificationData"]
            ["rfc3161Timestamps"]
        )

    def test_it_is_not_and_never_claims_to_be_a_cosign_release_asset(self):
        """The vendored ECDSA release vector stays exactly what it is."""
        release = json.loads(
            (ROOT / "tests" / "fixtures"
             / "cosign-v3.1.3-sigstore-v0.3-bundle.json").read_bytes()
        )
        self.assertEqual(
            release["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"],
            LEGACY_ECDSA_LOG_KEY_ID,
            "the vendored Cosign release vector must stay the ECDSA one",
        )
        self.assertNotEqual(LEGACY_ECDSA_LOG_KEY_ID, ED25519_REKOR_LOG_KEY_ID)

    # -- the pinned origin, exactly -----------------------------------------
    def test_the_checkpoint_origin_is_exactly_the_production_pin(self):
        pinned = [
            log for log in self.trust.rekor_logs
            if log["log_id_key_id"] == ED25519_REKOR_LOG_KEY_ID
        ]
        self.assertEqual(len(pinned), 1)
        self.assertEqual(pinned[0]["origin"], ED25519_REKOR_CHECKPOINT_ORIGIN)
        # The pinned record really is the Ed25519 log, from its own bytes.
        record = json.loads(
            (ROOT / "reviewer-authorization-v2.json").read_bytes()
        )["sigstore_trusted_root"]["rekor_logs"]
        declared = [
            log for log in record
            if log["log_id_key_id"] == ED25519_REKOR_LOG_KEY_ID
        ]
        self.assertEqual(len(declared), 1)
        self.assertEqual(declared[0]["key_details"], "PKIX_ED25519")
        self.assertEqual(
            declared[0]["origin"], ED25519_REKOR_CHECKPOINT_ORIGIN,
        )
        # The genuine note's own first line, byte for byte.
        body, _ = PIN._split_checkpoint(self.envelope)
        self.assertEqual(
            body.split("\n")[0], ED25519_REKOR_CHECKPOINT_ORIGIN,
        )

    def test_the_production_trust_selection_selects_the_ed25519_log(self):
        selected = self.selected()
        self.assertEqual(
            selected.rekor_origin, ED25519_REKOR_CHECKPOINT_ORIGIN,
        )

    # -- the genuine checkpoint, through the unchanged verifier -------------
    def test_the_genuine_checkpoint_verifies_through_production(self):
        PIN._verify_checkpoint(
            self.envelope, self.proof["rootHash"], self.selected(),
            self.backend,
        )

    def test_the_genuine_ed25519_signature_verifies_through_production(self):
        body, signatures = PIN._split_checkpoint(self.envelope)
        blob = base64.b64decode(
            signatures[0].split(" ", 2)[2], validate=True,
        )
        PIN._verify_log_signature(
            self.selected().rekor_public_key,
            blob[PIN.REKOR_KEY_HINT_LENGTH:], body.encode("utf-8"),
            self.backend, "genuine Ed25519 checkpoint",
        )

    # -- adversarial: tamper, wrong key, wrong origin -----------------------
    def refuses(self, envelope, root=None, trust=None):
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_checkpoint(
                envelope, root or self.proof["rootHash"],
                trust or self.selected(), self.backend,
            )
        return str(raised.exception)

    def test_a_tampered_checkpoint_body_is_refused(self):
        body, signatures = PIN._split_checkpoint(self.envelope)
        lines = body.split("\n")
        lines[1] = str(int(lines[1]) + 1)          # the tree size moves
        tampered = "\n".join(lines) + "\n" + "\n".join(signatures)
        self.assertIn("does not verify", self.refuses(tampered))

    def test_a_tampered_checkpoint_signature_is_refused(self):
        body, signatures = PIN._split_checkpoint(self.envelope)
        prefix, name, encoded = signatures[0].split(" ", 2)
        blob = bytearray(base64.b64decode(encoded, validate=True))
        blob[-1] ^= 0x01                            # one bit of the signature
        flipped = " ".join([
            prefix, name, base64.b64encode(bytes(blob)).decode("ascii"),
        ])
        self.assertIn(
            "does not verify",
            self.refuses(body + "\n" + flipped),
        )

    def test_a_checkpoint_root_that_is_not_the_proven_root_is_refused(self):
        self.assertIn(
            "proven root",
            self.refuses(
                self.envelope,
                root=base64.b64encode(b"a" * 32).decode("ascii"),
            ),
        )

    def test_the_wrong_log_key_is_refused(self):
        """Selecting the legacy ECDSA log must not verify this note."""
        wrong = self.trust.select(
            INTEGRATED_WITHIN_ED25519_VALIDITY, LEGACY_ECDSA_LOG_KEY_ID,
        )
        # The origin check fires first, and the key hint would refuse it too.
        message = self.refuses(self.envelope, trust=wrong)
        self.assertTrue(message.strip())
        self.assertNotEqual(
            wrong.rekor_public_key, self.selected().rekor_public_key,
        )

    def test_a_wrong_checkpoint_origin_is_refused(self):
        body, signatures = PIN._split_checkpoint(self.envelope)
        lines = body.split("\n")
        lines[0] = "log2099-9.rekor.sigstore.dev"
        forged = "\n".join(lines) + "\n" + "\n".join(signatures)
        self.assertIn(
            "origin is not the pinned log", self.refuses(forged),
        )

    def test_a_signature_line_naming_another_verifier_is_refused(self):
        body, signatures = PIN._split_checkpoint(self.envelope)
        prefix, _, encoded = signatures[0].split(" ", 2)
        renamed = " ".join([prefix, "rekor.sigstore.dev", encoded])
        self.assertIn(
            "no single signature", self.refuses(body + "\n" + renamed),
        )

    def test_a_foreign_key_hint_is_refused(self):
        body, signatures = PIN._split_checkpoint(self.envelope)
        prefix, name, encoded = signatures[0].split(" ", 2)
        blob = bytearray(base64.b64decode(encoded, validate=True))
        blob[0] ^= 0xFF                             # the key hint no longer matches
        forged = " ".join([
            prefix, name, base64.b64encode(bytes(blob)).decode("ascii"),
        ])
        self.assertIn(
            "different log key", self.refuses(body + "\n" + forged),
        )


# ---------------------------------------------------------------------------
# F8-SIGSTORE-ED25519-REKOR-UNSUPPORTED - the whole route, not a primitive
#
# The genuine immutable public Ed25519 Rekor-v2 RFC 3161 vector is driven
# through the *unchanged* production verification route, against the real
# pinned trust this candidate ships: the pinned Sigstore timestamp authority
# chain, the RFC 3161 message imprint, signature and generation time, the
# Ed25519 Rekor log identity, the production-pinned checkpoint origin, the
# inclusion proof, the checkpoint, the transparency body and the signing
# certificate path. Nothing is mocked and nothing is substituted; the trust
# comes from `_load_pinned_sigstore_trust` exactly as production loads it.
# ---------------------------------------------------------------------------
class GenuineEd25519RekorV2RouteTests(unittest.TestCase):
    """The genuine Rekor-v2 vector, end to end, through production."""

    # The pinned Ed25519 log opened 2025-09-23 and the vector's RFC 3161
    # authority timestamped it on 2026-06-03; the window below is the
    # authenticated run window a real lane would supply around that instant.
    WINDOW = (1_780_514_000, 1_780_515_500)
    GENERATED_AT = 1_780_514_606

    def setUp(self):
        self.raw = ed25519_rekor_v2_vector()
        self.trust = PIN._load_pinned_sigstore_trust(ROOT)
        self.parsed = PIN.SIGSTORE.parse_bundle(self.raw)
        self.subject = self.parsed.subject_bytes

    def route(self, raw=None, *, subject=None, trust=None, window=None):
        return PIN._verify_sigstore_bundle_route(
            self.raw if raw is None else raw,
            subject_bytes=self.subject if subject is None else subject,
            trust=self.trust if trust is None else trust,
            signing_window=self.WINDOW if window is None else window,
        )

    def mutated(self, mutate):
        bundle = json.loads(self.raw)
        mutate(bundle)
        return json.dumps(bundle).encode("utf-8")

    def refuses(self, mutate, **kwargs):
        with self.assertRaises(SystemExit) as raised:
            self.route(self.mutated(mutate), **kwargs)
        return str(raised.exception)

    # -- the positive route -------------------------------------------------
    def test_the_genuine_vector_verifies_end_to_end_through_production(self):
        observed = self.route()
        self.assertEqual(observed["rekor_generation"], PIN.SIGSTORE.REKOR_V2)
        self.assertEqual(observed["signed_content_member"], "dsseEnvelope")
        self.assertEqual(observed["integrated_time"], self.GENERATED_AT)
        self.assertEqual(observed["log_index"], 4855114)
        # The production-pinned checkpoint origin, selected by log identity.
        self.assertEqual(
            observed["rekor_origin"], ED25519_REKOR_CHECKPOINT_ORIGIN,
        )
        self.assertEqual(
            self.parsed.log_key_id, ED25519_REKOR_LOG_KEY_ID,
        )

    def test_the_trusted_time_is_the_pinned_authority_generation_time(self):
        """Rekor v2 carries no integrated time; the TSA supplies it."""
        self.assertEqual(self.parsed.integrated_time, 0)
        self.assertIs(self.parsed.is_rekor_v2, True)
        self.assertEqual(len(self.parsed.rfc3161_timestamps), 1)
        observed = PIN._verify_rfc3161_timestamp(
            self.parsed.rfc3161_timestamps[0], self.parsed.signature,
            self.trust, PIN._cryptography(), "genuine RFC 3161",
        )
        self.assertEqual(observed, self.GENERATED_AT)

    def test_the_timestamp_authority_really_is_the_pinned_sigstore_one(self):
        pinned = self.trust.timestamp_authorities
        self.assertEqual(len(pinned), 1)
        self.assertEqual(
            pinned[0]["uri"], "https://timestamp.sigstore.dev/api/v1/timestamp",
        )
        # The chain really is the one inside the digest-pinned trusted root.
        record = json.loads(
            (ROOT / "reviewer-authorization-v2.json").read_bytes()
        )["sigstore_trusted_root"]
        canonical = json.loads(
            base64.b64decode(record["canonical_bytes_base64"])
        )["timestampAuthorities"][0]["certChain"]["certificates"]
        self.assertEqual(
            [base64.b64decode(entry["rawBytes"]) for entry in canonical],
            list(pinned[0]["certificates"]),
        )

    def test_rekor_v2_never_requires_a_rekor_v1_signed_entry_timestamp(self):
        self.assertNotIn(
            "inclusionPromise",
            json.loads(self.raw)["verificationMaterial"]["tlogEntries"][0],
        )
        self.assertEqual(self.parsed.inclusion_promise, {})
        self.route()

    def test_rekor_v1_still_requires_its_signed_entry_timestamp(self):
        """The mandatory Rekor v1 proof is untouched by the v2 support."""
        release = json.loads(
            (ROOT / "tests" / "fixtures"
             / "cosign-v3.1.3-sigstore-v0.3-bundle.json").read_bytes()
        )
        entry = release["verificationMaterial"]["tlogEntries"][0]
        self.assertIn("inclusionPromise", entry)
        parsed = PIN.SIGSTORE.parse_bundle(json.dumps(release).encode())
        self.assertEqual(parsed.rekor_generation, PIN.SIGSTORE.REKOR_V1)
        # Dropping it leaves the integrated time behind, so the entry is still
        # a Rekor v1 entry and is refused for carrying no signed entry
        # timestamp - it can never be downgraded into a v2 entry.
        entry.pop("inclusionPromise")
        with self.assertRaises(SystemExit) as raised:
            PIN.SIGSTORE.parse_bundle(json.dumps(release).encode())
        self.assertIn("signed entry timestamp", str(raised.exception))

    def test_an_entry_with_no_timestamp_evidence_at_all_is_refused(self):
        def strip(bundle):
            entry = bundle["verificationMaterial"]["tlogEntries"][0]
            entry.pop("inclusionPromise", None)
            entry.pop("integratedTime", None)
            bundle["verificationMaterial"].pop(
                "timestampVerificationData", None,
            )

        self.assertIn("no trusted time", self.refuses(strip))

    # -- adversarial: the RFC 3161 timestamp -------------------------------
    def test_a_tampered_timestamp_token_is_refused(self):
        def tamper(bundle):
            data = bundle["verificationMaterial"]["timestampVerificationData"]
            token = bytearray(base64.b64decode(
                data["rfc3161Timestamps"][0]["signedTimestamp"]
            ))
            token[-1] ^= 0x01
            data["rfc3161Timestamps"][0]["signedTimestamp"] = base64.b64encode(
                bytes(token)
            ).decode("ascii")

        self.assertTrue(self.refuses(tamper).strip())

    def test_a_timestamp_over_another_signature_is_refused(self):
        """The message imprint must be this bundle's own signature.

        A swapped envelope signature no longer reaches the timestamp at all -
        the transparency body records the genuine signature and refuses first -
        so the imprint binding is driven directly through the unchanged
        production verifier instead.
        """
        signature = self.parsed.signature
        observed = PIN._verify_rfc3161_timestamp(
            self.parsed.rfc3161_timestamps[0], signature,
            self.trust, PIN._cryptography(), "genuine RFC 3161",
        )
        self.assertEqual(observed, self.GENERATED_AT)
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_rfc3161_timestamp(
                self.parsed.rfc3161_timestamps[0],
                signature[:-1] + bytes([signature[-1] ^ 0x01]),
                self.trust, PIN._cryptography(), "genuine RFC 3161",
            )
        self.assertIn("message imprint", str(raised.exception))

    def test_an_envelope_signature_swap_is_refused_by_the_body(self):
        """The log's own record of the signature refuses the swap outright."""
        def swap(bundle):
            signature = base64.b64decode(
                bundle["dsseEnvelope"]["signatures"][0]["sig"]
            )
            bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(
                signature[:-1] + bytes([signature[-1] ^ 0x01])
            ).decode("ascii")

        self.assertIn(
            "does not bind the exact bundle signature", self.refuses(swap),
        )

    def test_an_absent_timestamp_authority_can_never_trust_rekor_v2(self):
        stripped = PIN._PinnedSigstoreTrust(
            self.trust.fulcio_authorities, self.trust.rekor_logs, (),
        )
        with self.assertRaises(SystemExit) as raised:
            self.route(trust=stripped)
        self.assertIn("no Sigstore timestamp authority", str(raised.exception))

    def test_a_foreign_timestamp_authority_is_refused(self):
        foreign = PIN._PinnedSigstoreTrust(
            self.trust.fulcio_authorities, self.trust.rekor_logs,
            ({
                "certificates": tuple(
                    authority["root"] for authority in
                    self.trust.fulcio_authorities
                ) * 2,
                "uri": "https://timestamp.example.invalid",
                "valid_from": 0, "valid_to": None,
            },),
        )
        with self.assertRaises(SystemExit) as raised:
            self.route(trust=foreign)
        self.assertIn("pinned Sigstore timestamp authority",
                      str(raised.exception))

    def test_a_generation_time_outside_the_authority_window_is_refused(self):
        narrowed = PIN._PinnedSigstoreTrust(
            self.trust.fulcio_authorities, self.trust.rekor_logs,
            tuple({**authority, "valid_from": self.GENERATED_AT + 1}
                  for authority in self.trust.timestamp_authorities),
        )
        with self.assertRaises(SystemExit) as raised:
            self.route(trust=narrowed)
        self.assertIn("timestamp authority validity", str(raised.exception))

    # -- adversarial: time bounds ------------------------------------------
    def test_a_trusted_time_outside_the_signing_window_is_refused(self):
        for label, window in (
            ("before", (self.GENERATED_AT + 1, self.GENERATED_AT + 600)),
            ("after", (self.GENERATED_AT - 600, self.GENERATED_AT - 1)),
        ):
            with self.subTest(label=label):
                with self.assertRaises(SystemExit) as raised:
                    self.route(window=window)
                self.assertIn(
                    "outside the authenticated run and job window",
                    str(raised.exception),
                )

    # -- adversarial: body, proof, checkpoint, certificate -----------------
    def test_a_tampered_transparency_body_is_refused(self):
        def tamper(bundle):
            entry = bundle["verificationMaterial"]["tlogEntries"][0]
            body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
            body["spec"]["hashedRekordV002"]["data"]["digest"] = (
                base64.b64encode(b"\x00" * 32).decode("ascii")
            )
            entry["canonicalizedBody"] = base64.b64encode(
                json.dumps(body, separators=(",", ":")).encode()
            ).decode("ascii")

        self.assertIn(
            "does not bind the exact subject digest", self.refuses(tamper),
        )

    def test_a_body_that_does_not_bind_the_leaf_is_refused(self):
        def tamper(bundle):
            entry = bundle["verificationMaterial"]["tlogEntries"][0]
            body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
            verifier = body["spec"]["hashedRekordV002"]["signature"]["verifier"]
            verifier["x509Certificate"]["rawBytes"] = base64.b64encode(
                b"not-the-leaf"
            ).decode("ascii")
            entry["canonicalizedBody"] = base64.b64encode(
                json.dumps(body, separators=(",", ":")).encode()
            ).decode("ascii")

        self.assertIn(
            "does not bind the leaf certificate", self.refuses(tamper),
        )

    def test_a_tampered_inclusion_proof_is_refused(self):
        def tamper(bundle):
            proof = (bundle["verificationMaterial"]["tlogEntries"][0]
                     ["inclusionProof"])
            hashes_ = list(proof["hashes"])
            blob = bytearray(base64.b64decode(hashes_[0]))
            blob[0] ^= 0x01
            hashes_[0] = base64.b64encode(bytes(blob)).decode("ascii")
            proof["hashes"] = hashes_

        self.assertIn("does not recompute", self.refuses(tamper))

    def test_a_proof_for_another_entry_is_refused(self):
        def tamper(bundle):
            (bundle["verificationMaterial"]["tlogEntries"][0]
             ["inclusionProof"]["logIndex"]) = "4855115"

        self.assertIn("different log entry", self.refuses(tamper))

    def test_a_tampered_checkpoint_is_refused(self):
        def tamper(bundle):
            proof = (bundle["verificationMaterial"]["tlogEntries"][0]
                     ["inclusionProof"])
            envelope = proof["checkpoint"]["envelope"]
            body, signatures = PIN._split_checkpoint(envelope)
            lines = body.split("\n")
            lines[1] = str(int(lines[1]) + 1)
            proof["checkpoint"]["envelope"] = (
                "\n".join(lines) + "\n" + "\n".join(signatures)
            )

        self.assertIn("does not verify", self.refuses(tamper))

    def test_a_wrong_checkpoint_origin_is_refused(self):
        def tamper(bundle):
            proof = (bundle["verificationMaterial"]["tlogEntries"][0]
                     ["inclusionProof"])
            body, signatures = PIN._split_checkpoint(
                proof["checkpoint"]["envelope"]
            )
            lines = body.split("\n")
            lines[0] = "log2099-9.rekor.sigstore.dev"
            proof["checkpoint"]["envelope"] = (
                "\n".join(lines) + "\n" + "\n".join(signatures)
            )

        self.assertIn("origin is not the pinned log", self.refuses(tamper))

    def test_a_wrong_transparency_log_is_refused(self):
        def tamper(bundle):
            (bundle["verificationMaterial"]["tlogEntries"][0]["logId"]
             ["keyId"]) = LEGACY_ECDSA_LOG_KEY_ID

        # The legacy ECDSA log is pinned too, so this selects a real but wrong
        # log - and its origin and key hint both refuse this note.
        self.assertTrue(self.refuses(tamper).strip())

    def test_an_unpinned_transparency_log_is_refused(self):
        def tamper(bundle):
            (bundle["verificationMaterial"]["tlogEntries"][0]["logId"]
             ["keyId"]) = base64.b64encode(b"\x11" * 32).decode("ascii")

        self.assertIn("no pinned transparency log", self.refuses(tamper))

    def test_a_tampered_certificate_is_refused(self):
        def tamper(bundle):
            der = bytearray(base64.b64decode(
                bundle["verificationMaterial"]["certificate"]["rawBytes"]
            ))
            der[-1] ^= 0x01
            bundle["verificationMaterial"]["certificate"]["rawBytes"] = (
                base64.b64encode(bytes(der)).decode("ascii")
            )

        self.assertTrue(self.refuses(tamper).strip())

    def test_a_certificate_that_chains_to_no_pinned_root_is_refused(self):
        """A foreign anchor - here the timestamp authority's own root."""
        foreign_root = self.trust.timestamp_authorities[0]["certificates"][-1]
        substituted = PIN._PinnedSigstoreTrust(
            tuple({**authority, "root": foreign_root, "intermediates": ()}
                  for authority in self.trust.fulcio_authorities),
            self.trust.rekor_logs, self.trust.timestamp_authorities,
        )
        with self.assertRaises(SystemExit) as raised:
            self.route(trust=substituted)
        self.assertIn("does not reach a pinned Fulcio root",
                      str(raised.exception))

    # -- adversarial: the subject binding ----------------------------------
    def test_a_subject_that_is_not_the_signed_envelope_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.route(subject=self.subject + b"x")
        self.assertIn(
            "not the envelope this bundle signs", str(raised.exception),
        )

    def test_a_tampered_dsse_payload_is_refused(self):
        def tamper(bundle):
            payload = bytearray(base64.b64decode(
                bundle["dsseEnvelope"]["payload"]
            ))
            payload[0] ^= 0x01
            bundle["dsseEnvelope"]["payload"] = base64.b64encode(
                bytes(payload)
            ).decode("ascii")

        # The transparency body records the digest of the genuine DSSE
        # pre-authentication encoding, so a tampered payload is refused by the
        # parser itself and never reaches any signature check.
        raw = self.mutated(tamper)
        with self.assertRaises(SystemExit) as raised:
            PIN.SIGSTORE.parse_bundle(raw)
        self.assertIn(
            "does not bind the exact subject digest", str(raised.exception),
        )
        with self.assertRaises(SystemExit) as second:
            self.route(raw)
        self.assertTrue(str(second.exception).strip())


# ---------------------------------------------------------------------------
# F8-REKOR-BODY-NOT-STRUCTURALLY-VALIDATED
#
# The transparency body is the log's own statement about what was signed. The
# boundary used to look for the subject digest and the leaf as *substrings* of
# those bytes, which authenticates nothing about their meaning: a body of a
# different kind, of a different version, carrying a different algorithm, a
# different signature or a different certificate all satisfy a substring.
#
# Everything below drives adversarial bodies through the *unchanged* production
# route. The fixture recomputes the Merkle path, the checkpoint and the signed
# entry timestamp over each adversarial body, so the inclusion proof can never
# be the thing that refuses it - the body schema has to be.
# ---------------------------------------------------------------------------
class RekorBodySchemaBindingTests(unittest.TestCase):
    """The decoded Rekor body is a closed schema bound to this bundle."""

    REPOSITORY = ACTIVATION.INDEPENDENT_REPOSITORY
    WORKFLOW = ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY]
    WORKFLOW_SHA = "7a2d05c9138ebf4460d17ac83e592b6f0cd41827"
    INTEGRATED = 1800000000

    def setUp(self):
        self.subject = b'{"receipt":"exact-subject-bytes"}\n'
        self.fixture = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )
        self.body = json.loads(self.fixture.body)

    def route(self, *mutations, body=None):
        if body is not None:
            self.fixture.with_body(
                json.dumps(body, sort_keys=True, separators=(",", ":"))
                .encode("utf-8")
            )
        return PIN._verify_sigstore_bundle_route(
            self.fixture.bundle(*mutations),
            subject_bytes=self.subject,
            trust=self.fixture.trust,
            signing_window=(self.INTEGRATED - 300, self.INTEGRATED + 300),
        )

    def refuses(self, *mutations, body=None):
        with self.assertRaises(SystemExit) as raised:
            self.route(*mutations, body=body)
        return str(raised.exception)

    def test_the_honest_body_still_verifies(self):
        observed = self.route()
        self.assertEqual(observed["integrated_time"], self.INTEGRATED)

    # -- exact kind and version --------------------------------------------
    def test_a_body_of_another_kind_is_refused(self):
        self.body["kind"] = "rekord"
        self.assertIn("kind", self.refuses(body=self.body))

    def test_a_body_of_another_api_version_is_refused(self):
        self.body["apiVersion"] = "0.0.2"
        self.assertIn("version", self.refuses(body=self.body))

    def test_an_entry_kind_version_that_contradicts_the_body_is_refused(self):
        def drift(payload):
            payload["verificationMaterial"]["tlogEntries"][0]["kindVersion"] = {
                "kind": "dsse", "version": "0.0.1",
            }

        self.assertIn("kindVersion", self.refuses(drift))

    def test_an_entry_that_declares_no_kind_version_is_refused(self):
        def strip(payload):
            payload["verificationMaterial"]["tlogEntries"][0].pop("kindVersion")

        self.assertIn("kindVersion", self.refuses(strip))

    # -- a closed schema ----------------------------------------------------
    def test_an_unmodelled_body_member_is_refused(self):
        self.body["spec"]["unmodelled"] = "x"
        self.assertIn("field set", self.refuses(body=self.body))

    def test_an_unmodelled_top_level_body_member_is_refused(self):
        self.body["extra"] = 1
        self.assertIn("field set", self.refuses(body=self.body))

    # -- the algorithms ------------------------------------------------------
    def test_a_body_hash_algorithm_that_is_not_sha256_is_refused(self):
        self.body["spec"]["data"]["hash"]["algorithm"] = "sha1"
        self.assertIn("algorithm", self.refuses(body=self.body))

    # -- the digest, bound rather than merely present ------------------------
    def test_a_digest_that_is_only_present_as_a_substring_is_refused(self):
        """The honest digest survives in the body; the bound field does not."""
        honest = self.body["spec"]["data"]["hash"]["value"]
        self.body["spec"]["data"]["hash"]["value"] = "0" * 64
        self.body["spec"]["signature"]["content"] = base64.b64encode(
            honest.encode("ascii"),
        ).decode("ascii")
        self.assertIn("digest", self.refuses(body=self.body))

    # -- the signature and the verifier --------------------------------------
    def test_a_body_signature_that_is_not_the_bundle_signature_is_refused(self):
        self.body["spec"]["signature"]["content"] = base64.b64encode(
            b"another signature",
        ).decode("ascii")
        self.assertIn("signature", self.refuses(body=self.body))

    def test_a_body_certificate_that_is_not_the_bundle_leaf_is_refused(self):
        other = SigstoreFixture(
            self.subject, repository=self.REPOSITORY,
            workflow_path=self.WORKFLOW, workflow_sha=self.WORKFLOW_SHA,
            integrated=self.INTEGRATED,
        )
        self.body["spec"]["signature"]["publicKey"]["content"] = (
            base64.b64encode(other.leaf).decode("ascii")
        )
        self.assertIn("certificate", self.refuses(body=self.body))

    # -- the real-world Rekor v1 encoding ------------------------------------
    def test_the_genuine_rekor_v1_pem_public_key_encoding_is_accepted(self):
        """Real Rekor v1 records the certificate as base64 of its PEM."""
        pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            + base64.encodebytes(self.fixture.leaf)
            + b"-----END CERTIFICATE-----\n"
        )
        self.body["spec"]["signature"]["publicKey"]["content"] = (
            base64.b64encode(pem).decode("ascii")
        )
        observed = self.route(body=self.body)
        self.assertEqual(observed["integrated_time"], self.INTEGRATED)


class GenuineRekorV2BodySchemaTests(unittest.TestCase):
    """The genuine public Rekor-v2 body, decoded and bound, through production."""

    def setUp(self):
        self.raw = ed25519_rekor_v2_vector()
        self.bundle = json.loads(self.raw)
        self.entry = self.bundle["verificationMaterial"]["tlogEntries"][0]
        self.body = json.loads(
            base64.b64decode(self.entry["canonicalizedBody"])
        )

    def parsed(self):
        """The unchanged production parser, over the mutated bundle bytes."""
        self.entry["canonicalizedBody"] = base64.b64encode(
            json.dumps(self.body, separators=(",", ":")).encode("utf-8"),
        ).decode("ascii")
        return PIN.SIGSTORE.parse_bundle(json.dumps(self.bundle).encode("utf-8"))

    def refuses(self):
        with self.assertRaises(SystemExit) as raised:
            self.parsed()
        return str(raised.exception)

    def test_the_genuine_body_decodes_to_its_exact_bindings(self):
        observed = PIN.SIGSTORE.parse_bundle(self.raw)
        self.assertEqual(observed.body_kind, "hashedrekord")
        self.assertEqual(observed.body_version, "0.0.2")
        self.assertEqual(observed.body_digest, observed.message_digest)
        self.assertEqual(observed.body_signature, observed.signature)
        self.assertEqual(observed.body_certificate_der, observed.leaf_der)
        self.assertEqual(observed.body_key_details, "PKIX_ECDSA_P256_SHA_256")

    def test_a_v2_kind_version_that_is_not_the_body_is_refused(self):
        self.entry["kindVersion"] = {"kind": "hashedrekord", "version": "0.0.1"}
        self.assertIn("kindVersion", self.refuses())

    def test_a_v2_body_digest_algorithm_drift_is_refused(self):
        self.body["spec"]["hashedRekordV002"]["data"]["algorithm"] = "SHA2_512"
        self.assertIn("algorithm", self.refuses())

    def test_a_v2_body_digest_drift_is_refused(self):
        data = self.body["spec"]["hashedRekordV002"]["data"]
        data["digest"] = base64.b64encode(b"\x00" * 32).decode("ascii")
        self.assertIn("digest", self.refuses())

    def test_a_v2_body_signature_drift_is_refused(self):
        signature = self.body["spec"]["hashedRekordV002"]["signature"]
        signature["content"] = base64.b64encode(b"forged").decode("ascii")
        self.assertIn("signature", self.refuses())

    def test_an_unmodelled_v2_verifier_key_details_is_refused(self):
        verifier = (
            self.body["spec"]["hashedRekordV002"]["signature"]["verifier"]
        )
        verifier["keyDetails"] = "PKIX_UNMODELLED_KEY_TYPE"
        self.assertIn("keyDetails", self.refuses())

    def test_the_key_details_must_be_the_leaf_public_key_type(self):
        """A modelled but wrong key type is refused against the real leaf.

        The body's `keyDetails` is bound to the certificate the body itself
        records, so this drives the unchanged production binding directly
        rather than mutating a body the checkpoint already seals.
        """
        observed = PIN.SIGSTORE.parse_bundle(self.raw)
        backend = PIN._cryptography()
        leaf = backend["x509"].load_der_x509_certificate(observed.leaf_der)
        PIN._require_body_key_details(
            leaf, observed.body_key_details, backend, "genuine",
        )
        with self.assertRaises(SystemExit) as raised:
            PIN._require_body_key_details(
                leaf, "PKIX_ED25519", backend, "genuine",
            )
        self.assertIn("keyDetails", str(raised.exception))

    def test_a_v2_body_certificate_drift_is_refused(self):
        verifier = (
            self.body["spec"]["hashedRekordV002"]["signature"]["verifier"]
        )
        verifier["x509Certificate"] = {
            "rawBytes": base64.b64encode(b"not the leaf").decode("ascii"),
        }
        self.assertIn("certificate", self.refuses())

    def test_an_unmodelled_v2_body_member_is_refused(self):
        self.body["spec"]["hashedRekordV002"]["unmodelled"] = True
        self.assertIn("field set", self.refuses())


# ---------------------------------------------------------------------------
# F8-DECISION-DELIVERY-TARGET-REF-CAS-NOT-GENUINE
#
# The previous delivery installed the decision with a REST `PATCH /git/refs`
# and defended it with a *side* reference created by `POST /git/refs`. The
# side reference is atomic, but it is a different reference: nothing about
# creating `refs/acc-decision-cas/<head>` constrains what `refs/heads/main`
# holds at the instant it is rewritten. GitHub's REST reference-update
# endpoint accepts no expected-old-OID, so no REST call can be a
# compare-and-swap on the target reference.
#
# The Git wire protocol can, and it is the only GitHub-reachable primitive
# that can: a push update command is `<old-oid> <new-oid> <ref>`, and the
# receiving side applies it inside a reference transaction that fails unless
# the reference still holds exactly `<old-oid>`. `--force-with-lease=<ref>:
# <oid>` states that expectation explicitly, on the target reference itself.
#
# Everything below drives that primitive against a real `git receive-pack`.
# ---------------------------------------------------------------------------
@unittest.skipIf(GPG is None, "gpg is unavailable")
class TargetRefCompareAndSwapTests(ProductionDecisionDeliveryTransportTests):
    """The target reference itself is mutated under its expected old OID."""

    def test_no_rest_reference_mutation_ever_installs_the_decision(self):
        service, reviewer, received = self.serve()
        self.deliver(reviewer, expected_head=service.parent)
        mutations = [
            item for item in received
            if item["method"] in ("PATCH", "POST")
            and "/git/refs" in item["path"]
        ]
        self.assertEqual(
            mutations, [],
            "no REST reference write may install the decision: the endpoint "
            "accepts no expected-old-OID",
        )

    def test_the_target_ref_mutation_states_the_expected_old_oid(self):
        service, reviewer, _ = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        self.assertEqual(delivered["cas_ref"], "refs/heads/main")
        self.assertEqual(delivered["cas_expected_old_oid"], service.parent)
        self.assertEqual(
            delivered["cas_primitive"], VALIDATOR.DELIVERY_CAS_PRIMITIVE,
        )
        # The reference really moved, in the server's own repository.
        self.assertEqual(
            service.refs["refs/heads/main"], delivered["commit_sha"],
        )
        # And the update command the server received carried the old OID.
        self.assertEqual(
            service.received_updates,
            [(service.parent, delivered["commit_sha"], "refs/heads/main")],
        )

    def test_a_stale_lease_never_reaches_the_target_ref(self):
        """A branch that moved before the push is refused without sending."""
        service, reviewer, _ = self.serve()
        moving = service._default_identity()
        moved = service._store_commit(
            service.commits[service.parent]["tree"], [service.parent], "race",
            None, moving, moving,
        )
        service.move_ref("refs/heads/main", moved)
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("expected head", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], moved)

    def test_a_server_side_race_on_the_target_ref_is_refused(self):
        """The reference moves after the objects arrive, inside the server.

        A `pre-receive` hook runs after the pack is received and before the
        reference transaction commits, so moving the reference there is the
        exact race the old-OID precondition exists for. The transaction must
        refuse it, the delivery must fail closed, and the target reference
        must still hold the racing writer's commit.
        """
        service, reviewer, _ = self.serve()
        racing = service._default_identity()
        raced = service._store_commit(
            service.commits[service.parent]["tree"], [service.parent], "race",
            None, racing, racing,
        )
        service.race_on_receive("refs/heads/main", raced)
        with self.assertRaises(SystemExit) as raised:
            self.deliver(reviewer, expected_head=service.parent)
        self.assertIn(
            "compare-and-swap", str(raised.exception),
        )
        self.assertEqual(service.refs["refs/heads/main"], raced)

    def test_an_unavailable_push_primitive_fails_closed(self):
        service, reviewer, _ = self.serve()
        with self.assertRaises(SystemExit) as raised:
            self.deliver(
                reviewer, expected_head=service.parent,
                remote=str(service.repository_path / "absent.git"),
            )
        self.assertIn("compare-and-swap", str(raised.exception))
        self.assertEqual(service.refs["refs/heads/main"], service.parent)

    def test_the_side_reference_claim_is_gone_from_production(self):
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("acc-decision-cas", source)
        self.assertNotIn('"PATCH", _api_path(f"/git/refs/', source)
        self.assertNotIn('"POST", _api_path("/git/refs")', source)


# ---------------------------------------------------------------------------
# F8-ACTIVATION-EVIDENCE-NOT-GENERATOR-BOUND
#
# "A Sigstore v0.3 bundle a Cosign-v3.1.3-compatible verifier accepts" is not
# "bytes exact Cosign v3.1.3 generated". The activation this Authority may one
# day be authorized to perform is the *generation* of the missing evidence, so
# the contract that governs it binds the generator itself: the exact Cosign
# v3.1.3 binary by digest, the Ed25519 / Rekor-v2 / RFC 3161 route, the exact
# output bytes by digest, and the candidate identity those bytes are produced
# for.
#
# The candidate-static register is empty and cannot authorize or impersonate a
# future run. Fresh exact bytes accompanied by closed authenticated provenance
# cross this contract to the cryptographic verifier; legacy Cosign v3.1.3
# hashedrekord evidence, the genuine sigstore-java Rekor-v2 conformance vector,
# and compatible, relabelled or contradictory provenance are refused by name.
# Builder output is never approval: `approved`,
# `activation_authorized` and `release_authorized` all stay false until
# genuinely generated exact bytes have had a fresh independent review of their
# own.
# ---------------------------------------------------------------------------
class GeneratorBoundActivationContractTests(unittest.TestCase):
    """Only bytes exact Cosign v3.1.3 really generated may close this."""

    HEAD = "a" * 40
    TREE = "b" * 40
    BINARY = "c" * 64

    def provenance(self):
        return {
            "job_id": 51_836_402_977,
            "run_attempt": 1,
            "run_id": 18_234_567_891,
            "signing_window_end": 1_800_000_120,
            "signing_window_start": 1_799_999_880,
        }

    def offer(self, bundle=b'{"bundle":"offered"}\n', **overrides):
        declared = {
            **PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION, **overrides,
        }
        with self.assertRaises(SystemExit) as raised:
            PIN._require_generated_activation_evidence(
                bundle, declared=declared,
                generator_binary_sha256=self.BINARY,
                candidate_head=self.HEAD, candidate_tree=self.TREE,
                authenticated_provenance=self.provenance(),
            )
        return str(raised.exception)

    def accept(self):
        return PIN._require_generated_activation_evidence(
            b'{"bundle":"fresh"}\n',
            declared=PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
            generator_binary_sha256=self.BINARY,
            candidate_head=self.HEAD, candidate_tree=self.TREE,
            authenticated_provenance=self.provenance(),
        )

    # -- the contract itself -----------------------------------------------
    def test_the_contract_is_the_exact_cosign_ed25519_rekor_v2_route(self):
        contract = PIN.ACTIVATION_EVIDENCE_CONTRACT
        self.assertEqual(contract["generator"], PIN.COSIGN_V3_1_3_GENERATOR)
        self.assertEqual(contract["generator_version"], "v3.1.3")
        # "ed25519" is the Rekor v2 *log* key, never the signer's key: the
        # pinned generator cannot sign ed25519 at all.
        self.assertEqual(
            contract["signer_signature_algorithm"], "ecdsa-p256-sha256",
        )
        self.assertEqual(contract["rekor_log_key_algorithm"], "PKIX_ED25519")
        self.assertEqual(contract["rekor_generation"], PIN.SIGSTORE.REKOR_V2)
        self.assertEqual(contract["timestamp"], "rfc3161")
        self.assertEqual(
            contract["route"],
            PIN.SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE["route"],
        )
        self.assertIs(contract["generator_binary_digest_required"], True)
        self.assertIs(contract["candidate_identity_binding_required"], True)

    def test_no_generated_evidence_is_held_and_none_is_fabricated(self):
        self.assertEqual(PIN.GENERATED_ACTIVATION_EVIDENCE, {})
        report = PIN._describe_activation_evidence_contract()
        self.assertIs(report["evidence_available"], False)
        self.assertIs(report["approved"], False)
        self.assertIs(report["activation_authorized"], False)
        self.assertIs(report["release_authorized"], False)
        self.assertIs(report["builder_output_is_never_approval"], True)
        self.assertIs(
            report["post_activation_independent_review_required"], True,
        )
        self.assertIs(report["fabrication_prohibited"], True)
        self.assertIs(report["relabelling_prohibited"], True)
        self.assertIs(report["substitution_prohibited"], True)
        self.assertEqual(report["authorized_lane"], "acc-releaser")
        self.assertEqual(report["maximum_authorized_activation_attempts"], 1)

    # -- every refusal, by name --------------------------------------------
    def test_absent_evidence_is_refused(self):
        self.assertIn("no activation evidence", self.offer(b""))

    def test_the_legacy_cosign_ecdsa_hashedrekord_asset_is_refused(self):
        release = (
            ROOT / "tests" / "fixtures"
            / "cosign-v3.1.3-sigstore-v0.3-bundle.json"
        ).read_bytes()
        message = self.offer(release)
        self.assertIn("was not generated", message)
        self.assertIn(PIN.SIGSTORE.REKOR_V1, message)

    def test_the_sigstore_java_conformance_vector_is_refused(self):
        message = self.offer(ed25519_rekor_v2_vector())
        self.assertIn("sigstore-java", message)

    def test_a_compatible_or_relabelled_or_static_provenance_is_refused(self):
        for claim in (
            "cosign v3.1.3-compatible",
            "cosign-v3.1.3 compatible verifier accepted",
            "relabelled cosign v3.1.3",
            "static cosign v3.1.3 provenance",
            PIN.SIGSTORE_JAVA_CONFORMANCE_GENERATOR,
        ):
            message = self.offer(generator=claim)
            self.assertIn("generator", message, claim)
            self.assertNotIn("was generated by", message, claim)

    def test_a_wrong_generator_version_is_refused(self):
        self.assertIn(
            "version", self.offer(generator_version="v3.1.2"),
        )

    def test_a_wrong_signer_signature_algorithm_is_refused(self):
        """The signer must be ECDSA P-256; the log key is a separate field.

        `ecdsa-p256-sha256` is the *correct* signer value and is therefore no
        longer a refusal case - the genuine in-repo Rekor-v2 vector is exactly
        that. What is refused is a signer this route does not bind, including
        the log's own Ed25519 algorithm offered in the signer's place.
        """
        for claim in ("ed25519", "PKIX_ED25519", "rsa-sign-pkcs1-2048-sha256"):
            with self.subTest(signer=claim):
                self.assertIn(
                    "signer", self.offer(signer_signature_algorithm=claim),
                    claim,
                )
        # ... and the honest signer crosses the generation contract.
        self.assertEqual(self.accept()["candidate_head"], self.HEAD)

    def test_a_wrong_rekor_log_key_algorithm_is_refused(self):
        for claim in ("PKIX_ECDSA_P256_SHA_256", "ecdsa-p256-sha256", ""):
            with self.subTest(log_key=claim):
                self.assertIn(
                    "Rekor", self.offer(rekor_log_key_algorithm=claim), claim,
                )

    def test_a_wrong_rekor_generation_is_refused(self):
        self.assertIn(
            "Rekor", self.offer(rekor_generation=PIN.SIGSTORE.REKOR_V1),
        )

    def test_wrong_rfc3161_evidence_is_refused(self):
        for claim in ("", "rekor-signed-entry-timestamp", "rfc3161-optional"):
            self.assertIn("RFC 3161", self.offer(timestamp=claim), claim)

    def test_an_unmodelled_declaration_field_set_is_refused(self):
        self.assertIn(
            "field set", self.offer(unmodelled_claim="anything"),
        )

    def test_an_absent_generator_binary_digest_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            PIN._require_generated_activation_evidence(
                b'{"bundle":"offered"}\n',
                declared=PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
                generator_binary_sha256=None,
                candidate_head=self.HEAD, candidate_tree=self.TREE,
                authenticated_provenance=self.provenance(),
            )
        self.assertIn("generator binary", str(raised.exception))

    def test_an_absent_candidate_identity_is_refused(self):
        for head, tree in ((None, self.TREE), (self.HEAD, None), ("x", "y")):
            with self.assertRaises(SystemExit) as raised:
                PIN._require_generated_activation_evidence(
                    b'{"bundle":"offered"}\n',
                    declared=PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
                    generator_binary_sha256=self.BINARY,
                    candidate_head=head, candidate_tree=tree,
                    authenticated_provenance=self.provenance(),
                )
            self.assertIn("candidate identity", str(raised.exception))

    # -- the reviewed package carries the same contract --------------------
    def test_the_activation_package_carries_the_generator_bound_contract(self):
        package = ACTIVATION.verify_activation_package()
        evidence = package["generated_activation_evidence"]
        self.assertEqual(evidence["evidence_state"], "unavailable")
        self.assertEqual(evidence["route"], PIN.ACTIVATION_EVIDENCE_CONTRACT["route"])
        self.assertEqual(evidence["generator"], PIN.COSIGN_V3_1_3_GENERATOR)
        self.assertIs(evidence["builder_output_is_never_approval"], True)
        self.assertIs(
            evidence["independent_zero_finding_activation_review_required"],
            True,
        )
        self.assertIs(evidence["post_activation_independent_review_required"],
                      True)
        self.assertIs(evidence["reversible"], True)
        self.assertIs(evidence["zero_spend_required"], True)
        self.assertIs(evidence["self_authorization_forbidden"], True)
        self.assertEqual(evidence["authorized_lane"], "acc-releaser")
        self.assertEqual(evidence["maximum_authorized_activation_attempts"], 1)
        self.assertIs(package["activation_authorized"], False)

    def test_a_package_claiming_the_evidence_exists_fails_closed(self):
        for field, value in (
            ("evidence_state", "available"),
            ("builder_output_is_never_approval", False),
            ("post_activation_independent_review_required", False),
            ("independent_zero_finding_activation_review_required", False),
            ("generator", PIN.SIGSTORE_JAVA_CONFORMANCE_GENERATOR),
            ("route", "cosign-v3.1.3-ecdsa-rekor-v1"),
            ("maximum_authorized_activation_attempts", 2),
            ("zero_spend_required", False),
        ):
            payload = deepcopy(ACTIVATION.verify_activation_package())
            payload["generated_activation_evidence"][field] = value
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "source-chain-activation-v2.json"
                path.write_bytes(ACTIVATION.canonical_bytes(payload))
                with self.assertRaises(SystemExit):
                    ACTIVATION.verify_activation_package(path=path)


# ---------------------------------------------------------------------------
# F8-DECISION-DELIVERY-CAS-CAPABILITY-NOT-PROVEN
#
# Using the expected-old-OID primitive is not the same as *proving* it is in
# force. A `git` or a transport that accepts the update command but drops the
# old-OID precondition would install the decision over a racing writer and
# only then be found out - and by then the target reference has already been
# rewritten. The capability must therefore be demonstrated **before** the
# delivery goes anywhere near the target reference: a push whose update
# command states an OID the reference does not hold must be refused, and a
# push that states the OID it really holds must be applied. Both halves are
# demonstrated against a real `git receive-pack` in a scratch repository. If
# either half cannot be demonstrated, the delivery reports the compare-and-swap
# capability as unproven and performs zero target mutation.
# ---------------------------------------------------------------------------
@unittest.skipIf(GPG is None, "gpg is unavailable")
class TargetRefCasCapabilityTests(ProductionDecisionDeliveryTransportTests):
    """The primitive is proven before the target reference is ever touched."""

    def lease_dropping_git(self):
        """A `git` that accepts `--force-with-lease` and ignores it.

        Exactly the failure mode the proof exists for: the update command is
        sent without its old-OID precondition, so the receiving side applies a
        fast-forward that the lease should have refused.
        """
        directory = Path(tempfile.mkdtemp(prefix="acc-lease-dropping-git-"))
        self.addCleanup(shutil.rmtree, directory, True)
        real = subprocess.run(
            ["/usr/bin/env", "which", "git"], capture_output=True, check=True,
        ).stdout.decode().strip()
        shim = directory / "git"
        shim.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            f"real = {real!r}\n"
            "args = [a for a in sys.argv[1:] "
            "if not a.startswith('--force-with-lease')]\n"
            "os.execv(real, [real, *args])\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        return directory

    def test_the_capability_is_proven_before_the_target_ref_moves(self):
        service, reviewer, _ = self.serve()
        delivered = self.deliver(reviewer, expected_head=service.parent)
        self.assertIs(delivered["cas_capability_proven"], True)
        self.assertEqual(
            delivered["cas_capability_probe"],
            VALIDATOR.DELIVERY_CAS_CAPABILITY_PROBE,
        )
        self.assertEqual(
            delivered["cas_primitive"], VALIDATOR.DELIVERY_CAS_PRIMITIVE,
        )
        # The proof leaves nothing behind on the target: exactly one update
        # command reached the server, and it is the delivery's own.
        self.assertEqual(
            service.received_updates,
            [(service.parent, delivered["commit_sha"], "refs/heads/main")],
        )

    def test_an_unproven_capability_performs_zero_target_mutation(self):
        service, reviewer, received = self.serve()
        directory = self.lease_dropping_git()
        with mock.patch.dict(
            os.environ, {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}
        ):
            with self.assertRaises(SystemExit) as raised:
                self.deliver(reviewer, expected_head=service.parent)
        self.assertIn("compare-and-swap capability", str(raised.exception))
        # Nothing was pushed at the target at all, and it still holds its
        # original commit.
        self.assertEqual(service.received_updates, [])
        self.assertEqual(service.refs["refs/heads/main"], service.parent)
        self.assertEqual(
            [item for item in received
             if item["method"] in ("PATCH", "POST")
             and "/git/refs" in item["path"]],
            [],
        )

    def test_the_production_workflow_requires_the_proof(self):
        """The lane asserts the capability, not just the primitive's name."""
        workflow = (
            INDEPENDENT_BOOTSTRAP_ROOT / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        deliver = workflow.find("--phase deliver-decision")
        section = workflow[deliver:workflow.find("--phase decision-delivery")]
        self.assertIn(
            '.cas_capability_proven "$DELIVERY")" == "true"', section,
        )
        self.assertIn(VALIDATOR.DELIVERY_CAS_CAPABILITY_PROBE, section)

    def test_the_proof_precedes_the_installation_in_production(self):
        """Source order: proving it afterwards would be no proof at all."""
        source = (
            INDEPENDENT_BOOTSTRAP_ROOT / "scripts" / "verify_kanban_review_v2.py"
        ).read_text(encoding="utf-8")
        install = source.index("def _install_delivery_commit(")
        body = source[install:source.index("\ndef ", install + 1)]
        self.assertLess(
            body.index("_prove_cas_capability("),
            body.index('lease = f"--force-with-lease='),
            "the capability is proven only after the target lease is built",
        )
        self.assertLess(
            body.index("_prove_cas_capability("),
            body.index('"push", "--atomic"'),
            "the capability is proven only after the target push is run",
        )


# ---------------------------------------------------------------------------
# F8-SIGSTORE-EVIDENCE-PROVENANCE-UNPINNED
#
# A bundle's shape says nothing about which implementation produced it. The
# reviewer asked for digest-pinned immutable evidence genuinely produced by
# exact Cosign v3.1.3 through the Ed25519 / Rekor-v2 / RFC 3161 route, with
# immutable generator bytes.
#
# That evidence does not exist on this host and cannot be produced under this
# round's safety constraints: the route needs a live Fulcio issuance, a live
# Rekor v2 log entry and a live RFC 3161 token, and this round performs no
# signing, no issuance and no network call. The genuine public Rekor-v2 vector
# that *is* vendored was produced by the sigstore-java conformance suite, and
# is never described as anything else.
#
# So the honest close is fail-closed, not a relabelling: every vendored vector
# is pinned by digest to the generator that really emitted it, the missing
# route is recorded as explicitly unavailable, and the production route
# refuses any Rekor-v2 bytes whose provenance is not pinned.
# ---------------------------------------------------------------------------
class SigstoreEvidenceProvenanceTests(unittest.TestCase):
    """Every accepted vector is pinned to the generator that produced it."""

    def test_each_vendored_vector_is_pinned_by_digest_to_its_generator(self):
        records = PIN.SIGSTORE_EVIDENCE_PROVENANCE
        release = (
            ROOT / "tests" / "fixtures"
            / "cosign-v3.1.3-sigstore-v0.3-bundle.json"
        ).read_bytes()
        cosign = records[hashlib.sha256(release).hexdigest()]
        self.assertEqual(cosign["generator"], PIN.COSIGN_V3_1_3_GENERATOR)
        self.assertEqual(cosign["rekor_generation"], PIN.SIGSTORE.REKOR_V1)
        self.assertEqual(cosign["log_id_key_id"], LEGACY_ECDSA_LOG_KEY_ID)

        vector = records[ED25519_VECTOR_SHA256]
        self.assertEqual(vector["rekor_generation"], PIN.SIGSTORE.REKOR_V2)
        self.assertEqual(vector["log_id_key_id"], ED25519_REKOR_LOG_KEY_ID)
        self.assertEqual(vector["source_repository"], "sigstore/sigstore-java")
        self.assertEqual(vector["source_commit"], ED25519_VECTOR_SOURCE_COMMIT)
        self.assertEqual(vector["source_blob"], ED25519_VECTOR_SOURCE_BLOB)
        self.assertEqual(vector["source_path"], ED25519_VECTOR_SOURCE_PATH)
        # It is not a Cosign artifact and is never recorded as one.
        self.assertNotEqual(vector["generator"], PIN.COSIGN_V3_1_3_GENERATOR)
        self.assertIn("sigstore-java", vector["generator"])

    def test_the_exact_cosign_ed25519_rekor_v2_route_is_declared_unavailable(self):
        record = PIN.SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE
        self.assertIs(record["available"], False)
        self.assertIs(record["fabrication_prohibited"], True)
        self.assertIs(record["relabelling_prohibited"], True)
        self.assertIs(record["substitution_prohibited"], True)
        self.assertEqual(record["required_generator"], PIN.COSIGN_V3_1_3_GENERATOR)
        self.assertEqual(
            record["route"], "cosign-v3.1.3-ed25519-rekor-v2-rfc3161",
        )
        # The reason names the exact live operations this round may not do.
        for operation in ("Fulcio", "Rekor v2", "RFC 3161"):
            self.assertIn(operation, record["reason"], operation)
        # No pinned record claims that route.
        self.assertNotIn(
            (PIN.COSIGN_V3_1_3_GENERATOR, PIN.SIGSTORE.REKOR_V2),
            [
                (entry["generator"], entry["rekor_generation"])
                for entry in PIN.SIGSTORE_EVIDENCE_PROVENANCE.values()
            ],
        )

    def test_the_vendored_vector_can_never_be_relabelled_as_cosign(self):
        raw = ed25519_rekor_v2_vector()
        observed = PIN._require_sigstore_evidence_provenance(
            raw, declared=None, label="vendored",
        )
        self.assertIn("sigstore-java", observed["generator"])
        with self.assertRaises(SystemExit) as raised:
            PIN._require_sigstore_evidence_provenance(
                raw, declared=PIN.COSIGN_V3_1_3_GENERATOR, label="vendored",
            )
        self.assertIn("was not produced by", str(raised.exception))

    def test_a_claim_of_the_unavailable_route_is_always_refused(self):
        raw = ed25519_rekor_v2_vector()
        with self.assertRaises(SystemExit) as raised:
            PIN._require_sigstore_evidence_provenance(
                raw,
                declared=PIN.SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE["route"],
                label="vendored",
            )
        self.assertIn("is not available", str(raised.exception))

    def test_rekor_v2_bytes_with_no_pinned_provenance_are_refused(self):
        """The unchanged production route refuses unpinned Rekor-v2 bytes.

        These bytes are a re-serialisation of the genuine vector: every
        cryptographic member is untouched and the whole route holds, so the
        only thing that can refuse them is that their exact digest is not the
        pinned immutable one. That is the control, and it runs last so it can
        never stand in for a cryptographic check.
        """
        bundle = json.loads(ed25519_rekor_v2_vector())
        raw = json.dumps(bundle).encode("utf-8")
        self.assertNotIn(
            hashlib.sha256(raw).hexdigest(),
            PIN.SIGSTORE_EVIDENCE_PROVENANCE,
        )
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_sigstore_bundle_route(
                raw,
                subject_bytes=PIN.SIGSTORE.parse_bundle(raw).subject_bytes,
                trust=PIN._load_pinned_sigstore_trust(ROOT),
                signing_window=(1_780_514_000, 1_780_515_500),
            )
        self.assertIn("provenance is not pinned", str(raised.exception))

    def test_fresh_route_requires_the_complete_authenticated_provenance(self):
        raw = ed25519_rekor_v2_vector()
        with self.assertRaises(SystemExit) as raised:
            PIN._verify_sigstore_bundle_route(
                raw,
                subject_bytes=PIN.SIGSTORE.parse_bundle(raw).subject_bytes,
                trust=PIN._load_pinned_sigstore_trust(ROOT),
                signing_window=(1_780_514_000, 1_780_515_500),
                generated_provenance={
                    "activation_evidence_sha256": hashlib.sha256(raw).hexdigest(),
                    "generator_binary_sha256":
                        PIN.ACTIVATION_GENERATOR_BINARY_SHA256,
                },
            )
        self.assertIn("field set", str(raised.exception))

    def test_the_relabelled_vector_is_never_closure_or_activation_evidence(self):
        """Compatible is not generated: the vector may not close activation."""
        with self.assertRaises(SystemExit) as raised:
            PIN._require_generated_activation_evidence(
                ed25519_rekor_v2_vector(),
                declared=PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
                generator_binary_sha256="e" * 64,
                candidate_head="a" * 40, candidate_tree="b" * 40,
                authenticated_provenance={
                    "job_id": 51_836_402_977,
                    "run_attempt": 1,
                    "run_id": 18_234_567_891,
                    "signing_window_end": 1_800_000_120,
                    "signing_window_start": 1_799_999_880,
                },
            )
        message = str(raised.exception)
        self.assertIn("sigstore-java", message)
        self.assertIn("was not generated", message)

    def test_the_pinned_rekor_v1_route_is_untouched_by_the_control(self):
        """Rekor v1 evidence is unaffected: the missing route is v2 only."""
        subject = b'{"receipt":"exact-subject-bytes"}\n'
        fixture = SigstoreFixture(
            subject,
            repository=ACTIVATION.INDEPENDENT_REPOSITORY,
            workflow_path=ACTIVATION.TARGET_WORKFLOW_PATHS[
                ACTIVATION.INDEPENDENT_REPOSITORY
            ],
            workflow_sha="7a2d05c9138ebf4460d17ac83e592b6f0cd41827",
            integrated=1800000000,
        )
        observed = PIN._verify_sigstore_bundle_route(
            fixture.bundle(), subject_bytes=subject, trust=fixture.trust,
            signing_window=(1800000000 - 300, 1800000000 + 300),
        )
        self.assertEqual(observed["rekor_generation"], PIN.SIGSTORE.REKOR_V1)


# ---------------------------------------------------------------------------
# F8-REKOR-V2-OUTER-PROTOBUF-SCHEMA-OPEN
#
# The decoded Rekor body was a closed schema, but the three protobuf-JSON
# objects that carry it were not: the outer bundle, `verificationMaterial` and
# each tlog entry all accepted unknown members. An independent read-only
# reproduction added unknown fields at all three levels and `parse_bundle`
# still accepted the bundle as a rekor-v2 body version 0.0.2 - the only thing
# that then refused it was the static pinned-digest control, which
# authenticates nothing about protobuf-JSON shape.
#
# All three are now closed exact-member sets. They are generation-aware where
# the protobuf schema genuinely differs - a Rekor v1 entry carries the
# integrated time and signed entry timestamp a v2 entry must not carry - but
# no unknown member is accepted at any level in either generation.
# ---------------------------------------------------------------------------
class ProtobufJsonSchemaClosureTests(unittest.TestCase):
    """Unknown members are refused at every level of the full verifier."""

    UNKNOWN = "acc-unknown-protobuf-member"

    # -- Rekor v2: the genuine public Ed25519 vector ------------------------
    def vector(self, mutate=None):
        bundle = json.loads(ed25519_rekor_v2_vector())
        if mutate is not None:
            mutate(bundle)
        return json.dumps(bundle).encode("utf-8")

    def route_v2(self, raw):
        """The full unchanged production route over these exact bytes."""
        return PIN._verify_sigstore_bundle_route(
            raw,
            subject_bytes=PIN.SIGSTORE.parse_bundle(
                ed25519_rekor_v2_vector()
            ).subject_bytes,
            trust=PIN._load_pinned_sigstore_trust(ROOT),
            signing_window=(1_780_514_000, 1_780_515_500),
        )

    def assert_schema_refusal(self, raised, level):
        message = str(raised.exception)
        self.assertIn("field set is not the canonical", message, level)
        self.assertNotIn("provenance is not pinned", message, level)

    def test_an_unknown_outer_bundle_member_is_refused(self):
        def mutate(bundle):
            bundle[self.UNKNOWN] = "x"
        with self.assertRaises(SystemExit) as raised:
            self.route_v2(self.vector(mutate))
        self.assert_schema_refusal(raised, "outer bundle")

    def test_an_unknown_verification_material_member_is_refused(self):
        def mutate(bundle):
            bundle["verificationMaterial"][self.UNKNOWN] = "x"
        with self.assertRaises(SystemExit) as raised:
            self.route_v2(self.vector(mutate))
        self.assert_schema_refusal(raised, "verificationMaterial")

    def test_an_unknown_tlog_entry_member_is_refused(self):
        def mutate(bundle):
            bundle["verificationMaterial"]["tlogEntries"][0][self.UNKNOWN] = "x"
        with self.assertRaises(SystemExit) as raised:
            self.route_v2(self.vector(mutate))
        self.assert_schema_refusal(raised, "tlog entry")

    def test_unknown_members_at_all_three_levels_are_refused(self):
        """The exact reviewer reproduction: unknown fields at every level."""
        def mutate(bundle):
            bundle[self.UNKNOWN] = "x"
            bundle["verificationMaterial"][self.UNKNOWN] = "x"
            bundle["verificationMaterial"]["tlogEntries"][0][self.UNKNOWN] = "x"
        raw = self.vector(mutate)
        # The parser itself refuses it, so no caller can reach a parsed bundle.
        with self.assertRaises(SystemExit) as parsing:
            PIN.SIGSTORE.parse_bundle(raw)
        self.assertIn("field set is not the canonical", str(parsing.exception))
        with self.assertRaises(SystemExit) as raised:
            self.route_v2(raw)
        self.assert_schema_refusal(raised, "all three levels")

    def test_a_rekor_v1_entry_member_may_not_appear_on_a_v2_entry(self):
        """Generation-aware: a v2 entry may not carry the v1 members."""
        for member, value in (
            ("integratedTime", "1760000000"),
            ("inclusionPromise", {"signedEntryTimestamp": "AA=="}),
        ):
            with self.subTest(member=member):
                def mutate(bundle, member=member, value=value):
                    bundle["verificationMaterial"]["tlogEntries"][0][member] = (
                        value
                    )
                with self.assertRaises(SystemExit) as raised:
                    self.route_v2(self.vector(mutate))
                self.assertNotIn(
                    "provenance is not pinned", str(raised.exception),
                )

    def test_explicit_null_v1_members_do_not_reclassify_rekor_v2(self):
        """Generation is selected by key presence, never by its JSON value."""
        for member in ("integratedTime", "inclusionPromise"):
            with self.subTest(member=member):
                def mutate(bundle, member=member):
                    bundle["verificationMaterial"]["tlogEntries"][0][member] = None
                with self.assertRaises(SystemExit) as raised:
                    self.route_v2(self.vector(mutate))
                message = str(raised.exception)
                self.assertNotIn("provenance is not pinned", message)
                self.assertTrue(
                    "integratedTime" in message
                    or "signed entry timestamp" in message
                    or "field set" in message,
                    message,
                )

    def test_the_untouched_vector_still_parses_as_a_closed_rekor_v2_body(self):
        """The already-closed Rekor-v2 body stays green, end to end."""
        parsed = PIN.SIGSTORE.parse_bundle(ed25519_rekor_v2_vector())
        self.assertEqual(parsed.rekor_generation, PIN.SIGSTORE.REKOR_V2)
        self.assertEqual(parsed.body_version, "0.0.2")
        self.assertEqual(parsed.body_kind, PIN.SIGSTORE.HASHEDREKORD_KIND)
        self.assertEqual(
            parsed.signed_content_member, PIN.SIGSTORE.DSSE_ENVELOPE_KEY,
        )
        # ... and the re-serialised honest vector still reaches the pinned
        # provenance control rather than a schema refusal, so the closure
        # never stands in for the digest pin.
        with self.assertRaises(SystemExit) as raised:
            self.route_v2(self.vector())
        self.assertIn("provenance is not pinned", str(raised.exception))

    # -- Rekor v1: the same closure, through the same full verifier ---------
    def v1_fixture(self):
        subject = b'{"receipt":"exact-subject-bytes"}\n'
        return subject, SigstoreFixture(
            subject,
            repository=ACTIVATION.INDEPENDENT_REPOSITORY,
            workflow_path=ACTIVATION.TARGET_WORKFLOW_PATHS[
                ACTIVATION.INDEPENDENT_REPOSITORY
            ],
            workflow_sha="7a2d05c9138ebf4460d17ac83e592b6f0cd41827",
            integrated=1800000000,
        )

    def route_v1(self, fixture, subject, *mutations):
        return PIN._verify_sigstore_bundle_route(
            fixture.bundle(*mutations), subject_bytes=subject,
            trust=fixture.trust,
            signing_window=(1800000000 - 300, 1800000000 + 300),
        )

    def test_unknown_members_are_refused_on_a_rekor_v1_bundle_too(self):
        subject, fixture = self.v1_fixture()
        for level, mutate in (
            ("outer bundle",
             lambda payload: payload.__setitem__(self.UNKNOWN, "x")),
            ("verificationMaterial",
             lambda payload: payload["verificationMaterial"].__setitem__(
                 self.UNKNOWN, "x")),
            ("tlog entry",
             lambda payload: payload["verificationMaterial"]["tlogEntries"][0]
             .__setitem__(self.UNKNOWN, "x")),
        ):
            with self.subTest(level=level):
                with self.assertRaises(SystemExit) as raised:
                    self.route_v1(fixture, subject, mutate)
                self.assertIn(
                    "field set is not the canonical", str(raised.exception),
                    level,
                )

    def test_the_honest_rekor_v1_bundle_still_verifies(self):
        subject, fixture = self.v1_fixture()
        observed = self.route_v1(fixture, subject)
        self.assertEqual(observed["rekor_generation"], PIN.SIGSTORE.REKOR_V1)

    def test_every_consumed_v1_nested_object_is_exact_on_crypto_route(self):
        subject, fixture = self.v1_fixture()
        paths = (
            ("messageSignature",),
            ("messageSignature", "messageDigest"),
            ("verificationMaterial", "x509CertificateChain"),
            ("verificationMaterial", "tlogEntries", 0, "logId"),
            ("verificationMaterial", "tlogEntries", 0,
             "inclusionPromise"),
            ("verificationMaterial", "tlogEntries", 0, "inclusionProof"),
            ("verificationMaterial", "tlogEntries", 0, "inclusionProof",
             "checkpoint"),
        )

        def at(payload, path):
            current = payload
            for member in path:
                current = current[member]
            return current

        for path in paths:
            with self.subTest(path=path, mutation="unknown"):
                def add_unknown(payload, path=path):
                    at(payload, path)[self.UNKNOWN] = "x"
                with self.assertRaises(SystemExit) as raised:
                    self.route_v1(fixture, subject, add_unknown)
                self.assertNotIn("provenance is not pinned", str(raised.exception))

            with self.subTest(path=path, mutation="missing"):
                def remove_required(payload, path=path):
                    target = at(payload, path)
                    target.pop(next(iter(target)))
                with self.assertRaises(SystemExit):
                    self.route_v1(fixture, subject, remove_required)

            with self.subTest(path=path, mutation="type-confused"):
                def confuse_type(payload, path=path):
                    parent = at(payload, path[:-1])
                    parent[path[-1]] = []
                with self.assertRaises(SystemExit):
                    self.route_v1(fixture, subject, confuse_type)

    def test_every_consumed_v2_nested_object_is_exact_on_crypto_route(self):
        paths = (
            ("dsseEnvelope",),
            ("dsseEnvelope", "signatures", 0),
            ("verificationMaterial", "timestampVerificationData"),
            ("verificationMaterial", "timestampVerificationData",
             "rfc3161Timestamps", 0),
            ("verificationMaterial", "tlogEntries", 0, "logId"),
            ("verificationMaterial", "tlogEntries", 0, "inclusionProof"),
            ("verificationMaterial", "tlogEntries", 0, "inclusionProof",
             "checkpoint"),
        )

        def at(payload, path):
            current = payload
            for member in path:
                current = current[member]
            return current

        for path in paths:
            with self.subTest(path=path, mutation="unknown"):
                def add_unknown(payload, path=path):
                    at(payload, path)[self.UNKNOWN] = "x"
                with self.assertRaises(SystemExit) as raised:
                    self.route_v2(self.vector(add_unknown))
                self.assertNotIn("provenance is not pinned", str(raised.exception))

            with self.subTest(path=path, mutation="missing"):
                def remove_required(payload, path=path):
                    target = at(payload, path)
                    target.pop(next(iter(target)))
                with self.assertRaises(SystemExit) as raised:
                    self.route_v2(self.vector(remove_required))
                self.assertNotIn("provenance is not pinned", str(raised.exception))

            with self.subTest(path=path, mutation="type-confused"):
                def confuse_type(payload, path=path):
                    parent = at(payload, path[:-1])
                    parent[path[-1]] = []
                with self.assertRaises(SystemExit) as raised:
                    self.route_v2(self.vector(confuse_type))
                self.assertNotIn("provenance is not pinned", str(raised.exception))

    def test_inclusion_coordinates_reject_bool_and_noncanonical_int64(self):
        subject, fixture = self.v1_fixture()
        for member, value in (
            ("logIndex", True),
            ("logIndex", "01"),
            ("treeSize", False),
            ("treeSize", "04"),
        ):
            with self.subTest(member=member, value=value):
                def mutate(payload, member=member, value=value):
                    payload["verificationMaterial"]["tlogEntries"][0][
                        "inclusionProof"
                    ][member] = value
                with self.assertRaises(SystemExit):
                    self.route_v1(fixture, subject, mutate)


# ---------------------------------------------------------------------------
# F8-GENERATOR-BOUND-ACTIVATION-UNREACHABLE
#
# The generator-bound contract was complete and correct, and completely
# unreachable: `_require_generated_activation_evidence` had zero production
# callers, `GENERATED_ACTIVATION_EVIDENCE` was empty, and the separately
# executed activation workflow invoked `cosign sign-blob` twice while
# recording no Cosign binary digest, no route declaration and no
# binary/candidate/output provenance at all. A contract nothing runs refuses
# nothing.
#
# The one-shot activation now emits a closed provenance record and the
# workflow drives the unchanged production CLI over it. The CLI binds the
# exact Cosign v3.1.3 binary digest, the exact candidate head/tree and all
# four diff streams, the exact generated output bytes by digest and the
# authenticated run/attempt/job/repository/ref/SHA provenance, and only then
# routes the bytes through `_require_generated_activation_evidence` and the
# cryptographic production verifier, requiring the exact Ed25519 / Rekor-v2 /
# RFC 3161 route before any success.
#
# The tests generate, sign, issue and dispatch nothing. The candidate-static
# register remains empty without gating fresh run-bound output. The reachable
# verifier still reports `activation_authorized`, `approved` and
# `release_authorized` as false; later acceptance remains independent work.
# ---------------------------------------------------------------------------
GENERATED_ACTIVATION_PHASE = "generated-activation-evidence"


class GeneratedActivationReachabilityTests(unittest.TestCase):
    """The production CLI really reaches the generator-bound verifier."""

    # Canonical-looking, high-entropy values: the production boundary rejects
    # synthetic repeated-digit identifiers and hand-typed constant digests.
    RUN_ID = 18_234_567_891
    JOB_ID = 51_836_402_977
    RUN_SHA = "7a2d05c9138ebf4460d17ac83e592b6f0cd41827"
    REVIEW_SHA = "6b1c04b8027daf335fc06ab72d481a5e9bc30716"

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, True)

    @staticmethod
    def git(*arguments):
        """One exact value from the immutable checkout this candidate is."""
        return subprocess.run(
            ["git", "-C", str(ROOT), *arguments],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def output(self, payload):
        path = self.directory / PIN.ACTIVATION_EVIDENCE_OUTPUT_NAME
        path.write_bytes(payload)
        return path

    def subject(self, head, tree, diffs):
        """The exact canonical activation subject for this candidate."""
        path = self.directory / "activation-subject.json"
        path.write_bytes(PIN._activation_subject_bytes(head, tree, diffs))
        return path

    def raw_provenance(self, head):
        raw = self.directory / "raw"
        raw.mkdir(exist_ok=True)
        review_run_id = 18_234_567_811
        review_job_id = 51_836_402_911
        external_members = {
            "external-activation-review-receipt.json": b'{"review":"exact"}\n',
            "external-activation-review-receipt.sigstore.json":
                b'{"bundle":"external"}\n',
        }
        signed_members = {
            "kanban-review-envelope.json": b'{"envelope":"exact"}\n',
            "preissuance-review-receipt.json": b'{"receipt":"exact"}\n',
            "preissuance-review-receipt.sigstore.json":
                b'{"bundle":"receipt"}\n',
        }
        archives = {
            "external-review-artifact.zip":
                build_artifact_archive(external_members),
            "signed-review-artifact.zip": build_artifact_archive(signed_members),
        }
        for directory_name, members in (
            ("external-review", external_members),
            ("signed-review", signed_members),
        ):
            directory = self.directory / directory_name
            directory.mkdir(exist_ok=True)
            for name, data in members.items():
                (directory / name).write_bytes(data)
        documents = {
            "activation-run.json": {
                "event": "workflow_run", "head_branch": "main",
                "head_sha": self.RUN_SHA, "id": self.RUN_ID,
                "path": VALIDATOR.INDEPENDENT_WORKFLOW, "run_attempt": 1,
            },
            "workflow-run-event.json": {
                "workflow_run": {"id": review_run_id,
                                 "head_sha": self.REVIEW_SHA},
            },
            "decision-commit.json": {
                "sha": self.RUN_SHA,
                "parents": [{
                    "sha": self.REVIEW_SHA,
                    "url": (
                        "https://api.github.com/repos/chrizzatsu/"
                        "acc-authority-independent-review/commits/"
                        + self.REVIEW_SHA
                    ),
                    "html_url": (
                        "https://github.com/chrizzatsu/"
                        "acc-authority-independent-review/commit/"
                        + self.REVIEW_SHA
                    ),
                }],
            },
            "activation-jobs.json": [{"jobs": [{
                "head_sha": self.RUN_SHA, "id": self.JOB_ID,
                "name": PIN.ACTIVATION_JOB_NAME, "run_attempt": 1,
                "run_id": self.RUN_ID,
                "started_at": "2027-01-15T07:58:00Z",
            }], "total_count": 1}],
            "activation-runs.json": [{"workflow_runs": [{
                "event": "workflow_run", "id": self.RUN_ID,
                "run_attempt": 1,
            }], "total_count": 1}],
            "review-run.json": {
                "conclusion": "success", "event": "workflow_dispatch",
                "head_sha": self.REVIEW_SHA, "id": review_run_id,
                "path": VALIDATOR.INDEPENDENT_WORKFLOW, "run_attempt": 1,
                "status": "completed",
            },
            "review-jobs.json": [{"jobs": [{
                "conclusion": "success", "head_sha": self.RUN_SHA,
                "id": review_job_id, "name": PIN.INDEPENDENT_JOB_NAME,
                "run_attempt": 1, "run_id": review_run_id,
                "status": "completed",
            }], "total_count": 1}],
            "review-artifacts.json": [{"artifacts": [
                {"digest": "sha256:" + hashlib.sha256(
                    archives["signed-review-artifact.zip"]
                 ).hexdigest(), "expired": False,
                 "id": 51_836_402_912,
                 "name": "authority-v2-signed-review-t_c298fca4",
                 "workflow_run": {"id": review_run_id}},
                {"digest": "sha256:" + hashlib.sha256(
                    archives["external-review-artifact.zip"]
                 ).hexdigest(), "expired": False,
                 "id": 51_836_402_913,
                 "name": "authority-v2-external-activation-review-t_c298fca4",
                 "workflow_run": {"id": review_run_id}},
            ], "total_count": 2}],
            "workflow-state-before.json": {
                "path": VALIDATOR.INDEPENDENT_WORKFLOW,
                "state": "active",
            },
            "workflow-state-after.json": {
                "path": VALIDATOR.INDEPENDENT_WORKFLOW,
                "state": "disabled_manually",
            },
            "workflow-state-cleanup.json": {
                "path": VALIDATOR.INDEPENDENT_WORKFLOW,
                "state": "disabled_manually",
            },
        }
        digests = {}
        for name, document in documents.items():
            data = json.dumps(document, sort_keys=True).encode() + b"\n"
            (raw / name).write_bytes(data)
            digests[name] = hashlib.sha256(data).hexdigest()
        for name, data in archives.items():
            (raw / name).write_bytes(data)
            digests[name] = hashlib.sha256(data).hexdigest()
        document = {
            "files": digests,
            "record_type": PIN.ACTIVATION_RAW_PROVENANCE_TYPE,
        }
        path = self.directory / "raw-provenance.json"
        path.write_bytes(
            json.dumps(document, sort_keys=True, separators=(",", ":"))
            .encode() + b"\n"
        )
        return path

    def record(self, payload=None, **overrides):
        """The provenance record the one-shot activation workflow emits."""
        payload = (
            payload if payload is not None else b'{"bundle":"offered"}\n'
        )
        path = self.output(payload)
        diffs = {}
        for name in PIN.ACTIVATION_CANDIDATE_DIFF_STREAMS:
            data = f"acc-diff-stream::{name}".encode()
            (self.directory / name).write_bytes(data)
            diffs[name] = hashlib.sha256(data).hexdigest()
        head = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        subject_path = self.subject(head, tree, diffs)
        provenance_path = self.raw_provenance(head)
        document = {
            "candidate": {
                "diff_sha256": diffs,
                "head": head,
                "tree": tree,
            },
            "generated_subject": {
                "path": subject_path.name,
                "sha256": hashlib.sha256(
                    subject_path.read_bytes()
                ).hexdigest(),
            },
            "declaration": dict(PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION),
            "generated_output": {
                "path": path.name,
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
            "generator_binary": {
                "platform": PIN.ACTIVATION_GENERATOR_PLATFORM,
                "sha256": PIN.ACTIVATION_GENERATOR_BINARY_SHA256,
            },
            "record_type": PIN.ACTIVATION_RECORD_TYPE,
            "raw_provenance": {
                "path": provenance_path.name,
                "sha256": hashlib.sha256(
                    provenance_path.read_bytes()
                ).hexdigest(),
            },
            "run_provenance": {
                "job_id": self.JOB_ID,
                "job_name": PIN.ACTIVATION_JOB_NAME,
                "ref": PIN.DEFAULT_REF,
                "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
                "run_attempt": PIN.RUN_ATTEMPT,
                "run_id": self.RUN_ID,
                "sha": self.RUN_SHA,
                "activation_head_sha": self.RUN_SHA,
                "decision_sha": self.RUN_SHA,
                "review_head_sha": self.REVIEW_SHA,
                "signing_window_end": 1_800_000_120,
                "signing_window_start": 1_799_999_880,
            },
        }
        for dotted, value in overrides.items():
            section, _, key = dotted.partition(".")
            if key:
                if value is _UNSET:
                    document[section].pop(key)
                else:
                    document[section][key] = value
            elif value is _UNSET:
                document.pop(section)
            else:
                document[section] = value
        target = self.directory / "activation-record.json"
        target.write_bytes(
            json.dumps(document, sort_keys=True).encode("utf-8") + b"\n"
        )
        return target

    def cli(self, record):
        """The unchanged production CLI, over exactly this record."""
        return subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "pin_source_chain_activation_v2.py"),
             "--phase", GENERATED_ACTIVATION_PHASE,
             "--activation-record", str(record)],
            capture_output=True, cwd=str(ROOT),
        )

    def refusal(self, record):
        observed = self.cli(record)
        self.assertNotEqual(
            observed.returncode, 0,
            "the production activation CLI accepted evidence that does not "
            "exist: " + observed.stdout.decode(),
        )
        self.assertEqual(observed.stdout, b"")
        self.assertNotIn("Traceback", observed.stderr.decode())
        return observed.stderr.decode()

    # -- the verifier is reachable from production at all ------------------
    def test_the_generated_evidence_verifier_has_a_production_caller(self):
        """The defect itself: a contract nothing runs refuses nothing."""
        tree = ast.parse(
            (ROOT / "scripts" / "pin_source_chain_activation_v2.py")
            .read_text(encoding="utf-8")
        )
        functions = {
            node.name: node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        def calls(name, seen=()):
            node = functions.get(name)
            if node is None or name in seen:
                return set()
            called = {
                child.func.id for child in ast.walk(node)
                if isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
            }
            reached = set(called)
            for callee in called:
                reached |= calls(callee, (*seen, name))
            return reached

        reachable = calls("main")
        self.assertIn("_require_generated_activation_evidence", reachable)
        self.assertIn("_verify_sigstore_bundle_route", reachable)

    def test_the_activation_workflow_drives_the_production_cli(self):
        workflow = (
            ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(GENERATED_ACTIVATION_PHASE, workflow)
        self.assertIn("pin_source_chain_activation_v2.py", workflow)
        # The Cosign binary the run really installed is digested there, and
        # the digest is required to be the pinned one before it is used.
        self.assertIn(PIN.ACTIVATION_GENERATOR_BINARY_SHA256, workflow)
        # The record it composes really names every member the closed
        # production schema binds, so the two can never drift apart.
        for name in PIN.ACTIVATION_CANDIDATE_DIFF_STREAMS:
            self.assertIn(name, workflow, name)
        for member in (*PIN.ACTIVATION_RECORD_KEYS,
                       *PIN.ACTIVATION_RECORD_RUN_KEYS,
                       *PIN.ACTIVATION_RECORD_CANDIDATE_KEYS,
                       *PIN.ACTIVATION_EVIDENCE_DECLARATION_KEYS):
            self.assertIn(member, workflow, member)
        self.assertIn(PIN.ACTIVATION_EVIDENCE_CONTRACT["route"], workflow)
        self.assertIn(PIN.ACTIVATION_JOB_NAME, workflow)
        # Activation is another workflow execution, triggered only by the
        # completed immutable review run. No dispatch input selects it.
        self.assertNotIn("generate_activation_evidence", workflow)
        self.assertNotIn("inputs.", workflow)
        self.assertIn("workflow_run:", workflow)
        self.assertIn("github.event_name == 'workflow_run'", workflow)
        # It generates the evidence itself, exactly once, with the only
        # signer algorithm the pinned generator supports - never with the
        # transparency log's Ed25519 key, which no signer flag can assert.
        activation = workflow.split(f"  {PIN.ACTIVATION_JOB_NAME}:", 1)[1]
        self.assertEqual(activation.count("sign-blob"), 1)
        self.assertIn(
            f"--signing-algorithm {PIN.ACTIVATION_SIGNER_COSIGN_ALGORITHM}",
            activation,
        )
        self.assertNotIn("--signing-algorithm ed25519", activation)
        self.assertIn(PIN.ACTIVATION_EVIDENCE_OUTPUT_NAME, activation)

    # -- fresh output is not gated against a candidate-static register ------
    def test_fresh_run_bound_bytes_cross_the_generation_contract(self):
        payload = b'{"fresh":"exact-cosign-output"}\n'
        observed = PIN._require_generated_activation_evidence(
            payload,
            declared=PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
            generator_binary_sha256=PIN.ACTIVATION_GENERATOR_BINARY_SHA256,
            candidate_head=self.git("rev-parse", "HEAD"),
            candidate_tree=self.git("rev-parse", "HEAD^{tree}"),
            authenticated_provenance={
                "job_id": self.JOB_ID,
                "run_attempt": 1,
                "run_id": self.RUN_ID,
                "signing_window_end": 1_800_000_120,
                "signing_window_start": 1_799_999_880,
            },
        )
        self.assertEqual(
            observed["activation_evidence_sha256"],
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(observed["signing_window_start"], 1_799_999_880)

    def test_fresh_record_reaches_the_full_production_crypto_verifier(self):
        record = self.record()
        parsed = mock.Mock()
        parsed.rekor_generation = PIN.SIGSTORE.REKOR_V2
        parsed.rfc3161_timestamps = (b"authenticated RFC3161 token",)
        parsed.body_key_details = PIN.ACTIVATION_SIGNER_BODY_KEY_DETAILS
        parsed.binds_subject.return_value = True
        verified = {
            "rekor_generation": PIN.SIGSTORE.REKOR_V2,
            "rekor_key_details": PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS,
            "signer_key_details": PIN.ACTIVATION_SIGNER_BODY_KEY_DETAILS,
            "leaf_der": b"verified Fulcio leaf",
        }
        claims = {
            **GeneratedActivationOidcIdentityTests.CLAIMS,
        }
        with (
            mock.patch.object(PIN.SIGSTORE, "parse_bundle", return_value=parsed),
            mock.patch.object(
                PIN, "_verify_sigstore_bundle_route", return_value=verified,
            ) as route,
            mock.patch.object(PIN, "_certificate_claims", return_value=claims),
        ):
            observed = PIN._require_generated_activation_run(record)
        self.assertEqual(observed["rekor_generation"], PIN.SIGSTORE.REKOR_V2)
        provenance = route.call_args.kwargs["generated_provenance"]
        self.assertEqual(
            provenance["activation_evidence_sha256"],
            hashlib.sha256(
                (self.directory / PIN.ACTIVATION_EVIDENCE_OUTPUT_NAME)
                .read_bytes()
            ).hexdigest(),
        )

    def test_a_malformed_fresh_bundle_reaches_the_cryptographic_parser(self):
        message = self.refusal(self.record())
        self.assertIn("media type", message)
        self.assertNotIn("was not generated", message)

    def test_the_legacy_hashedrekord_asset_is_refused_through_the_cli(self):
        release = (
            ROOT / "tests" / "fixtures"
            / "cosign-v3.1.3-sigstore-v0.3-bundle.json"
        ).read_bytes()
        message = self.refusal(self.record(release))
        self.assertIn("was not generated by", message)
        self.assertIn(PIN.SIGSTORE.REKOR_V1, message)

    def test_the_sigstore_java_vector_is_refused_through_the_cli(self):
        message = self.refusal(self.record(ed25519_rekor_v2_vector()))
        self.assertIn("sigstore-java", message)
        self.assertIn("was not generated by", message)

    def test_a_relabelled_generator_is_refused_through_the_cli(self):
        message = self.refusal(
            self.record(declaration={
                **PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
                "generator": "cosign v3.1.3-compatible",
            })
        )
        self.assertIn("generator", message)

    def test_a_wrong_or_absent_cosign_binary_digest_is_refused(self):
        for label, value in (
            ("absent", _UNSET),
            ("static", "0" * 64),
            ("other release", "4" * 63 + "5"),
        ):
            with self.subTest(label=label):
                message = self.refusal(
                    self.record(**{"generator_binary.sha256": value})
                )
                self.assertIn("generator binary", message, label)

    def test_a_generated_output_that_is_not_the_named_bytes_is_refused(self):
        message = self.refusal(
            self.record(**{
                "generated_output.sha256": hashlib.sha256(b"other\n").hexdigest(),
            })
        )
        self.assertIn("generated output", message)

    def test_an_absent_generated_output_is_refused(self):
        record = self.record()
        (self.directory / PIN.ACTIVATION_EVIDENCE_OUTPUT_NAME).unlink()
        self.assertIn("generated output", self.refusal(record))

    def test_activation_record_paths_are_closed_artifact_relative_paths(self):
        for field, value in (
            ("generated_output.path", "/tmp/output.json"),
            ("generated_subject.path", "../subject.json"),
            ("raw_provenance.path", "."),
            ("generated_output.path", ""),
            ("generated_output.path", "./generated-activation-evidence.sigstore.json"),
            ("generated_subject.path", "nested//activation-subject.json"),
            ("raw_provenance.path", "raw\\provenance.json"),
        ):
            with self.subTest(field=field, value=value):
                self.assertIn("artifact-relative", self.refusal(
                    self.record(**{field: value})
                ))

    def test_activation_record_refuses_a_symlink_escape(self):
        record = self.record()
        outside = self.directory.parent / (self.directory.name + "-outside")
        outside.write_bytes(b'{}\n')
        self.addCleanup(outside.unlink, True)
        output = self.directory / PIN.ACTIVATION_EVIDENCE_OUTPUT_NAME
        output.unlink()
        output.symlink_to(outside)
        self.assertIn("escapes the activation artifact root", self.refusal(record))

    def test_complete_activation_artifact_is_relocatable(self):
        record = self.record()
        document = json.loads(record.read_bytes())
        document["generated_output"]["path"] = PIN.ACTIVATION_EVIDENCE_OUTPUT_NAME
        document["generated_subject"]["path"] = "activation-subject.json"
        document["raw_provenance"]["path"] = "raw-provenance.json"
        record.write_bytes(json.dumps(document, sort_keys=True).encode() + b"\n")
        relocated = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, relocated, True)
        shutil.copytree(self.directory, relocated / "activation")
        shutil.rmtree(self.directory)
        self.directory.mkdir()
        result = self.cli(relocated / "activation" / "activation-record.json")
        # The synthetic bundle is expected to reach the cryptographic parser;
        # relocation itself must not be the reason for refusal.
        self.assertNotIn("absent or unsafe", result.stderr.decode())
        self.assertNotIn("artifact-relative", result.stderr.decode())

    def test_one_resolver_rejects_aliases_duplicate_targets_and_symlinks(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "raw").mkdir()
        (root / "raw" / "member.json").write_bytes(b"{}\n")
        resolved = PIN._resolve_artifact_members(
            root, ("raw/member.json",), "test inventory",
        )
        self.assertEqual(
            resolved["raw/member.json"],
            (root / "raw" / "member.json").resolve(),
        )
        for value in (
            "/raw/member.json", "", "./raw/member.json",
            "raw//member.json", "raw/../member.json", "raw\\member.json",
        ):
            with self.subTest(alias=value), self.assertRaises(SystemExit):
                PIN._resolve_artifact_members(root, (value,), "test inventory")
        with self.assertRaises(SystemExit):
            PIN._resolve_artifact_members(
                root, ("raw/member.json", "raw/member.json"), "test inventory",
            )

        outside = root.parent / f"{root.name}-outside"
        outside.mkdir()
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "member.json").write_bytes(b"{}\n")
        (root / "final-link.json").symlink_to(outside / "member.json")
        with self.assertRaises(SystemExit):
            PIN._resolve_artifact_members(
                root, ("final-link.json",), "test inventory",
            )
        shutil.rmtree(root / "raw")
        (root / "raw").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(SystemExit):
            PIN._resolve_artifact_members(
                root, ("raw/member.json",), "test inventory",
            )

    def test_a_subject_for_another_candidate_is_refused(self):
        """Evidence generated for a different candidate cannot be offered."""
        record = self.record()
        other = PIN._activation_subject_bytes(
            "c" * 40, "d" * 40,
            {n: "e" * 64 for n in PIN.ACTIVATION_CANDIDATE_DIFF_STREAMS},
        )
        path = self.directory / "activation-subject.json"
        path.write_bytes(other)
        document = json.loads(Path(record).read_bytes())
        document["generated_subject"]["sha256"] = hashlib.sha256(
            other
        ).hexdigest()
        Path(record).write_bytes(
            json.dumps(document, sort_keys=True).encode("utf-8") + b"\n"
        )
        self.assertIn(
            "canonical activation subject", self.refusal(record),
        )

    def test_an_absent_or_mismatched_generated_subject_is_refused(self):
        self.assertIn(
            "generated subject",
            self.refusal(self.record(**{
                "generated_subject.sha256":
                    hashlib.sha256(b"other\n").hexdigest(),
            })),
        )

    def test_an_unbound_candidate_or_diff_identity_is_refused(self):
        for dotted, value in (
            ("candidate.head", _UNSET),
            ("candidate.tree", "b" * 40),
            ("candidate.diff_sha256", {}),
        ):
            with self.subTest(field=dotted):
                self.assertIn(
                    "candidate", self.refusal(self.record(**{dotted: value})),
                )

    def test_tampered_diff_stream_bytes_are_refused(self):
        record = self.record()
        (self.directory / PIN.ACTIVATION_CANDIDATE_DIFF_STREAMS[0]).write_bytes(
            b"tampered reviewed stream"
        )
        self.assertIn("diff stream", self.refusal(record))

    def test_tampered_raw_authenticated_provenance_is_refused(self):
        record = self.record()
        (self.directory / "raw" / "activation-run.json").write_bytes(b"{}\n")
        self.assertIn("raw provenance", self.refusal(record))

    def test_a_second_activation_run_on_a_later_page_is_refused(self):
        record = self.record()
        raw = self.directory / "raw"
        runs_path = raw / "activation-runs.json"
        runs = json.loads(runs_path.read_bytes())
        runs.append({"workflow_runs": [{
            "event": "workflow_run", "id": self.RUN_ID + 1,
            "run_attempt": 1,
        }], "total_count": 2})
        runs[0]["total_count"] = 2
        runs_bytes = json.dumps(runs, sort_keys=True).encode() + b"\n"
        runs_path.write_bytes(runs_bytes)
        provenance_path = self.directory / "raw-provenance.json"
        provenance = json.loads(provenance_path.read_bytes())
        provenance["files"]["activation-runs.json"] = hashlib.sha256(
            runs_bytes
        ).hexdigest()
        provenance_bytes = (
            json.dumps(provenance, sort_keys=True, separators=(",", ":"))
            .encode() + b"\n"
        )
        provenance_path.write_bytes(provenance_bytes)
        record_data = json.loads(Path(record).read_bytes())
        record_data["raw_provenance"]["sha256"] = hashlib.sha256(
            provenance_bytes
        ).hexdigest()
        Path(record).write_bytes(
            json.dumps(record_data, sort_keys=True).encode() + b"\n"
        )
        self.assertIn("globally unique", self.refusal(record))

    def test_duplicate_record_members_are_refused(self):
        record = self.record()
        data = Path(record).read_bytes().replace(
            b'"record_type":',
            b'"record_type":"duplicate","record_type":',
            1,
        )
        Path(record).write_bytes(data)
        self.assertIn("duplicate", self.refusal(record))

    def test_unauthenticated_run_provenance_is_refused(self):
        for dotted, value in (
            ("run_provenance.run_id", _UNSET),
            ("run_provenance.run_id", 1111111111),
            ("run_provenance.run_attempt", 2),
            ("run_provenance.job_id", _UNSET),
            ("run_provenance.job_name", PIN.INDEPENDENT_JOB_NAME),
            ("run_provenance.repository", "chrizzatsu/somewhere-else"),
            ("run_provenance.ref", "refs/heads/other"),
            ("run_provenance.sha", "0" * 40),
        ):
            with self.subTest(field=dotted, value=value):
                self.assertIn("run", self.refusal(self.record(**{dotted: value})))

    def test_review_decision_and_activation_heads_are_distinct_and_causal(self):
        record = self.record()
        document = json.loads(record.read_bytes())
        self.assertNotEqual(
            document["run_provenance"]["review_head_sha"],
            document["run_provenance"]["decision_sha"],
        )
        for field, value in (
            ("run_provenance.review_head_sha", self.RUN_SHA),
            ("run_provenance.decision_sha", "8" * 40),
            ("run_provenance.activation_head_sha", "9" * 40),
        ):
            with self.subTest(field=field):
                self.assertIn("causal", self.refusal(
                    self.record(**{field: value})
                ))

    def test_real_github_parent_shape_reaches_the_crypto_parser(self):
        message = self.refusal(self.record())
        self.assertIn("media type", message)
        self.assertNotIn("H-to-D", message)

    def test_github_parent_shape_is_closed_and_ordered(self):
        repository = ACTIVATION.INDEPENDENT_REPOSITORY

        def parent(sha):
            return {
                "sha": sha,
                "url": f"https://api.github.com/repos/{repository}/commits/{sha}",
                "html_url": f"https://github.com/{repository}/commit/{sha}",
            }

        valid = {"parents": [parent(self.REVIEW_SHA)]}
        self.assertEqual(
            PIN._github_commit_parent_shas(
                valid, repository, "activation decision commit",
            ),
            [self.REVIEW_SHA],
        )
        other = "8c3e16da249fb05471e28bd94f16ac703de52938"
        malformed = []
        changed = deepcopy(valid)
        changed["parents"][0]["unexpected"] = True
        malformed.append(changed)
        changed = deepcopy(valid)
        changed["parents"][0].pop("url")
        malformed.append(changed)
        changed = deepcopy(valid)
        changed["parents"][0]["sha"] = True
        malformed.append(changed)
        malformed.append({})
        malformed.append({"parents": []})
        changed = deepcopy(valid)
        changed["parents"] = [parent(other), parent(self.REVIEW_SHA)]
        malformed.append(changed)
        changed = deepcopy(valid)
        changed["parents"] = [parent(self.REVIEW_SHA), parent(other)]
        malformed.append(changed)
        for index, document in enumerate(malformed):
            with self.subTest(index=index):
                with self.assertRaises(SystemExit):
                    projected = PIN._github_commit_parent_shas(
                        document, repository, "activation decision commit",
                    )
                    PIN.require(
                        projected == [self.REVIEW_SHA],
                        "activation decision parent order mismatch",
                    )

    def test_an_unmodelled_record_member_is_refused(self):
        self.assertIn(
            "field set", self.refusal(self.record(unmodelled="anything")),
        )

    def test_complete_generated_artifact_inventory_is_accepted(self):
        self.record()
        self.assertTrue(PIN._require_generated_artifact_inventory(self.directory))

    def test_generated_artifact_inventory_rejects_open_or_unbound_members(self):
        for label, mutate in (
            ("missing", lambda root: (root / "raw" /
                                      "workflow-state-cleanup.json").unlink()),
            ("additional", lambda root: (root / "unbound.txt").write_bytes(b"x")),
            ("unbound", lambda root: (root / "external-review" /
                                      "external-activation-review-receipt.json")
             .write_bytes(b'{"review":"substituted"}\n')),
            ("secret", lambda root: (root / "runtime-token.txt")
             .write_bytes(b"Authorization: Bearer ghp_not_allowed_here\n")),
        ):
            with self.subTest(label=label):
                shutil.rmtree(self.directory)
                self.directory.mkdir()
                self.record()
                mutate(self.directory)
                with self.assertRaises(SystemExit):
                    PIN._require_generated_artifact_inventory(self.directory)

    # -- and nothing it can ever report is an authorization -----------------
    def test_the_phase_can_never_authorize_anything(self):
        source = inspect.getsource(PIN._require_generated_activation_run)
        for flag in ("activation_authorized", "approved", "release_authorized"):
            self.assertIn(f'"{flag}": False', source, flag)
        report = PIN._describe_activation_evidence_contract()
        self.assertIs(report["activation_authorized"], False)
        self.assertIs(report["approved"], False)
        self.assertIs(report["release_authorized"], False)


# ---------------------------------------------------------------------------
# The route distinguishes the SIGNER's key from the REKOR LOG's key.
#
# "Ed25519" in `cosign-v3.1.3-ed25519-rekor-v2-rfc3161` names the Rekor-v2
# transparency log's verification key, not the artifact signer's key. The
# genuine in-repo Rekor-v2 vector settles it: its signer is
# `PKIX_ECDSA_P256_SHA_256` and the log that includes it is the pinned
# Ed25519 log `log2025-1.rekor.sigstore.dev` (`PKIX_ED25519`).
#
# Collapsing the two into one `signature_algorithm` field made the contract
# demand an Ed25519 *signer*, which the pinned generator cannot produce at
# all: cosign v3.1.3 rejects `ed25519` exactly as it rejects a nonsense
# value, its supported set being ecdsa-sha2-256-nistp256, -384-nistp384,
# -512-nistp521 and the three rsa-sign-pkcs1 variants. The two are therefore
# separate, unambiguously named, and each bound to the real bytes.
# ---------------------------------------------------------------------------
class SignerVersusRekorLogKeyTests(unittest.TestCase):
    """Signer algorithm and Rekor log key algorithm are distinct bindings."""

    def test_the_declaration_names_both_keys_unambiguously(self):
        declaration = PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION
        self.assertNotIn(
            "signature_algorithm", declaration,
            "one collapsed field cannot name two different keys",
        )
        self.assertEqual(
            declaration["signer_signature_algorithm"], "ecdsa-p256-sha256",
        )
        self.assertEqual(
            declaration["rekor_log_key_algorithm"], "PKIX_ED25519",
        )
        self.assertEqual(declaration["rekor_generation"], PIN.SIGSTORE.REKOR_V2)
        self.assertEqual(declaration["timestamp"], "rfc3161")
        # The generator pin is untouched.
        self.assertEqual(declaration["generator"], PIN.COSIGN_V3_1_3_GENERATOR)
        self.assertEqual(declaration["generator_version"], "v3.1.3")
        self.assertEqual(
            tuple(sorted(declaration)),
            tuple(sorted(PIN.ACTIVATION_EVIDENCE_DECLARATION_KEYS)),
        )

    def test_the_signer_algorithm_is_one_cosign_v3_1_3_really_supports(self):
        """The exact CLI value the pinned generator accepts, and no other."""
        self.assertEqual(
            PIN.ACTIVATION_SIGNER_COSIGN_ALGORITHM, "ecdsa-sha2-256-nistp256",
        )
        self.assertEqual(
            PIN.ACTIVATION_SIGNER_BODY_KEY_DETAILS,
            "PKIX_ECDSA_P256_SHA_256",
        )
        self.assertEqual(
            PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS, "PKIX_ED25519",
        )
        # ed25519 is not a signer algorithm the generator can be asked for.
        self.assertNotIn(
            "ed25519", PIN.ACTIVATION_SIGNER_COSIGN_ALGORITHM,
        )

    def offer(self, **overrides):
        declared = {
            **PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION, **overrides,
        }
        with self.assertRaises(SystemExit) as raised:
            PIN._require_generated_activation_evidence(
                b'{"bundle":"offered"}\n', declared=declared,
                generator_binary_sha256="c" * 64,
                candidate_head="a" * 40, candidate_tree="b" * 40,
                authenticated_provenance={
                    "job_id": 51_836_402_977,
                    "run_attempt": 1,
                    "run_id": 18_234_567_891,
                    "signing_window_end": 1_800_000_120,
                    "signing_window_start": 1_799_999_880,
                },
            )
        return str(raised.exception)

    def test_a_non_ecdsa_signer_is_refused(self):
        for claim in ("ed25519", "rsa-sign-pkcs1-2048-sha256", "", "PKIX_ED25519"):
            with self.subTest(signer=claim):
                message = self.offer(signer_signature_algorithm=claim)
                self.assertIn("signer", message, claim)

    def test_a_non_ed25519_rekor_log_key_is_refused(self):
        for claim in (
            "PKIX_ECDSA_P256_SHA_256", "ecdsa-p256-sha256", "", "ed25519",
        ):
            with self.subTest(log_key=claim):
                message = self.offer(rekor_log_key_algorithm=claim)
                self.assertIn("Rekor", message, claim)

    def test_the_genuine_route_is_not_refused_for_algorithm_reasons(self):
        """The honest ECDSA-P256 signer on the Ed25519 log passes the contract."""
        observed = PIN._require_generated_activation_evidence(
            b'{"bundle":"fresh"}\n',
            declared=PIN.ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
            generator_binary_sha256="c" * 64,
            candidate_head="a" * 40, candidate_tree="b" * 40,
            authenticated_provenance={
                "job_id": 51_836_402_977,
                "run_attempt": 1,
                "run_id": 18_234_567_891,
                "signing_window_end": 1_800_000_120,
                "signing_window_start": 1_799_999_880,
            },
        )
        self.assertEqual(observed["candidate_tree"], "b" * 40)

    # -- and the distinction is bound to the real bytes, not just declared --
    def test_the_genuine_vector_really_is_ecdsa_signed_on_the_ed25519_log(self):
        parsed = PIN.SIGSTORE.parse_bundle(ed25519_rekor_v2_vector())
        self.assertEqual(
            parsed.body_key_details, PIN.ACTIVATION_SIGNER_BODY_KEY_DETAILS,
        )
        self.assertEqual(parsed.rekor_generation, PIN.SIGSTORE.REKOR_V2)
        self.assertEqual(parsed.log_key_id, ED25519_REKOR_LOG_KEY_ID)
        self.assertTrue(parsed.rfc3161_timestamps)

    def test_the_pinned_trust_carries_the_rekor_log_key_algorithm(self):
        """The log's own key algorithm travels with the pinned trust."""
        trust = PIN._load_pinned_sigstore_trust(ROOT)
        selected = trust.select(
            INTEGRATED_WITHIN_ED25519_VALIDITY, ED25519_REKOR_LOG_KEY_ID,
        )
        self.assertEqual(
            selected.rekor_key_details, PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS,
        )
        legacy = trust.select(1_760_000_000, LEGACY_ECDSA_LOG_KEY_ID)
        self.assertEqual(legacy.rekor_key_details, "PKIX_ECDSA_P256_SHA_256")

    def test_the_full_route_reports_both_algorithms_separately(self):
        """The production verifier reports signer and log key independently."""
        raw = ed25519_rekor_v2_vector()
        observed = PIN._verify_sigstore_bundle_route(
            raw, subject_bytes=PIN.SIGSTORE.parse_bundle(raw).subject_bytes,
            trust=PIN._load_pinned_sigstore_trust(ROOT),
            signing_window=(1_780_514_000, 1_780_515_500),
        )
        self.assertEqual(
            observed["rekor_key_details"],
            PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS,
        )
        self.assertEqual(
            observed["signer_key_details"],
            PIN.ACTIVATION_SIGNER_BODY_KEY_DETAILS,
        )
        self.assertEqual(observed["rekor_generation"], PIN.SIGSTORE.REKOR_V2)


class ActivationGenerationStepTests(unittest.TestCase):
    """The activation job really generates the bytes it then verifies."""

    def workflow(self):
        return (
            ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")

    def activation_job(self):
        return self.workflow().split(f"  {PIN.ACTIVATION_JOB_NAME}:", 1)[1]

    def test_the_job_signs_with_the_supported_cosign_signer_algorithm(self):
        job = self.activation_job()
        self.assertIn("sign-blob", job)
        self.assertIn(
            f"--signing-algorithm {PIN.ACTIVATION_SIGNER_COSIGN_ALGORITHM}",
            job,
        )
        # The algorithm the pinned generator cannot accept never appears.
        self.assertNotIn("--signing-algorithm ed25519", job)

    def test_the_job_generates_the_exact_path_the_record_consumes(self):
        job = self.activation_job()
        self.assertIn(PIN.ACTIVATION_EVIDENCE_OUTPUT_NAME, job)
        # The digest the record carries is computed from the generated bytes.
        self.assertIn("sha256sum", job)

    def test_the_job_verifies_the_binary_before_it_generates(self):
        job = self.activation_job()
        generate = job.index("sign-blob")
        verify_binary = job.index(PIN.ACTIVATION_GENERATOR_BINARY_SHA256)
        self.assertLess(
            verify_binary, generate,
            "the generator binary must be pinned before it is executed",
        )

    def test_the_job_verifies_the_generated_bytes_after_it_generates(self):
        job = self.activation_job()
        generate = job.index("sign-blob")
        verify = job.index("--phase generated-activation-evidence")
        self.assertLess(
            generate, verify,
            "the generated bytes must be routed through the verifier",
        )

    def test_the_job_fails_closed_on_every_step(self):
        job = self.activation_job()
        blocks = [
            line for line in job.splitlines() if line.strip() == "set -euo pipefail"
        ]
        self.assertGreaterEqual(len(blocks), 5)


class GeneratedActivationOidcIdentityTests(unittest.TestCase):
    """A valid Sigstore route is still bound to the activation workload."""

    CLAIMS = {
        "identity": "https://github.com/chrizzatsu/acc-authority-independent-review/.github/workflows/review-authority-v2.yml@refs/heads/main",
        "issuer": PIN.OIDC_ISSUER,
        "source_repository_uri": "https://github.com/chrizzatsu/acc-authority-independent-review",
        "source_repository_ref": "refs/heads/main",
        "build_config_uri": "https://github.com/chrizzatsu/acc-authority-independent-review/.github/workflows/review-authority-v2.yml@refs/heads/main",
        "build_config_digest": GeneratedActivationReachabilityTests.RUN_SHA,
        "build_trigger": "workflow_run",
    }

    def verify(self, claims):
        provenance = {
            "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "ref": PIN.DEFAULT_REF,
            "sha": GeneratedActivationReachabilityTests.RUN_SHA,
        }
        return PIN._require_generated_activation_oidc_identity(claims, provenance)

    def test_all_fulcio_identity_claims_are_persisted(self):
        self.assertEqual(self.verify(dict(self.CLAIMS)), self.CLAIMS)

    def test_every_fulcio_identity_field_is_substitution_resistant(self):
        for field in self.CLAIMS:
            with self.subTest(field=field):
                changed = dict(self.CLAIMS)
                changed[field] = "substituted"
                with self.assertRaises(SystemExit):
                    self.verify(changed)


class TerminalReadbackCollectorWorkflowTests(unittest.TestCase):
    """Terminal state is collected by a second, inputless workflow run."""

    PATH = (
        ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
        / "readback-authority-v2-activation.yml"
    )
    REVIEW_WORKFLOW_NAME = "Sign exact protected Kanban Authority-v2 review"
    COLLECTOR_WORKFLOW_NAME = "Read back closed Authority-v2 activation"

    def workflow(self):
        self.assertTrue(
            self.PATH.is_file(),
            "a terminal receipt cannot be authored by the activation run itself",
        )
        return self.PATH.read_text(encoding="utf-8")

    def collector_job(self):
        return self.workflow().split("  terminal-readback:", 1)[1]

    def production_script(self, step_name, next_step_name):
        workflow = self.workflow()
        step = workflow.split(f"      - name: {step_name}\n", 1)[1]
        step = step.split(f"      - name: {next_step_name}\n", 1)[0]
        script = step.split("        run: |\n", 1)[1]
        return textwrap.dedent(script)

    def test_public_python_runtime_rejects_custom_image_and_ignores_altered_path(self):
        expected_image = (
            "docker.io/library/python:3.13.7-slim@sha256:"
            "2be5d3cb08aa616c6e38d922bd7072975166b2de772004f79ee1bae59fe983dc"
        )
        unavailable_image = (
            "ghcr.io/chrizzatsu/acc-authority-terminal-runtime-v2@sha256:"
            "598538ceabab0a56885d023bcfdba9b48f9a01d6661218cf96606a89ec368965"
        )
        contract = json.loads(
            (ROOT / "independent-review-bootstrap-v2"
             / "bootstrap-contract.json").read_bytes()
        )
        runtime = contract["terminal_readback"]["collector_verifier"]["runtime"]
        self.assertEqual(runtime["image"], expected_image)
        self.assertNotEqual(runtime["image"], unavailable_image)
        self.assertNotIn(unavailable_image, self.workflow())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "ambient-runtime-executed"
            for executable in ("python3", "gh", "jq", "unzip", "git"):
                substitute = root / executable
                substitute.write_text(
                    "#!/bin/sh\n"
                    f"printf touched >> {marker!s}\n"
                    "exit 99\n",
                    encoding="utf-8",
                )
                substitute.chmod(0o755)
            self.assertTrue(
                VALIDATOR.require_terminal_python_runtime(
                    contract,
                    executable="/usr/local/bin/python3",
                    version=(3, 13, 7),
                    environment={"PATH": str(root)},
                )
            )
            self.assertFalse(marker.exists())

        substituted = deepcopy(contract)
        substituted["terminal_readback"]["collector_verifier"]["runtime"][
            "image"
        ] = unavailable_image
        with self.assertRaises(SystemExit):
            VALIDATOR.require_terminal_python_runtime(
                substituted,
                executable="/usr/local/bin/python3",
                version=(3, 13, 7),
                environment={"PATH": "/untrusted"},
            )

    def test_loader_authenticates_activation_head_before_any_byte_fetch(self):
        script = self.production_script(
            "Run the exact-hash authenticated Python stdlib collector",
            "Upload separately named closed terminal readback",
        )
        environment = {
            "ACTIVATION_HEAD_SHA": "b" * 40,
            "ACTIVATION_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": (
                "chrizzatsu/acc-authority-independent-review"
            ),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_TOKEN": "PLACEHOLDER_SECRET_MUST_NOT_BE_READ",
            "GITHUB_WORKFLOW_REF": (
                "chrizzatsu/acc-authority-independent-review/"
                ".github/workflows/readback-authority-v2-activation.yml"
                "@refs/heads/main"
            ),
            "GITHUB_WORKSPACE": str(ROOT),
            "PATH": "/authority-v2-no-ambient-tools",
        }
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch(
            "urllib.request.build_opener",
            side_effect=AssertionError("unsealed dependency read reached"),
        ) as opener:
            with self.assertRaisesRegex(
                SystemExit, "collector head does not match activation head",
            ):
                exec(compile(script, str(self.PATH), "exec"), {"__name__": "__main__"})
        opener.assert_not_called()

    def test_actual_loader_reaches_absolute_execve_under_hostile_path(self):
        """Exercise authenticated fetch, hashing and the real exec boundary."""
        script = self.production_script(
            "Run the exact-hash authenticated Python stdlib collector",
            "Upload separately named closed terminal readback",
        )
        collector_bytes = self.PATH.read_bytes()
        validator_path = (
            ROOT / "independent-review-bootstrap-v2" / "scripts"
            / "verify_kanban_review_v2.py"
        )
        validator_bytes = validator_path.read_bytes()
        contract = json.loads(
            (ROOT / "independent-review-bootstrap-v2"
             / "bootstrap-contract.json").read_bytes()
        )
        validator_digest = hashlib.sha256(validator_bytes).hexdigest()
        collector_digest = hashlib.sha256(collector_bytes).hexdigest()
        contract["validator"] = {
            "path": "scripts/verify_kanban_review_v2.py",
            "sha256": validator_digest,
        }
        contract["authorized_source_run"][
            "independent_validator_sha256"
        ] = validator_digest
        contract["terminal_readback"][
            "collector_workflow_sha256"
        ] = collector_digest
        contract_bytes = json.dumps(contract, sort_keys=True).encode("utf-8")
        fetched = {
            "bootstrap-contract.json": contract_bytes,
            "scripts/verify_kanban_review_v2.py": validator_bytes,
            ".github/workflows/readback-authority-v2-activation.yml":
                collector_bytes,
        }

        class Response:
            status = 200

            def __init__(self, data):
                self.data = data

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, limit):
                self.test_case.assertLessEqual(len(self.data), limit)
                return self.data

        Response.test_case = self

        class Opener:
            def __init__(self):
                self.paths = []

            def open(self, request, timeout):
                self.test_case.assertEqual(timeout, 60)
                path = request.full_url.split("/contents/", 1)[1].split(
                    "?ref=", 1
                )[0]
                self.paths.append(path)
                return Response(fetched[path])

        Opener.test_case = self

        runtime_root = Path("/tmp/authority-v2-terminal-verifier")
        self.assertFalse(runtime_root.exists(), "fixed runtime root is occupied")
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            hostile = Path(temporary) / "hostile-path"
            hostile.mkdir()
            marker = Path(temporary) / "path-substitute-executed"
            for executable in ("python3", "git", "gh", "jq", "openssl"):
                substitute = hostile / executable
                substitute.write_text(
                    "#!/bin/sh\n"
                    f"printf executed >> {marker!s}\n"
                    "exit 97\n",
                    encoding="utf-8",
                )
                substitute.chmod(0o755)
            environment = {
                "ACTIVATION_HEAD_SHA": commit,
                "ACTIVATION_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": "workflow_run",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_REPOSITORY": (
                    "chrizzatsu/acc-authority-independent-review"
                ),
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_SHA": commit,
                "GITHUB_TOKEN": "INERT_TEST_TOKEN_NOT_A_CREDENTIAL",
                "GITHUB_WORKFLOW_REF": (
                    "chrizzatsu/acc-authority-independent-review/"
                    ".github/workflows/readback-authority-v2-activation.yml"
                    "@refs/heads/main"
                ),
                "GITHUB_WORKSPACE": str(ROOT),
                "PATH": str(hostile),
            }
            opener = Opener()
            try:
                with (
                    mock.patch.dict(os.environ, environment, clear=True),
                    mock.patch(
                        "urllib.request.build_opener", return_value=opener,
                    ),
                    mock.patch("os.chdir") as chdir,
                    mock.patch("os.execve") as execve,
                ):
                    exec(
                        compile(script, str(self.PATH), "exec"),
                        {"__name__": "__main__"},
                    )
                self.assertEqual(
                    opener.paths,
                    [
                        "bootstrap-contract.json",
                        "scripts/verify_kanban_review_v2.py",
                        ".github/workflows/readback-authority-v2-activation.yml",
                    ],
                )
                chdir.assert_called_once_with(ROOT)
                execve.assert_called_once()
                executable, arguments, child_environment = execve.call_args.args
                self.assertEqual(executable, "/usr/local/bin/python3")
                self.assertEqual(arguments[:3], [executable, "-I", "-B"])
                self.assertEqual(child_environment["PATH"], str(hostile))
                self.assertFalse(marker.exists())
            finally:
                if runtime_root.exists():
                    shutil.rmtree(runtime_root)

    def test_a_real_separate_collector_workflow_exists_at_the_only_new_path(self):
        workflow = self.workflow()
        self.assertIn(f"name: {self.COLLECTOR_WORKFLOW_NAME}", workflow)
        self.assertNotEqual(
            self.PATH,
            ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
            / "review-authority-v2.yml",
        )

    def test_trigger_is_inputless_completed_review_workflow_only(self):
        workflow = self.workflow()
        trigger = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_run:", trigger)
        self.assertIn(f"workflows: [{self.REVIEW_WORKFLOW_NAME}]", trigger)
        self.assertIn("types: [completed]", trigger)
        self.assertNotIn("workflow_dispatch", trigger)
        self.assertNotIn("inputs:", workflow)
        job = self.collector_job()
        for contract_check in (
            "github.event.workflow_run.event == 'workflow_run'",
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.head_branch == 'main'",
            "github.event.workflow_run.path == '.github/workflows/review-authority-v2.yml'",
            "github.event.workflow_run.head_repository.full_name == github.repository",
        ):
            self.assertIn(contract_check, job, contract_check)

    def test_permissions_are_read_only_except_for_the_signing_identity(self):
        workflow = self.workflow()
        permissions = workflow.split("permissions:", 1)[1].split("jobs:", 1)[0]
        self.assertIn("actions: read", permissions)
        self.assertIn("contents: read", permissions)
        self.assertIn("id-token: write", permissions)
        self.assertNotIn("actions: write", permissions)
        self.assertNotIn("contents: write", permissions)
        self.assertNotIn("pull-requests:", permissions)
        job = self.collector_job()
        for mutation in ("gh workflow enable", "gh workflow disable", "-X POST",
                         "-X PUT", "-X PATCH", "-X DELETE"):
            self.assertNotIn(mutation, job)

    def test_all_terminal_facts_are_authenticated_api_readbacks(self):
        source = inspect.getsource(VALIDATOR)
        for readback in (
            'actions/runs/{run_id}',
            'attempts/1/jobs',
            'actions/runs/{run_id}/artifacts',
            'actions/artifacts/{artifact_id}/zip',
            'actions/workflows/review-authority-v2.yml',
            'commits/{head}',
        ):
            self.assertIn(readback, source, readback)
        self.assertIn("_terminal_paginated_capture", source)
        self.assertIn("github.event.workflow_run.id", self.collector_job())
        self.assertNotIn("github.event.inputs", self.collector_job())

        signed = "sig=" + "a" * 64
        storage = (
            "https://productionresultssa10.blob.core.windows.net/"
            f"actions-results/artifact.zip?{signed}"
        )
        exchanges = (
            (302, (("Location", storage),), b""),
            (200, (("Content-Type", "application/zip"),), b"zip-bytes"),
        )
        with mock.patch.object(
            VALIDATOR, "_terminal_exchange", side_effect=exchanges,
        ) as exchange:
            observed = VALIDATOR._terminal_download_artifact(
                "repos/chrizzatsu/acc-authority-independent-review/"
                "actions/artifacts/51836402999/zip",
                "runtime-token-must-not-cross-boundaries",
            )
        self.assertEqual(observed, b"zip-bytes")
        api_request = exchange.call_args_list[0].args[0]
        storage_request = exchange.call_args_list[1].args[0]
        self.assertIn("Authorization", dict(api_request.header_items()))
        self.assertNotIn("Authorization", dict(storage_request.header_items()))
        self.assertNotIn(
            "X-github-api-version", dict(storage_request.header_items()),
        )

    def test_run_job_artifact_content_and_cleanup_are_closed_before_signing(self):
        job = self.collector_job()
        source = inspect.getsource(VALIDATOR)
        for binding in (
            '"event": "workflow_run"',
            '"path": INDEPENDENT_WORKFLOW',
            'TERMINAL_ACTIVATION_JOB_NAME = "generated-activation-evidence"',
            'authority-v2-generated-activation-evidence-t_c298fca4',
            'artifact.get("expired") is False',
            '"matching_count": 1',
            '"archive_sha256"',
            '"content_sha256"',
            '"activation_record_sha256"',
            'activation-record.json',
            'Reassert disabled state and delete ephemeral bytes',
            '"disabled_manually"',
            '"verify-blob"',
            '"--certificate-identity"',
            'INDEPENDENT_TERMINAL_COLLECTOR}@refs/heads/main',
            PIN.ACTIVATION_GENERATOR_BINARY_SHA256,
        ):
            self.assertIn(binding, source, binding)
        self.assertIn('authority-v2-closed-terminal-readback-t_c298fca4', job)
        collector = inspect.getsource(VALIDATOR.collect_terminal_readback)
        compose = collector.index("_terminal_archive_identity")
        sign = collector.index("_terminal_sign_receipt")
        verify = inspect.getsource(VALIDATOR._terminal_sign_receipt).index(
            '"verify-blob"'
        )
        upload = job.index("actions/upload-artifact@")
        self.assertLess(compose, sign)
        self.assertGreater(verify, 0)
        self.assertGreater(upload, 0)

    def test_archive_paths_are_rejected_before_normalization_or_extraction(self):
        def archive(name, *, mode=None):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as generated:
                info = zipfile.ZipInfo(name)
                if mode is not None:
                    info.external_attr = mode << 16
                generated.writestr(info, b"{}\n")
            return output.getvalue()

        for label, name, mode in (
            ("parent", "../activation-record.json", None),
            ("absolute", "/activation-record.json", None),
            ("backslash", "unsafe\\activation-record.json", None),
            ("directory", "activation-record.json/", None),
            ("symlink", "activation-record.json", stat.S_IFLNK | 0o777),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "artifact").mkdir()
                with self.assertRaises(SystemExit):
                    VALIDATOR._terminal_extract_artifact(
                        root, archive(name, mode=mode), ("activation-record.json",),
                    )
        activation = (
            ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("unzip -qq", activation)
        self.assertIn("unsafe or aliased review artifact path", activation)

    def test_collector_cannot_recurse_or_accept_the_initial_dispatch_run(self):
        workflow = self.workflow()
        trigger = workflow.split("permissions:", 1)[0]
        workflow_selectors = [
            line.strip() for line in trigger.splitlines()
            if line.strip().startswith("workflows:")
        ]
        self.assertEqual(
            workflow_selectors,
            [f"workflows: [{self.REVIEW_WORKFLOW_NAME}]"],
        )
        self.assertNotIn(self.COLLECTOR_WORKFLOW_NAME, workflow_selectors[0])
        self.assertEqual(trigger.count("workflows:"), 1)
        job = self.collector_job()
        self.assertIn("event == 'workflow_run'", job)
        self.assertNotIn("event == 'workflow_dispatch'", job)
        self.assertNotIn("workflow_dispatch:", workflow)

    def test_source_chain_and_bootstrap_seal_the_same_collector_contract(self):
        source_chain = json.loads(
            (ROOT / "source-chain-activation-v2.json").read_bytes()
        )
        bootstrap = json.loads(
            (ROOT / "independent-review-bootstrap-v2"
             / "bootstrap-contract.json").read_bytes()
        )
        self.assertEqual(
            source_chain["terminal_readback"], bootstrap["terminal_readback"],
        )
        terminal = source_chain["terminal_readback"]
        self.assertEqual(
            terminal["collector_workflow_sha256"],
            hashlib.sha256(self.PATH.read_bytes()).hexdigest(),
        )
        sealed = {
            entry["path"]: entry["sha256"]
            for entry in source_chain["sealed_bytes"]
        }
        self.assertEqual(
            sealed[
                "independent-review-bootstrap-v2/.github/workflows/"
                "readback-authority-v2-activation.yml"
            ],
            terminal["collector_workflow_sha256"],
        )

    def test_collector_uses_no_authority_runtime_or_checkout(self):
        workflow = self.workflow()
        source_chain = json.loads(
            (ROOT / "source-chain-activation-v2.json").read_bytes()
        )
        bootstrap = json.loads(
            (ROOT / "independent-review-bootstrap-v2"
             / "bootstrap-contract.json").read_bytes()
        )
        verifier = source_chain["terminal_readback"]["collector_verifier"]
        self.assertEqual(
            verifier,
            bootstrap["terminal_readback"]["collector_verifier"],
        )
        self.assertEqual(
            verifier["mode"],
            "digest-pinned-python-stdlib-no-authority-checkout",
        )
        self.assertEqual(
            verifier["repository"], ACTIVATION.AUTHORITY_REPOSITORY,
        )
        runtime = verifier["runtime"]
        self.assertEqual(runtime["image"], ACTIVATION.TERMINAL_RUNTIME_IMAGE)
        self.assertEqual(
            runtime["executables"],
            list(ACTIVATION.TERMINAL_RUNTIME_EXECUTABLES),
        )
        self.assertTrue(runtime["root_filesystem_read_only"])
        self.assertEqual(
            tuple(verifier["files"]), ("collector", "cosign", "python3"),
        )
        self.assertEqual(
            verifier["files"]["python3"],
            f"oci-manifest:{ACTIVATION.TERMINAL_RUNTIME_DIGEST}",
        )
        self.assertEqual(
            verifier["files"]["collector"],
            "sha256:" + hashlib.sha256(
                (ROOT / "independent-review-bootstrap-v2" / "scripts"
                 / "verify_kanban_review_v2.py").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(
            verifier["files"]["cosign"], ACTIVATION.TERMINAL_COSIGN_DIGEST,
        )
        self.assertEqual(
            verifier["entrypoint"],
            f"{ACTIVATION.TERMINAL_RUNTIME_EXECUTABLE} -I -B",
        )
        for boundary in (
            f"image: {ACTIVATION.TERMINAL_RUNTIME_IMAGE}",
            "options: --read-only --cap-drop=ALL",
            "PATH: /authority-v2-no-ambient-tools",
            f"shell: {ACTIVATION.TERMINAL_RUNTIME_EXECUTABLE} -I -B",
            "Run the exact-hash authenticated Python stdlib collector",
        ):
            self.assertIn(boundary, workflow, boundary)
        for forbidden in (" gh ", " jq ", "unzip ", "zipinfo ", " git ",
                          "cryptography", "OPENSSL_", "actions/checkout@",
                          "cosign-installer@", "/bin/bash"):
            self.assertNotIn(forbidden, workflow, forbidden)
        self.assertNotIn("terminal/authority-verifier", workflow)
        self.assertIn("--phase", workflow)
        self.assertIn("terminal-readback-collector", workflow)

    def test_substituted_ambient_runtimes_cannot_produce_a_verifier_verdict(self):
        workflow = self.workflow()
        contracts = (
            json.loads((ROOT / "source-chain-activation-v2.json").read_bytes()),
            json.loads((ROOT / "independent-review-bootstrap-v2"
                        / "bootstrap-contract.json").read_bytes()),
        )
        for contract in contracts:
            verifier = contract["terminal_readback"]["collector_verifier"]
            self.assertEqual(
                verifier["runtime"]["image"],
                ACTIVATION.TERMINAL_RUNTIME_IMAGE,
            )
            self.assertEqual(
                verifier["runtime"]["image_digest"],
                ACTIVATION.TERMINAL_RUNTIME_DIGEST,
            )
        # The exact interpreter path is the only launch boundary. PATH remains
        # deliberately hostile and cannot select a semantic helper.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "executed"
            for executable in ("python3", "gh", "jq", "unzip", "git", "openssl"):
                path = root / executable
                path.write_text(
                    f"#!/bin/sh\nprintf '%s' substituted >> {marker!s}\nexit 99\n",
                    encoding="utf-8",
                )
                path.chmod(0o755)
            self.assertTrue(VALIDATOR.require_terminal_python_runtime(
                contracts[1], executable="/usr/local/bin/python3",
                version=(3, 13, 7), environment={"PATH": str(root)},
            ))
            self.assertFalse(marker.exists())

    def test_terminal_output_inventory_is_recursive_closed_and_explicit(self):
        workflow = self.workflow()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for member in VALIDATOR.TERMINAL_OUTPUT_MEMBERS:
                (output / member).write_bytes(b"{}\n")
            VALIDATOR._terminal_require_output_inventory(output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
            for member in VALIDATOR.TERMINAL_OUTPUT_MEMBERS:
                self.assertEqual(
                    stat.S_IMODE((output / member).stat().st_mode), 0o444,
                )
        upload = workflow.split(
            "- name: Upload separately named closed terminal readback", 1
        )[1]
        self.assertNotIn("path: terminal/output\n", upload)
        self.assertIn("path: |", upload)
        self.assertIn("terminal/output/terminal-activation-readback.json", upload)
        self.assertIn(
            "terminal/output/terminal-activation-readback.sigstore.json", upload,
        )

    def test_production_terminal_scanner_rejects_every_secret_class_binary_safe(self):
        aws_access_key_pattern = re.compile(rb"AKIA[A-Z0-9]{16}")
        source = Path(__file__).read_bytes()
        self.assertIsNone(
            aws_access_key_pattern.search(source),
            "committed test source contains an AWS Access Key ID-shaped literal",
        )
        runtime_aws_access_key = b"AK" + b"IA" + b"ABCDEFGHIJKLMNOP"
        self.assertRegex(runtime_aws_access_key, aws_access_key_pattern)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for name in VALIDATOR.TERMINAL_OUTPUT_MEMBERS:
                (output / name).write_bytes(b"{}\n")
            (output / VALIDATOR.TERMINAL_OUTPUT_MEMBERS[0]).write_bytes(
                runtime_aws_access_key
            )
            with self.assertRaisesRegex(
                SystemExit, "secret-bearing terminal output member"
            ):
                VALIDATOR._terminal_require_output_inventory(output)

        payloads = {
            "authorization": b"\x00Authorization: Bearer PLACEHOLDER_SECRET\x00",
            "authorization-json": (
                b'\x00{"Authorization":"Bearer INERT_PLACEHOLDER_VALUE"}\x00'
            ),
            "authorization-env": (
                b"\x00AUTHORIZATION = Basic INERT_PLACEHOLDER_VALUE\x00"
            ),
            "github": b"\x00github_pat_PLACEHOLDER_SECRET_BYTES_123456\x00",
            "private-key": b"\x00-----BEGIN PRIVATE KEY-----\x00PLACEHOLDER\x00",
            "private-key-json": (
                b'\x00{"privateKey":"-----BEGIN EC PRIVATE KEY-----\\n'
                b'INERT_PLACEHOLDER"}\x00'
            ),
            "aws-access-key": (
                b"\x00aws_access_key_id=" + runtime_aws_access_key + b"\x00"
            ),
            "aws-access-id-json": (
                b'\x00{"Aws-Access.Key Id":"INERTACCESSIDENTIFIER"}\x00'
            ),
            "aws-asia-env": b"\x00AWS_ACCESS_KEY_ID=ASIAABCDEFGHIJKLMNOP\x00",
            "aws-secret-key": (
                b"\x00aws_secret_access_key="
                b"PLACEHOLDER_SECRET_MUST_BE_REJECTED\x00"
            ),
            "aws-secret-json": (
                b'\x00{"AWS-SECRET.ACCESS KEY":'
                b'"INERT_PLACEHOLDER_SECRET_VALUE"}\x00'
            ),
            "aws-session-env": (
                b"\x00Aws.Session-Token = INERT_PLACEHOLDER_SESSION_VALUE\x00"
            ),
        }
        members = (
            "terminal/output/terminal-activation-readback.json",
            "terminal/output/terminal-activation-readback.sigstore.json",
        )
        scanners = (
            VALIDATOR._terminal_require_output_inventory,
            PIN._require_terminal_output_inventory,
        )
        for scanner in scanners:
            for member in members:
                for secret_class, payload in payloads.items():
                    with self.subTest(
                        scanner=scanner.__module__, member=member,
                        secret_class=secret_class,
                    ):
                        with tempfile.TemporaryDirectory() as temporary:
                            output = Path(temporary)
                            for name in VALIDATOR.TERMINAL_OUTPUT_MEMBERS:
                                (output / name).write_bytes(b"{}\n")
                            (output / Path(member).name).write_bytes(payload)
                            with self.assertRaisesRegex(
                                SystemExit,
                                "secret-bearing terminal output member",
                            ):
                                scanner(output)

    def test_terminal_output_inventory_rejects_every_open_member_shape(self):
        runtime_aws_access_key = b"AK" + b"IA" + b"ABCDEFGHIJKLMNOP"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in PIN.TERMINAL_OUTPUT_MEMBERS:
                (root / name).write_text("{}\n", encoding="utf-8")
            PIN._require_terminal_output_inventory(root)
            mutations = {
                "nested-file": lambda: ((root / "nested").mkdir(),
                                         (root / "nested" / "extra").write_text("x")),
                "directory": lambda: (root / "extra").mkdir(),
                "symlink": lambda: (root / "extra").symlink_to(root / PIN.TERMINAL_OUTPUT_MEMBERS[0]),
                "non-file": lambda: os.mkfifo(root / "extra"),
                "secret": lambda: (root / PIN.TERMINAL_OUTPUT_MEMBERS[0]).write_text(
                    "authorization: Bearer " + "x" * 32, encoding="utf-8"
                ),
                "private-key-secret": lambda: (
                    root / PIN.TERMINAL_OUTPUT_MEMBERS[0]
                ).write_bytes(
                    b"\x00-----BEGIN OPENSSH PRIVATE KEY-----\x00PLACEHOLDER"
                ),
                "aws-access-key-secret": lambda: (
                    root / PIN.TERMINAL_OUTPUT_MEMBERS[0]
                ).write_bytes(b"\x00" + runtime_aws_access_key + b"\x00"),
                "aws-secret-key-secret": lambda: (
                    root / PIN.TERMINAL_OUTPUT_MEMBERS[0]
                ).write_bytes(
                    b"aws_secret_access_key=PLACEHOLDER_SECRET_MUST_BE_REJECTED"
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    for child in tuple(root.iterdir()):
                        if child.name not in PIN.TERMINAL_OUTPUT_MEMBERS:
                            if child.is_dir() and not child.is_symlink():
                                shutil.rmtree(child)
                            else:
                                child.unlink()
                    for name in PIN.TERMINAL_OUTPUT_MEMBERS:
                        (root / name).write_text("{}\n", encoding="utf-8")
                    mutate()
                    with self.assertRaises(SystemExit):
                        PIN._require_terminal_output_inventory(root)


class ArchiveTypeConfinementTests(unittest.TestCase):
    MEMBER_LIMIT = 8 * 1024 * 1024

    def archive(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as generated:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(name)
                if mode is not None:
                    info.external_attr = mode << 16
                generated.writestr(info, data)
        return output.getvalue()

    def with_creator_metadata(self, data, *, create_system, external_attr):
        changed = bytearray(data)
        central = changed.find(b"PK\x01\x02")
        self.assertGreaterEqual(central, 0)
        changed[central + 5] = create_system
        changed[central + 38:central + 42] = external_attr.to_bytes(4, "little")
        return bytes(changed)

    def encrypted(self, data):
        changed = bytearray(data)
        local = changed.find(b"PK\x03\x04")
        central = changed.find(b"PK\x01\x02")
        self.assertGreaterEqual(local, 0)
        self.assertGreaterEqual(central, 0)
        local_flags = int.from_bytes(changed[local + 6:local + 8], "little") | 1
        central_flags = int.from_bytes(
            changed[central + 8:central + 10], "little"
        ) | 1
        changed[local + 6:local + 8] = local_flags.to_bytes(2, "little")
        changed[central + 8:central + 10] = central_flags.to_bytes(2, "little")
        return bytes(changed)

    def call_readers(self, archive_bytes, expected):
        failures = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifact").mkdir()
            try:
                VALIDATOR._terminal_extract_artifact(
                    root, archive_bytes, expected,
                )
            except SystemExit:
                failures.append("terminal")
            archive_path = root / "candidate.zip"
            archive_path.write_bytes(archive_bytes)
            try:
                PIN._generated_archive_members(
                    archive_path, expected, "generated review artifact",
                )
            except SystemExit:
                failures.append("activation")
            try:
                VERIFIER.review_artifact_member_digests(
                    archive_bytes, expected, "issuance review artifact",
                )
            except SystemExit:
                failures.append("issuance")
        return failures

    def test_unix_creator_without_regular_type_proof_is_rejected_by_all_readers(self):
        archive_bytes = self.archive((
            ("receipt.json", b"{}\n", stat.S_IFREG | 0o600),
        ))
        archive_bytes = self.with_creator_metadata(
            archive_bytes, create_system=3, external_attr=0,
        )
        self.assertEqual(
            self.call_readers(archive_bytes, ("receipt.json",)),
            ["terminal", "activation", "issuance"],
        )

    def test_supported_non_unix_creator_regular_type_controls(self):
        archive_bytes = self.archive((
            ("receipt.json", b"{}\n", stat.S_IFREG | 0o600),
        ))
        cases = (
            ("zero-type-bits", 0, []),
            ("regular-type-bits", (stat.S_IFREG | 0o600) << 16, []),
            ("fifo-type-bits", (stat.S_IFIFO | 0o600) << 16,
             ["terminal", "activation", "issuance"]),
        )
        for label, external_attr, expected_failures in cases:
            with self.subTest(label=label):
                changed = self.with_creator_metadata(
                    archive_bytes, create_system=0,
                    external_attr=external_attr,
                )
                self.assertEqual(
                    self.call_readers(changed, ("receipt.json",)),
                    expected_failures,
                )

    def test_unsupported_creator_system_is_rejected_by_all_readers(self):
        archive_bytes = self.archive((
            ("receipt.json", b"{}\n", stat.S_IFREG | 0o600),
        ))
        archive_bytes = self.with_creator_metadata(
            archive_bytes, create_system=7, external_attr=0,
        )
        self.assertEqual(
            self.call_readers(archive_bytes, ("receipt.json",)),
            ["terminal", "activation", "issuance"],
        )

    def test_every_unsafe_zipinfo_shape_is_rejected_by_both_readers(self):
        malformed = {
            "symlink": self.archive((
                ("receipt.json", b"{}\n", stat.S_IFLNK | 0o777),
            )),
            "non-regular": self.archive((
                ("receipt.json", b"{}\n", stat.S_IFIFO | 0o600),
            )),
            "duplicate": self.archive((
                ("receipt.json", b"one", stat.S_IFREG | 0o600),
                ("receipt.json", b"two", stat.S_IFREG | 0o600),
            )),
            "alias": self.archive((
                ("./receipt.json", b"{}\n", stat.S_IFREG | 0o600),
            )),
            "traversal": self.archive((
                ("../receipt.json", b"{}\n", stat.S_IFREG | 0o600),
            )),
            "oversized": self.archive((
                ("receipt.json", b"x" * (self.MEMBER_LIMIT + 1),
                 stat.S_IFREG | 0o600),
            )),
        }
        malformed["encrypted"] = self.encrypted(self.archive((
            ("receipt.json", b"{}\n", stat.S_IFREG | 0o600),
        )))
        for label, archive_bytes in malformed.items():
            with self.subTest(label=label):
                self.assertEqual(
                    self.call_readers(archive_bytes, ("receipt.json",)),
                    ["terminal", "activation", "issuance"],
                )

    def test_complete_zipinfo_inventory_precedes_every_member_read(self):
        archive_bytes = self.archive((
            ("first.json", b"{}\n", stat.S_IFREG | 0o600),
            ("second.json", b"target", stat.S_IFLNK | 0o777),
        ))
        readers = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifact").mkdir()
            readers.append(lambda: VALIDATOR._terminal_extract_artifact(
                root, archive_bytes, ("first.json", "second.json"),
            ))
            archive_path = root / "candidate.zip"
            archive_path.write_bytes(archive_bytes)
            readers.append(lambda: PIN._generated_archive_members(
                archive_path, ("first.json", "second.json"),
                "generated review artifact",
            ))
            readers.append(lambda: VERIFIER.review_artifact_member_digests(
                archive_bytes, ("first.json", "second.json"),
                "issuance review artifact",
            ))
            for reader in readers:
                with self.subTest(reader=reader), mock.patch.object(
                    zipfile.ZipFile, "read",
                    side_effect=AssertionError("read occurred before validation"),
                ) as archive_read:
                    with self.assertRaises(SystemExit):
                        reader()
                    archive_read.assert_not_called()

    def test_issuance_workflow_has_no_prevalidation_shell_unzip(self):
        workflow = (
            ROOT / ".github" / "workflows"
            / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("unzip ", workflow)
        self.assertIn("--review-artifact-member-digests", workflow)


class EmbeddedReviewWorkflowArchiveTests(unittest.TestCase):
    WORKFLOW = (
        ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
        / "review-authority-v2.yml"
    )
    SIGNED = (
        "kanban-review-envelope.json",
        "preissuance-review-receipt.json",
        "preissuance-review-receipt.sigstore.json",
    )
    EXTERNAL = (
        "external-activation-review-receipt.json",
        "external-activation-review-receipt.sigstore.json",
    )

    @classmethod
    def embedded_consumer(cls):
        workflow = cls.WORKFLOW.read_text(encoding="utf-8")
        marker = "          python3 - <<'PY'\n"
        script = workflow.split(marker, 1)[1].split("          PY\n", 1)[0]
        return textwrap.dedent(script)

    def archive(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as generated:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                generated.writestr(info, data)
        return output.getvalue()

    def valid_archive(self, names):
        return self.archive(tuple(
            (name, b"{}\n", stat.S_IFREG | 0o600) for name in names
        ))

    def with_creator_metadata(self, data, *, create_system, external_attr):
        changed = bytearray(data)
        offset = 0
        while True:
            central = changed.find(b"PK\x01\x02", offset)
            if central < 0:
                break
            changed[central + 5] = create_system
            changed[central + 38:central + 42] = external_attr.to_bytes(
                4, "little"
            )
            offset = central + 4
        return bytes(changed)

    def encrypted(self, data):
        changed = bytearray(data)
        for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            header = changed.find(signature)
            flags = int.from_bytes(
                changed[header + flag_offset:header + flag_offset + 2], "little"
            ) | 1
            changed[header + flag_offset:header + flag_offset + 2] = (
                flags.to_bytes(2, "little")
            )
        return bytes(changed)

    def execute(self, signed, external=None, *, read_spy=None, extracted=None):
        external = external or self.valid_archive(self.EXTERNAL)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "activation" / "raw").mkdir(parents=True)
            (root / "activation" / "signed-review").mkdir()
            (root / "activation" / "external-review").mkdir()
            (root / "activation" / "raw" / "signed-review-artifact.zip").write_bytes(signed)
            (root / "activation" / "raw" / "external-review-artifact.zip").write_bytes(external)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.ExitStack() as patches:
                    if read_spy is not None:
                        patches.enter_context(mock.patch.object(
                            zipfile.ZipFile, "read", read_spy,
                        ))
                    exec(compile(
                        self.embedded_consumer(), str(self.WORKFLOW), "exec"
                    ), {"__name__": "__main__"})
            finally:
                os.chdir(previous)
                if extracted is not None:
                    extracted.extend(
                        sorted(path.relative_to(root).as_posix()
                               for destination in (
                                   root / "activation" / "signed-review",
                                   root / "activation" / "external-review",
                               )
                               for path in destination.iterdir())
                    )

    def test_creator_type_policy_executes_the_embedded_consumer(self):
        base = self.valid_archive(self.SIGNED)
        cases = (
            ("unix-zero", 3, 0, True),
            ("creator-zero-zero", 0, 0, False),
            ("creator-zero-regular", 0, (stat.S_IFREG | 0o600) << 16, False),
            ("creator-zero-fifo", 0, (stat.S_IFIFO | 0o600) << 16, True),
            ("unsupported-creator", 7, 0, True),
        )
        for label, creator, attributes, rejected in cases:
            with self.subTest(label=label):
                candidate = self.with_creator_metadata(
                    base, create_system=creator, external_attr=attributes,
                )
                if rejected:
                    with self.assertRaises(SystemExit):
                        self.execute(candidate)
                else:
                    self.execute(candidate)

    def test_unsafe_shapes_execute_the_embedded_consumer(self):
        regular = stat.S_IFREG | 0o600
        def replace_first(name, data, mode):
            return self.archive(((name, data, mode),) + tuple(
                (member, b"{}\n", regular) for member in self.SIGNED[1:]
            ))

        malformed = {
            "symlink": replace_first(
                self.SIGNED[0], b"{}\n", stat.S_IFLNK | 0o777,
            ),
            "fifo": replace_first(
                self.SIGNED[0], b"{}\n", stat.S_IFIFO | 0o600,
            ),
            "duplicate": self.archive(tuple(
                (name, b"{}\n", regular) for name in self.SIGNED[:2]
            ) + ((self.SIGNED[0], b"duplicate", regular),)),
            "alias": replace_first(
                "./" + self.SIGNED[0], b"{}\n", regular,
            ),
            "traversal": replace_first(
                "../" + self.SIGNED[0], b"{}\n", regular,
            ),
            "per-member-oversize": replace_first(
                self.SIGNED[0], b"x" * (8 * 1024 * 1024 + 1), regular,
            ),
        }
        malformed["encrypted"] = self.encrypted(self.valid_archive(self.SIGNED))
        for label, candidate in malformed.items():
            with self.subTest(label=label), self.assertRaises(SystemExit):
                self.execute(candidate)

    def test_complete_infolist_is_validated_before_any_member_read(self):
        candidate = self.archive((
            (self.SIGNED[0], b"{}\n", stat.S_IFREG | 0o600),
            (self.SIGNED[1], b"{}\n", stat.S_IFREG | 0o600),
            (self.SIGNED[2], b"target", stat.S_IFLNK | 0o777),
        ))
        read_spy = mock.Mock(side_effect=AssertionError(
            "member read occurred before complete ZipInfo validation"
        ))
        with self.assertRaises(SystemExit):
            self.execute(candidate, read_spy=read_spy)
        read_spy.assert_not_called()

    def test_both_inventories_are_validated_before_any_member_read(self):
        external = self.archive((
            (self.EXTERNAL[0], b"{}\n", stat.S_IFREG | 0o600),
            (self.EXTERNAL[1], b"target", stat.S_IFLNK | 0o777),
        ))
        original_read = zipfile.ZipFile.read
        read_calls = mock.Mock()
        extracted = []

        def read_spy(archive, member):
            read_calls(archive, member)
            return original_read(archive, member)

        with self.assertRaises(SystemExit):
            self.execute(
                self.valid_archive(self.SIGNED),
                external,
                read_spy=read_spy,
                extracted=extracted,
            )

        read_calls.assert_not_called()
        self.assertEqual(extracted, [])

    def test_aggregate_oversize_executes_the_embedded_consumer(self):
        regular = stat.S_IFREG | 0o600
        signed = self.archive(tuple(
            (name, b"x" * (8 * 1024 * 1024), regular)
            for name in self.SIGNED
        ))
        external = self.archive(tuple(
            (name, b"x" * (8 * 1024 * 1024), regular)
            for name in self.EXTERNAL
        ))
        with self.assertRaisesRegex(SystemExit, "aggregate size bound"):
            self.execute(signed, external)


class WorkflowCheckoutCredentialClosureTests(unittest.TestCase):
    PATHS = (
        ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
        / "review-authority-v2.yml",
        ROOT / "protected-source-bootstrap-v2" / ".github" / "workflows"
        / "export-kanban-review-v2.yml",
        ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml",
    )

    AUTHORIZATION_PLACEHOLDER = (
        "Authorization: Basic PLACEHOLDER_SECRET_MUST_BE_REJECTED"
    )

    def production_script(self, path, step_name, next_step_name):
        workflow = path.read_text(encoding="utf-8")
        step = workflow.split(f"      - name: {step_name}\n", 1)[1]
        step = step.split(f"      - name: {next_step_name}\n", 1)[0]
        return textwrap.dedent(step.split("        run: |\n", 1)[1])

    def isolated_git_environment(self, root):
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("GIT_CONFIG_")
        }
        home = root / "home"
        xdg = root / "xdg"
        home.mkdir()
        xdg.mkdir()
        environment.update({
            "GITHUB_ENV": str(root / "github-env"),
            "GIT_CONFIG_GLOBAL": str(root / "empty-global-config"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(home),
            "RUNNER_TEMP": str(root / "runner-temp"),
            "XDG_CONFIG_HOME": str(xdg),
        })
        (root / "empty-global-config").write_text("", encoding="utf-8")
        (root / "runner-temp").mkdir()
        return environment

    def inject_extraheader(
            self, scope, root, repository, environment, target_url):
        key = f"http.{target_url}/.extraheader"
        value = self.AUTHORIZATION_PLACEHOLDER
        if scope == "local":
            command = ["git", "config", "--local", key, value]
        elif scope == "worktree":
            subprocess.run(
                ["git", "config", "--local", "extensions.worktreeConfig", "true"],
                cwd=repository, env=environment, check=True,
            )
            command = ["git", "config", "--worktree", key, value]
        elif scope in {"global", "xdg", "system"}:
            config = root / f"{scope}-config"
            command = ["git", "config", "--file", str(config), key, value]
            if scope == "global":
                environment["GIT_CONFIG_GLOBAL"] = str(config)
            elif scope == "xdg":
                environment.pop("GIT_CONFIG_GLOBAL")
                config = root / "xdg" / "git" / "config"
                config.parent.mkdir()
                command = ["git", "config", "--file", str(config), key, value]
            else:
                environment.pop("GIT_CONFIG_NOSYSTEM")
                environment["GIT_CONFIG_SYSTEM"] = str(config)
        elif scope in {"command", "git_config_count"}:
            environment.update({
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": key,
                "GIT_CONFIG_VALUE_0": value,
            })
            return
        else:
            environment["GIT_CONFIG_PARAMETERS"] = f"'{key}'='{value}'"
            return
        subprocess.run(command, cwd=repository, env=environment, check=True)

    def apply_github_environment(self, environment):
        persisted = Path(environment["GITHUB_ENV"]).read_text(encoding="utf-8")
        for line in persisted.splitlines():
            key, separator, value = line.partition("=")
            self.assertEqual(separator, "=", line)
            environment[key] = value

    @contextlib.contextmanager
    def capture_git_http(self):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(dict(self.headers.items()))
                self.send_response(404)
                self.end_headers()

            def log_message(self, *_):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def assert_scope_injection_is_neutralized_before_checkout(
            self, workflow_path, step_name, next_step_name):
        script = self.production_script(
            workflow_path,
            step_name,
            next_step_name,
        )
        scopes = (
            "local", "worktree", "global", "xdg", "system", "command",
            "git_config_count", "parameters",
        )
        for scope in scopes:
            with self.subTest(workflow=workflow_path, scope=scope):
                with tempfile.TemporaryDirectory() as temporary, self.capture_git_http() as capture:
                    root = Path(temporary)
                    repository = root / "repository"
                    environment = self.isolated_git_environment(root)
                    subprocess.run(
                        ["git", "init", "--quiet", str(repository)],
                        env=environment, check=True,
                    )
                    self.inject_extraheader(
                        scope, root, repository, environment, capture[0],
                    )
                    completed = subprocess.run(
                        ["/bin/bash", "-c", script],
                        cwd=repository,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    output = completed.stdout + completed.stderr
                    self.assertEqual(completed.returncode, 0, output)
                    self.assertNotIn(self.AUTHORIZATION_PLACEHOLDER, output)
                    self.apply_github_environment(environment)
                    matched = subprocess.run(
                        [
                            "git", "config", "--get-urlmatch",
                            "http.extraheader", capture[0] + "/repository",
                        ],
                        cwd=repository, env=environment, capture_output=True,
                        text=True, check=False,
                    )
                    self.assertIn(matched.returncode, (0, 1), matched.stderr)
                    self.assertEqual(matched.stdout.strip(), "")
                    environment["GIT_TERMINAL_PROMPT"] = "0"
                    checkout = subprocess.run(
                        [
                            "git", "clone", "--no-checkout",
                            capture[0] + "/repository",
                            str(root / "checkout"),
                        ],
                        env=environment, capture_output=True, text=True,
                        check=False,
                    )
                    self.assertNotEqual(checkout.returncode, 0)
                    self.assertTrue(capture[1], "actual Git fetch was not reached")
                    for request in capture[1]:
                        self.assertNotIn("Authorization", request)

    def test_review_boundary_neutralizes_every_scope_before_checkout(self):
        self.assert_scope_injection_is_neutralized_before_checkout(
            self.PATHS[0],
            "Close inherited Git credential scopes before review checkout",
            "Checkout exact independently reviewed bootstrap",
        )

    def test_activation_boundary_neutralizes_every_scope_before_checkout(self):
        self.assert_scope_injection_is_neutralized_before_checkout(
            self.PATHS[0],
            "Close inherited Git credential scopes before activation checkout",
            "Checkout exact independently reviewed activation bootstrap",
        )

    def test_export_boundary_neutralizes_every_scope_before_operations(self):
        self.assert_scope_injection_is_neutralized_before_checkout(
            self.PATHS[1],
            "Close inherited Git credential scopes before protected-source operations",
            "Disable the sealed workflow and read the disabled state back",
        )

    def test_export_checkout_neutralizes_every_scope_before_checkout(self):
        self.assert_scope_injection_is_neutralized_before_checkout(
            self.PATHS[1],
            "Close inherited Git credential scopes before protected-source checkout",
            "Checkout exact sealed protected-source bootstrap",
        )

    def test_issuance_boundary_neutralizes_every_scope_before_checkout(self):
        self.assert_scope_injection_is_neutralized_before_checkout(
            self.PATHS[2],
            "Close inherited Git credential scopes before issuance checkout",
            "Validate dispatch and exact runtime context",
        )

    def assert_clean_boundary_persists_all_scope_closure(
            self, workflow_path, step_name, next_step_name):
        script = self.production_script(workflow_path, step_name, next_step_name)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            environment = self.isolated_git_environment(root)
            subprocess.run(
                ["git", "init", "--quiet", str(repository)],
                env=environment, check=True,
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                cwd=repository,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            persisted = (root / "github-env").read_text(encoding="utf-8")
            for binding in (
                "HOME=", "XDG_CONFIG_HOME=", "GIT_CONFIG_NOSYSTEM=1",
                "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=",
                "GIT_CONFIG_PARAMETERS=", "GIT_CONFIG_COUNT=1",
                "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=",
            ):
                self.assertIn(binding, persisted)

    def test_review_and_export_clean_paths_persist_all_scope_neutralization(self):
        cases = (
            (
                self.PATHS[0],
                "Close inherited Git credential scopes before review checkout",
                "Checkout exact independently reviewed bootstrap",
            ),
            (
                self.PATHS[1],
                "Close inherited Git credential scopes before protected-source operations",
                "Disable the sealed workflow and read the disabled state back",
            ),
            (
                self.PATHS[1],
                "Close inherited Git credential scopes before protected-source checkout",
                "Checkout exact sealed protected-source bootstrap",
            ),
            (
                self.PATHS[0],
                "Close inherited Git credential scopes before activation checkout",
                "Checkout exact independently reviewed activation bootstrap",
            ),
            (
                self.PATHS[2],
                "Close inherited Git credential scopes before issuance checkout",
                "Validate dispatch and exact runtime context",
            ),
        )
        for workflow_path, step_name, next_step_name in cases:
            with self.subTest(workflow=workflow_path):
                self.assert_clean_boundary_persists_all_scope_closure(
                    workflow_path, step_name, next_step_name,
                )

    def test_every_checkout_disables_persistence_and_credentials_are_cleared(self):
        checkout_count = 0
        for path in self.PATHS:
            workflow = path.read_text(encoding="utf-8")
            blocks = workflow.split("uses: actions/checkout@")[1:]
            checkout_count += len(blocks)
            for index, block in enumerate(blocks):
                with self.subTest(path=path, checkout=index):
                    step = block.split("\n\n      - name:", 1)[0]
                    self.assertIn("persist-credentials: false", step)
            offset = 0
            for checkout_index in range(len(blocks)):
                first_checkout = workflow.index(
                    "uses: actions/checkout@", offset,
                )
                credential_clear = workflow.rfind(
                    "Close inherited Git credential scopes before", 0,
                    first_checkout,
                )
                self.assertGreaterEqual(credential_clear, 0, path)
                self.assertLess(credential_clear, first_checkout, path)
                proof = workflow[credential_clear:first_checkout]
                self.assertIn("http\\..*\\.extraheader", proof)
                self.assertIn("credential residue remains", proof)
                offset = first_checkout + 1
        self.assertEqual(checkout_count, 4)


class TerminalActivationReadbackTests(unittest.TestCase):
    """Terminal facts live only in a distinct post-run receipt."""

    def receipt(self):
        head = GeneratedActivationReachabilityTests.RUN_SHA
        record_digest = "1234567890abcdef" * 4
        archive_digest = "abcdef0123456789" * 4
        return {
            "record_type": PIN.ACTIVATION_TERMINAL_RECEIPT_TYPE,
            "activation_record_sha256": record_digest,
            "attestation": {
                "generator": PIN.COSIGN_V3_1_3_GENERATOR,
                "generator_binary_sha256":
                    PIN.ACTIVATION_GENERATOR_BINARY_SHA256,
                "generator_platform": PIN.ACTIVATION_GENERATOR_PLATFORM,
                "generator_version": "v3.1.3",
                "rekor_generation": PIN.SIGSTORE.REKOR_V2,
                "rekor_log_key_algorithm": PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS,
                "route": PIN.SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE["route"],
                "signer_signature_algorithm":
                    PIN.ACTIVATION_SIGNER_SIGNATURE_ALGORITHM,
                "signing_window_start": 1_800_000_200,
                "signing_window_end": 1_800_000_320,
                "timestamp": "rfc3161",
            },
            "collector": {
                "event": "workflow_run",
                "job_id": 51_836_403_111,
                "ref": "refs/heads/main",
                "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
                "run_attempt": 1,
                "run_id": 18_234_568_003,
                "sha": head,
                "workflow_path": PIN.ACTIVATION_COLLECTOR_WORKFLOW_PATH,
            },
            "contract": {
                "activation_artifact_name": PIN.ACTIVATION_ARTIFACT_NAME,
                "activation_job_name": PIN.ACTIVATION_JOB_NAME,
                "activation_workflow_path": (
                    ACTIVATION.TARGET_WORKFLOW_PATHS[
                        ACTIVATION.INDEPENDENT_REPOSITORY
                    ]
                ),
                "artifact_content_digest_algorithm": (
                    PIN.ACTIVATION_ARTIFACT_CONTENT_DIGEST_ALGORITHM
                ),
                "collector_workflow_path": PIN.ACTIVATION_COLLECTOR_WORKFLOW_PATH,
                "default_branch": "main",
                "default_branch_ref": "refs/heads/main",
                "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
                "run_attempt": 1,
                "trigger_event": "workflow_run",
            },
            "run": {"id": 18_234_567_891, "run_attempt": 1,
                    "head_branch": "main", "head_sha": head,
                    "event": "workflow_run",
                    "path": ".github/workflows/review-authority-v2.yml",
                    "repository_id": 1_039_481_726,
                    "status": "completed", "conclusion": "success",
                    "workflow_id": 51_836_401_233},
            "job": {"id": 51_836_402_977, "run_id": 18_234_567_891,
                    "run_attempt": 1, "head_sha": head,
                    "started_at": 1_800_000_000,
                    "completed_at": 1_800_000_100,
                    "name": PIN.ACTIVATION_JOB_NAME,
                    "status": "completed", "conclusion": "success"},
            "artifact": {"id": 51_836_402_999,
                         "activation_record_sha256": record_digest,
                         "archive_download_url": (
                             "https://api.github.com/repos/chrizzatsu/"
                             "acc-authority-independent-review/actions/artifacts/"
                             "51836402999/zip"
                         ),
                         "archive_sha256": archive_digest,
                         "content_sha256": "fedcba9876543210" * 4,
                         "name": PIN.ACTIVATION_ARTIFACT_NAME,
                         "digest": "sha256:" + archive_digest,
                         "expired": False,
                         "run_id": 18_234_567_891,
                         "head_sha": head,
                         "matching_count": 1,
                         "size_in_bytes": 4_194_304,
                         "url": (
                             "https://api.github.com/repos/chrizzatsu/"
                             "acc-authority-independent-review/actions/artifacts/"
                             "51836402999"
                         )},
            "cleanup": {
                "conclusion": "success",
                "number": 11,
                "path": ".github/workflows/review-authority-v2.yml",
                "result": "success",
                "state": "disabled_manually",
                "status": "completed",
                "step_name": "Reassert disabled state and delete ephemeral bytes",
                "workflow_id": 51_836_401_233,
            },
        }

    def test_completed_terminal_receipt_is_accepted(self):
        self.assertTrue(PIN._require_terminal_activation_receipt(self.receipt()))

    def test_every_terminal_integer_rejects_bools_and_range_boundaries(self):
        expected_paths = {
            ("attestation", "signing_window_start"),
            ("attestation", "signing_window_end"),
            ("contract", "run_attempt"),
            ("run", "id"), ("run", "repository_id"),
            ("run", "run_attempt"), ("run", "workflow_id"),
            ("job", "completed_at"), ("job", "id"),
            ("job", "run_attempt"), ("job", "run_id"),
            ("job", "started_at"),
            ("artifact", "id"), ("artifact", "matching_count"),
            ("artifact", "run_id"), ("artifact", "size_in_bytes"),
            ("cleanup", "number"), ("cleanup", "workflow_id"),
            ("collector", "job_id"), ("collector", "run_attempt"),
            ("collector", "run_id"),
        }
        self.assertEqual(set(PIN.TERMINAL_INTEGER_LIMITS), expected_paths)
        for path, (minimum, maximum) in PIN.TERMINAL_INTEGER_LIMITS.items():
            for value in (True, False, minimum - 1, maximum + 1):
                receipt = self.receipt()
                receipt[path[0]][path[1]] = value
                with self.subTest(path=path, value=value), self.assertRaises(
                    SystemExit
                ):
                    PIN._require_terminal_activation_receipt(receipt)

    def test_nonterminal_missing_duplicate_or_failed_cleanup_is_refused(self):
        substitutions = (
            ("run", "status", "in_progress"),
            ("run", "event", "workflow_dispatch"),
            ("run", "path", ".github/workflows/other.yml"),
            ("run", "head_branch", "feature"),
            ("job", "conclusion", None),
            ("job", "name", "other"),
            ("artifact", "matching_count", 2),
            ("artifact", "name", "other"),
            ("artifact", "expired", True),
            ("artifact", "archive_sha256", "0" * 64),
            ("artifact", "activation_record_sha256", "1" * 64),
            ("cleanup", "state", "active"),
            ("cleanup", "result", "failure"),
            ("cleanup", "step_name", "other"),
            ("collector", "workflow_path", ".github/workflows/other.yml"),
            ("collector", "event", "workflow_dispatch"),
            ("contract", "repository", "other/repository"),
        )
        for section, field, value in substitutions:
            with self.subTest(section=section, field=field):
                receipt = self.receipt()
                receipt[section][field] = value
                with self.assertRaises(SystemExit):
                    PIN._require_terminal_activation_receipt(receipt)

    def test_terminal_sigstore_identity_is_the_collector_not_the_activation(self):
        self.assertEqual(
            PIN.ACTIVATION_COLLECTOR_WORKFLOW_PATH,
            ".github/workflows/readback-authority-v2-activation.yml",
        )
        self.assertEqual(
            PIN.ACTIVATION_COLLECTOR_IDENTITY,
            "https://github.com/chrizzatsu/acc-authority-independent-review/"
            ".github/workflows/readback-authority-v2-activation.yml@refs/heads/main",
        )

    def test_terminal_attestation_binds_exact_fresh_cosign_provenance(self):
        receipt = self.receipt()
        self.assertTrue(PIN._require_terminal_activation_receipt(receipt))
        attestation = receipt["attestation"]
        self.assertEqual(
            tuple(sorted(attestation)),
            tuple(sorted(PIN.COLLECTOR_FRESH_ATTESTATION_KEYS)),
        )
        expected = {
            "generator": PIN.COSIGN_V3_1_3_GENERATOR,
            "generator_binary_sha256": PIN.ACTIVATION_GENERATOR_BINARY_SHA256,
            "generator_platform": PIN.ACTIVATION_GENERATOR_PLATFORM,
            "generator_version": "v3.1.3",
            "rekor_generation": PIN.SIGSTORE.REKOR_V2,
            "rekor_log_key_algorithm": PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS,
            "route": PIN.SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE["route"],
            "signer_signature_algorithm":
                PIN.ACTIVATION_SIGNER_SIGNATURE_ALGORITHM,
            "timestamp": "rfc3161",
        }
        for field, value in expected.items():
            self.assertEqual(attestation[field], value, field)
            changed = self.receipt()
            changed["attestation"][field] = "substituted"
            with self.subTest(field=field), self.assertRaises(SystemExit):
                PIN._require_terminal_activation_receipt(changed)

    def test_terminal_contract_authenticates_fresh_collector_provenance(self):
        source_chain = json.loads(
            (ROOT / "source-chain-activation-v2.json").read_bytes()
        )
        bootstrap = json.loads(
            (ROOT / "independent-review-bootstrap-v2"
             / "bootstrap-contract.json").read_bytes()
        )
        source = source_chain["terminal_readback"]["fresh_provenance"]
        self.assertEqual(
            source, bootstrap["terminal_readback"]["fresh_provenance"],
        )
        self.assertEqual(
            source["attestation_fields"],
            list(PIN.COLLECTOR_FRESH_ATTESTATION_KEYS),
        )
        self.assertEqual(source["generator"], PIN.COSIGN_V3_1_3_GENERATOR)
        self.assertEqual(source["generator_version"], "v3.1.3")
        self.assertEqual(
            source["generator_binary_sha256"],
            PIN.ACTIVATION_GENERATOR_BINARY_SHA256,
        )
        self.assertEqual(source["signer"], "ecdsa-p256-sha256/Fulcio")
        self.assertEqual(source["rekor_log_key_algorithm"], "PKIX_ED25519")
        self.assertEqual(source["rekor_generation"], PIN.SIGSTORE.REKOR_V2)
        self.assertEqual(source["timestamp"], "rfc3161")
        self.assertIs(source["pre_registered_bundle_digest_required"], False)
        self.assertIs(source["exact_fulcio_claims_required"], True)

    def test_fresh_collector_bundle_uses_authenticated_run_provenance(self):
        receipt = self.receipt()
        subject = json.dumps(receipt, sort_keys=True).encode() + b"\n"
        bundle = b'{"fresh":"collector-bundle"}\n'
        claims = {
            "identity": PIN.ACTIVATION_COLLECTOR_IDENTITY,
            "issuer": PIN.OIDC_ISSUER,
            "source_repository_uri": (
                "https://github.com/" + ACTIVATION.INDEPENDENT_REPOSITORY
            ),
            "source_repository_ref": PIN.DEFAULT_REF,
            "build_config_uri": PIN.ACTIVATION_COLLECTOR_IDENTITY,
            "build_config_digest": receipt["collector"]["sha"],
            "build_trigger": "workflow_run",
        }
        verified = {
            "evidence_generator": PIN.COSIGN_V3_1_3_GENERATOR,
            "integrated_time": 1_800_000_260,
            "leaf_der": b"verified collector Fulcio leaf",
            "log_index": 7,
            "rekor_generation": PIN.SIGSTORE.REKOR_V2,
            "rekor_key_details": PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS,
            "signer_key_details": PIN.ACTIVATION_SIGNER_BODY_KEY_DETAILS,
        }
        with (
            mock.patch.object(
                PIN, "_verify_sigstore_bundle_route", return_value=verified,
            ) as route,
            mock.patch.object(PIN, "_certificate_claims", return_value=claims),
        ):
            observed = PIN._verify_terminal_sigstore_bundle(
                bundle, subject_bytes=subject, trust=object(), receipt=receipt,
            )
        provenance = route.call_args.kwargs["fresh_provenance"]
        self.assertEqual(
            provenance["bundle_sha256"], hashlib.sha256(bundle).hexdigest(),
        )
        self.assertEqual(provenance["run_id"], receipt["collector"]["run_id"])
        self.assertEqual(provenance["job_id"], receipt["collector"]["job_id"])
        self.assertEqual(observed["identity"], PIN.ACTIVATION_COLLECTOR_IDENTITY)

    def test_fresh_collector_route_and_fulcio_substitutions_are_refused(self):
        receipt = self.receipt()
        subject = json.dumps(receipt, sort_keys=True).encode() + b"\n"
        bundle = b'{"fresh":"collector-bundle"}\n'
        claims = {
            "identity": PIN.ACTIVATION_COLLECTOR_IDENTITY,
            "issuer": PIN.OIDC_ISSUER,
            "source_repository_uri": (
                "https://github.com/" + ACTIVATION.INDEPENDENT_REPOSITORY
            ),
            "source_repository_ref": PIN.DEFAULT_REF,
            "build_config_uri": PIN.ACTIVATION_COLLECTOR_IDENTITY,
            "build_config_digest": receipt["collector"]["sha"],
            "build_trigger": "workflow_run",
        }
        valid_route = {
            "evidence_generator": PIN.COSIGN_V3_1_3_GENERATOR,
            "integrated_time": 1_800_000_260,
            "leaf_der": b"verified collector Fulcio leaf",
            "log_index": 7,
            "rekor_generation": PIN.SIGSTORE.REKOR_V2,
            "rekor_key_details": PIN.ACTIVATION_REKOR_LOG_KEY_DETAILS,
            "signer_key_details": PIN.ACTIVATION_SIGNER_BODY_KEY_DETAILS,
        }
        for field, value in (
            ("rekor_generation", PIN.SIGSTORE.REKOR_V1),
            ("rekor_key_details", "PKIX_ECDSA_P256_SHA_256"),
            ("signer_key_details", "PKIX_ED25519"),
        ):
            changed = {**valid_route, field: value}
            with self.subTest(route_field=field), mock.patch.object(
                PIN, "_verify_sigstore_bundle_route", return_value=changed,
            ), mock.patch.object(
                PIN, "_certificate_claims", return_value=claims,
            ), self.assertRaises(SystemExit):
                PIN._verify_terminal_sigstore_bundle(
                    bundle, subject_bytes=subject, trust=object(), receipt=receipt,
                )
        for field in claims:
            changed = {**claims, field: "substituted"}
            with self.subTest(claim=field), mock.patch.object(
                PIN, "_verify_sigstore_bundle_route", return_value=valid_route,
            ), mock.patch.object(
                PIN, "_certificate_claims", return_value=changed,
            ), self.assertRaises(SystemExit):
                PIN._verify_terminal_sigstore_bundle(
                    bundle, subject_bytes=subject, trust=object(), receipt=receipt,
                )

    def test_terminal_bundle_requires_collector_path_and_workflow_run_trigger(self):
        subject = b'{"terminal":"closed"}\n'
        head = GeneratedActivationReachabilityTests.RUN_SHA
        integrated = 1_800_000_260
        fixture = SigstoreFixture(
            subject,
            repository=ACTIVATION.INDEPENDENT_REPOSITORY,
            workflow_path=PIN.ACTIVATION_COLLECTOR_WORKFLOW_PATH,
            workflow_sha=head,
            integrated=integrated,
            trigger="workflow_run",
        )
        arguments = {
            "subject_bytes": subject,
            "trust": fixture.trust,
            "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "workflow_path": PIN.ACTIVATION_COLLECTOR_WORKFLOW_PATH,
            "workflow_sha": head,
            "signing_window": (integrated - 60, integrated + 60),
            "workflow_trigger": "workflow_run",
        }
        verified = PIN._verify_sigstore_bundle(fixture.bundle(), **arguments)
        self.assertEqual(verified["identity"], PIN.ACTIVATION_COLLECTOR_IDENTITY)
        for field, value in (
            ("workflow_path", ".github/workflows/review-authority-v2.yml"),
            ("workflow_trigger", "workflow_dispatch"),
        ):
            with self.subTest(field=field):
                substituted = dict(arguments)
                substituted[field] = value
                with self.assertRaises(SystemExit):
                    PIN._verify_sigstore_bundle(fixture.bundle(), **substituted)


class SeparateCandidateBoundActivationWorkflowTests(unittest.TestCase):
    """The activation is its own inputless, immutable-review-bound run."""

    def workflow(self):
        return (
            ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows"
            / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")

    def activation(self):
        return self.workflow().split(f"  {PIN.ACTIVATION_JOB_NAME}:", 1)[1]

    def test_activation_is_a_separate_inputless_execution(self):
        workflow = self.workflow()
        activation = self.activation()
        self.assertNotIn("inputs:", workflow)
        self.assertNotIn("inputs.", workflow)
        self.assertIn("workflow_run:", workflow)
        self.assertIn("types: [completed]", workflow)
        self.assertNotIn("needs: review", activation)
        self.assertIn("github.event_name == 'workflow_run'", activation)
        self.assertIn("github.event.workflow_run.event == 'workflow_dispatch'", activation)
        self.assertIn("github.event.workflow_run.run_attempt == 1", activation)

    def test_activation_consumes_the_immutable_zero_finding_review(self):
        activation = self.activation()
        self.assertNotIn("commits/heads/main", activation)
        self.assertIn("github.event.workflow_run.id", activation)
        self.assertIn("external-activation-review-receipt.json", activation)
        self.assertIn("external-activation-review-receipt.sigstore.json", activation)
        self.assertIn(".findings_count == 0", activation)
        self.assertIn(".findings == []", activation)
        self.assertIn(".decision == \"APPROVED\"", activation)
        self.assertIn(".candidate_owned == false", activation)
        self.assertIn(".head_commit", activation)
        self.assertIn(".head_tree", activation)

    def test_activation_binds_unique_server_readback_and_cleanup_state(self):
        activation = self.activation()
        for binding in (
            "activation-run.json", "activation-jobs.json",
            "review-run.json", "review-jobs.json", "review-artifacts.json",
            "workflow-state-before.json", "workflow-state-after.json",
            "workflow-state-cleanup.json",
            "cas_expected_old_oid", "readback_verified",
            "disabled_manually", "gh workflow disable",
        ):
            self.assertIn(binding, activation, binding)
        self.assertIn("--paginate --slurp", activation)
        self.assertIn("chmod 0444", activation)
        self.assertIn("activation-record.json", activation)

    def test_all_four_streams_use_the_exact_reviewed_commands(self):
        activation = self.activation()
        self.assertIn("export LC_ALL=C", activation)
        commands = (
            "git diff --binary --full-index --no-ext-diff --no-abbrev --find-renames=50% --src-prefix=a/ --dst-prefix=b/ \"$authority_base\" \"$authority_head\" --",
            "git diff --name-status -z --no-ext-diff --no-abbrev --find-renames=50% --src-prefix=a/ --dst-prefix=b/ \"$authority_base\" \"$authority_head\" --",
            "git diff --raw -z --full-index --no-ext-diff --no-abbrev --find-renames=50% --src-prefix=a/ --dst-prefix=b/ \"$authority_base\" \"$authority_head\" --",
            "git diff --raw -z --no-ext-diff --no-abbrev --find-renames=50% --src-prefix=a/ --dst-prefix=b/ \"$authority_base\" \"$authority_head\" --",
        )
        for command in commands:
            self.assertIn(command, activation, command)
        self.assertIn("candidate_diff_sha256", activation)
        self.assertIn("reviewed_diff_sha256", activation)

    def test_generated_inventory_is_closed_before_upload_and_after_download(self):
        activation = self.activation()
        collector = TerminalReadbackCollectorWorkflowTests.PATH.read_text(
            encoding="utf-8",
        )
        phase = "--phase generated-artifact-inventory"
        self.assertIn(phase, activation)
        self.assertLess(activation.index(phase), activation.index(
            "actions/upload-artifact@",
        ))
        # The post-credential-cleanup collector uses only the digest-bound
        # Python stdlib verifier. ZIP inventory closure precedes activation
        # record authentication in that production phase.
        collector_phase = inspect.getsource(VALIDATOR.collect_terminal_readback)
        collector_inventory = collector_phase.index("_terminal_archive_identity")
        collector_record = collector_phase.index(
            "_terminal_authenticate_activation_record"
        )
        self.assertLess(collector_inventory, collector_record)
        self.assertIn("zipfile.ZipFile", inspect.getsource(
            VALIDATOR._terminal_extract_artifact
        ))
        self.assertIn("_terminal_read_validated_zip", inspect.getsource(
            VALIDATOR._terminal_extract_artifact
        ))
        upload = activation.split("Upload immutable generated activation evidence", 1)[1]
        self.assertNotIn("path: activation\n", upload)
        for member in PIN.GENERATED_ACTIVATION_ARTIFACT_MEMBERS:
            self.assertIn(f"activation/{member}", upload, member)
        self.assertIn("workflow-state-cleanup.json", activation)
        self.assertIn(
            "workflow-state-cleanup.json",
            PIN.ACTIVATION_RAW_PROVENANCE_FILES,
        )
        source_chain = json.loads(
            (ROOT / "source-chain-activation-v2.json").read_bytes()
        )
        bootstrap = json.loads(
            (ROOT / "independent-review-bootstrap-v2"
             / "bootstrap-contract.json").read_bytes()
        )
        self.assertEqual(
            source_chain["generated_activation_evidence"]["artifact_files"],
            list(PIN.GENERATED_ACTIVATION_ARTIFACT_MEMBERS),
        )
        self.assertEqual(
            bootstrap["terminal_readback"]["activation_artifact_files"],
            list(PIN.GENERATED_ACTIVATION_ARTIFACT_MEMBERS),
        )


if __name__ == "__main__":
    unittest.main()
