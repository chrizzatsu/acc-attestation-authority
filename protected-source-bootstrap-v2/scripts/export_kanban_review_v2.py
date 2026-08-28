#!/usr/bin/env python3
"""Export one immutable protected Kanban Authority-v2 review with self-measured bytes.

This helper runs only inside the protected source repository. Only the
execution phase is selectable: every path it reads or writes is a constant
relative to this sealed checkout, and every run fact comes from the
authenticated GitHub Actions server environment rather than from an argument.

`--phase gate` is the fail-closed one-attempt gate the lane runs before any
protected action. `--phase export` re-runs that same gate and only then emits
the artifact.

It never accepts caller-supplied receipt or envelope bytes. It re-serialises
the exact sealed protected reviewer result, binds it to every byte this run
executed, and writes the artifact members exclusively, so a pre-planted file
can never be passed off as an export.

Before activation the sealed contract is `unavailable`, every live binding is
null and this helper fails closed. After activation it emits the exact
artifact/envelope/receipt chain the independent lane re-derives.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = "bootstrap-contract.json"
WORKFLOW_PATH = ".github/workflows/export-kanban-review-v2.yml"
HELPER_PATH = "scripts/export_kanban_review_v2.py"
OUTPUT_DIRECTORY = "protected-review"
ENVELOPE_NAME = "kanban-review-envelope.json"
RECEIPT_NAME = "preissuance-review-receipt.json"
# Documented authenticated Git commit projections the workflow fetches with the
# run's own credential. Constant paths: no caller may choose or substitute one.
AUTHENTICATED_DIRECTORY = "authenticated"
SOURCE_COMMIT_FILE = "authenticated/source-commit.json"
INDEPENDENT_COMMIT_FILE = "authenticated/independent-commit.json"
AUTHORITY_COMMIT_FILE = "authenticated/authority-commit.json"
AUTHORITY_CHECKOUT = "authenticated/authority-checkout"
AUTHORITY_REMOTES = (
    "https://github.com/chrizzatsu/acc-attestation-authority",
    "https://github.com/chrizzatsu/acc-attestation-authority.git",
    "git@github.com:chrizzatsu/acc-attestation-authority.git",
    "ssh://git@github.com/chrizzatsu/acc-attestation-authority.git",
)
# The exact critical artifacts the Authority verifier re-derives.
CRITICAL_ARTIFACT_PATHS = (
    "AUTHORITY-V2-SHA256SUMS",
    "authority-v2-policy.json",
    "protected-asset-receipt-v2.json",
    "reviewer-authorization-v2.json",
    "schemas/authority-v2-subject.schema.json",
)
CANDIDATE_FIELDS = (
    "artifact_sha256", "base_commit", "base_tree", "canonical_diff_sha256",
    "changed_path_manifest", "head_commit", "head_tree",
    "internal_manifest", "repository", "sole_parent",
)
INTERNAL_MANIFEST_PATH = "AUTHORITY-V2-SHA256SUMS"
CONTRACT_IDENTITY = "acc-authority-v2-protected-source-bootstrap"
# One activation, enforced rather than declared.
#
# `GITHUB_RUN_ATTEMPT == 1` only blocks reruns of one run: a second
# `workflow_dispatch` is a different run id that is also attempt 1, so attempt
# alone can never bound the activation. Two authenticated server facts do.
#
# First, the sealed workflow is disabled before any protected action runs, and
# that disable is read back from the server here rather than assumed, so while
# this run proceeds no further activation run id can come into existence.
# Second, the complete run inventory is read back through one exhaustive
# traversal that terminates only where the server itself stops advertising
# `rel="next"` -- never at a fixed page count, which silently truncated the
# inventory and hid any additional authorized run past the last captured page.
# `MAXIMUM_CAPTURED_PAGES` is a finite fail-closed bound on that traversal: it
# is an error to reach it, never a termination.
GITHUB_API_ROOT = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
API_VERSION_HEADER = "x-github-api-version-selected"
LINK_HEADER = "link"
SERVER_PAGE_STATUS = 200
RAW_DIRECTORY = f"{AUTHENTICATED_DIRECTORY}/raw"
RAW_RUNS_PREFIX = "runs"
RAW_WORKFLOW_STATE = "workflow-state"
RUNS_PER_PAGE = 100
MAXIMUM_CAPTURED_PAGES = 100
MAX_AUTHORIZED_RUN_SET = RUNS_PER_PAGE * MAXIMUM_CAPTURED_PAGES
# The one server state in which no additional activation run can be dispatched.
DISABLED_WORKFLOW_STATE = "disabled_manually"
RUN_SET_LABEL = "protected-source authorized activation run set"
WORKFLOW_STATE_LABEL = "protected-source authorized workflow disable readback"
GATE_PHASE = "gate"
EXPORT_PHASE = "export"
PHASES = (EXPORT_PHASE, GATE_PHASE)
BRANCH_REF_PREFIX = "refs/heads/"
ARTIFACT_DOMAIN = b"acc-authority-v2-protected-source-artifact\0"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
# `authorized_pending_evidence` is the immutable pre-activation authorization:
# the reviewed repository, workflow, helper and blob bindings plus attempt 1 are
# pinned, and every live identifier is derived from authenticated server state
# at runtime. It exists so the sealed bytes are executable without first
# knowing evidence that only running them can produce.
UNAVAILABLE = "unavailable"
AUTHORIZED_PENDING_EVIDENCE = "authorized_pending_evidence"
READY = "ready"
ACTIVATION_STATES = (AUTHORIZED_PENDING_EVIDENCE, READY, UNAVAILABLE)
AUTHORIZED_STATES = (AUTHORIZED_PENDING_EVIDENCE, READY)
RECEIPT_FIELDS = (
    "schema_version", "receipt_type", "reviewer_profile", "review_outcome",
    "approved", "findings_count", "findings", "release_authorized",
    "activation_authorized", "activation_findings", "candidate",
    "protected_identity_asset", "closure_matrix", "classifications",
    "source_execution_chain",
)
CHAIN_FIELDS = (
    "artifact_content_sha256", "authority_head_commit", "authority_head_tree",
    "authority_repository", "certificate_github_workflow_sha", "envelope_sha256",
    "independent_bootstrap_commit", "independent_bootstrap_tree",
    "independent_validator_sha256", "independent_workflow_sha256",
    "review_receipt_sha256", "reviewer_task_id", "run_attempt", "run_head_sha",
    "run_id", "source_bootstrap_commit", "source_bootstrap_tree",
    "source_helper_path", "source_helper_sha256", "source_repository",
    "source_workflow_path", "source_workflow_sha256",
)
SELF_REFERENTIAL_CHAIN_FIELDS = frozenset(
    {"artifact_content_sha256", "envelope_sha256", "review_receipt_sha256"}
)
RECEIPT_CHAIN_FIELDS = tuple(
    name for name in CHAIN_FIELDS if name not in SELF_REFERENTIAL_CHAIN_FIELDS
)
# Live identifiers only an executed run can produce. They are never read from a
# caller and never required to be pre-pinned before the run exists.
LIVE_DERIVED_FIELDS = (
    "authority_head_commit", "authority_head_tree",
    "independent_bootstrap_commit", "independent_bootstrap_tree",
    "source_bootstrap_commit", "source_bootstrap_tree",
)
BINDING_HEX40_FIELDS = LIVE_DERIVED_FIELDS
# Reviewed blob bindings: known before any run and pinned at review time.
BINDING_HEX64_FIELDS = (
    "independent_validator_sha256", "independent_workflow_sha256",
)
REVIEW_RESULT_PINNED_FIELDS = (
    "activation_authorized", "activation_findings", "approved",
    "classifications", "closure_matrix", "findings", "findings_count",
    "protected_identity_asset", "release_authorized", "review_outcome",
)
CLOSURE_KEYS = tuple(f"F{number}" for number in range(1, 13))
# F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE forces the final Authority decision.
# The strictly distinct activation-only decision is the only thing this chain
# may authorize, and it never implies final approval.
REVIEW_OUTCOME = "ACTIVATION_ONLY"
FINAL_APPROVED = False
FINAL_RELEASE_AUTHORIZED = False
CLOSED_CLOSURES = tuple(f"F{number}" for number in range(1, 12))
OPEN_CLOSURES = ("F12",)
# F8 asserts that the authenticated source chain really exists. Before one
# exact authorized attempt-1 run head, tree, artifact, envelope and receipt
# digest are deterministically pinned there is no live evidence at all, so F8
# is unknowable and must stay open beside F12. It may close only in a later
# fresh direct-child candidate whose `ready` bindings pin every live field.
LIVE_EVIDENCE_CLOSURE = "F8"
LIVE_EVIDENCE_FINDING = "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"
PREACTIVATION_OPEN_CLOSURES = (*OPEN_CLOSURES, LIVE_EVIDENCE_CLOSURE)
PREACTIVATION_CLOSED_CLOSURES = tuple(
    name for name in CLOSURE_KEYS if name not in PREACTIVATION_OPEN_CLOSURES
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
PREACTIVATION_MESSAGE = (
    "protected-source export requires an authenticated, environment-gated, "
    "non-caller-selectable immutable Kanban source for task {task}; the sealed "
    "bootstrap contract is still {state} and no activation is authorized. "
    "F8 remains open."
)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


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


def read_sealed_bytes(root, relative, label):
    path = Path(root) / relative
    require(path.is_file() and not path.is_symlink(), f"{label} is absent or unsafe")
    return path.read_bytes()


def measured_sha256(root, relative, label):
    return hashlib.sha256(read_sealed_bytes(root, relative, label)).hexdigest()


# ---------------------------------------------------------------------------
# Raw authenticated GitHub captures
#
# `gh api -i` writes the exact status line, header block and body of one
# authenticated read. The lane records every such read at a constant path and
# follows `rel="next"` until the server itself terminates the traversal. The
# page set consumed here is therefore the server's own, never a page count
# this helper or its workflow chose.
# ---------------------------------------------------------------------------
def parse_http_capture(data, label):
    """Split one raw `gh api -i` capture into status, headers and body."""
    require(type(data) is bytes and data, f"{label} capture is empty")
    normalised = data.replace(b"\r\n", b"\n")
    separator = normalised.find(b"\n\n")
    require(separator > 0, f"{label} capture carries no header block")
    head = normalised[:separator].decode("utf-8", "replace").split("\n")
    body = normalised[separator + 2:]
    match = re.fullmatch(r"HTTP/[0-9.]+ (\d{3})(?: .*)?", head[0].strip())
    require(match is not None, f"{label} capture has no HTTP status line")
    headers = {}
    for line in head[1:]:
        name, colon, value = line.partition(":")
        require(colon, f"{label} capture header line is malformed")
        name, value = name.strip().lower(), value.strip()
        # GitHub may repeat a header; keep every value, joined as sent.
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return {"status": int(match.group(1)), "headers": headers, "body": body}


def link_relations(headers, label):
    """Every `rel=` target the server advertised on this exact response."""
    raw = headers.get(LINK_HEADER)
    if raw is None:
        return {}
    relations = {}
    for element in raw.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"\s*', element)
        require(match is not None, f"{label} Link header element is unparsable")
        target, relation = match.group(1), match.group(2)
        require(
            relation not in relations,
            f'{label} Link header repeats rel="{relation}"',
        )
        relations[relation] = target
    return relations


def read_capture(root, name, label):
    """One authenticated capture, read from a constant path and never a caller."""
    capture = parse_http_capture(
        read_sealed_bytes(root, f"{RAW_DIRECTORY}/{name}.http", label), label,
    )
    require(
        capture["status"] == SERVER_PAGE_STATUS,
        f"{label} is not an authenticated HTTP {SERVER_PAGE_STATUS} read",
    )
    require(
        capture["headers"].get(API_VERSION_HEADER) == GITHUB_API_VERSION,
        f"{label} carries no exact GitHub API version provenance",
    )
    capture["json"] = closed_json(capture["body"], label)
    return capture


def captured_collection(root, prefix, endpoint, label):
    """An exhaustive traversal proved terminated by the server's own headers.

    Page one is the exact internally derived canonical endpoint. Every later
    page is precisely the target the previous page advertised as `rel="next"`,
    and the traversal ends only where the server advertises no next page at
    all. A missing capture, an omitted page, a page beyond the advertised
    termination, a substituted or foreign next target, a non-200 status and a
    traversal that reaches the finite bound all fail closed.
    """
    first = f"{endpoint}?per_page={RUNS_PER_PAGE}&page=1"
    pages = []
    number = 1
    while True:
        page_label = f"{label} page {number}"
        capture = read_capture(root, f"{prefix}-page-{number}", page_label)
        relations = link_relations(capture["headers"], page_label)
        for relation, target in relations.items():
            require(
                target.startswith(f"{endpoint}?"),
                f'{page_label} advertises a foreign rel="{relation}" target',
            )
        if number > 1:
            require(
                relations.get("prev") is not None
                and relations.get("first") == first,
                f"{page_label} does not link back to the traversal it belongs to",
            )
        pages.append(capture["json"])
        following = relations.get("next")
        if following is None:
            break
        require(
            number < MAXIMUM_CAPTURED_PAGES,
            f"{label} pagination exceeded the authenticated bound",
        )
        require(
            following == f"{endpoint}?per_page={RUNS_PER_PAGE}&page={number + 1}",
            f"{page_label} advertises a substituted next page",
        )
        number += 1
    # A page beyond the server-advertised termination is an unadvertised read.
    require(
        not (Path(root) / RAW_DIRECTORY / f"{prefix}-page-{number + 1}.http"
             ).exists(),
        f"{label} captured a page the server never advertised",
    )
    return pages


def workflow_endpoint(contract):
    """The canonical Actions endpoint of the one sealed workflow."""
    return (
        f'{GITHUB_API_ROOT}/repos/{contract["repository"]}/actions/workflows'
        f'/{PurePosixPath(contract["workflow"]["path"]).name}'
    )


def runs_endpoint(contract):
    """The canonical run-list endpoint of the one sealed workflow."""
    return f"{workflow_endpoint(contract)}/runs"


def artifact_content_sha256(members):
    digest = hashlib.sha256(ARTIFACT_DOMAIN)
    for name in sorted(members):
        encoded = name.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(members[name]).to_bytes(8, "big"))
        digest.update(members[name])
    return digest.hexdigest()


def authenticated_commit(root, relative, label):
    """One documented authenticated Git commit projection, read from a constant path."""
    payload = closed_json(read_sealed_bytes(root, relative, label), label)
    require(type(payload) is dict, f"{label} is malformed")
    sha = payload.get("sha")
    require(
        type(sha) is str and HEX40.fullmatch(sha) is not None,
        f"{label} commit SHA is absent or malformed",
    )
    tree = payload.get("tree")
    require(type(tree) is dict, f"{label} tree object is absent")
    tree_sha = tree.get("sha")
    require(
        type(tree_sha) is str and HEX40.fullmatch(tree_sha) is not None,
        f"{label} tree SHA is absent or malformed",
    )
    return sha, tree_sha


def authenticated_commits(root):
    """Every live commit/tree identifier, from authenticated server metadata only."""
    source_commit, source_tree = authenticated_commit(
        root, SOURCE_COMMIT_FILE, "authenticated protected-source commit",
    )
    independent_commit, independent_tree = authenticated_commit(
        root, INDEPENDENT_COMMIT_FILE, "authenticated independent bootstrap commit",
    )
    authority_commit, authority_tree = authenticated_commit(
        root, AUTHORITY_COMMIT_FILE, "authenticated Authority candidate commit",
    )
    return {
        "authority_head_commit": authority_commit,
        "authority_head_tree": authority_tree,
        "independent_bootstrap_commit": independent_commit,
        "independent_bootstrap_tree": independent_tree,
        "source_bootstrap_commit": source_commit,
        "source_bootstrap_tree": source_tree,
    }


# ---------------------------------------------------------------------------
# The complete Authority candidate binding, recomputed from the authenticated
# checkout the workflow materialised at a constant path. The Authority verifier
# accepts nothing less: repository, base, head, tree, sole parent, canonical
# binary full-index diff, the complete status-aware changed-path manifest with
# modes, object ids and rename semantics, the tracked internal manifest and the
# critical artifact digests.
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
    """Every changed path with its status, similarity, modes, oids and digests."""
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


def authority_candidate_binding(root, contract, commits):
    """The exact contract the production Authority verifier requires."""
    checkout = Path(root) / AUTHORITY_CHECKOUT
    require(
        checkout.is_dir() and not checkout.is_symlink(),
        "the authenticated Authority checkout is absent or unsafe",
    )
    binding = contract["authority_binding"]
    base = binding.get("authority_base_commit")
    base_tree = binding.get("authority_base_tree")
    require(
        type(base) is str and HEX40.fullmatch(base) is not None
        and type(base_tree) is str and HEX40.fullmatch(base_tree) is not None,
        "the sealed contract does not pin the reviewed Authority base",
    )
    remote = _git_text(checkout, "remote", "get-url", "origin")
    require(remote in AUTHORITY_REMOTES, "Authority checkout origin identity mismatch")
    require(
        _git(checkout, "status", "--porcelain=v1", "-z",
             "--untracked-files=all") == b"",
        "the authenticated Authority checkout is not exactly clean",
    )
    head = commits["authority_head_commit"]
    require(
        _git_text(checkout, "rev-parse", "HEAD") == head,
        "the authenticated Authority checkout is not at the authenticated head",
    )
    require(
        _git_text(checkout, "rev-parse", f"{head}^{{tree}}")
        == commits["authority_head_tree"],
        "the authenticated Authority checkout tree contradicts the server state",
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
    diff = _git(
        checkout, "diff", "--binary", "--full-index", "--no-ext-diff",
        "--no-abbrev", "--find-renames=50%", "--src-prefix=a/",
        "--dst-prefix=b/", base, head, "--",
    )
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
    candidate = {
        "repository": contract["authority_repository"],
        "base_commit": base,
        "base_tree": base_tree,
        "head_commit": head,
        "head_tree": commits["authority_head_tree"],
        "sole_parent": base,
        "canonical_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "changed_path_manifest": manifest,
        "internal_manifest": internal_text,
        "artifact_sha256": {
            path: hashlib.sha256(
                _git(checkout, "show", f"{head}:{path}")).hexdigest()
            for path in CRITICAL_ARTIFACT_PATHS
        },
    }
    require(
        tuple(sorted(candidate)) == CANDIDATE_FIELDS,
        "Authority candidate binding field set mismatch",
    )
    return candidate


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
    later page and a run set larger than the bound are all refused: the
    authorized run may only be chosen out of a provably complete set. The page
    count is the server's own -- never a fixed count that could truncate the
    inventory and hide an additional authorized run past the last page.
    """
    require(
        type(pages) is list and pages and len(pages) <= MAXIMUM_CAPTURED_PAGES,
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


def sole_authorized_run(runs, *, repository, workflow_path, trigger, head_branch,
                        head_sha, label):
    """Exactly one authorized attempt-1 run for the sealed workflow/ref/head."""
    matching = [
        entry for entry in runs
        if entry.get("path") == workflow_path
        and type(entry.get("head_repository")) is dict
        and entry["head_repository"].get("full_name") == repository
        and entry.get("event") == trigger
        and entry.get("head_branch") == head_branch
        and entry.get("head_sha") == head_sha
        and entry.get("run_attempt") == 1
    ]
    require(
        len(matching) == 1,
        f"{label} must hold exactly one authorized attempt-1 run for the sealed "
        f"workflow, ref and head, but holds {len(matching)}, so the authorized "
        "activation run is additional or ambiguous",
    )
    require(
        len(runs) == 1,
        f"{label} holds {len(runs)} runs of the sealed workflow, so the "
        "authorized activation run is additional or ambiguous",
    )
    return matching[0]


def disabled_workflow_readback(root, contract):
    """The authenticated proof that no further activation run can be created.

    The activation lane disables the sealed workflow before any protected
    action runs. This is that server readback, and it is what makes the
    one-attempt bound technical rather than procedural: while the workflow is
    `disabled_manually` no additional `workflow_dispatch` run id can come into
    existence behind this run's back. An enabled workflow, a workflow disabled
    for some other reason, a foreign workflow and an absent readback all fail
    closed.
    """
    payload = read_capture(root, RAW_WORKFLOW_STATE, WORKFLOW_STATE_LABEL)["json"]
    require(type(payload) is dict, f"{WORKFLOW_STATE_LABEL} is malformed")
    require(
        payload.get("path") == contract["workflow"]["path"],
        f"{WORKFLOW_STATE_LABEL} is not the sealed workflow",
    )
    require(
        payload.get("url") == workflow_endpoint(contract),
        f"{WORKFLOW_STATE_LABEL} payload does not carry its canonical endpoint",
    )
    identifier = payload.get("id")
    require(
        type(identifier) is int and type(identifier) is not bool
        and identifier > 0,
        f"{WORKFLOW_STATE_LABEL} workflow id is absent or malformed",
    )
    require(
        payload.get("state") == DISABLED_WORKFLOW_STATE,
        f"{WORKFLOW_STATE_LABEL} reports state {payload.get('state')!r} rather "
        f"than {DISABLED_WORKFLOW_STATE!r}, so an additional authorized "
        "activation run could still be dispatched",
    )
    return payload


def captured_workflow_run_pages(root, contract):
    """The one exhaustively captured workflow-run traversal, as page bodies.

    The gate and the export consume exactly this set, so the run the lane
    admits can never differ from the run the receipt binds.
    """
    return captured_collection(
        root, RAW_RUNS_PREFIX, runs_endpoint(contract), RUN_SET_LABEL,
    )


def authorized_activation_run(root, contract, metadata):
    """Fail closed unless this run is the only authorized activation run.

    `GITHUB_RUN_ATTEMPT == 1` cannot distinguish two sequential
    `workflow_dispatch` runs, because each of them is attempt 1. So the sealed
    workflow must already be disabled on the server, and the complete run set
    read back from the authenticated Actions server must contain exactly this
    one authorized run.
    """
    disabled_workflow_readback(root, contract)
    workflow = contract["workflow"]
    observed = sole_authorized_run(
        complete_workflow_run_set(
            captured_workflow_run_pages(root, contract), RUN_SET_LABEL,
        ),
        repository=contract["repository"],
        workflow_path=workflow["path"],
        trigger=workflow["trigger"],
        head_branch=sealed_head_branch(workflow["ref"], RUN_SET_LABEL),
        head_sha=metadata["run_head_sha"],
        label=RUN_SET_LABEL,
    )
    require(
        observed["id"] == metadata["run_id"],
        "the only authorized activation run is not this run",
    )
    return observed


def resolve_bindings(contract, commits, metadata):
    """Bind every live field from authenticated server state, never from a caller.

    A sealed value that is still null is supplied by the authenticated server
    state of this run. A sealed value that a later exact pinning already fixed
    must equal that same authenticated value, so pinning can never drift.
    """
    binding = contract["authority_binding"]
    resolved = {}
    for field in LIVE_DERIVED_FIELDS:
        derived = commits[field]
        sealed = binding.get(field)
        require(
            sealed is None or sealed == derived,
            f"sealed {field} contradicts the authenticated server state",
        )
        resolved[field] = derived
    require(
        resolved["source_bootstrap_commit"] == metadata["run_head_sha"],
        "authenticated source commit is not this run head",
    )
    for field in BINDING_HEX64_FIELDS:
        value = binding.get(field)
        require(
            type(value) is str and HEX64.fullmatch(value) is not None,
            f"reviewed blob binding {field} is unpinned",
        )
        resolved[field] = value
    return resolved


def run_metadata(environment, contract):
    """Every run fact comes from the authenticated Actions server environment."""
    run_id = environment.get("GITHUB_RUN_ID", "")
    run_attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    head_sha = environment.get("GITHUB_SHA", "")
    repository = environment.get("GITHUB_REPOSITORY", "")
    event = environment.get("GITHUB_EVENT_NAME", "")
    ref = environment.get("GITHUB_REF", "")
    workflow_ref = environment.get("GITHUB_WORKFLOW_REF", "")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None,
            "protected-source run id is absent")
    require(run_attempt == "1", "protected-source export requires run attempt 1")
    require(HEX40.fullmatch(head_sha) is not None, "protected-source run head is absent")
    require(repository == contract["repository"],
            "protected-source run repository is not the sealed repository")
    require(event == contract["workflow"]["trigger"],
            "protected-source run trigger is not the sealed trigger")
    require(ref == contract["workflow"]["ref"],
            "protected-source run ref is not the sealed ref")
    expected_workflow_ref = (
        f'{contract["repository"]}/{contract["workflow"]["path"]}'
        f'@{contract["workflow"]["ref"]}'
    )
    require(workflow_ref == expected_workflow_ref,
            "protected-source run workflow identity is not the sealed workflow")
    return {"run_id": int(run_id), "run_attempt": 1, "run_head_sha": head_sha}


def _validate_contract_state(contract, measurements):
    """Reject every internal state contradiction before anything is emitted."""
    require(
        contract.get("contract") == CONTRACT_IDENTITY,
        "protected-source bootstrap contract identity mismatch",
    )
    require(
        measurements["source_workflow_sha256"] == contract["workflow"]["sha256"]
        and measurements["source_helper_sha256"] == contract["helper"]["sha256"],
        "executed protected-source bytes differ from the sealed bootstrap",
    )
    binding = contract["authority_binding"]
    review = contract["protected_review_result"]
    state = binding.get("activation_state")
    require(state in ACTIVATION_STATES, "protected-source activation state is not modelled")
    require(
        review.get("activation_state") == state,
        "protected-source review result contradicts the activation state",
    )
    require(
        contract.get("repository_created") is (state == READY)
        and contract.get("workflow_dispatched") is (state == READY),
        "protected-source repository/dispatch posture contradicts the activation state",
    )
    require(
        binding.get("authorized_run_attempt") == 1
        and type(binding.get("authorized_run_attempt")) is int,
        "protected-source contract must authorize exactly attempt 1",
    )
    if state == UNAVAILABLE:
        for field in (*LIVE_DERIVED_FIELDS, *BINDING_HEX64_FIELDS):
            require(
                binding.get(field) is None,
                f"unavailable protected-source contract pins {field}",
            )
        for field in REVIEW_RESULT_PINNED_FIELDS:
            require(
                review.get(field) is None,
                f"unavailable protected-source contract pins review {field}",
            )
        return state
    if state == AUTHORIZED_PENDING_EVIDENCE:
        for field in LIVE_DERIVED_FIELDS:
            require(
                binding.get(field) is None,
                f"authorized protected-source contract pre-pins live evidence {field}",
            )
    else:
        for field in LIVE_DERIVED_FIELDS:
            value = binding.get(field)
            require(
                type(value) is str and HEX40.fullmatch(value) is not None,
                f"ready protected-source contract leaves {field} unpinned",
            )
    for field in BINDING_HEX64_FIELDS:
        value = binding.get(field)
        require(
            type(value) is str and HEX64.fullmatch(value) is not None,
            f"authorized protected-source contract leaves {field} unpinned",
        )
    _validate_review_decision(review, state)
    require(
        type(review.get("classifications")) is dict
        and type(review.get("protected_identity_asset")) is dict,
        "ready protected-source review result members are malformed",
    )
    return state


def validate_review_decision(review, state):
    """The only decision this sealed chain may carry at this activation state.

    Final Authority approval and release authorization stay false and closure
    F12 stays open, because no documented GitHub release API establishes the
    exclusive publication transition F12 would need. Closure F8 additionally
    stays open until the activation state is `ready`, so no receipt producible
    before deterministically pinned live evidence can ever claim an
    authenticated source chain. The strictly distinct activation-only decision
    may be authorized with zero activation findings, and it authorizes nothing
    beyond the exact acc-releaser activation.
    """
    closed_closures, open_closures = required_closures(state)
    require(type(review) is dict, "protected review result is malformed")
    require(
        review.get("review_outcome") == REVIEW_OUTCOME,
        "protected review outcome is not the activation-only decision",
    )
    require(
        review.get("approved") is FINAL_APPROVED
        and review.get("release_authorized") is FINAL_RELEASE_AUTHORIZED,
        "protected review result claims final Authority approval or release",
    )
    closure = review.get("closure_matrix")
    require(
        type(closure) is dict
        and tuple(sorted(closure)) == tuple(sorted(CLOSURE_KEYS))
        and all(type(value) is bool for value in closure.values()),
        "protected review closure matrix mismatch",
    )
    for name in closed_closures:
        require(closure[name] is True, f"protected review closure {name} is not closed")
    for name in open_closures:
        require(
            closure[name] is False,
            f"protected review closure {name} may not be closed at activation "
            f"state {state}",
        )
    findings = review.get("findings")
    require(
        type(findings) is list and findings,
        "protected review result must record its open closures as findings",
    )
    observed = []
    for entry in findings:
        require(
            type(entry) is dict and tuple(sorted(entry)) == FINDING_KEYS,
            "protected review finding is malformed",
        )
        require(
            type(entry["finding"]) is str and entry["finding"],
            "protected review finding text is absent",
        )
        observed.append(entry["closure"])
    require(
        sorted(observed) == sorted(name for name, value in closure.items() if not value),
        "protected review findings do not match the open closures exactly",
    )
    require(
        type(review.get("findings_count")) is int
        and type(review.get("findings_count")) is not bool
        and review["findings_count"] == len(findings),
        "protected review findings count mismatch",
    )
    if state == READY:
        require(
            review.get("activation_authorized") is True,
            "protected review result does not authorize the exact activation",
        )
        require(
            type(review.get("activation_findings")) is list
            and review["activation_findings"] == [],
            "protected review activation findings must be exactly zero",
        )
    else:
        require(
            review.get("activation_authorized") is False,
            "a pre-activation protected review may never authorize activation",
        )
        require(
            review.get("activation_findings") == [ACTIVATION_FINDING],
            "a pre-activation protected review must record the exact finding",
        )


_validate_review_decision = validate_review_decision


def build_chain(contract, measurements, metadata, resolved):
    return {
        "authority_head_commit": resolved["authority_head_commit"],
        "authority_head_tree": resolved["authority_head_tree"],
        "authority_repository": contract["authority_repository"],
        "certificate_github_workflow_sha": resolved["independent_bootstrap_commit"],
        "independent_bootstrap_commit": resolved["independent_bootstrap_commit"],
        "independent_bootstrap_tree": resolved["independent_bootstrap_tree"],
        "independent_validator_sha256": resolved["independent_validator_sha256"],
        "independent_workflow_sha256": resolved["independent_workflow_sha256"],
        "reviewer_task_id": contract["reviewer_task_id"],
        "run_attempt": metadata["run_attempt"],
        "run_head_sha": metadata["run_head_sha"],
        "run_id": metadata["run_id"],
        "source_bootstrap_commit": resolved["source_bootstrap_commit"],
        "source_bootstrap_tree": resolved["source_bootstrap_tree"],
        "source_helper_path": contract["helper"]["path"],
        "source_helper_sha256": measurements["source_helper_sha256"],
        "source_repository": contract["repository"],
        "source_workflow_path": contract["workflow"]["path"],
        "source_workflow_sha256": measurements["source_workflow_sha256"],
    }


def build(contract, measurements, metadata, root=ROOT):
    """Emit the exact receipt and envelope bytes, or fail closed pre-authorization.

    Authenticated server metadata is read only once the sealed contract proves
    the activation is authorized, so an unauthorized state always fails closed
    with the exact pre-activation reason.
    """
    authorized_state(contract, measurements)
    authorized_activation_run(root, contract, metadata)
    resolved = resolve_bindings(contract, authenticated_commits(root), metadata)
    binding = resolved
    chain = build_chain(contract, measurements, metadata, resolved)
    require(
        tuple(sorted(chain)) == tuple(sorted(RECEIPT_CHAIN_FIELDS)),
        "protected-source execution chain field set mismatch",
    )
    review = contract["protected_review_result"]
    receipt = {
        "schema_version": review["schema_version"],
        "receipt_type": review["receipt_type"],
        "reviewer_profile": review["reviewer_profile"],
        "review_outcome": review["review_outcome"],
        "approved": review["approved"],
        "findings_count": review["findings_count"],
        "findings": review["findings"],
        "release_authorized": review["release_authorized"],
        "activation_authorized": review["activation_authorized"],
        "activation_findings": review["activation_findings"],
        "candidate": authority_candidate_binding(root, contract, resolved),
        "protected_identity_asset": review["protected_identity_asset"],
        "closure_matrix": review["closure_matrix"],
        "classifications": review["classifications"],
        "source_execution_chain": chain,
    }
    require(
        tuple(sorted(receipt)) == tuple(sorted(RECEIPT_FIELDS)),
        "protected-source receipt field set mismatch",
    )
    receipt_bytes = canonical(receipt)
    envelope = {
        "schema_version": 2,
        "task_id": contract["reviewer_task_id"],
        "source_repository": contract["repository"],
        "source_workflow": contract["workflow"]["path"],
        "source_workflow_sha256": measurements["source_workflow_sha256"],
        "source_helper": contract["helper"]["path"],
        "source_helper_sha256": measurements["source_helper_sha256"],
        "source_run_id": metadata["run_id"],
        "source_run_attempt": metadata["run_attempt"],
        "source_run_head_sha": metadata["run_head_sha"],
        "artifact_name": contract["artifact"]["name"],
        "review_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "immutable": True,
    }
    return canonical(envelope), receipt_bytes


def write_exclusive(directory, name, data):
    """Write one artifact member exclusively; a pre-planted file fails closed."""
    path = Path(directory) / name
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise SystemExit(
            f"protected-source artifact member already exists or is unsafe: {name}"
        ) from error
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "protected-source artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def sealed_contract(root):
    contract = closed_json(
        read_sealed_bytes(root, CONTRACT_PATH, "protected-source bootstrap contract"),
        "protected-source bootstrap contract",
    )
    require(type(contract) is dict, "protected-source bootstrap contract is malformed")
    return contract


def sealed_measurements(root):
    return {
        "source_workflow_sha256": measured_sha256(
            root, WORKFLOW_PATH, "executed protected-source workflow",
        ),
        "source_helper_sha256": measured_sha256(
            root, HELPER_PATH, "executed protected-source helper",
        ),
    }


def authorized_state(contract, measurements):
    """The sealed activation state, or the exact pre-activation failure."""
    state = _validate_contract_state(contract, measurements)
    if state not in AUTHORIZED_STATES:
        raise SystemExit(
            PREACTIVATION_MESSAGE.format(
                task=contract["reviewer_task_id"], state=state,
            )
        )
    return state


def gate(environment, root=ROOT):
    """Exclude every additional activation run before any protected action.

    This is the whole one-attempt decision, taken before the lane clones the
    Authority candidate or writes a single artifact byte. It authenticates the
    sealed contract, requires the server readback that the sealed workflow is
    already disabled, and requires the complete captured run inventory to hold
    exactly this one authorized attempt-1 run. It reads nothing protected and
    writes nothing at all, so a failure here costs the activation nothing.
    """
    contract = sealed_contract(root)
    authorized_state(contract, sealed_measurements(root))
    observed = authorized_activation_run(
        root, contract, run_metadata(environment, contract),
    )
    return {
        "authorized_run_id": observed["id"],
        "gated": True,
        "workflow_state": DISABLED_WORKFLOW_STATE,
    }


def export(environment, root=ROOT):
    contract = sealed_contract(root)
    measurements = sealed_measurements(root)
    envelope_bytes, receipt_bytes = build(
        contract, measurements, run_metadata(environment, contract), root,
    )
    require(
        [ENVELOPE_NAME, RECEIPT_NAME] == sorted(contract["artifact"]["files"]),
        "protected-source artifact member inventory mismatch",
    )
    directory = Path(root) / OUTPUT_DIRECTORY
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        require(
            directory.is_dir() and not directory.is_symlink()
            and not any(directory.iterdir()),
            "protected-source output directory is not empty or is unsafe",
        )
    write_exclusive(directory, ENVELOPE_NAME, envelope_bytes)
    write_exclusive(directory, RECEIPT_NAME, receipt_bytes)
    return {
        "artifact_content_sha256": artifact_content_sha256({
            ENVELOPE_NAME: envelope_bytes, RECEIPT_NAME: receipt_bytes,
        }),
        "envelope_sha256": hashlib.sha256(envelope_bytes).hexdigest(),
        "exported": True,
        "review_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Export the sealed protected Kanban Authority-v2 review. "
                    "Only the execution phase is selectable; every path, run, "
                    "state and byte comes from the sealed contract, an "
                    "authenticated read or the Actions server environment.",
    )
    parser.add_argument("--phase", choices=PHASES, default=EXPORT_PHASE)
    arguments = parser.parse_args()
    if arguments.phase == GATE_PHASE:
        print(json.dumps(gate(os.environ), sort_keys=True))
        return
    print(json.dumps(export(os.environ), sort_keys=True))


if __name__ == "__main__":
    main()
