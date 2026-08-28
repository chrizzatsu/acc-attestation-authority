#!/usr/bin/env python3
"""Generate three canonical subjects bound to authenticated GitHub issuance."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

try:
    from scripts import collect_github_issuance_v2 as GITHUB_ISSUANCE
except ModuleNotFoundError:  # direct execution from the scripts directory
    import collect_github_issuance_v2 as GITHUB_ISSUANCE

ROOT = Path(__file__).resolve().parents[1]
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
EXACT_CASES = ("future", "in_window", "stale")
EXACT_REPOSITORY = "chrizzatsu/acc-attestation-authority"
EXACT_WORKFLOW_REF = "chrizzatsu/acc-attestation-authority/.github/workflows/sign-clerk-attestation-v2.yml@refs/heads/main"

# ---------------------------------------------------------------------------
# EVIDENCE-RUNNER-STATE-CONTRADICTS-CANDIDATE
#
# One internally consistent runner-state artifact, every field of which is
# derived from the exact immutable checkout rather than declared: the exact
# head, its tree, the commit count reachable from it and the terminal state of
# the round. A downstream receipt or manifest can then bind it without
# contradicting the candidate it describes.
# ---------------------------------------------------------------------------
RUNNER_STATE_ARTIFACT_TYPE = "acc-authority-v2-runner-state"
RUNNER_STATE_NAME = "authority-v2-runner-state.json"
RUNNER_STATE_KEYS = (
    "artifact_type", "base_commit", "commit_count", "consistent",
    "derived_closure_sha256", "head_commit", "head_tree", "recovery_round",
    "schema_version", "terminal_state",
)
RUNNER_STATE_BASE_KEY = "authority_repository_base"
RUNNER_TERMINAL_STATES = (
    "blocked_builder_failed", "changes_requested", "completed",
)
# The one non-terminal state a round may hold while the write-free F12
# publication gate is still running. It exists so the complete canonical
# release inventory can be verified *before* this round claims a completed
# terminal state, and it may never appear in a sealed final evidence set.
RUNNER_STAGING_STATE = "verification_pending"
RUNNER_STATES = (*RUNNER_TERMINAL_STATES, RUNNER_STAGING_STATE)

# ---------------------------------------------------------------------------
# F12-VERIFY-ONLY-CLI-AND-EVIDENCE-TERMINAL-BROKEN
#
# Nothing in a round may become terminal or immutable before the unchanged
# verify-only publication path has confirmed, over the complete canonical
# release inventory, the expected non-authorizing state: the deep plan
# verified with no blocker, `F12` still open and release authorization still
# false. The gate result names the exact bytes it verified, so the inventory
# that is made terminal and then sealed is provably the very inventory that
# was verified - byte for byte - and drift or a reordered run fails closed.
# ---------------------------------------------------------------------------
VERIFY_ONLY_GATE_KEYS = (
    "asset_digests", "assets_verified", "blocked_by",
    "canonical_inventory_sha256", "deep_plan_verified",
    "f12_closed", "inventory", "publication", "release_authorized",
    "release_evidence_verified", "state", "transports_constructed",
    "verify_only", "writes_performed",
)
VERIFY_ONLY_VERIFIED_STATE = "verified"
VERIFY_ONLY_PUBLICATION = "unavailable"

# ---------------------------------------------------------------------------
# EVIDENCE-ARTIFACTS-NOT-IMMUTABLY-SEALED
#
# Regenerated evidence is owner-writable until it is sealed. Sealing sets a
# 0555 directory and 0444 files, reads both modes back from the filesystem and
# recomputes every hash from the sealed bytes, so the recorded digests are the
# digests of the immutable artifacts rather than of what was intended.
# ---------------------------------------------------------------------------
SEALED_DIRECTORY_MODE = 0o555
FINAL_EVIDENCE_ARTIFACT_TYPE = "acc-authority-v2-final-evidence"
SEALED_FILE_MODE = 0o444


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def fingerprint(prefix, value):
    require(bool(value), "protected identity input is absent")
    return hashlib.sha256(prefix + value.encode("utf-8")).hexdigest()


def _reviewed_base_commit(repository_root):
    """The exact reviewed base this candidate must be a direct child of."""
    policy = json.loads(
        (Path(repository_root) / "authority-v2-policy.json").read_bytes()
    )
    base = policy[RUNNER_STATE_BASE_KEY]["commit"]
    require(
        type(base) is str and SHA40.fullmatch(base) is not None,
        "the reviewed Authority base commit is malformed",
    )
    return base


def _git_text(repository_root, *arguments):
    """Read one exact value from the immutable checkout, or fail closed."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository_root), *arguments],
            check=True, capture_output=True,
            env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(
            f"runner state read failed: {' '.join(arguments)}"
        ) from error
    return completed.stdout.decode("utf-8").strip()


def canonical_runner_state(state):
    return json.dumps(state, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def build_runner_state(*, repository_root, recovery_round, terminal_state,
                       base_commit=None, derived_closure_sha256=None):
    """Derive one internally consistent runner-state artifact from Git alone.

    The head, its tree and the reachable commit count are read from the exact
    immutable checkout, never taken from a caller, so the artifact can never
    contradict the candidate it describes.
    """
    require(
        type(recovery_round) is int and type(recovery_round) is not bool
        and recovery_round >= 0,
        "runner recovery round must be a non-negative integer",
    )
    require(
        terminal_state in RUNNER_STATES,
        "runner terminal state is not a modelled terminal state",
    )
    repository_root = Path(repository_root)
    head_commit = _git_text(repository_root, "rev-parse", "HEAD")
    require(
        SHA40.fullmatch(head_commit) is not None,
        "runner state head is not an exact object name",
    )
    head_tree = _git_text(repository_root, "rev-parse", "HEAD^{tree}")
    require(
        SHA40.fullmatch(head_tree) is not None,
        "runner state head tree is not an exact object name",
    )
    # The prescribed count is the exact candidate range, never the whole
    # history reachable from HEAD: a candidate is base..head and nothing else.
    base = base_commit if base_commit is not None else _reviewed_base_commit(
        repository_root,
    )
    require(
        SHA40.fullmatch(base) is not None,
        "runner state base commit is not an exact object name",
    )
    parents = _git_text(
        repository_root, "rev-list", "--parents", "-n", "1", head_commit,
    ).split()
    require(
        parents == [head_commit, base],
        "the runner state head is not an ordinary non-merge direct child of "
        "the reviewed base",
    )
    raw_count = _git_text(
        repository_root, "rev-list", "--count", f"{base}..{head_commit}",
    )
    require(
        re.fullmatch(r"[1-9][0-9]*", raw_count) is not None,
        "runner state candidate commit count is malformed",
    )
    commit_count = int(raw_count)
    # The three Git-derived facts must agree with one another, so a partially
    # rewritten or substituted checkout can never produce a consistent state.
    require(
        _git_text(repository_root, "rev-parse", f"{head_commit}^{{tree}}")
        == head_tree,
        "runner state head tree is not the tree of the runner state head",
    )
    require(
        derived_closure_sha256 is None
        or (type(derived_closure_sha256) is str
            and SHA64.fullmatch(derived_closure_sha256) is not None),
        "runner state derived closure digest is malformed",
    )
    return {
        "artifact_type": RUNNER_STATE_ARTIFACT_TYPE,
        "base_commit": base,
        "commit_count": commit_count,
        "consistent": True,
        "derived_closure_sha256": derived_closure_sha256,
        "head_commit": head_commit,
        "head_tree": head_tree,
        "recovery_round": recovery_round,
        "schema_version": 1,
        "terminal_state": terminal_state,
    }


def seal_evidence_directory(directory):
    """Seal regenerated evidence immutable, read the modes back and rehash.

    Files become 0444 and the directory 0555. Both modes are then read back
    from the filesystem, and every digest is recomputed from the sealed bytes,
    so the manifest describes the immutable artifacts that now exist.
    """
    directory = Path(directory)
    require(
        directory.is_dir() and not directory.is_symlink(),
        "regenerated evidence directory is absent or unsafe",
    )
    children = sorted(directory.iterdir(), key=lambda child: child.name)
    require(children, "regenerated evidence directory is empty")
    for child in children:
        require(
            child.is_file() and not child.is_symlink(),
            f"regenerated evidence member is not a regular file: {child.name}",
        )
    for child in children:
        os.chmod(child, SEALED_FILE_MODE)
    os.chmod(directory, SEALED_DIRECTORY_MODE)
    directory_mode = os.stat(directory).st_mode & 0o777
    require(
        directory_mode == SEALED_DIRECTORY_MODE,
        "regenerated evidence directory did not seal read-only",
    )
    entries = []
    for child in children:
        status = os.stat(child)
        mode = status.st_mode & 0o777
        require(
            mode == SEALED_FILE_MODE,
            f"regenerated evidence member did not seal read-only: {child.name}",
        )
        sealed = child.read_bytes()
        entries.append({
            "mode": format(mode, "04o"),
            "mode_readback": format(mode, "04o"),
            "name": child.name,
            "sha256": hashlib.sha256(sealed).hexdigest(),
            "size": len(sealed),
        })
    require(
        [entry["size"] for entry in entries]
        == [os.stat(directory / entry["name"]).st_size for entry in entries],
        "regenerated evidence size readback mismatch",
    )
    return {
        "directory_mode": format(directory_mode, "04o"),
        "directory_mode_readback": format(directory_mode, "04o"),
        "entries": entries,
        "hashes_recomputed_after_sealing": True,
        "mode_readback_verified": True,
    }


FINAL_EVIDENCE_MANIFEST_NAME = "AUTHORITY-V2-FINAL-EVIDENCE.json"


def authenticated_verify_only_gate(path):
    """The write-free F12 gate a round may not become terminal without.

    The document is the unchanged output of the verify-only publication path.
    It is accepted only if it really is a verified, non-authorizing,
    write-free confirmation: `state` exactly `verified`, the deep plan
    verified, no blocker at all, `F12` still open, release authorization still
    false, publication still unavailable and zero writes and zero transports.
    A blocked, absent, malformed, authorizing or F12-closing result stops the
    run here instead of letting it claim a completed round or seal anything.
    """
    label = "publication verify-only gate"
    path = Path(path)
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} result is absent or unsafe",
    )
    try:
        document = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit(f"{label} result is not valid UTF-8 JSON") from error
    require(
        type(document) is dict
        and tuple(sorted(document)) == tuple(sorted(VERIFY_ONLY_GATE_KEYS)),
        f"{label} result field set mismatch",
    )
    require(
        document["verify_only"] is True
        and document["writes_performed"] == 0
        and document["transports_constructed"] == 0,
        f"{label} result is not a write-free verify-only confirmation",
    )
    require(
        document["state"] == VERIFY_ONLY_VERIFIED_STATE,
        f"{label} did not reach the verified state: "
        f"{document['state']}",
    )
    require(
        document["deep_plan_verified"] is True,
        f"{label} did not verify the deep publication plan",
    )
    require(
        document["blocked_by"] is None,
        f"{label} is blocked by {document['blocked_by']}",
    )
    # The gate is a confirmation that publication stays unavailable. A result
    # that closed F12 or authorized a release is not a gate at all.
    require(
        document["f12_closed"] is False
        and document["release_authorized"] is False
        and document["publication"] == VERIFY_ONLY_PUBLICATION,
        f"{label} result is not the expected non-authorizing F12 state",
    )
    digests = document["asset_digests"]
    inventory = document["inventory"]
    require(
        type(digests) is dict and type(inventory) is list
        and sorted(digests) == sorted(inventory)
        and len(inventory) == len(set(inventory)),
        f"{label} result does not name the exact bytes it verified",
    )
    for name in sorted(digests):
        require(
            type(digests[name]) is str
            and SHA64.fullmatch(digests[name]) is not None,
            f"{label} result carries a malformed digest for {name}",
        )
    require(
        document["assets_verified"] == len(inventory),
        f"{label} result inventory contradicts its own asset count",
    )
    # The canonical map is reconstructed here from the gate's own names and
    # digests and required to be exactly the map the gate declares. Declaring
    # the honest map digest while having verified one member more - or one
    # fewer - is the superset defect this closes: the digest can no longer
    # describe an inventory the gate does not itself hold.
    require(
        document["canonical_inventory_sha256"] == canonical_inventory_sha256(
            {"digests": dict(digests), "inventory": list(inventory)},
        ),
        f"{label} result does not carry the canonical inventory map of the "
        f"exact bytes it names",
    )
    return document


def require_gated_bytes(directory, gate, names, label):
    """Every byte about to become terminal is a byte the gate really verified.

    The digest is recomputed here from the file on disk, so an artifact that
    changed after the gate ran - or was never part of the verified inventory
    at all - fails closed instead of being sealed.
    """
    directory = Path(directory)
    digests = gate["asset_digests"]
    for name in sorted(names):
        require(
            name in digests,
            f"{label} member was never verified by the publication gate: "
            f"{name}",
        )
        member = directory / name
        require(
            member.is_file() and not member.is_symlink(),
            f"{label} member is absent or unsafe: {name}",
        )
        require(
            hashlib.sha256(member.read_bytes()).hexdigest() == digests[name],
            f"{label} member changed after the publication gate verified it: "
            f"{name}",
        )


RELEASE_CHECKSUM_MANIFEST_NAME = "AUTHORITY-V2-RELEASE-SHA256SUMS"
# The release assets that are not signed release evidence: the four reviewed
# public documents and the two pre-issuance review artifacts. The last
# non-mutating gate verifies them exactly as it verifies the evidence, so they
# are sealed with everything else - gating an asset and then leaving it mutable
# is the defect this set exists to close. The release checksum manifest never
# enumerates them: its byte stream is recomputed by the unchanged production
# release verifier over the signed release evidence alone.
SEALED_PUBLIC_ASSET_NAMES = (
    "authority-v2-policy.json",
    "authority-v2-subject.schema.json",
    "github-environment-v2-contract.json",
    "preissuance-review-receipt.json",
    "preissuance-review-receipt.sigstore.json",
    "protected-asset-receipt-v2.json",
)
FINAL_EVIDENCE_SCHEMA_VERSION = 2
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  (\S+)\n")


def _final_evidence_members(directory, *, expected=None):
    """The complete inventory of the directory that is about to be sealed.

    Complete means complete: nothing is excluded, so a member that no gate
    ever saw cannot hide behind an exclusion. The final evidence manifest is
    the receipt *of* this inventory and may never be one of its members - a
    receipt kept inside the set it describes could not carry its own digest,
    and writing it after the inventory was verified is exactly the ordering
    defect this boundary exists to refuse.
    """
    directory = Path(directory)
    require(
        directory.is_dir() and not directory.is_symlink(),
        "final evidence directory is absent or unsafe",
    )
    observed = sorted(child.name for child in directory.iterdir())
    require(observed, "final evidence directory is empty")
    require(
        FINAL_EVIDENCE_MANIFEST_NAME not in observed,
        "the final evidence manifest may not live inside the inventory it "
        "seals",
    )
    for name in observed:
        member = directory / name
        require(
            member.is_file() and not member.is_symlink(),
            f"final evidence member is not a regular file: {name}",
        )
    if expected is not None:
        require(
            observed == sorted(expected),
            "final evidence inventory is not the exact expected inventory",
        )
    return observed


def _release_checksum_inventory(directory, observed):
    """The complete inventory, read back out of the release checksum manifest.

    The checksum manifest is itself one of the bytes the verify-only gate
    confirms, so its own enumeration is authenticated evidence rather than a
    local assertion. Requiring the directory to hold exactly those members
    plus the manifest itself closes the inventory equality in *both*
    directions: an extra member the gate never verified and a verified member
    that quietly vanished are equally refused.
    """
    directory = Path(directory)
    path = directory / RELEASE_CHECKSUM_MANIFEST_NAME
    require(
        path.is_file() and not path.is_symlink(),
        "the final evidence carries no release checksum manifest",
    )
    raw = path.read_bytes().decode("utf-8", "replace")
    listed, offset = {}, 0
    while offset < len(raw):
        match = CHECKSUM_LINE.match(raw, offset)
        require(
            match is not None,
            "the release checksum manifest is not canonical sha256sum output",
        )
        digest, name = match.group(1), match.group(2)
        require(
            name not in listed and name != RELEASE_CHECKSUM_MANIFEST_NAME,
            f"the release checksum manifest repeats or names itself: {name}",
        )
        listed[name] = digest
        offset = match.end()
    require(listed, "the release checksum manifest enumerates nothing")
    # Exact equality, in both directions, against the complete inventory: the
    # signed release evidence the manifest enumerates, the manifest itself and
    # the reviewed public release assets, which are sealed here but never
    # enumerated by the manifest the production release verifier recomputes.
    # A member outside that set, a missing member and a manifest entry that
    # names a public asset all fail closed.
    require(
        sorted([
            *listed, RELEASE_CHECKSUM_MANIFEST_NAME, *SEALED_PUBLIC_ASSET_NAMES,
        ]) == sorted(observed),
        "the final evidence inventory is not exactly the inventory the "
        "release checksum manifest enumerates together with the reviewed "
        "public release assets",
    )
    return listed


def build_final_evidence_manifest(directory, *, expected=None):
    """Compose the final evidence manifest, before anything is made terminal.

    It is composed out of the exact bytes the last non-mutating verify-only
    gate is about to confirm, and it records the complete inventory together
    with every member digest. Because it is composed *first* and recomputed
    again at sealing time, the seal can prove that nothing was created or
    rewritten in between.
    """
    directory = Path(directory)
    # The one canonical map, composed here and carried by this manifest. The
    # gate and the seal consume exactly these bytes rather than deriving their
    # own inventory again.
    canonical = build_canonical_inventory(directory, expected=expected)
    observed = list(canonical["inventory"])
    listed = _release_checksum_inventory(directory, observed)
    digests = canonical["digests"]
    for name, digest in sorted(listed.items()):
        require(
            digests[name] == digest,
            f"the release checksum manifest contradicts the member bytes: "
            f"{name}",
        )
    runner_state_path = directory / RUNNER_STATE_NAME
    require(
        runner_state_path.is_file() and not runner_state_path.is_symlink(),
        "the final evidence carries no sealed runner state",
    )
    runner_state = json.loads(runner_state_path.read_bytes())
    require(
        runner_state.get("artifact_type") == RUNNER_STATE_ARTIFACT_TYPE
        and runner_state.get("consistent") is True,
        "the final evidence runner state is not a consistent runner state",
    )
    require(
        runner_state.get("terminal_state") in RUNNER_TERMINAL_STATES,
        "the final evidence runner state is not a modelled terminal state",
    )
    return {
        "artifact_type": FINAL_EVIDENCE_ARTIFACT_TYPE,
        "canonical_inventory_sha256": canonical_inventory_sha256(canonical),
        "derived_closure_sha256": runner_state.get("derived_closure_sha256"),
        "inventory": observed,
        "member_sha256": digests,
        "runner_state_sha256": digests[RUNNER_STATE_NAME],
        "runner_terminal_state": runner_state.get("terminal_state"),
        "schema_version": FINAL_EVIDENCE_SCHEMA_VERSION,
        "sealed_after_release_manifest": True,
    }


# ---------------------------------------------------------------------------
# The one canonical complete inventory and digest map.
#
# It is composed exactly once, before the last non-mutating verify-only gate,
# and the same map is then consumed unchanged by the gate, by the final
# evidence manifest and by the seal. Three independent derivations of "the
# same" set were three chances to disagree; one map, identified by the digest
# of its own canonical bytes, cannot.
# ---------------------------------------------------------------------------
CANONICAL_INVENTORY_KEYS = ("digests", "inventory")


def build_canonical_inventory(directory, *, expected=None):
    """The complete inventory of `directory` and every member digest, once."""
    directory = Path(directory)
    observed = _final_evidence_members(directory, expected=expected)
    return {
        "digests": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in observed
        },
        "inventory": list(observed),
    }


def canonical_inventory_bytes(document):
    """The exact bytes the canonical map is identified by."""
    require(
        type(document) is dict
        and tuple(sorted(document)) == CANONICAL_INVENTORY_KEYS,
        "the canonical inventory field set is not the canonical map",
    )
    return json.dumps(
        {
            "digests": dict(document["digests"]),
            "inventory": list(document["inventory"]),
        },
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def canonical_inventory_sha256(document):
    return hashlib.sha256(canonical_inventory_bytes(document)).hexdigest()


def require_canonical_inventory(document, digests, label):
    """Full bidirectional name and digest equality against one map.

    Not a subset in either direction: every name the map records is a name
    these bytes carry, every name these bytes carry is a name the map records,
    and every digest is equal. A map that omits a member, names one that was
    never seen, or records a digest that is not the byte stream is refused.
    """
    require(
        type(document) is dict
        and tuple(sorted(document)) == CANONICAL_INVENTORY_KEYS
        and type(document["digests"]) is dict
        and type(document["inventory"]) is list,
        f"{label} is not the canonical inventory map",
    )
    require(
        sorted(document["inventory"]) == sorted(document["digests"])
        and len(document["inventory"]) == len(set(document["inventory"])),
        f"{label} is not the canonical inventory: its own names and digests "
        "disagree",
    )
    require(
        sorted(document["digests"]) == sorted(digests),
        f"{label} is not the canonical inventory of these bytes: "
        f"{sorted(document['digests'])} against {sorted(digests)}",
    )
    for name in sorted(digests):
        require(
            document["digests"][name] == digests[name],
            f"{label} is not the canonical inventory digest for {name}",
        )
    return document


def canonical_final_evidence_manifest(manifest):
    return json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def write_final_evidence_manifest(path, directory, *, expected=None):
    """Write the composed manifest exclusively, outside the sealed inventory."""
    path = Path(path)
    directory = Path(directory).resolve()
    require(
        path.resolve().parent != directory,
        "the final evidence manifest may not be written into the inventory "
        "it seals",
    )
    manifest = build_final_evidence_manifest(directory, expected=expected)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, canonical_final_evidence_manifest(manifest))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def seal_final_evidence(directory, *, expected=None, gate=None, manifest=None):
    """Make the already-verified final evidence immutable, and nothing else.

    Every byte here was confirmed by the last non-mutating verify-only gate
    before this ran, so this boundary creates nothing and rewrites nothing: it
    only changes modes. It proves, in both directions and byte for byte, that
    the complete sealed inventory is exactly the inventory that gate verified,
    and that the manifest composed beforehand still describes exactly these
    bytes. A member created after the gate, a member that drifted, a missing
    member and a manifest that no longer matches all fail closed.
    """
    directory = Path(directory)
    observed = _final_evidence_members(directory, expected=expected)
    require(
        gate is not None,
        "the final evidence may not be sealed without the authenticated "
        "verify-only publication gate",
    )
    require(
        manifest is not None,
        "the final evidence manifest must be composed before the verify-only "
        "publication gate and supplied to the seal",
    )
    # Every sealed byte is a byte the gate really verified, recomputed here.
    digests = gate["asset_digests"]
    require_gated_bytes(directory, gate, observed, "final evidence")
    # ... and the gate verified nothing inside this set that is not sealed.
    listed = _release_checksum_inventory(directory, observed)
    for name, digest in sorted(listed.items()):
        require(
            digests.get(name) == digest,
            f"the publication gate did not verify the release checksum "
            f"manifest entry for {name}",
        )
    composed = build_final_evidence_manifest(directory, expected=expected)
    manifest_path = Path(manifest)
    require(
        manifest_path.is_file() and not manifest_path.is_symlink(),
        "the final evidence manifest is absent or unsafe",
    )
    # The one canonical map: composed before the gate, carried by the manifest
    # and consumed unchanged here. The checks above prove that every sealed
    # byte was gated; these prove the converse, which nothing proved before -
    # the gate consumed exactly this map and verified nothing outside it. Full
    # bidirectional equality by name and by digest, never a subset either way.
    recorded = json.loads(manifest_path.read_bytes())
    canonical = build_canonical_inventory(directory, expected=expected)
    identity = canonical_inventory_sha256(canonical)
    require(
        recorded.get("canonical_inventory_sha256") == identity,
        "the final evidence manifest does not carry the canonical inventory "
        "map of exactly these bytes",
    )
    require(
        gate.get("canonical_inventory_sha256") == identity,
        "the publication gate did not consume the canonical inventory map "
        "the final evidence manifest composed",
    )
    # ... and the manifest's own recorded inventory really is that map, so the
    # digest it carries can never describe a map it does not itself hold.
    require_canonical_inventory(
        {
            "digests": recorded.get("member_sha256"),
            "inventory": recorded.get("inventory"),
        },
        canonical["digests"], "the final evidence manifest inventory",
    )
    # The complete sealed inventory is the map, in both directions, and the
    # gate's own record of every one of those members agrees with it. Full
    # bidirectional member equality across all three - gate inventory,
    # manifest canonical map and observed sealed inventory - so neither a
    # superset nor a subset escapes at any of the three boundaries.
    require(
        sorted(canonical["inventory"]) == sorted(observed),
        "the complete sealed inventory is not the canonical inventory map",
    )
    require_canonical_inventory(
        {"digests": dict(digests), "inventory": sorted(digests)},
        canonical["digests"], "the publication gate inventory",
    )
    require(
        sorted(digests) == sorted(observed),
        "the publication gate inventory is not the canonical inventory of "
        "exactly the sealed bytes",
    )
    for name in sorted(canonical["digests"]):
        require(
            digests.get(name) == canonical["digests"][name],
            f"the publication gate asset map is not the canonical inventory "
            f"digest for {name}",
        )
    require(
        manifest_path.resolve().parent != directory.resolve(),
        "the final evidence manifest may not live inside the inventory it "
        "seals",
    )
    require(
        manifest_path.read_bytes()
        == canonical_final_evidence_manifest(composed),
        "the final evidence manifest was not composed over exactly these "
        "verified bytes",
    )
    sealing = seal_evidence_directory(directory)
    names = [entry["name"] for entry in sealing["entries"]]
    require(
        names == observed,
        "final evidence sealing did not cover the complete inventory",
    )
    # The receipt itself becomes immutable too, once what it describes has.
    os.chmod(manifest_path, SEALED_FILE_MODE)
    require(
        os.stat(manifest_path).st_mode & 0o777 == SEALED_FILE_MODE,
        "the final evidence manifest did not seal read-only",
    )
    return {
        **composed,
        "canonical_inventory_sha256": identity,
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest(),
        "sealing": sealing,
    }


def write_runner_state(directory, state):
    """Write the runner-state artifact exclusively, then seal the directory."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(
        not any(directory.iterdir()),
        "runner state directory must be empty; overwrite is forbidden",
    )
    path = directory / RUNNER_STATE_NAME
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, canonical_runner_state(state))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return seal_evidence_directory(directory)


def build_subjects(policy_path, output_dir, publishable_key, api_instance_id,
                   authenticated_issuance, *, seal=False):
    require(type(authenticated_issuance) is GITHUB_ISSUANCE.AuthenticatedIssuance,
            "subjects require an authenticated GitHub issuance object")
    issuance_binding = GITHUB_ISSUANCE.subject_issuance_binding(authenticated_issuance)
    reviewed_activation_sha = authenticated_issuance.candidate_head
    review_receipt_sha256 = authenticated_issuance.review_receipt_sha256
    policy_path = Path(policy_path).resolve()
    output_dir = Path(output_dir).resolve()
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes)
    require(policy_path == (ROOT / "authority-v2-policy.json").resolve(), "only the committed Authority-v2 policy path is accepted")
    require(SHA40.fullmatch(reviewed_activation_sha) is not None, "reviewed activation SHA must be exact lowercase 40-hex")
    require(SHA64.fullmatch(review_receipt_sha256) is not None, "review receipt SHA-256 must be exact lowercase 64-hex")
    require(os.environ.get("GITHUB_SHA") == reviewed_activation_sha, "reviewed activation SHA does not equal GITHUB_SHA")
    require(os.environ.get("GITHUB_REF") == "refs/heads/main", "issuance is main-only")
    require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "issuance requires workflow_dispatch")
    require(os.environ.get("GITHUB_REPOSITORY") == EXACT_REPOSITORY, "repository identity mismatch")
    require(os.environ.get("GITHUB_WORKFLOW_REF") == EXACT_WORKFLOW_REF, "workflow identity mismatch")

    subject_policy = policy["subject"]
    publishable_fp = fingerprint(b"acc-clerk-instance-v1\0", publishable_key)
    instance_fp = fingerprint(b"acc-clerk-api-instance-v1\0", api_instance_id)
    require(publishable_fp == subject_policy["clerk_publishable_key_fingerprint_sha256"], "publishable fingerprint mismatch")
    require(instance_fp == subject_policy["clerk_api_instance_id_fingerprint_sha256"], "API instance fingerprint mismatch")
    require(subject_policy["required_environment_type"] == "development", "only the existing development instance is permitted")

    expected_cases = policy["temporal_subject_contract"]["cases"]
    require(tuple(policy["temporal_subject_contract"]["required_case_order"]) == EXACT_CASES, "exact case order mismatch")
    require(set(expected_cases) == set(EXACT_CASES), "exactly three case contracts are required")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(output_dir.iterdir()), "output directory must be empty; overwrite is forbidden")

    policy_sha = hashlib.sha256(policy_bytes).hexdigest()
    generated = []
    for case in EXACT_CASES:
        payload = {
            "schema_version": 2,
            "authority_id": policy["authority_id"],
            "case": case,
            "authority_policy_sha256": policy_sha,
            "reviewed_activation_sha": reviewed_activation_sha,
            "preissuance_review_receipt_sha256": review_receipt_sha256,
            "issuance": issuance_binding,
            "workflow_evidence": {
                "repository": EXACT_REPOSITORY, "workflow_ref": EXACT_WORKFLOW_REF,
                "git_ref": "refs/heads/main", "event_name": "workflow_dispatch",
            },
            "subject": {
                "clerk_publishable_key_fingerprint_sha256": publishable_fp,
                "clerk_api_instance_id_fingerprint_sha256": instance_fp,
                "environment_type": "development",
                "acc_production_base_sha": subject_policy["acc_production_base_sha"],
            },
            "case_contract": expected_cases[case],
            "privacy": policy["privacy"],
        }
        path = output_dir / f"authority-v2-{case}.json"
        path.write_bytes(canonical(payload))
        generated.append(path)
    require(sorted(p.name for p in output_dir.iterdir()) == [p.name for p in generated], "missing or extra generated artifacts")
    if seal:
        # Regenerated evidence is sealed immutable, its modes are read back and
        # every digest is recomputed from the sealed bytes.
        seal_evidence_directory(output_dir)
    return generated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=ROOT / "authority-v2-policy.json")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--github-issuance", type=Path)
    parser.add_argument("--github-issuance-sha256")
    parser.add_argument("--candidate-head")
    parser.add_argument("--candidate-tree")
    parser.add_argument("--canonical-diff-sha256")
    parser.add_argument("--review-receipt-sha256")
    parser.add_argument("--seal-evidence", action="store_true")
    # The runner-state artifact is evidence about this exact round, not a
    # subject: it derives its head, tree and commit count from the immutable
    # checkout and records only the round and terminal state it was told.
    parser.add_argument("--emit-runner-state", action="store_true")
    parser.add_argument("--recovery-round", type=int)
    parser.add_argument("--terminal-state", choices=RUNNER_STATES)
    parser.add_argument("--runner-state-dir", type=Path)
    parser.add_argument("--derived-closure-sha256")
    parser.add_argument("--seal-final-evidence", type=Path)
    # The final evidence manifest is composed *before* the last non-mutating
    # verify-only gate, out of exactly the bytes that gate then confirms, and
    # is written outside the inventory it describes. Sealing afterwards
    # creates nothing and rewrites nothing.
    # The one canonical complete inventory and digest map, emitted before a
    # non-mutating gate so the gate consumes it rather than deriving its own.
    parser.add_argument("--emit-canonical-inventory", type=Path)
    parser.add_argument("--canonical-inventory", type=Path)
    parser.add_argument("--emit-final-evidence-manifest", type=Path)
    parser.add_argument("--final-evidence-manifest", type=Path)
    parser.add_argument("--final-evidence-member", action="append", default=[])
    # The write-free F12 publication gate. A round may not claim a completed
    # terminal state, and may not seal anything, without it.
    parser.add_argument("--verify-only-result", type=Path)
    args = parser.parse_args()

    if args.emit_canonical_inventory is not None:
        require(
            args.canonical_inventory is not None,
            "emitting the canonical inventory map requires "
            "--canonical-inventory",
        )
        canonical = build_canonical_inventory(
            args.emit_canonical_inventory,
            expected=args.final_evidence_member or None,
        )
        target = Path(args.canonical_inventory)
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
        )
        try:
            os.write(descriptor, canonical_inventory_bytes(canonical))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        print(json.dumps({
            "canonical_inventory": str(target),
            "canonical_inventory_sha256": canonical_inventory_sha256(canonical),
            "member_count": len(canonical["inventory"]),
            "raw_values_emitted": False,
            "sealed": False,
        }, sort_keys=True))
        return

    if args.emit_final_evidence_manifest is not None:
        require(
            args.final_evidence_manifest is not None,
            "composing the final evidence manifest requires "
            "--final-evidence-manifest",
        )
        written = write_final_evidence_manifest(
            args.final_evidence_manifest, args.emit_final_evidence_manifest,
            expected=args.final_evidence_member or None,
        )
        print(json.dumps({
            "final_evidence_manifest": str(written),
            "final_evidence_manifest_sha256": hashlib.sha256(
                written.read_bytes()
            ).hexdigest(),
            "raw_values_emitted": False,
            "sealed": False,
        }, sort_keys=True))
        return

    if args.seal_final_evidence is not None:
        require(
            args.verify_only_result is not None,
            "sealing the final evidence requires the authenticated "
            "--verify-only-result publication gate",
        )
        require(
            args.final_evidence_manifest is not None,
            "sealing the final evidence requires the --final-evidence-manifest "
            "composed before the verify-only publication gate",
        )
        emitted = seal_final_evidence(
            args.seal_final_evidence,
            expected=args.final_evidence_member or None,
            gate=authenticated_verify_only_gate(args.verify_only_result),
            manifest=args.final_evidence_manifest,
        )
        print(json.dumps({
            "final_evidence": emitted,
            "raw_values_emitted": False,
            "sealed": True,
        }, sort_keys=True))
        return

    if args.emit_runner_state:
        require(
            args.recovery_round is not None and args.terminal_state is not None,
            "a runner state requires an exact recovery round and terminal state",
        )
        state = build_runner_state(
            repository_root=ROOT, recovery_round=args.recovery_round,
            terminal_state=args.terminal_state,
            derived_closure_sha256=args.derived_closure_sha256,
        )
        if args.terminal_state == "completed":
            # A completed round is a claim about a run that already passed
            # every non-mutating gate, so the write-free F12 publication gate
            # must have confirmed the complete canonical release inventory
            # *before* this artifact exists. The gate must moreover have run
            # over a runner state that was not yet completed: a gate produced
            # over this very artifact would prove nothing about ordering.
            require(
                args.verify_only_result is not None,
                "a completed runner state requires the authenticated "
                "--verify-only-result publication gate",
            )
            gate = authenticated_verify_only_gate(args.verify_only_result)
            staged = gate["asset_digests"].get(RUNNER_STATE_NAME)
            require(
                staged is not None,
                "the publication gate never verified a runner state",
            )
            require(
                staged != hashlib.sha256(
                    canonical_runner_state(state)
                ).hexdigest(),
                "the publication gate was produced over this completed runner "
                "state, so it cannot have preceded it",
            )
        emitted = {
            "raw_values_emitted": False,
            "runner_state": state,
            "sealed": False,
        }
        if args.runner_state_dir is not None:
            emitted["sealing"] = write_runner_state(args.runner_state_dir, state)
            emitted["sealed"] = True
        print(json.dumps(emitted, sort_keys=True))
        return

    for name in ("output_dir", "github_issuance", "github_issuance_sha256",
                 "candidate_head", "candidate_tree", "canonical_diff_sha256",
                 "review_receipt_sha256"):
        require(
            getattr(args, name) is not None,
            f"subject generation requires --{name.replace('_', '-')}",
        )
    issuance = GITHUB_ISSUANCE.verify_authenticated_issuance_bytes(
        args.github_issuance.read_bytes(), args.github_issuance_sha256,
        {"head_commit": args.candidate_head, "head_tree": args.candidate_tree,
         "canonical_diff_sha256": args.canonical_diff_sha256,
         "review_receipt_sha256": args.review_receipt_sha256},
    )
    generated = build_subjects(
        args.policy, args.output_dir, os.environ.get("CLERK_PUBLISHABLE_KEY", ""),
        os.environ.get("CLERK_API_INSTANCE_ID", ""), issuance,
        seal=args.seal_evidence,
    )
    print(json.dumps({"generated_subjects": [p.name for p in generated], "generated_count": len(generated), "raw_values_emitted": False}, sort_keys=True))


if __name__ == "__main__":
    main()
