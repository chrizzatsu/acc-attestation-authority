#!/usr/bin/env python3
"""Atomic, fail-closed Authority-v2 GitHub release publication state machine."""
import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from collections.abc import Mapping
from pathlib import Path

try:
    from scripts import verify_authority_v2 as AUTHORITY
except ModuleNotFoundError:
    import verify_authority_v2 as AUTHORITY

EXPECTED_REPOSITORY = "chrizzatsu/acc-attestation-authority"
EXPECTED_REF = "refs/heads/main"
EXPECTED_TRIGGER = "workflow_dispatch"
GITHUB_API_VERSION = "2026-03-10"
RELEASE_TAG = "clerk-instance-attestation-v2"
EXACT_TAG_REF = f"refs/tags/{RELEASE_TAG}"
PUBLICATION_CLAIM_TAG = "authority-v2-publication-claim"
PUBLICATION_CLAIM_REF = f"refs/tags/{PUBLICATION_CLAIM_TAG}"
RELEASE_TITLE = "ACC Clerk instance attestation v2"
RELEASE_PAGE_SIZE = 100
MAX_RELEASE_PAGES = 100
PUBLICATION_UNAVAILABLE_REMEDIATION = (
    "GitHub documents neither a durable server-owned pre-draft publication state "
    "nor an atomic draft-to-immutable transition, so a later independently "
    "reviewed candidate may enable publication only after documented server "
    "semantics make every fallible write exactly reconstructable."
)
RELEASE_NOTES = "Exact three-case keyless Authority-v2 evidence. Independent post-issuance review remains mandatory."
EXPECTED_RELEASE_ASSET_NAMES = (
    "AUTHORITY-V2-RELEASE-SHA256SUMS",
    "authority-v2-future.json",
    "authority-v2-future.sigstore.json",
    "authority-v2-in_window.json",
    "authority-v2-in_window.sigstore.json",
    "authority-v2-policy.json",
    "authority-v2-runner-state.json",
    "authority-v2-stale.json",
    "authority-v2-stale.sigstore.json",
    "authority-v2-subject.schema.json",
    "github-environment-v2-contract.json",
    "preissuance-review-receipt.json",
    "preissuance-review-receipt.sigstore.json",
    "protected-asset-receipt-v2.json",
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
STRONG_ETAG = re.compile(r'"[^"\r\n]+"')
REVIEWED_PUBLIC_ASSET_PATHS = {
    "authority-v2-policy.json": "authority-v2-policy.json",
    "authority-v2-subject.schema.json": "schemas/authority-v2-subject.schema.json",
    "github-environment-v2-contract.json": "github-environment-v2-contract.json",
    "protected-asset-receipt-v2.json": "protected-asset-receipt-v2.json",
}
RELEASE_EVIDENCE_ASSET_NAMES = (
    "AUTHORITY-V2-RELEASE-SHA256SUMS",
    "authority-v2-future.json",
    "authority-v2-future.sigstore.json",
    "authority-v2-in_window.json",
    "authority-v2-in_window.sigstore.json",
    "authority-v2-runner-state.json",
    "authority-v2-stale.json",
    "authority-v2-stale.sigstore.json",
)
WRITER_EXCLUSION_CONTRACT_PATH = (
    AUTHORITY.ROOT / "publication-writer-exclusion-v2.json"
)
PROHIBITED_PUBLICATION_WRITES = (
    "DELETE /repos/{repository}/releases/{release_id}",
    "PATCH /repos/{repository}/releases/{release_id}",
    "POST /repos/{repository}/git/refs",
    "POST /repos/{repository}/git/tags",
    "POST /repos/{repository}/releases",
    "POST uploads.github.com release assets",
)
# F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE: the exact impossibility that keeps
# F12 false. Every one of these must stay exactly as sealed.
EXCLUSIVE_TRANSITION_IMPOSSIBILITY_FLAGS = {
    "atomic_transition_available": False,
    "binds_exact_activation_sha": False,
    "binds_verified_immutable_asset_snapshots": False,
    "compare_and_swap_available": False,
    "documented_github_release_api_provides_it": False,
    "excludes_every_authorized_writer": False,
    "local_simulation_is_not_evidence": True,
    "self_asserted_exclusivity_rejected": True,
}
EXCLUSIVE_TRANSITION_IMPOSSIBILITY_KEYS = tuple(sorted(
    (*EXCLUSIVE_TRANSITION_IMPOSSIBILITY_FLAGS, "reason", "required_primitive")
))
KNOWN_WRITER_MODEL_KEYS = (
    "enumerated_writer_classes", "exhaustive", "limits",
    "unbounded_writer_classes",
)
# F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE: the impossibility is sealed with
# authoritative GitHub semantics and with the exact exhaustive live
# authorized-writer proof the platform does not make available. Neither may be
# weakened, and no status, transport outcome or local simulation may replace
# them.
SEMANTIC_CITATION_KEYS = (
    "documented_behaviour", "endpoint", "proves_exclusivity", "source",
    "status",
)
DOCUMENTED_CREATE_REF_STATUSES = (201, 409, 422)
CREATE_REF_ENDPOINT = "POST /repos/{owner}/{repo}/git/refs"
AUTHORITATIVE_DOCUMENTATION_PREFIX = "https://docs.github.com/"
MISSING_WRITER_PROOF_KEYS = (
    "attempted_live_inventory_endpoints", "proof_available", "required_proof",
    "simulated_or_self_asserted_proof_rejected", "unavailable_because",
    "writer_set_is_unbounded",
)
ATTEMPTED_INVENTORY_KEYS = ("endpoint", "insufficient_because", "returns")


def require(condition, message):
    if not condition:
        raise SystemExit(message)


# ---------------------------------------------------------------------------
# F12-RACE-SAFE-PUBLICATION-UNAVAILABLE: server-atomic claim-ref primitive
#
# GitHub Create a reference (POST /repos/{owner}/{repo}/git/refs) is
# server-atomic and fails when the ref already exists. This is the sole
# documented no-overwrite, server-backed primitive available for exclusive
# publication claiming. update-ref and force are never used.
# ---------------------------------------------------------------------------
CLAIM_REF_CONTRACT = {
    "method": "POST",
    "endpoint": "/repos/{owner}/{repo}/git/refs",
    "server_atomic": True,
    "fails_when_ref_exists": True,
    "no_overwrite": True,
    "never_use_update_ref": True,
    "never_use_force": True,
    "success_status": 201,
    "non_authoritative_statuses": [409, 422],
    "non_201_is_never_already_exists_proof": True,
    "authoritative_existence_requires_authenticated_readback": True,
    "expected_tag_object_sha_derived_from_request_identity": True,
    "confirmed_absence_requires_authenticated_visibility_listing": True,
    "visibility_listing_endpoint": "/repos/{owner}/{repo}/git/matching-refs/tags/",
    "visibility_listing_exhaustive_pagination_required": True,
    "visibility_listing_page_size": 100,
    "visibility_listing_max_pages": 100,
    "visibility_listing_ref_prefix": "refs/tags/",
    "visibility_listing_completion_proof_required": True,
    "documented_semantics": (
        "GitHub Create a reference is documented to atomically create a new "
        "ref only if it does not already exist, and to answer HTTP 201 when it "
        "did. HTTP 422 is documented as a generic validation failure and HTTP "
        "409 as a generic conflict: neither uniquely proves that a ref of that "
        "name already exists, and neither says anything about the object the "
        "name resolves to. Every non-201 outcome, including transport "
        "ambiguity, therefore stays non-authoritative until an authenticated "
        "readback resolves the exact annotated tag object. No update-ref or "
        "force-push is ever used."
    ),
}

CLAIM_REF_RECONCILIATION_STATES = (
    "created_by_this_attempt",
    "absent",
    "mismatch_collision",
    "readback_ambiguous",
)
CREATE_REF_OUTCOMES = (
    "created",
    "non_authoritative_conflict",
    "non_authoritative_error",
    "transport_ambiguous",
)
CREATE_REF_NON_AUTHORITATIVE = (
    "non_authoritative_conflict",
    "non_authoritative_error",
    "transport_ambiguous",
)
CLAIM_MESSAGE_PREFIX = "acc-authority-v2-publication-claim-v2\n"


CLAIM_TAG_OBJECT_TAGGER = "acc-authority-v2 <acc-authority-v2@invalid> 0 +0000"
TAG_REF_VISIBILITY_PATH = (
    f"/repos/{EXPECTED_REPOSITORY}/git/matching-refs/tags/"
)
TAG_REF_PREFIX = "refs/tags/"
TAG_REF_PAGE_SIZE = 100
MAX_TAG_REF_PAGES = 100
API_HOSTS = ("", "api.github.com")
LINK_NEXT = re.compile(r'<(?P<url>[^<>]*)>\s*;\s*rel="next"')
LINK_NEXT_TOKEN = re.compile(r'rel\s*=\s*"?next"?', re.IGNORECASE)


def tag_ref_visibility_page_path(page):
    """The exact deterministic page path of the matching-refs endpoint."""
    return f"{TAG_REF_VISIBILITY_PATH}?per_page={TAG_REF_PAGE_SIZE}&page={page}"


def parse_next_visibility_page(headers, current_page):
    """Resolve the next deterministic page, or report why traversal cannot go on.

    Returns (next_page, state). `state` is "complete" when this page is the
    documented last one, "continue" when a well-formed monotonic next link
    advances exactly one page on the exact same endpoint, and "malformed" for
    a duplicate, unparsable, foreign, non-monotonic or looping link.
    """
    if type(headers) is not dict:
        return None, "malformed"
    links = [value for name, value in headers.items() if name.lower() == "link"]
    if len(links) > 1:
        return None, "malformed"
    if not links:
        return None, "complete"
    link = links[0]
    if type(link) is not str:
        return None, "malformed"
    matches = LINK_NEXT.findall(link)
    if not matches:
        # A header that advertises a next relation without a parsable target,
        # or that is not a well-formed link header at all, is malformed. Only
        # a well-formed header with no next relation ends the traversal.
        if LINK_NEXT_TOKEN.search(link) is not None:
            return None, "malformed"
        if "rel=" not in link:
            return None, "malformed"
        return None, "complete"
    if len(matches) > 1:
        return None, "malformed"
    parts = urllib.parse.urlsplit(matches[0])
    if parts.netloc not in API_HOSTS:
        return None, "malformed"
    if parts.path != TAG_REF_VISIBILITY_PATH:
        return None, "malformed"
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    if sorted(query) != ["page", "per_page"]:
        return None, "malformed"
    if query["per_page"] != [str(TAG_REF_PAGE_SIZE)]:
        return None, "malformed"
    raw_page = query["page"]
    if len(raw_page) != 1 or not re.fullmatch(r"[1-9][0-9]*", raw_page[0]):
        return None, "malformed"
    next_page = int(raw_page[0])
    if next_page != current_page + 1:
        return None, "malformed"
    return next_page, "continue"


def _is_authenticated_absence_evidence(absence_evidence, expected_ref):
    """Prove the same credential could have seen the ref had it existed.

    A documented HTTP 404 on a single ref read is indistinguishable from a
    permission-masked 404, and one page of the matching-refs listing is
    indistinguishable from a listing that hides the target on a later page.
    The only evidence accepted here is a deterministic, bounded, exhaustively
    paginated authenticated HTTP 200 traversal of the exact matching-refs
    endpoint by the same credential, with explicit proof of completion, no
    malformed/contradictory/looping pagination metadata, every ref carrying
    the exact expected prefix, and the target absent from every page.
    """
    if type(absence_evidence) is not dict:
        return False
    if absence_evidence.get("authenticated") is not True:
        return False
    if absence_evidence.get("status") != 200:
        return False
    if absence_evidence.get("complete") is not True:
        return False
    if absence_evidence.get("prefix") != TAG_REF_PREFIX:
        return False
    pages = absence_evidence.get("pages")
    if type(pages) is not int or type(pages) is bool:
        return False
    if not 1 <= pages <= MAX_TAG_REF_PAGES:
        return False
    refs = absence_evidence.get("refs")
    if type(refs) is not list:
        return False
    for entry in refs:
        if type(entry) is not dict:
            return False
        name = entry.get("ref")
        if type(name) is not str or not name:
            return False
        if not name.startswith(TAG_REF_PREFIX):
            return False
        if expected_ref is not None and name == expected_ref:
            return False
    if expected_ref is not None and not expected_ref.startswith(TAG_REF_PREFIX):
        return False
    return True


def classify_ref_read(status, *, absence_evidence=None, expected_ref=None):
    """Classify an HTTP status from an authenticated authorized ref read.

    A documented 404 alone is never confirmed absence: it is
    `readback_ambiguous` until an authenticated visibility listing proves the
    credential could have seen the ref. 401/403/429/5xx, permission/auth/
    rate-limit/network/timeout/malformed responses are unknown_error. Every
    state other than confirmed_absent/confirmed_present prohibits any retry or
    write progression.
    """
    if status == 200:
        return "confirmed_present"
    if status == 404:
        if _is_authenticated_absence_evidence(absence_evidence, expected_ref):
            return "confirmed_absent"
        return "readback_ambiguous"
    return "unknown_error"


def expected_claim_tag_object_sha(activation_sha, message):
    """Derive the exact annotated tag-object SHA this request identity implies.

    The claim tag object is fully determined by the activation commit, the
    fixed claim tag name, a fixed deterministic tagger and the exact
    nonce/issuance/plan-bearing claim message, so the Git object name is a pure
    function of the authoritative request identity. Any other annotated tag
    object — however closely its payload, target or message match — has a
    different name and is rejected.
    """
    require(
        type(activation_sha) is str
        and HEX40.fullmatch(activation_sha) is not None,
        "claim tag-object derivation requires an exact activation commit",
    )
    require(
        type(message) is str and message.startswith(CLAIM_MESSAGE_PREFIX),
        "claim tag-object derivation requires the exact claim message",
    )
    body = (
        f"object {activation_sha}\n"
        f"type commit\n"
        f"tag {PUBLICATION_CLAIM_TAG}\n"
        f"tagger {CLAIM_TAG_OBJECT_TAGGER}\n"
        f"\n{message}\n"
    ).encode("utf-8")
    header = b"tag " + str(len(body)).encode("ascii") + b"\0"
    return hashlib.sha1(header + body).hexdigest()


def classify_create_ref_outcome(status):
    """Classify the HTTP outcome of a POST /repos/{owner}/{repo}/git/refs.

    F12-CREATE-REF-STATUS-SEMANTICS-MISCLASSIFIED: HTTP 422 is a documented
    generic validation failure, not a unique already-exists proof, and HTTP 409
    is a documented generic conflict. Only the documented 201 is a creation.

    201  = created.
    409  = non_authoritative_conflict.
    422  = non_authoritative_conflict.
    None = transport_ambiguous (timeout/network; server state unknown).
    every other non-201 status = non_authoritative_error.

    No outcome in this function ever proves that a claim already exists; only
    `classify_claim_readback` over an authenticated readback can do that.
    """
    if status is None:
        return "transport_ambiguous"
    if status == 201:
        return "created"
    if status in (409, 422):
        return "non_authoritative_conflict"
    return "non_authoritative_error"


def create_ref_outcome_proves_existing_claim(outcome):
    """No create-ref HTTP outcome is, by itself, proof of an existing claim."""
    require(outcome in CREATE_REF_OUTCOMES, "create-ref outcome is not modelled")
    return False


def _claim_message_payload(message):
    """Return the canonical claim payload carried by an annotated tag message.

    Returns None when the message is absent, forged, non-canonical or does not
    carry the exact publication-claim identity prefix.
    """
    if type(message) is not str or not message.startswith(CLAIM_MESSAGE_PREFIX):
        return None
    payload_data = message[len(CLAIM_MESSAGE_PREFIX):].encode("utf-8")
    try:
        payload = _closed_json(payload_data, "publication claim message")
    except SystemExit:
        return None
    if type(payload) is not dict or payload_data != _json_bytes(payload):
        return None
    return payload


def classify_claim_readback(ref_readback, tag_object, *, expected_ref,
                            expected_tag, expected_target,
                            expected_request_identity, expected_plan_sha256,
                            expected_tag_object_sha=None,
                            expected_message=None):
    """Classify an authenticated readback of the deterministic claim ref.

    Only a nonce/issuance/plan-bearing annotated tag object with the exact
    tag-object SHA, object type, tag name, message, commit target and request
    identity is `created_by_this_attempt`. A direct commit ref, a lightweight
    tag, a substituted object, a foreign nonce/issuance/plan or any other
    resolved owner is `mismatch_collision`. An absent readback allows only a
    bounded retry, and anything unresolved, masked or malformed is
    `readback_ambiguous`. Every non-`created_by_this_attempt` state prohibits
    writes.
    """
    if ref_readback is None:
        return "absent"
    if type(ref_readback) is not dict:
        return "readback_ambiguous"
    if ref_readback.get("ref") != expected_ref:
        return "readback_ambiguous"
    ref_object = ref_readback.get("object")
    if type(ref_object) is not dict:
        return "readback_ambiguous"
    ref_object_sha = ref_object.get("sha")
    if type(ref_object_sha) is not str or HEX40.fullmatch(ref_object_sha) is None:
        return "readback_ambiguous"
    if ref_object.get("type") != "tag":
        # A direct commit ref or a lightweight tag owns the exact claim name.
        return "mismatch_collision"
    if (
        expected_tag_object_sha is not None
        and ref_object_sha != expected_tag_object_sha
    ):
        return "mismatch_collision"
    if type(tag_object) is not dict:
        return "readback_ambiguous"
    if tag_object.get("sha") != ref_object_sha:
        return "readback_ambiguous"
    target = tag_object.get("object")
    if type(target) is not dict:
        return "mismatch_collision"
    if tag_object.get("tag") != expected_tag:
        return "mismatch_collision"
    if target.get("type") != "commit" or target.get("sha") != expected_target:
        return "mismatch_collision"
    message = tag_object.get("message")
    payload = _claim_message_payload(message)
    if payload is None:
        return "mismatch_collision"
    issuance = payload.get("issuance")
    if type(issuance) is not dict:
        return "mismatch_collision"
    if issuance.get("nonce_issuance_sha256") != expected_request_identity:
        return "mismatch_collision"
    if payload.get("release", {}).get("target_commitish") != expected_target:
        return "mismatch_collision"
    if payload.get("publication_plan_sha256") != expected_plan_sha256:
        return "mismatch_collision"
    if expected_message is not None and message != expected_message:
        return "mismatch_collision"
    return "created_by_this_attempt"


class TransportError(Exception):
    """A transport result for which the remote state cannot be known."""


@dataclass(frozen=True)
class ApiResponse:
    status: int
    headers: dict
    body: bytes


@dataclass(frozen=True)
class BoundPublicationAsset:
    name: str
    data: bytes
    sha256: str


@dataclass(frozen=True)
class PublicationPlan:
    activation_sha: str
    assets: tuple


@dataclass(frozen=True)
class TagRulesetBinding:
    ruleset_id: int
    etag: str
    canonical_sha256: str


@dataclass(frozen=True)
class PublicationGuards:
    immutable_releases_sha256: str
    tag_ruleset: TagRulesetBinding


def bind_publication(activation_sha, assets):
    require(type(activation_sha) is str and HEX40.fullmatch(activation_sha) is not None, "activation SHA is malformed")
    require(type(assets) is dict and assets, "publication assets are absent")
    bound = []
    for name, data in assets.items():
        require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None, "publication asset name is malformed")
        require(type(data) is bytes, "publication asset bytes are malformed")
        snapshot = bytes(data)
        bound.append(BoundPublicationAsset(name, snapshot, hashlib.sha256(snapshot).hexdigest()))
    require(len({asset.name for asset in bound}) == len(bound), "duplicate publication asset name")
    return PublicationPlan(activation_sha, tuple(sorted(bound, key=lambda asset: asset.name)))


def _validate_plan(plan, expected_names=None):
    require(type(plan) is PublicationPlan and type(plan.assets) is tuple and plan.assets, "publication plan is malformed")
    require(type(plan.activation_sha) is str and HEX40.fullmatch(plan.activation_sha) is not None, "activation SHA is malformed")
    bound_assets = {}
    for asset in plan.assets:
        require(type(asset) is BoundPublicationAsset, "publication plan asset is malformed")
        require(type(asset.name) is str and re.fullmatch(r"[A-Za-z0-9_.-]+", asset.name) is not None, "publication plan asset name is malformed")
        require(type(asset.data) is bytes and HEX64.fullmatch(asset.sha256) is not None, "publication plan asset binding is malformed")
        require(asset.name not in bound_assets, "publication plan has duplicate assets")
        require(hashlib.sha256(asset.data).hexdigest() == asset.sha256, "publication plan asset binding mismatch")
        bound_assets[asset.name] = asset.data
    require(tuple(bound_assets) == tuple(sorted(bound_assets)), "publication plan asset order mismatch")
    if expected_names is not None:
        require(tuple(bound_assets) == tuple(sorted(expected_names)), "exact Authority-v2 publication asset set mismatch")
    return bound_assets


def _plan_binding_sha256(plan):
    bound_assets = _validate_plan(plan)
    digest = hashlib.sha256(b"acc-authority-v2-publication-plan\0")
    digest.update(plan.activation_sha.encode("ascii"))
    for name, data in bound_assets.items():
        encoded_name = name.encode("ascii")
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def reject_self_asserted_exclusivity(evidence):
    """No self-asserted or locally simulated exclusivity claim is ever evidence.

    Exclusivity would need a documented server-owned exclusive/CAS/atomic
    release transition. None exists, so every claim of exclusivity — however it
    labels its own source — is rejected outright.
    """
    raise SystemExit(
        "self-asserted or locally simulated publication exclusivity is not "
        "evidence: documented GitHub release APIs establish no exhaustive "
        "exclusive/compare-and-swap/atomic transition binding the exact "
        "activation SHA and verified immutable asset snapshots against every "
        "authorized writer, so F12 stays false and every publication write "
        f"stays prohibited (rejected claim: {type(evidence).__name__})"
    )


def _require_exclusive_transition_impossibility(contract):
    impossibility = contract.get("exclusive_transition_impossibility")
    require(
        type(impossibility) is dict
        and tuple(sorted(impossibility)) == EXCLUSIVE_TRANSITION_IMPOSSIBILITY_KEYS,
        "publication exclusive-transition impossibility block is malformed",
    )
    for name, expected in EXCLUSIVE_TRANSITION_IMPOSSIBILITY_FLAGS.items():
        require(
            impossibility[name] is expected,
            f"publication exclusive-transition impossibility {name} mismatch",
        )
    require(
        type(impossibility["reason"]) is str and impossibility["reason"]
        and type(impossibility["required_primitive"]) is str
        and impossibility["required_primitive"],
        "publication exclusive-transition impossibility is not stated exactly",
    )
    model = contract.get("known_writer_model")
    require(
        type(model) is dict and tuple(sorted(model)) == KNOWN_WRITER_MODEL_KEYS,
        "publication known-writer model is malformed",
    )
    require(
        model["exhaustive"] is False,
        "the known publication writer model may never claim to be exhaustive",
    )
    enumerated = model["enumerated_writer_classes"]
    unbounded = model["unbounded_writer_classes"]
    limits = model["limits"]
    require(
        type(enumerated) is list and enumerated
        and all(type(entry) is str and entry for entry in enumerated)
        and enumerated == sorted(enumerated),
        "publication enumerated writer classes are malformed",
    )
    require(
        type(unbounded) is list and unbounded
        and all(type(entry) is str and entry for entry in unbounded)
        and not set(unbounded) & set(enumerated),
        "publication writer model must keep at least one unbounded writer class",
    )
    require(
        type(limits) is list and limits
        and all(type(entry) is str and entry for entry in limits),
        "publication writer model limits are not stated exactly",
    )


def _require_authoritative_semantics(contract):
    """The documented semantics that keep every outcome non-authoritative."""
    citations = contract.get("authoritative_semantic_citations")
    require(
        type(citations) is list and len(citations) >= len(DOCUMENTED_CREATE_REF_STATUSES),
        "publication authoritative semantic citations are absent",
    )
    observed = set()
    for citation in citations:
        require(
            type(citation) is dict
            and tuple(sorted(citation)) == SEMANTIC_CITATION_KEYS,
            "publication semantic citation is malformed",
        )
        require(
            citation["proves_exclusivity"] is False,
            "no documented GitHub response may be cited as proof of exclusivity",
        )
        require(
            type(citation["source"]) is str
            and citation["source"].startswith(AUTHORITATIVE_DOCUMENTATION_PREFIX),
            "publication semantic citation is not an authoritative source",
        )
        require(
            type(citation["status"]) is int
            and type(citation["status"]) is not bool,
            "publication semantic citation status is malformed",
        )
        require(
            type(citation["documented_behaviour"]) is str
            and citation["documented_behaviour"]
            and type(citation["endpoint"]) is str and citation["endpoint"],
            "publication semantic citation is not stated exactly",
        )
        if citation["endpoint"] == CREATE_REF_ENDPOINT:
            require(
                citation["status"] not in observed,
                "publication semantics cite a create-ref status twice",
            )
            observed.add(citation["status"])
    require(
        sorted(observed) == sorted(DOCUMENTED_CREATE_REF_STATUSES),
        "publication semantics do not cite exactly the documented create-ref "
        "statuses",
    )


def _require_missing_writer_proof(contract):
    """The exhaustive live authorized-writer proof stays explicitly absent."""
    proof = contract.get("missing_exhaustive_writer_proof")
    require(
        type(proof) is dict and tuple(sorted(proof)) == MISSING_WRITER_PROOF_KEYS,
        "publication missing exhaustive-writer proof block is malformed",
    )
    require(
        proof["proof_available"] is False,
        "an exhaustive authorized-writer proof may never be claimed available",
    )
    require(
        proof["writer_set_is_unbounded"] is True,
        "the publication writer set may never be declared bounded",
    )
    require(
        proof["simulated_or_self_asserted_proof_rejected"] is True,
        "a simulated or self-asserted writer proof may never be accepted",
    )
    require(
        type(proof["required_proof"]) is str and proof["required_proof"]
        and type(proof["unavailable_because"]) is str
        and proof["unavailable_because"],
        "the missing exhaustive-writer proof is not stated exactly",
    )
    attempted = proof["attempted_live_inventory_endpoints"]
    require(
        type(attempted) is list and attempted,
        "no live authorized-writer inventory endpoint was even attempted",
    )
    for entry in attempted:
        require(
            type(entry) is dict
            and tuple(sorted(entry)) == ATTEMPTED_INVENTORY_KEYS,
            "attempted authorized-writer inventory entry is malformed",
        )
        require(
            all(
                type(entry[key]) is str and entry[key]
                for key in ATTEMPTED_INVENTORY_KEYS
            ),
            "attempted authorized-writer inventory entry is not stated exactly",
        )


def _require_publication_writer_exclusion(plan):
    _validate_plan(plan, EXPECTED_RELEASE_ASSET_NAMES)
    try:
        contract_data = WRITER_EXCLUSION_CONTRACT_PATH.read_bytes()
    except OSError as error:
        raise SystemExit("publication writer-exclusion contract is absent") from error
    contract = _closed_json(contract_data, "publication writer-exclusion contract")
    require(
        type(contract) is dict
        and contract.get("schema_version") == 1
        and contract.get("contract")
        == "acc-authority-v2-exclusive-publication-writer-precondition"
        and contract.get("repository") == EXPECTED_REPOSITORY,
        "publication writer-exclusion contract mismatch",
    )
    require(
        contract.get("github_release_cas_supported") is False
        and contract.get("documented_atomic_draft_asset_tag_transition_available")
        is False
        and contract.get("documented_exhaustive_writer_inventory_available") is False
        and contract.get("post_patch_race_detection_is_closure") is False,
        "publication writer-exclusion semantics mismatch",
    )
    precondition = contract.get("activation_precondition")
    require(
        type(precondition) is dict
        and precondition.get("state") == "unavailable"
        and precondition.get("no_fallback") is True
        and contract.get("irreversible_publication_forbidden") is True
        and contract.get("publication_writes_prohibited") is True
        and contract.get("every_publication_write_prohibited") is True
        and contract.get("publication_performed") is False,
        "publication writer-exclusion contract no longer prohibits publication",
    )
    require(
        contract.get("f12_closed") is False
        and contract.get("release_authorized") is False,
        "F12 and release authorization must both stay false",
    )
    require(
        contract.get("prohibited_writes") == list(PROHIBITED_PUBLICATION_WRITES),
        "publication prohibited-write inventory mismatch",
    )
    _require_exclusive_transition_impossibility(contract)
    _require_authoritative_semantics(contract)
    _require_missing_writer_proof(contract)


def _publication_claim_digest(authenticated_issuance):
    issuance_type = AUTHORITY.GITHUB_ISSUANCE.AuthenticatedIssuance
    require(type(authenticated_issuance) is issuance_type,
            "publication claim requires authenticated issuance")
    require(type(authenticated_issuance.issuance_nonce) is str
            and HEX64.fullmatch(authenticated_issuance.issuance_nonce) is not None,
            "publication claim nonce is malformed")
    require(type(authenticated_issuance.sha256) is str
            and HEX64.fullmatch(authenticated_issuance.sha256) is not None,
            "publication claim issuance digest is malformed")
    claim = hashlib.sha256(b"acc-authority-v2-publication-claim\0")
    claim.update(authenticated_issuance.issuance_nonce.encode("ascii"))
    claim.update(authenticated_issuance.sha256.encode("ascii"))
    return claim.hexdigest()


def _publication_claim_payload(authenticated_issuance, plan, guards, draft_id):
    require(type(draft_id) is int and type(draft_id) is not bool and draft_id > 0,
            "publication claim draft id is malformed")
    require(type(guards) is PublicationGuards, "publication claim guards are malformed")
    _validate_plan(plan, EXPECTED_RELEASE_ASSET_NAMES)
    return {
        "schema_version": 2,
        "claim_type": "acc-authority-v2-durable-publication-state",
        "issuance": {
            "nonce": authenticated_issuance.issuance_nonce,
            "sha256": authenticated_issuance.sha256,
            "nonce_issuance_sha256": _publication_claim_digest(authenticated_issuance),
        },
        "draft_id": draft_id,
        "release": {
            "tag": RELEASE_TAG,
            "target_commitish": plan.activation_sha,
            "name": RELEASE_TITLE,
            "body": RELEASE_NOTES,
            "prerelease": False,
        },
        "asset_plan": [
            {"name": asset.name, "size": len(asset.data), "sha256": asset.sha256}
            for asset in plan.assets
        ],
        "publication_plan_sha256": _plan_binding_sha256(plan),
        "guards": {
            "immutable_releases_sha256": guards.immutable_releases_sha256,
            "tag_ruleset": {
                "ruleset_id": guards.tag_ruleset.ruleset_id,
                "etag": guards.tag_ruleset.etag,
                "canonical_sha256": guards.tag_ruleset.canonical_sha256,
            },
        },
    }


def _publication_claim_message(authenticated_issuance, plan, guards, draft_id):
    payload = _publication_claim_payload(
        authenticated_issuance, plan, guards, draft_id,
    )
    return "acc-authority-v2-publication-claim-v2\n" + _json_bytes(payload).decode("utf-8")


def _parse_publication_claim_message(message, authenticated_issuance, plan, guards):
    prefix = "acc-authority-v2-publication-claim-v2\n"
    require(type(message) is str and message.startswith(prefix),
            "publication claim message identity mismatch")
    payload_data = message[len(prefix):].encode("utf-8")
    payload = _closed_json(payload_data, "publication claim message")
    require(payload_data == _json_bytes(payload),
            "publication claim message is not canonical exact JSON")
    draft_id = payload.get("draft_id") if type(payload) is dict else None
    require(type(draft_id) is int and type(draft_id) is not bool and draft_id > 0,
            "publication claim draft id is malformed")
    expected = _publication_claim_payload(
        authenticated_issuance, plan, guards, draft_id,
    )
    require(payload == expected, "publication claim state binding mismatch")
    return draft_id


def _write_private_snapshot(directory, name, data):
    path = directory / name
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                require(written > 0, "publication snapshot write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o600)
        return path
    except OSError as error:
        raise SystemExit(f"publication snapshot failed: {name}") from error


def _validate_reviewed_public_assets(bound_assets):
    for asset_name, repository_path in REVIEWED_PUBLIC_ASSET_PATHS.items():
        reviewed_bytes = _read_asset(AUTHORITY.ROOT / repository_path)
        require(bound_assets[asset_name] == reviewed_bytes, f"reviewed public asset byte mismatch: {asset_name}")


def _verify_snapshot_postcondition(snapshot_paths, bound_assets):
    for name, path in snapshot_paths.items():
        try:
            observed = path.lstat()
        except OSError as error:
            raise SystemExit(f"publication verification snapshot disappeared: {name}") from error
        require(stat.S_ISREG(observed.st_mode) and not stat.S_ISLNK(observed.st_mode), f"publication verification snapshot is malformed: {name}")
        require(stat.S_IMODE(observed.st_mode) == 0o600, f"publication verification snapshot mode mismatch: {name}")
        require(path.read_bytes() == bound_assets[name], f"publication verification snapshot changed: {name}")


def verify_publication_plan(
        plan, review_receipt_sha256, cosign_path, authenticated_issuance):
    bound_assets = _validate_plan(plan, EXPECTED_RELEASE_ASSET_NAMES)
    require(type(authenticated_issuance) is AUTHORITY.GITHUB_ISSUANCE.AuthenticatedIssuance,
            "publication requires authenticated GitHub issuance")
    require(authenticated_issuance.candidate_head == plan.activation_sha
            and authenticated_issuance.review_receipt_sha256 == review_receipt_sha256,
            "publication issuance candidate/reviewer binding mismatch")
    require(type(review_receipt_sha256) is str and HEX64.fullmatch(review_receipt_sha256) is not None, "preissuance review receipt hash is malformed")
    receipt_name = "preissuance-review-receipt.json"
    require(hashlib.sha256(bound_assets[receipt_name]).hexdigest() == review_receipt_sha256, "preissuance review receipt hash mismatch")
    _validate_reviewed_public_assets(bound_assets)

    approved_cosign = AUTHORITY.validate_cosign_binary(cosign_path)
    try:
        with tempfile.TemporaryDirectory(prefix="authority-v2-publication-") as temporary_directory:
            snapshot_root = Path(temporary_directory)
            os.chmod(snapshot_root, 0o700)
            release_root = snapshot_root / "release"
            review_root = snapshot_root / "review"
            release_root.mkdir(mode=0o700)
            review_root.mkdir(mode=0o700)
            snapshot_paths = {
                name: _write_private_snapshot(release_root, name, bound_assets[name])
                for name in RELEASE_EVIDENCE_ASSET_NAMES
            }
            snapshot_paths[receipt_name] = _write_private_snapshot(
                review_root, receipt_name, bound_assets[receipt_name]
            )
            review_bundle_name = "preissuance-review-receipt.sigstore.json"
            snapshot_paths[review_bundle_name] = _write_private_snapshot(
                review_root, review_bundle_name, bound_assets[review_bundle_name]
            )
            receipt_snapshot = AUTHORITY._bind_file(snapshot_paths[receipt_name])
            review_bundle_snapshot = AUTHORITY._bind_file(
                snapshot_paths[review_bundle_name]
            )
            try:
                AUTHORITY._authenticate_review_receipt_with_cosign(
                    receipt_snapshot, review_bundle_snapshot, approved_cosign,
                )
            finally:
                os.close(receipt_snapshot.descriptor)
                os.close(review_bundle_snapshot.descriptor)
            AUTHORITY.verify_release(
                release_root,
                plan.activation_sha,
                snapshot_paths[receipt_name],
                review_receipt_sha256,
                approved_cosign,
                authenticated_issuance,
            )
            _verify_snapshot_postcondition(snapshot_paths, bound_assets)
        _validate_plan(plan, EXPECTED_RELEASE_ASSET_NAMES)
        return plan
    finally:
        if type(approved_cosign) is AUTHORITY.VerifiedCosign:
            approved_cosign.close()


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        redirected = super().redirect_request(request, file_pointer, code, message, headers, new_url)
        if redirected is None:
            return None
        old = urllib.parse.urlparse(request.full_url)
        new = urllib.parse.urlparse(new_url)
        require(new.scheme == "https", "GitHub API redirect is not HTTPS")
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            redirected.remove_header("Authorization")
        return redirected


def _closed_json(data, label):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(type(key) is str and key not in result, f"{label} has duplicate or non-string member")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit(f"{label} is not valid UTF-8 JSON") from error


def _json_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class GitHubTransport:
    """Minimal GitHub REST transport that preserves every HTTP status."""

    def __init__(self, token):
        require(type(token) is str and token != "", "GitHub token is absent")
        self._token = token
        self._opener = urllib.request.build_opener(_SafeRedirectHandler())

    def request(self, method, path, *, headers=None, body=None):
        url = path if path.startswith("https://") else f"https://api.github.com{path}"
        request_headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        request_headers.update(headers or {})
        request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
        try:
            with self._opener.open(request, timeout=30) as response:
                return ApiResponse(response.status, dict(response.headers.items()), response.read())
        except urllib.error.HTTPError as error:
            try:
                response_body = error.read()
            except OSError:
                response_body = b""
            return ApiResponse(error.code, dict(error.headers.items()), response_body)
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            raise TransportError("GitHub API transport outcome is ambiguous") from error


def _guard_resource_path(path):
    parsed = urllib.parse.urlparse(path)
    expected_host = (
        (parsed.scheme == "" and parsed.netloc == "")
        or (parsed.scheme == "https" and parsed.netloc == "api.github.com")
    )
    if not expected_host or parsed.fragment != "":
        return parsed, None
    return parsed, parsed.path


def _targets_publication_guard_resource(path):
    _, api_path = _guard_resource_path(path)
    if api_path is None:
        return False
    ruleset_base = f"/repos/{EXPECTED_REPOSITORY}/rulesets"
    return (
        api_path == f"/repos/{EXPECTED_REPOSITORY}/immutable-releases"
        or api_path == ruleset_base
        or api_path.startswith(f"{ruleset_base}/")
    )


def _is_publication_guard_path(method, path):
    parsed, api_path = _guard_resource_path(path)
    if api_path is None:
        return False
    ruleset_base = f"/repos/{EXPECTED_REPOSITORY}/rulesets"
    if method != "GET":
        return False
    if api_path == f"/repos/{EXPECTED_REPOSITORY}/immutable-releases":
        return parsed.query == ""
    if api_path == ruleset_base:
        return parsed.query == (
            "includes_parents=false&targets=tag&per_page=100&page=1"
        )
    return (
        re.fullmatch(rf"{re.escape(ruleset_base)}/[1-9][0-9]*", api_path)
        is not None
        and parsed.query == "includes_parents=false"
    )


class AdministrationReadAppTransport:
    """Environment-gated GitHub App transport limited to guard GETs."""

    def __init__(self, backend):
        require(hasattr(backend, "request"), "administration-read App transport is absent")
        self._backend = backend

    def request(self, method, path, *, headers=None, body=None):
        require(
            _is_publication_guard_path(method, path) and body is None,
            "administration-read App transport is limited to publication guard GETs",
        )
        return self._backend.request(method, path, headers=headers, body=body)


class PublicationReadTransport:
    """Read-only repository transport.

    Authority-v2 publication is unavailable, so this transport structurally
    prohibits every draft, asset, tag and claim mutation. It also can never
    service administration guard reads.
    """

    def __init__(self, backend):
        require(hasattr(backend, "request"), "publication read transport is absent")
        self._backend = backend

    def request(self, method, path, *, headers=None, body=None):
        require(
            method == "GET" and body is None,
            "publication is unavailable: every release mutation is prohibited",
        )
        require(
            not _targets_publication_guard_resource(path),
            "publication read transport cannot service administration guard reads",
        )
        return self._backend.request(method, path, headers=headers, body=body)


def verify_runtime_context(environment, activation_sha):
    require(isinstance(environment, Mapping), "runtime environment is malformed")
    require(type(activation_sha) is str and HEX40.fullmatch(activation_sha) is not None, "activation SHA is malformed")
    require(environment.get("GITHUB_REPOSITORY") == EXPECTED_REPOSITORY, "runtime repository mismatch")
    require(environment.get("GITHUB_REF") == EXPECTED_REF, "publication is main-only")
    require(environment.get("GITHUB_EVENT_NAME") == EXPECTED_TRIGGER, "publication requires workflow_dispatch")
    require(environment.get("GITHUB_SHA") == activation_sha, "runtime activation SHA mismatch")


def _header(headers, requested_name):
    matches = [value for name, value in headers.items() if name.lower() == requested_name.lower()]
    require(len(matches) == 1 and type(matches[0]) is str, f"missing or duplicate {requested_name} header")
    return matches[0]


def _strong_etag(response, label="release"):
    etag = _header(response.headers, "ETag")
    require(
        STRONG_ETAG.fullmatch(etag) is not None and not etag.startswith("W/"),
        f"{label} ETag is missing or weak",
    )
    return etag


def _asset_api_path(url, asset_id):
    expected_path = f"/repos/{EXPECTED_REPOSITORY}/releases/assets/{asset_id}"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme:
        require(parsed.scheme == "https" and parsed.netloc == "api.github.com", "asset API host mismatch")
        require(parsed.query == "" and parsed.fragment == "", "asset API URL has unexpected components")
        path = parsed.path
    else:
        path = url
    require(path == expected_path, "asset API path mismatch")
    return path


def _release_assets(payload, expected_names):
    assets = payload.get("assets")
    require(type(assets) is list, "release assets have wrong JSON type")
    observed = {}
    for asset in assets:
        require(type(asset) is dict, "release asset is malformed")
        name = asset.get("name")
        asset_id = asset.get("id")
        url = asset.get("url")
        require(type(name) is str and type(asset_id) is int and type(asset_id) is not bool and type(url) is str, "release asset identity has wrong JSON type")
        require(name not in observed, "duplicate release asset name")
        observed[name] = _asset_api_path(url, asset_id)
    require(tuple(sorted(observed)) == tuple(sorted(expected_names)), "release asset set mismatch")
    return observed


def _validate_release(payload, *, release_id, activation_sha, draft, immutable, expected_names):
    require(type(payload) is dict, "release response has wrong JSON type")
    exact = {
        "id": release_id,
        "tag_name": RELEASE_TAG,
        "target_commitish": activation_sha,
        "name": RELEASE_TITLE,
        "body": RELEASE_NOTES,
        "draft": draft,
        "prerelease": False,
        "immutable": immutable,
    }
    for field, expected in exact.items():
        observed = payload.get(field)
        require(type(observed) is type(expected), f"release {field} has wrong JSON type")
        require(observed == expected, f"release {field} mismatch")
    return _release_assets(payload, expected_names)


def _validate_tag(payload, activation_sha):
    require(type(payload) is dict, "tag response has wrong JSON type")
    require(payload.get("ref") == EXACT_TAG_REF, "tag ref mismatch")
    target = payload.get("object")
    require(type(target) is dict, "tag target is malformed")
    require(target.get("type") == "commit" and target.get("sha") == activation_sha, "tag target mismatch")


def _canonical_sha256(payload):
    return hashlib.sha256(_json_bytes(payload)).hexdigest()


def _validate_immutable_releases(payload):
    require(type(payload) is dict, "immutable releases response has wrong JSON type")
    require(
        set(payload) == {"enabled", "enforced_by_owner"},
        "immutable releases response field set mismatch",
    )
    require(type(payload["enabled"]) is bool, "immutable releases enabled state is malformed")
    require(
        type(payload["enforced_by_owner"]) is bool,
        "immutable releases owner enforcement state is malformed",
    )
    require(payload["enabled"] is True, "repository immutable releases are not enabled")
    return _canonical_sha256(payload)


def _exact_tag_conditions():
    return {
        "ref_name": {
            "include": [EXACT_TAG_REF, PUBLICATION_CLAIM_REF],
            "exclude": [],
        }
    }


def _targets_exact_tag(payload):
    return (
        type(payload) is dict
        and payload.get("target") == "tag"
        and payload.get("conditions") == _exact_tag_conditions()
    )


def _validate_tag_ruleset(payload, expected_id, etag):
    require(type(payload) is dict, "full tag ruleset has wrong JSON type")
    require(
        type(payload.get("id")) is int
        and type(payload.get("id")) is not bool
        and payload["id"] == expected_id,
        "full tag ruleset id mismatch",
    )
    require(type(payload.get("name")) is str and payload["name"] != "", "full tag ruleset name is malformed")
    require(payload.get("target") == "tag", "full ruleset does not target tags")
    require(payload.get("source_type") == "Repository", "tag ruleset source type mismatch")
    require(payload.get("source") == EXPECTED_REPOSITORY, "tag ruleset repository source mismatch")
    require(payload.get("enforcement") == "active", "tag ruleset is not active")
    require(payload.get("bypass_actors") == [], "tag ruleset bypass actors are present or unreadable")
    require(payload.get("conditions") == _exact_tag_conditions(), "tag ruleset does not target only the exact release tag")

    rules = payload.get("rules")
    require(type(rules) is list, "tag ruleset rules are malformed")
    by_type = {}
    for rule in rules:
        require(type(rule) is dict and type(rule.get("type")) is str, "tag ruleset rule is malformed")
        rule_type = rule["type"]
        require(rule_type not in by_type, "tag ruleset contains duplicate rule types")
        by_type[rule_type] = rule
    require(set(by_type) == {"deletion", "update"}, "tag ruleset must allow creation and prohibit only update and deletion")
    require(by_type["deletion"] == {"type": "deletion"}, "tag deletion rule is malformed")
    require(
        by_type["update"] == {
            "type": "update",
            "parameters": {"update_allows_fetch_and_merge": False},
        },
        "tag update rule is malformed",
    )
    return TagRulesetBinding(
        ruleset_id=expected_id,
        etag=etag,
        canonical_sha256=_canonical_sha256(payload),
    )


def _ruleset_ids(response):
    link_headers = [
        value
        for name, value in response.headers.items()
        if type(name) is str and name.lower() == "link"
    ]
    require(
        len(link_headers) <= 1
        and all(type(value) is str for value in link_headers),
        "tag ruleset pagination header is malformed",
    )
    require(
        not link_headers or 'rel="next"' not in link_headers[0],
        "tag ruleset list pagination is ambiguous",
    )
    summaries = _closed_json(response.body, "tag ruleset list")
    require(
        type(summaries) is list and len(summaries) < 100,
        "tag ruleset list is malformed or incomplete",
    )
    ruleset_ids = []
    for summary in summaries:
        require(type(summary) is dict, "tag ruleset summary is malformed")
        ruleset_id = summary.get("id")
        require(
            type(ruleset_id) is int
            and type(ruleset_id) is not bool
            and ruleset_id > 0,
            "tag ruleset summary id is malformed",
        )
        require(ruleset_id not in ruleset_ids, "duplicate tag ruleset summary id")
        ruleset_ids.append(ruleset_id)
    return tuple(ruleset_ids)


class PublicationService:
    """Read-only publication reconciler.

    Authority-v2 publication is unavailable: GitHub documents no durable
    server-owned pre-draft state and no atomic draft-to-immutable transition,
    so no draft, asset, tag or claim write exists here at all. What remains is
    an exact, idempotent, write-free reconciliation of whatever publication
    state a repository is already in.
    """

    def __init__(self, read_transport, guard_transport):
        require(
            type(read_transport) is PublicationReadTransport,
            "publication read transport role mismatch",
        )
        require(
            type(guard_transport) is AdministrationReadAppTransport,
            "publication guard transport role mismatch",
        )
        require(
            read_transport is not guard_transport,
            "publication transport roles must be distinct",
        )
        self._read_transport = read_transport
        self._guard_transport = guard_transport

    def _request_with(self, transport, method, path, *, headers=None, body=None):
        try:
            response = transport.request(method, path, headers=headers, body=body)
        except TransportError as error:
            raise SystemExit("publication transport outcome is ambiguous") from error
        except SystemExit:
            raise
        except Exception as error:
            raise SystemExit("publication transport failed closed") from error
        require(type(response) is ApiResponse, "publication transport returned an invalid response")
        require(type(response.status) is int and type(response.status) is not bool, "publication HTTP status is malformed")
        require(type(response.headers) is dict and type(response.body) is bytes, "publication response is malformed")
        return response

    def _request(self, method, path, *, headers=None, body=None):
        return self._request_with(
            self._read_transport, method, path, headers=headers, body=body,
        )

    def _guard_request(self, method, path, *, headers=None, body=None):
        return self._request_with(
            self._guard_transport, method, path, headers=headers, body=body,
        )

    def _immutable_releases_binding(self):
        path = f"/repos/{EXPECTED_REPOSITORY}/immutable-releases"
        response = self._guard_request("GET", path)
        require(response.status == 200, "immutable releases readback did not return HTTP 200")
        payload = _closed_json(response.body, "immutable releases response")
        return _validate_immutable_releases(payload)

    def _tag_ruleset_binding(self):
        base_path = f"/repos/{EXPECTED_REPOSITORY}/rulesets"
        response = self._guard_request(
            "GET",
            f"{base_path}?includes_parents=false&targets=tag&per_page=100&page=1",
        )
        require(response.status == 200, "tag ruleset list did not return HTTP 200")
        full_rulesets = self._read_full_rulesets(base_path, _ruleset_ids(response))
        matches = [item for item in full_rulesets if _targets_exact_tag(item[1])]
        require(len(matches) == 1, "exact-tag protection ruleset is absent or ambiguous")
        ruleset_id, payload, detail = matches[0]
        return _validate_tag_ruleset(
            payload, ruleset_id, _strong_etag(detail, "tag ruleset")
        )

    def _read_full_rulesets(self, base_path, ruleset_ids):
        full_rulesets = []
        for ruleset_id in ruleset_ids:
            detail = self._guard_request(
                "GET", f"{base_path}/{ruleset_id}?includes_parents=false"
            )
            require(detail.status == 200, "full tag ruleset read did not return HTTP 200")
            payload = _closed_json(detail.body, "full tag ruleset")
            require(
                type(payload) is dict
                and type(payload.get("id")) is int
                and type(payload.get("id")) is not bool
                and payload["id"] == ruleset_id,
                "full tag ruleset identity mismatch",
            )
            full_rulesets.append((ruleset_id, payload, detail))
        return tuple(full_rulesets)

    def _publication_guards(self):
        return PublicationGuards(
            immutable_releases_sha256=self._immutable_releases_binding(),
            tag_ruleset=self._tag_ruleset_binding(),
        )

    def _snapshot(self, release_id):
        path = f"/repos/{EXPECTED_REPOSITORY}/releases/{release_id}"
        response = self._request("GET", path)
        require(response.status == 200, "release snapshot read did not return HTTP 200")
        return _closed_json(response.body, "release snapshot"), _strong_etag(response)

    def _exhaustive_releases(self):
        """Documented paginated release listing; drafts are included for push access."""
        releases = []
        for page in range(1, MAX_RELEASE_PAGES + 1):
            response = self._request(
                "GET",
                f"/repos/{EXPECTED_REPOSITORY}/releases?per_page={RELEASE_PAGE_SIZE}&page={page}",
            )
            require(response.status == 200, "release listing did not return HTTP 200")
            payload = _closed_json(response.body, "release listing")
            require(type(payload) is list, "release listing has wrong JSON type")
            releases.extend(payload)
            if len(payload) < RELEASE_PAGE_SIZE:
                return tuple(releases)
        raise SystemExit("release listing exceeded the exhaustive reconciliation bound")

    def _matching_release(self, activation_sha, expected_names):
        matches = []
        for payload in self._exhaustive_releases():
            require(type(payload) is dict, "listed release has wrong JSON type")
            if payload.get("tag_name") != RELEASE_TAG:
                continue
            release_id = payload.get("id")
            require(
                type(release_id) is int and type(release_id) is not bool and release_id > 0,
                "listed release id is malformed",
            )
            matches.append(release_id)
        require(len(matches) <= 1, "publication reconciliation found colliding releases")
        if not matches:
            return None
        release_id = matches[0]
        snapshot, _ = self._snapshot(release_id)
        draft = snapshot.get("draft") if type(snapshot) is dict else None
        immutable = snapshot.get("immutable") if type(snapshot) is dict else None
        require(type(draft) is bool and type(immutable) is bool,
                "reconciled release state is malformed")
        assets = _validate_release(
            snapshot, release_id=release_id, activation_sha=activation_sha,
            draft=draft, immutable=immutable, expected_names=expected_names,
        )
        return {"id": release_id, "draft": draft, "immutable": immutable,
                "asset_paths": assets}

    def _asset_digests(self, asset_paths):
        digests = {}
        for name in sorted(asset_paths):
            response = self._request(
                "GET", asset_paths[name],
                headers={"Accept": "application/octet-stream"},
            )
            require(response.status == 200, f"asset download failed closed: {name}")
            digests[name] = hashlib.sha256(response.body).hexdigest()
        return digests

    def _read_tag_ref_visibility(self):
        """Exhaustively traverse the exact matching-refs endpoint, read-only.

        Absence is proven only by a deterministic bounded traversal in which
        every page is an authenticated HTTP 200, the pagination metadata is
        well formed, monotonic and non-looping, every ref carries the exact
        expected prefix, and the documented last page ends the traversal. Any
        other outcome returns incomplete evidence, which classifies as
        readback_ambiguous and prohibits all retry and write progression.
        """
        incomplete = {
            "authenticated": True,
            "complete": False,
            "pages": 0,
            "prefix": TAG_REF_PREFIX,
            "refs": None,
            "status": None,
        }
        refs = []
        page = 1
        for visited in range(1, MAX_TAG_REF_PAGES + 1):
            try:
                response = self._request(
                    "GET", tag_ref_visibility_page_path(page),
                )
            except SystemExit:
                return dict(incomplete, pages=visited - 1)
            if response.status != 200:
                return dict(incomplete, pages=visited - 1, status=response.status)
            try:
                payload = _closed_json(response.body, "tag ref visibility listing")
            except SystemExit:
                return dict(incomplete, pages=visited - 1, status=200)
            if type(payload) is not list:
                return dict(incomplete, pages=visited - 1, status=200)
            for entry in payload:
                if type(entry) is not dict:
                    return dict(incomplete, pages=visited - 1, status=200)
                name = entry.get("ref")
                if (
                    type(name) is not str
                    or not name
                    or not name.startswith(TAG_REF_PREFIX)
                ):
                    return dict(incomplete, pages=visited - 1, status=200)
            refs.extend(payload)
            next_page, state = parse_next_visibility_page(response.headers, page)
            if state == "malformed":
                return dict(incomplete, pages=visited, status=200)
            if state == "complete":
                return {
                    "authenticated": True,
                    "complete": True,
                    "pages": visited,
                    "prefix": TAG_REF_PREFIX,
                    "refs": refs,
                    "status": 200,
                }
            page = next_page
        # The advertised traversal never terminated inside the bound.
        return dict(incomplete, pages=MAX_TAG_REF_PAGES, status=200)

    def _read_ref(self, tag):
        encoded = urllib.parse.quote(tag, safe="")
        expected_ref = f"refs/tags/{tag}"
        response = self._request(
            "GET", f"/repos/{EXPECTED_REPOSITORY}/git/ref/tags/{encoded}",
        )
        absence_evidence = None
        if response.status == 404:
            absence_evidence = self._read_tag_ref_visibility()
        read_state = classify_ref_read(
            response.status,
            absence_evidence=absence_evidence,
            expected_ref=expected_ref,
        )
        require(
            read_state in ("confirmed_absent", "confirmed_present"),
            "tag ref read is not a documented authenticated HTTP 200, and no "
            "exhaustively paginated authenticated visibility listing confirms "
            f"absence: {read_state} ({expected_ref})",
        )
        if read_state == "confirmed_absent":
            return None
        return _closed_json(response.body, "tag ref readback")

    def _read_claim_tag_object(self, ref_payload):
        """Resolve the annotated tag object the claim ref names, or None."""
        if type(ref_payload) is not dict:
            return None
        ref_object = ref_payload.get("object")
        if type(ref_object) is not dict:
            return None
        if ref_object.get("type") != "tag":
            return None
        tag_object_sha = ref_object.get("sha")
        if type(tag_object_sha) is not str or HEX40.fullmatch(tag_object_sha) is None:
            return None
        tag_response = self._request(
            "GET", f"/repos/{EXPECTED_REPOSITORY}/git/tags/{tag_object_sha}",
        )
        require(tag_response.status == 200,
                "publication claim tag-object read did not return HTTP 200")
        return _closed_json(
            tag_response.body, "publication claim tag-object readback",
        )

    def _read_publication_claim(self, authenticated_issuance, plan, guards):
        ref_payload = self._read_ref(PUBLICATION_CLAIM_TAG)
        if ref_payload is None:
            return None
        tag_payload = self._read_claim_tag_object(ref_payload)
        request_identity = _publication_claim_digest(authenticated_issuance)
        plan_sha256 = _plan_binding_sha256(plan)
        state = classify_claim_readback(
            ref_payload, tag_payload,
            expected_ref=PUBLICATION_CLAIM_REF,
            expected_tag=PUBLICATION_CLAIM_TAG,
            expected_target=plan.activation_sha,
            expected_request_identity=request_identity,
            expected_plan_sha256=plan_sha256,
        )
        require(
            state == "created_by_this_attempt",
            f"publication claim readback is not authoritative: {state}",
        )
        draft_id = _parse_publication_claim_message(
            tag_payload.get("message"), authenticated_issuance, plan, guards,
        )
        expected_message = _publication_claim_message(
            authenticated_issuance, plan, guards, draft_id,
        )
        require(
            expected_message == tag_payload.get("message"),
            "publication claim message is not the exact reconstructed claim",
        )
        # Bind the exact annotated tag object this request identity implies, so
        # a different tag object carrying the same payload, target and message
        # can never be accepted as this attempt's claim.
        expected_tag_object_sha = expected_claim_tag_object_sha(
            plan.activation_sha, expected_message,
        )
        bound_state = classify_claim_readback(
            ref_payload, tag_payload,
            expected_ref=PUBLICATION_CLAIM_REF,
            expected_tag=PUBLICATION_CLAIM_TAG,
            expected_target=plan.activation_sha,
            expected_request_identity=request_identity,
            expected_plan_sha256=plan_sha256,
            expected_tag_object_sha=expected_tag_object_sha,
            expected_message=expected_message,
        )
        require(
            bound_state == "created_by_this_attempt",
            f"publication claim readback is not authoritative: {bound_state}",
        )
        payload = _publication_claim_payload(
            authenticated_issuance, plan, guards, draft_id,
        )
        return {"tag_object_sha": expected_tag_object_sha, **payload}

    def reconcile(self, authenticated_issuance, plan):
        """Exactly and idempotently discover every publication state; write nothing.

        Accepts only these exact states: unpublished (no release, no tag),
        unclaimed_draft (mutable draft, no tag), claimed_draft (mutable draft
        with claim, no tag), or published (immutable, not draft, final tag).
        Any other combination is rejected as irrecoverable partial state.
        """
        require(
            type(authenticated_issuance) is AUTHORITY.GITHUB_ISSUANCE.AuthenticatedIssuance,
            "publication reconciliation requires authenticated GitHub issuance",
        )
        bound_assets = _validate_plan(plan, EXPECTED_RELEASE_ASSET_NAMES)
        expected_names = tuple(sorted(bound_assets))
        expected_hashes = {asset.name: asset.sha256 for asset in plan.assets}
        activation_sha = plan.activation_sha

        guards = self._publication_guards()
        release = self._matching_release(activation_sha, expected_names)
        claim = self._read_publication_claim(authenticated_issuance, plan, guards)
        final_ref = self._read_ref(RELEASE_TAG)
        if final_ref is not None:
            _validate_tag(final_ref, activation_sha)

        draft = None
        if release is not None:
            digests = self._asset_digests(release["asset_paths"])
            require(digests == expected_hashes,
                    "reconciled release assets do not match the reviewed plan")
            draft = {
                "id": release["id"],
                "draft": release["draft"],
                "immutable": release["immutable"],
                "assets": digests,
            }
        if claim is not None:
            require(draft is not None and claim["draft_id"] == draft["id"],
                    "durable publication claim does not reference the discovered draft")

        if release is not None and release["immutable"] and not release["draft"]:
            require(final_ref is not None,
                    "published immutable release lacks final tag")
            state = "published"
        elif release is None:
            require(final_ref is None,
                    "final tag present but no release exists")
            state = "unpublished"
        elif release["draft"] and not release["immutable"]:
            require(final_ref is None,
                    "irrecoverable partial state: mutable draft with final tag present")
            if claim is not None:
                state = "claimed_draft"
            else:
                state = "unclaimed_draft"
        else:
            raise SystemExit(
                "irrecoverable partial publication state: draft="
                + str(release["draft"]) + " immutable="
                + str(release["immutable"]) + " final_tag="
                + str(final_ref is not None)
            )
        return {
            "publication_state": state,
            "publication_available": False,
            "draft": draft,
            "claim": claim,
            "final_tag": None if final_ref is None else {
                "ref": EXACT_TAG_REF, "target": activation_sha,
            },
            "guards": {
                "immutable_releases_sha256": guards.immutable_releases_sha256,
                "tag_ruleset": {
                    "ruleset_id": guards.tag_ruleset.ruleset_id,
                    "etag": guards.tag_ruleset.etag,
                    "canonical_sha256": guards.tag_ruleset.canonical_sha256,
                },
            },
            "asset_plan": [
                {"name": asset.name, "size": len(asset.data), "sha256": asset.sha256}
                for asset in plan.assets
            ],
            "publication_plan_sha256": _plan_binding_sha256(plan),
            "release_tag": RELEASE_TAG,
            "target_commitish": activation_sha,
            "writes_performed": 0,
            "remediation": PUBLICATION_UNAVAILABLE_REMEDIATION,
        }

    def publish(self, authenticated_issuance, assets, review_receipt_sha256, cosign_path):
        """Verify everything, then fail closed: no publication write exists."""
        _publication_preflight(
            authenticated_issuance, assets, review_receipt_sha256, cosign_path,
        )
        raise SystemExit(
            "Authority-v2 publication is unavailable: draft creation, asset upload, "
            "tag creation and durable claim writes are prohibited. "
            + PUBLICATION_UNAVAILABLE_REMEDIATION
        )


def _read_asset(path):
    path = Path(path)
    try:
        observed = path.lstat()
        require(stat.S_ISREG(observed.st_mode) and not stat.S_ISLNK(observed.st_mode), f"publication asset is not a regular non-symlink file: {path.name}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_mode, item.st_size,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            require(identity(observed) == identity(opened), f"publication asset changed while opening: {path.name}")
            chunks = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            require(identity(os.fstat(descriptor)) == identity(opened), f"publication asset changed while reading: {path.name}")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise SystemExit(f"publication asset binding failed: {path.name}") from error


def _parse_assets(specifications):
    assets = {}
    for specification in specifications:
        require("=" in specification, "asset must use NAME=PATH")
        name, raw_path = specification.split("=", 1)
        require(name not in assets, "duplicate publication asset name")
        assets[name] = _read_asset(raw_path)
    require(tuple(sorted(assets)) == tuple(sorted(EXPECTED_RELEASE_ASSET_NAMES)), "exact Authority-v2 publication asset set mismatch")
    return assets


def _authenticate_issuance_asset(path, issuance_sha256, activation_sha, review_receipt_sha256):
    data = _read_asset(path)
    payload = _closed_json(data, "authenticated GitHub issuance")
    require(data == AUTHORITY.GITHUB_ISSUANCE.canonical(payload),
            "authenticated GitHub issuance is not canonical exact bytes")
    candidate = payload.get("candidate") if type(payload) is dict else None
    require(type(candidate) is dict and set(candidate) == {
        "head_commit", "head_tree", "canonical_diff_sha256",
    }, "authenticated GitHub issuance candidate field set mismatch")
    expected_candidate = {
        "head_commit": activation_sha,
        "head_tree": candidate["head_tree"],
        "canonical_diff_sha256": candidate["canonical_diff_sha256"],
        "review_receipt_sha256": review_receipt_sha256,
    }
    return AUTHORITY.GITHUB_ISSUANCE.verify_authenticated_issuance_bytes(
        data, issuance_sha256, expected_candidate,
    )


def _publication_preflight(authenticated_issuance, assets,
                           review_receipt_sha256, cosign_path):
    """Every non-mutating publication proof, in one place, transport-free.

    The publish path and the verify-only path run exactly this: authenticated
    issuance re-verification against the exact candidate bindings, the bound
    publication plan over the complete release asset inventory, the full plan
    verification - manifest bytes, every subject and bundle, the preissuance
    receipt and the pinned Cosign snapshot - and the writer exclusion proof.
    No transport is constructed here and no write is reachable from it.
    """
    require(
        type(authenticated_issuance)
        is AUTHORITY.GITHUB_ISSUANCE.AuthenticatedIssuance,
        "publication requires authenticated GitHub issuance",
    )
    expected_candidate = {
        "head_commit": authenticated_issuance.candidate_head,
        "head_tree": authenticated_issuance.candidate_tree,
        "canonical_diff_sha256": authenticated_issuance.canonical_diff_sha256,
        "review_receipt_sha256": review_receipt_sha256,
    }
    authenticated_issuance = (
        AUTHORITY.GITHUB_ISSUANCE.verify_authenticated_issuance_bytes(
            authenticated_issuance.data, authenticated_issuance.sha256,
            expected_candidate,
        )
    )
    plan = bind_publication(authenticated_issuance.candidate_head, assets)
    plan = verify_publication_plan(
        plan, review_receipt_sha256, cosign_path, authenticated_issuance,
    )
    _require_publication_writer_exclusion(plan)
    return plan


SOURCE_CHAIN_BLOCKER = "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"


def _activation_module():
    """The Authority's own activation verifier, loaded from the candidate."""
    import importlib.util
    path = AUTHORITY.ROOT / "scripts" / "verify_source_chain_activation_v2.py"
    spec = importlib.util.spec_from_file_location(
        "verify_source_chain_activation_v2", path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Where the closure phase seals the derived live activation closure: a sibling
# of the checkout, never a path inside it, so the reviewed tree stays exactly
# clean. These names mirror `pin_source_chain_activation_v2.py` exactly.
LIVE_ACTIVATION_EVIDENCE_DIRECTORY = "acc-live-activation-evidence"
DERIVED_CLOSURE_NAME = "derived-activation-closure.json"


def _authenticated_derived_closure():
    """The derived live activation closure, re-derived, never believed.

    The real F8 evidence does not live in the candidate. The candidate is a
    false builder by construction - its own `f8_closed` is false and must stay
    false - so consulting only the candidate could never let an authenticated
    run reach a truthful `verified`. The evidence is the closure that
    `pin_source_chain_activation_v2.py --phase closure` seals beside the
    checkout after authenticating real live evidence.

    Nothing here trusts what that document says about itself. The bytes are
    handed to the unchanged Authority verifier, which re-derives readiness
    from the evidence alone; a closure that merely *declares* a closed F8, or
    one whose evidence is partial or unauthenticated, is refused and leaves
    the precondition blocked. Its absence is the ordinary case and is not an
    error.
    """
    path = (
        AUTHORITY.ROOT.parent / LIVE_ACTIVATION_EVIDENCE_DIRECTORY
        / DERIVED_CLOSURE_NAME
    )
    if not path.is_file() or path.is_symlink():
        return None
    try:
        package, readiness = _activation_module().verify_activation_package(
            path=path, root=AUTHORITY.ROOT, with_readiness=True,
        )
    except SystemExit:
        # A closure the Authority boundary refuses is not evidence at all.
        return None
    if readiness["f8_closed"] is not True:
        return None
    if readiness["activation_authorized"] is not True:
        return None
    receipt = package["external_activation_review"]["receipt_sha256"]
    if type(receipt) is not str or not receipt:
        return None
    return {
        "derived_closure_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "external_review_receipt_sha256": receipt,
    }


def _release_evidence_precondition():
    """Whether the deep publication legs are reachable at all, and why not.

    The full plan verification re-derives the Authority candidate through the
    pinned source chain. That chain is pinned either by the candidate itself -
    which a false builder never does - or by an authenticated derived live
    activation closure. Absent both, the leg is genuinely unavailable and the
    truthful answer is a verified blocked result naming the exact blocker -
    never a patched success and never a silent pass.
    """
    package = _activation_module().verify_activation_package()
    if package["f8_closed"] is True and package["activation_state"] == "ready":
        return None
    if _authenticated_derived_closure() is not None:
        return None
    return SOURCE_CHAIN_BLOCKER


def _verify_release_evidence_without_transport(assets, review_receipt_sha256):
    """Every publication leg that is reachable now, run for real.

    The exact asset inventory, every asset's bytes, the release checksum
    manifest recomputed byte for byte over the release evidence set, the
    preissuance receipt digest binding and the writer exclusion contract. A
    corrupt asset, a corrupt manifest, a corrupt receipt or an inventory that
    is not the release evidence set all fail closed here.
    """
    inventory = sorted(assets)
    require(
        inventory == sorted(EXPECTED_RELEASE_ASSET_NAMES),
        "verify-only publication asset inventory mismatch",
    )
    for name in inventory:
        require(
            type(assets[name]) is bytes and assets[name],
            f"verify-only publication asset bytes are malformed: {name}",
        )
    expected = "".join(
        f"{hashlib.sha256(assets[name]).hexdigest()}  {name}\n"
        for name in sorted(RELEASE_EVIDENCE_ASSET_NAMES)
        if name != "AUTHORITY-V2-RELEASE-SHA256SUMS"
    ).encode("utf-8")
    require(
        assets["AUTHORITY-V2-RELEASE-SHA256SUMS"] == expected,
        "verify-only release manifest raw bytes mismatch",
    )
    require(
        hashlib.sha256(
            assets["preissuance-review-receipt.json"]
        ).hexdigest() == review_receipt_sha256,
        "verify-only preissuance receipt digest mismatch",
    )
    for name, relative in sorted(REVIEWED_PUBLIC_ASSET_PATHS.items()):
        require(
            assets[name] == (AUTHORITY.ROOT / relative).read_bytes(),
            f"verify-only public asset is not the reviewed candidate byte "
            f"stream: {name}",
        )
    exclusion = _closed_json(
        WRITER_EXCLUSION_CONTRACT_PATH.read_bytes(),
        "publication writer exclusion contract",
    )
    require(
        exclusion["release_authorized"] is False
        and exclusion["f12_closed"] is False
        and exclusion["every_publication_write_prohibited"] is True
        and exclusion["publication_writes_prohibited"] is True,
        "the writer exclusion contract no longer models publication as "
        "unavailable, so a verify-only confirmation is not authoritative",
    )
    return inventory


CANONICAL_INVENTORY_KEYS = ("digests", "inventory")


def canonical_inventory_bytes(document):
    """The exact bytes the one canonical inventory map is identified by.

    Identical to the generator's own canonicalisation, so the digest the gate
    reports is the digest the final evidence manifest recorded and the digest
    the seal recomputes. One map, one identity, three consumers.
    """
    return json.dumps(
        {
            "digests": dict(document["digests"]),
            "inventory": list(document["inventory"]),
        },
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def require_canonical_inventory(document, digests, label):
    """Full bidirectional name and digest equality against one map.

    Never a subset in either direction: a map that omits a verified asset,
    names one that was never verified, or records a digest that is not the
    byte stream this gate hashed is refused.
    """
    require(
        isinstance(document, Mapping),
        f"{label} carries no canonical inventory map",
    )
    require(
        tuple(sorted(document)) == CANONICAL_INVENTORY_KEYS
        and isinstance(document["digests"], Mapping)
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
        f"{label} is not the canonical inventory of the verified bytes",
    )
    for name in sorted(digests):
        require(
            document["digests"][name] == digests[name],
            f"{label} is not the canonical inventory digest for {name}",
        )
    return {
        "digests": dict(document["digests"]),
        "inventory": sorted(document["inventory"]),
    }


def canonical_inventory_from_document(path, label):
    """The one canonical map, read from the artifact that composed it.

    Two artifacts carry it: the standalone map the generator emits before the
    first gate, and the final evidence manifest, which composes it once and
    carries it as its own inventory. Both are read here; neither is derived.
    """
    path = Path(path)
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} is absent or unsafe",
    )
    document = _closed_json(path.read_bytes(), label)
    if isinstance(document.get("digests"), Mapping):
        digests = document["digests"]
    else:
        digests = document.get("member_sha256")
    require(
        isinstance(digests, Mapping) and type(document.get("inventory")) is list,
        f"{label} carries no canonical inventory map",
    )
    return {"digests": digests, "inventory": document["inventory"]}


def verify_only_publication_state(assets, *, review_receipt_sha256,
                                  cosign_path, authenticated_issuance,
                                  canonical_inventory):
    """Confirm the expected F12-blocked state without attempting a write.

    Publication is unavailable by construction: no documented GitHub semantics
    establish an exhaustive exclusive writer proof, so `F12` stays open and
    `release_authorized` stays false. This path runs the *identical* preflight
    the publish path runs - the same deep asset, manifest, receipt, Sigstore
    and writer-exclusion verification over the same unified release evidence
    inventory - and then reports the confirmed state instead of raising, so a
    run can reach a truthful terminal state. It constructs no transport and no
    write is reachable from it.
    """
    # Every reachable leg runs for real, with no bypass of any kind.
    inventory = _verify_release_evidence_without_transport(
        assets, review_receipt_sha256,
    )
    # The one canonical *complete* map of the release asset set - the exact
    # bytes this round goes on to make terminal and immutable. It is composed
    # once, before this gate runs, and consumed here unchanged: this gate
    # derives no second inventory of its own. It recomputes the digest of
    # every one of the fourteen byte streams it verified - not of the
    # release-evidence subset, which is what let six gated assets never be
    # sealed - and requires full bidirectional equality with the map, never a
    # subset in either direction. It then reports that exact map by digest, so
    # the final evidence manifest and the seal provably consume the same one.
    require(
        canonical_inventory is not None,
        "the verify-only publication gate requires the canonical inventory "
        "map composed before it",
    )
    canonical = require_canonical_inventory(
        canonical_inventory,
        {
            name: hashlib.sha256(assets[name]).hexdigest()
            for name in inventory
        },
        "the verify-only publication gate canonical inventory",
    )
    blocker = _release_evidence_precondition()
    state = {
        # The exact bytes this gate verified, named one by one - the canonical
        # map itself, unchanged. Whatever a run goes on to make terminal or
        # immutable must be byte for byte these bytes, so an inventory that
        # drifted after verification is refused rather than silently sealed.
        "asset_digests": {
            name: hashlib.sha256(assets[name]).hexdigest()
            for name in inventory
        },
        "assets_verified": len(inventory),
        "canonical_inventory_sha256": hashlib.sha256(
            canonical_inventory_bytes(canonical)
        ).hexdigest(),
        "f12_closed": False,
        "inventory": inventory,
        "publication": "unavailable",
        "release_authorized": False,
        "release_evidence_verified": len(RELEASE_EVIDENCE_ASSET_NAMES),
        "transports_constructed": 0,
        "verify_only": True,
        "writes_performed": 0,
    }
    if blocker is not None:
        # Truthful: the deep plan leg is genuinely unreachable until the
        # source chain is pinned, so the result is a verified blocked result
        # naming the exact blocker rather than a patched success.
        return {
            **state,
            "blocked_by": blocker,
            "deep_plan_verified": False,
            "state": "blocked",
        }
    plan = _publication_preflight(
        authenticated_issuance, assets, review_receipt_sha256, cosign_path,
    )
    require(
        sorted(asset.name for asset in plan.assets) == inventory,
        "the verified publication plan is not the release asset inventory",
    )
    return {
        **state,
        "blocked_by": None,
        "deep_plan_verified": True,
        "state": "verified",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--reviewed-activation-sha", required=True)
    parser.add_argument("--preissuance-review-receipt-sha256", required=True)
    parser.add_argument("--github-issuance", type=Path, required=True)
    parser.add_argument("--github-issuance-sha256", required=True)
    parser.add_argument("--cosign", required=True)
    parser.add_argument("--asset", action="append", default=[], metavar="NAME=PATH")
    # The final evidence manifest composed *before* this gate runs. It carries
    # the one canonical complete inventory and digest map; this gate consumes
    # that map unchanged rather than deriving a second one of its own.
    parser.add_argument("--canonical-inventory", type=Path)
    args = parser.parse_args()
    verify_runtime_context(os.environ, args.reviewed_activation_sha)
    assets = _parse_assets(args.asset)
    issuance = _authenticate_issuance_asset(
        args.github_issuance, args.github_issuance_sha256,
        args.reviewed_activation_sha, args.preissuance_review_receipt_sha256,
    )
    if args.verify_only:
        require(
            args.canonical_inventory is not None,
            "--verify-only requires --canonical-inventory: the canonical "
            "inventory map composed before the gate",
        )
        # The identical preflight, with no transport constructed at all.
        print(json.dumps(verify_only_publication_state(
            assets,
            review_receipt_sha256=args.preissuance_review_receipt_sha256,
            cosign_path=args.cosign,
            authenticated_issuance=issuance,
            canonical_inventory=canonical_inventory_from_document(
                args.canonical_inventory,
                "the canonical inventory map",
            ),
        ), sort_keys=True))
        return
    mutation_token = os.environ.get("GH_TOKEN", "")
    guard_token = os.environ.get("GH_GUARD_APP_TOKEN", "")
    require(
        mutation_token != guard_token,
        "guard App token and mutation GITHUB_TOKEN must be distinct",
    )
    read_transport = PublicationReadTransport(GitHubTransport(mutation_token))
    guard_transport = AdministrationReadAppTransport(GitHubTransport(guard_token))
    PublicationService(read_transport, guard_transport).publish(
        issuance, assets, args.preissuance_review_receipt_sha256, args.cosign,
    )


if __name__ == "__main__":
    main()
