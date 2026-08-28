#!/usr/bin/env python3
"""Verify one exact GitHub Environment/OIDC issuance chain."""
import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

EXPECTED_REPOSITORY = "chrizzatsu/acc-attestation-authority"
EXPECTED_REF = "refs/heads/main"
EXPECTED_WORKFLOW_PATH = ".github/workflows/sign-clerk-attestation-v2.yml"
EXPECTED_WORKFLOW_REF = f"{EXPECTED_REPOSITORY}/{EXPECTED_WORKFLOW_PATH}@refs/heads/main"
EXPECTED_ENVIRONMENT = "attestation"
EXPECTED_EVENT = "workflow_dispatch"
EXPECTED_TAG = "clerk-instance-attestation-v2"
EXPECTED_RELEASE_NAME = "ACC Clerk instance attestation v2"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SUBJECT_BINDING_FIELDS = (
    "issuance_sha256", "candidate_head", "candidate_tree", "canonical_diff_sha256",
    "review_receipt_sha256", "issuance_nonce", "release_tag", "release_name",
    "run_id", "run_attempt", "job_id", "environment",
    "approver", "actor", "oidc_issuer", "oidc_audience", "oidc_subject", "workflow_ref",
)

_AUTHENTICATED_TOKEN = object()


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _closed_json(data, label):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(type(key) is str and key not in result, f"{label} has duplicate member")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit(f"{label} is not valid UTF-8 JSON") from error


def _exact_fields(value, fields, label):
    require(type(value) is dict and set(value) == set(fields), f"{label} field set mismatch")


def _integer(value, label):
    require(type(value) is int and value > 0, f"{label} must be a positive JSON integer")
    return value


def _string(value, label):
    require(type(value) is str and value != "", f"{label} must be a non-empty JSON string")
    return value


@dataclass(frozen=True)
class AuthenticatedIssuance:
    data: bytes
    sha256: str
    candidate_head: str
    candidate_tree: str
    canonical_diff_sha256: str
    review_receipt_sha256: str
    issuance_nonce: str
    release_tag: str
    release_name: str
    run_id: int
    run_attempt: int
    job_id: int
    environment: str
    approver: str
    actor: str
    oidc_issuer: str
    oidc_audience: str
    oidc_subject: str
    workflow_ref: str
    verification_token: object


def _validate(readbacks, candidate):
    _exact_fields(readbacks, {"dispatch_inputs", "run", "job", "approval", "oidc"}, "GitHub issuance readbacks")
    _exact_fields(candidate, {"head_commit", "head_tree", "canonical_diff_sha256", "review_receipt_sha256"}, "candidate issuance binding")
    head = candidate["head_commit"]
    tree = candidate["head_tree"]
    diff = candidate["canonical_diff_sha256"]
    review_receipt_sha256 = candidate["review_receipt_sha256"]
    require(type(head) is str and HEX40.fullmatch(head), "candidate head mismatch")
    require(type(tree) is str and HEX40.fullmatch(tree), "candidate tree mismatch")
    require(type(diff) is str and HEX64.fullmatch(diff), "candidate diff mismatch")
    require(type(review_receipt_sha256) is str and HEX64.fullmatch(review_receipt_sha256), "candidate reviewer receipt mismatch")

    dispatch = readbacks["dispatch_inputs"]
    _exact_fields(dispatch, {"candidate_head", "candidate_tree", "canonical_diff_sha256", "review_receipt_sha256", "issuance_nonce", "release_tag", "release_name"}, "dispatch inputs")
    require(dispatch["candidate_head"] == head and dispatch["candidate_tree"] == tree and dispatch["canonical_diff_sha256"] == diff, "dispatch candidate binding mismatch")
    require(type(dispatch["review_receipt_sha256"]) is str and HEX64.fullmatch(dispatch["review_receipt_sha256"]), "review receipt hash mismatch")
    require(dispatch["review_receipt_sha256"] == review_receipt_sha256, "dispatch reviewer receipt does not match the independently expected receipt")
    require(type(dispatch["issuance_nonce"]) is str and HEX64.fullmatch(dispatch["issuance_nonce"]), "issuance nonce mismatch")
    require(dispatch["release_tag"] == EXPECTED_TAG and dispatch["release_name"] == EXPECTED_RELEASE_NAME, "release identity mismatch")

    run = readbacks["run"]
    _exact_fields(run, {"id", "run_attempt", "head_sha", "head_branch", "event", "status", "actor", "workflow_path"}, "workflow run")
    run_id = _integer(run["id"], "run id")
    require(type(run["run_attempt"]) is int and run["run_attempt"] == 1, "workflow rerun attempt is forbidden")
    require(run["head_sha"] == head and run["head_branch"] == "main" and run["event"] == EXPECTED_EVENT, "workflow run candidate/context mismatch")
    require(run["status"] == "in_progress" and run["workflow_path"] == EXPECTED_WORKFLOW_PATH, "workflow run state/path mismatch")
    actor = _string(run["actor"], "workflow actor")

    job = readbacks["job"]
    _exact_fields(job, {"id", "run_id", "name", "status"}, "workflow job")
    job_id = _integer(job["id"], "job id")
    job_run_id = _integer(job["run_id"], "workflow job run reference")
    require(job_run_id == run_id and job["name"] == "issue" and job["status"] == "in_progress", "workflow job binding mismatch")

    approval = readbacks["approval"]
    _exact_fields(approval, {"environments", "state", "user"}, "environment approval")
    require(
        type(approval["environments"]) is list
        and len(approval["environments"]) == 1,
        "run-scoped environment approval environments mismatch",
    )
    approval_environment = approval["environments"][0]
    _exact_fields(approval_environment, {"name"}, "environment approval environment")
    _exact_fields(approval["user"], {"login"}, "environment approval user")
    approver = _string(approval["user"]["login"], "environment approver")
    require(
        approval_environment["name"] == EXPECTED_ENVIRONMENT
        and approval["state"] == "approved",
        "run-scoped environment approval mismatch",
    )
    require(approver != actor, "environment self-review is forbidden")

    oidc = readbacks["oidc"]
    _exact_fields(oidc, {"iss", "aud", "sub", "repository", "workflow_ref", "workflow_sha", "ref", "event_name", "actor", "environment", "run_id", "run_attempt"}, "OIDC claims")
    expected_sub = f"repo:{EXPECTED_REPOSITORY}:environment:{EXPECTED_ENVIRONMENT}"
    require(oidc["iss"] == OIDC_ISSUER and oidc["aud"] == "sigstore" and oidc["sub"] == expected_sub, "OIDC issuer/audience/subject mismatch")
    require(oidc["repository"] == EXPECTED_REPOSITORY and oidc["workflow_ref"] == EXPECTED_WORKFLOW_REF, "OIDC repository/workflow mismatch")
    require(oidc["workflow_sha"] == head and oidc["ref"] == EXPECTED_REF and oidc["event_name"] == EXPECTED_EVENT, "OIDC candidate/ref/event mismatch")
    require(oidc["actor"] == actor and oidc["environment"] == EXPECTED_ENVIRONMENT, "OIDC actor/environment mismatch")
    require(oidc["run_id"] == str(run_id) and oidc["run_attempt"] == "1", "OIDC run/attempt mismatch")

    return {
        "schema_version": 1,
        "receipt_type": "acc-authority-v2-authenticated-github-issuance",
        "candidate": {"head_commit": head, "head_tree": tree, "canonical_diff_sha256": diff},
        "review_receipt_sha256": dispatch["review_receipt_sha256"],
        "issuance_nonce": dispatch["issuance_nonce"],
        "release": {"tag": dispatch["release_tag"], "name": dispatch["release_name"]},
        "github": readbacks,
    }


def _from_payload(payload, data, digest):
    github = payload["github"]
    return AuthenticatedIssuance(
        data=data, sha256=digest,
        candidate_head=payload["candidate"]["head_commit"], candidate_tree=payload["candidate"]["head_tree"],
        canonical_diff_sha256=payload["candidate"]["canonical_diff_sha256"],
        review_receipt_sha256=payload["review_receipt_sha256"], issuance_nonce=payload["issuance_nonce"],
        release_tag=payload["release"]["tag"], release_name=payload["release"]["name"],
        run_id=github["run"]["id"], run_attempt=github["run"]["run_attempt"], job_id=github["job"]["id"],
        environment=github["oidc"]["environment"],
        approver=github["approval"]["user"]["login"], actor=github["run"]["actor"], oidc_issuer=github["oidc"]["iss"],
        oidc_audience=github["oidc"]["aud"],
        oidc_subject=github["oidc"]["sub"], workflow_ref=github["oidc"]["workflow_ref"],
        verification_token=_AUTHENTICATED_TOKEN,
    )


def collect_authenticated_issuance(readbacks, candidate):
    payload = _validate(readbacks, candidate)
    data = canonical(payload)
    return _from_payload(payload, data, hashlib.sha256(data).hexdigest())


def collect_authenticated_issuance_bytes(data, candidate):
    require(type(data) is bytes, "GitHub issuance fixture bytes are required")
    readbacks = _closed_json(data, "GitHub issuance readbacks")
    require(data == canonical(readbacks), "GitHub issuance readbacks must be canonical exact bytes")
    return collect_authenticated_issuance(readbacks, candidate)


def verify_authenticated_issuance_bytes(data, digest, candidate):
    require(type(data) is bytes and type(digest) is str and HEX64.fullmatch(digest), "authenticated issuance bytes/hash malformed")
    require(hashlib.sha256(data).hexdigest() == digest, "authenticated issuance hash mismatch")
    payload = _closed_json(data, "authenticated GitHub issuance")
    require(data == canonical(payload), "authenticated issuance must be canonical exact bytes with final LF")
    _exact_fields(payload, {"schema_version", "receipt_type", "candidate", "review_receipt_sha256", "issuance_nonce", "release", "github"}, "authenticated issuance")
    require(type(payload["schema_version"]) is int and payload["schema_version"] == 1
            and type(payload["receipt_type"]) is str
            and payload["receipt_type"] == "acc-authority-v2-authenticated-github-issuance",
            "authenticated issuance contract mismatch")
    readbacks = payload["github"]
    expected = _validate(readbacks, candidate)
    require(data == canonical(expected), "authenticated issuance content mismatch")
    return _from_payload(payload, data, digest)


def subject_issuance_binding(issuance):
    require(type(issuance) is AuthenticatedIssuance and issuance.verification_token is _AUTHENTICATED_TOKEN, "subject lacks authenticated issuance")
    binding = {
        "issuance_sha256": issuance.sha256, "candidate_head": issuance.candidate_head,
        "candidate_tree": issuance.candidate_tree, "canonical_diff_sha256": issuance.canonical_diff_sha256,
        "review_receipt_sha256": issuance.review_receipt_sha256, "issuance_nonce": issuance.issuance_nonce,
        "release_tag": issuance.release_tag, "release_name": issuance.release_name,
        "run_id": issuance.run_id, "run_attempt": issuance.run_attempt, "job_id": issuance.job_id,
        "environment": issuance.environment,
        "approver": issuance.approver, "actor": issuance.actor, "oidc_issuer": issuance.oidc_issuer,
        "oidc_audience": issuance.oidc_audience,
        "oidc_subject": issuance.oidc_subject, "workflow_ref": issuance.workflow_ref,
    }
    require(tuple(binding) == SUBJECT_BINDING_FIELDS, "subject issuance binding field order mismatch")
    return binding


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--readbacks", type=Path, required=True)
    parser.add_argument("--candidate-head", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--canonical-diff-sha256", required=True)
    parser.add_argument("--review-receipt-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    issuance = collect_authenticated_issuance_bytes(
        args.readbacks.read_bytes(),
        {"head_commit": args.candidate_head, "head_tree": args.candidate_tree,
         "canonical_diff_sha256": args.canonical_diff_sha256,
         "review_receipt_sha256": args.review_receipt_sha256},
    )
    require(args.output.parent.is_dir() and not args.output.exists(), "issuance output must be a new file")
    args.output.write_bytes(issuance.data)
    print(json.dumps({"github_issuance_sha256": issuance.sha256, "run_id": issuance.run_id,
                      "job_id": issuance.job_id}, sort_keys=True))


if __name__ == "__main__":
    main()
