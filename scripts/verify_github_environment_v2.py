#!/usr/bin/env python3
"""Verify live GitHub repository/Environment JSON against the exact v2 contract.

This module is read-only. It opens no network connection, spawns no process and
performs no GitHub write of any kind: it only classifies and binds evidence that
an authenticated read-only caller already captured.

SEALED-GITHUB-READBACK-ENVIRONMENT-MISMATCH: an authenticated HTTP 200 read, an
unauthenticated or permission-masked 404 and a confirmed absence are three
different facts. Only an authenticated 200 proves the Environment exists, and a
404 is treated as confirmed absence only when an authenticated listing proves
the same credential could have seen the Environment had it existed.
"""
import argparse
import json
import re
from pathlib import Path

SEALED_READBACK_KEYS = (
    "authenticated_read_only",
    "confirmed_absence_requires_authenticated_permission_proof",
    "confirmed_absence_requires_exhaustive_authenticated_pagination",
    "environment_id",
    "environment_secrets_total_count",
    "http_status",
    "masked_or_unauthenticated_statuses",
    "no_github_write_performed",
    "permission_masked_404_is_not_absence",
    "prevent_self_review",
    "protected_branches",
    "required_reviewer_logins",
    "sealed_state",
    "state_change_fails_closed",
)
SEALED_ENVIRONMENT_NAME = "attestation"
# A single Environment listing page proves nothing. Confirmed absence needs a
# deterministic, exhaustive, bounded traversal of the Environment listing made
# by the *same* authenticated credential that read the target Environment, on
# the *same* repository endpoint, whose every page reconciles with the
# documented `Link` next relation and whose totals, page numbers and entries
# are internally consistent. Anything less is `masked_or_absent`.
ENVIRONMENT_PAGE_SIZE = 100
MAX_ENVIRONMENT_PAGES = 100
LINK_NEXT = re.compile(r'<(?P<url>[^<>]*)>\s*;\s*rel="next"')
LINK_NEXT_TOKEN = re.compile(r'rel\s*=\s*"?next"?', re.IGNORECASE)
# The only accepted next target: the same documented API endpoint, either
# absolute on the documented host or as a bare path. Parsed with `re` alone so
# this module keeps importing no transport library of any kind.
API_ORIGIN = "https://api.github.com"
NEXT_TARGET = re.compile(
    r"\A(?:" + re.escape(API_ORIGIN) + r")?(?P<path>/[^?#]*)\?(?P<query>[^?#]*)\Z"
)
QUERY_PAIR = re.compile(r"\A(?P<key>[a-z_]+)=(?P<value>[0-9]+)\Z")
PAGE_NUMBER = re.compile(r"\A[1-9][0-9]*\Z")
ENVIRONMENT_TARGET_REQUEST_KEYS = (
    "credential_identity", "repository", "request_path",
)
ENVIRONMENT_PROOF_KEYS = (
    "credential_identity", "endpoint_path", "pages", "per_page", "repository",
)
ENVIRONMENT_PAGE_KEYS = (
    "authenticated", "credential_identity", "environments", "headers", "page",
    "request_path", "status", "total_count",
)
ENVIRONMENT_READ_STATES = (
    "authenticated_present",
    "confirmed_absent",
    "masked_or_absent",
    "unauthenticated",
    "unknown",
)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def environment_listing_path(repository):
    """The exact documented Environment listing endpoint of one repository."""
    return f"/repos/{repository}/environments"


def environment_listing_page_path(repository, page):
    """The exact deterministic page path of that listing endpoint."""
    return (
        f"{environment_listing_path(repository)}"
        f"?per_page={ENVIRONMENT_PAGE_SIZE}&page={page}"
    )


def _parse_next_environment_page(headers, current_page, repository):
    """Resolve the next deterministic page, or report why traversal cannot go on.

    Returns (next_page, state). `state` is "complete" when this page is the
    documented last one, "continue" when a well-formed monotonic next link
    advances exactly one page on the exact same endpoint, and "malformed" for a
    duplicate, unparsable, foreign, non-monotonic or looping link.
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
        if LINK_NEXT_TOKEN.search(link) is not None:
            return None, "malformed"
        if "rel=" not in link:
            return None, "malformed"
        return None, "complete"
    if len(matches) > 1:
        return None, "malformed"
    target = NEXT_TARGET.fullmatch(matches[0])
    if target is None:
        return None, "malformed"
    if target["path"] != environment_listing_path(repository):
        return None, "malformed"
    query = {}
    for chunk in target["query"].split("&"):
        pair = QUERY_PAIR.fullmatch(chunk)
        if pair is None or pair["key"] in query:
            return None, "malformed"
        query[pair["key"]] = pair["value"]
    if sorted(query) != ["page", "per_page"]:
        return None, "malformed"
    if query["per_page"] != str(ENVIRONMENT_PAGE_SIZE):
        return None, "malformed"
    if PAGE_NUMBER.fullmatch(query["page"]) is None:
        return None, "malformed"
    next_page = int(query["page"])
    if next_page != current_page + 1:
        return None, "malformed"
    return next_page, "continue"


def _bound_target_request(target_request, sealed_environment):
    """The exact authenticated target read a permission proof must bind to.

    Returns (credential_identity, repository) or None. Without a well-formed
    target request there is nothing to bind the listing to, so a 404 can never
    become confirmed absence.
    """
    if type(target_request) is not dict:
        return None
    if tuple(sorted(target_request)) != ENVIRONMENT_TARGET_REQUEST_KEYS:
        return None
    identity = target_request["credential_identity"]
    repository = target_request["repository"]
    if type(identity) is not str or not identity:
        return None
    if type(repository) is not str or not repository:
        return None
    expected = f"{environment_listing_path(repository)}/{sealed_environment}"
    if target_request["request_path"] != expected:
        return None
    return identity, repository


def _is_authenticated_permission_proof(permission_proof, sealed_environment,
                                       target_request=None):
    """Prove the same credential could have seen the Environment had it existed.

    The proof must be an exhaustive, bounded traversal of the same repository's
    Environment listing, made by the same credential identity as the target
    read, on the exact deterministic page paths, reconciled page by page
    against the documented `Link` next relation, with one consistent total, no
    duplicate or unadvertised page, no repeated Environment and at least one
    Environment actually observed. A listing that names the sealed Environment
    contradicts the 404 and is never a proof of absence.
    """
    bound = _bound_target_request(target_request, sealed_environment)
    if bound is None:
        return False
    identity, repository = bound
    if type(permission_proof) is not dict:
        return False
    if tuple(sorted(permission_proof)) != ENVIRONMENT_PROOF_KEYS:
        return False
    if permission_proof["credential_identity"] != identity:
        return False
    if permission_proof["repository"] != repository:
        return False
    if permission_proof["endpoint_path"] != environment_listing_path(repository):
        return False
    per_page = permission_proof["per_page"]
    if type(per_page) is not int or type(per_page) is bool:
        return False
    if per_page != ENVIRONMENT_PAGE_SIZE:
        return False
    pages = permission_proof["pages"]
    if type(pages) is not list or not pages:
        return False
    if len(pages) > MAX_ENVIRONMENT_PAGES:
        return False
    observed = []
    totals = set()
    expected_page = 1
    complete = False
    for page in pages:
        if complete:
            # a page the documented traversal never advertised
            return False
        if type(page) is not dict:
            return False
        if tuple(sorted(page)) != ENVIRONMENT_PAGE_KEYS:
            return False
        if page["status"] != 200 or page["authenticated"] is not True:
            return False
        if page["credential_identity"] != identity:
            return False
        number = page["page"]
        if type(number) is not int or type(number) is bool:
            return False
        if number != expected_page:
            return False
        if page["request_path"] != environment_listing_page_path(
            repository, expected_page,
        ):
            return False
        total = page["total_count"]
        if type(total) is not int or type(total) is bool or total < 0:
            return False
        totals.add(total)
        entries = page["environments"]
        if type(entries) is not list:
            return False
        for entry in entries:
            if type(entry) is not dict:
                return False
            name = entry.get("name")
            if type(name) is not str or not name:
                return False
            observed.append(name)
        next_page, state = _parse_next_environment_page(
            page["headers"], expected_page, repository,
        )
        if state == "malformed":
            return False
        if state == "complete":
            complete = True
            continue
        # a page that advertises a successor must itself be a full page
        if len(entries) != ENVIRONMENT_PAGE_SIZE:
            return False
        expected_page = next_page
    if not complete:
        return False
    if len(totals) != 1:
        return False
    if len(observed) != totals.pop():
        return False
    if len(set(observed)) != len(observed):
        return False
    if not observed:
        return False
    return sealed_environment not in observed


def classify_environment_read(status, *, authenticated, permission_proof=None,
                              sealed_environment=SEALED_ENVIRONMENT_NAME,
                              target_request=None):
    """Classify one GitHub Environment read; never conflate masking with absence."""
    if authenticated is not True:
        return "unauthenticated"
    if status == 200:
        return "authenticated_present"
    if status in (401, 403):
        return "unauthenticated"
    if status == 404:
        if _is_authenticated_permission_proof(
            permission_proof, sealed_environment, target_request,
        ):
            return "confirmed_absent"
        return "masked_or_absent"
    return "unknown"


def _sealed_readback_contract(contract):
    require(type(contract) is dict, "environment contract is malformed")
    sealed = contract.get("sealed_environment_readback")
    require(type(sealed) is dict, "sealed Environment readback contract is absent")
    require(
        tuple(sorted(sealed)) == SEALED_READBACK_KEYS,
        "sealed Environment readback field set mismatch",
    )
    require(
        sealed["authenticated_read_only"] is True
        and sealed["no_github_write_performed"] is True
        and sealed["permission_masked_404_is_not_absence"] is True
        and sealed["confirmed_absence_requires_authenticated_permission_proof"] is True
        and sealed["confirmed_absence_requires_exhaustive_authenticated_pagination"]
        is True
        and sealed["state_change_fails_closed"] is True,
        "sealed Environment readback semantics mismatch",
    )
    require(sealed["http_status"] == 200, "sealed Environment readback status mismatch")
    require(
        type(sealed["environment_id"]) is int
        and type(sealed["environment_id"]) is not bool
        and sealed["environment_id"] > 0,
        "sealed Environment id is malformed",
    )
    require(
        sealed["environment_secrets_total_count"] == 0
        and type(sealed["environment_secrets_total_count"]) is int,
        "sealed Environment must hold zero environment secrets",
    )
    require(
        sealed["prevent_self_review"] is True,
        "sealed Environment protection posture mismatch",
    )
    declared_policy = contract.get("deployment_branch_policy")
    require(type(declared_policy) is dict, "environment branch-policy contract is absent")
    require(
        type(sealed["protected_branches"]) is bool
        and sealed["protected_branches"] is declared_policy.get("protected_branches"),
        "sealed Environment protected-branches posture contradicts the contract",
    )
    logins = sealed["required_reviewer_logins"]
    require(
        type(logins) is list and logins
        and all(type(login) is str and login for login in logins)
        and logins == sorted(logins),
        "sealed Environment reviewer logins are malformed",
    )
    require(
        sealed["masked_or_unauthenticated_statuses"] == [401, 403, 404],
        "sealed Environment masked-status set mismatch",
    )
    return sealed


def _observed_user_reviewer_logins(environment):
    logins = []
    prevent_self_review = None
    for rule in environment.get("protection_rules", []):
        if type(rule) is dict and rule.get("type") == "required_reviewers":
            prevent_self_review = rule.get("prevent_self_review")
            for reviewer in rule.get("reviewers") or []:
                require(type(reviewer) is dict, "Environment reviewer entry is malformed")
                require(
                    reviewer.get("type") == "User",
                    "only exact User Environment reviewers are sealed",
                )
                identity = reviewer.get("reviewer")
                require(type(identity) is dict, "Environment reviewer identity is malformed")
                login = identity.get("login")
                require(type(login) is str and login, "Environment reviewer login is absent")
                logins.append(login)
    return sorted(logins), prevent_self_review


def verify_sealed_environment_readback(environment, environment_secrets, contract, *,
                                       environment_status, authenticated,
                                       permission_proof=None, target_request=None):
    """Bind the exact sealed authenticated Environment state or fail closed."""
    sealed = _sealed_readback_contract(contract)
    read_state = classify_environment_read(
        environment_status,
        authenticated=authenticated,
        permission_proof=permission_proof,
        sealed_environment=contract.get("environment", SEALED_ENVIRONMENT_NAME),
        target_request=target_request,
    )
    require(
        read_state == "authenticated_present",
        "sealed Environment readback requires an authenticated HTTP 200 read, "
        f"observed {read_state}",
    )
    require(type(environment) is dict, "Environment readback body is malformed")
    observed_id = environment.get("id")
    require(
        type(observed_id) is int and type(observed_id) is not bool
        and observed_id == sealed["environment_id"],
        "live Environment id differs from the sealed authenticated readback",
    )
    logins, prevent_self_review = _observed_user_reviewer_logins(environment)
    require(
        logins == sealed["required_reviewer_logins"],
        "live Environment required reviewers differ from the sealed readback",
    )
    require(
        prevent_self_review is sealed["prevent_self_review"],
        "live Environment prevent-self-review differs from the sealed readback",
    )
    branch_policy = environment.get("deployment_branch_policy") or {}
    require(
        branch_policy.get("protected_branches") is sealed["protected_branches"],
        "live Environment protected-branches mode differs from the sealed readback",
    )
    require(type(environment_secrets) is dict, "Environment secrets readback is malformed")
    total_count = environment_secrets.get("total_count")
    secrets = environment_secrets.get("secrets")
    require(
        type(total_count) is int and type(total_count) is not bool
        and type(secrets) is list,
        "Environment secrets readback is malformed",
    )
    require(
        total_count == len(secrets),
        "Environment secrets readback count mismatch",
    )
    require(
        total_count == sealed["environment_secrets_total_count"],
        "live Environment holds secrets while the sealed readback records none",
    )
    return {
        "environment_id": observed_id,
        "environment_read": read_state,
        "environment_secrets_total_count": total_count,
        "github_write_performed": False,
        "prevent_self_review": True,
        "protected_branches": True,
        "required_reviewer_logins": logins,
        "sealed_state_unchanged": True,
    }


def verify_environment(repository, environment, branches, immutable_releases, contract,
                       branch_policies_status=200, *, environment_status,
                       authenticated, environment_secrets, permission_proof=None,
                       target_request=None):
    sealed = verify_sealed_environment_readback(
        environment, environment_secrets, contract,
        environment_status=environment_status,
        authenticated=authenticated,
        permission_proof=permission_proof,
        target_request=target_request,
    )
    require(repository.get("full_name") == contract["repository"], "repository identity mismatch")
    require(repository.get("private") is False, "zero-spend runner contract requires a public repository")
    require(environment.get("name") == contract["environment"], "Environment identity mismatch")
    require(environment.get("can_admins_bypass") is False, "Environment admin bypass must be disabled")
    branch_policy = environment.get("deployment_branch_policy") or {}
    expected_branch_policy = contract["deployment_branch_policy"]
    require(branch_policy.get("protected_branches") is expected_branch_policy["protected_branches"], "protected-branch policy mismatch")
    require(branch_policy.get("custom_branch_policies") is expected_branch_policy["custom_branch_policies"], "custom branch policy mismatch")

    reviewers = []
    prevent_self_review = None
    for rule in environment.get("protection_rules", []):
        if rule.get("type") == "required_reviewers":
            reviewers = rule.get("reviewers") or []
            prevent_self_review = rule.get("prevent_self_review")
    require(len(reviewers) >= contract["required_reviewers"]["minimum_count"], "required Environment reviewer absent")
    require(prevent_self_review is True, "Environment prevent-self-review must be enabled")

    require(type(branch_policies_status) is int, "branch-policy HTTP status is malformed")
    protected_mode = branch_policy.get("protected_branches") is True
    if protected_mode:
        require(branch_policies_status == 404,
                "protected-branches mode requires documented branch-policy HTTP 404")
        require(branches is None, "protected-branches mode must not trust a branch-policy body")
        policy_mode = "protected_branches"
        main_only = False
    else:
        require(branch_policies_status == 200,
                "custom branch-policy readback did not return HTTP 200")
        require(type(branches) is dict, "custom branch-policy body is malformed")
        policies = branches.get("branch_policies") or []
        total_count = branches.get("total_count")
        require(type(total_count) is int and total_count >= 0,
                "custom branch-policy count has wrong JSON type")
        require(total_count == len(policies), "custom branch-policy count mismatch")
        require(expected_branch_policy.get("allowed_refs") == ["refs/heads/main"],
                "custom branch-policy contract is not exact main")
        require(len(policies) == 1 and type(policies[0]) is dict
                and policies[0].get("name") == "main"
                and policies[0].get("type", "branch") == "branch",
                "custom branch-policy readback is not exact main")
        policy_mode = "custom_branch_policies"
        main_only = True
    require(contract["fallback_path"] is False, "fallback path must remain false")
    require(contract["repository_immutable_releases_required_before_issuance"] is True, "immutable-release requirement missing")
    require(immutable_releases.get("enabled") is True, "repository immutable releases must be enabled before issuance")
    require(contract["maximum_incremental_spend_eur"] == "0.00", "zero-spend contract mismatch")
    return {
        "repository_public": True,
        "environment": contract["environment"],
        "required_reviewer_count": len(reviewers),
        "prevent_self_review": True,
        "admin_bypass": False,
        "deployment_branch_policy_mode": policy_mode,
        "main_only": main_only,
        "immutable_releases": True,
        "maximum_incremental_spend_eur": "0.00",
        **sealed,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-json", type=Path, required=True)
    parser.add_argument("--environment-json", type=Path, required=True)
    parser.add_argument("--branch-policies-json", type=Path, required=True)
    parser.add_argument("--branch-policies-status", type=int, required=True)
    parser.add_argument("--immutable-releases-json", type=Path, required=True)
    parser.add_argument("--environment-status", type=int, required=True)
    parser.add_argument("--environment-secrets-json", type=Path, required=True)
    parser.add_argument("--environment-authenticated", required=True,
                        choices=("true", "false"))
    parser.add_argument("--contract", type=Path, required=True)
    args = parser.parse_args()
    branches = None
    if args.branch_policies_status == 200:
        branches = json.loads(args.branch_policies_json.read_bytes())
    result = verify_environment(
        json.loads(args.repository_json.read_bytes()),
        json.loads(args.environment_json.read_bytes()),
        branches,
        json.loads(args.immutable_releases_json.read_bytes()),
        json.loads(args.contract.read_bytes()),
        branch_policies_status=args.branch_policies_status,
        environment_status=args.environment_status,
        authenticated=args.environment_authenticated == "true",
        environment_secrets=json.loads(args.environment_secrets_json.read_bytes()),
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
