from scripts import collect_github_issuance_v2 as ISSUANCE


def authenticated_issuance(head="a" * 40, tree="b" * 40, diff="c" * 64,
                           review_receipt_sha256="d" * 64, nonce="e" * 64):
    candidate = {"head_commit": head, "head_tree": tree,
                 "canonical_diff_sha256": diff,
                 "review_receipt_sha256": review_receipt_sha256}
    readbacks = {
        "dispatch_inputs": {"candidate_head": head, "candidate_tree": tree,
            "canonical_diff_sha256": diff, "review_receipt_sha256": review_receipt_sha256,
            "issuance_nonce": nonce, "release_tag": "clerk-instance-attestation-v2",
            "release_name": "ACC Clerk instance attestation v2"},
        "run": {"id": 101, "run_attempt": 1, "head_sha": head, "head_branch": "main",
            "event": "workflow_dispatch", "status": "in_progress", "actor": "acc-release-actor",
            "workflow_path": ".github/workflows/sign-clerk-attestation-v2.yml"},
        "job": {"id": 202, "run_id": 101, "name": "issue", "status": "in_progress"},
        "approval": {"environments": [{"name": "attestation"}], "state": "approved",
            "user": {"login": "independent-reviewer"}},
        "oidc": {"iss": "https://token.actions.githubusercontent.com", "aud": "sigstore",
            "sub": "repo:chrizzatsu/acc-attestation-authority:environment:attestation",
            "repository": "chrizzatsu/acc-attestation-authority",
            "workflow_ref": "chrizzatsu/acc-attestation-authority/.github/workflows/sign-clerk-attestation-v2.yml@refs/heads/main",
            "workflow_sha": head, "ref": "refs/heads/main", "event_name": "workflow_dispatch",
            "actor": "acc-release-actor", "environment": "attestation", "run_id": "101",
            "run_attempt": "1"},
    }
    return ISSUANCE.collect_authenticated_issuance(readbacks, candidate)
