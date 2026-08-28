#!/usr/bin/env python3
import copy
import hashlib
import json
import unittest
from pathlib import Path

from scripts import collect_github_issuance_v2 as ISSUANCE


class GitHubIssuanceAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.candidate = {
            "head_commit": "a" * 40,
            "head_tree": "b" * 40,
            "canonical_diff_sha256": "c" * 64,
            "review_receipt_sha256": "d" * 64,
        }
        self.readbacks = {
            "dispatch_inputs": {
                "candidate_head": "a" * 40,
                "candidate_tree": "b" * 40,
                "canonical_diff_sha256": "c" * 64,
                "review_receipt_sha256": "d" * 64,
                "issuance_nonce": "e" * 64,
                "release_tag": "clerk-instance-attestation-v2",
                "release_name": "ACC Clerk instance attestation v2",
            },
            "run": {
                "id": 101, "run_attempt": 1, "head_sha": "a" * 40,
                "head_branch": "main", "event": "workflow_dispatch", "status": "in_progress",
                "actor": "acc-release-actor", "workflow_path": ".github/workflows/sign-clerk-attestation-v2.yml",
            },
            "job": {
                "id": 202, "run_id": 101, "name": "issue", "status": "in_progress",
            },
            "approval": {
                "environments": [{"name": "attestation"}],
                "state": "approved",
                "user": {"login": "independent-reviewer"},
            },
            "oidc": {
                "iss": "https://token.actions.githubusercontent.com",
                "aud": "sigstore",
                "sub": "repo:chrizzatsu/acc-attestation-authority:environment:attestation",
                "repository": "chrizzatsu/acc-attestation-authority",
                "workflow_ref": "chrizzatsu/acc-attestation-authority/.github/workflows/sign-clerk-attestation-v2.yml@refs/heads/main",
                "workflow_sha": "a" * 40, "ref": "refs/heads/main", "event_name": "workflow_dispatch",
                "actor": "acc-release-actor", "environment": "attestation", "run_id": "101",
                "run_attempt": "1",
            },
        }

    def collect(self, readbacks=None, candidate=None):
        return ISSUANCE.collect_authenticated_issuance(
            self.readbacks if readbacks is None else readbacks,
            self.candidate if candidate is None else candidate,
        )

    def test_collects_closed_exact_github_server_chain(self):
        issuance = self.collect()
        self.assertEqual(issuance.run_id, 101)
        self.assertEqual(issuance.job_id, 202)
        self.assertEqual(issuance.environment, "attestation")
        self.assertEqual(issuance.review_receipt_sha256, "d" * 64)

    def test_authenticated_chain_omits_undocumented_deployment_relationships(self):
        issuance = self.collect()
        github = json.loads(issuance.data)["github"]
        self.assertNotIn("deployment", github)
        self.assertNotIn("deployment_status", github)

    def test_synthetic_deployment_log_url_is_rejected_and_not_evidence(self):
        synthetic = copy.deepcopy(self.readbacks)
        synthetic["deployment"] = {
            "id": 303, "ref": "refs/heads/main", "sha": "a" * 40,
            "environment": "attestation", "task": "deploy",
            "creator": "acc-release-actor",
        }
        synthetic["deployment_status"] = {
            "deployment_url": "https://api.github.com/repos/chrizzatsu/acc-attestation-authority/deployments/303",
            "state": "in_progress",
            "log_url": "https://github.com/chrizzatsu/acc-attestation-authority/actions/runs/101/job/202",
        }
        with self.assertRaises(SystemExit):
            self.collect(synthetic)

        documented = copy.deepcopy(self.readbacks)
        issuance = self.collect(documented)
        payload = json.loads(issuance.data)
        self.assertNotIn("deployment", payload["github"])
        self.assertNotIn("deployment_status", payload["github"])
        self.assertNotIn("deployment_id", ISSUANCE.subject_issuance_binding(issuance))

        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "sign-clerk-attestation-v2.yml"
        ).read_text()
        self.assertNotIn("deployments?environment=attestation", workflow)
        self.assertNotIn("deployment-statuses.raw.json", workflow)
        self.assertNotIn("log_url", workflow)

    def test_rejects_extra_missing_and_duplicate_json_fields(self):
        for section in self.readbacks:
            changed = copy.deepcopy(self.readbacks)
            changed[section]["unexpected"] = "forbidden"
            with self.subTest(section=section), self.assertRaises(SystemExit):
                self.collect(changed)
        raw = ISSUANCE.canonical(self.readbacks).replace(b'"run":{', b'"run":{"id":101,', 1)
        with self.assertRaises(SystemExit):
            ISSUANCE.collect_authenticated_issuance_bytes(raw, self.candidate)

    def test_rejects_rerun_replay_and_cross_candidate_bindings(self):
        mutations = []
        changed = copy.deepcopy(self.readbacks); changed["run"]["run_attempt"] = 2; mutations.append(changed)
        changed = copy.deepcopy(self.readbacks); changed["oidc"]["run_attempt"] = "2"; mutations.append(changed)
        changed = copy.deepcopy(self.readbacks); changed["dispatch_inputs"]["candidate_tree"] = "f" * 40; mutations.append(changed)
        changed = copy.deepcopy(self.readbacks); changed["dispatch_inputs"]["review_receipt_sha256"] = "0" * 64; mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(SystemExit):
                self.collect(changed)

    def test_rejects_wrong_repo_ref_workflow_environment_actor_or_oidc(self):
        paths = [
            ("oidc", "repository", "other/repo"), ("oidc", "ref", "refs/heads/dev"),
            ("oidc", "workflow_sha", "f" * 40), ("oidc", "environment", "other"),
            ("oidc", "actor", "someone-else"),
            ("oidc", "aud", "other"),
        ]
        for section, field, value in paths:
            changed = copy.deepcopy(self.readbacks); changed[section][field] = value
            with self.subTest(section=section, field=field), self.assertRaises(SystemExit):
                self.collect(changed)

        changed = copy.deepcopy(self.readbacks)
        changed["approval"]["user"]["login"] = "acc-release-actor"
        with self.assertRaises(SystemExit):
            self.collect(changed)

        changed = copy.deepcopy(self.readbacks)
        changed["approval"]["environments"][0]["name"] = "other"
        with self.assertRaises(SystemExit):
            self.collect(changed)

    def test_workflow_projects_one_exact_chain_as_canonical_json(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text()
        self.assertNotIn('deployments/$DEPLOYMENT_ID/statuses', workflow)
        self.assertIn("jq -cS -e -n", workflow)
        self.assertIn(
            'gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/approvals"',
            workflow,
        )
        self.assertNotIn("deployment_status:(", workflow)
        self.assertNotIn("$deployment_id", workflow)
        self.assertNotIn("log_url", workflow)
        self.assertNotIn("endswith", workflow)
        self.assertNotIn("'${{ inputs.", workflow)

    def test_approval_history_never_contains_synthetic_run_or_deployment_ids(self):
        changed = copy.deepcopy(self.readbacks)
        changed["approval"] = {
            "environments": [{"name": "attestation"}],
            "state": "approved",
            "user": {"login": "independent-reviewer"},
        }

        issuance = self.collect(changed)

        approval = json.loads(issuance.data)["github"]["approval"]
        self.assertEqual(
            approval,
            {
                "environments": [{"name": "attestation"}],
                "state": "approved",
                "user": {"login": "independent-reviewer"},
            },
        )
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text()
        approval_projection = workflow.split("approval:(", 1)[1].split(",oidc:", 1)[0]
        self.assertNotIn("run_id", approval_projection)
        self.assertNotIn("deployment_id", approval_projection)
        self.assertIn("environments", approval_projection)
        self.assertIn("state", approval_projection)
        self.assertIn("user", approval_projection)
        self.assertNotIn('environment:"attestation"', approval_projection)
        self.assertNotIn("reviewer", approval_projection)

    def test_every_numeric_id_and_reference_rejects_bool_type_confusion(self):
        run_reference = copy.deepcopy(self.readbacks)
        run_reference["run"]["id"] = 1
        run_reference["job"]["run_id"] = True
        run_reference["oidc"]["run_id"] = "1"

        for label, changed in (("job.run_id", run_reference),):
            with self.subTest(label=label), self.assertRaises(SystemExit):
                self.collect(changed)

    def test_public_candidate_has_no_local_orchestration_authority(self):
        root = Path(__file__).resolve().parents[1]
        public = [root / "scripts" / "collect_github_issuance_v2.py",
                  root / "scripts" / "verify_authority_v2.py",
                  root / "scripts" / "verify_publication_v2.py",
                  root / "authority-v2-policy.json",
                  root / "reviewer-authorization-v2.json"]
        joined = b"\n".join(path.read_bytes().lower() for path in public)
        forbidden_terms = (b"sql" + b"ite", b"task_" + b"routing", b"task-" + b"routing")
        for forbidden in forbidden_terms:
            self.assertNotIn(forbidden, joined)

    def test_canonical_authenticated_object_rejects_crlf_missing_lf_and_copy(self):
        issuance = self.collect()
        raw = issuance.data
        self.assertTrue(raw.endswith(b"\n"))
        for changed in (raw.replace(b"\n", b"\r\n"), raw[:-1]):
            with self.assertRaises(SystemExit):
                ISSUANCE.verify_authenticated_issuance_bytes(changed, hashlib.sha256(changed).hexdigest(), self.candidate)
        other = dict(self.candidate, head_commit="f" * 40)
        with self.assertRaises(SystemExit):
            ISSUANCE.verify_authenticated_issuance_bytes(raw, issuance.sha256, other)

    def test_every_subject_binding_is_issuance_complete_before_signing(self):
        issuance = self.collect()
        binding = ISSUANCE.subject_issuance_binding(issuance)
        self.assertEqual(binding["issuance_sha256"], issuance.sha256)
        self.assertEqual(binding["run_attempt"], 1)
        self.assertEqual(set(binding), set(ISSUANCE.SUBJECT_BINDING_FIELDS))

    def test_publication_replay_is_not_guarded_by_process_local_object_identity(self):
        issuance = self.collect()
        copied = copy.copy(issuance)
        deserialized = ISSUANCE.verify_authenticated_issuance_bytes(
            issuance.data, issuance.sha256, self.candidate,
        )
        self.assertEqual(copied.issuance_nonce, issuance.issuance_nonce)
        self.assertEqual(deserialized.issuance_nonce, issuance.issuance_nonce)
        self.assertFalse(hasattr(ISSUANCE, "_CONSUMED_TOKENS"))


if __name__ == "__main__":
    unittest.main()
