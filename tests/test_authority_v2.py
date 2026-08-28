#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from tests.issuance_fixture import authenticated_issuance

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module("build_authority_v2", ROOT / "scripts" / "build_authority_v2.py")
VERIFIER = load_module("verify_authority_v2", ROOT / "scripts" / "verify_authority_v2.py")
ENV_VERIFIER = load_module("verify_github_environment_v2", ROOT / "scripts" / "verify_github_environment_v2.py")


SIGNING_WORKFLOW_RELPATH = ".github/workflows/sign-clerk-attestation-v2.yml"
REVIEW_BOOTSTRAP_RELDIR = "independent-review-bootstrap-v2"
REVIEW_WORKFLOW_RELPATH = ".github/workflows/review-authority-v2.yml"
# The single approved command for the one dedicated post-download
# signed-review inventory step. It is the exact prior production line, so the
# executed inventory stays the same exact three-file check the producer uploads.
APPROVED_SIGNED_REVIEW_INVENTORY_COMMAND = (
    "python3 scripts/verify_authority_v2.py "
    "--verify-signed-review-artifact-inventory "
    '"$AUTHORITY_V2_RUNTIME/independent-review"'
)


def copy_candidate_tree(destination):
    """Copy every manifest-covered candidate artifact into a scratch root."""
    for name in (*VERIFIER.EXPECTED_MANIFEST_PATHS, "AUTHORITY-V2-SHA256SUMS"):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def recompute_candidate_manifest(candidate_root):
    """Recompute AUTHORITY-V2-SHA256SUMS so manifest hash checks pass."""
    lines = []
    for name in VERIFIER.EXPECTED_MANIFEST_PATHS:
        digest = hashlib.sha256((candidate_root / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    (candidate_root / "AUTHORITY-V2-SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def http_capture(payload, *, link=None, status=200,
                 api_version="2022-11-28"):
    """One raw `gh api -i` response capture, exactly as the lane records it."""
    headers = [f"HTTP/2.0 {status} Ok"]
    if api_version is not None:
        headers.append(f"x-github-api-version-selected: {api_version}")
    if link is not None:
        headers.append(f"link: {link}")
    headers.append("content-type: application/json; charset=utf-8")
    body = json.dumps(payload, sort_keys=True).encode() + b"\n"
    return "\r\n".join(headers).encode() + b"\r\n\r\n" + body


def workflow_state_capture(contract, **overrides):
    """The authenticated readback that the sealed workflow really is disabled."""
    payload = {
        "id": 42424242,
        "name": "Export immutable protected Kanban Authority-v2 review",
        "path": contract["workflow"]["path"],
        "state": EXPORT.DISABLED_WORKFLOW_STATE,
        "url": EXPORT.workflow_endpoint(contract),
    }
    payload.update(overrides)
    return {name: value for name, value in payload.items() if value is not None}


def write_run_captures(root, pages, *, contract=None, workflow_state=None,
                       unterminated=None):
    """Write the exhaustive server traversal exactly as the lane captured it.

    Every page but the last advertises the server's own `rel="next"`, and the
    traversal ends where that advertisement stops. `unterminated` models a
    server that never stops advertising one, which must fail closed at the
    finite bound rather than run on.
    """
    if contract is None:
        contract = json.loads((Path(root) / EXPORT.CONTRACT_PATH).read_bytes())
    raw = Path(root) / EXPORT.RAW_DIRECTORY
    raw.mkdir(parents=True, exist_ok=True)
    for stale in raw.glob("runs-page-*.http"):
        stale.unlink()
    endpoint = EXPORT.runs_endpoint(contract)
    per_page = EXPORT.RUNS_PER_PAGE
    first = f"{endpoint}?per_page={per_page}&page=1"
    total = unterminated or len(pages)
    for number in range(1, total + 1):
        page = pages[number - 1] if number <= len(pages) else {
            "total_count": pages[-1]["total_count"], "workflow_runs": [],
        }
        relations = []
        if number > 1:
            relations.append(
                f'<{endpoint}?per_page={per_page}&page={number - 1}>; rel="prev"'
            )
            relations.append(f'<{first}>; rel="first"')
        if number < total or unterminated:
            relations.append(
                f'<{endpoint}?per_page={per_page}&page={number + 1}>; rel="next"'
            )
        (raw / f"runs-page-{number}.http").write_bytes(
            http_capture(page, link=", ".join(relations) or None)
        )
    state = raw / f"{EXPORT.RAW_WORKFLOW_STATE}.http"
    if workflow_state is False:
        state.unlink(missing_ok=True)
    else:
        state.write_bytes(
            http_capture(workflow_state_capture(contract, **(workflow_state or {})))
        )


def verify_candidate_at(candidate_root):
    """Run the candidate verifier against a scratch candidate root."""
    with (
        mock.patch.object(VERIFIER, "ROOT", candidate_root),
        mock.patch.object(VERIFIER, "POLICY_PATH", candidate_root / "authority-v2-policy.json"),
        mock.patch.object(VERIFIER, "SCHEMA_PATH", candidate_root / "schemas/authority-v2-subject.schema.json"),
        mock.patch.object(VERIFIER, "RECEIPT_PATH", candidate_root / "protected-asset-receipt-v2.json"),
        mock.patch.object(VERIFIER, "ENV_CONTRACT_PATH", candidate_root / "github-environment-v2-contract.json"),
        mock.patch.object(VERIFIER, "MANIFEST_PATH", candidate_root / "AUTHORITY-V2-SHA256SUMS"),
    ):
        return VERIFIER.verify_candidate()



def hashedrekord_body(subject, signature, certificate):
    """A real Rekor v1 hashedrekord 0.0.1 body, bound to these exact bytes.

    The transparency body is a closed schema the parser decodes and binds, so
    a placeholder string is not a bundle any boundary may accept. This is the
    smallest body that really records this subject, this signature and this
    certificate.
    """
    return json.dumps({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(subject).hexdigest(),
            }},
            "signature": {
                "content": base64.b64encode(signature).decode("ascii"),
                "publicKey": {
                    "content": base64.b64encode(certificate).decode("ascii"),
                },
            },
        },
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")


class AuthorityV2Tests(unittest.TestCase):
    def setUp(self):
        self.policy_path = ROOT / "authority-v2-policy.json"
        self.policy_bytes = self.policy_path.read_bytes()
        self.policy = json.loads(self.policy_bytes)
        self.activation = "a" * 40
        self.receipt_hash = "b" * 64
        self.issuance = authenticated_issuance(head=self.activation, review_receipt_sha256=self.receipt_hash)

    def exact_environment(self):
        return {
            "GITHUB_SHA": self.activation,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": GENERATOR.EXACT_REPOSITORY,
            "GITHUB_WORKFLOW_REF": GENERATOR.EXACT_WORKFLOW_REF,
        }

    def approved_cosign_fixture(self, root):
        path = root / "cosign"
        version = dict(
            VERIFIER.EXPECTED_COSIGN_BUILD,
            platform=VERIFIER.current_cosign_platform(),
        )
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"VERSION = {version!r}\n"
            "if sys.argv[1:] == ['version', '--json']:\n"
            "    print(json.dumps(VERSION))\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        approval = mock.patch.dict(
            VERIFIER.APPROVED_COSIGN_DIGESTS,
            {VERIFIER.current_cosign_platform(): digest},
            clear=True,
        )
        return path, approval

    def test_cosign_invocation_object_cannot_be_replaced_after_last_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original, approval = self.approved_cosign_fixture(root)
            subject, bundle = root / "subject.json", root / "bundle.json"
            marker = root / "invocation-replacement-executed"
            subject.write_bytes(b'{}\n')
            bundle.write_text(json.dumps(self.valid_bundle()), encoding="utf-8")
            with approval:
                validated = VERIFIER.validate_cosign_binary(original)
                try:
                    real_run = subprocess.run
                    rejected_swaps = []

                    def swap_invocation_then_run(command, **options):
                        replacement = root / "invocation-replacement"
                        replacement.write_text(
                            "#!/usr/bin/env python3\nimport pathlib\n"
                            f"pathlib.Path({str(marker)!r}).write_text('executed')\n",
                            encoding="utf-8",
                        )
                        replacement.chmod(0o755)
                        try:
                            os.replace(replacement, command[0])
                        except OSError as error:
                            rejected_swaps.append(error)
                        return real_run(command, **options)

                    with mock.patch.object(
                        VERIFIER.subprocess, "run", side_effect=swap_invocation_then_run
                    ):
                        VERIFIER._execute_cosign(validated, subject, bundle, "a" * 40)
                finally:
                    validated.close()
        self.assertEqual(len(rejected_swaps), 1)
        self.assertFalse(marker.exists())

    def test_linux_executes_only_the_held_descriptor_via_proc_self_fd(self):
        with tempfile.TemporaryDirectory() as td:
            original, approval = self.approved_cosign_fixture(Path(td))
            with approval:
                validated = VERIFIER.validate_cosign_binary(original)
                try:
                    real_stat = VERIFIER.os.stat
                    observed = {}

                    def descriptor_stat(path, *arguments, **options):
                        prefix = "/proc/self/fd/"
                        if type(path) is str and path.startswith(prefix):
                            return os.fstat(int(path.removeprefix(prefix)))
                        return real_stat(path, *arguments, **options)

                    def descriptor_run(command, **options):
                        inherited = options["pass_fds"]
                        self.assertEqual(command[0], f"/proc/self/fd/{inherited[0]}")
                        self.assertEqual(
                            VERIFIER._stat_identity(os.fstat(inherited[0])),
                            validated.identity,
                        )
                        observed["command"] = command
                        return subprocess.CompletedProcess(command, 0)

                    with (
                        mock.patch.object(VERIFIER.sys, "platform", "linux"),
                        mock.patch.object(VERIFIER.os, "stat", side_effect=descriptor_stat),
                        mock.patch.object(VERIFIER.subprocess, "run", side_effect=descriptor_run),
                    ):
                        VERIFIER._run_verified_cosign(validated, ["verify-blob"])
                finally:
                    validated.close()
        self.assertEqual(observed["command"][1:], ["verify-blob"])

    def test_unsupported_descriptor_execution_platform_fails_before_exec(self):
        with tempfile.TemporaryDirectory() as td:
            original, approval = self.approved_cosign_fixture(Path(td))
            with approval:
                validated = VERIFIER.validate_cosign_binary(original)
                try:
                    with (
                        mock.patch.object(VERIFIER.sys, "platform", "win32"),
                        mock.patch.object(VERIFIER.subprocess, "run") as run,
                        self.assertRaises(SystemExit),
                    ):
                        VERIFIER._run_verified_cosign(validated, ["verify-blob"])
                    run.assert_not_called()
                finally:
                    validated.close()

    def test_generator_emits_exact_three_canonical_bound_subjects(self):
        old_env = {key: os.environ.get(key) for key in self.exact_environment()}
        old_fingerprint = GENERATOR.fingerprint
        os.environ.update(self.exact_environment())
        expected_pub = self.policy["subject"]["clerk_publishable_key_fingerprint_sha256"]
        expected_instance = self.policy["subject"]["clerk_api_instance_id_fingerprint_sha256"]
        GENERATOR.fingerprint = lambda prefix, value: expected_pub if prefix.startswith(b"acc-clerk-instance") else expected_instance
        try:
            with tempfile.TemporaryDirectory() as td:
                out = Path(td)
                generated = GENERATOR.build_subjects(
                    self.policy_path, out, "fixture-publishable", "fixture-instance", self.issuance
                )
                self.assertEqual([p.name for p in generated], [
                    "authority-v2-future.json",
                    "authority-v2-in_window.json",
                    "authority-v2-stale.json",
                ])
                expected_hash = hashlib.sha256(self.policy_bytes).hexdigest()
                for path in generated:
                    payload = json.loads(path.read_bytes())
                    self.assertEqual(path.read_bytes(), VERIFIER.canonical(payload))
                    self.assertEqual(payload, VERIFIER.expected_subject(self.policy, payload["case"], self.activation, self.receipt_hash, self.issuance))
                    self.assertEqual(payload["authority_policy_sha256"], expected_hash)
                    self.assertNotIn("trusted_evaluation_time", json.dumps(payload))
        finally:
            GENERATOR.fingerprint = old_fingerprint
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_generator_rejects_identity_mismatch_and_non_main_context(self):
        old_env = {key: os.environ.get(key) for key in self.exact_environment()}
        os.environ.update(self.exact_environment())
        try:
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(SystemExit):
                    GENERATOR.build_subjects(self.policy_path, Path(td), "wrong", "wrong", self.issuance)
            os.environ["GITHUB_REF"] = "refs/heads/main-suffix"
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(SystemExit):
                    GENERATOR.build_subjects(self.policy_path, Path(td), "wrong", "wrong", self.issuance)
        finally:
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_trusted_time_is_bundle_only_and_classifies_all_exact_cases(self):
        self.assertNotIn("trusted", inspect.signature(VERIFIER.verify_release).parameters)
        trusted = datetime(2026, 8, 25, tzinfo=timezone.utc)
        expected = {"future": "reject_future", "in_window": "accept_freshness_only", "stale": "reject_stale"}
        for case, result in expected.items():
            self.assertEqual(VERIFIER.evaluate(self.policy["temporal_subject_contract"]["cases"][case], trusted), result)

    def valid_bundle(self):
        """The real Cosign v3.1.3 protobuf-JSON v0.3 shape, minimally filled."""
        return {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(hashlib.sha256(b"subject").digest()).decode("ascii"),
                },
                "signature": base64.b64encode(b"signature").decode("ascii"),
            },
            "verificationMaterial": {
                # Raw Cosign v3.1.3 keyless output: the protobuf `content`
                # oneof member appears directly, carrying only the leaf.
                "certificate": {"rawBytes": "Y2VydA=="},
                "tlogEntries": [{
                    "integratedTime": "1787620000",
                    "logIndex": "42",
                    "logId": {"keyId": "cmVrb3I="},
                    "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                    "canonicalizedBody": base64.b64encode(hashedrekord_body(b"subject", b"signature", b"cert")).decode("ascii"),
                    "inclusionPromise": {"signedEntryTimestamp": "c2V0"},
                    "inclusionProof": {
                        "logIndex": "42",
                        "treeSize": "43",
                        "rootHash": "cm9vdA==",
                        "hashes": [],
                        "checkpoint": {"envelope": "checkpoint"},
                    }
                }]
            }
        }

    def test_rekor_time_requires_certificate_transparency_and_integer_time(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bundle.json"
            path.write_text(json.dumps(self.valid_bundle()), encoding="utf-8")
            observed = VERIFIER.extract_rekor_time(path)
            self.assertEqual(int(observed.timestamp()), 1787620000)
            for mutation in ("numeric-time", "leading-zero-time", "numeric-log-index", "missing-certificate",
                             "missing-proof", "missing-promise", "missing-message-signature",
                             "missing-body", "bespoke-legacy-certificate", "bespoke-legacy-chain",
                             "versioned-media-type", "extra-entry"):
                bundle = deepcopy(self.valid_bundle())
                material = bundle["verificationMaterial"]
                if mutation == "numeric-time":
                    material["tlogEntries"][0]["integratedTime"] = 1787620000
                elif mutation == "leading-zero-time":
                    material["tlogEntries"][0]["integratedTime"] = "01787620000"
                elif mutation == "numeric-log-index":
                    material["tlogEntries"][0]["logIndex"] = 42
                elif mutation == "missing-certificate":
                    material.pop("certificate")
                elif mutation == "missing-proof":
                    material["tlogEntries"][0].pop("inclusionProof")
                elif mutation == "missing-promise":
                    material["tlogEntries"][0].pop("inclusionPromise")
                elif mutation == "missing-message-signature":
                    bundle.pop("messageSignature")
                elif mutation == "missing-body":
                    material["tlogEntries"][0].pop("canonicalizedBody")
                elif mutation == "bespoke-legacy-certificate":
                    material["content"] = {"certificate": material["certificate"]}
                    material.pop("certificate")
                elif mutation == "bespoke-legacy-chain":
                    material["x509CertificateChain"] = {
                        "certificates": [material["certificate"]],
                    }
                elif mutation == "versioned-media-type":
                    bundle["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.3"
                else:
                    material["tlogEntries"].append(deepcopy(material["tlogEntries"][0]))
                path.write_text(json.dumps(bundle), encoding="utf-8")
                with self.assertRaises(SystemExit, msg=mutation):
                    VERIFIER.extract_rekor_time(path)

    def test_policy_schema_workflow_and_release_identity_are_literal(self):
        self.assertEqual(self.policy["reviewer_owned_interpretations"], {
            "loopback_api_url_or_sdk_owned_test_fetch": "Acceptable only when the actual @clerk/backend SDK request, authentication, deserialization and error closures execute, with no caller-reachable authority mutation or transport substitution.",
            "non_detached_candidate_child": "Acceptable only for the exact committed candidate clean-launched outside the caller-compromisable heap, with contained descendant lifecycle and no helper or launcher substitution."
        })
        self.assertEqual(hashlib.sha256(self.policy_bytes).hexdigest(), VERIFIER.EXPECTED_POLICY_SHA256)
        schema = json.loads((ROOT / "schemas" / "authority-v2-subject.schema.json").read_bytes())
        self.assertEqual(schema["properties"]["authority_policy_sha256"]["const"], VERIFIER.EXPECTED_POLICY_SHA256)
        tuples = {item["properties"]["case"]["const"]: item["properties"]["case_contract"]["const"] for item in schema["oneOf"]}
        self.assertEqual(tuples, self.policy["temporal_subject_contract"]["cases"])
        workflow = (ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text(encoding="utf-8")
        self.assertIn("on:\n  workflow_dispatch:", workflow)
        self.assertTrue(workflow.startswith(VERIFIER.EXPECTED_WORKFLOW_HEADER))
        self.assertIn("${{ inputs.review_receipt_sha256 }}", workflow)
        self.assertIn("scripts/collect_github_issuance_v2.py", workflow)
        self.assertIn("actions/runs/$GITHUB_RUN_ID/approvals", workflow)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", workflow)
        self.assertNotIn("deployments?environment=attestation", workflow)
        self.assertIn("scripts/verify_publication_v2.py", workflow)
        publication_step = workflow.split("scripts/verify_publication_v2.py", 1)[1]
        self.assertIn('--preissuance-review-receipt-sha256 "$REVIEW_HASH"', publication_step)
        self.assertIn("--github-issuance", publication_step)
        self.assertIn('--cosign "$COSIGN_PATH"', publication_step)
        self.assertNotIn("gh release", workflow)
        environment_contract = json.loads((ROOT / "github-environment-v2-contract.json").read_bytes())
        self.assertEqual(environment_contract["authenticated_issuance"]["run_attempt"], 1)
        self.assertEqual(environment_contract["authenticated_issuance"]["oidc_audience"], "sigstore")
        self.assertNotIn("environment_deployment_status", environment_contract["authenticated_issuance"]["exact_server_readbacks"])
        self.assertEqual(
            environment_contract["authenticated_issuance"]["unsupported_deployment_relationship_evidence"],
            VERIFIER.EXPECTED_UNSUPPORTED_DEPLOYMENT_EVIDENCE,
        )
        self.assertEqual(
            environment_contract["authenticated_issuance"]["run_scoped_environment_approval_binding"],
            VERIFIER.EXPECTED_RUN_SCOPED_APPROVAL_BINDING,
        )
        self.assertTrue(environment_contract["authenticated_issuance"]["self_review_forbidden"])
        for alternate in ("schedule:", "push:", "pull_request:", "workflow_call:"):
            self.assertNotIn(alternate, workflow)
        self.assertEqual(self.policy["issuance_contract"]["release_tag"], "clerk-instance-attestation-v2")
        self.assertEqual(
            self.policy["publication_contract"],
            VERIFIER.EXPECTED_PUBLICATION_CONTRACT,
        )
        publication = self.policy["publication_contract"]
        self.assertEqual(publication["activation_state"], "unavailable")
        for prohibited in (
            "draft_creation_allowed", "asset_upload_allowed", "tag_or_claim_write_allowed",
        ):
            self.assertFalse(publication[prohibited])
        self.assertTrue(publication["irreversible_publication_forbidden"])
        self.assertTrue(publication["reconciliation"]["read_only"])
        self.assertTrue(publication["reconciliation"]["idempotent"])
        github_issuance = self.policy["issuance_contract"]["authenticated_github_issuance"]
        self.assertEqual(github_issuance["contract"], "authenticated-github-environment-oidc-issuance-v2")
        self.assertEqual(github_issuance["run_attempt"], 1)
        self.assertEqual(github_issuance["oidc_audience"], "sigstore")
        self.assertEqual(
            github_issuance["unsupported_deployment_relationship_evidence"],
            VERIFIER.EXPECTED_UNSUPPORTED_DEPLOYMENT_EVIDENCE,
        )
        self.assertEqual(
            github_issuance["run_scoped_environment_approval_binding"],
            VERIFIER.EXPECTED_RUN_SCOPED_APPROVAL_BINDING,
        )
        self.assertTrue(github_issuance["durable_github_nonce_and_issuance_claim"])
        self.assertTrue(github_issuance["all_subjects_validated_before_first_sign_blob"])
        self.assertIn("preissuance-review-receipt.sigstore.json", publication_step)
        self.assertNotIn("COSIGN_PRIVATE_KEY", workflow)
        self.assertIn("Generate sign and verify exact authenticated issuance without publication", workflow)
        self.assertEqual(self.policy["cosign_verification_contract"]["approved_standalone_sha256"], VERIFIER.APPROVED_COSIGN_DIGESTS)
        self.assertEqual(self.policy["issuance_contract"]["preissuance_receipt_contract"]["closure_matrix_keys"], list(VERIFIER.EXPECTED_CLOSURES))

    def test_source_reviewed_issuance_lane_has_no_repository_write_credential(self):
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        permissions = workflow.split("permissions:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(
            permissions,
            "  actions: read\n  contents: read\n  id-token: write",
        )
        self.assertNotIn("contents: write", workflow)
        checkout = workflow.split(
            "uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            1,
        )[1].split("\n\n", 1)[0]
        self.assertIn("persist-credentials: false", checkout)

    def test_complete_candidate_boundary_rejects_public_binding_mutations(self):
        def copy_candidate(destination):
            for name in (*VERIFIER.EXPECTED_MANIFEST_PATHS, "AUTHORITY-V2-SHA256SUMS"):
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)

        def verify_at(candidate_root):
            with (
                mock.patch.object(VERIFIER, "ROOT", candidate_root),
                mock.patch.object(VERIFIER, "POLICY_PATH", candidate_root / "authority-v2-policy.json"),
                mock.patch.object(VERIFIER, "SCHEMA_PATH", candidate_root / "schemas/authority-v2-subject.schema.json"),
                mock.patch.object(VERIFIER, "RECEIPT_PATH", candidate_root / "protected-asset-receipt-v2.json"),
                mock.patch.object(VERIFIER, "ENV_CONTRACT_PATH", candidate_root / "github-environment-v2-contract.json"),
                mock.patch.object(VERIFIER, "MANIFEST_PATH", candidate_root / "AUTHORITY-V2-SHA256SUMS"),
            ):
                return VERIFIER.verify_candidate()

        mutations = {
            "policy": lambda root: (root / "authority-v2-policy.json").write_bytes(self.policy_bytes + b" "),
            "schema": lambda root: (root / "schemas/authority-v2-subject.schema.json").write_bytes(
                (root / "schemas/authority-v2-subject.schema.json").read_bytes() + b" "
            ),
            "protected-receipt": lambda root: (root / "protected-asset-receipt-v2.json").write_bytes(
                (root / "protected-asset-receipt-v2.json").read_bytes() + b" "
            ),
            "manifest": lambda root: (root / "AUTHORITY-V2-SHA256SUMS").write_text(
                "0" * 64 + (root / "AUTHORITY-V2-SHA256SUMS").read_text(encoding="utf-8")[64:], encoding="utf-8"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                candidate_root = Path(td)
                copy_candidate(candidate_root)
                mutate(candidate_root)
                with self.assertRaises(SystemExit):
                    verify_at(candidate_root)

    def test_environment_contract_rejects_admin_bypass_self_review_and_non_main(self):
        contract = json.loads((ROOT / "github-environment-v2-contract.json").read_bytes())
        sealed = contract["sealed_environment_readback"]
        repository = {"full_name": contract["repository"], "private": False}
        environment = {
            "id": sealed["environment_id"],
            "name": contract["environment"],
            "can_admins_bypass": False,
            "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "User", "reviewer": {"login": sealed["required_reviewer_logins"][0]}}]}]
        }
        branches = None
        secrets = {"total_count": 0, "secrets": []}
        immutable = {"enabled": True, "enforced_by_owner": False}
        result = ENV_VERIFIER.verify_environment(
            repository, environment, branches, immutable, contract,
            branch_policies_status=404,
            environment_status=200, authenticated=True, environment_secrets=secrets,
        )
        self.assertFalse(result["main_only"])
        for mutation in ("admin-bypass", "self-review", "non-main", "private-repository", "mutable-releases"):
            repo_changed = deepcopy(repository)
            env_changed = deepcopy(environment)
            branches_changed = deepcopy(branches)
            immutable_changed = deepcopy(immutable)
            branch_status = 404
            if mutation == "admin-bypass":
                env_changed["can_admins_bypass"] = True
            elif mutation == "self-review":
                env_changed["protection_rules"][0]["prevent_self_review"] = False
            elif mutation == "non-main":
                env_changed["deployment_branch_policy"] = {"protected_branches": False, "custom_branch_policies": True}
                branches_changed = {"total_count": 1, "branch_policies": [{"type": "branch", "name": "release/*"}]}
                branch_status = 200
            elif mutation == "private-repository":
                repo_changed["private"] = True
            else:
                immutable_changed["enabled"] = False
            with self.assertRaises(SystemExit, msg=mutation):
                ENV_VERIFIER.verify_environment(
                    repo_changed, env_changed, branches_changed, immutable_changed, contract,
                    branch_policies_status=branch_status,
                    environment_status=200, authenticated=True,
                    environment_secrets=deepcopy(secrets),
                )

    def test_protected_branch_mode_accepts_documented_branch_policy_404(self):
        contract = json.loads((ROOT / "github-environment-v2-contract.json").read_bytes())
        sealed = contract["sealed_environment_readback"]
        repository = {"full_name": contract["repository"], "private": False}
        environment = {
            "id": sealed["environment_id"],
            "name": contract["environment"],
            "can_admins_bypass": False,
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
            "protection_rules": [{
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{
                    "type": "User",
                    "reviewer": {"login": sealed["required_reviewer_logins"][0]},
                }],
            }],
        }
        immutable = {"enabled": True, "enforced_by_owner": False}

        result = ENV_VERIFIER.verify_environment(
            repository, environment, None, immutable, contract,
            branch_policies_status=404,
            environment_status=200, authenticated=True,
            environment_secrets={"total_count": 0, "secrets": []},
        )

        self.assertEqual(result["deployment_branch_policy_mode"], "protected_branches")
        workflow = (ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text()
        self.assertIn("--branch-policies-status", workflow)

    def test_review_receipt_requires_pinned_independent_sigstore_identity(self):
        authorization = json.loads((ROOT / "reviewer-authorization-v2.json").read_bytes())
        signature = authorization["review_receipt_signature"]
        self.assertEqual(signature["issuer"], "https://token.actions.githubusercontent.com")
        self.assertEqual(
            signature["identity"],
            "https://github.com/chrizzatsu/acc-authority-independent-review/.github/workflows/review-authority-v2.yml@refs/heads/main",
        )
        command = VERIFIER._review_receipt_cosign_command(
            Path("/private/receipt.json"), Path("/private/receipt.sigstore.json"), "d" * 40,
        )
        self.assertEqual(command[0], "verify-blob")
        self.assertIn(signature["identity"], command)
        self.assertIn(signature["issuer"], command)

        workflow = (ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text()
        self.assertNotIn("review_receipt_bundle_base64:", workflow)
        self.assertNotIn("review_receipt_base64:", workflow)
        self.assertIn("independent_review_run_id:", workflow)
        self.assertIn("actions/download-artifact@", workflow)
        authenticated = workflow.index("--authenticate-preissuance-review-bundle")
        collected = workflow.index("scripts/collect_github_issuance_v2.py")
        self.assertLess(authenticated, collected)

    def test_signed_review_artifact_name_matches_producer_and_consumer(self):
        """F3: SIGNED-REVIEW-ARTIFACT-NAME-UNVERIFIED adversarial probe.

        The signed review artifact name, files, and retention must be
        byte-identical across all four production sources:
          1. bootstrap contract signed_artifact metadata
          2. producer upload-artifact step in the independent review workflow
          3. consumer download-artifact step in the signing workflow
          4. verifier literal in verify_authority_v2.py

        Any divergence means the download silently fails, fetches the wrong
        artifact, or an attacker substitutes a forged artifact name.
        """
        # --- Source 1: bootstrap contract signed_artifact metadata ---
        bootstrap_contract = json.loads(
            (ROOT / "independent-review-bootstrap-v2" / "bootstrap-contract.json").read_bytes()
        )
        signed = bootstrap_contract["signed_artifact"]
        contract_name = signed["name"]
        contract_files = signed["files"]
        contract_retention = signed["retention_days"]
        self.assertEqual(contract_name, "authority-v2-signed-review-t_c298fca4")
        self.assertEqual(contract_files, [
            "kanban-review-envelope.json",
            "preissuance-review-receipt.json",
            "preissuance-review-receipt.sigstore.json",
        ])
        self.assertEqual(contract_retention, 1)

        # --- Source 2: producer upload-artifact in independent review workflow ---
        producer_workflow = (
            ROOT / "independent-review-bootstrap-v2" / ".github" / "workflows" / "review-authority-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f"name: {contract_name}",
            producer_workflow,
            "producer upload artifact name must match contract signed_artifact.name",
        )
        self.assertIn(
            f"retention-days: {contract_retention}",
            producer_workflow,
            "producer retention-days must match contract signed_artifact.retention_days",
        )
        for filename in contract_files:
            self.assertIn(
                filename,
                producer_workflow,
                f"producer upload must include contract signed_artifact file: {filename}",
            )

        # --- Source 3: consumer download-artifact in signing workflow ---
        signing_workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f"name: {contract_name}",
            signing_workflow,
            "consumer download artifact name must match contract signed_artifact.name",
        )
        self.assertNotIn(
            "name: authority-v2-signed-review-${{ inputs.candidate_head }}",
            signing_workflow,
            "signing workflow must not use inputs.candidate_head for signed review artifact name",
        )

        # --- Source 4: verifier literal binding ---
        self.assertEqual(
            VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_NAME,
            contract_name,
            "verifier must have a literal expected signed review artifact name matching the contract",
        )
        self.assertEqual(
            VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES,
            contract_files,
            "verifier must have literal expected signed review artifact files matching the contract",
        )
        self.assertEqual(
            VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_RETENTION_DAYS,
            contract_retention,
            "verifier must have literal expected signed review artifact retention_days matching the contract",
        )

        # --- Adversarial: verify_independent_review_bootstrap rejects divergent signed_artifact ---
        for mutation_label, mutate_fn in (
            ("divergent-name", lambda c: c["signed_artifact"].__setitem__("name", "authority-v2-signed-review-t_ATTACKER")),
            ("divergent-files", lambda c: c["signed_artifact"].__setitem__("files", ["forged.json"])),
            ("extra-file", lambda c: c["signed_artifact"]["files"].append("extra-injected.json")),
            ("divergent-retention", lambda c: c["signed_artifact"].__setitem__("retention_days", 90)),
            ("missing-signed-artifact", lambda c: c.__delitem__("signed_artifact")),
        ):
            with self.subTest(mutation=mutation_label), tempfile.TemporaryDirectory() as td:
                changed = Path(td) / "bootstrap"
                shutil.copytree(ROOT / "independent-review-bootstrap-v2", changed)
                changed_contract_path = changed / "bootstrap-contract.json"
                changed_contract = json.loads(changed_contract_path.read_bytes())
                mutate_fn(changed_contract)
                changed_contract_path.write_bytes(VERIFIER.canonical(changed_contract))
                with self.assertRaises(SystemExit, msg=mutation_label):
                    VERIFIER.verify_independent_review_bootstrap(changed)

    def test_artifact_action_parsers_cover_optional_metadata_and_key_order(self):
        upload_uses = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        download_uses = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
        upload = """jobs:
  review:
    steps:
      - id: signed-review
        if: ${{ always() }}
        with:
          retention-days: 1
          path: |
            protected-review/kanban-review-envelope.json
            protected-review/preissuance-review-receipt.json
            protected-review/preissuance-review-receipt.sigstore.json
          name: authority-v2-signed-review-t_c298fca4
          if-no-files-found: error
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
"""
        download = """jobs:
  issue:
    steps:
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        if: ${{ success() }}
        id: signed-review
        with:
          github-token: ${{ steps.review-token.outputs.token }}
          run-id: ${{ inputs.independent_review_run_id }}
          repository: chrizzatsu/acc-authority-independent-review
          path: ${{ runner.temp }}/authority-v2-runtime/independent-review
          name: authority-v2-signed-review-t_c298fca4
"""
        self.assertEqual(
            VERIFIER._parse_upload_artifact_steps(upload),
            [{
                "uses": upload_uses,
                "with": {
                    "name": "authority-v2-signed-review-t_c298fca4",
                    "if-no-files-found": "error",
                    "retention-days": "1",
                    "path": (
                        "protected-review/kanban-review-envelope.json\n"
                        "protected-review/preissuance-review-receipt.json\n"
                        "protected-review/preissuance-review-receipt.sigstore.json\n"
                    ),
                },
            }],
        )
        self.assertEqual(
            VERIFIER._parse_download_artifact_steps(download),
            [{
                "uses": download_uses,
                "with": {
                    "name": "authority-v2-signed-review-t_c298fca4",
                    "path": "${{ runner.temp }}/authority-v2-runtime/independent-review",
                    "repository": "chrizzatsu/acc-authority-independent-review",
                    "run-id": "${{ inputs.independent_review_run_id }}",
                    "github-token": "${{ steps.review-token.outputs.token }}",
                },
            }],
        )

    def test_producer_upload_artifact_name_parsed_and_bound_by_verifier(self):
        """F3: SIGNED-REVIEW-ARTIFACT-NAME-UNVERIFIED producer-step binding.

        verify_independent_review_bootstrap must parse the upload-artifact
        step in the producer workflow and require exact name, files, and
        retention_days match. Modifying the workflow step while updating
        the contract's workflow sha256 must still fail closed.
        """
        bootstrap_root = ROOT / "independent-review-bootstrap-v2"

        # Build targeted mutations that hit the upload-artifact path block
        upload_path_block = (
            "            protected-review/kanban-review-envelope.json\n"
            "            protected-review/preissuance-review-receipt.json\n"
            "            protected-review/preissuance-review-receipt.sigstore.json\n"
        )
        forged_path_block = (
            "            protected-review/kanban-review-envelope.json\n"
            "            protected-review/preissuance-review-receipt.json\n"
            "            protected-review/FORGED.sigstore.json\n"
        )
        duplicate_upload_suffix = (
            "\n"
            "      - id: attacker-upload\n"
            "        if: ${{ always() }}\n"
            "        with:\n"
            "          retention-days: 1\n"
            "          path: |\n"
            "            protected-review/kanban-review-envelope.json\n"
            "            protected-review/preissuance-review-receipt.json\n"
            "            protected-review/preissuance-review-receipt.sigstore.json\n"
            "          name: authority-v2-signed-review-t_ATTACKER\n"
            "          if-no-files-found: error\n"
            "        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
        )
        for label, old_fragment, new_fragment in (
            (
                "divergent-upload-name",
                "name: authority-v2-signed-review-t_c298fca4",
                "name: authority-v2-signed-review-t_ATTACKER",
            ),
            (
                "divergent-upload-retention",
                "retention-days: 1",
                "retention-days: 90",
            ),
            (
                "divergent-upload-files",
                upload_path_block,
                forged_path_block,
            ),
            (
                "divergent-upload-action-pin",
                "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
                "actions/upload-artifact@" + "0" * 40,
            ),
            (
                "incomplete-upload-with-map",
                "          if-no-files-found: error\n",
                "",
            ),
            (
                "extra-upload-with-map-key",
                "          if-no-files-found: error\n",
                "          if-no-files-found: error\n          compression-level: 9\n",
            ),
            (
                "duplicate-upload-step",
                "            protected-review/preissuance-review-receipt.sigstore.json\n",
                "            protected-review/preissuance-review-receipt.sigstore.json\n" + duplicate_upload_suffix,
            ),
        ):
            with self.subTest(mutation=label), tempfile.TemporaryDirectory() as td:
                changed = Path(td) / "bootstrap"
                shutil.copytree(bootstrap_root, changed)
                wf_path = changed / ".github" / "workflows" / "review-authority-v2.yml"
                original_text = wf_path.read_text(encoding="utf-8")
                modified_text = original_text.replace(old_fragment, new_fragment, 1)
                self.assertNotEqual(original_text, modified_text, f"replacement had no effect: {label}")
                wf_path.write_text(modified_text, encoding="utf-8")
                # Update the contract workflow sha256 to match the modified bytes
                # so the hash check alone does NOT catch this
                contract_path = changed / "bootstrap-contract.json"
                contract = json.loads(contract_path.read_bytes())
                contract["workflow"]["sha256"] = hashlib.sha256(
                    wf_path.read_bytes()
                ).hexdigest()
                contract_path.write_bytes(VERIFIER.canonical(contract))
                with self.assertRaises(SystemExit, msg=label):
                    VERIFIER.verify_independent_review_bootstrap(changed)

    def test_consumer_download_artifact_name_parsed_and_bound_by_verifier(self):
        """F3: SIGNED-REVIEW-ARTIFACT-NAME-UNVERIFIED consumer-step binding.

        verify_candidate must parse the download-artifact step in the
        signing workflow for the signed review artifact and require the
        exact name matches the verifier literal. Substituting the name
        while keeping manifests consistent must still fail closed.
        """
        def copy_candidate(destination):
            for name in (*VERIFIER.EXPECTED_MANIFEST_PATHS, "AUTHORITY-V2-SHA256SUMS"):
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)

        def verify_at(candidate_root):
            with (
                mock.patch.object(VERIFIER, "ROOT", candidate_root),
                mock.patch.object(VERIFIER, "POLICY_PATH", candidate_root / "authority-v2-policy.json"),
                mock.patch.object(VERIFIER, "SCHEMA_PATH", candidate_root / "schemas/authority-v2-subject.schema.json"),
                mock.patch.object(VERIFIER, "RECEIPT_PATH", candidate_root / "protected-asset-receipt-v2.json"),
                mock.patch.object(VERIFIER, "ENV_CONTRACT_PATH", candidate_root / "github-environment-v2-contract.json"),
                mock.patch.object(VERIFIER, "MANIFEST_PATH", candidate_root / "AUTHORITY-V2-SHA256SUMS"),
            ):
                return VERIFIER.verify_candidate()

        duplicate_download_suffix = (
            "\n"
            "      - id: attacker-download\n"
            "        if: ${{ always() }}\n"
            "        with:\n"
            "          github-token: ${{ steps.review-token.outputs.token }}\n"
            "          run-id: ${{ inputs.independent_review_run_id }}\n"
            "          repository: chrizzatsu/acc-authority-independent-review\n"
            "          path: injected\n"
            "          name: authority-v2-signed-review-t_ATTACKER\n"
            "        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
        )
        for label, old_fragment, new_fragment in (
            (
                "divergent-consumer-download-name",
                "name: authority-v2-signed-review-t_c298fca4",
                "name: authority-v2-signed-review-t_ATTACKER",
            ),
            (
                "divergent-consumer-action-pin",
                "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
                "actions/download-artifact@" + "0" * 40,
            ),
            (
                "divergent-consumer-path",
                "path: ${{ runner.temp }}/authority-v2-runtime/independent-review",
                "path: injected",
            ),
            (
                "divergent-consumer-repository",
                "repository: chrizzatsu/acc-authority-independent-review",
                "repository: attacker/review",
            ),
            (
                "divergent-consumer-run-id",
                "run-id: ${{ inputs.independent_review_run_id }}",
                "run-id: 1234",
            ),
            (
                "divergent-consumer-token",
                "github-token: ${{ steps.review-token.outputs.token }}",
                "github-token: ${{ github.token }}",
            ),
            (
                "extra-consumer-with-map-key",
                "          github-token: ${{ steps.review-token.outputs.token }}\n",
                "          github-token: ${{ steps.review-token.outputs.token }}\n          merge-multiple: true\n",
            ),
            (
                "missing-post-download-inventory",
                (
            "      - name: Inventory the exact downloaded signed review artifact\n"
            "        run: |-\n"
            f"          {APPROVED_SIGNED_REVIEW_INVENTORY_COMMAND}\n"
                ),
                "",
            ),
            (
                "duplicate-consumer-download-step",
                "          github-token: ${{ steps.review-token.outputs.token }}\n",
                "          github-token: ${{ steps.review-token.outputs.token }}\n" + duplicate_download_suffix,
            ),
        ):
            with self.subTest(mutation=label), tempfile.TemporaryDirectory() as td:
                candidate_root = Path(td)
                copy_candidate(candidate_root)
                wf_path = candidate_root / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
                original_text = wf_path.read_text(encoding="utf-8")
                modified_text = original_text.replace(old_fragment, new_fragment, 1)
                self.assertNotEqual(original_text, modified_text, f"replacement had no effect: {label}")
                wf_path.write_text(modified_text, encoding="utf-8")
                # Recompute manifest so the manifest hash check passes
                self._recompute_manifest(candidate_root)
                with self.assertRaises(SystemExit, msg=label):
                    verify_at(candidate_root)

    def test_signed_review_post_download_inventory_rejects_missing_and_extra_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES:
                (root / name).write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                VERIFIER.verify_signed_review_artifact_inventory(root),
                sorted(VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES),
            )
            (root / VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES[0]).unlink()
            with self.assertRaises(SystemExit):
                VERIFIER.verify_signed_review_artifact_inventory(root)
            (root / VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES[0]).write_text("{}\n", encoding="utf-8")
            (root / "attacker-extra.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                VERIFIER.verify_signed_review_artifact_inventory(root)

    def _recompute_manifest(self, candidate_root):
        """Recompute AUTHORITY-V2-SHA256SUMS so manifest hash checks pass."""
        lines = []
        for name in VERIFIER.EXPECTED_MANIFEST_PATHS:
            path = candidate_root / name
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (candidate_root / "AUTHORITY-V2-SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def _copy_candidate(self, destination):
        """Copy every manifest-covered candidate artifact into a scratch root."""
        for name in (*VERIFIER.EXPECTED_MANIFEST_PATHS, "AUTHORITY-V2-SHA256SUMS"):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)

    def _verify_at(self, candidate_root):
        """Run the candidate verifier against a scratch candidate root."""
        with (
            mock.patch.object(VERIFIER, "ROOT", candidate_root),
            mock.patch.object(VERIFIER, "POLICY_PATH", candidate_root / "authority-v2-policy.json"),
            mock.patch.object(VERIFIER, "SCHEMA_PATH", candidate_root / "schemas/authority-v2-subject.schema.json"),
            mock.patch.object(VERIFIER, "RECEIPT_PATH", candidate_root / "protected-asset-receipt-v2.json"),
            mock.patch.object(VERIFIER, "ENV_CONTRACT_PATH", candidate_root / "github-environment-v2-contract.json"),
            mock.patch.object(VERIFIER, "MANIFEST_PATH", candidate_root / "AUTHORITY-V2-SHA256SUMS"),
        ):
            return VERIFIER.verify_candidate()

    def test_independent_review_bootstrap_is_sealed_and_rejects_caller_receipt_bytes(self):
        bootstrap = ROOT / "independent-review-bootstrap-v2"
        contract = VERIFIER.verify_independent_review_bootstrap(bootstrap)
        workflow = bootstrap / contract["workflow"]["path"]
        workflow_bytes = workflow.read_bytes()
        self.assertEqual(
            hashlib.sha256(workflow_bytes).hexdigest(),
            contract["workflow"]["sha256"],
        )
        self.assertEqual(
            contract["workflow"]["identity"],
            "https://github.com/chrizzatsu/acc-authority-independent-review/.github/workflows/review-authority-v2.yml@refs/heads/main",
        )
        self.assertEqual(
            contract["protected_source"]["task_id"], "t_c298fca4"
        )
        self.assertTrue(contract["caller_supplied_receipt_bytes_forbidden"])
        workflow_text = workflow_bytes.decode("utf-8")
        self.assertNotIn("review_receipt_base64:", workflow_text)
        self.assertNotIn("review_receipt_bundle_base64:", workflow_text)
        self.assertIn("download-artifact", workflow_text)

        authority_workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text()
        self.assertNotIn("review_receipt_base64:", authority_workflow)
        self.assertNotIn("review_receipt_bundle_base64:", authority_workflow)
        self.assertIn("independent_review_run_id:", authority_workflow)

        with tempfile.TemporaryDirectory() as td:
            changed = Path(td) / "bootstrap"
            shutil.copytree(bootstrap, changed)
            changed_contract_path = changed / "bootstrap-contract.json"
            changed_contract = json.loads(changed_contract_path.read_bytes())
            changed_contract["workflow"]["identity"] = (
                "https://github.com/example/forged/.github/workflows/review.yml@refs/heads/main"
            )
            changed_contract_path.write_bytes(VERIFIER.canonical(changed_contract))
            with self.assertRaises(SystemExit):
                VERIFIER.verify_independent_review_bootstrap(changed)
            (changed / contract["workflow"]["path"]).unlink()
            with self.assertRaises(SystemExit):
                VERIFIER.verify_independent_review_bootstrap(changed)

    def test_all_closed_subjects_and_review_bindings_precede_first_sign_blob(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subjects = root / "subjects"
            subjects.mkdir()
            for case in VERIFIER.EXPECTED_CASES:
                payload = VERIFIER.expected_subject(
                    self.policy, case, self.activation, self.receipt_hash, self.issuance
                )
                if case == "stale":
                    payload["caller_injected"] = True
                (subjects / f"authority-v2-{case}.json").write_bytes(VERIFIER.canonical(payload))
            receipt = root / "receipt.json"
            receipt.write_bytes(b"{}\n")
            receipt_bundle = root / "receipt.sigstore.json"
            receipt_bundle.write_bytes(b"{}\n")
            issuance = root / "issuance.json"
            issuance.write_bytes(self.issuance.data)
            cosign = mock.Mock(spec=VERIFIER.VerifiedCosign)

            with (
                mock.patch.object(VERIFIER, "verify_candidate", return_value=(self.policy, 1)),
                mock.patch.object(VERIFIER, "recompute_review_bindings", return_value={"candidate": {}, "protected_identity_asset": {}}),
                mock.patch.object(VERIFIER, "authenticate_github_issuance", return_value=self.issuance),
                mock.patch.object(VERIFIER, "verify_preissuance_receipt", return_value={}),
                mock.patch.object(VERIFIER, "validate_cosign_binary", return_value=cosign),
                mock.patch.object(VERIFIER, "_authenticate_review_receipt_with_cosign", return_value=None),
                mock.patch.object(VERIFIER, "_run_verified_cosign") as run,
                self.assertRaises(SystemExit),
            ):
                VERIFIER.sign_subjects(
                    subjects, "/approved/cosign", self.activation,
                    receipt, self.receipt_hash, receipt_bundle,
                    issuance, self.issuance.sha256,
                )

            run.assert_not_called()

    def test_protected_branch_mode_never_claims_main_only(self):
        contract = json.loads((ROOT / "github-environment-v2-contract.json").read_bytes())
        sealed = contract["sealed_environment_readback"]
        repository = {"full_name": contract["repository"], "private": False}
        environment = {
            "id": sealed["environment_id"],
            "name": contract["environment"],
            "can_admins_bypass": False,
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
            "protection_rules": [{
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{
                    "type": "User",
                    "reviewer": {"login": sealed["required_reviewer_logins"][0]},
                }],
            }],
        }
        immutable = {"enabled": True, "enforced_by_owner": False}

        protected = ENV_VERIFIER.verify_environment(
            repository, environment, None, immutable, contract,
            branch_policies_status=404,
            environment_status=200, authenticated=True,
            environment_secrets={"total_count": 0, "secrets": []},
        )

        self.assertFalse(protected["main_only"])
        self.assertNotIn("allowed_refs", contract["deployment_branch_policy"])

        custom_contract = deepcopy(contract)
        custom_contract["deployment_branch_policy"] = {
            "protected_branches": False,
            "custom_branch_policies": True,
            "allowed_refs": ["refs/heads/main"],
        }
        custom_environment = deepcopy(environment)
        custom_environment["deployment_branch_policy"] = {
            "protected_branches": False,
            "custom_branch_policies": True,
        }
        custom_contract["sealed_environment_readback"]["protected_branches"] = False
        custom = ENV_VERIFIER.verify_environment(
            repository, custom_environment,
            {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]},
            immutable, custom_contract, branch_policies_status=200,
            environment_status=200, authenticated=True,
            environment_secrets={"total_count": 0, "secrets": []},
        )
        self.assertTrue(custom["main_only"])

    def test_release_inventory_rejects_missing_extra_and_swapped_names_before_cosign(self):
        # The one shared release evidence inventory, including the sealed
        # runner state every downstream verifier now binds.
        names = VERIFIER.release_evidence_inventory()
        self.assertIn(VERIFIER.RUNNER_STATE_ASSET_NAME, names)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in names:
                (root / name).write_text("{}", encoding="utf-8")
            self.assertEqual(VERIFIER.verify_release_inventory(root), names)
            (root / names[0]).unlink()
            with self.assertRaises(SystemExit):
                VERIFIER.verify_release_inventory(root)
            (root / names[0]).write_text("{}", encoding="utf-8")
            (root / "authority-v2-extra.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(SystemExit):
                VERIFIER.verify_release_inventory(root)

    # ------------------------------------------------------------------
    # t_0c90990f FINDING 1 -- structural fail-closed artifact enumeration
    # ------------------------------------------------------------------
    UPLOAD_USES = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    DOWNLOAD_USES = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"

    def expected_upload_step(self):
        return {"uses": self.UPLOAD_USES, "with": dict(VERIFIER.EXPECTED_SIGNED_REVIEW_UPLOAD_WITH)}

    def expected_download_step(self):
        return {"uses": self.DOWNLOAD_USES, "with": dict(VERIFIER.EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH)}

    def test_artifact_enumeration_reads_quoted_keys(self):
        """F1: single/double quoted mapping keys must never hide an invocation."""
        quoted = """jobs:
  review:
    steps:
      - "name": Upload immutable signed review artifact
        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        "with":
          'name': authority-v2-signed-review-t_c298fca4
          'if-no-files-found': error
          'retention-days': 1
          'path': |
            protected-review/kanban-review-envelope.json
            protected-review/preissuance-review-receipt.json
            protected-review/preissuance-review-receipt.sigstore.json
"""
        self.assertEqual(
            VERIFIER._parse_upload_artifact_steps(quoted),
            [self.expected_upload_step()],
            "quoted keys must not hide an upload-artifact invocation",
        )

    def test_artifact_enumeration_reads_spaced_keys(self):
        """F1: space-separated `key :` mapping keys must never hide an invocation."""
        spaced = """jobs:
  issue:
    steps:
      - name : Download exact independently signed receipt
        uses : actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with :
          name : authority-v2-signed-review-t_c298fca4
          path : ${{ runner.temp }}/authority-v2-runtime/independent-review
          repository : chrizzatsu/acc-authority-independent-review
          run-id : ${{ inputs.independent_review_run_id }}
          github-token : ${{ steps.review-token.outputs.token }}
"""
        self.assertEqual(
            VERIFIER._parse_download_artifact_steps(spaced),
            [self.expected_download_step()],
            "spaced keys must not hide a download-artifact invocation",
        )

    def test_artifact_enumeration_reads_flow_maps(self):
        """F1: flow-map steps and flow-map `with` blocks must never hide an invocation."""
        flow_upload = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - {name: Upload, uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02,"
            " with: {name: authority-v2-signed-review-t_c298fca4, if-no-files-found: error, retention-days: 1,"
            ' path: "protected-review/kanban-review-envelope.json\\nprotected-review/preissuance-review-receipt.json'
            '\\nprotected-review/preissuance-review-receipt.sigstore.json\\n"}}\n'
        )
        flow_download = (
            "jobs:\n"
            "  issue:\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
            "        with: {name: authority-v2-signed-review-t_c298fca4,"
            ' path: "${{ runner.temp }}/authority-v2-runtime/independent-review",'
            " repository: chrizzatsu/acc-authority-independent-review,"
            ' run-id: "${{ inputs.independent_review_run_id }}",'
            ' github-token: "${{ steps.review-token.outputs.token }}"}\n'
        )
        self.assertEqual(
            VERIFIER._parse_upload_artifact_steps(flow_upload),
            [self.expected_upload_step()],
            "flow-map steps must not hide an upload-artifact invocation",
        )
        self.assertEqual(
            VERIFIER._parse_download_artifact_steps(flow_download),
            [self.expected_download_step()],
            "flow-map `with` must not hide a download-artifact invocation",
        )

    def test_artifact_enumeration_is_key_order_independent(self):
        """F1: mapping key order must never change the enumerated result."""
        reordered = """jobs:
  issue:
    steps:
      - with:
          github-token: ${{ steps.review-token.outputs.token }}
          run-id: ${{ inputs.independent_review_run_id }}
          repository: chrizzatsu/acc-authority-independent-review
          path: ${{ runner.temp }}/authority-v2-runtime/independent-review
          name: authority-v2-signed-review-t_c298fca4
        id: signed-review
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        if: ${{ success() }}
"""
        self.assertEqual(
            VERIFIER._parse_download_artifact_steps(reordered),
            [self.expected_download_step()],
        )

    def test_artifact_enumeration_fails_closed_on_unsupported_yaml_forms(self):
        """F1: anchors/aliases, merge keys, tags, multi-doc, tabs and folded scalars fail closed."""
        alias = """jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with: &signed_review_with
          name: authority-v2-signed-review-t_c298fca4
          if-no-files-found: error
          retention-days: 1
          path: protected-review/kanban-review-envelope.json
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with: *signed_review_with
"""
        merge_key = """jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          <<: *defaults
          name: authority-v2-signed-review-t_c298fca4
"""
        tagged = """jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with: !!map
          name: authority-v2-signed-review-t_c298fca4
"""
        multi_document = """---
jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
---
jobs:
  shadow:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
"""
        folded = """jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          path: >
            protected-review/kanban-review-envelope.json
"""
        tabbed = "jobs:\n\treview:\n\t\tsteps:\n\t\t  - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
        for label, text in (
            ("anchor-and-alias", alias),
            ("merge-key", merge_key),
            ("explicit-tag", tagged),
            ("multi-document", multi_document),
            ("folded-block-scalar", folded),
            ("tab-indentation", tabbed),
        ):
            with self.subTest(form=label):
                with self.assertRaises(SystemExit, msg=label):
                    VERIFIER._parse_upload_artifact_steps(text)

    def test_artifact_enumeration_fails_closed_on_hidden_duplicate_keys(self):
        """F1: duplicate mapping keys must fail closed, never let one silently win."""
        duplicate_uses = """jobs:
  review:
    steps:
      - name: Upload immutable signed review artifact
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        uses: actions/upload-artifact@0000000000000000000000000000000000000000
        with:
          name: authority-v2-signed-review-t_c298fca4
"""
        duplicate_with_key = """jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: authority-v2-signed-review-t_c298fca4
          name: authority-v2-signed-review-t_ATTACKER
"""
        duplicate_quoted_key = """jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        "uses": actions/upload-artifact@0000000000000000000000000000000000000000
"""
        duplicate_flow_key = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - {uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02,"
            " uses: actions/upload-artifact@0000000000000000000000000000000000000000}\n"
        )
        duplicate_job_key = """jobs:
  review:
    steps:
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
  review:
    steps:
      - uses: actions/upload-artifact@0000000000000000000000000000000000000000
"""
        for label, text in (
            ("duplicate-uses-key", duplicate_uses),
            ("duplicate-with-key", duplicate_with_key),
            ("duplicate-quoted-key", duplicate_quoted_key),
            ("duplicate-flow-key", duplicate_flow_key),
            ("duplicate-job-key", duplicate_job_key),
        ):
            with self.subTest(form=label):
                with self.assertRaises(SystemExit, msg=label):
                    VERIFIER._parse_upload_artifact_steps(text)

    def test_producer_hidden_duplicate_upload_forms_fail_closed(self):
        """F1: a second producer upload hidden behind quoted/spaced/flow syntax must be counted."""
        tail = "            protected-review/preissuance-review-receipt.sigstore.json\n"
        injections = {
            "hidden-quoted-key-upload": (
                "\n"
                '      - "name": Attacker upload\n'
                '        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"\n'
                '        "with":\n'
                '          "name": authority-v2-signed-review-t_ATTACKER\n'
                '          "if-no-files-found": error\n'
                '          "retention-days": 1\n'
                '          "path": protected-review/kanban-review-envelope.json\n'
            ),
            "hidden-spaced-key-upload": (
                "\n"
                "      - name : Attacker upload\n"
                "        uses : actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
                "        with :\n"
                "          name : authority-v2-signed-review-t_ATTACKER\n"
                "          path : protected-review/kanban-review-envelope.json\n"
            ),
            "hidden-flow-map-upload": (
                "\n"
                "      - {name: Attacker upload,"
                " uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02,"
                " with: {name: authority-v2-signed-review-t_ATTACKER,"
                " path: protected-review/kanban-review-envelope.json}}\n"
            ),
        }
        for label, injection in injections.items():
            with self.subTest(mutation=label), tempfile.TemporaryDirectory() as td:
                changed = Path(td) / "bootstrap"
                shutil.copytree(ROOT / "independent-review-bootstrap-v2", changed)
                wf_path = changed / ".github" / "workflows" / "review-authority-v2.yml"
                original = wf_path.read_text(encoding="utf-8")
                modified = original.replace(tail, tail + injection, 1)
                self.assertNotEqual(original, modified, f"replacement had no effect: {label}")
                wf_path.write_text(modified, encoding="utf-8")
                contract_path = changed / "bootstrap-contract.json"
                contract = json.loads(contract_path.read_bytes())
                contract["workflow"]["sha256"] = hashlib.sha256(wf_path.read_bytes()).hexdigest()
                contract_path.write_bytes(VERIFIER.canonical(contract))
                with self.assertRaises(SystemExit, msg=label):
                    VERIFIER.verify_independent_review_bootstrap(changed)

    def test_consumer_hidden_duplicate_download_forms_fail_closed(self):
        """F1: a second Authority download hidden behind quoted/spaced/flow syntax must be counted."""
        tail = "          github-token: ${{ steps.review-token.outputs.token }}\n"
        injections = {
            "hidden-quoted-key-download": (
                "\n"
                '      - "name": Attacker download\n'
                '        "uses": "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"\n'
                '        "with":\n'
                '          "name": authority-v2-signed-review-t_ATTACKER\n'
                '          "path": injected\n'
            ),
            "hidden-spaced-key-download": (
                "\n"
                "      - name : Attacker download\n"
                "        uses : actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
                "        with :\n"
                "          name : authority-v2-signed-review-t_ATTACKER\n"
                "          path : injected\n"
            ),
            "hidden-flow-map-download": (
                "\n"
                "      - {name: Attacker download,"
                " uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093,"
                " with: {name: authority-v2-signed-review-t_ATTACKER, path: injected}}\n"
            ),
        }
        for label, injection in injections.items():
            with self.subTest(mutation=label), tempfile.TemporaryDirectory() as td:
                candidate_root = Path(td)
                self._copy_candidate(candidate_root)
                wf_path = candidate_root / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
                original = wf_path.read_text(encoding="utf-8")
                modified = original.replace(tail, tail + injection, 1)
                self.assertNotEqual(original, modified, f"replacement had no effect: {label}")
                wf_path.write_text(modified, encoding="utf-8")
                self._recompute_manifest(candidate_root)
                with self.assertRaises(SystemExit, msg=label):
                    self._verify_at(candidate_root)

    # ------------------------------------------------------------------
    # t_0c90990f FINDING 2 -- active post-download inventory step binding
    # ------------------------------------------------------------------
    def test_signed_review_inventory_step_is_structurally_bound_after_download(self):
        """F2: the shipped signing workflow binds one active inventory step after the download."""
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        binding = VERIFIER.bound_signed_review_inventory_step(workflow)
        self.assertEqual(binding["job"], "issue")
        self.assertGreater(binding["inventory_step_index"], binding["download_step_index"])

    def test_signed_review_inventory_binding_rejects_inactive_split_and_misordered(self):
        """F2: commented, dead-if, pre-download, split, non-executed and duplicated commands fail closed."""
        command = VERIFIER.EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND
        executed = f"          {command}\n"
        step_header = "      - name: Inventory the exact downloaded signed review artifact\n"
        download_header = "      - name: Download exact independently signed receipt\n"

        def commented(text):
            return text.replace(executed, f"          # {command}\n", 1)

        def dead_literal_if(text):
            return text.replace(step_header, step_header + "        if: false\n", 1)

        def dead_expression_if(text):
            return text.replace(step_header, step_header + "        if: ${{ false }}\n", 1)

        def dead_download_if(text):
            return text.replace(download_header, download_header + "        if: false\n", 1)

        def pre_download_only(text):
            moved = text.replace(executed, "", 1)
            return moved.replace(
                download_header,
                "      - name: Pre-download inventory\n"
                "        run: |\n"
                f"          {command}\n"
                "\n" + download_header,
                1,
            )

        def split_continuation(text):
            return text.replace(
                executed,
                "          python3 scripts/verify_authority_v2.py"
                " --verify-signed-review-artifact-inventory \\\n"
                '            "$AUTHORITY_V2_RUNTIME/independent-review"\n',
                1,
            )

        def non_executed_assignment(text):
            return text.replace(executed, f"          INVENTORY_CHECK='{command}'\n", 1)

        def non_executed_step_name(text):
            return text.replace(executed, "", 1).replace(step_header, f"      - name: {command}\n", 1)

        def duplicate_command(text):
            return text.replace(executed, executed + executed, 1)

        for label, mutate in (
            ("commented-inventory-command", commented),
            ("dead-literal-if-on-inventory-step", dead_literal_if),
            ("dead-expression-if-on-inventory-step", dead_expression_if),
            ("dead-if-on-consumer-download-step", dead_download_if),
            ("pre-download-inventory-only", pre_download_only),
            ("split-continuation-inventory-command", split_continuation),
            ("non-executed-variable-assignment", non_executed_assignment),
            ("non-executed-step-name", non_executed_step_name),
            ("duplicate-inventory-command", duplicate_command),
        ):
            with self.subTest(mutation=label), tempfile.TemporaryDirectory() as td:
                candidate_root = Path(td)
                self._copy_candidate(candidate_root)
                wf_path = candidate_root / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
                original = wf_path.read_text(encoding="utf-8")
                modified = mutate(original)
                self.assertNotEqual(original, modified, f"mutation had no effect: {label}")
                wf_path.write_text(modified, encoding="utf-8")
                self._recompute_manifest(candidate_root)
                with self.assertRaises(SystemExit, msg=label):
                    self._verify_at(candidate_root)

    def test_candidate_verifier_positive(self):
        policy, scanned = VERIFIER.verify_candidate()
        self.assertEqual(policy, self.policy)
        self.assertGreater(scanned, 0)


def pinned_chain_contracts():
    """Exactly pinned copies of both sealed bootstrap contracts for attack tests."""
    independent = json.loads(
        (ROOT / "independent-review-bootstrap-v2" / "bootstrap-contract.json").read_bytes()
    )
    source = json.loads(
        (ROOT / "protected-source-bootstrap-v2" / "bootstrap-contract.json").read_bytes()
    )
    run = independent["authorized_source_run"]
    run.update({
        "activation_state": "ready",
        "run_id": 4242,
        "run_head_sha": "1" * 40,
        "source_bootstrap_commit": "2" * 40,
        "source_bootstrap_tree": "3" * 40,
        "artifact_content_sha256": "4" * 64,
        "envelope_sha256": "5" * 64,
        "review_receipt_sha256": "6" * 64,
        "authority_head_commit": "7" * 40,
        "authority_head_tree": "8" * 40,
        "independent_bootstrap_commit": "9" * 40,
        "independent_bootstrap_tree": "e" * 40,
        "certificate_github_workflow_sha": "9" * 40,
    })
    return independent, source


class SourceExecutionChainTests(unittest.TestCase):
    """Adversarial coverage for UNAUTHENTICATED-INDEPENDENT-REVIEW-RECEIPT."""

    def setUp(self):
        self.source_root = ROOT / "protected-source-bootstrap-v2"
        self.independent_root = ROOT / "independent-review-bootstrap-v2"
        self.independent, self.source = pinned_chain_contracts()

    def test_protected_source_bootstrap_seals_every_export_byte(self):
        contract = VERIFIER.verify_protected_source_bootstrap(self.source_root)
        self.assertEqual(contract["repository"], VERIFIER.EXPECTED_SOURCE_REPOSITORY)
        for section, relative in (
            ("workflow", VERIFIER.EXPECTED_SOURCE_WORKFLOW_PATH),
            ("helper", VERIFIER.EXPECTED_SOURCE_HELPER_PATH),
        ):
            self.assertEqual(contract[section]["path"], relative)
            self.assertEqual(
                hashlib.sha256((self.source_root / relative).read_bytes()).hexdigest(),
                contract[section]["sha256"],
            )
        self.assertFalse(contract["publication_performed"])
        self.assertFalse(contract["repository_created"])

    def test_forged_source_or_validator_bytes_with_real_workflow_identity_fail_closed(self):
        expected = VERIFIER.expected_source_execution_chain(self.independent, self.source)
        self.assertEqual(
            expected["certificate_github_workflow_sha"],
            expected["independent_bootstrap_commit"],
        )
        VERIFIER.verify_source_execution_chain(expected, self.independent, self.source)
        for field in (
            "source_workflow_sha256", "source_helper_sha256",
            "independent_workflow_sha256", "independent_validator_sha256",
        ):
            forged = dict(expected, **{field: "0" * 64})
            with self.subTest(field=field), self.assertRaises(SystemExit):
                VERIFIER.verify_source_execution_chain(forged, self.independent, self.source)
        for root, relative in (
            (self.source_root, VERIFIER.EXPECTED_SOURCE_WORKFLOW_PATH),
            (self.source_root, VERIFIER.EXPECTED_SOURCE_HELPER_PATH),
            (self.independent_root, VERIFIER.EXPECTED_REVIEWER_WORKFLOW_PATH),
            (self.independent_root, "scripts/verify_kanban_review_v2.py"),
        ):
            with tempfile.TemporaryDirectory() as td:
                forged_root = Path(td) / "bootstrap"
                shutil.copytree(root, forged_root)
                target = forged_root / relative
                target.write_bytes(target.read_bytes() + b"# forged\n")
                verify = (
                    VERIFIER.verify_protected_source_bootstrap
                    if root is self.source_root
                    else VERIFIER.verify_independent_review_bootstrap
                )
                with self.subTest(forged=relative), self.assertRaises(SystemExit):
                    verify(forged_root)

    def test_caller_selected_source_run_substitution_fails_closed(self):
        run = VERIFIER.authorized_source_run(self.independent)
        self.assertFalse(run["caller_selectable"])
        self.assertEqual(run["selector"], "immutable-contract-pinned")
        expected = VERIFIER.expected_source_execution_chain(self.independent, self.source)
        for field, substitute in (
            ("run_id", 9999), ("run_attempt", 2), ("run_head_sha", "b" * 40),
            ("source_repository", "chrizzatsu/attacker-orchestration"),
            ("artifact_content_sha256", "b" * 64), ("envelope_sha256", "b" * 64),
            ("review_receipt_sha256", "b" * 64), ("reviewer_task_id", "t_00000000"),
            ("authority_repository", "chrizzatsu/attacker-authority"),
            ("authority_head_commit", "b" * 40), ("authority_head_tree", "b" * 40),
            ("source_bootstrap_commit", "b" * 40), ("source_bootstrap_tree", "b" * 40),
            ("independent_bootstrap_commit", "b" * 40),
            ("independent_bootstrap_tree", "b" * 40),
        ):
            substituted = dict(expected, **{field: substitute})
            with self.subTest(field=field), self.assertRaises(SystemExit):
                VERIFIER.verify_source_execution_chain(substituted, self.independent, self.source)
        substituted_contract = deepcopy(self.independent)
        substituted_contract["authorized_source_run"]["caller_selectable"] = True
        with self.assertRaises(SystemExit):
            VERIFIER.expected_source_execution_chain(substituted_contract, self.source)
        workflow_text = (
            self.independent_root / VERIFIER.EXPECTED_REVIEWER_WORKFLOW_PATH
        ).read_text(encoding="utf-8")
        self.assertNotIn("source_run_id:", workflow_text)
        self.assertNotIn("inputs.source_run_id", workflow_text)

    def test_missing_protected_source_repository_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            absent = Path(td) / "protected-source-bootstrap-v2"
            with self.assertRaises(SystemExit):
                VERIFIER.verify_protected_source_bootstrap(absent)
            partial = Path(td) / "partial"
            shutil.copytree(self.source_root, partial)
            (partial / VERIFIER.EXPECTED_SOURCE_HELPER_PATH).unlink()
            with self.assertRaises(SystemExit):
                VERIFIER.verify_protected_source_bootstrap(partial)

    def test_missing_independent_bootstrap_repository_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            absent = Path(td) / "independent-review-bootstrap-v2"
            with self.assertRaises(SystemExit):
                VERIFIER.verify_independent_review_bootstrap(absent)
            partial = Path(td) / "partial"
            shutil.copytree(self.independent_root, partial)
            (partial / "scripts" / "verify_kanban_review_v2.py").unlink()
            with self.assertRaises(SystemExit):
                VERIFIER.verify_independent_review_bootstrap(partial)

    def test_certificate_workflow_sha_must_equal_pinned_bootstrap_commit(self):
        run = VERIFIER.authorized_source_run(self.independent)
        pinned = run["independent_bootstrap_commit"]
        command = VERIFIER._review_receipt_cosign_command(
            Path("/private/receipt.json"), Path("/private/receipt.sigstore.json"), pinned,
        )
        self.assertIn("--certificate-github-workflow-sha", command)
        self.assertEqual(command[command.index("--certificate-github-workflow-sha") + 1], pinned)
        mismatched = deepcopy(self.independent)
        mismatched["authorized_source_run"]["certificate_github_workflow_sha"] = "c" * 40
        with self.assertRaises(SystemExit):
            VERIFIER.expected_source_execution_chain(mismatched, self.source)
        with self.assertRaises(SystemExit):
            VERIFIER._review_receipt_cosign_command(
                Path("/private/receipt.json"), Path("/private/receipt.sigstore.json"), None,
            )

    def test_source_execution_chain_is_fail_closed_until_independently_proven(self):
        sealed_independent = json.loads(
            (self.independent_root / "bootstrap-contract.json").read_bytes()
        )
        sealed_source = json.loads((self.source_root / "bootstrap-contract.json").read_bytes())
        run = VERIFIER.authorized_source_run(sealed_independent)
        self.assertEqual(
            run["activation_state"], VERIFIER.AUTHORIZED_PENDING_EVIDENCE,
        )
        self.assertTrue(run["no_fallback"])
        with self.assertRaises(SystemExit):
            VERIFIER.expected_source_execution_chain(sealed_independent, sealed_source)
        with self.assertRaises(SystemExit):
            VERIFIER.verify_source_execution_chain({}, sealed_independent, sealed_source)



_AUTHORITY_CANDIDATE = None


class AuthorityCandidateFixture:
    """A real Authority candidate checkout on the exact reviewed base commit.

    The sealed exporter now derives the complete Authority candidate binding
    from an authenticated checkout, so the bootstrap tests may no longer use a
    synthetic head: they need a genuine ordinary non-merge direct child of the
    reviewed base whose critical artifacts are the real reviewed bytes.
    """

    ARTIFACTS = (
        "AUTHORITY-V2-SHA256SUMS",
        "authority-v2-policy.json",
        "protected-asset-receipt-v2.json",
        "reviewer-authorization-v2.json",
        "schemas/authority-v2-subject.schema.json",
    )

    def __init__(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name) / "authority"
        self.root.mkdir()
        policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        self.base = policy["authority_repository_base"]["commit"]
        self._git("init", "-q")
        self._git("config", "user.email", "fixture@example.invalid")
        self._git("config", "user.name", "Fixture")
        self._git(
            "remote", "add", "origin",
            "https://github.com/chrizzatsu/acc-attestation-authority",
        )
        self._git("fetch", "-q", str(ROOT), self.base)
        self._git("checkout", "-q", self.base)
        for relative in self.ARTIFACTS:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        self._git("add", "-A")
        self._git("commit", "-qm", "candidate")
        self.head = self._git("rev-parse", "HEAD")
        self.tree = self._git("rev-parse", "HEAD^{tree}")

    def _git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True, capture_output=True,
        ).stdout.decode().strip()

    def bindings(self):
        return VERIFIER.recompute_candidate_bindings(self.root, self.base, self.head)

    def materialise(self, destination):
        """Copy the authenticated Authority checkout to a constant path."""
        shutil.copytree(self.root, destination, symlinks=False)
        return destination


def validator_checkout(case):
    """A validator root carrying the authenticated Authority checkout."""
    root = Path(tempfile.mkdtemp())
    case.addCleanup(shutil.rmtree, root, True)
    authority_candidate().materialise(root / VALIDATOR.AUTHORITY_CHECKOUT)
    return root


def authority_candidate():
    global _AUTHORITY_CANDIDATE
    if _AUTHORITY_CANDIDATE is None:
        _AUTHORITY_CANDIDATE = AuthorityCandidateFixture()
    return _AUTHORITY_CANDIDATE


EXPORT = load_module(
    "export_kanban_review_v2",
    ROOT / "protected-source-bootstrap-v2" / "scripts" / "export_kanban_review_v2.py",
)
VALIDATOR = load_module(
    "verify_kanban_review_v2",
    ROOT / "independent-review-bootstrap-v2" / "scripts" / "verify_kanban_review_v2.py",
)


class SealedBootstrapExecutionTests(unittest.TestCase):
    """Drive the sealed export helper and independent validator for real."""

    RUN_ID = 4242
    RUN_HEAD = "1" * 40
    SOURCE_TREE = "3" * 40
    BOOTSTRAP_COMMIT = "9" * 40
    BOOTSTRAP_TREE = "e" * 40

    @classmethod
    def setUpClass(cls):
        cls.AUTHORITY_HEAD = authority_candidate().head
        cls.AUTHORITY_TREE = authority_candidate().tree

    def setUp(self):
        self.source_root = ROOT / "protected-source-bootstrap-v2"
        self.independent_root = ROOT / "independent-review-bootstrap-v2"
        self.source_contract = json.loads(
            (self.source_root / "bootstrap-contract.json").read_bytes()
        )
        self.source_workflow = (
            self.source_root / VERIFIER.EXPECTED_SOURCE_WORKFLOW_PATH
        ).read_bytes()
        self.source_helper = (
            self.source_root / VERIFIER.EXPECTED_SOURCE_HELPER_PATH
        ).read_bytes()
        self.independent_workflow = (
            self.independent_root / VERIFIER.EXPECTED_REVIEWER_WORKFLOW_PATH
        ).read_bytes()
        self.independent_validator = (
            self.independent_root / VERIFIER.EXPECTED_REVIEWER_VALIDATOR_PATH
        ).read_bytes()
        self.source_contract["authority_binding"].update({
            "authority_head_commit": self.AUTHORITY_HEAD,
            "authority_head_tree": self.AUTHORITY_TREE,
            "source_bootstrap_tree": self.SOURCE_TREE,
            "independent_bootstrap_commit": self.BOOTSTRAP_COMMIT,
            "independent_bootstrap_tree": self.BOOTSTRAP_TREE,
            "independent_workflow_sha256": hashlib.sha256(self.independent_workflow).hexdigest(),
            "independent_validator_sha256": hashlib.sha256(self.independent_validator).hexdigest(),
            "activation_state": "ready",
        })
        self.metadata = {
            "run_id": self.RUN_ID, "run_attempt": 1, "run_head_sha": self.RUN_HEAD,
        }
        self.validator_root = validator_checkout(self)
        self.receipt, self.envelope = self._build_receipt_and_envelope()
        self.run = self.pinned_run()
        self.run_metadata = {
            "id": self.RUN_ID, "run_attempt": 1, "head_sha": self.RUN_HEAD,
            "path": VERIFIER.EXPECTED_SOURCE_WORKFLOW_PATH,
            "event": "workflow_dispatch", "head_branch": "main",
            "conclusion": "success",
            "head_repository": {"full_name": VERIFIER.EXPECTED_SOURCE_REPOSITORY},
        }
        self.run_pages = [
            {"total_count": 1, "workflow_runs": [self.run_metadata] if page == 0 else []}
            for page in range(1)
        ]

    def _build_receipt_and_envelope(self):
        """Build receipt/envelope directly for test fixtures.

        The exporter now fails closed (no authenticated Kanban source exists),
        so tests that need receipt/envelope bytes construct them directly.
        """
        review = self.review_result()
        binding = self.source_contract["authority_binding"]
        chain = {
            "authority_repository": self.source_contract["authority_repository"],
            "authority_head_commit": binding["authority_head_commit"],
            "authority_head_tree": binding["authority_head_tree"],
            "certificate_github_workflow_sha": binding["independent_bootstrap_commit"],
            "independent_bootstrap_commit": binding["independent_bootstrap_commit"],
            "independent_bootstrap_tree": binding["independent_bootstrap_tree"],
            "independent_validator_sha256": binding["independent_validator_sha256"],
            "independent_workflow_sha256": binding["independent_workflow_sha256"],
            "reviewer_task_id": self.source_contract["reviewer_task_id"],
            "source_bootstrap_commit": self.metadata["run_head_sha"],
            "source_bootstrap_tree": binding["source_bootstrap_tree"],
            "source_helper_path": self.source_contract["helper"]["path"],
            "source_helper_sha256": hashlib.sha256(self.source_helper).hexdigest(),
            "source_repository": self.source_contract["repository"],
            "source_workflow_path": self.source_contract["workflow"]["path"],
            "source_workflow_sha256": hashlib.sha256(self.source_workflow).hexdigest(),
            "run_id": self.metadata["run_id"],
            "run_attempt": self.metadata["run_attempt"],
            "run_head_sha": self.metadata["run_head_sha"],
        }
        receipt = {key: review[key] for key in EXPORT.RECEIPT_FIELDS if key != "source_execution_chain"}
        receipt["source_execution_chain"] = chain
        receipt_bytes = EXPORT.canonical(receipt)
        receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
        envelope = {
            "schema_version": 2,
            "task_id": self.source_contract["reviewer_task_id"],
            "source_repository": self.source_contract["repository"],
            "source_workflow": self.source_contract["workflow"]["path"],
            "source_workflow_sha256": hashlib.sha256(self.source_workflow).hexdigest(),
            "source_helper": self.source_contract["helper"]["path"],
            "source_helper_sha256": hashlib.sha256(self.source_helper).hexdigest(),
            "source_run_id": self.metadata["run_id"],
            "source_run_attempt": self.metadata["run_attempt"],
            "source_run_head_sha": self.metadata["run_head_sha"],
            "artifact_name": self.source_contract["artifact"]["name"],
            "review_receipt_sha256": receipt_sha256,
            "immutable": True,
        }
        envelope_bytes = EXPORT.canonical(envelope)
        return receipt_bytes, envelope_bytes

    def review_result(self):
        return {
            "schema_version": 2,
            "receipt_type": "acc-authority-v2-preissuance-independent-review",
            "reviewer_profile": "acc-reviewer",
            "review_outcome": "ACTIVATION_ONLY",
            "approved": False,
            "findings_count": 1,
            "findings": [{
                "closure": "F12",
                "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE",
            }],
            "release_authorized": False,
            "activation_authorized": True,
            "activation_findings": [],
            "candidate": authority_candidate().bindings(),
            "protected_identity_asset": {"sha256": "d" * 64},
            "closure_matrix": {
                f"F{number}": number != 12 for number in range(1, 13)
            },
            "classifications": {"hard_stop_class": None},
        }

    def pinned_run(self):
        contract = json.loads(
            (self.independent_root / "bootstrap-contract.json").read_bytes()
        )
        contract["authorized_source_run"].update({
            "activation_state": "ready",
            "run_id": self.RUN_ID,
            "run_head_sha": self.RUN_HEAD,
            "source_bootstrap_commit": self.RUN_HEAD,
            "source_bootstrap_tree": self.SOURCE_TREE,
            "artifact_content_sha256": VALIDATOR.artifact_content_sha256({
                "kanban-review-envelope.json": self.envelope,
                "preissuance-review-receipt.json": self.receipt,
            }),
            "envelope_sha256": hashlib.sha256(self.envelope).hexdigest(),
            "review_receipt_sha256": hashlib.sha256(self.receipt).hexdigest(),
            "authority_head_commit": self.AUTHORITY_HEAD,
            "authority_head_tree": self.AUTHORITY_TREE,
            "independent_bootstrap_commit": self.BOOTSTRAP_COMMIT,
            "independent_bootstrap_tree": self.BOOTSTRAP_TREE,
            "certificate_github_workflow_sha": self.BOOTSTRAP_COMMIT,
            "independent_workflow_sha256": hashlib.sha256(self.independent_workflow).hexdigest(),
            "independent_validator_sha256": hashlib.sha256(self.independent_validator).hexdigest(),
        })
        self.contract = contract
        return VALIDATOR.authorized_source_run(contract)

    def test_sealed_export_output_is_the_only_accepted_chain(self):
        self.assertEqual(
            VALIDATOR.verify(
                self.run, self.envelope, self.receipt,
                root=self.validator_root,
            ),
            {"activation_authorized": True,
             "release_authorized": False,
             "review_receipt_sha256": self.run["review_receipt_sha256"],
             "source_verified": True},
        )
        chain = json.loads(self.receipt)["source_execution_chain"]
        self.assertEqual(set(chain), set(VERIFIER.RECEIPT_SOURCE_CHAIN_FIELDS))
        observed = {
            **chain,
            "artifact_content_sha256": VERIFIER.protected_artifact_content_sha256({
                "kanban-review-envelope.json": self.envelope,
                "preissuance-review-receipt.json": self.receipt,
            }),
            "envelope_sha256": hashlib.sha256(self.envelope).hexdigest(),
            "review_receipt_sha256": hashlib.sha256(self.receipt).hexdigest(),
        }
        self.assertEqual(
            VERIFIER.verify_source_execution_chain(
                observed, self.contract, self.source_contract,
            ),
            observed,
        )

    def test_forged_envelope_or_receipt_bytes_fail_even_with_a_real_identity(self):
        forged_receipt = VALIDATOR.canonical(
            {**json.loads(self.receipt), "release_authorized": True,
             "findings_count": 0}
        )
        for label, envelope, receipt in (
            ("receipt-appended", self.envelope, self.receipt + b" "),
            ("envelope-appended", self.envelope + b" ", self.receipt),
            ("receipt-reserialised", self.envelope, forged_receipt + b"\n"),
            ("envelope-swapped", self.receipt, self.receipt),
        ):
            with self.subTest(label=label), self.assertRaises(SystemExit):
                VALIDATOR.verify(
                    self.run, envelope, receipt, root=self.validator_root,
                )
        caller_chain = json.loads(self.receipt)
        caller_chain["source_execution_chain"]["source_workflow_sha256"] = "0" * 64
        caller_bytes = VALIDATOR.canonical(caller_chain)
        run = dict(self.run, review_receipt_sha256=hashlib.sha256(caller_bytes).hexdigest())
        with self.assertRaises(SystemExit):
            VALIDATOR.verify(
                run, self.envelope, caller_bytes, root=self.validator_root,
            )

    def test_forged_executed_source_or_validator_bytes_fail_closed(self):
        source_commit_data = {"sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE}}
        VALIDATOR.verify_source_bytes(
            self.run, self.run_metadata, self.source_workflow, self.source_helper,
            source_commit_data,
        )
        VALIDATOR.verify_bootstrap_bytes(
            self.run, self.independent_workflow, self.independent_validator,
            self.BOOTSTRAP_COMMIT, self.BOOTSTRAP_TREE,
        )
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_bytes(
                self.run, self.run_metadata, self.source_workflow + b"# forged\n",
                self.source_helper, source_commit_data,
            )
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_bytes(
                self.run, self.run_metadata, self.source_workflow,
                self.source_helper + b"# forged\n", source_commit_data,
            )
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_bootstrap_bytes(
                self.run, self.independent_workflow + b"# forged\n",
                self.independent_validator, self.BOOTSTRAP_COMMIT, self.BOOTSTRAP_TREE,
            )
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_bootstrap_bytes(
                self.run, self.independent_workflow,
                self.independent_validator + b"# forged\n", self.BOOTSTRAP_COMMIT,
                self.BOOTSTRAP_TREE,
            )

    def test_certificate_workflow_sha_must_equal_the_pinned_bootstrap_commit(self):
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_bootstrap_bytes(
                self.run, self.independent_workflow, self.independent_validator,
                "b" * 40, self.BOOTSTRAP_TREE,
            )
        mismatched = deepcopy(self.contract)
        mismatched["authorized_source_run"].update({
            "activation_state": "ready",
            "certificate_github_workflow_sha": "b" * 40,
        })
        with self.assertRaises(SystemExit):
            VALIDATOR.resolve_live_run(
                VALIDATOR.authorized_source_run(mismatched),
                bootstrap_commit=self.BOOTSTRAP_COMMIT,
                bootstrap_tree=self.BOOTSTRAP_TREE,
                source_run_metadata=self.run_metadata,
                source_run_pages=self.run_pages,
                source_commit={"sha": self.RUN_HEAD,
                               "tree": {"sha": self.SOURCE_TREE}},
                authority_commit={"sha": self.AUTHORITY_HEAD,
                                  "tree": {"sha": self.AUTHORITY_TREE}},
                envelope_data=self.envelope,
                receipt_data=self.receipt,
            )

    def test_caller_selected_source_run_substitution_fails_closed(self):
        source_commit_data = {"sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE}}
        for field, substitute in (
            ("id", 9999), ("run_attempt", 2), ("head_sha", "b" * 40),
            ("path", ".github/workflows/attacker.yml"),
            ("event", "push"), ("head_branch", "attacker"), ("conclusion", "failure"),
        ):
            with self.subTest(field=field), self.assertRaises(SystemExit):
                VALIDATOR.verify_source_bytes(
                    self.run, dict(self.run_metadata, **{field: substitute}),
                    self.source_workflow, self.source_helper, source_commit_data,
                )
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_bytes(
                self.run,
                dict(self.run_metadata, head_repository={"full_name": "chrizzatsu/attacker"}),
                self.source_workflow, self.source_helper, source_commit_data,
            )
        for mutation in (
            {"caller_selectable": True},
            {"selector": "caller-supplied"},
            {"no_fallback": False},
            {"activation_state": "unavailable"},
        ):
            changed = deepcopy(self.contract)
            changed["authorized_source_run"].update(mutation)
            with self.subTest(mutation=sorted(mutation)), self.assertRaises(SystemExit):
                VALIDATOR.authorized_source_run(changed)

    def test_caller_created_canonical_approved_json_with_exact_helper_hashes_rejected(self):
        """UNAUTHENTICATED-INDEPENDENT-REVIEW-RECEIPT adversarial probe.

        A caller-created canonical APPROVED JSON, even with exact reviewed
        helper hashes, must never be accepted. The exporter must not accept
        any caller-supplied --review argument or mutable KANBAN_REVIEW_RESULT_PATH.
        """
        # The exporter must not have a --review parameter at all
        import inspect
        sig = inspect.signature(EXPORT.main)
        # Also verify that build() does not accept a review parameter
        build_sig = inspect.signature(EXPORT.build)
        self.assertNotIn("review", {p.name for p in build_sig.parameters.values()})

        # The workflow must not reference KANBAN_REVIEW_RESULT_PATH or --review
        workflow_text = (
            self.source_root / VERIFIER.EXPECTED_SOURCE_WORKFLOW_PATH
        ).read_text(encoding="utf-8")
        self.assertNotIn("KANBAN_REVIEW_RESULT_PATH", workflow_text)
        self.assertNotIn("--review", workflow_text)

        # The exporter CLI must not accept --review
        import argparse
        # Re-read the exporter source to confirm --review is structurally absent
        exporter_source = (
            self.source_root / VERIFIER.EXPECTED_SOURCE_HELPER_PATH
        ).read_text(encoding="utf-8")
        self.assertNotIn("--review", exporter_source)
        self.assertNotIn("KANBAN_REVIEW", exporter_source)

    def test_arbitrary_tree_shas_lacking_commit_tree_proof_must_fail(self):
        """F2: UNAUTHENTICATED-EXECUTION-TREE-BINDING adversarial probe.

        Arbitrary source/independent tree SHAs lacking commit→tree proof must
        be rejected. Both verify_bootstrap_bytes and verify_source_bytes must
        verify the tree binding from authenticated git data.
        """
        # verify_bootstrap_bytes must accept a bootstrap_tree parameter
        sig = inspect.signature(VALIDATOR.verify_bootstrap_bytes)
        params = {p.name for p in sig.parameters.values()}
        self.assertIn("bootstrap_tree", params,
                      "verify_bootstrap_bytes must accept bootstrap_tree for commit→tree verification")

        # verify_source_bytes must accept source_commit_data for tree verification
        sig2 = inspect.signature(VALIDATOR.verify_source_bytes)
        params2 = {p.name for p in sig2.parameters.values()}
        self.assertIn("source_commit_data", params2,
                      "verify_source_bytes must accept source_commit_data for tree verification")

        # Forged independent tree must be rejected
        forged_contract = deepcopy(self.contract)
        forged_contract["authorized_source_run"]["independent_bootstrap_tree"] = "0" * 40
        forged_run = VALIDATOR.authorized_source_run(forged_contract)
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_bootstrap_bytes(
                forged_run, self.independent_workflow, self.independent_validator,
                self.BOOTSTRAP_COMMIT, self.BOOTSTRAP_TREE,
            )

        # Correct tree must pass
        VALIDATOR.verify_bootstrap_bytes(
            self.run, self.independent_workflow, self.independent_validator,
            self.BOOTSTRAP_COMMIT, self.BOOTSTRAP_TREE,
        )

        # Forged source tree must be rejected via authenticated commit data
        source_commit_data = {"sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE}}
        forged_source_contract = deepcopy(self.contract)
        forged_source_contract["authorized_source_run"]["source_bootstrap_tree"] = "f" * 40
        forged_source_run = VALIDATOR.authorized_source_run(forged_source_contract)
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_bytes(
                forged_source_run, self.run_metadata, self.source_workflow, self.source_helper,
                source_commit_data,
            )

        # Correct source tree must pass
        VALIDATOR.verify_source_bytes(
            self.run, self.run_metadata, self.source_workflow, self.source_helper,
            source_commit_data,
        )

    def test_unrelated_commit_carrying_pinned_tree_must_be_rejected(self):
        """F2-audit: source_commit_data.sha must equal run_head_sha and
        source_bootstrap_commit must equal run_head_sha.

        An attacker can supply a commit record from an unrelated commit that
        happens to carry the pinned tree SHA. The verifier must bind the
        authenticated commit identity to the pinned run head.
        """
        # Attack: correct tree, wrong commit sha
        unrelated_commit = "c" * 40
        forged_commit_data = {"sha": unrelated_commit, "tree": {"sha": self.SOURCE_TREE}}
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_bytes(
                self.run, self.run_metadata, self.source_workflow, self.source_helper,
                forged_commit_data,
            )

        # Also: a sealed source_bootstrap_commit that contradicts the
        # authenticated server state must reject at runtime resolution.
        diverged_contract = deepcopy(self.contract)
        diverged_contract["authorized_source_run"].update({
            "activation_state": "ready",
            "source_bootstrap_commit": "d" * 40,
        })
        with self.assertRaises(SystemExit):
            VALIDATOR.resolve_live_run(
                VALIDATOR.authorized_source_run(diverged_contract),
                bootstrap_commit=self.BOOTSTRAP_COMMIT,
                bootstrap_tree=self.BOOTSTRAP_TREE,
                source_run_metadata=self.run_metadata,
                source_run_pages=self.run_pages,
                source_commit={"sha": self.RUN_HEAD,
                               "tree": {"sha": self.SOURCE_TREE}},
                authority_commit={"sha": self.AUTHORITY_HEAD,
                                  "tree": {"sha": self.AUTHORITY_TREE}},
                envelope_data=self.envelope,
                receipt_data=self.receipt,
            )

    def test_export_helper_refuses_unpinned_or_forged_executed_bytes(self):
        unpinned = deepcopy(self.source_contract)
        unpinned["authority_binding"]["authority_head_commit"] = None
        with self.assertRaises(SystemExit):
            EXPORT.build(
                unpinned,
                {
                    "source_workflow_sha256": hashlib.sha256(self.source_workflow).hexdigest(),
                    "source_helper_sha256": hashlib.sha256(self.source_helper).hexdigest(),
                },
                self.metadata,
            )
        with self.assertRaises(SystemExit):
            EXPORT.build(
                self.source_contract,
                {"source_workflow_sha256": "0" * 64,
                 "source_helper_sha256": hashlib.sha256(self.source_helper).hexdigest()},
                self.metadata,
            )
        # Even with valid contract and measurements, build fails closed
        # because no authenticated immutable Kanban source exists
        with self.assertRaises(SystemExit):
            EXPORT.build(
                self.source_contract,
                {
                    "source_workflow_sha256": hashlib.sha256(self.source_workflow).hexdigest(),
                    "source_helper_sha256": hashlib.sha256(self.source_helper).hexdigest(),
                },
                self.metadata,
            )
        contract = self.source_contract
        workflow_ref = (
            f'{contract["repository"]}/{contract["workflow"]["path"]}'
            f'@{contract["workflow"]["ref"]}'
        )
        authenticated = {
            "GITHUB_RUN_ID": "7",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": self.RUN_HEAD,
            "GITHUB_REPOSITORY": contract["repository"],
            "GITHUB_EVENT_NAME": contract["workflow"]["trigger"],
            "GITHUB_REF": contract["workflow"]["ref"],
            "GITHUB_WORKFLOW_REF": workflow_ref,
        }
        self.assertEqual(
            EXPORT.run_metadata(authenticated, contract),
            {"run_id": 7, "run_attempt": 1, "run_head_sha": self.RUN_HEAD},
        )
        for overrides in (
            {"GITHUB_RUN_ID": "0"},
            {"GITHUB_RUN_ATTEMPT": "2"},
            {"GITHUB_SHA": "nope"},
            {"GITHUB_REPOSITORY": "chrizzatsu/other"},
            {"GITHUB_EVENT_NAME": "push"},
            {"GITHUB_REF": "refs/heads/attacker"},
            {"GITHUB_WORKFLOW_REF": "chrizzatsu/other/x.yml@refs/heads/main"},
        ):
            environment = dict(authenticated, **overrides)
            with self.subTest(overrides=overrides), self.assertRaises(SystemExit):
                EXPORT.run_metadata(environment, contract)



# ---------------------------------------------------------------------------
# t_c678e93e FINDING 1 -- F3-POST-DOWNLOAD-INVENTORY-SHELL-EXECUTION-FAIL-OPEN
#
# The signed-review inventory must live in one dedicated, condition-free step
# placed immediately after the one authorized `actions/download-artifact`
# invocation, and the parsed `run` scalar of that step must be byte-for-byte
# the single approved one-line command. Anything that merely *contains* the
# command text -- heredoc data, text after `exit`, an uncalled function body,
# a compound or split command, a comment, surrounding text -- never executes
# the inventory in the order the Authority relies on and must fail closed.
# ---------------------------------------------------------------------------
class PostDownloadInventoryStepTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / SIGNING_WORKFLOW_RELPATH).read_text(encoding="utf-8")
        self.command = APPROVED_SIGNED_REVIEW_INVENTORY_COMMAND
        self.step_block = (
            "      - name: Inventory the exact downloaded signed review artifact\n"
            "        run: |-\n"
            f"          {self.command}\n"
        )
        self.download_header = "      - name: Download exact independently signed receipt\n"
        self.next_step_header = "      - name: Read back run job approval and OIDC claims\n"
        self.job_header = "  issue:\n    runs-on: ubuntu-latest\n"

    def dedicated_step(self, run_body, name_suffix="", extra_keys=""):
        return (
            f"      - name: Inventory the exact downloaded signed review artifact{name_suffix}\n"
            f"{extra_keys}"
            f"{run_body}"
        )

    def assert_rejected(self, label, mutate, expected_fragment=None):
        with tempfile.TemporaryDirectory() as td:
            candidate_root = Path(td)
            copy_candidate_tree(candidate_root)
            wf_path = candidate_root / SIGNING_WORKFLOW_RELPATH
            original = wf_path.read_text(encoding="utf-8")
            modified = mutate(original)
            self.assertNotEqual(original, modified, f"mutation had no effect: {label}")
            wf_path.write_text(modified, encoding="utf-8")
            recompute_candidate_manifest(candidate_root)
            with self.assertRaises(SystemExit, msg=label) as raised:
                verify_candidate_at(candidate_root)
            if expected_fragment is not None:
                self.assertIn(expected_fragment, str(raised.exception), label)

    # -- positive binding ------------------------------------------------
    def test_verifier_constant_is_the_exact_approved_one_line_command(self):
        """The bound command is the reviewer-approved scalar and stays one line."""
        self.assertEqual(
            VERIFIER.EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND,
            self.command,
        )
        self.assertNotIn("\n", VERIFIER.EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND)
        self.assertEqual(
            VERIFIER.EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND.strip(),
            VERIFIER.EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND,
        )

    def test_dedicated_step_directly_follows_the_authorized_download(self):
        """The shipped workflow ships exactly one dedicated post-download inventory step."""
        self.assertIn(self.step_block, self.workflow)
        binding = VERIFIER.bound_signed_review_inventory_step(self.workflow)
        self.assertEqual(binding["job"], "issue")
        self.assertEqual(
            binding["inventory_step_index"], binding["download_step_index"] + 1
        )
        document = VERIFIER.workflow_document(self.workflow)
        job = document["jobs"]["issue"]
        step = job["steps"][binding["inventory_step_index"]]
        self.assertEqual(sorted(step), ["name", "run"])
        self.assertEqual(step["run"], self.command)

    def test_inventory_command_text_appears_in_exactly_one_run_scalar(self):
        """No other run scalar may carry the inventory command text in any form."""
        document = VERIFIER.workflow_document(self.workflow)
        carrying = [
            run
            for _job, _index, step in VERIFIER._workflow_steps(document)
            if (run := step.get("run")) is not None
            and any(
                marker in run
                for marker in VERIFIER.SIGNED_REVIEW_INVENTORY_REFERENCE_MARKERS
            )
        ]
        self.assertEqual(carrying, [self.command])

    # -- shell-execution fail-open mutations -----------------------------
    def test_non_executing_command_text_fails_closed(self):
        """Heredoc data, post-exit text and uncalled functions never execute."""
        heredoc = self.dedicated_step(
            "        run: |\n"
            "          cat <<'REVIEWER_INVENTORY' >/dev/null\n"
            f"          {self.command}\n"
            "          REVIEWER_INVENTORY\n"
        )
        post_exit = self.dedicated_step(
            "        run: |\n"
            "          exit 0\n"
            f"          {self.command}\n"
        )
        unreachable_after_true_exit = self.dedicated_step(
            "        run: |\n"
            "          if true; then exit 0; fi\n"
            f"          {self.command}\n"
        )
        uncalled_function = self.dedicated_step(
            "        run: |\n"
            "          signed_review_inventory() {\n"
            f"            {self.command}\n"
            "          }\n"
        )
        quoted_probe = self.dedicated_step(
            "        run: |\n"
            f"          INVENTORY_PROBE='{self.command}'\n"
        )
        for label, replacement in (
            ("reviewer-heredoc-data", heredoc),
            ("command-after-exit", post_exit),
            ("command-after-unreachable-branch", unreachable_after_true_exit),
            ("command-in-uncalled-function", uncalled_function),
            ("command-in-quoted-variable-probe", quoted_probe),
        ):
            self.assert_rejected(
                label, lambda text, r=replacement: text.replace(self.step_block, r, 1)
            )

    def test_compound_split_and_control_flow_command_forms_fail_closed(self):
        """Only a bare one-line command may be the bound inventory scalar."""
        compound = self.dedicated_step(f"        run: |-\n          true && {self.command}\n")
        preamble = self.dedicated_step(
            "        run: |-\n          set -euo pipefail\n" f"          {self.command}\n"
        )
        trailing_echo = self.dedicated_step(
            "        run: |-\n" f"          {self.command}\n          echo inventoried\n"
        )
        control_flow = self.dedicated_step(
            "        run: |-\n"
            f"          if {self.command}; then true; fi\n"
        )
        split_continuation = self.dedicated_step(
            "        run: |-\n"
            "          python3 scripts/verify_authority_v2.py"
            " --verify-signed-review-artifact-inventory \\\n"
            '            "$AUTHORITY_V2_RUNTIME/independent-review"\n'
        )
        subshell = self.dedicated_step(
            "        run: |-\n" f"          ( {self.command} )\n"
        )
        for label, replacement in (
            ("compound-and-command", compound),
            ("shell-preamble-before-command", preamble),
            ("extra-command-after-inventory", trailing_echo),
            ("control-flow-wrapped-command", control_flow),
            ("split-continuation-command", split_continuation),
            ("subshell-wrapped-command", subshell),
        ):
            self.assert_rejected(
                label, lambda text, r=replacement: text.replace(self.step_block, r, 1)
            )

    def test_comment_blank_and_surrounding_text_scalars_fail_closed(self):
        """Comments, blank commands and surrounding text are never byte-exact."""
        trailing_comment = self.dedicated_step(
            "        run: |-\n" f"          {self.command} # reviewer inventory\n"
        )
        comment_line = self.dedicated_step(
            "        run: |-\n"
            "          # reviewer inventory\n"
            f"          {self.command}\n"
        )
        commented_out = self.dedicated_step(
            "        run: |-\n" f"          # {self.command}\n"
        )
        blank_command = self.dedicated_step("        run: |-\n          true\n")
        kept_trailing_newline = self.dedicated_step(
            "        run: |\n" f"          {self.command}\n"
        )
        trailing_space = self.dedicated_step(
            "        run: |-\n" f"          {self.command} \n"
        )
        for label, replacement in (
            ("trailing-comment-on-command", trailing_comment),
            ("comment-line-above-command", comment_line),
            ("fully-commented-out-command", commented_out),
            ("blank-inventory-command", blank_command),
            ("block-scalar-keeps-trailing-newline", kept_trailing_newline),
            ("trailing-space-after-command", trailing_space),
        ):
            self.assert_rejected(
                label, lambda text, r=replacement: text.replace(self.step_block, r, 1)
            )

    def test_uniform_block_scalar_indentation_is_not_part_of_the_command(self):
        """Block-scalar indentation is stripped by YAML, so it never changes bytes."""
        reindented = self.workflow.replace(
            self.step_block,
            self.dedicated_step(
                "        run: |-\n" f"           {self.command}\n"
            ),
            1,
        )
        self.assertNotEqual(reindented, self.workflow)
        binding = VERIFIER.bound_signed_review_inventory_step(reindented)
        self.assertEqual(
            binding["inventory_step_index"], binding["download_step_index"] + 1
        )
        document = VERIFIER.workflow_document(reindented)
        step = document["jobs"]["issue"]["steps"][binding["inventory_step_index"]]
        self.assertEqual(step["run"], self.command)

    def test_non_exact_command_bytes_fail_closed(self):
        """Every semantically equivalent but non-exact scalar is rejected."""
        mutations = {
            "swapped-interpreter": self.command.replace("python3 ", "python ", 1),
            "swapped-verifier-path": self.command.replace(
                "scripts/verify_authority_v2.py", "scripts/verify_publication_v2.py", 1
            ),
            "swapped-inventory-flag": self.command.replace(
                "--verify-signed-review-artifact-inventory",
                "--verify-release-inventory",
                1,
            ),
            "unquoted-inventory-root": self.command.replace(
                '"$AUTHORITY_V2_RUNTIME/independent-review"',
                "$AUTHORITY_V2_RUNTIME/independent-review",
                1,
            ),
            "rebound-inventory-root": self.command.replace(
                '"$AUTHORITY_V2_RUNTIME/independent-review"',
                '"$AUTHORITY_V2_RUNTIME"',
                1,
            ),
            "attacker-controlled-inventory-root": self.command.replace(
                '"$AUTHORITY_V2_RUNTIME/independent-review"',
                '"$RUNNER_TEMP/attacker"',
                1,
            ),
        }
        for label, command in mutations.items():
            self.assertNotEqual(command, self.command, label)
            replacement = self.dedicated_step(f"        run: |-\n          {command}\n")
            self.assert_rejected(
                label, lambda text, r=replacement: text.replace(self.step_block, r, 1)
            )

    def test_conditional_and_extra_step_keys_fail_closed(self):
        """A dedicated step declares only `name` and `run`, on a condition-free job."""
        for label, extra in (
            ("step-if-literal-false", "        if: false\n"),
            ("step-if-expression-false", "        if: ${{ false }}\n"),
            ("step-if-always", "        if: ${{ always() }}\n"),
            ("step-if-success", "        if: ${{ success() }}\n"),
            ("step-continue-on-error", "        continue-on-error: true\n"),
            ("step-shell-override", "        shell: sh\n"),
        ):
            replacement = self.dedicated_step(
                "        run: |-\n" f"          {self.command}\n", extra_keys=extra
            )
            self.assert_rejected(
                label, lambda text, r=replacement: text.replace(self.step_block, r, 1)
            )

        self.assert_rejected(
            "conditional-download-job",
            lambda text: text.replace(
                self.job_header, "  issue:\n    if: false\n    runs-on: ubuntu-latest\n", 1
            ),
        )
        self.assert_rejected(
            "conditional-authorized-download-step",
            lambda text: text.replace(
                self.download_header, self.download_header + "        if: false\n", 1
            ),
        )

    def test_placement_and_duplication_fail_closed(self):
        """Pre-download, delayed, duplicated and missing inventory steps fail closed."""
        def removed(text):
            return text.replace(self.step_block, "", 1)

        def pre_download(text):
            return removed(text).replace(
                self.download_header, self.step_block + "\n" + self.download_header, 1
            )

        def delayed(text):
            return removed(text).replace(
                self.next_step_header, self.step_block + "\n" + self.next_step_header, 1
            )

        def duplicated(text):
            return text.replace(self.step_block, self.step_block + "\n" + self.step_block, 1)

        def duplicated_elsewhere(text):
            return text.replace(
                self.next_step_header, self.step_block + "\n" + self.next_step_header, 1
            )

        def name_only(text):
            return removed(text).replace(
                self.next_step_header, f"      - name: {self.command}\n", 1
            )

        for label, mutate in (
            ("inventory-step-removed", removed),
            ("pre-download-inventory-step", pre_download),
            ("inventory-step-not-immediately-after-download", delayed),
            ("duplicated-adjacent-inventory-step", duplicated),
            ("duplicated-later-inventory-step", duplicated_elsewhere),
            ("command-only-in-a-step-name", name_only),
        ):
            self.assert_rejected(label, mutate)

    def test_binding_alone_requires_one_semantic_download_before_the_inventory(self):
        """Called directly, the binding still rejects a mixed-case second download."""
        alias_download = (
            "\n"
            "      - name: Attacker download\n"
            "        uses: ACTIONS/DOWNLOAD-ARTIFACT@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
            "        with:\n"
            "          name: authority-v2-signed-review-t_ATTACKER\n"
            "          path: injected\n"
        )
        checkout_tail = "          fetch-depth: 2\n"
        mutated = self.workflow.replace(
            checkout_tail, checkout_tail + alias_download, 1
        )
        self.assertNotEqual(mutated, self.workflow)
        with self.assertRaises(SystemExit) as raised:
            VERIFIER.bound_signed_review_inventory_step(mutated)
        self.assertIn(
            "total download-artifact invocations, found 3", str(raised.exception)
        )

    def test_inert_command_copies_alongside_the_dedicated_step_fail_closed(self):
        """A second, non-executing copy may not sit beside the real dedicated step.

        The dedicated step is left intact here, so only the rule that the command
        text may appear in no other `run` scalar can reject these probes.
        """
        probes = {
            "reviewer-heredoc-probe": (
                "      - name: Reviewer inventory probe\n"
                "        run: |\n"
                "          cat <<'REVIEWER_INVENTORY' >/dev/null\n"
                f"          {self.command}\n"
                "          REVIEWER_INVENTORY\n"
            ),
            "post-exit-probe": (
                "      - name: Reviewer inventory probe\n"
                "        run: |\n"
                "          exit 0\n"
                f"          {self.command}\n"
            ),
            "uncalled-function-probe": (
                "      - name: Reviewer inventory probe\n"
                "        run: |\n"
                "          signed_review_inventory() {\n"
                f"            {self.command}\n"
                "          }\n"
            ),
            "commented-probe": (
                "      - name: Reviewer inventory probe\n"
                "        run: |\n"
                f"          # {self.command}\n"
            ),
            "dead-if-probe": (
                "      - name: Reviewer inventory probe\n"
                "        if: false\n"
                "        run: |\n"
                f"          {self.command}\n"
            ),
            "quoted-assignment-probe": (
                "      - name: Reviewer inventory probe\n"
                "        run: |\n"
                f"          INVENTORY_PROBE='{self.command}'\n"
            ),
            "documentation-echo-probe": (
                "      - name: Reviewer inventory probe\n"
                "        run: |\n"
                '          echo "runs --verify-signed-review-artifact-inventory later"\n'
            ),
        }
        for label, probe in probes.items():
            self.assert_rejected(
                label,
                lambda text, pr=probe: text.replace(
                    self.next_step_header, pr + "\n" + self.next_step_header, 1
                ),
                "appears outside the one dedicated",
            )

    def test_inventory_root_env_must_resolve_to_the_authorized_download_path(self):
        """The inventoried root must resolve to the exact authorized download path."""
        env_line = "      AUTHORITY_V2_RUNTIME: ${{ runner.temp }}/authority-v2-runtime\n"
        self.assertIn(env_line, self.workflow)
        self.assertEqual(
            VERIFIER.EXPECTED_SIGNED_REVIEW_INVENTORY_ROOT.replace(
                "$AUTHORITY_V2_RUNTIME", "${{ runner.temp }}/authority-v2-runtime"
            ),
            VERIFIER.EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH["path"],
        )
        self.assertNotIn("SIGNED_REVIEW_ARTIFACT_DIR", self.workflow)
        for label, replacement in (
            (
                "runtime-root-env-rebound",
                "      AUTHORITY_V2_RUNTIME: ${{ runner.temp }}/attacker-runtime\n",
            ),
            ("runtime-root-env-removed", ""),
        ):
            self.assert_rejected(
                label, lambda text, r=replacement: text.replace(env_line, r, 1)
            )

    def test_executed_inventory_matches_the_producer_artifact_files(self):
        """The executed inventory is the same exact three-file producer check."""
        self.assertIn(
            "--verify-signed-review-artifact-inventory",
            VERIFIER.EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND,
        )
        self.assertEqual(
            sorted(VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES),
            sorted(
                line.removeprefix("protected-review/")
                for line in VERIFIER.EXPECTED_SIGNED_REVIEW_UPLOAD_WITH["path"].splitlines()
            ),
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES:
                (root / name).write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                VERIFIER.verify_signed_review_artifact_inventory(root),
                sorted(VERIFIER.EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES),
            )


# ---------------------------------------------------------------------------
# t_c678e93e FINDING 2 -- F3-ARTIFACT-ACTION-CASE-ALIAS-NOT-ENUMERATED
#
# GitHub resolves an action's owner/repository case-insensitively while the
# pinned ref stays byte-exact. Enumeration must therefore case-fold only the
# owner/repository portion, so `Actions/Upload-Artifact@<pin>` and
# `ACTIONS/DOWNLOAD-ARTIFACT@<pin>` are counted as semantic invocations, while
# the sole authorized upload and download still have to match the pinned `uses`
# byte for byte.
# ---------------------------------------------------------------------------
class ArtifactActionCaseAliasTests(unittest.TestCase):
    UPLOAD_PIN = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    DOWNLOAD_PIN = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    UPLOAD_TAIL = "            protected-review/preissuance-review-receipt.sigstore.json\n"
    CHECKOUT_TAIL = (
        "          fetch-depth: 2\n"
        "          persist-credentials: false\n"
    )

    def setUp(self):
        self.review_workflow = (
            ROOT / REVIEW_BOOTSTRAP_RELDIR / REVIEW_WORKFLOW_RELPATH
        ).read_text(encoding="utf-8")
        self.signing_workflow = (ROOT / SIGNING_WORKFLOW_RELPATH).read_text(encoding="utf-8")

    def assert_producer_rejected(self, label, mutate, expected_fragment=None):
        with tempfile.TemporaryDirectory() as td:
            changed = Path(td) / "bootstrap"
            shutil.copytree(ROOT / REVIEW_BOOTSTRAP_RELDIR, changed)
            wf_path = changed / REVIEW_WORKFLOW_RELPATH
            original = wf_path.read_text(encoding="utf-8")
            modified = mutate(original)
            self.assertNotEqual(original, modified, f"mutation had no effect: {label}")
            wf_path.write_text(modified, encoding="utf-8")
            contract_path = changed / "bootstrap-contract.json"
            contract = json.loads(contract_path.read_bytes())
            contract["workflow"]["sha256"] = hashlib.sha256(wf_path.read_bytes()).hexdigest()
            contract_path.write_bytes(VERIFIER.canonical(contract))
            with self.assertRaises(SystemExit, msg=label) as raised:
                VERIFIER.verify_independent_review_bootstrap(changed)
            if expected_fragment is not None:
                self.assertIn(expected_fragment, str(raised.exception), label)

    def assert_consumer_rejected(self, label, mutate, expected_fragment=None):
        with tempfile.TemporaryDirectory() as td:
            candidate_root = Path(td)
            copy_candidate_tree(candidate_root)
            wf_path = candidate_root / SIGNING_WORKFLOW_RELPATH
            original = wf_path.read_text(encoding="utf-8")
            modified = mutate(original)
            self.assertNotEqual(original, modified, f"mutation had no effect: {label}")
            wf_path.write_text(modified, encoding="utf-8")
            recompute_candidate_manifest(candidate_root)
            with self.assertRaises(SystemExit, msg=label) as raised:
                verify_candidate_at(candidate_root)
            if expected_fragment is not None:
                self.assertIn(expected_fragment, str(raised.exception), label)

    # -- classification --------------------------------------------------
    def test_only_the_owner_and_repository_portion_is_case_folded(self):
        """Mixed-case owner/repository aliases classify; the pinned ref never folds."""
        cases = {
            self.UPLOAD_PIN: "actions/upload-artifact",
            "Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02":
                "actions/upload-artifact",
            "ACTIONS/UPLOAD-ARTIFACT@ea165f8d65b6e75b540449e92b4886f43607fa02":
                "actions/upload-artifact",
            "aCtIoNs/uPlOaD-aRtIfAcT@0000000000000000000000000000000000000000":
                "actions/upload-artifact",
            "actions/upload-artifact": "actions/upload-artifact",
            "Actions/Upload-Artifact": "actions/upload-artifact",
            self.DOWNLOAD_PIN: "actions/download-artifact",
            "Actions/Download-Artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093":
                "actions/download-artifact",
            "ACTIONS/DOWNLOAD-ARTIFACT@d3f86a106a0bac45b974a628896c90dbdf5c8093":
                "actions/download-artifact",
            "actions/upload-artifact-evil@ea165f8d65b6e75b540449e92b4886f43607fa02": None,
            "attacker/actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02": None,
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262": None,
            "": None,
            None: None,
            17: None,
        }
        for uses, expected in cases.items():
            with self.subTest(uses=uses):
                self.assertEqual(VERIFIER._semantic_artifact_action(uses), expected)

        # The ref half must never be case-folded into the authorized pin.
        upper_ref = "actions/upload-artifact@EA165F8D65B6E75B540449E92B4886F43607FA02"
        self.assertEqual(
            VERIFIER._semantic_artifact_action(upper_ref), "actions/upload-artifact"
        )
        self.assertNotEqual(upper_ref, VERIFIER.EXPECTED_UPLOAD_ARTIFACT_USES)

    def test_mixed_case_aliases_are_enumerated_but_never_the_authorized_pin(self):
        """Aliases are counted as semantic invocations and keep their exact bytes."""
        alias_upload = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - name: Upload immutable signed review artifact\n"
            "        uses: Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "        with:\n"
            "          name: authority-v2-signed-review-t_c298fca4\n"
            "          if-no-files-found: error\n"
            "          retention-days: 1\n"
            "          path: |\n"
            "            protected-review/kanban-review-envelope.json\n"
            "            protected-review/preissuance-review-receipt.json\n"
            "            protected-review/preissuance-review-receipt.sigstore.json\n"
        )
        alias_download = (
            "jobs:\n"
            "  issue:\n"
            "    steps:\n"
            "      - name: Download exact independently signed receipt\n"
            "        uses: ACTIONS/DOWNLOAD-ARTIFACT@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
            "        with:\n"
            "          name: authority-v2-signed-review-t_c298fca4\n"
            "          path: ${{ runner.temp }}/authority-v2-runtime/independent-review\n"
            "          repository: chrizzatsu/acc-authority-independent-review\n"
            "          run-id: ${{ inputs.independent_review_run_id }}\n"
            "          github-token: ${{ steps.review-token.outputs.token }}\n"
        )
        uploads = VERIFIER._parse_upload_artifact_steps(alias_upload)
        self.assertEqual(len(uploads), 1, "mixed-case upload alias was not enumerated")
        self.assertEqual(
            uploads[0]["uses"],
            "Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        )
        self.assertNotEqual(uploads[0]["uses"], VERIFIER.EXPECTED_UPLOAD_ARTIFACT_USES)
        self.assertEqual(uploads[0]["with"], VERIFIER.EXPECTED_SIGNED_REVIEW_UPLOAD_WITH)

        downloads = VERIFIER._parse_download_artifact_steps(alias_download)
        self.assertEqual(len(downloads), 1, "mixed-case download alias was not enumerated")
        self.assertEqual(
            downloads[0]["uses"],
            "ACTIONS/DOWNLOAD-ARTIFACT@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        )
        self.assertNotEqual(downloads[0]["uses"], VERIFIER.EXPECTED_DOWNLOAD_ARTIFACT_USES)
        self.assertEqual(downloads[0]["with"], VERIFIER.EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH)

    def test_unpinned_and_alias_only_invocations_are_still_enumerated(self):
        """An unpinned or mixed-case-only `uses` never disappears from the count."""
        unpinned = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: Actions/Upload-Artifact\n"
        )
        self.assertEqual(len(VERIFIER._parse_upload_artifact_steps(unpinned)), 1)

    # -- producer: exactly one total upload ------------------------------
    def test_mixed_case_duplicate_producer_upload_fails_closed(self):
        """A second producer upload written in mixed case must be counted."""
        injections = {
            "mixed-case-plain-upload": (
                "\n"
                "      - name: Attacker upload\n"
                "        uses: Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
                "        with:\n"
                "          name: authority-v2-signed-review-t_ATTACKER\n"
                "          path: protected-review/kanban-review-envelope.json\n"
            ),
            "mixed-case-quoted-key-upload": (
                "\n"
                '      - "name": Attacker upload\n'
                '        "uses": "ACTIONS/UPLOAD-ARTIFACT@ea165f8d65b6e75b540449e92b4886f43607fa02"\n'
                '        "with":\n'
                '          "name": authority-v2-signed-review-t_ATTACKER\n'
                '          "path": protected-review/kanban-review-envelope.json\n'
            ),
            "mixed-case-spaced-key-upload": (
                "\n"
                "      - name : Attacker upload\n"
                "        uses : Actions/UPLOAD-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
                "        with :\n"
                "          name : authority-v2-signed-review-t_ATTACKER\n"
                "          path : protected-review/kanban-review-envelope.json\n"
            ),
            "mixed-case-flow-map-upload": (
                "\n"
                "      - {name: Attacker upload,"
                " uses: aCtIoNs/uPlOaD-aRtIfAcT@ea165f8d65b6e75b540449e92b4886f43607fa02,"
                " with: {name: authority-v2-signed-review-t_ATTACKER,"
                " path: protected-review/kanban-review-envelope.json}}\n"
            ),
            "mixed-case-key-order-upload": (
                "\n"
                "      - with:\n"
                "          path: protected-review/kanban-review-envelope.json\n"
                "          name: authority-v2-signed-review-t_ATTACKER\n"
                "        id: attacker-upload\n"
                "        uses: Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
                "        name: Attacker upload\n"
            ),
            "mixed-case-unpinned-upload": (
                "\n"
                "      - name: Attacker upload\n"
                "        uses: Actions/Upload-Artifact\n"
                "        with:\n"
                "          name: authority-v2-signed-review-t_ATTACKER\n"
                "          path: protected-review/kanban-review-envelope.json\n"
            ),
        }
        for label, injection in injections.items():
            self.assert_producer_rejected(
                label,
                lambda text, i=injection: text.replace(
                    self.UPLOAD_TAIL, self.UPLOAD_TAIL + i, 1
                ),
                "upload-artifact steps, found 4",
            )

    def test_mixed_case_alias_cannot_replace_the_authorized_producer_upload(self):
        """The sole authorized upload still needs the byte-exact pinned `uses`."""
        for label, alias in (
            ("alias-owner-cased", "Actions/Upload-Artifact"),
            ("alias-fully-uppercased", "ACTIONS/UPLOAD-ARTIFACT"),
        ):
            self.assert_producer_rejected(
                label,
                lambda text, a=alias: text.replace(
                    f"uses: {self.UPLOAD_PIN}\n",
                    f"uses: {a}@ea165f8d65b6e75b540449e92b4886f43607fa02\n",
                    1,
                ),
                "upload-artifact action or complete with-map mismatch",
            )

    # -- consumer: exactly one total Authority download ------------------
    def test_mixed_case_duplicate_consumer_download_fails_closed(self):
        """A second Authority download written in mixed case must be counted."""
        injections = {
            "mixed-case-plain-download": (
                "\n"
                "      - name: Attacker download\n"
                "        uses: Actions/Download-Artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
                "        with:\n"
                "          name: authority-v2-signed-review-t_ATTACKER\n"
                "          path: injected\n"
            ),
            "mixed-case-quoted-key-download": (
                "\n"
                '      - "name": Attacker download\n'
                '        "uses": "ACTIONS/DOWNLOAD-ARTIFACT@d3f86a106a0bac45b974a628896c90dbdf5c8093"\n'
                '        "with":\n'
                '          "name": authority-v2-signed-review-t_ATTACKER\n'
                '          "path": injected\n'
            ),
            "mixed-case-spaced-key-download": (
                "\n"
                "      - name : Attacker download\n"
                "        uses : Actions/DOWNLOAD-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
                "        with :\n"
                "          name : authority-v2-signed-review-t_ATTACKER\n"
                "          path : injected\n"
            ),
            "mixed-case-flow-map-download": (
                "\n"
                "      - {name: Attacker download,"
                " uses: aCtIoNs/dOwNlOaD-aRtIfAcT@d3f86a106a0bac45b974a628896c90dbdf5c8093,"
                " with: {name: authority-v2-signed-review-t_ATTACKER, path: injected}}\n"
            ),
            "mixed-case-key-order-download": (
                "\n"
                "      - with:\n"
                "          path: injected\n"
                "          name: authority-v2-signed-review-t_ATTACKER\n"
                "        id: attacker-download\n"
                "        uses: ACTIONS/Download-Artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
                "        name: Attacker download\n"
            ),
            "mixed-case-unpinned-download": (
                "\n"
                "      - name: Attacker download\n"
                "        uses: Actions/Download-Artifact\n"
                "        with:\n"
                "          name: authority-v2-signed-review-t_ATTACKER\n"
                "          path: injected\n"
            ),
        }
        for label, injection in injections.items():
            self.assert_consumer_rejected(
                label,
                lambda text, i=injection: text.replace(
                    self.CHECKOUT_TAIL, self.CHECKOUT_TAIL + i, 1
                ),
                "total download-artifact steps, found 3",
            )

    def test_mixed_case_alias_cannot_replace_the_authorized_consumer_download(self):
        """The sole authorized download still needs the byte-exact pinned `uses`."""
        for label, alias in (
            ("alias-owner-cased", "Actions/Download-Artifact"),
            ("alias-fully-uppercased", "ACTIONS/DOWNLOAD-ARTIFACT"),
        ):
            self.assert_consumer_rejected(
                label,
                lambda text, a=alias: text.replace(
                    f"uses: {self.DOWNLOAD_PIN}\n",
                    f"uses: {a}@d3f86a106a0bac45b974a628896c90dbdf5c8093\n",
                    1,
                ),
            )

    # -- hidden mixed-case duplicates in unsupported/ambiguous YAML ------
    def test_mixed_case_hidden_duplicate_yaml_forms_fail_closed(self):
        """Aliases, merge keys and duplicate keys never hide a mixed-case invocation."""
        anchor_alias = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "        with: &signed_review_with\n"
            "          name: authority-v2-signed-review-t_c298fca4\n"
            "      - uses: ACTIONS/UPLOAD-ARTIFACT@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "        with: *signed_review_with\n"
        )
        merge_key = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "        with:\n"
            "          <<: *defaults\n"
            "          name: authority-v2-signed-review-t_c298fca4\n"
        )
        duplicate_uses = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "        uses: ACTIONS/UPLOAD-ARTIFACT@0000000000000000000000000000000000000000\n"
        )
        duplicate_quoted_uses = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            '        "uses": Actions/Upload-Artifact@0000000000000000000000000000000000000000\n'
        )
        duplicate_flow_uses = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - {uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02,"
            " uses: Actions/Upload-Artifact@0000000000000000000000000000000000000000}\n"
        )
        duplicate_job = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: ACTIONS/UPLOAD-ARTIFACT@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
        )
        tagged = (
            "jobs:\n"
            "  review:\n"
            "    steps:\n"
            "      - uses: Actions/Upload-Artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "        with: !!map\n"
            "          name: authority-v2-signed-review-t_c298fca4\n"
        )
        for label, text in (
            ("mixed-case-anchor-and-alias", anchor_alias),
            ("mixed-case-merge-key", merge_key),
            ("mixed-case-duplicate-uses-key", duplicate_uses),
            ("mixed-case-duplicate-quoted-uses-key", duplicate_quoted_uses),
            ("mixed-case-duplicate-flow-uses-key", duplicate_flow_uses),
            ("mixed-case-duplicate-job-key", duplicate_job),
            ("mixed-case-explicit-tag", tagged),
        ):
            with self.subTest(form=label), self.assertRaises(SystemExit, msg=label):
                VERIFIER._parse_upload_artifact_steps(text)

    def test_shipped_sources_still_enumerate_the_exact_uploads_and_download(self):
        """The producer keeps exactly its three authorized artifact uploads."""
        uploads = VERIFIER._parse_upload_artifact_steps(self.review_workflow)
        self.assertEqual(
            uploads,
            [
                {
                    "uses": VERIFIER.EXPECTED_UPLOAD_ARTIFACT_USES,
                    "with": VERIFIER.EXPECTED_SIGNED_REVIEW_UPLOAD_WITH,
                },
                {
                    "uses": VERIFIER.EXPECTED_UPLOAD_ARTIFACT_USES,
                    "with": VERIFIER.EXPECTED_EXTERNAL_REVIEW_UPLOAD_WITH,
                },
                {
                    "uses": VERIFIER.EXPECTED_UPLOAD_ARTIFACT_USES,
                    "with": VERIFIER.EXPECTED_GENERATED_ACTIVATION_UPLOAD_WITH,
                },
            ],
        )
        # The consumer keeps exactly its two authorized artifact downloads:
        # the signed review artifact and the external activation review
        # artifact the derived closure lane consumes. Nothing else may appear.
        downloads = VERIFIER._parse_download_artifact_steps(self.signing_workflow)
        self.assertEqual(
            downloads,
            [
                {
                    "uses": VERIFIER.EXPECTED_DOWNLOAD_ARTIFACT_USES,
                    "with": VERIFIER.EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH,
                },
                {
                    "uses": VERIFIER.EXPECTED_DOWNLOAD_ARTIFACT_USES,
                    "with": VERIFIER.EXPECTED_EXTERNAL_REVIEW_DOWNLOAD_WITH,
                },
            ],
        )
        self.assertEqual(
            downloads,
            [
                {"uses": VERIFIER.EXPECTED_DOWNLOAD_ARTIFACT_USES, "with": entry}
                for entry in VERIFIER.EXPECTED_CONSUMER_DOWNLOADS
            ],
        )
        self.assertEqual(len(VERIFIER._parse_upload_artifact_steps(self.signing_workflow)), 0)


class SealedEnvironmentReadbackTests(unittest.TestCase):
    """SEALED-GITHUB-READBACK-ENVIRONMENT-MISMATCH.

    Source evidence must distinguish an authenticated HTTP 200 read from an
    unauthenticated or permission-masked 404 and from confirmed absence, and
    must bind the exact current authenticated read-only Environment state.
    """

    SEALED_ENVIRONMENT_ID = 20467803126
    SEALED_REVIEWER = "chrizzatsu"

    def setUp(self):
        self.contract = json.loads(
            (ROOT / "github-environment-v2-contract.json").read_bytes()
        )
        self.repository = {"full_name": self.contract["repository"], "private": False}
        self.environment = {
            "id": self.SEALED_ENVIRONMENT_ID,
            "name": self.contract["environment"],
            "can_admins_bypass": False,
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
            "protection_rules": [{
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"login": self.SEALED_REVIEWER}},
                ],
            }],
        }
        self.secrets = {"total_count": 0, "secrets": []}
        self.immutable = {"enabled": True, "enforced_by_owner": False}

    def sealed(self):
        return self.contract["sealed_environment_readback"]

    def test_contract_seals_the_exact_current_authenticated_environment_state(self):
        sealed = self.sealed()
        self.assertEqual(sealed["http_status"], 200)
        self.assertEqual(sealed["environment_id"], self.SEALED_ENVIRONMENT_ID)
        self.assertEqual(sealed["required_reviewer_logins"], [self.SEALED_REVIEWER])
        self.assertIs(sealed["prevent_self_review"], True)
        self.assertIs(sealed["protected_branches"], True)
        self.assertEqual(sealed["environment_secrets_total_count"], 0)
        self.assertIs(sealed["authenticated_read_only"], True)
        self.assertIs(sealed["no_github_write_performed"], True)
        self.assertIs(sealed["permission_masked_404_is_not_absence"], True)
        self.assertIs(
            sealed["confirmed_absence_requires_authenticated_permission_proof"], True
        )

    def test_authenticated_200_is_the_only_present_classification(self):
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(200, authenticated=True),
            "authenticated_present",
        )
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(200, authenticated=False),
            "unauthenticated",
        )

    def test_masked_404_is_never_confirmed_absence_without_permission_proof(self):
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(404, authenticated=True),
            "masked_or_absent",
        )
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(404, authenticated=False),
            "unauthenticated",
        )
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(
                404, authenticated=True, permission_proof=None,
            ),
            "masked_or_absent",
        )
        # A bare HTTP 200 naming some other Environment proves nothing: it binds
        # no credential identity, no request path and no exhaustive traversal.
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(
                404, authenticated=True,
                permission_proof={"status": 200, "environment_names": ["other"]},
            ),
            "masked_or_absent",
        )
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(
                404, authenticated=True,
                permission_proof=self._proof(),
                target_request=self._target_request(),
            ),
            "confirmed_absent",
        )

    def test_permission_proof_must_itself_be_an_authenticated_200_listing(self):
        for proof in (
            {"status": 403, "environment_names": ["other"]},
            {"status": 404, "environment_names": []},
            {"status": 200},
            {"environment_names": ["other"]},
            {"status": 200, "environment_names": ["attestation"]},
            "200",
            [],
        ):
            with self.subTest(proof=proof):
                self.assertEqual(
                    ENV_VERIFIER.classify_environment_read(
                        404, authenticated=True, permission_proof=proof,
                        target_request=self._target_request(),
                    ),
                    "masked_or_absent",
                )

    # --- confirmed absence needs an exhaustive, identity-bound traversal ---

    CREDENTIAL = "github-app-installation:acc-environment-reader:41424344"

    def _target_request(self, **overrides):
        repository = self.contract["repository"]
        request = {
            "credential_identity": self.CREDENTIAL,
            "repository": repository,
            "request_path": (
                f"/repos/{repository}/environments/{self.contract['environment']}"
            ),
        }
        request.update(overrides)
        return request

    def _page(self, number, names, *, total=None, next_page=None, **overrides):
        repository = self.contract["repository"]
        payload = {
            "page": number,
            "status": 200,
            "authenticated": True,
            "credential_identity": self.CREDENTIAL,
            "request_path": (
                f"/repos/{repository}/environments"
                f"?per_page={ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE}&page={number}"
            ),
            "total_count": len(names) if total is None else total,
            "environments": [{"name": name} for name in names],
            "headers": {},
        }
        if next_page is not None:
            payload["headers"] = {"Link": (
                f"<https://api.github.com/repos/{repository}/environments"
                f"?per_page={ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE}&page={next_page}>"
                '; rel="next"'
            )}
        payload.update(overrides)
        return payload

    def _proof(self, pages=None, **overrides):
        repository = self.contract["repository"]
        proof = {
            "credential_identity": self.CREDENTIAL,
            "repository": repository,
            "endpoint_path": f"/repos/{repository}/environments",
            "per_page": ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE,
            "pages": [self._page(1, ["build", "other"])] if pages is None else pages,
        }
        proof.update(overrides)
        return proof

    def _classify(self, proof, target_request=None):
        return ENV_VERIFIER.classify_environment_read(
            404, authenticated=True, permission_proof=proof,
            target_request=self._target_request() if target_request is None
            else target_request,
        )

    def test_exhaustive_multipage_listing_confirms_absence(self):
        first = [f"env-{index}" for index in range(ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE)]
        pages = [
            self._page(1, first, total=len(first) + 1, next_page=2),
            self._page(2, ["tail"], total=len(first) + 1),
        ]
        self.assertEqual(self._classify(self._proof(pages)), "confirmed_absent")
        self.assertEqual(self._classify(self._proof()), "confirmed_absent")

    def test_incomplete_or_unreconciled_pagination_is_never_absence(self):
        repository = self.contract["repository"]
        first = [f"env-{index}" for index in range(ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE)]
        foreign_link = (
            '<https://evil.example/repos/x/environments?per_page=100&page=2>; rel="next"'
        )
        cases = {
            "advertised-next-page-absent": [
                self._page(1, first, total=len(first) + 1, next_page=2),
            ],
            "unadvertised-extra-page": [
                self._page(1, ["other"], total=2),
                self._page(2, ["tail"], total=2),
            ],
            "non-monotonic-next": [
                self._page(1, first, total=len(first) + 1, next_page=3),
                self._page(3, ["tail"], total=len(first) + 1),
            ],
            "looping-next": [
                self._page(1, first, total=len(first) + 1, next_page=1),
            ],
            "foreign-next-host": [
                self._page(1, first, total=len(first) + 1,
                           headers={"Link": foreign_link}),
                self._page(2, ["tail"], total=len(first) + 1),
            ],
            "duplicate-link-headers": [
                self._page(
                    1, first, total=len(first) + 1,
                    headers={
                        "Link": (
                            f'<https://api.github.com/repos/{repository}/environments'
                            f'?per_page=100&page=2>; rel="next"'
                        ),
                        "link": (
                            f'<https://api.github.com/repos/{repository}/environments'
                            f'?per_page=100&page=2>; rel="next"'
                        ),
                    },
                ),
                self._page(2, ["tail"], total=len(first) + 1),
            ],
            "unparsable-next-token": [
                self._page(1, first, total=len(first) + 1,
                           headers={"Link": 'rel="next"'}),
                self._page(2, ["tail"], total=len(first) + 1),
            ],
            "wrong-per-page-next": [
                self._page(
                    1, first, total=len(first) + 1,
                    headers={"Link": (
                        f'<https://api.github.com/repos/{repository}/environments'
                        f'?per_page=50&page=2>; rel="next"'
                    )},
                ),
                self._page(2, ["tail"], total=len(first) + 1),
            ],
            "non-sequential-page-numbers": [
                self._page(1, first, total=len(first) + 1, next_page=2),
                self._page(5, ["tail"], total=len(first) + 1),
            ],
            "totals-disagree": [
                self._page(1, first, total=len(first) + 1, next_page=2),
                self._page(2, ["tail"], total=999),
            ],
            "total-count-mismatch": [self._page(1, ["other"], total=7)],
            "duplicate-environment-across-pages": [
                self._page(1, first, total=len(first) + 1, next_page=2),
                self._page(2, [first[0]], total=len(first) + 1),
            ],
            "empty-listing-proves-nothing": [self._page(1, [], total=0)],
            "no-pages": [],
            "short-first-page-with-next": [
                self._page(1, ["other"], total=2, next_page=2),
                self._page(2, ["tail"], total=2),
            ],
        }
        for name, pages in cases.items():
            with self.subTest(name=name):
                self.assertEqual(
                    self._classify(self._proof(pages)), "masked_or_absent",
                )

    def test_unbound_credential_or_request_identity_is_never_absence(self):
        repository = self.contract["repository"]
        other = "chrizzatsu/other-repository"
        cases = {
            "absent-target-request": (self._proof(), None, True),
            "malformed-target-request": (self._proof(), "nope", True),
            "target-credential-differs": (
                self._proof(), self._target_request(credential_identity="other"), True,
            ),
            "target-repository-differs": (
                self._proof(), self._target_request(repository=other), True,
            ),
            "target-path-is-not-the-sealed-environment": (
                self._proof(),
                self._target_request(request_path=f"/repos/{repository}/environments/x"),
                True,
            ),
            "proof-credential-absent": (
                self._proof(credential_identity=None), None, False,
            ),
            "page-credential-differs": (
                self._proof([self._page(1, ["other"], credential_identity="drifted")]),
                None, False,
            ),
            "proof-repository-differs": (
                self._proof(repository=other), None, False,
            ),
            "endpoint-path-differs": (
                self._proof(endpoint_path=f"/repos/{other}/environments"), None, False,
            ),
            "page-request-path-differs": (
                self._proof([self._page(
                    1, ["other"],
                    request_path=f"/repos/{repository}/environments?per_page=100&page=2",
                )]),
                None, False,
            ),
            "per-page-differs": (self._proof(per_page=50), None, False),
        }
        for name, (proof, target, explicit) in cases.items():
            with self.subTest(name=name):
                observed = ENV_VERIFIER.classify_environment_read(
                    404, authenticated=True, permission_proof=proof,
                    target_request=target if explicit else self._target_request(),
                )
                self.assertEqual(observed, "masked_or_absent")

    def test_substituted_or_contradicting_listing_data_is_never_absence(self):
        cases = {
            "page-status-not-200": [self._page(1, ["other"], status=403)],
            "page-not-authenticated": [self._page(1, ["other"], authenticated=False)],
            "sealed-environment-present": [self._page(1, ["attestation", "other"])],
            "sealed-environment-on-later-page": [
                self._page(
                    1,
                    [f"env-{index}" for index in range(ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE)],
                    total=ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE + 1, next_page=2,
                ),
                self._page(
                    2, ["attestation"],
                    total=ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE + 1,
                ),
            ],
            "environment-entry-malformed": [
                self._page(1, [], total=1, environments=["other"]),
            ],
            "environment-name-not-a-string": [
                self._page(1, [], total=1, environments=[{"name": 7}]),
            ],
            "environments-not-a-list": [
                self._page(1, [], total=1, environments={"name": "other"}),
            ],
            "headers-not-a-mapping": [self._page(1, ["other"], headers=[])],
            "page-number-not-an-integer": [self._page(1, ["other"], page="1")],
            "total-count-not-an-integer": [self._page(1, ["other"], total="1")],
        }
        for name, pages in cases.items():
            with self.subTest(name=name):
                self.assertEqual(
                    self._classify(self._proof(pages)), "masked_or_absent",
                )

    def test_contract_declares_the_exhaustive_absence_rule(self):
        sealed = self.sealed()
        self.assertIs(
            sealed["confirmed_absence_requires_exhaustive_authenticated_pagination"],
            True,
        )
        self.assertIn(
            "confirmed_absence_requires_exhaustive_authenticated_pagination",
            ENV_VERIFIER.SEALED_READBACK_KEYS,
        )
        self.assertEqual(ENV_VERIFIER.ENVIRONMENT_PAGE_SIZE, 100)
        self.assertGreaterEqual(ENV_VERIFIER.MAX_ENVIRONMENT_PAGES, 1)

    def test_documents_state_the_exhaustive_absence_rule(self):
        for document in ("README.md", "VERIFY-AUTHORITY-V2.md"):
            text = (ROOT / document).read_text(encoding="utf-8")
            with self.subTest(document=document):
                self.assertIn("/repos/{owner}/{repo}/environments", text)
                self.assertIn("masked_or_absent", text)
                self.assertIn("credential", text)

    def test_live_authenticated_200_readback_is_unaffected(self):
        result = ENV_VERIFIER.verify_sealed_environment_readback(
            self.environment, self.secrets, self.contract,
            environment_status=200, authenticated=True,
        )
        self.assertEqual(result["environment_id"], self.SEALED_ENVIRONMENT_ID)
        self.assertEqual(result["environment_read"], "authenticated_present")
        self.assertEqual(result["environment_secrets_total_count"], 0)
        self.assertIs(result["github_write_performed"], False)

    def test_unauthenticated_forbidden_and_unknown_statuses_are_distinguished(self):
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(401, authenticated=True),
            "unauthenticated",
        )
        self.assertEqual(
            ENV_VERIFIER.classify_environment_read(403, authenticated=True),
            "unauthenticated",
        )
        for status in (429, 500, 502, 302, None):
            with self.subTest(status=status):
                self.assertEqual(
                    ENV_VERIFIER.classify_environment_read(status, authenticated=True),
                    "unknown",
                )

    def test_exact_live_readback_binds_and_reports_the_sealed_state(self):
        result = ENV_VERIFIER.verify_sealed_environment_readback(
            self.environment, self.secrets, self.contract,
            environment_status=200, authenticated=True,
        )
        self.assertEqual(result, {
            "environment_id": self.SEALED_ENVIRONMENT_ID,
            "environment_read": "authenticated_present",
            "environment_secrets_total_count": 0,
            "github_write_performed": False,
            "prevent_self_review": True,
            "protected_branches": True,
            "required_reviewer_logins": [self.SEALED_REVIEWER],
            "sealed_state_unchanged": True,
        })

    def test_live_readback_that_differs_from_the_sealed_state_fails_closed(self):
        mutations = {
            "masked-404": (lambda: None, dict(environment_status=404)),
            "unauthenticated": (lambda: None, dict(authenticated=False)),
            "other-status": (lambda: None, dict(environment_status=500)),
            "different-id": (
                lambda: self.environment.update(id=1), {},
            ),
            "missing-id": (
                lambda: self.environment.pop("id"), {},
            ),
            "string-id": (
                lambda: self.environment.update(id=str(self.SEALED_ENVIRONMENT_ID)), {},
            ),
            "other-reviewer": (
                lambda: self.environment["protection_rules"][0]["reviewers"].__setitem__(
                    0, {"type": "User", "reviewer": {"login": "someone-else"}},
                ),
                {},
            ),
            "extra-reviewer": (
                lambda: self.environment["protection_rules"][0]["reviewers"].append(
                    {"type": "User", "reviewer": {"login": "someone-else"}},
                ),
                {},
            ),
            "team-reviewer": (
                lambda: self.environment["protection_rules"][0]["reviewers"].__setitem__(
                    0, {"type": "Team", "reviewer": {"slug": "chrizzatsu"}},
                ),
                {},
            ),
            "self-review-allowed": (
                lambda: self.environment["protection_rules"][0].update(
                    prevent_self_review=False,
                ),
                {},
            ),
            "custom-branch-policies": (
                lambda: self.environment.update(deployment_branch_policy={
                    "protected_branches": False, "custom_branch_policies": True,
                }),
                {},
            ),
            "environment-secret-present": (
                lambda: self.secrets.update(
                    total_count=1, secrets=[{"name": "ANY"}],
                ),
                {},
            ),
            "secret-count-mismatch": (
                lambda: self.secrets.update(total_count=0, secrets=[{"name": "ANY"}]),
                {},
            ),
            "secrets-malformed": (lambda: self.secrets.clear(), {}),
        }
        for name, (mutate, overrides) in mutations.items():
            with self.subTest(name=name):
                self.setUp()
                mutate()
                call = {"environment_status": 200, "authenticated": True}
                call.update(overrides)
                with self.assertRaises(SystemExit):
                    ENV_VERIFIER.verify_sealed_environment_readback(
                        self.environment, self.secrets, self.contract, **call,
                    )

    def test_full_environment_verification_requires_the_sealed_readback(self):
        result = ENV_VERIFIER.verify_environment(
            self.repository, self.environment, None, self.immutable, self.contract,
            branch_policies_status=404,
            environment_status=200,
            authenticated=True,
            environment_secrets=self.secrets,
        )
        self.assertEqual(result["environment_id"], self.SEALED_ENVIRONMENT_ID)
        self.assertEqual(result["environment_read"], "authenticated_present")
        self.assertEqual(result["environment_secrets_total_count"], 0)
        self.assertIs(result["sealed_state_unchanged"], True)
        with self.assertRaises(SystemExit):
            ENV_VERIFIER.verify_environment(
                self.repository, self.environment, None, self.immutable, self.contract,
                branch_policies_status=404,
                environment_status=404,
                authenticated=True,
                environment_secrets=self.secrets,
            )

    def test_authority_verifier_binds_the_sealed_readback_block_exactly(self):
        self.assertEqual(
            VERIFIER.EXPECTED_SEALED_ENVIRONMENT_READBACK, self.sealed(),
        )
        for mutate in (
            lambda block: block.update(environment_id=1),
            lambda block: block.update(http_status=404),
            lambda block: block.update(environment_secrets_total_count=1),
            lambda block: block.update(prevent_self_review=False),
            lambda block: block.update(protected_branches=False),
            lambda block: block.update(required_reviewer_logins=["someone-else"]),
            lambda block: block.update(permission_masked_404_is_not_absence=False),
            lambda block: block.pop("environment_id"),
            lambda block: block.update(extra_member=True),
        ):
            with self.subTest(mutate=mutate):
                block = deepcopy(self.sealed())
                mutate(block)
                with self.assertRaises(SystemExit):
                    VERIFIER._require_exact_json(
                        block,
                        VERIFIER.EXPECTED_SEALED_ENVIRONMENT_READBACK,
                        "environment sealed readback contract",
                    )

    def test_environment_verifier_source_performs_no_github_write(self):
        source = (ROOT / "scripts" / "verify_github_environment_v2.py").read_text(
            encoding="utf-8",
        )
        for forbidden in (
            "urllib", "requests", "http.client", "socket", "subprocess",
            "POST", "PATCH", "PUT", "DELETE",
        ):
            self.assertNotIn(forbidden, source, forbidden)


class ExecutableSealedBootstrapTests(unittest.TestCase):
    """F8-SEALED-BOOTSTRAP-NONEXECUTABLE.

    The six sealed bootstrap bytes must be executable and internally state
    consistent: the protected lane deterministically emits the exact
    artifact/envelope/receipt chain from authenticated, non-caller-selectable
    server state instead of always exiting, and the independent lane
    re-derives and validates the same pre/post activation state without any
    caller-selectable path, run, state, artifact or byte substitution.
    """

    RUN_ID = 4242
    RUN_HEAD = "1" * 40
    SOURCE_TREE = "3" * 40
    BOOTSTRAP_COMMIT = "9" * 40
    BOOTSTRAP_TREE = "e" * 40

    @classmethod
    def setUpClass(cls):
        cls.candidate = authority_candidate()
        cls.AUTHORITY_HEAD = cls.candidate.head
        cls.AUTHORITY_TREE = cls.candidate.tree

    def setUp(self):
        self.validator_root = validator_checkout(self)
        self.source_root = ROOT / "protected-source-bootstrap-v2"
        self.independent_root = ROOT / "independent-review-bootstrap-v2"
        self.source_workflow = (
            self.source_root / EXPORT.WORKFLOW_PATH
        ).read_bytes()
        self.source_helper = (self.source_root / EXPORT.HELPER_PATH).read_bytes()
        self.independent_workflow = (
            self.independent_root / VALIDATOR.INDEPENDENT_WORKFLOW_PATH
        ).read_bytes()
        self.independent_validator = (
            self.independent_root / VALIDATOR.INDEPENDENT_VALIDATOR_PATH
        ).read_bytes()
        self.sealed_source_contract = json.loads(
            (self.source_root / EXPORT.CONTRACT_PATH).read_bytes()
        )
        self.sealed_independent_contract = json.loads(
            (self.independent_root / VALIDATOR.CONTRACT_PATH).read_bytes()
        )

    # --- sealed pre-activation posture ---

    def test_sealed_contracts_are_internally_state_consistent_before_activation(self):
        binding = self.sealed_source_contract["authority_binding"]
        review = self.sealed_source_contract["protected_review_result"]
        self.assertEqual(
            binding["activation_state"], EXPORT.AUTHORIZED_PENDING_EVIDENCE,
        )
        self.assertEqual(
            review["activation_state"], EXPORT.AUTHORIZED_PENDING_EVIDENCE,
        )
        self.assertEqual(binding["authorized_run_attempt"], 1)
        self.assertIs(self.sealed_source_contract["repository_created"], False)
        self.assertIs(self.sealed_source_contract["workflow_dispatched"], False)
        for field in EXPORT.LIVE_DERIVED_FIELDS:
            self.assertIsNone(binding[field], field)
        for field in EXPORT.BINDING_HEX64_FIELDS:
            self.assertRegex(binding[field], r"\A[0-9a-f]{64}\Z")
        for field in EXPORT.REVIEW_RESULT_PINNED_FIELDS:
            self.assertIsNotNone(review[field], field)
        run = self.sealed_independent_contract["authorized_source_run"]
        self.assertEqual(
            run["activation_state"], EXPORT.AUTHORIZED_PENDING_EVIDENCE,
        )
        self.assertEqual(run["run_attempt"], 1)
        self.assertIs(self.sealed_independent_contract["repository_created"], False)

    def test_shipped_exporter_runs_and_fails_closed_only_before_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._checkout(Path(td))
            result = EXPORT.export(self._environment(), root=root)
            self.assertIs(result["exported"], True)
            self.assertTrue((root / EXPORT.OUTPUT_DIRECTORY).exists())
        unauthorized = deepcopy(self.sealed_source_contract)
        unauthorized["authority_binding"]["activation_state"] = "unavailable"
        unauthorized["protected_review_result"]["activation_state"] = "unavailable"
        for field in (*EXPORT.LIVE_DERIVED_FIELDS, *EXPORT.BINDING_HEX64_FIELDS):
            unauthorized["authority_binding"][field] = None
        for field in EXPORT.REVIEW_RESULT_PINNED_FIELDS:
            unauthorized["protected_review_result"][field] = None
        with tempfile.TemporaryDirectory() as td:
            root = self._checkout(Path(td), contract=unauthorized)
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._environment(), root=root)
            self.assertIn("F8 remains open", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())

    def test_shipped_validator_accepts_authorization_and_rejects_unavailable(self):
        run = VALIDATOR.authorized_source_run(
            deepcopy(self.sealed_independent_contract)
        )
        self.assertEqual(
            run["activation_state"], VALIDATOR.AUTHORIZED_PENDING_EVIDENCE,
        )
        unauthorized = deepcopy(self.sealed_independent_contract)
        unauthorized["authorized_source_run"]["activation_state"] = "unavailable"
        with self.assertRaises(SystemExit) as raised:
            VALIDATOR.authorized_source_run(unauthorized)
        self.assertIn("unavailable", str(raised.exception))

    # --- the exporter really exports ---

    def _checkout(self, base, *, contract=None):
        """Materialise a sealed protected-source checkout in a temp directory."""
        root = base / "protected-source"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / "scripts").mkdir(parents=True)
        (root / EXPORT.WORKFLOW_PATH).write_bytes(self.source_workflow)
        (root / EXPORT.HELPER_PATH).write_bytes(self.source_helper)
        payload = self.sealed_source_contract if contract is None else contract
        (root / EXPORT.CONTRACT_PATH).write_bytes(
            json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
        )
        self._write_authenticated(root)
        return root

    def _run_entry(self, **overrides):
        """One authenticated Actions workflow-run list entry."""
        entry = {
            "id": self.RUN_ID,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": self.RUN_HEAD,
            "path": EXPORT.WORKFLOW_PATH,
            "status": "completed",
            "conclusion": "success",
            "head_repository": {
                "full_name": self.sealed_source_contract["repository"],
            },
        }
        entry.update(overrides)
        return entry

    def _paginate(self, entries=None):
        """The exact page set a terminated server traversal returns.

        The traversal ends where the server stops advertising a next page, so
        the minimal page set is what both lanes read: never a fixed count.
        """
        entries = [self._run_entry()] if entries is None else list(entries)
        per_page = EXPORT.RUNS_PER_PAGE
        return [
            {
                "total_count": len(entries),
                "workflow_runs": entries[index * per_page:(index + 1) * per_page],
            }
            for index in range(max(1, -(-len(entries) // per_page)))
        ]

    def _source_run_pages(self, entries=None):
        return self._paginate(entries)

    def _write_authenticated(self, root, **overrides):
        """The authenticated, non-caller-selectable server commit projections."""
        documents = {
            EXPORT.SOURCE_COMMIT_FILE: {
                "sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE},
            },
            EXPORT.INDEPENDENT_COMMIT_FILE: {
                "sha": self.BOOTSTRAP_COMMIT, "tree": {"sha": self.BOOTSTRAP_TREE},
            },
            EXPORT.AUTHORITY_COMMIT_FILE: {
                "sha": self.AUTHORITY_HEAD, "tree": {"sha": self.AUTHORITY_TREE},
            },
        }
        documents.update(overrides)
        directory = root / EXPORT.AUTHENTICATED_DIRECTORY
        directory.mkdir(parents=True, exist_ok=True)
        for relative, payload in documents.items():
            (root / relative).write_bytes(
                json.dumps(payload, sort_keys=True).encode() + b"\n"
            )
        write_run_captures(root, self._paginate())
        checkout = root / EXPORT.AUTHORITY_CHECKOUT
        if not checkout.exists():
            self.candidate.materialise(checkout)
        return root

    def _ready_contract(self, **binding_overrides):
        contract = deepcopy(self.sealed_source_contract)
        contract["repository_created"] = True
        contract["workflow_dispatched"] = True
        contract["authority_binding"].update({
            "activation_state": "ready",
            "authority_head_commit": self.AUTHORITY_HEAD,
            "authority_head_tree": self.AUTHORITY_TREE,
            "independent_bootstrap_commit": self.BOOTSTRAP_COMMIT,
            "independent_bootstrap_tree": self.BOOTSTRAP_TREE,
            "independent_validator_sha256": hashlib.sha256(
                self.independent_validator
            ).hexdigest(),
            "independent_workflow_sha256": hashlib.sha256(
                self.independent_workflow
            ).hexdigest(),
            "source_bootstrap_commit": self.RUN_HEAD,
            "source_bootstrap_tree": self.SOURCE_TREE,
        })
        contract["authority_binding"].update(binding_overrides)
        contract["protected_review_result"].update({
            "activation_authorized": True,
            "activation_findings": [],
            "activation_state": "ready",
            "approved": False,
            "classifications": {"privacy": "public-safe"},
            "closure_matrix": {
                f"F{number}": number != 12 for number in range(1, 13)
            },
            "findings": [{
                "closure": "F12",
                "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE",
            }],
            "findings_count": 1,
            "protected_identity_asset": {"raw_value_present": False},
            "release_authorized": False,
            "review_outcome": "ACTIVATION_ONLY",
        })
        return contract

    def _environment(self, **overrides):
        contract = self.sealed_source_contract
        environment = {
            "GITHUB_RUN_ID": str(self.RUN_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": self.RUN_HEAD,
            "GITHUB_REPOSITORY": contract["repository"],
            "GITHUB_EVENT_NAME": contract["workflow"]["trigger"],
            "GITHUB_REF": contract["workflow"]["ref"],
            "GITHUB_WORKFLOW_REF": (
                f'{contract["repository"]}/{contract["workflow"]["path"]}'
                f'@{contract["workflow"]["ref"]}'
            ),
        }
        environment.update(overrides)
        return environment

    def _export(self, base, *, contract=None, environment=None):
        root = self._checkout(base, contract=contract or self._ready_contract())
        result = EXPORT.export(environment or self._environment(), root=root)
        directory = root / EXPORT.OUTPUT_DIRECTORY
        return result, {
            EXPORT.ENVELOPE_NAME: (directory / EXPORT.ENVELOPE_NAME).read_bytes(),
            EXPORT.RECEIPT_NAME: (directory / EXPORT.RECEIPT_NAME).read_bytes(),
        }

    def test_ready_activation_state_emits_the_exact_chain_deterministically(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            result_a, members_a = self._export(Path(first))
            result_b, members_b = self._export(Path(second))
        self.assertEqual(members_a, members_b)
        self.assertEqual(result_a, result_b)
        self.assertIs(result_a["exported"], True)
        receipt = json.loads(members_a[EXPORT.RECEIPT_NAME])
        self.assertEqual(
            hashlib.sha256(members_a[EXPORT.RECEIPT_NAME]).hexdigest(),
            result_a["review_receipt_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(members_a[EXPORT.ENVELOPE_NAME]).hexdigest(),
            result_a["envelope_sha256"],
        )
        self.assertEqual(
            EXPORT.artifact_content_sha256(members_a),
            result_a["artifact_content_sha256"],
        )
        chain = receipt["source_execution_chain"]
        self.assertEqual(chain["run_id"], self.RUN_ID)
        self.assertEqual(chain["run_attempt"], 1)
        self.assertEqual(chain["run_head_sha"], self.RUN_HEAD)
        self.assertEqual(chain["source_bootstrap_commit"], self.RUN_HEAD)
        self.assertEqual(
            chain["source_workflow_sha256"],
            hashlib.sha256(self.source_workflow).hexdigest(),
        )
        self.assertEqual(
            chain["source_helper_sha256"],
            hashlib.sha256(self.source_helper).hexdigest(),
        )
        # The emitted candidate is the complete contract the production
        # Authority verifier requires, not merely a head and a tree.
        candidate = receipt["candidate"]
        self.assertEqual(candidate, self.candidate.bindings())
        self.assertEqual(candidate["head_commit"], self.AUTHORITY_HEAD)
        self.assertEqual(candidate["head_tree"], self.AUTHORITY_TREE)
        self.assertEqual(candidate["base_commit"], self.candidate.base)
        self.assertEqual(candidate["sole_parent"], self.candidate.base)
        self.assertEqual(candidate["repository"], VERIFIER.EXPECTED_REPOSITORY)
        VERIFIER._validate_manifest_shape(candidate["changed_path_manifest"])
        self.assertEqual(
            candidate["artifact_sha256"]["authority-v2-policy.json"],
            VERIFIER.EXPECTED_POLICY_SHA256,
        )
        self.assertTrue(candidate["internal_manifest"].endswith("\n"))

    def test_exporter_takes_only_a_phase_and_no_caller_selectable_path(self):
        """Only the execution phase is selectable, and nothing else at all.

        The one-attempt gate has to be decidable before any protected action,
        which needs a phase the workflow can name. It selects which constant
        sequence runs; it never selects a path, a byte, a run or a review.
        """
        source = (
            self.source_root / EXPORT.HELPER_PATH
        ).read_text(encoding="utf-8")
        for forbidden in (
            "--contract", "--workflow", "--helper", "--out", "--run",
            "--receipt", "--envelope", "--root",
        ):
            self.assertNotIn(forbidden, source, forbidden)
        self.assertEqual(source.count("add_argument"), 1)
        self.assertIn('parser.add_argument("--phase", choices=PHASES', source)
        self.assertEqual(EXPORT.PHASES, ("export", "gate"))
        self.assertEqual(
            self.sealed_source_contract["caller_selectable_inputs"], []
        )
        self.assertEqual(self.sealed_source_contract["phases"], ["export", "gate"])
        self.assertIs(
            self.sealed_source_contract["caller_selectable_paths_forbidden"], True
        )
        workflow = (self.source_root / EXPORT.WORKFLOW_PATH).read_text(encoding="utf-8")
        self.assertIn(
            "python3 scripts/export_kanban_review_v2.py --phase gate\n", workflow,
        )
        self.assertIn(
            "python3 scripts/export_kanban_review_v2.py --phase export\n", workflow,
        )

    def test_exporter_never_exits_unconditionally(self):
        with tempfile.TemporaryDirectory() as td:
            _, members = self._export(Path(td))
        self.assertTrue(members[EXPORT.RECEIPT_NAME])
        self.assertTrue(members[EXPORT.ENVELOPE_NAME])

    # --- exporter attacks ---

    def test_null_versus_ready_contradictions_fail_closed(self):
        contradictions = {
            "ready-with-null-authority-head": lambda c: c["authority_binding"].update(
                authority_head_commit=None,
            ),
            "ready-with-null-source-commit": lambda c: c["authority_binding"].update(
                source_bootstrap_commit=None,
            ),
            "ready-with-null-review": lambda c: c["protected_review_result"].update(
                review_outcome=None,
            ),
            "ready-with-null-activation-decision": lambda c: c[
                "protected_review_result"
            ].update(activation_authorized=None),
            "ready-with-null-activation-findings": lambda c: c[
                "protected_review_result"
            ].update(activation_findings=None),
            "ready-binding-unavailable-review": lambda c: c[
                "protected_review_result"
            ].update(activation_state="unavailable"),
            "ready-without-repository-created": lambda c: c.update(
                repository_created=False,
            ),
            "ready-without-dispatch": lambda c: c.update(workflow_dispatched=False),
            "unavailable-with-pinned-head": lambda c: (
                c["authority_binding"].update(
                    activation_state="unavailable",
                    authority_head_commit="7" * 40,
                ),
                c["protected_review_result"].update(activation_state="unavailable"),
                c.update(repository_created=False, workflow_dispatched=False),
            ),
            "unmodelled-state": lambda c: (
                c["authority_binding"].update(activation_state="partially-ready"),
                c["protected_review_result"].update(activation_state="partially-ready"),
            ),
            "non-activation-outcome": lambda c: c["protected_review_result"].update(
                review_outcome="REJECTED",
            ),
            "extra-open-closure": lambda c: c["protected_review_result"].update(
                closure_matrix={
                    f"F{number}": number not in (8, 12) for number in range(1, 13)
                },
            ),
            "malformed-findings": lambda c: c["protected_review_result"].update(
                findings_count=1, findings=[{"id": "X"}],
            ),
        }
        for name, mutate in contradictions.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                contract = self._ready_contract()
                mutate(contract)
                with self.assertRaises(SystemExit):
                    self._export(Path(td), contract=contract)

    def test_forged_or_substituted_run_state_fails_closed(self):
        for name, overrides in {
            "attempt-2": {"GITHUB_RUN_ATTEMPT": "2"},
            "missing-run-id": {"GITHUB_RUN_ID": ""},
            "zero-run-id": {"GITHUB_RUN_ID": "0"},
            "foreign-repository": {"GITHUB_REPOSITORY": "chrizzatsu/other"},
            "foreign-event": {"GITHUB_EVENT_NAME": "push"},
            "foreign-ref": {"GITHUB_REF": "refs/heads/attacker"},
            "foreign-workflow-ref": {"GITHUB_WORKFLOW_REF": "chrizzatsu/other/x.yml@refs/heads/main"},
            "head-not-pinned-bootstrap-commit": {"GITHUB_SHA": "b" * 40},
            "malformed-head": {"GITHUB_SHA": "not-a-sha"},
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                with self.assertRaises(SystemExit):
                    self._export(Path(td), environment=self._environment(**overrides))

    def test_altered_sealed_bytes_fail_closed(self):
        for name, mutate in {
            "altered-helper": lambda root: (root / EXPORT.HELPER_PATH).write_bytes(
                self.source_helper + b"\n# altered\n"
            ),
            "altered-workflow": lambda root: (root / EXPORT.WORKFLOW_PATH).write_bytes(
                self.source_workflow + b"\n"
            ),
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = self._checkout(Path(td), contract=self._ready_contract())
                mutate(root)
                with self.assertRaises(SystemExit):
                    EXPORT.export(self._environment(), root=root)

    def test_preplanted_artifact_member_is_never_passed_off_as_an_export(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._checkout(Path(td), contract=self._ready_contract())
            directory = root / EXPORT.OUTPUT_DIRECTORY
            directory.mkdir()
            (directory / EXPORT.RECEIPT_NAME).write_bytes(b'{"forged":true}\n')
            with self.assertRaises(SystemExit):
                EXPORT.export(self._environment(), root=root)

    # --- independent lane re-derives exactly what the exporter emitted ---

    def _live_run(self, members, **overrides):
        """Resolve the live run exactly as the independent lane does at runtime."""
        contract = deepcopy(self.sealed_independent_contract)
        run = VALIDATOR.authorized_source_run(contract)
        live = VALIDATOR.resolve_live_run(
            run,
            bootstrap_commit=self.BOOTSTRAP_COMMIT,
            bootstrap_tree=self.BOOTSTRAP_TREE,
            source_run_metadata=self._run_metadata(),
            source_run_pages=self._source_run_pages(),
            source_commit={"sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE}},
            authority_commit={
                "sha": self.AUTHORITY_HEAD, "tree": {"sha": self.AUTHORITY_TREE},
            },
            envelope_data=members[EXPORT.ENVELOPE_NAME],
            receipt_data=members[EXPORT.RECEIPT_NAME],
        )
        live.update(overrides)
        return live

    def _pinned_run(self, members, **overrides):
        contract = deepcopy(self.sealed_independent_contract)
        run = contract["authorized_source_run"]
        receipt = members[EXPORT.RECEIPT_NAME]
        envelope = members[EXPORT.ENVELOPE_NAME]
        run.update({
            "activation_state": "ready",
            "artifact_content_sha256": EXPORT.artifact_content_sha256(members),
            "authority_head_commit": self.AUTHORITY_HEAD,
            "authority_head_tree": self.AUTHORITY_TREE,
            "certificate_github_workflow_sha": self.BOOTSTRAP_COMMIT,
            "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
            "independent_bootstrap_commit": self.BOOTSTRAP_COMMIT,
            "independent_bootstrap_tree": self.BOOTSTRAP_TREE,
            "independent_validator_sha256": hashlib.sha256(
                self.independent_validator
            ).hexdigest(),
            "independent_workflow_sha256": hashlib.sha256(
                self.independent_workflow
            ).hexdigest(),
            "review_receipt_sha256": hashlib.sha256(receipt).hexdigest(),
            "run_head_sha": self.RUN_HEAD,
            "run_id": self.RUN_ID,
            "source_bootstrap_commit": self.RUN_HEAD,
            "source_bootstrap_tree": self.SOURCE_TREE,
            "source_helper_sha256": hashlib.sha256(self.source_helper).hexdigest(),
            "source_workflow_sha256": hashlib.sha256(self.source_workflow).hexdigest(),
        })
        run.update(overrides)
        return contract

    def _run_metadata(self, **overrides):
        metadata = {
            "id": self.RUN_ID,
            "run_attempt": 1,
            "head_sha": self.RUN_HEAD,
            "path": EXPORT.WORKFLOW_PATH,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "conclusion": "success",
            "head_repository": {
                "full_name": self.sealed_source_contract["repository"],
            },
        }
        metadata.update(overrides)
        return metadata

    def test_independent_lane_accepts_exactly_the_emitted_chain(self):
        with tempfile.TemporaryDirectory() as td:
            _, members = self._export(Path(td))
            source_contract = json.dumps(
                self._ready_contract(), indent=2, sort_keys=True
            ).encode() + b"\n"
        contract = self._pinned_run(members)
        contract["protected_source"]["bootstrap_contract_sha256"] = hashlib.sha256(
            source_contract
        ).hexdigest()
        run = VALIDATOR.authorized_source_run(contract)
        VALIDATOR.verify_source_contract_state(contract, run, source_contract)
        VALIDATOR.verify_bootstrap_bytes(
            run, self.independent_workflow, self.independent_validator,
            self.BOOTSTRAP_COMMIT, self.BOOTSTRAP_TREE,
        )
        VALIDATOR.verify_source_bytes(
            run, self._run_metadata(), self.source_workflow, self.source_helper,
            {"sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE}},
        )
        result = VALIDATOR.verify(
            run, members[EXPORT.ENVELOPE_NAME], members[EXPORT.RECEIPT_NAME],
            root=self.validator_root,
        )
        self.assertIs(result["source_verified"], True)
        self.assertEqual(
            result["review_receipt_sha256"],
            hashlib.sha256(members[EXPORT.RECEIPT_NAME]).hexdigest(),
        )

    def test_independent_lane_rejects_state_and_artifact_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            _, members = self._export(Path(td))
        ready_contract = self._ready_contract()
        source_bytes = json.dumps(
            ready_contract, indent=2, sort_keys=True
        ).encode() + b"\n"
        digest = hashlib.sha256(source_bytes).hexdigest()

        def bound(**overrides):
            contract = self._pinned_run(members, **overrides)
            contract["protected_source"]["bootstrap_contract_sha256"] = digest
            return contract

        # A protected lane that never left the pre-activation state.
        preactivation = deepcopy(ready_contract)
        preactivation["authority_binding"]["activation_state"] = "unavailable"
        preactivation["protected_review_result"]["activation_state"] = "unavailable"
        preactivation_bytes = json.dumps(
            preactivation, indent=2, sort_keys=True
        ).encode() + b"\n"
        contract = bound()
        contract["protected_source"]["bootstrap_contract_sha256"] = hashlib.sha256(
            preactivation_bytes
        ).hexdigest()
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_contract_state(
                contract, VALIDATOR.authorized_source_run(contract),
                preactivation_bytes,
            )

        # Substituted protected contract bytes.
        contract = bound()
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_contract_state(
                contract, VALIDATOR.authorized_source_run(contract),
                source_bytes + b" ",
            )

        # Contradicting pinned binding between the two lanes.
        contract = bound(authority_head_commit="0" * 40)
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_contract_state(
                contract, VALIDATOR.authorized_source_run(contract), source_bytes,
            )

        # Forged run metadata and forged artifact bytes.
        contract = bound()
        run = VALIDATOR.authorized_source_run(contract)
        for name, metadata in {
            "foreign-run-id": self._run_metadata(id=9999),
            "attempt-2": self._run_metadata(run_attempt=2),
            "foreign-head": self._run_metadata(head_sha="0" * 40),
            "foreign-repository": self._run_metadata(
                head_repository={"full_name": "chrizzatsu/other"},
            ),
            "wrong-event": self._run_metadata(event="push"),
            "failed-run": self._run_metadata(conclusion="failure"),
        }.items():
            with self.subTest(name=name), self.assertRaises(SystemExit):
                VALIDATOR.verify_source_bytes(
                    run, metadata, self.source_workflow, self.source_helper,
                    {"sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE}},
                )
        with self.assertRaises(SystemExit):
            VALIDATOR.verify_source_bytes(
                run, self._run_metadata(), self.source_workflow + b"\n",
                self.source_helper,
                {"sha": self.RUN_HEAD, "tree": {"sha": self.SOURCE_TREE}},
            )
        for name, (envelope, receipt) in {
            "forged-receipt": (
                members[EXPORT.ENVELOPE_NAME],
                members[EXPORT.RECEIPT_NAME] + b" ",
            ),
            "forged-envelope": (
                members[EXPORT.ENVELOPE_NAME] + b" ",
                members[EXPORT.RECEIPT_NAME],
            ),
            "swapped-members": (
                members[EXPORT.RECEIPT_NAME], members[EXPORT.ENVELOPE_NAME],
            ),
        }.items():
            with self.subTest(name=name), self.assertRaises(SystemExit):
                VALIDATOR.verify(
                    run, envelope, receipt, root=self.validator_root,
                )

    def test_independent_lane_takes_no_caller_selectable_path(self):
        source = (
            self.independent_root / VALIDATOR.INDEPENDENT_VALIDATOR_PATH
        ).read_text(encoding="utf-8")
        for forbidden in (
            "--authorization", "--independent-workflow", "--independent-validator",
            "--bootstrap-commit", "--bootstrap-tree", "--run-metadata",
            "--executed-source-workflow", "--executed-source-helper",
            "--source-commit-data", "--source-envelope", "--receipt",
        ):
            self.assertNotIn(forbidden, source, forbidden)
        self.assertIn('parser.add_argument("--phase"', source)
        self.assertEqual(source.count("add_argument"), 1)
        self.assertIs(
            self.sealed_independent_contract["caller_selectable_paths_forbidden"],
            True,
        )
        self.assertEqual(
            self.sealed_independent_contract["workflow"]["caller_inputs"], []
        )
        workflow = (
            self.independent_root / VALIDATOR.INDEPENDENT_WORKFLOW_PATH
        ).read_text(encoding="utf-8")
        self.assertIn(
            "python3 scripts/verify_kanban_review_v2.py --phase bootstrap", workflow,
        )
        self.assertIn(
            "python3 scripts/verify_kanban_review_v2.py --phase chain", workflow,
        )


class ActivationOnlyDecisionTests(ExecutableSealedBootstrapTests):
    """The sealed chain must be able to represent the mandatory decision.

    F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE forces final `approved=false`,
    `release_authorized=false` and closure `F12=false`. A protected receipt
    that still asserts `release_authorized=true` or `F12=true` is a
    contradiction and must reject. The strictly distinct activation-only
    fields `activation_authorized=true` and `activation_findings=[]` are the
    only thing the chain may authorize, and they never imply final Authority
    approval.
    """

    def _activation_only_contract(self, **review_overrides):
        contract = self._ready_contract()
        contract["protected_review_result"].update(review_overrides)
        return contract

    # --- the shipped canonical policy states the mandatory decision ---

    def test_policy_requires_the_activation_only_decision(self):
        """The policy states the decision without ever carrying it.

        The activation-only decision is the only thing the sealed chain may
        ever authorize, and it never implies final Authority approval. At
        candidate handoff the policy itself is candidate owned, so it records
        the decision contract with `activation_authorized` false, F8 and F12
        open, and the exact open activation finding. Only an authenticated
        exporter run plus an independent external activation review can move
        that to true, and never inside this candidate.
        """
        policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        receipt_contract = policy["issuance_contract"]["preissuance_receipt_contract"]
        self.assertIs(receipt_contract["approved"], False)
        self.assertIs(receipt_contract["release_authorized"], False)
        self.assertEqual(receipt_contract["review_outcome"], "ACTIVATION_ONLY")
        self.assertIs(receipt_contract["activation_authorized"], False)
        self.assertEqual(
            receipt_contract["activation_findings"],
            [{"closure": "F8",
              "finding": "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"}],
        )
        self.assertEqual(
            receipt_contract["closure_matrix_required_true"],
            [f"F{number}" for number in range(1, 8)]
            + [f"F{number}" for number in range(9, 12)],
        )
        self.assertEqual(
            receipt_contract["closure_matrix_required_false"], ["F8", "F12"],
        )
        self.assertEqual(
            receipt_contract["activation_authorizes_only"],
            "exact-acc-releaser-activation",
        )
        self.assertIs(receipt_contract["final_authority_approval"], False)
        self.assertIs(
            policy["issuance_state_at_candidate_handoff"]["activation_authorized"],
            False,
            "the policy self-authorizes the activation at candidate handoff",
        )

    # --- the sealed contract carries the distinct activation-only fields ---

    def test_sealed_review_result_declares_the_activation_only_fields(self):
        """Pre-review the sealed result records why activation is unauthorized."""
        review = self.sealed_source_contract["protected_review_result"]
        self.assertIs(review["activation_authorized"], False)
        self.assertEqual(review["activation_findings"], [EXPORT.ACTIVATION_FINDING])
        ready = self._ready_contract()["protected_review_result"]
        self.assertIs(ready["activation_authorized"], True)
        self.assertEqual(ready["activation_findings"], [])
        self.assertIn("activation_authorized", EXPORT.REVIEW_RESULT_PINNED_FIELDS)
        self.assertIn("activation_findings", EXPORT.REVIEW_RESULT_PINNED_FIELDS)
        self.assertIn("activation_authorized", EXPORT.RECEIPT_FIELDS)
        self.assertIn("activation_findings", EXPORT.RECEIPT_FIELDS)

    # --- the emitted receipt carries exactly the mandatory decision ---

    def test_emitted_receipt_is_activation_only_and_never_release_authorized(self):
        with tempfile.TemporaryDirectory() as td:
            _, members = self._export(Path(td))
        receipt = json.loads(members[EXPORT.RECEIPT_NAME])
        self.assertEqual(receipt["review_outcome"], "ACTIVATION_ONLY")
        self.assertIs(receipt["approved"], False)
        self.assertIs(receipt["release_authorized"], False)
        self.assertIs(receipt["activation_authorized"], True)
        self.assertEqual(receipt["activation_findings"], [])
        self.assertIs(receipt["closure_matrix"]["F12"], False)
        for number in range(1, 12):
            self.assertIs(receipt["closure_matrix"][f"F{number}"], True, number)
        self.assertEqual(receipt["findings_count"], len(receipt["findings"]))
        self.assertEqual(
            sorted(entry["closure"] for entry in receipt["findings"]), ["F12"],
        )

    def test_activation_only_receipt_is_accepted_by_the_independent_lane(self):
        with tempfile.TemporaryDirectory() as td:
            _, members = self._export(Path(td))
        contract = self._pinned_run(members)
        run = VALIDATOR.authorized_source_run(contract)
        result = VALIDATOR.verify(
            run, members[EXPORT.ENVELOPE_NAME], members[EXPORT.RECEIPT_NAME],
            root=self.validator_root,
        )
        self.assertIs(result["source_verified"], True)
        self.assertIs(result["activation_authorized"], True)
        self.assertIs(result["release_authorized"], False)

    # --- adversarial: the contradiction must reject on both lanes ---

    CONTRADICTIONS = {
        "release-authorized-true": {"release_authorized": True},
        "approved-true": {"approved": True},
        "approved-outcome": {"review_outcome": "APPROVED"},
        "f12-closed": {
            "closure_matrix": {f"F{number}": True for number in range(1, 13)},
        },
        "f12-closed-with-finding": {
            "closure_matrix": {f"F{number}": True for number in range(1, 13)},
            "findings": [
                {"closure": "F12", "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE"},
            ],
            "findings_count": 1,
        },
        "zero-final-findings": {"findings": [], "findings_count": 0},
        "findings-count-mismatch": {"findings_count": 4},
        "finding-without-open-closure": {
            "findings": [
                {"closure": "F12", "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE"},
                {"closure": "F3", "finding": "F3-INVENTED"},
            ],
            "findings_count": 2,
        },
        "open-closure-without-finding": {
            "closure_matrix": {
                f"F{number}": number not in (11, 12) for number in range(1, 13)
            },
        },
        "activation-not-authorized": {"activation_authorized": False},
        "activation-findings-present": {
            "activation_findings": [{"id": "A1"}],
        },
        "activation-findings-not-a-list": {"activation_findings": {}},
    }

    def test_protected_exporter_rejects_every_decision_contradiction(self):
        for name, overrides in self.CONTRADICTIONS.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                contract = self._activation_only_contract(**overrides)
                with self.assertRaises(SystemExit):
                    self._export(Path(td), contract=contract)

    def test_independent_verifier_rejects_every_decision_contradiction(self):
        with tempfile.TemporaryDirectory() as td:
            _, members = self._export(Path(td))
        base_receipt = json.loads(members[EXPORT.RECEIPT_NAME])
        for name, overrides in self.CONTRADICTIONS.items():
            with self.subTest(name=name):
                forged = dict(base_receipt)
                forged.update(overrides)
                forged_bytes = VALIDATOR.canonical(forged)
                envelope = json.loads(members[EXPORT.ENVELOPE_NAME])
                envelope["review_receipt_sha256"] = hashlib.sha256(
                    forged_bytes
                ).hexdigest()
                envelope_bytes = VALIDATOR.canonical(envelope)
                contract = self._pinned_run({
                    EXPORT.ENVELOPE_NAME: envelope_bytes,
                    EXPORT.RECEIPT_NAME: forged_bytes,
                })
                run = VALIDATOR.authorized_source_run(contract)
                with self.assertRaises(SystemExit):
                    VALIDATOR.verify(
                        run, envelope_bytes, forged_bytes,
                        root=self.validator_root,
                    )

    def test_authority_preissuance_receipt_rejects_release_authorization(self):
        self.assertIs(VERIFIER.EXPECTED_FINAL_APPROVED, False)
        self.assertIs(VERIFIER.EXPECTED_FINAL_RELEASE_AUTHORIZED, False)
        self.assertEqual(VERIFIER.EXPECTED_REVIEW_OUTCOME, "ACTIVATION_ONLY")
        self.assertEqual(
            VERIFIER.EXPECTED_OPEN_CLOSURES, ("F12",),
        )
        self.assertEqual(
            VERIFIER.EXPECTED_CLOSED_CLOSURES,
            tuple(f"F{number}" for number in range(1, 12)),
        )
        self.assertIn("activation_authorized", VERIFIER.EXPECTED_RECEIPT_FIELDS)
        self.assertIn("activation_findings", VERIFIER.EXPECTED_RECEIPT_FIELDS)

    # --- F8 may never be closed before live evidence is pinned ---

    def test_sealed_pre_activation_contract_records_f8_open_beside_f12(self):
        """`authorized_pending_evidence` pins no live evidence at all.

        F8 asserts the authenticated source chain exists; before one exact
        authorized attempt-1 run head, tree, artifact, envelope and receipt
        digest are pinned, that is unknowable, so the sealed contract must
        carry F8 open and record it as an exact finding beside F12.
        """
        review = self.sealed_source_contract["protected_review_result"]
        binding = self.sealed_source_contract["authority_binding"]
        self.assertEqual(
            binding["activation_state"], EXPORT.AUTHORIZED_PENDING_EVIDENCE,
        )
        for field in EXPORT.LIVE_DERIVED_FIELDS:
            self.assertIsNone(binding[field], field)
        self.assertIs(review["closure_matrix"]["F8"], False)
        self.assertIs(review["closure_matrix"]["F12"], False)
        for number in (1, 2, 3, 4, 5, 6, 7, 9, 10, 11):
            self.assertIs(review["closure_matrix"][f"F{number}"], True, number)
        self.assertEqual(
            sorted(entry["closure"] for entry in review["findings"]),
            ["F12", "F8"],
        )
        self.assertEqual(review["findings_count"], 2)
        by_closure = {entry["closure"]: entry["finding"] for entry in review["findings"]}
        self.assertEqual(
            by_closure["F8"], "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE",
        )
        self.assertEqual(
            by_closure["F12"], "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE",
        )
        declaration = self.sealed_source_contract["activation_only_decision"]
        self.assertEqual(declaration["live_evidence_closure"], "F8")
        self.assertEqual(
            declaration["pre_activation_closure_matrix_required_false"],
            ["F12", "F8"],
        )
        activation = json.loads((ROOT / "source-chain-activation-v2.json").read_bytes())
        self.assertIs(activation["f8_closed"], review["closure_matrix"]["F8"])
        self.assertIs(
            activation["post_activation_proof"]["live_evidence_pinned"], False,
        )

    def test_documents_state_the_pre_activation_f8_rule(self):
        for document in ("README.md", "VERIFY-AUTHORITY-V2.md"):
            text = (ROOT / document).read_text(encoding="utf-8")
            with self.subTest(document=document):
                self.assertIn("F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE", text)
                self.assertIn("`ready`", text)
                self.assertIn("F8", text)

    def _pre_activation_contract(self, **review_overrides):
        contract = deepcopy(self.sealed_source_contract)
        contract["protected_review_result"].update(review_overrides)
        return contract

    def test_exporter_rejects_f8_closed_while_evidence_is_unpinned(self):
        forged = self._pre_activation_contract(
            closure_matrix={f"F{number}": number != 12 for number in range(1, 13)},
            findings=[{
                "closure": "F12",
                "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE",
            }],
            findings_count=1,
        )
        with tempfile.TemporaryDirectory() as td:
            root = self._checkout(Path(td), contract=forged)
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._environment(), root=root)
            self.assertIn("F8", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())

    def test_exporter_rejects_a_ready_contract_that_leaves_f8_open(self):
        """`ready` means every live binding is pinned, so F8 must be closed."""
        contract = self._ready_contract()
        contract["protected_review_result"].update(
            closure_matrix={
                f"F{number}": number not in (8, 12) for number in range(1, 13)
            },
            findings=[
                {"closure": "F8", "finding": "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"},
                {"closure": "F12", "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE"},
            ],
            findings_count=2,
        )
        with tempfile.TemporaryDirectory() as td:
            root = self._checkout(Path(td), contract=contract)
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._environment(), root=root)
            self.assertIn("F8", str(raised.exception))

    def test_authority_verifier_rejects_a_pre_activation_contract_closing_f8(self):
        forged = self._pre_activation_contract(
            closure_matrix={f"F{number}": number != 12 for number in range(1, 13)},
            findings=[{
                "closure": "F12",
                "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE",
            }],
            findings_count=1,
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "protected-source-bootstrap-v2"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / "scripts").mkdir(parents=True)
            (root / EXPORT.WORKFLOW_PATH).write_bytes(self.source_workflow)
            (root / EXPORT.HELPER_PATH).write_bytes(self.source_helper)
            (root / EXPORT.CONTRACT_PATH).write_bytes(
                json.dumps(self.sealed_source_contract, indent=2, sort_keys=True)
                .encode() + b"\n"
            )
            VERIFIER.verify_protected_source_bootstrap(root=root)
            (root / EXPORT.CONTRACT_PATH).write_bytes(
                json.dumps(forged, indent=2, sort_keys=True).encode() + b"\n"
            )
            with self.assertRaises(SystemExit) as raised:
                VERIFIER.verify_protected_source_bootstrap(root=root)
            self.assertIn("F8", str(raised.exception))

    def test_activation_authorization_never_implies_final_approval(self):
        with tempfile.TemporaryDirectory() as td:
            _, members = self._export(Path(td))
        receipt = json.loads(members[EXPORT.RECEIPT_NAME])
        self.assertIs(receipt["activation_authorized"], True)
        self.assertEqual(receipt["activation_findings"], [])
        self.assertIs(receipt["approved"], False)
        self.assertIs(receipt["release_authorized"], False)
        writer = json.loads(
            (ROOT / "publication-writer-exclusion-v2.json").read_bytes()
        )
        self.assertIs(writer["f12_closed"], False)
        self.assertIs(writer["release_authorized"], False)
        self.assertIs(receipt["closure_matrix"]["F12"], writer["f12_closed"])
        self.assertIs(receipt["release_authorized"], writer["release_authorized"])
        activation = json.loads((ROOT / "source-chain-activation-v2.json").read_bytes())
        self.assertIs(activation["authorizes"]["release"], False)
        self.assertIs(activation["authorizes"]["publication"], False)
        self.assertIs(activation["authorizes"]["acc_releaser_activation"], True)


class ActualSealedBootstrapEndToEndTests(unittest.TestCase):
    """F8-SEALED-BOOTSTRAP-NONEXECUTABLE, end to end on the real bytes.

    This drives the ACTUAL six sealed contract/workflow/helper files
    unchanged. It supplies only authenticated, non-caller-selectable GitHub
    attempt-1 server context, and requires the protected lane to emit and the
    independent lane to verify the exact artifact/envelope/receipt chain
    without any of the six files being mutated.
    """

    RUN_ID = 918273645
    SOURCE_HEAD = "1" * 40
    SOURCE_TREE = "2" * 40
    INDEPENDENT_HEAD = "3" * 40
    INDEPENDENT_TREE = "4" * 40

    SEALED_FILES = (
        ("protected-source-bootstrap-v2", "bootstrap-contract.json"),
        ("protected-source-bootstrap-v2", ".github/workflows/export-kanban-review-v2.yml"),
        ("protected-source-bootstrap-v2", "scripts/export_kanban_review_v2.py"),
        ("independent-review-bootstrap-v2", "bootstrap-contract.json"),
        ("independent-review-bootstrap-v2", ".github/workflows/review-authority-v2.yml"),
        ("independent-review-bootstrap-v2", "scripts/verify_kanban_review_v2.py"),
    )

    @classmethod
    def setUpClass(cls):
        cls.candidate = authority_candidate()
        cls.AUTHORITY_HEAD = cls.candidate.head
        cls.AUTHORITY_TREE = cls.candidate.tree

    def setUp(self):
        self.validator_root = validator_checkout(self)
        self.sealed_digests = {
            f"{directory}/{relative}": hashlib.sha256(
                (ROOT / directory / relative).read_bytes()
            ).hexdigest()
            for directory, relative in self.SEALED_FILES
        }
        self.source_contract_bytes = (
            ROOT / "protected-source-bootstrap-v2" / "bootstrap-contract.json"
        ).read_bytes()
        self.independent_contract = json.loads(
            (ROOT / "independent-review-bootstrap-v2" / "bootstrap-contract.json")
            .read_bytes()
        )

    def _assert_sealed_bytes_unchanged(self):
        for directory, relative in self.SEALED_FILES:
            key = f"{directory}/{relative}"
            self.assertEqual(
                hashlib.sha256((ROOT / directory / relative).read_bytes()).hexdigest(),
                self.sealed_digests[key],
                key,
            )

    def _materialise(self, base, directory):
        """Copy the ACTUAL sealed bytes verbatim; never edit them."""
        root = base / directory
        for source_directory, relative in self.SEALED_FILES:
            if source_directory != directory:
                continue
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / source_directory / relative).read_bytes())
        return root

    def _commit_metadata(self, sha, tree):
        """The documented authenticated Git commit object projection."""
        return {"sha": sha, "tree": {"sha": tree}}

    def _run_entry(self, **overrides):
        """One authenticated Actions workflow-run list entry."""
        entry = {
            "id": self.RUN_ID,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": self.SOURCE_HEAD,
            "path": EXPORT.WORKFLOW_PATH,
            "status": "completed",
            "conclusion": "success",
            "head_repository": {
                "full_name": json.loads(self.source_contract_bytes)["repository"],
            },
        }
        entry.update(overrides)
        return entry

    def _paginate(self, entries=None):
        """The exact page set a terminated server traversal returns.

        The page count is the server's own: the traversal ends where the
        server stops advertising `rel="next"`, never at a fixed count.
        """
        entries = [self._run_entry()] if entries is None else list(entries)
        per_page = EXPORT.RUNS_PER_PAGE
        return [
            {
                "total_count": len(entries),
                "workflow_runs": entries[index * per_page:(index + 1) * per_page],
            }
            for index in range(max(1, -(-len(entries) // per_page)))
        ]

    def _capture(self, payload, **kwargs):
        return http_capture(payload, **kwargs)

    def _write_run_captures(self, root, pages, **kwargs):
        write_run_captures(root, pages, **kwargs)

    def _source_run_pages(self, entries=None):
        return self._paginate(entries)

    def _write_authenticated(self, root, **documents):
        directory = root / EXPORT.AUTHENTICATED_DIRECTORY
        directory.mkdir(parents=True, exist_ok=True)
        for name, payload in documents.items():
            (directory / name).write_bytes(
                json.dumps(payload, sort_keys=True).encode() + b"\n"
            )
        if not (root / EXPORT.RAW_DIRECTORY / "runs-page-1.http").exists():
            write_run_captures(root, self._paginate())
        checkout = root / EXPORT.AUTHORITY_CHECKOUT
        if not checkout.exists():
            self.candidate.materialise(checkout)

    def _server_context(self, contract, **overrides):
        environment = {
            "GITHUB_RUN_ID": str(self.RUN_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": self.SOURCE_HEAD,
            "GITHUB_REPOSITORY": contract["repository"],
            "GITHUB_EVENT_NAME": contract["workflow"]["trigger"],
            "GITHUB_REF": contract["workflow"]["ref"],
            "GITHUB_WORKFLOW_REF": (
                f'{contract["repository"]}/{contract["workflow"]["path"]}'
                f'@{contract["workflow"]["ref"]}'
            ),
        }
        environment.update(overrides)
        return environment

    def _export_from_actual_bytes(self, base, **overrides):
        root = self._materialise(base, "protected-source-bootstrap-v2")
        contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
        # the authenticated run set always describes the run actually executing
        entry = {}
        if overrides.get("GITHUB_RUN_ID", "").isdigit():
            entry["id"] = int(overrides["GITHUB_RUN_ID"])
        if "GITHUB_SHA" in overrides:
            entry["head_sha"] = overrides["GITHUB_SHA"]
        write_run_captures(
            root, self._paginate([self._run_entry(**entry)]), contract=contract,
        )
        self._write_authenticated(
            root,
            **{
                Path(EXPORT.SOURCE_COMMIT_FILE).name: self._commit_metadata(
                    self.SOURCE_HEAD, self.SOURCE_TREE,
                ),
                Path(EXPORT.INDEPENDENT_COMMIT_FILE).name: self._commit_metadata(
                    self.INDEPENDENT_HEAD, self.INDEPENDENT_TREE,
                ),
                Path(EXPORT.AUTHORITY_COMMIT_FILE).name: self._commit_metadata(
                    self.AUTHORITY_HEAD, self.AUTHORITY_TREE,
                ),
            },
        )
        result = EXPORT.export(
            self._server_context(contract, **overrides), root=root,
        )
        directory = root / EXPORT.OUTPUT_DIRECTORY
        members = {
            EXPORT.ENVELOPE_NAME: (directory / EXPORT.ENVELOPE_NAME).read_bytes(),
            EXPORT.RECEIPT_NAME: (directory / EXPORT.RECEIPT_NAME).read_bytes(),
        }
        return root, result, members

    def _source_run_metadata(self, contract, **overrides):
        metadata = {
            "id": self.RUN_ID,
            "run_attempt": 1,
            "head_sha": self.SOURCE_HEAD,
            "path": contract["workflow"]["path"],
            "event": "workflow_dispatch",
            "head_branch": "main",
            "conclusion": "success",
            "head_repository": {"full_name": contract["repository"]},
        }
        metadata.update(overrides)
        return metadata

    # --- the sealed reviewed posture is authorized, not circular ---

    def test_sealed_contracts_ship_authorized_pending_evidence(self):
        source = json.loads(self.source_contract_bytes)
        binding = source["authority_binding"]
        self.assertEqual(
            binding["activation_state"], EXPORT.AUTHORIZED_PENDING_EVIDENCE,
        )
        self.assertEqual(binding["authorized_run_attempt"], 1)
        # reviewed repo/workflow/blob bindings are pinned before any run
        self.assertEqual(
            source["workflow"]["sha256"],
            self.sealed_digests[
                "protected-source-bootstrap-v2/"
                ".github/workflows/export-kanban-review-v2.yml"
            ],
        )
        self.assertEqual(
            source["helper"]["sha256"],
            self.sealed_digests[
                "protected-source-bootstrap-v2/scripts/export_kanban_review_v2.py"
            ],
        )
        self.assertEqual(
            binding["independent_workflow_sha256"],
            self.sealed_digests[
                "independent-review-bootstrap-v2/"
                ".github/workflows/review-authority-v2.yml"
            ],
        )
        self.assertEqual(
            binding["independent_validator_sha256"],
            self.sealed_digests[
                "independent-review-bootstrap-v2/scripts/verify_kanban_review_v2.py"
            ],
        )
        # live evidence stays unpinned; it can only exist after the run
        for field in EXPORT.LIVE_DERIVED_FIELDS:
            self.assertIsNone(binding[field], field)
        run = self.independent_contract["authorized_source_run"]
        self.assertEqual(
            run["activation_state"], EXPORT.AUTHORIZED_PENDING_EVIDENCE,
        )
        self.assertEqual(run["run_attempt"], 1)

    def test_f8_and_post_activation_proof_remain_false(self):
        activation = json.loads((ROOT / "source-chain-activation-v2.json").read_bytes())
        self.assertIs(activation["f8_closed"], False)
        self.assertEqual(activation["activation_state"], "unavailable")
        self.assertIs(
            activation["post_activation_proof"]["live_evidence_pinned"], False,
        )
        self.assertIs(activation["repositories_created"], False)
        self.assertIs(activation["runs_observed"], False)

    # --- the end-to-end regression on the real bytes ---

    def test_actual_sealed_bytes_emit_and_independently_verify(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, result, members = self._export_from_actual_bytes(base)
            independent_root = self._materialise(
                base, "independent-review-bootstrap-v2",
            )
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            contract = json.loads(
                (independent_root / VALIDATOR.CONTRACT_PATH).read_bytes()
            )
            run = VALIDATOR.authorized_source_run(contract)
            live = VALIDATOR.resolve_live_run(
                run,
                bootstrap_commit=self.INDEPENDENT_HEAD,
                bootstrap_tree=self.INDEPENDENT_TREE,
                source_run_metadata=self._source_run_metadata(source_contract),
                source_run_pages=self._source_run_pages(),
                source_commit=self._commit_metadata(
                    self.SOURCE_HEAD, self.SOURCE_TREE,
                ),
                authority_commit=self._commit_metadata(
                    self.AUTHORITY_HEAD, self.AUTHORITY_TREE,
                ),
                envelope_data=members[EXPORT.ENVELOPE_NAME],
                receipt_data=members[EXPORT.RECEIPT_NAME],
            )
            VALIDATOR.verify_source_contract_state(
                contract, live,
                (source_root / EXPORT.CONTRACT_PATH).read_bytes(),
            )
            VALIDATOR.verify_bootstrap_bytes(
                live,
                (independent_root / VALIDATOR.INDEPENDENT_WORKFLOW_PATH).read_bytes(),
                (independent_root / VALIDATOR.INDEPENDENT_VALIDATOR_PATH).read_bytes(),
                self.INDEPENDENT_HEAD,
                self.INDEPENDENT_TREE,
            )
            VALIDATOR.verify_source_bytes(
                live,
                self._source_run_metadata(source_contract),
                (source_root / EXPORT.WORKFLOW_PATH).read_bytes(),
                (source_root / EXPORT.HELPER_PATH).read_bytes(),
                self._commit_metadata(self.SOURCE_HEAD, self.SOURCE_TREE),
            )
            verified = VALIDATOR.verify(
                live, members[EXPORT.ENVELOPE_NAME], members[EXPORT.RECEIPT_NAME],
                root=self.validator_root,
            )

        self.assertIs(result["exported"], True)
        self.assertIs(verified["source_verified"], True)
        # Pre-activation the sealed chain authorizes nothing; the external
        # post-candidate review is the only thing that ever can.
        self.assertIs(verified["activation_authorized"], False)
        self.assertIs(verified["release_authorized"], False)
        self.assertEqual(
            verified["review_receipt_sha256"], result["review_receipt_sha256"],
        )
        chain = json.loads(members[EXPORT.RECEIPT_NAME])["source_execution_chain"]
        self.assertEqual(chain["run_id"], self.RUN_ID)
        self.assertEqual(chain["run_attempt"], 1)
        self.assertEqual(chain["run_head_sha"], self.SOURCE_HEAD)
        self.assertEqual(chain["source_bootstrap_commit"], self.SOURCE_HEAD)
        self.assertEqual(chain["source_bootstrap_tree"], self.SOURCE_TREE)
        self.assertEqual(chain["independent_bootstrap_commit"], self.INDEPENDENT_HEAD)
        self.assertEqual(chain["independent_bootstrap_tree"], self.INDEPENDENT_TREE)
        self.assertEqual(chain["authority_head_commit"], self.AUTHORITY_HEAD)
        self.assertEqual(chain["authority_head_tree"], self.AUTHORITY_TREE)
        self._assert_sealed_bytes_unchanged()

    def test_live_ids_come_only_from_authenticated_server_context(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            _, first_result, _ = self._export_from_actual_bytes(Path(first))
            _, second_result, _ = self._export_from_actual_bytes(
                Path(second), GITHUB_RUN_ID="777000777",
            )
        self.assertNotEqual(
            first_result["review_receipt_sha256"],
            second_result["review_receipt_sha256"],
        )
        self._assert_sealed_bytes_unchanged()

    # --- fail closed before authorization, and under every substitution ---

    def test_unavailable_state_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            contract["authority_binding"]["activation_state"] = "unavailable"
            contract["protected_review_result"]["activation_state"] = "unavailable"
            for field in (*EXPORT.LIVE_DERIVED_FIELDS, *EXPORT.BINDING_HEX64_FIELDS):
                contract["authority_binding"][field] = None
            for field in EXPORT.REVIEW_RESULT_PINNED_FIELDS:
                contract["protected_review_result"][field] = None
            (root / EXPORT.CONTRACT_PATH).write_bytes(
                json.dumps(contract, indent=2, sort_keys=True).encode() + b"\n"
            )
            self._write_authenticated(
                root,
                **{
                    Path(EXPORT.SOURCE_COMMIT_FILE).name: self._commit_metadata(
                        self.SOURCE_HEAD, self.SOURCE_TREE),
                    Path(EXPORT.INDEPENDENT_COMMIT_FILE).name: self._commit_metadata(
                        self.INDEPENDENT_HEAD, self.INDEPENDENT_TREE),
                    Path(EXPORT.AUTHORITY_COMMIT_FILE).name: self._commit_metadata(
                        self.AUTHORITY_HEAD, self.AUTHORITY_TREE),
                },
            )
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._server_context(contract), root=root)
            self.assertIn("F8 remains open", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    def test_forged_server_context_and_metadata_fail_closed(self):
        substitutions = {
            "attempt-2": {"GITHUB_RUN_ATTEMPT": "2"},
            "missing-run-id": {"GITHUB_RUN_ID": ""},
            "foreign-repository": {"GITHUB_REPOSITORY": "chrizzatsu/attacker"},
            "foreign-event": {"GITHUB_EVENT_NAME": "push"},
            "foreign-ref": {"GITHUB_REF": "refs/heads/attacker"},
            "foreign-workflow-ref": {
                "GITHUB_WORKFLOW_REF": "chrizzatsu/attacker/x.yml@refs/heads/main",
            },
            "malformed-head": {"GITHUB_SHA": "nope"},
        }
        for name, overrides in substitutions.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                with self.assertRaises(SystemExit):
                    self._export_from_actual_bytes(Path(td), **overrides)
        self._assert_sealed_bytes_unchanged()

    def test_forged_authenticated_metadata_fails_closed(self):
        cases = {
            "source-commit-mismatch": (
                Path(EXPORT.SOURCE_COMMIT_FILE).name,
                {"sha": "9" * 40, "tree": {"sha": "2" * 40}},
            ),
            "source-tree-malformed": (
                Path(EXPORT.SOURCE_COMMIT_FILE).name,
                {"sha": "1" * 40, "tree": {"sha": "not-a-tree"}},
            ),
            "source-tree-absent": (
                Path(EXPORT.SOURCE_COMMIT_FILE).name, {"sha": "1" * 40},
            ),
            "independent-commit-malformed": (
                Path(EXPORT.INDEPENDENT_COMMIT_FILE).name,
                {"sha": "zz", "tree": {"sha": "4" * 40}},
            ),
            "authority-commit-malformed": (
                Path(EXPORT.AUTHORITY_COMMIT_FILE).name, {"tree": {"sha": "6" * 40}},
            ),
        }
        for name, (document, payload) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                root = self._materialise(base, "protected-source-bootstrap-v2")
                contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
                documents = {
                    Path(EXPORT.SOURCE_COMMIT_FILE).name: self._commit_metadata(
                        self.SOURCE_HEAD, self.SOURCE_TREE),
                    Path(EXPORT.INDEPENDENT_COMMIT_FILE).name: self._commit_metadata(
                        self.INDEPENDENT_HEAD, self.INDEPENDENT_TREE),
                    Path(EXPORT.AUTHORITY_COMMIT_FILE).name: self._commit_metadata(
                        self.AUTHORITY_HEAD, self.AUTHORITY_TREE),
                }
                documents[document] = payload
                self._write_authenticated(root, **documents)
                with self.assertRaises(SystemExit):
                    EXPORT.export(self._server_context(contract), root=root)
        self._assert_sealed_bytes_unchanged()

    def test_altered_sealed_bytes_fail_closed(self):
        for relative in (EXPORT.WORKFLOW_PATH, EXPORT.HELPER_PATH):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                root = self._materialise(base, "protected-source-bootstrap-v2")
                (root / relative).write_bytes(
                    (root / relative).read_bytes() + b"\n# altered\n"
                )
                contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
                self._write_authenticated(
                    root,
                    **{
                        Path(EXPORT.SOURCE_COMMIT_FILE).name: self._commit_metadata(
                            self.SOURCE_HEAD, self.SOURCE_TREE),
                        Path(EXPORT.INDEPENDENT_COMMIT_FILE).name: self._commit_metadata(
                            self.INDEPENDENT_HEAD, self.INDEPENDENT_TREE),
                        Path(EXPORT.AUTHORITY_COMMIT_FILE).name: self._commit_metadata(
                            self.AUTHORITY_HEAD, self.AUTHORITY_TREE),
                    },
                )
                with self.assertRaises(SystemExit):
                    EXPORT.export(self._server_context(contract), root=root)
        self._assert_sealed_bytes_unchanged()

    def test_independent_lane_rejects_a_forged_live_run(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, _, members = self._export_from_actual_bytes(base)
            independent_root = self._materialise(
                base, "independent-review-bootstrap-v2",
            )
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            contract = json.loads(
                (independent_root / VALIDATOR.CONTRACT_PATH).read_bytes()
            )
            run = VALIDATOR.authorized_source_run(contract)
            for name, overrides in {
                "foreign-run-id": {"id": 424242},
                "attempt-2": {"run_attempt": 2},
                "foreign-head": {"head_sha": "0" * 40},
                "failed-run": {"conclusion": "failure"},
            }.items():
                with self.subTest(name=name), self.assertRaises(SystemExit):
                    live = VALIDATOR.resolve_live_run(
                        run,
                        bootstrap_commit=self.INDEPENDENT_HEAD,
                        bootstrap_tree=self.INDEPENDENT_TREE,
                        source_run_metadata=self._source_run_metadata(
                            source_contract, **overrides,
                        ),
                        source_run_pages=self._source_run_pages(
                            [self._run_entry(**overrides)],
                        ),
                        source_commit=self._commit_metadata(
                            self.SOURCE_HEAD, self.SOURCE_TREE),
                        authority_commit=self._commit_metadata(
                            self.AUTHORITY_HEAD, self.AUTHORITY_TREE),
                        envelope_data=members[EXPORT.ENVELOPE_NAME],
                        receipt_data=members[EXPORT.RECEIPT_NAME],
                    )
                    VALIDATOR.verify_source_bytes(
                        live,
                        self._source_run_metadata(source_contract, **overrides),
                        (source_root / EXPORT.WORKFLOW_PATH).read_bytes(),
                        (source_root / EXPORT.HELPER_PATH).read_bytes(),
                        self._commit_metadata(self.SOURCE_HEAD, self.SOURCE_TREE),
                    )
        self._assert_sealed_bytes_unchanged()

    def test_independent_lane_rejects_substituted_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, _, members = self._export_from_actual_bytes(base)
            independent_root = self._materialise(
                base, "independent-review-bootstrap-v2",
            )
            contract = json.loads(
                (independent_root / VALIDATOR.CONTRACT_PATH).read_bytes()
            )
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            run = VALIDATOR.authorized_source_run(contract)
            for name, (envelope, receipt) in {
                "receipt-appended": (
                    members[EXPORT.ENVELOPE_NAME], members[EXPORT.RECEIPT_NAME] + b" ",
                ),
                "envelope-appended": (
                    members[EXPORT.ENVELOPE_NAME] + b" ", members[EXPORT.RECEIPT_NAME],
                ),
                "swapped": (
                    members[EXPORT.RECEIPT_NAME], members[EXPORT.ENVELOPE_NAME],
                ),
            }.items():
                with self.subTest(name=name), self.assertRaises(SystemExit):
                    live = VALIDATOR.resolve_live_run(
                        run,
                        bootstrap_commit=self.INDEPENDENT_HEAD,
                        bootstrap_tree=self.INDEPENDENT_TREE,
                        source_run_metadata=self._source_run_metadata(source_contract),
                        source_run_pages=self._source_run_pages(),
                        source_commit=self._commit_metadata(
                            self.SOURCE_HEAD, self.SOURCE_TREE),
                        authority_commit=self._commit_metadata(
                            self.AUTHORITY_HEAD, self.AUTHORITY_TREE),
                        envelope_data=envelope,
                        receipt_data=receipt,
                    )
                    VALIDATOR.verify(
                        live, envelope, receipt, root=self.validator_root,
                    )
        self._assert_sealed_bytes_unchanged()

    # --- F8 stays open in the actually emitted pre-activation receipt ---

    def test_actual_emitted_pre_activation_receipt_keeps_f8_open(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, _, members = self._export_from_actual_bytes(base)
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            receipt = json.loads(members[EXPORT.RECEIPT_NAME])
            self.assertEqual(
                source_contract["authority_binding"]["activation_state"],
                EXPORT.AUTHORIZED_PENDING_EVIDENCE,
            )
            self.assertIs(receipt["closure_matrix"]["F8"], False)
            self.assertIs(receipt["closure_matrix"]["F12"], False)
            self.assertEqual(
                sorted(entry["closure"] for entry in receipt["findings"]),
                ["F12", "F8"],
            )
            self.assertEqual(receipt["findings_count"], 2)
            self.assertIs(receipt["approved"], False)
            self.assertIs(receipt["release_authorized"], False)
            # and the independent lane still accepts exactly these bytes
            live = self._independent_lane(
                base, self._source_run_pages(), members, source_contract,
            )
            verified = VALIDATOR.verify(
                live, members[EXPORT.ENVELOPE_NAME], members[EXPORT.RECEIPT_NAME],
                root=self.validator_root,
            )
            self.assertIs(verified["source_verified"], True)
            self.assertIs(verified["release_authorized"], False)
        self._assert_sealed_bytes_unchanged()

    def test_independent_lane_rejects_a_pre_activation_receipt_closing_f8(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, _, members = self._export_from_actual_bytes(base)
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            forged = json.loads(members[EXPORT.RECEIPT_NAME])
            forged["closure_matrix"] = {
                f"F{number}": number != 12 for number in range(1, 13)
            }
            forged["findings"] = [{
                "closure": "F12",
                "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE",
            }]
            forged["findings_count"] = 1
            receipt_bytes = VALIDATOR.canonical(forged)
            envelope = json.loads(members[EXPORT.ENVELOPE_NAME])
            envelope["review_receipt_sha256"] = hashlib.sha256(
                receipt_bytes
            ).hexdigest()
            envelope_bytes = VALIDATOR.canonical(envelope)
            forged_members = {
                EXPORT.ENVELOPE_NAME: envelope_bytes,
                EXPORT.RECEIPT_NAME: receipt_bytes,
            }
            live = self._independent_lane(
                base, self._source_run_pages(), forged_members, source_contract,
            )
            self.assertEqual(
                live["activation_state"], EXPORT.AUTHORIZED_PENDING_EVIDENCE,
            )
            with self.assertRaises(SystemExit) as raised:
                VALIDATOR.verify(
                    live, envelope_bytes, receipt_bytes,
                    root=self.validator_root,
                )
            self.assertIn("F8", str(raised.exception))
        self._assert_sealed_bytes_unchanged()

    # --- exactly one authorized attempt-1 activation run ---

    def _commit_documents(self):
        return {
            Path(EXPORT.SOURCE_COMMIT_FILE).name: self._commit_metadata(
                self.SOURCE_HEAD, self.SOURCE_TREE),
            Path(EXPORT.INDEPENDENT_COMMIT_FILE).name: self._commit_metadata(
                self.INDEPENDENT_HEAD, self.INDEPENDENT_TREE),
            Path(EXPORT.AUTHORITY_COMMIT_FILE).name: self._commit_metadata(
                self.AUTHORITY_HEAD, self.AUTHORITY_TREE),
        }

    def _export_with_run_pages(self, base, pages):
        root = self._materialise(base, "protected-source-bootstrap-v2")
        contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
        write_run_captures(root, pages, contract=contract)
        self._write_authenticated(root, **self._commit_documents())
        return EXPORT.export(self._server_context(contract), root=root), root

    def _independent_lane(self, base, pages, members, source_contract):
        """Re-run the independent selection and chain binding over one run set."""
        independent_root = self._materialise(
            base, "independent-review-bootstrap-v2",
        )
        contract = json.loads(
            (independent_root / VALIDATOR.CONTRACT_PATH).read_bytes()
        )
        run = VALIDATOR.authorized_source_run(contract)
        VALIDATOR.select_authorized_run(run, pages)
        return VALIDATOR.resolve_live_run(
            run,
            bootstrap_commit=self.INDEPENDENT_HEAD,
            bootstrap_tree=self.INDEPENDENT_TREE,
            source_run_metadata=self._source_run_metadata(source_contract),
            source_run_pages=pages,
            source_commit=self._commit_metadata(self.SOURCE_HEAD, self.SOURCE_TREE),
            authority_commit=self._commit_metadata(
                self.AUTHORITY_HEAD, self.AUTHORITY_TREE,
            ),
            envelope_data=members[EXPORT.ENVELOPE_NAME],
            receipt_data=members[EXPORT.RECEIPT_NAME],
        )

    def test_two_attempt_1_dispatch_runs_fail_closed_in_both_lanes(self):
        """Two sequential `workflow_dispatch` runs are each `run_attempt` 1.

        `GITHUB_RUN_ATTEMPT == 1` cannot tell them apart, so the authorized
        activation run must be selected from the authenticated server run set,
        which may hold exactly one authorized attempt-1 run for the sealed
        workflow, ref and head.
        """
        first = self._run_entry()
        second = self._run_entry(id=self.RUN_ID + 1)
        self.assertEqual(first["run_attempt"], second["run_attempt"], 1)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["head_sha"], second["head_sha"])
        self.assertEqual(first["event"], second["event"])
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            pages = self._paginate([second, first])
            with self.assertRaises(SystemExit) as raised:
                self._export_with_run_pages(base, pages)
            self.assertIn("ambiguous", str(raised.exception))
            self.assertFalse(
                (base / "protected-source-bootstrap-v2"
                 / EXPORT.OUTPUT_DIRECTORY).exists()
            )
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, _, members = self._export_from_actual_bytes(base)
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            with self.assertRaises(SystemExit) as raised:
                self._independent_lane(
                    base, self._source_run_pages([second, first]), members,
                    source_contract,
                )
            self.assertIn("ambiguous", str(raised.exception))
        self._assert_sealed_bytes_unchanged()

    def test_later_inserted_successful_run_is_rejected_by_the_independent_lane(self):
        """A newer successful run may never replace the authorized chain.

        A newest-first `per_page=1` selection would have returned the inserted
        run, so the exhaustive bounded run set must reject it, including when
        it only appears on a later page.
        """
        authorized = self._run_entry()
        inserted = self._run_entry(
            id=self.RUN_ID + 7, head_sha="a" * 40, conclusion="success",
        )
        self.assertEqual(inserted["conclusion"], "success")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, _, members = self._export_from_actual_bytes(base)
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            independent_root = self._materialise(
                base, "independent-review-bootstrap-v2",
            )
            contract = json.loads(
                (independent_root / VALIDATOR.CONTRACT_PATH).read_bytes()
            )
            run = VALIDATOR.authorized_source_run(contract)
            # newest first, exactly as the Actions list endpoint orders runs
            adjacent = self._source_run_pages([inserted, authorized])
            self.assertEqual(adjacent[0]["workflow_runs"][0]["id"], inserted["id"])
            with self.assertRaises(SystemExit) as raised:
                VALIDATOR.select_authorized_run(run, adjacent)
            self.assertIn("ambiguous", str(raised.exception))
            with self.assertRaises(SystemExit):
                self._independent_lane(base, adjacent, members, source_contract)
            # the same inserted run hidden on a later page
            filler = [
                self._run_entry(id=self.RUN_ID + 1000 + offset)
                for offset in range(EXPORT.RUNS_PER_PAGE - 1)
            ]
            later_page = self._source_run_pages([authorized, *filler, inserted])
            self.assertEqual(len(later_page[0]["workflow_runs"]), EXPORT.RUNS_PER_PAGE)
            self.assertEqual(later_page[1]["workflow_runs"][0]["id"], inserted["id"])
            with self.assertRaises(SystemExit):
                VALIDATOR.select_authorized_run(run, later_page)
            with self.assertRaises(SystemExit):
                self._independent_lane(base, later_page, members, source_contract)
        self._assert_sealed_bytes_unchanged()

    def test_malformed_or_incomplete_run_pagination_fails_closed(self):
        """A run set that is not provably complete can never select a run."""
        authorized = self._run_entry()
        duplicate_pages = self._source_run_pages([authorized, authorized])
        truncated = self._source_run_pages([authorized])
        truncated[0]["total_count"] = 2
        inconsistent = self._source_run_pages([authorized, authorized])
        inconsistent[0]["total_count"] = 5
        oversized = self._source_run_pages([authorized])
        for page in oversized:
            page["total_count"] = EXPORT.MAX_AUTHORIZED_RUN_SET + 1
        # A traversal that never reached a terminated page at all.
        short_set = []
        malformed_page = self._source_run_pages([authorized])
        malformed_page[0] = {"total_count": 1, "workflow_runs": {}}
        missing_total = self._source_run_pages([authorized])
        for page in missing_total:
            page.pop("total_count")
        malformed_id = self._source_run_pages([dict(authorized, id="4242")])
        cases = {
            "duplicate-run-across-pages": duplicate_pages,
            "truncated-first-page": truncated,
            "pages-disagree-on-total": inconsistent,
            "run-set-beyond-the-bound": oversized,
            "short-page-set": short_set,
            "malformed-page-list": malformed_page,
            "absent-total": missing_total,
            "malformed-run-id": malformed_id,
        }
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source_root, _, members = self._export_from_actual_bytes(base)
            source_contract = json.loads(
                (source_root / EXPORT.CONTRACT_PATH).read_bytes()
            )
            independent_root = self._materialise(
                base, "independent-review-bootstrap-v2",
            )
            contract = json.loads(
                (independent_root / VALIDATOR.CONTRACT_PATH).read_bytes()
            )
            run = VALIDATOR.authorized_source_run(contract)
            for name, pages in cases.items():
                with self.subTest(name=name), self.assertRaises(SystemExit):
                    VALIDATOR.select_authorized_run(run, pages)
                with self.subTest(name=name, lane="chain"), self.assertRaises(SystemExit):
                    self._independent_lane(base, pages, members, source_contract)
        for name, pages in cases.items():
            if name == "short-page-set":
                continue
            with self.subTest(name=name, lane="export"), \
                    tempfile.TemporaryDirectory() as td:
                with self.assertRaises(SystemExit):
                    self._export_with_run_pages(Path(td), pages)
        self._assert_sealed_bytes_unchanged()

    def test_absent_authenticated_run_set_fails_closed(self):
        """No authenticated run readback at all is never an authorization."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            directory = root / EXPORT.AUTHENTICATED_DIRECTORY
            directory.mkdir(parents=True, exist_ok=True)
            for name, payload in self._commit_documents().items():
                (directory / name).write_bytes(
                    json.dumps(payload, sort_keys=True).encode() + b"\n"
                )
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._server_context(contract), root=root)
            self.assertIn("absent", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()


class OneActivationRunInventoryTests(ActualSealedBootstrapEndToEndTests):
    """The two source/activation defects the immutable review found.

    1. `GITHUB_RUN_ATTEMPT == 1` blocks reruns of one run, never a second
       `workflow_dispatch` run id, and the sealed workflow stayed enabled with
       no authenticated disable, cleanup or readback on either path.
    2. The authorized run inventory was a fixed three-page capture, so a run
       set larger than 300 was silently truncated and an additional authorized
       run hidden past page three was never seen at all.
    """

    # --- exhaustive server-driven pagination ---

    def test_more_than_three_hundred_runs_are_traversed_exhaustively(self):
        """A run set past the old fixed three-page capture is still complete.

        301 runs need four pages. The traversal terminates only where the
        server stops advertising `rel="next"`, so every run is read back and
        the activation fails closed on the whole inventory -- never on a view
        truncated at the last page some fixed count happened to capture.
        """
        authorized = self._run_entry()
        filler = [
            self._run_entry(id=self.RUN_ID + 1000 + offset, event="schedule")
            for offset in range(300)
        ]
        entries = [authorized, *filler]
        self.assertEqual(len(entries), 301)
        pages = self._paginate(entries)
        self.assertEqual(len(pages), 4)
        self.assertEqual(
            [len(page["workflow_runs"]) for page in pages], [100, 100, 100, 1],
        )
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            write_run_captures(root, pages, contract=contract)
            self._write_authenticated(root, **self._commit_documents())
            # the whole inventory really is read back: no page is dropped and
            # no run past the old 300-run bound is silently invisible
            captured = EXPORT.captured_workflow_run_pages(root, contract)
            self.assertEqual(len(captured), 4)
            runs = EXPORT.complete_workflow_run_set(captured)
            self.assertEqual(len(runs), 301)
            self.assertEqual(
                [entry["id"] for entry in runs], [entry["id"] for entry in entries],
            )
            # and a 301-run reality is an ambiguous activation, not an export
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._server_context(contract), root=root)
            self.assertIn("ambiguous", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    def test_the_sole_authorized_run_still_exports_over_the_new_traversal(self):
        """The terminated single-page traversal is the ordinary success path."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            result, root = self._export_with_run_pages(
                base, self._paginate([self._run_entry()]),
            )
            self.assertTrue(result["exported"])
            self.assertTrue((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    def test_an_additional_authorized_run_hidden_past_page_three_fails_closed(self):
        """The exact truncation the fixed three-page capture allowed.

        A second attempt-1 `workflow_dispatch` run for the sealed workflow,
        ref and head, sitting on page four, must make the activation ambiguous
        rather than invisible.
        """
        authorized = self._run_entry()
        hidden = self._run_entry(id=self.RUN_ID + 1)
        filler = [
            self._run_entry(id=self.RUN_ID + 1000 + offset, event="schedule")
            for offset in range(300)
        ]
        pages = self._paginate([authorized, *filler, hidden])
        self.assertEqual(len(pages), 4)
        self.assertEqual(pages[3]["workflow_runs"][-1]["id"], hidden["id"])
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            with self.assertRaises(SystemExit) as raised:
                self._export_with_run_pages(base, pages)
            self.assertIn("ambiguous", str(raised.exception))
            self.assertFalse(
                (base / "protected-source-bootstrap-v2"
                 / EXPORT.OUTPUT_DIRECTORY).exists()
            )
        self._assert_sealed_bytes_unchanged()

    def test_unterminated_pagination_fails_closed_at_the_finite_cap(self):
        """A server that never stops advertising `rel="next"` may not run on.

        The cap is a fail-closed bound, never a termination: reaching it is an
        error, not a complete inventory.
        """
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            self._write_authenticated(root, **self._commit_documents())
            self._write_run_captures(
                root, self._paginate([self._run_entry()]),
                unterminated=EXPORT.MAXIMUM_CAPTURED_PAGES,
            )
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._server_context(contract), root=root)
            self.assertIn("bound", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    def test_a_page_the_server_never_advertised_fails_closed(self):
        """A page beyond the server-advertised termination is unadvertised."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            self._write_authenticated(root, **self._commit_documents())
            self._write_run_captures(root, self._paginate([self._run_entry()]))
            (root / EXPORT.RAW_DIRECTORY / "runs-page-2.http").write_bytes(
                self._capture({"total_count": 1, "workflow_runs": []})
            )
            with self.assertRaises(SystemExit) as raised:
                EXPORT.export(self._server_context(contract), root=root)
            self.assertIn("never advertised", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    def test_a_substituted_or_foreign_next_target_fails_closed(self):
        """Only the server's own next page of this exact endpoint is followed."""
        entries = [self._run_entry(), *(
            self._run_entry(id=self.RUN_ID + 2000 + offset, event="schedule")
            for offset in range(100)
        )]
        for name in ("foreign-next", "substituted-next", "unauthenticated-page"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                root = self._materialise(base, "protected-source-bootstrap-v2")
                contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
                self._write_authenticated(root, **self._commit_documents())
                pages = self._paginate(entries)
                self.assertEqual(len(pages), 2)
                self._write_run_captures(root, pages, contract=contract)
                endpoint = EXPORT.runs_endpoint(contract)
                forged = {
                    "foreign-next":
                        "https://example.invalid/runs?per_page=100&page=2",
                    "substituted-next": f"{endpoint}?per_page=100&page=3",
                    "unauthenticated-page": None,
                }[name]
                first = root / EXPORT.RAW_DIRECTORY / "runs-page-1.http"
                if forged is None:
                    first.write_bytes(self._capture(
                        pages[0], status=403,
                        link=f'<{endpoint}?per_page=100&page=2>; rel="next"',
                    ))
                else:
                    first.write_bytes(
                        self._capture(pages[0], link=f'<{forged}>; rel="next"')
                    )
                with self.assertRaises(SystemExit):
                    EXPORT.export(self._server_context(contract), root=root)
                self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    # --- fail-closed one-attempt disable, readback and cleanup ---

    def test_the_gate_excludes_additional_runs_before_any_protected_action(self):
        """`--phase gate` decides the one-attempt question and writes nothing."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            self._write_run_captures(root, self._paginate([self._run_entry()]),
                                     contract=contract)
            gated = EXPORT.gate(self._server_context(contract), root=root)
            self.assertEqual(gated["authorized_run_id"], self.RUN_ID)
            self.assertEqual(
                gated["workflow_state"], EXPORT.DISABLED_WORKFLOW_STATE,
            )
            self.assertIs(gated["gated"], True)
            # the gate needs no protected read at all, and writes nothing
            self.assertFalse((root / EXPORT.AUTHORITY_CHECKOUT).exists())
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
            # a second attempt-1 dispatch is refused by the gate alone,
            # before the lane clones or writes anything protected
            self._write_run_captures(
                root,
                self._paginate(
                    [self._run_entry(), self._run_entry(id=self.RUN_ID + 1)]
                ),
                contract=contract,
            )
            with self.assertRaises(SystemExit) as raised:
                EXPORT.gate(self._server_context(contract), root=root)
            self.assertIn("ambiguous", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    def test_the_gate_fails_closed_before_the_activation_is_authorized(self):
        """An unavailable contract never gates anything open."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            contract["authority_binding"]["activation_state"] = "unavailable"
            contract["protected_review_result"]["activation_state"] = "unavailable"
            for field in (*EXPORT.LIVE_DERIVED_FIELDS, *EXPORT.BINDING_HEX64_FIELDS):
                contract["authority_binding"][field] = None
            for field in EXPORT.REVIEW_RESULT_PINNED_FIELDS:
                contract["protected_review_result"][field] = None
            (root / EXPORT.CONTRACT_PATH).write_bytes(
                json.dumps(contract, indent=2, sort_keys=True).encode() + b"\n"
            )
            self._write_run_captures(root, self._paginate([self._run_entry()]),
                                     contract=contract)
            with self.assertRaises(SystemExit) as raised:
                EXPORT.gate(self._server_context(contract), root=root)
            self.assertIn("F8 remains open", str(raised.exception))
        self._assert_sealed_bytes_unchanged()

    def test_an_enabled_or_absent_workflow_state_readback_fails_closed(self):
        """No authenticated disable readback is never a one-attempt bound."""
        cases = {
            "still-active": {"state": "active"},
            "disabled-by-inactivity": {"state": "disabled_inactivity"},
            "foreign-workflow": {"path": ".github/workflows/other.yml"},
            "absent-state": {"state": None},
            "absent-id": {"id": None},
        }
        for name, override in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                root = self._materialise(base, "protected-source-bootstrap-v2")
                contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
                self._write_authenticated(root, **self._commit_documents())
                self._write_run_captures(
                    root, self._paginate([self._run_entry()]),
                    contract=contract, workflow_state=override,
                )
                with self.assertRaises(SystemExit):
                    EXPORT.gate(self._server_context(contract), root=root)
                with self.assertRaises(SystemExit):
                    EXPORT.export(self._server_context(contract), root=root)
                self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = self._materialise(base, "protected-source-bootstrap-v2")
            contract = json.loads((root / EXPORT.CONTRACT_PATH).read_bytes())
            self._write_authenticated(root, **self._commit_documents())
            self._write_run_captures(
                root, self._paginate([self._run_entry()]),
                contract=contract, workflow_state=False,
            )
            with self.assertRaises(SystemExit) as raised:
                EXPORT.gate(self._server_context(contract), root=root)
            self.assertIn("absent", str(raised.exception))
            self.assertFalse((root / EXPORT.OUTPUT_DIRECTORY).exists())
        self._assert_sealed_bytes_unchanged()

    def test_the_sealed_workflow_disables_and_reads_back_on_both_paths(self):
        """The sealed workflow itself carries the one-attempt mechanism."""
        text = (
            ROOT / "protected-source-bootstrap-v2"
            / ".github/workflows/export-kanban-review-v2.yml"
        ).read_text(encoding="utf-8")
        jobs = VERIFIER.workflow_document(text)["jobs"]
        self.assertEqual(sorted(jobs), ["cleanup", "export", "single-activation"])
        # the authenticated disable precedes every protected action
        self.assertEqual(jobs["export"]["needs"], "single-activation")
        self.assertEqual(
            jobs["single-activation"]["permissions"], {"actions": "write"},
        )
        # the export lane itself never holds a write grant
        self.assertEqual(
            jobs["export"]["permissions"], {"actions": "read", "contents": "read"},
        )
        # cleanup covers the failure path as well as the success path
        self.assertEqual(jobs["cleanup"]["if"], "always()")
        self.assertEqual(jobs["cleanup"]["needs"], ["single-activation", "export"])
        self.assertEqual(jobs["cleanup"]["permissions"], {"actions": "write"})
        for job in ("single-activation", "cleanup"):
            block = "\n".join(step.get("run", "") for step in jobs[job]["steps"])
            self.assertIn("--method PUT", block)
            self.assertIn("/disable", block)
            self.assertIn("disabled_manually", block)
        # the gate runs before the Authority checkout and before the export
        runs = [step.get("run", "") for step in jobs["export"]["steps"]]
        gate_index = next(
            index for index, run in enumerate(runs) if "--phase gate" in run
        )
        clone_index = next(
            index for index, run in enumerate(runs) if "gh repo clone" in run
        )
        export_index = next(
            index for index, run in enumerate(runs) if "--phase export" in run
        )
        self.assertLess(gate_index, clone_index)
        self.assertLess(gate_index, export_index)
        # the fixed three-page capture is gone; the traversal is server driven
        self.assertNotIn("workflow-runs-page-3.json", text)
        self.assertIn('rel="next"', text)
        self.assertIn("unterminated pagination", text)


class ExporterToAuthorityBoundaryTests(unittest.TestCase):
    """F8-BOOTSTRAP-RECEIPT-INCOMPATIBLE-WITH-AUTHORITY.

    The shipped exporter and the shipped independent validator must produce and
    authenticate exactly the contract the production Authority verifier
    requires. This drives the real helpers end to end and feeds their exact
    output bytes into ``validate_preissuance_receipt_bytes`` unmodified.
    """

    RUN_ID = 17_493_820_551
    INDEPENDENT_COMMIT = "b" * 39 + "c"

    @classmethod
    def setUpClass(cls):
        cls.candidate = authority_candidate()
        cls.policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        cls.authority = cls.candidate.root
        cls.base = cls.candidate.base
        cls.head = cls.candidate.head
        cls.expected = cls.candidate.bindings()

    # -- sealed protected-source checkout ---------------------------------
    def _sealed_source(self, directory, *, state):
        shutil.copytree(ROOT / "protected-source-bootstrap-v2", directory)
        contract = json.loads((directory / "bootstrap-contract.json").read_bytes())
        binding = contract["authority_binding"]
        binding["activation_state"] = state
        contract["protected_review_result"]["activation_state"] = state
        contract["repository_created"] = state == "ready"
        contract["workflow_dispatched"] = state == "ready"
        if state == "ready":
            review = contract["protected_review_result"]
            review["closure_matrix"]["F8"] = True
            review["findings"] = [{
                "closure": "F12",
                "finding": "F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE",
            }]
            review["findings_count"] = 1
            # The activation authorization only exists once the external
            # post-candidate review has authenticated, i.e. at `ready`.
            review["activation_authorized"] = True
            review["activation_findings"] = []
            binding.update({
                "authority_head_commit": self.head,
                "authority_head_tree": self.expected["head_tree"],
                "independent_bootstrap_commit": self.INDEPENDENT_COMMIT,
                "independent_bootstrap_tree": "d" * 39 + "e",
                "source_bootstrap_commit": self.source_head,
                "source_bootstrap_tree": self.source_tree,
            })
        (directory / "bootstrap-contract.json").write_bytes(
            json.dumps(contract, indent=2, sort_keys=True).encode() + b"\n"
        )
        authenticated = directory / "authenticated"
        authenticated.mkdir()
        (authenticated / "source-commit.json").write_bytes(json.dumps({
            "sha": self.source_head, "tree": {"sha": self.source_tree},
        }).encode())
        (authenticated / "independent-commit.json").write_bytes(json.dumps({
            "sha": self.INDEPENDENT_COMMIT, "tree": {"sha": "d" * 39 + "e"},
        }).encode())
        (authenticated / "authority-commit.json").write_bytes(json.dumps({
            "sha": self.head, "tree": {"sha": self.expected["head_tree"]},
        }).encode())
        run = {
            "id": self.RUN_ID, "run_attempt": 1, "head_sha": self.source_head,
            "path": contract["workflow"]["path"], "event": "workflow_dispatch",
            "head_branch": "main",
            "head_repository": {"full_name": contract["repository"]},
        }
        # One terminated server traversal, plus the authenticated readback
        # that the sealed workflow is already disabled.
        write_run_captures(
            directory, [{"total_count": 1, "workflow_runs": [run]}],
            contract=contract,
        )
        self.candidate.materialise(authenticated / "authority-checkout")
        return contract

    def _environment(self, contract):
        return {
            "GITHUB_RUN_ID": str(self.RUN_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": self.source_head,
            "GITHUB_REPOSITORY": contract["repository"],
            "GITHUB_EVENT_NAME": contract["workflow"]["trigger"],
            "GITHUB_REF": contract["workflow"]["ref"],
            "GITHUB_WORKFLOW_REF": (
                f'{contract["repository"]}/{contract["workflow"]["path"]}'
                f'@{contract["workflow"]["ref"]}'
            ),
        }

    def setUp(self):
        self.source_head = "a" * 39 + "1"
        self.source_tree = "f" * 39 + "2"
        self.validator_root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.validator_root, True)
        self.candidate.materialise(
            self.validator_root / VALIDATOR.AUTHORITY_CHECKOUT
        )

    def export(self, state):
        directory = Path(tempfile.mkdtemp()) / "protected-source"
        self.addCleanup(shutil.rmtree, directory.parent, True)
        contract = self._sealed_source(directory, state=state)
        EXPORT.export(self._environment(contract), root=directory)
        exported = directory / "protected-review"
        return (
            (exported / "kanban-review-envelope.json").read_bytes(),
            (exported / "preissuance-review-receipt.json").read_bytes(),
        )

    # -- behaviour --------------------------------------------------------
    def test_exporter_emits_the_complete_authority_candidate_contract(self):
        _, receipt = self.export("ready")
        candidate = json.loads(receipt)["candidate"]
        self.assertEqual(candidate, self.expected)
        self.assertEqual(candidate["repository"], VERIFIER.EXPECTED_REPOSITORY)
        self.assertEqual(candidate["base_commit"], self.base)
        self.assertEqual(candidate["sole_parent"], self.base)
        self.assertTrue(candidate["changed_path_manifest"])
        VERIFIER._validate_manifest_shape(candidate["changed_path_manifest"])
        self.assertEqual(
            candidate["artifact_sha256"]["authority-v2-policy.json"],
            VERIFIER.EXPECTED_POLICY_SHA256,
        )

    def test_independent_validator_authenticates_the_complete_binding(self):
        envelope, receipt = self.export("ready")
        run = self.pinned_run(envelope, receipt)
        self.assertEqual(
            VALIDATOR.verify(
                run, envelope, receipt, root=self.validator_root,
            )["source_verified"],
            True,
        )
        # Only the candidate binding differs: every digest is repinned so the
        # validator cannot fall back on a byte-digest mismatch.
        for mutate in (
            lambda c: c.update(canonical_diff_sha256="0" * 64),
            lambda c: c.update(base_commit="0" * 40),
            lambda c: c.update(sole_parent="0" * 40),
            lambda c: c.update(repository="chrizzatsu/other"),
            lambda c: c["changed_path_manifest"].pop(),
            lambda c: c["changed_path_manifest"][0].update(new_sha256="0" * 64),
            lambda c: c["artifact_sha256"].update({
                "authority-v2-policy.json": "0" * 64,
            }),
            lambda c: c.update(internal_manifest="forged\n"),
            lambda c: c.pop("artifact_sha256"),
        ):
            with self.subTest(mutate=mutate):
                decoded = json.loads(receipt)
                mutate(decoded["candidate"])
                forged = VALIDATOR.canonical(decoded)
                # Repin every digest, including the envelope's own receipt
                # binding, so only the candidate contract differs.
                rebound = VALIDATOR.canonical({
                    **json.loads(envelope),
                    "review_receipt_sha256": hashlib.sha256(forged).hexdigest(),
                })
                with self.assertRaises(SystemExit):
                    VALIDATOR.verify(
                        self.pinned_run(rebound, forged), rebound, forged,
                        root=self.validator_root,
                    )

    def _live_authority_root(self, envelope, receipt):
        """A later Authority candidate whose independent lane pins live evidence.

        The reviewed protected-source template stays exactly as shipped: only
        the independent lane's authorized source run becomes `ready`, which is
        the only transition the production Authority verifier accepts.
        """
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for relative in (
            "authority-v2-policy.json", "protected-asset-receipt-v2.json",
            "reviewer-authorization-v2.json", "AUTHORITY-V2-SHA256SUMS",
        ):
            (root / relative).write_bytes((ROOT / relative).read_bytes())
        for directory in (
            "scripts", "schemas", "protected-source-bootstrap-v2",
            "independent-review-bootstrap-v2",
        ):
            shutil.copytree(ROOT / directory, root / directory)
        independent_path = (
            root / "independent-review-bootstrap-v2" / "bootstrap-contract.json"
        )
        independent = json.loads(independent_path.read_bytes())
        independent["authorized_source_run"] = {
            **independent["authorized_source_run"],
            **self.pinned_run(envelope, receipt),
            "activation_state": "ready",
        }
        independent_path.write_bytes(
            json.dumps(independent, indent=2, sort_keys=True).encode() + b"\n"
        )
        return root

    def test_live_evidence_chain_satisfies_the_production_authority_verifier(self):
        envelope, receipt = self.export("ready")
        ready = load_module(
            "verify_authority_v2_live",
            self._live_authority_root(envelope, receipt)
            / "scripts" / "verify_authority_v2.py",
        )
        digest = hashlib.sha256(receipt).hexdigest()
        verified = ready.validate_preissuance_receipt_bytes(
            receipt, self.head, digest, self.expected,
            ready._expected_protected_binding(
                self.policy,
                json.loads((ROOT / "protected-asset-receipt-v2.json").read_bytes()),
            ),
            authenticated_issuance=authenticated_issuance(
                head=self.head, tree=self.expected["head_tree"],
                diff=self.expected["canonical_diff_sha256"],
                review_receipt_sha256=digest,
            ),
            envelope_data=envelope,
        )
        self.assertEqual(verified["candidate"], self.expected)
        self.assertIs(verified["approved"], False)
        self.assertIs(verified["release_authorized"], False)
        self.assertIs(verified["activation_authorized"], True)
        self.assertIs(verified["closure_matrix"]["F8"], True)
        self.assertIs(verified["closure_matrix"]["F12"], False)

    def pinned_run(self, envelope, receipt):
        contract = json.loads(
            (ROOT / "independent-review-bootstrap-v2"
             / "bootstrap-contract.json").read_bytes()
        )
        contract["authorized_source_run"].update({
            "activation_state": "ready",
            "run_id": self.RUN_ID,
            "run_head_sha": self.source_head,
            "source_bootstrap_commit": self.source_head,
            "source_bootstrap_tree": self.source_tree,
            "artifact_content_sha256": VALIDATOR.artifact_content_sha256({
                "kanban-review-envelope.json": envelope,
                "preissuance-review-receipt.json": receipt,
            }),
            "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
            "review_receipt_sha256": hashlib.sha256(receipt).hexdigest(),
            "authority_head_commit": self.head,
            "authority_head_tree": self.expected["head_tree"],
            "independent_bootstrap_commit": self.INDEPENDENT_COMMIT,
            "independent_bootstrap_tree": "d" * 39 + "e",
            "certificate_github_workflow_sha": self.INDEPENDENT_COMMIT,
        })
        self.independent_contract = contract
        return VALIDATOR.authorized_source_run(contract)

    def test_pre_activation_export_keeps_f8_open_and_authority_rejects_it(self):
        envelope, receipt = self.export(
            EXPORT.AUTHORIZED_PENDING_EVIDENCE,
        )
        decoded = json.loads(receipt)
        self.assertIs(decoded["closure_matrix"]["F8"], False)
        self.assertIs(decoded["approved"], False)
        self.assertIs(decoded["release_authorized"], False)
        with self.assertRaises(SystemExit):
            VERIFIER.validate_preissuance_receipt_bytes(
                receipt, self.head, hashlib.sha256(receipt).hexdigest(),
                self.expected,
                VERIFIER._expected_protected_binding(
                    self.policy,
                    json.loads(
                        (ROOT / "protected-asset-receipt-v2.json").read_bytes()
                    ),
                ),
                authenticated_issuance=authenticated_issuance(
                    head=self.head, tree=self.expected["head_tree"],
                    diff=self.expected["canonical_diff_sha256"],
                    review_receipt_sha256=hashlib.sha256(receipt).hexdigest(),
                ),
                envelope_data=envelope,
            )


# ---------------------------------------------------------------------------
# EVIDENCE-RUNNER-STATE-CONTRADICTS-CANDIDATE
# EVIDENCE-ARTIFACTS-NOT-IMMUTABLY-SEALED
#
# Evidence generation must be able to emit one internally consistent
# runner-state artifact - recovery round, exact immutable head, tree, commit
# count and terminal state - that a downstream receipt or manifest can bind,
# and it must seal every regenerated artifact under a 0555 directory with 0444
# files, read the modes back and recompute every hash after sealing.
# ---------------------------------------------------------------------------
def _git_text(root, *arguments):
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True,
    ).stdout.decode().strip()


class RunnerStateEvidenceTests(unittest.TestCase):
    """One internally consistent runner-state artifact, derived from Git."""

    def setUp(self):
        self.head = _git_text(ROOT, "rev-parse", "HEAD")
        self.tree = _git_text(ROOT, "rev-parse", "HEAD^{tree}")

    def test_runner_state_records_round_head_tree_count_and_terminal_state(self):
        state = GENERATOR.build_runner_state(
            repository_root=ROOT, recovery_round=1, terminal_state="completed",
        )
        self.assertEqual(state["recovery_round"], 1)
        self.assertEqual(state["head_commit"], self.head)
        self.assertEqual(state["head_tree"], self.tree)
        self.assertEqual(
            state["commit_count"],
            int(_git_text(
                ROOT, "rev-list", "--count",
                f'{state["base_commit"]}..{state["head_commit"]}',
            )),
            "the runner state must count the exact candidate range only",
        )
        self.assertEqual(state["commit_count"], 1)
        self.assertEqual(
            state["base_commit"],
            json.loads((ROOT / "authority-v2-policy.json").read_bytes())
            ["authority_repository_base"]["commit"],
        )
        self.assertIsNone(state["derived_closure_sha256"])
        self.assertEqual(state["terminal_state"], "completed")
        self.assertEqual(
            state["artifact_type"], GENERATOR.RUNNER_STATE_ARTIFACT_TYPE,
        )
        self.assertIs(state["consistent"], True)
        self.assertEqual(
            sorted(state), sorted(GENERATOR.RUNNER_STATE_KEYS),
        )

    def test_runner_state_is_canonical_and_reserializes_exactly(self):
        state = GENERATOR.build_runner_state(
            repository_root=ROOT, recovery_round=0, terminal_state="completed",
        )
        data = GENERATOR.canonical_runner_state(state)
        self.assertEqual(data, GENERATOR.canonical_runner_state(json.loads(data)))
        self.assertTrue(data.endswith(b"\n"))

    def test_a_contradictory_runner_round_or_terminal_state_is_refused(self):
        for label, kwargs in (
            ("negative-round", {"recovery_round": -1}),
            ("boolean-round", {"recovery_round": True}),
            ("unmodelled-terminal-state", {"terminal_state": "in_progress"}),
            ("absent-terminal-state", {"terminal_state": ""}),
        ):
            with self.subTest(label=label):
                arguments = {
                    "repository_root": ROOT, "recovery_round": 0,
                    "terminal_state": "completed", **kwargs,
                }
                with self.assertRaises(SystemExit):
                    GENERATOR.build_runner_state(**arguments)

    def test_a_runner_state_outside_a_clean_checkout_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit):
                GENERATOR.build_runner_state(
                    repository_root=Path(td), recovery_round=0,
                    terminal_state="completed",
                )

    def test_a_blocked_terminal_state_never_claims_a_completed_round(self):
        state = GENERATOR.build_runner_state(
            repository_root=ROOT, recovery_round=2,
            terminal_state="blocked_builder_failed",
        )
        self.assertEqual(state["terminal_state"], "blocked_builder_failed")
        self.assertEqual(state["head_commit"], self.head)
        self.assertGreater(state["commit_count"], 0)


class ImmutableEvidenceSealingTests(unittest.TestCase):
    """0555 directory, 0444 files, mode readback and post-seal hashes."""

    def sealed(self, names=("a.json", "b.json")):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(self.force_remove, directory)
        for index, name in enumerate(names):
            (directory / name).write_bytes(f'{{"n":{index}}}\n'.encode())
        return directory, GENERATOR.seal_evidence_directory(directory)

    @staticmethod
    def force_remove(directory):
        directory = Path(directory)
        if directory.is_dir():
            os.chmod(directory, 0o700)
            for child in directory.iterdir():
                os.chmod(child, 0o600)
        shutil.rmtree(directory, ignore_errors=True)

    def test_sealing_sets_a_0555_directory_and_0444_files(self):
        directory, manifest = self.sealed()
        self.assertEqual(manifest["directory_mode"], "0555")
        self.assertEqual(
            oct(os.stat(directory).st_mode & 0o777), oct(0o555),
        )
        for entry in manifest["entries"]:
            self.assertEqual(entry["mode"], "0444")
            self.assertEqual(
                oct(os.stat(directory / entry["name"]).st_mode & 0o777),
                oct(0o444),
            )

    def test_sealing_reads_the_modes_back_and_records_them(self):
        _, manifest = self.sealed()
        self.assertIs(manifest["mode_readback_verified"], True)
        self.assertEqual(manifest["directory_mode_readback"], "0555")
        for entry in manifest["entries"]:
            self.assertEqual(entry["mode_readback"], "0444")

    def test_every_hash_is_recomputed_after_the_final_sealing(self):
        directory, manifest = self.sealed()
        self.assertIs(manifest["hashes_recomputed_after_sealing"], True)
        for entry in manifest["entries"]:
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256((directory / entry["name"]).read_bytes()).hexdigest(),
            )
            self.assertEqual(
                entry["size"], (directory / entry["name"]).stat().st_size,
            )
        self.assertEqual(
            [entry["name"] for entry in manifest["entries"]],
            sorted(entry["name"] for entry in manifest["entries"]),
        )

    def test_a_sealed_directory_refuses_a_further_write(self):
        directory, _ = self.sealed()
        with self.assertRaises(PermissionError):
            (directory / "c.json").write_bytes(b"{}\n")
        with self.assertRaises(PermissionError):
            (directory / "a.json").write_bytes(b"{}\n")

    def test_sealing_refuses_an_unsafe_or_absent_directory(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit):
                GENERATOR.seal_evidence_directory(Path(td) / "absent")
            nested = Path(td) / "nested"
            (nested / "inner").mkdir(parents=True)
            with self.assertRaises(SystemExit):
                GENERATOR.seal_evidence_directory(nested)

    def staged_gate(self, round_number):
        """The real pre-terminal ordering the production CLI now requires.

        The round first emits a non-terminal `verification_pending` runner
        state, the write-free verify-only publication gate runs over the
        complete inventory that carries *that* artifact, and only then may the
        round emit a completed terminal runner state.
        """
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        staged = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-runner-state", "--recovery-round", str(round_number),
             "--terminal-state", GENERATOR.RUNNER_STAGING_STATE],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(staged.returncode, 0, staged.stderr.decode())
        state = json.loads(staged.stdout)["runner_state"]
        self.assertEqual(
            state["terminal_state"], GENERATOR.RUNNER_STAGING_STATE,
        )
        (directory / GENERATOR.RUNNER_STATE_NAME).write_bytes(
            GENERATOR.canonical_runner_state(state)
        )
        return write_gate(
            directory / "verify-only-publication.json",
            verify_only_gate_document(directory_digests(
                directory, [GENERATOR.RUNNER_STATE_NAME],
            )),
        )

    def test_a_completed_round_requires_the_pre_terminal_f12_gate(self):
        """No completed terminal artifact exists before the gate confirms."""
        ungated = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-runner-state", "--recovery-round", "1",
             "--terminal-state", "completed"],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertNotEqual(ungated.returncode, 0)
        self.assertIn("--verify-only-result", ungated.stderr.decode())
        self.assertEqual(ungated.stdout, b"")

    def test_a_blocked_gate_can_never_complete_a_round(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        staged = self.staged_gate(1)
        blocked = json.loads(staged.read_bytes())
        for label, override in (
            ("blocked", {"state": "blocked", "deep_plan_verified": False,
                         "blocked_by": "F8-AUTHENTICATED-SOURCE-CHAIN-"
                                       "UNAVAILABLE"}),
            ("deep-plan-unverified", {"deep_plan_verified": False}),
            ("named-blocker", {"blocked_by": "F12-EXCLUSIVE-PUBLICATION-"
                                             "UNAVAILABLE"}),
            ("f12-closed", {"f12_closed": True}),
            ("release-authorized", {"release_authorized": True}),
            ("not-verify-only", {"verify_only": False}),
            ("writes-performed", {"writes_performed": 1}),
            ("transport-constructed", {"transports_constructed": 1}),
            ("publication-available", {"publication": "available"}),
        ):
            with self.subTest(label=label):
                path = write_gate(
                    directory / f"{label}.json", {**blocked, **override},
                )
                observed = subprocess.run(
                    [sys.executable,
                     str(ROOT / "scripts" / "build_authority_v2.py"),
                     "--emit-runner-state", "--recovery-round", "1",
                     "--terminal-state", "completed",
                     "--verify-only-result", str(path)],
                    capture_output=True, cwd=str(ROOT),
                )
                self.assertNotEqual(observed.returncode, 0, label)
                self.assertEqual(observed.stdout, b"", label)
                self.assertNotIn("Traceback", observed.stderr.decode(), label)

    def test_a_gate_taken_over_the_completed_state_proves_no_ordering(self):
        """A gate produced over the completed artifact cannot precede it."""
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        completed = GENERATOR.build_runner_state(
            repository_root=ROOT, recovery_round=1, terminal_state="completed",
        )
        (directory / GENERATOR.RUNNER_STATE_NAME).write_bytes(
            GENERATOR.canonical_runner_state(completed)
        )
        path = write_gate(
            directory / "verify-only-publication.json",
            verify_only_gate_document(directory_digests(
                directory, [GENERATOR.RUNNER_STATE_NAME],
            )),
        )
        observed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-runner-state", "--recovery-round", "1",
             "--terminal-state", "completed",
             "--verify-only-result", str(path)],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertNotEqual(observed.returncode, 0)
        self.assertIn("cannot have preceded it", observed.stderr.decode())
        self.assertEqual(observed.stdout, b"")

    def test_the_generator_cli_emits_a_sealed_runner_state_manifest(self):
        observed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-runner-state", "--recovery-round", "1",
             "--terminal-state", "completed",
             "--verify-only-result", str(self.staged_gate(1))],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        emitted = json.loads(observed.stdout)
        self.assertEqual(emitted["runner_state"]["recovery_round"], 1)
        self.assertEqual(
            emitted["runner_state"]["head_commit"],
            _git_text(ROOT, "rev-parse", "HEAD"),
        )
        self.assertEqual(
            emitted["runner_state"]["head_tree"],
            _git_text(ROOT, "rev-parse", "HEAD^{tree}"),
        )
        self.assertEqual(emitted["runner_state"]["terminal_state"], "completed")
        self.assertIs(emitted["sealed"], False)
        self.assertIs(emitted["raw_values_emitted"], False)

    def test_the_generator_cli_seals_a_regenerated_evidence_directory(self):
        directory = Path(tempfile.mkdtemp()) / "evidence"
        self.addCleanup(self.force_remove, directory.parent)
        observed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-runner-state", "--recovery-round", "2",
             "--terminal-state", "completed",
             "--verify-only-result", str(self.staged_gate(2)),
             "--runner-state-dir", str(directory)],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        emitted = json.loads(observed.stdout)
        self.assertIs(emitted["sealed"], True)
        manifest = emitted["sealing"]
        self.assertEqual(manifest["directory_mode"], "0555")
        self.assertEqual(
            [entry["name"] for entry in manifest["entries"]],
            [GENERATOR.RUNNER_STATE_NAME],
        )
        entry = manifest["entries"][0]
        self.assertEqual(entry["mode"], "0444")
        self.assertEqual(
            entry["sha256"],
            hashlib.sha256(
                (directory / GENERATOR.RUNNER_STATE_NAME).read_bytes()
            ).hexdigest(),
        )
        state = json.loads((directory / GENERATOR.RUNNER_STATE_NAME).read_bytes())
        self.assertEqual(state["recovery_round"], 2)
        self.assertEqual(state["commit_count"], 1)

    def test_subject_generation_seals_its_output_directory(self):
        self.assertIn(
            "seal", inspect.signature(GENERATOR.build_subjects).parameters,
        )


# ---------------------------------------------------------------------------
# EVIDENCE-SEALING-NOT-APPLIED-TO-FINAL-EVIDENCE
#
# The complete final evidence set - every subject, every Sigstore bundle and
# the release checksum manifest - is sealed only once nothing may still
# change. Sealing too early and then appending a mutable artifact is refused.
# ---------------------------------------------------------------------------
# The complete release asset inventory: the eight signed release-evidence
# members and the six reviewed public / pre-issuance release assets. The last
# non-mutating gate verifies all fourteen, so all fourteen are sealed - a
# gated asset that stays mutable is the defect this inventory closes.
FINAL_EVIDENCE_INVENTORY = tuple(sorted([
    *VERIFIER.release_evidence_inventory(), VERIFIER.RELEASE_MANIFEST_NAME,
    *GENERATOR.SEALED_PUBLIC_ASSET_NAMES,
]))


# ---------------------------------------------------------------------------
# F12-VERIFY-ONLY-CLI-AND-EVIDENCE-TERMINAL-BROKEN
#
# The write-free verify-only publication gate must run over the complete
# canonical release inventory *before* this round claims a completed terminal
# state and before anything is sealed, and the bytes that are then made
# terminal and immutable must be byte for byte the bytes it verified.
#
# `verify_only_gate_document` reproduces the exact document the unchanged
# verify-only path emits. Its field set is asserted against the production
# module in `test_the_gate_document_is_the_production_verify_only_shape`, so
# it can never drift from what `verify_publication_v2.py --verify-only`
# actually writes, and it never stands in for the publication verification
# itself - that runs for real in `tests/test_publication_v2.py`.
# ---------------------------------------------------------------------------
def verify_only_gate_document(digests, **overrides):
    # The declared canonical map digest is, as in production, the digest of
    # the gate's own names and digests. An adversarial case overrides it.
    document = {
        "asset_digests": dict(digests),
        "assets_verified": len(digests),
        "blocked_by": None,
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
    document.update(overrides)
    return document


def directory_digests(directory, names):
    directory = Path(directory)
    return {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in names
    }


def write_gate(path, document):
    path = Path(path)
    path.write_bytes(
        json.dumps(document, sort_keys=True).encode("utf-8") + b"\n"
    )
    return path


class FinalEvidenceSealingTests(unittest.TestCase):
    """The exact workflow-produced final inventory is sealed and rehashed."""

    @staticmethod
    def force_remove(directory):
        directory = Path(directory)
        if directory.is_dir():
            os.chmod(directory, 0o700)
            for child in directory.iterdir():
                os.chmod(child, 0o600)
        shutil.rmtree(directory, ignore_errors=True)

    def workflow_dist(self):
        """Exactly what the issuance workflow leaves in dist before sealing."""
        directory = Path(tempfile.mkdtemp()) / "dist"
        directory.mkdir()
        self.addCleanup(self.force_remove, directory.parent)
        evidence = VERIFIER.release_evidence_inventory()
        lines = []
        for name in FINAL_EVIDENCE_INVENTORY:
            if name == "AUTHORITY-V2-RELEASE-SHA256SUMS":
                continue
            if name == GENERATOR.RUNNER_STATE_NAME:
                payload = GENERATOR.canonical_runner_state(
                    GENERATOR.build_runner_state(
                        repository_root=ROOT, recovery_round=0,
                        terminal_state="completed",
                    )
                )
            else:
                payload = json.dumps(
                    {"member": name}, sort_keys=True,
                ).encode() + b"\n"
            (directory / name).write_bytes(payload)
            # The release checksum manifest enumerates the signed release
            # evidence alone: its byte stream is the one the unchanged
            # production release verifier recomputes. The reviewed public
            # assets are sealed with everything else but never listed there.
            if name in evidence:
                lines.append(f"{hashlib.sha256(payload).hexdigest()}  {name}\n")
        (directory / "AUTHORITY-V2-RELEASE-SHA256SUMS").write_text(
            "".join(sorted(lines)), encoding="utf-8",
        )
        return directory

    def gate(self, directory, **overrides):
        """The verify-only gate over exactly the bytes now in `directory`."""
        digests = directory_digests(directory, FINAL_EVIDENCE_INVENTORY)
        return verify_only_gate_document(
            digests,
            canonical_inventory_sha256=GENERATOR.canonical_inventory_sha256({
                "digests": digests, "inventory": sorted(digests),
            }),
            **overrides,
        )

    def composed(self, directory, **kwargs):
        """The manifest the production lane composes *before* the gate."""
        return GENERATOR.write_final_evidence_manifest(
            Path(directory).parent / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME,
            directory, **kwargs,
        )

    def test_the_exact_workflow_inventory_seals_0555_and_0444(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        emitted = GENERATOR.seal_final_evidence(
            directory, expected=FINAL_EVIDENCE_INVENTORY,
            gate=self.gate(directory), manifest=manifest,
        )
        sealing = emitted["sealing"]
        self.assertEqual(sealing["directory_mode"], "0555")
        self.assertEqual(sealing["directory_mode_readback"], "0555")
        self.assertIs(sealing["mode_readback_verified"], True)
        self.assertIs(sealing["hashes_recomputed_after_sealing"], True)
        self.assertEqual(
            oct(os.stat(directory).st_mode & 0o777), oct(0o555),
        )
        # The receipt is never a member of the set it describes: the sealed
        # inventory is exactly the inventory the gate verified.
        self.assertEqual(
            [entry["name"] for entry in sealing["entries"]],
            sorted(FINAL_EVIDENCE_INVENTORY),
        )
        self.assertEqual(
            oct(os.stat(manifest).st_mode & 0o777), oct(0o444),
        )
        for entry in sealing["entries"]:
            member = directory / entry["name"]
            self.assertEqual(entry["mode"], "0444", entry["name"])
            self.assertEqual(entry["mode_readback"], "0444", entry["name"])
            self.assertEqual(
                oct(os.stat(member).st_mode & 0o777), oct(0o444), entry["name"],
            )
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256(member.read_bytes()).hexdigest(), entry["name"],
            )
            self.assertEqual(entry["size"], member.stat().st_size)

    def test_the_release_checksum_manifest_is_inside_the_sealed_set(self):
        directory = self.workflow_dist()
        emitted = GENERATOR.seal_final_evidence(
            directory, gate=self.gate(directory),
            manifest=self.composed(directory),
        )
        self.assertIn("AUTHORITY-V2-RELEASE-SHA256SUMS", emitted["inventory"])
        for name in FINAL_EVIDENCE_INVENTORY:
            self.assertIn(name, emitted["inventory"], name)
        self.assertIs(emitted["sealed_after_release_manifest"], True)

    def test_a_sealed_final_set_refuses_every_further_write(self):
        directory = self.workflow_dist()
        GENERATOR.seal_final_evidence(
            directory, gate=self.gate(directory),
            manifest=self.composed(directory),
        )
        with self.assertRaises(PermissionError):
            (directory / "authority-v2-late.sigstore.json").write_bytes(b"{}\n")
        with self.assertRaises(PermissionError):
            (directory / "AUTHORITY-V2-RELEASE-SHA256SUMS").write_bytes(b"x\n")

    def test_sealing_twice_or_over_a_wrong_inventory_is_refused(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        GENERATOR.seal_final_evidence(
            directory, gate=gate, manifest=manifest,
        )
        # A second seal cannot compose the manifest again over a directory
        # that is now read-only, so the round can never be replayed.
        with self.assertRaises(SystemExit):
            GENERATOR.seal_final_evidence(
                directory, gate=gate,
                manifest=self.composed(directory.parent / "twice"),
            )
        other = self.workflow_dist()
        with self.assertRaises(SystemExit):
            GENERATOR.seal_final_evidence(
                other, expected=(*FINAL_EVIDENCE_INVENTORY, "extra.json"),
                gate=self.gate(other), manifest=self.composed(other),
            )

    def test_the_cli_seals_the_exact_workflow_inventory(self):
        directory = self.workflow_dist()
        manifest_path = (
            directory.parent / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME
        )
        members = []
        for name in FINAL_EVIDENCE_INVENTORY:
            members += ["--final-evidence-member", name]
        # The real CLI composes the manifest first, exactly as the workflow
        # does, and only then is the gate taken over those very bytes.
        composing = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-final-evidence-manifest", str(directory),
             "--final-evidence-manifest", str(manifest_path), *members],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(composing.returncode, 0, composing.stderr.decode())
        gate = write_gate(
            directory.parent / "verify-only-publication.json",
            self.gate(directory),
        )
        arguments = [sys.executable,
                     str(ROOT / "scripts" / "build_authority_v2.py"),
                     "--seal-final-evidence", str(directory),
                     "--final-evidence-manifest", str(manifest_path),
                     "--verify-only-result", str(gate), *members]
        observed = subprocess.run(arguments, capture_output=True, cwd=str(ROOT))
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        emitted = json.loads(observed.stdout)
        self.assertIs(emitted["sealed"], True)
        self.assertIs(emitted["raw_values_emitted"], False)
        sealing = emitted["final_evidence"]["sealing"]
        self.assertEqual(sealing["directory_mode_readback"], "0555")
        self.assertEqual(
            sorted({entry["mode_readback"] for entry in sealing["entries"]}),
            ["0444"],
        )
        manifest = json.loads(manifest_path.read_bytes())
        self.assertEqual(
            manifest["artifact_type"], GENERATOR.FINAL_EVIDENCE_ARTIFACT_TYPE,
        )
        self.assertEqual(
            sorted(manifest["inventory"]), sorted(FINAL_EVIDENCE_INVENTORY),
        )
        self.assertFalse(
            (directory / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME).exists(),
            "the CLI created a member the publication gate never verified",
        )

    def test_the_gate_document_is_the_production_verify_only_shape(self):
        """The gate the seal requires is exactly what verify-only emits."""
        publication = load_module(
            "verify_publication_v2", ROOT / "scripts" / "verify_publication_v2.py",
        )
        produced = inspect.getsource(publication.verify_only_publication_state)
        # Every member the gate contract names really is emitted there.
        for key in GENERATOR.VERIFY_ONLY_GATE_KEYS:
            self.assertIn(f'"{key}"', produced, key)
        self.assertEqual(
            sorted(verify_only_gate_document({})),
            sorted(GENERATOR.VERIFY_ONLY_GATE_KEYS),
        )

    def test_the_seal_refuses_an_absent_or_malformed_gate(self):
        directory = self.workflow_dist()
        with self.assertRaises(SystemExit):
            GENERATOR.seal_final_evidence(
                directory, manifest=self.composed(directory),
            )
        for label, mutate in (
            ("blocked", lambda d: d.update(
                state="blocked", deep_plan_verified=False,
                blocked_by="F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE")),
            ("f12-closed", lambda d: d.update(f12_closed=True)),
            ("release-authorized", lambda d: d.update(release_authorized=True)),
            ("extra-member", lambda d: d.update(unexpected=True)),
            ("missing-member", lambda d: d.pop("asset_digests")),
            ("digest-count-drift", lambda d: d.update(assets_verified=99)),
        ):
            with self.subTest(label=label):
                other = self.workflow_dist()
                gate = self.gate(other)
                mutate(gate)
                path = write_gate(other.parent / "gate.json", gate)
                with self.assertRaises(SystemExit):
                    GENERATOR.seal_final_evidence(
                        other,
                        gate=GENERATOR.authenticated_verify_only_gate(path),
                        manifest=self.composed(other),
                    )

    def test_the_sealed_inventory_must_be_the_verified_inventory(self):
        """Byte-for-byte: an artifact that drifted after the gate is refused."""
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        (directory / "authority-v2-stale.json").write_bytes(b'{"drift":1}\n')
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn("changed after the publication gate", str(raised.exception))

    def test_a_member_the_gate_never_verified_is_refused(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        gate["asset_digests"].pop("authority-v2-stale.json")
        gate["inventory"] = sorted(gate["asset_digests"])
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn("never verified by the publication gate",
                      str(raised.exception))

    def test_a_non_terminal_runner_state_is_never_sealed(self):
        directory = self.workflow_dist()
        staged = GENERATOR.canonical_runner_state(
            GENERATOR.build_runner_state(
                repository_root=ROOT, recovery_round=0,
                terminal_state=GENERATOR.RUNNER_STAGING_STATE,
            )
        )
        (directory / GENERATOR.RUNNER_STATE_NAME).write_bytes(staged)
        # Everything else about the round is consistent, so the staging state
        # is the only reason this may not become terminal.
        (directory / "AUTHORITY-V2-RELEASE-SHA256SUMS").write_text(
            "".join(sorted(
                f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}"
                f"  {name}\n"
                for name in VERIFIER.release_evidence_inventory()
            )),
            encoding="utf-8",
        )
        # It is refused while the manifest is still being composed, before the
        # gate is ever taken ...
        with self.assertRaises(SystemExit) as raised:
            self.composed(directory)
        self.assertIn("not a modelled terminal state", str(raised.exception))
        # ... and again at the seal, which recomposes it for itself.
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=self.gate(directory),
                manifest=directory.parent / "absent-manifest.json",
            )
        self.assertIn("not a modelled terminal state", str(raised.exception))

    def test_the_issuance_workflow_gates_before_it_completes_or_seals(self):
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        gate = workflow.index("--verify-only")
        completed = workflow.index("--terminal-state completed")
        seal = workflow.index("--seal-final-evidence")
        self.assertLess(
            gate, completed,
            "the F12 gate must run before any completed terminal artifact",
        )
        self.assertLess(gate, seal, "the F12 gate must run before sealing")
        self.assertIn(GENERATOR.RUNNER_STAGING_STATE, workflow)
        self.assertIn("--verify-only-result", workflow)

    def test_the_issuance_workflow_seals_after_the_release_manifest(self):
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        seal = workflow.index("--seal-final-evidence")
        self.assertGreater(
            seal, workflow.index("AUTHORITY-V2-RELEASE-SHA256SUMS"),
            "final evidence is sealed before the release manifest exists",
        )
        self.assertGreater(
            seal, workflow.index("--sign-subject-dir"),
            "final evidence is sealed before the bundles exist",
        )
        self.assertNotIn(
            "--seal-evidence", workflow,
            "the workflow seals the subject directory before the bundles land",
        )
        for name in FINAL_EVIDENCE_INVENTORY:
            self.assertIn(f"--final-evidence-member {name}", workflow, name)
        self.assertIn("directory_mode_readback", workflow)
        self.assertIn("hashes_recomputed_after_sealing", workflow)


# ---------------------------------------------------------------------------
# F12-VERIFY-ONLY-CLI-AND-EVIDENCE-TERMINAL-BROKEN - the ordering itself
#
# The final evidence manifest is composed *before* the last non-mutating
# verify-only gate, out of exactly the bytes that gate then confirms. Sealing
# afterwards may therefore create nothing and rewrite nothing: it only makes
# the already-verified bytes immutable. The complete sealed inventory must be
# exactly the inventory the gate verified - proven out of the gate-verified
# release checksum manifest, in both directions and byte for byte - so a
# member that the gate never saw can never end up inside the sealed set.
# ---------------------------------------------------------------------------
class FinalEvidenceGateOrderingTests(unittest.TestCase):
    """Nothing is created or rewritten after the last verify-only gate."""

    workflow_dist = FinalEvidenceSealingTests.workflow_dist
    force_remove = staticmethod(FinalEvidenceSealingTests.force_remove)

    def gate(self, directory, **overrides):
        digests = directory_digests(directory, FINAL_EVIDENCE_INVENTORY)
        return verify_only_gate_document(
            digests,
            canonical_inventory_sha256=GENERATOR.canonical_inventory_sha256({
                "digests": digests, "inventory": sorted(digests),
            }),
            **overrides,
        )

    @staticmethod
    def snapshot(directory):
        """Exactly what is on disk: names, bytes and the inode behind them."""
        return {
            child.name: (
                hashlib.sha256(child.read_bytes()).hexdigest(),
                child.stat().st_ino,
                child.stat().st_size,
            )
            for child in Path(directory).iterdir()
        }

    def composed(self, directory):
        """The manifest, composed and written before the gate is taken."""
        return GENERATOR.write_final_evidence_manifest(
            Path(directory).parent / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME,
            directory, expected=FINAL_EVIDENCE_INVENTORY,
        )

    # -- the ordering ------------------------------------------------------
    def test_sealing_creates_and_rewrites_no_member_after_the_gate(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        before = self.snapshot(directory)
        GENERATOR.seal_final_evidence(
            directory, expected=FINAL_EVIDENCE_INVENTORY,
            gate=gate, manifest=manifest,
        )
        self.assertEqual(self.snapshot(directory), before)

    def test_the_sealed_inventory_is_exactly_the_gate_inventory(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        emitted = GENERATOR.seal_final_evidence(
            directory, gate=gate, manifest=manifest,
        )
        sealed = sorted(child.name for child in directory.iterdir())
        self.assertEqual(sealed, sorted(FINAL_EVIDENCE_INVENTORY))
        self.assertEqual(sealed, sorted(emitted["inventory"]))
        # Both directions, byte for byte, against the gate the CLI required.
        self.assertEqual(
            {name: gate["asset_digests"][name] for name in sealed},
            {
                name: hashlib.sha256(
                    (directory / name).read_bytes()
                ).hexdigest()
                for name in sealed
            },
        )
        self.assertEqual(sorted(emitted["member_sha256"]), sealed)

    def test_the_manifest_never_lives_inside_the_inventory_it_seals(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        (directory / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME).write_bytes(
            manifest.read_bytes()
        )
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=self.gate(directory), manifest=manifest,
            )
        self.assertIn("may not live inside", str(raised.exception))

    def test_sealing_without_a_manifest_composed_before_the_gate_is_refused(self):
        directory = self.workflow_dist()
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=self.gate(directory),
            )
        self.assertIn("final evidence manifest", str(raised.exception))

    def test_a_manifest_that_no_longer_describes_these_bytes_is_refused(self):
        """Composed before the gate, and never rewritten afterwards."""
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        document = json.loads(manifest.read_bytes())
        document["member_sha256"]["authority-v2-stale.json"] = "0" * 64
        manifest.write_bytes(
            json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
        )
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=self.gate(directory), manifest=manifest,
            )
        # A rewritten manifest no longer holds the canonical map it claims,
        # and is refused by the map before its bytes are compared at all.
        self.assertIn(
            "is not the canonical inventory digest for "
            "authority-v2-stale.json",
            str(raised.exception),
        )

    # -- the gate inventory equality, in both directions -------------------
    def test_a_member_created_after_the_gate_is_refused(self):
        """A file that appears once the gate is taken is not the inventory."""
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        extra = directory / "authority-v2-extra.json"
        extra.write_bytes(b'{"extra":1}\n')
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn(
            "never verified by the publication gate", str(raised.exception),
        )
        # And even a gate that did name it fails the inventory equality.
        gate["asset_digests"][extra.name] = hashlib.sha256(
            extra.read_bytes()
        ).hexdigest()
        gate["inventory"] = sorted(gate["asset_digests"])
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn("release checksum manifest", str(raised.exception))

    def test_a_member_removed_after_the_gate_is_refused(self):
        """The equality holds in the other direction too."""
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        (directory / "authority-v2-stale.sigstore.json").unlink()
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn("release checksum manifest", str(raised.exception))

    def test_a_release_checksum_digest_that_is_not_the_gate_digest_is_refused(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        gate = self.gate(directory)
        gate["asset_digests"]["authority-v2-stale.json"] = "1" * 64
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn("changed after the publication gate",
                      str(raised.exception))

    # -- the workflow really orders it this way ----------------------------
    def test_the_workflow_composes_the_manifest_before_the_last_gate(self):
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        compose = workflow.index("--emit-final-evidence-manifest")
        last_gate = workflow.index("verify-only-final.json")
        seal = workflow.index("--seal-final-evidence")
        self.assertLess(
            compose, last_gate,
            "the final evidence manifest is composed after the last gate",
        )
        self.assertLess(last_gate, seal)
        self.assertIn("--final-evidence-manifest", workflow)


# ---------------------------------------------------------------------------
# F8-ISSUANCE-ARTIFACT-BINDING-BYPASSABLE
#
# Naming an artifact proves nothing. The issuance lane must traverse every
# artifact page the server offers, select exactly one non-expired artifact per
# required name, download each one by its canonical server id, and recompute
# the archive size, the archive SHA-256 and the exact member bytes. Anything
# less lets a second, forged or expired artifact supply the digest the closure
# then trusts.
# ---------------------------------------------------------------------------
class IssuanceArtifactBindingTests(unittest.TestCase):
    """The issuance lane binds artifact bytes, never an artifact name."""

    REQUIRED_ARTIFACTS = (
        "authority-v2-external-activation-review-t_c298fca4",
        "authority-v2-signed-review-t_c298fca4",
    )

    def setUp(self):
        self.workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")

    def test_the_artifact_listing_is_exhaustively_paginated(self):
        """A fixed single page can hide the artifact that really matched."""
        self.assertNotIn(
            "artifacts?per_page=100&page=1\"", self.workflow,
            "the artifact listing reads one fixed page and stops",
        )
        self.assertIn(
            "--paginate", self.workflow,
            "the artifact listing does not exhaustively traverse its pages",
        )

    def test_exactly_one_non_expired_artifact_supplies_each_binding(self):
        """The digest must come from the same uniquely selected artifact."""
        listing = self.workflow[self.workflow.index("ARTIFACTS="):]
        listing = listing[:listing.index("authenticated-artifact-identity")]
        self.assertNotIn(
            'select(.name == $n)][0].digest', listing,
            "the digest is taken from an unchecked, possibly expired duplicate",
        )
        self.assertEqual(
            listing.count("if length == 1 then"), 1,
            "the artifact selection does not require exactly one match",
        )

    def test_each_artifact_is_downloaded_by_canonical_server_id(self):
        """The bytes must be fetched by server id, never by name."""
        self.assertIn(
            "actions/artifacts/$id/zip", self.workflow,
            "no artifact archive is downloaded by canonical server id",
        )

    def test_the_archive_size_and_digest_are_recomputed(self):
        """Server-declared size and digest must be checked against the bytes."""
        for probe, reason in (
            ("size_in_bytes", "the server-declared archive size is never checked"),
            ("sha256sum", "the archive digest is never recomputed locally"),
        ):
            self.assertIn(probe, self.workflow, reason)

    def test_the_exact_member_bytes_are_bound(self):
        """The archive members, not just the archive, must be bound."""
        self.assertIn(
            "--review-artifact-member-digests", self.workflow,
            "the archive members are never validated and bound",
        )
        self.assertNotIn(
            "unzip -", self.workflow,
            "shell extraction must not precede complete ZipInfo validation",
        )
        self.assertIn(
            "archive_sha256", self.workflow,
            "the recomputed archive digest never reaches the sealed evidence",
        )

    def test_the_closure_requires_identity_and_digest_together(self):
        """A matching name may never rescue a mismatched digest."""
        source = (
            ROOT / "scripts" / "pin_source_chain_activation_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            'or server["artifact_name"] == SOURCE_ARTIFACT_NAME', source,
            "the closure still accepts a name in place of a digest",
        )


# ---------------------------------------------------------------------------
# F12-VERIFY-ONLY-CLI-AND-EVIDENCE-TERMINAL-BROKEN
#
# A run may not declare itself `completed` and seal its final evidence 0555 /
# 0444 and only afterwards discover whether the publication leg is blocked.
# The verify-only gate is what proves F12 is still open, so it has to run
# before any terminal state is emitted and before anything is sealed.
# ---------------------------------------------------------------------------
class VerifyOnlyTerminalOrderingTests(unittest.TestCase):
    """The verify-only F12 gate precedes every terminal, sealing step."""

    def setUp(self):
        self.workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")

    def index(self, probe):
        found = self.workflow.find(probe)
        self.assertGreater(found, 0, f"{probe} is absent from the workflow")
        return found

    def test_no_terminal_or_sealed_state_is_established_before_the_gate(self):
        """Nothing may become terminal or immutable before F12 is confirmed.

        The runner-state artifact is a required, unchanged input to the
        verify-only command, so it is staged first; but it stays mutable and
        unbound until this gate has run. Every step that makes the run
        terminal or the evidence immutable must follow the gate.
        """
        verify = self.index("verify_publication_v2.py --verify-only")
        for probe, reason in (
            ("--seal-final-evidence",
             "the final evidence is sealed before the F12 gate ran"),
            ("directory_mode_readback",
             "the 0555 directory seal is asserted before the F12 gate ran"),
            ("mode_readback] | unique",
             "the 0444 member seal is asserted before the F12 gate ran"),
            ("final_evidence.runner_terminal_state",
             "the sealed terminal state is bound before the F12 gate ran"),
        ):
            self.assertLess(verify, self.index(probe), reason)

    def test_the_gate_asserts_the_expected_false_f12_posture(self):
        """Ordering alone is not the fix; the gate must assert the posture."""
        verify = self.index("verify_publication_v2.py --verify-only")
        sealing = self.index("--seal-final-evidence")
        gate = self.workflow[verify:sealing]
        for probe in (".f12_closed", ".release_authorized", ".verify_only",
                      ".writes_performed", ".transports_constructed"):
            self.assertIn(
                probe, gate,
                f"the F12 gate never asserts {probe}",
            )

    def test_the_verified_inventory_is_the_inventory_that_gets_sealed(self):
        """One canonical complete inventory, verified then sealed unchanged."""
        verify = self.index("verify_publication_v2.py --verify-only")
        sealing = self.index("--seal-final-evidence")
        gate = self.workflow[verify:sealing]
        self.assertIn(
            "sha256sum -c AUTHORITY-V2-RELEASE-SHA256SUMS", gate,
            "the verified inventory is never re-proved identical before sealing",
        )
        for name in FINAL_EVIDENCE_INVENTORY:
            self.assertIn(f"--final-evidence-member {name}", self.workflow, name)
        for name in FINAL_EVIDENCE_INVENTORY:
            if name != "AUTHORITY-V2-FINAL-EVIDENCE.json":
                self.assertIn(f"--asset {name}=", self.workflow, name)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# F12-INVENTORY-MAP-NOT-CANONICAL-OR-SHARED
#
# The gate, the final manifest and the seal each derived their own inventory
# and digest map. Three derivations of "the same" set is three chances to
# disagree, and the seal only ever proved that every sealed member had been
# gated - never that the gate had verified nothing else. A gate over a
# *superset* therefore sealed happily.
#
# One canonical complete map is composed before the last non-mutating gate,
# carried by the manifest, consumed unchanged by the gate and by the seal, and
# compared in both directions by name and by digest.
# ---------------------------------------------------------------------------
class CanonicalInventoryMapTests(FinalEvidenceSealingTests):
    """One map, composed once, consumed unchanged by gate, manifest and seal."""

    def prepared(self):
        directory = self.workflow_dist()
        manifest = self.composed(directory)
        document = json.loads(Path(manifest).read_bytes())
        return directory, manifest, document

    def test_the_manifest_carries_the_canonical_map_by_digest(self):
        directory, _, document = self.prepared()
        canonical = GENERATOR.build_canonical_inventory(directory)
        self.assertEqual(
            document["canonical_inventory_sha256"],
            hashlib.sha256(
                GENERATOR.canonical_inventory_bytes(canonical)
            ).hexdigest(),
        )
        self.assertEqual(canonical["digests"], document["member_sha256"])
        self.assertEqual(canonical["inventory"], document["inventory"])

    def test_the_gate_must_carry_the_manifest_canonical_map_digest(self):
        directory, manifest, _ = self.prepared()
        gate = self.gate(directory)
        gate["canonical_inventory_sha256"] = "f" * 64
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn("canonical inventory", str(raised.exception))

    def test_a_map_over_a_superset_of_the_sealed_inventory_is_refused(self):
        """Bidirectional: the map names nothing the sealed set does not hold.

        The gate's own asset inventory is wider than the sealed set by
        construction - the reviewed public assets are release assets that
        never become sealed dist members - so the map that has to match the
        sealed set exactly is the release-evidence map the manifest carries.
        """
        directory, manifest, _ = self.prepared()
        document = json.loads(Path(manifest).read_bytes())
        document["member_sha256"]["authority-v2-never-sealed.json"] = "a" * 64
        document["inventory"] = sorted(document["member_sha256"])
        Path(manifest).write_bytes(
            json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
        )
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=self.gate(directory), manifest=manifest,
            )
        self.assertIn("is not the canonical inventory", str(raised.exception))

    def test_a_map_that_omits_a_sealed_member_is_refused(self):
        directory, manifest, _ = self.prepared()
        document = json.loads(Path(manifest).read_bytes())
        dropped = sorted(document["member_sha256"])[0]
        document["member_sha256"].pop(dropped)
        document["inventory"] = sorted(document["member_sha256"])
        Path(manifest).write_bytes(
            json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
        )
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=self.gate(directory), manifest=manifest,
            )
        self.assertIn("is not the canonical inventory", str(raised.exception))

    def test_a_gate_whose_map_is_not_the_manifest_map_is_refused(self):
        """A digest the gate recorded that is not the byte stream is refused."""
        directory, manifest, document = self.prepared()
        name = sorted(document["member_sha256"])[0]
        gate = self.gate(directory)
        gate["asset_digests"][name] = "b" * 64
        with self.assertRaises(SystemExit) as raised:
            GENERATOR.seal_final_evidence(
                directory, gate=gate, manifest=manifest,
            )
        self.assertIn("changed after the publication gate",
                      str(raised.exception))

    def test_the_honest_shared_map_still_seals(self):
        directory, manifest, _ = self.prepared()
        emitted = GENERATOR.seal_final_evidence(
            directory, gate=self.gate(directory), manifest=manifest,
        )
        self.assertEqual(
            emitted["inventory"], sorted(FINAL_EVIDENCE_INVENTORY),
        )
        self.assertEqual(
            emitted["canonical_inventory_sha256"],
            json.loads(Path(manifest).read_bytes())[
                "canonical_inventory_sha256"
            ],
        )

    # -----------------------------------------------------------------------
    # F12-GATE-SUPERSET-NOT-BIDIRECTIONALLY-EQUAL-TO-SEAL
    #
    # The seal proved that every sealed member had been gated, and that the
    # gate *declared* the canonical map digest, but never that the gate's own
    # asset inventory really was that map. A gate that verified a fifteenth
    # member while still declaring the honest fourteen-member digest therefore
    # sealed happily: gate_inventory_count=15, sealed_inventory_count=14,
    # extra_gate_member_sealed=false.
    #
    # The map is now reconstructed from the gate's own names and digests and
    # required to be the map it declares, and the seal compares gate
    # inventory, manifest canonical map and observed sealed inventory in both
    # directions. Neither a superset nor a subset escapes.
    # -----------------------------------------------------------------------
    def cli_seal(self, directory, manifest_path, gate_document):
        """Seal through the unchanged production CLI, exactly as the lane does."""
        members = []
        for name in FINAL_EVIDENCE_INVENTORY:
            members += ["--final-evidence-member", name]
        gate = write_gate(
            Path(directory).parent / "verify-only-publication.json",
            gate_document,
        )
        return subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "build_authority_v2.py"),
             "--seal-final-evidence", str(directory),
             "--final-evidence-manifest", str(manifest_path),
             "--verify-only-result", str(gate), *members],
            capture_output=True, cwd=str(ROOT),
        )

    def cli_composed(self, directory, manifest_path):
        members = []
        for name in FINAL_EVIDENCE_INVENTORY:
            members += ["--final-evidence-member", name]
        composing = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "build_authority_v2.py"),
             "--emit-final-evidence-manifest", str(directory),
             "--final-evidence-manifest", str(manifest_path), *members],
            capture_output=True, cwd=str(ROOT),
        )
        self.assertEqual(composing.returncode, 0, composing.stderr.decode())
        return manifest_path

    def cli_prepared(self):
        directory = self.workflow_dist()
        manifest_path = self.cli_composed(
            directory,
            directory.parent / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME,
        )
        return directory, manifest_path

    def test_a_gate_over_a_superset_of_the_sealed_inventory_is_refused(self):
        """The exact reviewer reproduction, through the unchanged CLI."""
        directory, manifest_path = self.cli_prepared()
        honest = self.gate(directory)
        gate = dict(honest)
        # A fifteenth member the gate claims to have verified and the seal
        # never observes, while the declared map digest still describes the
        # honest fourteen.
        gate["asset_digests"] = {
            **honest["asset_digests"], "authority-v2-extra-gated.json": "c" * 64,
        }
        gate["inventory"] = sorted(gate["asset_digests"])
        gate["assets_verified"] = len(gate["inventory"])
        self.assertEqual(len(gate["inventory"]), 15)
        self.assertEqual(len(honest["inventory"]), 14)
        self.assertEqual(
            gate["canonical_inventory_sha256"],
            honest["canonical_inventory_sha256"],
        )
        observed = self.cli_seal(directory, manifest_path, gate)
        self.assertNotEqual(
            observed.returncode, 0,
            "the CLI sealed a fourteen-member inventory under a fifteen-member "
            "gate: " + observed.stdout.decode(),
        )
        self.assertIn("canonical inventory", observed.stderr.decode())
        # Nothing was made immutable by the refused run.
        self.assertNotEqual(
            oct(os.stat(directory).st_mode & 0o777), oct(0o555),
        )

    def test_a_gate_that_omits_a_sealed_member_is_refused(self):
        """The other direction: a gate narrower than the sealed inventory."""
        directory, manifest_path = self.cli_prepared()
        honest = self.gate(directory)
        gate = dict(honest)
        digests = dict(honest["asset_digests"])
        digests.pop(sorted(digests)[0])
        gate["asset_digests"] = digests
        gate["inventory"] = sorted(digests)
        gate["assets_verified"] = len(gate["inventory"])
        observed = self.cli_seal(directory, manifest_path, gate)
        self.assertNotEqual(
            observed.returncode, 0,
            "the CLI sealed a member the publication gate never verified: "
            + observed.stdout.decode(),
        )

    def test_a_gate_whose_declared_map_digest_is_reconstructed(self):
        """The declared digest must be the digest of the gate's own map."""
        directory, manifest_path = self.cli_prepared()
        gate = self.gate(directory)
        reconstructed = GENERATOR.canonical_inventory_sha256({
            "digests": dict(gate["asset_digests"]),
            "inventory": list(gate["inventory"]),
        })
        self.assertEqual(gate["canonical_inventory_sha256"], reconstructed)
        observed = self.cli_seal(directory, manifest_path, gate)
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())
        emitted = json.loads(observed.stdout)
        self.assertIs(emitted["sealed"], True)
        self.assertEqual(
            emitted["final_evidence"]["canonical_inventory_sha256"],
            reconstructed,
        )
        self.assertEqual(
            sorted(emitted["final_evidence"]["inventory"]),
            sorted(FINAL_EVIDENCE_INVENTORY),
        )


# ---------------------------------------------------------------------------
# F12-CANONICAL-INVENTORY-NOT-COMPLETE
#
# The last non-mutating gate verified all fourteen release assets, but the one
# canonical map - and therefore the final evidence manifest and the seal -
# covered only the eight release-evidence members. Six gated assets were never
# made immutable at all:
#
#   authority-v2-policy.json               github-environment-v2-contract.json
#   authority-v2-subject.schema.json       preissuance-review-receipt.json
#   protected-asset-receipt-v2.json        preissuance-review-receipt.sigstore.json
#
# The sealed inventory is now the complete fourteen-asset release inventory,
# and the release checksum manifest keeps enumerating exactly the seven signed
# release-evidence members the unchanged production release verifier
# recomputes byte for byte.
# ---------------------------------------------------------------------------
COMPLETE_RELEASE_INVENTORY = FINAL_EVIDENCE_INVENTORY
GATED_BUT_NEVER_SEALED = (
    "authority-v2-policy.json",
    "authority-v2-subject.schema.json",
    "github-environment-v2-contract.json",
    "preissuance-review-receipt.json",
    "preissuance-review-receipt.sigstore.json",
    "protected-asset-receipt-v2.json",
)


class CompleteSealedInventoryTests(unittest.TestCase):
    """Everything the gate verified is sealed; nothing gated stays mutable."""

    force_remove = staticmethod(FinalEvidenceSealingTests.force_remove)

    complete_dist = FinalEvidenceSealingTests.workflow_dist

    def gate(self, directory, **overrides):
        digests = directory_digests(directory, COMPLETE_RELEASE_INVENTORY)
        return verify_only_gate_document(
            digests,
            canonical_inventory_sha256=GENERATOR.canonical_inventory_sha256({
                "digests": digests, "inventory": sorted(digests),
            }),
            **overrides,
        )

    def composed(self, directory):
        return GENERATOR.write_final_evidence_manifest(
            Path(directory).parent / GENERATOR.FINAL_EVIDENCE_MANIFEST_NAME,
            directory, expected=COMPLETE_RELEASE_INVENTORY,
        )

    def test_the_complete_fourteen_asset_inventory_seals(self):
        self.assertEqual(len(COMPLETE_RELEASE_INVENTORY), 14)
        self.assertEqual(
            sorted(GENERATOR.SEALED_PUBLIC_ASSET_NAMES),
            sorted(GATED_BUT_NEVER_SEALED),
        )
        directory = self.complete_dist()
        manifest = self.composed(directory)
        emitted = GENERATOR.seal_final_evidence(
            directory, expected=COMPLETE_RELEASE_INVENTORY,
            gate=self.gate(directory), manifest=manifest,
        )
        sealed = [entry["name"] for entry in emitted["sealing"]["entries"]]
        self.assertEqual(sealed, sorted(COMPLETE_RELEASE_INVENTORY))
        self.assertEqual(sorted(emitted["member_sha256"]), sealed)
        for name in GENERATOR.SEALED_PUBLIC_ASSET_NAMES:
            self.assertIn(name, sealed, name)
            self.assertEqual(
                oct(os.stat(directory / name).st_mode & 0o777), oct(0o444),
                name,
            )

    def test_the_release_manifest_still_enumerates_only_signed_evidence(self):
        """The production release verifier's own byte stream is unchanged."""
        directory = self.complete_dist()
        listed = GENERATOR._release_checksum_inventory(
            directory, sorted(COMPLETE_RELEASE_INVENTORY),
        )
        self.assertEqual(
            sorted(listed), sorted(VERIFIER.release_evidence_inventory()),
        )

    def test_a_public_release_asset_missing_from_the_sealed_set_is_refused(self):
        """Never a subset: a gated asset that is not sealed fails closed."""
        for name in GENERATOR.SEALED_PUBLIC_ASSET_NAMES:
            directory = self.complete_dist()
            manifest = self.composed(directory)
            gate = self.gate(directory)
            (directory / name).unlink()
            with self.assertRaises(SystemExit) as raised:
                GENERATOR.seal_final_evidence(
                    directory, gate=gate, manifest=manifest,
                )
            self.assertIn("release checksum manifest", str(raised.exception),
                          name)

    def test_the_workflow_seals_every_asset_its_gate_verifies(self):
        """The production workflow wires the complete map end to end."""
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text(encoding="utf-8")
        seal = workflow.split("--seal-final-evidence", 1)[1]
        sealed = sorted(
            line.split("--final-evidence-member", 1)[1].strip().rstrip(" \\")
            for line in seal.splitlines()
            if "--final-evidence-member" in line
        )
        self.assertEqual(sealed, sorted(COMPLETE_RELEASE_INVENTORY))
        # ... and the gate really verified exactly those fourteen names.
        gated = sorted(set(
            fragment.split("=", 1)[0]
            for fragment in workflow.split("--asset ")[1:]
        ))
        self.assertEqual(gated, sorted(COMPLETE_RELEASE_INVENTORY))
