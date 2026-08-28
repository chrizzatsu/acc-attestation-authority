#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from unittest import mock

from tests.issuance_fixture import authenticated_issuance

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_module("verify_authority_v2_f8_f12", ROOT / "scripts" / "verify_authority_v2.py")

OFFICIAL_COSIGN_V3_1_3_LINUX_AMD64_OUTPUT = (
    '{"gitVersion":"v3.1.3","gitCommit":"11926fa5bbbbde47e88fc006b625a17769b743b2",'
    '"gitTreeState":"clean","buildDate":"2026-08-05T23:43:27Z","goVersion":"go1.26.4",'
    '"compiler":"gc","platform":"linux/amd64"}'
)


def git(root, *args, input_bytes=None):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_bytes,
        check=True,
        capture_output=True,
    ).stdout



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


class CandidateRepositoryTests(unittest.TestCase):
    def make_repository(self, root):
        git(root, "init", "-q")
        git(root, "config", "user.email", "fixture@example.invalid")
        git(root, "config", "user.name", "Fixture")
        git(root, "remote", "add", "origin", "https://github.com/chrizzatsu/acc-attestation-authority.git")
        (root / "delete.txt").write_text("delete\n", encoding="utf-8")
        (root / "modify.txt").write_text("before\n", encoding="utf-8")
        (root / "old-name.txt").write_text("rename me\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "base")
        base = git(root, "rev-parse", "HEAD").decode().strip()

        (root / "delete.txt").unlink()
        (root / "modify.txt").write_text("after\n", encoding="utf-8")
        (root / "old-name.txt").rename(root / "new-name.txt")
        (root / "binary.bin").write_bytes(b"\x00\xffbinary\n")
        for name in (
            "authority-v2-policy.json",
            "schemas/authority-v2-subject.schema.json",
            "protected-asset-receipt-v2.json",
            "reviewer-authorization-v2.json",
            "AUTHORITY-V2-SHA256SUMS",
        ):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + "\n", encoding="utf-8")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "candidate")
        head = git(root, "rev-parse", "HEAD").decode().strip()
        return base, head

    def test_canonical_diff_bytes_are_exact_prescribed_git_stdout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_repository(root)
            env = dict(os.environ, LC_ALL="C")
            expected = subprocess.run(
                [
                    "git", "-C", str(root), "diff", "--binary", "--full-index",
                    "--no-ext-diff", "--no-abbrev", "--find-renames=50%", "--src-prefix=a/",
                    "--dst-prefix=b/", base, head, "--",
                ],
                check=True,
                capture_output=True,
                env=env,
            ).stdout
            observed = VERIFIER.canonical_diff_bytes(root, base, head)
            self.assertEqual(observed, expected)
            self.assertEqual(
                VERIFIER.recompute_candidate_bindings(root, base, head)["canonical_diff_sha256"],
                hashlib.sha256(expected).hexdigest(),
            )

    def test_git_recomputation_covers_add_modify_delete_rename_modes_oids_and_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base, head = self.make_repository(root)
            candidate = VERIFIER.recompute_candidate_bindings(root, base, head)
            self.assertEqual(candidate["repository"], "chrizzatsu/acc-attestation-authority")
            self.assertEqual(candidate["base_commit"], base)
            self.assertEqual(candidate["head_commit"], head)
            self.assertEqual(candidate["sole_parent"], base)
            self.assertRegex(candidate["base_tree"], r"^[0-9a-f]{40}$")
            self.assertRegex(candidate["head_tree"], r"^[0-9a-f]{40}$")
            self.assertEqual(candidate["internal_manifest"], "AUTHORITY-V2-SHA256SUMS\n")
            by_status = {entry["status"]: entry for entry in candidate["changed_path_manifest"] if entry["status"] != "A"}
            self.assertEqual(set(by_status), {"M", "D", "R"})
            self.assertEqual(by_status["R"]["old_path"], "old-name.txt")
            self.assertEqual(by_status["R"]["new_path"], "new-name.txt")
            self.assertEqual(by_status["R"]["similarity"], 100)
            self.assertIsNone(by_status["D"]["new_blob_oid"])
            self.assertIsNone(by_status["D"]["new_sha256"])
            self.assertIsNone(next(e for e in candidate["changed_path_manifest"] if e["new_path"] == "binary.bin")["old_sha256"])
            for entry in candidate["changed_path_manifest"]:
                self.assertEqual(set(entry), {
                    "status", "similarity", "old_path", "new_path", "old_mode",
                    "new_mode", "old_blob_oid", "new_blob_oid", "old_sha256", "new_sha256",
                })
            names = {
                path
                for entry in candidate["changed_path_manifest"]
                for path in (entry["old_path"], entry["new_path"])
                if path is not None
            }
            self.assertIn("AUTHORITY-V2-SHA256SUMS", names)

    def test_recomputation_rejects_dirty_wrong_head_wrong_parent_and_wrong_remote(self):
        mutations = ("dirty", "wrong-head", "wrong-parent", "wrong-remote")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                base, head = self.make_repository(root)
                requested_head = head
                if mutation == "dirty":
                    (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
                elif mutation == "wrong-head":
                    requested_head = base
                elif mutation == "wrong-parent":
                    base = "0" * 40
                else:
                    git(root, "remote", "set-url", "origin", "https://github.com/example/wrong.git")
                with self.assertRaises(SystemExit):
                    VERIFIER.recompute_candidate_bindings(root, base, requested_head)

    def test_candidate_manifest_rejects_crlf_and_missing_final_lf_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            names = ("first.txt", "second.txt")
            for name in names:
                (root / name).write_bytes((name + "\n").encode("utf-8"))
            canonical_manifest = b"".join(
                f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n".encode("ascii")
                for name in names
            )
            manifest = root / "SHA256SUMS"
            with mock.patch.object(VERIFIER, "ROOT", root):
                manifest.write_bytes(canonical_manifest)
                VERIFIER.verify_manifest(manifest, names)
                for changed in (
                    canonical_manifest.replace(b"\n", b"\r\n"),
                    canonical_manifest.removesuffix(b"\n"),
                ):
                    manifest.write_bytes(changed)
                    with self.assertRaises(SystemExit):
                        VERIFIER.verify_manifest(manifest, names)

    def test_candidate_tree_tracks_no_compiled_python_artifacts(self):
        raw = git(ROOT, "ls-files", "-s", "-z", "--full-name")
        tracked = []
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            meta, _, path_raw = entry.partition(b"\t")
            _mode, _oid, stage = meta.split(b" ")
            self.assertEqual(stage, b"0", "candidate tree carries an unmerged entry")
            tracked.append(path_raw.decode("utf-8"))
        offending = sorted(
            path
            for path in tracked
            if path.endswith(".pyc") or "__pycache__" in PurePosixPath(path).parts
        )
        self.assertEqual(
            offending,
            [],
            "candidate tree tracks generated Python bytecode: " + ", ".join(offending),
        )


class CosignBoundaryTests(unittest.TestCase):
    def make_cosign_with_version_output(self, root, version_output):
        path = root / "cosign-version-fixture"
        script = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"VERSION_OUTPUT = {version_output!r}\n"
            "if sys.argv[1:] == ['version', '--json']:\n"
            "    sys.stdout.write(VERSION_OUTPUT); sys.exit(0)\n"
            "sys.exit(0)\n"
        )
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
        return path

    def make_cosign(self, root, verify_body="sys.exit(0)"):
        path = root / "cosign"
        version = {
            "gitVersion": "v3.1.3",
            "gitCommit": VERIFIER.EXPECTED_COSIGN_BUILD["gitCommit"],
            "gitTreeState": VERIFIER.EXPECTED_COSIGN_BUILD["gitTreeState"],
            "buildDate": VERIFIER.EXPECTED_COSIGN_BUILD["buildDate"],
            "goVersion": VERIFIER.EXPECTED_COSIGN_BUILD["goVersion"],
            "compiler": "gc",
            "platform": VERIFIER.current_cosign_platform(),
        }
        script = (
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            f"VERSION = {version!r}\n"
            "if sys.argv[1:] == ['version', '--json']:\n"
            "    print(json.dumps(VERSION)); sys.exit(0)\n"
            + verify_body + "\n"
        )
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
        return path

    def approve_fixture(self, path):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return mock.patch.dict(VERIFIER.APPROVED_COSIGN_DIGESTS, {VERIFIER.current_cosign_platform(): digest}, clear=True)

    def valid_bundle_bytes(self):
        """The real Cosign v3.1.3 protobuf-JSON v0.3 shape, minimally filled."""
        payload = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(
                        hashlib.sha256(b"subject").digest()
                    ).decode("ascii"),
                },
                "signature": base64.b64encode(b"signature").decode("ascii"),
            },
            "verificationMaterial": {
                "certificate": {"rawBytes": "Y2VydA=="},
                "tlogEntries": [{
                    "integratedTime": "1787620000", "logIndex": "42",
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
                    },
                }],
            },
        }
        return json.dumps(payload, separators=(",", ":")).encode()

    def test_official_linux_amd64_build_identity_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            executable = self.make_cosign_with_version_output(
                Path(td), OFFICIAL_COSIGN_V3_1_3_LINUX_AMD64_OUTPUT
            )
            approved_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            with (
                mock.patch.object(VERIFIER.platform, "system", return_value="Linux"),
                mock.patch.object(VERIFIER.platform, "machine", return_value="x86_64"),
                mock.patch.dict(
                    VERIFIER.APPROVED_COSIGN_DIGESTS,
                    {"linux/amd64": approved_digest},
                    clear=True,
                ),
            ):
                self.assertEqual(VERIFIER.validate_cosign_binary(executable), executable)

    def test_verified_cosign_object_can_cross_the_integrated_publication_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            executable = self.make_cosign(Path(td))
            with self.approve_fixture(executable):
                verified = VERIFIER.validate_cosign_binary(executable)
                try:
                    self.assertIs(VERIFIER.validate_cosign_binary(verified), verified)
                finally:
                    verified.close()

    def test_darwin_arm64_requires_exact_platform_with_official_shared_build(self):
        darwin_output = OFFICIAL_COSIGN_V3_1_3_LINUX_AMD64_OUTPUT.replace(
            '"platform":"linux/amd64"', '"platform":"darwin/arm64"'
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with (
                mock.patch.object(VERIFIER.platform, "system", return_value="Darwin"),
                mock.patch.object(VERIFIER.platform, "machine", return_value="arm64"),
            ):
                exact = self.make_cosign_with_version_output(root, darwin_output)
                exact_digest = hashlib.sha256(exact.read_bytes()).hexdigest()
                with mock.patch.dict(
                    VERIFIER.APPROVED_COSIGN_DIGESTS,
                    {"darwin/arm64": exact_digest},
                    clear=True,
                ):
                    self.assertEqual(VERIFIER.validate_cosign_binary(exact), exact)

                wrong = self.make_cosign_with_version_output(
                    root, OFFICIAL_COSIGN_V3_1_3_LINUX_AMD64_OUTPUT
                )
                wrong_digest = hashlib.sha256(wrong.read_bytes()).hexdigest()
                with (
                    mock.patch.dict(
                        VERIFIER.APPROVED_COSIGN_DIGESTS,
                        {"darwin/arm64": wrong_digest},
                        clear=True,
                    ),
                    self.assertRaises(SystemExit),
                ):
                    VERIFIER.validate_cosign_binary(wrong)

    def test_wrong_digest_and_original_symlink_are_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "executed"
            executable = self.make_cosign(root, f"pathlib.Path({str(marker)!r}).write_text('yes'); sys.exit(0)")
            with self.assertRaises(SystemExit):
                VERIFIER.validate_cosign_binary(executable)
            self.assertFalse(marker.exists())
            link = root / "cosign-link"
            link.symlink_to(executable)
            with self.approve_fixture(executable), self.assertRaises(SystemExit):
                VERIFIER.validate_cosign_binary(link)
            self.assertFalse(marker.exists())

    def test_digest_approved_fixture_still_requires_exact_closed_build_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            expected = dict(VERIFIER.EXPECTED_COSIGN_BUILD, platform=VERIFIER.current_cosign_platform())
            mutations = {
                "version": dict(expected, gitVersion="v3.1.2"),
                "commit": dict(expected, gitCommit="0" * 40),
                "extra-field": dict(expected, selfReported=True),
            }
            for name, version in mutations.items():
                with self.subTest(name=name):
                    executable = self.make_cosign_with_version_output(root, json.dumps(version))
                    with self.approve_fixture(executable), self.assertRaises(SystemExit):
                        VERIFIER.validate_cosign_binary(executable)

    def test_validated_cosign_uses_private_snapshot_after_original_inode_replacement_between_invocations(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = self.make_cosign(root)
            subject, bundle = root / "subject.json", root / "bundle.json"
            marker = root / "replacement-executed"
            subject.write_bytes(b'{}\n')
            bundle.write_bytes(self.valid_bundle_bytes())
            with self.approve_fixture(original):
                validated = VERIFIER.validate_cosign_binary(original)
                try:
                    VERIFIER._execute_cosign(validated, subject, bundle, "a" * 40)
                    replacement = root / "replacement"
                    replacement.write_text(
                        "#!/usr/bin/env python3\n"
                        "import pathlib, sys\n"
                        f"pathlib.Path({str(marker)!r}).write_text('executed')\n"
                        "sys.exit(0)\n",
                        encoding="utf-8",
                    )
                    replacement.chmod(0o755)
                    os.replace(replacement, original)
                    VERIFIER._execute_cosign(validated, subject, bundle, "a" * 40)
                finally:
                    close = getattr(validated, "close", None)
                    if close is not None:
                        close()
            self.assertFalse(marker.exists())

    def test_cosign_symlink_swap_at_execute_boundary_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = self.make_cosign(root)
            subject = root / "subject.json"
            bundle = root / "bundle.json"
            marker = root / "symlink-target-executed"
            subject.write_bytes(b'{}\n')
            bundle.write_bytes(self.valid_bundle_bytes())
            target = root / "target"
            target.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                f"pathlib.Path({str(marker)!r}).write_text('executed')\n"
                "sys.exit(0)\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            with self.approve_fixture(original):
                validated = VERIFIER.validate_cosign_binary(original)
                try:
                    execution_path = getattr(validated, "path", validated)
                    try:
                        execution_path.unlink()
                        execution_path.symlink_to(target)
                    except OSError:
                        self.assertEqual(platform.system(), "Darwin")
                    else:
                        with self.assertRaises(SystemExit):
                            VERIFIER._execute_cosign(validated, subject, bundle, "a" * 40)
                finally:
                    close = getattr(validated, "close", None)
                    if close is not None:
                        close()
            self.assertFalse(marker.exists())

    def test_cosign_regular_inode_swap_between_open_and_execute_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = self.make_cosign(root)
            subject, bundle = root / "subject.json", root / "bundle.json"
            marker = root / "replacement-executed"
            subject.write_bytes(b'{}\n')
            bundle.write_bytes(self.valid_bundle_bytes())
            with self.approve_fixture(original):
                validated = VERIFIER.validate_cosign_binary(original)
                try:
                    real_run = subprocess.run
                    def swap_then_run(*arguments, **options):
                        replacement = root / "replacement"
                        replacement.write_text(
                            "#!/usr/bin/env python3\n"
                            "import pathlib, sys\n"
                            f"pathlib.Path({str(marker)!r}).write_text('executed')\n"
                            "sys.exit(0)\n",
                            encoding="utf-8",
                        )
                        replacement.chmod(0o755)
                        os.replace(replacement, validated.path)
                        return real_run(*arguments, **options)
                    with mock.patch.object(VERIFIER.subprocess, "run", side_effect=swap_then_run), self.assertRaises(SystemExit):
                        VERIFIER._execute_cosign(validated, subject, bundle, "a" * 40)
                finally:
                    validated.close()
            self.assertFalse(marker.exists())

    def test_signing_workflow_uses_one_verified_snapshot_across_all_invocations(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subject_dir = root / "subjects"
            subject_dir.mkdir()
            original = root / "cosign"
            marker = root / "replacement-executed"
            counter = root / "counter"
            bundle = self.valid_bundle_bytes()
            version = dict(VERIFIER.EXPECTED_COSIGN_BUILD, platform=VERIFIER.current_cosign_platform())
            original.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                f"VERSION = {version!r}\n"
                f"ORIGINAL = pathlib.Path({str(original)!r})\n"
                f"COUNTER = pathlib.Path({str(counter)!r})\n"
                f"BUNDLE = {bundle!r}\n"
                "if sys.argv[1:] == ['version', '--json']:\n"
                "    print(json.dumps(VERSION)); sys.exit(0)\n"
                "assert sys.argv[1] == 'sign-blob' and '--key' not in sys.argv\n"
                "bundle_path = pathlib.Path(sys.argv[sys.argv.index('--bundle') + 1])\n"
                "bundle_path.write_bytes(BUNDLE)\n"
                "count = int(COUNTER.read_text()) + 1 if COUNTER.exists() else 1\n"
                "COUNTER.write_text(str(count))\n"
                "if count == 1:\n"
                "    replacement = ORIGINAL.with_name('replacement')\n"
                "    replacement.write_text('#!/usr/bin/env python3\\nimport pathlib\\n' + "
                f"f\"pathlib.Path({str(marker)!r}).write_text('executed')\\n\")\n"
                "    replacement.chmod(0o755); os.replace(replacement, ORIGINAL)\n"
                "sys.exit(0)\n",
                encoding="utf-8",
            )
            original.chmod(0o755)
            issuance = authenticated_issuance()
            policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
            for case in VERIFIER.EXPECTED_CASES:
                subject = VERIFIER.expected_subject(
                    policy, case, issuance.candidate_head,
                    issuance.review_receipt_sha256, issuance,
                )
                (subject_dir / f"authority-v2-{case}.json").write_bytes(
                    VERIFIER.canonical(subject)
                )
            receipt = root / "receipt.json"
            receipt.write_bytes(b"{}\n")
            receipt_bundle = root / "receipt.sigstore.json"
            receipt_bundle.write_bytes(b"{}\n")
            envelope = root / "kanban-review-envelope.json"
            envelope.write_bytes(b"{}\n")
            issuance_path = root / "issuance.json"
            issuance_path.write_bytes(issuance.data)
            with (
                self.approve_fixture(original),
                mock.patch.object(VERIFIER, "verify_candidate", return_value=(policy, 1)),
                mock.patch.object(VERIFIER, "recompute_review_bindings", return_value={
                    "candidate": {}, "protected_identity_asset": {},
                }),
                mock.patch.object(VERIFIER, "authenticate_github_issuance", return_value=issuance),
                mock.patch.object(VERIFIER, "_authenticate_review_receipt_with_cosign"),
                mock.patch.object(VERIFIER, "validate_preissuance_receipt_bytes", return_value={}),
            ):
                with self.assertRaises(SystemExit):
                    VERIFIER.sign_subjects(
                        subject_dir, original, issuance.candidate_head,
                        receipt, issuance.review_receipt_sha256, receipt_bundle,
                        issuance_path, issuance.sha256,
                    )
                generated = VERIFIER.sign_subjects(
                    subject_dir, original, issuance.candidate_head,
                    receipt, issuance.review_receipt_sha256, receipt_bundle,
                    issuance_path, issuance.sha256,
                    review_envelope_path=envelope,
                )
            self.assertEqual(counter.read_text(), "3")
            self.assertFalse(marker.exists())
            self.assertEqual(
                [path.name for path in generated],
                [f"authority-v2-{case}.sigstore.json" for case in VERIFIER.EXPECTED_CASES],
            )
            self.assertTrue(all(path.read_bytes() == bundle for path in generated))

    def test_actual_controlled_cosign_execution_requires_every_exact_github_claim(self):
        expected = {
            "--certificate-identity": VERIFIER.EXPECTED_IDENTITY,
            "--certificate-oidc-issuer": VERIFIER.EXPECTED_ISSUER,
            "--certificate-github-workflow-repository": VERIFIER.EXPECTED_REPOSITORY,
            "--certificate-github-workflow-ref": "refs/heads/main",
            "--certificate-github-workflow-sha": "a" * 40,
            "--certificate-github-workflow-trigger": "workflow_dispatch",
        }
        checks = "; ".join(
            f"assert sys.argv[sys.argv.index({flag!r}) + 1] == {value!r}"
            for flag, value in expected.items()
        )
        verify_body = (
            "assert sys.argv[1] == 'verify-blob'; "
            "assert '--key' not in sys.argv and '--certificate' not in sys.argv; "
            "assert not any(key.startswith(('COSIGN_', 'SIGSTORE_')) for key in os.environ); "
            f"{checks}; sys.exit(0)"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cosign = self.make_cosign(root, verify_body)
            subject = root / "subject.json"
            bundle = root / "bundle.json"
            subject.write_bytes(b'{}\n')
            bundle.write_bytes(self.valid_bundle_bytes())
            with self.approve_fixture(cosign), mock.patch.dict(os.environ, {"COSIGN_PRIVATE_KEY": "forbidden", "SIGSTORE_TEST_OVERRIDE": "forbidden"}):
                VERIFIER.verify_cosign_pair(subject, bundle, cosign, "a" * 40)
                mutations = {
                    "repository": ("EXPECTED_REPOSITORY", "example/wrong"),
                    "ref": ("EXPECTED_GIT_REF", "refs/heads/other"),
                    "trigger": ("EXPECTED_TRIGGER", "push"),
                    "identity": ("EXPECTED_IDENTITY", "https://example.invalid/wrong"),
                    "issuer": ("EXPECTED_ISSUER", "https://example.invalid"),
                }
                for name, (attribute, value) in mutations.items():
                    with self.subTest(name=name), mock.patch.object(VERIFIER, attribute, value, create=True), self.assertRaises(SystemExit):
                        VERIFIER.verify_cosign_pair(subject, bundle, cosign, "a" * 40)
                with self.subTest(name="sha"), self.assertRaises(SystemExit):
                    VERIFIER.verify_cosign_pair(subject, bundle, cosign, "b" * 40)

    def test_bundle_swap_during_verification_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subject = root / "subject.json"
            bundle = root / "bundle.json"
            subject.write_bytes(b'{}\n')
            bundle.write_bytes(self.valid_bundle_bytes())
            verify_body = (
                f"pathlib.Path({str(bundle)!r}).write_bytes(b'swapped'); sys.exit(0)"
            )
            cosign = self.make_cosign(root, verify_body)
            with self.approve_fixture(cosign), self.assertRaises(SystemExit):
                VERIFIER.verify_cosign_pair(subject, bundle, cosign, "a" * 40)

    def test_private_snapshot_swap_during_verification_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subject = root / "subject.json"
            bundle = root / "bundle.json"
            subject.write_bytes(b'{}\n')
            bundle.write_bytes(self.valid_bundle_bytes())
            verify_body = (
                "snapshot = pathlib.Path(sys.argv[sys.argv.index('--bundle') + 1]); "
                "os.chmod(snapshot, 0o600); snapshot.write_bytes(b'swapped'); sys.exit(0)"
            )
            cosign = self.make_cosign(root, verify_body)
            with self.approve_fixture(cosign), self.assertRaises(SystemExit):
                VERIFIER.verify_cosign_pair(subject, bundle, cosign, "a" * 40)


class ReleaseArtifactBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        self.activation = "a" * 40
        self.receipt_hash = "b" * 64
        self.issuance = authenticated_issuance(head=self.activation, review_receipt_sha256=self.receipt_hash)

    def write_release(self, root):
        names = []
        for index, case in enumerate(VERIFIER.EXPECTED_CASES):
            subject_name = f"authority-v2-{case}.json"
            bundle_name = f"authority-v2-{case}.sigstore.json"
            subject = VERIFIER.expected_subject(self.policy, case, self.activation, self.receipt_hash, self.issuance)
            (root / subject_name).write_bytes(VERIFIER.canonical(subject))
            bundle = {"fixture_case": case, "fixture_index": index}
            (root / bundle_name).write_bytes(json.dumps(bundle, sort_keys=True).encode())
            names.extend((subject_name, bundle_name))
        lines = [
            f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}"
            for name in names
        ]
        (root / "AUTHORITY-V2-RELEASE-SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return names

    def rewrite_manifest(self, root, names):
        lines = [f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}" for name in names]
        (root / "AUTHORITY-V2-RELEASE-SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def verify(self, root):
        trusted = datetime(2026, 8, 25, tzinfo=timezone.utc)

        def verify_pair(subject, bundle, _cosign, _activation):
            payload = json.loads(subject.data)
            evidence = json.loads(bundle.data)
            if evidence.get("fixture_case") != payload.get("case"):
                raise SystemExit("fixture signature does not bind this subject")
            return trusted

        with (
            mock.patch.object(VERIFIER, "verify_candidate", return_value=(self.policy, 1)),
            mock.patch.object(VERIFIER, "verify_preissuance_receipt", return_value={}),
            mock.patch.object(VERIFIER, "validate_cosign_binary", return_value=Path("/approved/cosign")),
            mock.patch.object(VERIFIER, "_verify_bound_cosign_pair", side_effect=verify_pair),
        ):
            return VERIFIER.verify_release(root, self.activation, root / "receipt", self.receipt_hash, "/approved/cosign", self.issuance)

    def test_release_verifier_rejects_missing_extra_modified_and_swapped_subjects_and_bundles(self):
        mutations = (
            "missing-subject", "missing-bundle", "extra-subject", "extra-bundle",
            "modified-subject", "modified-bundle", "swapped-subjects", "swapped-bundles",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                names = self.write_release(root)
                if mutation == "missing-subject":
                    (root / "authority-v2-future.json").unlink()
                elif mutation == "missing-bundle":
                    (root / "authority-v2-future.sigstore.json").unlink()
                elif mutation == "extra-subject":
                    (root / "authority-v2-extra.json").write_bytes(b"{}")
                elif mutation == "extra-bundle":
                    (root / "authority-v2-extra.sigstore.json").write_bytes(b"{}")
                elif mutation == "modified-subject":
                    (root / "authority-v2-future.json").write_bytes(b"{}\n")
                elif mutation == "modified-bundle":
                    (root / "authority-v2-future.sigstore.json").write_bytes(b'{"fixture_case":"stale"}')
                elif mutation == "swapped-subjects":
                    first = root / "authority-v2-future.json"
                    second = root / "authority-v2-stale.json"
                    first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
                    first.write_bytes(second_bytes)
                    second.write_bytes(first_bytes)
                else:
                    first = root / "authority-v2-future.sigstore.json"
                    second = root / "authority-v2-stale.sigstore.json"
                    first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
                    first.write_bytes(second_bytes)
                    second.write_bytes(first_bytes)
                if not mutation.startswith(("missing", "extra")):
                    self.rewrite_manifest(root, names)
                with self.assertRaises(SystemExit):
                    self.verify(root)

    def test_release_manifest_rejects_crlf_and_missing_final_lf_bytes(self):
        for mutation in ("crlf", "missing-final-lf"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                self.write_release(root)
                manifest = root / "AUTHORITY-V2-RELEASE-SHA256SUMS"
                original = manifest.read_bytes()
                manifest.write_bytes(
                    original.replace(b"\n", b"\r\n")
                    if mutation == "crlf"
                    else original.removesuffix(b"\n")
                )
                with self.assertRaises(SystemExit):
                    self.verify(root)

    def test_release_boundary_rejects_every_alternate_subject_binding(self):
        mutations = {
            "repository": lambda payload: payload["workflow_evidence"].update(repository="example/wrong"),
            "workflow-ref": lambda payload: payload["workflow_evidence"].update(workflow_ref="example/wrong/.github/workflows/wrong.yml@refs/heads/main"),
            "git-ref": lambda payload: payload["workflow_evidence"].update(git_ref="refs/heads/other"),
            "trigger": lambda payload: payload["workflow_evidence"].update(event_name="push"),
            "workflow-sha": lambda payload: payload.update(reviewed_activation_sha="c" * 40),
            "policy": lambda payload: payload.update(authority_policy_sha256="d" * 64),
            "receipt": lambda payload: payload.update(preissuance_review_receipt_sha256="e" * 64),
            "case-contract": lambda payload: payload.update(case_contract=self.policy["temporal_subject_contract"]["cases"]["future"]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                names = self.write_release(root)
                subject_path = root / "authority-v2-stale.json"
                payload = json.loads(subject_path.read_bytes())
                mutate(payload)
                subject_path.write_bytes(VERIFIER.canonical(payload))
                self.rewrite_manifest(root, names)
                with self.assertRaises(SystemExit):
                    self.verify(root)

if __name__ == "__main__":
    unittest.main()
