#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
import urllib.parse
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


PUBLICATION = load_module("verify_publication_v2", ROOT / "scripts" / "verify_publication_v2.py")


class FixtureTransport:
    def __init__(
        self,
        responses,
        *,
        immutable_releases=None,
        ruleset_lists=None,
        ruleset_details=None,
        tag_ref_visibility=None,
    ):
        self.responses = list(responses)
        self.calls = []
        self.immutable_releases = immutable_releases or [
            response(200, {"enabled": True, "enforced_by_owner": False})
        ] * 3
        self.ruleset_lists = ruleset_lists or [response(200, [{"id": 37}])] * 3
        self.ruleset_details = ruleset_details or [
            response(200, exact_tag_ruleset(), etag='"ruleset-37"')
        ] * 3
        self.tag_ref_visibility = (
            tag_ref_visibility
            if tag_ref_visibility is not None
            else response(200, [{"ref": "refs/tags/unrelated-existing-tag"}])
        )

    def request(self, method, path, *, headers=None, body=None):
        self.calls.append((method, path, dict(headers or {}), body))
        immutable_path = (
            f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/immutable-releases"
        )
        rulesets_path = f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/rulesets"
        if method == "GET" and path.startswith(PUBLICATION.TAG_REF_VISIBILITY_PATH):
            if isinstance(self.tag_ref_visibility, Exception):
                raise self.tag_ref_visibility
            return self.tag_ref_visibility
        if method == "GET" and path == immutable_path:
            return self._next_guard(self.immutable_releases)
        if method == "GET" and path.startswith(f"{rulesets_path}?"):
            return self._next_guard(self.ruleset_lists)
        if method == "GET" and path.startswith(f"{rulesets_path}/"):
            return self._next_guard(self.ruleset_details)
        if not self.responses:
            raise AssertionError("unexpected transport call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    @staticmethod
    def _next_guard(responses):
        if not responses:
            raise AssertionError("unexpected repeated publication guard read")
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def response(status, payload=None, *, etag=None, body=None):
    headers = {} if etag is None else {"ETag": etag}
    encoded = body if body is not None else json.dumps(payload or {}).encode()
    return PUBLICATION.ApiResponse(status=status, headers=headers, body=encoded)


def exact_tag_ruleset(*, ruleset_id=37):
    return {
        "id": ruleset_id,
        "name": "Protect the exact Authority-v2 release tag",
        "target": "tag",
        "source_type": "Repository",
        "source": PUBLICATION.EXPECTED_REPOSITORY,
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {
                "include": [
                    f"refs/tags/{PUBLICATION.RELEASE_TAG}",
                    PUBLICATION.PUBLICATION_CLAIM_REF,
                ],
                "exclude": [],
            }
        },
        "rules": [
            {"type": "deletion"},
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": False},
            },
        ],
        "node_id": "RRS_exact_authority_v2_tag",
        "created_at": "2026-08-25T00:00:00Z",
        "updated_at": "2026-08-25T00:00:00Z",
    }


class PublicationTests(unittest.TestCase):
    """Read-only publication guard, readback and reconciliation behaviour."""

    def setUp(self):
        self.sha = "a" * 40
        self.assets = {"one.txt": b"one\n", "two.bin": b"\x00two"}
        self.issuance = authenticated_issuance(head=self.sha)

    def test_authenticated_issuance_cli_boundary_reads_one_exact_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "github-issuance.json"
            path.write_bytes(self.issuance.data)
            with mock.patch.object(PUBLICATION, "_read_asset", wraps=PUBLICATION._read_asset) as read_asset:
                observed = PUBLICATION._authenticate_issuance_asset(
                    path, self.issuance.sha256, self.sha,
                    self.issuance.review_receipt_sha256,
                )
            self.assertEqual(read_asset.call_count, 1)
            self.assertEqual(observed.sha256, self.issuance.sha256)

    def test_guard_reads_require_distinct_unconfusable_app_transport(self):
        immutable_path = (
            f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/immutable-releases"
        )
        read_backend = FixtureTransport(self.successful_responses())
        guard_backend = FixtureTransport([], immutable_releases=[response(403)])
        reader = PUBLICATION.PublicationReadTransport(read_backend)
        guards = PUBLICATION.AdministrationReadAppTransport(guard_backend)

        with self.assertRaises(SystemExit):
            self.reconcile_transport(reader, guard_transport=guards)

        self.assertEqual(read_backend.calls, [])
        self.assertEqual(guard_backend.calls[0][0:2], ("GET", immutable_path))
        with self.assertRaises(SystemExit):
            reader.request("GET", immutable_path)
        with self.assertRaises(SystemExit):
            reader.request("GET", f"{immutable_path}?confused=true")
        with self.assertRaises(SystemExit):
            guards.request(
                "GET",
                f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/rulesets?per_page=100",
            )
        with self.assertRaises(SystemExit):
            guards.request(
                "PATCH",
                f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/releases/7",
            )

        contract = json.loads((ROOT / "github-app-guard-v2-contract.json").read_bytes())
        self.assertEqual(contract["transport_role"], "administration-read-guards-only")
        self.assertEqual(contract["repository_selection"], [PUBLICATION.EXPECTED_REPOSITORY])
        self.assertEqual(contract["token_permissions"], {"administration": "read"})
        self.assertEqual(contract["activation_precondition"]["state"], "unavailable")
        self.assertTrue(contract["activation_precondition"]["no_fallback"])
        workflow = (
            ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml"
        ).read_text()
        self.assertIn(
            "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
            workflow,
        )
        self.assertIn("permission-administration: read", workflow)
        self.assertIn("GH_GUARD_APP_TOKEN: ${{ steps.guard-token.outputs.token }}", workflow)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)

    def release(self, *, draft, immutable=False, assets=None, target=None, release_id=7):
        asset_rows = []
        names = sorted(self.assets) if assets is None else sorted(assets)
        for index, name in enumerate(names, start=1):
            asset_rows.append({
                "id": index,
                "name": name,
                "size": len(self.assets.get(name, b"")),
                "url": f"https://api.github.com/repos/{PUBLICATION.EXPECTED_REPOSITORY}/releases/assets/{index}",
            })
        return {
            "id": release_id,
            "tag_name": PUBLICATION.RELEASE_TAG,
            "target_commitish": self.sha if target is None else target,
            "name": PUBLICATION.RELEASE_TITLE,
            "body": PUBLICATION.RELEASE_NOTES,
            "draft": draft,
            "prerelease": False,
            "immutable": immutable,
            "assets": asset_rows,
        }

    def successful_responses(self):
        """One exact published repository state, reconciled with reads only."""
        published = self.release(draft=False, immutable=True)
        downloads = [response(200, body=self.assets[name]) for name in sorted(self.assets)]
        return [
            response(200, [published]),
            response(200, published, etag='"release-7"'),
            response(404),
            response(200, {
                "ref": f"refs/tags/{PUBLICATION.RELEASE_TAG}",
                "object": {"type": "commit", "sha": self.sha},
            }),
            *downloads,
        ]

    def run_service(self, responses):
        transport = FixtureTransport(responses)
        result = self.reconcile_transport(transport)
        return result, transport

    def reconcile_transport(self, transport, assets=None, guard_transport=None, plan=None):
        selected_assets = self.assets if assets is None else assets
        read_transport = (
            transport
            if type(transport) is PUBLICATION.PublicationReadTransport
            else PUBLICATION.PublicationReadTransport(transport)
        )
        guard_transport = guard_transport or PUBLICATION.AdministrationReadAppTransport(
            transport
        )
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(selected_assets))
        ):
            bound = plan or PUBLICATION.bind_publication(self.sha, selected_assets)
            return PUBLICATION.PublicationService(
                read_transport, guard_transport,
            ).reconcile(self.issuance, bound)

    def test_published_state_is_reconciled_without_any_mutation(self):
        result, transport = self.run_service(self.successful_responses())
        self.assertEqual(result["publication_state"], "published")
        self.assertFalse(result["publication_available"])
        self.assertEqual(result["draft"]["id"], 7)
        self.assertTrue(result["draft"]["immutable"])
        self.assertEqual(result["final_tag"], {
            "ref": PUBLICATION.EXACT_TAG_REF, "target": self.sha,
        })
        self.assertEqual(result["writes_performed"], 0)
        self.assertTrue(all(call[0] == "GET" for call in transport.calls))
        full_ruleset_prefix = f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/rulesets/37?"
        self.assertTrue(any(
            call[0] == "GET" and call[1].startswith(full_ruleset_prefix)
            for call in transport.calls
        ))
        self.assertEqual(
            transport.calls[0][0:2],
            ("GET", f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/immutable-releases"),
        )

    def test_no_publication_mutation_exists_in_the_verifier_source(self):
        source = (ROOT / "scripts" / "verify_publication_v2.py").read_text()
        service = source.split("class PublicationService:", 1)[1]
        for forbidden in ('"POST"', '"PATCH"', '"PUT"', '"DELETE"'):
            self.assertNotIn(forbidden, service)
        self.assertIn("publication is unavailable", source)
        workflow = (ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text()
        self.assertIn("group: immutable-clerk-attestation-v2", workflow)
        self.assertIn("cancel-in-progress: false", workflow)

    def test_release_name_and_body_are_exact_on_every_readback(self):
        exact = self.release(draft=True, assets=[])
        exact.update(name=PUBLICATION.RELEASE_TITLE, body=PUBLICATION.RELEASE_NOTES)
        PUBLICATION._validate_release(
            exact, release_id=7, activation_sha=self.sha,
            draft=True, immutable=False, expected_names=(),
        )
        for field, value in (("name", "caller title"), ("body", "caller body")):
            changed = dict(exact, **{field: value})
            with self.subTest(field=field), self.assertRaises(SystemExit):
                PUBLICATION._validate_release(
                    changed, release_id=7, activation_sha=self.sha,
                    draft=True, immutable=False, expected_names=(),
                )
        for missing in ("name", "body"):
            changed = dict(exact)
            changed.pop(missing)
            with self.subTest(missing=missing), self.assertRaises(SystemExit):
                PUBLICATION._validate_release(
                    changed, release_id=7, activation_sha=self.sha,
                    draft=True, immutable=False, expected_names=(),
                )

    def test_claim_binding_is_durable_across_issuance_deserialization(self):
        candidate = {
            "head_commit": self.issuance.candidate_head,
            "head_tree": self.issuance.candidate_tree,
            "canonical_diff_sha256": self.issuance.canonical_diff_sha256,
            "review_receipt_sha256": self.issuance.review_receipt_sha256,
        }
        deserialized = PUBLICATION.AUTHORITY.GITHUB_ISSUANCE.verify_authenticated_issuance_bytes(
            self.issuance.data, self.issuance.sha256, candidate,
        )
        self.assertEqual(
            PUBLICATION._publication_claim_digest(self.issuance),
            PUBLICATION._publication_claim_digest(deserialized),
        )
        self.assertEqual(
            PUBLICATION.PUBLICATION_CLAIM_REF,
            "refs/tags/authority-v2-publication-claim",
        )
        self.assertFalse(
            hasattr(PUBLICATION.AUTHORITY.GITHUB_ISSUANCE, "_CONSUMED_TOKENS")
        )

    def test_immutable_releases_disabled_or_ambiguous_fails_closed(self):
        failures = [
            response(404),
            response(200, {"enabled": False, "enforced_by_owner": False}),
            response(200, {"enabled": True}),
            response(401),
            response(403),
            response(429),
            response(500),
            PUBLICATION.TransportError("ambiguous immutable-release readback"),
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                transport = FixtureTransport(
                    self.successful_responses(), immutable_releases=[failure]
                )
                with self.assertRaises(SystemExit):
                    self.reconcile_transport(transport)
                self.assertFalse(
                    any(call[0] != "GET" for call in transport.calls)
                )

    def test_exact_tag_ruleset_is_full_active_and_without_bypass(self):
        invalid_rulesets = {}
        mutations = {
            "inactive": lambda item: item.update(enforcement="evaluate"),
            "wrong-target": lambda item: item.update(target="branch"),
            "wrong-ref": lambda item: item["conditions"]["ref_name"].update(
                include=["refs/tags/other"]
            ),
            "excluded-ref": lambda item: item["conditions"]["ref_name"].update(
                exclude=[f"refs/tags/{PUBLICATION.RELEASE_TAG}"]
            ),
            "bypass-actor": lambda item: item.update(
                bypass_actors=[
                    {"actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"}
                ]
            ),
            "missing-update": lambda item: item.update(rules=[{"type": "deletion"}]),
            "missing-deletion": lambda item: item.update(
                rules=[
                    {
                        "type": "update",
                        "parameters": {"update_allows_fetch_and_merge": False},
                    }
                ]
            ),
        }
        for name, mutate in mutations.items():
            changed = deepcopy(exact_tag_ruleset())
            mutate(changed)
            invalid_rulesets[name] = response(200, changed, etag='"ruleset-37"')
        invalid_rulesets.update({
            "missing-etag": response(200, exact_tag_ruleset()),
            "weak-etag": response(200, exact_tag_ruleset(), etag='W/"ruleset-37"'),
        })

        for name, detail in invalid_rulesets.items():
            with self.subTest(name=name):
                transport = FixtureTransport(
                    self.successful_responses(), ruleset_details=[detail]
                )
                with self.assertRaises(SystemExit):
                    self.reconcile_transport(transport)
                self.assertFalse(any(call[0] != "GET" for call in transport.calls))

    def test_ruleset_auth_permission_rate_limit_network_and_ambiguous_reads_fail_closed(self):
        failures = [
            response(401),
            response(403),
            response(404),
            response(429),
            response(500),
            PUBLICATION.TransportError("ambiguous ruleset readback"),
        ]
        for stage in ("list", "full"):
            for failure in failures:
                with self.subTest(stage=stage, failure=failure):
                    options = (
                        {"ruleset_lists": [failure]}
                        if stage == "list"
                        else {"ruleset_details": [failure]}
                    )
                    transport = FixtureTransport(
                        self.successful_responses(), **options
                    )
                    with self.assertRaises(SystemExit):
                        self.reconcile_transport(transport)
                    self.assertFalse(any(call[0] != "GET" for call in transport.calls))

    def test_absent_or_ambiguous_tag_protection_fails_closed(self):
        transport = FixtureTransport(
            self.successful_responses(), ruleset_lists=[response(200, [])]
        )
        with self.assertRaises(SystemExit):
            self.reconcile_transport(transport)
        self.assertFalse(any(call[0] != "GET" for call in transport.calls))

    def test_only_literal_200_or_404_resolves_a_tag_ref(self):
        for status in (401, 403, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(SystemExit):
                self.run_service([response(200, []), response(status)])
        with self.assertRaises(SystemExit):
            self.run_service([response(200, []), PUBLICATION.TransportError("network")])
        with self.assertRaises(SystemExit):
            self.run_service([response(200, []), response(200, {"ref": "refs/tags/other"})])

    def test_release_listing_auth_permission_rate_limit_and_network_fail_closed(self):
        failures = [response(status) for status in (401, 403, 404, 429, 500)]
        failures.append(PUBLICATION.TransportError("network"))
        for failure in failures:
            with self.subTest(failure=failure), self.assertRaises(SystemExit):
                self.run_service([failure])

    def test_every_reconciled_asset_byte_is_hashed_against_the_bound_plan(self):
        base = self.successful_responses()
        for index in range(4, len(base)):
            with self.subTest(index=index), self.assertRaises(SystemExit):
                changed = list(base)
                changed[index] = response(200, body=b"modified")
                self.run_service(changed)

    def test_prebound_plan_uses_identical_bytes_after_caller_asset_swap(self):
        original = dict(self.assets)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(original))
        ):
            plan = PUBLICATION.bind_publication(self.sha, original)
        self.assets = {**original, "one.txt": b"swapped after binding"}
        transport = FixtureTransport([
            response(200, [self.release(draft=False, immutable=True, assets=sorted(original))]),
            response(200, self.release(draft=False, immutable=True, assets=sorted(original)), etag='"release-7"'),
            response(404),
            response(200, {
                "ref": f"refs/tags/{PUBLICATION.RELEASE_TAG}",
                "object": {"type": "commit", "sha": self.sha},
            }),
            *[response(200, body=original[name]) for name in sorted(original)],
        ])
        result = self.reconcile_transport(transport, assets=original, plan=plan)
        self.assertEqual(result["draft"]["assets"], {
            name: hashlib.sha256(data).hexdigest() for name, data in original.items()
        })

    def test_tag_drift_and_wrong_release_state_are_detected(self):
        base = self.successful_responses()
        mutations = {
            "wrong-tag-target": (3, response(200, {
                "ref": f"refs/tags/{PUBLICATION.RELEASE_TAG}",
                "object": {"type": "commit", "sha": "b" * 40},
            })),
            "wrong-id": (1, response(200, self.release(
                draft=False, immutable=True, release_id=8), etag='"post"')),
            "wrong-target": (1, response(200, self.release(
                draft=False, immutable=True, target="b" * 40), etag='"post"')),
            "extra-asset": (1, response(200, self.release(
                draft=False, immutable=True,
                assets=["attacker.bin", *sorted(self.assets)]), etag='"post"')),
            "missing-etag": (1, response(200, self.release(draft=False, immutable=True))),
            "weak-etag": (1, response(200, self.release(
                draft=False, immutable=True), etag='W/"post"')),
        }
        for name, (index, value) in mutations.items():
            with self.subTest(name=name), self.assertRaises(SystemExit):
                changed = list(base)
                changed[index] = value
                self.run_service(changed)

    def test_writer_exclusion_contract_keeps_publication_prohibited(self):
        plan = PUBLICATION.bind_publication(self.sha, self.assets)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            PUBLICATION._require_publication_writer_exclusion(plan)
            contract = json.loads(
                (ROOT / "publication-writer-exclusion-v2.json").read_bytes()
            )
            self.assertEqual(contract["activation_precondition"]["state"], "unavailable")
            self.assertTrue(contract["activation_precondition"]["no_fallback"])
            self.assertFalse(contract["github_release_cas_supported"])
            self.assertTrue(contract["publication_writes_prohibited"])
            for flipped in (
                {"activation_precondition": {**contract["activation_precondition"], "state": "ready"}},
                {"irreversible_publication_forbidden": False},
                {"publication_writes_prohibited": False},
            ):
                changed = json.dumps({**contract, **flipped}).encode()
                with tempfile.TemporaryDirectory() as td:
                    forged = Path(td) / "publication-writer-exclusion-v2.json"
                    forged.write_bytes(changed)
                    with (
                        self.subTest(flipped=sorted(flipped)),
                        mock.patch.object(
                            PUBLICATION, "WRITER_EXCLUSION_CONTRACT_PATH", forged,
                        ),
                        self.assertRaises(SystemExit),
                    ):
                        PUBLICATION._require_publication_writer_exclusion(plan)

    def test_runtime_context_rejects_alternate_repository_ref_trigger_and_sha(self):
        environment = {
            "GITHUB_REPOSITORY": PUBLICATION.EXPECTED_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": self.sha,
        }
        PUBLICATION.verify_runtime_context(environment, self.sha)
        mutations = {
            "repository": ("GITHUB_REPOSITORY", "example/wrong"),
            "ref": ("GITHUB_REF", "refs/heads/other"),
            "trigger": ("GITHUB_EVENT_NAME", "push"),
            "sha": ("GITHUB_SHA", "b" * 40),
        }
        for name, (key, value) in mutations.items():
            with self.subTest(name=name), self.assertRaises(SystemExit):
                changed = dict(environment, **{key: value})
                PUBLICATION.verify_runtime_context(changed, self.sha)

    def test_cli_asset_boundary_rejects_missing_extra_duplicate_and_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paths = {}
            for name in PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES:
                path = root / name
                path.write_bytes(name.encode())
                paths[name] = path
            specs = [f"{name}={paths[name]}" for name in PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES]
            self.assertEqual(set(PUBLICATION._parse_assets(specs)), set(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES))
            for changed in (specs[:-1], [*specs, f"extra={paths[PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES[0]]}"], [*specs, specs[0]]):
                with self.assertRaises(SystemExit):
                    PUBLICATION._parse_assets(changed)
            target = paths[PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES[0]]
            link = root / "linked"
            link.symlink_to(target)
            replaced = [f"{PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES[0]}={link}", *specs[1:]]
            with self.assertRaises(SystemExit):
                PUBLICATION._parse_assets(replaced)


class VerifiedPublicationPlanTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.receipt = b"canonical independent review receipt fixture\n"
        self.receipt_sha256 = hashlib.sha256(self.receipt).hexdigest()
        self.issuance = authenticated_issuance(head=self.sha, review_receipt_sha256=self.receipt_sha256)
        self.policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        self.assets = self._publication_assets()

    def test_no_caller_constructible_publication_capability_exists(self):
        self.assertFalse(hasattr(PUBLICATION, "VerifiedPublicationPlan"))
        self.assertFalse(hasattr(PUBLICATION.PublicationService, "publish_plan"))
        source = (ROOT / "scripts" / "verify_publication_v2.py").read_text()
        publish = source.split("    def publish(", 1)[1].split("\n\ndef ", 1)[0]
        # The publish path now runs exactly the shared, transport-free
        # preflight and can still only fail closed afterwards.
        self.assertLess(
            publish.index("_publication_preflight("),
            publish.index("publication is unavailable"),
        )
        preflight = source.split("def _publication_preflight(", 1)[1].split(
            "\n\ndef ", 1)[0]
        self.assertLess(
            preflight.index("verify_publication_plan("),
            preflight.index("_require_publication_writer_exclusion("),
        )
        for absent in ("self._request(", "self._publication_guards()", "_snapshot("):
            self.assertNotIn(absent, publish)
            self.assertNotIn(absent, preflight)

    def _publication_assets(self):
        authority = PUBLICATION.AUTHORITY
        assets = {
            "authority-v2-policy.json": (ROOT / "authority-v2-policy.json").read_bytes(),
            "authority-v2-subject.schema.json": (ROOT / "schemas" / "authority-v2-subject.schema.json").read_bytes(),
            "github-environment-v2-contract.json": (ROOT / "github-environment-v2-contract.json").read_bytes(),
            "preissuance-review-receipt.json": self.receipt,
            "preissuance-review-receipt.sigstore.json": b'{"fixture":"review-signature"}\n',
            "protected-asset-receipt-v2.json": (ROOT / "protected-asset-receipt-v2.json").read_bytes(),
        }
        evidence_names = []
        for index, case in enumerate(authority.EXPECTED_CASES):
            subject_name = f"authority-v2-{case}.json"
            bundle_name = f"authority-v2-{case}.sigstore.json"
            subject = authority.expected_subject(
                self.policy, case, self.sha, self.receipt_sha256, self.issuance
            )
            assets[subject_name] = authority.canonical(subject)
            assets[bundle_name] = json.dumps(
                {"fixture_case": case, "fixture_index": index}, sort_keys=True
            ).encode("utf-8")
            evidence_names.extend((subject_name, bundle_name))
        runner_state = json.dumps({
            "artifact_type": "acc-authority-v2-runner-state",
            "consistent": True, "terminal_state": "completed",
        }, sort_keys=True).encode("utf-8") + b"\n"
        assets["authority-v2-runner-state.json"] = runner_state
        evidence_names.append("authority-v2-runner-state.json")
        evidence_names.sort()
        assets["AUTHORITY-V2-RELEASE-SHA256SUMS"] = (
            "".join(
                f"{hashlib.sha256(assets[name]).hexdigest()}  {name}\n"
                for name in evidence_names
            ).encode("utf-8")
        )
        self.assertEqual(set(assets), set(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES))
        return assets

    def _materialise(self, root, payloads):
        """Read the exact publication asset bytes through the lane's own reader."""
        directory = Path(root) / "assets"
        directory.mkdir(parents=True, exist_ok=True)
        assets = {}
        for name, payload in payloads.items():
            target = directory / name
            target.write_bytes(payload)
            assets[name] = PUBLICATION._read_asset(target)
        return assets

    def _approved_cosign(self, root):
        authority = PUBLICATION.AUTHORITY
        directory = tempfile.TemporaryDirectory(dir=root)
        snapshot_root = Path(directory.name)
        os.chmod(snapshot_root, 0o700)
        executable = snapshot_root / "cosign"
        executable.write_bytes(b"approved immutable cosign fixture")
        os.chmod(executable, 0o500)
        identity = authority._stat_identity(executable.lstat())
        return authority.VerifiedCosign(
            Path("/approved/cosign"), executable, identity,
            hashlib.sha256(executable.read_bytes()).hexdigest(), directory,
        )

    def _verification_patches(self, approved_cosign, *, verify_pair=None):
        authority = PUBLICATION.AUTHORITY
        trusted = datetime(2026, 8, 25, tzinfo=timezone.utc)

        def verify_receipt(path, activation_sha, receipt_sha256, repository_root=authority.ROOT,
                           authenticated_issuance=None, envelope_path=None):
            self.assertEqual(authenticated_issuance.data, self.issuance.data)
            self.assertEqual(authenticated_issuance.sha256, self.issuance.sha256)
            self.assertEqual(activation_sha, self.sha)
            self.assertEqual(receipt_sha256, self.receipt_sha256)
            self.assertEqual(path.read_bytes(), self.receipt)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            return {}

        def exact_pair(subject, bundle, _cosign, _activation):
            payload = json.loads(subject.data)
            evidence = json.loads(bundle.data)
            if evidence.get("fixture_case") != payload.get("case"):
                raise SystemExit("fixture cryptographic binding mismatch")
            self.assertEqual(stat.S_IMODE(subject.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(bundle.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(subject.path.parent.stat().st_mode), 0o700)
            return trusted

        def authenticate_review(receipt, bundle, _cosign):
            self.assertEqual(receipt.data, self.receipt)
            if bundle.data != b'{"fixture":"review-signature"}\n':
                raise SystemExit("fixture review signature mismatch")

        return (
            mock.patch.object(authority, "verify_candidate", return_value=(self.policy, 1)),
            mock.patch.object(authority, "verify_preissuance_receipt", side_effect=verify_receipt),
            mock.patch.object(authority, "validate_cosign_binary", return_value=approved_cosign),
            mock.patch.object(authority, "_authenticate_review_receipt_with_cosign", side_effect=authenticate_review),
            mock.patch.object(authority, "_verify_bound_cosign_pair", side_effect=verify_pair or exact_pair),
        )

    def _successful_responses(self, assets):
        names = sorted(assets)
        release_assets = [
            {
                "id": index,
                "name": name,
                "url": f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/releases/assets/{index}",
            }
            for index, name in enumerate(names, start=1)
        ]

        def release(draft, immutable=False):
            return {
                "id": 7,
                "tag_name": PUBLICATION.RELEASE_TAG,
                "target_commitish": self.sha,
                "name": PUBLICATION.RELEASE_TITLE,
                "body": PUBLICATION.RELEASE_NOTES,
                "draft": draft,
                "prerelease": False,
                "immutable": immutable,
                "assets": release_assets,
            }

        tag = {
            "ref": f"refs/tags/{PUBLICATION.RELEASE_TAG}",
            "object": {"type": "commit", "sha": self.sha},
        }
        claim_sha = "f" * 40
        plan = PUBLICATION.bind_publication(self.sha, assets)
        guards = PUBLICATION.PublicationGuards(
            immutable_releases_sha256=PUBLICATION._canonical_sha256(
                {"enabled": True, "enforced_by_owner": False}
            ),
            tag_ruleset=PUBLICATION._validate_tag_ruleset(
                exact_tag_ruleset(), 37, '"ruleset-37"'
            ),
        )
        claim_message = PUBLICATION._publication_claim_message(
            self.issuance, plan, guards, 7
        )
        return [
            response(404),
            response(404), response(404),
            response(201, {**release(True), "assets": []}),
            *[response(201, {"id": index, "name": name}) for index, name in enumerate(names, start=1)],
            response(200, release(True), etag='"draft-strong"'),
            *[response(200, body=assets[name]) for name in names],
            response(201, {
                "sha": claim_sha,
                "tag": PUBLICATION.PUBLICATION_CLAIM_TAG,
                "message": claim_message,
                "object": {"type": "commit", "sha": self.sha},
            }),
            response(201, {
                "ref": PUBLICATION.PUBLICATION_CLAIM_REF,
                "object": {"type": "tag", "sha": claim_sha},
            }),
            response(200, release(True), etag='"claimed-draft"'),
            *[response(200, body=assets[name]) for name in names],
            response(404), response(404),
            response(200, release(False, True)),
            response(200, release(False, True), etag='"published-strong"'),
            *[response(200, body=assets[name]) for name in names],
            response(200, tag),
        ]

    def test_crypto_verification_consumes_once_bound_bytes_then_fails_closed(self):
        original = dict(self.assets)
        cryptographic_inputs = {}
        transport = FixtureTransport([])

        def verify_pair(subject, bundle, _cosign, _activation):
            payload = json.loads(subject.data)
            case = payload["case"]
            cryptographic_inputs[f"authority-v2-{case}.json"] = subject.data
            cryptographic_inputs[f"authority-v2-{case}.sigstore.json"] = bundle.data
            for name in tuple(self.assets):
                self.assets[name] = b"caller map changed after binding"
            evidence = json.loads(bundle.data)
            if evidence.get("fixture_case") != case:
                raise SystemExit("fixture cryptographic binding mismatch")
            return datetime(2026, 8, 25, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as td:
            approved = self._approved_cosign(td)
            patches = self._verification_patches(approved, verify_pair=verify_pair)
            with patches[0], patches[1], patches[2] as cosign_validation, patches[3], patches[4]:
                with self.assertRaises(SystemExit) as raised:
                    PUBLICATION.PublicationService(
                        PUBLICATION.PublicationReadTransport(transport),
                        PUBLICATION.AdministrationReadAppTransport(transport),
                    ).publish(
                        self.issuance, self.assets, self.receipt_sha256, "/approved/cosign"
                    )

        self.assertIn("publication is unavailable", str(raised.exception))
        self.assertEqual(cosign_validation.call_count, 1)
        self.assertEqual(transport.calls, [])
        for name, data in cryptographic_inputs.items():
            self.assertEqual(data, original[name])

    def test_cryptographic_failure_makes_zero_transport_calls(self):
        transport = FixtureTransport([])

        def reject(*_arguments):
            raise SystemExit("cryptographic verification failed")

        with tempfile.TemporaryDirectory() as td:
            approved = self._approved_cosign(td)
            patches = self._verification_patches(approved, verify_pair=reject)
            with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(SystemExit):
                PUBLICATION.PublicationService(
                    PUBLICATION.PublicationReadTransport(transport),
                    PUBLICATION.AdministrationReadAppTransport(transport),
                ).publish(
                    self.issuance, self.assets, self.receipt_sha256, "/approved/cosign"
                )

        self.assertEqual(transport.calls, [])

    def test_every_swapped_review_or_evidence_asset_fails_before_transport(self):
        swaps = {
            "policy": ("authority-v2-policy.json", "authority-v2-subject.schema.json"),
            "schema": ("authority-v2-subject.schema.json", "authority-v2-policy.json"),
            "environment": ("github-environment-v2-contract.json", "protected-asset-receipt-v2.json"),
            "protected-receipt": ("protected-asset-receipt-v2.json", "github-environment-v2-contract.json"),
            "preissuance-receipt": ("preissuance-review-receipt.json", "protected-asset-receipt-v2.json"),
            "preissuance-signature": ("preissuance-review-receipt.sigstore.json", "protected-asset-receipt-v2.json"),
            "manifest": ("AUTHORITY-V2-RELEASE-SHA256SUMS", "authority-v2-policy.json"),
            "subject": ("authority-v2-future.json", "authority-v2-stale.json"),
            "bundle": ("authority-v2-future.sigstore.json", "authority-v2-stale.sigstore.json"),
        }
        for label, (target, source) in swaps.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                changed = dict(self.assets)
                changed[target] = changed[source]
                transport = FixtureTransport([])
                approved = self._approved_cosign(td)
                patches = self._verification_patches(approved)
                try:
                    with patches[0], patches[1], patches[2], patches[3], patches[4], self.assertRaises(SystemExit):
                        PUBLICATION.PublicationService(
                            PUBLICATION.PublicationReadTransport(transport),
                            PUBLICATION.AdministrationReadAppTransport(transport),
                        ).publish(
                            self.issuance, changed, self.receipt_sha256, "/approved/cosign"
                        )
                finally:
                    approved.close()
                self.assertEqual(transport.calls, [])

    def test_verified_asset_snapshot_mutation_is_rejected_before_transport(self):
        with tempfile.TemporaryDirectory() as td:
            approved = self._approved_cosign(td)
            patches = self._verification_patches(approved)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                verified = PUBLICATION.verify_publication_plan(
                    PUBLICATION.bind_publication(self.sha, self.assets),
                    self.receipt_sha256,
                    "/approved/cosign",
                    self.issuance,
                )

        object.__setattr__(verified.assets[0], "data", b"mutated after verification")
        transport = FixtureTransport([])
        with self.assertRaises(SystemExit):
            PUBLICATION._validate_plan(verified, PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES)
        self.assertEqual(transport.calls, [])

    def test_cli_requires_review_receipt_hash_and_approved_cosign_path(self):
        base = [
            "verify_publication_v2.py",
            "--reviewed-activation-sha", self.sha,
        ]
        missing_arguments = (
            [*base, "--cosign", "/approved/cosign"],
            [*base, "--preissuance-review-receipt-sha256", self.receipt_sha256],
        )
        for arguments in missing_arguments:
            with self.subTest(arguments=arguments), mock.patch.object(sys, "argv", arguments):
                with self.assertRaises(SystemExit) as raised:
                    PUBLICATION.main()
                self.assertEqual(raised.exception.code, 2)


class RepositoryStateServer:
    """Read-only model of one exact repository publication state.

    It records every request so a test can prove that reconciliation performs
    no draft, upload, tag or claim mutation.
    """

    def __init__(self, test_case, *, draft_id=7, claim_message=None, published=False,
                 claim_tag_object_sha=None, tag_listing_status=200,
                 tag_listing_includes_claim=False, tag_ref_pages=None):
        self.test_case = test_case
        self.draft_id = draft_id
        self.claim_message = claim_message
        self.published = published
        self.claim_tag_object_sha = claim_tag_object_sha or (
            PUBLICATION.expected_claim_tag_object_sha(
                test_case.sha, claim_message,
            )
            if claim_message is not None else "f" * 40
        )
        self.tag_listing_status = tag_listing_status
        self.tag_listing_includes_claim = tag_listing_includes_claim
        self.tag_ref_pages = tag_ref_pages
        self.calls = []

    def _default_tag_refs(self):
        refs = [{"ref": "refs/tags/unrelated-existing-tag"}]
        if self.tag_listing_includes_claim or self.claim_message is not None:
            refs.append({"ref": PUBLICATION.PUBLICATION_CLAIM_REF})
        if self.published:
            refs.append({"ref": f"refs/tags/{PUBLICATION.RELEASE_TAG}"})
        return refs

    def _tag_listing_page(self, path):
        """One page of the authenticated tag-ref visibility listing."""
        query = urllib.parse.parse_qs(path.split("?", 1)[1] if "?" in path else "")
        page = int(query.get("page", ["1"])[0])
        if self.tag_ref_pages is None:
            if self.tag_listing_status != 200:
                return response(self.tag_listing_status, {"message": "Not Found"})
            if page != 1:
                raise AssertionError(f"unexpected extra visibility page: {page}")
            return response(200, self._default_tag_refs())
        if page < 1 or page > len(self.tag_ref_pages):
            # An advertised page the server does not actually serve.
            return response(404, {"message": "Not Found"})
        spec = self.tag_ref_pages[page - 1]
        if "status" in spec:
            return response(spec["status"], {"message": "unavailable"})
        payload = spec["body"] if "body" in spec else spec.get("refs", [])
        headers = {}
        if spec.get("raw_link") is not None:
            headers["Link"] = spec["raw_link"]
        elif spec.get("next") is not None:
            target = (
                f"{PUBLICATION.TAG_REF_VISIBILITY_PATH}"
                f"?per_page={PUBLICATION.TAG_REF_PAGE_SIZE}&page={spec['next']}"
            )
            headers["Link"] = f'<{target}>; rel="next"'
        if spec.get("duplicate_link"):
            headers = dict(headers)
            headers["link"] = headers.get("Link", "")
        return PUBLICATION.ApiResponse(
            status=200, headers=headers, body=json.dumps(payload).encode(),
        )

    def _release(self):
        return self.test_case.release(
            release_id=self.draft_id,
            draft=not self.published,
            immutable=self.published,
            assets=sorted(self.test_case.assets),
        )

    def request(self, method, path, *, headers=None, body=None):
        self.calls.append((method, path, dict(headers or {}), body))
        repo = PUBLICATION.EXPECTED_REPOSITORY
        claim_ref = f"/repos/{repo}/git/ref/tags/{PUBLICATION.PUBLICATION_CLAIM_TAG}"
        final_ref = f"/repos/{repo}/git/ref/tags/{PUBLICATION.RELEASE_TAG}"
        if method != "GET":
            raise AssertionError(f"reconciliation attempted a mutation: {method} {path}")
        if path == f"/repos/{repo}/immutable-releases":
            return response(200, {"enabled": True, "enforced_by_owner": False})
        if path.startswith(f"/repos/{repo}/rulesets?"):
            return response(200, [{"id": 37}])
        if path.startswith(f"/repos/{repo}/rulesets/"):
            return response(200, exact_tag_ruleset(), etag='"ruleset-37"')
        if path.startswith(f"/repos/{repo}/releases?"):
            page = int(path.rsplit("page=", 1)[1])
            return response(200, [self._release()] if page == 1 else [])
        if path == f"/repos/{repo}/releases/{self.draft_id}":
            return response(200, self._release(), etag='"release-7"')
        if path.startswith(f"/repos/{repo}/releases/assets/"):
            asset_id = int(path.rsplit("/", 1)[1])
            name = sorted(self.test_case.assets)[asset_id - 1]
            return response(200, body=self.test_case.assets[name])
        if path.startswith(PUBLICATION.TAG_REF_VISIBILITY_PATH):
            return self._tag_listing_page(path)
        if path == claim_ref:
            if self.claim_message is None:
                return response(404)
            return response(200, {
                "ref": PUBLICATION.PUBLICATION_CLAIM_REF,
                "object": {"type": "tag", "sha": self.claim_tag_object_sha},
            })
        if path == f"/repos/{repo}/git/tags/{self.claim_tag_object_sha}":
            return response(200, {
                "sha": self.claim_tag_object_sha,
                "tag": PUBLICATION.PUBLICATION_CLAIM_TAG,
                "message": self.claim_message,
                "object": {"type": "commit", "sha": self.test_case.sha},
            })
        if path == final_ref:
            if not self.published:
                return response(404)
            return response(200, {
                "ref": f"refs/tags/{PUBLICATION.RELEASE_TAG}",
                "object": {"type": "commit", "sha": self.test_case.sha},
            })
        if path == f"/repos/{repo}/releases/tags/{PUBLICATION.RELEASE_TAG}":
            return response(200, self._release()) if self.published else response(404)
        raise AssertionError(f"unexpected request: {method} {path}")


class AmbiguousClaimRefTests(unittest.TestCase):
    """Adversarial coverage for IRRECOVERABLE-PARTIAL-TAG-CLAIM."""

    def setUp(self):
        self.sha = "a" * 40
        self.assets = {"one.txt": b"one\n", "two.bin": b"\x00two"}
        self.issuance = authenticated_issuance(head=self.sha)
        self.plan = PUBLICATION.bind_publication(self.sha, self.assets)

    def release(self, *, release_id=7, draft=True, immutable=False, assets=(), target=None):
        asset_rows = []
        for index, name in enumerate(sorted(assets), start=1):
            asset_rows.append({
                "id": index,
                "name": name,
                "size": len(self.assets[name]),
                "url": f"https://api.github.com/repos/{PUBLICATION.EXPECTED_REPOSITORY}/releases/assets/{index}",
            })
        return {
            "id": release_id,
            "tag_name": PUBLICATION.RELEASE_TAG,
            "target_commitish": self.sha if target is None else target,
            "name": PUBLICATION.RELEASE_TITLE,
            "body": PUBLICATION.RELEASE_NOTES,
            "draft": draft,
            "prerelease": False,
            "immutable": immutable,
            "assets": asset_rows,
        }

    def _guards(self):
        return PUBLICATION.PublicationGuards(
            immutable_releases_sha256=PUBLICATION._canonical_sha256(
                {"enabled": True, "enforced_by_owner": False}
            ),
            tag_ruleset=PUBLICATION._validate_tag_ruleset(
                exact_tag_ruleset(), 37, '"ruleset-37"'
            ),
        )

    def _service(self, server):
        return PUBLICATION.PublicationService(
            PUBLICATION.PublicationReadTransport(server),
            PUBLICATION.AdministrationReadAppTransport(server),
        )

    def _claim_message(self, draft_id=7):
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            return PUBLICATION._publication_claim_message(
                self.issuance, self.plan, self._guards(), draft_id,
            )

    def test_publication_is_unavailable_and_performs_no_write(self):
        server = RepositoryStateServer(self)
        with (
            mock.patch.object(
                PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
            ),
            mock.patch.object(
                PUBLICATION, "verify_publication_plan",
                side_effect=lambda plan, *_arguments: plan,
            ),
        ):
            with self.assertRaises(SystemExit) as raised:
                self._service(server).publish(
                    self.issuance, self.assets,
                    self.issuance.review_receipt_sha256, "/approved/cosign",
                )
        self.assertIn("publication is unavailable", str(raised.exception))
        self.assertEqual(server.calls, [])

    def test_every_publication_mutation_is_structurally_prohibited(self):
        server = RepositoryStateServer(self)
        transport = PUBLICATION.PublicationReadTransport(server)
        for method, path, body in (
            ("POST", f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/releases", b"{}"),
            ("POST", "https://uploads.github.com/repos/x/releases/7/assets?name=a", b"x"),
            ("POST", f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/git/tags", b"{}"),
            ("POST", f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/git/refs", b"{}"),
            ("PATCH", f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/releases/7", b"{}"),
            ("DELETE", f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/releases/7", None),
        ):
            with self.subTest(method=method), self.assertRaises(SystemExit):
                transport.request(method, path, body=body)
        self.assertEqual(server.calls, [])
        for removed in ("_create_draft", "_delete_draft", "_upload_assets",
                        "_claim_publication", "_reconcile_claimed_publication"):
            self.assertFalse(hasattr(PUBLICATION.PublicationService, removed))
        self.assertFalse(hasattr(PUBLICATION, "ContentsWriteTransport"))

    def test_ambiguous_claim_ref_after_populated_draft_when_the_server_created_it(self):
        server = RepositoryStateServer(self, claim_message=self._claim_message(7))
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            report = self._service(server).reconcile(self.issuance, self.plan)
            repeated = self._service(server).reconcile(self.issuance, self.plan)
        self.assertEqual(report, repeated)
        self.assertEqual(report["publication_state"], "claimed_draft")
        self.assertFalse(report["publication_available"])
        self.assertEqual(report["draft"]["id"], 7)
        self.assertEqual(report["claim"]["draft_id"], 7)
        self.assertIsNone(report["final_tag"])
        self.assertEqual(report["draft"]["assets"], {
            name: hashlib.sha256(data).hexdigest()
            for name, data in self.assets.items()
        })
        self.assertEqual(
            report["publication_plan_sha256"],
            PUBLICATION._plan_binding_sha256(self.plan),
        )
        self.assertEqual(report["guards"], report["claim"]["guards"])
        self.assertEqual(report["writes_performed"], 0)
        self.assertTrue(all(call[0] == "GET" for call in server.calls))

    def test_ambiguous_claim_ref_after_populated_draft_when_the_server_did_not(self):
        server = RepositoryStateServer(self, claim_message=None)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            report = self._service(server).reconcile(self.issuance, self.plan)
            repeated = self._service(server).reconcile(self.issuance, self.plan)
        self.assertEqual(report, repeated)
        self.assertEqual(report["publication_state"], "unclaimed_draft")
        self.assertIsNone(report["claim"])
        self.assertEqual(report["draft"]["id"], 7)
        self.assertIsNone(report["final_tag"])
        self.assertEqual(report["writes_performed"], 0)
        creations = [
            call for call in server.calls
            if call[0] == "POST" and call[1].endswith("/releases")
        ]
        self.assertEqual(creations, [])

    def test_reconciliation_fails_closed_on_ambiguous_or_mismatched_draft_state(self):
        class TwoDraftServer(RepositoryStateServer):
            def request(self, method, path, *, headers=None, body=None):
                repo = PUBLICATION.EXPECTED_REPOSITORY
                if method == "GET" and path.startswith(f"/repos/{repo}/releases?"):
                    self.calls.append((method, path, dict(headers or {}), body))
                    page = int(path.rsplit("page=", 1)[1])
                    if page != 1:
                        return response(200, [])
                    return response(200, [
                        self.test_case.release(release_id=7, assets=sorted(self.test_case.assets)),
                        self.test_case.release(release_id=9, assets=sorted(self.test_case.assets)),
                    ])
                return super().request(method, path, headers=headers, body=body)

        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            with self.assertRaises(SystemExit):
                self._service(TwoDraftServer(self)).reconcile(self.issuance, self.plan)
            forged = RepositoryStateServer(self, claim_message=self._claim_message(99))
            with self.assertRaises(SystemExit):
                self._service(forged).reconcile(self.issuance, self.plan)

    def test_mutable_draft_with_final_tag_present_must_be_rejected(self):
        """F4: IRRECOVERABLE-PARTIAL-TAG-CLAIM-CLOSURE-INCOMPLETE adversarial probe.

        A mutable populated draft plus an existing final tag is an irrecoverable
        partial state. The reconciler must reject it, not report unclaimed_draft.
        """
        class DraftWithFinalTagServer(RepositoryStateServer):
            """Simulates draft=true, immutable=false, but final_tag present."""
            def request(self, method, path, *, headers=None, body=None):
                repo = PUBLICATION.EXPECTED_REPOSITORY
                final_ref = f"/repos/{repo}/git/ref/tags/{PUBLICATION.RELEASE_TAG}"
                if method == "GET" and path == final_ref:
                    self.calls.append((method, path, dict(headers or {}), body))
                    return response(200, {
                        "ref": f"refs/tags/{PUBLICATION.RELEASE_TAG}",
                        "object": {"type": "commit", "sha": self.test_case.sha},
                    })
                return super().request(method, path, headers=headers, body=body)

        server = DraftWithFinalTagServer(self)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            with self.assertRaises(SystemExit):
                self._service(server).reconcile(self.issuance, self.plan)

    def test_no_contract_or_document_claims_publication_resumability(self):
        writer = json.loads((ROOT / "publication-writer-exclusion-v2.json").read_bytes())
        self.assertTrue(writer["publication_writes_prohibited"])
        self.assertTrue(writer["irreversible_publication_forbidden"])
        self.assertEqual(writer["activation_precondition"]["state"], "unavailable")
        policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        publication = policy["publication_contract"]
        self.assertEqual(publication["activation_state"], "unavailable")
        self.assertFalse(publication["draft_creation_allowed"])
        self.assertFalse(publication["asset_upload_allowed"])
        self.assertFalse(publication["tag_or_claim_write_allowed"])
        for document in ("README.md", "VERIFY-AUTHORITY-V2.md"):
            text = (ROOT / document).read_text(encoding="utf-8")
            self.assertNotIn("resumable", text.lower())
        source = (ROOT / "scripts" / "verify_publication_v2.py").read_text(encoding="utf-8")
        self.assertNotIn("ambiguous_patch_resume", source)
        workflow = (ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("gh release create", workflow)
        self.assertNotIn("gh release upload", workflow)



class ClaimRefOutcomeTests(unittest.TestCase):
    """F12-RACE-SAFE-PUBLICATION-UNAVAILABLE adversarial coverage.

    Tests the documented server-atomic create-ref primitive, exact HTTP/API
    outcome classes, idempotent ambiguous-outcome reconciliation, immutable
    execution handles, no mutable reread, simultaneous competitors, stale
    absence, preexisting/mismatched claim, transport ambiguity, auth/permission/
    rate-limit/network/API failures, tag/draft/asset swaps, and immutable
    readback. Every publication write remains prohibited.
    """

    def setUp(self):
        self.sha = "a" * 40
        self.assets = {"one.txt": b"one\n", "two.bin": b"\x00two"}
        self.issuance = authenticated_issuance(head=self.sha)
        self.plan = PUBLICATION.bind_publication(self.sha, self.assets)
        self.claim_digest = PUBLICATION._publication_claim_digest(self.issuance)

    def _guards(self):
        return PUBLICATION.PublicationGuards(
            immutable_releases_sha256=PUBLICATION._canonical_sha256(
                {"enabled": True, "enforced_by_owner": False}
            ),
            tag_ruleset=PUBLICATION._validate_tag_ruleset(
                exact_tag_ruleset(), 37, '"ruleset-37"'
            ),
        )

    def _claim_message(self, draft_id=7):
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            return PUBLICATION._publication_claim_message(
                self.issuance, self.plan, self._guards(), draft_id,
            )

    def _annotated_claim(self, *, tag_object_sha="f" * 40, target=None, message=None):
        """The exact authenticated annotated-tag claim readback pair."""
        ref_readback = {
            "ref": PUBLICATION.PUBLICATION_CLAIM_REF,
            "object": {"type": "tag", "sha": tag_object_sha},
        }
        tag_object = {
            "sha": tag_object_sha,
            "tag": PUBLICATION.PUBLICATION_CLAIM_TAG,
            "message": self._claim_message() if message is None else message,
            "object": {"type": "commit", "sha": target or self.sha},
        }
        return ref_readback, tag_object

    def _classify(self, ref_readback, tag_object):
        return PUBLICATION.classify_claim_readback(
            ref_readback, tag_object,
            expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
            expected_tag=PUBLICATION.PUBLICATION_CLAIM_TAG,
            expected_target=self.sha,
            expected_request_identity=self.claim_digest,
            expected_plan_sha256=PUBLICATION._plan_binding_sha256(self.plan),
        )

    def test_confirmed_absent_only_for_documented_404_on_authenticated_read(self):
        """A 404 needs authenticated visibility evidence to mean absence."""
        self.assertEqual(
            PUBLICATION.classify_ref_read(404), "readback_ambiguous",
        )
        outcome = PUBLICATION.classify_ref_read(
            404,
            absence_evidence={
                "authenticated": True,
                "status": 200,
                "complete": True,
                "pages": 1,
                "prefix": "refs/tags/",
                "refs": [{"ref": "refs/tags/unrelated-existing-tag"}],
            },
            expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
        )
        self.assertEqual(outcome, "confirmed_absent")
        for ambiguous in (401, 403, 429, 500, 502, 503):
            outcome = PUBLICATION.classify_ref_read(ambiguous)
            self.assertEqual(outcome, "unknown_error", f"HTTP {ambiguous}")

    def test_401_403_429_5xx_permission_auth_rate_limit_prohibit_writes(self):
        for status in (401, 403, 429, 500, 502, 503):
            with self.subTest(status=status):
                self.assertIn(
                    PUBLICATION.classify_ref_read(status),
                    ("unknown_error",),
                )

    def test_claim_ref_creation_is_server_atomic_no_overwrite(self):
        contract = PUBLICATION.CLAIM_REF_CONTRACT
        self.assertEqual(contract["method"], "POST")
        self.assertEqual(contract["endpoint"], "/repos/{owner}/{repo}/git/refs")
        self.assertIs(contract["server_atomic"], True)
        self.assertIs(contract["fails_when_ref_exists"], True)
        self.assertIs(contract["no_overwrite"], True)
        self.assertIs(contract["never_use_update_ref"], True)
        self.assertIs(contract["never_use_force"], True)
        self.assertEqual(contract["success_status"], 201)
        self.assertEqual(contract["non_authoritative_statuses"], [409, 422])
        self.assertNotIn("already_exists_status", contract)

    def test_ambiguous_transport_outcome_reconciliation(self):
        for state_name, expected in [
            ("created_by_this_attempt", "created_by_this_attempt"),
            ("absent", "absent"),
            ("mismatch_collision", "mismatch_collision"),
            ("readback_ambiguous", "readback_ambiguous"),
        ]:
            self.assertIn(state_name, PUBLICATION.CLAIM_REF_RECONCILIATION_STATES)

    def test_immutable_readback_after_timeout_classifies_exact_match(self):
        ref_readback, tag_object = self._annotated_claim()
        self.assertEqual(
            self._classify(ref_readback, tag_object), "created_by_this_attempt",
        )

    def test_readback_absent_allows_bounded_retry(self):
        self.assertEqual(self._classify(None, None), "absent")

    def test_readback_mismatch_or_collision_prohibits_write(self):
        ref_readback, tag_object = self._annotated_claim(target="b" * 40)
        self.assertEqual(
            self._classify(ref_readback, tag_object), "mismatch_collision",
        )

    def test_readback_ambiguity_prohibits_write(self):
        malformed = {"ref": PUBLICATION.PUBLICATION_CLAIM_REF}
        self.assertEqual(self._classify(malformed, None), "readback_ambiguous")

    def test_tag_tree_blob_unknown_and_missing_object_type_rejected(self):
        """Only an annotated tag object may own the claim ref.

        A direct commit ref, a tree, a blob, an unknown or a missing object
        type never resolves to an authoritative claim.
        """
        _, tag_object = self._annotated_claim()
        for bad_type in ("commit", "tree", "blob", "unknown", ""):
            with self.subTest(object_type=bad_type):
                readback = {
                    "ref": PUBLICATION.PUBLICATION_CLAIM_REF,
                    "object": {"type": bad_type, "sha": self.sha},
                }
                self.assertNotEqual(
                    self._classify(readback, tag_object),
                    "created_by_this_attempt",
                    f"object type {bad_type!r} must not be accepted",
                )
        missing_type = {
            "ref": PUBLICATION.PUBLICATION_CLAIM_REF,
            "object": {"sha": self.sha},
        }
        self.assertNotEqual(
            self._classify(missing_type, tag_object), "created_by_this_attempt",
        )

    def test_simultaneous_competitors_fail_closed(self):
        """Two competitors: only a documented 201 is a creation.

        The loser's 409/422 is a non-authoritative conflict, never a unique
        already-exists proof.
        """
        self.assertEqual(
            PUBLICATION.classify_create_ref_outcome(201), "created"
        )
        for status in (409, 422):
            self.assertEqual(
                PUBLICATION.classify_create_ref_outcome(status),
                "non_authoritative_conflict",
            )
        for status in (401, 403, 429, 500, 502, 503, 404):
            self.assertEqual(
                PUBLICATION.classify_create_ref_outcome(status),
                "non_authoritative_error",
            )

    def test_stale_absence_after_preexisting_claim_fails_closed(self):
        """Stale cached 404 must never authorize create after an existing claim."""
        ref_readback, tag_object = self._annotated_claim(target="b" * 40)
        self.assertEqual(
            self._classify(ref_readback, tag_object), "mismatch_collision",
        )

    def test_no_mutable_reread_after_snapshot_validation(self):
        """Plan assets are bound at snapshot time; no path reread occurs."""
        plan = PUBLICATION.bind_publication(self.sha, self.assets)
        original_data = {a.name: a.data for a in plan.assets}
        self.assets["one.txt"] = b"mutated after binding"
        bound_data = {a.name: a.data for a in plan.assets}
        self.assertEqual(original_data, bound_data)

    def test_claim_ref_collision_is_never_inferred_from_422_alone(self):
        """422 is a documented generic validation failure, not existence proof."""
        outcome = PUBLICATION.classify_create_ref_outcome(422)
        self.assertEqual(outcome, "non_authoritative_conflict")
        self.assertFalse(
            PUBLICATION.create_ref_outcome_proves_existing_claim(outcome)
        )
        ref_readback, tag_object = self._annotated_claim(target="b" * 40)
        self.assertEqual(
            self._classify(ref_readback, tag_object), "mismatch_collision",
        )

    def test_transport_ambiguity_before_server_create_prohibits(self):
        """Transport timeout before a known create outcome is unknown."""
        self.assertEqual(
            PUBLICATION.classify_create_ref_outcome(None), "transport_ambiguous"
        )

    def test_transport_ambiguity_after_server_create_requires_readback(self):
        """After timeout we must readback; only the exact annotated tag proceeds."""
        self.assertEqual(self._classify(None, None), "absent")
        ref_readback, tag_object = self._annotated_claim()
        self.assertEqual(
            self._classify(ref_readback, tag_object), "created_by_this_attempt",
        )

    def test_partial_upload_does_not_allow_publication_finalization(self):
        """Partial asset upload with publication unavailable fails closed."""
        half_assets = {"one.txt": b"one\n"}
        half_plan = PUBLICATION.bind_publication(self.sha, half_assets)
        with self.assertRaises(SystemExit):
            PUBLICATION._validate_plan(half_plan, tuple(sorted(self.assets)))

    def test_post_validation_pathname_replacement_fails_closed(self):
        """After plan binding, injecting a new asset name fails."""
        plan = PUBLICATION.bind_publication(self.sha, self.assets)
        self.assertEqual(
            tuple(a.name for a in plan.assets), tuple(sorted(self.assets))
        )
        forged = dict(self.assets)
        forged["injected.txt"] = b"injected"
        forged_plan = PUBLICATION.bind_publication(self.sha, forged)
        self.assertNotEqual(
            PUBLICATION._plan_binding_sha256(plan),
            PUBLICATION._plan_binding_sha256(forged_plan),
        )

    def test_every_write_remains_prohibited_unless_all_preconditions_validate(self):
        """Publication contract explicitly keeps all writes prohibited."""
        policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        pub = policy["publication_contract"]
        self.assertEqual(pub["activation_state"], "unavailable")
        self.assertFalse(pub["draft_creation_allowed"])
        self.assertFalse(pub["asset_upload_allowed"])
        self.assertFalse(pub["tag_or_claim_write_allowed"])
        self.assertTrue(pub["irreversible_publication_forbidden"])
        writer = json.loads(
            (ROOT / "publication-writer-exclusion-v2.json").read_bytes()
        )
        self.assertTrue(writer["publication_writes_prohibited"])

    def test_claim_ref_contract_binds_exact_activation_sha_and_asset_digest(self):
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            plan = PUBLICATION.bind_publication(self.sha, self.assets)
            claim_payload = PUBLICATION._publication_claim_payload(
                self.issuance, plan, self._guards(), 7,
            )
        self.assertEqual(claim_payload["release"]["target_commitish"], self.sha)
        self.assertEqual(
            claim_payload["publication_plan_sha256"],
            PUBLICATION._plan_binding_sha256(plan),
        )
        self.assertIn("asset_plan", claim_payload)
        for asset_entry in claim_payload["asset_plan"]:
            self.assertIn("sha256", asset_entry)
            self.assertIn("name", asset_entry)
            self.assertIn("size", asset_entry)


class CreateRefStatusSemanticsTests(unittest.TestCase):
    """F12-CREATE-REF-STATUS-SEMANTICS-MISCLASSIFIED.

    HTTP 422 is never unique already-exists proof. Only documented 201 is a
    creation, and every non-201 outcome stays non-authoritative until an exact
    authenticated readback proves a nonce/issuance/plan-bearing annotated tag
    object with the exact tag-object SHA, type, tag, message, object target and
    request identity.
    """

    TAG_OBJECT_SHA = "f" * 40

    def setUp(self):
        self.sha = "a" * 40
        self.assets = {"one.txt": b"one\n", "two.bin": b"\x00two"}
        self.issuance = authenticated_issuance(head=self.sha)
        self.plan = PUBLICATION.bind_publication(self.sha, self.assets)
        self.identity = PUBLICATION._publication_claim_digest(self.issuance)
        self.message = self._claim_message()

    def _guards(self):
        return PUBLICATION.PublicationGuards(
            immutable_releases_sha256=PUBLICATION._canonical_sha256(
                {"enabled": True, "enforced_by_owner": False}
            ),
            tag_ruleset=PUBLICATION._validate_tag_ruleset(
                exact_tag_ruleset(), 37, '"ruleset-37"'
            ),
        )

    def _claim_message(self, draft_id=7):
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            return PUBLICATION._publication_claim_message(
                self.issuance, self.plan, self._guards(), draft_id,
            )

    def _ref(self, *, object_type="tag", sha=None):
        return {
            "ref": PUBLICATION.PUBLICATION_CLAIM_REF,
            "object": {"type": object_type, "sha": sha or self.TAG_OBJECT_SHA},
        }

    def _tag(self, **overrides):
        payload = {
            "sha": self.TAG_OBJECT_SHA,
            "tag": PUBLICATION.PUBLICATION_CLAIM_TAG,
            "message": self.message,
            "object": {"type": "commit", "sha": self.sha},
        }
        payload.update(overrides)
        return payload

    def _classify(self, ref_readback, tag_object):
        return PUBLICATION.classify_claim_readback(
            ref_readback, tag_object,
            expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
            expected_tag=PUBLICATION.PUBLICATION_CLAIM_TAG,
            expected_target=self.sha,
            expected_request_identity=self.identity,
            expected_plan_sha256=PUBLICATION._plan_binding_sha256(self.plan),
        )

    # --- documented outcome classification ---

    def test_only_documented_201_is_a_creation(self):
        self.assertEqual(PUBLICATION.classify_create_ref_outcome(201), "created")

    def test_409_and_422_are_non_authoritative_not_already_exists(self):
        for status in (409, 422):
            with self.subTest(status=status):
                outcome = PUBLICATION.classify_create_ref_outcome(status)
                self.assertEqual(outcome, "non_authoritative_conflict")
                self.assertNotEqual(outcome, "already_exists")
                self.assertIn(outcome, PUBLICATION.CREATE_REF_NON_AUTHORITATIVE)

    def test_transport_ambiguity_and_other_non_201_are_non_authoritative(self):
        self.assertEqual(
            PUBLICATION.classify_create_ref_outcome(None), "transport_ambiguous"
        )
        for status in (200, 202, 301, 401, 403, 404, 429, 500, 502, 503):
            with self.subTest(status=status):
                outcome = PUBLICATION.classify_create_ref_outcome(status)
                self.assertEqual(outcome, "non_authoritative_error")
                self.assertIn(outcome, PUBLICATION.CREATE_REF_NON_AUTHORITATIVE)

    def test_no_create_ref_outcome_alone_ever_proves_an_existing_claim(self):
        for status in (201, 409, 422, None, 403, 500):
            with self.subTest(status=status):
                self.assertFalse(
                    PUBLICATION.create_ref_outcome_proves_existing_claim(
                        PUBLICATION.classify_create_ref_outcome(status)
                    )
                )

    def test_contract_records_the_documented_non_authoritative_statuses(self):
        contract = PUBLICATION.CLAIM_REF_CONTRACT
        self.assertEqual(contract["success_status"], 201)
        self.assertEqual(contract["non_authoritative_statuses"], [409, 422])
        self.assertNotIn("already_exists_status", contract)
        self.assertIs(contract["non_201_is_never_already_exists_proof"], True)
        self.assertIs(
            contract["authoritative_existence_requires_authenticated_readback"], True
        )
        self.assertIs(contract["never_use_update_ref"], True)
        self.assertIs(contract["never_use_force"], True)

    # --- exact annotated tag-object readback ---

    def test_exact_annotated_tag_object_readback_is_created_by_this_attempt(self):
        self.assertEqual(
            self._classify(self._ref(), self._tag()), "created_by_this_attempt"
        )

    def test_absent_readback_allows_bounded_retry_only(self):
        self.assertEqual(self._classify(None, None), "absent")

    def test_direct_commit_ref_and_lightweight_tag_reject(self):
        for object_type in ("commit", "tree", "blob", "unknown", ""):
            with self.subTest(object_type=object_type):
                state = self._classify(
                    self._ref(object_type=object_type, sha=self.sha), self._tag()
                )
                self.assertEqual(state, "mismatch_collision")

    def test_missing_or_malformed_ref_object_is_ambiguous(self):
        for ref_readback in (
            {"ref": PUBLICATION.PUBLICATION_CLAIM_REF},
            {"ref": PUBLICATION.PUBLICATION_CLAIM_REF, "object": {"type": "tag"}},
            {"ref": PUBLICATION.PUBLICATION_CLAIM_REF,
             "object": {"type": "tag", "sha": "not-hex"}},
            {"object": {"type": "tag", "sha": TAG_OBJECT_SHA_LITERAL}},
            {"ref": "refs/tags/other", "object": {"type": "tag", "sha": TAG_OBJECT_SHA_LITERAL}},
            "a string",
            [],
        ):
            with self.subTest(ref_readback=ref_readback):
                self.assertEqual(
                    self._classify(ref_readback, self._tag()), "readback_ambiguous"
                )

    def test_unresolved_or_substituted_tag_object_is_ambiguous(self):
        self.assertEqual(self._classify(self._ref(), None), "readback_ambiguous")
        self.assertEqual(self._classify(self._ref(), "not-json"), "readback_ambiguous")
        self.assertEqual(
            self._classify(self._ref(), self._tag(sha="b" * 40)),
            "readback_ambiguous",
        )
        self.assertEqual(
            self._classify(self._ref(), self._tag(object={"type": "tag", "sha": self.sha})),
            "mismatch_collision",
        )
        self.assertEqual(
            self._classify(self._ref(), self._tag(object={"sha": self.sha})),
            "mismatch_collision",
        )

    def test_wrong_tag_name_or_target_is_a_collision(self):
        self.assertEqual(
            self._classify(self._ref(), self._tag(tag="some-other-tag")),
            "mismatch_collision",
        )
        self.assertEqual(
            self._classify(
                self._ref(), self._tag(object={"type": "commit", "sha": "b" * 40})
            ),
            "mismatch_collision",
        )

    def test_mismatched_nonce_issuance_or_plan_message_is_a_collision(self):
        other_issuance = authenticated_issuance(head=self.sha, nonce="c" * 64)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            other_message = PUBLICATION._publication_claim_message(
                other_issuance, self.plan, self._guards(), 7,
            )
        self.assertEqual(
            self._classify(self._ref(), self._tag(message=other_message)),
            "mismatch_collision",
        )
        other_plan = PUBLICATION.bind_publication(self.sha, {"one.txt": b"one\n"})
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", ("one.txt",)
        ):
            other_plan_message = PUBLICATION._publication_claim_message(
                self.issuance, other_plan, self._guards(), 7,
            )
        self.assertEqual(
            self._classify(self._ref(), self._tag(message=other_plan_message)),
            "mismatch_collision",
        )

    def test_missing_forged_or_non_canonical_claim_message_rejects(self):
        for message in (
            None,
            "",
            "not a claim message",
            self.message + " ",
            self.message.replace("acc-authority-v2-publication-claim-v2", "forged"),
            123,
        ):
            with self.subTest(message=message):
                self.assertNotEqual(
                    self._classify(self._ref(), self._tag(message=message)),
                    "created_by_this_attempt",
                )

    def test_exact_expected_message_binding_is_enforced_when_supplied(self):
        self.assertEqual(
            PUBLICATION.classify_claim_readback(
                self._ref(), self._tag(),
                expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
                expected_tag=PUBLICATION.PUBLICATION_CLAIM_TAG,
                expected_target=self.sha,
                expected_request_identity=self.identity,
                expected_plan_sha256=PUBLICATION._plan_binding_sha256(self.plan),
                expected_message=self.message,
            ),
            "created_by_this_attempt",
        )
        self.assertEqual(
            PUBLICATION.classify_claim_readback(
                self._ref(), self._tag(),
                expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
                expected_tag=PUBLICATION.PUBLICATION_CLAIM_TAG,
                expected_target=self.sha,
                expected_request_identity=self.identity,
                expected_plan_sha256=PUBLICATION._plan_binding_sha256(self.plan),
                expected_message=self._claim_message(draft_id=9),
            ),
            "mismatch_collision",
        )

    def test_wrong_request_identity_rejects(self):
        self.assertEqual(
            PUBLICATION.classify_claim_readback(
                self._ref(), self._tag(),
                expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
                expected_tag=PUBLICATION.PUBLICATION_CLAIM_TAG,
                expected_target=self.sha,
                expected_request_identity="0" * 64,
                expected_plan_sha256=PUBLICATION._plan_binding_sha256(self.plan),
            ),
            "mismatch_collision",
        )

    def test_tag_object_sha_binding_rejects_object_substitution(self):
        self.assertEqual(
            PUBLICATION.classify_claim_readback(
                self._ref(), self._tag(),
                expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
                expected_tag=PUBLICATION.PUBLICATION_CLAIM_TAG,
                expected_target=self.sha,
                expected_request_identity=self.identity,
                expected_plan_sha256=PUBLICATION._plan_binding_sha256(self.plan),
                expected_tag_object_sha="b" * 40,
            ),
            "mismatch_collision",
        )


TAG_OBJECT_SHA_LITERAL = "f" * 40


class CreateRefReconcilerIntegrationTests(AmbiguousClaimRefTests):
    """The actual reconciler must use the repaired create-ref semantics."""

    def test_reconciler_classifies_the_live_claim_through_the_classifier(self):
        message = self._claim_message()
        server = RepositoryStateServer(self, claim_message=message)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ), mock.patch.object(
            PUBLICATION, "classify_claim_readback",
            wraps=PUBLICATION.classify_claim_readback,
        ) as classify:
            result = self._service(server).reconcile(self.issuance, self.plan)
        self.assertEqual(result["publication_state"], "claimed_draft")
        self.assertEqual(result["writes_performed"], 0)
        classify.assert_called()
        self.assertEqual(
            classify.call_args.kwargs["expected_ref"],
            PUBLICATION.PUBLICATION_CLAIM_REF,
        )
        self.assertEqual(
            classify.call_args.kwargs["expected_tag"],
            PUBLICATION.PUBLICATION_CLAIM_TAG,
        )
        self.assertEqual(classify.call_args.kwargs["expected_target"], self.sha)
        self.assertEqual(
            classify.call_args.kwargs["expected_request_identity"],
            PUBLICATION._publication_claim_digest(self.issuance),
        )
        self.assertEqual(
            classify.call_args.kwargs["expected_plan_sha256"],
            PUBLICATION._plan_binding_sha256(self.plan),
        )

    def test_reconciler_rejects_a_lightweight_commit_claim_ref(self):
        server = RepositoryStateServer(self, claim_message=self._claim_message())
        repo = PUBLICATION.EXPECTED_REPOSITORY
        claim_path = f"/repos/{repo}/git/ref/tags/{PUBLICATION.PUBLICATION_CLAIM_TAG}"
        original = server.request

        def lightweight(method, path, *, headers=None, body=None):
            if path == claim_path:
                return response(200, {
                    "ref": PUBLICATION.PUBLICATION_CLAIM_REF,
                    "object": {"type": "commit", "sha": self.sha},
                })
            return original(method, path, headers=headers, body=body)

        server.request = lightweight
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ), self.assertRaises(SystemExit):
            self._service(server).reconcile(self.issuance, self.plan)

    def test_reconciler_rejects_a_foreign_nonce_bearing_claim(self):
        other = authenticated_issuance(head=self.sha, nonce="c" * 64)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            foreign_message = PUBLICATION._publication_claim_message(
                other, self.plan, self._guards(), 7,
            )
        server = RepositoryStateServer(self, claim_message=foreign_message)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ), self.assertRaises(SystemExit):
            self._service(server).reconcile(self.issuance, self.plan)

    def test_reconciler_rejects_a_masked_or_ambiguous_claim_ref_read(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                server = RepositoryStateServer(self, claim_message=self._claim_message())
                repo = PUBLICATION.EXPECTED_REPOSITORY
                claim_path = (
                    f"/repos/{repo}/git/ref/tags/{PUBLICATION.PUBLICATION_CLAIM_TAG}"
                )
                original = server.request

                def masked(method, path, *, headers=None, body=None, _status=status):
                    if path == claim_path:
                        return response(_status, {})
                    return original(method, path, headers=headers, body=body)

                server.request = masked
                with mock.patch.object(
                    PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES",
                    tuple(sorted(self.assets)),
                ), self.assertRaises(SystemExit):
                    self._service(server).reconcile(self.issuance, self.plan)


class ExclusivePublicationImpossibilityTests(unittest.TestCase):
    """F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE.

    Documented GitHub release APIs establish no exhaustive exclusive/CAS/atomic
    transition binding the exact activation SHA and verified immutable asset
    snapshots against every authorized writer, so F12 stays false,
    release_authorized stays false, every publication write stays prohibited
    and self-asserted or locally simulated exclusivity must reject.
    """

    def setUp(self):
        self.sha = "a" * 40
        self.assets = {"one.txt": b"one\n", "two.bin": b"\x00two"}
        self.plan = PUBLICATION.bind_publication(self.sha, self.assets)
        self.contract = json.loads(
            (ROOT / "publication-writer-exclusion-v2.json").read_bytes()
        )

    def _require(self, contract):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "publication-writer-exclusion-v2.json"
            path.write_bytes(json.dumps(contract, indent=2, sort_keys=True).encode() + b"\n")
            with mock.patch.object(
                PUBLICATION, "WRITER_EXCLUSION_CONTRACT_PATH", path
            ), mock.patch.object(
                PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
            ):
                return PUBLICATION._require_publication_writer_exclusion(self.plan)

    def test_contract_keeps_f12_and_release_authorization_false(self):
        self.assertIs(self.contract["f12_closed"], False)
        self.assertIs(self.contract["release_authorized"], False)
        self.assertIs(self.contract["publication_writes_prohibited"], True)
        self.assertIs(self.contract["publication_performed"], False)

    def test_contract_seals_the_exact_technical_impossibility(self):
        impossibility = self.contract["exclusive_transition_impossibility"]
        self.assertIs(
            impossibility["documented_github_release_api_provides_it"], False
        )
        self.assertIs(impossibility["binds_exact_activation_sha"], False)
        self.assertIs(
            impossibility["binds_verified_immutable_asset_snapshots"], False
        )
        self.assertIs(impossibility["excludes_every_authorized_writer"], False)
        self.assertIs(impossibility["compare_and_swap_available"], False)
        self.assertIs(impossibility["atomic_transition_available"], False)
        self.assertIs(impossibility["self_asserted_exclusivity_rejected"], True)
        self.assertIs(impossibility["local_simulation_is_not_evidence"], True)
        self.assertTrue(impossibility["required_primitive"])
        self.assertTrue(impossibility["reason"])

    def test_contract_states_the_exhaustive_known_writer_model_limits(self):
        model = self.contract["known_writer_model"]
        self.assertIs(model["exhaustive"], False)
        self.assertEqual(
            model["enumerated_writer_classes"],
            sorted(model["enumerated_writer_classes"]),
        )
        self.assertTrue(model["enumerated_writer_classes"])
        self.assertTrue(model["unbounded_writer_classes"])
        self.assertTrue(model["limits"])
        for writer_class in model["unbounded_writer_classes"]:
            self.assertNotIn(writer_class, model["enumerated_writer_classes"])

    def test_contract_prohibits_every_publication_write_class(self):
        self.assertEqual(
            self.contract["prohibited_writes"],
            [
                "DELETE /repos/{repository}/releases/{release_id}",
                "PATCH /repos/{repository}/releases/{release_id}",
                "POST /repos/{repository}/git/refs",
                "POST /repos/{repository}/git/tags",
                "POST /repos/{repository}/releases",
                "POST uploads.github.com release assets",
            ],
        )
        self.assertIs(self.contract["every_publication_write_prohibited"], True)

    def test_shipped_contract_passes_the_writer_exclusion_gate(self):
        self.assertIsNone(self._require(self.contract))

    def test_self_asserted_or_simulated_exclusivity_rejects(self):
        for mutate in (
            lambda c: c["exclusive_transition_impossibility"].update(
                documented_github_release_api_provides_it=True,
            ),
            lambda c: c["exclusive_transition_impossibility"].update(
                compare_and_swap_available=True,
            ),
            lambda c: c["exclusive_transition_impossibility"].update(
                atomic_transition_available=True,
            ),
            lambda c: c["exclusive_transition_impossibility"].update(
                excludes_every_authorized_writer=True,
            ),
            lambda c: c["exclusive_transition_impossibility"].update(
                self_asserted_exclusivity_rejected=False,
            ),
            lambda c: c["exclusive_transition_impossibility"].update(
                local_simulation_is_not_evidence=False,
            ),
            lambda c: c["known_writer_model"].update(exhaustive=True),
            lambda c: c["known_writer_model"].update(unbounded_writer_classes=[]),
            lambda c: c.update(f12_closed=True),
            lambda c: c.update(release_authorized=True),
            lambda c: c.update(every_publication_write_prohibited=False),
            lambda c: c.update(publication_writes_prohibited=False),
            lambda c: c.update(publication_performed=True),
            lambda c: c.update(github_release_cas_supported=True),
            lambda c: c.update(prohibited_writes=[]),
            lambda c: c.pop("exclusive_transition_impossibility"),
            lambda c: c.pop("known_writer_model"),
        ):
            with self.subTest(mutate=mutate):
                contract = deepcopy(self.contract)
                mutate(contract)
                with self.assertRaises(SystemExit):
                    self._require(contract)

    def test_locally_simulated_exclusivity_evidence_is_rejected_outright(self):
        for evidence in (
            {"source": "local_simulation", "exclusive": True},
            {"source": "self_asserted", "exclusive": True},
            {"source": "documented_github_api", "exclusive": True},
            {"exclusive": True},
            None,
            "exclusive",
        ):
            with self.subTest(evidence=evidence):
                with self.assertRaises(SystemExit):
                    PUBLICATION.reject_self_asserted_exclusivity(evidence)

    def test_publish_still_fails_closed_with_the_exact_impossibility(self):
        issuance = authenticated_issuance(head=self.sha)
        server = mock.Mock()
        service = PUBLICATION.PublicationService(
            PUBLICATION.PublicationReadTransport(server),
            PUBLICATION.AdministrationReadAppTransport(server),
        )
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ), mock.patch.object(
            PUBLICATION, "verify_publication_plan",
            side_effect=lambda plan, *_arguments: plan,
        ), self.assertRaises(SystemExit) as raised:
            service.publish(
                issuance, self.assets, issuance.review_receipt_sha256,
                "/approved/cosign",
            )
        self.assertIn("publication is unavailable", str(raised.exception))
        server.request.assert_not_called()

    def test_policy_and_contract_agree_that_publication_stays_unavailable(self):
        policy = json.loads((ROOT / "authority-v2-policy.json").read_bytes())
        publication = policy["publication_contract"]
        self.assertEqual(publication["activation_state"], "unavailable")
        self.assertIs(publication["exhaustive_writer_exclusion_available"], False)
        self.assertEqual(
            publication["writer_exclusion_contract_path"],
            "publication-writer-exclusion-v2.json",
        )
        self.assertEqual(
            self.contract["activation_precondition"]["state"], "unavailable",
        )


class DerivedClaimTagObjectShaTests(AmbiguousClaimRefTests):
    """HIGH-1: the reconciler must bind the exact expected tag-object SHA.

    Without it, any other annotated tag object carrying the same payload,
    target and message is accepted as this attempt's claim.
    """

    def test_expected_tag_object_sha_is_derived_from_the_request_identity(self):
        message = self._claim_message()
        derived = PUBLICATION.expected_claim_tag_object_sha(
            self.plan.activation_sha, message,
        )
        self.assertRegex(derived, r"\A[0-9a-f]{40}\Z")
        self.assertEqual(
            derived,
            PUBLICATION.expected_claim_tag_object_sha(
                self.plan.activation_sha, message,
            ),
        )
        other = authenticated_issuance(head=self.sha, nonce="c" * 64)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            foreign = PUBLICATION._publication_claim_message(
                other, self.plan, self._guards(), 7,
            )
        self.assertNotEqual(
            derived,
            PUBLICATION.expected_claim_tag_object_sha(
                self.plan.activation_sha, foreign,
            ),
        )
        self.assertNotEqual(
            derived,
            PUBLICATION.expected_claim_tag_object_sha("b" * 40, message),
        )

    def test_reconciler_accepts_only_the_derived_tag_object_sha(self):
        message = self._claim_message()
        derived = PUBLICATION.expected_claim_tag_object_sha(
            self.plan.activation_sha, message,
        )
        server = RepositoryStateServer(
            self, claim_message=message, claim_tag_object_sha=derived,
        )
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            result = self._service(server).reconcile(self.issuance, self.plan)
        self.assertEqual(result["publication_state"], "claimed_draft")
        self.assertEqual(result["claim"]["tag_object_sha"], derived)
        self.assertEqual(result["writes_performed"], 0)

    def test_other_annotated_tag_object_with_matching_content_rejects(self):
        """Same payload, same target, same message, different tag object."""
        message = self._claim_message()
        derived = PUBLICATION.expected_claim_tag_object_sha(
            self.plan.activation_sha, message,
        )
        for substitute in ("f" * 40, "0" * 40, "1234567890abcdef" * 2 + "12345678"):
            with self.subTest(tag_object_sha=substitute):
                self.assertNotEqual(substitute, derived)
                server = RepositoryStateServer(
                    self, claim_message=message, claim_tag_object_sha=substitute,
                )
                with mock.patch.object(
                    PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES",
                    tuple(sorted(self.assets)),
                ), self.assertRaises(SystemExit) as raised:
                    self._service(server).reconcile(self.issuance, self.plan)
                self.assertIn("not authoritative", str(raised.exception))

    def test_classifier_receives_the_derived_tag_object_sha(self):
        message = self._claim_message()
        derived = PUBLICATION.expected_claim_tag_object_sha(
            self.plan.activation_sha, message,
        )
        server = RepositoryStateServer(
            self, claim_message=message, claim_tag_object_sha=derived,
        )
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ), mock.patch.object(
            PUBLICATION, "classify_claim_readback",
            wraps=PUBLICATION.classify_claim_readback,
        ) as classify:
            self._service(server).reconcile(self.issuance, self.plan)
        bound = [
            call.kwargs["expected_tag_object_sha"]
            for call in classify.call_args_list
            if call.kwargs.get("expected_tag_object_sha") is not None
        ]
        self.assertEqual(bound, [derived])


COMPLETE_PAGE = {"complete": True, "pages": 1, "prefix": "refs/tags/"}


class AuthenticatedRefAbsenceTests(AmbiguousClaimRefTests):
    """HIGH-2: a bare HTTP 404 is never confirmed absence.

    Absence needs explicit authenticated visibility evidence that the same
    credential could have seen the ref had it existed.
    """

    def test_404_without_absence_evidence_is_ambiguous(self):
        self.assertEqual(
            PUBLICATION.classify_ref_read(404), "readback_ambiguous",
        )
        self.assertEqual(
            PUBLICATION.classify_ref_read(404, absence_evidence=None),
            "readback_ambiguous",
        )

    def test_404_with_authenticated_visibility_listing_is_confirmed_absent(self):
        evidence = {
            "authenticated": True,
            "status": 200,
            "complete": True,
            "pages": 1,
            "prefix": "refs/tags/",
            "refs": [{"ref": "refs/tags/unrelated"}],
        }
        self.assertEqual(
            PUBLICATION.classify_ref_read(
                404, absence_evidence=evidence,
                expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
            ),
            "confirmed_absent",
        )

    def test_masked_or_contradictory_absence_evidence_is_ambiguous(self):
        for evidence in (
            {"authenticated": False, "status": 200, "refs": [], **COMPLETE_PAGE},
            {"authenticated": True, "status": 403, "refs": [], **COMPLETE_PAGE},
            {"authenticated": True, "status": 404, "refs": [], **COMPLETE_PAGE},
            {"authenticated": True, "status": 200, **COMPLETE_PAGE},
            {"authenticated": True, "status": 200, "refs": "none", **COMPLETE_PAGE},
            {"status": 200, "refs": [], **COMPLETE_PAGE},
            {"authenticated": True, "status": 200, **COMPLETE_PAGE,
             "refs": [{"ref": PUBLICATION.PUBLICATION_CLAIM_REF}]},
            {"authenticated": True, "status": 200, "refs": [{"name": "x"}],
             **COMPLETE_PAGE},
            "listing",
            [],
            None,
        ):
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    PUBLICATION.classify_ref_read(
                        404, absence_evidence=evidence,
                        expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
                    ),
                    "readback_ambiguous",
                )

    def test_200_and_error_statuses_keep_their_documented_meaning(self):
        self.assertEqual(PUBLICATION.classify_ref_read(200), "confirmed_present")
        for status in (401, 403, 429, 500, 502, 503, None):
            with self.subTest(status=status):
                self.assertEqual(
                    PUBLICATION.classify_ref_read(status), "unknown_error",
                )

    def test_reconciler_reads_authenticated_visibility_before_trusting_404(self):
        server = RepositoryStateServer(self)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            result = self._service(server).reconcile(self.issuance, self.plan)
        self.assertEqual(result["publication_state"], "unclaimed_draft")
        self.assertEqual(result["writes_performed"], 0)
        self.assertIn(
            PUBLICATION.tag_ref_visibility_page_path(1),
            [path for _method, path, _headers, _body in server.calls],
        )

    def test_permission_masked_404_listing_prohibits_progression(self):
        for masked_status in (403, 404, 401, 500):
            with self.subTest(masked_status=masked_status):
                server = RepositoryStateServer(
                    self, tag_listing_status=masked_status,
                )
                with mock.patch.object(
                    PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES",
                    tuple(sorted(self.assets)),
                ), self.assertRaises(SystemExit) as raised:
                    self._service(server).reconcile(self.issuance, self.plan)
                self.assertIn("authenticated", str(raised.exception))

    def test_unconfirmed_404_contradicted_by_the_listing_prohibits_progression(self):
        server = RepositoryStateServer(self, tag_listing_includes_claim=True)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ), self.assertRaises(SystemExit):
            self._service(server).reconcile(self.issuance, self.plan)

    def test_absence_evidence_is_never_a_write(self):
        server = RepositoryStateServer(self)
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            self._service(server).reconcile(self.issuance, self.plan)
        for method, _path, _headers, _body in server.calls:
            self.assertEqual(method, "GET")


class TagRefVisibilityPaginationTests(AmbiguousClaimRefTests):
    """HIGH: one matching-refs page is not proof of exhaustive absence.

    After an exact-ref 404, absence is only authenticated when the exact
    matching-refs endpoint is traversed deterministically and exhaustively by
    the same credential, every page reads successfully, the pagination
    metadata is well formed, monotonic and non-looping, every ref carries the
    exact expected prefix, and completion is explicitly proven.
    """

    def _visibility_path(self, page):
        return (
            f"{PUBLICATION.TAG_REF_VISIBILITY_PATH}"
            f"?per_page={PUBLICATION.TAG_REF_PAGE_SIZE}&page={page}"
        )

    def _paged_server(self, pages, **kwargs):
        return RepositoryStateServer(self, tag_ref_pages=pages, **kwargs)

    def _reconcile(self, server):
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ):
            return self._service(server).reconcile(self.issuance, self.plan)

    def _expect_ambiguous(self, server):
        with mock.patch.object(
            PUBLICATION, "EXPECTED_RELEASE_ASSET_NAMES", tuple(sorted(self.assets))
        ), self.assertRaises(SystemExit) as raised:
            self._service(server).reconcile(self.issuance, self.plan)
        return str(raised.exception)

    # --- the exhaustive positive path ---

    def test_exhaustive_multi_page_absence_is_authenticated(self):
        pages = [
            {"refs": [{"ref": f"refs/tags/bulk-{index}"} for index in range(3)],
             "next": 2},
            {"refs": [{"ref": "refs/tags/last-unrelated-tag"}], "next": None},
        ]
        server = self._paged_server(pages)
        result = self._reconcile(server)
        self.assertEqual(result["publication_state"], "unclaimed_draft")
        self.assertEqual(result["writes_performed"], 0)
        requested = [path for _m, path, _h, _b in server.calls]
        self.assertIn(self._visibility_path(1), requested)
        self.assertIn(self._visibility_path(2), requested)
        for method, _path, _headers, _body in server.calls:
            self.assertEqual(method, "GET")

    # --- the defect: the target hides on a later page ---

    def test_target_on_page_two_is_never_absence(self):
        pages = [
            {"refs": [{"ref": "refs/tags/unrelated-existing-tag"}], "next": 2},
            {"refs": [{"ref": PUBLICATION.PUBLICATION_CLAIM_REF}], "next": None},
        ]
        message = self._expect_ambiguous(self._paged_server(pages))
        self.assertIn("readback_ambiguous", message)

    def test_target_on_a_deep_page_is_never_absence(self):
        pages = [
            {"refs": [{"ref": f"refs/tags/bulk-{index}"}], "next": index + 2}
            for index in range(4)
        ]
        pages.append({"refs": [{"ref": PUBLICATION.PUBLICATION_CLAIM_REF}],
                      "next": None})
        message = self._expect_ambiguous(self._paged_server(pages))
        self.assertIn("readback_ambiguous", message)

    # --- incomplete or missing completeness evidence ---

    def test_unterminated_traversal_is_ambiguous(self):
        """A final page that still advertises a next page never completes."""
        pages = [
            {"refs": [{"ref": "refs/tags/unrelated-existing-tag"}], "next": 2},
            {"refs": [{"ref": "refs/tags/second"}], "next": 3},
        ]
        message = self._expect_ambiguous(self._paged_server(pages))
        self.assertIn("readback_ambiguous", message)

    def test_traversal_beyond_the_bound_is_ambiguous(self):
        pages = [
            {"refs": [{"ref": f"refs/tags/bulk-{index}"}], "next": index + 2}
            for index in range(PUBLICATION.MAX_TAG_REF_PAGES + 2)
        ]
        message = self._expect_ambiguous(self._paged_server(pages))
        self.assertIn("readback_ambiguous", message)

    def test_evidence_without_explicit_completion_is_ambiguous(self):
        for evidence in (
            {"authenticated": True, "status": 200, "refs": [], "pages": 1,
             "prefix": "refs/tags/"},
            {"authenticated": True, "status": 200, "refs": [], "complete": False,
             "pages": 1, "prefix": "refs/tags/"},
            {"authenticated": True, "status": 200, "refs": [], "complete": "yes",
             "pages": 1, "prefix": "refs/tags/"},
            {"authenticated": True, "status": 200, "refs": [], "complete": True,
             "pages": 0, "prefix": "refs/tags/"},
            {"authenticated": True, "status": 200, "refs": [], "complete": True,
             "pages": 1, "prefix": "refs/heads/"},
            {"authenticated": True, "status": 200,
             "refs": [{"ref": "refs/heads/main"}], "complete": True, "pages": 1,
             "prefix": "refs/tags/"},
        ):
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    PUBLICATION.classify_ref_read(
                        404, absence_evidence=evidence,
                        expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
                    ),
                    "readback_ambiguous",
                )

    def test_complete_exhaustive_evidence_is_confirmed_absent(self):
        self.assertEqual(
            PUBLICATION.classify_ref_read(
                404,
                absence_evidence={
                    "authenticated": True,
                    "status": 200,
                    "refs": [{"ref": "refs/tags/unrelated-existing-tag"}],
                    "complete": True,
                    "pages": 2,
                    "prefix": "refs/tags/",
                },
                expected_ref=PUBLICATION.PUBLICATION_CLAIM_REF,
            ),
            "confirmed_absent",
        )

    # --- malformed / contradictory / looping pagination metadata ---

    def test_malformed_link_header_is_ambiguous(self):
        for link in (
            "not-a-link-header",
            "<>; rel=\"next\"",
            "<https://api.github.com/nonsense>; rel=\"next\"",
            "; rel=\"next\"",
            "<{path}?per_page=100&page=abc>; rel=\"next\"",
            "<{path}?per_page=7&page=2>; rel=\"next\"",
            "<{path}?page=2>; rel=\"next\"",
            "<{other}?per_page=100&page=2>; rel=\"next\"",
        ):
            with self.subTest(link=link):
                pages = [{
                    "refs": [{"ref": "refs/tags/unrelated-existing-tag"}],
                    "raw_link": link.format(
                        path=PUBLICATION.TAG_REF_VISIBILITY_PATH,
                        other=f"/repos/{PUBLICATION.EXPECTED_REPOSITORY}/git/refs",
                    ),
                }]
                message = self._expect_ambiguous(self._paged_server(pages))
                self.assertIn("readback_ambiguous", message)

    def test_contradictory_or_looping_next_links_are_ambiguous(self):
        for name, pages in {
            "self-loop": [
                {"refs": [{"ref": "refs/tags/a"}], "next": 1},
            ],
            "backwards": [
                {"refs": [{"ref": "refs/tags/a"}], "next": 2},
                {"refs": [{"ref": "refs/tags/b"}], "next": 1},
            ],
            "skips-a-page": [
                {"refs": [{"ref": "refs/tags/a"}], "next": 3},
            ],
            "zero-page": [
                {"refs": [{"ref": "refs/tags/a"}], "next": 0},
            ],
        }.items():
            with self.subTest(name=name):
                message = self._expect_ambiguous(self._paged_server(pages))
                self.assertIn("readback_ambiguous", message)

    def test_duplicate_link_headers_are_ambiguous(self):
        pages = [{
            "refs": [{"ref": "refs/tags/a"}],
            "duplicate_link": True,
            "next": 2,
        }]
        message = self._expect_ambiguous(self._paged_server(pages))
        self.assertIn("readback_ambiguous", message)

    # --- page-fetch ambiguity ---

    def test_page_fetch_failure_is_ambiguous(self):
        for status in (403, 404, 429, 500, 502):
            with self.subTest(status=status):
                pages = [
                    {"refs": [{"ref": "refs/tags/a"}], "next": 2},
                    {"status": status},
                ]
                message = self._expect_ambiguous(self._paged_server(pages))
                self.assertIn("readback_ambiguous", message)

    def test_malformed_page_body_is_ambiguous(self):
        for name, page in {
            "not-a-list": {"body": {"refs": []}},
            "entry-not-a-dict": {"refs": ["refs/tags/a"]},
            "entry-without-ref": {"refs": [{"name": "a"}]},
            "empty-ref": {"refs": [{"ref": ""}]},
            "wrong-prefix": {"refs": [{"ref": "refs/heads/main"}]},
        }.items():
            with self.subTest(name=name):
                message = self._expect_ambiguous(self._paged_server([page]))
                self.assertIn("readback_ambiguous", message)

    def test_first_page_failure_is_ambiguous_and_reads_nothing_further(self):
        server = self._paged_server([{"status": 403}])
        self._expect_ambiguous(server)
        requested = [path for _m, path, _h, _b in server.calls]
        self.assertIn(self._visibility_path(1), requested)
        self.assertNotIn(self._visibility_path(2), requested)

    # --- prior semantics preserved ---

    def test_exhaustive_absence_preserves_the_derived_tag_object_binding(self):
        message = self._claim_message()
        derived = PUBLICATION.expected_claim_tag_object_sha(
            self.plan.activation_sha, message,
        )
        server = self._paged_server(
            [
                {"refs": [{"ref": PUBLICATION.PUBLICATION_CLAIM_REF}], "next": 2},
                {"refs": [{"ref": "refs/tags/other"}], "next": None},
            ],
            claim_message=message,
            claim_tag_object_sha=derived,
        )
        result = self._reconcile(server)
        self.assertEqual(result["publication_state"], "claimed_draft")
        self.assertEqual(result["claim"]["tag_object_sha"], derived)


class SealedPublicationImpossibilityProofTests(ExclusivePublicationImpossibilityTests):
    """The impossibility must be sealed with authoritative semantics and the
    exact exhaustive-writer proof that GitHub does not make available.

    F12 stays false because no documented server primitive atomically binds the
    final immutable release assets to the exact activation SHA while excluding
    every authorized writer, and because no documented endpoint can enumerate
    those writers exhaustively. Both facts are sealed with citations rather
    than asserted, and nothing here simulates a closure.
    """

    def test_documented_create_ref_status_semantics_are_cited_exactly(self):
        citations = self.contract["authoritative_semantic_citations"]
        self.assertIsInstance(citations, list)
        self.assertGreaterEqual(len(citations), 3)
        by_status = {}
        for citation in citations:
            self.assertEqual(
                sorted(citation),
                ["documented_behaviour", "endpoint", "proves_exclusivity",
                 "source", "status"],
            )
            self.assertIs(citation["proves_exclusivity"], False)
            self.assertTrue(citation["source"].startswith("https://docs.github.com/"))
            if citation["endpoint"] == PUBLICATION.CREATE_REF_ENDPOINT:
                by_status[citation["status"]] = citation
        self.assertEqual(sorted(by_status), [201, 409, 422])
        self.assertIn("created", by_status[201]["documented_behaviour"].lower())
        self.assertIn("conflict", by_status[409]["documented_behaviour"].lower())
        self.assertIn("validation", by_status[422]["documented_behaviour"].lower())
        self.assertTrue(
            any(
                citation["endpoint"] != PUBLICATION.CREATE_REF_ENDPOINT
                for citation in citations
            ),
            "the absent release compare-and-swap semantics are not cited",
        )

    def test_missing_exhaustive_writer_proof_is_sealed_not_invented(self):
        proof = self.contract["missing_exhaustive_writer_proof"]
        self.assertIs(proof["proof_available"], False)
        self.assertIs(proof["writer_set_is_unbounded"], True)
        self.assertIs(proof["simulated_or_self_asserted_proof_rejected"], True)
        self.assertTrue(proof["required_proof"])
        self.assertTrue(proof["unavailable_because"])
        self.assertTrue(proof["attempted_live_inventory_endpoints"])
        for entry in proof["attempted_live_inventory_endpoints"]:
            self.assertEqual(
                sorted(entry), ["endpoint", "insufficient_because", "returns"],
            )
            self.assertTrue(entry["insufficient_because"])

    def test_the_verifier_rejects_a_weakened_or_absent_proof(self):
        self._require(self.contract)
        for mutate in (
            lambda c: c.pop("authoritative_semantic_citations"),
            lambda c: c.pop("missing_exhaustive_writer_proof"),
            lambda c: c["missing_exhaustive_writer_proof"].update(
                proof_available=True,
            ),
            lambda c: c["missing_exhaustive_writer_proof"].update(
                writer_set_is_unbounded=False,
            ),
            lambda c: c["missing_exhaustive_writer_proof"].update(
                simulated_or_self_asserted_proof_rejected=False,
            ),
            lambda c: c["missing_exhaustive_writer_proof"].update(
                attempted_live_inventory_endpoints=[],
            ),
            lambda c: c["authoritative_semantic_citations"].pop(0),
            lambda c: c["authoritative_semantic_citations"][0].update(
                proves_exclusivity=True,
            ),
            lambda c: c["authoritative_semantic_citations"][0].update(
                source="https://example.invalid/made-up",
            ),
        ):
            with self.subTest(mutate=mutate):
                payload = deepcopy(self.contract)
                mutate(payload)
                with self.assertRaises(SystemExit):
                    self._require(payload)

    def test_no_status_or_transport_outcome_is_ever_exclusivity_evidence(self):
        for status in (201, 409, 422, 500):
            outcome = PUBLICATION.classify_create_ref_outcome(status)
            self.assertNotEqual(outcome, "already_exists")
        self.assertEqual(
            PUBLICATION.classify_create_ref_outcome(None), "transport_ambiguous",
        )
        with self.assertRaises(SystemExit):
            PUBLICATION.reject_self_asserted_exclusivity(
                {"exclusive": True, "source": "local-simulation"},
            )


# ---------------------------------------------------------------------------
# Verify-only publication: identical deep verification, no transport, no write
# ---------------------------------------------------------------------------
class VerifyOnlyPublicationPreflightTests(VerifiedPublicationPlanTests):
    """`--verify-only` runs the same preflight the publish path runs."""

    def verify_only(self, root, payloads):
        """Drive verify-only with no patch, bypass or stand-in of any kind.

        Every reachable leg runs for real. The deep plan leg is genuinely
        unreachable until the source chain is pinned, and the result says so
        truthfully rather than being patched into a success.
        """
        assets = self._materialise(root, payloads)
        return PUBLICATION.verify_only_publication_state(
            assets,
            review_receipt_sha256=self.receipt_sha256,
            cosign_path=self._approved_cosign(root),
            authenticated_issuance=self.issuance,
            # The one canonical *complete* map, composed over exactly these
            # bytes before the gate runs, exactly as the production lane
            # composes it: every release asset, never the evidence subset.
            canonical_inventory={
                "digests": {
                    name: hashlib.sha256(assets[name]).hexdigest()
                    for name in sorted(
                        PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES,
                    )
                },
                "inventory": sorted(
                    PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES,
                ),
            },
        )

    def test_verify_only_runs_the_same_preflight_as_publish(self):
        with tempfile.TemporaryDirectory() as td:
            observed = self.verify_only(Path(td), self._publication_assets())
        self.assertIs(observed["f12_closed"], False)
        self.assertIs(observed["release_authorized"], False)
        self.assertIs(observed["verify_only"], True)
        self.assertEqual(observed["writes_performed"], 0)
        self.assertEqual(observed["transports_constructed"], 0)
        self.assertEqual(observed["publication"], "unavailable")
        # Truthful blocked result: the deep plan leg is unreachable until the
        # source chain is pinned, and nothing pretends otherwise.
        self.assertEqual(observed["state"], "blocked")
        self.assertIs(observed["deep_plan_verified"], False)
        self.assertEqual(
            observed["blocked_by"], PUBLICATION.SOURCE_CHAIN_BLOCKER,
        )
        self.assertEqual(
            observed["assets_verified"],
            len(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES),
        )
        self.assertEqual(
            observed["release_evidence_verified"],
            len(PUBLICATION.RELEASE_EVIDENCE_ASSET_NAMES),
        )
        self.assertIn("authority-v2-runner-state.json", observed["inventory"])
        self.assertEqual(len(observed["inventory"]), 14)

    def test_verify_only_rejects_every_corrupt_or_swapped_asset(self):
        for label, damage in (
            ("corrupt-subject", ("authority-v2-future.json", b'{"forged":1}\n')),
            ("corrupt-bundle",
             ("authority-v2-future.sigstore.json", b'{"forged":1}\n')),
            ("corrupt-runner-state",
             ("authority-v2-runner-state.json", b'{"forged":1}\n')),
            ("corrupt-release-manifest",
             ("AUTHORITY-V2-RELEASE-SHA256SUMS", b"0\n")),
            ("corrupt-policy", ("authority-v2-policy.json", b"{}\n")),
        ):
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as td:
                    payloads = self._publication_assets()
                    payloads[damage[0]] = damage[1]
                    with self.assertRaises(SystemExit):
                        self.verify_only(Path(td), payloads)

    def test_verify_only_constructs_no_transport_and_reaches_no_write(self):
        calls = []

        class Trap:
            def __init__(self, *args, **kwargs):
                calls.append(("constructed", args, kwargs))

            def __getattr__(self, name):
                raise AssertionError(f"transport used in verify-only: {name}")

        with tempfile.TemporaryDirectory() as td:
            with (
                mock.patch.object(PUBLICATION, "GitHubTransport", Trap),
                mock.patch.object(PUBLICATION, "PublicationReadTransport", Trap),
                mock.patch.object(
                    PUBLICATION, "AdministrationReadAppTransport", Trap,
                ),
                mock.patch.object(
                    PUBLICATION.PublicationService, "publish",
                    lambda *a, **k: (_ for _ in ()).throw(
                        AssertionError("publish reached in verify-only")
                    ),
                ),
            ):
                observed = self.verify_only(
                    Path(td), self._publication_assets(),
                )
        self.assertEqual(calls, [], "verify-only constructed a transport")
        self.assertIs(observed["verify_only"], True)

    def test_verify_only_uses_no_patch_bypass_or_stand_in(self):
        """The positive verify-only path exercises the real verification."""
        source = (ROOT / "tests" / "test_publication_v2.py").read_text()
        block = source.split("    def verify_only(self, root, payloads):", 1)[1]
        block = block.split("\n    def ", 1)[0]
        for forbidden in ("_verification" + "_patches", "mock.patch", "patches["):
            self.assertNotIn(forbidden, block, forbidden)

    def test_the_publish_path_still_fails_closed_after_the_same_preflight(self):
        source = (ROOT / "scripts" / "verify_publication_v2.py").read_text()
        self.assertIn("_publication_preflight", source)
        # Both paths run the identical preflight helper.
        self.assertEqual(source.count("_publication_preflight("), 3)
        self.assertIn(
            "Authority-v2 publication is unavailable", source,
        )


# ---------------------------------------------------------------------------
# F12-VERIFY-ONLY-CLI-AND-EVIDENCE-TERMINAL-BROKEN
#
# The verify-only precondition only ever consulted the *candidate's own*
# activation package. The shipped candidate is a false builder - `f8_closed`
# is false by construction and must stay false - so verify-only could never
# reach `verified`, whatever real evidence existed. The gap is that the real
# F8 evidence does not live in the candidate: it is the derived live
# activation closure that `pin_source_chain_activation_v2.py --phase closure`
# seals beside the checkout after authenticating live evidence.
#
# The precondition now consults that derived closure and *re-derives*
# readiness from it through the unchanged Authority verifier. Nothing here
# trusts a flag: a closure the Authority boundary does not itself derive a
# closed F8 from leaves verify-only blocked. The candidate's own posture is
# untouched, so absent that authenticated evidence the answer is still
# `blocked_by = F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE`.
# ---------------------------------------------------------------------------
def derived_closure_package(**damage):
    """A derived closure with the fields real live evidence would pin."""
    package = json.loads(
        (ROOT / "source-chain-activation-v2.json").read_bytes()
    )
    activation = PUBLICATION._activation_module()
    def digest(seed):
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()
    def oid(seed):
        return hashlib.sha1(seed.encode("utf-8")).hexdigest()
    for field in activation.PRODUCER_UNPINNED_FIELDS:
        package["producer_bindings"][field] = (
            oid(field) if field == "certificate_github_workflow_sha"
            else digest(field)
        )
    for field in activation.REVIEWED_SOURCE_UNPINNED_FIELDS:
        package["reviewed_source"][field] = oid(field)
    package["external_activation_review"]["state"] = (
        activation.EXTERNAL_REVIEW_AUTHENTICATED
    )
    package["external_activation_review"]["receipt_sha256"] = digest("receipt")
    # A real derived closure declares the readiness its evidence supports.
    # The Authority re-derives it and refuses any package where the two
    # disagree, in either direction.
    for key, value in {
        "activation_authorized": True, "activation_state": "ready",
        "f8_closed": True, "live_evidence_pinned": True,
        "repositories_created": True, "runs_observed": True,
        "workflows_written": True,
    }.items():
        if key in package:
            package[key] = value
    # A ready package describes repositories, runs and dispatch that really
    # exist. These mirror what the closure phase fills in from live evidence.
    for name, entry in (package.get("target_repositories") or {}).items():
        entry["created"] = True
        # `workflow_dispatch_authorized` stays false even when ready: the
        # activation never authorises its own dispatch.
        if entry.get("repository_id") is None:
            entry["repository_id"] = 55667788
        if entry.get("repository_node_id") is None:
            entry["repository_node_id"] = "R_kgDO" + name.split("/")[-1][:12]
    dispatch = package.get("authorized_dispatch")
    if isinstance(dispatch, dict) and dispatch.get("run_id") is None:
        dispatch["run_id"] = 3344556677
    proof = package.get("post_activation_proof")
    if isinstance(proof, dict):
        proof["live_evidence_pinned"] = True
    for key, value in damage.items():
        section, _, field = key.partition("__")
        package[section][field] = value
    return package


def _bare_flag_package():
    """Declares a closed F8 while carrying no pinned evidence at all."""
    package = json.loads(
        (ROOT / "source-chain-activation-v2.json").read_bytes()
    )
    for key, value in {
        "activation_authorized": True, "activation_state": "ready",
        "f8_closed": True, "live_evidence_pinned": True,
        "repositories_created": True, "runs_observed": True,
        "workflows_written": True,
    }.items():
        if key in package:
            package[key] = value
    return package


class DerivedClosureVerifyOnlyTests(VerifyOnlyPublicationPreflightTests):
    """Verify-only reaches `verified` only on real derived F8 evidence."""

    def place(self, package):
        """Seal a derived closure exactly where the closure phase seals it."""
        activation = PUBLICATION._activation_module()
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(
                PUBLICATION, "LIVE_ACTIVATION_EVIDENCE_DIRECTORY",
                str(directory),
            )
        )
        target = directory / PUBLICATION.DERIVED_CLOSURE_NAME
        target.write_bytes(activation.canonical_bytes(package))
        return target

    def test_the_candidate_alone_still_blocks_verify_only(self):
        """The false builder posture is untouched by any of this."""
        self.assertIsNone(
            getattr(PUBLICATION, "_authenticated_derived_closure")(),
            "a derived closure is present before the test placed one",
        )
        with tempfile.TemporaryDirectory() as td:
            observed = self.verify_only(Path(td), self._publication_assets())
        self.assertEqual(observed["state"], "blocked")
        self.assertEqual(
            observed["blocked_by"], PUBLICATION.SOURCE_CHAIN_BLOCKER,
        )

    def test_authenticated_derived_evidence_clears_the_precondition(self):
        """The precondition the finding names really is cleared.

        The blocker is derived, not declared: with an authenticated derived
        closure in place `_release_evidence_precondition` returns `None`, so
        `SOURCE_CHAIN_BLOCKER` is no longer what stands between this run and
        a `verified` result.

        Reaching `state=verified` additionally requires the candidate's own
        sealed independent-review bootstrap contract to be in the `ready`
        activation state, because the deep plan leg re-derives the Authority
        candidate through `pinned_independent_bootstrap_commit`. Only a real
        closure run against live GitHub evidence regenerates the candidate
        into that state. This test therefore proves the precondition, and
        never synthesises the verified document.
        """
        self.place(derived_closure_package())
        self.assertIsNone(
            PUBLICATION._release_evidence_precondition(),
            "authenticated derived evidence did not clear the precondition",
        )
        bound = PUBLICATION._authenticated_derived_closure()
        self.assertIsNotNone(bound)
        self.assertRegex(bound["derived_closure_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertRegex(
            bound["external_review_receipt_sha256"], r"\A[0-9a-f]{64}\Z",
        )
        # The candidate's own posture is untouched by any of this.
        candidate = json.loads(
            (ROOT / "source-chain-activation-v2.json").read_bytes()
        )
        self.assertIs(candidate["f8_closed"], False)
        self.assertIs(candidate["activation_authorized"], False)

    def test_the_deep_leg_still_requires_a_ready_candidate_bootstrap(self):
        """Truthful: the remaining gate is the candidate, not the blocker."""
        self.place(derived_closure_package())
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as raised:
                self.verify_only(Path(td), self._publication_assets())
        self.assertIn("bootstrap", str(raised.exception))

    def test_a_closure_the_authority_refuses_leaves_verify_only_blocked(self):
        """No flag is trusted: the Authority must derive the closure itself."""
        for label, package in (
            ("unauthenticated-external",
             derived_closure_package(
                 external_activation_review__state="unavailable",
                 external_activation_review__receipt_sha256=None,
             )),
            ("partially-pinned-producer",
             derived_closure_package(
                 producer_bindings__envelope_sha256=None,
             )),
            # The bare flag: a package that declares a closed F8 while its
            # evidence is entirely unpinned. Only re-derivation refuses this.
            ("self-declared-closed-with-no-evidence", _bare_flag_package()),
        ):
            with self.subTest(label=label):
                target = self.place(package)
                with tempfile.TemporaryDirectory() as td:
                    observed = self.verify_only(
                        Path(td), self._publication_assets(),
                    )
                self.assertEqual(observed["state"], "blocked", label)
                self.assertEqual(
                    observed["blocked_by"], PUBLICATION.SOURCE_CHAIN_BLOCKER,
                )
                target.unlink()

    def test_the_precondition_never_reads_a_caller_supplied_flag(self):
        source = (ROOT / "scripts" / "verify_publication_v2.py").read_text()
        block = source.split("def _authenticated_derived_closure", 1)[1]
        block = block.split("\ndef ", 1)[0]
        self.assertIn("verify_activation_package", block)
        self.assertIn("with_readiness=True", block)
        # The closure's own declared state is never what is believed.
        self.assertNotIn('package["f8_closed"] is True', block)


# ---------------------------------------------------------------------------
# F12-INVENTORY-MAP-NOT-CANONICAL-OR-SHARED
#
# The gate used to build its own digest map out of whatever `--asset` handed
# it. Nothing tied that map to the one canonical complete map composed before
# the gate, so the gate could confirm one inventory while the manifest and the
# seal described another. The gate now consumes that exact map and compares it
# in both directions, by name and by digest, against the bytes it verified.
# ---------------------------------------------------------------------------
class VerifyOnlyCanonicalInventoryTests(VerifyOnlyPublicationPreflightTests):
    """The gate consumes the one canonical map and never derives its own."""

    def state(self, root, *, mutate=None):
        payloads = self._publication_assets()
        assets = self._materialise(root, payloads)
        names = sorted(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES)
        canonical = {
            "digests": {
                name: hashlib.sha256(assets[name]).hexdigest()
                for name in names
            },
            "inventory": names,
        }
        if mutate is not None:
            mutate(canonical)
        return PUBLICATION.verify_only_publication_state(
            assets,
            review_receipt_sha256=self.receipt_sha256,
            cosign_path=self._approved_cosign(root),
            authenticated_issuance=self.issuance,
            canonical_inventory=canonical,
        )

    def test_the_gate_reports_the_canonical_map_it_consumed(self):
        """The map covers exactly the bytes that become terminal and sealed."""
        names = sorted(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES)
        with tempfile.TemporaryDirectory() as td:
            observed = self.state(Path(td))
        self.assertEqual(
            observed["canonical_inventory_sha256"],
            hashlib.sha256(json.dumps({
                "digests": {
                    name: observed["asset_digests"][name] for name in names
                },
                "inventory": names,
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n").hexdigest(),
        )

    def test_a_map_that_omits_a_verified_asset_is_refused(self):
        def drop(canonical):
            name = canonical["inventory"][0]
            canonical["digests"].pop(name)
            canonical["inventory"].remove(name)

        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as raised:
                self.state(Path(td), mutate=drop)
        self.assertIn("canonical inventory", str(raised.exception))

    def test_a_map_that_names_an_asset_that_was_never_verified_is_refused(self):
        def add(canonical):
            canonical["digests"]["authority-v2-phantom.json"] = "c" * 64
            canonical["inventory"] = sorted(canonical["digests"])


        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as raised:
                self.state(Path(td), mutate=add)
        self.assertIn("canonical inventory", str(raised.exception))

    def test_a_map_digest_that_is_not_the_verified_bytes_is_refused(self):
        def drift(canonical):
            canonical["digests"][canonical["inventory"][0]] = "d" * 64

        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as raised:
                self.state(Path(td), mutate=drift)
        self.assertIn("canonical inventory", str(raised.exception))

    def test_the_gate_cannot_run_without_the_canonical_map(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            assets = self._materialise(root, self._publication_assets())
            with self.assertRaises(SystemExit) as raised:
                PUBLICATION.verify_only_publication_state(
                    assets,
                    review_receipt_sha256=self.receipt_sha256,
                    cosign_path=self._approved_cosign(root),
                    authenticated_issuance=self.issuance,
                    canonical_inventory=None,
                )
        self.assertIn("canonical inventory", str(raised.exception))


# ---------------------------------------------------------------------------
# F12-CANONICAL-INVENTORY-NOT-COMPLETE
#
# The gate verified all fourteen release assets, but the one canonical map it
# consumed covered only the eight release-evidence members - so the map the
# final evidence manifest carried and the seal made immutable was a subset of
# what was gated. Six verified assets were gated and never sealed:
# `authority-v2-policy.json`, `authority-v2-subject.schema.json`,
# `github-environment-v2-contract.json`, `preissuance-review-receipt.json`,
# `preissuance-review-receipt.sigstore.json` and
# `protected-asset-receipt-v2.json`.
#
# One map, complete, in both directions: every asset the gate verifies is a
# member of it and every member of it is an asset the gate verified.
# ---------------------------------------------------------------------------
GATED_BUT_NEVER_SEALED = (
    "authority-v2-policy.json",
    "authority-v2-subject.schema.json",
    "github-environment-v2-contract.json",
    "preissuance-review-receipt.json",
    "preissuance-review-receipt.sigstore.json",
    "protected-asset-receipt-v2.json",
)


class CompleteCanonicalInventoryTests(VerifyOnlyPublicationPreflightTests):
    """The one canonical map is the complete release asset inventory."""

    def gate(self, root, names):
        """The gate, driven with a canonical map scoped to `names`."""
        assets = self._materialise(root, self._publication_assets())
        names = sorted(names)
        return PUBLICATION.verify_only_publication_state(
            assets,
            review_receipt_sha256=self.receipt_sha256,
            cosign_path=self._approved_cosign(root),
            authenticated_issuance=self.issuance,
            canonical_inventory={
                "digests": {
                    name: hashlib.sha256(assets[name]).hexdigest()
                    for name in names
                },
                "inventory": names,
            },
        )

    def test_the_complete_fourteen_asset_map_is_the_canonical_map(self):
        """The map the gate accepts covers every asset it verified."""
        names = sorted(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES)
        self.assertEqual(len(names), 14)
        with tempfile.TemporaryDirectory() as td:
            observed = self.gate(Path(td), names)
        self.assertEqual(sorted(observed["asset_digests"]), names)
        self.assertEqual(
            observed["canonical_inventory_sha256"],
            hashlib.sha256(json.dumps({
                "digests": {
                    name: observed["asset_digests"][name] for name in names
                },
                "inventory": names,
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n").hexdigest(),
        )

    def test_a_map_scoped_to_the_release_evidence_subset_is_refused(self):
        """The exact prior defect: gated fourteen, mapped and sealed eight."""
        subset = sorted(PUBLICATION.RELEASE_EVIDENCE_ASSET_NAMES)
        self.assertEqual(len(subset), 8)
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as raised:
                self.gate(Path(td), subset)
        self.assertIn("canonical inventory", str(raised.exception))

    def test_every_asset_omitted_by_the_prior_defect_is_in_the_map(self):
        """Each of the six is named, individually, in both directions."""
        names = sorted(PUBLICATION.EXPECTED_RELEASE_ASSET_NAMES)
        for omitted in GATED_BUT_NEVER_SEALED:
            self.assertIn(omitted, names, omitted)
            self.assertNotIn(
                omitted, PUBLICATION.RELEASE_EVIDENCE_ASSET_NAMES, omitted,
            )
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(SystemExit) as raised:
                    self.gate(
                        Path(td),
                        [name for name in names if name != omitted],
                    )
            self.assertIn("canonical inventory", str(raised.exception), omitted)


if __name__ == "__main__":
    unittest.main()
