#!/usr/bin/env python3
"""Fail-closed Authority-v2 candidate, receipt, and signed-release verifier."""
import argparse
import hashlib
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

SAFE_ZIP_MEMBER_BYTES = 8 * 1024 * 1024
SAFE_ZIP_AGGREGATE_BYTES = 32 * 1024 * 1024
ZIP_CREATOR_MSDOS = 0
ZIP_CREATOR_UNIX = 3
ZIP_NON_UNIX_CREATOR_SYSTEMS = frozenset((ZIP_CREATOR_MSDOS,))
ISSUANCE_REVIEW_ARTIFACT_MEMBERS = {
    "authority-v2-signed-review-t_c298fca4": (
        "kanban-review-envelope.json",
        "preissuance-review-receipt.json",
        "preissuance-review-receipt.sigstore.json",
    ),
    "authority-v2-external-activation-review-t_c298fca4": (
        "external-activation-review-receipt.json",
        "external-activation-review-receipt.sigstore.json",
    ),
}

try:
    from scripts import collect_github_issuance_v2 as GITHUB_ISSUANCE
    from scripts import sigstore_bundle_v03 as SIGSTORE
except ModuleNotFoundError:
    import collect_github_issuance_v2 as GITHUB_ISSUANCE
    import sigstore_bundle_v03 as SIGSTORE

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "authority-v2-policy.json"
SCHEMA_PATH = ROOT / "schemas" / "authority-v2-subject.schema.json"
RECEIPT_PATH = ROOT / "protected-asset-receipt-v2.json"
ENV_CONTRACT_PATH = ROOT / "github-environment-v2-contract.json"
MANIFEST_PATH = ROOT / "AUTHORITY-V2-SHA256SUMS"
REVIEWER_AUTHORIZATION_PATH = ROOT / "reviewer-authorization-v2.json"
INDEPENDENT_REVIEW_BOOTSTRAP_PATH = ROOT / "independent-review-bootstrap-v2"
PROTECTED_SOURCE_BOOTSTRAP_PATH = ROOT / "protected-source-bootstrap-v2"
EXPECTED_POLICY_SHA256 = "aa47dd97fdc649733b0e218ce5ad82ca9a606f7e5480623edffc18fafbfb1069"
EXPECTED_REVIEWER_AUTHORIZATION_SHA256 = "ff160a49ad451f5b2cc2142038e921a0df06a3c712e0a376faa3745f59caf783"
EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT = {
        "authority_scope": "preissuance-independent-review",
        "bootstrap": {
            "collector_workflow_sha256": "d0f2def206d2084108b863d47f89db66b3842dd6de93bf2d8477660d19661924",
            "contract_path": "independent-review-bootstrap-v2/bootstrap-contract.json",
            "contract_sha256": "037b8406ea6f426fe7b1267c7b59763dfb60be188c5f81204c93a83fff1bd3a3",
            "protected_source_task_id": "t_c298fca4",
            "validator_sha256": "32052fbddfe07fcf837a1ec496e5391ae1464627a3792fd070150d1d982ba643",
            "workflow_sha256": "b63b15a8e8102b1032f626fffa4d62a187165166de11989d13215f2893ec331c"
        },
        "contract": "authenticated-github-environment-oidc-issuance-v2",
        "evidence_requirements": [
            "exact candidate head tree and canonical binary full-index diff SHA-256",
            "exact canonical independent zero-finding review receipt SHA-256 acquired from the contract-pinned protected immutable orchestration artifact and authenticated by the pinned independent Sigstore identity and pinned certificate workflow SHA",
            "exact protected-source and independent-review execution chain covering every executed workflow validator and helper byte at the pinned run heads",
            "unique 64-hex issuance nonce and exact immutable release tag and name",
            "GitHub run attempt 1 job and run-scoped independent Environment approval readbacks",
            "GitHub Actions OIDC repository workflow SHA ref event actor and environment claims",
            "closed-schema canonical authenticated issuance with fail-closed unavailable GitHub publication"
        ],
        "protected_source_bootstrap": {
            "contract_path": "protected-source-bootstrap-v2/bootstrap-contract.json",
            "contract_sha256": "f10259daf66fd26e83b65c2ae8489800ac9976dc0ee8baf1dcca8b44cb4b5c6b",
            "helper_sha256": "7206b39ca7098b9117d65a8e4569bd91137dddd1bed11b26c4ac26c46ac13959",
            "repository": "chrizzatsu/acc-authority-protected-source",
            "workflow_sha256": "a56b0c601647960ca06f49c0af73b321c83aae16768d24693d54af39b336dc20"
        },
        "receipt_type": "acc-authority-v2-github-issuance-authorization-contract",
        "review_receipt_signature": {
            "identity": "https://github.com/chrizzatsu/acc-authority-independent-review/.github/workflows/review-authority-v2.yml@refs/heads/main",
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": "chrizzatsu/acc-authority-independent-review",
            "workflow_ref": "refs/heads/main",
            "workflow_trigger": "workflow_dispatch"
        },
        "schema_version": 6,
        "sigstore_trusted_root": {
            "canonical_bytes_base64": "ewogICJtZWRpYVR5cGUiOiAiYXBwbGljYXRpb24vdm5kLmRldi5zaWdzdG9yZS50cnVzdGVkcm9vdCtqc29uO3ZlcnNpb249MC4xIiwKICAidGxvZ3MiOiBbCiAgICB7CiAgICAgICJiYXNlVXJsIjogImh0dHBzOi8vcmVrb3Iuc2lnc3RvcmUuZGV2IiwKICAgICAgImhhc2hBbGdvcml0aG0iOiAiU0hBMl8yNTYiLAogICAgICAicHVibGljS2V5IjogewogICAgICAgICJyYXdCeXRlcyI6ICJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUyRzJZKzJ0YWJkVFY1QmNHaUJJeDBhOWZBRndya0JibUxTR3RrczRMM3FYNnlZWTB6dWZCbmhDOFVyL2l5NTVHaFdQLzlBL2JZMkxoQzMwTTkrUll0dz09IiwKICAgICAgICAia2V5RGV0YWlscyI6ICJQS0lYX0VDRFNBX1AyNTZfU0hBXzI1NiIsCiAgICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0YXJ0IjogIjIwMjEtMDEtMTJUMTE6NTM6MjdaIgogICAgICAgIH0KICAgICAgfSwKICAgICAgImxvZ0lkIjogewogICAgICAgICJrZXlJZCI6ICJ3Tkk5YXRRR2x6K1ZXZk82TFJ5Z0g0UVVmWS84VzRSRndpVDVpNVdSZ0IwPSIKICAgICAgfQogICAgfSwKICAgIHsKICAgICAgImJhc2VVcmwiOiAiaHR0cHM6Ly9sb2cyMDI1LTEucmVrb3Iuc2lnc3RvcmUuZGV2IiwKICAgICAgImhhc2hBbGdvcml0aG0iOiAiU0hBMl8yNTYiLAogICAgICAicHVibGljS2V5IjogewogICAgICAgICJyYXdCeXRlcyI6ICJNQ293QlFZREsyVndBeUVBdDhybHAxa25Hd2pmYmNYQVlQWUFrbjBYaUx6MXg4TzR0MFlrRWhpZTI0ND0iLAogICAgICAgICJrZXlEZXRhaWxzIjogIlBLSVhfRUQyNTUxOSIsCiAgICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0YXJ0IjogIjIwMjUtMDktMjNUMDA6MDA6MDBaIgogICAgICAgIH0KICAgICAgfSwKICAgICAgImxvZ0lkIjogewogICAgICAgICJrZXlJZCI6ICJ6eEdaRlZ2ZDBGRW1qUjhXckZ3TWRjQUo5dnRhWS9RWGY0NFkxd1VlUDZBPSIKICAgICAgfQogICAgfQogIF0sCiAgImNlcnRpZmljYXRlQXV0aG9yaXRpZXMiOiBbCiAgICB7CiAgICAgICJzdWJqZWN0IjogewogICAgICAgICJvcmdhbml6YXRpb24iOiAic2lnc3RvcmUuZGV2IiwKICAgICAgICAiY29tbW9uTmFtZSI6ICJzaWdzdG9yZSIKICAgICAgfSwKICAgICAgInVyaSI6ICJodHRwczovL2Z1bGNpby5zaWdzdG9yZS5kZXYiLAogICAgICAiY2VydENoYWluIjogewogICAgICAgICJjZXJ0aWZpY2F0ZXMiOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgICJyYXdCeXRlcyI6ICJNSUlCK0RDQ0FYNmdBd0lCQWdJVE5Wa0Rab0Npb2ZQRHN5N2RmbTZnZUxidWh6QUtCZ2dxaGtqT1BRUURBekFxTVJVd0V3WURWUVFLRXd4emFXZHpkRzl5WlM1a1pYWXhFVEFQQmdOVkJBTVRDSE5wWjNOMGIzSmxNQjRYRFRJeE1ETXdOekF6TWpBeU9Wb1hEVE14TURJeU16QXpNakF5T1Zvd0tqRVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVJFd0R3WURWUVFERXdoemFXZHpkRzl5WlRCMk1CQUdCeXFHU000OUFnRUdCU3VCQkFBaUEySUFCTFN5QTdJaTVrK3BOTzhaRVdZMHlsZW1XRG93T2tOYTNrTCtHWkU1WjVHV2VoTDkvQTliUk5BM1JicnNaNWkwSmNhc3RhUkw3U3A1ZnAvakQ1ZHhxYy9VZFRWbmx2UzE2YW4rMllmc3dlL1F1TG9sUlVDcmNPRTIrMmlBNSt0emQ2Tm1NR1F3RGdZRFZSMFBBUUgvQkFRREFnRUdNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUV3SFFZRFZSME9CQllFRk1qRkhRQkJtaVFwTWxFazZ3MnVTdTFLQnRQc01COEdBMVVkSXdRWU1CYUFGTWpGSFFCQm1pUXBNbEVrNncydVN1MUtCdFBzTUFvR0NDcUdTTTQ5QkFNREEyZ0FNR1VDTUg4bGlXSmZNdWk2dlhYQmhqRGdZNE13c2xtTi9USnhWZS84M1dyRm9td21OZjA1NnkxWDQ4RjljNG0zYTNvelhBSXhBS2pSYXk1L2FqL2pzS0tHSWttUWF0akk4dXVwSHIvK0N4RnZhSldtcFlxTmtMREdSVSs5b3J6aDVoSTJScmN1YVE9PSIKICAgICAgICAgIH0KICAgICAgICBdCiAgICAgIH0sCiAgICAgICJ2YWxpZEZvciI6IHsKICAgICAgICAic3RhcnQiOiAiMjAyMS0wMy0wN1QwMzoyMDoyOVoiLAogICAgICAgICJlbmQiOiAiMjAyMi0xMi0zMVQyMzo1OTo1OS45OTlaIgogICAgICB9CiAgICB9LAogICAgewogICAgICAic3ViamVjdCI6IHsKICAgICAgICAib3JnYW5pemF0aW9uIjogInNpZ3N0b3JlLmRldiIsCiAgICAgICAgImNvbW1vbk5hbWUiOiAic2lnc3RvcmUiCiAgICAgIH0sCiAgICAgICJ1cmkiOiAiaHR0cHM6Ly9mdWxjaW8uc2lnc3RvcmUuZGV2IiwKICAgICAgImNlcnRDaGFpbiI6IHsKICAgICAgICAiY2VydGlmaWNhdGVzIjogWwogICAgICAgICAgewogICAgICAgICAgICAicmF3Qnl0ZXMiOiAiTUlJQ0dqQ0NBYUdnQXdJQkFnSVVBTG5WaVZmblUwYnJKYXNtUmtIcm4vVW5mYVF3Q2dZSUtvWkl6ajBFQXdNd0tqRVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVJFd0R3WURWUVFERXdoemFXZHpkRzl5WlRBZUZ3MHlNakEwTVRNeU1EQTJNVFZhRncwek1URXdNRFV4TXpVMk5UaGFNRGN4RlRBVEJnTlZCQW9UREhOcFozTjBiM0psTG1SbGRqRWVNQndHQTFVRUF4TVZjMmxuYzNSdmNtVXRhVzUwWlhKdFpXUnBZWFJsTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUU4UlZTL3lzSCtOT3Z1RFp5UEladGlsZ1VGOU5sYXJZcEFkOUhQMXZCQkgxVTVDVjc3TFNTN3MwWmlING5FN0h2N3B0UzZMdnZSL1NUazc5OExWZ016TGxKNEhlSWZGM3RIU2FleExjWXBTQVNyMWtTME4vUmdCSnovOWpXQ2lYbm8zc3dlVEFPQmdOVkhROEJBZjhFQkFNQ0FRWXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd013RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBZEJnTlZIUTRFRmdRVTM5UHB6MVlrRVpiNXFOanBLRldpeGk0WVpEOHdId1lEVlIwakJCZ3dGb0FVV01BZVg1RkZwV2FwZXN5UW9aTWkwQ3JGeGZvd0NnWUlLb1pJemowRUF3TURad0F3WkFJd1BDc1FLNERZaVpZRFBJYURpNUhGS25meFh4NkFTU1ZtRVJmc3luWUJpWDJYNlNKUm5aVTg0LzlEWmRuRnZ2eG1BakJPdDZRcEJsYzRKLzBEeHZrVENxcGNsdnppTDZCQ0NQbmpkbElCM1B1M0J4c1BteWdVWTdJaTJ6YmRDZGxpaW93PSIKICAgICAgICAgIH0sCiAgICAgICAgICB7CiAgICAgICAgICAgICJyYXdCeXRlcyI6ICJNSUlCOXpDQ0FYeWdBd0lCQWdJVUFMWk5BUEZkeEhQd2plRGxvRHd5WUNoQU8vNHdDZ1lJS29aSXpqMEVBd013S2pFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUkV3RHdZRFZRUURFd2h6YVdkemRHOXlaVEFlRncweU1URXdNRGN4TXpVMk5UbGFGdzB6TVRFd01EVXhNelUyTlRoYU1Db3hGVEFUQmdOVkJBb1RESE5wWjNOMGIzSmxMbVJsZGpFUk1BOEdBMVVFQXhNSWMybG5jM1J2Y21Vd2RqQVFCZ2NxaGtqT1BRSUJCZ1VyZ1FRQUlnTmlBQVQ3WGVGVDRyYjNQUUd3UzRJYWp0TGszL09sbnBnYW5nYUJjbFlwc1lCcjVpKzR5bkIwN2NlYjNMUDBPSU9aZHhleFg2OWM1aVZ1eUpSUStIejA1eWkrVUYzdUJXQWxIcGlTNXNoMCtIMkdIRTdTWHJrMUVDNW0xVHIxOUw5Z2c5MmpZekJoTUE0R0ExVWREd0VCL3dRRUF3SUJCakFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQjBHQTFVZERnUVdCQlJZd0I1ZmtVV2xacWw2ekpDaGt5TFFLc1hGK2pBZkJnTlZIU01FR0RBV2dCUll3QjVma1VXbFpxbDZ6SkNoa3lMUUtzWEYrakFLQmdncWhrak9QUVFEQXdOcEFEQm1BakVBajFuSGVYWnArMTNOV0JOYStFRHNEUDhHMVdXZzF0Q01XUC9XSFBxcGFWbzBqaHN3ZU5GWmdTczBlRTd3WUk0cUFqRUEyV0I5b3Q5OHNJa29GM3ZaWWRkMy9WdFdCNWI5VE5NZWE3SXgvc3RKNVRmY0xMZUFCTEU0Qk5KT3NRNHZuQkhKIgogICAgICAgICAgfQogICAgICAgIF0KICAgICAgfSwKICAgICAgInZhbGlkRm9yIjogewogICAgICAgICJzdGFydCI6ICIyMDIyLTA0LTEzVDIwOjA2OjE1WiIKICAgICAgfQogICAgfQogIF0sCiAgImN0bG9ncyI6IFsKICAgIHsKICAgICAgImJhc2VVcmwiOiAiaHR0cHM6Ly9jdGZlLnNpZ3N0b3JlLmRldi90ZXN0IiwKICAgICAgImhhc2hBbGdvcml0aG0iOiAiU0hBMl8yNTYiLAogICAgICAicHVibGljS2V5IjogewogICAgICAgICJyYXdCeXRlcyI6ICJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUViZndSK1JKdWRYc2NnUkJScEtYMVhGRHkzUHl1ZER4ei9TZm5SaTFmVDhla3BmQmQyTzF1b3o3anIzWjhuS3p4QTY5RVVRK2VGQ0ZJM3pldWJQV1U3dz09IiwKICAgICAgICAia2V5RGV0YWlscyI6ICJQS0lYX0VDRFNBX1AyNTZfU0hBXzI1NiIsCiAgICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0YXJ0IjogIjIwMjEtMDMtMTRUMDA6MDA6MDBaIiwKICAgICAgICAgICJlbmQiOiAiMjAyMi0xMC0zMVQyMzo1OTo1OS45OTlaIgogICAgICAgIH0KICAgICAgfSwKICAgICAgImxvZ0lkIjogewogICAgICAgICJrZXlJZCI6ICJDR0NTOENoUy8yaEYwZEZySjRTY1JXY1lyQlk5d3pqU2JlYThJZ1kyYjNJPSIKICAgICAgfQogICAgfSwKICAgIHsKICAgICAgImJhc2VVcmwiOiAiaHR0cHM6Ly9jdGZlLnNpZ3N0b3JlLmRldi8yMDIyIiwKICAgICAgImhhc2hBbGdvcml0aG0iOiAiU0hBMl8yNTYiLAogICAgICAicHVibGljS2V5IjogewogICAgICAgICJyYXdCeXRlcyI6ICJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVpUFNsRmkwQ21GVGZFakNVcUY5SHVDRWNZWE5LQWFZYWxJSm1CWjh5eWV6UGpUcWh4cktCcE1uYW9jVnRMSkJJMWVNM3VYblF6UUdBSmRKNGdzOUZ5dz09IiwKICAgICAgICAia2V5RGV0YWlscyI6ICJQS0lYX0VDRFNBX1AyNTZfU0hBXzI1NiIsCiAgICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0YXJ0IjogIjIwMjItMTAtMjBUMDA6MDA6MDBaIgogICAgICAgIH0KICAgICAgfSwKICAgICAgImxvZ0lkIjogewogICAgICAgICJrZXlJZCI6ICIzVDB3YXNiSEVUSmpHUjRjbVdjM0FxSktYcmplUEszL2g0cHlnQzhwN280PSIKICAgICAgfQogICAgfQogIF0sCiAgInRpbWVzdGFtcEF1dGhvcml0aWVzIjogWwogICAgewogICAgICAic3ViamVjdCI6IHsKICAgICAgICAib3JnYW5pemF0aW9uIjogInNpZ3N0b3JlLmRldiIsCiAgICAgICAgImNvbW1vbk5hbWUiOiAic2lnc3RvcmUtdHNhLXNlbGZzaWduZWQiCiAgICAgIH0sCiAgICAgICJ1cmkiOiAiaHR0cHM6Ly90aW1lc3RhbXAuc2lnc3RvcmUuZGV2L2FwaS92MS90aW1lc3RhbXAiLAogICAgICAiY2VydENoYWluIjogewogICAgICAgICJjZXJ0aWZpY2F0ZXMiOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgICJyYXdCeXRlcyI6ICJNSUlDRURDQ0FaYWdBd0lCQWdJVU9oTlVMd3lRWWU2OHdVTXZ5NHFPaXlvaml3d3dDZ1lJS29aSXpqMEVBd013T1RFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNU0F3SGdZRFZRUURFeGR6YVdkemRHOXlaUzEwYzJFdGMyVnNabk5wWjI1bFpEQWVGdzB5TlRBME1EZ3dOalU1TkROYUZ3MHpOVEEwTURZd05qVTVORE5hTUM0eEZUQVRCZ05WQkFvVERITnBaM04wYjNKbExtUmxkakVWTUJNR0ExVUVBeE1NYzJsbmMzUnZjbVV0ZEhOaE1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFNHJhMlo4aEtOaWcyVDlrRmpDQVRvR0czMGpreStXUXYzQnpMK21LdmgxU0tOUi9Vd3V3c2ZOQ2c0c3J5b1lBZDhFNmlzb3ZWQTNNNGFvTmRtOVFEaTUwWjhuVEV5dnFnZkRQdFRJd1hJdGZpVy9BRmYxVjd1d2tia0FvajB4eGNvMm93YURBT0JnTlZIUThCQWY4RUJBTUNCNEF3SFFZRFZSME9CQllFRkluOWVVT0h6OUJsUnNNQ1JzY3NjMXQ5dE9zRE1COEdBMVVkSXdRWU1CYUFGSmpzQWU5L3UxSC8xSlVlYjRxSW1GTUhpYzYvTUJZR0ExVWRKUUVCL3dRTU1Bb0dDQ3NHQVFVRkJ3TUlNQW9HQ0NxR1NNNDlCQU1EQTJnQU1HVUNNRHRwc1YvNkthTzBxeUYvVU1zWDJhU1VYS1FGZG9HVHB0UUdjMGZ0cTFjc3VsSFBHRzZkc215TU5kM0pCK0czRVFJeEFPYWp2QmNqcEptS2I0TnYrMlRhb2o4VWM1K2I2aWg2RlhDQ0tyYVNxdXBlMDd6cXN3TWNYSlRlMWNFeHZIdnZsdz09IgogICAgICAgICAgfSwKICAgICAgICAgIHsKICAgICAgICAgICAgInJhd0J5dGVzIjogIk1JSUI5ekNDQVh5Z0F3SUJBZ0lVVjdmMEdMRE9vRXpJaDhMWFNXODBPSmlVcDE0d0NnWUlLb1pJemowRUF3TXdPVEVWTUJNR0ExVUVDaE1NYzJsbmMzUnZjbVV1WkdWMk1TQXdIZ1lEVlFRREV4ZHphV2R6ZEc5eVpTMTBjMkV0YzJWc1puTnBaMjVsWkRBZUZ3MHlOVEEwTURnd05qVTVORE5hRncwek5UQTBNRFl3TmpVNU5ETmFNRGt4RlRBVEJnTlZCQW9UREhOcFozTjBiM0psTG1SbGRqRWdNQjRHQTFVRUF4TVhjMmxuYzNSdmNtVXRkSE5oTFhObGJHWnphV2R1WldRd2RqQVFCZ2NxaGtqT1BRSUJCZ1VyZ1FRQUlnTmlBQVFVUU50ZlJUL291M1lBVGE2d0Iva0tUZTcwY2ZKd3lSSUJvdk1udDhSY0pwaC9DT0U4MnV5UzZGbXBwTExMMVZCUEdjUGZwUVBZSk5Yeld3aThpY3doS1E2Vy9RZTJoM29lYkJiMkZIcHdOSkRxbytUTWFDL3RkZmt2L0VsSkI3MmpSVEJETUE0R0ExVWREd0VCL3dRRUF3SUJCakFTQmdOVkhSTUJBZjhFQ0RBR0FRSC9BZ0VBTUIwR0ExVWREZ1FXQkJTWTdBSHZmN3RSLzlTVkhtK0tpSmhUQjRuT3Z6QUtCZ2dxaGtqT1BRUURBd05wQURCbUFqRUF3R0VHcmZHWlIxY2VuMVI4L0RUVk1JOTQzTHNzWm1KUnREcC9pN1NmR0htR1JQNmdSYnVqOXZPSzNiNjdaMFFRQWpFQXVUMkg2NzNMUUVhSFRjeVFTWnJrcDRtWDdXd2ttRitzVmJrWVk1bVhOK1JNSDEzS1VFSEhPcUFTYWVtWVdLL0UiCiAgICAgICAgICB9CiAgICAgICAgXQogICAgICB9LAogICAgICAidmFsaWRGb3IiOiB7CiAgICAgICAgInN0YXJ0IjogIjIwMjUtMDctMDRUMDA6MDA6MDBaIgogICAgICB9CiAgICB9CiAgXQp9Cg==",
            "fulcio_authorities": [
                {
                    "certificate_sha256": [
                        "03a38ffb1f450100c2596d1d10b900ac4d504058006dda58199576bbeb9c73d0"
                    ],
                    "common_name": "sigstore",
                    "organization": "sigstore.dev",
                    "root_sha256": "03a38ffb1f450100c2596d1d10b900ac4d504058006dda58199576bbeb9c73d0",
                    "uri": "https://fulcio.sigstore.dev",
                    "valid_from": "2021-03-07T03:20:29Z",
                    "valid_to": "2022-12-31T23:59:59.999Z"
                },
                {
                    "certificate_sha256": [
                        "15d795348226b4649f750f5802592c393bee7cc53c3b86982175b7ad087efe47",
                        "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1"
                    ],
                    "common_name": "sigstore",
                    "organization": "sigstore.dev",
                    "root_sha256": "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1",
                    "uri": "https://fulcio.sigstore.dev",
                    "valid_from": "2022-04-13T20:06:15Z",
                    "valid_to": None
                }
            ],
            "media_type": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "rekor_logs": [
                {
                    "base_url": "https://rekor.sigstore.dev",
                    "key_details": "PKIX_ECDSA_P256_SHA_256",
                    "log_id_key_id": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=",
                    "origin": "rekor.sigstore.dev",
                    "public_key_sha256": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                    "valid_from": "2021-01-12T11:53:27Z",
                    "valid_to": None
                },
                {
                    "base_url": "https://log2025-1.rekor.sigstore.dev",
                    "key_details": "PKIX_ED25519",
                    "log_id_key_id": "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=",
                    "origin": "log2025-1.rekor.sigstore.dev",
                    "public_key_sha256": "b54813cb63d8859870a5e78500cc6adcfdf59723edae93ee8d25faf2475a0690",
                    "valid_from": "2025-09-23T00:00:00Z",
                    "valid_to": None
                }
            ],
            "runtime_trust_fetch_forbidden": True,
            "sha256": "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
            "source_commit": "ba3066c420970c13772ba0625f09f1ec97193116",
            "source_path": "targets/trusted_root.json",
            "source_repository": "https://github.com/sigstore/root-signing"
        },
        "source_execution_chain": {
            "activation_state": "authorized_pending_evidence",
            "authorized_run_selector": "immutable-contract-pinned",
            "bound_fields": [
                "artifact_content_sha256",
                "authority_head_commit",
                "authority_head_tree",
                "authority_repository",
                "certificate_github_workflow_sha",
                "envelope_sha256",
                "independent_bootstrap_commit",
                "independent_bootstrap_tree",
                "independent_validator_sha256",
                "independent_workflow_sha256",
                "review_receipt_sha256",
                "reviewer_task_id",
                "run_attempt",
                "run_head_sha",
                "run_id",
                "source_bootstrap_commit",
                "source_bootstrap_tree",
                "source_helper_path",
                "source_helper_sha256",
                "source_repository",
                "source_workflow_path",
                "source_workflow_sha256"
            ],
            "caller_selectable_source_run": False,
            "caller_supplied_or_forged_envelope_or_receipt_bytes_rejected": True,
            "certificate_github_workflow_sha_equals_independent_bootstrap_commit": True,
            "every_executed_workflow_validator_and_helper_byte_verified_at_the_pinned_run_head": True,
            "live_evidence_derived_at_runtime": True,
            "missing_protected_source_or_independent_repository_fails_closed": True,
            "no_fallback": True
        }
    }
EXPECTED_PUBLICATION_CONTRACT = {
        "activation_state": "unavailable",
        "asset_upload_allowed": False,
        "confirmed_absence_status": 404,
        "documented_atomic_transition_available": False,
        "documented_durable_pre_draft_state_available": False,
        "draft_creation_allowed": False,
        "exact_tag_ruleset": {
            "bypass_actors": [],
            "creation_allowed": False,
            "enforcement": "active",
            "full_readback_required": True,
            "ref_exclude": [],
            "ref_include": [
                "refs/tags/clerk-instance-attestation-v2",
                "refs/tags/authority-v2-publication-claim"
            ],
            "rules": [
                {
                    "type": "deletion"
                },
                {
                    "parameters": {
                        "update_allows_fetch_and_merge": False
                    },
                    "type": "update"
                }
            ],
            "strong_etag_and_canonical_digest_bound": True,
            "target": "tag"
        },
        "exhaustive_writer_exclusion_available": False,
        "guard_transport": {
            "activation_state": "unavailable",
            "contract_path": "github-app-guard-v2-contract.json",
            "credential": "environment-gated GitHub App installation token",
            "no_fallback": True,
            "permission": "administration-read",
            "read_transport_credential": "ephemeral job GITHUB_TOKEN restricted to GET",
            "roles_distinct": True
        },
        "irreversible_publication_forbidden": True,
        "no_fallback": True,
        "overwrite_allowed": False,
        "postcondition_immutable": True,
        "prohibited_writes": [
            "POST /repos/{repository}/releases",
            "POST uploads.github.com release assets",
            "POST /repos/{repository}/git/tags",
            "POST /repos/{repository}/git/refs",
            "PATCH /repos/{repository}/releases/{release_id}",
            "DELETE /repos/{repository}/releases/{release_id}"
        ],
        "publication_guard_read_points": [
            "before_every_reconciliation"
        ],
        "publication_performed": False,
        "reconciliation": {
            "bound_fields": [
                "draft_id",
                "durable_claim",
                "final_tag",
                "complete_asset_name_size_sha256_plan",
                "publication_plan_sha256",
                "immutable_releases_sha256",
                "tag_ruleset_id_etag_canonical_sha256"
            ],
            "colliding_or_stranded_draft_rejected": True,
            "exact": True,
            "exhaustive_release_listing": True,
            "idempotent": True,
            "read_only": True,
            "states": [
                "unpublished",
                "unclaimed_draft",
                "claimed_draft",
                "published"
            ]
        },
        "release_name_and_body_exact_at_every_readback": True,
        "repository_immutable_releases_exact_readback_required": True,
        "tag_or_claim_write_allowed": False,
        "unavailable_reason": "GitHub documents neither a durable server-owned pre-draft publication state nor an atomic draft-to-immutable transition, so no fallible publication write is exactly reconstructable and every draft, upload, tag and claim write is prohibited.",
        "writer_exclusion_contract_path": "publication-writer-exclusion-v2.json"
    }
EXPECTED_PROTECTED_ASSET_SHA256 = "54cbc72994f8d2e2aefa5916bb02c3a3c26b5db11fbad86c9281fd4aa970f222"
EXPECTED_REPOSITORY = "chrizzatsu/acc-attestation-authority"
EXPECTED_IDENTITY = "https://github.com/chrizzatsu/acc-attestation-authority/.github/workflows/sign-clerk-attestation-v2.yml@refs/heads/main"
EXPECTED_WORKFLOW_REF = "chrizzatsu/acc-attestation-authority/.github/workflows/sign-clerk-attestation-v2.yml@refs/heads/main"
EXPECTED_ISSUER = "https://token.actions.githubusercontent.com"
EXPECTED_GIT_REF = "refs/heads/main"
EXPECTED_TRIGGER = "workflow_dispatch"
EXPECTED_UNSUPPORTED_DEPLOYMENT_EVIDENCE = {
    "deployment_id_omitted": True,
    "deployment_status_omitted": True,
    "log_url_relationship_forbidden": True,
}
EXPECTED_RUN_SCOPED_APPROVAL_BINDING = {
    "endpoint_template": (
        "https://api.github.com/repos/chrizzatsu/acc-attestation-authority/"
        "actions/runs/{run_id}/approvals"
    ),
    "projected_response_fields": ["environments", "state", "user"],
    "synthetic_run_ids_forbidden": True,
}
# SEALED-GITHUB-READBACK-ENVIRONMENT-MISMATCH: the exact current authenticated
# read-only Environment state. Any live difference fails closed.
EXPECTED_SEALED_ENVIRONMENT_READBACK = {
    "authenticated_read_only": True,
    "confirmed_absence_requires_authenticated_permission_proof": True,
    "confirmed_absence_requires_exhaustive_authenticated_pagination": True,
    "environment_id": 20467803126,
    "environment_secrets_total_count": 0,
    "http_status": 200,
    "masked_or_unauthenticated_statuses": [401, 403, 404],
    "no_github_write_performed": True,
    "permission_masked_404_is_not_absence": True,
    "prevent_self_review": True,
    "protected_branches": True,
    "required_reviewer_logins": ["chrizzatsu"],
    "sealed_state": "current-authenticated-read-only-live-environment-state",
    "state_change_fails_closed": True,
}
EXPECTED_REVIEWER_IDENTITY = EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT["review_receipt_signature"]["identity"]
EXPECTED_REVIEWER_ISSUER = EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT["review_receipt_signature"]["issuer"]
EXPECTED_REVIEWER_REPOSITORY = EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT["review_receipt_signature"]["repository"]
EXPECTED_REVIEWER_WORKFLOW_PATH = ".github/workflows/review-authority-v2.yml"
EXPECTED_TERMINAL_COLLECTOR_WORKFLOW_PATH = (
    ".github/workflows/readback-authority-v2-activation.yml"
)
EXPECTED_REVIEWER_VALIDATOR_PATH = "scripts/verify_kanban_review_v2.py"
EXPECTED_REVIEWER_TASK_ID = "t_c298fca4"
EXPECTED_INDEPENDENT_REPOSITORY = EXPECTED_REVIEWER_REPOSITORY
EXPECTED_REVIEWER_BOOTSTRAP_CONTRACT_TARGET = "bootstrap-contract.json"
# The four sealed reviewer bytes whose live path-to-blob membership the
# derived bootstrap binding must prove at the authenticated live head.
EXPECTED_REVIEWER_BOUND_PATHS = sorted((
    EXPECTED_TERMINAL_COLLECTOR_WORKFLOW_PATH,
    EXPECTED_REVIEWER_WORKFLOW_PATH,
    EXPECTED_REVIEWER_VALIDATOR_PATH,
    EXPECTED_REVIEWER_BOOTSTRAP_CONTRACT_TARGET,
))
# The live reviewer bootstrap identifiers are derived, never read from the
# sealed pre-live constants, which stay null until an authorized run exists.
EXPECTED_BOOTSTRAP_BINDING_PROVENANCE = "authenticated-canonical-github-readback"
EXPECTED_BOOTSTRAP_BINDING_FILE = "independent-bootstrap-binding.json"
EXPECTED_REVIEWER_BOOTSTRAP_CONTRACT_PATH = (
    "independent-review-bootstrap-v2/bootstrap-contract.json"
)
EXPECTED_BOOTSTRAP_BINDING_FIELDS = sorted((
    "bound_paths", "derived_from", "independent_bootstrap_commit",
    "independent_bootstrap_tree", "repository", "repository_id",
    "run_attempt", "run_head_sha", "run_id", "sealed_pre_live_commit",
    "sealed_pre_live_tree", "workflow_path",
))
# The authorized run inventory is no longer a fixed page set: it is one
# exhaustive `rel="next"` traversal captured raw under `authenticated/raw`,
# beside the read-only readback of the workflow's own disabled state.
EXPECTED_SOURCE_AUTHENTICATED_READ_INVENTORY = [
    "authenticated/authority-checkout",
    "authenticated/authority-commit.json",
    "authenticated/independent-commit.json",
    "authenticated/raw",
    "authenticated/source-commit.json",
]
EXPECTED_SOURCE_PHASES = ["export", "gate"]
# The reviewed pre-activation authorization: reviewed repo/workflow/blob
# bindings and attempt 1 are pinned, while every live identifier is derived
# from authenticated GitHub server state at runtime.
AUTHORIZED_PENDING_EVIDENCE = "authorized_pending_evidence"
EXPECTED_LIVE_DERIVED_FIELDS = [
    "authority_head_commit",
    "authority_head_tree",
    "independent_bootstrap_commit",
    "independent_bootstrap_tree",
    "source_bootstrap_commit",
    "source_bootstrap_tree",
]
EXPECTED_AUTHENTICATED_READ_INVENTORY = [
    "authenticated/artifact-archive.zip",
    "authenticated/authority-checkout",
    "authenticated/authority-commit.json",
    "authenticated/independent-commit.json",
    "authenticated/raw",
    "authenticated/reviewer-decision-blob.json",
    "authenticated/reviewer-decision-commit.json",
    "authenticated/reviewer-decision-delivery.json",
    "authenticated/reviewer-decision-readback.json",
    "authenticated/reviewer-repository.json",
    "authenticated/selected-artifact.json",
    "authenticated/server-objects.json",
    "authenticated/source-bootstrap-contract.json",
    "authenticated/source-commit.json",
    "authenticated/source-helper.py",
    "authenticated/source-run.json",
    "authenticated/source-workflow.yml",
]
EXPECTED_SOURCE_REPOSITORY = "chrizzatsu/acc-authority-protected-source"
EXPECTED_SOURCE_WORKFLOW_PATH = ".github/workflows/export-kanban-review-v2.yml"
EXPECTED_SOURCE_HELPER_PATH = "scripts/export_kanban_review_v2.py"
EXPECTED_SOURCE_ARTIFACT_NAME = "authority-v2-review-t_c298fca4"
EXPECTED_SIGNED_REVIEW_ARTIFACT_NAME = "authority-v2-signed-review-t_c298fca4"
EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES = [
    "kanban-review-envelope.json",
    "preissuance-review-receipt.json",
    "preissuance-review-receipt.sigstore.json",
]
EXPECTED_SIGNED_REVIEW_ARTIFACT_RETENTION_DAYS = 1
EXPECTED_UPLOAD_ARTIFACT_USES = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
EXPECTED_DOWNLOAD_ARTIFACT_USES = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact"
DOWNLOAD_ARTIFACT_ACTION = "actions/download-artifact"
# GitHub resolves the owner/repository half of a `uses` value
# case-insensitively while the pinned ref half stays byte-exact. Semantic
# enumeration therefore case-folds only the owner/repository half, so aliases
# such as `Actions/Upload-Artifact` and `ACTIONS/DOWNLOAD-ARTIFACT` are always
# counted, and never mistaken for the byte-for-byte authorized pinned use.
ARTIFACT_ACTION_REPOSITORIES = (UPLOAD_ARTIFACT_ACTION, DOWNLOAD_ARTIFACT_ACTION)
EXPECTED_INDEPENDENT_PHASES = ["bootstrap", "select", "chain", "external-review"]
# The external post-candidate activation review the reviewer produces once the
# exact Authority candidate exists. It is the only thing that may ever move the
# activation authorization from false to true.
EXPECTED_EXTERNAL_REVIEW_ARTIFACT_NAME = (
    "authority-v2-external-activation-review-t_c298fca4"
)
EXPECTED_GENERATED_ACTIVATION_ARTIFACT_NAME = (
    "authority-v2-generated-activation-evidence-t_c298fca4"
)
EXPECTED_GENERATED_ACTIVATION_ARTIFACT_FILES = [
    "activation-record.json", "activation-subject.json",
    "canonical-binary-full-index.diff",
    "external-review/external-activation-review-receipt.json",
    "external-review/external-activation-review-receipt.sigstore.json",
    "generated-activation-evidence.sigstore.json",
    "name-status-find-renames-50.z", "raw-provenance.json",
    "raw/activation-jobs.json", "raw/activation-run.json",
    "raw/activation-runs.json", "raw/decision-commit.json",
    "raw/external-review-artifact.zip", "raw/review-artifacts.json",
    "raw/review-jobs.json", "raw/review-run.json",
    "raw/signed-review-artifact.zip", "raw/workflow-run-event.json",
    "raw/workflow-state-after.json", "raw/workflow-state-before.json",
    "raw/workflow-state-cleanup.json",
    "raw-full-index-find-renames-50.z", "raw-status-authoritative.z",
    "signed-review/kanban-review-envelope.json",
    "signed-review/preissuance-review-receipt.json",
    "signed-review/preissuance-review-receipt.sigstore.json",
]
EXPECTED_EXTERNAL_REVIEW_ARTIFACT_FILES = [
    "external-activation-review-receipt.json",
    "external-activation-review-receipt.sigstore.json",
]
EXPECTED_SIGNED_REVIEW_UPLOAD_WITH = {
    "name": EXPECTED_SIGNED_REVIEW_ARTIFACT_NAME,
    "if-no-files-found": "error",
    "retention-days": "1",
    "path": "".join(f"protected-review/{name}\n" for name in EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES),
}
EXPECTED_EXTERNAL_REVIEW_UPLOAD_WITH = {
    "name": EXPECTED_EXTERNAL_REVIEW_ARTIFACT_NAME,
    "if-no-files-found": "error",
    "retention-days": "1",
    "path": "".join(
        f"protected-review/{name}\n"
        for name in EXPECTED_EXTERNAL_REVIEW_ARTIFACT_FILES
    ),
}
EXPECTED_GENERATED_ACTIVATION_UPLOAD_WITH = {
    "name": EXPECTED_GENERATED_ACTIVATION_ARTIFACT_NAME,
    "if-no-files-found": "error",
    "retention-days": "1",
    "path": "".join(
        f"activation/{name}\n"
        for name in EXPECTED_GENERATED_ACTIVATION_ARTIFACT_FILES
    ),
}
EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH = {
    "name": EXPECTED_SIGNED_REVIEW_ARTIFACT_NAME,
    "path": "${{ runner.temp }}/authority-v2-runtime/independent-review",
    "repository": "chrizzatsu/acc-authority-independent-review",
    "run-id": "${{ inputs.independent_review_run_id }}",
    "github-token": "${{ steps.review-token.outputs.token }}",
}
# The second, and only other, authorized consumer download: the immutable
# external activation review artifact the derived closure lane consumes. Both
# downloads are pinned to the exact action digest, artifact name, path,
# reviewer repository, authorized run id and Environment-gated token, so no
# third or substituted consumer download can ever be smuggled in.
EXPECTED_EXTERNAL_REVIEW_DOWNLOAD_WITH = {
    "name": EXPECTED_EXTERNAL_REVIEW_ARTIFACT_NAME,
    "path": "${{ runner.temp }}/authority-v2-runtime/external-activation-review",
    "repository": "chrizzatsu/acc-authority-independent-review",
    "run-id": "${{ inputs.independent_review_run_id }}",
    "github-token": "${{ steps.review-token.outputs.token }}",
}
EXPECTED_CONSUMER_DOWNLOADS = (
    EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH,
    EXPECTED_EXTERNAL_REVIEW_DOWNLOAD_WITH,
)
AUTHORITY_RUNTIME_ENV = "AUTHORITY_V2_RUNTIME"
EXPECTED_SIGNED_REVIEW_INVENTORY_ROOT = f"${AUTHORITY_RUNTIME_ENV}/independent-review"
# The single approved command for the one dedicated post-download signed review
# inventory step. It executes the same exact three-file inventory the producer
# uploads, so the bound step can never contradict the producer artifact. The
# bound `run` scalar must equal these bytes exactly: text that is merely
# *present* -- a heredoc body, text after `exit`, an uncalled function body, a
# compound or split command line, a comment, surrounding text -- never executes
# the inventory in the mandatory order after the authorized download and must
# fail closed.
EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND = (
    "python3 scripts/verify_authority_v2.py "
    "--verify-signed-review-artifact-inventory "
    f'"{EXPECTED_SIGNED_REVIEW_INVENTORY_ROOT}"'
)
# Any run scalar carrying this flag is an inventory reference, whether or not
# the shell would ever execute it.
SIGNED_REVIEW_INVENTORY_REFERENCE_MARKERS = (
    "--verify-signed-review-artifact-inventory",
)
EXPECTED_SIGNED_REVIEW_INVENTORY_STEP_KEYS = ["name", "run"]
SOURCE_CHAIN_HEX40_FIELDS = (
    "authority_head_commit", "authority_head_tree", "certificate_github_workflow_sha",
    "independent_bootstrap_commit", "independent_bootstrap_tree",
    "run_head_sha", "source_bootstrap_commit", "source_bootstrap_tree",
)
SOURCE_CHAIN_HEX64_FIELDS = (
    "artifact_content_sha256", "envelope_sha256", "independent_validator_sha256",
    "independent_workflow_sha256", "review_receipt_sha256", "source_helper_sha256",
    "source_workflow_sha256",
)
SOURCE_CHAIN_LITERAL_FIELDS = (
    "authority_repository", "reviewer_task_id", "source_helper_path",
    "source_repository", "source_workflow_path",
)
SOURCE_CHAIN_FIELDS = (
    *SOURCE_CHAIN_HEX40_FIELDS, *SOURCE_CHAIN_HEX64_FIELDS,
    *SOURCE_CHAIN_LITERAL_FIELDS, "run_attempt", "run_id",
)
SELF_REFERENTIAL_CHAIN_FIELDS = frozenset(
    {"artifact_content_sha256", "envelope_sha256", "review_receipt_sha256"}
)
RECEIPT_SOURCE_CHAIN_FIELDS = tuple(
    name for name in SOURCE_CHAIN_FIELDS
    if name not in SELF_REFERENTIAL_CHAIN_FIELDS
)
EXPECTED_REVIEWER_BOOTSTRAP_IDENTITY = (
    "https://github.com/chrizzatsu/acc-authority-independent-review/"
    ".github/workflows/review-authority-v2.yml@refs/heads/main"
)
EXPECTED_WORKFLOW_HEADER = """name: Issue immutable ACC Authority-v2 evidence

on:
  workflow_dispatch:
    inputs:
      candidate_head:
"""
EXPECTED_CASES = ("future", "in_window", "stale")
EXPECTED_CLOSURES = tuple(f"F{number}" for number in range(1, 13))
# F12-EXCLUSIVE-PUBLICATION-UNAVAILABLE forces the final Authority decision:
# no documented GitHub release API establishes an exhaustive exclusive/CAS/
# atomic transition binding the exact activation SHA and verified immutable
# asset snapshots against every authorized writer. The strictly distinct
# activation-only decision is the only thing the sealed chain may authorize.
EXPECTED_REVIEW_OUTCOME = "ACTIVATION_ONLY"
EXPECTED_FINAL_APPROVED = False
EXPECTED_FINAL_RELEASE_AUTHORIZED = False
EXPECTED_CLOSED_CLOSURES = tuple(f"F{number}" for number in range(1, 12))
EXPECTED_OPEN_CLOSURES = ("F12",)
# F8 may close only once the activation state is `ready` and every required
# live field is deterministically pinned. Any earlier state must record it as
# an exact open finding beside F12.
EXPECTED_LIVE_EVIDENCE_CLOSURE = "F8"
EXPECTED_LIVE_EVIDENCE_FINDING = "F8-AUTHENTICATED-SOURCE-CHAIN-UNAVAILABLE"
EXPECTED_PREACTIVATION_OPEN_CLOSURES = (
    *EXPECTED_OPEN_CLOSURES, EXPECTED_LIVE_EVIDENCE_CLOSURE,
)
EXPECTED_PREACTIVATION_CLOSED_CLOSURES = tuple(
    name for name in EXPECTED_CLOSURES
    if name not in EXPECTED_PREACTIVATION_OPEN_CLOSURES
)
READY_ACTIVATION_STATE = "ready"


def expected_closures_for(activation_state):
    """The exact closed/open partition an activation state may carry."""
    if activation_state == READY_ACTIVATION_STATE:
        return EXPECTED_CLOSED_CLOSURES, EXPECTED_OPEN_CLOSURES
    return EXPECTED_PREACTIVATION_CLOSED_CLOSURES, EXPECTED_PREACTIVATION_OPEN_CLOSURES
EXPECTED_FINDING_KEYS = ("closure", "finding")
EXPECTED_ACTIVATION_FINDING = {
    "closure": EXPECTED_LIVE_EVIDENCE_CLOSURE,
    "finding": EXPECTED_LIVE_EVIDENCE_FINDING,
}
EXPECTED_RECEIPT_FIELDS = (
    "activation_authorized", "activation_findings", "approved", "candidate",
    "classifications", "closure_matrix", "findings", "findings_count",
    "protected_identity_asset", "receipt_type", "release_authorized",
    "review_outcome", "reviewer_profile", "schema_version",
    "source_execution_chain",
)
EXPECTED_MANIFEST_PATHS = (
    ".github/disabled-workflows/sign-clerk-attestation-v1.yml",
    ".github/workflows/sign-clerk-attestation-v2.yml",
    "README.md",
    "VERIFY-AUTHORITY-V2.md",
    "authority-policy.json",
    "authority-v2-policy.json",
    "github-app-guard-v2-contract.json",
    "github-environment-v2-contract.json",
    "independent-review-bootstrap-v2/.github/workflows/readback-authority-v2-activation.yml",
    "independent-review-bootstrap-v2/.github/workflows/review-authority-v2.yml",
    "independent-review-bootstrap-v2/bootstrap-contract.json",
    "independent-review-bootstrap-v2/scripts/verify_kanban_review_v2.py",
    "protected-asset-receipt-v2.json",
    "protected-source-bootstrap-v2/.github/workflows/export-kanban-review-v2.yml",
    "protected-source-bootstrap-v2/bootstrap-contract.json",
    "protected-source-bootstrap-v2/scripts/export_kanban_review_v2.py",
    "publication-writer-exclusion-v2.json",
    "reviewer-authorization-v2.json",
    "schemas/authority-v2-subject.schema.json",
    "scripts/build_attestation.py",
    "scripts/build_authority_v2.py",
    "scripts/collect_github_issuance_v2.py",
    "scripts/pin_source_chain_activation_v2.py",
    "scripts/sigstore_bundle_v03.py",
    "scripts/verify_authority_v2.py",
    "scripts/verify_github_environment_v2.py",
    "scripts/verify_publication_v2.py",
    "scripts/verify_source_chain_activation_v2.py",
    "source-chain-activation-v2.json",
    "tests/fixtures/cosign-v3.1.3-sigstore-v0.3-bundle.json",
    "tests/issuance_fixture.py",
    "tests/test_authority_v2.py",
    "tests/test_candidate_review_v2.py",
    "tests/test_github_issuance_v2.py",
    "tests/test_publication_v2.py",
    "tests/test_source_chain_activation_v2.py",
)
RAW_PATTERNS = (
    re.compile(rb"pk_(?:test|live)_[A-Za-z0-9_-]{8,}"),
    re.compile(rb"sk_(?:test|live)_[A-Za-z0-9_-]{8,}"),
    re.compile(rb"\bins_[A-Za-z0-9_-]{8,}\b"),
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
APPROVED_COSIGN_DIGESTS = {
    "linux/amd64": "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    "linux/arm64": "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
    "darwin/amd64": "2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c",
    "darwin/arm64": "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76",
}
EXPECTED_COSIGN_BUILD = {
    "gitVersion": "v3.1.3",
    "gitCommit": "11926fa5bbbbde47e88fc006b625a17769b743b2",
    "gitTreeState": "clean",
    "buildDate": "2026-08-05T23:43:27Z",
    "goVersion": "go1.26.4",
    "compiler": "gc",
}


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def _zip_member_type_is_regular(info):
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if info.create_system == ZIP_CREATOR_UNIX:
        return file_type == stat.S_IFREG
    if info.create_system in ZIP_NON_UNIX_CREATOR_SYSTEMS:
        return file_type in (0, stat.S_IFREG)
    return False


def review_artifact_member_digests(archive_bytes, expected_members, label):
    """Hash an exact safe ZIP only after validating its complete metadata."""
    require(type(archive_bytes) is bytes and archive_bytes,
            f"{label} archive bytes are absent")
    expected = tuple(sorted(expected_members))
    require(expected and len(expected) == len(set(expected)),
            f"{label} expected member inventory is malformed")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            infos = archive.infolist()
            require(len(infos) == len(expected),
                    f"{label} member count mismatch")
            observed = {}
            total = 0
            for info in infos:
                name = info.filename
                require(type(name) is str and name and "\x00" not in name
                        and "\\" not in name and not name.startswith("/"),
                        f"{label} member name is unsafe")
                segments = name.split("/")
                require(all(part not in ("", ".", "..")
                            for part in segments),
                        f"{label} member path traverses or aliases")
                normalized = unicodedata.normalize(
                    "NFC", PurePosixPath(*segments).as_posix(),
                )
                require(normalized == name and "/" not in normalized
                        and normalized in expected
                        and normalized not in observed,
                        f"{label} member inventory is unsafe or aliased")
                require(not info.is_dir()
                        and _zip_member_type_is_regular(info),
                        f"{label} carries a non-regular member: {name}")
                require(info.flag_bits & 1 == 0,
                        f"{label} carries an encrypted member: {name}")
                require(type(info.file_size) is int
                        and type(info.file_size) is not bool
                        and 0 <= info.file_size <= SAFE_ZIP_MEMBER_BYTES,
                        f"{label} member exceeds its size bound: {name}")
                total += info.file_size
                require(total <= SAFE_ZIP_AGGREGATE_BYTES,
                        f"{label} exceeds its aggregate size bound")
                observed[normalized] = info
            require(tuple(sorted(observed)) == expected,
                    f"{label} member inventory is incomplete")
            members = {}
            for name in expected:
                data = archive.read(observed[name])
                require(len(data) == observed[name].file_size,
                        f"{label} member size changed while reading: {name}")
                members[name] = hashlib.sha256(data).hexdigest()
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        raise SystemExit(f"{label} is not a safe exact ZIP") from error
    return members


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


# ---------------------------------------------------------------------------
# Structural workflow-YAML reader
#
# Workflow files are read through this explicit, deliberately small YAML subset
# parser instead of line or substring regexes, so every artifact action
# invocation is enumerated regardless of quoted keys, spaced keys, flow maps,
# optional name/id/if metadata, or key order. Every valid YAML construct
# outside the supported subset -- anchors, aliases, merge keys, explicit tags,
# multiple documents, folded scalars, tab indentation -- fails closed instead
# of being silently mis-read. Scalars are preserved verbatim as text and no
# implicit typing is applied, so every comparison is against exact literal
# bytes.
# ---------------------------------------------------------------------------
YAML_PLAIN_FORBIDDEN_FIRST = "&*!|>%@`"
YAML_SUPPORTED_BLOCK_SCALARS = frozenset({"|", "|-"})


def _yaml_fail(reason):
    raise SystemExit(f"unsupported or ambiguous workflow YAML: {reason}")


def _yaml_quoted_end(text, start):
    """Return the index just past the quoted scalar beginning at `start`."""
    quote = text[start]
    index = start + 1
    while index < len(text):
        character = text[index]
        if quote == '"' and character == "\\":
            index += 2
            continue
        if character == quote:
            if quote == "'" and text[index + 1:index + 2] == "'":
                index += 2
                continue
            return index + 1
        index += 1
    _yaml_fail(f"unterminated quoted scalar in {text!r}")


def _yaml_single_quoted(text):
    if len(text) < 2 or not text.endswith("'"):
        _yaml_fail(f"malformed single-quoted scalar {text!r}")
    body, parts, index = text[1:-1], [], 0
    while index < len(body):
        character = body[index]
        if character == "'":
            if body[index + 1:index + 2] != "'":
                _yaml_fail(f"malformed single-quoted scalar {text!r}")
            parts.append("'")
            index += 2
            continue
        parts.append(character)
        index += 1
    return "".join(parts)


def _yaml_double_quoted(text):
    try:
        value = json.loads(text)
    except ValueError:
        _yaml_fail(f"malformed double-quoted scalar {text!r}")
    if type(value) is not str:
        _yaml_fail(f"malformed double-quoted scalar {text!r}")
    return value


def _yaml_scalar(text):
    """Return the exact text of one supported scalar, failing closed otherwise."""
    text = text.strip()
    if text == "":
        return None
    if text[0] == '"':
        return _yaml_double_quoted(text)
    if text[0] == "'":
        return _yaml_single_quoted(text)
    if text[0] in YAML_PLAIN_FORBIDDEN_FIRST or text.startswith("<<") or text == "~":
        _yaml_fail(f"unsupported scalar indicator in {text!r}")
    return text


def _yaml_strip_comment(content):
    """Drop a trailing ` #` comment without ever cutting inside a quoted scalar."""
    index = 0
    while index < len(content):
        character = content[index]
        if character in "'\"":
            index = _yaml_quoted_end(content, index)
            continue
        if character == "#" and (index == 0 or content[index - 1] == " "):
            return content[:index].rstrip()
        index += 1
    return content.rstrip()


def _yaml_split_key(content):
    """Split one block mapping entry into its exact key text and value text."""
    if content[0] in "'\"":
        end = _yaml_quoted_end(content, 0)
        key = _yaml_scalar(content[:end])
        remainder = content[end:].lstrip(" ")
        if not remainder.startswith(":"):
            _yaml_fail(f"quoted key without a value separator in {content!r}")
        return key, remainder[1:].strip()
    index = 0
    while index < len(content):
        character = content[index]
        if character in "'\"":
            index = _yaml_quoted_end(content, index)
            continue
        if character in "{[":
            _yaml_fail(f"flow collection used as a mapping key in {content!r}")
        if character == ":" and content[index + 1:index + 2] in {"", " "}:
            return _yaml_scalar(content[:index]), content[index + 1:].strip()
        index += 1
    _yaml_fail(f"line is not a supported mapping entry: {content!r}")


def _yaml_skip_spaces(text, index):
    while index < len(text) and text[index] == " ":
        index += 1
    return index


def _yaml_flow_scalar(text, index):
    if text[index] in "'\"":
        end = _yaml_quoted_end(text, index)
        return _yaml_scalar(text[index:end]), end
    start = index
    while index < len(text) and text[index] not in ",}]":
        if text[index] in "'\"":
            _yaml_fail(f"quote inside a plain flow scalar in {text!r}")
        index += 1
    return _yaml_scalar(text[start:index]), index


def _yaml_flow_key(text, index):
    if text[index] in "'\"":
        end = _yaml_quoted_end(text, index)
        return _yaml_scalar(text[index:end]), end
    start = index
    while index < len(text) and text[index] not in ":,{}[]":
        index += 1
    return _yaml_scalar(text[start:index]), index


def _yaml_flow_map(text, index):
    result = {}
    index = _yaml_skip_spaces(text, index + 1)
    if text[index:index + 1] == "}":
        return result, index + 1
    while True:
        index = _yaml_skip_spaces(text, index)
        key, index = _yaml_flow_key(text, index)
        index = _yaml_skip_spaces(text, index)
        if text[index:index + 1] != ":":
            _yaml_fail(f"flow mapping entry without a value in {text!r}")
        value, index = _yaml_flow_node(text, index + 1)
        if key in result:
            _yaml_fail(f"duplicate mapping key {key!r}")
        result[key] = value
        index = _yaml_skip_spaces(text, index)
        separator = text[index:index + 1]
        if separator == ",":
            index += 1
            continue
        if separator == "}":
            return result, index + 1
        _yaml_fail(f"malformed flow mapping in {text!r}")


def _yaml_flow_seq(text, index):
    items = []
    index = _yaml_skip_spaces(text, index + 1)
    if text[index:index + 1] == "]":
        return items, index + 1
    while True:
        value, index = _yaml_flow_node(text, index)
        items.append(value)
        index = _yaml_skip_spaces(text, index)
        separator = text[index:index + 1]
        if separator == ",":
            index += 1
            continue
        if separator == "]":
            return items, index + 1
        _yaml_fail(f"malformed flow sequence in {text!r}")


def _yaml_flow_node(text, index):
    index = _yaml_skip_spaces(text, index)
    if index >= len(text):
        _yaml_fail(f"empty flow node in {text!r}")
    if text[index] == "{":
        return _yaml_flow_map(text, index)
    if text[index] == "[":
        return _yaml_flow_seq(text, index)
    return _yaml_flow_scalar(text, index)


def _yaml_flow(text):
    value, end = _yaml_flow_node(text, 0)
    if text[end:].strip():
        _yaml_fail(f"trailing content after a flow collection in {text!r}")
    return value


class _WorkflowYamlReader:
    """Read the supported block-YAML subset of a workflow, failing closed."""

    def __init__(self, text):
        if "\t" in text:
            _yaml_fail("tab character")
        self.lines = text.splitlines()
        self.index = 0

    def document(self):
        node = self._peek()
        if node is None:
            return {}
        if node[0] != 0:
            _yaml_fail("document does not start at column zero")
        value = self._block(0)
        if self._peek() is not None:
            _yaml_fail("trailing content after the document")
        return value

    def _peek(self):
        while self.index < len(self.lines):
            raw = self.lines[self.index]
            content = raw.strip()
            if content == "" or content.startswith("#"):
                self.index += 1
                continue
            if content.startswith("---") or content.startswith("...") or content.startswith("%"):
                _yaml_fail("document marker or directive")
            return len(raw) - len(raw.lstrip(" ")), raw
        return None

    def _block(self, indent):
        node = self._peek()
        if node is None or node[0] < indent:
            return None
        column, raw = node
        if column != indent:
            _yaml_fail("unexpected indentation")
        content = _yaml_strip_comment(raw[column:])
        if content == "-" or content.startswith("- "):
            return self._sequence(indent)
        if content[0] in "{[":
            self.index += 1
            return _yaml_flow(content)
        return self._mapping(indent)

    def _sequence(self, indent):
        items = []
        while True:
            node = self._peek()
            if node is None or node[0] < indent:
                break
            column, raw = node
            if column != indent:
                _yaml_fail("unexpected indentation in sequence")
            content = _yaml_strip_comment(raw[column:])
            if not (content == "-" or content.startswith("- ")):
                break
            offset = _yaml_skip_spaces(raw, column + 1)
            if _yaml_strip_comment(raw[offset:]) == "":
                self.index += 1
                nested = self._peek()
                items.append(None if nested is None or nested[0] <= indent else self._block(nested[0]))
                continue
            self.lines[self.index] = " " * offset + raw[offset:]
            items.append(self._block(offset))
        return items

    def _mapping(self, indent):
        result = {}
        while True:
            node = self._peek()
            if node is None or node[0] < indent:
                break
            column, raw = node
            if column != indent:
                _yaml_fail("unexpected indentation in mapping")
            content = _yaml_strip_comment(raw[column:])
            if content == "-" or content.startswith("- "):
                break
            key, value_text = _yaml_split_key(content)
            if key in result:
                _yaml_fail(f"duplicate mapping key {key!r}")
            self.index += 1
            result[key] = self._value(indent, value_text)
        return result

    def _value(self, indent, value_text):
        if value_text == "":
            nested = self._peek()
            if nested is None or nested[0] < indent:
                return None
            if nested[0] > indent:
                return self._block(nested[0])
            content = _yaml_strip_comment(nested[1][indent:])
            if content == "-" or content.startswith("- "):
                return self._sequence(indent)
            return None
        if value_text[0] in "|>":
            if value_text not in YAML_SUPPORTED_BLOCK_SCALARS:
                _yaml_fail(f"unsupported block scalar header {value_text!r}")
            return self._block_scalar(indent, value_text)
        if value_text[0] in "{[":
            return _yaml_flow(value_text)
        return _yaml_scalar(value_text)

    def _block_scalar(self, indent, header):
        lines, content_indent = [], None
        while self.index < len(self.lines):
            raw = self.lines[self.index]
            if raw.strip() == "":
                lines.append("")
                self.index += 1
                continue
            column = len(raw) - len(raw.lstrip(" "))
            if column <= indent:
                break
            if content_indent is None:
                content_indent = column
            if column < content_indent:
                _yaml_fail("block scalar indentation decreases")
            lines.append(raw[content_indent:])
            self.index += 1
        while lines and lines[-1] == "":
            lines.pop()
        if not lines:
            return ""
        body = "".join(f"{line}\n" for line in lines)
        return body[:-1] if header == "|-" else body


def workflow_document(workflow_text):
    """Return the structural document of a workflow file, failing closed."""
    return _WorkflowYamlReader(workflow_text).document()


def _workflow_steps(document):
    """Yield (job_name, step_index, step) for every structurally declared step."""
    if type(document) is not dict:
        _yaml_fail("workflow root is not a mapping")
    jobs = document.get("jobs")
    if jobs is None:
        return
    if type(jobs) is not dict:
        _yaml_fail("`jobs` is not a mapping")
    for job_name, job in jobs.items():
        if type(job) is not dict:
            _yaml_fail(f"job {job_name!r} is not a mapping")
        steps = job.get("steps")
        if steps is None:
            continue
        if type(steps) is not list:
            _yaml_fail(f"job {job_name!r} `steps` is not a sequence")
        for step_index, step in enumerate(steps):
            if type(step) is not dict:
                _yaml_fail(f"job {job_name!r} step {step_index} is not a mapping")
            yield job_name, step_index, step


def _semantic_artifact_action(uses):
    """Classify a `uses` value, case-folding only the owner/repository portion.

    GitHub resolves the owner/repository half of an action reference
    case-insensitively, so `Actions/Upload-Artifact@<pin>` runs the very same
    action as the authorized pin. Folding only that half keeps every mixed-case
    alias -- pinned or not -- inside the semantic enumeration, while the ref
    half is preserved verbatim so an alias can never satisfy the byte-for-byte
    authorized `uses` comparison. Anything else classifies as not an artifact
    action at all.
    """
    if type(uses) is not str:
        return None
    repository = uses.split("@", 1)[0].casefold()
    return repository if repository in ARTIFACT_ACTION_REPOSITORIES else None


def _artifact_action_invocations(workflow_text):
    """Enumerate every artifact action invocation with its structural context."""
    invocations = []
    for job_name, step_index, step in _workflow_steps(workflow_document(workflow_text)):
        uses = step.get("uses")
        action = _semantic_artifact_action(uses)
        if action is None:
            continue
        with_map = step.get("with")
        if with_map is not None and type(with_map) is not dict:
            _yaml_fail(f"job {job_name!r} step {step_index} `with` is not a mapping")
        invocations.append({
            "job": job_name,
            "step_index": step_index,
            "action": action,
            "uses": uses,
            "with": with_map,
            "conditional": "if" in step,
        })
    return invocations


def _parse_artifact_steps(workflow_text, action):
    """Parse every invocation of one semantic action, keeping `uses` verbatim."""
    return [
        {"uses": invocation["uses"], "with": invocation["with"]}
        for invocation in _artifact_action_invocations(workflow_text)
        if invocation["action"] == action
    ]


def _parse_upload_artifact_steps(workflow_text):
    return _parse_artifact_steps(workflow_text, UPLOAD_ARTIFACT_ACTION)


def _parse_download_artifact_steps(workflow_text):
    return _parse_artifact_steps(workflow_text, DOWNLOAD_ARTIFACT_ACTION)


def bound_signed_review_inventory_step(workflow_text):
    """Bind the one dedicated inventory step that runs right after the download.

    The signed review inventory is a dedicated, condition-free step that must be
    placed immediately after the one authorized `actions/download-artifact`
    invocation, declare only `name` and `run`, and carry a `run` scalar that is
    byte-for-byte the single approved one-line command. Because the scalar is
    compared whole, every non-executing or reordered form fails closed: heredoc
    data, text after `exit`, unreachable text, an uncalled function body,
    compound/split/control-flow command lines, comments, a blank command,
    surrounding text, dead or live step conditions, pre-download or delayed
    placement, duplicates, and every non-exact scalar. The command text may not
    appear in any other `run` scalar at all, so a second inert copy can never
    stand in for the executed one.
    """
    document = workflow_document(workflow_text)
    steps = list(_workflow_steps(document))

    semantic_downloads = [
        invocation
        for invocation in _artifact_action_invocations(workflow_text)
        if invocation["action"] == DOWNLOAD_ARTIFACT_ACTION
    ]
    require(
        len(semantic_downloads) == len(EXPECTED_CONSUMER_DOWNLOADS),
        "signing workflow must have exactly "
        f"{len(EXPECTED_CONSUMER_DOWNLOADS)} total download-artifact "
        f"invocations, found {len(semantic_downloads)}",
    )
    downloads = [
        (job, index, step)
        for job, index, step in steps
        if step.get("uses") == EXPECTED_DOWNLOAD_ARTIFACT_USES
        and step.get("with") == EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH
    ]
    require(
        len(downloads) == 1,
        f"signing workflow must have exactly one exact signed review download step, found {len(downloads)}",
    )
    download_job, download_index, download_step = downloads[0]
    require("if" not in download_step, "signed review download step must be conditional-free")
    job = document["jobs"][download_job]
    require("if" not in job, "signed review download job must be conditional-free")
    job_env = job.get("env")
    runtime_root = job_env.get(AUTHORITY_RUNTIME_ENV) if type(job_env) is dict else None
    require(
        type(runtime_root) is str
        and EXPECTED_SIGNED_REVIEW_INVENTORY_ROOT.replace(
            f"${AUTHORITY_RUNTIME_ENV}", runtime_root
        )
        == EXPECTED_SIGNED_REVIEW_DOWNLOAD_WITH["path"],
        "inventoried root does not resolve to the exact authorized download path",
    )

    exact, referencing = [], []
    for step_job, index, step in steps:
        run = step.get("run")
        if run is None:
            continue
        require(type(run) is str, f"job {step_job!r} step {index} `run` is not a scalar")
        if run == EXPECTED_SIGNED_REVIEW_INVENTORY_COMMAND:
            exact.append((step_job, index, step))
        elif any(marker in run for marker in SIGNED_REVIEW_INVENTORY_REFERENCE_MARKERS):
            referencing.append((step_job, index))
    require(
        not referencing,
        "signed review inventory command text appears outside the one dedicated "
        f"step at {referencing}",
    )
    require(
        len(exact) == 1,
        "signing workflow must run the exact signed review inventory command as the "
        f"whole run scalar of exactly one dedicated step, found {len(exact)}",
    )
    inventory_job, inventory_index, inventory_step = exact[0]
    require("if" not in inventory_step, "signed review inventory step must be conditional-free")
    require(
        sorted(inventory_step) == EXPECTED_SIGNED_REVIEW_INVENTORY_STEP_KEYS,
        "signed review inventory step must be dedicated to `name` and `run` only",
    )
    require(inventory_job == download_job, "signed review inventory step is outside the download job")
    require(
        inventory_index == download_index + 1,
        "signed review inventory step does not run immediately after the exact download step",
    )
    return {
        "job": inventory_job,
        "download_step_index": download_index,
        "inventory_step_index": inventory_index,
    }


def verify_signed_review_artifact_inventory(root):
    """Require exactly the three contract-bound regular non-symlink files."""
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(),
            "signed review artifact inventory root is not a real directory")
    entries = list(root.iterdir())
    expected = sorted(EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES)
    require(sorted(path.name for path in entries) == expected,
            "signed review artifact inventory has missing or extra files")
    require(all(path.is_file() and not path.is_symlink() for path in entries),
            "signed review artifact inventory contains a non-regular file")
    return expected


def _activation_pinning_module():
    """The one activation pinning module, however this process loaded it."""
    for name in ("pin_source_chain_activation_v2",
                 "scripts.pin_source_chain_activation_v2"):
        loaded = sys.modules.get(name)
        if loaded is not None:
            return loaded
    try:
        from scripts import pin_source_chain_activation_v2 as loaded
    except ModuleNotFoundError:
        import pin_source_chain_activation_v2 as loaded
    return loaded


def derive_independent_bootstrap_binding(review_head, review_run_id, output):
    """Bind the dispatched independent review to the derived live bootstrap.

    The sealed reviewer contract keeps `independent_bootstrap_commit` and
    `independent_bootstrap_tree` null before activation, so the signing
    workflow may never compare its authenticated review head to them: that
    comparison is unsatisfiable and would stop every real run before Authority
    verification. This derives both values from authenticated canonical GitHub
    repository, run, job, commit and tree readbacks for the unique authorized
    independent run, binds the sealed workflow, validator and bootstrap
    contract path-to-blob digests at that live head, and only then confirms
    that the dispatched run and its head are exactly the authenticated ones.
    """
    require(
        type(review_head) is str
        and re.fullmatch(r"[0-9a-f]{40}", review_head) is not None,
        "the independent-review head is not a canonical 40-hex commit",
    )
    require(
        type(review_run_id) is str
        and re.fullmatch(r"[1-9][0-9]*", review_run_id) is not None,
        "the independent-review run id is not a canonical positive integer",
    )
    binding = _activation_pinning_module()._derive_independent_bootstrap_binding()
    require(
        type(binding) is dict
        and sorted(binding) == EXPECTED_BOOTSTRAP_BINDING_FIELDS,
        "the derived independent bootstrap binding is malformed",
    )
    require(
        binding["derived_from"] == EXPECTED_BOOTSTRAP_BINDING_PROVENANCE,
        "the independent bootstrap binding was not derived from authenticated "
        "canonical GitHub readback",
    )
    require(
        binding["sealed_pre_live_commit"] is None
        and binding["sealed_pre_live_tree"] is None,
        "the sealed pre-live bootstrap identifiers must stay unavailable",
    )
    require(
        binding["repository"] == EXPECTED_INDEPENDENT_REPOSITORY
        and binding["workflow_path"] == EXPECTED_REVIEWER_WORKFLOW_PATH
        and binding["run_attempt"] == 1,
        "the derived binding is not the authorized reviewer attempt-1 run",
    )
    commit = binding["independent_bootstrap_commit"]
    tree = binding["independent_bootstrap_tree"]
    for label, value in (("commit", commit), ("tree", tree)):
        require(
            type(value) is str
            and re.fullmatch(r"[0-9a-f]{40}", value) is not None,
            f"the derived independent bootstrap {label} is absent or malformed",
        )
    require(
        commit != tree,
        "the derived independent bootstrap commit and tree are the same object",
    )
    require(
        binding["run_id"] == int(review_run_id),
        "the dispatched independent-review run is not the unique authorized "
        "attempt-1 run the authenticated inventory selects",
    )
    require(
        binding["run_head_sha"] == review_head and commit == review_head,
        "the dispatched independent-review run head is not the authenticated "
        "live bootstrap commit",
    )
    require(
        sorted(binding["bound_paths"]) == EXPECTED_REVIEWER_BOUND_PATHS,
        "the derived binding does not bind every sealed reviewer path",
    )
    output = Path(output)
    require(
        not output.exists() and output.parent.is_dir()
        and not output.parent.is_symlink(),
        "the independent bootstrap binding output path is unsafe",
    )
    output.write_bytes(
        json.dumps(binding, indent=2, sort_keys=True).encode() + b"\n"
    )
    return binding


def utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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


def _exact_type(value, expected_type, label):
    require(type(value) is expected_type, f"{label} has wrong JSON type")


def _require_exact_json(observed, expected, label):
    require(type(observed) is type(expected), f"{label} has wrong JSON type")
    if type(expected) is dict:
        require(set(observed) == set(expected), f"{label} field set mismatch")
        for key in expected:
            _require_exact_json(observed[key], expected[key], f"{label}.{key}")
    elif type(expected) is list:
        require(len(observed) == len(expected), f"{label} list length mismatch")
        for index, (observed_item, expected_item) in enumerate(zip(observed, expected)):
            _require_exact_json(observed_item, expected_item, f"{label}[{index}]")
    else:
        require(observed == expected, f"{label} value mismatch")


def _git(repository_root, *arguments):
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    try:
        return subprocess.run(
            ["git", "-C", str(repository_root), *arguments],
            check=True,
            capture_output=True,
            env=environment,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Git recomputation failed: {' '.join(arguments)}") from error


def _repository_identity(repository_root):
    remote = _git(repository_root, "remote", "get-url", "origin").decode("utf-8").strip()
    accepted = {
        "https://github.com/chrizzatsu/acc-attestation-authority",
        "https://github.com/chrizzatsu/acc-attestation-authority.git",
        "git@github.com:chrizzatsu/acc-attestation-authority.git",
        "ssh://git@github.com/chrizzatsu/acc-attestation-authority.git",
    }
    require(remote in accepted, "Git origin repository identity mismatch")
    return EXPECTED_REPOSITORY


def canonical_diff_bytes(repository_root, base_commit, head_commit):
    return _git(
        Path(repository_root).resolve(),
        "diff", "--binary", "--full-index", "--no-ext-diff", "--no-abbrev",
        "--find-renames=50%",
        "--src-prefix=a/", "--dst-prefix=b/", base_commit, head_commit, "--",
    )


def _safe_git_path(raw_path):
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("changed path is not UTF-8") from error
    pure = PurePosixPath(path)
    require(
        path and not pure.is_absolute() and str(pure) == path and
        all(part not in ("", ".", "..") for part in pure.parts) and
        not any(ord(character) < 32 for character in path),
        "changed path is non-canonical",
    )
    return path


def _blob_sha256(repository_root, oid):
    blob = _git(repository_root, "cat-file", "blob", oid)
    return hashlib.sha256(blob).hexdigest()


def changed_path_manifest(repository_root, base_commit, head_commit):
    raw = _git(
        repository_root, "diff", "--raw", "-z", "--full-index", "--no-ext-diff",
        "--no-abbrev", "--find-renames=50%", base_commit, head_commit, "--",
    )
    fields = raw.split(b"\0")
    require(fields[-1] == b"", "Git raw diff is not NUL terminated")
    fields.pop()
    entries = []
    index = 0
    header_pattern = re.compile(
        rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMDR])([0-9]{1,3})?"
    )
    while index < len(fields):
        match = header_pattern.fullmatch(fields[index])
        require(match is not None, "unsupported or malformed Git status in candidate diff")
        old_mode_raw, new_mode_raw, old_oid_raw, new_oid_raw, status_raw, score_raw = match.groups()
        index += 1
        require(index < len(fields), "changed path missing from Git raw diff")
        first_path = _safe_git_path(fields[index])
        index += 1
        status_code = status_raw.decode("ascii")
        if status_code == "R":
            require(index < len(fields) and score_raw is not None, "rename destination or score missing")
            second_path = _safe_git_path(fields[index])
            index += 1
            old_path, new_path = first_path, second_path
            similarity = int(score_raw)
            require(50 <= similarity <= 100, "rename similarity is outside canonical threshold")
        else:
            require(score_raw is None, "non-rename status has a similarity score")
            old_path = None if status_code == "A" else first_path
            new_path = None if status_code == "D" else first_path
            similarity = None
        old_mode = old_mode_raw.decode("ascii") if old_mode_raw != b"000000" else None
        new_mode = new_mode_raw.decode("ascii") if new_mode_raw != b"000000" else None
        old_oid = old_oid_raw.decode("ascii") if old_oid_raw != b"0" * 40 else None
        new_oid = new_oid_raw.decode("ascii") if new_oid_raw != b"0" * 40 else None
        entries.append({
            "status": status_code,
            "similarity": similarity,
            "old_path": old_path,
            "new_path": new_path,
            "old_mode": old_mode,
            "new_mode": new_mode,
            "old_blob_oid": old_oid,
            "new_blob_oid": new_oid,
            "old_sha256": _blob_sha256(repository_root, old_oid) if old_oid else None,
            "new_sha256": _blob_sha256(repository_root, new_oid) if new_oid else None,
        })
    return entries


def _commit_file_sha256(repository_root, commit, path):
    return hashlib.sha256(_git(repository_root, "show", f"{commit}:{path}")).hexdigest()


def recompute_candidate_bindings(repository_root, base_commit, head_commit):
    repository_root = Path(repository_root).resolve()
    require(HEX40.fullmatch(base_commit) is not None, "base commit is malformed")
    require(HEX40.fullmatch(head_commit) is not None, "head commit is malformed")
    require(_git(repository_root, "status", "--porcelain=v1", "-z", "--untracked-files=all") == b"", "candidate checkout is not clean")
    actual_head = _git(repository_root, "rev-parse", "HEAD").decode().strip()
    require(actual_head == head_commit, "candidate checkout HEAD mismatch")
    actual_base = _git(repository_root, "rev-parse", f"{base_commit}^{{commit}}").decode().strip()
    require(actual_base == base_commit, "candidate base object mismatch")
    parent_line = _git(repository_root, "rev-list", "--parents", "-n", "1", head_commit).decode().strip().split()
    require(parent_line == [head_commit, base_commit], "candidate must have the exact base as sole parent")
    manifest = changed_path_manifest(repository_root, base_commit, head_commit)
    touched_paths = set()
    for entry in manifest:
        entry_paths = {path for path in (entry["old_path"], entry["new_path"]) if path}
        require(touched_paths.isdisjoint(entry_paths), "candidate changed-path manifest contains duplicate paths")
        touched_paths.update(entry_paths)
    require(any(entry["new_path"] == "AUTHORITY-V2-SHA256SUMS" for entry in manifest), "external manifest does not cover the candidate checksum file")
    artifact_paths = (
        "AUTHORITY-V2-SHA256SUMS",
        "authority-v2-policy.json",
        "protected-asset-receipt-v2.json",
        "reviewer-authorization-v2.json",
        "schemas/authority-v2-subject.schema.json",
    )
    diff = canonical_diff_bytes(repository_root, base_commit, head_commit)
    internal_manifest_bytes = _git(repository_root, "show", f"{head_commit}:AUTHORITY-V2-SHA256SUMS")
    try:
        internal_manifest = internal_manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("candidate internal manifest is not UTF-8") from error
    require(internal_manifest.endswith("\n"), "candidate internal manifest lacks final newline")
    return {
        "repository": _repository_identity(repository_root),
        "base_commit": base_commit,
        "base_tree": _git(repository_root, "rev-parse", f"{base_commit}^{{tree}}").decode().strip(),
        "head_commit": head_commit,
        "head_tree": _git(repository_root, "rev-parse", f"{head_commit}^{{tree}}").decode().strip(),
        "sole_parent": base_commit,
        "canonical_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "changed_path_manifest": manifest,
        "internal_manifest": internal_manifest,
        "artifact_sha256": {path: _commit_file_sha256(repository_root, head_commit, path) for path in artifact_paths},
    }


def expected_subject(policy, case, activation_sha, review_receipt_sha256, authenticated_issuance):
    subject = policy["subject"]
    require(type(authenticated_issuance) is GITHUB_ISSUANCE.AuthenticatedIssuance,
            "expected subject requires authenticated GitHub issuance")
    return {
        "schema_version": 2,
        "authority_id": policy["authority_id"],
        "case": case,
        "authority_policy_sha256": EXPECTED_POLICY_SHA256,
        "reviewed_activation_sha": activation_sha,
        "preissuance_review_receipt_sha256": review_receipt_sha256,
        "issuance": GITHUB_ISSUANCE.subject_issuance_binding(authenticated_issuance),
        "workflow_evidence": {
            "repository": EXPECTED_REPOSITORY,
            "workflow_ref": EXPECTED_WORKFLOW_REF,
            "git_ref": EXPECTED_GIT_REF,
            "event_name": EXPECTED_TRIGGER,
        },
        "subject": {
            "clerk_publishable_key_fingerprint_sha256": subject["clerk_publishable_key_fingerprint_sha256"],
            "clerk_api_instance_id_fingerprint_sha256": subject["clerk_api_instance_id_fingerprint_sha256"],
            "environment_type": "development",
            "acc_production_base_sha": subject["acc_production_base_sha"],
        },
        "case_contract": policy["temporal_subject_contract"]["cases"][case],
        "privacy": policy["privacy"],
    }


def _manifest_bytes(names, read_bytes):
    return b"".join(
        f"{hashlib.sha256(read_bytes(name)).hexdigest()}  {name}\n".encode("ascii")
        for name in names
    )


# ---------------------------------------------------------------------------
# F8-CANDIDATE-SELF-AUTHORIZATION
#
# The candidate may describe what an authorized activation would look like, but
# it may never carry one. Every candidate-owned boolean that would assert an
# activation, an approval, a release, a publication, a dispatch or a created
# repository must be literally false at handoff, in every artifact at once.
# This is checked exhaustively rather than by sampling, so a single flipped
# member in any one artifact fails the whole candidate closed.
# ---------------------------------------------------------------------------
POLICY_ARTIFACT = "authority-v2-policy.json"
SOURCE_BOOTSTRAP_ARTIFACT = "protected-source-bootstrap-v2/bootstrap-contract.json"
INDEPENDENT_BOOTSTRAP_ARTIFACT = (
    "independent-review-bootstrap-v2/bootstrap-contract.json"
)
ACTIVATION_ARTIFACT = "source-chain-activation-v2.json"
PUBLICATION_ARTIFACT = "publication-writer-exclusion-v2.json"
PREISSUANCE_CONTRACT_PATH = ("issuance_contract", "preissuance_receipt_contract")
HANDOFF_STATE_PATH = ("issuance_state_at_candidate_handoff",)
PROTECTED_REVIEW_PATH = ("protected_review_result",)
CANDIDATE_OWNED_FALSE_MEMBERS = (
    (POLICY_ARTIFACT, (*PREISSUANCE_CONTRACT_PATH, "activation_authorized")),
    (POLICY_ARTIFACT, (*PREISSUANCE_CONTRACT_PATH, "approved")),
    (POLICY_ARTIFACT, (*PREISSUANCE_CONTRACT_PATH, "final_authority_approval")),
    (POLICY_ARTIFACT, (*PREISSUANCE_CONTRACT_PATH, "release_authorized")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "activation_authorized")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "approval")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "github_environment_secrets_staged")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "release_authorized")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "release_published")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "subjects_issued")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "subjects_signed")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "workflow_dispatched")),
    (POLICY_ARTIFACT, (*HANDOFF_STATE_PATH, "workflow_live_on_main")),
    (SOURCE_BOOTSTRAP_ARTIFACT, (*PROTECTED_REVIEW_PATH, "activation_authorized")),
    (SOURCE_BOOTSTRAP_ARTIFACT, (*PROTECTED_REVIEW_PATH, "approved")),
    (SOURCE_BOOTSTRAP_ARTIFACT, (*PROTECTED_REVIEW_PATH, "release_authorized")),
    (SOURCE_BOOTSTRAP_ARTIFACT, ("repository_created",)),
    (SOURCE_BOOTSTRAP_ARTIFACT, ("workflow_dispatched",)),
    (INDEPENDENT_BOOTSTRAP_ARTIFACT, ("publication_performed",)),
    (INDEPENDENT_BOOTSTRAP_ARTIFACT, ("repository_created",)),
    (INDEPENDENT_BOOTSTRAP_ARTIFACT, ("workflow_dispatched",)),
    (PUBLICATION_ARTIFACT, ("release_authorized",)),
    (ACTIVATION_ARTIFACT, ("activation_authorized",)),
    (ACTIVATION_ARTIFACT, ("f8_closed",)),
    (ACTIVATION_ARTIFACT, ("repositories_created",)),
    (ACTIVATION_ARTIFACT, ("runs_observed",)),
    (ACTIVATION_ARTIFACT, ("workflows_written",)),
)
# Every candidate-owned closure matrix must keep exactly F8 and F12 open.
CANDIDATE_OWNED_CLOSURE_MATRICES = (
    (SOURCE_BOOTSTRAP_ARTIFACT, (*PROTECTED_REVIEW_PATH, "closure_matrix")),
)
CANDIDATE_HANDOFF_OPEN_CLOSURES = EXPECTED_PREACTIVATION_OPEN_CLOSURES


def _candidate_member(document, path, label):
    observed = document
    for key in path:
        require(
            type(observed) is dict and key in observed,
            f"{label} is absent from the candidate artifact",
        )
        observed = observed[key]
    return observed


def verify_candidate_self_authorization(repository_root=ROOT):
    """Fail closed unless every candidate-owned artifact ships unauthorized."""
    repository_root = Path(repository_root)
    documents = {}
    for relative in {name for name, _ in CANDIDATE_OWNED_FALSE_MEMBERS} | {
        name for name, _ in CANDIDATE_OWNED_CLOSURE_MATRICES
    }:
        path = repository_root / relative
        require(
            path.is_file() and not path.is_symlink(),
            f"candidate-owned artifact is absent or unsafe: {relative}",
        )
        documents[relative] = _closed_json(path.read_bytes(), relative)
    for relative, member in CANDIDATE_OWNED_FALSE_MEMBERS:
        label = f"{relative}:{'.'.join(member)}"
        observed = _candidate_member(documents[relative], member, label)
        require(
            observed is False,
            f"{label} must be literally false at candidate handoff, so the "
            "candidate can never authorize its own activation, approval, "
            "release, publication or dispatch",
        )
    for relative, member in CANDIDATE_OWNED_CLOSURE_MATRICES:
        label = f"{relative}:{'.'.join(member)}"
        matrix = _candidate_member(documents[relative], member, label)
        require(
            type(matrix) is dict and set(matrix) == set(EXPECTED_CLOSURES)
            and all(type(value) is bool for value in matrix.values()),
            f"{label} closure matrix field set mismatch",
        )
        for name in EXPECTED_CLOSURES:
            expected = name not in CANDIDATE_HANDOFF_OPEN_CLOSURES
            require(
                matrix[name] is expected,
                f"{label} closure {name} contradicts the candidate handoff "
                "partition, in which F8 and F12 stay open",
            )
    # The policy's own receipt contract must describe exactly that partition.
    contract = _candidate_member(
        documents[POLICY_ARTIFACT], PREISSUANCE_CONTRACT_PATH,
        "policy preissuance receipt contract",
    )
    require(
        sorted(contract["closure_matrix_required_false"])
        == sorted(CANDIDATE_HANDOFF_OPEN_CLOSURES),
        "the policy receipt contract does not keep F8 and F12 open at handoff",
    )
    require(
        sorted(contract["closure_matrix_required_true"])
        == sorted(EXPECTED_PREACTIVATION_CLOSED_CLOSURES),
        "the policy receipt contract closed closures contradict the handoff "
        "partition",
    )
    require(
        contract["activation_findings"] == [EXPECTED_ACTIVATION_FINDING],
        "the policy receipt contract does not record the exact open activation "
        "finding",
    )
    return {
        "candidate_owned_artifacts": len(documents),
        "candidate_owned_fields_checked": len(CANDIDATE_OWNED_FALSE_MEMBERS),
        "self_authorized": False,
    }


def verify_manifest(manifest_path, expected_names=EXPECTED_MANIFEST_PATHS):
    for name in expected_names:
        require(re.fullmatch(r"[A-Za-z0-9_./-]+", name) is not None, "manifest name is non-canonical")
        path = ROOT / name
        require(path.is_file() and not path.is_symlink(), f"manifest file absent or non-regular: {name}")
    observed = Path(manifest_path).read_bytes()
    expected = _manifest_bytes(expected_names, lambda name: (ROOT / name).read_bytes())
    require(observed == expected, "manifest raw bytes mismatch")


def _sealed_bootstrap_file(root, relative, label):
    path = Path(root) / relative
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} is absent or unsafe",
    )
    return path.read_bytes()


def verify_protected_source_bootstrap(root=PROTECTED_SOURCE_BOOTSTRAP_PATH):
    """Seal every byte of the protected Kanban export workflow and helper."""
    root = Path(root)
    contract_data = _sealed_bootstrap_file(
        root, "bootstrap-contract.json", "protected-source bootstrap contract",
    )
    workflow_data = _sealed_bootstrap_file(
        root, EXPECTED_SOURCE_WORKFLOW_PATH, "protected-source export workflow",
    )
    helper_data = _sealed_bootstrap_file(
        root, EXPECTED_SOURCE_HELPER_PATH, "protected-source export helper",
    )
    contract = _closed_json(contract_data, "protected-source bootstrap contract")
    require(
        type(contract) is dict
        and contract.get("schema_version") == 1
        and contract.get("contract") == "acc-authority-v2-protected-source-bootstrap"
        and contract.get("repository") == EXPECTED_SOURCE_REPOSITORY
        and contract.get("reviewer_task_id") == EXPECTED_REVIEWER_TASK_ID
        and contract.get("authority_repository") == EXPECTED_REPOSITORY
        and contract.get("independent_review_repository") == EXPECTED_REVIEWER_REPOSITORY,
        "protected-source bootstrap identity mismatch",
    )
    workflow = contract.get("workflow")
    helper = contract.get("helper")
    require(
        type(workflow) is dict
        and workflow.get("path") == EXPECTED_SOURCE_WORKFLOW_PATH
        and workflow.get("ref") == EXPECTED_GIT_REF
        and workflow.get("trigger") == EXPECTED_TRIGGER
        and workflow.get("job_environment") == "protected-kanban-export",
        "protected-source export workflow identity mismatch",
    )
    require(
        type(helper) is dict and helper.get("path") == EXPECTED_SOURCE_HELPER_PATH,
        "protected-source export helper identity mismatch",
    )
    require(
        hashlib.sha256(workflow_data).hexdigest() == workflow.get("sha256")
        and hashlib.sha256(helper_data).hexdigest() == helper.get("sha256"),
        "protected-source bootstrap byte binding mismatch",
    )
    artifact = contract.get("artifact")
    require(
        type(artifact) is dict
        and artifact.get("name") == EXPECTED_SOURCE_ARTIFACT_NAME
        and artifact.get("files") == [
            "kanban-review-envelope.json", "preissuance-review-receipt.json",
        ]
        and artifact.get("immutable_actions_artifact_required") is True,
        "protected-source artifact contract mismatch",
    )
    require(
        contract.get("caller_supplied_receipt_bytes_forbidden") is True
        and contract.get("caller_supplied_envelope_bytes_forbidden") is True
        and contract.get("caller_selectable_paths_forbidden") is True
        and contract.get("caller_selectable_inputs") == []
        and contract.get("exclusive_artifact_member_write_required") is True
        and contract.get("authenticated_server_run_state_required") is True
        and contract.get("repository_created") is False
        and contract.get("workflow_dispatched") is False
        and contract.get("publication_performed") is False
        and contract.get("zero_spend_required") is True,
        "protected-source bootstrap safety mismatch",
    )
    binding = contract.get("authority_binding")
    review_result = contract.get("protected_review_result")
    require(
        type(binding) is dict and type(review_result) is dict
        and binding.get("activation_state") == AUTHORIZED_PENDING_EVIDENCE
        and review_result.get("activation_state") == AUTHORIZED_PENDING_EVIDENCE
        and binding.get("no_fallback") is True,
        "protected-source bootstrap activation state is not the reviewed state",
    )
    require(
        binding.get("authorized_run_attempt") == 1
        and type(binding.get("authorized_run_attempt")) is int,
        "protected-source bootstrap does not authorize exactly attempt 1",
    )
    require(
        contract.get("live_identifiers_never_pre_pinned")
        == EXPECTED_LIVE_DERIVED_FIELDS
        and contract.get("authenticated_read_inventory")
        == EXPECTED_SOURCE_AUTHENTICATED_READ_INVENTORY
        and contract.get("phases") == EXPECTED_SOURCE_PHASES,
        "protected-source bootstrap runtime derivation inventory mismatch",
    )
    # `maximum_authorized_activation_attempts` and `GITHUB_RUN_ATTEMPT == 1`
    # are declarations; neither excludes a second `workflow_dispatch` run id.
    # The sealed bootstrap must carry the mechanism that does.
    one_activation = contract.get("one_activation")
    require(
        type(one_activation) is dict
        and one_activation.get("workflow_disabled_before_protected_actions") is True
        and one_activation.get(
            "additional_run_ids_excluded_before_protected_actions") is True
        and one_activation.get("authenticated_disable_readback_required") is True
        and one_activation.get("disable_covers_failure_paths") is True
        and one_activation.get("exhaustive_server_link_pagination_required") is True
        and one_activation.get("fixed_page_count_forbidden") is True
        and one_activation.get("gate_phase") == "gate"
        and one_activation.get("expected_workflow_state_before_protected_actions")
        == "disabled_manually",
        "protected-source bootstrap does not enforce one authorized activation",
    )
    require(
        all(binding.get(field) is None for field in EXPECTED_LIVE_DERIVED_FIELDS),
        "authorized protected-source bootstrap pre-pins live evidence",
    )
    require(
        all(
            type(binding.get(field)) is str
            and HEX64.fullmatch(binding[field]) is not None
            for field in ("independent_validator_sha256", "independent_workflow_sha256")
        ),
        "authorized protected-source bootstrap leaves a reviewed blob unpinned",
    )
    _require_activation_only_decision(
        {**review_result, "candidate": {}, "source_execution_chain": {}},
        review_result.get("activation_state"),
    )
    workflow_text = workflow_data.decode("utf-8")
    require(
        "review_receipt_base64:" not in workflow_text
        and "kanban_review_json:" not in workflow_text
        and "inputs." not in workflow_text
        and "KANBAN_REVIEW_RESULT_PATH" not in workflow_text
        and "--review" not in workflow_text
        and EXPECTED_SOURCE_HELPER_PATH in workflow_text,
        "protected-source export workflow accepts caller bytes or omits sealed export",
    )
    helper_text = helper_data.decode("utf-8")
    require(
        "--review" not in helper_text
        and "KANBAN_REVIEW" not in helper_text,
        "protected-source export helper accepts caller-supplied review bytes",
    )
    return contract


def verify_independent_review_bootstrap(root=INDEPENDENT_REVIEW_BOOTSTRAP_PATH):
    root = Path(root)
    contract_data = _sealed_bootstrap_file(
        root, "bootstrap-contract.json", "independent review bootstrap contract",
    )
    workflow_data = _sealed_bootstrap_file(
        root, EXPECTED_REVIEWER_WORKFLOW_PATH, "independent review workflow",
    )
    collector_data = _sealed_bootstrap_file(
        root, EXPECTED_TERMINAL_COLLECTOR_WORKFLOW_PATH,
        "independent terminal readback collector workflow",
    )
    validator_data = _sealed_bootstrap_file(
        root, EXPECTED_REVIEWER_VALIDATOR_PATH, "independent review validator",
    )
    contract = _closed_json(contract_data, "independent review bootstrap contract")
    require(
        type(contract) is dict
        and contract.get("schema_version") == 2
        and contract.get("contract") == "acc-authority-v2-independent-review-bootstrap"
        and contract.get("repository") == EXPECTED_REVIEWER_REPOSITORY,
        "independent review bootstrap identity mismatch",
    )
    workflow = contract.get("workflow")
    require(type(workflow) is dict, "independent review bootstrap workflow malformed")
    require(
        workflow.get("path") == EXPECTED_REVIEWER_WORKFLOW_PATH
        and workflow.get("ref") == EXPECTED_GIT_REF
        and workflow.get("trigger") == EXPECTED_TRIGGER
        and workflow.get("job_environment") == "independent-review"
        and workflow.get("identity") == EXPECTED_REVIEWER_BOOTSTRAP_IDENTITY
        and workflow.get("issuer") == EXPECTED_ISSUER
        and workflow.get("caller_inputs") == [],
        "independent review bootstrap workflow identity mismatch",
    )
    validator = contract.get("validator")
    require(
        type(validator) is dict
        and validator.get("path") == EXPECTED_REVIEWER_VALIDATOR_PATH,
        "independent review bootstrap validator malformed",
    )
    require(
        hashlib.sha256(workflow_data).hexdigest() == workflow.get("sha256")
        and hashlib.sha256(validator_data).hexdigest() == validator.get("sha256"),
        "independent review bootstrap byte binding mismatch",
    )
    terminal = contract.get("terminal_readback")
    require(
        type(terminal) is dict
        and terminal.get("collector_workflow_path")
        == EXPECTED_TERMINAL_COLLECTOR_WORKFLOW_PATH
        and terminal.get("collector_workflow_sha256")
        == hashlib.sha256(collector_data).hexdigest()
        and terminal.get("activation_workflow_path")
        == EXPECTED_REVIEWER_WORKFLOW_PATH
        and terminal.get("trigger") == "workflow_run"
        and terminal.get("caller_inputs") == []
        and terminal.get("terminal_api_readback_required") is True
        and terminal.get("artifact_exactly_one_non_expired") is True
        and terminal.get("artifact_archive_digest_recomputed") is True
        and terminal.get("artifact_content_digest_recomputed") is True
        and terminal.get("activation_record_digest_required") is True
        and terminal.get("closed_receipt_required") is True
        and terminal.get("recursion_forbidden") is True
        and terminal.get("no_repository_or_content_mutation") is True
        and terminal.get("permissions") == {
            "actions": "read", "contents": "read", "id-token": "write",
            "metadata": "read",
        },
        "independent terminal readback collector contract mismatch",
    )
    source = contract.get("protected_source")
    require(
        type(source) is dict
        and source.get("task_id") == EXPECTED_REVIEWER_TASK_ID
        and source.get("repository") == EXPECTED_SOURCE_REPOSITORY
        and source.get("workflow_path") == EXPECTED_SOURCE_WORKFLOW_PATH
        and source.get("workflow_ref") == EXPECTED_GIT_REF
        and source.get("helper_path") == EXPECTED_SOURCE_HELPER_PATH
        and source.get("bootstrap_contract_path")
        == "protected-source-bootstrap-v2/bootstrap-contract.json"
        and source.get("artifact_name") == EXPECTED_SOURCE_ARTIFACT_NAME
        and source.get("immutable_actions_artifact_required") is True
        and source.get("fallback") is False,
        "protected Kanban orchestration source mismatch",
    )
    require(
        contract.get("caller_supplied_receipt_bytes_forbidden") is True
        and contract.get("caller_supplied_bundle_bytes_forbidden") is True
        and contract.get("caller_supplied_source_run_forbidden") is True
        and contract.get("caller_selectable_paths_forbidden") is True
        and contract.get("same_activation_state_required") is True
        and contract.get("phases") == EXPECTED_INDEPENDENT_PHASES
        and contract.get("authenticated_read_inventory")
        == EXPECTED_AUTHENTICATED_READ_INVENTORY
        and contract.get("repository_created") is False
        and contract.get("workflow_dispatched") is False
        and contract.get("zero_spend_required") is True
        and contract.get("publication_performed") is False,
        "independent review bootstrap safety mismatch",
    )
    acquisition = contract.get("authority_acquisition")
    require(
        type(acquisition) is dict
        and acquisition.get("workflow_bytes_sha256_required") is True
        and acquisition.get("certificate_github_workflow_sha_required") is True
        and acquisition.get("sigstore_bundle_required") is True
        and acquisition.get("fallback") is False,
        "independent review acquisition contract mismatch",
    )
    signed = contract.get("signed_artifact")
    require(
        type(signed) is dict
        and signed.get("name") == EXPECTED_SIGNED_REVIEW_ARTIFACT_NAME
        and signed.get("files") == EXPECTED_SIGNED_REVIEW_ARTIFACT_FILES
        and signed.get("retention_days") == EXPECTED_SIGNED_REVIEW_ARTIFACT_RETENTION_DAYS,
        "independent review signed artifact metadata mismatch",
    )
    workflow_text = workflow_data.decode("utf-8")
    require(
        "review_receipt_base64:" not in workflow_text
        and "review_receipt_bundle_base64:" not in workflow_text
        and "source_run_id:" not in workflow_text
        and "inputs.source_run_id" not in workflow_text
        and "actions/download-artifact@" in workflow_text
        and EXPECTED_SOURCE_ARTIFACT_NAME in workflow_text
        and EXPECTED_REVIEWER_VALIDATOR_PATH in workflow_text
        and "--certificate-github-workflow-sha" in workflow_text,
        "independent review workflow accepts caller bytes or omits protected acquisition",
    )
    upload_steps = _parse_upload_artifact_steps(workflow_text)
    require(
        len(upload_steps) == 3,
        "independent review workflow must have exactly the signed review and "
        "external review and generated activation upload-artifact steps, found "
        f"{len(upload_steps)}",
    )
    require(
        upload_steps == [
            {
                "uses": EXPECTED_UPLOAD_ARTIFACT_USES,
                "with": EXPECTED_SIGNED_REVIEW_UPLOAD_WITH,
            },
            {
                "uses": EXPECTED_UPLOAD_ARTIFACT_USES,
                "with": EXPECTED_EXTERNAL_REVIEW_UPLOAD_WITH,
            },
            {
                "uses": EXPECTED_UPLOAD_ARTIFACT_USES,
                "with": EXPECTED_GENERATED_ACTIVATION_UPLOAD_WITH,
            },
        ],
        "independent review workflow upload-artifact action or complete with-map mismatch",
    )
    external = contract.get("external_activation_review")
    require(
        type(external) is dict
        and external.get("name") == EXPECTED_EXTERNAL_REVIEW_ARTIFACT_NAME
        and external.get("files") == EXPECTED_EXTERNAL_REVIEW_ARTIFACT_FILES
        and external.get("required_decision") == "APPROVED"
        and external.get("required_findings_count") == 0
        and external.get("required_activation_authorized") is True
        and external.get("candidate_authored_decision_forbidden") is True
        and type(external.get("decision_source")) is str
        and external.get("decision_source")
        and type(external.get("decision_path_template")) is str
        and "decision" not in external
        and external.get("reviewer_profile") == "acc-reviewer"
        and external.get("self_review_forbidden") is True
        and external.get("sigstore_bundle_required") is True
        and external.get("produced_after_exact_candidate_required") is True
        and external.get("retention_days")
        == EXPECTED_SIGNED_REVIEW_ARTIFACT_RETENTION_DAYS,
        "independent review external activation review contract mismatch",
    )
    receipt_member, bundle_member = EXPECTED_EXTERNAL_REVIEW_ARTIFACT_FILES
    require(
        f"--bundle protected-review/{bundle_member}" in workflow_text
        and f"protected-review/{receipt_member}" in workflow_text
        and "--phase external-review" in workflow_text,
        "independent review workflow cannot produce the external activation review",
    )
    validator_text = validator_data.decode("utf-8")
    require(
        "authorized_source_run" in validator_text
        and "verify_source_bytes" in validator_text
        and "verify_bootstrap_bytes" in validator_text
        and "verify_source_contract_state" in validator_text,
        "independent review validator omits executed-byte authentication",
    )
    require(
        validator_text.count("add_argument") == 1
        and 'parser.add_argument("--phase"' in validator_text,
        "independent review validator accepts caller-selectable inputs",
    )
    return contract


def authorized_source_run(contract):
    """Return the immutable, non-caller-selectable authorized protected-source run."""
    require(type(contract) is dict, "independent review bootstrap contract malformed")
    run = contract.get("authorized_source_run")
    require(type(run) is dict, "authorized protected-source run is absent")
    require(
        run.get("selector") == "immutable-contract-pinned"
        and run.get("caller_selectable") is False
        and run.get("no_fallback") is True,
        "authorized protected-source run must not be caller selectable",
    )
    require(
        run.get("activation_state")
        in {"ready", AUTHORIZED_PENDING_EVIDENCE, "unavailable"},
        "authorized protected-source run activation state mismatch",
    )
    require(
        run.get("source_repository") == EXPECTED_SOURCE_REPOSITORY
        and run.get("source_workflow_path") == EXPECTED_SOURCE_WORKFLOW_PATH
        and run.get("source_helper_path") == EXPECTED_SOURCE_HELPER_PATH
        and run.get("artifact_name") == EXPECTED_SOURCE_ARTIFACT_NAME
        and run.get("reviewer_task_id") == EXPECTED_REVIEWER_TASK_ID
        and run.get("authority_repository") == EXPECTED_REPOSITORY
        and run.get("run_attempt") == 1,
        "authorized protected-source run identity mismatch",
    )
    return run


def expected_source_execution_chain(independent_contract, source_contract):
    """Derive the only source/validator execution chain this Authority accepts."""
    run = authorized_source_run(independent_contract)
    require(
        run.get("activation_state") == "ready",
        "authorized protected-source execution chain is unavailable",
    )
    require(type(source_contract) is dict, "protected-source bootstrap contract malformed")
    for field in SOURCE_CHAIN_HEX40_FIELDS:
        require(
            type(run.get(field)) is str and HEX40.fullmatch(run[field]) is not None,
            f"authorized protected-source run {field} is unpinned",
        )
    for field in SOURCE_CHAIN_HEX64_FIELDS:
        require(
            type(run.get(field)) is str and HEX64.fullmatch(run[field]) is not None,
            f"authorized protected-source run {field} is unpinned",
        )
    require(
        type(run.get("run_id")) is int and type(run["run_id"]) is not bool
        and run["run_id"] > 0,
        "authorized protected-source run id is unpinned",
    )
    require(
        run["source_workflow_sha256"] == source_contract.get("workflow", {}).get("sha256")
        and run["source_helper_sha256"] == source_contract.get("helper", {}).get("sha256"),
        "authorized protected-source run does not seal the exact export bytes",
    )
    require(
        run["certificate_github_workflow_sha"] == run["independent_bootstrap_commit"],
        "certificate workflow SHA must equal the pinned independent bootstrap commit",
    )
    chain = {field: run[field] for field in SOURCE_CHAIN_FIELDS}
    require(set(chain) == set(SOURCE_CHAIN_FIELDS), "source execution chain field set mismatch")
    return chain


def verify_source_execution_chain(observed, independent_contract, source_contract):
    """Fail closed unless the observed chain equals the pinned chain byte for byte."""
    expected = expected_source_execution_chain(independent_contract, source_contract)
    _exact_type(observed, dict, "source execution chain")
    require(set(observed) == set(expected), "source execution chain field set mismatch")
    _require_exact_json(observed, expected, "source execution chain")
    return expected


def receipt_source_execution_chain(chain):
    """The receipt embeds every chain field except its own self-referential digests."""
    _exact_type(chain, dict, "source execution chain")
    return {field: chain[field] for field in RECEIPT_SOURCE_CHAIN_FIELDS}


def _expected_protected_binding(policy, protected_receipt):
    asset = protected_receipt["protected_asset"]
    protected = policy["protected_identity_asset"]
    return {
        "sha256": EXPECTED_PROTECTED_ASSET_SHA256,
        "present": asset["present"],
        "directory_mode": protected["directory_mode"],
        "file_mode": protected["file_mode"],
        "environment_type": protected["environment_type_verified"],
        "raw_publishable_key_present": asset["raw_publishable_key_present"],
        "raw_api_instance_id_present": asset["raw_api_instance_id_present"],
        "clerk_publishable_key_fingerprint_sha256": policy["subject"]["clerk_publishable_key_fingerprint_sha256"],
        "clerk_api_instance_id_fingerprint_sha256": policy["subject"]["clerk_api_instance_id_fingerprint_sha256"],
    }


def _validate_manifest_shape(entries):
    _exact_type(entries, list, "changed_path_manifest")
    exact_fields = {
        "status", "similarity", "old_path", "new_path", "old_mode", "new_mode",
        "old_blob_oid", "new_blob_oid", "old_sha256", "new_sha256",
    }
    all_paths = set()
    for entry in entries:
        _exact_type(entry, dict, "changed-path entry")
        require(set(entry) == exact_fields, "changed-path entry field set mismatch")
        _exact_type(entry["status"], str, "changed-path status")
        require(entry["status"] in {"A", "M", "D", "R"}, "changed-path status mismatch")
        for key in ("old_path", "new_path", "old_mode", "new_mode", "old_blob_oid", "new_blob_oid", "old_sha256", "new_sha256"):
            require(type(entry[key]) in (str, type(None)), f"changed-path {key} has wrong JSON type")
        require(type(entry["similarity"]) in (int, type(None)) and type(entry["similarity"]) is not bool, "rename similarity has wrong JSON type")
        for key in ("old_blob_oid", "new_blob_oid"):
            require(entry[key] is None or HEX40.fullmatch(entry[key]) is not None, f"malformed {key}")
        for key in ("old_sha256", "new_sha256"):
            require(entry[key] is None or HEX64.fullmatch(entry[key]) is not None, f"malformed {key}")
        for key in ("old_mode", "new_mode"):
            require(entry[key] is None or re.fullmatch(r"[0-7]{6}", entry[key]) is not None, f"malformed {key}")
        entry_paths = {path for path in (entry["old_path"], entry["new_path"]) if path}
        require(all_paths.isdisjoint(entry_paths), "duplicate path in changed-path manifest")
        all_paths.update(entry_paths)


def _issuance_candidate(expected_candidate, review_receipt_sha256):
    return {
        "head_commit": expected_candidate["head_commit"],
        "head_tree": expected_candidate["head_tree"],
        "canonical_diff_sha256": expected_candidate["canonical_diff_sha256"],
        "review_receipt_sha256": review_receipt_sha256,
    }


def protected_artifact_content_sha256(members):
    """Digest the exact immutable protected-source artifact members."""
    digest = hashlib.sha256(b"acc-authority-v2-protected-source-artifact\0")
    for name in sorted(members):
        encoded = name.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(members[name]).to_bytes(8, "big"))
        digest.update(members[name])
    return digest.hexdigest()


def authenticate_receipt_source_chain(receipt, receipt_data, envelope_data):
    """Authenticate the entire protected-source and validator execution chain."""
    require(type(receipt_data) is bytes, "preissuance receipt bytes are required")
    require(
        type(envelope_data) is bytes,
        "preissuance receipt requires the exact protected Kanban envelope bytes",
    )
    independent_contract = verify_independent_review_bootstrap()
    source_contract = verify_protected_source_bootstrap()
    embedded = receipt.get("source_execution_chain")
    _exact_type(embedded, dict, "receipt source execution chain")
    require(
        set(embedded) == set(RECEIPT_SOURCE_CHAIN_FIELDS),
        "receipt source execution chain field set mismatch",
    )
    observed = {
        **embedded,
        "artifact_content_sha256": protected_artifact_content_sha256({
            "kanban-review-envelope.json": envelope_data,
            "preissuance-review-receipt.json": receipt_data,
        }),
        "envelope_sha256": hashlib.sha256(envelope_data).hexdigest(),
        "review_receipt_sha256": hashlib.sha256(receipt_data).hexdigest(),
    }
    return verify_source_execution_chain(observed, independent_contract, source_contract)


def validate_preissuance_receipt_bytes(data, activation_sha, receipt_sha256, expected_candidate, expected_protected,
                                         authenticated_issuance=None, envelope_data=None):
    require(type(data) is bytes, "preissuance receipt bytes are required")
    require(HEX40.fullmatch(activation_sha) is not None, "activation SHA format mismatch")
    require(HEX64.fullmatch(receipt_sha256) is not None, "preissuance receipt hash format mismatch")
    require(hashlib.sha256(data).hexdigest() == receipt_sha256, "preissuance receipt hash mismatch")
    for pattern in RAW_PATTERNS:
        require(pattern.search(data) is None, "raw identity value in preissuance receipt")
    receipt = _closed_json(data, "preissuance receipt")
    require(data == canonical(receipt), "preissuance receipt must be canonical JSON")
    require(
        set(receipt) == set(EXPECTED_RECEIPT_FIELDS),
        "preissuance receipt top-level field set mismatch",
    )
    type_contract = {
        "schema_version": int, "receipt_type": str, "reviewer_profile": str,
        "review_outcome": str, "approved": bool, "findings_count": int, "findings": list,
        "release_authorized": bool, "activation_authorized": bool,
        "activation_findings": list, "candidate": dict,
        "protected_identity_asset": dict,
        "closure_matrix": dict, "classifications": dict, "source_execution_chain": dict,
    }
    for key, expected_type in type_contract.items():
        _exact_type(receipt[key], expected_type, key)
    require(receipt["schema_version"] == 2, "preissuance receipt schema mismatch")
    require(receipt["receipt_type"] == "acc-authority-v2-preissuance-independent-review", "preissuance receipt type mismatch")
    require(receipt["reviewer_profile"] == "acc-reviewer", "independent reviewer profile mismatch")
    _require_activation_only_decision(receipt, READY_ACTIVATION_STATE)
    _validate_manifest_shape(receipt["candidate"].get("changed_path_manifest"))
    _require_exact_json(receipt["candidate"], expected_candidate, "preissuance candidate")
    require(receipt["candidate"]["head_commit"] == activation_sha, "preissuance candidate SHA mismatch")
    _require_exact_json(receipt["protected_identity_asset"], expected_protected, "protected identity asset")
    require(receipt["classifications"] == {"hard_stop_class": None}, "preissuance classification mismatch")
    authenticate_receipt_source_chain(receipt, data, envelope_data)
    require(
        type(authenticated_issuance) is GITHUB_ISSUANCE.AuthenticatedIssuance
        and authenticated_issuance.review_receipt_sha256 == receipt_sha256,
        "preissuance receipt lacks the exact authenticated GitHub issuance binding",
    )
    require(
        authenticated_issuance.candidate_head == expected_candidate["head_commit"]
        and authenticated_issuance.candidate_tree == expected_candidate["head_tree"]
        and authenticated_issuance.canonical_diff_sha256 == expected_candidate["canonical_diff_sha256"],
        "authenticated GitHub issuance does not bind the exact reviewed candidate",
    )
    return receipt


def recompute_review_bindings(activation_sha, repository_root=ROOT):
    policy_bytes = (Path(repository_root) / "authority-v2-policy.json").read_bytes()
    require(hashlib.sha256(policy_bytes).hexdigest() == EXPECTED_POLICY_SHA256, "preissuance policy hash mismatch")
    policy = _closed_json(policy_bytes, "authority policy")
    protected_receipt = _closed_json((Path(repository_root) / "protected-asset-receipt-v2.json").read_bytes(), "protected asset receipt")
    base = policy["authority_repository_base"]["commit"]
    expected_candidate = recompute_candidate_bindings(repository_root, base, activation_sha)
    require(expected_candidate["base_tree"] == policy["authority_repository_base"]["tree"], "candidate base tree mismatch")
    require(expected_candidate["artifact_sha256"]["authority-v2-policy.json"] == EXPECTED_POLICY_SHA256, "candidate policy object hash mismatch")
    return {"candidate": expected_candidate, "protected_identity_asset": _expected_protected_binding(policy, protected_receipt)}


def authenticate_github_issuance(issuance_path, issuance_sha256, expected_candidate, review_receipt_sha256):
    path = Path(issuance_path)
    require(path.is_file() and not path.is_symlink(), "GitHub issuance object must be a regular non-symlink file")
    return GITHUB_ISSUANCE.verify_authenticated_issuance_bytes(
        path.read_bytes(), issuance_sha256, _issuance_candidate(expected_candidate, review_receipt_sha256),
    )


def _require_activation_only_decision(receipt, activation_state):
    """The mandatory decision: activation only, never final Authority approval.

    Closure F8 may be closed only at activation state `ready`; any earlier
    state must record it open beside F12, so no pre-activation receipt can
    claim an authenticated source chain that does not exist yet.
    """
    closed_closures, open_closures = expected_closures_for(activation_state)
    require(
        receipt["review_outcome"] == EXPECTED_REVIEW_OUTCOME,
        "preissuance review outcome is not the activation-only decision",
    )
    require(
        receipt["approved"] is EXPECTED_FINAL_APPROVED
        and receipt["release_authorized"] is EXPECTED_FINAL_RELEASE_AUTHORIZED,
        "preissuance receipt claims final Authority approval or release authorization",
    )
    closure = receipt["closure_matrix"]
    require(
        set(closure) == set(EXPECTED_CLOSURES),
        "preissuance closure matrix field set mismatch",
    )
    require(
        all(type(value) is bool for value in closure.values()),
        "preissuance closure matrix is not literal boolean",
    )
    for name in closed_closures:
        require(closure[name] is True, f"preissuance closure {name} is not closed")
    for name in open_closures:
        require(
            closure[name] is False,
            f"preissuance closure {name} may not be closed at activation state "
            f"{activation_state}",
        )
    findings = receipt["findings"]
    require(
        type(findings) is list and findings,
        "preissuance receipt must record its open closures as findings",
    )
    observed = []
    for entry in findings:
        require(
            type(entry) is dict and tuple(sorted(entry)) == EXPECTED_FINDING_KEYS,
            "preissuance finding is malformed",
        )
        require(
            type(entry["finding"]) is str and entry["finding"],
            "preissuance finding text is absent",
        )
        observed.append(entry["closure"])
    require(
        sorted(observed) == sorted(name for name, value in closure.items() if not value),
        "preissuance findings do not match the open closures exactly",
    )
    require(
        type(receipt["findings_count"]) is int
        and receipt["findings_count"] == len(findings),
        "preissuance findings count mismatch",
    )
    # The activation authorization is external and post-candidate: before the
    # activation state is `ready` no receipt may assert it, and the reason must
    # be recorded as an exact activation finding.
    if activation_state == READY_ACTIVATION_STATE:
        require(
            receipt["activation_authorized"] is True,
            "preissuance receipt does not authorize the exact activation",
        )
        require(
            receipt["activation_findings"] == [],
            "preissuance activation findings must be exactly zero",
        )
    else:
        require(
            receipt["activation_authorized"] is False,
            "a pre-activation receipt may never authorize the activation",
        )
        require(
            receipt["activation_findings"] == [EXPECTED_ACTIVATION_FINDING],
            "a pre-activation receipt must record the exact activation finding",
        )


def verify_preissuance_receipt(receipt_path, activation_sha, receipt_sha256, repository_root=ROOT,
                               authenticated_issuance=None, github_issuance_path=None,
                               github_issuance_sha256=None, envelope_path=None):
    receipt_path = Path(receipt_path)
    require(receipt_path.is_file() and not receipt_path.is_symlink(), "preissuance receipt must be a regular non-symlink file")
    data = receipt_path.read_bytes()
    require(envelope_path is not None,
            "preissuance receipt requires the exact protected Kanban envelope")
    envelope_path = Path(envelope_path)
    require(envelope_path.is_file() and not envelope_path.is_symlink(),
            "protected Kanban envelope must be a regular non-symlink file")
    envelope_data = envelope_path.read_bytes()
    bindings = recompute_review_bindings(activation_sha, repository_root)
    if authenticated_issuance is None:
        require(github_issuance_path is not None and github_issuance_sha256 is not None,
                "preissuance receipt requires exact authenticated GitHub issuance")
        authenticated_issuance = authenticate_github_issuance(
            github_issuance_path, github_issuance_sha256, bindings["candidate"], receipt_sha256,
        )
    return validate_preissuance_receipt_bytes(
        data, activation_sha, receipt_sha256, bindings["candidate"], bindings["protected_identity_asset"],
        authenticated_issuance=authenticated_issuance, envelope_data=envelope_data,
    )


def verify_candidate():
    policy_bytes = POLICY_PATH.read_bytes()
    require(hashlib.sha256(policy_bytes).hexdigest() == EXPECTED_POLICY_SHA256, "exact reviewed policy hash mismatch")
    policy = _closed_json(policy_bytes, "authority policy")
    require(policy["expected_sigstore_identity"] == EXPECTED_IDENTITY, "literal Sigstore identity mismatch")
    require(policy["expected_workflow_ref"] == EXPECTED_WORKFLOW_REF, "literal workflow ref mismatch")
    require(policy["expected_oidc_issuer"] == EXPECTED_ISSUER, "literal OIDC issuer mismatch")
    require(policy["protected_identity_asset"]["sha256"] == EXPECTED_PROTECTED_ASSET_SHA256, "protected asset hash mismatch")
    candidate_contract = policy["candidate_review_contract"]
    require(candidate_contract["canonical_diff_locale"] == "LC_ALL=C", "canonical diff locale mismatch")
    require(candidate_contract["canonical_diff_command"] == "git diff --binary --full-index --no-ext-diff --no-abbrev --find-renames=50% --src-prefix=a/ --dst-prefix=b/ <base> <head> --", "canonical diff command mismatch")
    require(candidate_contract["changed_path_statuses"] == ["A", "M", "D", "R"], "changed-path status contract mismatch")
    require(candidate_contract["external_receipt_covers_internal_manifest"] == "AUTHORITY-V2-SHA256SUMS", "external manifest self-coverage mismatch")
    require(policy["cosign_verification_contract"]["approved_standalone_sha256"] == APPROVED_COSIGN_DIGESTS, "approved Cosign digest table mismatch")
    require(policy["cosign_verification_contract"]["certificate_claims"] == {
        "identity": EXPECTED_IDENTITY,
        "issuer": EXPECTED_ISSUER,
        "github_workflow_repository": EXPECTED_REPOSITORY,
        "github_workflow_ref": EXPECTED_GIT_REF,
        "github_workflow_sha": "exact reviewed activation SHA",
        "github_workflow_trigger": EXPECTED_TRIGGER,
    }, "Cosign certificate claim contract mismatch")
    _require_exact_json(
        policy["publication_contract"], EXPECTED_PUBLICATION_CONTRACT,
        "publication state contract",
    )
    issuance_contract = policy["issuance_contract"]
    github_contract = issuance_contract["authenticated_github_issuance"]
    require(github_contract["contract"] == "authenticated-github-environment-oidc-issuance-v2", "GitHub issuance contract mismatch")
    require(github_contract["run_attempt"] == 1 and github_contract["environment"] == "attestation", "GitHub run/environment contract mismatch")
    require(github_contract["oidc_audience"] == "sigstore", "GitHub OIDC audience contract mismatch")
    _require_exact_json(
        github_contract["unsupported_deployment_relationship_evidence"],
        EXPECTED_UNSUPPORTED_DEPLOYMENT_EVIDENCE,
        "GitHub unsupported deployment evidence contract",
    )
    _require_exact_json(
        github_contract["run_scoped_environment_approval_binding"],
        EXPECTED_RUN_SCOPED_APPROVAL_BINDING,
        "GitHub run-scoped approval binding contract",
    )
    require(github_contract["prevent_self_review"] is True and github_contract["subject_binding_before_signing"] is True,
            "GitHub approval/subject binding contract mismatch")
    require(github_contract["publication_revalidates_in_one_integrated_path"] is True
            and github_contract["durable_github_nonce_and_issuance_claim"] is True
            and github_contract["replay_copy_cross_candidate_and_duplicate_publication_rejected"] is True,
            "GitHub one-time publication contract mismatch")
    require(github_contract["all_subjects_validated_before_first_sign_blob"] is True,
            "pre-sign subject validation contract mismatch")
    _require_exact_json(
        github_contract["independent_review_receipt_signature"],
        {
            "bundle_required": True,
            "identity": EXPECTED_REVIEWER_IDENTITY,
            "issuer": EXPECTED_REVIEWER_ISSUER,
            "verified_before_issuance": True,
            "verified_before_first_subject_signature": True,
            "verified_immediately_before_publication_transport": True,
        },
        "independent reviewer signature contract",
    )
    authorization_bytes = REVIEWER_AUTHORIZATION_PATH.read_bytes()
    require(hashlib.sha256(authorization_bytes).hexdigest() == EXPECTED_REVIEWER_AUTHORIZATION_SHA256,
            "reviewer authorization contract hash mismatch")
    _require_exact_json(_closed_json(authorization_bytes, "reviewer authorization contract"),
                        EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT, "reviewer authorization contract")
    bootstrap = verify_independent_review_bootstrap()
    sealed_bootstrap = EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT["bootstrap"]
    require(
        hashlib.sha256(
            (INDEPENDENT_REVIEW_BOOTSTRAP_PATH / "bootstrap-contract.json").read_bytes()
        ).hexdigest()
        == sealed_bootstrap["contract_sha256"]
        and bootstrap["terminal_readback"]["collector_workflow_sha256"]
        == sealed_bootstrap["collector_workflow_sha256"]
        and bootstrap["workflow"]["sha256"] == sealed_bootstrap["workflow_sha256"]
        and bootstrap["validator"]["sha256"] == sealed_bootstrap["validator_sha256"],
        "reviewer authorization bootstrap hash mismatch",
    )
    source_bootstrap = verify_protected_source_bootstrap()
    sealed_source = EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT["protected_source_bootstrap"]
    require(
        hashlib.sha256(
            (PROTECTED_SOURCE_BOOTSTRAP_PATH / "bootstrap-contract.json").read_bytes()
        ).hexdigest()
        == sealed_source["contract_sha256"]
        and source_bootstrap["workflow"]["sha256"] == sealed_source["workflow_sha256"]
        and source_bootstrap["helper"]["sha256"] == sealed_source["helper_sha256"]
        and source_bootstrap["repository"] == sealed_source["repository"],
        "protected-source bootstrap hash mismatch",
    )
    require(
        bootstrap["protected_source"]["bootstrap_contract_sha256"]
        == sealed_source["contract_sha256"],
        "independent review bootstrap does not seal the protected-source contract",
    )
    chain_contract = EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT["source_execution_chain"]
    require(
        chain_contract["caller_selectable_source_run"] is False
        and chain_contract["authorized_run_selector"] == "immutable-contract-pinned"
        and chain_contract[
            "certificate_github_workflow_sha_equals_independent_bootstrap_commit"
        ] is True
        and chain_contract[
            "every_executed_workflow_validator_and_helper_byte_verified_at_the_pinned_run_head"
        ] is True
        and chain_contract["no_fallback"] is True
        and tuple(chain_contract["bound_fields"]) == tuple(sorted(SOURCE_CHAIN_FIELDS)),
        "source execution chain authorization contract mismatch",
    )
    sealed_run = authorized_source_run(bootstrap)
    require(
        sealed_run["activation_state"] == chain_contract["activation_state"],
        "source execution chain activation state mismatch",
    )
    require(
        sealed_run["source_workflow_sha256"] == sealed_source["workflow_sha256"]
        and sealed_run["source_helper_sha256"] == sealed_source["helper_sha256"]
        and sealed_run["independent_workflow_sha256"] == sealed_bootstrap["workflow_sha256"]
        and sealed_run["independent_validator_sha256"] == sealed_bootstrap["validator_sha256"],
        "authorized protected-source run does not seal the reviewed bootstrap bytes",
    )
    require(issuance_contract["release_actions_role"] == "acc-releaser", "release role mismatch")
    require(issuance_contract["release_tag"] == "clerk-instance-attestation-v2", "immutable release tag mismatch")
    require(issuance_contract["release_tag_immutable"] is True, "release tag must be immutable")
    require(issuance_contract["release_collision_behavior"] == "fail_closed", "release collision must fail closed")
    require(tuple(policy["temporal_subject_contract"]["required_case_order"]) == EXPECTED_CASES, "case order mismatch")
    require(set(policy["temporal_subject_contract"]["cases"]) == set(EXPECTED_CASES), "exactly three cases required")
    require("derived only" in policy["temporal_subject_contract"]["trusted_time_source"], "trusted-time derivation contract missing")
    require("trusted_evaluation_time_utc" not in policy_bytes.decode(), "static trusted evaluation time is forbidden")

    protected_receipt = _closed_json(RECEIPT_PATH.read_bytes(), "protected asset receipt")
    asset = protected_receipt["protected_asset"]
    require(asset["sha256"] == EXPECTED_PROTECTED_ASSET_SHA256, "protected asset receipt hash mismatch")
    for key in ("present", "directory_mode_0700", "file_mode_0600", "atomic_creation", "raw_publishable_key_present", "raw_api_instance_id_present", "environment_type_development", "publishable_fingerprint_match", "api_instance_id_fingerprint_match"):
        require(asset[key] is True, f"protected invariant false: {key}")
    for key in ("raw_values_emitted", "raw_values_publicly_persisted", "raw_values_attached_to_public_tracking"):
        require(asset[key] is False, f"privacy invariant true: {key}")
    require(protected_receipt["candidate_handoff"]["approved"] is False, "candidate cannot self-approve")

    environment_contract = _closed_json(ENV_CONTRACT_PATH.read_bytes(), "environment contract")
    require(environment_contract["repository"] == EXPECTED_REPOSITORY, "environment repository mismatch")
    require(environment_contract["can_admins_bypass"] is False, "admin bypass forbidden")
    require(environment_contract["fallback_path"] is False, "environment fallback forbidden")
    require(environment_contract["deployment_branch_policy"] == {
        "protected_branches": True,
        "custom_branch_policies": False,
    }, "environment protected-branch mode mismatch")
    _require_exact_json(
        environment_contract["deployment_branch_policy_readback"],
        {
            "protected_branches_mode_status": 404,
            "protected_branches_mode_is_main_only": False,
            "custom_main_mode_status": 200,
            "custom_main_mode_exact_ref": EXPECTED_GIT_REF,
        },
        "environment branch-policy readback contract",
    )
    _require_exact_json(
        environment_contract["sealed_environment_readback"],
        EXPECTED_SEALED_ENVIRONMENT_READBACK,
        "environment sealed readback contract",
    )
    environment_issuance = environment_contract["authenticated_issuance"]
    require(environment_issuance["oidc_audience"] == "sigstore", "environment OIDC audience mismatch")
    _require_exact_json(
        environment_issuance["unsupported_deployment_relationship_evidence"],
        EXPECTED_UNSUPPORTED_DEPLOYMENT_EVIDENCE,
        "environment unsupported deployment evidence contract",
    )
    _require_exact_json(
        environment_issuance["run_scoped_environment_approval_binding"],
        EXPECTED_RUN_SCOPED_APPROVAL_BINDING,
        "environment run-scoped approval binding contract",
    )

    schema = _closed_json(SCHEMA_PATH.read_bytes(), "subject schema")
    require(schema["properties"]["authority_policy_sha256"]["const"] == EXPECTED_POLICY_SHA256, "schema policy hash is not exact")
    require(len(schema["oneOf"]) == 3, "schema must bind three exact tuples")

    workflow = (ROOT / ".github" / "workflows" / "sign-clerk-attestation-v2.yml").read_text(encoding="utf-8")
    require(workflow.startswith(EXPECTED_WORKFLOW_HEADER), "exact workflow dispatch header mismatch")
    require(re.search(r"(?m)^on:\s*$\n\s+workflow_dispatch:\s*$", workflow) is not None, "workflow_dispatch trigger missing")
    require(re.search(r"(?m)^\s+(schedule|push|pull_request|workflow_call):", workflow) is None, "alternate workflow trigger forbidden")
    require("environment: attestation" in workflow and "runs-on: ubuntu-latest" in workflow, "issuance environment/runner mismatch")
    require("scripts/collect_github_issuance_v2.py" in workflow, "GitHub issuance collector missing")
    require(
        'gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/approvals"'
        in workflow,
        "exact run-scoped approval endpoint missing",
    )
    require(
        "deployment_status" not in workflow
        and "log_url" not in workflow
        and "deployments?environment=attestation" not in workflow,
        "unsupported deployment relationship evidence is present",
    )
    require(
        "|{environments:[.environments[]|{name}],state,user:(.user|{login})}"
        in workflow,
        "documented approval response projection missing",
    )
    require("scripts/verify_publication_v2.py" in workflow, "executable publication verifier missing")
    require(
        "permission-administration: read" in workflow
        and "GH_GUARD_APP_TOKEN: ${{ steps.guard-token.outputs.token }}" in workflow
        and "GH_TOKEN: ${{ github.token }}" in workflow,
        "separate GitHub App guard and GITHUB_TOKEN mutation transports missing",
    )
    require(
        "review_receipt_base64:" not in workflow
        and "review_receipt_bundle_base64:" not in workflow
        and "independent_review_run_id:" in workflow
        and "actions/download-artifact@" in workflow,
        "Authority accepts caller review bytes or omits independent artifact acquisition",
    )
    consumer_downloads = _parse_download_artifact_steps(workflow)
    require(
        len(consumer_downloads) == len(EXPECTED_CONSUMER_DOWNLOADS),
        "signing workflow must have exactly "
        f"{len(EXPECTED_CONSUMER_DOWNLOADS)} total download-artifact steps, "
        f"found {len(consumer_downloads)}",
    )
    require(
        consumer_downloads == [
            {"uses": EXPECTED_DOWNLOAD_ARTIFACT_USES, "with": expected}
            for expected in EXPECTED_CONSUMER_DOWNLOADS
        ],
        "signing workflow download-artifact action or complete with-map mismatch",
    )
    # The live reviewer bootstrap binding must be derived, never read from a
    # sealed pre-live constant: `jq -e` on a deliberately null field can only
    # fail closed, which would make Authority verification unreachable.
    sealed_contract = _closed_json(
        (INDEPENDENT_REVIEW_BOOTSTRAP_PATH / "bootstrap-contract.json").read_bytes(),
        "independent-review bootstrap contract",
    )
    for field in sealed_contract["live_identifiers_never_pre_pinned"]:
        require(
            sealed_contract["authorized_source_run"][field] is None,
            f"the sealed reviewer bootstrap contract pre-pins {field}",
        )
        for line in workflow.splitlines():
            require(
                not ("jq -e" in line
                     and EXPECTED_REVIEWER_BOOTSTRAP_CONTRACT_PATH in line
                     and f".{field}" in line),
                f"the signing workflow reads the unavailable sealed {field}, "
                "so no real run could reach Authority verification",
            )
    require(
        "--derive-independent-bootstrap-binding" in workflow
        and '--review-head "$REVIEW_HEAD"' in workflow
        and '--independent-review-run-id "$INDEPENDENT_REVIEW_RUN_ID"' in workflow,
        "the signing workflow does not derive the live reviewer bootstrap binding",
    )
    for field in ("independent_bootstrap_commit", "independent_bootstrap_tree"):
        require(
            f'jq -er .{field} "$AUTHORITY_V2_RUNTIME/{EXPECTED_BOOTSTRAP_BINDING_FILE}"'
            in workflow,
            f"the signing workflow does not consume the derived {field}",
        )
    bound_signed_review_inventory_step(workflow)
    require("--key" not in workflow and "COSIGN_PRIVATE_KEY" not in workflow and "--clobber" not in workflow, "forbidden signing/publication fallback")

    guard_contract = _closed_json(
        (ROOT / "github-app-guard-v2-contract.json").read_bytes(),
        "GitHub App guard contract",
    )
    require(
        guard_contract["transport_role"] == "administration-read-guards-only"
        and guard_contract["repository_selection"] == [EXPECTED_REPOSITORY]
        and guard_contract["token_permissions"] == {"administration": "read"}
        and guard_contract["activation_precondition"]["state"] == "unavailable"
        and guard_contract["activation_precondition"]["no_fallback"] is True,
        "GitHub App guard fail-closed contract mismatch",
    )
    writer_contract = _closed_json(
        (ROOT / "publication-writer-exclusion-v2.json").read_bytes(),
        "publication writer exclusion contract",
    )
    require(
        writer_contract["github_release_cas_supported"] is False
        and writer_contract["documented_atomic_draft_asset_tag_transition_available"] is False
        and writer_contract["documented_exhaustive_writer_inventory_available"] is False
        and writer_contract["activation_precondition"]["state"] == "unavailable"
        and writer_contract["activation_precondition"]["no_fallback"] is True
        and writer_contract["irreversible_publication_forbidden"] is True,
        "publication writer exclusion fail-closed contract mismatch",
    )

    verify_candidate_self_authorization(ROOT)
    verify_manifest(MANIFEST_PATH)
    scanned = 0
    for name in (*EXPECTED_MANIFEST_PATHS, "AUTHORITY-V2-SHA256SUMS"):
        data = (ROOT / name).read_bytes()
        for pattern in RAW_PATTERNS:
            require(pattern.search(data) is None, f"raw identity pattern in public tree: {name}")
        scanned += 1
    return policy, scanned


def extract_rekor_time_bytes(bundle_bytes):
    """The verified Rekor trusted time, read through the one shared v0.3 parser.

    The Authority boundary and the live activation pinning boundary share
    ``scripts/sigstore_bundle_v03``, so a bundle either satisfies the single
    canonical Cosign v3.1.3 protobuf-JSON v0.3 contract at both boundaries or
    at neither. This boundary keeps its own strictly narrower requirements on
    top of the shared contract: only the exact canonical media type, only the
    canonical protobuf-JSON int64 *string* encodings, and a complete inclusion
    proof with a signed checkpoint.
    """
    parsed = SIGSTORE.parse_bundle(
        bundle_bytes, media_types=(SIGSTORE.CANONICAL_MEDIA_TYPE,),
    )
    require(
        parsed.canonical_integrated_time
        and type(parsed.tlog_entry.get("logIndex")) is str,
        "verified Rekor integratedTime must be canonical protobuf-JSON int64",
    )
    proof = parsed.inclusion_proof
    require(proof.get("rootHash") and proof.get("checkpoint", {}).get("envelope"), "Rekor inclusion proof/checkpoint absent")
    try:
        return datetime.fromtimestamp(parsed.integrated_time, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise SystemExit("verified Rekor integratedTime is outside supported UTC range") from error


def extract_rekor_time(bundle_path):
    return extract_rekor_time_bytes(Path(bundle_path).read_bytes())


def evaluate(case_contract, trusted_time):
    start = utc(case_contract["not_before_utc"])
    end = utc(case_contract["not_after_utc"])
    if trusted_time < start:
        return "reject_future"
    if trusted_time > end:
        return "reject_stale"
    return "accept_freshness_only"


def current_cosign_platform():
    operating_system = platform.system().lower()
    machine = platform.machine().lower()
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    value = f"{operating_system}/{architecture}" if architecture else "unsupported"
    require(value in APPROVED_COSIGN_DIGESTS, "Cosign platform is not approved")
    return value


@dataclass(frozen=True)
class BoundFile:
    path: Path
    descriptor: int
    identity: tuple
    data: bytes


def _stat_identity(observed):
    return (
        observed.st_dev, observed.st_ino, observed.st_mode, observed.st_size,
        observed.st_mtime_ns, observed.st_ctime_ns,
    )


def _bind_file(path):
    path = Path(path)
    try:
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode), f"artifact is not a regular non-symlink file: {path.name}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        require(_stat_identity(before) == _stat_identity(opened), f"artifact changed while binding: {path.name}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        require(_stat_identity(opened) == _stat_identity(after), f"artifact changed while reading: {path.name}")
        return BoundFile(path=path, descriptor=descriptor, identity=_stat_identity(after), data=b"".join(chunks))
    except OSError as error:
        raise SystemExit(f"artifact binding failed: {path.name}") from error


def _verify_bound_source(bound):
    try:
        require(_stat_identity(os.fstat(bound.descriptor)) == bound.identity, f"bound artifact descriptor changed: {bound.path.name}")
        require(_stat_identity(bound.path.lstat()) == bound.identity, f"bound artifact path changed: {bound.path.name}")
    except OSError as error:
        raise SystemExit(f"bound artifact disappeared: {bound.path.name}") from error


def _write_snapshot(directory, name, data, mode=0o400):
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o400)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "snapshot write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)
    return path


@dataclass(frozen=True, eq=False)
class VerifiedCosign:
    original_path: Path
    path: Path
    identity: tuple
    digest: str
    temporary_directory: object

    def __str__(self):
        return str(self.path)

    def __eq__(self, other):
        return self.original_path == other

    def close(self):
        _unseal_darwin_execution_object(self.path)
        self.temporary_directory.cleanup()

    def __del__(self):
        self.close()


def _read_descriptor(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _open_verified_cosign(cosign):
    require(type(cosign) is VerifiedCosign, "unverified Cosign execution object")
    try:
        before = cosign.path.lstat()
        require(not stat.S_ISLNK(before.st_mode), "Cosign execution snapshot became a symlink")
        descriptor = os.open(cosign.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        require(_stat_identity(before) == cosign.identity == _stat_identity(opened), "Cosign execution snapshot identity changed")
        require(stat.S_ISREG(opened.st_mode) and opened.st_mode & 0o111 != 0, "Cosign execution snapshot is not executable")
        require(hashlib.sha256(_read_descriptor(descriptor)).hexdigest() == cosign.digest, "Cosign execution snapshot digest changed")
        require(_stat_identity(os.fstat(descriptor)) == cosign.identity, "Cosign execution snapshot changed while opening")
        return descriptor
    except OSError as error:
        raise SystemExit("Cosign execution snapshot binding failed") from error


def _darwin_immutable_flag():
    require(sys.platform == "darwin", "Darwin Cosign sealing requested on another platform")
    immutable = getattr(stat, "UF_IMMUTABLE", None)
    require(type(immutable) is int and immutable > 0, "Darwin immutable file flag is unavailable")
    require(hasattr(os, "chflags"), "Darwin immutable file sealing is unavailable")
    return immutable


def _seal_darwin_execution_object(path):
    if sys.platform != "darwin":
        return
    immutable = _darwin_immutable_flag()
    path = Path(path)
    directory = path.parent
    try:
        observed = path.lstat()
        require(stat.S_ISREG(observed.st_mode) and not stat.S_ISLNK(observed.st_mode), "Darwin Cosign execution object is malformed")
        require(stat.S_ISDIR(directory.lstat().st_mode), "Darwin Cosign execution directory is malformed")
        os.chflags(path, observed.st_flags | immutable, follow_symlinks=False)
        directory_state = directory.lstat()
        os.chflags(
            directory,
            directory_state.st_flags | immutable,
            follow_symlinks=False,
        )
        require(path.lstat().st_flags & immutable == immutable, "Darwin Cosign execution object is not immutable")
        require(directory.lstat().st_flags & immutable == immutable, "Darwin Cosign execution directory is not immutable")
    except OSError as error:
        raise SystemExit("Darwin Cosign execution object sealing failed") from error


def _unseal_darwin_execution_object(path):
    if sys.platform != "darwin":
        return
    immutable = _darwin_immutable_flag()
    path = Path(path)
    directory = path.parent
    try:
        for target in (directory, path):
            try:
                observed = target.lstat()
            except FileNotFoundError:
                continue
            os.chflags(
                target,
                observed.st_flags & ~immutable,
                follow_symlinks=False,
            )
    except OSError as error:
        raise SystemExit("Darwin Cosign execution object cleanup failed") from error


def _descriptor_execution_path(descriptor, identity):
    require(sys.platform.startswith("linux"), "unsupported Cosign descriptor execution platform")
    path = f"/proc/self/fd/{descriptor}"
    try:
        require(_stat_identity(os.stat(path)) == identity, "Cosign descriptor execution identity mismatch")
    except OSError as error:
        raise SystemExit("Cosign descriptor execution mechanism is unavailable") from error
    return path


def _run_verified_cosign(cosign, arguments, **options):
    require("pass_fds" not in options and "close_fds" not in options, "Cosign descriptor inheritance is verifier-owned")
    descriptor = _open_verified_cosign(cosign)
    try:
        if sys.platform == "darwin":
            execution_path = str(cosign.path)
            immutable = _darwin_immutable_flag()
            require(cosign.path.lstat().st_flags & immutable == immutable, "Darwin Cosign execution object lost immutability")
            require(cosign.path.parent.lstat().st_flags & immutable == immutable, "Darwin Cosign execution directory lost immutability")
        else:
            execution_path = _descriptor_execution_path(descriptor, cosign.identity)
        completed = subprocess.run(
            [execution_path, *arguments], check=True,
            stdin=subprocess.DEVNULL, pass_fds=(descriptor,), **options,
        )
        require(
            hashlib.sha256(_read_descriptor(descriptor)).hexdigest() == cosign.digest,
            "Cosign execution object changed during invocation",
        )
        require(
            _stat_identity(os.fstat(descriptor)) == cosign.identity,
            "Cosign execution object identity changed during invocation",
        )
        require(
            _stat_identity(cosign.path.lstat()) == cosign.identity,
            "Cosign execution path changed during invocation",
        )
        return completed
    finally:
        os.close(descriptor)


def validate_cosign_binary(cosign_path):
    if type(cosign_path) is VerifiedCosign:
        descriptor = _open_verified_cosign(cosign_path)
        os.close(descriptor)
        return cosign_path
    original = Path(cosign_path)
    require(original.is_absolute(), "cosign path must be absolute")
    bound = _bind_file(original)
    temporary_directory = None
    snapshot = None
    try:
        require(bound.identity[2] & 0o111 != 0, "cosign path must be executable")
        selected_platform = current_cosign_platform()
        digest = hashlib.sha256(bound.data).hexdigest()
        require(digest == APPROVED_COSIGN_DIGESTS[selected_platform], "cosign standalone artifact digest mismatch")
        temporary_directory = tempfile.TemporaryDirectory(prefix="authority-v2-cosign-")
        snapshot_dir = Path(temporary_directory.name)
        os.chmod(snapshot_dir, 0o700)
        snapshot = _write_snapshot(snapshot_dir, "cosign", bound.data, mode=0o500)
        _seal_darwin_execution_object(snapshot)
        identity = _stat_identity(snapshot.lstat())
        verified = VerifiedCosign(original, snapshot, identity, digest, temporary_directory)
        try:
            completed = _run_verified_cosign(verified, ["version", "--json"], capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as error:
            raise SystemExit("cosign structured version execution failed") from error
        version = _closed_json(completed.stdout.encode("utf-8"), "cosign version")
        require(version == dict(EXPECTED_COSIGN_BUILD, platform=selected_platform), "cosign structured build identity mismatch")
        return verified
    except BaseException:
        if snapshot is not None:
            _unseal_darwin_execution_object(snapshot)
        if temporary_directory is not None:
            temporary_directory.cleanup()
        raise
    finally:
        os.close(bound.descriptor)


def _cosign_command(subject_snapshot, bundle_snapshot, activation_sha):
    return [
        "verify-blob", "--bundle", str(bundle_snapshot),
        "--certificate-identity", EXPECTED_IDENTITY,
        "--certificate-oidc-issuer", EXPECTED_ISSUER,
        "--certificate-github-workflow-repository", EXPECTED_REPOSITORY,
        "--certificate-github-workflow-ref", EXPECTED_GIT_REF,
        "--certificate-github-workflow-sha", activation_sha,
        "--certificate-github-workflow-trigger", EXPECTED_TRIGGER,
        str(subject_snapshot),
    ]


def _review_receipt_cosign_command(receipt_snapshot, bundle_snapshot, bootstrap_commit):
    signature = EXPECTED_REVIEWER_AUTHORIZATION_CONTRACT["review_receipt_signature"]
    require(
        type(bootstrap_commit) is str and HEX40.fullmatch(bootstrap_commit) is not None,
        "pinned independent bootstrap commit is unavailable",
    )
    return [
        "verify-blob", "--bundle", str(bundle_snapshot),
        "--certificate-identity", EXPECTED_REVIEWER_IDENTITY,
        "--certificate-oidc-issuer", EXPECTED_REVIEWER_ISSUER,
        "--certificate-github-workflow-repository", EXPECTED_REVIEWER_REPOSITORY,
        "--certificate-github-workflow-ref", signature["workflow_ref"],
        "--certificate-github-workflow-sha", bootstrap_commit,
        "--certificate-github-workflow-trigger", signature["workflow_trigger"],
        str(receipt_snapshot),
    ]


def pinned_independent_bootstrap_commit():
    """Only the sealed contract may name the commit the certificate must carry."""
    run = authorized_source_run(verify_independent_review_bootstrap())
    require(
        run.get("activation_state") == "ready"
        and type(run.get("independent_bootstrap_commit")) is str
        and HEX40.fullmatch(run["independent_bootstrap_commit"]) is not None
        and run.get("certificate_github_workflow_sha")
        == run["independent_bootstrap_commit"],
        "pinned independent bootstrap commit is unavailable",
    )
    return run["independent_bootstrap_commit"]


def _authenticate_review_receipt_with_cosign(receipt, bundle, cosign):
    with tempfile.TemporaryDirectory(prefix="authority-v2-review-auth-") as temp_dir:
        snapshot_dir = Path(temp_dir)
        os.chmod(snapshot_dir, 0o700)
        receipt_snapshot = _write_snapshot(snapshot_dir, "receipt.json", receipt.data)
        bundle_snapshot = _write_snapshot(snapshot_dir, "receipt.sigstore.json", bundle.data)
        try:
            _run_verified_cosign(
                cosign,
                _review_receipt_cosign_command(
                    receipt_snapshot, bundle_snapshot,
                    pinned_independent_bootstrap_commit(),
                ),
                env=_cosign_environment(), capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise SystemExit("independent review receipt signature was rejected") from error
        _verify_bound_source(receipt)
        _verify_bound_source(bundle)
        require(receipt_snapshot.read_bytes() == receipt.data,
                "review receipt snapshot changed during authentication")
        require(bundle_snapshot.read_bytes() == bundle.data,
                "review receipt bundle snapshot changed during authentication")


def authenticate_preissuance_review_bundle(receipt_path, bundle_path, cosign_path):
    receipt = _bind_file(receipt_path)
    bundle = _bind_file(bundle_path)
    cosign = validate_cosign_binary(cosign_path)
    try:
        _authenticate_review_receipt_with_cosign(receipt, bundle, cosign)
        return hashlib.sha256(receipt.data).hexdigest()
    finally:
        os.close(receipt.descriptor)
        os.close(bundle.descriptor)
        cosign.close()


def _cosign_environment():
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith("COSIGN_") and not key.startswith("SIGSTORE_")
    }


def _execute_cosign(cosign, subject, bundle, activation_sha):
    try:
        _run_verified_cosign(
            cosign, _cosign_command(subject, bundle, activation_sha),
            env=_cosign_environment(), capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit("cosign rejected signature or exact GitHub workflow claims") from error


def sign_subjects(subject_dir, cosign_path, activation_sha, review_receipt_path,
                  review_receipt_sha256, review_receipt_bundle_path,
                  github_issuance_path, github_issuance_sha256,
                  review_envelope_path=None):
    subject_dir = Path(subject_dir)
    try:
        directory_stat = subject_dir.lstat()
    except OSError as error:
        raise SystemExit("subject directory is absent") from error
    require(stat.S_ISDIR(directory_stat.st_mode) and not stat.S_ISLNK(directory_stat.st_mode), "subject directory must be a non-symlink directory")
    require(HEX40.fullmatch(activation_sha) is not None, "activation SHA format mismatch")
    require(HEX64.fullmatch(review_receipt_sha256) is not None,
            "preissuance review receipt hash format mismatch")
    expected_subject_names = [f"authority-v2-{case}.json" for case in EXPECTED_CASES]
    require(sorted(path.name for path in subject_dir.iterdir()) == sorted(expected_subject_names),
            "subject directory must contain exactly three unsigned subjects")
    bundle_paths = [subject_dir / f"authority-v2-{case}.sigstore.json" for case in EXPECTED_CASES]
    require(not any(path.exists() or path.is_symlink() for path in bundle_paths), "signature bundle overwrite is forbidden")
    policy, _ = verify_candidate()
    bindings = recompute_review_bindings(activation_sha)
    authenticated_issuance = authenticate_github_issuance(
        github_issuance_path, github_issuance_sha256,
        bindings["candidate"], review_receipt_sha256,
    )
    require(review_envelope_path is not None,
            "subject signing requires the exact protected Kanban envelope")
    envelope = _bind_file(review_envelope_path)
    receipt = _bind_file(review_receipt_path)
    review_bundle = _bind_file(review_receipt_bundle_path)
    cosign = validate_cosign_binary(cosign_path)
    generated = []
    subjects = []
    try:
        _authenticate_review_receipt_with_cosign(receipt, review_bundle, cosign)
        validate_preissuance_receipt_bytes(
            receipt.data, activation_sha, review_receipt_sha256,
            bindings["candidate"], bindings["protected_identity_asset"],
            authenticated_issuance=authenticated_issuance,
            envelope_data=envelope.data,
        )
        for case in EXPECTED_CASES:
            subject = _bind_file(subject_dir / f"authority-v2-{case}.json")
            payload = _closed_json(subject.data, f"unsigned subject {case}")
            require(subject.data == canonical(payload), f"unsigned subject is non-canonical: {case}")
            _require_exact_json(
                payload,
                expected_subject(policy, case, activation_sha, review_receipt_sha256,
                                 authenticated_issuance),
                f"unsigned subject {case}",
            )
            subjects.append(subject)
        for subject, bundle_path in zip(subjects, bundle_paths):
            with tempfile.TemporaryDirectory(prefix="authority-v2-sign-") as temp_dir:
                snapshot_dir = Path(temp_dir)
                os.chmod(snapshot_dir, 0o700)
                subject_snapshot = _write_snapshot(snapshot_dir, "subject.json", subject.data)
                bundle_snapshot = snapshot_dir / "bundle.sigstore.json"
                _run_verified_cosign(
                    cosign, ["sign-blob", "--yes", "--bundle", str(bundle_snapshot), str(subject_snapshot)],
                    env=_cosign_environment(), capture_output=True,
                )
                bundle = _bind_file(bundle_snapshot)
                try:
                    _verify_bound_source(subject)
                    _verify_bound_source(bundle)
                    generated.append(_write_snapshot(subject_dir, bundle_path.name, bundle.data, mode=0o600))
                finally:
                    os.close(bundle.descriptor)
        return generated
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit("keyless Cosign signing failed closed") from error
    finally:
        for subject in subjects:
            os.close(subject.descriptor)
        os.close(receipt.descriptor)
        os.close(review_bundle.descriptor)
        cosign.close()


def _verify_bound_cosign_pair(subject, bundle, cosign, activation_sha):
    with tempfile.TemporaryDirectory(prefix="authority-v2-bound-") as temp_dir:
        snapshot_dir = Path(temp_dir)
        os.chmod(snapshot_dir, 0o700)
        subject_snapshot = _write_snapshot(snapshot_dir, "subject.json", subject.data)
        bundle_snapshot = _write_snapshot(snapshot_dir, "bundle.sigstore.json", bundle.data)
        _execute_cosign(cosign, subject_snapshot, bundle_snapshot, activation_sha)
        require(subject_snapshot.read_bytes() == subject.data, "subject snapshot changed during Cosign execution")
        require(bundle_snapshot.read_bytes() == bundle.data, "bundle snapshot changed during Cosign execution")
        _verify_bound_source(subject)
        _verify_bound_source(bundle)
        return extract_rekor_time_bytes(bundle.data)


def verify_cosign_pair(subject_path, bundle_path, cosign_path, activation_sha):
    require(HEX40.fullmatch(activation_sha) is not None, "activation SHA format mismatch")
    cosign = validate_cosign_binary(cosign_path)
    subject = _bind_file(subject_path)
    bundle = _bind_file(bundle_path)
    try:
        return _verify_bound_cosign_pair(subject, bundle, cosign, activation_sha)
    finally:
        os.close(subject.descriptor)
        os.close(bundle.descriptor)


# The one release evidence inventory every downstream verifier shares: the
# three signed subjects with their bundles, plus the sealed runner state that
# records the terminal state this exact run really reached. The release
# checksum manifest, the final evidence manifest and publication verification
# all bind exactly this set.
RUNNER_STATE_ASSET_NAME = "authority-v2-runner-state.json"
FINAL_EVIDENCE_ASSET_NAME = "AUTHORITY-V2-FINAL-EVIDENCE.json"
RELEASE_MANIFEST_NAME = "AUTHORITY-V2-RELEASE-SHA256SUMS"


def release_evidence_inventory():
    names = [RUNNER_STATE_ASSET_NAME]
    for case in EXPECTED_CASES:
        names.extend([
            f"authority-v2-{case}.json", f"authority-v2-{case}.sigstore.json",
        ])
    return sorted(names)


def verify_release_inventory(release_dir):
    release_dir = Path(release_dir).resolve()
    expected_names = release_evidence_inventory()
    actual = sorted(
        path.name for path in release_dir.iterdir()
        if path.name not in (RELEASE_MANIFEST_NAME, FINAL_EVIDENCE_ASSET_NAME)
    )
    require(
        actual == expected_names,
        "missing or extra release evidence artifacts",
    )
    return expected_names


def verify_release(release_dir, activation_sha, review_receipt_path, review_receipt_sha256,
                   cosign_path, authenticated_issuance, review_envelope_path=None):
    policy, _ = verify_candidate()
    require(HEX40.fullmatch(activation_sha) is not None, "activation SHA format mismatch")
    require(HEX64.fullmatch(review_receipt_sha256) is not None, "preissuance review receipt hash format mismatch")
    verify_preissuance_receipt(
        review_receipt_path, activation_sha, review_receipt_sha256,
        authenticated_issuance=authenticated_issuance,
        envelope_path=review_envelope_path,
    )
    release_dir = Path(release_dir).resolve()
    expected_names = verify_release_inventory(release_dir)
    cosign = cosign_path if type(cosign_path) is VerifiedCosign else validate_cosign_binary(cosign_path)
    manifest_path = release_dir / "AUTHORITY-V2-RELEASE-SHA256SUMS"
    try:
        manifest_stat = manifest_path.lstat()
    except OSError as error:
        raise SystemExit("release manifest is absent") from error
    require(stat.S_ISREG(manifest_stat.st_mode) and not stat.S_ISLNK(manifest_stat.st_mode), "release manifest must be a regular non-symlink file")
    manifest_bytes = manifest_path.read_bytes()
    expected_manifest = _manifest_bytes(expected_names, lambda name: (release_dir / name).read_bytes())
    require(manifest_bytes == expected_manifest, "release manifest raw bytes mismatch")
    expected_hashes = {name: hashlib.sha256((release_dir / name).read_bytes()).hexdigest() for name in expected_names}
    results = {}
    for case in EXPECTED_CASES:
        subject_path = release_dir / f"authority-v2-{case}.json"
        bundle_path = release_dir / f"authority-v2-{case}.sigstore.json"
        subject = _bind_file(subject_path)
        bundle = _bind_file(bundle_path)
        try:
            require(hashlib.sha256(subject.data).hexdigest() == expected_hashes[subject_path.name], f"subject hash mismatch: {case}")
            require(hashlib.sha256(bundle.data).hexdigest() == expected_hashes[bundle_path.name], f"bundle hash mismatch: {case}")
            payload = _closed_json(subject.data, f"subject {case}")
            require(subject.data == canonical(payload), f"non-canonical subject: {case}")
            _require_exact_json(
                payload,
                expected_subject(policy, case, activation_sha, review_receipt_sha256,
                                 authenticated_issuance),
                f"subject exact-byte contract {case}",
            )
            trusted_time = _verify_bound_cosign_pair(subject, bundle, cosign, activation_sha)
            observed = evaluate(payload["case_contract"], trusted_time)
            require(observed == payload["case_contract"]["expected_freshness_result"], f"trusted-time result mismatch: {case}")
            results[case] = {"trusted_time_source": "verified_rekor_integratedTime", "freshness_result": observed}
        finally:
            os.close(subject.descriptor)
            os.close(bundle.descriptor)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", type=Path)
    parser.add_argument("--reviewed-activation-sha")
    parser.add_argument("--preissuance-review-receipt", type=Path)
    parser.add_argument("--preissuance-review-receipt-sha256")
    parser.add_argument("--preissuance-review-envelope", type=Path)
    parser.add_argument("--github-issuance", type=Path)
    parser.add_argument("--github-issuance-sha256")
    parser.add_argument("--cosign")
    parser.add_argument("--sign-subject-dir", type=Path)
    parser.add_argument("--verify-cosign-binary")
    parser.add_argument("--authenticate-preissuance-review-bundle", action="store_true")
    parser.add_argument("--verify-signed-review-artifact-inventory", type=Path)
    parser.add_argument("--review-artifact-member-digests", type=Path)
    parser.add_argument("--review-artifact-name")
    parser.add_argument("--preissuance-review-receipt-bundle", type=Path)
    parser.add_argument("--emit-review-bindings", action="store_true")
    parser.add_argument("--derive-independent-bootstrap-binding", action="store_true")
    parser.add_argument("--independent-review-run-id")
    parser.add_argument("--review-head")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.review_artifact_member_digests:
        require(
            args.review_artifact_name in ISSUANCE_REVIEW_ARTIFACT_MEMBERS,
            "issuance review artifact name is not canonical",
        )
        archive_path = args.review_artifact_member_digests
        require(
            archive_path.is_file() and not archive_path.is_symlink(),
            "issuance review artifact archive is absent or unsafe",
        )
        print(json.dumps(review_artifact_member_digests(
            archive_path.read_bytes(),
            ISSUANCE_REVIEW_ARTIFACT_MEMBERS[args.review_artifact_name],
            f"issuance review artifact {args.review_artifact_name}",
        ), sort_keys=True))
    elif args.derive_independent_bootstrap_binding:
        require(
            args.review_head and args.independent_review_run_id and args.output,
            "the independent bootstrap binding requires the authenticated "
            "review head, the dispatched run id and an output path",
        )
        binding = derive_independent_bootstrap_binding(
            args.review_head, args.independent_review_run_id, args.output,
        )
        print(json.dumps({
            "independent_bootstrap_commit":
                binding["independent_bootstrap_commit"],
            "independent_bootstrap_tree": binding["independent_bootstrap_tree"],
            "run_id": binding["run_id"],
        }, sort_keys=True))
    elif args.verify_signed_review_artifact_inventory:
        files = verify_signed_review_artifact_inventory(
            args.verify_signed_review_artifact_inventory,
        )
        print(json.dumps({"signed_review_artifact_inventory_verified": True,
                          "files": files}, sort_keys=True))
    elif args.authenticate_preissuance_review_bundle:
        require(args.preissuance_review_receipt and args.preissuance_review_receipt_bundle and args.cosign,
                "review receipt authentication requires receipt, bundle and cosign")
        digest = authenticate_preissuance_review_bundle(
            args.preissuance_review_receipt,
            args.preissuance_review_receipt_bundle,
            args.cosign,
        )
        print(json.dumps({"preissuance_review_signature_verified": True,
                          "review_receipt_sha256": digest}, sort_keys=True))
    elif args.verify_cosign_binary:
        verified = validate_cosign_binary(args.verify_cosign_binary)
        print(json.dumps({"cosign_verified": True, "path": str(verified.original_path), "sha256": verified.digest}, sort_keys=True))
        verified.close()
    elif args.sign_subject_dir:
        require(args.cosign and args.reviewed_activation_sha
                and args.preissuance_review_receipt and args.preissuance_review_receipt_sha256
                and args.preissuance_review_receipt_bundle
                and args.preissuance_review_envelope
                and args.github_issuance and args.github_issuance_sha256,
                "subject signing requires authenticated receipt, envelope, issuance and cosign")
        generated = sign_subjects(
            args.sign_subject_dir, args.cosign, args.reviewed_activation_sha,
            args.preissuance_review_receipt, args.preissuance_review_receipt_sha256,
            args.preissuance_review_receipt_bundle,
            args.github_issuance, args.github_issuance_sha256,
            review_envelope_path=args.preissuance_review_envelope,
        )
        print(json.dumps({"signed": [path.name for path in generated]}, sort_keys=True))
    elif args.emit_review_bindings:
        require(args.reviewed_activation_sha, "review bindings require activation SHA")
        print(json.dumps(recompute_review_bindings(args.reviewed_activation_sha), sort_keys=True))
    elif args.release_dir or args.preissuance_review_receipt:
        require(args.reviewed_activation_sha and args.preissuance_review_receipt and args.preissuance_review_receipt_sha256
                and args.github_issuance and args.github_issuance_sha256,
                "verification requires activation SHA, receipt/hash and authenticated GitHub issuance/hash")
        bindings = recompute_review_bindings(args.reviewed_activation_sha)
        issuance = authenticate_github_issuance(args.github_issuance, args.github_issuance_sha256,
                                                bindings["candidate"], args.preissuance_review_receipt_sha256)
        if args.release_dir:
            require(args.cosign, "release verification requires cosign")
            result = verify_release(args.release_dir, args.reviewed_activation_sha,
                                    args.preissuance_review_receipt, args.preissuance_review_receipt_sha256,
                                    args.cosign, issuance,
                                    review_envelope_path=args.preissuance_review_envelope)
            print(json.dumps(result, sort_keys=True))
        else:
            verify_candidate()
            verify_preissuance_receipt(args.preissuance_review_receipt, args.reviewed_activation_sha,
                                       args.preissuance_review_receipt_sha256,
                                       authenticated_issuance=issuance,
                                       envelope_path=args.preissuance_review_envelope)
            print(json.dumps({"preissuance_receipt_verified": True}, sort_keys=True))
    else:
        policy, scanned = verify_candidate()
        print(json.dumps({"verified": True, "authority_id": policy["authority_id"], "files_scanned": scanned}, sort_keys=True))


if __name__ == "__main__":
    main()
