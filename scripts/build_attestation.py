#!/usr/bin/env python3
import datetime as dt
import hashlib
import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / 'authority-policy.json'
OUT = ROOT / 'clerk-instance-attestation-v1.json'

policy_bytes = POLICY_PATH.read_bytes()
policy = json.loads(policy_bytes)
secret = os.environ.get('CLERK_SECRET_KEY', '')
publishable = os.environ.get('CLERK_PUBLISHABLE_KEY', '')
if not secret or not publishable:
    raise SystemExit('required protected Clerk credentials are absent')

req = urllib.request.Request(
    'https://api.clerk.com/v1/instance',
    headers={'Authorization': f'Bearer {secret}', 'User-Agent': 'apex-acc-attestation-authority/1'},
)
with urllib.request.urlopen(req, timeout=30) as response:
    if response.status != 200:
        raise SystemExit(f'Clerk instance readback failed with HTTP {response.status}')
    instance = json.load(response)

instance_id = str(instance.get('id') or '')
environment_type = str(instance.get('environment_type') or instance.get('environmentType') or '')
if not instance_id:
    raise SystemExit('Clerk readback omitted instance id')

pub_fp = hashlib.sha256(b'acc-clerk-instance-v1\0' + publishable.encode()).hexdigest()
id_fp = hashlib.sha256(b'acc-clerk-api-instance-v1\0' + instance_id.encode()).hexdigest()
subject = policy['subject']
if pub_fp != subject['clerk_publishable_key_fingerprint_sha256']:
    raise SystemExit('publishable-key instance fingerprint mismatch')
if id_fp != subject['clerk_api_instance_id_fingerprint_sha256']:
    raise SystemExit('Clerk API instance fingerprint mismatch')
if environment_type != subject['required_environment_type']:
    raise SystemExit(f'environment type mismatch: {environment_type!r}')

now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
not_before = dt.datetime.fromisoformat(policy['validity']['not_before_utc'].replace('Z', '+00:00'))
not_after = dt.datetime.fromisoformat(policy['validity']['not_after_utc'].replace('Z', '+00:00'))
if not (not_before <= now <= not_after):
    raise SystemExit('authority policy is outside its validity window')

attestation = {
    'schema_version': 1,
    'attestation_id': 'apex-acc-clerk-instance-attestation-v1',
    'authority_id': policy['authority_id'],
    'authority_policy_sha256': hashlib.sha256(policy_bytes).hexdigest(),
    'sigstore_certificate_identity': policy['expected_sigstore_identity'],
    'sigstore_oidc_issuer': policy['expected_oidc_issuer'],
    'issued_at_utc': now.isoformat().replace('+00:00', 'Z'),
    'valid_until_utc': policy['validity']['not_after_utc'],
    'github_evidence': {
        'repository': os.environ.get('GITHUB_REPOSITORY'),
        'workflow_ref': os.environ.get('GITHUB_WORKFLOW_REF'),
        'workflow_sha': os.environ.get('GITHUB_SHA'),
        'run_id': os.environ.get('GITHUB_RUN_ID'),
        'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'actor': os.environ.get('GITHUB_ACTOR'),
        'event_name': os.environ.get('GITHUB_EVENT_NAME'),
    },
    'subject': {
        'clerk_publishable_key_fingerprint_sha256': pub_fp,
        'clerk_api_instance_id_fingerprint_sha256': id_fp,
        'environment_type': environment_type,
        'api_authenticated_readback': True,
        'raw_instance_id_persisted': False,
        'raw_credential_persisted': False,
        'acc_production_base_sha': subject['acc_production_base_sha'],
    },
    'owner_authorization': policy['owner_authorization'],
    'operation_contract': policy['operation_contract'],
    'claims': {
        'exact_instance_bound': True,
        'development_instance': True,
        'billing_api_forbidden': True,
        'plan_or_subscription_change_forbidden': True,
        'maximum_incremental_spend_eur': '0.00',
        'contact_points_forbidden': True,
        'customer_communication_forbidden': True,
        'single_temporary_non_customer_principal_only': True,
        'cleanup_and_no_mutation_readback_required': True,
        'fail_closed_on_any_mismatch': True,
    },
    'evidence_sources': policy['evidence_sources'],
    'privacy': policy['privacy'],
}
OUT.write_text(json.dumps(attestation, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
print(json.dumps({
    'attestation_written': True,
    'environment_type': environment_type,
    'exact_instance_bound': True,
    'policy_sha256': attestation['authority_policy_sha256'],
    'attestation_sha256': hashlib.sha256(OUT.read_bytes()).hexdigest(),
    'secret_or_pii_emitted': False,
}))
