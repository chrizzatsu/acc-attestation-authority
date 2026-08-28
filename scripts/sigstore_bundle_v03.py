#!/usr/bin/env python3
"""The single canonical Cosign v3.1.3 Sigstore protobuf-JSON v0.3 bundle parser.

Every Authority-v2 boundary that reads a Sigstore bundle - the live activation
pinning boundary and the Authority release boundary - reads it through exactly
this module, so the two can never drift into mutually incompatible bespoke
shapes again.

The official Sigstore bundle format encodes the ``VerificationMaterial``
protobuf ``oneof content`` DIRECTLY as a member of ``verificationMaterial``;
protobuf JSON never wraps a oneof in a literal ``content`` object. Exactly one
canonical member is accepted here.

A raw Cosign v3.1.3 keyless ``sign-blob --bundle`` emits the ``certificate``
member, carrying the Fulcio leaf and nothing else::

    {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "verificationMaterial": {
        "certificate": {"rawBytes": "<leaf DER, base64>"},
        "tlogEntries": [{...}]
      },
      "messageSignature": {
        "messageDigest": {"algorithm": "SHA2_256", "digest": ...},
        "signature": ...
      }
    }

The equally canonical ``x509CertificateChain`` member carries the leaf first,
optionally followed by issuing intermediates::

      "verificationMaterial": {
        "x509CertificateChain": {"certificates": [{"rawBytes": ...}, ...]},
        "tlogEntries": [{...}]
      }

Both normalise to the same contract: one leaf plus zero or more *untrusted*
intermediates. Neither form is ever required to carry a trust anchor, so the
path to a pinned Fulcio root is always built from pinned trust material.

Rejected, at every boundary: a literal nested ``content`` object, a
``certificate`` member beside a duplicated ``x509CertificateChain``, a
``publicKey`` member, no member at all, and any malformed member. Nothing here
trusts a value it did not decode itself: every base64 member is decoded with
validation, every int64 is accepted only in a canonical protobuf-JSON
representation, and every structural violation raises ``SystemExit`` so callers
fail closed.
"""
import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Tuple

CANONICAL_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
# The versioned parameter form the same v0.3 protobuf schema is also served as.
VERSIONED_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle+json;version=0.3"
MEDIA_TYPES = (VERSIONED_MEDIA_TYPE, CANONICAL_MEDIA_TYPE)
DIGEST_ALGORITHM = "SHA2_256"
SHA256_DIGEST_BYTES = 32
CERTIFICATE_KEY = "certificate"
CHAIN_KEY = "x509CertificateChain"
CERTIFICATES_KEY = "certificates"
RAW_BYTES_KEY = "rawBytes"
CERTIFICATE_CHAIN_KEYS = (CERTIFICATES_KEY,)
# The canonical protobuf `oneof content` members this boundary accepts. They
# are mutually exclusive: a bundle carries exactly one of them, directly.
CANONICAL_CONTENT_MEMBERS = (CERTIFICATE_KEY, CHAIN_KEY)
# Members no keyless workload bundle may carry, and the literal `content`
# wrapper that is not protobuf JSON at all.
NESTED_CONTENT_KEY = "content"
FORBIDDEN_MATERIAL_KEYS = (NESTED_CONTENT_KEY, "publicKey")
CANONICAL_UINT64 = re.compile(r"0|[1-9][0-9]*")
CANONICAL_POSITIVE_INT64 = re.compile(r"[1-9][0-9]*")
INT64_MAX = 2 ** 63 - 1
# The two canonical signed-content members. A bundle carries exactly one: a
# detached message signature over a blob, or a DSSE envelope over an in-toto
# statement. Both bind a single subject byte stream, so every caller below
# sees the same contract.
MESSAGE_SIGNATURE_KEY = "messageSignature"
DSSE_ENVELOPE_KEY = "dsseEnvelope"
SIGNED_CONTENT_MEMBERS = (MESSAGE_SIGNATURE_KEY, DSSE_ENVELOPE_KEY)
MESSAGE_SIGNATURE_KEYS = ("messageDigest", "signature")
MESSAGE_DIGEST_KEYS = ("algorithm", "digest")
DSSE_ENVELOPE_KEYS = ("payload", "payloadType", "signatures")
DSSE_SIGNATURE_KEYS = ("sig",)
DSSE_PAE_PREFIX = b"DSSEv1"
TIMESTAMP_DATA_KEY = "timestampVerificationData"
RFC3161_TIMESTAMPS_KEY = "rfc3161Timestamps"
SIGNED_TIMESTAMP_KEY = "signedTimestamp"
TIMESTAMP_DATA_KEYS = (RFC3161_TIMESTAMPS_KEY,)
RFC3161_TIMESTAMP_KEYS = (SIGNED_TIMESTAMP_KEY,)
# The two transparency-log generations this boundary accepts, told apart by
# the evidence the entry itself carries rather than by a caller's assertion.
# A Rekor v1 entry carries an integrated time and a signed entry timestamp; a
# Rekor v2 entry carries neither and is timestamped by an RFC 3161 authority
# instead. Requiring the v1 signed entry timestamp of a v2 entry made every
# genuine Rekor v2 bundle unverifiable; dropping it for v1 would remove a
# mandatory proof. Both are therefore kept, each on its own generation.
REKOR_V1 = "rekor-v1"
REKOR_V2 = "rekor-v2"
# ---------------------------------------------------------------------------
# The three protobuf-JSON objects that carry the body, closed like the body.
#
# Closing the decoded transparency body while leaving the objects around it
# open authenticated the log's statement but not the envelope it arrived in:
# unknown members could be added to the outer bundle, to
# `verificationMaterial` and to every tlog entry, and only a static pinned
# digest would notice. Each of the three is therefore an exact member set
# here. They are generation-aware exactly where the protobuf schema really
# differs - a Rekor v1 entry is timestamped by the log and carries its
# integrated time and signed entry timestamp, a Rekor v2 entry carries
# neither - and no unknown member is admitted in either generation.
# ---------------------------------------------------------------------------
BUNDLE_BASE_KEYS = ("mediaType", "verificationMaterial")
MATERIAL_BASE_KEYS = ("tlogEntries",)
MATERIAL_OPTIONAL_KEYS = (TIMESTAMP_DATA_KEY,)
TLOG_ENTRY_BASE_KEYS = (
    "canonicalizedBody", "inclusionProof", "kindVersion", "logId", "logIndex",
)
# The two members the log's own timestamping adds on Rekor v1, and only there.
TLOG_ENTRY_V1_KEYS = (
    *TLOG_ENTRY_BASE_KEYS, "inclusionPromise", "integratedTime",
)
LOG_ID_KEYS = ("keyId",)
INCLUSION_PROMISE_KEYS = ("signedEntryTimestamp",)
INCLUSION_PROOF_KEYS = (
    "checkpoint", "hashes", "logIndex", "rootHash", "treeSize",
)
CHECKPOINT_KEYS = ("envelope",)
# ---------------------------------------------------------------------------
# The transparency body, as a closed schema rather than a byte haystack.
#
# The canonicalised body is the log's own statement about what was signed, and
# it is the only place the log records the digest, the signature and the
# signing certificate. Searching those bytes for a substring authenticates
# nothing about their meaning: a body of a different kind, of a different
# version, declaring a different hash algorithm, or carrying a different
# signature or certificate all satisfy a substring. Every member below is
# therefore decoded, its field set is closed, and every value that also appears
# elsewhere in the bundle is required to be exactly equal to it.
# ---------------------------------------------------------------------------
KIND_VERSION_KEY = "kindVersion"
KIND_VERSION_KEYS = ("kind", "version")
HASHEDREKORD_KIND = "hashedrekord"
# Each transparency generation records a hashedrekord at exactly one schema
# version, so the generation the entry's own evidence proves also fixes the
# version it may declare. A v2 entry claiming the v1 schema, or the reverse,
# is a contradiction and is refused.
HASHEDREKORD_VERSIONS = {REKOR_V1: "0.0.1", REKOR_V2: "0.0.2"}
BODY_KEYS = ("apiVersion", "kind", "spec")
# Rekor v1 hashedrekord 0.0.1: a hex digest and a base64 PEM certificate.
BODY_V1_SPEC_KEYS = ("data", "signature")
BODY_V1_DATA_KEYS = ("hash",)
BODY_V1_HASH_KEYS = ("algorithm", "value")
BODY_V1_HASH_ALGORITHM = "sha256"
BODY_V1_SIGNATURE_KEYS = ("content", "publicKey")
BODY_V1_PUBLIC_KEY_KEYS = ("content",)
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
PEM_CERTIFICATE_HEADER = b"-----BEGIN CERTIFICATE-----"
PEM_CERTIFICATE_FOOTER = b"-----END CERTIFICATE-----"
# Rekor v2 hashedrekord 0.0.2: a base64 digest and a protobuf verifier.
BODY_V2_SPEC_KEYS = ("hashedRekordV002",)
BODY_V2_RECORD_KEYS = ("data", "signature")
BODY_V2_DATA_KEYS = ("algorithm", "digest")
BODY_V2_DIGEST_ALGORITHM = DIGEST_ALGORITHM
BODY_V2_SIGNATURE_KEYS = ("content", "verifier")
BODY_V2_VERIFIER_KEYS = ("keyDetails", "x509Certificate")
# The `PublicKeyDetails` values a Fulcio code-signing workload certificate is
# ever issued for. Anything else is unmodelled here and fails closed; the
# caller additionally binds this to the leaf's own public key.
BODY_KEY_DETAILS = (
    "PKIX_ECDSA_P256_SHA_256",
    "PKIX_ECDSA_P384_SHA_384",
    "PKIX_ECDSA_P521_SHA_512",
    "PKIX_ED25519",
)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def closed_json(data, label):
    """Parse JSON that may not repeat a member, or fail closed."""

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(type(key) is str and key not in result, f"{label} duplicate member")
            result[key] = value
        return result

    require(type(data) is bytes and data, f"{label} bytes are required")
    try:
        return json.loads(data, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit(f"{label} is not valid UTF-8 JSON") from error


def _b64(value, label):
    require(type(value) is str and value, f"{label} is absent")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error, TypeError) as error:
        raise SystemExit(f"{label} is not canonical base64") from error


def _int64(value, label, *, pattern=CANONICAL_UINT64):
    """A protobuf-JSON int64: a canonical decimal string, or a literal int."""
    if type(value) is str:
        require(
            pattern.fullmatch(value) is not None,
            f"{label} is not a canonical protobuf-JSON int64",
        )
        value = int(value)
    require(
        type(value) is int and type(value) is not bool and 0 <= value <= INT64_MAX,
        f"{label} is not a canonical protobuf-JSON int64",
    )
    return value


@dataclass(frozen=True)
class SigstoreBundleV03:
    """One authenticated-shape Cosign v3.1.3 Sigstore v0.3 bundle."""

    media_type: str
    content_member: str
    encoded_chain: Tuple[str, ...]
    certificate_chain: Tuple[bytes, ...]
    digest_algorithm: str
    message_digest: bytes
    signature: bytes
    tlog_entry: Mapping
    integrated_time: int
    canonical_integrated_time: bool
    log_index: int
    log_key_id: str
    canonicalized_body: bytes
    encoded_body: str
    inclusion_promise: Mapping
    inclusion_proof: Mapping
    signed_content_member: str = MESSAGE_SIGNATURE_KEY
    rekor_generation: str = REKOR_V1
    # The exact subject bytes a DSSE bundle signs: the pre-authentication
    # encoding, which is what the signature and the log entry both bind. A
    # detached message-signature bundle carries none, because its subject is
    # supplied by the caller and matched through `binds_subject`.
    dsse_subject: bytes = b""
    rfc3161_timestamps: Tuple[bytes, ...] = ()
    # The decoded transparency body, as the log itself recorded it. Every one
    # of these is required to be exactly equal to the bundle member it covers.
    body_kind: str = HASHEDREKORD_KIND
    body_version: str = ""
    body_digest: bytes = b""
    body_signature: bytes = b""
    body_certificate_der: bytes = b""
    body_key_details: str = ""

    @property
    def leaf_der(self):
        return self.certificate_chain[0]

    @property
    def encoded_leaf(self):
        return self.encoded_chain[0]

    @property
    def untrusted_intermediates(self):
        """Issuing certificates the bundle carried, which are never trusted.

        A canonical bundle may carry none, so a caller must build the path to a
        pinned root from pinned trust material and treat these only as extra
        untrusted candidates.
        """
        return self.certificate_chain[1:]

    def binds_subject(self, subject_bytes):
        """True only when the declared digest is the exact subject digest."""
        return self.message_digest == hashlib.sha256(subject_bytes).digest()

    @property
    def subject_bytes(self):
        """The bytes this bundle really signs, when it carries them itself."""
        return self.dsse_subject

    @property
    def is_rekor_v2(self):
        return self.rekor_generation == REKOR_V2


def parse_certificate_chain(material, label="Sigstore bundle"):
    """The leaf and any untrusted intermediates, from the canonical oneof.

    Exactly one direct ``content`` oneof member is accepted. The result is
    normalised so both canonical encodings look identical to every caller: the
    leaf first, then whatever untrusted issuing certificates the bundle chose
    to carry, which may legitimately be none at all.
    """
    require(type(material) is dict, f"{label} has no verification material")
    for forbidden in FORBIDDEN_MATERIAL_KEYS:
        require(
            forbidden not in material,
            f"{label} uses a non-canonical verification material shape: "
            f"verificationMaterial.{forbidden} is not a Sigstore v0.3 "
            "protobuf-JSON content oneof member",
        )
    present = [key for key in CANONICAL_CONTENT_MEMBERS if key in material]
    require(
        present,
        f"{label} carries no canonical verificationMaterial content member: "
        f"exactly one of {' or '.join(CANONICAL_CONTENT_MEMBERS)} is required",
    )
    require(
        len(present) == 1,
        f"{label} carries {' and '.join(present)} together, but the protobuf "
        "content oneof admits exactly one member; a direct certificate beside "
        "a duplicated chain is the rejected bespoke shape",
    )
    member = present[0]
    if member == CERTIFICATE_KEY:
        encoded = [_raw_bytes(material[CERTIFICATE_KEY], f"{label} certificate")]
    else:
        chain = material[CHAIN_KEY]
        require(
            type(chain) is dict,
            f"{label} carries no certificate chain",
        )
        _exact_members(
            chain, CERTIFICATE_CHAIN_KEYS, f"{label} certificate chain",
        )
        require(
            type(chain[CERTIFICATES_KEY]) is list
            and chain[CERTIFICATES_KEY],
            f"{label} carries no certificate chain",
        )
        encoded = [
            _raw_bytes(entry, f"{label} certificate chain entry {index}")
            for index, entry in enumerate(chain[CERTIFICATES_KEY])
        ]
        require(
            len(set(encoded)) == len(encoded),
            f"{label} certificate chain repeats a certificate",
        )
    decoded = tuple(
        _b64(value, f"{label} certificate {index}")
        for index, value in enumerate(encoded)
    )
    return member, tuple(encoded), decoded


def _raw_bytes(entry, label):
    require(
        type(entry) is dict and tuple(sorted(entry)) == (RAW_BYTES_KEY,),
        f"{label} is not a canonical protobuf-JSON X509Certificate",
    )
    value = entry[RAW_BYTES_KEY]
    require(
        type(value) is str and value,
        f"{label} carries no rawBytes string",
    )
    return value


def _dsse_pae(payload_type, payload):
    """The DSSE pre-authentication encoding: what a DSSE signature covers."""
    encoded_type = payload_type.encode("utf-8")
    return b" ".join([
        DSSE_PAE_PREFIX,
        str(len(encoded_type)).encode("ascii"), encoded_type,
        str(len(payload)).encode("ascii"), payload,
    ])


def _parse_dsse_envelope(envelope, label):
    """One DSSE envelope, reduced to the same subject/signature contract."""
    _exact_members(envelope, DSSE_ENVELOPE_KEYS, f"{label} DSSE envelope")
    payload_type = envelope.get("payloadType")
    require(
        type(payload_type) is str and payload_type,
        f"{label} DSSE envelope declares no payload type",
    )
    payload = _b64(envelope.get("payload"), f"{label} DSSE payload")
    signatures = envelope.get("signatures")
    require(
        type(signatures) is list and len(signatures) == 1
        and type(signatures[0]) is dict,
        f"{label} DSSE envelope carries no single signature",
    )
    signature_object = _exact_members(
        signatures[0], DSSE_SIGNATURE_KEYS, f"{label} DSSE signature object",
    )
    signature = _b64(signature_object["sig"], f"{label} DSSE signature")
    subject = _dsse_pae(payload_type, payload)
    return {
        "digest": hashlib.sha256(subject).digest(),
        "payload": payload,
        "payload_type": payload_type,
        "signature": signature,
        "subject": subject,
    }


def _parse_signed_content(bundle, label):
    """The one canonical signed-content member, normalised for every caller."""
    present = [key for key in SIGNED_CONTENT_MEMBERS if key in bundle]
    require(
        len(present) == 1,
        f"{label} carries no single canonical signed content member: exactly "
        f"one of {' or '.join(SIGNED_CONTENT_MEMBERS)} is required",
    )
    member = present[0]
    if member == DSSE_ENVELOPE_KEY:
        parsed = _parse_dsse_envelope(bundle[DSSE_ENVELOPE_KEY], label)
        return (member, DIGEST_ALGORITHM, parsed["digest"],
                parsed["signature"], parsed["subject"])
    message = bundle[MESSAGE_SIGNATURE_KEY]
    _exact_members(
        message, MESSAGE_SIGNATURE_KEYS, f"{label} message signature object",
    )
    digest = message["messageDigest"]
    _exact_members(
        digest, MESSAGE_DIGEST_KEYS, f"{label} message digest object",
    )
    require(
        digest["algorithm"] == DIGEST_ALGORITHM,
        f"{label} message digest algorithm is not {DIGEST_ALGORITHM}",
    )
    declared = _b64(digest["digest"], f"{label} message digest")
    require(
        len(declared) == SHA256_DIGEST_BYTES,
        f"{label} message digest is not a SHA-256 digest",
    )
    signature = _b64(message["signature"], f"{label} message signature")
    return member, DIGEST_ALGORITHM, declared, signature, b""


def _parse_rfc3161_timestamps(material, label):
    """Every RFC 3161 token the bundle carries, decoded and never trusted."""
    data = material.get(TIMESTAMP_DATA_KEY)
    if data is None:
        return ()
    require(
        type(data) is dict,
        f"{label} timestamp verification data is malformed",
    )
    _exact_members(
        data, TIMESTAMP_DATA_KEYS, f"{label} timestamp verification data",
    )
    tokens = data[RFC3161_TIMESTAMPS_KEY]
    require(
        type(tokens) is list and tokens,
        f"{label} timestamp verification data carries no RFC 3161 timestamp",
    )
    decoded = []
    for index, entry in enumerate(tokens):
        require(
            type(entry) is dict,
            f"{label} RFC 3161 timestamp {index} is not a canonical "
            "protobuf-JSON RFC3161SignedTimestamp",
        )
        _exact_members(
            entry, RFC3161_TIMESTAMP_KEYS,
            f"{label} RFC 3161 timestamp {index}",
        )
        decoded.append(
            _b64(entry[SIGNED_TIMESTAMP_KEY], f"{label} RFC 3161 timestamp {index}")
        )
    return tuple(decoded)


def _exact_members(payload, keys, label):
    """A closed object: exactly these members, no more and no fewer."""
    require(type(payload) is dict, f"{label} is malformed")
    require(
        tuple(sorted(payload)) == tuple(sorted(keys)),
        f"{label} field set is not the canonical "
        f"{{{', '.join(sorted(keys))}}}",
    )
    return payload


def _closed_object(payload, known, label):
    """Close an object: no member outside the canonical protobuf-JSON set.

    Every member this schema *requires* is already required, one by one, by
    the code that decodes it, so this boundary adds exactly the half that was
    missing - the refusal of anything else - and never restates a requirement
    whose own refusal is more precise than this one would be.
    """
    require(type(payload) is dict, f"{label} is malformed")
    unknown = sorted(set(payload) - set(known))
    require(
        not unknown,
        f"{label} field set is not the canonical "
        f"{{{', '.join(sorted(known))}}}: unknown protobuf-JSON member "
        f"{', '.join(unknown)}",
    )
    return payload


def parse_kind_version(entry, generation, label):
    """The entry's own `kindVersion`, closed and pinned to the generation."""
    declared = entry.get(KIND_VERSION_KEY)
    require(
        type(declared) is dict,
        f"{label} transparency entry carries no canonical {KIND_VERSION_KEY}",
    )
    _exact_members(
        declared, KIND_VERSION_KEYS, f"{label} transparency {KIND_VERSION_KEY}",
    )
    kind, version = declared["kind"], declared["version"]
    require(
        kind == HASHEDREKORD_KIND,
        f"{label} transparency {KIND_VERSION_KEY} kind is {kind!r} and not "
        f"the only accepted kind {HASHEDREKORD_KIND!r}",
    )
    expected = HASHEDREKORD_VERSIONS[generation]
    require(
        version == expected,
        f"{label} transparency {KIND_VERSION_KEY} declares version "
        f"{version!r}, but a {generation} entry records {HASHEDREKORD_KIND} "
        f"{expected}",
    )
    return kind, version


def _body_certificate(value, label):
    """The certificate a Rekor v1 body records, in either real encoding.

    Rekor v1 records the signing certificate as base64 of its PEM, which is
    what a genuine Cosign entry carries; some producers record the bare DER.
    Both decode to one DER certificate here, and the caller then requires it
    to be exactly the leaf the bundle carries - so the encoding is never the
    thing that decides whether the binding holds.
    """
    decoded = _b64(value, label)
    stripped = decoded.strip()
    if not stripped.startswith(PEM_CERTIFICATE_HEADER):
        return decoded
    require(
        stripped.endswith(PEM_CERTIFICATE_FOOTER),
        f"{label} is not a complete PEM certificate",
    )
    inner = stripped[len(PEM_CERTIFICATE_HEADER):-len(PEM_CERTIFICATE_FOOTER)]
    return _b64(b"".join(inner.split()).decode("ascii"), label)


def parse_rekor_body(body, generation, label):
    """The decoded transparency body, as a closed schema with real bindings."""
    document = closed_json(body, f"{label} transparency body")
    _exact_members(document, BODY_KEYS, f"{label} transparency body")
    expected = HASHEDREKORD_VERSIONS[generation]
    require(
        document["kind"] == HASHEDREKORD_KIND,
        f"{label} transparency body kind is {document['kind']!r} and not "
        f"the only accepted kind {HASHEDREKORD_KIND!r}",
    )
    require(
        document["apiVersion"] == expected,
        f"{label} transparency body apiVersion is "
        f"{document['apiVersion']!r} and not the {generation} version "
        f"{expected!r}",
    )
    spec = document["spec"]
    if generation == REKOR_V2:
        _exact_members(spec, BODY_V2_SPEC_KEYS, f"{label} transparency spec")
        record = _exact_members(
            spec[BODY_V2_SPEC_KEYS[0]], BODY_V2_RECORD_KEYS,
            f"{label} transparency hashedrekord",
        )
        data = _exact_members(
            record["data"], BODY_V2_DATA_KEYS, f"{label} transparency data",
        )
        require(
            data["algorithm"] == BODY_V2_DIGEST_ALGORITHM,
            f"{label} transparency body digest algorithm is "
            f"{data['algorithm']!r} and not {BODY_V2_DIGEST_ALGORITHM}",
        )
        digest = _b64(data["digest"], f"{label} transparency body digest")
        signature = _exact_members(
            record["signature"], BODY_V2_SIGNATURE_KEYS,
            f"{label} transparency signature",
        )
        verifier = _exact_members(
            signature["verifier"], BODY_V2_VERIFIER_KEYS,
            f"{label} transparency verifier",
        )
        key_details = verifier["keyDetails"]
        require(
            key_details in BODY_KEY_DETAILS,
            f"{label} transparency verifier keyDetails {key_details!r} is not "
            "a modelled Fulcio code-signing public key type",
        )
        certificate = _b64(
            _raw_bytes(
                verifier["x509Certificate"],
                f"{label} transparency verifier certificate",
            ),
            f"{label} transparency verifier certificate",
        )
        return {
            "certificate": certificate, "digest": digest,
            "key_details": key_details,
            "kind": document["kind"], "version": document["apiVersion"],
            "signature": _b64(
                signature["content"], f"{label} transparency body signature",
            ),
        }
    _exact_members(spec, BODY_V1_SPEC_KEYS, f"{label} transparency spec")
    data = _exact_members(
        spec["data"], BODY_V1_DATA_KEYS, f"{label} transparency data",
    )
    digest_member = _exact_members(
        data["hash"], BODY_V1_HASH_KEYS, f"{label} transparency hash",
    )
    require(
        digest_member["algorithm"] == BODY_V1_HASH_ALGORITHM,
        f"{label} transparency body hash algorithm is "
        f"{digest_member['algorithm']!r} and not {BODY_V1_HASH_ALGORITHM}",
    )
    value = digest_member["value"]
    require(
        type(value) is str and SHA256_HEX.fullmatch(value) is not None,
        f"{label} transparency body digest is not a canonical SHA-256 hex "
        "digest",
    )
    signature = _exact_members(
        spec["signature"], BODY_V1_SIGNATURE_KEYS,
        f"{label} transparency signature",
    )
    public_key = _exact_members(
        signature["publicKey"], BODY_V1_PUBLIC_KEY_KEYS,
        f"{label} transparency public key",
    )
    return {
        "certificate": _body_certificate(
            public_key["content"], f"{label} transparency body certificate",
        ),
        "digest": bytes.fromhex(value),
        "key_details": "",
        "kind": document["kind"], "version": document["apiVersion"],
        "signature": _b64(
            signature["content"], f"{label} transparency body signature",
        ),
    }


def _bind_body(parsed, label):
    """Decode the transparency body and pin it to the entry's own kindVersion.

    Both are read from the same entry, so a body and a `kindVersion` that
    disagree - about the kind or about the schema version - are a contradiction
    the log itself never produces, and the entry is refused.
    """
    generation = parsed["generation"]
    kind, version = parse_kind_version(parsed["entry"], generation, label)
    body = parse_rekor_body(parsed["body"], generation, label)
    require(
        (body["kind"], body["version"]) == (kind, version),
        f"{label} transparency {KIND_VERSION_KEY} {kind}/{version} is not the "
        f"body it covers, which records {body['kind']}/{body['version']}",
    )
    parsed["decoded_body"] = body
    return parsed


def _parse_tlog_entry(material, label, *, timestamps):
    entries = material.get("tlogEntries")
    require(
        type(entries) is list and len(entries) == 1,
        f"{label} carries no single transparency entry",
    )
    entry = entries[0]
    require(type(entry) is dict, f"{label} transparency entry is malformed")
    # Refuse unknown members before anything is read. The exact generation
    # field set is enforced below once key *presence* has classified the
    # entry; a present JSON null is still a present Rekor-v1 member and may
    # never be mistaken for an absent Rekor-v2 member.
    _closed_object(entry, TLOG_ENTRY_V1_KEYS, f"{label} transparency entry")
    log_index = _int64(entry.get("logIndex"), f"{label} logIndex")
    log_id = entry.get("logId")
    _exact_members(log_id, LOG_ID_KEYS, f"{label} transparency logId")
    require(
        type(log_id["keyId"]) is str
        and log_id["keyId"],
        f"{label} transparency entry names no transparency log",
    )
    encoded_body = entry.get("canonicalizedBody")
    require(
        type(encoded_body) is str and encoded_body,
        f"{label} transparency entry carries no canonicalised body",
    )
    body = _b64(encoded_body, f"{label} transparency body")
    proof = entry.get("inclusionProof")
    _exact_members(
        proof, INCLUSION_PROOF_KEYS, f"{label} Rekor inclusion proof",
    )
    checkpoint = _exact_members(
        proof["checkpoint"], CHECKPOINT_KEYS,
        f"{label} Rekor inclusion checkpoint",
    )
    require(
        type(checkpoint["envelope"]) is str and checkpoint["envelope"],
        f"{label} Rekor inclusion checkpoint carries no envelope",
    )
    proof_index = _int64(
        proof["logIndex"], f"{label} inclusion proof logIndex",
    )
    tree_size = _int64(
        proof["treeSize"], f"{label} inclusion proof treeSize",
        pattern=CANONICAL_POSITIVE_INT64,
    )
    require(
        tree_size > 0,
        f"{label} Rekor inclusion proof coordinates are out of range",
    )
    require(
        type(proof["hashes"]) is list
        and all(type(value) is str for value in proof["hashes"])
        and type(proof["rootHash"]) is str and proof["rootHash"],
        f"{label} Rekor inclusion proof members are malformed",
    )

    # Which generation this entry is, decided by the evidence it carries and
    # never by a caller. A Rekor v1 entry is timestamped by the log itself and
    # must therefore still carry both its integrated time and its signed entry
    # timestamp; a Rekor v2 entry is timestamped by an RFC 3161 authority and
    # carries neither. Nothing can be downgraded between the two: dropping the
    # signed entry timestamp of a v1 entry leaves its integrated time behind,
    # and claiming v2 requires an RFC 3161 token this boundary then verifies
    # against the pinned timestamp authority.
    has_promise = "inclusionPromise" in entry
    has_time = "integratedTime" in entry
    if not has_promise and not has_time:
        _exact_members(
            entry, TLOG_ENTRY_BASE_KEYS, f"{label} transparency entry",
        )
        require(
            timestamps,
            f"{label} carries neither a signed entry timestamp nor an "
            "RFC 3161 timestamp, so it carries no trusted time at all",
        )
        return _bind_body({
            "entry": entry,
            "generation": REKOR_V2,
            "integrated_time": 0,
            "canonical_integrated_time": False,
            "log_index": log_index,
            "log_key_id": log_id["keyId"],
            "encoded_body": encoded_body,
            "body": body,
            "promise": {},
            "proof": proof,
        }, label)
    require(
        has_promise,
        f"{label} carries no signed entry timestamp",
    )
    require(
        has_time,
        f"{label} carries no integratedTime",
    )
    _exact_members(
        entry, TLOG_ENTRY_V1_KEYS, f"{label} transparency entry",
    )
    promise = entry.get("inclusionPromise")
    raw_time = entry.get("integratedTime")
    integrated = _int64(
        raw_time, f"{label} integratedTime", pattern=CANONICAL_POSITIVE_INT64,
    )
    require(integrated > 0, f"{label} carries no trusted time")
    _exact_members(
        promise, INCLUSION_PROMISE_KEYS,
        f"{label} transparency inclusion promise",
    )
    require(
        type(promise["signedEntryTimestamp"]) is str
        and promise["signedEntryTimestamp"],
        f"{label} carries no signed entry timestamp",
    )
    return _bind_body({
        "entry": entry,
        "generation": REKOR_V1,
        "integrated_time": integrated,
        "canonical_integrated_time": type(raw_time) is str,
        "log_index": log_index,
        "log_key_id": log_id["keyId"],
        "encoded_body": encoded_body,
        "body": body,
        "promise": promise,
        "proof": proof,
    }, label)


def parse_bundle(data, *, label="Sigstore bundle", media_types=MEDIA_TYPES):
    """Authenticate the shape of one Cosign v3.1.3 Sigstore v0.3 bundle."""
    bundle = closed_json(data, label)
    require(type(bundle) is dict, f"{label} is malformed")
    require(
        bundle.get("mediaType") in media_types,
        f"{label} media type is not a supported Sigstore v0.3 bundle",
    )
    material = bundle.get("verificationMaterial")
    member, encoded_chain, chain = parse_certificate_chain(material, label)
    (signed_member, algorithm, digest, signature,
     dsse_subject) = _parse_signed_content(bundle, label)
    # The two objects that carry the entry are closed here, against the exact
    # oneof members this bundle really chose. Neither admits an unknown member.
    _closed_object(
        bundle, (*BUNDLE_BASE_KEYS, signed_member), f"{label} object",
    )
    _closed_object(
        material, (*MATERIAL_BASE_KEYS, member, *MATERIAL_OPTIONAL_KEYS),
        f"{label} verificationMaterial",
    )
    timestamps = _parse_rfc3161_timestamps(material, label)
    tlog = _parse_tlog_entry(material, label, timestamps=timestamps)
    # The body is the log's own statement about what was signed, so every
    # member it records must be *equal* to the bundle member it covers. A
    # substring search over these bytes would authenticate none of it.
    decoded = tlog["decoded_body"]
    require(
        decoded["digest"] == digest,
        f"{label} transparency body does not bind the exact subject digest",
    )
    require(
        decoded["signature"] == signature,
        f"{label} transparency body does not bind the exact bundle signature",
    )
    require(
        decoded["certificate"] == chain[0],
        f"{label} transparency body does not bind the leaf certificate",
    )
    return SigstoreBundleV03(
        media_type=bundle["mediaType"],
        content_member=member,
        encoded_chain=encoded_chain,
        certificate_chain=chain,
        digest_algorithm=algorithm,
        message_digest=digest,
        signature=signature,
        tlog_entry=tlog["entry"],
        integrated_time=tlog["integrated_time"],
        canonical_integrated_time=tlog["canonical_integrated_time"],
        log_index=tlog["log_index"],
        log_key_id=tlog["log_key_id"],
        canonicalized_body=tlog["body"],
        encoded_body=tlog["encoded_body"],
        inclusion_promise=tlog["promise"],
        inclusion_proof=tlog["proof"],
        signed_content_member=signed_member,
        rekor_generation=tlog["generation"],
        dsse_subject=dsse_subject,
        rfc3161_timestamps=timestamps,
        body_kind=tlog["decoded_body"]["kind"],
        body_version=tlog["decoded_body"]["version"],
        body_digest=tlog["decoded_body"]["digest"],
        body_signature=tlog["decoded_body"]["signature"],
        body_certificate_der=tlog["decoded_body"]["certificate"],
        body_key_details=tlog["decoded_body"]["key_details"],
    )
