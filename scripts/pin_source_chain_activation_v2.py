#!/usr/bin/env python3
"""Derive F8 from authenticated live GitHub evidence, never from a caller.

:func:`derive_activation_closure` is the only production entry point and it is
one indivisible operation. It accepts no transport, no trust material, no
evidence object, no closure flag and no run identifier: every capability it
needs it obtains for itself, and every intermediate stays a local value, so
nothing partial escapes and no directly constructible object can skip a proof.

- Sigstore trust is loaded only from the candidate's own contract bytes: the
  official ``sigstore/root-signing`` ``targets/trusted_root.json`` vendored into
  ``reviewer-authorization-v2.json`` and bound to its immutable source
  repository, commit, path and digest. Nothing is fetched at runtime and only
  the roots and log keys valid at the Rekor integrated time are used.
- The transport is one fixed read-only client the operation instantiates
  itself, with two explicit boundaries and no automatic redirect following.
  The authenticated boundary is HTTPS to ``api.github.com`` with full
  certificate verification and a runtime token that is never logged or
  persisted. Immutable artifact bytes cross the second boundary: the canonical
  artifact-id ZIP endpoint answers exactly one documented redirect, its
  ``Location`` is validated strictly against the approved signed GitHub
  artifact storage origin class, and that target is then read over verified
  HTTPS with no credential, no API version and no GitHub header, no further
  redirect and a hard byte bound. Both can express nothing but a GET.
- The authorized runs are selected from exhaustive authenticated listings of
  the sealed workflow, never named by a caller. Exactly one successful
  attempt-1 ``workflow_dispatch`` run on the default branch may exist.
- Every repository, run, job, commit, tree, path, blob and immutable artifact
  is authenticated with canonical identifiers, complete permission and
  pagination provenance and byte recomputation, the external activation review
  is verified against the exact clean checkout, and both Sigstore bundles are
  cryptographically verified against the pinned trust.

Anything ambiguous - a non-200 API read, a direct ``200`` where the documented
artifact redirect belongs, an absent, repeated, relative, plain-HTTP,
credential-bearing, foreign or unsigned redirect target, a second redirect, a
mutable URL, a missing page, an absent permission header, a substituted tree,
blob, run or repository, a wrong workflow, ref, trigger or issuer, an absent
certificate, transparency entry or trusted time - fails closed. The module
spawns no process and writes nothing.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Mapping

SAFE_ZIP_MEMBER_BYTES = 8 * 1024 * 1024
SAFE_ZIP_AGGREGATE_BYTES = 32 * 1024 * 1024
ZIP_CREATOR_MSDOS = 0
ZIP_CREATOR_UNIX = 3
ZIP_NON_UNIX_CREATOR_SYSTEMS = frozenset((ZIP_CREATOR_MSDOS,))

ROOT = Path(__file__).resolve().parents[1]

# This operation must recompute every external-review binding from an exactly
# clean Authority checkout, so it may never write a byte into the checkout it
# is verifying. Importing a sibling module would otherwise leave a bytecode
# cache behind and make the checkout dirty against itself.
sys.dont_write_bytecode = True

try:
    from scripts import verify_source_chain_activation_v2 as ACTIVATION
    from scripts import sigstore_bundle_v03 as SIGSTORE
except ModuleNotFoundError:  # direct execution from the scripts directory
    import verify_source_chain_activation_v2 as ACTIVATION
    import sigstore_bundle_v03 as SIGSTORE

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
API_ROOT = "https://api.github.com"
CANONICAL_STATUS = 200
PER_PAGE = 100
MAX_PAGES = 100
PERMISSION_HEADER = "x-accepted-github-permissions"
API_VERSION_HEADER = "x-github-api-version-selected"
API_VERSION = "2022-11-28"
JSON_CONTENT_TYPE = "application/json"
ZIP_CONTENT_TYPE = "application/zip"
API_HOST = "api.github.com"
LOCATION_HEADER = "location"
# GitHub answers the artifact ZIP endpoint with exactly one documented
# redirect to signed storage; the archive itself never comes from the API.
ARTIFACT_REDIRECT_STATUS = 302
MAXIMUM_ARTIFACT_BYTES = 64 * 1024 * 1024
# The narrow GitHub Actions artifact storage origin class the documented
# redirect may name, and nothing else.
ARTIFACT_STORAGE_HOST_SUFFIXES = (
    ".blob.core.windows.net",
    ".actions.githubusercontent.com",
)
ARTIFACT_STORAGE_SIGNATURE_PARAMETER = "sig"
MINIMUM_STORAGE_SIGNATURE_LENGTH = 16
# Nothing that could authenticate the reader may cross to storage.
STORAGE_FORBIDDEN_REQUEST_HEADERS = (
    "authorization", "proxy-authorization", "cookie", "authentication",
    "x-github-api-version",
)
CONTENTS_READ = "contents=read"
ACTIONS_READ = "actions=read"
METADATA_READ = "metadata=read"
DEFAULT_BRANCH = "main"
DEFAULT_REF = "refs/heads/main"
TRIGGER = "workflow_dispatch"
RUN_ATTEMPT = 1
BLOB_MODE = "100644"
MINIMUM_CANONICAL_ID = 1_000_000
MAXIMUM_CANONICAL_ID = 2 ** 63 - 1
MINIMUM_DIGEST_ENTROPY = 8
MINIMUM_ID_ENTROPY = 4
MAXIMUM_SIGNING_WINDOW_SECONDS = 86_400
SOURCE_JOB_NAME = "export"
INDEPENDENT_JOB_NAME = "review"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
FULCIO_OIDS = {
    "1.3.6.1.4.1.57264.1.8": "issuer",
    "1.3.6.1.4.1.57264.1.12": "source_repository_uri",
    "1.3.6.1.4.1.57264.1.14": "source_repository_ref",
    "1.3.6.1.4.1.57264.1.18": "build_config_uri",
    "1.3.6.1.4.1.57264.1.19": "build_config_digest",
    "1.3.6.1.4.1.57264.1.20": "build_trigger",
}
SAN_OID = "2.5.29.17"
# No injected transport may carry a closure switch, an approval or a write.
FORBIDDEN_TRANSPORT_STEMS = (
    "f8", "clos", "approv", "authoriz", "post", "put", "patch", "delete",
    "write", "dispatch", "create", "update",
)
SIGSTORE_MEDIA_TYPES = (
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
    "application/vnd.dev.sigstore.bundle.v0.3+json",
)


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


# ---------------------------------------------------------------------------
# Canonical identifier and digest hygiene
# ---------------------------------------------------------------------------
def _require_canonical_id(value, label):
    """A canonical GitHub identifier, never a synthetic fixture number."""
    require(
        type(value) is int and type(value) is not bool,
        f"{label} is not a canonical integer identifier",
    )
    require(
        MINIMUM_CANONICAL_ID <= value <= MAXIMUM_CANONICAL_ID,
        f"{label} is outside the canonical GitHub identifier range",
    )
    digits = str(value)
    require(
        len(set(digits)) > 1,
        f"{label} is a synthetic repeated-digit identifier",
    )
    require(
        len(set(digits)) >= MINIMUM_ID_ENTROPY,
        f"{label} is a synthetic low-entropy identifier",
    )
    return value


def _require_non_synthetic_digest(value, label, *, pattern=HEX64):
    """A digest that was really computed, not a hand-typed fixture constant."""
    require(
        type(value) is str and pattern.fullmatch(value) is not None,
        f"{label} is malformed",
    )
    require(
        len(set(value)) >= MINIMUM_DIGEST_ENTROPY,
        f"{label} is a synthetic low-entropy digest",
    )
    return value


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _git_blob_oid(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# ---------------------------------------------------------------------------
# The explicit injected read-only transport boundary
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _TransportResponse:
    """One canonical read. There is no way to express a write."""

    url: str
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""


class _ReadOnlyTransport:
    """The only evidence source. Subclasses may expose exactly one read."""

    def get(self, url):
        raise NotImplementedError("a read-only transport must implement get()")


def _require_read_only_transport(transport):
    """Only a real read-only transport subclass may supply live evidence."""
    require(
        isinstance(transport, _ReadOnlyTransport),
        "live activation evidence requires an explicit _ReadOnlyTransport",
    )
    for name in dir(transport):
        lowered = name.lower()
        require(
            not any(stem in lowered for stem in FORBIDDEN_TRANSPORT_STEMS),
            f"the injected transport exposes a caller-controlled member: {name}",
        )
    return transport


def _lowered_headers(headers, label):
    """One unambiguous case-folded header mapping, or nothing."""
    require(type(headers) is dict, f"{label} carries no response headers")
    lowered = {}
    for key, value in headers.items():
        require(
            type(key) is str and type(value) is str,
            f"{label} response headers are malformed",
        )
        name = key.lower()
        require(name not in lowered, f"{label} repeats a response header")
        lowered[name] = value
    return lowered


def _require_artifact_storage_url(location, label):
    """The one documented redirect target: an immutable signed storage URL.

    A relative, plain-HTTP, credential-bearing, fragmented, ported, foreign,
    look-alike, traversing, unsigned or otherwise ambiguous target is refused
    before anything is dialled, so no read can be steered off the approved
    GitHub artifact storage origin class.
    """
    require(
        type(location) is str and location != "",
        f"{label} carries no redirect target",
    )
    require(
        location == location.strip()
        and not any(character in location for character in "\r\n\t "),
        f"{label} redirect target is malformed",
    )
    try:
        parsed = urllib.parse.urlsplit(location)
        port = parsed.port
    except ValueError as error:
        raise SystemExit(f"{label} redirect target is malformed") from error
    require(
        parsed.scheme == "https",
        f"{label} redirect target is not verified HTTPS",
    )
    require(
        parsed.netloc != "",
        f"{label} redirect target is relative or malformed",
    )
    require(parsed.fragment == "", f"{label} redirect target carries a fragment")
    host = parsed.hostname
    require(
        type(host) is str and host != "" and not host.endswith("."),
        f"{label} redirect target host is malformed",
    )
    require(
        port is None and parsed.netloc == host,
        f"{label} redirect target authority is not canonical: it carries "
        "user information, a port or non-canonical case",
    )
    require(
        host != API_HOST and any(
            host.endswith(suffix) and len(host) > len(suffix)
            for suffix in ARTIFACT_STORAGE_HOST_SUFFIXES
        ),
        f"{label} redirect target is not an approved GitHub artifact "
        "storage origin",
    )
    require(
        parsed.path.startswith("/") and len(parsed.path) > 1
        and ".." not in parsed.path,
        f"{label} redirect target path is not canonical",
    )
    require(
        parsed.query != "",
        f"{label} redirect target is mutable: it is not a signed download",
    )
    try:
        parameters = urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True, strict_parsing=True,
        )
    except ValueError as error:
        raise SystemExit(
            f"{label} redirect target query is malformed"
        ) from error
    require(
        all(len(values) == 1 for values in parameters.values()),
        f"{label} redirect target repeats a query parameter",
    )
    signature = parameters.get(ARTIFACT_STORAGE_SIGNATURE_PARAMETER, [""])[0]
    require(
        len(signature) >= MINIMUM_STORAGE_SIGNATURE_LENGTH,
        f"{label} redirect target is mutable: it carries no download signature",
    )
    return location


def _require_unauthenticated_request(request, label):
    """Nothing that authenticates the reader may cross to artifact storage."""
    for name, _ in request.header_items():
        lowered = name.lower()
        require(
            lowered not in STORAGE_FORBIDDEN_REQUEST_HEADERS
            and not lowered.startswith("x-github"),
            f"{label} would forward {name} to artifact storage",
        )
    require(
        request.get_method() == "GET",
        f"{label} storage read is not a GET",
    )
    require(
        type(request.full_url) is str
        and request.full_url.startswith("https://"),
        f"{label} storage read is not verified HTTPS",
    )
    return request


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """No exchange ever auto-follows a redirect.

    ``urlopen`` would silently follow an artifact redirect onto a foreign host
    and carry the runtime token with it. Every hop this module takes is
    validated and dialled explicitly instead, so the handler refuses the
    redirect and urllib surfaces the 3xx response itself.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _GitHubReadOnlyTransport(_ReadOnlyTransport):
    """The one production transport: two explicit read-only HTTPS boundaries.

    It can express nothing but a read. The API boundary is authenticated,
    canonical and fixed to ``api.github.com``; the artifact storage boundary is
    unauthenticated and fixed to the approved signed storage origin class.
    Neither ever follows a redirect, the scheme is HTTPS with full certificate
    and hostname verification, and the runtime token is read from the
    environment, sent only to the API and never logged, echoed or persisted.
    """

    _TOKEN_VARIABLES = ("GITHUB_TOKEN", "GH_TOKEN")

    def __init__(self):
        token = ""
        for name in self._TOKEN_VARIABLES:
            token = os.environ.get(name, "")
            if token:
                break
        require(
            type(token) is str and token != "",
            "no authenticated GitHub runtime token is available, so no "
            "activation evidence can be read and F8 stays open",
        )
        self.__token = token
        self.__context = ssl.create_default_context()
        self.__context.check_hostname = True
        self.__context.verify_mode = ssl.CERT_REQUIRED
        self.__opener = urllib.request.build_opener(
            _RefuseRedirects(),
            urllib.request.HTTPSHandler(context=self.__context),
        )

    def get(self, url):
        require(
            type(url) is str and url.startswith(f"{API_ROOT}/"),
            "the production transport reads only canonical GitHub API URLs",
        )
        return self._exchange(self._api_request(url))

    def read_immutable_zip(self, url):
        """The two-boundary immutable artifact read.

        Boundary one is the canonical authenticated ``api.github.com``
        artifact-id ZIP endpoint with redirect following disabled: exactly one
        documented redirect to a strictly validated signed storage target is
        accepted. Boundary two is a verified-HTTPS read of that target which
        carries no credential, no API version and no GitHub header, may not
        redirect again and returns bounded bytes only.
        """
        require(
            type(url) is str and url.startswith(f"{API_ROOT}/")
            and url.endswith("/zip"),
            "the production transport downloads only canonical artifact ZIPs",
        )
        label = "artifact download"
        redirect = self._exchange(self._api_request(url))
        require(
            type(redirect) is _TransportResponse,
            f"{label} did not return a canonical transport response",
        )
        require(
            redirect.status == ARTIFACT_REDIRECT_STATUS,
            f"{label} did not answer with the one documented artifact redirect",
        )
        target = _require_artifact_storage_url(
            _lowered_headers(redirect.headers, label).get(LOCATION_HEADER),
            label,
        )
        request = self._storage_request(target)
        _require_unauthenticated_request(request, label)
        return redirect, self._exchange(request, limit=MAXIMUM_ARTIFACT_BYTES)

    def _api_request(self, url):
        """Boundary one: the authenticated canonical GitHub API read."""
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self.__token}")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", API_VERSION)
        return request

    def _storage_request(self, url):
        """Boundary two: no credential, no API version, no GitHub header."""
        request = urllib.request.Request(url)
        request.add_header("Accept", ZIP_CONTENT_TYPE)
        return request

    def _exchange(self, request, limit=None):
        """The single HTTPS exchange. Nothing but a GET can be expressed."""
        try:
            with self.__opener.open(request, timeout=30) as response:
                body = (
                    response.read() if limit is None
                    else response.read(limit + 1)
                )
                return _TransportResponse(
                    url=response.geturl(),
                    status=response.status,
                    headers={
                        key: value for key, value in response.headers.items()
                    },
                    body=body,
                )
        except urllib.error.HTTPError as error:
            return _TransportResponse(
                url=request.full_url, status=error.code,
                headers={key: value for key, value in error.headers.items()},
                body=b"",
            )
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise SystemExit(
                "the authenticated GitHub read failed, so the transport is "
                f"ambiguous and F8 stays open: {type(error).__name__}"
            ) from error


def _transport_factory():
    """The only way a transport ever enters the production operation."""
    return _GitHubReadOnlyTransport()


def _read(transport, url, label, *, permission, content_type):
    require(
        type(url) is str and url.startswith(f"{API_ROOT}/"),
        f"{label} is not a canonical GitHub API URL",
    )
    response = transport.get(url)
    require(
        type(response) is _TransportResponse,
        f"{label} did not return a canonical transport response",
    )
    require(
        response.url == url,
        f"{label} was answered from a different URL: transport is ambiguous",
    )
    require(
        response.status == CANONICAL_STATUS,
        f"{label} is not an authenticated HTTP 200 read",
    )
    lowered = _lowered_headers(response.headers, label)
    require(
        lowered.get(PERMISSION_HEADER) == permission,
        f"{label} lacks the exact permission provenance {permission}",
    )
    require(
        lowered.get(API_VERSION_HEADER) == API_VERSION,
        f"{label} lacks the pinned GitHub API version provenance",
    )
    observed_type = lowered.get("content-type", "")
    require(
        observed_type.split(";")[0].strip() == content_type,
        f"{label} content type is not {content_type}",
    )
    require(type(response.body) is bytes, f"{label} body is not bytes")
    return lowered, response.body


def _read_artifact_zip(transport, url, label):
    """Read one immutable artifact ZIP across the two documented boundaries.

    Boundary one is the canonical authenticated ``api.github.com`` artifact-id
    ZIP endpoint. It must answer the one documented redirect - never a direct
    ``200`` - with complete permission and API-version provenance and exactly
    one strictly validated signed storage ``Location``. Boundary two is the
    unauthenticated verified-HTTPS read of that exact target: it may not
    redirect again, may not impersonate the GitHub API, must serve a ZIP and
    must return bounded bytes.
    """
    require(
        type(url) is str and url.startswith(f"{API_ROOT}/")
        and url.endswith("/zip"),
        f"{label} is not the canonical GitHub artifact ZIP endpoint",
    )
    exchange = transport.read_immutable_zip(url)
    require(
        type(exchange) is tuple and len(exchange) == 2
        and all(type(item) is _TransportResponse for item in exchange),
        f"{label} did not return the two documented transport boundaries",
    )
    redirect, storage = exchange
    # --- boundary one: the authenticated canonical API redirect ------------
    require(
        redirect.url == url,
        f"{label} was answered from a different URL: transport is ambiguous",
    )
    require(
        redirect.status == ARTIFACT_REDIRECT_STATUS,
        f"{label} is not the one documented authenticated artifact redirect",
    )
    api_headers = _lowered_headers(redirect.headers, label)
    require(
        api_headers.get(PERMISSION_HEADER) == ACTIONS_READ,
        f"{label} lacks the exact permission provenance {ACTIONS_READ}",
    )
    require(
        api_headers.get(API_VERSION_HEADER) == API_VERSION,
        f"{label} lacks the pinned GitHub API version provenance",
    )
    target = _require_artifact_storage_url(
        api_headers.get(LOCATION_HEADER), label,
    )
    # --- boundary two: the unauthenticated signed immutable storage read ---
    storage_label = f"{label} storage read"
    require(
        storage.url == target,
        f"{storage_label} was answered from a different URL: "
        "transport is ambiguous",
    )
    require(
        storage.status == CANONICAL_STATUS,
        f"{storage_label} is not a verified HTTPS 200 read",
    )
    storage_headers = _lowered_headers(storage.headers, storage_label)
    require(
        PERMISSION_HEADER not in storage_headers
        and API_VERSION_HEADER not in storage_headers
        and LOCATION_HEADER not in storage_headers,
        f"{storage_label} impersonates the GitHub API or redirects again",
    )
    observed_type = storage_headers.get("content-type", "")
    require(
        observed_type.split(";")[0].strip() == ZIP_CONTENT_TYPE,
        f"{storage_label} content type is not {ZIP_CONTENT_TYPE}",
    )
    body = storage.body
    require(
        type(body) is bytes and 0 < len(body) <= MAXIMUM_ARTIFACT_BYTES,
        f"{storage_label} returned no bounded archive bytes",
    )
    return storage_headers, body


def _read_json(transport, url, label, *, permission):
    headers, body = _read(
        transport, url, label,
        permission=permission, content_type=JSON_CONTENT_TYPE,
    )
    return headers, ACTIVATION._closed_json(body, label)


_LINK_NEXT = re.compile(r'<(?P<url>[^>]+)>;\s*rel="next"')


def _read_collection(transport, endpoint, label, *, permission, key):
    """Exhaustively paginate one canonical collection endpoint.

    A truncated traversal, a missing or malformed ``Link``, a next target that
    is not the very next page of the same endpoint, a repeated identifier or a
    total that the pages do not add up to all fail closed.
    """
    require(
        type(endpoint) is str and endpoint.startswith(f"{API_ROOT}/")
        and "?" not in endpoint,
        f"{label} pagination endpoint is not canonical",
    )
    collected = []
    seen = set()
    total = None
    page = 1
    while True:
        require(page <= MAX_PAGES, f"{label} pagination exceeded its bound")
        url = f"{endpoint}?per_page={PER_PAGE}&page={page}"
        headers, payload = _read_json(
            transport, url, f"{label} page {page}", permission=permission,
        )
        require(type(payload) is dict, f"{label} page {page} is not a JSON object")
        require(
            type(payload.get("total_count")) is int
            and type(payload.get("total_count")) is not bool
            and payload["total_count"] >= 0,
            f"{label} page {page} carries no total count",
        )
        if total is None:
            total = payload["total_count"]
        require(
            payload["total_count"] == total,
            f"{label} pages disagree about the total count",
        )
        entries = payload.get(key)
        require(type(entries) is list, f"{label} page {page} collection is malformed")
        for entry in entries:
            require(type(entry) is dict, f"{label} entry is malformed")
            identifier = entry.get("id")
            require(
                type(identifier) is int and type(identifier) is not bool,
                f"{label} entry carries no canonical identifier",
            )
            require(identifier not in seen, f"{label} repeats an entry across pages")
            seen.add(identifier)
            collected.append(entry)
        link = headers.get("link")
        match = _LINK_NEXT.search(link) if type(link) is str else None
        if match is None:
            require(
                len(entries) < PER_PAGE or len(collected) == total,
                f"{label} pagination terminated before the documented last page",
            )
            break
        require(
            link.count('rel="next"') == 1,
            f"{label} Link header repeats rel=\"next\"",
        )
        require(
            match.group("url") == f"{endpoint}?per_page={PER_PAGE}&page={page + 1}",
            f"{label} next page link is not the following page of this endpoint",
        )
        require(
            len(entries) == PER_PAGE,
            f"{label} advertised a next page after a short page",
        )
        page += 1
    require(
        len(collected) == total,
        f"{label} pagination is incomplete: the pages do not add up to the total",
    )
    return collected


# ---------------------------------------------------------------------------
# Canonical repository, run, job, tree, blob and artifact evidence
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _AuthenticatedRepository:
    full_name: str
    identifier: int
    node_id: str


@dataclass(frozen=True)
class _AuthenticatedRun:
    repository: _AuthenticatedRepository
    run_id: int
    workflow_id: int
    head_sha: str
    head_tree: str
    # The authenticated interval the signature must fall inside: the latest
    # authenticated start bound and the earliest authenticated successful
    # completion bound of this exact run and its expected job.
    signing_window: tuple


@dataclass(frozen=True)
class _AuthenticatedArtifact:
    artifact_id: int
    name: str
    members: Mapping[str, bytes]
    content_sha256: str


def _authenticate_repository(transport, full_name):
    url = f"{API_ROOT}/repos/{full_name}"
    _, payload = _read_json(
        transport, url, f"repository {full_name}", permission=METADATA_READ,
    )
    require(type(payload) is dict, f"repository {full_name} response is malformed")
    require(
        payload.get("full_name") == full_name,
        f"repository {full_name} identity mismatch",
    )
    identifier = _require_canonical_id(payload.get("id"), f"repository {full_name} id")
    node_id = payload.get("node_id")
    require(
        type(node_id) is str and node_id.startswith("R_") and len(node_id) > 8,
        f"repository {full_name} node id is malformed",
    )
    require(payload.get("url") == url, f"repository {full_name} API URL is not canonical")
    require(
        payload.get("html_url") == f"https://github.com/{full_name}",
        f"repository {full_name} HTML URL is not canonical",
    )
    require(
        payload.get("default_branch") == DEFAULT_BRANCH
        and payload.get("visibility") == "public"
        and payload.get("private") is False
        and payload.get("archived") is False
        and payload.get("disabled") is False,
        f"repository {full_name} posture mismatch",
    )
    permissions = payload.get("permissions")
    require(
        type(permissions) is dict and permissions
        and all(type(value) is bool for value in permissions.values()),
        f"repository {full_name} carries no permission provenance",
    )
    require(
        permissions.get("push") is False and permissions.get("admin") is False,
        f"repository {full_name} evidence was read with write permission",
    )
    # The canonical numeric identifier must resolve back to this repository.
    _, by_id = _read_json(
        transport, f"{API_ROOT}/repositories/{identifier}",
        f"repository {full_name} canonical id readback", permission=METADATA_READ,
    )
    require(
        type(by_id) is dict and by_id.get("id") == identifier
        and by_id.get("full_name") == full_name,
        f"repository {full_name} canonical id does not resolve to this repository",
    )
    return _AuthenticatedRepository(full_name, identifier, node_id)


def _epoch(value, label):
    require(
        type(value) is str and value != "" and value.endswith("Z"),
        f"{label} is absent or is not a UTC instant",
    )
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z", value,
    )
    require(match is not None, f"{label} is not a canonical UTC instant")
    import calendar
    return calendar.timegm(tuple(int(part) for part in match.groups()) + (0, 0, 0))


def _authenticate_run(transport, repository, run_id, *, workflow_path, job_name):
    url = f"{API_ROOT}/repos/{repository.full_name}/actions/runs/{run_id}"
    _, payload = _read_json(
        transport, url, f"run {run_id}", permission=ACTIONS_READ,
    )
    require(type(payload) is dict, f"run {run_id} response is malformed")
    require(payload.get("id") == run_id, f"run {run_id} identity mismatch")
    require(payload.get("url") == url, f"run {run_id} API URL is not canonical")
    require(
        payload.get("run_attempt") == RUN_ATTEMPT
        and type(payload.get("run_attempt")) is int
        and type(payload.get("run_attempt")) is not bool,
        f"run {run_id} is not the authorized attempt 1",
    )
    require(
        payload.get("previous_attempt_url") is None,
        f"run {run_id} is a re-run, not the authorized attempt 1",
    )
    require(
        payload.get("status") == "completed"
        and payload.get("conclusion") == "success",
        f"run {run_id} did not complete successfully",
    )
    require(
        payload.get("event") == TRIGGER,
        f"run {run_id} was not triggered by {TRIGGER}",
    )
    require(
        payload.get("head_branch") == DEFAULT_BRANCH,
        f"run {run_id} did not run on {DEFAULT_REF}",
    )
    require(
        payload.get("path") == workflow_path,
        f"run {run_id} did not execute the expected workflow",
    )
    workflow_id = _require_canonical_id(
        payload.get("workflow_id"), f"run {run_id} workflow id",
    )
    for key in ("repository", "head_repository"):
        nested = payload.get(key)
        require(
            type(nested) is dict and nested.get("id") == repository.identifier
            and nested.get("full_name") == repository.full_name,
            f"run {run_id} {key} is not the expected repository",
        )
    head_sha = _require_non_synthetic_digest(
        payload.get("head_sha"), f"run {run_id} head sha", pattern=HEX40,
    )
    # cosign signs and Rekor integrates the entry while the job is running, so
    # the authenticated timeline - not the completion instant - is what bounds
    # the trusted time. Every bound must be present, parsable and monotonic.
    created = _epoch(payload.get("created_at"), f"run {run_id} creation time")
    started = _epoch(payload.get("run_started_at"), f"run {run_id} start time")
    completed = _epoch(payload.get("updated_at"), f"run {run_id} completion time")
    require(
        created <= started <= completed,
        f"run {run_id} timestamps are contradictory or non-monotonic",
    )

    jobs = _read_collection(
        transport,
        f"{API_ROOT}/repos/{repository.full_name}/actions/runs/{run_id}"
        f"/attempts/{RUN_ATTEMPT}/jobs",
        f"run {run_id} attempt {RUN_ATTEMPT} jobs",
        permission=ACTIONS_READ, key="jobs",
    )
    matching = [job for job in jobs if job.get("name") == job_name]
    require(
        len(matching) == 1,
        f"run {run_id} does not carry exactly one {job_name} job",
    )
    job = matching[0]
    _require_canonical_id(job.get("id"), f"run {run_id} job id")
    require(
        job.get("run_id") == run_id and job.get("run_attempt") == RUN_ATTEMPT,
        f"run {run_id} job is not bound to this run attempt",
    )
    require(
        job.get("status") == "completed" and job.get("conclusion") == "success",
        f"run {run_id} job {job_name} did not succeed",
    )
    require(
        job.get("head_sha") == head_sha,
        f"run {run_id} job head does not match the run head",
    )
    job_started = _epoch(job.get("started_at"), f"run {run_id} job start time")
    job_completed = _epoch(
        job.get("completed_at"), f"run {run_id} job completion time",
    )
    require(
        job_started <= job_completed,
        f"run {run_id} job timestamps are contradictory or non-monotonic",
    )
    require(
        started <= job_started and job_completed <= completed,
        f"run {run_id} job did not execute inside its own run",
    )
    # The strictest intersection that still proves the signature happened
    # inside this exact run and this exact job.
    window = (max(started, job_started), min(completed, job_completed))
    require(
        window[0] <= window[1]
        and window[1] - window[0] <= MAXIMUM_SIGNING_WINDOW_SECONDS,
        f"run {run_id} authenticated signing window is empty or implausible",
    )

    head_tree = _authenticate_commit(transport, repository, head_sha)
    return _AuthenticatedRun(
        repository, run_id, workflow_id, head_sha, head_tree, window,
    )


def _authenticate_commit(transport, repository, commit):
    url = f"{API_ROOT}/repos/{repository.full_name}/git/commits/{commit}"
    _, payload = _read_json(
        transport, url, f"{repository.full_name} commit {commit}",
        permission=CONTENTS_READ,
    )
    require(
        type(payload) is dict and payload.get("sha") == commit
        and payload.get("url") == url,
        f"{repository.full_name} commit {commit} identity mismatch",
    )
    tree = payload.get("tree")
    require(type(tree) is dict, f"{repository.full_name} commit {commit} has no tree")
    return _require_non_synthetic_digest(
        tree.get("sha"), f"{repository.full_name} commit {commit} tree", pattern=HEX40,
    )


def _authenticate_tree_membership(transport, repository, tree_sha, sealed):
    """The exact sealed path to blob membership in the live tree."""
    url = (
        f"{API_ROOT}/repos/{repository.full_name}/git/trees/{tree_sha}?recursive=1"
    )
    _, payload = _read_json(
        transport, url, f"{repository.full_name} tree {tree_sha}",
        permission=CONTENTS_READ,
    )
    require(
        type(payload) is dict and payload.get("sha") == tree_sha,
        f"{repository.full_name} tree {tree_sha} identity mismatch",
    )
    require(
        payload.get("truncated") is False,
        f"{repository.full_name} tree {tree_sha} listing is truncated",
    )
    entries = payload.get("tree")
    require(type(entries) is list, f"{repository.full_name} tree listing is malformed")
    members = {}
    for entry in entries:
        require(type(entry) is dict, f"{repository.full_name} tree entry is malformed")
        path = entry.get("path")
        require(type(path) is str and path, f"{repository.full_name} tree path is malformed")
        require(path not in members, f"{repository.full_name} tree repeats a path")
        members[path] = entry
    for target_path, data in sealed.items():
        entry = members.get(target_path)
        require(
            entry is not None,
            f"{repository.full_name} tree does not carry the sealed {target_path}",
        )
        require(
            entry.get("type") == "blob" and entry.get("mode") == BLOB_MODE,
            f"{repository.full_name} sealed {target_path} is not a regular blob",
        )
        expected_oid = _git_blob_oid(data)
        require(
            entry.get("sha") == expected_oid,
            f"{repository.full_name} sealed {target_path} blob was substituted",
        )
        blob_url = (
            f"{API_ROOT}/repos/{repository.full_name}/git/blobs/{expected_oid}"
        )
        _, blob = _read_json(
            transport, blob_url,
            f"{repository.full_name} blob {target_path}", permission=CONTENTS_READ,
        )
        require(
            type(blob) is dict and blob.get("sha") == expected_oid
            and blob.get("encoding") == "base64",
            f"{repository.full_name} blob {target_path} response is malformed",
        )
        try:
            decoded = base64.b64decode(blob.get("content", ""), validate=False)
        except (ValueError, TypeError) as error:
            raise SystemExit(
                f"{repository.full_name} blob {target_path} is not base64"
            ) from error
        require(
            _git_blob_oid(decoded) == expected_oid and decoded == data,
            f"{repository.full_name} blob {target_path} bytes were substituted",
        )
    return members


def _validated_zip_infos(archive, expected, label, *, destination=None):
    """Validate a complete flat ZIP inventory before any member is read."""
    expected = tuple(sorted(expected))
    require(expected and len(expected) == len(set(expected)),
            f"{label} expected inventory is malformed")
    infos = archive.infolist()
    observed = {}
    total = 0
    root = None
    if destination is not None:
        destination = Path(destination)
        require(destination.is_dir() and not destination.is_symlink(),
                f"{label} extraction root is unsafe")
        root = destination.resolve()
    for info in infos:
        name = info.filename
        require(type(name) is str and name and "\x00" not in name
                and "\\" not in name and not name.startswith("/"),
                f"{label} archive member name is unsafe")
        segments = name.split("/")
        require(all(segment not in ("", ".", "..") for segment in segments),
                f"{label} archive member path traverses or aliases")
        normalized = unicodedata.normalize(
            "NFC", PurePosixPath(*segments).as_posix(),
        )
        require(normalized == name and "/" not in normalized,
                f"{label} archive member path is not canonical and flat")
        require(normalized in expected,
                f"{label} archive member inventory carries an additional member: "
                f"{name}")
        require(normalized not in observed,
                f"{label} repeats an archive member path: {name}")
        require(not info.is_dir() and _zip_member_type_is_regular(info),
                f"{label} carries a non-regular member: {name}")
        require(info.flag_bits & 1 == 0,
                f"{label} carries an encrypted member: {name}")
        require(type(info.file_size) is int and type(info.file_size) is not bool
                and 0 <= info.file_size <= SAFE_ZIP_MEMBER_BYTES,
                f"{label} member exceeds its uncompressed size bound: {name}")
        total += info.file_size
        require(total <= SAFE_ZIP_AGGREGATE_BYTES,
                f"{label} exceeds its aggregate uncompressed size bound")
        if root is not None:
            target = (root / normalized).resolve()
            require(target.parent == root,
                    f"{label} member escapes its extraction root: {name}")
        observed[normalized] = info
    require(tuple(sorted(observed)) == expected,
            f"{label} member inventory is incomplete")
    return tuple((name, observed[name]) for name in expected)


def _read_validated_zip(archive, expected, label, *, destination=None):
    """Read exact regular members only after the complete metadata pass."""
    infos = _validated_zip_infos(
        archive, expected, label, destination=destination,
    )
    members = {}
    for name, info in infos:
        data = archive.read(info)
        require(len(data) == info.file_size,
                f"{label} member size changed while reading: {name}")
        members[name] = data
    return members


def _authenticate_artifact(transport, run, name, expected_files):
    """Immutable download by canonical artifact id only."""
    artifacts = _read_collection(
        transport,
        f"{API_ROOT}/repos/{run.repository.full_name}/actions/runs"
        f"/{run.run_id}/artifacts",
        f"run {run.run_id} artifacts", permission=ACTIONS_READ, key="artifacts",
    )
    matching = [entry for entry in artifacts if entry.get("name") == name]
    require(len(matching) == 1, f"run {run.run_id} does not carry exactly one {name}")
    artifact = matching[0]
    artifact_id = _require_canonical_id(artifact.get("id"), f"artifact {name} id")
    require(
        artifact.get("expired") is False,
        f"artifact {name} has expired and is no longer immutable evidence",
    )
    workflow_run = artifact.get("workflow_run")
    require(
        type(workflow_run) is dict and workflow_run.get("id") == run.run_id
        and workflow_run.get("head_sha") == run.head_sha,
        f"artifact {name} is not bound to the authorized run",
    )
    canonical = (
        f"{API_ROOT}/repos/{run.repository.full_name}/actions/artifacts"
        f"/{artifact_id}"
    )
    require(
        artifact.get("url") == canonical,
        f"artifact {name} API URL is not canonical",
    )
    require(
        artifact.get("archive_download_url") == f"{canonical}/zip",
        f"artifact {name} download URL is mutable or not canonical",
    )
    size = artifact.get("size_in_bytes")
    require(
        type(size) is int and type(size) is not bool and size > 0,
        f"artifact {name} size is malformed",
    )
    declared = artifact.get("digest")
    require(
        type(declared) is str and declared.startswith("sha256:"),
        f"artifact {name} declares no SHA-256 digest",
    )
    _require_non_synthetic_digest(declared[7:], f"artifact {name} digest")

    # The bytes come from untrusted storage across the documented redirect,
    # so they are bound back to this authenticated artifact-list metadata.
    _, body = _read_artifact_zip(
        transport, f"{canonical}/zip", f"artifact {name} download",
    )
    require(len(body) == size, f"artifact {name} download size mismatch")
    require(_sha256(body) == declared[7:], f"artifact {name} download digest mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            members = _read_validated_zip(
                archive, expected_files, f"artifact {name}",
            )
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as error:
        raise SystemExit(f"artifact {name} is not a readable archive") from error
    return _AuthenticatedArtifact(
        artifact_id, name, members,
        _artifact_content_sha256(members),
    )


def _artifact_content_sha256(members):
    """The sealed protected-source artifact content digest, recomputed."""
    digest = hashlib.sha256(b"acc-authority-v2-protected-source-artifact\0")
    for member in sorted(members):
        encoded = member.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(members[member]).to_bytes(8, "big"))
        digest.update(members[member])
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# A real Sigstore boundary: DER certificate extensions and Rekor inclusion
# ---------------------------------------------------------------------------
def _der_read(data, offset):
    require(offset < len(data), "DER object is truncated")
    tag = data[offset]
    offset += 1
    require(offset < len(data), "DER length is truncated")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        require(1 <= count <= 4, "unsupported DER length encoding")
        require(offset + count <= len(data), "DER length is truncated")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    require(offset + length <= len(data), "DER content is truncated")
    return tag, data[offset:offset + length], offset + length


def _der_children(content):
    children = []
    offset = 0
    while offset < len(content):
        tag, value, offset = _der_read(content, offset)
        children.append((tag, value))
    return children


def _der_elements(content):
    """Every child, with the exact encoded bytes it occupies.

    CMS signature verification is over encoded structures, not over decoded
    values, so the raw bytes have to survive parsing.
    """
    elements, offset = [], 0
    while offset < len(content):
        start = offset
        tag, value, offset = _der_read(content, offset)
        elements.append((tag, value, content[start:offset]))
    return elements


def _der_oid(raw):
    require(len(raw) >= 1, "DER object identifier is empty")
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    require(value == 0, "DER object identifier is truncated")
    return ".".join(parts)


def _certificate_claims(der_bytes):
    """Extract the Fulcio claims from a DER certificate, without trusting JSON."""
    require(type(der_bytes) is bytes and der_bytes, "certificate DER bytes are required")
    tag, certificate, _ = _der_read(der_bytes, 0)
    require(tag == 0x30, "certificate is not a DER SEQUENCE")
    tag, tbs = _der_children(certificate)[0]
    require(tag == 0x30, "certificate tbsCertificate is not a DER SEQUENCE")
    extensions = None
    for child_tag, child in _der_children(tbs):
        if child_tag == 0xA3:
            inner = _der_children(child)
            require(inner and inner[0][0] == 0x30, "certificate extensions are malformed")
            extensions = inner[0][1]
    require(extensions is not None, "certificate carries no extensions")
    claims = {}
    for extension_tag, extension in _der_children(extensions):
        require(extension_tag == 0x30, "certificate extension is malformed")
        parts = _der_children(extension)
        require(len(parts) in (2, 3), "certificate extension shape is malformed")
        require(parts[0][0] == 0x06, "certificate extension has no object identifier")
        oid = _der_oid(parts[0][1])
        value = parts[-1]
        require(value[0] == 0x04, "certificate extension value is not an OCTET STRING")
        if oid in FULCIO_OIDS:
            inner_tag, inner, _ = _der_read(value[1], 0)
            require(inner_tag == 0x0C, "Fulcio claim is not a DER UTF8String")
            claims[FULCIO_OIDS[oid]] = inner.decode("utf-8")
        elif oid == SAN_OID:
            names_tag, names, _ = _der_read(value[1], 0)
            require(names_tag == 0x30, "subject alternative name is malformed")
            uris = [
                raw.decode("utf-8") for name_tag, raw in _der_children(names)
                if name_tag == 0x86
            ]
            require(len(uris) == 1, "certificate carries no single SAN URI identity")
            claims["identity"] = uris[0]
    return claims


def _rfc6962_root(leaf_hash, index, size, path):
    require(
        type(index) is int and type(size) is int and 0 <= index < size,
        "Rekor inclusion proof index is outside the tree",
    )
    node, last = index, size - 1
    digest = leaf_hash
    for sibling in path:
        require(
            type(sibling) is bytes and len(sibling) == 32,
            "Rekor inclusion proof hash is malformed",
        )
        if node % 2 == 1 or node == last:
            digest = hashlib.sha256(b"\x01" + sibling + digest).digest()
            while node % 2 == 0 and node != 0:
                node //= 2
                last //= 2
        else:
            digest = hashlib.sha256(b"\x01" + digest + sibling).digest()
        node //= 2
        last //= 2
    require(last == 0, "Rekor inclusion proof does not reach the tree root")
    return digest


@dataclass(frozen=True)
class _SigstoreTrustRoot:
    """Immutable pinned Sigstore trust material.

    This candidate seals no Sigstore trust root: the protected-source and
    independent-review repositories do not exist, so there is no authenticated
    provenance for a Fulcio root or a Rekor key yet. The boundary therefore
    requires the trust material to be supplied explicitly and fails closed
    when it is absent, rather than trusting whatever a bundle carries.
    """

    fulcio_roots: tuple
    rekor_public_key: bytes
    rekor_origin: str
    # The transparency log's own key identity, exactly as the pinned trusted
    # root states it. A signed-note key hint is the first four bytes of the
    # *log identity*, which is what a note verifier is keyed by. For Rekor v1
    # that identity happens to equal SHA-256 of the DER public key, so this
    # changes nothing there; Rekor v2 derives its log id differently, and
    # assuming the v1 coincidence held universally is what made every genuine
    # Ed25519 Rekor v2 checkpoint unverifiable.
    rekor_log_id: bytes = b""
    # The pinned transparency log's own key algorithm, as the trusted root
    # states it. It is the log key, never the signer's key.
    rekor_key_details: str = ""
    # The pinned Fulcio intermediates. A canonical Sigstore v0.3 bundle need
    # not carry any issuing certificate at all - raw Cosign keyless output
    # carries only the leaf - so the path to a pinned root is built from the
    # pinned trust material rather than from anything the bundle asserts.
    fulcio_intermediates: tuple = ()
    # The pinned RFC 3161 timestamp authorities. A Rekor v2 entry takes its
    # trusted time from one of these and from nowhere else.
    timestamp_authorities: tuple = ()

    def log_id(self):
        """The hex log identity the Rekor signed entry timestamp binds."""
        return hashlib.sha256(self.rekor_public_key).hexdigest()

    def log_key_id(self):
        """The base64 key identity a Sigstore bundle carries."""
        return base64.b64encode(
            hashlib.sha256(self.rekor_public_key).digest()
        ).decode("ascii")


# ---------------------------------------------------------------------------
# Pinned Sigstore trust, loaded only from the candidate-bound contract bytes
# ---------------------------------------------------------------------------
SIGSTORE_TRUST_KEY = "sigstore_trusted_root"
SIGSTORE_TRUST_KEYS = (
    "canonical_bytes_base64", "fulcio_authorities", "media_type", "rekor_logs",
    "runtime_trust_fetch_forbidden", "sha256", "source_commit", "source_path",
    "source_repository",
)
SIGSTORE_TRUST_SOURCE_REPOSITORY = "https://github.com/sigstore/root-signing"
SIGSTORE_TRUST_SOURCE_PATH = "targets/trusted_root.json"
MANIFEST_NAME = "AUTHORITY-V2-SHA256SUMS"
ACTIVATION_PACKAGE_NAME = "source-chain-activation-v2.json"
DERIVED_CLOSURE_NAME = "derived-activation-closure.json"
SOURCE_ARTIFACT_NAME = "authority-v2-review-t_c298fca4"
SEALED_FILE_MODE = 0o444
SIGSTORE_TRUST_SOURCE_COMMIT = "ba3066c420970c13772ba0625f09f1ec97193116"
SIGSTORE_TRUST_SHA256 = (
    "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
)
SIGSTORE_TRUST_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
)
FULCIO_AUTHORITY_KEYS = (
    "certificate_sha256", "common_name", "organization", "root_sha256", "uri",
    "valid_from", "valid_to",
)
REKOR_LOG_KEYS = (
    "base_url", "key_details", "log_id_key_id", "origin", "public_key_sha256",
    "valid_from", "valid_to",
)


@dataclass(frozen=True)
class _PinnedSigstoreTrust:
    """Every Fulcio root, Rekor key and timestamp authority the candidate pins."""

    fulcio_authorities: tuple
    rekor_logs: tuple
    timestamp_authorities: tuple = ()

    def select(self, integrated_time, log_key_id):
        """Only the roots and the log key valid at the integrated time."""
        valid = tuple(
            authority for authority in self.fulcio_authorities
            if authority["valid_from"] <= integrated_time
            and (authority["valid_to"] is None
                 or integrated_time <= authority["valid_to"])
        )
        roots = tuple(authority["root"] for authority in valid)
        require(
            roots,
            "no pinned Fulcio root is valid at the Rekor integrated time",
        )
        intermediates = tuple(
            certificate for authority in valid
            for certificate in authority["intermediates"]
        )
        matching = [
            log for log in self.rekor_logs
            if log["valid_from"] <= integrated_time
            and (log["valid_to"] is None or integrated_time <= log["valid_to"])
            and log_key_id in (log["log_id_key_id"], log["log_id_hex"])
        ]
        require(
            len(matching) == 1,
            "no pinned transparency log matches this entry at its integrated time",
        )
        log = matching[0]
        return _SigstoreTrustRoot(
            fulcio_roots=roots,
            fulcio_intermediates=intermediates,
            rekor_public_key=log["public_key"],
            rekor_origin=log["origin"],
            rekor_log_id=log.get("log_id_bytes", b""),
            rekor_key_details=log.get("key_details", ""),
            timestamp_authorities=self.timestamp_authorities,
        )


def _instant(value, label):
    """One RFC 3339 UTC instant from the pinned trust metadata."""
    require(type(value) is str and value.endswith("Z"), f"{label} is not UTC")
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z", value,
    )
    require(match is not None, f"{label} is not a canonical UTC instant")
    import calendar
    return calendar.timegm(tuple(int(part) for part in match.groups()) + (0, 0, 0))


def _load_pinned_sigstore_trust(repository_root):
    """Load the canonical Sigstore trusted root from the candidate itself.

    The bytes are the exact public artifact the candidate vendored, bound to
    their immutable source repository, commit, path and digest. They are never
    fetched at runtime and never supplied by a caller, and every root and key
    the loader returns is re-derived from those exact bytes.
    """
    path = Path(repository_root) / ACTIVATION.TRUST_RECORD_PATH
    require(
        path.is_file() and not path.is_symlink(),
        "the candidate-bound reviewer authorization record is absent or unsafe",
    )
    record = ACTIVATION._closed_json(path.read_bytes(), "reviewer authorization")
    pinned = record.get(SIGSTORE_TRUST_KEY)
    require(
        type(pinned) is dict
        and tuple(sorted(pinned)) == SIGSTORE_TRUST_KEYS,
        "the candidate pins no canonical Sigstore trusted root",
    )
    require(
        pinned["source_repository"] == SIGSTORE_TRUST_SOURCE_REPOSITORY
        and pinned["source_commit"] == SIGSTORE_TRUST_SOURCE_COMMIT
        and pinned["source_path"] == SIGSTORE_TRUST_SOURCE_PATH
        and pinned["sha256"] == SIGSTORE_TRUST_SHA256,
        "the pinned Sigstore trusted root source or digest is substituted",
    )
    require(
        pinned["runtime_trust_fetch_forbidden"] is True,
        "the pinned Sigstore trust must forbid any runtime trust fetch",
    )
    # The anchor is never a caller input and never a second duplicated literal
    # here: it is exactly the record this candidate's own sealed manifest
    # covers. The manifest is re-verified against the checkout, and the record
    # must hash to the entry the manifest pins, so a substituted anchor can
    # only be a substituted candidate - which the Authority verifier rejects
    # independently against its own sealed constant.
    require(
        _sha256(path.read_bytes()) == ACTIVATION.manifest_digest(
            Path(repository_root), ACTIVATION.TRUST_RECORD_PATH,
        ),
        "the pinned Sigstore trusted root is not the sealed manifest bytes",
    )
    require(
        pinned["sha256"] == _sha256(
            base64.b64decode(pinned["canonical_bytes_base64"], validate=True)
        ),
        "the pinned Sigstore trusted root is not the reviewed exact bytes",
    )
    try:
        canonical = base64.b64decode(pinned["canonical_bytes_base64"], validate=True)
    except (ValueError, TypeError) as error:
        raise SystemExit(
            "the pinned Sigstore trusted root bytes are not base64"
        ) from error
    require(
        _sha256(canonical) == pinned["sha256"],
        "the pinned Sigstore trusted root bytes do not match their sealed digest",
    )
    document = ACTIVATION._closed_json(canonical, "Sigstore trusted root")
    require(
        type(document) is dict
        and document.get("mediaType") == SIGSTORE_TRUST_MEDIA_TYPE
        and pinned["media_type"] == SIGSTORE_TRUST_MEDIA_TYPE,
        "the pinned Sigstore trusted root schema is not the supported schema",
    )

    authorities = []
    declared = pinned["fulcio_authorities"]
    observed = document.get("certificateAuthorities")
    require(
        type(declared) is list and declared
        and type(observed) is list and len(declared) == len(observed),
        "the pinned Fulcio authority inventory does not match the trusted root",
    )
    for entry, source in zip(declared, observed):
        require(
            type(entry) is dict and tuple(sorted(entry)) == FULCIO_AUTHORITY_KEYS,
            "a pinned Fulcio authority record is malformed",
        )
        chain = source.get("certChain", {}).get("certificates")
        require(type(chain) is list and chain, "a pinned Fulcio chain is empty")
        try:
            certificates = [
                base64.b64decode(item["rawBytes"], validate=True) for item in chain
            ]
        except (ValueError, TypeError, KeyError) as error:
            raise SystemExit("a pinned Fulcio certificate is not base64") from error
        require(
            entry["certificate_sha256"]
            == [_sha256(item) for item in certificates],
            "a pinned Fulcio certificate digest does not match the trusted root",
        )
        require(
            entry["root_sha256"] == _sha256(certificates[-1])
            and entry["uri"] == source.get("uri"),
            "a pinned Fulcio root binding does not match the trusted root",
        )
        valid_to = entry["valid_to"]
        authorities.append({
            "root": certificates[-1],
            # Everything below the anchor in the pinned Fulcio chain. A bundle
            # never has to carry these, so the path to the pinned root is built
            # from them rather than from anything a bundle asserts.
            "intermediates": tuple(certificates[:-1]),
            "uri": entry["uri"],
            "valid_from": _instant(entry["valid_from"], "Fulcio validity start"),
            "valid_to": None if valid_to is None else _instant(
                valid_to, "Fulcio validity end",
            ),
        })

    logs = []
    declared = pinned["rekor_logs"]
    observed = document.get("tlogs")
    require(
        type(declared) is list and declared
        and type(observed) is list and len(declared) == len(observed),
        "the pinned transparency log inventory does not match the trusted root",
    )
    for entry, source in zip(declared, observed):
        require(
            type(entry) is dict and tuple(sorted(entry)) == REKOR_LOG_KEYS,
            "a pinned transparency log record is malformed",
        )
        key = source.get("publicKey", {})
        try:
            der = base64.b64decode(key["rawBytes"], validate=True)
        except (ValueError, TypeError, KeyError) as error:
            raise SystemExit("a pinned Rekor key is not base64") from error
        require(
            entry["public_key_sha256"] == _sha256(der)
            and entry["log_id_key_id"] == source.get("logId", {}).get("keyId")
            and entry["key_details"] == key.get("keyDetails")
            and entry["base_url"] == source.get("baseUrl"),
            "a pinned Rekor log binding does not match the trusted root",
        )
        require(
            type(entry["origin"]) is str and entry["origin"]
            and entry["origin"] in entry["base_url"],
            "a pinned Rekor origin does not belong to its log",
        )
        valid_to = entry["valid_to"]
        logs.append({
            # The log's own key algorithm, already required above to equal the
            # trusted root's keyDetails. The route binds it, so "Ed25519" can
            # be proven of the *log* rather than assumed of the signer.
            "key_details": entry["key_details"],
            "log_id_key_id": entry["log_id_key_id"],
            "log_id_bytes": base64.b64decode(
                entry["log_id_key_id"], validate=True,
            ),
            "log_id_hex": _sha256(der),
            "origin": entry["origin"],
            "public_key": der,
            "valid_from": _instant(entry["valid_from"], "Rekor validity start"),
            "valid_to": None if valid_to is None else _instant(
                valid_to, "Rekor validity end",
            ),
        })
    # The pinned RFC 3161 timestamp authorities, taken from the very same
    # digest-pinned canonical trusted root bytes. A Rekor v2 entry's trusted
    # time may come only from one of these.
    timestamps = []
    for source in document.get("timestampAuthorities") or []:
        require(
            type(source) is dict,
            "a pinned Sigstore timestamp authority record is malformed",
        )
        chain = source.get("certChain", {}).get("certificates")
        require(
            type(chain) is list and len(chain) >= 2,
            "a pinned Sigstore timestamp authority publishes no issuing chain",
        )
        try:
            certificates = [
                base64.b64decode(item["rawBytes"], validate=True)
                for item in chain
            ]
        except (ValueError, TypeError, KeyError) as error:
            raise SystemExit(
                "a pinned Sigstore timestamp certificate is not base64"
            ) from error
        window = source.get("validFor") or {}
        end = window.get("end")
        timestamps.append({
            "certificates": tuple(certificates),
            "uri": source.get("uri"),
            "valid_from": _instant(
                window.get("start"), "timestamp authority validity start",
            ),
            "valid_to": None if end is None else _instant(
                end, "timestamp authority validity end",
            ),
        })
    # A trusted root that names no timestamp authority is not refused here:
    # a Rekor v1 bundle never needs one. It is refused at the point of use, by
    # `_verify_rfc3161_timestamp`, so a Rekor v2 entry can never be trusted
    # without a pinned authority to have timestamped it.
    return _PinnedSigstoreTrust(
        tuple(authorities), tuple(logs), tuple(timestamps),
    )


def _cryptography():
    """The verification backend, or an exact fail-closed refusal."""
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    except ImportError as error:  # pragma: no cover - environment dependent
        raise SystemExit(
            "Sigstore verification is unavailable: no trusted cryptographic "
            "verifier is installed, so the activation evidence cannot be "
            "authenticated and F8 stays open"
        ) from error
    return {
        "x509": x509, "InvalidSignature": InvalidSignature, "hashes": hashes,
        "serialization": serialization, "ec": ec, "ed25519": ed25519,
        "padding": padding, "rsa": rsa,
    }


def _x509_verification():
    """The established RFC 5280 path-validation primitive, or a refusal.

    There is no hand-rolled fallback: when ``cryptography.x509.verification``
    or its dependency is unavailable nothing can validate a certificate path
    against the pinned Fulcio trust, so the boundary fails closed here with an
    exact verification error rather than accepting a chain permissively.
    """
    try:
        from cryptography.x509 import verification
    except ImportError as error:  # pragma: no cover - environment dependent
        raise SystemExit(
            "Sigstore certificate verification is unavailable: the RFC 5280 "
            "cryptography.x509.verification path-validation primitive is not "
            "installed, so no certificate chain can be validated against the "
            "pinned Fulcio trust and F8 stays open"
        ) from error
    for name in ("PolicyBuilder", "Store", "ExtensionPolicy", "Criticality",
                 "VerificationError"):
        if not hasattr(verification, name):  # pragma: no cover - version guard
            raise SystemExit(
                "Sigstore certificate verification is unavailable: the "
                "installed cryptography.x509.verification primitive does not "
                f"provide {name}, so no certificate chain can be validated "
                "against the pinned Fulcio trust and F8 stays open"
            )
    return {
        "PolicyBuilder": verification.PolicyBuilder,
        "Store": verification.Store,
        "ExtensionPolicy": verification.ExtensionPolicy,
        "Criticality": verification.Criticality,
        "VerificationError": verification.VerificationError,
    }


# A Fulcio issued workload certificate is a code-signing end entity: it asserts
# digitalSignature, never signs certificates, and carries the codeSigning
# extended key usage. Anything else is refused before the chain is trusted.
RFC5280_MAX_CHAIN_DEPTH = 4
CODE_SIGNING_EKU = "1.3.6.1.5.5.7.3.3"


def _require_leaf_key_usage(_policy, _certificate, value):
    if value is None or not value.digital_signature:
        raise ValueError("leaf keyUsage does not assert digitalSignature")
    if value.key_cert_sign or value.crl_sign:
        raise ValueError("leaf keyUsage asserts a certificate authority usage")


def _require_leaf_extended_key_usage(_policy, _certificate, value):
    if value is None:
        raise ValueError("leaf carries no extended key usage")
    if not any(usage.dotted_string == CODE_SIGNING_EKU for usage in value):
        raise ValueError("leaf extended key usage is not codeSigning")


def _require_leaf_basic_constraints(_policy, _certificate, value):
    # RFC 5280 §4.2.1.9: basicConstraints "MUST appear as a critical extension
    # in all CA certificates" and need not appear at all in an end entity,
    # whose absence *is* the assertion that it is not a CA. Every genuine
    # Fulcio workload certificate omits it, so requiring it present refused
    # every real Sigstore bundle before any cryptography ran. What must never
    # be accepted is a leaf that asserts a certificate authority, and that is
    # exactly what is checked here when the extension is present.
    if value is None:
        return
    if value.ca or value.path_length is not None:
        raise ValueError("leaf basicConstraints asserts a certificate authority")


def _require_leaf_subject_alternative_name(_policy, _certificate, value):
    if value is None:
        raise ValueError("leaf carries no subject alternative name")


def _leaf_extension_policy(primitive):
    """Every end-entity extension constraint, on top of RFC 5280 itself."""
    criticality = primitive["Criticality"]
    from cryptography import x509

    return (
        primitive["ExtensionPolicy"].permit_all()
        .may_be_present(
            x509.BasicConstraints, criticality.CRITICAL,
            _require_leaf_basic_constraints,
        )
        .require_present(
            x509.KeyUsage, criticality.CRITICAL, _require_leaf_key_usage,
        )
        .require_present(
            x509.ExtendedKeyUsage, criticality.AGNOSTIC,
            _require_leaf_extended_key_usage,
        )
        .require_present(
            x509.SubjectAlternativeName, criticality.CRITICAL,
            _require_leaf_subject_alternative_name,
        )
    )


# Every critical extension this boundary understands. RFC 5280 §6.1 requires a
# path validator to reject any certificate that marks an extension critical
# which the validator cannot process, so the set is stated exactly rather than
# assumed.
RECOGNISED_CRITICAL_EXTENSIONS = frozenset({
    "2.5.29.15",   # keyUsage
    "2.5.29.17",   # subjectAlternativeName
    "2.5.29.19",   # basicConstraints
    "2.5.29.37",   # extendedKeyUsage
})


def _certificate_extension(certificate, extension_class, backend):
    try:
        return certificate.extensions.get_extension_for_class(extension_class)
    except backend["x509"].ExtensionNotFound:
        return None


def _require_recognised_criticality(certificate, label):
    for extension in certificate.extensions:
        require(
            not extension.critical
            or extension.oid.dotted_string in RECOGNISED_CRITICAL_EXTENSIONS,
            f"{label} marks an unrecognised extension critical: "
            f"{extension.oid.dotted_string}",
        )


def _require_issuer_profile(certificate, backend, label, *, below):
    """RFC 5280 §6.1.4: an issuer is a CA that may sign this far down."""
    constraints = _certificate_extension(
        certificate, backend["x509"].BasicConstraints, backend,
    )
    require(
        constraints is not None and constraints.critical
        and constraints.value.ca is True,
        f"{label} is not a certificate authority",
    )
    usage = _certificate_extension(certificate, backend["x509"].KeyUsage, backend)
    require(
        usage is not None and usage.value.key_cert_sign,
        f"{label} does not assert the keyCertSign key usage",
    )
    path_length = constraints.value.path_length
    require(
        path_length is None or path_length >= below,
        f"{label} pathLenConstraint is violated by the certificates below it",
    )


def _require_leaf_profile(certificate, backend, label):
    """The end-entity contract a Fulcio workload certificate must satisfy."""
    usage = _certificate_extension(certificate, backend["x509"].KeyUsage, backend)
    require(
        usage is not None and usage.critical,
        f"{label} carries no critical key usage",
    )
    require(
        usage.value.digital_signature,
        f"{label} key usage does not assert digitalSignature",
    )
    require(
        not usage.value.key_cert_sign and not usage.value.crl_sign,
        f"{label} key usage asserts a certificate authority usage",
    )
    extended = _certificate_extension(
        certificate, backend["x509"].ExtendedKeyUsage, backend,
    )
    require(
        extended is not None
        and any(
            entry.dotted_string == CODE_SIGNING_EKU for entry in extended.value
        ),
        f"{label} extended key usage is not codeSigning",
    )
    names = _certificate_extension(
        certificate, backend["x509"].SubjectAlternativeName, backend,
    )
    require(
        names is not None and names.critical,
        f"{label} carries no critical subject alternative name",
    )
    constraints = _certificate_extension(
        certificate, backend["x509"].BasicConstraints, backend,
    )
    # RFC 5280 §4.2.1.9: basicConstraints need not appear in an end entity, and
    # its absence *is* the assertion that the subject is not a CA. Every
    # genuine Fulcio workload certificate omits it. What may never be accepted
    # is a leaf that asserts a certificate authority.
    require(
        constraints is None
        or (constraints.value.ca is False
            and constraints.value.path_length is None),
        f"{label} basicConstraints asserts a certificate authority",
    )


def _verify_certificate_chain(chain_der, trust, backend, label, *, integrated_time):
    """RFC 5280 path validation from the leaf to an exactly pinned Fulcio root.

    A Fulcio workload certificate is a **code-signing** end entity: it carries
    the codeSigning extended key usage and nothing else. The established
    ``cryptography.x509.verification`` primitive only exposes the TLS client
    and TLS server profiles, both of which reject a code-signing leaf outright
    for lacking their own required extended key usage - so no genuine Sigstore
    certificate could ever pass through it. The path is therefore validated
    here against the code-signing profile, with every cryptographic step
    performed by an established library primitive
    (``Certificate.verify_directly_issued_by``, which performs issuer name
    chaining, signature-algorithm compatibility and signature verification)
    and every RFC 5280 §6.1 constraint stated exactly:

    * the trust anchor always comes from the pinned store, never from the
      bundle, so a foreign self-signed certificate can never become one;
    * every certificate in the path is valid at the trusted time;
    * every issuer is a CA asserting keyCertSign, and its pathLenConstraint
      is honoured by the certificates below it;
    * the chain depth is bounded;
    * the end entity satisfies the code-signing contract exactly;
    * a certificate marking an extension critical that this validator does
      not process is refused.

    There is no permissive fallback anywhere: every refusal is fatal.
    """
    # The availability gate stays exactly as it was: when the RFC 5280
    # verification module or its dependency is absent, nothing here may run.
    _x509_verification()
    x509 = backend["x509"]
    require(chain_der, f"{label} chain carries no issued leaf")
    try:
        chain = [x509.load_der_x509_certificate(entry) for entry in chain_der]
    except ValueError as error:
        raise SystemExit(f"{label} certificate is not valid DER") from error
    try:
        roots = [x509.load_der_x509_certificate(entry) for entry in trust.fulcio_roots]
    except ValueError as error:
        raise SystemExit("pinned Fulcio root is not valid DER") from error
    require(roots, "no Fulcio root is pinned, so no certificate can be trusted")
    try:
        pinned_intermediates = [
            x509.load_der_x509_certificate(entry)
            for entry in getattr(trust, "fulcio_intermediates", ())
        ]
    except ValueError as error:
        raise SystemExit("pinned Fulcio intermediate is not valid DER") from error
    moment = _utc_instant(integrated_time)
    # A canonical Sigstore v0.3 bundle need not carry any issuing certificate:
    # raw Cosign keyless output carries only the leaf. The path is therefore
    # built from the pinned Fulcio intermediates, with anything the bundle
    # happens to carry added purely as further *untrusted* candidates.
    encoding = backend["serialization"].Encoding.DER
    pinned = {root.public_bytes(encoding) for root in roots}
    candidates, seen = [], set(pinned)
    for certificate in (*chain[1:], *pinned_intermediates):
        encoded = certificate.public_bytes(encoding)
        if encoded in seen:
            continue
        seen.add(encoded)
        candidates.append(certificate)

    leaf = chain[0]
    path, current = [leaf], leaf
    while True:
        require(
            len(path) <= RFC5280_MAX_CHAIN_DEPTH,
            f"{label} certificate chain is longer than the permitted depth",
        )
        anchor = _issued_by_any(current, roots, label)
        if anchor is not None:
            path.append(anchor)
            break
        issuer = _issued_by_any(current, candidates, label)
        require(
            issuer is not None,
            f"{label} certificate chain does not reach a pinned Fulcio root",
        )
        candidates = [
            entry for entry in candidates
            if entry.public_bytes(encoding) != issuer.public_bytes(encoding)
        ]
        path.append(issuer)
        current = issuer

    for index, certificate in enumerate(path):
        _require_recognised_criticality(
            certificate, f"{label} certificate {index}",
        )
        require(
            certificate.not_valid_before_utc <= moment
            <= certificate.not_valid_after_utc,
            f"{label} certificate {index} was not valid at the trusted time",
        )
    for index, certificate in enumerate(path[1:], start=1):
        _require_issuer_profile(
            certificate, backend, f"{label} issuer {index}", below=index - 1,
        )
    _require_leaf_profile(leaf, backend, label)
    _require_certificate_validity(leaf, integrated_time, label)
    return leaf


def _issued_by_any(certificate, issuers, label):
    """The one pinned or carried certificate that really issued this one."""
    for issuer in issuers:
        if issuer.subject != certificate.issuer:
            continue
        try:
            certificate.verify_directly_issued_by(issuer)
        except (ValueError, TypeError):
            continue
        except Exception as error:  # InvalidSignature and friends
            if type(error).__name__ != "InvalidSignature":
                raise SystemExit(
                    f"{label} certificate chain is not verifiable against the "
                    f"pinned Fulcio trust: {error}"
                ) from error
            continue
        return issuer
    return None


def _utc_instant(integrated_time, label="Rekor integrated time"):
    """The exact UTC instant the transparency log integrated this entry."""
    from datetime import datetime, timezone

    require(
        type(integrated_time) is int and type(integrated_time) is not bool
        and integrated_time > 0,
        f"{label} is not a positive integer",
    )
    try:
        return datetime.fromtimestamp(integrated_time, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise SystemExit(f"{label} is outside the supported UTC range") from error


def _require_certificate_validity(certificate, integrated_time, label):
    moment = _utc_instant(integrated_time)
    require(
        certificate.not_valid_before_utc <= moment <= certificate.not_valid_after_utc,
        f"{label} certificate was not valid at the Rekor integrated time",
    )


def _verify_subject_signature(certificate, signature, subject_bytes, backend):
    key = certificate.public_key()
    try:
        if isinstance(key, backend["ec"].EllipticCurvePublicKey):
            key.verify(
                signature, subject_bytes,
                backend["ec"].ECDSA(backend["hashes"].SHA256()),
            )
        elif isinstance(key, backend["rsa"].RSAPublicKey):
            key.verify(
                signature, subject_bytes, backend["padding"].PKCS1v15(),
                backend["hashes"].SHA256(),
            )
        elif isinstance(key, backend["ed25519"].Ed25519PublicKey):
            key.verify(signature, subject_bytes)
        else:
            raise SystemExit("Sigstore leaf uses an unsupported signing key type")
    except backend["InvalidSignature"] as error:
        raise SystemExit(
            "Sigstore signature does not verify over the exact subject bytes"
        ) from error


def _verify_log_signature(public_key_der, signature, message, backend, label):
    try:
        key = backend["serialization"].load_der_public_key(public_key_der)
    except ValueError as error:
        raise SystemExit("pinned Rekor public key is malformed") from error
    try:
        if isinstance(key, backend["ec"].EllipticCurvePublicKey):
            key.verify(
                signature, message, backend["ec"].ECDSA(backend["hashes"].SHA256()),
            )
        elif isinstance(key, backend["rsa"].RSAPublicKey):
            key.verify(
                signature, message, backend["padding"].PKCS1v15(),
                backend["hashes"].SHA256(),
            )
        elif isinstance(key, backend["ed25519"].Ed25519PublicKey):
            key.verify(signature, message)
        else:
            raise SystemExit("pinned Rekor key type is unsupported")
    except backend["InvalidSignature"] as error:
        raise SystemExit(f"{label} does not verify against the pinned Rekor key") from error


CHECKPOINT_SIGNATURE_PREFIX = "\u2014 "
REKOR_KEY_HINT_LENGTH = 4


def _split_checkpoint(envelope):
    """Split a transparency note into its signed body and its signature lines."""
    require(type(envelope) is str and envelope, "Rekor checkpoint is absent")
    separator = envelope.find("\n\n")
    require(separator != -1, "Rekor checkpoint has no signature separator")
    body = envelope[:separator + 1]
    signatures = [
        line for line in envelope[separator + 2:].split("\n") if line
    ]
    require(signatures, "Rekor checkpoint carries no signature line")
    return body, signatures


def _verify_checkpoint(envelope, root_hash_b64, trust, backend):
    body, signatures = _split_checkpoint(envelope)
    lines = body.split("\n")
    require(
        len(lines) >= 4 and lines[0] == trust.rekor_origin,
        "Rekor checkpoint origin is not the pinned log",
    )
    require(
        lines[2] == root_hash_b64,
        "Rekor checkpoint does not carry the proven root",
    )
    # The signed note spec allows the origin to carry a tree ID suffix
    # (e.g. "rekor.sigstore.dev - 1193050959916656506") while the signature
    # line uses only the verifier name (e.g. "rekor.sigstore.dev"). Both are
    # matched against the pinned origin: the body origin must be an exact
    # match, and the signature verifier name must be the hostname prefix.
    verifier_name = (
        trust.rekor_origin.split(" - ", 1)[0]
        if " - " in trust.rekor_origin
        else trust.rekor_origin
    )
    matching = [
        line for line in signatures
        if line.startswith(CHECKPOINT_SIGNATURE_PREFIX + verifier_name + " ")
    ]
    require(
        len(matching) == 1,
        "Rekor checkpoint carries no single signature from the pinned log",
    )
    encoded = matching[0].split(" ", 2)[2]
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise SystemExit("Rekor checkpoint signature is not base64") from error
    require(
        len(blob) > REKOR_KEY_HINT_LENGTH,
        "Rekor checkpoint signature is truncated",
    )
    # The signed-note key hint is the first four bytes of the log identity the
    # pinned trusted root states. Rekor v1's identity is SHA-256 of the DER
    # public key, so this is byte-identical there; Rekor v2 pins a distinct
    # log identity and only this derivation accepts its genuine checkpoints.
    expected_hint = (
        trust.rekor_log_id or hashlib.sha256(trust.rekor_public_key).digest()
    )[:REKOR_KEY_HINT_LENGTH]
    require(
        blob[:REKOR_KEY_HINT_LENGTH] == expected_hint,
        "Rekor checkpoint was signed by a different log key",
    )
    _verify_log_signature(
        trust.rekor_public_key, blob[REKOR_KEY_HINT_LENGTH:],
        body.encode("utf-8"), backend, "Rekor checkpoint signature",
    )


# ---------------------------------------------------------------------------
# RFC 3161 trusted timestamping, against the pinned Sigstore timestamp authority
#
# A Rekor v2 entry carries no integrated time and no signed entry timestamp:
# the trusted time comes from an RFC 3161 timestamp token over the signature
# bytes, issued by the timestamp authority the pinned trusted root names. The
# token is a CMS SignedData structure, so it is decoded here exactly and every
# part of it is verified: the signer really is the pinned authority, the signed
# attributes really cover the TSTInfo that was returned, the message imprint
# really is the digest of this bundle's own signature, and the generation time
# really falls inside the authority's validity.
# ---------------------------------------------------------------------------
CMS_SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"
PKCS9_CONTENT_TYPE_OID = "1.2.840.113549.1.9.3"
PKCS9_MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4"
SHA256_OID = "2.16.840.1.101.3.4.2.1"
TIMESTAMPING_EKU = "1.3.6.1.5.5.7.3.8"
DER_SET_TAG = 0x31
# RFC 3161 PKIStatus: granted and grantedWithMods, and nothing else.
TIMESTAMP_GRANTED_STATUSES = (0, 1)
GENERALIZED_TIME = re.compile(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z")


def _der_sequence(tag, value, label):
    require(tag == 0x30, f"{label} is not a DER SEQUENCE")
    return _der_elements(value)


def _der_integer(value, label):
    require(value, f"{label} is not a DER INTEGER")
    return int.from_bytes(value, "big", signed=True)


def _parse_timestamp_token(token, label):
    """One RFC 3161 timestamp token, decoded out of its CMS SignedData."""
    require(
        type(token) is bytes and token,
        f"{label} carries no RFC 3161 timestamp token",
    )
    tag, content, _ = _der_read(token, 0)
    children = _der_sequence(tag, content, f"{label} ContentInfo")
    # RFC 3161 §2.4.2: a timestamp may travel either as a bare `ContentInfo`
    # or wrapped in the `TimeStampResp` the authority answered with. Both are
    # accepted, and a response that did not grant the token is refused.
    if children and children[0][0] == 0x30:
        require(
            len(children) == 2,
            f"{label} is not a canonical RFC 3161 TimeStampResp",
        )
        status = _der_elements(children[0][1])
        require(
            status and status[0][0] == 0x02
            and _der_integer(status[0][1], f"{label} status")
            in TIMESTAMP_GRANTED_STATUSES,
            f"{label} timestamp authority did not grant this token",
        )
        tag, content, _ = _der_read(children[1][2], 0)
        children = _der_sequence(tag, content, f"{label} ContentInfo")
    require(
        len(children) == 2 and children[0][0] == 0x06
        and _der_oid(children[0][1]) == CMS_SIGNED_DATA_OID
        and children[1][0] == 0xA0,
        f"{label} is not a CMS SignedData content info",
    )
    inner = _der_elements(children[1][1])
    require(
        len(inner) == 1 and inner[0][0] == 0x30,
        f"{label} SignedData is malformed",
    )
    signed_data = _der_elements(inner[0][1])
    require(
        len(signed_data) >= 4,
        f"{label} SignedData carries too few members",
    )
    encapsulated = None
    signer_infos = None
    for index, (child_tag, child, _raw) in enumerate(signed_data):
        if index == 2:
            require(child_tag == 0x30, f"{label} encapContentInfo is malformed")
            encapsulated = _der_elements(child)
        elif child_tag == DER_SET_TAG and index >= 3:
            signer_infos = _der_elements(child)
    require(
        encapsulated is not None and len(encapsulated) == 2
        and encapsulated[0][0] == 0x06
        and _der_oid(encapsulated[0][1]) == TST_INFO_OID
        and encapsulated[1][0] == 0xA0,
        f"{label} does not encapsulate an RFC 3161 TSTInfo",
    )
    content_tag, content_value, _ = _der_read(encapsulated[1][1], 0)
    require(
        content_tag == 0x04,
        f"{label} TSTInfo content is not an OCTET STRING",
    )
    require(
        signer_infos is not None and len(signer_infos) == 1
        and signer_infos[0][0] == 0x30,
        f"{label} carries no single signer info",
    )
    signer = _der_elements(signer_infos[0][1])
    require(len(signer) >= 5, f"{label} signer info is malformed")
    signed_attributes = None
    signature = None
    issuer_and_serial = None
    for child_tag, child, raw in signer:
        if child_tag == 0x30 and issuer_and_serial is None and signed_attributes is None:
            parts = _der_elements(child)
            if len(parts) == 2 and parts[1][0] == 0x02:
                issuer_and_serial = (parts[0][2], _der_integer(parts[1][1], label))
        elif child_tag == 0xA0:
            # signedAttrs is [0] IMPLICIT; the signature covers it re-tagged
            # as the DER SET OF it really is.
            signed_attributes = (child, bytes([DER_SET_TAG]) + raw[1:])
        elif child_tag == 0x04:
            signature = child
    require(
        issuer_and_serial is not None,
        f"{label} signer info names no issuer and serial number",
    )
    require(
        signed_attributes is not None,
        f"{label} signer info carries no signed attributes",
    )
    require(signature, f"{label} signer info carries no signature")
    return {
        "issuer_and_serial": issuer_and_serial,
        "signature": signature,
        "signed_attributes": signed_attributes[0],
        "signed_attributes_der": signed_attributes[1],
        "tst_info": content_value,
    }


def _signed_attribute(attributes, oid, label):
    """One CMS signed attribute value, by object identifier."""
    for tag, value, _raw in _der_elements(attributes):
        require(tag == 0x30, f"{label} signed attribute is malformed")
        parts = _der_elements(value)
        require(
            len(parts) == 2 and parts[0][0] == 0x06
            and parts[1][0] == DER_SET_TAG,
            f"{label} signed attribute shape is malformed",
        )
        if _der_oid(parts[0][1]) != oid:
            continue
        values = _der_elements(parts[1][1])
        require(
            len(values) == 1,
            f"{label} signed attribute {oid} carries no single value",
        )
        return values[0]
    raise SystemExit(f"{label} carries no signed attribute {oid}")


def _parse_tst_info(der, label):
    """The message imprint and generation time an RFC 3161 authority asserted."""
    tag, content, _ = _der_read(der, 0)
    members = _der_sequence(tag, content, f"{label} TSTInfo")
    require(len(members) >= 5, f"{label} TSTInfo carries too few members")
    require(members[0][0] == 0x02, f"{label} TSTInfo version is malformed")
    imprint = _der_elements(members[2][1])
    require(
        members[2][0] == 0x30 and len(imprint) == 2 and imprint[1][0] == 0x04,
        f"{label} TSTInfo message imprint is malformed",
    )
    algorithm = _der_elements(imprint[0][1])
    require(
        imprint[0][0] == 0x30 and algorithm and algorithm[0][0] == 0x06
        and _der_oid(algorithm[0][1]) == SHA256_OID,
        f"{label} TSTInfo message imprint is not SHA-256",
    )
    generated = None
    for child_tag, child, _raw in members[3:]:
        if child_tag == 0x18:
            generated = child.decode("ascii", "replace")
            break
    match = GENERALIZED_TIME.fullmatch(generated or "")
    require(
        match is not None,
        f"{label} TSTInfo carries no canonical UTC generation time",
    )
    import calendar

    return {
        "generated_at": calendar.timegm(
            tuple(int(part) for part in match.groups()) + (0, 0, 0)
        ),
        "imprint": imprint[1][1],
    }


def _pinned_timestamp_signer(authorities, issuer_and_serial, backend, label):
    """The exact pinned timestamp certificate this token says signed it."""
    issuer_der, serial = issuer_and_serial
    x509 = backend["x509"]
    for authority in authorities:
        try:
            certificates = [
                x509.load_der_x509_certificate(entry)
                for entry in authority["certificates"]
            ]
        except ValueError as error:
            raise SystemExit(
                "a pinned timestamp authority certificate is not valid DER"
            ) from error
        require(
            len(certificates) >= 2,
            f"{label} pinned timestamp authority publishes no issuing chain",
        )
        signer, anchor = certificates[0], certificates[-1]
        encoding = backend["serialization"].Encoding.DER
        if (signer.issuer.public_bytes() != issuer_der
                or signer.serial_number != serial):
            continue
        # The pinned chain is complete by construction, so the signer is
        # verified directly against the pinned anchor rather than through a
        # path that could be built from anything the token carried.
        for lower, upper in zip(certificates, certificates[1:]):
            try:
                lower.verify_directly_issued_by(upper)
            except Exception as error:
                raise SystemExit(
                    f"{label} pinned timestamp authority chain does not verify: "
                    f"{error}"
                ) from error
        require(
            anchor.public_bytes(encoding) == certificates[-1].public_bytes(encoding),
            f"{label} pinned timestamp anchor is not the pinned anchor",
        )
        _require_issuer_profile(
            anchor, backend, f"{label} timestamp authority anchor", below=0,
        )
        extended = _certificate_extension(
            signer, backend["x509"].ExtendedKeyUsage, backend,
        )
        require(
            extended is not None and extended.critical
            and [entry.dotted_string for entry in extended.value]
            == [TIMESTAMPING_EKU],
            f"{label} timestamp signer is not a critical timestamping "
            "certificate",
        )
        return {"certificates": certificates, "signer": signer,
                "valid_from": authority["valid_from"],
                "valid_to": authority["valid_to"]}
    raise SystemExit(
        f"{label} was not signed by any pinned Sigstore timestamp authority"
    )


def _verify_rfc3161_timestamp(token, signature_bytes, trust, backend, label):
    """One genuine RFC 3161 timestamp over exactly this bundle's signature."""
    authorities = getattr(trust, "timestamp_authorities", ())
    require(
        authorities,
        "no Sigstore timestamp authority is pinned, so no RFC 3161 timestamp "
        "can be trusted",
    )
    parsed = _parse_timestamp_token(token, label)
    pinned = _pinned_timestamp_signer(
        authorities, parsed["issuer_and_serial"], backend, label,
    )
    # The signed attributes really describe the TSTInfo that was returned.
    content_type = _signed_attribute(
        parsed["signed_attributes"], PKCS9_CONTENT_TYPE_OID, label,
    )
    require(
        content_type[0] == 0x06
        and _der_oid(content_type[1]) == TST_INFO_OID,
        f"{label} signed content type is not an RFC 3161 TSTInfo",
    )
    digest = _signed_attribute(
        parsed["signed_attributes"], PKCS9_MESSAGE_DIGEST_OID, label,
    )
    require(
        digest[0] == 0x04
        and digest[1] == hashlib.sha256(parsed["tst_info"]).digest(),
        f"{label} signed message digest is not the digest of the TSTInfo it "
        "returned",
    )
    # The authority's own signature over those attributes.
    _verify_subject_signature(
        pinned["signer"], parsed["signature"], parsed["signed_attributes_der"],
        backend,
    )
    info = _parse_tst_info(parsed["tst_info"], label)
    require(
        info["imprint"] == hashlib.sha256(signature_bytes).digest(),
        f"{label} message imprint is not the digest of this bundle's signature",
    )
    generated = info["generated_at"]
    moment = _utc_instant(generated, f"{label} generation time")
    require(
        pinned["signer"].not_valid_before_utc <= moment
        <= pinned["signer"].not_valid_after_utc,
        f"{label} was generated outside the pinned timestamp certificate "
        "validity",
    )
    require(
        pinned["valid_from"] <= generated
        and (pinned["valid_to"] is None or generated <= pinned["valid_to"]),
        f"{label} was generated outside the pinned timestamp authority "
        "validity",
    )
    return generated


def _verify_signed_entry_timestamp(entry, body_encoded, integrated, trust, backend):
    promise = entry.get("inclusionPromise")
    require(
        type(promise) is dict
        and type(promise.get("signedEntryTimestamp")) is str,
        "Sigstore bundle carries no signed entry timestamp",
    )
    try:
        signature = base64.b64decode(
            promise["signedEntryTimestamp"], validate=True,
        )
    except (ValueError, TypeError) as error:
        raise SystemExit("signed entry timestamp is not base64") from error
    log_index = entry.get("logIndex")
    if type(log_index) is str and re.fullmatch(r"[0-9]+", log_index):
        log_index = int(log_index)
    require(
        type(log_index) is int and type(log_index) is not bool and log_index >= 0,
        "Sigstore transparency entry log index is malformed",
    )
    payload = json.dumps(
        {
            "body": body_encoded,
            "integratedTime": integrated,
            "logID": trust.log_id(),
            "logIndex": log_index,
        },
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    _verify_log_signature(
        trust.rekor_public_key, signature, payload, backend,
        "signed entry timestamp",
    )
    return log_index


def _trusted_signing_time(parsed, trust, backend, label):
    """The instant this bundle is trusted at, proven rather than asserted.

    A Rekor v1 entry is timestamped by the log itself, so its integrated time
    is the trusted time and its signed entry timestamp still has to verify
    below. A Rekor v2 entry carries no integrated time at all: every RFC 3161
    token it carries is verified here against the pinned Sigstore timestamp
    authority, over exactly this bundle's own signature bytes, and the time
    they agree on is the trusted time. A bundle with neither never reaches
    this point, and a v2 bundle whose tokens disagree is refused.
    """
    if not parsed.is_rekor_v2:
        return parsed.integrated_time
    require(
        parsed.rfc3161_timestamps,
        f"{label} Rekor v2 entry carries no RFC 3161 timestamp, so it carries "
        "no trusted time",
    )
    observed = {
        _verify_rfc3161_timestamp(
            token, parsed.signature, trust, backend,
            f"{label} RFC 3161 timestamp {index}",
        )
        for index, token in enumerate(parsed.rfc3161_timestamps)
    }
    require(
        len(observed) == 1,
        f"{label} RFC 3161 timestamps disagree about the trusted time",
    )
    return observed.pop()


# The `PublicKeyDetails` value each Fulcio code-signing public key is issued
# as. The body names one; the leaf carries one; a body that names a different
# key type than the certificate it records is refused.
# ---------------------------------------------------------------------------
# Sigstore evidence provenance: which implementation really produced the bytes.
#
# A bundle's shape says nothing about its generator, and two generators that
# both emit a valid Sigstore v0.3 bundle are still two different provenances.
# Every vector this Authority holds is therefore pinned by the SHA-256 of its
# exact immutable bytes to the generator that really emitted it, together with
# the public source those bytes were fetched from. Nothing is ever recorded as
# having been produced by an implementation that did not produce it.
#
# The route the Authority is asked to evidence - exact Cosign v3.1.3 through
# the Ed25519 / Rekor-v2 / RFC 3161 path - is NOT held. Producing it requires
# a live Fulcio issuance, a live Rekor v2 log entry and a live RFC 3161
# timestamp, none of which may be performed here, and no offline construction
# of those is anything but fabricated provenance. The honest close is a
# fail-closed one: the missing route is recorded as explicitly unavailable and
# the verification route below refuses any Rekor-v2 bytes whose provenance is
# not pinned, rather than accepting another generator's bytes under Cosign's
# name.
# ---------------------------------------------------------------------------
COSIGN_V3_1_3_GENERATOR = "cosign v3.1.3"
SIGSTORE_JAVA_CONFORMANCE_GENERATOR = (
    "sigstore-java conformance test suite"
)
SIGSTORE_EVIDENCE_PROVENANCE = {
    # The vendored Cosign v3.1.3 release asset: ECDSA P-256, legacy Rekor v1.
    "976bcb216e45ed0274e464e2e16d81e84cc85a69b3ed6e3488c1e7cda116379a": {
        "generator": COSIGN_V3_1_3_GENERATOR,
        "log_id_key_id": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=",
        "rekor_generation": SIGSTORE.REKOR_V1,
        "signature_algorithm": "ecdsa-p256-sha256",
        "source_blob": "",
        "source_commit": "",
        "source_path": "tests/fixtures/cosign-v3.1.3-sigstore-v0.3-bundle.json",
        "source_repository": "sigstore/cosign",
    },
    # The genuine public Rekor-v2 conformance vector. It is a real Sigstore
    # v0.3 bundle from a real Ed25519 Rekor v2 log with a real RFC 3161
    # timestamp - and it was produced by the sigstore-java conformance suite,
    # not by Cosign. It is never described otherwise.
    "1d86a26555d7db11c517a2c6c766452a6c19550c1cde49ef1a7a3ccb5a1c2b66": {
        "generator": SIGSTORE_JAVA_CONFORMANCE_GENERATOR,
        "log_id_key_id": "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=",
        "rekor_generation": SIGSTORE.REKOR_V2,
        "signature_algorithm": "ecdsa-p256-sha256",
        "source_blob": "ab4ef344952003756722c3cd547a0ae25e443b8a",
        "source_commit": "42071e4bb62d1423257814defb7ec765153c81c4",
        "source_path": (
            "sigstore-java/src/test/resources/dev/sigstore/samples/bundles/"
            "bundle.dsse.rekor-v2.sigstore"
        ),
        "source_repository": "sigstore/sigstore-java",
    },
}
SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE = {
    "available": False,
    "fabrication_prohibited": True,
    "reason": (
        "digest-pinned immutable evidence produced by exact Cosign v3.1.3 "
        "through the Ed25519 / Rekor-v2 / RFC 3161 route is not held. "
        "Producing it requires a live Fulcio keyless issuance, a live Rekor "
        "v2 log entry and a live RFC 3161 timestamp; this round performs no "
        "signing, no issuance and no network call, and an offline "
        "construction of any of the three would be fabricated provenance. "
        "The genuine public Rekor-v2 vector that is held was produced by the "
        "sigstore-java conformance test suite and is recorded as such."
    ),
    "relabelling_prohibited": True,
    "required_generator": COSIGN_V3_1_3_GENERATOR,
    "required_rekor_generation": SIGSTORE.REKOR_V2,
    "required_timestamp": "rfc3161",
    "route": "cosign-v3.1.3-ed25519-rekor-v2-rfc3161",
    "substitution_prohibited": True,
}


# ---------------------------------------------------------------------------
# The exact generator-bound activation contract.
#
# "A Sigstore v0.3 bundle that a Cosign-v3.1.3-compatible verifier accepts" is
# not "bytes that exact Cosign v3.1.3 generated". The activation this Authority
# may one day be authorized to perform is the *generation* of the evidence that
# is missing, so the contract that governs it binds the generator itself: the
# exact Cosign v3.1.3 binary by the digest of its immutable bytes, the
# Ed25519 / Rekor-v2 / RFC 3161 route, the exact output bytes by digest, and
# the candidate identity those bytes were produced for.
#
# `GENERATED_ACTIVATION_EVIDENCE` describes candidate-static evidence only. It
# is empty, and deliberately is not an allow-list for fresh output: the exact
# binary/candidate/output/run provenance emitted by the separately executed
# activation is the evidence that takes fresh bytes to the cryptographic
# verifier. Known immutable bytes attributed to another generator remain
# rejected by `SIGSTORE_EVIDENCE_PROVENANCE` below.
# Only a separately authorized releaser may perform that one reversible,
# zero-spend, evidence-producing activation, and only after an independent
# zero-finding activation review it does not itself author. Builder output is
# never approval: `approved`, `activation_authorized` and `release_authorized`
# all stay false until genuinely generated exact bytes have had a fresh
# independent review of their own.
# ---------------------------------------------------------------------------
# The two keys the route binds, which one field can never name at once.
#
# "Ed25519" in the route name is the *transparency log's* verification key -
# the pinned Rekor v2 log `log2025-1.rekor.sigstore.dev`, whose trusted-root
# keyDetails is `PKIX_ED25519`. The *signer* is a Fulcio-issued workload key,
# and the pinned generator supports exactly one usable curve for it:
# `cosign sign-blob --signing-algorithm` accepts ecdsa-sha2-256-nistp256,
# -384-nistp384, -512-nistp521 and three rsa-sign-pkcs1 variants, and rejects
# `ed25519` exactly as it rejects a nonsense value. The repository's own
# genuine Rekor-v2 vector settles the reading: an ECDSA-P256-signed bundle
# included in the Ed25519 log.
#
# Collapsing both into one `signature_algorithm` therefore demanded a signer
# the generator cannot produce. They are separate and separately bound.
ACTIVATION_SIGNER_COSIGN_ALGORITHM = "ecdsa-sha2-256-nistp256"
ACTIVATION_SIGNER_SIGNATURE_ALGORITHM = "ecdsa-p256-sha256"
ACTIVATION_SIGNER_BODY_KEY_DETAILS = "PKIX_ECDSA_P256_SHA_256"
ACTIVATION_REKOR_LOG_KEY_DETAILS = "PKIX_ED25519"
ACTIVATION_EVIDENCE_DECLARATION_KEYS = (
    "generator", "generator_version", "rekor_generation",
    "rekor_log_key_algorithm", "route", "signer_signature_algorithm",
    "timestamp",
)
ACTIVATION_EVIDENCE_CONTRACT_DECLARATION = {
    "generator": COSIGN_V3_1_3_GENERATOR,
    "generator_version": "v3.1.3",
    "rekor_generation": SIGSTORE.REKOR_V2,
    "rekor_log_key_algorithm": ACTIVATION_REKOR_LOG_KEY_DETAILS,
    "route": SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE["route"],
    "signer_signature_algorithm": ACTIVATION_SIGNER_SIGNATURE_ALGORITHM,
    "timestamp": "rfc3161",
}
ACTIVATION_EVIDENCE_CONTRACT = {
    **ACTIVATION_EVIDENCE_CONTRACT_DECLARATION,
    "candidate_identity_binding_required": True,
    "generator_binary_digest_required": True,
}
ACTIVATION_EVIDENCE_LANE = "acc-releaser"
ACTIVATION_EVIDENCE_MAXIMUM_ATTEMPTS = 1
# Empty, and truthfully so. No bytes this repository holds were generated
# through the contract route, and none may be invented into it.
GENERATED_ACTIVATION_EVIDENCE = {}
ACTIVATION_AUTHENTICATED_PROVENANCE_KEYS = (
    "job_id", "run_attempt", "run_id", "signing_window_end",
    "signing_window_start",
)
ACTIVATION_GENERATED_PROVENANCE_KEYS = (
    *ACTIVATION_AUTHENTICATED_PROVENANCE_KEYS,
    "activation_evidence_sha256", "candidate_head", "candidate_tree",
    "generator_binary_sha256",
)


def _describe_activation_evidence_contract():
    """The contract's state, stated rather than inferred, and non-authorizing.

    Nothing here can authorize anything: it reports that the generated
    evidence does not exist, that only a separately authorized releaser may
    ever produce it, and that every approval flag stays false until bytes that
    really were generated have had a fresh independent review.
    """
    return {
        "activation_authorized": False,
        "approved": False,
        "authorized_lane": ACTIVATION_EVIDENCE_LANE,
        "builder_output_is_never_approval": True,
        "contract": dict(ACTIVATION_EVIDENCE_CONTRACT),
        "evidence_available": bool(GENERATED_ACTIVATION_EVIDENCE),
        "fabrication_prohibited": True,
        "independent_zero_finding_activation_review_required": True,
        "maximum_authorized_activation_attempts":
            ACTIVATION_EVIDENCE_MAXIMUM_ATTEMPTS,
        "post_activation_independent_review_required": True,
        "reason": SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE["reason"],
        "relabelling_prohibited": True,
        "release_authorized": False,
        "reversible": True,
        "self_authorization_forbidden": True,
        "substitution_prohibited": True,
        "zero_spend_required": True,
    }


def _require_generated_activation_evidence(
        bundle_bytes, *, declared, generator_binary_sha256, candidate_head,
        candidate_tree, authenticated_provenance, label="activation evidence"):
    """Accept only bytes exact Cosign v3.1.3 really generated, or fail closed.

    Every refusal names its own reason. Absent evidence, a generator that is
    merely compatible with or relabelled as Cosign, a wrong version, a wrong
    signature algorithm, a wrong Rekor generation, wrong RFC 3161 evidence, an
    unbound generator binary, an unbound candidate identity, unauthenticated
    run provenance and bytes whose pinned immutable provenance names a
    different generator are all refused here. Fresh output is not compared to
    a candidate-static digest register: after these generation bindings pass,
    the caller must send the exact bytes through the full cryptographic route.
    """
    require(
        type(bundle_bytes) is bytes and bundle_bytes,
        f"{label}: no activation evidence was supplied, and none may be "
        f"fabricated",
    )
    require(
        isinstance(declared, Mapping)
        and tuple(sorted(declared)) == ACTIVATION_EVIDENCE_DECLARATION_KEYS,
        f"{label} declaration field set is not the activation contract's: "
        f"{ACTIVATION_EVIDENCE_DECLARATION_KEYS}",
    )
    require(
        declared["generator"] == COSIGN_V3_1_3_GENERATOR,
        f"{label} names generator {declared['generator']!r}, which is not the "
        f"exact generator this contract binds ({COSIGN_V3_1_3_GENERATOR!r}); "
        f"a compatible, relabelled or static provenance is not a generator",
    )
    require(
        declared["generator_version"]
        == ACTIVATION_EVIDENCE_CONTRACT["generator_version"],
        f"{label} names generator version "
        f"{declared['generator_version']!r}, not the exact bound version "
        f"{ACTIVATION_EVIDENCE_CONTRACT['generator_version']!r}",
    )
    require(
        declared["signer_signature_algorithm"]
        == ACTIVATION_EVIDENCE_CONTRACT["signer_signature_algorithm"],
        f"{label} names signer signature algorithm "
        f"{declared['signer_signature_algorithm']!r}, not the bound signer "
        f"algorithm "
        f"{ACTIVATION_EVIDENCE_CONTRACT['signer_signature_algorithm']!r}; the "
        f"signer is a Fulcio workload key, never the transparency log key",
    )
    require(
        declared["rekor_log_key_algorithm"]
        == ACTIVATION_EVIDENCE_CONTRACT["rekor_log_key_algorithm"],
        f"{label} names Rekor log key algorithm "
        f"{declared['rekor_log_key_algorithm']!r}, not the bound Rekor "
        f"transparency log key algorithm "
        f"{ACTIVATION_EVIDENCE_CONTRACT['rekor_log_key_algorithm']!r}",
    )
    require(
        declared["rekor_generation"]
        == ACTIVATION_EVIDENCE_CONTRACT["rekor_generation"],
        f"{label} names Rekor generation {declared['rekor_generation']!r}, "
        f"not the bound Rekor generation "
        f"{ACTIVATION_EVIDENCE_CONTRACT['rekor_generation']!r}",
    )
    require(
        declared["timestamp"] == ACTIVATION_EVIDENCE_CONTRACT["timestamp"],
        f"{label} names timestamp evidence {declared['timestamp']!r}: this "
        f"contract binds RFC 3161 timestamp evidence and nothing else",
    )
    require(
        declared["route"] == ACTIVATION_EVIDENCE_CONTRACT["route"],
        f"{label} names route {declared['route']!r}, not the bound route "
        f"{ACTIVATION_EVIDENCE_CONTRACT['route']!r}",
    )
    require(
        type(generator_binary_sha256) is str
        and HEX64.fullmatch(generator_binary_sha256) is not None,
        f"{label} binds no generator binary digest: the exact immutable "
        f"Cosign v3.1.3 bytes that produced the evidence must be named",
    )
    require(
        type(candidate_head) is str and HEX40.fullmatch(candidate_head)
        and type(candidate_tree) is str and HEX40.fullmatch(candidate_tree),
        f"{label} binds no candidate identity: the exact head and tree the "
        f"evidence was generated for must be named",
    )
    require(
        isinstance(authenticated_provenance, Mapping)
        and tuple(sorted(authenticated_provenance))
        == ACTIVATION_AUTHENTICATED_PROVENANCE_KEYS,
        f"{label} carries no closed authenticated run provenance",
    )
    _require_canonical_id(
        authenticated_provenance["run_id"], f"{label} run id",
    )
    _require_canonical_id(
        authenticated_provenance["job_id"], f"{label} job id",
    )
    require(
        authenticated_provenance["run_attempt"] == RUN_ATTEMPT
        and type(authenticated_provenance["run_attempt"]) is int
        and type(authenticated_provenance["run_attempt"]) is not bool,
        f"{label} is not bound to authenticated attempt {RUN_ATTEMPT}",
    )
    start = authenticated_provenance["signing_window_start"]
    end = authenticated_provenance["signing_window_end"]
    require(
        type(start) is int and type(start) is not bool and start > 0
        and type(end) is int and type(end) is not bool and end >= start
        and end - start <= MAXIMUM_SIGNING_WINDOW_SECONDS,
        f"{label} authenticated signing window is absent or implausible",
    )
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    pinned = SIGSTORE_EVIDENCE_PROVENANCE.get(digest)
    if pinned is not None:
        # Bytes whose immutable provenance is already pinned to somebody else:
        # the legacy Cosign v3.1.3 ECDSA hashedrekord release asset and the
        # genuine sigstore-java Rekor-v2 conformance vector both land here, and
        # neither may ever be offered as evidence this route generated.
        raise SystemExit(
            f"{label} was not generated by {COSIGN_V3_1_3_GENERATOR} through "
            f"the {ACTIVATION_EVIDENCE_CONTRACT['route']} route: the pinned "
            f"immutable provenance of {digest} is {pinned['generator']!r} "
            f"({pinned['rekor_generation']}, "
            f"{pinned['signature_algorithm']})"
        )
    return {
        **dict(authenticated_provenance),
        "activation_evidence_sha256": digest,
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "generator_binary_sha256": generator_binary_sha256,
    }


# ---------------------------------------------------------------------------
# The production reachability of the generator-bound contract.
#
# The contract above was complete and unreachable: nothing in production ever
# called it, so it refused nothing. The one authorized activation run emits a
# closed provenance record naming the exact Cosign v3.1.3 binary it installed,
# the exact candidate head/tree and all four diff streams it generated
# evidence for, the exact output bytes by digest, and its own authenticated
# run, attempt, job and repository/ref/SHA identity. `--phase
# generated-activation-evidence` is the production caller that consumes that
# record: it binds every one of those, routes the output bytes through
# `_require_generated_activation_evidence` and then through the cryptographic
# production verifier, and requires the exact Ed25519 / Rekor-v2 / RFC 3161
# route before it may report anything at all.
#
# The CLI itself generates nothing, signs nothing, issues nothing, dispatches
# nothing and reaches no network. The separately triggered workflow generates
# the offered bytes; the CLI accepts only their closed authenticated provenance
# and then runs the full cryptographic verifier. The candidate-static register
# stays empty without gating fresh run-bound output. `activation_authorized`,
# `approved` and `release_authorized` stay false regardless of the result.
# ---------------------------------------------------------------------------
ACTIVATION_RECORD_TYPE = "acc-authority-v2-generated-activation-evidence"
# The one separately triggered job that may ever produce activation evidence.
# It is a job of its own, never the review job: a review run that never asks
# for activation must not be able to fail on activation evidence it does not
# claim, and activation evidence must not be able to ride a review job's
# success. The two closures stay decoupled.
ACTIVATION_JOB_NAME = "generated-activation-evidence"
# The exact file the activation job generates and the record then consumes.
ACTIVATION_EVIDENCE_OUTPUT_NAME = "generated-activation-evidence.sigstore.json"
# The activation lane runs on the pinned GitHub-hosted Ubuntu image, so the
# generator binary is the Authority's approved linux/amd64 Cosign v3.1.3
# artifact and no other. The digest is stated here because the workflow must
# embed it to check the binary it really installed *before* using it, and it
# is cross-checked against the Authority's own approved table below so the two
# can never drift apart.
ACTIVATION_GENERATOR_PLATFORM = "linux/amd64"
ACTIVATION_GENERATOR_BINARY_SHA256 = (
    "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
)
# The four canonical candidate diff streams. All four are bound: a record that
# names fewer describes a different candidate than the one reviewed.
ACTIVATION_CANDIDATE_DIFF_STREAMS = (
    "canonical-binary-full-index.diff",
    "name-status-find-renames-50.z",
    "raw-full-index-find-renames-50.z",
    "raw-status-authoritative.z",
)
ACTIVATION_RECORD_KEYS = (
    "candidate", "declaration", "generated_output", "generated_subject",
    "generator_binary", "raw_provenance", "record_type", "run_provenance",
)
# The exact bytes the generated evidence must sign. They are recomputed here
# from the candidate identity the record itself binds, so evidence generated
# for a different candidate - or for no candidate at all - cannot be offered
# for this one. The activation job composes exactly these bytes.
ACTIVATION_SUBJECT_TYPE = "acc-authority-v2-generated-activation-subject"
ACTIVATION_SUBJECT_KEYS = (
    "candidate_diff_sha256", "candidate_head", "candidate_tree",
    "repository", "subject_type",
)
ACTIVATION_RECORD_CANDIDATE_KEYS = ("diff_sha256", "head", "tree")
ACTIVATION_RECORD_OUTPUT_KEYS = ("path", "sha256")
ACTIVATION_RECORD_SUBJECT_KEYS = ("path", "sha256")
ACTIVATION_RECORD_BINARY_KEYS = ("platform", "sha256")
ACTIVATION_RAW_PROVENANCE_TYPE = (
    "acc-authority-v2-authenticated-activation-provenance"
)
ACTIVATION_RAW_PROVENANCE_KEYS = ("files", "record_type")
ACTIVATION_RAW_PROVENANCE_FILES = (
    "activation-jobs.json", "activation-run.json", "activation-runs.json",
    "decision-commit.json",
    "external-review-artifact.zip", "review-artifacts.json",
    "review-jobs.json", "review-run.json", "signed-review-artifact.zip",
    "workflow-state-after.json", "workflow-state-before.json",
    "workflow-state-cleanup.json", "workflow-run-event.json",
)
GENERATED_ACTIVATION_ARTIFACT_MEMBERS = tuple(sorted((
    "activation-record.json",
    "activation-subject.json",
    "canonical-binary-full-index.diff",
    "external-review/external-activation-review-receipt.json",
    "external-review/external-activation-review-receipt.sigstore.json",
    "generated-activation-evidence.sigstore.json",
    "name-status-find-renames-50.z",
    "raw-provenance.json",
    *(f"raw/{name}" for name in ACTIVATION_RAW_PROVENANCE_FILES),
    "raw-full-index-find-renames-50.z",
    "raw-status-authoritative.z",
    "signed-review/kanban-review-envelope.json",
    "signed-review/preissuance-review-receipt.json",
    "signed-review/preissuance-review-receipt.sigstore.json",
)))
GENERATED_ARTIFACT_ARCHIVES = {
    "raw/external-review-artifact.zip": (
        "external-review/external-activation-review-receipt.json",
        "external-review/external-activation-review-receipt.sigstore.json",
    ),
    "raw/signed-review-artifact.zip": (
        "signed-review/kanban-review-envelope.json",
        "signed-review/preissuance-review-receipt.json",
        "signed-review/preissuance-review-receipt.sigstore.json",
    ),
}
GENERATED_ARTIFACT_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(
        rb"(?ix)[\"']?authorization[\"']?\s*[:=]\s*[\"']?\s*"
        rb"(?:bearer|basic)\s+[A-Za-z0-9._~+:/=-]+"
    ),
    re.compile(rb"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(rb"(?i)(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(
        rb"(?ix)[\"']?aws[\s_.-]*(?:access[\s_.-]*key[\s_.-]*id|"
        rb"secret[\s_.-]*access[\s_.-]*key|session[\s_.-]*token)"
        rb"[\"']?\s*[:=]\s*[\"']?\s*[A-Za-z0-9_./+=-]{16,}"
    ),
)
ACTIVATION_RECORD_RUN_KEYS = (
    "activation_head_sha", "decision_sha", "job_id", "job_name", "ref",
    "repository", "review_head_sha", "run_attempt", "run_id", "sha",
    "signing_window_end", "signing_window_start",
)
ACTIVATION_TERMINAL_RECEIPT_TYPE = (
    "acc-authority-v2-terminal-activation-readback"
)
ACTIVATION_ARTIFACT_NAME = (
    "authority-v2-generated-activation-evidence-t_c298fca4"
)
ACTIVATION_COLLECTOR_WORKFLOW_PATH = (
    ".github/workflows/readback-authority-v2-activation.yml"
)
ACTIVATION_COLLECTOR_IDENTITY = (
    "https://github.com/chrizzatsu/acc-authority-independent-review/"
    ".github/workflows/readback-authority-v2-activation.yml@refs/heads/main"
)
ACTIVATION_CLEANUP_STEP_NAME = (
    "Reassert disabled state and delete ephemeral bytes"
)
ACTIVATION_ARTIFACT_CONTENT_DIGEST_ALGORITHM = (
    "sha256(acc-authority-v2-generated-activation-artifact\\0 || "
    "sorted(uint64be(len(name))||name||uint64be(len(bytes))||bytes))"
)
COLLECTOR_FRESH_ATTESTATION_KEYS = (
    "generator", "generator_binary_sha256", "generator_platform",
    "generator_version", "rekor_generation", "rekor_log_key_algorithm",
    "route", "signer_signature_algorithm", "signing_window_end",
    "signing_window_start", "timestamp",
)
COLLECTOR_FRESH_PROVENANCE_KEYS = (
    *COLLECTOR_FRESH_ATTESTATION_KEYS,
    "bundle_sha256", "job_id", "run_attempt", "run_id", "workflow_sha",
)
COLLECTOR_FULCIO_CLAIM_KEYS = (
    "build_config_digest", "build_config_uri", "build_trigger", "identity",
    "issuer", "source_repository_ref", "source_repository_uri",
)
MAXIMUM_TERMINAL_STEP_NUMBER = 2 ** 31 - 1
MAXIMUM_TERMINAL_TIMESTAMP = 2 ** 63 - 1
TERMINAL_INTEGER_LIMITS = {
    ("attestation", "signing_window_start"): (
        1, MAXIMUM_TERMINAL_TIMESTAMP,
    ),
    ("attestation", "signing_window_end"): (
        1, MAXIMUM_TERMINAL_TIMESTAMP,
    ),
    ("contract", "run_attempt"): (RUN_ATTEMPT, RUN_ATTEMPT),
    ("run", "id"): (MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID),
    ("run", "repository_id"): (
        MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID,
    ),
    ("run", "run_attempt"): (RUN_ATTEMPT, RUN_ATTEMPT),
    ("run", "workflow_id"): (
        MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID,
    ),
    ("job", "completed_at"): (1, MAXIMUM_TERMINAL_TIMESTAMP),
    ("job", "id"): (MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID),
    ("job", "run_attempt"): (RUN_ATTEMPT, RUN_ATTEMPT),
    ("job", "run_id"): (MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID),
    ("job", "started_at"): (1, MAXIMUM_TERMINAL_TIMESTAMP),
    ("artifact", "id"): (MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID),
    ("artifact", "matching_count"): (1, 1),
    ("artifact", "run_id"): (
        MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID,
    ),
    ("artifact", "size_in_bytes"): (1, MAXIMUM_ARTIFACT_BYTES),
    ("cleanup", "number"): (1, MAXIMUM_TERMINAL_STEP_NUMBER),
    ("cleanup", "workflow_id"): (
        MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID,
    ),
    ("collector", "job_id"): (
        MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID,
    ),
    ("collector", "run_attempt"): (RUN_ATTEMPT, RUN_ATTEMPT),
    ("collector", "run_id"): (
        MINIMUM_CANONICAL_ID, MAXIMUM_CANONICAL_ID,
    ),
}


def _terminal_activation_contract():
    return {
        "activation_artifact_name": ACTIVATION_ARTIFACT_NAME,
        "activation_job_name": ACTIVATION_JOB_NAME,
        "activation_workflow_path": ACTIVATION.TARGET_WORKFLOW_PATHS[
            ACTIVATION.INDEPENDENT_REPOSITORY
        ],
        "artifact_content_digest_algorithm": (
            ACTIVATION_ARTIFACT_CONTENT_DIGEST_ALGORITHM
        ),
        "collector_workflow_path": ACTIVATION_COLLECTOR_WORKFLOW_PATH,
        "default_branch": DEFAULT_BRANCH,
        "default_branch_ref": DEFAULT_REF,
        "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
        "run_attempt": RUN_ATTEMPT,
        "trigger_event": "workflow_run",
    }


def _require_terminal_integer(value, label, minimum, maximum):
    require(
        type(value) is int,
        f"{label} must be an integer, never a boolean",
    )
    require(
        minimum <= value <= maximum,
        f"{label} is outside its exact allowed range",
    )
    return value


def _require_terminal_integers(receipt):
    for path, limits in TERMINAL_INTEGER_LIMITS.items():
        section, field = path
        _require_terminal_integer(
            receipt[section][field],
            f"terminal activation {section} {field}",
            *limits,
        )


def _require_terminal_attestation(receipt):
    attestation = _require_exact_members(
        receipt["attestation"],
        COLLECTOR_FRESH_ATTESTATION_KEYS,
        "terminal activation attestation",
    )
    expected = {
        "generator": COSIGN_V3_1_3_GENERATOR,
        "generator_binary_sha256": ACTIVATION_GENERATOR_BINARY_SHA256,
        "generator_platform": ACTIVATION_GENERATOR_PLATFORM,
        "generator_version": ACTIVATION_EVIDENCE_CONTRACT["generator_version"],
        "rekor_generation": SIGSTORE.REKOR_V2,
        "rekor_log_key_algorithm": ACTIVATION_REKOR_LOG_KEY_DETAILS,
        "route": ACTIVATION_EVIDENCE_CONTRACT["route"],
        "signer_signature_algorithm": ACTIVATION_SIGNER_SIGNATURE_ALGORITHM,
        "timestamp": "rfc3161",
    }
    require(
        all(attestation[field] == value for field, value in expected.items()),
        "terminal activation attestation generator route is substituted",
    )
    start = attestation["signing_window_start"]
    end = attestation["signing_window_end"]
    require(
        type(start) is int and type(start) is not bool
        and type(end) is int and type(end) is not bool
        and 0 < start <= end and end - start <= MAXIMUM_SIGNING_WINDOW_SECONDS,
        "terminal activation attestation window is malformed",
    )
    return attestation


def _terminal_receipt_sections(receipt):
    specifications = {
        "run": (
            "conclusion", "event", "head_branch", "head_sha", "id", "path",
            "repository_id", "run_attempt", "status", "workflow_id",
        ),
        "job": (
            "completed_at", "conclusion", "head_sha", "id", "name",
            "run_attempt", "run_id", "started_at", "status",
        ),
        "artifact": (
            "activation_record_sha256", "archive_download_url", "archive_sha256",
            "content_sha256", "digest", "expired", "head_sha", "id",
            "matching_count", "name", "run_id", "size_in_bytes", "url",
        ),
        "cleanup": (
            "conclusion", "number", "path", "result", "state", "status",
            "step_name", "workflow_id",
        ),
        "collector": (
            "event", "job_id", "ref", "repository", "run_attempt", "run_id",
            "sha", "workflow_path",
        ),
    }
    return {
        name: _require_exact_members(
            receipt[name], members, f"terminal activation {name}",
        )
        for name, members in specifications.items()
    }


def _require_terminal_ids(sections):
    run, job = sections["run"], sections["job"]
    artifact, collector = sections["artifact"], sections["collector"]
    for value, label in (
        (run["id"], "run id"), (run["repository_id"], "repository id"),
        (run["workflow_id"], "workflow id"), (job["id"], "job id"),
        (artifact["id"], "artifact id"),
        (collector["run_id"], "collector run id"),
        (collector["job_id"], "collector job id"),
    ):
        _require_canonical_id(value, f"terminal activation {label}")


def _require_terminal_run_binding(sections, contract):
    run, job, artifact = (
        sections["run"], sections["job"], sections["artifact"]
    )
    require(
        run["run_attempt"] == RUN_ATTEMPT
        and type(run["run_attempt"]) is int
        and type(run["run_attempt"]) is not bool
        and run["status"] == job["status"] == "completed"
        and run["conclusion"] == job["conclusion"] == "success",
        "terminal activation run or job is missing, nonterminal, or failed",
    )
    head = _require_non_synthetic_digest(
        run["head_sha"], "terminal activation head", pattern=HEX40,
    )
    require(
        run["event"] == "workflow_run"
        and run["path"] == contract["activation_workflow_path"]
        and run["head_branch"] == DEFAULT_BRANCH
        and job["run_id"] == artifact["run_id"] == run["id"]
        and job["run_attempt"] == RUN_ATTEMPT and job["head_sha"] == head
        and job["started_at"] <= job["completed_at"]
        and job["name"] == ACTIVATION_JOB_NAME and artifact["head_sha"] == head
        and artifact["name"] == ACTIVATION_ARTIFACT_NAME
        and artifact["matching_count"] == 1
        and type(artifact["matching_count"]) is int
        and type(artifact["matching_count"]) is not bool,
        "terminal activation artifact is missing, duplicated, or substituted",
    )
    return head


def _require_terminal_collector(collector, head):
    require(
        collector == {
            "event": "workflow_run", "job_id": collector["job_id"],
            "ref": DEFAULT_REF, "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "run_attempt": RUN_ATTEMPT, "run_id": collector["run_id"],
            "sha": head, "workflow_path": ACTIVATION_COLLECTOR_WORKFLOW_PATH,
        },
        "terminal activation collector identity is substituted",
    )


def _require_terminal_artifact(receipt, artifact):
    require(
        type(artifact["digest"]) is str
        and artifact["digest"].startswith("sha256:"),
        "terminal activation artifact digest is malformed",
    )
    _require_non_synthetic_digest(
        artifact["digest"][7:], "terminal activation artifact digest",
    )
    for field in ("archive_sha256", "content_sha256",
                  "activation_record_sha256"):
        _require_non_synthetic_digest(
            artifact[field], f"terminal activation artifact {field}",
        )
    repository_api = (
        f"https://api.github.com/repos/{ACTIVATION.INDEPENDENT_REPOSITORY}/"
        f"actions/artifacts/{artifact['id']}"
    )
    require(
        artifact["digest"] == f"sha256:{artifact['archive_sha256']}"
        and artifact["activation_record_sha256"]
        == receipt["activation_record_sha256"]
        and artifact["expired"] is False
        and type(artifact["size_in_bytes"]) is int
        and type(artifact["size_in_bytes"]) is not bool
        and artifact["size_in_bytes"] > 0 and artifact["url"] == repository_api
        and artifact["archive_download_url"] == f"{repository_api}/zip",
        "terminal activation artifact archive or content identity mismatch",
    )


def _require_terminal_cleanup(cleanup, run, contract):
    require(
        cleanup == {
            "conclusion": "success", "number": cleanup["number"],
            "path": contract["activation_workflow_path"], "result": "success",
            "state": "disabled_manually", "status": "completed",
            "step_name": ACTIVATION_CLEANUP_STEP_NAME,
            "workflow_id": run["workflow_id"],
        }
        and type(cleanup["number"]) is int
        and type(cleanup["number"]) is not bool and cleanup["number"] > 0,
        "terminal activation cleanup did not succeed with workflow disabled",
    )


def _require_terminal_activation_receipt(receipt):
    """Verify facts collected only after the activation run completed."""
    _require_exact_members(
        receipt,
        ("activation_record_sha256", "artifact", "attestation", "cleanup",
         "collector", "contract", "job", "record_type", "run"),
        "terminal activation receipt",
    )
    require(
        receipt["record_type"] == ACTIVATION_TERMINAL_RECEIPT_TYPE,
        "terminal activation receipt type mismatch",
    )
    _require_non_synthetic_digest(
        receipt["activation_record_sha256"], "terminal activation record digest",
    )
    expected_contract = _terminal_activation_contract()
    contract = _require_exact_members(
        receipt["contract"], tuple(expected_contract),
        "terminal activation contract",
    )
    require(
        contract == expected_contract,
        "terminal activation receipt does not bind the production contract",
    )
    _require_terminal_attestation(receipt)
    sections = _terminal_receipt_sections(receipt)
    _require_terminal_integers(receipt)
    _require_terminal_ids(sections)
    head = _require_terminal_run_binding(sections, contract)
    _require_terminal_collector(sections["collector"], head)
    _require_terminal_artifact(receipt, sections["artifact"])
    _require_terminal_cleanup(sections["cleanup"], sections["run"], contract)
    return True


def _resolve_artifact_members(root, values, label):
    """Resolve unique canonical POSIX members without crossing a symlink."""
    root_path = Path(root)
    require(
        root_path.is_dir() and not root_path.is_symlink(),
        f"{label} root is absent or unsafe",
    )
    try:
        resolved_root = root_path.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as error:
        raise SystemExit(f"{label} root cannot be resolved") from error
    require(
        type(values) in (tuple, list),
        f"{label} member inventory is malformed",
    )
    resolved_members = {}
    normalized_targets = set()
    for value in values:
        require(
            type(value) is str and value and "\\" not in value
            and not value.startswith("/"),
            f"{label} is not a closed artifact-relative path: {value!r}",
        )
        parts = value.split("/")
        require(
            parts and all(part not in ("", ".", "..") for part in parts)
            and PurePosixPath(*parts).as_posix() == value,
            f"{label} is not a canonical artifact-relative path: {value!r}",
        )
        require(
            value not in resolved_members,
            f"{label} repeats a normalized target: {value}",
        )
        candidate = root_path
        for index, part in enumerate(parts):
            candidate = candidate / part
            require(
                not candidate.is_symlink(),
                f"{label} escapes the activation artifact root or crosses "
                f"a symbolic link: {value}",
            )
            if index < len(parts) - 1:
                require(
                    candidate.is_dir(),
                    f"{label} ancestor is absent or unsafe: {value}",
                )
        require(
            candidate.is_file(),
            f"{label} is not a closed artifact-relative regular file: {value}",
        )
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, RuntimeError, OSError) as error:
            raise SystemExit(
                f"{label} is not a closed artifact-relative regular file: {value}"
            ) from error
        require(
            resolved.parent == resolved_root or resolved_root in resolved.parents,
            f"{label} escapes the activation artifact root: {value}",
        )
        target = resolved.as_posix()
        require(
            target not in normalized_targets,
            f"{label} repeats a normalized target: {value}",
        )
        normalized_targets.add(target)
        resolved_members[value] = resolved
    return resolved_members


def _artifact_relative_path(record_path, value, label):
    """Resolve one declared member through the shared closed resolver."""
    return _resolve_artifact_members(
        Path(record_path).parent, (value,), label,
    )[value]


def _require_exact_members(payload, keys, label):
    """A closed object: exactly these members, no more and no fewer."""
    require(
        isinstance(payload, Mapping)
        and tuple(sorted(payload)) == tuple(sorted(keys)),
        f"{label} field set is not the canonical "
        f"{{{', '.join(sorted(keys))}}}",
    )
    return payload


GITHUB_COMMIT_PARENT_KEYS = ("html_url", "sha", "url")


def _github_commit_parent_shas(commit, repository, label):
    """Validate GitHub's real commit parent objects and project their SHAs."""
    require(
        isinstance(commit, Mapping) and "parents" in commit,
        f"{label} omits parents",
    )
    parents = commit["parents"]
    require(type(parents) is list, f"{label} parents are malformed")
    projected = []
    for index, parent in enumerate(parents):
        parent_label = f"{label} parent {index}"
        _require_exact_members(parent, GITHUB_COMMIT_PARENT_KEYS, parent_label)
        sha = parent["sha"]
        require(
            type(sha) is str and HEX40.fullmatch(sha) is not None,
            f"{parent_label} SHA is malformed",
        )
        require(
            type(parent["url"]) is str
            and parent["url"]
            == f"{API_ROOT}/repos/{repository}/commits/{sha}",
            f"{parent_label} API URL is malformed or substituted",
        )
        require(
            type(parent["html_url"]) is str
            and parent["html_url"]
            == f"https://github.com/{repository}/commit/{sha}",
            f"{parent_label} HTML URL is malformed or substituted",
        )
        projected.append(sha)
    return projected


def _activation_subject_bytes(candidate_head, candidate_tree, diffs):
    """The exact candidate-specific bytes the activation evidence signs."""
    return json.dumps(
        {
            "candidate_diff_sha256": {
                name: diffs[name]
                for name in ACTIVATION_CANDIDATE_DIFF_STREAMS
            },
            "candidate_head": candidate_head,
            "candidate_tree": candidate_tree,
            "repository": ACTIVATION.INDEPENDENT_REPOSITORY,
            "subject_type": ACTIVATION_SUBJECT_TYPE,
        },
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def _approved_generator_binary_digest():
    """The exact Cosign v3.1.3 digest sealed into this standalone verifier."""
    return ACTIVATION_GENERATOR_BINARY_SHA256


def _require_raw_activation_provenance(member, *, record_path, run):
    """Bind the closed raw GitHub readback inventory to this exact run."""
    label = "activation evidence raw provenance"
    _require_exact_members(member, ACTIVATION_RECORD_OUTPUT_KEYS, label)
    declared = _require_non_synthetic_digest(
        member["sha256"], f"{label} digest",
    )
    path = _artifact_relative_path(record_path, member["path"], label)
    data = path.read_bytes()
    require(
        hashlib.sha256(data).hexdigest() == declared,
        f"{label} is not the exact closed record it names",
    )
    document = ACTIVATION._closed_json(data, label)
    _require_exact_members(document, ACTIVATION_RAW_PROVENANCE_KEYS, label)
    require(
        document["record_type"] == ACTIVATION_RAW_PROVENANCE_TYPE,
        f"{label} record type mismatch",
    )
    files = document["files"]
    _require_exact_members(files, ACTIVATION_RAW_PROVENANCE_FILES, label)
    raw_members = _resolve_artifact_members(
        path.parent,
        tuple(f"raw/{name}" for name in ACTIVATION_RAW_PROVENANCE_FILES),
        label,
    )
    observed = {}
    for name in ACTIVATION_RAW_PROVENANCE_FILES:
        expected = _require_non_synthetic_digest(
            files[name], f"{label} {name} digest",
        )
        candidate = raw_members[f"raw/{name}"]
        payload = candidate.read_bytes()
        require(
            hashlib.sha256(payload).hexdigest() == expected,
            f"{label} member digest mismatch: {name}",
        )
        if name.endswith(".json"):
            try:
                observed[name] = json.loads(payload)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise SystemExit(f"{label} member is not JSON: {name}") from error
        else:
            observed[name] = payload

    activation = observed["activation-run.json"]
    require(
        type(activation) is dict
        and activation.get("id") == run["run_id"]
        and activation.get("run_attempt") == RUN_ATTEMPT
        and activation.get("event") == "workflow_run"
        and activation.get("head_branch") == DEFAULT_BRANCH
        and activation.get("head_sha") == run["sha"]
        and activation.get("path")
        == ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY],
        f"{label} activation run readback mismatch",
    )
    review_head = run["review_head_sha"]
    decision_sha = run["decision_sha"]
    activation_head = run["activation_head_sha"]
    event = observed["workflow-run-event.json"]
    decision = observed["decision-commit.json"]
    decision_parents = _github_commit_parent_shas(
        decision,
        ACTIVATION.INDEPENDENT_REPOSITORY,
        f"{label} decision commit",
    )
    require(
        review_head != decision_sha
        and decision_sha == activation_head == run["sha"]
        and type(event) is dict
        and type(event.get("workflow_run")) is dict
        and event["workflow_run"].get("head_sha") == review_head
        and type(decision) is dict and decision.get("sha") == decision_sha
        and decision_parents == [review_head],
        f"{label} H-to-D workflow_run causal binding mismatch",
    )
    def exhaustive_members(name, member_name):
        pages = observed[name]
        require(
            type(pages) is list and pages,
            f"{label} {name} is not an exhaustive page traversal",
        )
        members = []
        totals = []
        for page in pages:
            require(
                type(page) is dict
                and type(page.get("total_count")) is int
                and type(page["total_count"]) is not bool
                and type(page.get(member_name)) is list,
                f"{label} {name} page is malformed",
            )
            totals.append(page["total_count"])
            members.extend(page[member_name])
        require(
            len(set(totals)) == 1 and totals[0] == len(members),
            f"{label} {name} traversal is incomplete",
        )
        return members

    jobs = exhaustive_members("activation-jobs.json", "jobs")
    matching = [
        job for job in jobs or []
        if type(job) is dict and job.get("name") == ACTIVATION_JOB_NAME
    ]
    require(
        len(matching) == 1
        and matching[0].get("id") == run["job_id"]
        and matching[0].get("run_id") == run["run_id"]
        and matching[0].get("run_attempt") == RUN_ATTEMPT
        and matching[0].get("head_sha") == run["sha"],
        f"{label} activation job readback mismatch",
    )
    require(
        _epoch(matching[0].get("started_at"), f"{label} job start")
        == run["signing_window_start"],
        f"{label} signing window is not the authenticated job start",
    )
    runs = exhaustive_members("activation-runs.json", "workflow_runs")
    unique = [
        item for item in runs or []
        if type(item) is dict and item.get("event") == "workflow_run"
    ]
    require(
        len(unique) == 1 and unique[0].get("id") == run["run_id"]
        and unique[0].get("run_attempt") == RUN_ATTEMPT,
        f"{label} does not prove one globally unique activation run",
    )
    review = observed["review-run.json"]
    review_id = review.get("id") if type(review) is dict else None
    _require_canonical_id(review_id, f"{label} review run id")
    require(
        review.get("run_attempt") == RUN_ATTEMPT
        and review.get("event") == TRIGGER
        and review.get("status") == "completed"
        and review.get("conclusion") == "success"
        and review.get("head_sha") == review_head
        and event["workflow_run"].get("id") == review_id
        and review.get("path")
        == ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY],
        f"{label} immutable review run mismatch",
    )
    review_jobs = exhaustive_members("review-jobs.json", "jobs")
    selected = [
        job for job in review_jobs or []
        if type(job) is dict and job.get("name") == INDEPENDENT_JOB_NAME
        and job.get("run_id") == review_id
        and job.get("run_attempt") == RUN_ATTEMPT
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
    ]
    require(
        len(selected) == 1,
        f"{label} immutable review job is absent or ambiguous",
    )
    artifacts = exhaustive_members("review-artifacts.json", "artifacts")
    required_artifacts = {
        "authority-v2-signed-review-t_c298fca4",
        "authority-v2-external-activation-review-t_c298fca4",
    }
    selected_artifacts = [
        artifact for artifact in artifacts or []
        if type(artifact) is dict
        and artifact.get("name") in required_artifacts
        and artifact.get("expired") is False
        and type(artifact.get("workflow_run")) is dict
        and artifact["workflow_run"].get("id") == review_id
    ]
    require(
        len(selected_artifacts) == len(required_artifacts)
        and {item["name"] for item in selected_artifacts} == required_artifacts,
        f"{label} immutable review artifact inventory mismatch",
    )
    for artifact in selected_artifacts:
        _require_canonical_id(artifact.get("id"), f"{label} artifact id")
        digest = artifact.get("digest")
        require(
            type(digest) is str and digest.startswith("sha256:")
            and HEX64.fullmatch(digest[7:]) is not None,
            f"{label} artifact digest is malformed",
        )
        archive_name = (
            "signed-review-artifact.zip"
            if artifact["name"].startswith("authority-v2-signed-review-")
            else "external-review-artifact.zip"
        )
        require(
            digest == "sha256:" + hashlib.sha256(
                observed[archive_name]
            ).hexdigest(),
            f"{label} artifact archive is not the server-digested bytes",
        )
    for name in (
        "workflow-state-before.json", "workflow-state-after.json",
        "workflow-state-cleanup.json",
    ):
        state = observed[name]
        require(
            type(state) is dict
            and state.get("path")
            == ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY],
            f"{label} workflow state readback mismatch",
        )
    require(
        observed["workflow-state-after.json"].get("state")
        == observed["workflow-state-cleanup.json"].get("state")
        == "disabled_manually",
        f"{label} does not prove the activation workflow was disabled before generation",
    )
    return {
        name: run[name]
        for name in ACTIVATION_AUTHENTICATED_PROVENANCE_KEYS
    }


def _generated_archive_members(archive_path, expected, label):
    """Read one exact regular-file ZIP inventory without path aliases."""
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = _read_validated_zip(archive, expected, label)
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as error:
        raise SystemExit(f"{label} is not a safe exact ZIP") from error
    return members


def _require_generated_artifact_inventory(root):
    """Close every generated artifact byte before upload and after download."""
    root = Path(root)
    require(
        root.is_dir() and not root.is_symlink(),
        "generated activation artifact root is absent or unsafe",
    )
    observed = []
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        require(
            not candidate.is_symlink(),
            f"generated activation artifact carries a symbolic link: {relative}",
        )
        if candidate.is_dir():
            continue
        require(
            candidate.is_file(),
            f"generated activation artifact carries a non-file: {relative}",
        )
        data = candidate.read_bytes()
        require(data, f"generated activation artifact member is empty: {relative}")
        for pattern in GENERATED_ARTIFACT_SECRET_PATTERNS:
            require(
                pattern.search(data) is None,
                f"generated activation artifact carries secret-bearing bytes: "
                f"{relative}",
            )
        lowered = relative.lower()
        require(
            not any(term in lowered for term in (
                ".env", "credential", "private-key", "runtime-token",
            )),
            f"generated activation artifact carries a secret-bearing member: "
            f"{relative}",
        )
        observed.append(relative)
    require(
        tuple(sorted(observed)) == GENERATED_ACTIVATION_ARTIFACT_MEMBERS,
        "generated activation artifact inventory is missing or additional",
    )
    fixed_members = _resolve_artifact_members(
        root, GENERATED_ACTIVATION_ARTIFACT_MEMBERS,
        "generated activation artifact inventory",
    )

    record_path = fixed_members["activation-record.json"]
    record = ACTIVATION._closed_json(
        record_path.read_bytes(), "generated activation artifact record",
    )
    _require_exact_members(
        record, ACTIVATION_RECORD_KEYS, "generated activation artifact record",
    )
    bindings = {
        record["generated_output"]["path"]:
            record["generated_output"]["sha256"],
        record["generated_subject"]["path"]:
            record["generated_subject"]["sha256"],
        record["raw_provenance"]["path"]:
            record["raw_provenance"]["sha256"],
        **record["candidate"]["diff_sha256"],
    }
    expected_bindings = {
        ACTIVATION_EVIDENCE_OUTPUT_NAME,
        "activation-subject.json",
        "raw-provenance.json",
        *ACTIVATION_CANDIDATE_DIFF_STREAMS,
    }
    require(
        set(bindings) == expected_bindings,
        "generated activation artifact record paths are unbound or aliased",
    )
    bound_members = _resolve_artifact_members(
        root, tuple(bindings), "generated activation artifact record members",
    )
    for name, digest in bindings.items():
        _require_non_synthetic_digest(
            digest, f"generated activation artifact {name} digest",
        )
        require(
            hashlib.sha256(bound_members[name].read_bytes()).hexdigest() == digest,
            f"generated activation artifact record does not bind {name}",
        )

    raw_provenance = ACTIVATION._closed_json(
        fixed_members["raw-provenance.json"].read_bytes(),
        "generated activation raw provenance",
    )
    _require_exact_members(
        raw_provenance, ACTIVATION_RAW_PROVENANCE_KEYS,
        "generated activation raw provenance",
    )
    raw_files = raw_provenance["files"]
    _require_exact_members(
        raw_files, ACTIVATION_RAW_PROVENANCE_FILES,
        "generated activation raw provenance files",
    )
    raw_member_paths = _resolve_artifact_members(
        root, tuple(f"raw/{name}" for name in raw_files),
        "generated activation raw provenance members",
    )
    for name, digest in raw_files.items():
        _require_non_synthetic_digest(
            digest, f"generated activation raw provenance {name} digest",
        )
        require(
            hashlib.sha256(raw_member_paths[f"raw/{name}"].read_bytes()).hexdigest()
            == digest,
            f"generated activation raw provenance does not bind {name}",
        )

    for archive_name, extracted_paths in GENERATED_ARTIFACT_ARCHIVES.items():
        expected = tuple(Path(name).name for name in extracted_paths)
        archived = _generated_archive_members(
            fixed_members[archive_name], expected,
            f"generated artifact {archive_name}",
        )
        for extracted in extracted_paths:
            require(
                fixed_members[extracted].read_bytes()
                == archived[Path(extracted).name],
                f"generated activation artifact extracted member is not bound "
                f"to {archive_name}: {extracted}",
            )
    return True


def _require_generated_activation_run(record_path, *, root=ROOT):
    """Bind one authorized activation run to the bytes it really generated.

    Everything the record claims is bound before any of it is believed: the
    exact generator binary, the exact candidate identity and all four of its
    diff streams, the exact generated output bytes recomputed from disk, and
    the authenticated run, attempt, job and repository/ref/SHA this evidence
    was produced by. Only then are the output bytes offered to the
    generator-bound contract, and only bytes that contract accepts reach the
    cryptographic verifier and the exact Ed25519 / Rekor-v2 / RFC 3161 route
    requirement.

    Nothing here authorizes anything. It generates, signs, issues and
    dispatches nothing, and reaches no network; a successful return would
    still be builder evidence awaiting an independent review of its own.
    """
    label = "activation evidence record"
    path = Path(record_path)
    require(
        path.is_file() and not path.is_symlink(),
        f"{label} is absent or unsafe",
    )
    record = ACTIVATION._closed_json(path.read_bytes(), label)
    _require_exact_members(record, ACTIVATION_RECORD_KEYS, label)
    require(
        record["record_type"] == ACTIVATION_RECORD_TYPE,
        f"{label} is not a {ACTIVATION_RECORD_TYPE} record",
    )

    # -- the exact generator binary ----------------------------------------
    binary = record["generator_binary"]
    _require_exact_members(
        binary, ACTIVATION_RECORD_BINARY_KEYS, f"{label} generator binary",
    )
    require(
        binary["platform"] == ACTIVATION_GENERATOR_PLATFORM,
        f"{label} generator binary names platform "
        f"{binary['platform']!r}, not the pinned activation platform "
        f"{ACTIVATION_GENERATOR_PLATFORM!r}",
    )
    generator_binary_sha256 = _require_non_synthetic_digest(
        binary["sha256"], f"{label} generator binary digest",
    )
    require(
        generator_binary_sha256 == _approved_generator_binary_digest(),
        f"{label} generator binary digest is not the approved exact Cosign "
        f"v3.1.3 artifact this contract binds",
    )

    # -- the exact candidate identity, all four diff streams ---------------
    candidate = record["candidate"]
    _require_exact_members(
        candidate, ACTIVATION_RECORD_CANDIDATE_KEYS, f"{label} candidate",
    )
    candidate_head = _require_non_synthetic_digest(
        candidate["head"], f"{label} candidate head", pattern=HEX40,
    )
    candidate_tree = _require_non_synthetic_digest(
        candidate["tree"], f"{label} candidate tree", pattern=HEX40,
    )
    diffs = candidate["diff_sha256"]
    _require_exact_members(
        diffs, ACTIVATION_CANDIDATE_DIFF_STREAMS,
        f"{label} candidate diff streams",
    )
    diff_paths = _resolve_artifact_members(
        path.parent, ACTIVATION_CANDIDATE_DIFF_STREAMS,
        f"{label} candidate diff streams",
    )
    for name in ACTIVATION_CANDIDATE_DIFF_STREAMS:
        expected = _require_non_synthetic_digest(
            diffs[name], f"{label} candidate diff stream {name}",
        )
        stream_path = diff_paths[name]
        require(
            hashlib.sha256(stream_path.read_bytes()).hexdigest() == expected,
            f"{label} candidate diff stream is not the exact reviewed bytes: "
            f"{name}",
        )

    # -- the authenticated run this evidence was produced by ---------------
    run = record["run_provenance"]
    _require_exact_members(
        run, ACTIVATION_RECORD_RUN_KEYS, f"{label} run provenance",
    )
    require(
        run["repository"] == ACTIVATION.INDEPENDENT_REPOSITORY,
        f"{label} run provenance names repository {run['repository']!r}, not "
        f"the authorized activation repository "
        f"{ACTIVATION.INDEPENDENT_REPOSITORY!r}",
    )
    require(
        run["ref"] == DEFAULT_REF,
        f"{label} run provenance names ref {run['ref']!r}, not the authorized "
        f"activation ref {DEFAULT_REF!r}",
    )
    _require_non_synthetic_digest(
        run["sha"], f"{label} run provenance head sha", pattern=HEX40,
    )
    for field in ("review_head_sha", "decision_sha", "activation_head_sha"):
        _require_non_synthetic_digest(
            run[field], f"{label} causal {field}", pattern=HEX40,
        )
    _require_canonical_id(run["run_id"], f"{label} run provenance run id")
    _require_canonical_id(run["job_id"], f"{label} run provenance job id")
    require(
        run["run_attempt"] == RUN_ATTEMPT
        and type(run["run_attempt"]) is int
        and type(run["run_attempt"]) is not bool,
        f"{label} run provenance is not the sole authorized run attempt "
        f"{RUN_ATTEMPT}",
    )
    require(
        run["job_name"] == ACTIVATION_JOB_NAME,
        f"{label} run provenance names job {run['job_name']!r}, not the "
        f"separately triggered activation job {ACTIVATION_JOB_NAME!r}",
    )
    signing_window = _require_raw_activation_provenance(
        record["raw_provenance"], record_path=path, run=run,
    )

    # -- the exact generated output bytes, recomputed from disk ------------
    output = record["generated_output"]
    _require_exact_members(
        output, ACTIVATION_RECORD_OUTPUT_KEYS, f"{label} generated output",
    )
    declared_output = _require_non_synthetic_digest(
        output["sha256"], f"{label} generated output digest",
    )
    output_path = _artifact_relative_path(
        path, output["path"], f"{label} generated output",
    )
    bundle_bytes = output_path.read_bytes()
    require(
        hashlib.sha256(bundle_bytes).hexdigest() == declared_output,
        f"{label} generated output is not the exact bytes it names",
    )

    # -- the exact candidate-specific subject those bytes must sign ---------
    subject = record["generated_subject"]
    _require_exact_members(
        subject, ACTIVATION_RECORD_SUBJECT_KEYS, f"{label} generated subject",
    )
    declared_subject = _require_non_synthetic_digest(
        subject["sha256"], f"{label} generated subject digest",
    )
    subject_path = _artifact_relative_path(
        path, subject["path"], f"{label} generated subject",
    )
    subject_bytes = subject_path.read_bytes()
    require(
        hashlib.sha256(subject_bytes).hexdigest() == declared_subject,
        f"{label} generated subject is not the exact bytes it names",
    )
    # Recomputed from the candidate identity this record binds: evidence
    # generated for another candidate cannot be presented for this one.
    require(
        subject_bytes == _activation_subject_bytes(
            candidate_head, candidate_tree, diffs,
        ),
        f"{label} generated subject is not the canonical activation subject "
        f"of this exact candidate",
    )

    # -- and only now, the generator-bound contract itself ------------------
    generated = _require_generated_activation_evidence(
        bundle_bytes, declared=record["declaration"],
        generator_binary_sha256=generator_binary_sha256,
        candidate_head=candidate_head, candidate_tree=candidate_tree,
        authenticated_provenance=signing_window,
    )
    # Fresh bytes that cross the generation contract are always verified
    # cryptographically; no candidate-static digest register can short-circuit
    # or prevent this production route.
    parsed = SIGSTORE.parse_bundle(
        bundle_bytes, media_types=SIGSTORE_MEDIA_TYPES,
    )
    require(
        parsed.rekor_generation == SIGSTORE.REKOR_V2,
        f"{label} is not the bound {SIGSTORE.REKOR_V2} route",
    )
    require(
        bool(parsed.rfc3161_timestamps),
        f"{label} carries no RFC 3161 timestamp, which this route requires",
    )
    # The signer, as the transparency log itself recorded it. It is a Fulcio
    # workload key on P-256 - the only usable curve the pinned generator can
    # be asked for - and never the log's own key.
    require(
        parsed.body_key_details == ACTIVATION_SIGNER_BODY_KEY_DETAILS,
        f"{label} was signed with {parsed.body_key_details!r}, not the bound "
        f"signer key {ACTIVATION_SIGNER_BODY_KEY_DETAILS!r}",
    )
    require(
        parsed.binds_subject(subject_bytes),
        f"{label} generated evidence does not bind the exact candidate "
        f"activation subject it was supposed to sign",
    )
    verified = _verify_sigstore_bundle_route(
        bundle_bytes, subject_bytes=subject_bytes,
        trust=_load_pinned_sigstore_trust(root),
        signing_window=(generated["signing_window_start"],
                        generated["signing_window_end"]),
        generated_provenance=generated,
    )
    oidc_identity = _require_generated_activation_oidc_identity(
        _certificate_claims(verified["leaf_der"]), run,
    )
    # ... and the log that included it really is the pinned Ed25519 Rekor v2
    # log, proven from the pinned trust rather than from the bundle's claim.
    require(
        verified["rekor_key_details"] == ACTIVATION_REKOR_LOG_KEY_DETAILS,
        f"{label} was included in a log keyed "
        f"{verified['rekor_key_details']!r}, not the bound Ed25519 Rekor v2 "
        f"transparency log {ACTIVATION_REKOR_LOG_KEY_DETAILS!r}",
    )
    require(
        verified["signer_key_details"] == ACTIVATION_SIGNER_BODY_KEY_DETAILS,
        f"{label} signer key is not the bound "
        f"{ACTIVATION_SIGNER_BODY_KEY_DETAILS!r}",
    )
    return {
        "activation_authorized": False,
        "approved": False,
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "generated_activation_evidence": generated,
        "fulcio_oidc_identity": oidc_identity,
        "generator_binary_sha256": generator_binary_sha256,
        "raw_values_emitted": False,
        "rekor_generation": verified["rekor_generation"],
        "rekor_log_key_algorithm": verified["rekor_key_details"],
        "release_authorized": False,
        "route": ACTIVATION_EVIDENCE_CONTRACT["route"],
        "run_id": run["run_id"],
        "signer_signature_algorithm":
            ACTIVATION_EVIDENCE_CONTRACT["signer_signature_algorithm"],
    }


def _require_sigstore_evidence_provenance(bundle_bytes, *, declared, label):
    """The pinned provenance of these exact bytes, or a closed refusal.

    `declared` is whatever a caller claims produced them. A claim that does
    not match the pinned record for those exact bytes is refused, and a claim
    of the route this Authority does not hold is refused outright - so no
    other generator's evidence can ever be presented as Cosign's.
    """
    require(
        type(bundle_bytes) is bytes and bundle_bytes,
        f"{label} Sigstore evidence bytes are required",
    )
    require(
        declared != SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE["route"],
        f"{label} claims the {SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE['route']} "
        f"route, which is not available: "
        f"{SIGSTORE_EVIDENCE_ROUTE_UNAVAILABLE['reason']}",
    )
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    record = SIGSTORE_EVIDENCE_PROVENANCE.get(digest)
    require(
        record is not None,
        f"{label} Sigstore evidence provenance is not pinned: no immutable "
        f"record names what produced {digest}",
    )
    require(
        declared is None or declared == record["generator"],
        f"{label} Sigstore evidence was not produced by {declared!r}: the "
        f"pinned provenance of {digest} is {record['generator']!r}",
    )
    return dict(record)


BODY_KEY_DETAILS_CURVES = {
    "PKIX_ECDSA_P256_SHA_256": "secp256r1",
    "PKIX_ECDSA_P384_SHA_384": "secp384r1",
    "PKIX_ECDSA_P521_SHA_512": "secp521r1",
}
BODY_KEY_DETAILS_ED25519 = "PKIX_ED25519"


def _require_body_key_details(leaf, key_details, backend, label):
    """The body's declared key type really is the leaf's own public key type."""
    ec, ed25519 = backend["ec"], backend["ed25519"]
    public_key = leaf.public_key()
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        observed = BODY_KEY_DETAILS_ED25519
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        observed = {
            curve: name
            for name, curve in BODY_KEY_DETAILS_CURVES.items()
        }.get(public_key.curve.name, "")
    else:
        observed = ""
    require(
        observed and observed == key_details,
        f"{label} transparency verifier keyDetails {key_details!r} is not the "
        f"public key type of the certificate the body records",
    )


def _require_body_binds_bundle(parsed, digest, leaf_der, label):
    """The decoded transparency body is exactly this bundle, member by member.

    The body is the log's own statement about what was signed. Each member it
    records - the digest, the signature and the signing certificate - is
    required to be *equal* to the corresponding bundle member rather than
    merely present somewhere in the body bytes, so a body that records a
    different artifact, a different signature or a different certificate can
    never pass. The encodings differ by generation (Rekor v1 records a hex
    digest and a PEM certificate, Rekor v2 a base64 digest and DER rawBytes);
    the parser has already normalised both, so exactly one comparison stands
    here for both generations.
    """
    require(
        parsed.body_digest == digest,
        f"{label} transparency body does not bind the exact subject digest",
    )
    require(
        parsed.body_signature == parsed.signature,
        f"{label} transparency body does not bind the exact bundle signature",
    )
    require(
        parsed.body_certificate_der == leaf_der,
        f"{label} transparency body does not bind the leaf certificate",
    )


def _require_fresh_sigstore_provenance(
        bundle_bytes, provenance, signing_window, label):
    """Authenticate fresh Cosign bytes without a pre-existing digest list."""
    _require_exact_members(
        provenance, COLLECTOR_FRESH_PROVENANCE_KEYS,
        f"{label} fresh collector provenance",
    )
    expected = {
        "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "generator": COSIGN_V3_1_3_GENERATOR,
        "generator_binary_sha256": ACTIVATION_GENERATOR_BINARY_SHA256,
        "generator_platform": ACTIVATION_GENERATOR_PLATFORM,
        "generator_version": ACTIVATION_EVIDENCE_CONTRACT["generator_version"],
        "rekor_generation": SIGSTORE.REKOR_V2,
        "rekor_log_key_algorithm": ACTIVATION_REKOR_LOG_KEY_DETAILS,
        "route": ACTIVATION_EVIDENCE_CONTRACT["route"],
        "signer_signature_algorithm": ACTIVATION_SIGNER_SIGNATURE_ALGORITHM,
        "timestamp": "rfc3161",
    }
    require(
        all(provenance[field] == value for field, value in expected.items()),
        f"{label} fresh collector provenance is substituted",
    )
    _require_canonical_id(provenance["run_id"], f"{label} collector run id")
    _require_canonical_id(provenance["job_id"], f"{label} collector job id")
    require(
        provenance["run_attempt"] == RUN_ATTEMPT
        and type(provenance["run_attempt"]) is int
        and type(provenance["run_attempt"]) is not bool,
        f"{label} fresh collector attempt is malformed",
    )
    _require_non_synthetic_digest(
        provenance["workflow_sha"], f"{label} collector workflow SHA",
        pattern=HEX40,
    )
    start = provenance["signing_window_start"]
    end = provenance["signing_window_end"]
    require(
        type(start) is int and type(start) is not bool
        and type(end) is int and type(end) is not bool
        and (start, end) == signing_window
        and 0 < start <= end
        and end - start <= MAXIMUM_SIGNING_WINDOW_SECONDS,
        f"{label} fresh collector signing window is malformed",
    )
    return {"generator": COSIGN_V3_1_3_GENERATOR}


def _verify_sigstore_bundle_route(bundle_bytes, *, subject_bytes, trust,
                                 signing_window, generated_provenance=None,
                                 fresh_provenance=None):
    """The complete Sigstore verification route, for one bundle, end to end.

    Nothing here trusts a locally asserted success object. The trusted time is
    proven - by the log for Rekor v1, by the pinned RFC 3161 timestamp
    authority for Rekor v2. The leaf chains to an exactly pinned Fulcio root
    through the code-signing profile, is valid at that trusted time and really
    signs the exact subject bytes. The transparency entry binds those bytes
    and that certificate; its signed entry timestamp verifies against the
    pinned Rekor key on Rekor v1, where it stays mandatory; its inclusion
    proof recomputes the signed checkpoint root; and the checkpoint itself
    verifies against the pinned log identity and the pinned origin.

    This is the whole route every Authority boundary runs. The Fulcio workload
    claims a *particular* boundary additionally requires are enforced by its
    caller, over the leaf this returns.
    """
    require(
        type(bundle_bytes) is bytes and bundle_bytes,
        "Sigstore bundle bytes are required",
    )
    require(
        type(subject_bytes) is bytes and subject_bytes,
        "the exact Sigstore subject bytes are required",
    )
    require(
        type(trust) in (_PinnedSigstoreTrust, _SigstoreTrustRoot),
        "Sigstore verification requires pinned Fulcio and Rekor trust material",
    )
    require(
        generated_provenance is None or fresh_provenance is None,
        "Sigstore evidence carries conflicting fresh provenance routes",
    )
    backend = _cryptography()
    # One shared canonical contract with the Authority boundary: the real
    # Cosign v3.1.3 protobuf-JSON v0.3 shape, never a bespoke legacy one.
    parsed = SIGSTORE.parse_bundle(bundle_bytes, media_types=SIGSTORE_MEDIA_TYPES)
    chain_der = list(parsed.certificate_chain)
    entry = parsed.tlog_entry
    label = "Sigstore bundle"


    # A DSSE bundle carries the exact bytes it signs, so the caller's subject
    # must be those bytes and not merely hash to the same digest.
    if parsed.signed_content_member == SIGSTORE.DSSE_ENVELOPE_KEY:
        require(
            subject_bytes == parsed.dsse_subject,
            "Sigstore DSSE subject bytes are not the envelope this bundle signs",
        )

    integrated = _trusted_signing_time(parsed, trust, backend, label)
    require(
        type(signing_window) is tuple and len(signing_window) == 2
        and all(
            type(bound) is int and type(bound) is not bool
            for bound in signing_window
        )
        and signing_window[0] <= signing_window[1],
        "the authenticated signing window is malformed",
    )
    require(
        signing_window[0] <= integrated <= signing_window[1],
        "Sigstore trusted time is outside the authenticated run and job window",
    )
    log_key_id = parsed.log_key_id
    if type(trust) is _PinnedSigstoreTrust:
        # Only the pinned roots and the pinned log key that were valid at the
        # moment the transparency log integrated this entry may be used.
        trust = trust.select(integrated, log_key_id)
    else:
        require(
            log_key_id in (trust.log_id(), trust.log_key_id()),
            "Sigstore transparency entry names a different transparency log",
        )

    leaf = _verify_certificate_chain(
        chain_der, trust, backend, "Sigstore leaf", integrated_time=integrated,
    )

    signature = parsed.signature
    require(
        parsed.binds_subject(subject_bytes),
        "Sigstore message digest is not the exact subject digest",
    )
    _verify_subject_signature(leaf, signature, subject_bytes, backend)

    body_encoded = parsed.encoded_body
    body = parsed.canonicalized_body
    _require_body_binds_bundle(
        parsed, parsed.message_digest, parsed.leaf_der, label,
    )
    if parsed.is_rekor_v2:
        _require_body_key_details(
            leaf, parsed.body_key_details, backend, label,
        )
    if parsed.is_rekor_v2:
        # Rekor v2 publishes no signed entry timestamp at all; the trusted
        # time already came from the pinned RFC 3161 authority above.
        log_index = parsed.log_index
    else:
        # Rekor v1 is timestamped by the log, so its signed entry timestamp
        # stays mandatory and must verify against the pinned Rekor key.
        log_index = _verify_signed_entry_timestamp(
            entry, body_encoded, integrated, trust, backend,
        )

    proof = parsed.inclusion_proof
    proof_index = proof.get("logIndex")
    tree_size = proof.get("treeSize")
    if type(proof_index) is str and re.fullmatch(r"[0-9]+", proof_index):
        proof_index = int(proof_index)
    if type(tree_size) is str and re.fullmatch(r"[1-9][0-9]*", tree_size):
        tree_size = int(tree_size)
    require(
        type(proof_index) is int and type(tree_size) is int
        and type(proof_index) is not bool and type(tree_size) is not bool,
        "Rekor inclusion proof coordinates are malformed",
    )
    require(
        proof_index == log_index,
        "Rekor inclusion proof is for a different log entry",
    )
    hashes_ = proof.get("hashes")
    require(type(hashes_) is list, "Rekor inclusion proof carries no hashes")
    path = []
    for value in hashes_:
        require(type(value) is str, "Rekor inclusion proof hash is malformed")
        try:
            path.append(base64.b64decode(value, validate=True))
        except (ValueError, TypeError) as error:
            raise SystemExit("Rekor inclusion proof hash is not base64") from error
    root = proof.get("rootHash")
    require(type(root) is str and root, "Rekor inclusion proof carries no root hash")
    try:
        expected_root = base64.b64decode(root, validate=True)
    except (ValueError, TypeError) as error:
        raise SystemExit("Rekor inclusion proof root is not base64") from error
    leaf_hash = hashlib.sha256(b"\x00" + body).digest()
    require(
        _rfc6962_root(leaf_hash, proof_index, tree_size, path) == expected_root,
        "Rekor inclusion proof does not recompute the checkpoint root",
    )
    checkpoint = proof.get("checkpoint")
    require(
        type(checkpoint) is dict and type(checkpoint.get("envelope")) is str,
        "Rekor checkpoint is absent",
    )
    _verify_checkpoint(checkpoint["envelope"], root, trust, backend)
    # Everything cryptographic has now held. Rekor v2 evidence additionally
    # needs one complete immutable provenance route: a pinned held vector, or
    # the closed binary/candidate/output/run provenance of a fresh activation.
    # This runs last so it can never mask a cryptographic refusal, and Rekor v1
    # is untouched by it.
    provenance = {}
    if parsed.is_rekor_v2:
        if fresh_provenance is not None:
            provenance = _require_fresh_sigstore_provenance(
                bundle_bytes, fresh_provenance, signing_window, label,
            )
        elif generated_provenance is None:
            provenance = _require_sigstore_evidence_provenance(
                bundle_bytes, declared=None, label=label,
            )
        else:
            _require_exact_members(
                generated_provenance, ACTIVATION_GENERATED_PROVENANCE_KEYS,
                "fresh Sigstore evidence provenance",
            )
            require(
                generated_provenance["activation_evidence_sha256"]
                == hashlib.sha256(bundle_bytes).hexdigest()
                and generated_provenance["generator_binary_sha256"]
                == ACTIVATION_GENERATOR_BINARY_SHA256,
                "fresh Sigstore evidence is not bound to its authenticated "
                "generator provenance",
            )
            _require_non_synthetic_digest(
                generated_provenance["candidate_head"],
                "fresh Sigstore evidence candidate head", pattern=HEX40,
            )
            _require_non_synthetic_digest(
                generated_provenance["candidate_tree"],
                "fresh Sigstore evidence candidate tree", pattern=HEX40,
            )
            _require_canonical_id(
                generated_provenance["run_id"],
                "fresh Sigstore evidence run id",
            )
            _require_canonical_id(
                generated_provenance["job_id"],
                "fresh Sigstore evidence job id",
            )
            require(
                generated_provenance["run_attempt"] == RUN_ATTEMPT
                and (
                    generated_provenance["signing_window_start"],
                    generated_provenance["signing_window_end"],
                ) == signing_window,
                "fresh Sigstore evidence run attempt or signing window is not "
                "the authenticated production value",
            )
            provenance = {"generator": COSIGN_V3_1_3_GENERATOR}
    return {
        "evidence_generator": provenance.get("generator", ""),
        "integrated_time": integrated,
        "leaf_der": chain_der[0],
        "log_index": log_index,
        "rekor_generation": parsed.rekor_generation,
        # The two keys, reported apart so no caller can confuse them: the
        # transparency log's own key algorithm from the pinned trust, and the
        # signer's key algorithm as the log itself recorded it.
        "rekor_key_details": trust.rekor_key_details,
        "rekor_origin": trust.rekor_origin,
        "signed_content_member": parsed.signed_content_member,
        "signer_key_details": parsed.body_key_details,
    }


def _verify_sigstore_bundle(bundle_bytes, *, subject_bytes, trust,
                                      repository, workflow_path,
                                      workflow_sha, signing_window,
                                      workflow_trigger=TRIGGER):
    """The full route, plus the Fulcio workload claims this boundary requires.

    Everything cryptographic happens in `_verify_sigstore_bundle_route`, which
    is the one route every Sigstore bundle takes. Only once it has authorised
    the leaf are the GitHub Actions workload claims of *this* Authority's own
    receipts enforced on top of it.
    """
    verified = _verify_sigstore_bundle_route(
        bundle_bytes, subject_bytes=subject_bytes, trust=trust,
        signing_window=signing_window,
    )
    claims = _certificate_claims(verified["leaf_der"])
    expected_identity = (
        f"https://github.com/{repository}/{workflow_path}@{DEFAULT_REF}"
    )
    require(
        claims.get("identity") == expected_identity,
        "Sigstore certificate identity mismatch",
    )
    require(claims.get("issuer") == OIDC_ISSUER, "Sigstore OIDC issuer mismatch")
    require(
        claims.get("source_repository_uri") == f"https://github.com/{repository}",
        "Sigstore certificate source repository mismatch",
    )
    require(
        claims.get("source_repository_ref") == DEFAULT_REF,
        "Sigstore certificate ref is not refs/heads/main",
    )
    require(
        claims.get("build_config_uri") == expected_identity,
        "Sigstore certificate workflow path mismatch",
    )
    require(
        claims.get("build_config_digest") == workflow_sha,
        "Sigstore certificate workflow SHA mismatch",
    )
    require(
        claims.get("build_trigger") == workflow_trigger,
        f"Sigstore certificate build trigger is not {workflow_trigger}",
    )
    return {
        "integrated_time": verified["integrated_time"],
        "log_index": verified["log_index"],
        "certificate_workflow_sha": claims["build_config_digest"],
        "identity": claims["identity"],
    }


def _verify_terminal_sigstore_bundle(
        bundle_bytes, *, subject_bytes, trust, receipt):
    """Verify one fresh collector bundle through its signed run provenance."""
    _require_terminal_activation_receipt(receipt)
    attestation = receipt["attestation"]
    collector = receipt["collector"]
    provenance = {
        **attestation,
        "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "job_id": collector["job_id"],
        "run_attempt": collector["run_attempt"],
        "run_id": collector["run_id"],
        "workflow_sha": collector["sha"],
    }
    verified = _verify_sigstore_bundle_route(
        bundle_bytes,
        subject_bytes=subject_bytes,
        trust=trust,
        signing_window=(
            attestation["signing_window_start"],
            attestation["signing_window_end"],
        ),
        fresh_provenance=provenance,
    )
    require(
        verified["evidence_generator"] == COSIGN_V3_1_3_GENERATOR
        and verified["rekor_generation"] == SIGSTORE.REKOR_V2
        and verified["rekor_key_details"] == ACTIVATION_REKOR_LOG_KEY_DETAILS
        and verified["signer_key_details"]
        == ACTIVATION_SIGNER_BODY_KEY_DETAILS,
        "terminal Sigstore bundle did not use exact Cosign v3.1.3 P-256, "
        "Ed25519 Rekor v2 and RFC 3161 provenance",
    )
    claims = _certificate_claims(verified["leaf_der"])
    expected_claims = {
        "identity": ACTIVATION_COLLECTOR_IDENTITY,
        "issuer": OIDC_ISSUER,
        "source_repository_uri": (
            f"https://github.com/{ACTIVATION.INDEPENDENT_REPOSITORY}"
        ),
        "source_repository_ref": DEFAULT_REF,
        "build_config_uri": ACTIVATION_COLLECTOR_IDENTITY,
        "build_config_digest": collector["sha"],
        "build_trigger": "workflow_run",
    }
    _require_exact_members(
        claims, COLLECTOR_FULCIO_CLAIM_KEYS, "terminal collector Fulcio claims",
    )
    require(
        claims == expected_claims,
        "terminal collector Fulcio workload identity is substituted",
    )
    return {
        "certificate_workflow_sha": claims["build_config_digest"],
        "identity": claims["identity"],
        "integrated_time": verified["integrated_time"],
        "log_index": verified["log_index"],
    }


def _require_generated_activation_oidc_identity(claims, provenance):
    """Bind the verified Fulcio leaf to the authenticated workflow_run."""
    repository = provenance["repository"]
    workflow_path = ACTIVATION.TARGET_WORKFLOW_PATHS[repository]
    workflow_identity = (
        f"https://github.com/{repository}/{workflow_path}@{provenance['ref']}"
    )
    expected = {
        "identity": workflow_identity,
        "issuer": OIDC_ISSUER,
        "source_repository_uri": f"https://github.com/{repository}",
        "source_repository_ref": provenance["ref"],
        "build_config_uri": workflow_identity,
        "build_config_digest": provenance["sha"],
        "build_trigger": "workflow_run",
    }
    _require_exact_members(claims, tuple(expected), "generated Fulcio identity")
    for field, value in expected.items():
        require(
            claims[field] == value,
            f"generated Fulcio identity {field} mismatch",
        )
    return dict(claims)


# ---------------------------------------------------------------------------
# The single F8 derivation
# ---------------------------------------------------------------------------
def _sealed_bytes_for(repository_full_name):
    sealed = {}
    for path, (_, repository) in ACTIVATION.SEALED_BYTE_ROLES.items():
        if repository != repository_full_name:
            continue
        target = path.split("/", 1)[1]
        sealed[target] = (ROOT / path).read_bytes()
    return sealed


def _authenticate_external_activation_review(transport, independent, run_id, *,
                                             repository_root, base_commit,
                                             trust, contract):
    """Read, authenticate and verify the external activation review itself.

    Nothing about the review may be supplied by a caller. The receipt enters
    only as immutable artifact bytes downloaded by canonical artifact id from a
    post-candidate run of the exact named independent-review authority, its
    Sigstore provenance is cryptographically verified against pinned trust
    material, and the bytes are then verified against the exact clean checkout.
    """
    require(
        type(contract) is dict
        and contract.get("repository") == ACTIVATION.INDEPENDENT_REPOSITORY
        and contract.get("workflow_path")
        == ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.INDEPENDENT_REPOSITORY],
        "the sealed external activation review authority is not the reviewer",
    )
    run = _authenticate_run(
        transport, independent, run_id,
        workflow_path=contract["workflow_path"], job_name=INDEPENDENT_JOB_NAME,
    )
    _authenticate_tree_membership(
        transport, independent, run.head_tree,
        _sealed_bytes_for(ACTIVATION.INDEPENDENT_REPOSITORY),
    )
    artifact = _authenticate_artifact(
        transport, run, contract["artifact_name"], contract["artifact_files"],
    )
    receipt_member, bundle_member = contract["artifact_files"]
    receipt_bytes = artifact.members[receipt_member]
    bundle_bytes = artifact.members[bundle_member]
    receipt_sha256 = _sha256(receipt_bytes)
    _verify_sigstore_bundle(
        bundle_bytes,
        subject_bytes=receipt_bytes,
        trust=trust,
        repository=ACTIVATION.INDEPENDENT_REPOSITORY,
        workflow_path=contract["workflow_path"],
        workflow_sha=run.head_sha,
        signing_window=run.signing_window,
    )
    review = ACTIVATION.verify_external_activation_review(
        receipt_bytes,
        repository_root=repository_root,
        base_commit=base_commit,
        receipt_sha256=receipt_sha256,
    )
    # The review can only be an approval if it was produced after the exact
    # candidate it approves already existed.
    authored = ACTIVATION._text(
        repository_root, "show", "-s", "--format=%ct", review["head_commit"],
    )
    require(
        re.fullmatch(r"[1-9][0-9]*", authored) is not None
        and int(authored) <= run.signing_window[0],
        "the external activation review predates the candidate it approves",
    )
    return review, run, artifact


def _select_sole_authorized_run(transport, repository, workflow_path, job_name):
    """The unique authorized attempt-1 run, from exhaustive authenticated lists.

    No caller may name a run. The workflow is located by its sealed path in the
    complete workflow inventory, its complete run history is traversed
    exhaustively, and exactly one successful attempt-1 ``workflow_dispatch``
    run on the default branch may exist. An additional or ambiguous run fails
    closed.
    """
    workflows = _read_collection(
        transport, f"{API_ROOT}/repos/{repository.full_name}/actions/workflows",
        f"{repository.full_name} workflow inventory",
        permission=ACTIONS_READ, key="workflows",
    )
    matching = [entry for entry in workflows if entry.get("path") == workflow_path]
    require(
        len(matching) == 1,
        f"{repository.full_name} does not carry exactly one {workflow_path}",
    )
    workflow_id = _require_canonical_id(
        matching[0].get("id"), f"{repository.full_name} workflow id",
    )
    runs = _read_collection(
        transport,
        f"{API_ROOT}/repos/{repository.full_name}/actions/workflows"
        f"/{workflow_id}/runs",
        f"{repository.full_name} authorized run inventory",
        permission=ACTIONS_READ, key="workflow_runs",
    )
    authorized = [
        entry for entry in runs
        if entry.get("run_attempt") == RUN_ATTEMPT
        and entry.get("status") == "completed"
        and entry.get("conclusion") == "success"
        and entry.get("event") == TRIGGER
        and entry.get("head_branch") == DEFAULT_BRANCH
        and entry.get("path") == workflow_path
    ]
    require(
        len(authorized) == 1,
        f"{repository.full_name} does not hold exactly one authorized attempt-1 "
        f"{workflow_path} run, so the authorized activation run is absent, "
        "additional or ambiguous",
    )
    run_id = _require_canonical_id(
        authorized[0].get("id"), f"{repository.full_name} authorized run id",
    )
    run = _authenticate_run(
        transport, repository, run_id,
        workflow_path=workflow_path, job_name=job_name,
    )
    require(
        run.workflow_id == workflow_id,
        f"{repository.full_name} authorized run is not the sealed workflow",
    )
    return run


# ---------------------------------------------------------------------------
# The live independent-review bootstrap binding the signing workflow consumes
# ---------------------------------------------------------------------------
INDEPENDENT_BOOTSTRAP_CONTRACT_PATH = (
    "independent-review-bootstrap-v2/bootstrap-contract.json"
)
INDEPENDENT_BOOTSTRAP_CONTRACT_TARGET = "bootstrap-contract.json"
INDEPENDENT_BOOTSTRAP_LIVE_FIELDS = (
    "independent_bootstrap_commit", "independent_bootstrap_tree",
)
INDEPENDENT_VALIDATOR_TARGET = "scripts/verify_kanban_review_v2.py"
INDEPENDENT_COLLECTOR_TARGET = ACTIVATION.TERMINAL_COLLECTOR_PATH
BOOTSTRAP_BINDING_PROVENANCE = "authenticated-canonical-github-readback"


def _require_unpinned_independent_bootstrap(repository_root):
    """The sealed reviewer contract must keep its live identifiers unavailable.

    A candidate that pre-pinned a future bootstrap commit would decide, before
    any run existed, which head the workflow later "authenticates" against, so
    the pre-live constants must stay null and stay declared as never
    pre-pinned. Nothing here may ever become the derived value.
    """
    path = Path(repository_root) / INDEPENDENT_BOOTSTRAP_CONTRACT_PATH
    require(
        path.is_file() and not path.is_symlink(),
        "the sealed independent-review bootstrap contract is absent or unsafe",
    )
    data = path.read_bytes()
    contract = ACTIVATION._closed_json(
        data, "independent-review bootstrap contract",
    )
    require(
        type(contract) is dict
        and contract.get("repository") == ACTIVATION.INDEPENDENT_REPOSITORY,
        "the sealed bootstrap contract is not the reviewer bootstrap",
    )
    require(
        data == (ROOT / INDEPENDENT_BOOTSTRAP_CONTRACT_PATH).read_bytes(),
        "the reviewer bootstrap contract is not the sealed candidate bytes",
    )
    never = contract.get("live_identifiers_never_pre_pinned")
    require(
        type(never) is list,
        "the sealed bootstrap contract declares no never-pre-pinned identifiers",
    )
    authorized = contract.get("authorized_source_run")
    require(
        type(authorized) is dict,
        "the sealed bootstrap contract carries no authorized source run",
    )
    for field in INDEPENDENT_BOOTSTRAP_LIVE_FIELDS:
        require(
            field in never,
            f"the sealed bootstrap contract permits pre-pinning {field}",
        )
        require(
            authorized.get(field) is None,
            f"the sealed bootstrap contract pre-pins {field}, so the live "
            "bootstrap commit would be caller-preselected instead of derived "
            "from authenticated GitHub state",
        )
    return contract


def _required_independent_bootstrap_digests(contract, package):
    """Sealed target path to candidate-required SHA-256, for every bound byte.

    The review workflow, terminal collector, validator and bootstrap contract
    itself are each bound by path and by the exact byte digest this reviewed
    candidate requires, so a live head carrying any other bytes at those paths
    fails closed even when every identifier looks canonical.
    """
    sealed = _sealed_bytes_for(ACTIVATION.INDEPENDENT_REPOSITORY)
    workflow_path = ACTIVATION.TARGET_WORKFLOW_PATHS[
        ACTIVATION.INDEPENDENT_REPOSITORY
    ]
    workflow = contract.get("workflow")
    validator = contract.get("validator")
    terminal = contract.get("terminal_readback")
    require(
        type(workflow) is dict and type(validator) is dict
        and type(terminal) is dict,
        "the sealed bootstrap contract binds no workflow, collector or "
        "validator blob",
    )
    require(
        workflow.get("path") == workflow_path
        and terminal.get("collector_workflow_path")
        == INDEPENDENT_COLLECTOR_TARGET
        and validator.get("path") == INDEPENDENT_VALIDATOR_TARGET,
        "the sealed bootstrap contract binds a foreign workflow, collector "
        "or validator path",
    )
    authorized = contract["authorized_source_run"]
    contract_digest = None
    for entry in package["sealed_bytes"]:
        if entry["path"] == INDEPENDENT_BOOTSTRAP_CONTRACT_PATH:
            contract_digest = entry["sha256"]
    require(
        contract_digest is not None,
        "the activation package seals no independent-review bootstrap contract",
    )
    required = {
        workflow_path: workflow.get("sha256"),
        INDEPENDENT_COLLECTOR_TARGET: terminal.get(
            "collector_workflow_sha256"
        ),
        INDEPENDENT_VALIDATOR_TARGET: validator.get("sha256"),
        INDEPENDENT_BOOTSTRAP_CONTRACT_TARGET: contract_digest,
    }
    require(
        sorted(required) == sorted(sealed),
        "the bound reviewer paths are not exactly the sealed reviewer bytes",
    )
    # The contract's own authorized-run digests may not contradict the blobs
    # the same contract binds, so one sealed byte can never be bound twice.
    require(
        authorized.get("independent_workflow_sha256") == required[workflow_path]
        and authorized.get("independent_validator_sha256")
        == required[INDEPENDENT_VALIDATOR_TARGET],
        "the sealed bootstrap contract contradicts its own bound blob digests",
    )
    for target_path, digest in sorted(required.items()):
        _require_non_synthetic_digest(
            digest, f"required {target_path} digest",
        )
        require(
            _sha256(sealed[target_path]) == digest,
            f"the reviewed candidate does not carry the bound {target_path} bytes",
        )
    return required


def _derive_independent_bootstrap_binding(repository_root=ROOT):
    """Derive the live reviewer bootstrap commit and tree, never read them.

    The signing workflow may not compare its authenticated review head to a
    sealed pre-live constant: that constant is deliberately unavailable, so the
    comparison could only ever fail closed and Authority verification would be
    unreachable in every real run. The binding is instead derived here, from
    authenticated canonical GitHub state alone: the reviewer repository is
    resolved through its own canonical identifier, the unique authorized
    attempt-1 ``workflow_dispatch`` run is selected from the exhaustive
    authenticated run inventory of the sealed workflow, its head commit is read
    back through the canonical commit endpoint to its tree, and the sealed
    workflow, validator and bootstrap-contract paths are proven present in that
    live tree as regular blobs whose Git object names and bytes recompute to
    the exact digests this reviewed candidate requires.

    Nothing is taken from a caller and nothing is taken from the sealed
    pre-live constants, which must still be null. An absent, additional or
    ambiguous run, a synthetic or repeated identifier, a substituted tree or
    blob, a mismatched commit-to-tree readback, a missing page, an absent
    permission header or any non-200 read all fail closed.
    """
    repository_root = Path(repository_root)
    contract = _require_unpinned_independent_bootstrap(repository_root)
    package = ACTIVATION.verify_activation_package()
    required = _required_independent_bootstrap_digests(contract, package)
    workflow_path = ACTIVATION.TARGET_WORKFLOW_PATHS[
        ACTIVATION.INDEPENDENT_REPOSITORY
    ]
    sealed = _sealed_bytes_for(ACTIVATION.INDEPENDENT_REPOSITORY)

    transport = _require_read_only_transport(_transport_factory())
    independent = _authenticate_repository(
        transport, ACTIVATION.INDEPENDENT_REPOSITORY,
    )
    run = _select_sole_authorized_run(
        transport, independent, workflow_path, INDEPENDENT_JOB_NAME,
    )
    members = _authenticate_tree_membership(
        transport, independent, run.head_tree, sealed,
    )
    for target_path, digest in sorted(required.items()):
        entry = members.get(target_path)
        require(
            entry is not None,
            f"the live reviewer head does not carry the bound {target_path}",
        )
        require(
            entry.get("type") == "blob" and entry.get("mode") == BLOB_MODE
            and entry.get("sha") == _git_blob_oid(sealed[target_path]),
            f"the live reviewer {target_path} blob was substituted",
        )
        require(
            _sha256(sealed[target_path]) == digest,
            f"the live reviewer {target_path} bytes are not the bound bytes",
        )

    commit = _require_non_synthetic_digest(
        run.head_sha, "live reviewer bootstrap commit", pattern=HEX40,
    )
    tree = _require_non_synthetic_digest(
        run.head_tree, "live reviewer bootstrap tree", pattern=HEX40,
    )
    require(
        _authenticate_commit(transport, independent, commit) == tree,
        "the canonical reviewer commit readback does not resolve to the "
        "authenticated live tree",
    )
    require(
        commit != tree,
        "the live reviewer bootstrap commit and tree are the same object",
    )
    for field in INDEPENDENT_BOOTSTRAP_LIVE_FIELDS:
        require(
            contract["authorized_source_run"][field] is None,
            f"the sealed bootstrap contract pre-pins {field}",
        )
    return {
        "bound_paths": dict(sorted(required.items())),
        "derived_from": BOOTSTRAP_BINDING_PROVENANCE,
        "independent_bootstrap_commit": commit,
        "independent_bootstrap_tree": tree,
        "repository": independent.full_name,
        "repository_id": independent.identifier,
        "run_attempt": RUN_ATTEMPT,
        "run_head_sha": run.head_sha,
        "run_id": run.run_id,
        "sealed_pre_live_commit": None,
        "sealed_pre_live_tree": None,
        "workflow_path": workflow_path,
    }


def _reviewed_base_commit(repository_root):
    """The reviewed Authority base, read from the candidate's own policy."""
    path = Path(repository_root) / "authority-v2-policy.json"
    require(
        path.is_file() and not path.is_symlink(),
        "the reviewed Authority policy is absent or unsafe",
    )
    policy = ACTIVATION._closed_json(path.read_bytes(), "authority policy")
    base = policy.get("authority_repository_base", {}).get("commit")
    require(
        type(base) is str and HEX40.fullmatch(base) is not None,
        "the reviewed Authority policy pins no base commit",
    )
    return base


def derive_activation_closure(repository_root=ROOT):
    """The single indivisible production operation that may ever close F8.

    It takes no transport, no trust material, no evidence object, no closure
    flag and no run identifier. It loads the pinned Sigstore trust from the
    candidate's own contract bytes, instantiates the one fixed read-only GitHub
    REST transport for itself, selects the unique authorized attempt-1 runs
    from exhaustive authenticated listings, authenticates every repository,
    run, job, commit, tree, path, blob and immutable artifact, recomputes every
    byte, verifies the external activation review against this exact clean
    checkout, cryptographically verifies both Sigstore bundles against the
    pinned roots and keys valid at their integrated times, and only then
    returns a pinned activation package. Every intermediate is a local value;
    nothing partial escapes and nothing constructible can skip a step.
    """
    repository_root = Path(repository_root)
    package = deepcopy(ACTIVATION.verify_activation_package())
    reviewed = ACTIVATION.verify_activation_package()
    base_commit = _reviewed_base_commit(repository_root)
    # Trust is bound to the candidate that ships this verifier, never to the
    # checkout under inspection and never to a caller.
    trust = _load_pinned_sigstore_trust(ROOT)
    transport = _require_read_only_transport(_transport_factory())

    # --- canonical repository, run and job evidence -----------------------
    repositories = {
        name: _authenticate_repository(transport, name)
        for name in ACTIVATION.TARGET_REPOSITORIES
    }
    source = repositories[ACTIVATION.SOURCE_REPOSITORY]
    independent = repositories[ACTIVATION.INDEPENDENT_REPOSITORY]
    source_workflow = ACTIVATION.TARGET_WORKFLOW_PATHS[ACTIVATION.SOURCE_REPOSITORY]
    independent_workflow = ACTIVATION.TARGET_WORKFLOW_PATHS[
        ACTIVATION.INDEPENDENT_REPOSITORY
    ]
    source_run = _select_sole_authorized_run(
        transport, source, source_workflow, SOURCE_JOB_NAME,
    )
    independent_run = _select_sole_authorized_run(
        transport, independent, independent_workflow, INDEPENDENT_JOB_NAME,
    )

    # --- exact sealed path to blob membership at both live heads ----------
    _authenticate_tree_membership(
        transport, source, source_run.head_tree,
        _sealed_bytes_for(ACTIVATION.SOURCE_REPOSITORY),
    )
    _authenticate_tree_membership(
        transport, independent, independent_run.head_tree,
        _sealed_bytes_for(ACTIVATION.INDEPENDENT_REPOSITORY),
    )

    # --- immutable artifacts, downloaded by canonical id only -------------
    producer = package["producer_bindings"]
    external_contract = package["external_activation_review"]
    require(
        external_contract["repository"] == ACTIVATION.INDEPENDENT_REPOSITORY
        and external_contract["workflow_path"] == independent_workflow,
        "the sealed external activation review authority is not the reviewer",
    )
    review_artifact = _authenticate_artifact(
        transport, source_run, producer["artifact_name"],
        producer["artifact_files"],
    )
    signed_artifact = _authenticate_artifact(
        transport, independent_run, producer["signed_artifact_name"],
        producer["signed_artifact_files"],
    )
    external_artifact = _authenticate_artifact(
        transport, independent_run, external_contract["artifact_name"],
        external_contract["artifact_files"],
    )

    # --- byte recomputation over the downloaded members -------------------
    envelope_name, receipt_name = sorted(producer["artifact_files"])
    envelope = review_artifact.members[envelope_name]
    receipt = review_artifact.members[receipt_name]
    require(
        signed_artifact.members[envelope_name] == envelope
        and signed_artifact.members[receipt_name] == receipt,
        "the signed artifact does not carry the exact protected-source bytes",
    )
    bundle_name = next(
        name for name in producer["signed_artifact_files"]
        if name.endswith(".sigstore.json")
    )
    bundle_bytes = signed_artifact.members[bundle_name]
    envelope_sha256 = _sha256(envelope)
    receipt_sha256 = _sha256(receipt)
    declared = ACTIVATION._closed_json(envelope, "protected review envelope")
    require(
        type(declared) is dict
        and declared.get("review_receipt_sha256") == receipt_sha256
        and declared.get("source_run_id") == source_run.run_id
        and declared.get("source_run_attempt") == RUN_ATTEMPT
        and declared.get("source_run_head_sha") == source_run.head_sha,
        "the recomputed envelope does not bind the authorized run and receipt",
    )

    # --- the external activation review, verified against this checkout ---
    external_receipt_name, external_bundle_name = external_contract["artifact_files"]
    external_receipt = external_artifact.members[external_receipt_name]
    external_bundle = external_artifact.members[external_bundle_name]
    external_receipt_sha256 = _sha256(external_receipt)
    external_review = ACTIVATION.verify_external_activation_review(
        external_receipt,
        repository_root=repository_root,
        base_commit=base_commit,
        receipt_sha256=external_receipt_sha256,
    )
    authored = ACTIVATION._text(
        repository_root, "show", "-s", "--format=%ct", external_review["head_commit"],
    )
    require(
        re.fullmatch(r"[1-9][0-9]*", authored) is not None
        and int(authored) <= independent_run.signing_window[0],
        "the external activation review predates the candidate it approves",
    )

    chain = ACTIVATION._closed_json(receipt, "protected review receipt")
    require(type(chain) is dict, "protected review receipt is malformed")
    execution = chain.get("source_execution_chain")
    require(
        type(execution) is dict
        and execution.get("run_id") == source_run.run_id
        and execution.get("run_attempt") == RUN_ATTEMPT
        and execution.get("run_head_sha") == source_run.head_sha
        and execution.get("source_bootstrap_commit") == source_run.head_sha
        and execution.get("source_bootstrap_tree") == source_run.head_tree
        and execution.get("independent_bootstrap_commit") == independent_run.head_sha
        and execution.get("independent_bootstrap_tree") == independent_run.head_tree
        and execution.get("authority_head_commit") == external_review["head_commit"]
        and execution.get("authority_head_tree") == external_review["head_tree"],
        "the downloaded receipt does not bind the authenticated live chain",
    )

    # --- cryptographic provenance against the pinned trust ----------------
    _verify_sigstore_bundle(
        external_bundle,
        subject_bytes=external_receipt,
        trust=trust,
        repository=ACTIVATION.INDEPENDENT_REPOSITORY,
        workflow_path=independent_workflow,
        workflow_sha=independent_run.head_sha,
        signing_window=independent_run.signing_window,
    )
    _verify_sigstore_bundle(
        bundle_bytes,
        subject_bytes=receipt,
        trust=trust,
        repository=ACTIVATION.INDEPENDENT_REPOSITORY,
        workflow_path=independent_workflow,
        workflow_sha=independent_run.head_sha,
        signing_window=independent_run.signing_window,
    )

    # --- pin, only now that every proof has passed ------------------------
    for name, repository in repositories.items():
        target = package["target_repositories"][name]
        target["created"] = True
        target["repository_id"] = repository.identifier
        target["repository_node_id"] = repository.node_id
    package["authorized_dispatch"]["run_id"] = source_run.run_id
    producer["artifact_content_sha256"] = review_artifact.content_sha256
    producer["certificate_github_workflow_sha"] = independent_run.head_sha
    producer["envelope_sha256"] = envelope_sha256
    producer["review_receipt_sha256"] = receipt_sha256
    producer["sigstore_bundle_sha256"] = _sha256(bundle_bytes)
    reviewed_source = package["reviewed_source"]
    reviewed_source["authority_head_commit"] = external_review["head_commit"]
    reviewed_source["authority_head_tree"] = external_review["head_tree"]
    reviewed_source["source_bootstrap_commit"] = source_run.head_sha
    reviewed_source["source_bootstrap_tree"] = source_run.head_tree
    reviewed_source["independent_bootstrap_commit"] = independent_run.head_sha
    reviewed_source["independent_bootstrap_tree"] = independent_run.head_tree
    package["activation_state"] = "ready"
    package["repositories_created"] = True
    package["workflows_written"] = True
    package["runs_observed"] = True
    package["post_activation_proof"]["live_evidence_pinned"] = True
    package["f8_closed"] = True
    # The authorization transition: false until, and only until, the external
    # post-candidate review and every live proof above have authenticated.
    package["external_activation_review"]["state"] = (
        ACTIVATION.EXTERNAL_REVIEW_AUTHENTICATED
    )
    package["external_activation_review"]["receipt_sha256"] = (
        external_receipt_sha256
    )
    package["activation_authorized"] = True

    for name in ACTIVATION.PERMANENTLY_UNAUTHORIZED:
        require(
            package["authorizes"][name] is False,
            f"the pinned activation package must never authorize {name}",
        )
    require(
        reviewed["activation_authorized"] is False
        and reviewed["external_activation_review"]["state"]
        == ACTIVATION.EXTERNAL_REVIEW_UNAVAILABLE,
        "the reviewed candidate must ship unauthorized, so the transition is real",
    )
    immutable = {
        name: value
        for name, value in reviewed["external_activation_review"].items()
        if name not in ACTIVATION.EXTERNAL_REVIEW_TRANSITION_KEYS
    }
    require(
        package["pre_activation_authorization"]
        == reviewed["pre_activation_authorization"]
        and package["authorizes"] == reviewed["authorizes"]
        and {
            name: value
            for name, value in package["external_activation_review"].items()
            if name not in ACTIVATION.EXTERNAL_REVIEW_TRANSITION_KEYS
        } == immutable,
        "pinning must preserve the exact reviewed pre-activation authorization",
    )
    ACTIVATION._verify_live_evidence_is_complete(package)
    return package


# ---------------------------------------------------------------------------
# F8-ACTIVATION-CLI-TRANSITION-DISCONNECTED
#
# One real command line path authenticates the live exporter artifact, the
# external independent-review receipt and its Sigstore bundle, derives F8
# internally from that evidence and hands the derived evidence straight to the
# Authority. The sealed evidence is dropped by the activation lane beside the
# Authority checkout, at a constant non-caller-selectable directory name, so
# the reviewed checkout itself stays exactly clean. Nothing here is a flag: a
# candidate-owned `ready`, a well-formed hash or a syntactically valid receipt
# all fail closed, and an unresolved or null state exits non-zero.
# ---------------------------------------------------------------------------
LIVE_EVIDENCE_DIRECTORY = "acc-live-activation-evidence"
LIVE_EVIDENCE_ENVELOPE = "kanban-review-envelope.json"
LIVE_EVIDENCE_RECEIPT = "preissuance-review-receipt.json"
LIVE_EVIDENCE_EXTERNAL_RECEIPT = "external-activation-review-receipt.json"
LIVE_EVIDENCE_EXTERNAL_BUNDLE = (
    "external-activation-review-receipt.sigstore.json"
)
# The third member the `authority-v2-signed-review` upload really carries: the
# Sigstore bundle the reviewer produced over the pre-issuance receipt. Binding
# only the envelope and the receipt left these bytes unauthenticated, so an
# archive carrying a substituted bundle still satisfied the closure.
LIVE_EVIDENCE_SIGNED_BUNDLE = "preissuance-review-receipt.sigstore.json"
LIVE_EVIDENCE_TIMELINE = "authenticated-run-timeline.json"
# The server-bound artifact identity the issuance lane authenticated before it
# placed a single byte in this inventory. The closure consumes it; it is never
# merely recorded.
LIVE_EVIDENCE_IDENTITY = "authenticated-artifact-identity.json"
# The immutable archive the issuance lane downloaded by canonical artifact id,
# kept beside the evidence it expanded. The canonical server id is part of the
# name, so the archive this closure opens is exactly the artifact the server
# named, never a same-shaped file that merely sits in the directory.
ARTIFACT_ARCHIVE_TEMPLATE = "artifact-{artifact_id}.zip"
LIVE_EVIDENCE_MEMBERS = (
    LIVE_EVIDENCE_IDENTITY,
    LIVE_EVIDENCE_TIMELINE,
    LIVE_EVIDENCE_EXTERNAL_RECEIPT,
    LIVE_EVIDENCE_EXTERNAL_BUNDLE,
    LIVE_EVIDENCE_ENVELOPE,
    LIVE_EVIDENCE_RECEIPT,
    LIVE_EVIDENCE_SIGNED_BUNDLE,
)
LIVE_TIMELINE_KEYS = (
    "independent_bootstrap_commit", "job_completed_at", "job_started_at",
    "repository", "run_attempt", "run_id", "run_started_at", "workflow_path",
)
REPORT_PHASE = "report"
CLOSURE_PHASE = "closure"
# The production caller of the generator-bound activation contract. It is the
# phase the one authorized activation run drives, and it authorizes nothing.
GENERATED_ACTIVATION_PHASE = "generated-activation-evidence"
GENERATED_ARTIFACT_INVENTORY_PHASE = "generated-artifact-inventory"
TERMINAL_OUTPUT_INVENTORY_PHASE = "terminal-output-inventory"
TERMINAL_READBACK_PHASE = "terminal-activation-readback"
PHASES = (
    REPORT_PHASE, CLOSURE_PHASE, GENERATED_ACTIVATION_PHASE,
    GENERATED_ARTIFACT_INVENTORY_PHASE,
    TERMINAL_OUTPUT_INVENTORY_PHASE,
    TERMINAL_READBACK_PHASE,
)

TERMINAL_OUTPUT_MEMBERS = (
    "terminal-activation-readback.json",
    "terminal-activation-readback.sigstore.json",
)
TERMINAL_SECRET_PATTERN = re.compile(
    rb"(?ix)([\"']?authorization[\"']?\s*[:=]\s*[\"']?\s*"
    rb"(?:bearer|basic)\s+[A-Za-z0-9._~+:/=-]+|"
    rb"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    rb"-----BEGIN[ ](?:[A-Z0-9]+[ ])*PRIVATE[ ]KEY-----|"
    rb"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    rb"[\"']?aws[\s_.-]*(?:access[\s_.-]*key[\s_.-]*id|"
    rb"secret[\s_.-]*access[\s_.-]*key|session[\s_.-]*token)"
    rb"[\"']?\s*[:=]\s*[\"']?\s*[A-Za-z0-9_./+=-]{16,})"
)


def _require_terminal_output_inventory(root):
    require(root.is_dir() and not root.is_symlink(),
            "terminal output root is absent or unsafe")
    observed = []
    for member in root.iterdir():
        require(member.name in TERMINAL_OUTPUT_MEMBERS,
                "unexpected terminal output member")
        require(member.is_file() and not member.is_symlink(),
                "terminal output member is not a regular file")
        data = member.read_bytes()
        require(data, "terminal output member is empty")
        require(TERMINAL_SECRET_PATTERN.search(data) is None,
                "secret-bearing terminal output member")
        observed.append(member.name)
    require(tuple(sorted(observed)) == TERMINAL_OUTPUT_MEMBERS,
            "terminal output inventory is incomplete")


def _live_evidence_bytes(directory, name):
    path = Path(directory) / name
    require(
        path.is_file() and not path.is_symlink(),
        f"sealed live activation evidence member is absent or unsafe: {name}",
    )
    data = path.read_bytes()
    require(data, f"sealed live activation evidence member is empty: {name}")
    return data


def _authenticated_signing_window(timeline, *, repository, workflow_path):
    """The authenticated run and job window the Rekor time must fall inside."""
    label = "authenticated run timeline"
    require(type(timeline) is dict, f"{label} is malformed")
    require(
        tuple(sorted(timeline)) == tuple(sorted(LIVE_TIMELINE_KEYS)),
        f"{label} field set mismatch",
    )
    require(
        timeline["repository"] == repository,
        f"{label} is not the independent reviewer's run",
    )
    require(
        timeline["workflow_path"] == workflow_path,
        f"{label} did not execute the sealed reviewer workflow",
    )
    require(
        timeline["run_attempt"] == RUN_ATTEMPT
        and type(timeline["run_attempt"]) is int
        and type(timeline["run_attempt"]) is not bool,
        f"{label} is not the authorized attempt 1",
    )
    _require_canonical_id(timeline["run_id"], f"{label} run id")
    require(
        type(timeline["independent_bootstrap_commit"]) is str
        and HEX40.fullmatch(timeline["independent_bootstrap_commit"]) is not None,
        f"{label} independent bootstrap commit is malformed",
    )
    bounds = []
    for field in ("run_started_at", "job_started_at", "job_completed_at"):
        value = timeline[field]
        require(
            type(value) is int and type(value) is not bool and value > 0,
            f"{label} {field} is absent or malformed",
        )
        bounds.append(value)
    run_started, job_started, job_completed = bounds
    require(
        run_started <= job_started < job_completed,
        f"{label} bounds are contradictory or non-monotonic",
    )
    require(
        job_completed - job_started <= MAXIMUM_SIGNING_WINDOW_SECONDS,
        f"{label} signing window is implausibly wide",
    )
    return (job_started, job_completed)


ARTIFACT_IDENTITY_KEYS = (
    "archive_sha256", "archive_size", "artifact_id", "digest",
    "members", "name",
)
# Each canonically downloaded archive must carry exactly the members
# this closure goes on to authenticate, so naming an artifact can
# never stand in for its bytes.
ARTIFACT_REQUIRED_MEMBERS = {
    "authority-v2-external-activation-review-t_c298fca4": (
        LIVE_EVIDENCE_EXTERNAL_RECEIPT, LIVE_EVIDENCE_EXTERNAL_BUNDLE,
    ),
    "authority-v2-signed-review-t_c298fca4": (
        LIVE_EVIDENCE_ENVELOPE, LIVE_EVIDENCE_RECEIPT,
        LIVE_EVIDENCE_SIGNED_BUNDLE,
    ),
}
REQUIRED_ARTIFACT_NAMES = (
    "authority-v2-external-activation-review-t_c298fca4",
    "authority-v2-signed-review-t_c298fca4",
)


def _require_artifact_identity(entries):
    """The canonical server-returned artifact identity for both artifacts.

    Nothing enters the sealed inventory until the issuance lane has resolved
    each artifact by its canonical server id and `sha256:` digest, so the
    bytes this closure authenticates and the artifacts the server named are
    one chain rather than two independent claims.
    """
    require(
        type(entries) is list and len(entries) == len(REQUIRED_ARTIFACT_NAMES),
        "the authenticated artifact identity inventory is incomplete",
    )
    resolved = {}
    for entry in entries:
        require(
            type(entry) is dict
            and tuple(sorted(entry)) == ARTIFACT_IDENTITY_KEYS,
            "an authenticated artifact identity entry is malformed",
        )
        name = entry["name"]
        require(
            name in REQUIRED_ARTIFACT_NAMES and name not in resolved,
            f"an authenticated artifact identity is foreign or repeated: {name}",
        )
        _require_canonical_id(entry["artifact_id"], f"{name} artifact id")
        _require_non_synthetic_digest(
            entry["archive_sha256"], f"{name} recomputed archive digest",
        )
        require(
            type(entry["archive_size"]) is int
            and type(entry["archive_size"]) is not bool
            and entry["archive_size"] > 0,
            f"{name} recomputed archive size is malformed",
        )
        members = entry["members"]
        require(
            type(members) is dict
            and tuple(sorted(members)) == tuple(sorted(
                ARTIFACT_REQUIRED_MEMBERS[name]
            )),
            f"{name} archive member inventory mismatch",
        )
        for member, digest in sorted(members.items()):
            _require_non_synthetic_digest(
                digest, f"{name} archive member {member}",
            )
        _require_non_synthetic_digest(
            entry["digest"].split(":", 1)[-1], f"{name} artifact digest",
        )
        require(
            entry["digest"].startswith("sha256:"),
            f"{name} artifact digest is not a canonical server digest",
        )
        # The server-returned digest and the digest recomputed over the
        # downloaded archive are one statement, never two independent claims
        # that merely both look like digests.
        require(
            entry["digest"] == "sha256:" + entry["archive_sha256"],
            f"the server-returned {name} artifact digest is not the digest "
            "recomputed over the downloaded archive",
        )
        resolved[name] = entry
    require(
        sorted(resolved) == sorted(REQUIRED_ARTIFACT_NAMES),
        "the authenticated artifact identity inventory is incomplete",
    )
    identifiers = [resolved[name]["artifact_id"] for name in sorted(resolved)]
    require(
        len(set(identifiers)) == len(identifiers),
        "two authenticated artifacts claim one canonical artifact id",
    )
    return resolved


def _authenticate_artifact_archives(directory, identity, bound_members):
    """Open the exact downloaded archives and bind every real member byte.

    The canonical server id names the archive, so the bytes opened here are
    the artifact the server named. The declared size must be the real size,
    the recomputed digest must be the archive on disk, and the complete real
    ZIP member inventory must be exactly the members this closure goes on to
    authenticate - each one hashing to the evidence byte it claims to carry.
    A missing, extra, repeated or drifted member fails closed.
    """
    directory = Path(directory)
    for name in sorted(REQUIRED_ARTIFACT_NAMES):
        entry = identity[name]
        relative = ARTIFACT_ARCHIVE_TEMPLATE.format(
            artifact_id=entry["artifact_id"],
        )
        path = directory / relative
        require(
            path.is_file() and not path.is_symlink(),
            f"the canonically downloaded {name} archive is absent or unsafe: "
            f"{relative}",
        )
        data = path.read_bytes()
        require(
            len(data) == entry["archive_size"],
            f"the canonically downloaded {name} archive size is not the "
            "authenticated archive size",
        )
        recomputed = _sha256(data)
        require(
            recomputed == entry["archive_sha256"],
            f"the canonically downloaded {name} archive bytes are not the "
            "authenticated archive digest",
        )
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = _read_validated_zip(
                    archive, ARTIFACT_REQUIRED_MEMBERS[name],
                    f"the canonically downloaded {name} archive",
                )
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as error:
            raise SystemExit(
                f"the canonically downloaded {name} archive is not a "
                "readable archive"
            ) from error
        require(
            sorted(members) == sorted(ARTIFACT_REQUIRED_MEMBERS[name]),
            f"the canonically downloaded {name} archive member inventory "
            "mismatch",
        )
        for member in sorted(members):
            digest = _sha256(members[member])
            require(
                digest == entry["members"].get(member),
                f"the canonically downloaded {name} archive member {member} "
                "is not the authenticated member digest",
            )
            require(
                digest == bound_members.get(member),
                f"the canonically downloaded {name} archive member {member} "
                "is not the byte this closure authenticated",
            )


def _authenticate_live_activation_evidence(directory, *, repository_root,
                                          base_commit):
    """Authenticate every sealed live activation byte, offline and fail-closed.

    The exporter artifact is recomputed member by member and must bind the
    authorized run and receipt it claims; the external independent-review
    receipt is verified against the exact clean Authority checkout; and its
    Sigstore bundle is cryptographically verified against the pinned Fulcio and
    Rekor trust inside the authenticated run and job window. Only evidence
    that survives all of this may reach the live server proof.
    """
    directory = Path(directory)
    require(
        directory.is_dir() and not directory.is_symlink(),
        f"sealed live activation evidence directory is absent or unsafe: "
        f"{LIVE_EVIDENCE_DIRECTORY}",
    )
    observed = sorted(entry.name for entry in directory.iterdir())
    require(
        DERIVED_CLOSURE_NAME not in observed,
        "a derived activation closure already exists, so this evidence set "
        "was already closed and may not be closed again",
    )
    # The identity is resolved first, because the canonical artifact ids it
    # carries are what name the archives that must be present: the inventory
    # is therefore the fixed evidence set plus exactly the archives the
    # server-returned ids identify, and nothing else.
    identity = _require_artifact_identity(
        ACTIVATION._closed_json(
            _live_evidence_bytes(directory, LIVE_EVIDENCE_IDENTITY),
            "authenticated artifact identity",
        ),
    )
    archive_names = [
        ARTIFACT_ARCHIVE_TEMPLATE.format(
            artifact_id=identity[name]["artifact_id"],
        )
        for name in sorted(REQUIRED_ARTIFACT_NAMES)
    ]
    require(
        observed == sorted(tuple(LIVE_EVIDENCE_MEMBERS) + tuple(archive_names)),
        f"sealed live activation evidence inventory mismatch in "
        f"{LIVE_EVIDENCE_DIRECTORY}: it must hold exactly the sealed members "
        f"and the canonically downloaded artifact archives "
        f"{', '.join(sorted(archive_names))}",
    )
    envelope = _live_evidence_bytes(directory, LIVE_EVIDENCE_ENVELOPE)
    receipt = _live_evidence_bytes(directory, LIVE_EVIDENCE_RECEIPT)
    external_receipt = _live_evidence_bytes(
        directory, LIVE_EVIDENCE_EXTERNAL_RECEIPT,
    )
    external_bundle = _live_evidence_bytes(
        directory, LIVE_EVIDENCE_EXTERNAL_BUNDLE,
    )
    # The third member the signed-review upload really carries. Its bytes are
    # authenticated exactly like every other evidence byte, so an archive that
    # substitutes the bundle can never satisfy this closure.
    signed_bundle = _live_evidence_bytes(
        directory, LIVE_EVIDENCE_SIGNED_BUNDLE,
    )
    # Every member of every downloaded archive is bound to the exact evidence
    # byte this closure authenticates, before any other leg runs.
    _authenticate_artifact_archives(directory, identity, {
        LIVE_EVIDENCE_ENVELOPE: _sha256(envelope),
        LIVE_EVIDENCE_RECEIPT: _sha256(receipt),
        LIVE_EVIDENCE_EXTERNAL_RECEIPT: _sha256(external_receipt),
        LIVE_EVIDENCE_EXTERNAL_BUNDLE: _sha256(external_bundle),
        LIVE_EVIDENCE_SIGNED_BUNDLE: _sha256(signed_bundle),
    })
    timeline = ACTIVATION._closed_json(
        _live_evidence_bytes(directory, LIVE_EVIDENCE_TIMELINE),
        "authenticated run timeline",
    )

    # --- the exporter artifact, recomputed member by member ---------------
    receipt_sha256 = _sha256(receipt)
    envelope_sha256 = _sha256(envelope)
    artifact_content_sha256 = _artifact_content_sha256({
        LIVE_EVIDENCE_ENVELOPE: envelope,
        LIVE_EVIDENCE_RECEIPT: receipt,
    })
    declared = ACTIVATION._closed_json(envelope, "protected review envelope")
    require(
        type(declared) is dict
        and declared.get("review_receipt_sha256") == receipt_sha256,
        "the sealed exporter envelope does not bind its own receipt bytes",
    )
    run_id = _require_canonical_id(
        declared.get("source_run_id"), "sealed exporter run id",
    )
    require(
        declared.get("source_run_attempt") == RUN_ATTEMPT,
        "the sealed exporter envelope is not the authorized attempt 1",
    )
    head_sha = declared.get("source_run_head_sha")
    require(
        type(head_sha) is str and HEX40.fullmatch(head_sha) is not None,
        "the sealed exporter envelope run head is malformed",
    )
    chain = ACTIVATION._closed_json(receipt, "protected review receipt")
    require(type(chain) is dict, "the sealed exporter receipt is malformed")
    execution = chain.get("source_execution_chain")
    require(
        type(execution) is dict
        and execution.get("run_id") == run_id
        and execution.get("run_attempt") == RUN_ATTEMPT
        and execution.get("run_head_sha") == head_sha,
        "the sealed exporter receipt does not bind the authorized run",
    )
    independent_repository = ACTIVATION.INDEPENDENT_REPOSITORY
    independent_workflow = ACTIVATION.TARGET_WORKFLOW_PATHS[
        independent_repository
    ]
    signing_window = _authenticated_signing_window(
        timeline,
        repository=independent_repository,
        workflow_path=independent_workflow,
    )
    workflow_sha = timeline["independent_bootstrap_commit"]
    require(
        execution.get("independent_bootstrap_commit") == workflow_sha,
        "the authenticated run timeline is not the run that signed this review",
    )
    independent_bootstrap_tree = execution.get("independent_bootstrap_tree")
    require(
        type(independent_bootstrap_tree) is str
        and HEX40.fullmatch(independent_bootstrap_tree) is not None,
        "the sealed exporter receipt does not bind the independent bootstrap "
        "tree",
    )

    # --- the external review, verified against the exact clean checkout ---
    external_receipt_sha256 = _sha256(external_receipt)
    external_review = ACTIVATION.verify_external_activation_review(
        external_receipt,
        repository_root=repository_root,
        base_commit=base_commit,
        receipt_sha256=external_receipt_sha256,
    )
    require(
        execution.get("authority_head_commit") == external_review["head_commit"]
        and execution.get("authority_head_tree") == external_review["head_tree"],
        "the sealed exporter receipt is not bound to the reviewed candidate",
    )

    # --- real cryptography against the pinned trust, never an assertion ---
    # The anchor is never a caller input: it is loaded only from the sealed,
    # manifest-covered record of the candidate under inspection.
    trust = _load_pinned_sigstore_trust(Path(repository_root))
    _verify_sigstore_bundle(
        external_bundle,
        subject_bytes=external_receipt,
        trust=trust,
        repository=independent_repository,
        workflow_path=independent_workflow,
        workflow_sha=workflow_sha,
        signing_window=signing_window,
    )
    # The signed-review bundle is the reviewer's own Sigstore statement over
    # the pre-issuance receipt. It travels in the same upload, so it is
    # verified by the same unchanged verifier against the same pinned trust
    # and the same authenticated window - never merely carried along.
    _verify_sigstore_bundle(
        signed_bundle,
        subject_bytes=receipt,
        trust=trust,
        repository=independent_repository,
        workflow_path=independent_workflow,
        workflow_sha=workflow_sha,
        signing_window=signing_window,
    )
    # The authenticated server provenance and reviewer decision delivery the
    # signed external receipt itself carries. F8 is derived from these, never
    # from a caller-supplied boolean.
    server = external_review["server_objects"]
    delivery = external_review["decision_delivery"]
    require(
        server["run_id"] == run_id and server["head_commit"] == head_sha,
        "the external review server provenance is not the authorized run",
    )
    require(
        server["artifact_content_sha256"] == artifact_content_sha256,
        "the external review server provenance is not these exporter bytes",
    )
    # The delivery is a reviewer-owned commit created *by* the signing run,
    # so it is that run's child, never the run head itself. Binding its sole
    # parent is what proves it belongs to this exact review.
    require(
        delivery["commit_parent"] == workflow_sha
        and delivery["commit_sha"] != workflow_sha,
        "the reviewer decision delivery is not the run that signed this review",
    )
    # The exporter artifact the reviewer authenticated must be exactly the
    # contract-pinned one. A name alone proves nothing, so the artifacts the
    # issuance lane resolved by canonical server id must additionally carry,
    # member by member, the very bytes this closure just authenticated.
    require(
        server["artifact_name"] == SOURCE_ARTIFACT_NAME,
        "the server-bound artifact identity is not the authenticated exporter "
        "artifact",
    )
    bound_members = {
        LIVE_EVIDENCE_ENVELOPE: envelope_sha256,
        LIVE_EVIDENCE_RECEIPT: receipt_sha256,
        LIVE_EVIDENCE_EXTERNAL_RECEIPT: external_receipt_sha256,
        LIVE_EVIDENCE_EXTERNAL_BUNDLE: _sha256(external_bundle),
        LIVE_EVIDENCE_SIGNED_BUNDLE: _sha256(signed_bundle),
    }
    for name in sorted(REQUIRED_ARTIFACT_NAMES):
        for member, digest in sorted(identity[name]["members"].items()):
            require(
                digest == bound_members[member],
                f"the canonically downloaded {name} archive member {member} "
                "is not the byte this closure authenticated",
            )
    return {
        "artifact_content_sha256": artifact_content_sha256,
        "authority_head_commit": external_review["head_commit"],
        "authority_head_tree": external_review["head_tree"],
        "decision_delivery": delivery,
        "envelope_sha256": envelope_sha256,
        "external_receipt_sha256": external_receipt_sha256,
        "independent_bootstrap_commit": workflow_sha,
        "independent_bootstrap_tree": independent_bootstrap_tree,
        "review_receipt_sha256": receipt_sha256,
        "run_head_sha": head_sha,
        "run_id": run_id,
        "server_objects": server,
        "artifact_identity": identity,
        "sigstore_bundle_sha256": _sha256(external_bundle),
        "signed_review_bundle_sha256": _sha256(signed_bundle),
        "signing_window": signing_window,
    }


def derive_live_activation_closure(repository_root=ROOT):
    """The one indivisible derived transition, from raw evidence to Authority.

    It authenticates the raw sealed evidence bytes for itself - the exporter
    artifact, the external independent-review receipt against the exact clean
    checkout, its Sigstore bundle against the pinned trust, and the
    authenticated run and job timeline - derives F8 internally from exactly
    that authenticated evidence, and hands the derived package straight to the
    Authority boundary, which re-verifies it and binds it. No caller supplies
    a transport, a trust anchor, an evidence object, a closure flag or an
    evidence boolean, and nothing partial escapes: an unresolved or null
    evidence set never produces a package at all.
    """
    repository_root = Path(repository_root)
    evidence = _authenticate_live_activation_evidence(
        repository_root.parent / LIVE_EVIDENCE_DIRECTORY,
        repository_root=repository_root,
        base_commit=_reviewed_base_commit(repository_root),
    )
    reviewed = ACTIVATION.verify_activation_package(
        path=repository_root / ACTIVATION_PACKAGE_NAME, root=repository_root,
    )
    package = deepcopy(reviewed)
    server = evidence["server_objects"]
    delivery = evidence["decision_delivery"]

    for name in ACTIVATION.TARGET_REPOSITORIES:
        target = package["target_repositories"][name]
        target["created"] = True
        target["repository_id"] = (
            server["repository_id"] if name == ACTIVATION.SOURCE_REPOSITORY
            else delivery["repository_id"]
        )
        target["repository_node_id"] = (
            f"R_{name.split('/')[-1]}_{target['repository_id']}"
        )
    package["authorized_dispatch"]["run_id"] = evidence["run_id"]
    producer = package["producer_bindings"]
    producer["artifact_content_sha256"] = evidence["artifact_content_sha256"]
    producer["certificate_github_workflow_sha"] = evidence[
        "independent_bootstrap_commit"
    ]
    producer["envelope_sha256"] = evidence["envelope_sha256"]
    producer["review_receipt_sha256"] = evidence["review_receipt_sha256"]
    producer["sigstore_bundle_sha256"] = evidence["sigstore_bundle_sha256"]
    reviewed_source = package["reviewed_source"]
    reviewed_source["authority_head_commit"] = evidence["authority_head_commit"]
    reviewed_source["authority_head_tree"] = evidence["authority_head_tree"]
    reviewed_source["source_bootstrap_commit"] = evidence["run_head_sha"]
    reviewed_source["source_bootstrap_tree"] = server["head_tree"]
    reviewed_source["independent_bootstrap_commit"] = evidence[
        "independent_bootstrap_commit"
    ]
    # The delivery commit's own tree carries the decision file, so it is not
    # the bootstrap tree; the authenticated execution chain supplies that.
    reviewed_source["independent_bootstrap_tree"] = evidence[
        "independent_bootstrap_tree"
    ]
    package["external_activation_review"]["state"] = (
        ACTIVATION.EXTERNAL_REVIEW_AUTHENTICATED
    )
    package["external_activation_review"]["receipt_sha256"] = evidence[
        "external_receipt_sha256"
    ]
    package["activation_state"] = "ready"
    package["repositories_created"] = True
    package["workflows_written"] = True
    package["runs_observed"] = True
    package["post_activation_proof"]["live_evidence_pinned"] = True
    package["f8_closed"] = True
    package["activation_authorized"] = True

    require(
        reviewed["activation_authorized"] is False
        and reviewed["f8_closed"] is False
        and reviewed["external_activation_review"]["state"]
        == ACTIVATION.EXTERNAL_REVIEW_UNAVAILABLE,
        "the reviewed candidate must ship unauthorized, so the transition is real",
    )
    for name in ACTIVATION.PERMANENTLY_UNAUTHORIZED:
        require(
            package["authorizes"][name] is False,
            f"the derived activation package must never authorize {name}",
        )
    require(
        package["pre_activation_authorization"]
        == reviewed["pre_activation_authorization"]
        and package["authorizes"] == reviewed["authorizes"],
        "the derivation must preserve the exact reviewed pre-activation grant",
    )

    # --- the Authority boundary: it re-verifies and binds the derived object
    data = ACTIVATION.canonical_bytes(package)
    bound = _bind_derived_closure_at_authority(
        data, repository_root=repository_root,
    )
    return package, bound


def _seal_derived_closure(repository_root, package):
    """Write the derived closure beside the sealed evidence, read-only.

    Downstream generation and verification bind this exact digest, so the
    evidence the Authority accepted is the evidence every later manifest and
    receipt carries.
    """
    directory = Path(repository_root).parent / LIVE_EVIDENCE_DIRECTORY
    require(
        directory.is_dir() and not directory.is_symlink(),
        "the sealed live activation evidence directory is absent",
    )
    path = directory / DERIVED_CLOSURE_NAME
    data = ACTIVATION.canonical_bytes(package)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise SystemExit(
            "the derived activation closure already exists or is unsafe"
        ) from error
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, SEALED_FILE_MODE)
    observed = os.stat(path).st_mode & 0o777
    require(
        observed == SEALED_FILE_MODE,
        "the derived activation closure did not seal read-only",
    )
    sealed = path.read_bytes()
    require(sealed == data, "the sealed derived closure is not the derived bytes")
    return {"mode": format(observed, "04o"), "sha256": _sha256(sealed)}


def _bind_derived_closure_at_authority(data, *, repository_root):
    """Hand the derived package to Authority verification and bind it.

    The Authority re-derives readiness from the derived evidence itself; a
    package whose declared state contradicts what the evidence supports can
    never be bound. Nothing is written outside a private temporary path, and
    the caller receives only what Authority itself accepted.
    """
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / ACTIVATION_PACKAGE_NAME
        path.write_bytes(data)
        package, readiness = ACTIVATION.verify_activation_package(
            path=path, root=repository_root, with_readiness=True,
        )
    require(
        readiness["f8_closed"] is True
        and readiness["activation_authorized"] is True,
        "the Authority boundary did not derive a closed F8 from this evidence",
    )
    require(
        package["external_activation_review"]["receipt_sha256"] is not None,
        "the bound derived closure carries no external review receipt digest",
    )
    return {
        "activation_authorized": readiness["activation_authorized"],
        "activation_state": readiness["activation_state"],
        "derived_closure_sha256": _sha256(data),
        "derived_from": readiness["derived_from"],
        "external_review_receipt_sha256":
            package["external_activation_review"]["receipt_sha256"],
        "f8_closed": readiness["f8_closed"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Report or derive the F8 state of the activation package. "
                    "This helper accepts no evidence, transport, trust "
                    "material, closure flag or run identifier from a caller: "
                    "the closure phase authenticates the sealed live evidence "
                    "and the live server state for itself, and reports nothing "
                    "at all unless every proof passes.",
    )
    parser.add_argument("--phase", choices=PHASES, default=REPORT_PHASE)
    # The closed provenance record the one authorized activation run emits.
    # It is evidence to be checked, never an authorization to be believed.
    parser.add_argument("--activation-record", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--terminal-receipt", type=Path)
    parser.add_argument("--terminal-bundle", type=Path)
    arguments = parser.parse_args()
    if arguments.phase == TERMINAL_OUTPUT_INVENTORY_PHASE:
        require(arguments.artifact_root is not None,
                "the terminal output inventory phase requires --artifact-root")
        require(arguments.activation_record is None
                and arguments.terminal_receipt is None
                and arguments.terminal_bundle is None,
                "the terminal output inventory phase accepts only --artifact-root")
        _require_terminal_output_inventory(arguments.artifact_root)
        print(json.dumps({
            "activation_authorized": False,
            "approved": False,
            "release_authorized": False,
            "terminal_output_inventory_closed": True,
        }, sort_keys=True))
        return
    if arguments.phase == GENERATED_ARTIFACT_INVENTORY_PHASE:
        require(
            arguments.artifact_root is not None,
            "the generated artifact inventory phase requires --artifact-root",
        )
        require(
            arguments.activation_record is None
            and arguments.terminal_receipt is None
            and arguments.terminal_bundle is None,
            "the generated artifact inventory phase accepts only --artifact-root",
        )
        _require_generated_artifact_inventory(arguments.artifact_root)
        print(json.dumps({
            "activation_authorized": False,
            "approved": False,
            "generated_artifact_inventory_closed": True,
            "release_authorized": False,
        }, sort_keys=True))
        return
    if arguments.phase == GENERATED_ACTIVATION_PHASE:
        require(
            arguments.activation_record is not None,
            "the generated activation evidence phase requires the "
            "--activation-record the authorized activation run emitted",
        )
        require(
            arguments.terminal_receipt is None
            and arguments.terminal_bundle is None
            and arguments.artifact_root is None,
            "the generated activation phase accepts no terminal readback bytes",
        )
        print(json.dumps(
            _require_generated_activation_run(arguments.activation_record),
            sort_keys=True,
        ))
        return
    if arguments.phase == TERMINAL_READBACK_PHASE:
        require(
            arguments.terminal_receipt is not None
            and arguments.terminal_bundle is not None,
            "the terminal readback phase requires --terminal-receipt and --terminal-bundle",
        )
        require(
            arguments.activation_record is None,
            "the terminal readback phase accepts no activation record input",
        )
        require(
            arguments.artifact_root is None,
            "the terminal readback phase accepts no artifact root input",
        )
        receipt_path = arguments.terminal_receipt
        require(
            receipt_path.is_file() and not receipt_path.is_symlink(),
            "terminal activation receipt is absent or unsafe",
        )
        receipt_bytes = receipt_path.read_bytes()
        receipt = ACTIVATION._closed_json(receipt_bytes, "terminal activation receipt")
        _require_terminal_activation_receipt(receipt)
        bundle_path = arguments.terminal_bundle
        require(
            bundle_path.is_file() and not bundle_path.is_symlink()
            and bundle_path.parent.resolve() == receipt_path.parent.resolve(),
            "terminal activation bundle is absent or nonportable",
        )
        identity = _verify_terminal_sigstore_bundle(
            bundle_path.read_bytes(), subject_bytes=receipt_bytes,
            trust=_load_pinned_sigstore_trust(ROOT), receipt=receipt,
        )
        require(
            identity["identity"] == ACTIVATION_COLLECTOR_IDENTITY,
            "terminal receipt was not signed by the pinned collector identity",
        )
        print(json.dumps({
            "activation_authorized": False,
            "approved": False,
            "release_authorized": False,
            "release_succeeded": False,
            "terminal_readback_verified": True,
            "terminal_receipt_identity": identity,
        }, sort_keys=True))
        return
    if arguments.phase == CLOSURE_PHASE:
        package, bound = derive_live_activation_closure()
        sealed = _seal_derived_closure(ROOT, package)
        require(
            sealed["sha256"] == bound["derived_closure_sha256"],
            "the sealed derived closure is not the object Authority bound",
        )
        print(json.dumps({
            **bound,
            "derived_closure_mode": sealed["mode"],
            "derived_closure_path": DERIVED_CLOSURE_NAME,
            "live_evidence_authenticated": True,
        }, sort_keys=True))
        return
    package = ACTIVATION.verify_activation_package()
    print(json.dumps({
        "activation_authorized": package["activation_authorized"],
        "activation_state": package["activation_state"],
        "f8_closed": package["f8_closed"],
        "live_evidence_authenticated": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
