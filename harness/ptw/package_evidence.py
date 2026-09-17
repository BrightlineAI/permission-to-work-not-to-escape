"""Trusted metadata collection. No resolver, package import or build execution."""
from datetime import datetime, timezone
import hashlib
import json
import re
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

from cvss import CVSS2, CVSS3, CVSS4
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from .policy import Invalid, parse_json

MAX_DOWNLOAD = 20 * 1024 * 1024


class EvidenceError(Invalid):
    """Operational uncertainty: block, but do not increment violation counts."""


def pins(specs, *, extras=None):
    if not isinstance(specs, list) or not 1 <= len(specs) <= 64:
        raise Invalid("Supply between 1 and 64 exact package pins")
    result = {}
    for text in specs:
        if not isinstance(text, str) or len(text) > 250:
            raise Invalid("Invalid package pin")
        try:
            requirement = Requirement(text)
            parts = list(requirement.specifier)
            if (requirement.url or (requirement.extras and extras is None) or requirement.marker or len(parts) != 1
                    or parts[0].operator != "==" or "*" in parts[0].version):
                raise ValueError()
            version = str(Version(parts[0].version))
            name = canonicalize_name(requirement.name, validate=True)
        except ValueError as exc:
            raise Invalid("Use name==version only; no URLs, extras, markers or ranges") from exc
        if name in result:
            raise Invalid("Duplicate package name")
        result[name] = version
        if extras is not None and requirement.extras:
            extras[name] = sorted(canonicalize_name(x) for x in requirement.extras)
    return dict(sorted(result.items()))


def timestamp(value):
    try:
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            raise ValueError()
        return value.timestamp()
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvidenceError("Missing or malformed publication time") from exc


def severity(vulnerability):
    if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str) or not vulnerability["id"]:
        raise EvidenceError("Malformed vulnerability record")
    if vulnerability.get("withdrawn"):
        if timestamp(vulnerability["withdrawn"]) > time.time():
            raise EvidenceError("Advisory withdrawal is in the future")
        return None
    scores = []
    vectors = vulnerability.get("severity", [])
    if not isinstance(vectors, list):
        raise EvidenceError("Malformed severity")
    classes = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}
    for value in vectors:
        try:
            scores.append(float(classes[value["type"]](value["score"]).scores()[0]))
        except Exception as exc:
            raise EvidenceError("Unknown or invalid CVSS severity") from exc
    if not scores:
        raise EvidenceError("Advisory has no usable CVSS severity")
    return max(scores)


def evaluate(evidence, rules, now=None):
    now = time.time() if now is None else now
    checked = evidence.get("checked_at")
    if (not isinstance(checked, (int, float)) or not 0 <= now - checked <= rules["evidence_max_age_seconds"]):
        raise EvidenceError("Evidence is stale or has an invalid collection time")
    published = timestamp(evidence.get("published_at"))
    if published > now:
        raise EvidenceError("Publication time is in the future")
    vulnerabilities = evidence.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise EvidenceError("Missing vulnerability evidence")
    reasons = []
    if now - published < rules["min_release_age_days"] * 86400:
        reasons.append("artifact younger than minimum release age")
    uncertain = None
    for vulnerability in vulnerabilities:
        try:
            score = severity(vulnerability)
        except EvidenceError as exc:
            uncertain = exc
            continue
        if score is not None and score >= rules["deny_cvss_at_or_above"]:
            reasons.append(vulnerability["id"] + ": CVSS " + str(score))
    if uncertain and not reasons:
        raise uncertain
    return reasons


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise EvidenceError("Unexpected evidence or artifact redirect")


class PyPIEvidence:
    """Fixed public endpoints, no ambient proxy credentials or alternate index."""
    hosts = ("pypi.org", "api.osv.dev", "files.pythonhosted.org")

    def __init__(self, *, native=False, sources=(), python='/usr/bin/python3'):
        self.http = build_opener(ProxyHandler({}), NoRedirect())
        self.native, self.sources = native, set(sources)
        self.python = python
        self.deadline = None

    def fetch(self, url, data=None, limit=4 * 1024 * 1024):
        endpoint = urlsplit(url)
        if (endpoint.scheme != "https" or endpoint.hostname not in
                self.hosts
                or endpoint.username or endpoint.password or endpoint.port not in (None, 443)):
            raise EvidenceError("Unapproved evidence or download destination")
        request = Request(url, data=json.dumps(data).encode() if data is not None else None,
                          headers={"Content-Type": "application/json", "User-Agent": "permission-to-work/0.2"})
        try:
            remaining = self.deadline - time.monotonic() if self.deadline is not None else 15
            if remaining <= 0:
                raise EvidenceError('Evidence deadline reached')
            with self.http.open(request, timeout=min(15, remaining)) as response:
                raw = response.read(limit + 1)
            if self.deadline is not None and time.monotonic() >= self.deadline:
                raise EvidenceError('Evidence deadline reached')
            if len(raw) > limit:
                raise EvidenceError("Response exceeds size limit")
            return raw
        except EvidenceError:
            raise
        except Exception as exc:
            raise EvidenceError("Evidence or artifact unavailable: " + type(exc).__name__) from exc

    def json(self, url, data=None):
        try:
            return parse_json(self.fetch(url, data))
        except (ValueError, TypeError) as exc:
            raise EvidenceError("Invalid evidence JSON") from exc

    def assess(self, name, version):
        checked = time.time()
        release = self.json("https://pypi.org/pypi/" + name + "/" + version + "/json")
        try:
            if (canonicalize_name(release["info"]["name"]) != name
                    or Version(release["info"]["version"]) != Version(version)):
                raise ValueError()
            candidates = []
            tags_order = None
            if self.native:
                from .package_install import target_tags
                tags_order = {tag: i for i, tag in enumerate(target_tags(self.python))}
            for item in release["urls"]:
                if item.get("packagetype") != "bdist_wheel" or item.get("yanked") is not False:
                    continue
                wheel_name, wheel_version, _, tags = parse_wheel_filename(item["filename"])
                if wheel_name != name or wheel_version != Version(version):
                    continue
                universal = any(t.interpreter == "py3" and t.abi == "none" and t.platform == "any" for t in tags)
                compatible = [tags_order[str(t)] for t in tags if str(t) in tags_order] if tags_order else []
                if compatible or (not self.native and universal):
                    candidates.append((min(compatible) if compatible else 0, item))
            if not candidates:
                sources = [x for x in release["urls"] if x.get("packagetype") == "sdist" and x.get("yanked") is False]
                if name not in self.sources or not sources:
                    raise EvidenceError("No compatible wheel; source build requires explicit build authority")
                item = sorted(sources, key=lambda x: x["filename"])[0]
            else:
                item = sorted(candidates, key=lambda pair: (pair[0], pair[1]["filename"]))[0][1]
            if not re.fullmatch("[0-9a-f]{64}", item["digests"]["sha256"]):
                raise ValueError()
            if urlsplit(item["url"]).hostname != "files.pythonhosted.org":
                raise ValueError()
            return {"name": name, "version": version, "filename": item["filename"], "url": item["url"],
                    "sha256": item["digests"]["sha256"], "published_at": item["upload_time_iso_8601"],
                    "checked_at": checked, "vulnerabilities": self.advisories("PyPI", name, version),
                    "artifact_kind": item["packagetype"],
                    "source": "PyPI release JSON and OSV exact-version query"}
        except EvidenceError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise EvidenceError("Malformed or unsupported package evidence") from exc

    def advisories(self, ecosystem, name, version):
        vulnerabilities, token, seen = [], None, set()
        for _ in range(10):
            query = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            if token:
                query["page_token"] = token
            response = self.json("https://api.osv.dev/v1/query", query)
            if not isinstance(response, dict) or set(response) - {"vulns", "next_page_token"}:
                raise EvidenceError("Unexpected vulnerability response fields")
            rows = response.get("vulns", [])
            if not isinstance(rows, list):
                raise EvidenceError("Malformed advisory list")
            vulnerabilities.extend(rows)
            token = response.get("next_page_token")
            if not token:
                return vulnerabilities
            if not isinstance(token, str) or token in seen:
                raise EvidenceError("Invalid vulnerability pagination")
            seen.add(token)
        raise EvidenceError("Incomplete vulnerability response")

    def download(self, evidence, destination):
        raw = self.fetch(evidence["url"], limit=128 * 1024 * 1024 if self.native or self.sources else MAX_DOWNLOAD)
        if hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
            raise EvidenceError("Artifact SHA256 does not match assessed metadata")
        with destination.open("xb") as handle:
            handle.write(raw)
