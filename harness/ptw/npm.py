"""Use npm's lock format, semver and offline installer behind the shared broker."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import time
from urllib.parse import quote, urlsplit

from .package_evidence import EvidenceError, PyPIEvidence
from .policy import Invalid, parse_json
from .supervisor import runtime_namespace

NAME = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
NODE_PATH = re.compile(r"node_modules/" + NAME + r"(?:/node_modules/" + NAME + r")*")
DEPENDENCIES = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LIFECYCLE = ("preinstall", "install", "postinstall")


def npm_root():
    command = os.environ.get("PTW_NPM") or shutil.which("npm")
    if not command:
        raise EvidenceError("npm is required for Node packages")
    root = Path(command).resolve().parent.parent
    if not (root / "bin/npm-cli.js").is_file():
        raise EvidenceError("Unsupported npm installation layout")
    return root


def semver_check(pairs):
    """Existing npm semver implementation; package code is never imported."""
    script = """
const fs = require('node:fs');
const semver = require('node:module').createRequire(process.argv[1])('semver');
const pairs = JSON.parse(fs.readFileSync(0, 'utf8'));
console.log(JSON.stringify(pairs.map(([v,r]) =>
  typeof r === 'string' && semver.validRange(r) !== null &&
  (v === null || (semver.valid(v) === v && semver.satisfies(v,r))))));
"""
    try:
        node = shutil.which("node")
        if not node:
            raise EvidenceError("Node is required for npm version validation")
        result = subprocess.run([str(Path(node).resolve()), "-e", script, str(npm_root() / "bin/npm-cli.js")],
            input=json.dumps(pairs), capture_output=True, text=True, timeout=15, check=True,
            env={"PATH": "/usr/bin:/bin"})
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise EvidenceError("Cannot validate npm versions with installed npm") from exc


def installation_plan(lock):
    """Dispatch explicit native authority without converting lock formats."""
    if isinstance(lock, dict) and lock.get('manager') == 'pnpm':
        if set(lock) != {'manager', 'files'}:
            raise Invalid('Malformed pnpm installation request')
        from .pnpm import PnpmPlan
        return PnpmPlan(lock['files'])
    return NpmPlan(lock)


class NpmPlan:
    def __init__(self, lock):
        if not isinstance(lock, dict) or lock.get("lockfileVersion") not in (2, 3):
            raise Invalid("npm needs a package-lock.json version 2 or 3")
        self.original_lock = copy.deepcopy(lock)
        nodes = lock.get("packages")
        if not isinstance(nodes, dict) or "" not in nodes or not 2 <= len(nodes) <= 2049:
            raise Invalid("npm lock must contain its root and 1 to 2048 package locations")
        self.nodes = copy.deepcopy(nodes)
        self.selected = {}
        self.locals, self.links, self.registry = {}, {}, {}
        from .workspace_policy import relative
        for path, entry in self.nodes.items():
            if not isinstance(entry, dict):
                raise Invalid('Malformed npm package entry')
            if path and not NODE_PATH.fullmatch(path) and '/node_modules/' not in path:
                relative(path)
                if any(p.startswith('.') or p in ('node_modules', 'private', 'secrets') for p in path.split('/')):
                    raise Invalid('Unsafe npm local source location')
                name = entry.get('name')
                if not isinstance(name, str) or not re.fullmatch(NAME, name) or not isinstance(entry.get('version'), str):
                    raise Invalid('Local npm source requires name and version')
                self.locals[path] = entry
        for path, entry in self.nodes.items():
            if entry.get('inBundle'):
                raise Invalid('Bundled package entries require separate assessment')
            if path == "":
                continue
            if path in self.locals:
                continue
            if not isinstance(path, str) or not (NODE_PATH.fullmatch(path) or any(
                    path.startswith(local + '/') and NODE_PATH.fullmatch(path[len(local) + 1:]) for local in self.locals)):
                raise Invalid("Unsafe npm package location")
            name = path.rsplit("node_modules/", 1)[1]
            if entry.get('link'):
                target = entry.get('resolved')
                if target not in self.locals or self.locals[target]['name'] != name:
                    raise Invalid('npm link must identify an approved in-project source')
                self.links[path] = target
                continue
            if entry.get("name", name) != name:
                raise Invalid("npm aliases cannot borrow another package's policy identity")
            version = entry.get("version")
            if not isinstance(version, str) or len(version) > 120:
                raise Invalid("Exact npm version required")
            if not isinstance(entry.get("resolved"), str) or not isinstance(entry.get("integrity"), str):
                raise Invalid("npm lock needs registry URL and integrity for every package")
            self.selected[name + "@" + version] = version
            self.registry[path] = entry
        if len(self.selected) > 1024:
            raise Invalid("Too many distinct npm package versions")
        if not all(semver_check([(v, v) for v in self.selected.values()])):
            raise Invalid("npm versions must be canonical exact semver")
        if self.locals and not all(semver_check([(e['version'], e['version']) for e in self.locals.values()])):
            raise Invalid('Local npm versions must be canonical semver')
        self.manifest = {"name": "ptw-private-environment", "version": "0.0.0", "private": True}
        for field in DEPENDENCIES:
            if field in nodes[""]:
                self.manifest[field] = nodes[""][field]
        if "peerDependenciesMeta" in nodes[""]:
            self.manifest["peerDependenciesMeta"] = nodes[""]["peerDependenciesMeta"]
        if 'workspaces' in nodes['']:
            self.manifest['workspaces'] = nodes['']['workspaces']
        self.nodes[""] = self.manifest
        self.lock = {"name": self.manifest["name"], "version": "0.0.0", "lockfileVersion": 3,
                     "requires": True, "packages": self.nodes}
        self.validate_graph()

    def validate_graph(self):
        checks = []
        for path, entry in self.nodes.items():
            if path in self.links:
                continue
            peer_meta = entry.get("peerDependenciesMeta", {})
            if not isinstance(peer_meta, dict) or any(not isinstance(v, dict) for v in peer_meta.values()):
                raise Invalid("Malformed npm peer metadata")
            for field in DEPENDENCIES:
                if path in self.registry and field == "devDependencies":
                    continue  # A registry dependency's own development tools are not installed.
                dependencies = entry.get(field, {})
                if not isinstance(dependencies, dict):
                    raise Invalid("Malformed npm dependency map")
                for name, constraint in dependencies.items():
                    if not re.fullmatch(NAME, name) or not isinstance(constraint, str) or len(constraint) > 1000:
                        raise Invalid("Malformed npm dependency")
                    local_constraint = constraint.startswith('file:')
                    if local_constraint:
                        from .npm_resolution import local_path
                        target = local_path(path, constraint[5:])
                        if target not in self.locals or self.locals[target]['name'] != name:
                            raise Invalid('npm file dependency is not a confined local source')
                    else:
                        checks.append((None, constraint))
                    if field == "dependencies" and name in entry.get("optionalDependencies", {}):
                        continue
                    # Peers resolve beside the package, not inside its own node_modules.
                    parent = path.rsplit("/node_modules/", 1)[0] if "/node_modules/" in path else ""
                    candidate = parent if field == "peerDependencies" else path
                    found = None
                    while True:
                        location = (candidate + "/" if candidate else "") + "node_modules/" + name
                        if location in self.nodes:
                            if local_constraint and self.links.get(location) != target:
                                raise Invalid('npm file dependency resolves to a different source identity')
                            selected = self.locals[self.links[location]] if location in self.links else self.nodes[location]
                            found = selected['version']
                            break
                        if not candidate:
                            break
                        candidate = candidate.rsplit("/node_modules/", 1)[0] if "/node_modules/" in candidate else ""
                    optional = field == "optionalDependencies" or (
                        field == "peerDependencies" and entry.get("peerDependenciesMeta", {}).get(name, {}).get("optional") is True)
                    if found is None:
                        if optional:
                            continue
                        raise Invalid("Locked dependency is missing: " + name + " required by " + (path or "root"))
                    if not local_constraint:
                        checks.append((found, constraint))
        if checks and not all(semver_check(checks)):
            raise Invalid("npm dependency/peer version mismatch or unsupported dependency source")

    def bind_evidence(self, evidence):
        by_name = {e["name"] + "@" + e["version"]: e for e in evidence}
        for path, entry in self.registry.items():
            name = path.rsplit("node_modules/", 1)[1]
            e = by_name[name + "@" + entry["version"]]
            if entry["resolved"] != e["url"] or entry["integrity"] != e["integrity"]:
                raise EvidenceError("npm lock artifact differs from the public registry: " + name)

    def inspect_archives(self, artifacts, evidence, build_names):
        scripts = set()
        expanded = 0
        for e in evidence:
            with tarfile.open(artifacts / e["filename"], "r|gz") as archive:
                seen, manifest = set(), None
                for member in archive:
                    expanded += member.size
                    if len(seen) >= 20000 or expanded > 512 * 1024 * 1024:
                        raise EvidenceError("npm archive set exceeds expansion limit")
                    p = PurePosixPath(member.name)
                    if (not p.parts or p.parts[0] != "package" or p.is_absolute() or
                            any(x in ("", ".", "..") for x in member.name.rstrip("/").split("/")) or
                            "\\" in member.name or member.name in seen or not (member.isfile() or member.isdir())):
                        raise EvidenceError("Unsafe npm archive member")
                    seen.add(member.name)
                    if "node_modules" in p.parts[1:]:
                        raise EvidenceError("Bundled npm dependencies must be separately assessed")
                    if member.name == "package/package.json":
                        if member.size > 1024 * 1024:
                            raise EvidenceError("npm package metadata is too large")
                        manifest = parse_json(archive.extractfile(member).read())
                if not isinstance(manifest, dict) or manifest.get("name") != e["name"] or manifest.get("version") != e["version"]:
                    raise EvidenceError("npm archive identity differs from the assessed release")
                if manifest.get("bundleDependencies") or manifest.get("bundledDependencies"):
                    raise EvidenceError("Bundled dependencies are not independently checked")
                for path, entry in self.registry.items():
                    if path and path.rsplit("node_modules/", 1)[1] == e["name"] and entry["version"] == e["version"]:
                        for field in ("dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta"):
                            if manifest.get(field, {}) != entry.get(field, {}):
                                raise EvidenceError("Archive dependency metadata differs from lock: " + e["name"] + "/" + field)
                hooks = manifest.get("scripts", {})
                if not isinstance(hooks, dict):
                    raise EvidenceError("Malformed npm lifecycle scripts")
                needs_build = any(k in hooks for k in LIFECYCLE) or "package/binding.gyp" in seen
                # npm's rebuild uses this lock hint. Derive it from the archive;
                # an untrusted lock must not suppress an authorized build.
                for path, entry in self.registry.items():
                    if path and path.rsplit("node_modules/", 1)[1] == e["name"] and entry["version"] == e["version"]:
                        entry["hasInstallScript"] = needs_build
                if needs_build:
                    if e["name"] not in build_names:
                        raise EvidenceError("Lifecycle build requires explicit policy authority: npm:" + e["name"])
                    scripts.add(e["name"])
        return scripts

    def install(self, artifacts, target, evidence, build_names, run_build):
        self.bind_evidence(evidence)
        builds = self.inspect_archives(artifacts, evidence, build_names)
        target.mkdir(mode=0o700)
        (target / "package.json").write_text(json.dumps(self.manifest))
        (target / "package-lock.json").write_text(json.dumps(self.lock))
        for path, entry in self.locals.items():
            folder = target / path
            folder.mkdir(parents=True)
            # Only reviewed metadata placeholders live in the package cache.
            # Actual source is mounted from the authorized command snapshot.
            (folder / 'package.json').write_text(json.dumps(entry))
        driver = artifacts / "install.cjs"
        driver.write_text("""
const cp = require('node:child_process');
const fs = require('node:fs');
const plan = JSON.parse(fs.readFileSync('/artifacts/plan.json','utf8'));
const common = ['--offline','--ignore-scripts','--no-audit','--no-fund','--bin-links=true',
 '--userconfig=/tmp/empty-user-npmrc','--globalconfig=/tmp/empty-global-npmrc','--cache=/tmp/npm-cache','--prefix=/target'];
function npm(args) { cp.execFileSync('/usr/bin/node',['/npm/bin/npm-cli.js',...args],{stdio:'inherit'}); }
if (plan.artifacts.length) npm(['cache','add',...plan.artifacts.map(x=>'/artifacts/'+x),...common]);
npm(['ci',...common,'--engine-strict','--include=dev','--include=optional','--include=peer']);
for (const name of plan.builds) {
 npm(['rebuild',name,...common.filter(x=>x!=='--ignore-scripts'),'--ignore-scripts=false']);
}
""")
        (artifacts / "plan.json").write_text(json.dumps({"artifacts": [e["filename"] for e in evidence], "builds": sorted(builds)}))
        command = runtime_namespace() + ["--ro-bind", str(npm_root()), "/npm",
            "--ro-bind", str(artifacts), "/artifacts", "--bind", str(target), "/target",
            "--chdir", "/target", "--", "/usr/bin/node", "/artifacts/install.cjs"]
        run_build(command)
        actual = {}
        for path in target.rglob('package.json'):
            relative = str(path.parent.relative_to(target))
            if relative in self.registry or NODE_PATH.fullmatch(relative):
                info = parse_json(path.read_text())
                actual[relative] = (info.get("name"), info.get("version"))
        # Optional platform-incompatible entries may be absent, but no unreviewed
        # package or mismatched version may be installed.
        for path, (name, version) in actual.items():
            if path not in self.nodes or name != path.rsplit("node_modules/", 1)[1] or version != self.nodes[path]["version"]:
                raise EvidenceError("npm installed a package outside the reviewed lock")
        for path, entry in self.registry.items():
            if path and path not in actual and not entry.get("optional"):
                raise EvidenceError("npm omitted a required package: " + path)
        # Do not let a forged optional flag hide a required dependency omitted by
        # platform selection or a failing lifecycle script.
        full_nodes = self.nodes
        try:
            self.nodes = {p: e for p, e in full_nodes.items() if not p or p in actual or p in self.locals or p in self.links}
            self.validate_graph()
        finally:
            self.nodes = full_nodes
        # The lock contains metadata for every workspace, including members a
        # narrower command cannot read. It is not needed at runtime. Receipts
        # retain the reviewed lock hash outside the package mount.
        (target / 'package-lock.json').unlink()
        (target / 'node_modules/.package-lock.json').unlink(missing_ok=True)


class NpmEvidence(PyPIEvidence):
    hosts = ("registry.npmjs.org", "api.osv.dev")

    def packument(self, name):
        return parse_json(self.fetch('https://registry.npmjs.org/' + quote(name, safe=''), limit=16 * 1024 * 1024))

    def artifact_allowed(self, url, name):
        endpoint = urlsplit(url)
        return (endpoint.scheme == 'https' and endpoint.hostname == 'registry.npmjs.org' and
                not endpoint.username and not endpoint.password and endpoint.port in (None, 443))

    def assess(self, name, version):
        checked = time.time()
        try:
            document = self.packument(name)
            record = document["versions"][version]
            if record["name"] != name or record["version"] != version:
                raise ValueError()
            dist = record["dist"]
            integrity = dist["integrity"]
            if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
                raise ValueError()
            expected = base64.b64decode(integrity[7:], validate=True)
            if len(expected) != 64 or base64.b64encode(expected).decode() != integrity[7:]:
                raise ValueError()
            if not self.artifact_allowed(dist['tarball'], name):
                raise ValueError()
            return {"name": name, "version": version, "filename": hashlib.sha256((name + "@" + version).encode()).hexdigest() + ".tgz",
                    "url": dist["tarball"], "integrity": integrity, "sha256": "",
                    "published_at": document["time"][version], "checked_at": checked,
                    "vulnerabilities": self.advisories("npm", name, version), "artifact_kind": "npm-tarball"}
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            if isinstance(exc, EvidenceError):
                raise
            raise EvidenceError("Missing or invalid npm release evidence") from exc

    def download(self, evidence, destination):
        raw = self.fetch(evidence["url"], limit=128 * 1024 * 1024)
        if "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode() != evidence["integrity"]:
            raise EvidenceError("npm artifact integrity mismatch")
        evidence["sha256"] = hashlib.sha256(raw).hexdigest()
        with destination.open("xb") as handle:
            handle.write(raw)
