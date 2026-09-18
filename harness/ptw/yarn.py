"""Original Yarn Classic metadata admission. No lock conversion or authority grant."""
import hashlib
import base64
import copy
import io
import json
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
from urllib.parse import urlsplit

from .npm import DEPENDENCIES, LIFECYCLE, NAME, semver_check
from .npm_resolution import declarations, local_path, node_inputs
from .package_evidence import EvidenceError
from .policy import Invalid, parse_json, save
from . import yarn_tool


class YarnEvidence:
    """Bind Classic's public alias to npm evidence without changing lock URLs.

    Only the exact public npm/Yarn origin substitution is supported. The broker
    downloads the metadata-authorized npm URL and checks the same SHA512; the
    installer also checks the original lock's SHA1. Private routes never alias.
    """
    NPM = 'https://registry.npmjs.org'
    YARN = 'https://registry.yarnpkg.com'

    def __init__(self, provider, plan):
        self.provider, self.records = provider, {}
        self.locked = {key: entry['resolved'].split('#')[0] for key, entry in plan.registry.items()}
        self.origins = {}
        for key, url in self.locked.items():
            self.origins.setdefault(key.rsplit('@', 1)[0], set()).add(self.origin(url))
        public = {o for origins in self.origins.values() for o in origins if o in (self.NPM, self.YARN)}
        self.default = self.YARN if public == {self.YARN} else self.NPM

    @staticmethod
    def origin(url):
        parsed = urlsplit(url)
        return parsed.scheme + '://' + parsed.netloc

    def url(self, name, version, url):
        # No credentials, query, fragment, nonstandard ports or lookalike hosts
        # can become a public alias. Private routing retains exact-origin checks.
        parsed = urlsplit(url)
        public = (self.origin(url) == self.NPM and not parsed.query and not parsed.fragment
                  and name not in getattr(self.provider, 'routes', {}))
        locked = self.locked.get(name + '@' + version)
        if locked is not None:
            alias = self.YARN + url[len(self.NPM):] if public else None
            return locked if locked == alias else url
        origins = self.origins.get(name, {self.default} if public else {self.origin(url)})
        if len(origins) != 1:
            raise EvidenceError('Yarn revision has ambiguous package origins')
        origin = next(iter(origins))
        if public and origin == self.YARN:
            return self.YARN + url[len(self.NPM):]
        if origin != self.origin(url):
            raise EvidenceError('Yarn revision changed package registry origin')
        return url

    def assess(self, name, version):
        record = self.provider.assess(name, version)
        projected = {**record, 'url': self.url(name, version, record['url'])}
        self.records[name, version] = (dict(record), dict(projected))
        return projected

    def download(self, record, destination):
        original, projected = self.records[record['name'], record['version']]
        if record != projected:
            raise EvidenceError('Yarn artifact evidence changed before download')
        self.provider.download(original, destination)
        record['sha256'] = original['sha256']


def build_order(dependencies):
    """Dependency-first traversal of verified locations, including non-build nodes.

    Cycles have no total dependency order. Break back edges deterministically,
    like Classic's cycle escape, while running each location at most once.
    """
    active, done, ordered = set(), set(), []
    for root in sorted(dependencies):
        stack = [(root, False)]
        while stack:
            node, finish = stack.pop()
            if finish:
                active.remove(node)
                done.add(node)
                ordered.append(node)
            elif node not in done and node not in active:
                active.add(node)
                stack.append((node, True))
                stack.extend((dep, False) for dep in sorted(dependencies[node], reverse=True))
    return ordered


def read_inputs(root):
    """Read only bounded manifests and the original lock, without source bytes.

    Native frozen installation validates the lock in the first tool milestone;
    independent locked graph/evidence admission is required before integration.
    """
    from .onboarding import data
    from .pnpm import source_path
    root = Path(root)
    for name in ('package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml'):
        if (root / name).exists() or (root / name).is_symlink():
            raise Invalid('Competing Node lock authorities')
    try:
        manifests, hashes = node_inputs(root)
    except (OSError, UnicodeError) as exc:
        raise Invalid('Yarn metadata must be ordinary in-project UTF-8 files') from exc
    files = {}
    for folder, manifest in manifests.items():
        if folder:
            source_path(folder)
        if set(manifest) & {'resolutions', 'flat', 'installConfig', 'pnpm'}:
            raise Invalid('Unsupported Yarn manifest configuration')
        if manifest.get('packageManager', 'yarn@' + yarn_tool.VERSION) != 'yarn@' + yarn_tool.VERSION:
            raise Invalid('Project packageManager differs from pinned Yarn Classic')
        if folder and 'workspaces' in manifest:
            raise Invalid('Nested Yarn workspace declarations are unsupported')
        if not folder and manifest.get('workspaces') and manifest.get('private') is not True:
            raise Invalid('Yarn workspaces require a private root')
        for name in ('.yarnrc', '.yarnrc.yml', '.npmrc', '.yarnclean', '.pnp.js', '.pnp.cjs'):
            path = root / folder / name
            if path.exists() or path.is_symlink():
                raise Invalid('Project Yarn configuration requires separate review')
        name = str(Path(folder) / 'package.json')
        raw = data(root / name)
        if hashlib.sha256(raw.encode()).hexdigest() != hashes[name]:
            raise Invalid('Yarn inputs changed during discovery')
        files[name] = raw
    lock = data(root / 'yarn.lock', limit=8 * 1024 * 1024)
    if '# yarn lockfile v1' not in lock[:200] or '__metadata:' in lock:
        raise Invalid('Only Yarn Classic v1 locks are admitted')
    files['yarn.lock'] = lock
    return files, manifests


class YarnPlan:
    """Original lock authority with independent graph and installed-byte checks."""
    def __init__(self, files, *, updating=False):
        from .workspace_policy import relative
        if not isinstance(files, dict) or not 2 <= len(files) <= 66:
            raise Invalid('Yarn requires bounded authoritative metadata')
        self.files = copy.deepcopy(files)
        # Reuse the filesystem admission rules on metadata only. No caller path
        # or project code is exposed to the parser or native installer.
        with tempfile.TemporaryDirectory(prefix='ptw-yarn-inputs-') as temporary:
            for name, text in self.files.items():
                relative(name)
                if (name != 'yarn.lock' and Path(name).name != 'package.json') or not isinstance(text, str) or len(text.encode()) > 8 * 1024 * 1024:
                    raise Invalid('Unexpected or oversized Yarn metadata')
                path = Path(temporary) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            admitted, self.manifests = read_inputs(temporary)
            if admitted != self.files:
                raise Invalid('Yarn metadata contains undeclared sources')
        self.original_lock = {'manager': 'yarn', 'files': self.files}
        self.lock = yarn_tool.parse_lock(self.files['yarn.lock'])
        self.locals = {p: m for p, m in self.manifests.items() if p}
        patterns = self.manifests[''].get('workspaces', [])
        if len({m.get('name') for m in self.locals.values()}) != len(self.locals):
            raise Invalid('Duplicate Yarn local package name')
        for folder, manifest in self.manifests.items():
            declarations(manifest, local_paths=self.locals, parent=folder)
            if folder and (not isinstance(manifest.get('name'), str) or
                    not re.fullmatch(NAME, manifest['name']) or
                    not all(semver_check([(manifest.get('version'), manifest.get('version'))]))):
                raise Invalid('Yarn local sources need canonical identities')
        self.workspaces = {m['name']: p for p, m in self.locals.items()
                           if any(Path(p).match(pattern) for pattern in patterns)}
        self.selected, self.registry, self.targets = {}, {}, {}
        checks = []
        for selector, entry in self.lock.items():
            if not isinstance(selector, str) or not isinstance(entry, dict) or set(entry) - {
                    'version', 'resolved', 'integrity', 'dependencies', 'optionalDependencies'}:
                raise Invalid('Unsupported Yarn lock entry')
            match = re.fullmatch('(' + NAME + ')@(.+)', selector)
            if not match or not isinstance(entry.get('version'), str):
                raise Invalid('Yarn lock needs canonical package selectors')
            name, constraint = match.groups()
            checks.append((entry['version'], entry['version']))
            if constraint.startswith('file:'):
                source = local_path('', constraint[5:])
                if (source not in self.locals or self.locals[source]['name'] != name or
                        self.locals[source]['version'] != entry['version'] or
                        set(entry) & {'resolved', 'integrity'}):
                    raise Invalid('Yarn file lock changes source identity')
                self.targets[selector] = ('local', source)
                continue
            checks.append((entry['version'], constraint))
            resolved, sri = entry.get('resolved'), entry.get('integrity')
            if not isinstance(resolved, str) or not isinstance(sri, str):
                raise Invalid('Yarn registry entries require origin and integrity')
            url, sep, fragment = resolved.partition('#')
            endpoint = urlsplit(url)
            if (endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password or
                    (sep and not re.fullmatch('[0-9a-f]{40}', fragment))):
                raise Invalid('Unsupported Yarn registry origin')
            try:
                raw = base64.b64decode(sri.removeprefix('sha512-'), validate=True)
                if len(raw) != 64 or sri != 'sha512-' + base64.b64encode(raw).decode():
                    raise ValueError()
            except ValueError as exc:
                raise Invalid('Yarn requires canonical SHA512 integrity') from exc
            key = name + '@' + entry['version']
            if key in self.registry and self.registry[key] != entry:
                raise Invalid('Conflicting Yarn entries for one package identity')
            self.registry[key], self.selected[key] = entry, entry['version']
            self.targets[selector] = ('registry', key)
        if len(self.selected) > 1024 or (checks and not all(semver_check(checks))):
            raise Invalid('Yarn version or range mismatch')
        if updating:
            # Only reviewed edits may omit old declaration comparisons. The
            # resulting new lock must pass the strict frozen graph checks.
            return
        # Traverse every original importer and every lock edge. Stale locks may
        # not silently resolve missing dependencies during a frozen install.
        pending, reached = list(self.manifests.items()), set()
        while pending:
            folder, manifest = pending.pop()
            for field in DEPENDENCIES:
                if folder is None and field in ('devDependencies', 'peerDependencies'):
                    continue
                deps = manifest.get(field, {})
                if not isinstance(deps, dict):
                    raise Invalid('Malformed Yarn dependency map')
                for name, spec in deps.items():
                    if field == 'peerDependencies':
                        continue  # Yarn v1 peers are verified against actual lookup.
                    kind, identity = self.reference(folder or '', name, spec)
                    if kind == 'registry' and identity not in reached:
                        reached.add(identity)
                        pending.append((None, self.registry[identity]))
        if reached != set(self.selected):
            raise Invalid('Yarn lock contains unreachable registry packages')

    def reference(self, folder, name, spec):
        if not isinstance(name, str) or not re.fullmatch(NAME, name) or not isinstance(spec, str):
            raise Invalid('Malformed Yarn dependency')
        if spec.startswith('file:'):
            source = local_path(folder, spec[5:])
            if source not in self.locals or self.locals[source]['name'] != name:
                raise Invalid('Yarn file dependency changes source identity')
            if self.targets.get(name + '@file:' + source) != ('local', source):
                raise Invalid('Yarn lock is stale: missing file source selector')
            return 'local', source
        if name in self.workspaces and all(semver_check([(self.locals[self.workspaces[name]]['version'], spec)])):
            return 'local', self.workspaces[name]
        selector = name + '@' + spec
        if selector not in self.targets:
            raise Invalid('Yarn lock is stale: missing selector ' + selector)
        return self.targets[selector]

    def bind_evidence(self, records):
        actual = {r['name'] + '@' + r['version']: r for r in records}
        if set(actual) != set(self.selected) or len(actual) != len(records):
            raise EvidenceError('Yarn evidence differs from locked identities')
        for key, entry in self.registry.items():
            record = actual[key]
            if (entry['resolved'].split('#')[0] != record['url'] or
                    entry['integrity'] != record['integrity']):
                raise EvidenceError('Yarn lock origin or integrity differs from evidence')

    def preserved(self, target):
        if any((Path(target) / n).read_bytes() != text.encode() for n, text in self.files.items()):
            raise EvidenceError('Native Yarn changed authoritative inputs')

    def install(self, artifacts, target, records, build_names, run_build):
        self.bind_evidence(records)
        target = Path(target)
        target.mkdir(parents=True, exist_ok=False)
        for name, text in self.files.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        mirror = target / '.ptw-yarn-mirror'
        mirror.mkdir()
        self.archive_contents, self.archive_manifests = {}, {}
        builds = set()
        expanded = 0
        for record in records:
            name, version = record['name'], record['version']
            key = name + '@' + version
            filename = record.get('filename')
            if not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.tgz', filename):
                raise EvidenceError('Unsafe Yarn artifact filename')
            artifact = Path(artifacts) / filename
            if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size > 128 * 1024 * 1024:
                raise EvidenceError('Yarn artifact must be a bounded ordinary file')
            raw = artifact.read_bytes()
            if yarn_tool.integrity(raw) != record['integrity']:
                raise EvidenceError('Yarn artifact integrity mismatch')
            fragment = self.registry[key]['resolved'].partition('#')[2]
            if fragment and hashlib.sha1(raw).hexdigest() != fragment:
                raise EvidenceError('Yarn resolved fragment differs from artifact')
            contents, seen = {}, set()
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
                members = archive.getmembers()
                expanded += sum(m.size for m in members)
                if len(members) > 20000 or expanded > 512 * 1024 * 1024:
                    raise EvidenceError('Yarn archive exceeds expansion limit')
                for member in members:
                    parts = member.name.rstrip('/').split('/')
                    if (parts[0] != 'package' or any(p in ('', '.', '..', 'node_modules') for p in parts) or
                            '\\' in member.name or member.name in seen or not (member.isfile() or member.isdir())):
                        raise EvidenceError('Unsafe Yarn archive member')
                    seen.add(member.name)
                    if member.isfile():
                        content = archive.extractfile(member).read()
                        contents['/'.join(parts[1:])] = hashlib.sha256(content).hexdigest()
                        if member.name == 'package/package.json':
                            manifest = parse_json(content)
                if 'package.json' not in contents or not isinstance(manifest, dict) or (manifest.get('name'), manifest.get('version')) != (name, version):
                    raise EvidenceError('Yarn archive identity mismatch')
                if manifest.get('bundledDependencies') or manifest.get('bundleDependencies'):
                    raise EvidenceError('Bundled Yarn packages require separate assessment')
                for field in ('dependencies', 'optionalDependencies'):
                    if manifest.get(field, {}) != self.registry[key].get(field, {}):
                        raise EvidenceError('Yarn lock edges differ from archive metadata')
                hooks = manifest.get('scripts', {})
                if not isinstance(hooks, dict):
                    raise EvidenceError('Malformed Yarn lifecycle scripts')
                if any(h in hooks for h in LIFECYCLE) or 'binding.gyp' in contents:
                    if name not in build_names or not callable(run_build):
                        raise EvidenceError('Yarn lifecycle build requires explicit controller approval')
                    if 'binding.gyp' in contents and 'install' not in hooks:
                        raise EvidenceError('Yarn native build requires an explicit install script')
                    builds.add(name)
                self.archive_contents[key], self.archive_manifests[key] = contents, manifest
            # Match Yarn's upstream offline mirror name, preserving the lock URL.
            mirror_name = urlsplit(record['url']).path.rsplit('/', 1)[-1]
            if name.startswith('@'):
                mirror_name = name.split('/')[0] + '-' + mirror_name
            if not re.fullmatch(r'@?[A-Za-z0-9_.+-]+\.tgz', mirror_name):
                raise EvidenceError('Unsupported Yarn offline mirror filename')
            destination = mirror / mirror_name
            if destination.exists() and destination.read_bytes() != raw:
                raise EvidenceError('Yarn offline mirror origin collision')
            destination.write_bytes(raw)
        result = yarn_tool.run(['install', '--frozen-lockfile'], cwd=target)
        self.preserved(target)
        if result.returncode:
            raise EvidenceError('Native Yarn frozen installation failed')
        # Cache and transport artifacts are not runtime authorities or outputs.
        for name in ('.ptw-yarn-cache', '.ptw-yarn-mirror'):
            shutil.rmtree(target / name)
        baseline = self.verify_installed(target, records)
        if builds:
            self.rebuild(target, builds, run_build, records, baseline)
            self.preserved(target)
            self.verify_installed(target, records, built=builds, baseline=baseline)
        save(target / '.ptw-yarn-sources.json', self.source_copies)
        return target

    def verify_installed(self, target, records, *, built=(), baseline=None):
        from .package_install import file_manifest
        self.bind_evidence(records)
        target = Path(target).resolve()
        contents = file_manifest(target)
        nodes = {target / p: m for p, m in self.manifests.items()}
        identities, installed = {}, {}
        self.source_copies = {p: [] for p in self.locals}
        for path in target.rglob('package.json'):
            folder = path.parent
            if 'node_modules' not in folder.relative_to(target).parts:
                continue
            name = folder.name if folder.parent.name == 'node_modules' else (
                folder.parent.name + '/' + folder.name if folder.parent.name.startswith('@') and folder.parent.parent.name == 'node_modules' else None)
            if name is None:
                continue
            manifest = parse_json(path.read_text())
            key = name + '@' + str(manifest.get('version'))
            prefix = str(folder.relative_to(target)) + '/'
            actual = {p[len(prefix):]: h for p, h in contents.items() if p.startswith(prefix) and not p[len(prefix):].startswith('node_modules/')}
            local = [p for p, m in self.locals.items() if m == manifest and actual == {
                'package.json': hashlib.sha256(self.files[p + '/package.json'].encode()).hexdigest()}]
            if manifest.get('name') != name:
                raise EvidenceError('Yarn installed package identity mismatch')
            if local:
                identity = ('local', local[0])
                self.source_copies[local[0]].append(str(folder.relative_to(target)))
            elif key in self.archive_contents:
                expected = self.archive_contents[key]
                if actual != expected and not (name in built and baseline is not None and actual.get('package.json') == expected['package.json']):
                    raise EvidenceError('Yarn installed content differs from assessed archive')
                identity = ('registry', key)
            else:
                raise EvidenceError('Yarn installed an unassessed package')
            installed[folder], nodes[folder], identities[folder] = manifest, manifest, identity

        def lookup(folder, name):
            while folder.is_relative_to(target):
                candidate = folder / 'node_modules' / name
                # A sibling NAME.js/NAME.json shadows the reviewed directory.
                if any(candidate.with_name(candidate.name + suffix).exists() for suffix in ('.js', '.json', '.node')):
                    raise EvidenceError('Yarn dependency shadowing path')
                if candidate.exists():
                    return candidate.resolve()
                if folder == target:
                    break
                folder = folder.parent
            return None

        checks, reached = [], set()
        dependencies = {str(p.relative_to(target)): set() for p in nodes}
        for folder, manifest in nodes.items():
            for field in DEPENDENCIES:
                if folder in installed and field == 'devDependencies':
                    continue
                deps = manifest.get(field, {})
                if not isinstance(deps, dict):
                    raise EvidenceError('Malformed installed Yarn dependencies')
                for name, spec in deps.items():
                    if field == 'dependencies' and name in manifest.get('optionalDependencies', {}):
                        continue
                    optional = field == 'optionalDependencies' or (field == 'peerDependencies' and manifest.get('peerDependenciesMeta', {}).get(name, {}).get('optional') is True)
                    found = lookup(folder, name)
                    if found is None:
                        if optional:
                            continue
                        raise EvidenceError('Yarn omitted required dependency: ' + name)
                    if found not in nodes or nodes[found].get('name') != name:
                        raise EvidenceError('Yarn dependency has an unreviewed lookup target')
                    dependencies[str(folder.relative_to(target))].add(str(found.relative_to(target)))
                    if field != 'peerDependencies':
                        parent = identities.get(folder, ('local', str(folder.relative_to(target))))
                        origin = parent[1] if parent[0] == 'local' else ''
                        origin = '' if origin == '.' else origin
                        expected = self.reference(origin, name, spec)
                        actual = identities.get(found, ('local', str(found.relative_to(target))))
                        if actual != expected:
                            raise EvidenceError('Yarn dependency differs from exact locked target')
                    if not spec.startswith('file:'):
                        checks.append((nodes[found]['version'], spec))
                    if found in installed:
                        reached.add(found)
        if reached != set(installed) or (checks and not all(semver_check(checks))):
            raise EvidenceError('Yarn installed graph violates original dependencies')
        tree = {}
        for path in target.rglob('*'):
            name, info = str(path.relative_to(target)), path.lstat()
            tree[name] = ('directory',) if stat.S_ISDIR(info.st_mode) else (
                'link' if stat.S_ISLNK(info.st_mode) else 'file', contents[name], bool(info.st_mode & 0o111))
        if baseline is not None:
            roots = {p for p, name in baseline['packages'].items() if name in built}
            for name in tree.keys() | baseline['tree'].keys():
                old, new = baseline['tree'].get(name), tree.get(name)
                if old == new:
                    continue
                output = next((Path(name).relative_to(root) for root in roots if Path(name).is_relative_to(root) and name != root), None)
                if (output is None or any(p in ('node_modules', '.bin', 'package.json') for p in output.parts) or
                        any(e is not None and e[0] == 'link' for e in (old, new))):
                    raise EvidenceError('Yarn build changed protected installation tree')
        return {'tree': tree, 'packages': {str(p.relative_to(target)): m['name'] for p, m in installed.items()},
                'dependencies': dependencies}

    def rebuild(self, target, names, run_build, records, baseline):
        from .supervisor import runtime_namespace
        directory, receipt = yarn_tool.verified()
        # Yarn run supplies its native lifecycle environment and local bin path.
        # Only explicit archive-derived hooks run; root/workspace hooks never do.
        jobs = []
        for location in build_order(baseline['dependencies']):
            name = baseline['packages'].get(location)
            if name not in names:
                continue
            folder = Path(target) / location
            path = folder / 'package.json'
            manifest = parse_json(path.read_text())
            for hook in LIFECYCLE:
                if hook not in manifest.get('scripts', {}):
                    continue
                jobs.append([location, hook, hashlib.sha256(path.read_bytes()).hexdigest()])
        # The supervisor copies /seed into /target before starting this payload.
        # One export contains every explicitly approved lifecycle hook; do not
        # chdir into a package before the supervisor has materialized the tree.
        script = '''
import hashlib,json,pathlib,subprocess,sys
for location,hook,expected in json.loads(sys.argv[1]):
    folder=pathlib.Path('/target')/location
    if hashlib.sha256((folder/'package.json').read_bytes()).hexdigest()!=expected:
        raise SystemExit('Yarn build changed installed package metadata')
    subprocess.run([sys.argv[2],'/yarn-tools/bin/yarn.js','--offline',
        '--no-default-rc','--non-interactive','--ignore-scripts','run',hook],
        cwd=folder,check=True)
'''
        command = runtime_namespace() + ['--ro-bind', str(directory / 'payload'), '/yarn-tools',
            '--bind', str(target), '/target', '--chdir', '/target',
            '--setenv', 'YARN_IGNORE_PATH', '1', '--setenv', 'CI', 'true',
            '--', '/usr/bin/python3', '-I', '-S', '-c', script, json.dumps(jobs), receipt['node']['path']]
        run_build(command)
        if yarn_tool.verified()[1] != receipt:
            raise EvidenceError('Yarn tooling changed during build')
        self.preserved(target)
        self.verify_installed(target, records, built=names, baseline=baseline)
