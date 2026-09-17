"""Frozen pnpm v9 input admission and broker-fed native installation.

YAML is data only. pnpm owns workspace/peer topology and frozen installation;
this adapter never converts the authoritative project lock to an npm lock.
"""
import base64
import copy
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import time

import yaml

from . import pnpm_tool
from .dependency_resolution import ResolutionError
from .npm import DEPENDENCIES, LIFECYCLE, NAME, semver_check
from .npm_resolution import declarations, local_path
from .package_evidence import EvidenceError, evaluate
from .policy import Invalid, digest, parse_json, save
from .workspace_policy import directory_fd, relative


class DataLoader(yaml.BaseLoader):
    """No tags, aliases, duplicate keys or unbounded nested structures."""
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise Invalid('pnpm YAML aliases are unsupported')
        event = self.peek_event()
        if event.tag is not None:
            raise Invalid('pnpm YAML tags are unsupported')
        self.nodes = getattr(self, 'nodes', 0) + 1
        self.depth = getattr(self, 'depth', 0) + 1
        if self.nodes > 100000 or self.depth > 40:
            raise Invalid('pnpm YAML exceeds structural limits')
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode) or key.value in result or key.value == '<<':
                raise Invalid('pnpm YAML requires unique scalar mapping keys')
            result[key.value] = self.construct_object(value, deep=deep)
        return result


def mapping(text):
    if not isinstance(text, str) or len(text.encode()) > 8 * 1024 * 1024:
        raise Invalid('pnpm YAML exceeds input limit')
    try:
        result = yaml.load(text, Loader=DataLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise Invalid('Malformed pnpm YAML') from exc
    if not isinstance(result, dict):
        raise Invalid('Expected pnpm YAML mapping')
    return result


def source_path(path):
    relative(path)
    if any(p.startswith('.') or p in ('node_modules', 'private', 'secrets', 'store', 'cache', 'state',
                                     'resolver-home') for p in path.split('/')):
        raise Invalid('Unsafe pnpm source location')
    return path


def read_inputs(root):
    """Read metadata only, checking parent confinement before any source read."""
    from .onboarding import data
    root = Path(root)
    files, manifests = {}, {}

    def read(name):
        fd = directory_fd((root / name).parent)
        os.close(fd)
        files[name] = data(root / name, 8 * 1024 * 1024)
        return files[name]

    if any((root / n).exists() for n in ('package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock')):
        raise Invalid('Competing Node lock authorities require explicit operator selection')
    read('pnpm-lock.yaml')
    folders = ['']
    if (root / 'pnpm-workspace.yaml').exists():
        workspace = mapping(read('pnpm-workspace.yaml'))
        if set(workspace) != {'packages'} or not isinstance(workspace['packages'], list):
            raise Invalid('Only explicit pnpm workspace package paths are supported')
        for pattern in workspace['packages']:
            source_path(pattern)
            if '**' in pattern or any(c in pattern for c in '?[]!{}'):
                raise Invalid('pnpm workspace globs support single directory wildcards')
            for path in root.glob(pattern):
                if len(folders) >= 64:
                    raise Invalid('Too many pnpm workspace sources')
                if path.is_symlink() or not path.is_dir():
                    raise Invalid('pnpm workspace must be an ordinary directory')
                folders.append(source_path(str(path.relative_to(root))))
    for folder in folders:
        if folder in manifests:
            continue
        manifest = parse_json(read(str(Path(folder) / 'package.json')))
        if not isinstance(manifest, dict) or 'pnpm' in manifest or 'workspaces' in manifest:
            raise Invalid('Unsupported pnpm manifest configuration')
        manager = manifest.get('packageManager')
        if manager is not None and manager != 'pnpm@' + pnpm_tool.VERSION:
            raise Invalid('Project packageManager differs from the pinned pnpm tool')
        manifests[folder] = manifest
        for field in DEPENDENCIES:
            deps = manifest.get(field, {})
            if not isinstance(deps, dict):
                raise Invalid('Expected pnpm dependency map')
            for value in deps.values():
                if isinstance(value, str) and value.startswith('file:'):
                    path = source_path(local_path(folder, value[5:]))
                    if path not in folders:
                        if len(folders) >= 64:
                            raise Invalid('Too many pnpm local sources')
                        folders.append(path)
    return files, manifests


class PnpmPlan:
    def __init__(self, files, *, updating=False):
        if not isinstance(files, dict) or not 2 <= len(files) <= 66:
            raise Invalid('pnpm requires bounded authoritative metadata')
        self.files = copy.deepcopy(files)
        self.original_lock = {'manager': 'pnpm', 'files': self.files}
        self.manifests = {}
        for name, text in files.items():
            relative(name)
            if not isinstance(text, str) or len(text.encode()) > 8 * 1024 * 1024:
                raise Invalid('pnpm metadata exceeds input limits')
            if name in ('pnpm-lock.yaml', 'pnpm-workspace.yaml'):
                continue
            if Path(name).name != 'package.json':
                raise Invalid('Unexpected pnpm metadata file')
            folder = str(Path(name).parent)
            folder = '' if folder == '.' else source_path(folder)
            manifest = parse_json(text)
            if not isinstance(manifest, dict) or 'pnpm' in manifest or 'workspaces' in manifest:
                raise Invalid('Unsupported pnpm manifest configuration')
            if manifest.get('packageManager', 'pnpm@' + pnpm_tool.VERSION) != 'pnpm@' + pnpm_tool.VERSION:
                raise Invalid('Project packageManager differs from the pinned pnpm tool')
            self.manifests[folder] = manifest
        if '' not in self.manifests or 'pnpm-lock.yaml' not in files:
            raise Invalid('pnpm requires a root manifest and lock')
        if 'pnpm-workspace.yaml' in files:
            config = mapping(files['pnpm-workspace.yaml'])
            if set(config) != {'packages'} or not isinstance(config['packages'], list):
                raise Invalid('Unsupported pnpm workspace configuration')
            for pattern in config['packages']:
                source_path(pattern)
                if '**' in pattern or any(c in pattern for c in '?[]!{}'):
                    raise Invalid('Unsupported pnpm workspace pattern')
        self.locals = {p: m for p, m in self.manifests.items() if p}
        for manifest in self.locals.values():
            if (not isinstance(manifest.get('name'), str) or not re.fullmatch(NAME, manifest['name']) or
                    not isinstance(manifest.get('version'), str) or
                    not all(semver_check([(manifest['version'], manifest['version'])]))):
                raise Invalid('Local pnpm sources require canonical package identities')
        identities = {m.get('name'): p for p, m in self.locals.items()}
        if len(identities) != len(self.locals):
            raise Invalid('Duplicate local pnpm package name')
        for folder, manifest in self.manifests.items():
            clean = copy.deepcopy(manifest)
            for field in DEPENDENCIES:
                deps = clean.get(field, {})
                if not isinstance(deps, dict):
                    raise Invalid('Expected pnpm dependency map')
                for name, spec in list(deps.items()):
                    if isinstance(spec, str) and spec.startswith('workspace:'):
                        if name not in identities:
                            raise Invalid('Workspace dependency has no admitted local source')
                        constraint = spec[10:]
                        version = self.locals[identities[name]].get('version')
                        if constraint not in ('*', '^', '~') and not all(semver_check([(version, constraint)])):
                            raise Invalid('Workspace dependency version mismatch')
                        deps[name] = version
            declarations(clean, local_paths=self.locals, parent=folder)
        self.lock = mapping(files['pnpm-lock.yaml'])
        if self.lock.get('lockfileVersion') != '9.0' or set(self.lock) - {
                'lockfileVersion', 'settings', 'importers', 'packages', 'snapshots'}:
            raise Invalid('Only the pnpm v9 lock schema is admitted')
        if self.lock.get('settings') != {'autoInstallPeers': 'true', 'excludeLinksFromLockfile': 'false'}:
            raise Invalid('Unsupported pnpm lock settings')
        importers = self.lock.get('importers')
        if not isinstance(importers, dict) or '.' not in importers:
            raise Invalid('Malformed pnpm importers')
        for path, importer in importers.items():
            folder = '' if path == '.' else source_path(path)
            if folder not in self.manifests or not isinstance(importer, dict) or set(importer) - set(DEPENDENCIES):
                raise Invalid('pnpm importer is outside admitted manifests')
            if updating:
                continue  # Old lock is never installed or passed to the solver.
            for field in DEPENDENCIES:
                entries = importer.get(field, {})
                if not isinstance(entries, dict):
                    raise Invalid('Malformed pnpm importer dependencies')
                declared = self.manifests[folder].get(field, {})
                if field == 'peerDependencies' and not entries:
                    continue  # Native frozen validation handles root peer resolution.
                if set(entries) != set(declared):
                    raise Invalid('pnpm lock is stale against manifest declarations')
                for name, entry in entries.items():
                    if not isinstance(entry, dict) or set(entry) != {'specifier', 'version'} or entry['specifier'] != declared[name]:
                        raise Invalid('pnpm lock is stale against manifest declarations')
                    version = entry['version']
                    if not isinstance(version, str):
                        raise Invalid('Malformed pnpm locked dependency')
                    if version.startswith('link:'):
                        target = source_path(local_path(folder, version[5:]))
                        spec = declared[name]
                        expected = identities.get(name) if spec.startswith('workspace:') else (
                            local_path(folder, spec[5:]) if spec.startswith('file:') else None)
                        if target != expected or target not in self.locals:
                            raise Invalid('pnpm link changes source identity')
                    elif name + '@' + version not in self.lock.get('snapshots', {}):
                        raise Invalid('pnpm importer lacks an assessed peer context')
        packages = self.lock.get('packages', {})
        snapshots = self.lock.get('snapshots', {})
        if not isinstance(packages, dict) or not isinstance(snapshots, dict) or len(packages) > 1024 or len(snapshots) > 2048:
            raise Invalid('pnpm graph exceeds package limits')
        self.selected, self.registry, self.local_packages = {}, {}, {}
        for key, entry in packages.items():
            if not isinstance(key, str) or not isinstance(entry, dict):
                raise Invalid('Malformed pnpm package')
            name, sep, version = key.rpartition('@')
            resolution = entry.get('resolution')
            if sep and re.fullmatch(NAME, name) and version.startswith('file:'):
                path = source_path(version[5:])
                if (path not in self.locals or self.locals[path]['name'] != name or
                        resolution != {'directory': path, 'type': 'directory'} or
                        entry.get('version', self.locals[path]['version']) != self.locals[path]['version']):
                    raise Invalid('pnpm file dependency changes source identity')
                self.local_packages[key] = path
                continue
            if not sep or not re.fullmatch(NAME, name) or not all(semver_check([(version, version)])):
                raise Invalid('pnpm package needs a canonical registry identity')
            if not isinstance(resolution, dict) or set(resolution) - {'integrity', 'tarball'}:
                raise Invalid('pnpm requires registry integrity and an approved origin')
            sri = resolution.get('integrity', '')
            try:
                raw = base64.b64decode(sri.removeprefix('sha512-'), validate=True)
                if len(raw) != 64 or sri != 'sha512-' + base64.b64encode(raw).decode():
                    raise ValueError()
            except (ValueError, TypeError, AttributeError) as exc:
                raise Invalid('pnpm requires canonical SHA512 integrity') from exc
            self.selected[key] = version
            self.registry[key] = entry
        # Snapshots are native peer contexts, not new policy identities.
        for key, entry in snapshots.items():
            if not isinstance(key, str) or not isinstance(entry, dict) or key.split('(', 1)[0] not in packages:
                raise Invalid('pnpm snapshot has no assessed package identity')
            if set(entry) - {'dependencies', 'optionalDependencies', 'transitivePeerDependencies', 'optional'}:
                raise Invalid('Unsupported pnpm snapshot fields')
            for field in ('dependencies', 'optionalDependencies'):
                deps = entry.get(field, {})
                if not isinstance(deps, dict):
                    raise Invalid('Malformed pnpm snapshot dependencies')
                for name, version in deps.items():
                    if (not re.fullmatch(NAME, name) or not isinstance(version, str) or
                            name + '@' + version not in snapshots):
                        raise Invalid('pnpm snapshot dependency lacks an assessed peer context')

    def bind_evidence(self, records):
        actual = {r['name'] + '@' + r['version']: r for r in records}
        if set(actual) != set(self.selected) or len(actual) != len(records):
            raise EvidenceError('pnpm evidence differs from locked package identities')
        for key, entry in self.registry.items():
            resolution, record = entry['resolution'], actual[key]
            if resolution['integrity'] != record['integrity']:
                raise EvidenceError('pnpm lock integrity differs from registry evidence')
            # A missing tarball means native pnpm's default public registry.
            default = 'https://registry.npmjs.org/' + record['name'] + '/-/' + record['name'].split('/')[-1] + '-' + record['version'] + '.tgz'
            if resolution.get('tarball', default) != record['url']:
                raise EvidenceError('pnpm lock origin differs from registry evidence')

    def materialize(self, target):
        target = Path(target)
        target.mkdir(parents=True, exist_ok=False)
        for name, text in self.files.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def preserved(self, target):
        if any((Path(target) / n).read_bytes() != text.encode() for n, text in self.files.items()):
            raise Invalid('Native pnpm changed authoritative inputs')

    def assess(self, provider, rules):
        records, deadline = [], time.monotonic() + 180
        if len(self.selected) > 256:
            raise ResolutionError('budget_exhausted', 'pnpm candidate assessment budget exhausted')
        if hasattr(provider, 'deadline'):
            provider.deadline = deadline
        for key, version in self.selected.items():
            if time.monotonic() >= deadline:
                raise ResolutionError('budget_exhausted', 'pnpm candidate assessment deadline reached')
            record = provider.assess(key.rsplit('@', 1)[0], version)
            if time.monotonic() >= deadline:
                raise ResolutionError('budget_exhausted', 'pnpm candidate assessment deadline reached')
            if (record.get('name'), record.get('version')) != (key.rsplit('@', 1)[0], version):
                raise EvidenceError('pnpm candidate evidence identity mismatch')
            if evaluate(record, rules):
                raise ResolutionError('unsatisfiable', 'Frozen pnpm lock violates package policy; review an update')
            records.append(record)
        self.bind_evidence(records)
        return records

    def inspect(self, stage):
        self.materialize(stage)
        result = pnpm_tool.run(['list', '--recursive', '--json', '--long', '--depth', 'Infinity', '--lockfile-only'], cwd=stage)
        self.preserved(stage)
        if result.returncode:
            raise Invalid('Native pnpm rejected the locked graph')
        graph = parse_json(result.stdout)
        if not isinstance(graph, list) or not graph:
            raise Invalid('Native pnpm returned an invalid graph')
        return graph

    def install(self, artifacts, target, records, build_names=(), run_build=None):
        """Native frozen import primitive; controller publication is a separate layer.

        No project code is copied. Local metadata placeholders retain native
        links; the controller must overlay only authorized source snapshots.
        Dependency lifecycle execution needs explicit policy authority and the
        controller's bounded build supervisor. Root and local hooks stay disabled.
        """
        self.bind_evidence(records)
        self.archive_contents = {}
        seed = Path(target).with_name(Path(target).name + '-fetch')
        seed.mkdir()
        (seed / 'artifacts').mkdir()
        # fetch runs a single synthetic project at '.'. Without that importer,
        # pnpm marks the recipe modified and serializes it even when frozen.
        # Keep separate package roots so different versions of one name survive.
        packages, roots, builds = {}, {'.': {}}, set()
        for record in records:
            name, version = record['name'], record['version']
            key = name + '@' + version
            filename = hashlib.sha256(key.encode()).hexdigest() + '.tgz'
            artifact_name = record.get('filename')
            if not isinstance(artifact_name, str) or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.tgz', artifact_name):
                raise EvidenceError('Unsafe pnpm artifact filename')
            artifact = Path(artifacts) / artifact_name
            if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size > 128 * 1024 * 1024:
                raise EvidenceError('pnpm artifact must be a bounded ordinary file')
            raw = artifact.read_bytes()
            if pnpm_tool.integrity(raw) != record['integrity']:
                raise EvidenceError('pnpm artifact integrity mismatch')
            (seed / 'artifacts' / filename).write_bytes(raw)
            packages[key] = {'resolution': {'integrity': record['integrity'], 'tarball': 'file:artifacts/' + filename}}
            # Admit archive data before native extraction or executable preparation.
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
                members = archive.getmembers()
                if len(members) > 20000 or sum(m.size for m in members) > 128 * 1024 * 1024:
                    raise EvidenceError('pnpm archive exceeds expansion limit')
                seen, manifest, contents = set(), None, {}
                for member in members:
                    parts = member.name.rstrip('/').split('/')
                    if (not parts or parts[0] != 'package' or any(p in ('', '.', '..') for p in parts) or
                            '\\' in member.name or member.name in seen or 'node_modules' in parts or
                            not (member.isfile() or member.isdir())):
                        raise EvidenceError('Unsafe pnpm archive member')
                    seen.add(member.name)
                    if member.isfile():
                        content = archive.extractfile(member).read()
                        contents['/'.join(parts[1:])] = hashlib.sha256(content).hexdigest()
                    if member.name == 'package/package.json':
                        manifest = parse_json(content)
                if not isinstance(manifest, dict) or (manifest.get('name'), manifest.get('version')) != (name, version):
                    raise EvidenceError('pnpm archive identity mismatch')
                if manifest.get('bundledDependencies') or manifest.get('bundleDependencies'):
                    raise EvidenceError('Bundled pnpm dependencies are unsupported')
                if not isinstance(manifest.get('scripts', {}), dict):
                    raise EvidenceError('Malformed pnpm scripts')
                if any(k in manifest.get('scripts', {}) for k in LIFECYCLE) or 'package/binding.gyp' in seen:
                    if name not in build_names or not callable(run_build):
                        raise EvidenceError('pnpm lifecycle build requires explicit controller approval')
                    if 'package/binding.gyp' in seen and not any(k in manifest.get('scripts', {}) for k in LIFECYCLE):
                        raise EvidenceError('Pinned pnpm rebuild requires an explicit native build script')
                    builds.add(name)
                self.archive_contents[key] = contents
            # Duplicate names at different versions require separate recipe roots.
            roots['package-' + str(len(roots))] = {'dependencies': {name: {'specifier': version, 'version': version}}}
        save(seed / 'pnpm-lock.yaml', {'lockfileVersion': '9.0',
            'settings': {'autoInstallPeers': True, 'excludeLinksFromLockfile': False},
            'importers': roots, 'packages': packages, 'snapshots': {key: {} for key in packages}})
        before = (seed / 'pnpm-lock.yaml').read_bytes()
        if records:
            result = pnpm_tool.run(['fetch'], cwd=seed)
            if (seed / 'pnpm-lock.yaml').read_bytes() != before or result.returncode:
                raise EvidenceError('Native pnpm store preparation failed without lock repair')
        self.materialize(target)
        if records:
            shutil.move(seed / 'store', Path(target) / 'store')
        result = pnpm_tool.run(['install', '--frozen-lockfile'], cwd=target)
        self.preserved(target)
        if result.returncode:
            raise EvidenceError('Native pnpm frozen installation failed')
        self.detach_local_metadata(target)
        baseline = self.verify_installed(target, records)
        if builds:
            # Builds may create outputs, but cannot redefine the reviewed graph.
            metadata = {str(path.relative_to(target)): path.read_bytes()
                        for path in Path(target).rglob('package.json')}
            pnpm_tool.rebuild(target, builds, run_build)
            self.preserved(target)
            if any((Path(target) / path).read_bytes() != raw for path, raw in metadata.items()):
                raise EvidenceError('pnpm build changed installed package metadata')
            self.verify_installed(target, records, built=builds, baseline=baseline)
        # Derived only after independent graph/content verification. Package-set
        # hashes bind this map at reuse; builds cannot nominate their own mounts.
        save(Path(target) / '.ptw-pnpm-sources.json', self.source_copies)
        return target

    def detach_local_metadata(self, target):
        """Copy native file: metadata hardlinks before strict installed validation.

        pnpm's directory fetcher forces hardlinks even with import-method=copy.
        Only complete inode groups rooted in admitted metadata are eligible;
        neither outside links nor arbitrary installed files are normalized.
        The native process has exited and this private stage has no workloads.
        """
        target = Path(target).resolve()
        groups = {}
        for path in target.rglob('*'):
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                groups.setdefault((info.st_dev, info.st_ino), []).append(path)
        sources = {target / p / 'package.json': p for p in set(self.local_packages.values())}
        copies = []
        for paths in groups.values():
            origins = set(paths) & sources.keys()
            if len(origins) != 1 or len(paths) != paths[0].stat().st_nlink:
                raise EvidenceError('pnpm metadata hardlink has an unreviewed origin or outside alias')
            origin = origins.pop()
            source = sources[origin]
            expected = self.files[source + '/package.json'].encode()
            if origin.read_bytes() != expected:
                raise EvidenceError('pnpm metadata hardlink differs from reviewed source')
            for path in paths:
                if path == origin:
                    continue
                parts = path.relative_to(target).parts
                package = tuple(self.locals[source]['name'].split('/'))
                if (parts[:2] != ('node_modules', '.pnpm') or
                        parts[3:] != ('node_modules', *package, 'package.json')):
                    raise EvidenceError('pnpm metadata hardlink has an unexpected installed path')
                copies.append((path, expected))
        # Validate all groups before changing any inode. Keep the staged source
        # and every authoritative input byte unchanged; replace only the copies.
        for path, raw in copies:
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
                temporary = Path(output.name)
                output.write(raw)
            try:
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)

    def verify_installed(self, target, records, *, built=(), baseline=None):
        """Bind bytes to assessed archives and actual edges to exact lock contexts.

        Walk native links from importers, without guessing pnpm's encoded store
        directory names. Range validation remains an independent check against
        archive-derived manifests. Only explicitly built packages may change
        their content, and their package.json remains bound to the archive.
        """
        from .package_install import file_manifest
        if built and baseline is None:
            raise EvidenceError('pnpm build verification requires a pre-build tree')
        self.bind_evidence(records)
        if set(getattr(self, 'archive_contents', {})) != set(self.selected):
            raise EvidenceError('pnpm installed verification requires assessed archive contents')
        target = Path(target).resolve()
        contents = file_manifest(target)
        installed, candidates = {}, {}
        for path in (target / 'node_modules/.pnpm').rglob('package.json'):
            folder = path.parent
            name = folder.name if folder.parent.name == 'node_modules' else (
                folder.parent.name + '/' + folder.name if folder.parent.name.startswith('@') and
                folder.parent.parent.name == 'node_modules' else None)
            if name is None:
                continue
            manifest = parse_json(path.read_text())
            key = name + '@' + str(manifest.get('version'))
            local_keys = {k for k, p in self.local_packages.items()
                          if self.locals[p] == manifest and self.locals[p]['name'] == name}
            if manifest.get('name') != name or (key not in self.selected and not local_keys):
                raise EvidenceError('pnpm installed an unassessed package identity')
            prefix = str(folder.relative_to(target)) + '/'
            actual = {p[len(prefix):]: h for p, h in contents.items()
                      if p.startswith(prefix) and not p[len(prefix):].startswith('node_modules/')}
            accepted = {k for k in local_keys if actual == {'package.json': hashlib.sha256(
                self.files[self.local_packages[k] + '/package.json'].encode()).hexdigest()}}
            if key in self.selected:
                expected = self.archive_contents[key]
                if (actual == expected or (name in built and
                        actual.get('package.json') == expected['package.json'])):
                    accepted.add(key)
            if not accepted:
                raise EvidenceError('pnpm installed content differs from assessed archive')
            installed[folder] = manifest
            candidates[folder] = accepted
        nodes = {target / p: m for p, m in self.manifests.items()}
        nodes.update(installed)

        def lookup(folder, name):
            while folder.is_relative_to(target):
                candidate = folder / 'node_modules' / name
                if candidate.exists():
                    return candidate.resolve()
                if folder == target:
                    break
                folder = folder.parent
            return None

        pending = [(target / ('' if p == '.' else p), entry, True)
                   for p, entry in self.lock['importers'].items()]
        contexts = {}
        while pending:
            folder, entry, importer = pending.pop()
            for field in (DEPENDENCIES if importer else ('dependencies', 'optionalDependencies')):
                for name, reference in entry.get(field, {}).items():
                    reference = reference['version'] if importer else reference
                    found = lookup(folder, name)
                    if found is None:
                        if field == 'optionalDependencies':
                            continue
                        raise EvidenceError('pnpm omitted a required dependency: ' + name)
                    if reference.startswith('link:'):
                        if found != (folder / reference[5:]).resolve() or found not in nodes:
                            raise EvidenceError('pnpm local dependency changed source identity')
                        continue
                    context = name + '@' + reference
                    identity = context.split('(', 1)[0]
                    if found not in installed or identity not in candidates[found]:
                        raise EvidenceError('pnpm dependency differs from exact locked target')
                    if importer and identity in self.local_packages:
                        parent = '' if folder == target else str(folder.relative_to(target))
                        spec = self.manifests[parent][field][name]
                        if (not spec.startswith('file:') or
                                local_path(parent, spec[5:]) != self.local_packages[identity]):
                            raise EvidenceError('pnpm file dependency changed declared source')
                    if found in contexts:
                        if contexts[found] != context:
                            raise EvidenceError('pnpm dependency differs from locked peer context')
                    else:
                        contexts[found] = context
                        snapshot = self.lock['snapshots'][context]
                        manifest = installed[found]
                        declared, required = set(), set()
                        for kind in ('dependencies', 'optionalDependencies', 'peerDependencies'):
                            dependencies = manifest.get(kind, {})
                            if not isinstance(dependencies, dict):
                                raise EvidenceError('Malformed installed pnpm dependencies')
                            declared.update(dependencies)
                            if kind == 'dependencies':
                                required.update(set(dependencies) - set(manifest.get('optionalDependencies', {})))
                            elif kind == 'peerDependencies':
                                required.update(n for n in dependencies if
                                    manifest.get('peerDependenciesMeta', {}).get(n, {}).get('optional') is not True)
                        locked = set(snapshot.get('dependencies', {})) | set(snapshot.get('optionalDependencies', {}))
                        if not required <= locked <= declared:
                            raise EvidenceError('pnpm locked edges differ from archive dependencies')
                        pending.append((found, snapshot, False))
        if set(contexts) != set(installed):
            raise EvidenceError('pnpm installed packages outside the locked reachable graph')
        self.source_copies = {p: [] for p in self.locals}
        local_origins = {}
        for folder, context in contexts.items():
            source = self.local_packages.get(context.split('(', 1)[0])
            if source is not None:
                self.source_copies[source].append(str(folder.relative_to(target)))
                local_origins[folder] = target / source
        checks = []
        for folder, manifest in nodes.items():
            if folder not in installed and str(folder.relative_to(target)) not in self.lock['importers']:
                continue
            for field in DEPENDENCIES:
                if folder in installed and field == 'devDependencies':
                    continue
                dependencies = manifest.get(field, {})
                if not isinstance(dependencies, dict):
                    raise EvidenceError('Malformed installed pnpm dependencies')
                for name, constraint in dependencies.items():
                    if not re.fullmatch(NAME, name) or not isinstance(constraint, str):
                        raise EvidenceError('Malformed installed pnpm dependency')
                    if field == 'dependencies' and name in manifest.get('optionalDependencies', {}):
                        continue
                    optional = field == 'optionalDependencies' or (field == 'peerDependencies' and
                        manifest.get('peerDependenciesMeta', {}).get(name, {}).get('optional') is True)
                    found = lookup(folder, name)
                    if found is None:
                        if optional:
                            continue
                        raise EvidenceError('pnpm omitted a required dependency: ' + name)
                    if found not in nodes or nodes[found].get('name') != name:
                        raise EvidenceError('pnpm dependency link has an unreviewed target')
                    if constraint.startswith('workspace:'):
                        constraint = constraint[10:]
                        if constraint in ('^', '~'):
                            constraint = '*'
                    if constraint.startswith('file:'):
                        expected = (local_origins.get(folder, folder) / constraint[5:]).resolve()
                        if expected != local_origins.get(found, found) or expected not in {target / p for p in self.locals}:
                            raise EvidenceError('pnpm local dependency changed source identity')
                    else:
                        checks.append((nodes[found].get('version'), constraint))
        if checks and not all(semver_check(checks)):
            raise EvidenceError('Installed pnpm dependency violates its original constraint')
        # Capture every entry, not just package contents. A sibling NAME.js can
        # shadow a verified NAME directory; nested node_modules and .bin also
        # alter lookup without changing any previously installed manifest.
        tree = {}
        for path in target.rglob('*'):
            name = str(path.relative_to(target))
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                tree[name] = ('link', contents[name])
            elif stat.S_ISDIR(info.st_mode):
                tree[name] = ('directory',)
            else:
                value = contents[name]
                if name == 'node_modules/.modules.yaml':
                    metadata = mapping(path.read_text())
                    # Pinned named rebuild adds ignoredBuilds: [] even when
                    # nothing was ignored. No other metadata change is allowed.
                    if metadata.get('ignoredBuilds') == []:
                        del metadata['ignoredBuilds']
                    value = digest(metadata)
                # Export intentionally normalizes permissions to 600/700.
                tree[name] = ('file', value, bool(info.st_mode & 0o111))
        if baseline is not None:
            roots = {path for path, name in baseline['packages'].items() if name in built}
            before = baseline['tree']
            for name in before.keys() | tree.keys():
                old, new = before.get(name), tree.get(name)
                if old == new:
                    continue
                output = next((Path(name).relative_to(root) for root in roots
                               if Path(name).is_relative_to(root) and name != root), None)
                if (output is None or any(p in ('node_modules', '.bin', 'package.json') for p in output.parts)
                        or any(entry is not None and entry[0] == 'link' for entry in (old, new))):
                    raise EvidenceError('pnpm build changed protected installation tree: ' + name)
        return {'tree': tree, 'packages': {str(folder.relative_to(target)): manifest['name']
                                         for folder, manifest in installed.items()}}
