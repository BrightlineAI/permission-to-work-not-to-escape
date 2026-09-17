"""Native Poetry solving over brokered wheel metadata, without a network or builds."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import tomllib
import zipfile

from packaging.metadata import Metadata
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from .dependency_resolution import ResolutionError, checked_requirement, metadata
from .package_evidence import EvidenceError, PyPIEvidence, evaluate
from .package_install import target_environment, target_tags
from .policy import Invalid, save
from .python_lock import export_lock, static_lock_project
from .python_runtime import verify


# The only repository is an in-memory native Repository. A missing entry ends
# this invocation with a data request, never an HTTP or source-build fallback.
SOLVE = r'''
import json, sys
from pathlib import Path
from cleo.io.null_io import NullIO
from poetry.factory import Factory
from poetry.core.constraints.version import Version, VersionUnion
from poetry.core.packages.package import Package
from poetry.core.packages.dependency import Dependency
from poetry.repositories.repository import Repository
from poetry.repositories.repository_pool import RepositoryPool
from poetry.puzzle.solver import Solver
from poetry.puzzle.exceptions import SolverProblemError
from poetry.puzzle.provider import Provider
from poetry.mixology.incompatibility import Incompatibility
from poetry.mixology.term import Term

config = json.loads(sys.argv[1])
catalog = json.loads(Path('catalog.json').read_text())
excluded = {tuple(x) for x in config['excluded']}
def result(value):
    Path('solve-result.json').write_text(json.dumps(value))
def need(kind, name, version=None):
    result(dict(outcome='need', kind=kind, name=name, version=version))
    raise SystemExit(0)

class Wheels(Repository):
    def _find_packages(self, name, constraint):
        if name not in catalog['versions']:
            need('versions', name)
        return [Package(name, v) for v in catalog['versions'][name]
                if (name, v) not in excluded and constraint.allows(Version.parse(v))]

    def package(self, name, version):
        key = name + '==' + str(version)
        if key not in catalog['metadata']:
            need('metadata', name, str(version))
        data = catalog['metadata'][key]
        package = Package(name, version)
        package.python_versions = data['requires_python'] or '*'
        package.files = data['files']
        package.extras = {e: [] for e in data['extras']}
        for raw in data['requires_dist']:
            # Unlike PackageInfo.to_package, never strip invalid markers or
            # silently skip a requirement. Both host and native parsers check it.
            dependency = Dependency.create_from_pep_508(raw)
            if dependency.is_direct_origin() or dependency.source_name:
                raise ValueError('nonregistry wheel requirement')
            for extra in dependency.in_extras:
                package.extras.setdefault(extra, []).append(dependency)
            package.add_dependency(dependency)
        return package

class RuntimeProvider(Provider):
    def incompatibilities_for(self, dependency_package):
        result = []
        for incompatibility in super().incompatibilities_for(dependency_package):
            terms = []
            for term in incompatibility.terms:
                dependency = term.dependency
                marker = dependency.transitive_marker.intersect(self._overrides_marker_intersection)
                if not term.is_positive() and marker.without_extras().validate(config['environment']):
                    if dependency.name not in catalog['versions']:
                        need('versions', dependency.name)
                    # Narrow native solver requirements after marker propagation
                    # and overrides. Search caches and lock preferences then see
                    # the same constraints; wheel declarations remain unchanged.
                    admitted = VersionUnion.of(*(Version.parse(v)
                        for v in catalog['compatible'][dependency.name]))
                    dependency = dependency.with_constraint(dependency.constraint.intersect(admitted))
                terms.append(Term(dependency, term.is_positive()))
            result.append(Incompatibility(terms, incompatibility.cause))
        return result

poetry = Factory().create_poetry(Path.cwd(), disable_plugins=True)
if not poetry.package.python_constraint.allows(Version.parse(config['runtime']['version'])):
    raise ValueError('project excludes reviewed runtime')
for dependency in poetry.package.all_requires:
    if dependency.is_direct_origin() or dependency.source_name:
        raise ValueError('nonregistry project dependency')
repository = Wheels('PyPI')
# Rehydrate lock preferences from checked artifacts. Untrusted lock dependency
# metadata must never short-circuit repository validation in Provider.get_locked.
locked = [repository.package(p.name, p.version)
          for p in poetry.locker.locked_repository().packages
          if (p.name, str(p.version)) not in excluded and p.name not in config['upgrade']]
try:
    pool = RepositoryPool([repository])
    solver = Solver(poetry.package, pool, [], locked, NullIO())
    solver._provider = RuntimeProvider(poetry.package, pool, NullIO(), locked=locked)
    solved = solver.solve(use_latest=config['upgrade']).get_solved_packages()
except SolverProblemError:
    result(dict(outcome='unsatisfiable'))
else:
    if any((p.name, str(p.version)) in excluded for p in solved):
        raise ValueError('solver retained an excluded version')
    poetry.locker.set_lock_data(poetry.package, solved)
    result(dict(outcome='resolved'))
'''


def compatible_versions(document, tags):
    """Filter validated listings by admitted wheel tags, never by evidence errors."""
    versions = set()
    for item in document['files']:
        _, version, _, wheel_tags = parse_wheel_filename(item['filename'])
        if any(str(tag) in tags for tag in wheel_tags):
            versions.add(str(version))
    return sorted(versions)


def metadata_record(index, name, version):
    """Checked foreign-wheel data for complete locking, never install authority."""
    document = index.document(name)
    candidates = [r for r in index.artifacts.values()
                  if r['name'] == name and r['version'] == version]
    if not candidates:
        raise EvidenceError('No registry wheel metadata for Poetry candidate')
    record = dict(min(candidates, key=lambda r: r['filename']))
    item = next(f for f in document['files'] if f['filename'] == record['filename'])
    record.update(published_at=item['upload-time'], checked_at=time.time(),
        vulnerabilities=index.provider.advisories('PyPI', name, version),
        artifact_kind='bdist_wheel', source='Checked registry listing and OSV; metadata only')
    return record


def wheel_metadata(path, record):
    """Read bounded wheel metadata as data; never import or extract the wheel."""
    try:
        name, version, _, _ = parse_wheel_filename(record['filename'])
        if name != record['name'] or version != Version(record['version']):
            raise EvidenceError('Wheel filename identity differs from evidence')
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise EvidenceError('Wheel digest differs from evidence')
        with zipfile.ZipFile(path) as wheel:
            members = wheel.infolist()
            if len(members) > 50000 or sum(m.file_size for m in members) > 400 * 1024 * 1024:
                raise EvidenceError('Wheel metadata input exceeds limits')
            entries = [m for m in members if m.filename.endswith('.dist-info/METADATA')]
            if len(entries) != 1 or entries[0].file_size > 1024 * 1024:
                raise EvidenceError('Exactly one bounded wheel metadata file required')
            item = entries[0]
            directory = item.filename.split('/')
            identity = directory[0][:-10].rsplit('-', 1)
            if (len(directory) != 2 or len(identity) != 2 or
                    canonicalize_name(identity[0]) != name or Version(identity[1]) != version):
                raise EvidenceError('Foreign wheel metadata directory')
            raw = wheel.read(item)
        parsed = Metadata.from_email(raw, validate=True)
        if canonicalize_name(parsed.name) != name or parsed.version != version or parsed.dynamic:
            raise EvidenceError('Wheel metadata identity or dynamic fields are unsupported')
        requires = [str(r) for r in parsed.requires_dist or []]
        for requirement in requires:
            checked_requirement(requirement)
        return dict(requires_dist=requires, requires_python=str(parsed.requires_python or ''),
            extras=parsed.provides_extra or [],
            files=[{'file': record['filename'], 'hash': 'sha256:' + record['sha256']}])
    except Invalid:
        # Invalid is a ValueError too. Preserve explicit declaration rejection
        # (including nonregistry origins), rather than relabeling it as missing
        # evidence in the generic malformed-metadata handler below.
        raise
    except (ValueError, TypeError, KeyError, AttributeError, zipfile.BadZipFile, ExceptionGroup) as exc:
        raise EvidenceError('Malformed wheel metadata') from exc


def update_poetry_lock(root, stage, rules, *, executable, groups=('dev', 'test'), extras=(),
                       upgrade=(), provider=None, seconds=180, max_rounds=8, max_assessments=256):
    """Return an assessed native lock; callers still need exact operator approval.

    The original, possibly just edited manifest is immutable. Lock versions are
    preferences, not constraints. The native solver sees confirmed policy
    exclusions in its repository, including transitive and formerly locked pins.
    """
    from .poetry_tool import run, verified
    from .python_index import WheelIndex
    if (type(max_rounds) is not int or not 1 <= max_rounds <= 8 or
            type(max_assessments) is not int or not 1 <= max_assessments <= 256 or
            type(seconds) not in (int, float) or not 0 < seconds <= 180):
        raise Invalid('Resolution budgets may only narrow the fixed limits')
    root, stage = Path(root), Path(stage)
    stage.mkdir(parents=True, exist_ok=False)
    started, attempts, outcome, inputs = time.monotonic(), [], 'invalid', {}
    excluded, records, wheels = set(), {}, {}
    catalog = {'versions': {}, 'compatible': {}, 'metadata': {}}
    metadata_only = set()

    def remaining():
        value = started + seconds - time.monotonic()
        if value <= 0:
            raise ResolutionError('budget_exhausted', 'Poetry resolution deadline reached')
        return value

    try:
        if getattr(provider, 'routes', None):
            raise Invalid('Private Poetry revisions require reviewed source routing')
        manifest = metadata(root, 'pyproject.toml', inputs)
        document = tomllib.loads(manifest)
        static_lock_project(document)
        poetry = document.get('tool', {}).get('poetry', {})
        if poetry.get('source') or (root / 'uv.lock').exists():
            raise Invalid('Select one public-registry Poetry authority')
        original_lock = metadata(root, 'poetry.lock', inputs)
        locked = tomllib.loads(original_lock)
        if any(p.get('source') for p in locked.get('package', [])):
            raise Invalid('Poetry lock sources require separate reviewed routing')
        version = metadata(root, '.python-version', inputs).strip() if (root / '.python-version').exists() else None
        upgrade = sorted({canonicalize_name(n, validate=True) for n in upgrade})
        directory, tool = verified()
        (stage / 'pyproject.toml').write_text(manifest)
        (stage / 'poetry.lock').write_text(original_lock)
        from .poetry_export import selection
        runtime, _ = selection(stage, executable=executable, version_request=version,
                               timeout=remaining(), directory=directory)
        save(stage / 'resolver-tool.json', dict(poetry_tool=tool, inputs=inputs, runtime=runtime,
            runner_sha256=hashlib.sha256(SOLVE.encode()).hexdigest()))
        if version is not None:
            (stage / '.python-version').write_text(metadata(root, '.python-version', {}))
        provider = provider or PyPIEvidence(native=rules.get('allow_native_wheels', False), python=executable)
        if isinstance(provider, PyPIEvidence):
            provider.deadline = started + seconds
        # Reuse listing validation without opening the HTTP fixture interface.
        index = WheelIndex(provider, stage / 'unused-index', started + seconds)
        tags = (set(target_tags(runtime['executable'])) if rules.get('allow_native_wheels', False)
                else {'py3-none-any'})
        environment = target_environment(runtime['executable'])

        def listing(name):
            if name not in catalog['versions']:
                document = index.document(name)
                catalog['versions'][name] = document['versions']
                catalog['compatible'][name] = compatible_versions(document, tags)

        downloaded, rejection_rounds = 0, 0
        for step in range(512):
            remaining()
            catalog_text = json.dumps(catalog)
            if len(catalog_text.encode()) > 16 * 1024 * 1024:
                raise ResolutionError('budget_exhausted', 'Poetry metadata catalog exceeds limit')
            (stage / 'catalog.json').write_text(catalog_text)
            output = stage / 'solve-result.json'
            output.unlink(missing_ok=True)
            attempt = dict(step=step + 1, outcome='running', excluded=sorted(excluded),
                catalog_sha256=hashlib.sha256(catalog_text.encode()).hexdigest())
            attempts.append(attempt)
            proc = run(SOLVE, dict(runtime=runtime, environment=environment,
                upgrade=upgrade, excluded=sorted(excluded)),
                cwd=stage, timeout=remaining(), directory=directory)
            attempt.update(returncode=proc.returncode, stderr_sha256=hashlib.sha256(proc.stderr.encode()).hexdigest())
            remaining()
            if proc.returncode:
                raise ResolutionError('unavailable', 'Native Poetry solver failed; see retained receipt')
            response = json.loads(metadata(stage, output.name, {}))
            if not isinstance(response, dict):
                raise Invalid('Malformed native Poetry response')
            attempt['response'] = response
            status = response.get('outcome')
            if metadata(stage, 'pyproject.toml', {}) != manifest:
                raise Invalid('Poetry solver changed project declarations')
            if status != 'resolved' and metadata(stage, 'poetry.lock', {}) != original_lock:
                raise Invalid('Incomplete Poetry resolution changed lock authority')
            if status == 'unsatisfiable' and set(response) == {'outcome'}:
                raise ResolutionError('unsatisfiable', 'Poetry cannot satisfy original constraints under policy')
            if status == 'resolved' and set(response) == {'outcome'}:
                break
            if status != 'need' or set(response) != {'outcome', 'kind', 'name', 'version'}:
                raise Invalid('Unexpected native Poetry response')
            name, version = response['name'], response['version']
            if not isinstance(name, str) or canonicalize_name(name, validate=True) != name:
                raise Invalid('Invalid native Poetry metadata name')
            if response['kind'] == 'versions' and version is None and name not in catalog['versions']:
                listing(name)
                attempt['outcome'] = 'metadata'
                continue
            if (response['kind'] != 'metadata' or not isinstance(version, str) or
                    str(Version(version)) != version or (name, version) in records):
                raise Invalid('Invalid or repeated native Poetry metadata request')
            listing(name)
            if version not in catalog['versions'][name]:
                excluded.add((name, version))
                attempt['outcome'] = 'unavailable_wheel'
                continue
            if len(records) >= max_assessments:
                raise ResolutionError('budget_exhausted', 'Poetry candidate assessment limit reached')
            if version in catalog['compatible'][name]:
                record = provider.assess(name, version)
            else:
                record = metadata_record(index, name, version)
                metadata_only.add((name, version))
            remaining()
            if record.get('name') != name or record.get('version') != version:
                raise EvidenceError('Candidate evidence identity mismatch')
            records[name, version] = record
            reasons = evaluate(record, rules)
            if reasons:
                excluded.add((name, version))
                rejection_rounds += 1
                attempt.update(outcome='policy_exclusion', reasons=reasons)
                if rejection_rounds >= max_rounds:
                    raise ResolutionError('budget_exhausted', 'Poetry candidate retry limit reached')
                continue
            if (record.get('artifact_kind') != 'bdist_wheel' or
                    not provider.artifact_allowed(record.get('url', ''), name)):
                raise EvidenceError('Poetry metadata requires a checked registry wheel')
            wheel = stage / ('artifact-' + str(len(records)) + '.whl')
            provider.download(record, wheel)
            if 'size' in record and wheel.stat().st_size != record['size']:
                raise EvidenceError('Poetry metadata wheel size differs from listing')
            downloaded += wheel.stat().st_size
            if downloaded > 512 * 1024 * 1024:
                raise ResolutionError('budget_exhausted', 'Poetry download budget exhausted')
            remaining()
            catalog['metadata'][name + '==' + version] = wheel_metadata(wheel, record)
            wheels[name, version] = wheel
            attempt['outcome'] = 'metadata'
        else:
            raise ResolutionError('budget_exhausted', 'Poetry metadata request limit reached')

        class Assessed:
            def assess(self, name, version):
                if (name, version) not in wheels or (name, version) in metadata_only:
                    raise EvidenceError('Native lock contains an unassessed candidate')
                return records[name, version]

            def download(self, evidence, path):
                shutil.copyfile(wheels[evidence['name'], evidence['version']], path)

        result = export_lock(stage, stage / 'export', rules, executable=executable,
            groups=groups, extras=extras, provider=Assessed(), seconds=remaining(), max_assessments=max_assessments)
        remaining()
        verify(runtime)
        if result['runtime'] != runtime:
            raise Invalid('Poetry resolution changed reviewed runtime')
        for name, sha in inputs.items():
            if hashlib.sha256(metadata(root, name, {}).encode()).hexdigest() != sha:
                raise Invalid('Poetry inputs changed during resolution')
        result['files'] = {'poetry.lock': metadata(stage, 'poetry.lock', {})}
        outcome = attempts[-1]['outcome'] = 'resolved'
        return result
    except subprocess.TimeoutExpired as exc:
        outcome = 'budget_exhausted'
        raise ResolutionError(outcome, 'Native Poetry resolver timed out') from exc
    except ResolutionError as exc:
        outcome = exc.outcome
        raise
    except EvidenceError:
        outcome = 'unavailable_evidence'
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise Invalid('Malformed Poetry resolution data') from exc
    finally:
        if attempts and attempts[-1]['outcome'] == 'running':
            attempts[-1]['outcome'] = outcome
        save(stage / 'resolution.json', dict(outcome=outcome, inputs=inputs, attempts=attempts,
            elapsed_seconds=time.monotonic() - started))
