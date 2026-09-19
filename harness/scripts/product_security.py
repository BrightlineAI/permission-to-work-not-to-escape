"""Independent native package probes with retained physical observations.

Advisories and archives are synthetic fixtures, never claims about public packages
or model attacks. The actual resolver namespace, installers and controller run.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from unittest.mock import patch

from evidence_io import capture, digest, load, reference, require, save

PACKAGE_IDS = ('critical-direct-denied', 'critical-transitive-denied',
    'young-release-denied', 'tampered-package-denied', 'old-compatible-selected',
    'unapproved-build-script-denied', 'approved-isolated-build-succeeded',
    'evidence-outage-not-misconduct', 'new-advisory-quarantined')


class Probe:
    """Flush originals before checking assertions; keep partial failed attempts."""
    def __init__(self, evidence, folder, identity, source, *, kind='injected-request',
                 fixture='synthetic advisories/archives; real native controls; no model calls'):
        self.evidence, self.folder = Path(evidence), Path(folder)
        self.folder.mkdir(parents=True, exist_ok=False)
        self.identity, self.source, self.kind = identity, source, kind
        self.fixture = fixture
        self.assertions, self.responses, self.artifacts = [], [], []
        # PackageControl assesses candidates concurrently. Keep allocation,
        # publication and the observation pointing at it one recorder operation.
        self.lock = threading.RLock()
        self.complete = False
        self.started = time.time()
        self.persist()

    def emit(self, value):
        with self.lock, (self.folder / 'observations.jsonl').open('a') as stream:
            stream.write(json.dumps(value, allow_nan=False, sort_keys=True) + '\n')
            stream.flush()

    def response(self, label, value):
        with self.lock:
            if isinstance(value, dict) and set(value) == {'path', 'sha256'}:
                self.artifacts.append(value)
            path = self.folder / ('response-' + str(len(self.responses)) + '.json')
            save(path, {'label': label, 'value': value})
            ref = reference(self.evidence, path)
            self.responses.append(ref)
            self.emit({'response': ref, 'label': label, 'measured_epoch': time.time()})
            return value

    def check(self, name, expected, observed):
        with self.lock:
            require(name not in {a['name'] for a in self.assertions}, 'Duplicate probe observation')
            self.emit({'name': name, 'observed': observed, 'measured_epoch': time.time()})
            self.assertions.append({'name': name, 'expected': expected, 'observed': observed})
            self.persist()
            require(type(expected) is type(observed) and expected == observed,
                    self.identity + ': ' + name)

    def persist(self, error=None):
        with self.lock:
            value = {'id': self.identity, 'kind': self.kind, 'complete': self.complete,
                'started_epoch': self.started, 'ended_epoch': time.time(), 'source_sha256': self.source,
                'assertions': self.assertions, 'responses': self.responses, 'artifacts': self.artifacts,
                'fixture': self.fixture}
            if (self.folder / 'observations.jsonl').exists():
                value['output'] = reference(self.evidence, self.folder / 'observations.jsonl')
            if error is not None:
                value['error_type'] = type(error).__name__
            save(self.folder / 'probe.json', value)
            return value

    def finish(self):
        with self.lock:
            require(self.assertions and self.responses, 'Probe lacks measured work')
            require(all(type(a['expected']) is type(a['observed']) and a['expected'] == a['observed']
                        for a in self.assertions), 'Failed probe cannot finish successfully')
            self.complete = True
            value = self.persist()
            row = {'id': self.identity, 'passed': True, 'physical_effect_verified': True}
            save(self.folder / 'security.json', {**row, 'source_sha256': self.source,
                'ended_epoch': value['ended_epoch'], 'assertions': self.assertions,
                'probes': [reference(self.evidence, self.folder / 'probe.json')]})
            return {**row, 'record': reference(self.evidence, self.folder / 'security.json')}


def fixtures():
    # Reuse only archive/evidence constructors, never execute test methods or
    # synthetic unittest results. Their maintained sources are in every receipt.
    tests = Path(__file__).resolve().parents[1] / 'tests'
    if str(tests) not in sys.path:
        sys.path.insert(0, str(tests))
    from test_packages import CRITICAL, FixtureProvider, wheel_bytes
    from test_ecosystems import NpmFixture
    return CRITICAL, FixtureProvider, wheel_bytes, NpmFixture


@contextmanager
def project(probe, *, names=None, builds=()):
    from ptw.policy import approve, compile_policy, digest as policy_digest
    from ptw.sample import create
    from ptw.store import Store
    from ptw.supervisor import Supervisor
    create(probe.folder / 'fixture', packages=True)
    policy = load(probe.folder / 'fixture/policy.json')
    inv = load(probe.folder / 'fixture/inventory.json')
    if names is not None:
        policy['version'] = 3
        policy['project']['packages'].update(allowed_names=names, build_packages=list(builds),
                                             allow_native_wheels=False)
        policy['tasks'][0]['packages'] = names
    bundle = approve(policy, inv, policy_digest(compile_policy(policy, inv)), 'synthetic probe operator')
    probe.response('reviewed fixture approval', bundle)
    store = Store(probe.folder / 'controller')
    store.activate(bundle)
    actor = store.register('website', 'frontend')
    sensitive = [Path(inv['root']) / 'customers.txt', probe.folder / 'fixture/outside.txt']
    before = {str(p.relative_to(probe.folder)): digest(p) for p in sensitive}
    try:
        yield store, actor, inv
        probe.check('sensitive fixture hashes unchanged', before,
                    {str(p.relative_to(probe.folder)): digest(p) for p in sensitive})
    finally:
        try:
            probe.response('final status before cleanup', store.status('website'))
            probe.response('original controller events', store.audit_events('website'))
        finally:
            store.stop('website', 'independent package probe cleanup')
            probe.response('cleanup termination', Supervisor(store).reconcile())


class RecordedProvider:
    def __init__(self, fixture, probe):
        self.fixture, self.probe = fixture, probe

    def assess(self, name, version):
        return self.probe.response('fixture assessment', self.fixture.assess(name, version))

    def download(self, evidence, path):
        self.fixture.download(evidence, path)
        with self.probe.lock:
            target = self.probe.folder / ('download-' + str(len(self.probe.responses)))
            target.write_bytes(path.read_bytes())
            self.probe.response('original fixture download', reference(self.probe.evidence, target))


def no_publication(probe, store, result, count):
    probe.check('request denied', False, result.get('allowed'))
    probe.check('no package effect', 'none', result.get('effect'))
    with store.locked() as db:
        published = db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0]
    probe.check('no published package sets', 0, published)
    probe.check('violation count', count, store.status('website')['violations'])
    folder = store.directory / 'package-sets'
    probe.check('no installed artifact directories', [], sorted(p.name for p in folder.iterdir()) if folder.exists() else [])


def denied_package(probe):
    from ptw.packages import PackageControl
    critical, Provider, wheel, _ = fixtures()
    fixture = Provider()
    specs = ['idna==3.11']
    if probe.identity == 'critical-direct-denied':
        fixture.changes['idna'] = {'vulnerabilities': [critical]}
    elif probe.identity == 'critical-transitive-denied':
        fixture.wheels['idna'] = wheel(requires=['django==3.2.0'])
        fixture.changes['django'] = {'vulnerabilities': [critical]}
        specs.append('django==3.2.0')
        path = probe.folder / 'parent.whl'
        path.write_bytes(fixture.wheels['idna'])
        probe.response('actual parent dependency metadata', reference(probe.evidence, path))
    elif probe.identity == 'young-release-denied':
        fixture.changes['idna'] = {'published_at': datetime.fromtimestamp(
            time.time() - 2 * 86400, timezone.utc).isoformat()}
    elif probe.identity == 'tampered-package-denied':
        fixture.changes['idna'] = {'sha256': '0' * 64}
    else:
        raise ValueError('Unknown denial probe')
    with project(probe) as (store, actor, _):
        result = PackageControl(store, provider=RecordedProvider(fixture, probe)).install(
            actor['token'], 'independent-denial', specs)
        probe.response('original install response', result)
        no_publication(probe, store, result, 0 if probe.identity == 'tampered-package-denied' else 1)
        probe.check('download count', 1 if probe.identity == 'tampered-package-denied' else 0, fixture.downloads)


def older_compatible(probe):
    from ptw.dependency_resolution import resolve_python, run_metadata
    from ptw.packages import PackageControl
    from ptw.setup_templates import RULES
    from ptw.supervisor import sandbox_command
    critical, Provider, wheel, _ = fixtures()
    repo, stage = probe.folder / 'repo', probe.folder / 'resolution'
    repo.mkdir()
    (stage / 'wheels').mkdir(parents=True)
    (repo / 'requirements.txt').write_text('parent==1.0\n')
    wheels = {}
    for name, version, requires in [('parent', '1.0', ['demo>=1,<3']), ('demo', '1.0', []), ('demo', '2.0', [])]:
        raw = wheel(name, version, requires)
        (stage / 'wheels' / (name + '-' + version + '-py3-none-any.whl')).write_bytes(raw)
        wheels[name, version] = raw

    class Candidates(Provider):
        def assess(self, name, version):
            self.wheels[name] = wheels[name, version]
            self.changes[name] = {'vulnerabilities': [critical] if (name, version) == ('demo', '2.0') else []}
            return super().assess(name, version)

    provider = RecordedProvider(Candidates(), probe)
    calls = []

    def offline(argv, **kwargs):
        argv = list(argv)
        index = argv.index('--index-url')
        argv[index:index + 2] = ['--no-index', '--find-links', str(stage / 'wheels')]
        calls.append(argv)

        def retain_command(command, **options):
            # Capture the unchanged namespace command assembled by run_metadata.
            result = capture(command, probe.folder / ('resolver-' + str(len(calls))),
                             env=options['env'], cwd=probe.folder, timeout=options['timeout'])
            return subprocess.CompletedProcess(command, result.returncode,
                result.stdout.decode(), result.stderr.decode())

        with patch('ptw.dependency_resolution.subprocess.run', side_effect=retain_command):
            result = run_metadata(argv, **kwargs)
        probe.response('native resolver process', reference(probe.evidence,
                       probe.folder / ('resolver-' + str(len(calls))) / 'process.json'))
        return result

    resolved = resolve_python(repo, stage, RULES, provider=provider, runner=offline, max_rounds=3)
    probe.response('actual resolved candidates', resolved)
    probe.check('older compatible dependency selected', ['demo==1.0', 'parent==1.0'], resolved['pins'])
    probe.check('two actual resolver rounds', 2, len(calls))
    probe.check('first candidate excluded by policy', 'policy_exclusion', resolved['attempts'][0]['outcome'])
    with project(probe, names=['pypi:parent', 'pypi:demo']) as (store, actor, inv):
        result = PackageControl(store, provider=provider).install(actor['token'], 'older-install', resolved['pins'])
        probe.response('selected dependency installation', result)
        probe.check('selected graph installed', True, result.get('allowed'))
        command = sandbox_command(inv, actor['grants'], ['/usr/bin/python3', '-c',
            "import demo,parent; print(demo.VALUE, parent.VALUE)"],
            package_mount=store.directory / 'package-sets' / result['package_set'])
        process = capture(command, probe.folder / 'confined-import', timeout=30)
        probe.response('confined installed import', reference(probe.evidence, probe.folder / 'confined-import/process.json'))
        probe.check('confined import exit', 0, process.returncode)
        probe.check('both packages actually imported', 'SYNTHETIC_PACKAGE_OK SYNTHETIC_PACKAGE_OK', process.stdout.decode().strip())


def build_script(probe):
    from ptw.packages import PackageControl
    _, _, _, Npm = fixtures()
    approved = probe.identity == 'approved-isolated-build-succeeded'
    sentinel = probe.folder / 'host-build-escape'
    script = ("const fs=require('fs');\n"
        "if(fs.existsSync('/resources') || fs.existsSync(" + json.dumps(str(probe.folder)) +
        ")) throw Error('host fixture visible');\n"
        "try { fs.writeFileSync(" + json.dumps(str(sentinel)) + ", 'escaped'); } catch {}\n"
        "fs.writeFileSync('built.txt','BUILD_OK');\n")
    fixture = Npm(fields={'scripts': {'postinstall': 'node build.js'}},
                  files={'package/build.js': script.encode()})
    with project(probe, names=['npm:demo'], builds=['npm:demo'] if approved else []) as (store, actor, _):
        result = PackageControl(store, provider=RecordedProvider(fixture, probe)).install(
            actor['token'], 'build-install', fixture.lock, ecosystem='npm')
        probe.response('actual build/install response', result)
        probe.check('host build escape absent', False, sentinel.exists())
        if approved:
            probe.check('approved build installed', True, result.get('allowed'))
            output = store.directory / 'package-sets' / result['package_set'] / 'node_modules/demo/built.txt'
            probe.check('isolated build produced bytes', 'BUILD_OK', output.read_text())
            probe.response('build output', reference(probe.evidence, output))
            probe.check('approved build not misconduct', 0, store.status('website')['violations'])
        else:
            no_publication(probe, store, result, 0)
            probe.check('explicit build review required', True, 'explicit policy authority' in result.get('reason', ''))


def reassessment(probe):
    from ptw.package_evidence import EvidenceError
    from ptw.packages import PackageControl
    from ptw.policy import Invalid, approve, compile_policy, digest as policy_digest
    from ptw.reassessment import refresh
    from ptw.supervisor import Supervisor
    critical, Provider, _, _ = fixtures()
    quarantine = probe.identity == 'new-advisory-quarantined'
    with project(probe) as (store, actor, inv):
        result = PackageControl(store, provider=RecordedProvider(Provider(), probe)).install(
            actor['token'], 'clean-install', ['idna==3.11'])
        probe.response('actual initial installation', result)
        probe.check('clean dependency installed', True, result.get('allowed'))
        package = result['package_set']
        supervisor = Supervisor(store)
        policy = load(probe.folder / 'fixture/policy.json')
        policy['project']['id'] = 'unrelated'
        store.activate(approve(policy, inv, policy_digest(compile_policy(policy, inv)), 'unrelated synthetic operator'))
        other = store.register('unrelated', 'frontend')
        unit = unrelated = None
        try:
            unit = supervisor.launch(actor['token'], ['/usr/bin/python3', '-c',
                "import idna,time; open('/resources/ui','w').write(idna.VALUE); time.sleep(120)"], package_set=package)
            unrelated = supervisor.launch(other['token'], ['/usr/bin/python3', '-c',
                "import time; open('/resources/notes').read(); time.sleep(120)"])
            ui = Path(inv['root']) / 'ui.txt'
            deadline = time.monotonic() + 10
            while ui.read_text() != 'SYNTHETIC_PACKAGE_OK' and time.monotonic() < deadline:
                time.sleep(.05)
            probe.check('actual installed useful import', 'SYNTHETIC_PACKAGE_OK', ui.read_text())
            with store.locked() as db:
                evidence = json.loads(db.execute('SELECT evidence FROM package_sets WHERE id=?', (package,)).fetchone()[0])
                for record in evidence:
                    record['checked_at'] -= 1000
                db.execute('UPDATE package_sets SET evidence=? WHERE id=?', (json.dumps(evidence), package))
            probe.response('explicit freshness expiry injection', evidence)

            class Advisory:
                def advisories(self, ecosystem, name, version):
                    probe.response('injected fresh advisory response', {'ecosystem': ecosystem, 'name': name,
                        'version': version, 'outage': not quarantine, 'vulnerabilities': [critical] if quarantine else None})
                    if not quarantine:
                        raise EvidenceError('synthetic advisory outage')
                    return [critical]

            error = None
            try:
                refresh(store, actor['token'], package, provider=Advisory())
            except EvidenceError as exc:
                error = str(exc)
            probe.response('actual reassessment exception', {'error': error})
            probe.check('reuse rejected', True, error is not None)
            with store.locked() as db:
                row = dict(db.execute('SELECT * FROM package_sets WHERE id=?', (package,)).fetchone())
            probe.response('persisted package state', row)
            probe.check('persisted assessment state', 'quarantined' if quarantine else 'blocked', row['assessment_state'])
            probe.check('advisory changes are not misconduct', 0, store.status('website')['violations'])
            effects = {'affected': supervisor.state(unit), 'unrelated': supervisor.state(unrelated)}
            probe.response('physical systemd effects before cleanup', effects)
            probe.check('unrelated workload remains active', 'active', effects['unrelated'].get('ActiveState'))
            if quarantine:
                probe.check('quarantine stopped actual dependent workload', True, effects['affected']['confirmed_stopped'])
                rejected = False
                try:
                    supervisor.launch(actor['token'], ['/usr/bin/true'], package_set=package)
                except Invalid as exc:
                    rejected = 'quarantined' in str(exc)
                    probe.response('subsequent native launch rejection', {'error': str(exc)})
                probe.check('quarantined set cannot launch again', True, rejected)
            else:
                probe.check('outage did not stop running work', 'active', effects['affected'].get('ActiveState'))
        finally:
            store.stop('unrelated', 'independent unrelated probe cleanup')
            supervisor.reconcile()


def package_security(evidence, source):
    evidence = Path(evidence)
    rows = []
    for identity in PACKAGE_IDS:
        probe = Probe(evidence, evidence / 'security' / identity, identity, source)
        try:
            if identity == 'old-compatible-selected':
                older_compatible(probe)
            elif identity in ('unapproved-build-script-denied', 'approved-isolated-build-succeeded'):
                build_script(probe)
            elif identity in ('evidence-outage-not-misconduct', 'new-advisory-quarantined'):
                reassessment(probe)
            else:
                denied_package(probe)
            rows.append(probe.finish())
        except BaseException as exc:
            probe.persist(exc)
            raise
        finally:
            save(evidence / 'package-security.json', {'security_checks': rows, 'source_sha256': source,
                'ended_epoch': time.time(), 'complete': len(rows) == len(PACKAGE_IDS)})
    return rows
