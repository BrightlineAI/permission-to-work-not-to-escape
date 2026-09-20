"""Closed synthetic sudo-child namespace fixture, never a task or launch API."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

SCRIPT = '/ptw-native-tools/placement.py'


def holder_identity():
    # Keep only fixed numeric kernel fields, never a broad process/status dump.
    expected = {'Uid': (4, 10), 'Gid': (4, 10), 'CapInh': (1, 16),
                'CapPrm': (1, 16), 'CapEff': (1, 16), 'CapBnd': (1, 16), 'CapAmb': (1, 16)}
    record = {}
    with open('/proc/self/status') as stream:
        for _ in range(128):
            line = stream.readline(512)
            if not line:
                break
            if not line.endswith('\n'):
                raise ValueError('Unbounded holder identity field')
            key, _, value = line.partition(':')
            if key not in expected:
                continue
            count, base = expected[key]
            words = value.split()
            alphabet = '0123456789' if base == 10 else '0123456789abcdefABCDEF'
            if key in record or len(words) != count or any(
                    len(word) > 16 or any(c not in alphabet for c in word) for word in words):
                raise ValueError('Malformed holder identity field')
            record[key] = [int(word, base) for word in words]
    if set(record) != set(expected):
        raise ValueError('Incomplete holder identity')
    return record


def device_identity():
    # Only fixed synthetic device metadata, no terminal contents or broad mount
    # dump. st_dev identifies the filesystem instance; namespace inodes are
    # bound separately. lstat rejects substituted pts directories/device links.
    nodes = {}
    for path in ('/dev', '/dev/pts', '/dev/pts/ptmx'):
        st = os.lstat(path)
        nodes[path] = {key: getattr(st, 'st_' + key)
                       for key in ('dev', 'ino', 'mode', 'rdev', 'uid', 'gid')}
    return {'nodes': nodes, 'ptmx_link': os.readlink('/dev/ptmx')}


def validate_devices(record, outer=None):
    # This file also runs with -I -S inside the immutable minimal tools mount.
    def require(valid, message):
        if not valid:
            raise ValueError(message)
    require(set(record) == {'nodes', 'ptmx_link'} and
            set(record['nodes']) == {'/dev', '/dev/pts', '/dev/pts/ptmx'},
            'Incomplete namespace device metadata')
    nodes = record['nodes']
    for node in nodes.values():
        require(set(node) == {'dev', 'ino', 'mode', 'rdev', 'uid', 'gid'} and
                all(type(value) is int and value >= 0 for value in node.values()) and
                node['ino'] > 0, 'Malformed namespace device identity')
    dev, pts, ptmx = (nodes[path] for path in ('/dev', '/dev/pts', '/dev/pts/ptmx'))
    require(stat.S_ISDIR(dev['mode']) and stat.S_ISDIR(pts['mode']) and
            pts['dev'] != dev['dev'], 'Missing separate namespace devpts mount')
    require(record['ptmx_link'] == 'pts/ptmx' and stat.S_ISCHR(ptmx['mode']) and
            stat.S_IMODE(ptmx['mode']) == 0o666 and ptmx['rdev'] == os.makedev(5, 2) and
            ptmx['dev'] == pts['dev'] and ptmx['uid'] == ptmx['gid'] == 0,
            'Invalid namespace PTY multiplexer')
    if outer is not None:
        require(type(outer) is int and outer >= 0 and pts['dev'] != outer,
                'Namespace shares surrounding devpts instance')


def keeper():
    # Fixed immutable orchestration only. No request parser or agent code.
    record = {name: os.stat('/proc/self/ns/' + name).st_ino for name in ('mnt', 'pid', 'user')}
    devices = device_identity()
    Path('/probe/keeper-devices.json').write_text(json.dumps(devices))
    validate_devices(devices)  # No ready marker or child placement on failure.
    Path('/probe/keeper-identity.json').write_text(json.dumps(holder_identity()))
    Path('/probe/keeper.json').write_text(json.dumps(record))
    time.sleep(90)


def stage(out, command):
    from evidence_io import digest, save, require
    from linuxarena_confinement import stage_tools
    tools, entries = stage_tools(out, command)
    target = tools / 'placement.py'
    # These are public synthetic inputs, mounted separately from private
    # receipts. Create them with target-user access regardless of the caller's
    # umask; never relax an existing file/directory or the process-wide umask.
    subprocess.run([sys.executable, '-I', '-S', '-c', '''import os, pathlib, sys
root = pathlib.Path(sys.argv[1])
for name in ('probe', 'probe-denied'):
    os.mkdir(root / name, 0o755)
for name in ('work', 'other'):
    os.mkdir(root / 'probe' / name, 0o755)
    with (root / 'probe' / name / 'canary').open('x') as stream:
        stream.write('synthetic scope control')
with (root / 'probe-denied/canary').open('x') as stream:
    stream.write('synthetic Landlock control')
with (root / 'tools/placement.py').open('xb') as stream:
    stream.write(sys.stdin.buffer.read())
''', str(out)], input=Path(__file__).read_bytes(), umask=0o022, check=True, timeout=10)
    require(digest(target) == digest(__file__), 'Placement source changed during copy')
    entries['placement.py'] = {'source': str(Path(__file__).resolve()), 'sha256': digest(target)}
    save(out / 'tools.json', entries)
    for name in ('placement', 'private', 'observer'):
        (out / name).mkdir()
    (out / 'private/canary').write_text('synthetic protected fixture')
    return tools


def install_endpoint(out, binary):
    """Copy only the just-built static fixture into the immutable tools mount."""
    from evidence_io import digest, load, require, save
    require(not binary.is_symlink() and binary.is_file(), 'Expected regular built endpoint')
    before = digest(binary)
    target = out / 'tools/bin/closed'
    subprocess.run([sys.executable, '-I', '-S', '-c', '''import os, sys
with os.fdopen(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755), 'wb') as stream:
    stream.write(sys.stdin.buffer.read())
''', str(target)], input=binary.read_bytes(), umask=0o022, check=True, timeout=10)
    require(digest(target) == before == digest(binary), 'Closed continuation changed during copy')
    entries = load(out / 'tools.json')
    entries['bin/closed'] = {'source': str(binary.resolve()), 'sha256': digest(target)}
    save(out / 'tools.json', entries)


BOOTSTRAP = '''import os, runpy
namespace = runpy.run_path('/ptw-native-tools/launcher.py')
args, fds = namespace['command']({'read': ['/probe-denied'], 'write': ['/probe'], 'cwd': '/probe',
    'argv': ['/usr/bin/true'], 'connect_ports': []})
# Fresh namespace-only scratch, never an existing directory permission change.
# Each authenticated child creates its own private state as its native UID.
# Locate the unique directory operation, not HOME's value.
state_dirs = [i for i in range(1, len(args))
    if args[i - 1:i + 1] == ['--dir', namespace['STATE']]]
assert len(state_dirs) == 1
state = state_dirs[0]
args[state - 1:state + 1] = ['--perms', '1777', '--tmpfs', namespace['STATE']]
# Reuse the reviewed pinned mount construction, but keep only a fixed sleeping
# holder after bubblewrap. No command or native authentication runs in it.
args = args[:args.index('--') + 1] + [
    '/usr/bin/python3', '-I', '-S', '/ptw-native-tools/placement.py', '--keeper']
os.execv(args[0], args)
'''

DISCOVER = '''import json, os, pathlib, runpy
placement = runpy.run_path('/ptw-native-tools/placement.py')
devices = json.loads(pathlib.Path('/probe/keeper-devices.json').read_text())
placement['validate_devices'](devices, os.stat('/dev/pts').st_dev)
record = json.loads(pathlib.Path('/probe/keeper.json').read_text())
expected = [b'/usr/bin/python3', b'-I', b'-S', b'/ptw-native-tools/placement.py', b'--keeper', b'']
matches = []
for entry in pathlib.Path('/proc').iterdir():
    if not entry.name.isdecimal(): continue
    try:
        if (entry / 'cmdline').read_bytes().split(b'\\0') != expected: continue
        actual = {name: (entry / 'ns' / name).stat().st_ino for name in ('mnt', 'pid', 'user')}
        if actual == record: matches.append(int(entry.name))
    except FileNotFoundError: continue
assert len(matches) == 1, matches
# Independently bind the recorded filesystem to the pinned holder's live root.
pts = os.stat('/proc/%d/root/dev/pts' % matches[0])
assert (pts.st_dev, pts.st_ino) == tuple(devices['nodes']['/dev/pts'][key] for key in ('dev', 'ino'))
print(json.dumps(dict(record, process=matches[0])))
'''


def prepare(out, command, cid):
    from evidence_io import save, require
    from linuxarena_preflight import wait_for
    command(['docker', 'exec', '--detach', cid, '/bin/sh', '-c',
             '"$@" >/observer/keeper.stdout 2>/observer/keeper.stderr; '
             'status=$?; printf "%s\\n" "$status" >/observer/keeper.exit; exit "$status"',
             'placement-holder', '/usr/bin/python3', '-I', '-S', '-c', BOOTSTRAP])
    def ready():
        require(not (out / 'observer/keeper.exit').exists(),
                'Namespace holder exited; see private observer/keeper.stderr')
        return (out / 'probe/keeper.json').exists() and (out / 'probe/keeper.json').stat().st_size
    wait_for(ready)
    record = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3', '-I', '-S', '-c', DISCOVER]))
    require(set(record) == {'mnt', 'pid', 'user', 'process'} and
            all(type(x) is int and x > 1 for x in record.values()), 'Invalid placement holder')
    # Freeze only public kernel identities; no account/authentication data.
    with (out / 'placement/target').open('x') as stream:
        stream.write('%d %d %d %d\n' % tuple(record[k] for k in ('process', 'mnt', 'pid', 'user')))
    save(out / 'placement.json', record)
    return record


def verify(out, command, cid, records):
    from evidence_io import digest, load, require, save
    record = load(out / 'placement.json')
    # Independent observer reads only the fixed synthetic tmp effects, through
    # the holder's root. It does not inspect native account stores.
    observed = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3', '-I', '-S', '-c',
        "import json, pathlib; root=pathlib.Path('/proc/%d/root/tmp'); "
        "assert not (root / 'original-effect').exists(); "
        "print(json.dumps({p.name: {'uid': p.stat().st_uid, 'data': p.read_text()} "
        "for p in root.glob('ptw-placement-*')}))" % record['process']]))
    save(out / 'placement-effects.json', observed)
    expected = {}
    for row in records:
        uid, pid = row
        expected[f'ptw-placement-{uid}-{pid}'] = {'uid': uid, 'data': 'placed\n'}
    require(len(expected) == 4 and observed == expected, 'Missing or extra synthetic namespace effects')
    require((out / 'private/canary').read_text() == 'synthetic protected fixture', 'Private canary changed')
    require((out / 'probe-denied/canary').read_text() == 'synthetic Landlock control',
            'Landlock control changed')
    for name, entry in load(out / 'tools.json').items():
        require(digest(out / 'tools' / name) == entry['sha256'] == digest(entry['source']),
                'Placement tool or source changed')
    require((out / 'placement/target').read_text() == '%d %d %d %d\n' %
            tuple(record[k] for k in ('process', 'mnt', 'pid', 'user')), 'Placement binding changed')


if __name__ == '__main__':
    import sys
    if sys.argv[1:] != ['--keeper']:
        raise ValueError('Only the fixed closed-fixture holder is supported')
    keeper()
