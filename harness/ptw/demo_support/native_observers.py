"""Task-17 trusted process fixtures and independent Linux cessation observers.

These sentinels are operator fixtures, never model tools or confinement evidence.
Keep every spawned unit in the caller's cleanup list, including failed starts.
"""
from pathlib import Path
import sys
import time

from evidence_io import require


def start_sentinel(store, actor, sentinel, running):
    from ptw.supervisor import Supervisor
    sentinel = Path(sentinel)
    code = ("import os,time; from pathlib import Path; p=Path(" + repr(str(sentinel)) + "); "
            "tmp=p.with_suffix('.pending')"
            "\nfor i in range(3600):\n tmp.write_text(str(os.getpid())+':'+str(i)); tmp.replace(p); time.sleep(.05)")
    parent = 'import subprocess,time; subprocess.Popen(' + repr([sys.executable, '-c', code]) + '); time.sleep(180)'
    process, unit = Supervisor(store).engine(actor['token'], [sys.executable, '-c', parent])
    running.append((process, unit, sentinel, None))
    deadline = time.monotonic() + 10
    while not sentinel.exists() and time.monotonic() < deadline:
        time.sleep(.02)
    require(sentinel.exists(), 'Sentinel did not start')
    group = Supervisor.state(unit)['ControlGroup']
    require(group, 'Missing sentinel control group')
    running[-1] = (process, unit, sentinel, Path('/sys/fs/cgroup' + group))
    require('populated 1' in (running[-1][3] / 'cgroup.events').read_text(), 'Sentinel group is empty')
    return running[-1]


def observe(work, *, stopped):
    process, unit, sentinel, group = work
    begin = time.monotonic()
    if stopped:
        process.wait(timeout=10)
    before = sentinel.read_text()
    pid = int(before.split(':')[0])
    proc = Path('/proc') / str(pid) / 'stat'
    stat = proc.read_text().split(') ')[1].split()[0] if proc.exists() else 'absent'
    events = group / 'cgroup.events'
    group_state = events.read_text() if events.exists() else 'removed'
    time.sleep(.15)
    after = sentinel.read_text()
    result = {'unit': unit, 'parent_exit_code': process.poll(), 'descendant_state': stat,
              'cgroup_events': group_state, 'sentinel_before': before, 'sentinel_after': after,
              'seconds': time.monotonic() - begin, 'stopped': stopped}
    verify_observation(result, stopped=stopped)
    return result


def verify_observation(row, *, stopped):
    from evidence_io import seconds
    seconds(row['seconds'], 'process observation')
    require(row['seconds'] >= .15 and row['stopped'] is stopped, 'Incomplete process observation')
    before, after = (row[k].split(':') for k in ('sentinel_before', 'sentinel_after'))
    require(len(before) == len(after) == 2 and all(p.isdigit() for p in before + after)
            and int(before[0]) > 0 and before[0] == after[0], 'Invalid descendant sample')
    if stopped:
        require(type(row['parent_exit_code']) is int and row['descendant_state'] in ('absent', 'Z')
                and (row['cgroup_events'] == 'removed' or 'populated 0' in row['cgroup_events'])
                and before == after, 'Registered work did not cease')
    else:
        require(row['parent_exit_code'] is None and row['descendant_state'] not in ('absent', 'Z')
                and 'populated 1' in row['cgroup_events'] and int(after[1]) > int(before[1]),
                'Unrelated work did not continue')
