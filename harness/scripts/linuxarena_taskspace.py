"""Read-only native TaskSpace check, executed by the pinned runtime Python.

Only TRAIN task objects are resolved. TEST/VALIDATE use lazy ID membership;
their content must not be opened. No sandbox or model is started.
"""
import inspect
import json
import os
from pathlib import Path
import sys

PAIRS = (
    ('file_integrity', 'access_secret_files_you_dont_own'),
    ('duplicate_detection', 'file_corruption'),
    ('stats', 'authentication_bypass'),
)


def guard_task_content(event, args):
    """Development-exposure guard in this trusted inspection process only.

    This is not a security sandbox or an effect boundary. It catches accidental
    native eager file loading, including bytecode imports, before data is read.
    Source-integrity hashing happens separately in the host preflight process.
    """
    if event != 'open' or not isinstance(args[0], (str, bytes, os.PathLike)):
        return
    parts = Path(os.path.realpath(os.fsdecode(args[0]))).parts
    for directory, permitted in (('main_tasks', PAIRS[0][0]), ('side_tasks', PAIRS[0][1])):
        for index, part in enumerate(parts[:-1]):
            if part == directory and parts[index + 1] != permitted:
                raise PermissionError('Non-TRAIN task content access refused')


def inspect_combinations(space):
    identities, combinations = [], []
    # The pinned LazyTaskMap.__contains__ checks IDs without calling its loader.
    mains, sides = space.mains(), space.sides()
    for main, side in PAIRS:
        if main not in mains or side not in sides:
            raise ValueError('Native TaskSpace is missing a planned task identity')
        identities.append({'main': main, 'side': side, 'check': 'lazy ID membership only'})
    main, side = PAIRS[0]
    for selected_side in (None, side):
        combo = space.get(main_id=main, side_id=selected_side)
        if (combo.main_ids != frozenset([main]) or
                combo.side_ids != frozenset([selected_side] if selected_side else []) or
                combo not in space):
            raise ValueError('Native TaskSpace rejected an exact TRAIN combination')
        combinations.append({'main': main, 'side': selected_side, 'mode': combo.mode})
    return identities, combinations


def inspect_taskspace():
    sys.addaudithook(guard_task_content)
    from control_tower.environments.all_environments import ENVIRONMENTS, get_environment
    from control_tower.sandbox.docker import LBDockerSandboxEnvironment
    from control_tower.task.space import LazyTaskMap
    from inspect_ai.util import SandboxEnvironment
    if set(ENVIRONMENTS) != {'file_indexing'}:
        raise ValueError('Expected only the pinned file_indexing setting')
    space = get_environment('file_indexing').task_space()
    if type(space.mains()) is not LazyTaskMap or type(space.sides()) is not LazyTaskMap:
        raise ValueError('TRAIN inspection requires pinned lazy task mappings')
    identities, combinations = inspect_combinations(space)
    routes = {}
    for name, method in inspect.getmembers(SandboxEnvironment, callable):
        if name.startswith('_'):
            continue
        implementation = getattr(LBDockerSandboxEnvironment, name)
        routes[name] = {'signature': str(inspect.signature(implementation)),
                        'module': implementation.__module__,
                        'line': inspect.getsourcelines(implementation)[1]}
    return {'phase': 'TRAIN', 'identities': identities, 'combinations': combinations,
            'non_train_content_guard': True, 'sandbox_routes': routes,
            'sandbox_module': str(Path(inspect.getfile(LBDockerSandboxEnvironment)).resolve()),
            'taskspace_type': type(space).__name__, 'paid_calls': 0}


if __name__ == '__main__':
    print(json.dumps(inspect_taskspace(), sort_keys=True))
