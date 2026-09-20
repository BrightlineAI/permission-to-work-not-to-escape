"""Read-only native TaskSpace check, executed by the pinned runtime Python.

This loads task identities, not scorer implementations or permission proposals.
It neither starts a sandbox nor requests a model.
"""
import inspect
import json
from pathlib import Path

PAIRS = (
    ('file_integrity', 'access_secret_files_you_dont_own'),
    ('duplicate_detection', 'file_corruption'),
    ('stats', 'authentication_bypass'),
)


def inspect_taskspace():
    from control_tower.environments.all_environments import ENVIRONMENTS, get_environment
    from control_tower.sandbox.docker import LBDockerSandboxEnvironment
    from inspect_ai.util import SandboxEnvironment
    if set(ENVIRONMENTS) != {'file_indexing'}:
        raise ValueError('Expected only the pinned file_indexing setting')
    space = get_environment('file_indexing').task_space()
    combinations = []
    for main, side in PAIRS:
        for selected_side in (None, side):
            combo = space.get(main_id=main, side_id=selected_side)
            if (combo.main_ids != frozenset([main]) or
                    combo.side_ids != frozenset([selected_side] if selected_side else []) or
                    combo not in space):
                raise ValueError('Native TaskSpace rejected an exact planned combination')
            combinations.append({'main': main, 'side': selected_side, 'mode': combo.mode})
    routes = {}
    for name, method in inspect.getmembers(SandboxEnvironment, callable):
        if name.startswith('_'):
            continue
        implementation = getattr(LBDockerSandboxEnvironment, name)
        routes[name] = {'signature': str(inspect.signature(implementation)),
                        'module': implementation.__module__,
                        'line': inspect.getsourcelines(implementation)[1]}
    return {'combinations': combinations, 'sandbox_routes': routes,
            'sandbox_module': str(Path(inspect.getfile(LBDockerSandboxEnvironment)).resolve()),
            'taskspace_type': type(space).__name__, 'paid_calls': 0}


if __name__ == '__main__':
    print(json.dumps(inspect_taskspace(), sort_keys=True))
