"""Public CI subset; mandatory Linux acceptance is the separate manager gate.

Keep every discovered case except these explicitly native owning classes.
Existing per-test native prerequisites still apply. This does not produce a
full native receipt or a product acceptance result.
"""
from pathlib import Path
import os
import unittest

NATIVE_CLASSES = frozenset({
    'test_product_safety_acceptance.InstalledSafetyTests',
    'test_product_demo.NativeDemoTests',
    'test_product_demo_dependency.NativeDependencyTests',
    'test_product_demo_task_scope.NativeTaskScopeTests',
    'test_product_demo_swarm.NativeSwarmTests',
    'test_product_release.NativeReleaseTests',
})


def partition(suite):
    from native_receipt import cases
    offline, native = [], []
    for test in cases(suite):
        selected = native if test.id().rsplit('.', 1)[0] in NATIVE_CLASSES else offline
        selected.append(test)
    return unittest.TestSuite(offline), unittest.TestSuite(native)


def main():
    if os.environ.get('PTW_LINUX_TESTS') == '1':
        raise ValueError('Use full normal discovery for mandatory native acceptance')
    loader = unittest.TestLoader()
    suite = loader.discover(str(Path(__file__).resolve().parents[1] / 'tests'))
    if loader.errors:
        raise ValueError('Offline discovery failed: ' + '\n'.join(loader.errors))
    offline, native = partition(suite)
    print(f'Public CI subset: {offline.countTestCases()} selected; '
          f'{native.countTestCases()} mandatory installed/native cases reserved for the manager gate.', flush=True)
    return 0 if unittest.TextTestRunner(verbosity=2).run(offline).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
