"""Installed deterministic demo CLI: python -B -m ptw.demo."""
from pathlib import Path
import sys


def main(argv=None):
    # The existing standalone workers also use this private script directory
    # inside their outer namespace. Keep their imports and execution unchanged.
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'demo_support'))
    from product_demo import main as run
    return run(argv)


if __name__ == '__main__':
    raise SystemExit(main())
