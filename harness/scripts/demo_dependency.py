"""Compatibility entry point; implementation ships in the runtime wheel."""
from pathlib import Path
import sys

__file__ = str(Path(__file__).resolve().parents[1] / 'ptw/demo_support/demo_dependency.py')
sys.path.insert(0, str(Path(__file__).parent))
exec(compile(Path(__file__).read_bytes(), __file__, 'exec'))
