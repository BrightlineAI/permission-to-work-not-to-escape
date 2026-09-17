# Dependency journey fixtures

These small projects are inputs for `product_ecosystems_acceptance.py`. Python
imports a checked public wheel, Node imports an npm package, and TypeScript
compiles and executes a typed addition function. The mixed fixture is assembled
from the Python and TypeScript directories under `backend` and `frontend` in a
fresh output directory. No fixture grants access to the repository root.

The driver uses scripted operator approval for these synthetic projects only.
It makes no model calls and is not evidence of a live Codex conversation. It
requires a native Linux namespace/systemd environment and registry access.
The driver also includes the npm workspace fixture. Its nested metadata staging
now reaches native service startup, which is blocked by the worker sandbox.
Native fixture results remain pending manager validation. Lock import,
private-registry and dependency-revision acceptance is not covered by this driver;
the focused ecosystem suite contains additional synthetic and native cases.
