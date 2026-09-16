"""Trusted pre-sandbox setup. Mount pinned descriptors, never mutable path aliases."""
import json
import os
import sys

from .policy import Invalid, open_resource, scope
from .supervisor import sandbox_command


def main():
    config = json.loads(sys.argv[1])
    inv, grants = config["inventory"], config["grants"]
    descriptors = {}
    try:
        for name, actions in scope(grants).items():
            if not ({"read", "write"} & actions):
                continue
            fd = open_resource(inv, inv["resources"][name]["path"], os.O_PATH)
            descriptors[name] = fd
            info = os.fstat(fd)
            if [info.st_dev, info.st_ino] != config["bindings"][name]:
                raise Invalid("Resource changed before sandbox launch")
            os.set_inheritable(fd, True)
        command = sandbox_command(inv, grants, sys.argv[2:], config["nono"], descriptors)
        os.execv(command[0], command)
    finally:
        for fd in descriptors.values():
            os.close(fd)


if __name__ == "__main__":
    main()
