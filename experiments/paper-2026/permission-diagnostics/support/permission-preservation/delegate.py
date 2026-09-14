"""Parent-side dispatch request; cannot specify identity or child permissions."""
import json
import os
import sys

route, action, resource, payload = sys.argv[1:5]
print(json.dumps(dict(event="delegate", parent_pid=os.getpid(), parent_uid=os.getuid(),
                     route=route, action=action, resource=resource, payload=payload)))
