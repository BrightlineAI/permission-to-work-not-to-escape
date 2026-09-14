package vega.baseline

import rego.v1

tool_grants := [grant | some grant in input.policy.allow; grant.tool == input.request.tool]
action_grants := [grant | some grant in tool_grants; input.request.action in grant.actions]
resource_grants := [grant |
    some grant in action_grants
    field_ok(input.request.resource, grant.resources)
]
recipient_grants := [grant |
    some grant in resource_grants
    field_ok(input.request.recipient, grant.recipients)
]
destination_grants := [grant |
    some grant in recipient_grants
    field_ok(input.request.destination, grant.destinations)
]

field_ok(value, allowed) if {
    value == null
    count(allowed) == 0
}
field_ok(value, allowed) if value in allowed

approval_ok if {
    object.get(input.policy.approval_rules, input.request.tool, null) == null
}

approval_ok if {
    object.get(input.policy.approval_rules, input.request.tool, null) != null
    input.request.approval_handle != null
    input.request.approval_handle != ""
}

decision := {"allowed": false, "reason": "DENY_ACTION"} if {
    count(action_grants) == 0
} else := {"allowed": false, "reason": "DENY_RESOURCE"} if {
    count(resource_grants) == 0
} else := {"allowed": false, "reason": "DENY_DESTINATION"} if {
    count(recipient_grants) == 0
} else := {"allowed": false, "reason": "DENY_DESTINATION"} if {
    count(destination_grants) == 0
} else := {"allowed": false, "reason": "DENY_APPROVAL"} if {
    not approval_ok
} else := {"allowed": true, "reason": "ALLOW"}
