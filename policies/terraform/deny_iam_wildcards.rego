# =============================================================================
# Policy: Deny IAM Policies with Wildcards
# =============================================================================
# This policy prevents IAM policies from using overly permissive wildcards:
#   - Action: "*" (allows all actions)
#   - Resource: "*" (applies to all resources)
#
# Such policies violate the principle of least privilege and pose significant
# security risks. Policies should specify explicit actions and resources.
# =============================================================================

package terraform

import rego.v1

# Deny IAM policies with Action = "*"
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    some statement in policy_doc.Statement

    # Check if Action is "*" (can be string or array)
    action_is_wildcard(statement.Action)

    msg := sprintf(
        "IAM policy '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}

# Deny IAM policies with Resource = "*"
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    some statement in policy_doc.Statement

    # Check if Resource is "*" (can be string or array)
    resource_is_wildcard(statement.Resource)

    # Only flag if this is an Allow statement (Deny with * is actually restrictive)
    statement.Effect == "Allow"

    msg := sprintf(
        "IAM policy '%s' contains Resource='*' in an Allow statement. Use specific resource ARNs.",
        [resource.address]
    )
}

# Deny IAM role policies with wildcards
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    some statement in policy_doc.Statement

    action_is_wildcard(statement.Action)

    msg := sprintf(
        "IAM role policy '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}

# Deny IAM role policies with Resource = "*"
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    some statement in policy_doc.Statement

    resource_is_wildcard(statement.Resource)
    statement.Effect == "Allow"

    msg := sprintf(
        "IAM role policy '%s' contains Resource='*' in an Allow statement. Use specific resource ARNs.",
        [resource.address]
    )
}

# Deny IAM user policies with wildcards
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_user_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    some statement in policy_doc.Statement

    action_is_wildcard(statement.Action)

    msg := sprintf(
        "IAM user policy '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}

# Deny IAM group policies with wildcards
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_group_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    some statement in policy_doc.Statement

    action_is_wildcard(statement.Action)

    msg := sprintf(
        "IAM group policy '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}

# Deny IAM policy documents (data source that might be attached)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_policy_document"

    some statement in resource.change.after.statement

    # Check actions array for wildcards
    some action in statement.actions
    action == "*"

    msg := sprintf(
        "IAM policy document '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}

# Helper: Check if Action contains wildcard
action_is_wildcard(action) if {
    action == "*"
}

action_is_wildcard(action) if {
    is_array(action)
    "*" in action
}

# Helper: Check if Resource contains wildcard
resource_is_wildcard(resource) if {
    resource == "*"
}

resource_is_wildcard(resource) if {
    is_array(resource)
    "*" in resource
}
