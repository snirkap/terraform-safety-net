# =============================================================================
# Policy: Deny IAM Policies with Wildcards
# =============================================================================
# This policy prevents IAM policies from using overly permissive wildcards:
#   - Action: "*" (allows all actions)
#   - Resource: "*" (applies to all resources)
# =============================================================================

package main

# Deny IAM policies with Action = "*"
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    statement := policy_doc.Statement[_]

    # Check if Action is "*"
    statement.Action == "*"

    msg := sprintf(
        "IAM policy '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}

# Deny IAM policies with Action array containing "*"
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    statement := policy_doc.Statement[_]

    # Check if Action array contains "*"
    statement.Action[_] == "*"

    msg := sprintf(
        "IAM policy '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}

# Deny IAM policies with Resource = "*" in Allow statements
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    statement := policy_doc.Statement[_]

    statement.Effect == "Allow"
    statement.Resource == "*"

    msg := sprintf(
        "IAM policy '%s' contains Resource='*' in an Allow statement. Use specific resource ARNs.",
        [resource.address]
    )
}

# Deny IAM policies with Resource array containing "*" in Allow statements
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    statement := policy_doc.Statement[_]

    statement.Effect == "Allow"
    statement.Resource[_] == "*"

    msg := sprintf(
        "IAM policy '%s' contains Resource='*' in an Allow statement. Use specific resource ARNs.",
        [resource.address]
    )
}

# Deny IAM role policies with Action = "*"
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] != "delete"

    policy_doc := json.unmarshal(resource.change.after.policy)
    statement := policy_doc.Statement[_]

    statement.Action == "*"

    msg := sprintf(
        "IAM role policy '%s' contains Action='*'. Use specific actions instead of wildcards.",
        [resource.address]
    )
}
