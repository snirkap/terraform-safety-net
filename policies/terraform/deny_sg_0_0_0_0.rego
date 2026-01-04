# =============================================================================
# Policy: Deny Security Groups with 0.0.0.0/0 on Sensitive Ports
# =============================================================================
# This policy prevents security groups from allowing inbound traffic from
# the entire internet (0.0.0.0/0 or ::/0) on sensitive ports:
#   - Port 22 (SSH)
#   - Port 3389 (RDP)
# =============================================================================

package main

# List of sensitive ports that should not be open to the world
sensitive_ports := [22, 3389]

# List of dangerous CIDR blocks (open to the world)
dangerous_cidrs := ["0.0.0.0/0", "::/0"]

# Deny security groups with dangerous ingress rules
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    resource.change.actions[_] != "delete"

    ingress := resource.change.after.ingress[_]

    # Check if the port range includes any sensitive port
    port := sensitive_ports[_]
    port >= ingress.from_port
    port <= ingress.to_port

    # Check if any CIDR block is dangerous
    cidr := ingress.cidr_blocks[_]
    cidr == dangerous_cidrs[_]

    msg := sprintf(
        "Security group '%s' allows ingress on port %d from %s. Restrict to specific IP ranges.",
        [resource.address, port, cidr]
    )
}

# Also check IPv6 CIDR blocks
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    resource.change.actions[_] != "delete"

    ingress := resource.change.after.ingress[_]

    # Check if the port range includes any sensitive port
    port := sensitive_ports[_]
    port >= ingress.from_port
    port <= ingress.to_port

    # Check if any IPv6 CIDR block is dangerous
    cidr := ingress.ipv6_cidr_blocks[_]
    cidr == dangerous_cidrs[_]

    msg := sprintf(
        "Security group '%s' allows ingress on port %d from %s (IPv6). Restrict to specific IP ranges.",
        [resource.address, port, cidr]
    )
}

# Deny security group rules (standalone resource) with dangerous ingress
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.actions[_] != "delete"
    resource.change.after.type == "ingress"

    # Check if the port range includes any sensitive port
    port := sensitive_ports[_]
    port >= resource.change.after.from_port
    port <= resource.change.after.to_port

    # Check if any CIDR block is dangerous
    cidr := resource.change.after.cidr_blocks[_]
    cidr == dangerous_cidrs[_]

    msg := sprintf(
        "Security group rule '%s' allows ingress on port %d from %s. Restrict to specific IP ranges.",
        [resource.address, port, cidr]
    )
}
