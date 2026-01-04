# =============================================================================
# Policy: Deny Security Groups with 0.0.0.0/0 on Sensitive Ports
# =============================================================================
# This policy prevents security groups from allowing inbound traffic from
# the entire internet (0.0.0.0/0 or ::/0) on sensitive ports:
#   - Port 22 (SSH)
#   - Port 3389 (RDP)
#
# These ports should only be accessible from specific trusted IP ranges.
# =============================================================================

package terraform

import rego.v1

# List of sensitive ports that should not be open to the world
sensitive_ports := {22, 3389}

# List of dangerous CIDR blocks (open to the world)
dangerous_cidrs := {"0.0.0.0/0", "::/0"}

# Deny security groups with dangerous ingress rules
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    resource.change.actions[_] != "delete"

    some ingress in resource.change.after.ingress

    # Check if the port range includes any sensitive port
    some port in sensitive_ports
    port >= ingress.from_port
    port <= ingress.to_port

    # Check if any CIDR block is dangerous
    some cidr in ingress.cidr_blocks
    cidr in dangerous_cidrs

    msg := sprintf(
        "Security group '%s' allows ingress on port %d from %s. Restrict to specific IP ranges.",
        [resource.address, port, cidr]
    )
}

# Also check IPv6 CIDR blocks
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    resource.change.actions[_] != "delete"

    some ingress in resource.change.after.ingress

    # Check if the port range includes any sensitive port
    some port in sensitive_ports
    port >= ingress.from_port
    port <= ingress.to_port

    # Check if any IPv6 CIDR block is dangerous
    some cidr in ingress.ipv6_cidr_blocks
    cidr in dangerous_cidrs

    msg := sprintf(
        "Security group '%s' allows ingress on port %d from %s (IPv6). Restrict to specific IP ranges.",
        [resource.address, port, cidr]
    )
}

# Deny security group rules (standalone resource) with dangerous ingress
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group_rule"
    resource.change.actions[_] != "delete"
    resource.change.after.type == "ingress"

    # Check if the port range includes any sensitive port
    some port in sensitive_ports
    port >= resource.change.after.from_port
    port <= resource.change.after.to_port

    # Check if any CIDR block is dangerous
    some cidr in resource.change.after.cidr_blocks
    cidr in dangerous_cidrs

    msg := sprintf(
        "Security group rule '%s' allows ingress on port %d from %s. Restrict to specific IP ranges.",
        [resource.address, port, cidr]
    )
}

# Deny VPC security group ingress rules (another standalone resource type)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_vpc_security_group_ingress_rule"
    resource.change.actions[_] != "delete"

    # Check if the port range includes any sensitive port
    some port in sensitive_ports
    port >= resource.change.after.from_port
    port <= resource.change.after.to_port

    # Check if CIDR is dangerous
    resource.change.after.cidr_ipv4 in dangerous_cidrs

    msg := sprintf(
        "VPC security group ingress rule '%s' allows ingress on port %d from %s. Restrict to specific IP ranges.",
        [resource.address, port, resource.change.after.cidr_ipv4]
    )
}
