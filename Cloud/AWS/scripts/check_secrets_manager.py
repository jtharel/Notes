import json, subprocess

PROFILE = "XXXXXXXXXXX"

print("Getting all IAM details...")
result = subprocess.run(
    ["aws", "iam", "get-account-authorization-details", "--profile", PROFILE, "--output", "json"],
    capture_output=True, text=True
)
data = json.loads(result.stdout)

def get_sm_actions(doc):
    actions = []
    for stmt in doc.get("Statement", []):
        action_list = stmt.get("Action", [])
        if isinstance(action_list, str):
            action_list = [action_list]
        for a in action_list:
            if "secretsmanager" in a.lower() or a == "*":
                actions.append(a)
    return actions

# Build map of managed policy names to their secretsmanager actions
sm_policies = {}
for policy in data.get("Policies", []):
    for version in policy.get("PolicyVersionList", []):
        if not version.get("IsDefaultVersion"):
            continue
        doc = version.get("Document", {})
        actions = get_sm_actions(doc)
        if actions:
            sm_policies[policy["PolicyName"]] = ", ".join(actions)

findings = []

# Check roles
for role in data.get("RoleDetailList", []):
    name = role["RoleName"]
    for policy in role.get("AttachedManagedPolicies", []):
        if policy["PolicyName"] in sm_policies:
            findings.append(("Role (attached)", name, policy["PolicyName"], sm_policies[policy["PolicyName"]]))
    for policy in role.get("RolePolicyList", []):
        actions = get_sm_actions(policy.get("PolicyDocument", {}))
        if actions:
            findings.append(("Role (inline)", name, policy["PolicyName"], ", ".join(actions)))

# Check users
for user in data.get("UserDetailList", []):
    name = user["UserName"]
    for policy in user.get("AttachedManagedPolicies", []):
        if policy["PolicyName"] in sm_policies:
            findings.append(("User (attached)", name, policy["PolicyName"], sm_policies[policy["PolicyName"]]))
    for policy in user.get("UserPolicyList", []):
        actions = get_sm_actions(policy.get("PolicyDocument", {}))
        if actions:
            findings.append(("User (inline)", name, policy["PolicyName"], ", ".join(actions)))

# Check groups
for group in data.get("GroupDetailList", []):
    name = group["GroupName"]
    for policy in group.get("AttachedManagedPolicies", []):
        if policy["PolicyName"] in sm_policies:
            findings.append(("Group (attached)", name, policy["PolicyName"], sm_policies[policy["PolicyName"]]))
    for policy in group.get("GroupPolicyList", []):
        actions = get_sm_actions(policy.get("PolicyDocument", {}))
        if actions:
            findings.append(("Group (inline)", name, policy["PolicyName"], ", ".join(actions)))

print()
print("=" * 60)
print(f"Principals with Secrets Manager access ({len(findings)}):")
print("=" * 60)
for f in findings:
    print(f"  [{f[0]}] {f[1]}")
    print(f"    Policy: {f[2]}")
    print(f"    Actions: {f[3]}")
    print()
if not findings:
    print("  None found")
