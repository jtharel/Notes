import json, subprocess

PROFILE = "XXXXXXXXXXXX"

print("Getting all IAM details...")
result = subprocess.run(
    ["aws", "iam", "get-account-authorization-details", "--profile", PROFILE, "--output", "json"],
    capture_output=True, text=True
)
data = json.loads(result.stdout)

# Actions that grant read access to secret values
READ_ACTIONS = ["secretsmanager:GetSecretValue", "secretsmanager:*", "*"]

def has_read_access(doc):
    actions_found = []
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        action_list = stmt.get("Action", [])
        if isinstance(action_list, str):
            action_list = [action_list]
        for a in action_list:
            if a in READ_ACTIONS or a.lower() in [x.lower() for x in READ_ACTIONS]:
                actions_found.append(a)
    return actions_found

# Build map of managed policy names to their secretsmanager read actions
sm_policies = {}
for policy in data.get("Policies", []):
    for version in policy.get("PolicyVersionList", []):
        if not version.get("IsDefaultVersion"):
            continue
        doc = version.get("Document", {})
        actions = has_read_access(doc)
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
        actions = has_read_access(policy.get("PolicyDocument", {}))
        if actions:
            findings.append(("Role (inline)", name, policy["PolicyName"], ", ".join(actions)))

# Check users
for user in data.get("UserDetailList", []):
    name = user["UserName"]
    for policy in user.get("AttachedManagedPolicies", []):
        if policy["PolicyName"] in sm_policies:
            findings.append(("User (attached)", name, policy["PolicyName"], sm_policies[policy["PolicyName"]]))
    for policy in user.get("UserPolicyList", []):
        actions = has_read_access(policy.get("PolicyDocument", {}))
        if actions:
            findings.append(("User (inline)", name, policy["PolicyName"], ", ".join(actions)))

# Check groups
for group in data.get("GroupDetailList", []):
    name = group["GroupName"]
    for policy in group.get("AttachedManagedPolicies", []):
        if policy["PolicyName"] in sm_policies:
            findings.append(("Group (attached)", name, policy["PolicyName"], sm_policies[policy["PolicyName"]]))
    for policy in group.get("GroupPolicyList", []):
        actions = has_read_access(policy.get("PolicyDocument", {}))
        if actions:
            findings.append(("Group (inline)", name, policy["PolicyName"], ", ".join(actions)))

# Separate wildcard admin from specific secretsmanager access
sm_specific = [f for f in findings if "secretsmanager" in f[3].lower()]
sm_wildcard = [f for f in findings if f[3] == "*"]

print()
print("=" * 60)
print(f"SECRETS READ ACCESS via secretsmanager:GetSecretValue ({len(sm_specific)}):")
print("=" * 60)
for f in sm_specific:
    print(f"  [{f[0]}] {f[1]}")
    print(f"    Policy: {f[2]}")
    print(f"    Actions: {f[3]}")
    print()
if not sm_specific:
    print("  None found")

print()
print("=" * 60)
print(f"SECRETS READ ACCESS via wildcard * ({len(sm_wildcard)}):")
print("=" * 60)
for f in sm_wildcard:
    print(f"  [{f[0]}] {f[1]}")
    print(f"    Policy: {f[2]}")
    print(f"    Actions: {f[3]}")
    print()
if not sm_wildcard:
    print("  None found")

print()
print(f"TOTAL: {len(findings)} principals can read secrets")
