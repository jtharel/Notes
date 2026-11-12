import json, subprocess, os

PROFILE = "XXXXXXXXXXX"

os.makedirs(PROFILE, exist_ok=True)


def run_aws(args):
    cmd = ["aws"] + args + ["--profile", PROFILE, "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, result.stderr
    if not result.stdout.strip():
        return None, "Empty response"
    return json.loads(result.stdout), None


print("=" * 70)
print(f"IAM ROLE ASSUMPTION AUDIT - {PROFILE}")
print("=" * 70)

# Step 1: Who am I?
print("\n[*] Getting current identity...")
identity, err = run_aws(["sts", "get-caller-identity"])
if not identity:
    print(f"  ERROR: {err}")
    exit(1)

my_account = identity["Account"]
my_arn = identity["Arn"]
my_user_id = identity.get("UserId", "")

print(f"  Account:  {my_account}")
print(f"  ARN:      {my_arn}")

# Extract principal identifiers to match against trust policies
# Could be user ARN, role ARN, or account root
my_principals = set()
my_principals.add(my_arn)
my_principals.add(f"arn:aws:iam::{my_account}:root")
my_principals.add(my_account)

# If it's a role, add the role ARN without session name
if ":assumed-role/" in my_arn:
    parts = my_arn.split("/")
    role_name = parts[1] if len(parts) > 1 else ""
    my_principals.add(f"arn:aws:iam::{my_account}:role/{role_name}")

# If it's a user
if ":user/" in my_arn:
    my_principals.add(my_arn)

print(f"\n  Matching against principals:")
for p in sorted(my_principals):
    print(f"    {p}")

# Step 2: List all roles
print(f"\n[*] Listing all IAM roles...")
roles, err = run_aws(["iam", "list-roles"])
if not roles:
    print(f"  ERROR: {err}")
    exit(1)

all_roles = roles.get("Roles", [])
print(f"  Found {len(all_roles)} role(s)")

# Step 3: Check each role's trust policy
print(f"\n[*] Checking trust policies...")

assumable = []
cross_account = []
wildcard = []

for role in all_roles:
    role_name = role["RoleName"]
    role_arn = role["Arn"]
    trust_policy = role.get("AssumeRolePolicyDocument", {})

    if isinstance(trust_policy, str):
        try:
            trust_policy = json.loads(trust_policy)
        except Exception:
            continue

    for stmt in trust_policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        principal = stmt.get("Principal", {})
        conditions = stmt.get("Condition", {})

        # Collect all principal values
        principal_values = set()
        if isinstance(principal, str):
            principal_values.add(principal)
        elif isinstance(principal, dict):
            for key, val in principal.items():
                if isinstance(val, str):
                    principal_values.add(val)
                elif isinstance(val, list):
                    principal_values.update(val)

        # Check for wildcard
        if "*" in principal_values:
            wildcard.append({
                "role_name": role_name,
                "role_arn": role_arn,
                "principals": list(principal_values),
                "conditions": conditions,
                "action": stmt.get("Action", ""),
            })
            continue

        # Check if my principal matches
        matched = my_principals.intersection(principal_values)

        # Also check if account root is trusted (means any principal in that account)
        account_root = f"arn:aws:iam::{my_account}:root"
        if account_root in principal_values:
            matched.add(account_root)

        if matched:
            assumable.append({
                "role_name": role_name,
                "role_arn": role_arn,
                "matched_on": list(matched),
                "all_principals": list(principal_values),
                "conditions": conditions,
                "action": stmt.get("Action", ""),
            })
        elif principal_values:
            # Check for cross-account trust
            for pv in principal_values:
                if ":root" in str(pv) and my_account not in str(pv):
                    cross_account.append({
                        "role_name": role_name,
                        "role_arn": role_arn,
                        "trusted_principal": pv,
                        "conditions": conditions,
                    })

# Report
print()
print("=" * 70)
print(f"1. ROLES YOUR PRINCIPAL CAN ASSUME — {len(assumable)}")
print("=" * 70)
print()

if assumable:
    for r in assumable:
        cond = " (has Conditions)" if r["conditions"] else ""
        print(f"  {r['role_name']}")
        print(f"    ARN: {r['role_arn']}")
        print(f"    Matched on: {', '.join(r['matched_on'])}")
        print(f"    Action: {r['action']}{cond}")
        if r["conditions"]:
            print(f"    Conditions: {json.dumps(r['conditions'], indent=6)}")
        print()
else:
    print("  None found — your principal is not explicitly trusted by any role.")

print()
print("=" * 70)
print(f"2. WILDCARD TRUST (* PRINCIPAL) — {len(wildcard)}")
print("=" * 70)
print("   Any AWS principal can attempt to assume these roles")
print()

if wildcard:
    for r in wildcard:
        cond = " (has Conditions)" if r["conditions"] else " ** NO CONDITIONS **"
        print(f"  {r['role_name']}")
        print(f"    ARN: {r['role_arn']}")
        print(f"    Action: {r['action']}{cond}")
        if r["conditions"]:
            print(f"    Conditions: {json.dumps(r['conditions'], indent=6)}")
        print()
else:
    print("  None found.")

print()
print("=" * 70)
print(f"3. CROSS-ACCOUNT TRUST — {len(cross_account)}")
print("=" * 70)
print()

if cross_account:
    # Group by trusted account
    by_account = {}
    for r in cross_account:
        acct = r["trusted_principal"]
        by_account.setdefault(acct, []).append(r)

    for acct, roles_list in by_account.items():
        print(f"  Trusted: {acct}")
        for r in roles_list:
            cond = " (has Conditions)" if r["conditions"] else ""
            print(f"    → {r['role_name']}{cond}")
        print()
else:
    print("  None found.")

# Summary
print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Current principal:         {my_arn}")
print(f"  Total roles in account:    {len(all_roles)}")
print(f"  Assumable by you:          {len(assumable)}")
print(f"  Wildcard trust (* ):       {len(wildcard)}")
print(f"  Cross-account trust:       {len(cross_account)}")
print()

# Save assumable roles for easy use
if assumable:
    outfile = os.path.join(PROFILE, "assumable_roles.json")
    with open(outfile, "w") as f:
        json.dump(assumable, f, indent=2, default=str)
    print(f"  Assumable roles saved to: {outfile}")
    print()
    print("  To assume a role:")
    print(f'    aws sts assume-role --role-arn "ROLE_ARN" --role-session-name "test" --profile {PROFILE}')
    print()
