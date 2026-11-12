import json, subprocess, os

PROFILE = "XXXXXXXXX"

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

# Step 4: Actually attempt to assume each candidate role
candidates = assumable + wildcard
if candidates:
    print()
    print("=" * 70)
    print(f"4. ATTEMPTING ROLE ASSUMPTION — {len(candidates)} candidate(s)")
    print("=" * 70)
    print()

    succeeded = []
    failed = []

    for i, r in enumerate(candidates, 1):
        role_arn = r["role_arn"]
        role_name = r["role_name"]
        print(f"  [{i}/{len(candidates)}] Trying {role_name}...", end=" ")

        result = subprocess.run(
            ["aws", "sts", "assume-role",
             "--role-arn", role_arn,
             "--role-session-name", "audit-test",
             "--duration-seconds", "900",
             "--profile", PROFILE,
             "--output", "json"],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            creds = json.loads(result.stdout).get("Credentials", {})
            print("SUCCESS")
            succeeded.append({
                "role_name": role_name,
                "role_arn": role_arn,
                "access_key": creds.get("AccessKeyId", ""),
                "secret_key": creds.get("SecretAccessKey", ""),
                "session_token": creds.get("SessionToken", ""),
                "expiration": creds.get("Expiration", ""),
            })
        else:
            err_msg = result.stderr.strip()
            short_err = err_msg.split(":")[-1].strip() if ":" in err_msg else err_msg
            if len(short_err) > 80:
                short_err = short_err[:80] + "..."
            print(f"DENIED — {short_err}")
            failed.append({
                "role_name": role_name,
                "role_arn": role_arn,
                "error": short_err,
            })

    # Report successful assumptions
    print()
    print("=" * 70)
    print(f"5. SUCCESSFULLY ASSUMED ROLES — {len(succeeded)}")
    print("=" * 70)
    print()

    if succeeded:
        for r in succeeded:
            print(f"  {r['role_name']}")
            print(f"    ARN: {r['role_arn']}")
            print(f"    Access Key:     {r['access_key']}")
            print(f"    Expiration:     {r['expiration']}")
            print()
            print(f"    To use this role:")
            print(f"      set AWS_ACCESS_KEY_ID={r['access_key']}")
            print(f"      set AWS_SECRET_ACCESS_KEY={r['secret_key']}")
            print(f"      set AWS_SESSION_TOKEN=<REDACTED>")
            print()

        # Save successful credentials
        outfile = os.path.join(PROFILE, "assumed_roles.json")
        with open(outfile, "w") as f:
            json.dump(succeeded, f, indent=2, default=str)
        print(f"  Credentials saved to: {outfile}")
    else:
        print("  No roles could be assumed.")

    print()
    print(f"  Failed: {len(failed)}")
    for r in failed:
        print(f"    {r['role_name']} — {r['error']}")

# Summary
print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Current principal:         {my_arn}")
print(f"  Total roles in account:    {len(all_roles)}")
print(f"  Trust policy match:        {len(assumable)}")
print(f"  Wildcard trust (* ):       {len(wildcard)}")
print(f"  Cross-account trust:       {len(cross_account)}")
if candidates:
    print(f"  Assumption attempted:      {len(candidates)}")
    print(f"  Assumption succeeded:      {len(succeeded)}")
    print(f"  Assumption denied:         {len(failed)}")
print()
           
