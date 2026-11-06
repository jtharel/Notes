import json, subprocess

PROFILE = "XXXXXXXXXX"

# Permissive action patterns to flag
WILDCARD_ACTIONS = ["*"]
DANGEROUS_PATTERNS = [
    "iam:*",
    "s3:*",
    "ec2:*",
    "lambda:*",
    "sts:*",
    "sts:AssumeRole",
    "secretsmanager:*",
    "kms:*",
    "rds:*",
    "dynamodb:*",
    "logs:*",
    "cloudformation:*",
    "cloudtrail:*",
    "organizations:*",
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:PassRole",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:PutBucketPolicy",
]


def run_aws(args):
    cmd = ["aws"] + args + ["--profile", PROFILE, "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout) if result.stdout.strip() else None


def analyze_policy_doc(doc):
    """Analyze a policy document for permissive rules. Returns list of issues."""
    issues = []
    for stmt in doc.get("Statement", []):
        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        conditions = stmt.get("Condition", {})
        has_condition = bool(conditions)

        # Check for NotAction (inverse allow — often more permissive than intended)
        not_actions = stmt.get("NotAction", [])
        if isinstance(not_actions, str):
            not_actions = [not_actions]

        # Full admin: Action * + Resource *
        if "*" in actions and "*" in resources:
            issues.append({
                "severity": "CRITICAL",
                "issue": "Full admin access (Action: *, Resource: *)",
                "actions": actions,
                "resources": resources,
                "condition": has_condition,
            })
            continue

        # Action wildcard with broad resources
        if "*" in actions:
            issues.append({
                "severity": "CRITICAL",
                "issue": "Wildcard action (Action: *)",
                "actions": actions,
                "resources": resources,
                "condition": has_condition,
            })
            continue

        # NotAction with Allow — grants everything EXCEPT listed actions
        if not_actions:
            issues.append({
                "severity": "HIGH",
                "issue": f"NotAction allow — permits all actions except: {', '.join(not_actions[:5])}",
                "actions": not_actions,
                "resources": resources,
                "condition": has_condition,
            })
            continue

        # Service-level wildcards (e.g., iam:*, s3:*, ec2:*)
        service_wildcards = [a for a in actions if a.endswith(":*")]
        if service_wildcards:
            issues.append({
                "severity": "HIGH",
                "issue": f"Service-level wildcard: {', '.join(service_wildcards)}",
                "actions": actions,
                "resources": resources,
                "condition": has_condition,
            })
            continue

        # Dangerous specific actions
        dangerous_found = [a for a in actions if a.lower() in [d.lower() for d in DANGEROUS_PATTERNS]]
        if dangerous_found and "*" in resources:
            issues.append({
                "severity": "MEDIUM",
                "issue": f"Dangerous actions on all resources: {', '.join(dangerous_found)}",
                "actions": actions,
                "resources": resources,
                "condition": has_condition,
            })

    return issues


print("=" * 70)
print("AWS PERMISSIVE POLICY AUDIT")
print("=" * 70)

print("\n[*] Getting IAM account authorization details...")
data = run_aws(["iam", "get-account-authorization-details"])
if not data:
    print("  ERROR: Could not retrieve IAM details. Check permissions.")
    exit(1)

# ============================================================
# Analyze managed policies
# ============================================================
print("[*] Analyzing managed policies...")
policy_findings = []

for policy in data.get("Policies", []):
    pname = policy["PolicyName"]
    parn = policy["Arn"]
    attachment_count = policy.get("AttachmentCount", 0)

    for version in policy.get("PolicyVersionList", []):
        if not version.get("IsDefaultVersion"):
            continue
        doc = version.get("Document", {})
        issues = analyze_policy_doc(doc)
        if issues:
            policy_findings.append({
                "type": "Managed Policy",
                "name": pname,
                "arn": parn,
                "attached_to_count": attachment_count,
                "issues": issues,
            })

# ============================================================
# Analyze inline policies on roles
# ============================================================
print("[*] Analyzing role inline policies...")
role_findings = []

for role in data.get("RoleDetailList", []):
    rname = role["RoleName"]

    # Inline policies
    for policy in role.get("RolePolicyList", []):
        doc = policy.get("PolicyDocument", {})
        issues = analyze_policy_doc(doc)
        if issues:
            role_findings.append({
                "type": "Role Inline",
                "principal": rname,
                "policy_name": policy["PolicyName"],
                "issues": issues,
            })

    # Attached managed policies (cross-reference)
    for attached in role.get("AttachedManagedPolicies", []):
        for pf in policy_findings:
            if pf["arn"] == attached.get("PolicyArn"):
                role_findings.append({
                    "type": "Role Attached",
                    "principal": rname,
                    "policy_name": attached["PolicyName"],
                    "issues": pf["issues"],
                })

# ============================================================
# Analyze inline policies on users
# ============================================================
print("[*] Analyzing user inline policies...")
user_findings = []

for user in data.get("UserDetailList", []):
    uname = user["UserName"]

    for policy in user.get("UserPolicyList", []):
        doc = policy.get("PolicyDocument", {})
        issues = analyze_policy_doc(doc)
        if issues:
            user_findings.append({
                "type": "User Inline",
                "principal": uname,
                "policy_name": policy["PolicyName"],
                "issues": issues,
            })

    for attached in user.get("AttachedManagedPolicies", []):
        for pf in policy_findings:
            if pf["arn"] == attached.get("PolicyArn"):
                user_findings.append({
                    "type": "User Attached",
                    "principal": uname,
                    "policy_name": attached["PolicyName"],
                    "issues": pf["issues"],
                })

# ============================================================
# Analyze inline policies on groups
# ============================================================
print("[*] Analyzing group inline policies...")
group_findings = []

for group in data.get("GroupDetailList", []):
    gname = group["GroupName"]

    for policy in group.get("GroupPolicyList", []):
        doc = policy.get("PolicyDocument", {})
        issues = analyze_policy_doc(doc)
        if issues:
            group_findings.append({
                "type": "Group Inline",
                "principal": gname,
                "policy_name": policy["PolicyName"],
                "issues": issues,
            })

    for attached in group.get("AttachedManagedPolicies", []):
        for pf in policy_findings:
            if pf["arn"] == attached.get("PolicyArn"):
                group_findings.append({
                    "type": "Group Attached",
                    "principal": gname,
                    "policy_name": attached["PolicyName"],
                    "issues": pf["issues"],
                })

# ============================================================
# REPORT
# ============================================================

# Section 1: Critical — full admin / wildcard
print()
print("=" * 70)
print("1. CRITICAL — FULL ADMIN / WILDCARD ACTION POLICIES")
print("=" * 70)
print()
critical = [p for p in policy_findings if any(i["severity"] == "CRITICAL" for i in p["issues"])]
if critical:
    for p in critical:
        print(f"  {p['name']}")
        print(f"    ARN: {p['arn']}")
        print(f"    Attached to: {p['attached_to_count']} principal(s)")
        for issue in p["issues"]:
            if issue["severity"] == "CRITICAL":
                cond_note = " (has Condition)" if issue["condition"] else " (NO condition)"
                print(f"    >> {issue['issue']}{cond_note}")
                print(f"       Resources: {', '.join(issue['resources'][:3])}")
        print()
else:
    print("  None found")

# Section 2: High — service wildcards, NotAction
print()
print("=" * 70)
print("2. HIGH — SERVICE WILDCARDS / NOTACTION ALLOWS")
print("=" * 70)
print()
high = [p for p in policy_findings if any(i["severity"] == "HIGH" for i in p["issues"])]
if high:
    for p in high:
        print(f"  {p['name']}")
        print(f"    ARN: {p['arn']}")
        print(f"    Attached to: {p['attached_to_count']} principal(s)")
        for issue in p["issues"]:
            if issue["severity"] == "HIGH":
                cond_note = " (has Condition)" if issue["condition"] else " (NO condition)"
                print(f"    >> {issue['issue']}{cond_note}")
                print(f"       Resources: {', '.join(issue['resources'][:3])}")
        print()
else:
    print("  None found")

# Section 3: Principals with permissive access
print()
print("=" * 70)
print("3. PRINCIPALS WITH PERMISSIVE POLICIES")
print("=" * 70)

all_principal_findings = role_findings + user_findings + group_findings

# Deduplicate and sort by severity
critical_principals = [f for f in all_principal_findings
                       if any(i["severity"] == "CRITICAL" for i in f["issues"])]
high_principals = [f for f in all_principal_findings
                   if any(i["severity"] == "HIGH" for i in f["issues"])
                   and f not in critical_principals]

print(f"\n  CRITICAL ({len(critical_principals)}):")
if critical_principals:
    # Deduplicate by principal name
    seen = set()
    for f in critical_principals:
        key = f"{f['principal']}|{f['policy_name']}"
        if key in seen:
            continue
        seen.add(key)
        print(f"    [{f['type']}] {f['principal']}")
        print(f"      Policy: {f['policy_name']}")
        for issue in f["issues"]:
            if issue["severity"] == "CRITICAL":
                print(f"      >> {issue['issue']}")
        print()
else:
    print("    None")

print(f"  HIGH ({len(high_principals)}):")
if high_principals:
    seen = set()
    for f in high_principals:
        key = f"{f['principal']}|{f['policy_name']}"
        if key in seen:
            continue
        seen.add(key)
        print(f"    [{f['type']}] {f['principal']}")
        print(f"      Policy: {f['policy_name']}")
        for issue in f["issues"]:
            if issue["severity"] == "HIGH":
                print(f"      >> {issue['issue']}")
        print()
else:
    print("    None")

# Summary
print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total managed policies analyzed: {len(data.get('Policies', []))}")
print(f"  Permissive managed policies:     {len(policy_findings)}")
print(f"    Critical (wildcard/admin):      {len(critical)}")
print(f"    High (service wildcard/NotAct): {len(high)}")
print(f"  Roles with permissive policies:   {len(set(f['principal'] for f in role_findings))}")
print(f"  Users with permissive policies:   {len(set(f['principal'] for f in user_findings))}")
print(f"  Groups with permissive policies:  {len(set(f['principal'] for f in group_findings))}")
print()
