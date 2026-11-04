import json, subprocess, base64, re

PROFILE = "XXXXXXXXXXXX"

# Patterns that suggest sensitive data in user-data scripts
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+', 'password'),
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+', 'api_key'),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*\S+', 'secret_key'),
    (r'(?i)(access[_-]?key[_-]?id|aws_access_key)\s*[=:]\s*\S+', 'access_key'),
    (r'(?i)(token|auth[_-]?token|bearer)\s*[=:]\s*\S+', 'token'),
    (r'(?i)(db[_-]?pass|database[_-]?password|mysql[_-]?pwd|rds[_-]?password)\s*[=:]\s*\S+', 'db_credential'),
    (r'(?i)(private[_-]?key|priv[_-]?key)\s*[=:]\s*\S+', 'private_key'),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'private_key_block'),
    (r'(?i)(connection[_-]?string|conn[_-]?str)\s*[=:]\s*\S+', 'connection_string'),
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key_id'),
    (r'(?i)(smtp[_-]?pass|mail[_-]?password)\s*[=:]\s*\S+', 'smtp_credential'),
    (r'(?i)curl\s+.*-u\s+\S+:\S+', 'curl_credential'),
    (r'(?i)(mysql|psql|mongo|redis).*-p\s*\S+', 'cli_db_credential'),
    (r'(?i)export\s+(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=', 'exported_aws_credential'),
]


def run_aws(args):
    cmd = ["aws"] + args + ["--profile", PROFILE, "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout) if result.stdout.strip() else None


def scan_userdata(text):
    hits = []
    for pattern, label in SECRET_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            # Find the full matching line for context
            for line_match in re.finditer(pattern, text):
                line_start = text.rfind('\n', 0, line_match.start()) + 1
                line_end = text.find('\n', line_match.end())
                if line_end == -1:
                    line_end = len(text)
                line_text = text[line_start:line_end].strip()
                # Truncate long lines
                if len(line_text) > 120:
                    line_text = line_text[:120] + "..."
                hits.append((label, line_text))
    return hits


print("=" * 70)
print("EC2 INSTANCE METADATA SECURITY AUDIT")
print("=" * 70)

# Step 1: Get all instances
print("\n[*] Enumerating EC2 instances...")
instances_data = run_aws(["ec2", "describe-instances"])
if not instances_data:
    print("  ERROR: Could not retrieve instances. Check permissions.")
    exit(1)

instances = []
for reservation in instances_data.get("Reservations", []):
    for inst in reservation.get("Instances", []):
        instances.append(inst)

print(f"  Found {len(instances)} instance(s)")

# Step 2: Analyze each instance
role_map = []
userdata_findings = []

for inst in instances:
    iid = inst["InstanceId"]
    state = inst.get("State", {}).get("Name", "unknown")
    # Get instance name from tags
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    name = tags.get("Name", "(no name)")

    # Role mapping
    iam_profile = inst.get("IamInstanceProfile", {})
    if iam_profile:
        role_map.append({
            "id": iid,
            "name": name,
            "state": state,
            "profile_arn": iam_profile.get("Arn", ""),
        })

    # User data check (only for running/stopped instances)
    if state in ("running", "stopped"):
        ud_result = run_aws([
            "ec2", "describe-instance-attribute",
            "--instance-id", iid,
            "--attribute", "userData"
        ])
        if ud_result:
            ud_value = ud_result.get("UserData", {}).get("Value", "")
            if ud_value:
                try:
                    decoded = base64.b64decode(ud_value).decode("utf-8", errors="replace")
                    secrets_found = scan_userdata(decoded)
                    userdata_findings.append({
                        "id": iid,
                        "name": name,
                        "state": state,
                        "has_userdata": True,
                        "size": len(decoded),
                        "secrets": secrets_found,
                        "preview": decoded[:300],
                    })
                except Exception as e:
                    userdata_findings.append({
                        "id": iid,
                        "name": name,
                        "state": state,
                        "has_userdata": True,
                        "size": len(ud_value),
                        "secrets": [],
                        "preview": f"(decode error: {e})",
                    })
            else:
                userdata_findings.append({
                    "id": iid,
                    "name": name,
                    "state": state,
                    "has_userdata": False,
                    "size": 0,
                    "secrets": [],
                    "preview": "",
                })

# ============================================================
# REPORT
# ============================================================

# Section 1: Instance Role Mapping
print()
print("=" * 70)
print(f"1. INSTANCES WITH IAM ROLES ATTACHED — {len(role_map)} instance(s)")
print("=" * 70)
print("   Cross-reference with secretsmanager audit for lateral movement risk")
print()
if role_map:
    for r in role_map:
        print(f"  {r['id']}  {r['name']}")
        print(f"    State: {r['state']}")
        print(f"    Profile: {r['profile_arn']}")
        print()
else:
    print("  None — no instance profiles attached")

# Section 2: User Data Secrets
instances_with_ud = [u for u in userdata_findings if u["has_userdata"]]
instances_with_secrets = [u for u in userdata_findings if u["secrets"]]
print()
print("=" * 70)
print(f"2. USER DATA ANALYSIS — {len(instances_with_ud)} with data, "
      f"{len(instances_with_secrets)} with potential secrets")
print("=" * 70)
print("   Risk: User data scripts often contain hardcoded credentials")
print()

if instances_with_secrets:
    print("  ** INSTANCES WITH POTENTIAL SECRETS IN USER DATA **")
    print()
    for u in instances_with_secrets:
        print(f"  {u['id']}  {u['name']}  [{u['state']}]")
        print(f"    User data size: {u['size']} bytes")
        print(f"    Findings:")
        seen = set()
        for label, context in u["secrets"]:
            key = (label, context)
            if key not in seen:
                seen.add(key)
                print(f"      [{label}] {context}")
        print()

if instances_with_ud and not instances_with_secrets:
    print("  User data present but no secret patterns detected:")
    for u in instances_with_ud:
        print(f"    {u['id']}  {u['name']}  ({u['size']} bytes)")
    print()

instances_no_ud = [u for u in userdata_findings if not u["has_userdata"]]
if instances_no_ud:
    print(f"  Instances with no user data: {len(instances_no_ud)}")
    for u in instances_no_ud:
        print(f"    {u['id']}  {u['name']}")
    print()

# Summary
print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total instances:          {len(instances)}")
print(f"  With IAM roles:           {len(role_map)}")
print(f"  With user data:           {len(instances_with_ud)}")
print(f"  With secrets in userdata: {len(instances_with_secrets)}")
print()
