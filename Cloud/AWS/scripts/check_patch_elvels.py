import json, subprocess, os

PROFILE = "XXXXXXXXXX"

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
print(f"PATCH COMPLIANCE AUDIT - {PROFILE}")
print("=" * 70)

# Step 1: Check which instances have SSM agents
print("\n[*] Checking for SSM managed instances...")
ssm_instances, err = run_aws(["ssm", "describe-instance-information"])

if err or not ssm_instances:
    print(f"  ERROR: Could not retrieve SSM instances. {err or ''}")
    print("  SSM may not be in use in this account.")
    exit(1)

managed = ssm_instances.get("InstanceInformationList", [])
print(f"  Found {len(managed)} SSM managed instance(s)")

# Step 2: Get patch compliance for all instances
print("\n[*] Checking patch compliance...")
patch_states, err = run_aws(["ssm", "describe-instance-patch-states"])

patch_map = {}
if patch_states:
    for ps in patch_states.get("InstancePatchStates", []):
        patch_map[ps["InstanceId"]] = ps

# Step 3: Get EC2 instance names for friendly output
print("[*] Getting EC2 instance details...")
ec2_data, _ = run_aws(["ec2", "describe-instances"])
name_map = {}
if ec2_data:
    for res in ec2_data.get("Reservations", []):
        for inst in res.get("Instances", []):
            iid = inst["InstanceId"]
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            name_map[iid] = tags.get("Name", "(no name)")

# ============================================================
# REPORT
# ============================================================

# Section 1: SSM Agent Status
print()
print("=" * 70)
print(f"1. SSM MANAGED INSTANCES — {len(managed)}")
print("=" * 70)
print()
print("{:<22} {:<30} {:<12} {:<15} {:<15}".format(
    "Instance ID", "Name", "Ping", "Platform", "Agent Ver"))
print("-" * 94)

online = 0
offline = 0
for inst in managed:
    iid = inst.get("InstanceId", "")
    name = name_map.get(iid, "(unknown)")
    if len(name) > 28:
        name = name[:28] + ".."
    ping = inst.get("PingStatus", "Unknown")
    platform = inst.get("PlatformName", "Unknown")
    if len(platform) > 13:
        platform = platform[:13] + ".."
    agent = inst.get("AgentVersion", "Unknown")

    if ping == "Online":
        online += 1
    else:
        offline += 1

    print("{:<22} {:<30} {:<12} {:<15} {:<15}".format(
        iid, name, ping, platform, agent))

print(f"\n  Online: {online} | Offline: {offline}")

# Section 2: Patch Compliance
print()
print("=" * 70)
print(f"2. PATCH COMPLIANCE — {len(patch_map)} instance(s) with patch data")
print("=" * 70)
print()

if not patch_map:
    print("  No patch compliance data available.")
    print("  Patch Manager may not be configured or no scan has been run.")
else:
    compliant = []
    non_compliant = []
    no_data = []

    for iid, ps in patch_map.items():
        name = name_map.get(iid, "(unknown)")
        missing = ps.get("MissingCount", 0)
        failed = ps.get("FailedCount", 0)
        installed = ps.get("InstalledCount", 0)
        pending = ps.get("InstalledPendingRebootCount", 0)
        rejected = ps.get("InstalledRejectedCount", 0)
        other = ps.get("InstalledOtherCount", 0)
        op_date = ps.get("OperationDate", "Never")
        operation = ps.get("Operation", "Unknown")

        entry = {
            "id": iid,
            "name": name,
            "missing": missing,
            "failed": failed,
            "installed": installed,
            "pending_reboot": pending,
            "rejected": rejected,
            "other": other,
            "op_date": str(op_date),
            "operation": operation,
        }

        if missing > 0 or failed > 0:
            non_compliant.append(entry)
        else:
            compliant.append(entry)

    if non_compliant:
        print("  ** NON-COMPLIANT INSTANCES (missing or failed patches) **")
        print()
        for e in sorted(non_compliant, key=lambda x: x["missing"], reverse=True):
            print(f"  {e['id']}  {e['name']}")
            print(f"    Missing: {e['missing']}  |  Failed: {e['failed']}  |  Installed: {e['installed']}")
            print(f"    Pending Reboot: {e['pending_reboot']}  |  Rejected: {e['rejected']}")
            print(f"    Last Scan: {e['op_date']}  ({e['operation']})")
            print()

    if compliant:
        print(f"  COMPLIANT INSTANCES ({len(compliant)}):")
        print()
        for e in compliant:
            print(f"  {e['id']}  {e['name']}")
            print(f"    Installed: {e['installed']}  |  Pending Reboot: {e['pending_reboot']}")
            print(f"    Last Scan: {e['op_date']}")
            print()

# Section 3: Instances without SSM (no visibility)
print()
print("=" * 70)
print("3. EC2 INSTANCES WITHOUT SSM AGENT")
print("=" * 70)
print()

ssm_ids = set(inst.get("InstanceId", "") for inst in managed)
all_instances = []
if ec2_data:
    for res in ec2_data.get("Reservations", []):
        for inst in res.get("Instances", []):
            if inst.get("State", {}).get("Name") in ("running", "stopped"):
                all_instances.append(inst["InstanceId"])

unmanaged = [iid for iid in all_instances if iid not in ssm_ids]

if unmanaged:
    print(f"  {len(unmanaged)} instance(s) have NO SSM agent — no patch visibility:")
    print()
    for iid in unmanaged:
        name = name_map.get(iid, "(unknown)")
        print(f"    {iid}  {name}")
    print()
    print("  ** These instances cannot be assessed for patch compliance **")
else:
    print("  All running/stopped instances have SSM agents.")

# Section 4: Check for Inspector findings
print()
print("=" * 70)
print("4. AWS INSPECTOR VULNERABILITY FINDINGS")
print("=" * 70)
print()

findings, ferr = run_aws(["inspector2", "list-findings",
    "--filter-criteria", json.dumps({
        "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]
    }),
    "--max-results", "25"])

if ferr:
    if "not enabled" in str(ferr).lower() or "AccessDeniedException" in str(ferr):
        print("  Inspector is NOT enabled in this account/region.")
    else:
        print(f"  Could not query Inspector: {str(ferr).strip()[:200]}")
else:
    inspector_findings = findings.get("findings", [])
    if not inspector_findings:
        print("  No package vulnerability findings from Inspector.")
    else:
        print(f"  Found {len(inspector_findings)} vulnerability finding(s) (showing up to 25):")
        print()

        # Group by severity
        by_severity = {}
        for f in inspector_findings:
            sev = f.get("severity", "UNKNOWN")
            by_severity.setdefault(sev, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
            if sev not in by_severity:
                continue
            print(f"  [{sev}] — {len(by_severity[sev])} finding(s)")
            for f in by_severity[sev][:5]:
                title = f.get("title", "N/A")
                if len(title) > 80:
                    title = title[:80] + "..."
                resource = ""
                for r in f.get("resources", []):
                    resource = r.get("id", "")
                print(f"    {title}")
                print(f"      Resource: {resource}")
            if len(by_severity[sev]) > 5:
                print(f"    ... and {len(by_severity[sev]) - 5} more {sev}")
            print()

# Summary
print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total EC2 instances (running/stopped): {len(all_instances)}")
print(f"  SSM managed:                           {len(managed)}")
print(f"  Without SSM (no visibility):           {len(unmanaged)}")
if patch_map:
    nc = len([p for p in patch_map.values() if p.get("MissingCount", 0) > 0 or p.get("FailedCount", 0) > 0])
    total_missing = sum(p.get("MissingCount", 0) for p in patch_map.values())
    print(f"  Patch data available:                  {len(patch_map)}")
    print(f"  Non-compliant instances:               {nc}")
    print(f"  Total missing patches:                 {total_missing}")
else:
    print(f"  Patch data available:                  None")
print()
