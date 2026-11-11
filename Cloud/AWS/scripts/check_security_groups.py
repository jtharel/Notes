import json, subprocess, os

PROFILE = "XXXXXXXXXXX"

os.makedirs(PROFILE, exist_ok=True)

# Ports that are especially dangerous when open to the internet
HIGH_RISK_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def run_aws(args):
    cmd = ["aws"] + args + ["--profile", PROFILE, "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout) if result.stdout.strip() else None


def format_port_range(perm):
    proto = perm.get("IpProtocol", "")
    if proto == "-1":
        return "ALL TRAFFIC"
    from_port = perm.get("FromPort", 0)
    to_port = perm.get("ToPort", 0)
    proto_name = proto.upper()
    if from_port == to_port:
        label = HIGH_RISK_PORTS.get(from_port, "")
        port_str = f"{from_port}/{proto_name}"
        if label:
            port_str += f" ({label})"
        return port_str
    elif from_port == 0 and to_port == 65535:
        return f"ALL PORTS/{proto_name}"
    else:
        return f"{from_port}-{to_port}/{proto_name}"


def get_risk_level(perm):
    proto = perm.get("IpProtocol", "")
    from_port = perm.get("FromPort", 0)
    to_port = perm.get("ToPort", 0)

    if proto == "-1":
        return "CRITICAL"
    if from_port == 0 and to_port == 65535:
        return "CRITICAL"
    for port in range(from_port, to_port + 1):
        if port in HIGH_RISK_PORTS:
            return "HIGH"
    return "MEDIUM"


print("=" * 70)
print(f"SECURITY GROUP AUDIT - {PROFILE}")
print("=" * 70)

print("\n[*] Getting security groups...")
data = run_aws(["ec2", "describe-security-groups"])

if not data:
    print("  ERROR: Could not retrieve security groups.")
    exit(1)

groups = data.get("SecurityGroups", [])
print(f"  Found {len(groups)} security group(s)")

# Analyze each group for public inbound rules
findings = []

for sg in groups:
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", "")
    vpc_id = sg.get("VpcId", "N/A")

    for perm in sg.get("IpPermissions", []):
        # Check for 0.0.0.0/0
        for ip_range in perm.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                findings.append({
                    "sg_id": sg_id,
                    "sg_name": sg_name,
                    "vpc_id": vpc_id,
                    "source": "0.0.0.0/0",
                    "port": format_port_range(perm),
                    "risk": get_risk_level(perm),
                    "description": ip_range.get("Description", ""),
                })

        # Check for ::/0
        for ip_range in perm.get("Ipv6Ranges", []):
            if ip_range.get("CidrIpv6") == "::/0":
                findings.append({
                    "sg_id": sg_id,
                    "sg_name": sg_name,
                    "vpc_id": vpc_id,
                    "source": "::/0",
                    "port": format_port_range(perm),
                    "risk": get_risk_level(perm),
                    "description": ip_range.get("Description", ""),
                })

# Sort by risk
risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
findings.sort(key=lambda x: risk_order.get(x["risk"], 99))

# Report
print()
print("=" * 70)
print(f"SECURITY GROUPS WITH UNRESTRICTED INBOUND RULES — {len(findings)} rule(s)")
print("=" * 70)
print()

if not findings:
    print("  No security groups with 0.0.0.0/0 or ::/0 inbound rules found.")
else:
    # Group by risk level
    for risk_level in ["CRITICAL", "HIGH", "MEDIUM"]:
        level_findings = [f for f in findings if f["risk"] == risk_level]
        if not level_findings:
            continue

        print(f"  [{risk_level}] — {len(level_findings)} rule(s)")
        print()

        # Group by security group
        by_sg = {}
        for f in level_findings:
            key = f["sg_id"]
            by_sg.setdefault(key, []).append(f)

        for sg_id, sg_findings in by_sg.items():
            sg_name = sg_findings[0]["sg_name"]
            vpc_id = sg_findings[0]["vpc_id"]
            print(f"    {sg_id}  ({sg_name})")
            print(f"      VPC: {vpc_id}")
            for f in sg_findings:
                desc = f"  — {f['description']}" if f["description"] else ""
                print(f"      {f['source']}  →  {f['port']}{desc}")
            print()

# Check which instances use these security groups
if findings:
    print()
    print("=" * 70)
    print("INSTANCES USING OPEN SECURITY GROUPS")
    print("=" * 70)
    print()

    open_sg_ids = set(f["sg_id"] for f in findings)

    ec2_data = run_aws(["ec2", "describe-instances"])
    if ec2_data:
        for res in ec2_data.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") not in ("running", "stopped"):
                    continue
                iid = inst["InstanceId"]
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                name = tags.get("Name", "(no name)")
                inst_sgs = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                matched = [sg for sg in inst_sgs if sg in open_sg_ids]
                if matched:
                    print(f"  {iid}  {name}")
                    print(f"    State: {inst.get('State', {}).get('Name')}")
                    print(f"    Public IP: {inst.get('PublicIpAddress', 'None')}")
                    for sg in matched:
                        sg_rules = [f for f in findings if f["sg_id"] == sg]
                        for r in sg_rules:
                            print(f"    >> {sg} — {r['source']} → {r['port']} [{r['risk']}]")
                    print()

# Summary
unique_sgs = set(f["sg_id"] for f in findings)
critical = len([f for f in findings if f["risk"] == "CRITICAL"])
high = len([f for f in findings if f["risk"] == "HIGH"])
medium = len([f for f in findings if f["risk"] == "MEDIUM"])

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total security groups:           {len(groups)}")
print(f"  Groups with public rules:        {len(unique_sgs)}")
print(f"  Total open rules:                {len(findings)}")
print(f"    Critical (all traffic/ports):   {critical}")
print(f"    High (sensitive ports):         {high}")
print(f"    Medium (other ports):           {medium}")
print()
