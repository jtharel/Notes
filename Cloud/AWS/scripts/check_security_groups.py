import json, subprocess, os

PROFILE = "XXXXXXXXXXXX"

os.makedirs(PROFILE, exist_ok=True)

# Known port labels for readability
KNOWN_PORTS = {
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
        label = KNOWN_PORTS.get(from_port, "")
        port_str = f"{from_port}/{proto_name}"
        if label:
            port_str += f" ({label})"
        return port_str
    elif from_port == 0 and to_port == 65535:
        return f"ALL PORTS/{proto_name}"
    else:
        return f"{from_port}-{to_port}/{proto_name}"


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
                    "description": ip_range.get("Description", ""),
                })

# Report
print()
print("=" * 70)
print(f"SECURITY GROUPS WITH UNRESTRICTED INBOUND RULES — {len(findings)} rule(s)")
print("=" * 70)
print()

if not findings:
    print("  No security groups with 0.0.0.0/0 or ::/0 inbound rules found.")
else:
    # Group by security group
    by_sg = {}
    for f in findings:
        by_sg.setdefault(f["sg_id"], []).append(f)

    for sg_id, sg_findings in by_sg.items():
        sg_name = sg_findings[0]["sg_name"]
        vpc_id = sg_findings[0]["vpc_id"]
        print(f"  {sg_id}  ({sg_name})")
        print(f"    VPC: {vpc_id}")
        for f in sg_findings:
            desc = f"  — {f['description']}" if f["description"] else ""
            print(f"    {f['source']}  →  {f['port']}{desc}")
        print()

# Check which resources use these security groups
if findings:
    open_sg_ids = set(f["sg_id"] for f in findings)
    found_any = False

    # EC2 Instances
    print()
    print("=" * 70)
    print("EC2 INSTANCES USING OPEN SECURITY GROUPS")
    print("=" * 70)
    print()

    ec2_data = run_aws(["ec2", "describe-instances"])
    found_ec2 = False
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
                    found_ec2 = True
                    found_any = True
                    print(f"  {iid}  {name}")
                    print(f"    State: {inst.get('State', {}).get('Name')}")
                    print(f"    Public IP: {inst.get('PublicIpAddress', 'None')}")
                    for sg in matched:
                        sg_rules = [f for f in findings if f["sg_id"] == sg]
                        for r in sg_rules:
                            print(f"    >> {sg} — {r['source']} → {r['port']}")
                    print()
    if not found_ec2:
        print("  None")

    # Load Balancers (ALB/NLB - ELBv2)
    print()
    print("=" * 70)
    print("LOAD BALANCERS USING OPEN SECURITY GROUPS")
    print("=" * 70)
    print()

    found_lb = False
    lbs = run_aws(["elbv2", "describe-load-balancers"])
    if lbs:
        for lb in lbs.get("LoadBalancers", []):
            lb_sgs = lb.get("SecurityGroups", [])
            matched = [sg for sg in lb_sgs if sg in open_sg_ids]
            if matched:
                found_lb = True
                found_any = True
                lb_name = lb.get("LoadBalancerName", "unnamed")
                lb_type = lb.get("Type", "unknown")
                lb_scheme = lb.get("Scheme", "unknown")
                lb_dns = lb.get("DNSName", "N/A")
                print(f"  {lb_name}")
                print(f"    Type: {lb_type}  |  Scheme: {lb_scheme}")
                print(f"    DNS: {lb_dns}")
                print(f"    ARN: {lb.get('LoadBalancerArn', 'N/A')}")
                for sg in matched:
                    sg_rules = [f for f in findings if f["sg_id"] == sg]
                    for r in sg_rules:
                        print(f"    >> {sg} — {r['source']} → {r['port']}")
                print()
    if not found_lb:
        print("  None")

    # Classic Load Balancers (ELBv1)
    classic_lbs = run_aws(["elb", "describe-load-balancers"])
    if classic_lbs:
        for lb in classic_lbs.get("LoadBalancerDescriptions", []):
            lb_sgs = lb.get("SecurityGroups", [])
            matched = [sg for sg in lb_sgs if sg in open_sg_ids]
            if matched:
                found_lb = True
                found_any = True
                print(f"  [Classic] {lb.get('LoadBalancerName', 'unnamed')}")
                print(f"    DNS: {lb.get('DNSName', 'N/A')}")
                for sg in matched:
                    sg_rules = [f for f in findings if f["sg_id"] == sg]
                    for r in sg_rules:
                        print(f"    >> {sg} — {r['source']} → {r['port']}")
                print()

    # RDS Instances
    print()
    print("=" * 70)
    print("RDS INSTANCES USING OPEN SECURITY GROUPS")
    print("=" * 70)
    print()

    found_rds = False
    rds_data = run_aws(["rds", "describe-db-instances"])
    if rds_data:
        for db in rds_data.get("DBInstances", []):
            db_sgs = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
            matched = [sg for sg in db_sgs if sg in open_sg_ids]
            if matched:
                found_rds = True
                found_any = True
                print(f"  {db.get('DBInstanceIdentifier', 'unnamed')}")
                print(f"    Engine: {db.get('Engine', 'N/A')} {db.get('EngineVersion', '')}")
                print(f"    Endpoint: {db.get('Endpoint', {}).get('Address', 'N/A')}:{db.get('Endpoint', {}).get('Port', 'N/A')}")
                print(f"    Public: {db.get('PubliclyAccessible', False)}")
                for sg in matched:
                    sg_rules = [f for f in findings if f["sg_id"] == sg]
                    for r in sg_rules:
                        print(f"    >> {sg} — {r['source']} → {r['port']}")
                print()
    if not found_rds:
        print("  None")

    # ElastiCache
    print()
    print("=" * 70)
    print("ELASTICACHE USING OPEN SECURITY GROUPS")
    print("=" * 70)
    print()

    found_cache = False
    cache_data = run_aws(["elasticache", "describe-cache-clusters", "--show-cache-node-info"])
    if cache_data:
        for cluster in cache_data.get("CacheClusters", []):
            cache_sgs = [sg["SecurityGroupId"] for sg in cluster.get("SecurityGroups", [])]
            matched = [sg for sg in cache_sgs if sg in open_sg_ids]
            if matched:
                found_cache = True
                found_any = True
                print(f"  {cluster.get('CacheClusterId', 'unnamed')}")
                print(f"    Engine: {cluster.get('Engine', 'N/A')} {cluster.get('EngineVersion', '')}")
                for sg in matched:
                    sg_rules = [f for f in findings if f["sg_id"] == sg]
                    for r in sg_rules:
                        print(f"    >> {sg} — {r['source']} → {r['port']}")
                print()
    if not found_cache:
        print("  None")

# Summary
unique_sgs = set(f["sg_id"] for f in findings)

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total security groups:           {len(groups)}")
print(f"  Groups with public rules:        {len(unique_sgs)}")
print(f"  Total open rules:                {len(findings)}")
print()
