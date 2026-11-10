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
print(f"SECURITY SERVICES AUDIT - {PROFILE}")
print("=" * 70)

# ============================================================
# 1. CloudTrail
# ============================================================
print("\n[*] Checking CloudTrail...")
trails, err = run_aws(["cloudtrail", "describe-trails"])

print()
print("=" * 70)
print("1. CLOUDTRAIL")
print("=" * 70)

if err:
    print(f"  ERROR: {err}")
elif not trails or not trails.get("trailList"):
    print("  ** NO TRAILS CONFIGURED ** — no audit logging")
else:
    for trail in trails["trailList"]:
        name = trail.get("Name", "unnamed")
        print(f"\n  Trail: {name}")
        print(f"    S3 Bucket:        {trail.get('S3BucketName', 'N/A')}")
        print(f"    Is Multi-Region:  {trail.get('IsMultiRegionTrail', False)}")
        print(f"    Log Validation:   {trail.get('LogFileValidationEnabled', False)}")
        print(f"    KMS Encrypted:    {'Yes' if trail.get('KmsKeyId') else 'No'}")
        print(f"    CloudWatch Logs:  {'Yes' if trail.get('CloudWatchLogsLogGroupArn') else 'No'}")

        # Check if trail is actually logging
        status, serr = run_aws(["cloudtrail", "get-trail-status", "--name", name])
        if status:
            print(f"    Is Logging:       {status.get('IsLogging', 'Unknown')}")
            print(f"    Latest Delivery:  {status.get('LatestDeliveryTime', 'Never')}")
        else:
            print(f"    Status: Could not retrieve ({serr})")

# ============================================================
# 2. Security Hub
# ============================================================
print()
print("\n[*] Checking Security Hub...")
hub, err = run_aws(["securityhub", "describe-hub"])

print()
print("=" * 70)
print("2. SECURITY HUB")
print("=" * 70)

if err:
    if "not subscribed" in str(err).lower() or "InvalidAccessException" in str(err):
        print("  ** NOT ENABLED ** — Security Hub is not active in this account/region")
    else:
        print(f"  ERROR: {err.strip()[:200]}")
else:
    print(f"  Status: ENABLED")
    print(f"  Hub ARN:            {hub.get('HubArn', 'N/A')}")
    print(f"  Subscribed At:      {hub.get('SubscribedAt', 'N/A')}")
    print(f"  Auto-Enable Controls: {hub.get('AutoEnableControls', 'N/A')}")

    # Check enabled standards
    standards, serr = run_aws(["securityhub", "get-enabled-standards"])
    if standards and standards.get("StandardsSubscriptions"):
        print(f"\n  Enabled Standards:")
        for s in standards["StandardsSubscriptions"]:
            print(f"    - {s.get('StandardsArn', 'N/A')}")
            print(f"      Status: {s.get('StandardsStatus', 'N/A')}")
    else:
        print("  No standards enabled")

# ============================================================
# 3. AWS Config
# ============================================================
print()
print("\n[*] Checking AWS Config...")
recorders, err = run_aws(["configservice", "describe-configuration-recorders"])

print()
print("=" * 70)
print("3. AWS CONFIG")
print("=" * 70)

if err:
    print(f"  ERROR: {err.strip()[:200]}")
elif not recorders or not recorders.get("ConfigurationRecorders"):
    print("  ** NOT CONFIGURED ** — no configuration recorders found")
else:
    for rec in recorders["ConfigurationRecorders"]:
        name = rec.get("name", "unnamed")
        print(f"\n  Recorder: {name}")
        print(f"    Role ARN:         {rec.get('roleARN', 'N/A')}")
        group = rec.get("recordingGroup", {})
        print(f"    All Resources:    {group.get('allSupported', False)}")
        print(f"    Include Global:   {group.get('includeGlobalResourceTypes', False)}")

    # Check recorder status
    rec_status, serr = run_aws(["configservice", "describe-configuration-recorder-status"])
    if rec_status and rec_status.get("ConfigurationRecordersStatus"):
        for rs in rec_status["ConfigurationRecordersStatus"]:
            print(f"\n    Recording:        {rs.get('recording', False)}")
            print(f"    Last Status:      {rs.get('lastStatus', 'N/A')}")

    # Check delivery channels
    channels, cerr = run_aws(["configservice", "describe-delivery-channels"])
    if channels and channels.get("DeliveryChannels"):
        for ch in channels["DeliveryChannels"]:
            print(f"\n  Delivery Channel: {ch.get('name', 'unnamed')}")
            print(f"    S3 Bucket:        {ch.get('s3BucketName', 'N/A')}")
            print(f"    SNS Topic:        {ch.get('snsTopicARN', 'None')}")

    # Check config rules
    rules, rerr = run_aws(["configservice", "describe-config-rules"])
    if rules and rules.get("ConfigRules"):
        print(f"\n  Config Rules: {len(rules['ConfigRules'])} active")
        for rule in rules["ConfigRules"][:10]:
            print(f"    - {rule.get('ConfigRuleName', 'N/A')} [{rule.get('ConfigRuleState', 'N/A')}]")
        if len(rules["ConfigRules"]) > 10:
            print(f"    ... and {len(rules['ConfigRules']) - 10} more")
    else:
        print("  No Config rules defined")

# Summary
print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
ct_active = trails and any(True for t in trails.get("trailList", []))
sh_active = hub and not err
cfg_active = recorders and bool(recorders.get("ConfigurationRecorders"))
print(f"  CloudTrail:    {'ACTIVE' if ct_active else 'NOT CONFIGURED'}")
print(f"  Security Hub:  {'ACTIVE' if sh_active else 'NOT ENABLED'}")
print(f"  AWS Config:    {'ACTIVE' if cfg_active else 'NOT CONFIGURED'}")
print()
