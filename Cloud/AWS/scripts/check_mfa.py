import json, subprocess, base64, csv, io, os

PROFILE = "XXXXXXXXXX"

# Create output directory
os.makedirs(PROFILE, exist_ok=True)

print("=" * 70)
print(f"MFA STATUS AUDIT - {PROFILE}")
print("=" * 70)

print("\n[*] Generating credential report...")
subprocess.run(
    ["aws", "iam", "generate-credential-report", "--profile", PROFILE],
    capture_output=True
)

import time
time.sleep(5)

print("[*] Downloading credential report...")
result = subprocess.run(
    ["aws", "iam", "get-credential-report", "--profile", PROFILE, "--output", "json"],
    capture_output=True, text=True
)

data = json.loads(result.stdout)
raw_b64 = data["Content"]

# Save raw report
with open(os.path.join(PROFILE, "mfa_report_b64.txt"), "w") as f:
    f.write(raw_b64)

# Decode and parse
decoded = base64.b64decode(raw_b64).decode()
rows = list(csv.DictReader(io.StringIO(decoded)))

# Save decoded CSV
with open(os.path.join(PROFILE, "credential_report.csv"), "w") as f:
    f.write(decoded)

print()
print("{:<35} {:<12} {:<18} {:<14} {:<14}".format("User", "MFA", "Password", "Key 1", "Key 2"))
print("-" * 93)
for r in rows:
    print("{:<35} {:<12} {:<18} {:<14} {:<14}".format(
        r["user"],
        r["mfa_active"],
        r.get("password_enabled", "N/A"),
        r.get("access_key_1_active", "N/A"),
        r.get("access_key_2_active", "N/A")
    ))

print()
print("=" * 70)
print(f"Done. Output saved to {PROFILE}\\")
print("=" * 70)
                  
