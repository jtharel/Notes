import zipfile, re, os, sys

# Directory containing the zip files
SCAN_DIR = sys.argv[1] if len(sys.argv) > 1 else "."

# Max file size to scan inside zip (skip large binaries)
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# File extensions to scan (skip images, compiled, etc.)
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs",
    ".sh", ".bash", ".ps1", ".bat", ".cmd",
    ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".tf", ".tfvars", ".hcl",
    ".txt", ".md", ".csv", ".html", ".htm",
    ".sql", ".dockerfile", ".config",
}

# Secret patterns
PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
    (r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}', 'AWS Secret Key'),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{4,}', 'Password'),
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[^\s"\']{8,}', 'API Key'),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?[^\s"\']{8,}', 'Secret Key'),
    (r'(?i)(access[_-]?key|access[_-]?token)\s*[=:]\s*["\']?[^\s"\']{8,}', 'Access Key/Token'),
    (r'(?i)(auth[_-]?token|bearer)\s*[=:]\s*["\']?[^\s"\']{8,}', 'Auth Token'),
    (r'(?i)(db[_-]?pass|database[_-]?password|mysql[_-]?pwd|rds[_-]?password)\s*[=:]\s*["\']?[^\s"\']{4,}', 'DB Credential'),
    (r'(?i)(private[_-]?key|priv[_-]?key)\s*[=:]\s*["\']?[^\s"\']{8,}', 'Private Key Reference'),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key Block'),
    (r'(?i)(connection[_-]?string|conn[_-]?str)\s*[=:]\s*["\']?[^\s"\']{10,}', 'Connection String'),
    (r'(?i)(smtp[_-]?pass|mail[_-]?password)\s*[=:]\s*["\']?[^\s"\']{4,}', 'SMTP Credential'),
    (r'(?i)mongodb(\+srv)?://\S+:\S+@', 'MongoDB Connection String'),
    (r'(?i)postgres://\S+:\S+@', 'PostgreSQL Connection String'),
    (r'(?i)mysql://\S+:\S+@', 'MySQL Connection String'),
    (r'(?i)redis://:\S+@', 'Redis Connection String'),
    (r'(?i)(slack[_-]?token|xox[bpars]-[0-9a-zA-Z-]+)', 'Slack Token'),
    (r'(?i)gh[pousr]_[0-9a-zA-Z]{36,}', 'GitHub Token'),
    (r'(?i)(sumo[_-]?logic|sumologic)\S*[=:]\s*["\']?[^\s"\']{8,}', 'Sumo Logic Key'),
    (r'(?i)export\s+(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|DB_PASSWORD)\s*=\s*\S+', 'Exported Secret'),
    (r'(?i)(client[_-]?secret)\s*[=:]\s*["\']?[^\s"\']{8,}', 'Client Secret'),
    (r'(?i)(encryption[_-]?key|encrypt[_-]?key|aes[_-]?key)\s*[=:]\s*["\']?[^\s"\']{8,}', 'Encryption Key'),
]

compiled = [(re.compile(p), label) for p, label in PATTERNS]


def should_scan(filename):
    _, ext = os.path.splitext(filename.lower())
    # Always scan files with no extension (could be .env, Dockerfile, etc.)
    if not ext:
        return True
    return ext in SCAN_EXTENSIONS


def scan_content(text, zip_name, inner_file):
    hits = []
    for line_num, line in enumerate(text.split('\n'), 1):
        for pattern, label in compiled:
            if pattern.search(line):
                line_preview = line.strip()
                if len(line_preview) > 150:
                    line_preview = line_preview[:150] + "..."
                hits.append({
                    "zip": zip_name,
                    "file": inner_file,
                    "line": line_num,
                    "type": label,
                    "content": line_preview,
                })
    return hits


# Main scan
all_findings = []
zips_scanned = 0
files_scanned = 0
errors = 0

zip_files = []
for root, dirs, files in os.walk(SCAN_DIR):
    for f in files:
        if f.lower().endswith(".zip"):
            zip_files.append(os.path.join(root, f))

print("=" * 70)
print("LAMBDA ZIP SECRET SCANNER")
print("=" * 70)
print(f"\n[*] Found {len(zip_files)} zip file(s) in {SCAN_DIR}")
print()

for zip_path in zip_files:
    zip_name = os.path.basename(zip_path)
    zips_scanned += 1
    sys.stdout.write(f"\r  Scanning [{zips_scanned}/{len(zip_files)}] {zip_name[:50]:<50}")
    sys.stdout.flush()

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_FILE_SIZE:
                    continue
                if not should_scan(info.filename):
                    continue

                files_scanned += 1
                try:
                    raw = zf.read(info.filename)
                    try:
                        text = raw.decode('utf-8', errors='replace')
                    except Exception:
                        continue

                    hits = scan_content(text, zip_name, info.filename)
                    all_findings.extend(hits)
                except Exception:
                    errors += 1
    except zipfile.BadZipFile:
        print(f"\n  WARNING: Bad zip file: {zip_name}")
        errors += 1
    except Exception as e:
        print(f"\n  ERROR: {zip_name}: {e}")
        errors += 1

print(f"\n\n[*] Done. Scanned {files_scanned} files across {zips_scanned} zips.\n")

# Report
if all_findings:
    # Group by zip
    by_zip = {}
    for f in all_findings:
        by_zip.setdefault(f["zip"], []).append(f)

    print("=" * 70)
    print(f"FINDINGS — {len(all_findings)} potential secret(s) in {len(by_zip)} zip(s)")
    print("=" * 70)
    print()

    for zip_name, findings in sorted(by_zip.items()):
        print(f"  {zip_name}")
        seen = set()
        for f in findings:
            key = (f["file"], f["type"], f["content"])
            if key in seen:
                continue
            seen.add(key)
            print(f"    [{f['type']}] {f['file']}:{f['line']}")
            print(f"      {f['content']}")
        print()
else:
    print("  No secrets found.")

# Summary
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Zip files scanned:    {zips_scanned}")
print(f"  Inner files scanned:  {files_scanned}")
print(f"  Potential secrets:    {len(all_findings)}")
print(f"  Errors:               {errors}")
if all_findings:
    types = {}
    for f in all_findings:
        types[f["type"]] = types.get(f["type"], 0) + 1
    print(f"\n  By type:")
    for t, count in sorted(types.items(), key=lambda x: -x[1]):
        print(f"    {t}: {count}")
print()
