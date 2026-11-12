from dissect.hypervisor.disk.vmdk import VMDK
from dissect.volume import disk
from dissect.ntfs import NTFS
import sys

vmdk_file = "XXXXXXXXX.vmdk"
cmd = sys.argv[1] if len(sys.argv) > 1 else "ls"
path = sys.argv[2] if len(sys.argv) > 2 else "/"

fh = open(vmdk_file, "rb")
vmdk = VMDK(fh)
d = disk.Disk(vmdk)

# Find the NTFS partition
ntfs = None
for part in d.partitions:
    try:
        vol = part.open()
        ntfs = NTFS(vol)
        # Test if it works
        _ = ntfs.mft.root
        print(f"Partition: offset={part.offset}, size={part.size}")
        break
    except Exception:
        continue

if ntfs is None:
    print("Could not find an NTFS partition. Listing all partitions:")
    for i, part in enumerate(d.partitions):
        print(f"  Partition {i}: offset={part.offset}, size={part.size}")
    exit(1)


def resolve(path):
    entry = ntfs.mft.root
    if path in ("", "/", "\\"):
        return entry
    parts = path.replace("\\", "/").strip("/").split("/")
    for p in parts:
        found = False
        for child in entry.listdir():
            if str(child).lower() == p.lower():
                entry = entry.get(str(child))
                found = True
                break
        if not found:
            return None
    return entry


def listdir(path):
    entry = resolve(path)
    if entry is None:
        print(f"  Path not found: {path}")
        return
    print(f"\n  Contents of: {path}\n")
    try:
        for child in entry.listdir():
            print(f"    {child}")
    except Exception as e:
        print(f"  Not a directory or error: {e}")


def cat(path):
    entry = resolve(path)
    if entry is None:
        print(f"  File not found: {path}")
        return
    try:
        data = entry.open().read()
        print(data.decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"  Cannot read: {e}")


def save(path, outfile):
    entry = resolve(path)
    if entry is None:
        print(f"  File not found: {path}")
        return
    try:
        data = entry.open().read()
        with open(outfile, "wb") as f:
            f.write(data)
        print(f"  Saved {len(data)} bytes to {outfile}")
    except Exception as e:
        print(f"  Cannot read: {e}")


if cmd == "ls":
    listdir(path)
elif cmd == "cat":
    cat(path)
elif cmd == "save" and len(sys.argv) > 3:
    save(path, sys.argv[3])
else:
    print("Usage:")
    print("  python browse_vmdk.py ls /")
    print("  python browse_vmdk.py cat /path/to/file")
    print("  python browse_vmdk.py save /path/to/file output.txt")
