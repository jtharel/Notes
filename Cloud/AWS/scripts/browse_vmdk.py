from dissect.hypervisor.disk.vmdk import VMDK
from dissect.volume import disk
import sys

vmdk_file = "XXXXXXX.vmdk"
cmd = sys.argv[1] if len(sys.argv) > 1 else "ls"
path = sys.argv[2] if len(sys.argv) > 2 else "/"

fh = open(vmdk_file, "rb")
vmdk = VMDK(fh)
d = disk.Disk(vmdk)

# Try to detect filesystem type on each partition
fs = None
fs_type = None

for i, part in enumerate(d.partitions):
    vol = part.open()

    # Try NTFS
    try:
        from dissect.ntfs import NTFS
        ntfs = NTFS(vol)
        _ = ntfs.mft.root
        fs = ntfs
        fs_type = "NTFS"
        print(f"Found NTFS partition {i}: offset={part.offset}, size={part.size}")
        break
    except Exception:
        pass

    # Reset volume position
    vol.seek(0)

    # Try ext4
    try:
        from dissect.extfs import ExtFS
        extfs = ExtFS(vol)
        _ = extfs.root
        fs = extfs
        fs_type = "ext4"
        print(f"Found ext4 partition {i}: offset={part.offset}, size={part.size}")
        break
    except Exception:
        pass

if fs is None:
    print("Could not find an NTFS or ext4 partition. Listing all partitions:")
    for i, part in enumerate(d.partitions):
        print(f"  Partition {i}: offset={part.offset}, size={part.size}")
    exit(1)


def get_root():
    if fs_type == "NTFS":
        return fs.mft.root
    else:
        return fs.root


def resolve(path):
    entry = get_root()
    if path in ("", "/", "\\"):
        return entry
    parts = path.replace("\\", "/").strip("/").split("/")
    for p in parts:
        found = False
        if fs_type == "NTFS":
            for child in entry.listdir():
                if str(child).lower() == p.lower():
                    entry = entry.get(str(child))
                    found = True
                    break
        else:
            for item in entry.listdir():
                try:
                    name, child_entry = item
                except (TypeError, ValueError):
                    name = str(item)
                    child_entry = None
                if name.lower() == p.lower():
                    if child_entry is not None:
                        entry = child_entry
                    else:
                        entry = fs.get(name, entry)
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
    print(f"\n  Contents of: {path}  [{fs_type}]\n")
    try:
        if fs_type == "NTFS":
            for child in entry.listdir():
                print(f"    {child}")
        else:
            for item in entry.listdir():
                if hasattr(item, '__iter__') and not isinstance(item, str) and len(item) == 2:
                    name, _ = item
                else:
                    name = str(item)
                print(f"    {name}")
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
