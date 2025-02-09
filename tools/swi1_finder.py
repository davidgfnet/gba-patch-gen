#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

# Automatic SWI-1 (WAITCNT) patch generator.
# This script takes ROMs and tries to find SWI 0x1 calls to the GBA BIOS
# that can potentially clear the WAITCNT register.
#
# Using an emulator (ie. gpsp) to validate whether the patched games are
# actually correctly patched (by detecting the WAITCNT writes).

# Strategy:
#  - Most ARM codepaths simply perform:
#     mov r0, constant
#     swi 0x00010000       -> emit this address for patching
#
#  - Thumb games are trickier but mostly follow this pattern:
#     mov r0, constant
#     bl routine
#     [...]
#    routine:
#     swi 0x1
#     bx lr
#
#    Instead of patching the SWI + BX instructions (4 bytes) we patch calls
#    to the subroutine, since we can simply patch the BL offset.
#    The patcher will be responible for providing a routine that performs SWI 1
#    without WAITCNT corruption. This can be tricky since Thumb's BL has only a
#    -/+4MB offset range, requiring some trampolines here or there.


import struct, hashlib

def ARM_SVC(n):
  return 0xef000000 | (n << 16)

def THUMB_SVC(n):
  return 0xdf00 | n

def process_rom(rom):
  targets = []

  # ARM mode operations: find the SVCs in ARM mode.
  for i in range(0, len(rom) & ~3, 4):
    v = struct.unpack("<I", rom[i:i+4])[0]
    if v == ARM_SVC(1):
      # Check that the previous opcode is a mov r0, cnt
      pv = struct.unpack("<I", rom[i-4:i])[0]
      if (pv & ~0xFF) == 0xe3a00000:
        # We ignore any SVC that doesn't set the MSB (doesnt clear WAITCNT)
        if (pv & 0x80) != 0:
          # Found a relevant sequence, emit an ARM patch
          targets.append({
            "inst-type": "swi1-arm",
            "inst-offset": hex(i),
          })

  # Thumb mode operations: find SVC + bx lr blocks.
  svc_candidates = set()
  for i in range(0, len(rom) & ~3, 2):
    v = struct.unpack("<H", rom[i:i+2])[0]
    if v == THUMB_SVC(1):
      # Check that the next opcode is a bx lr
      nv = struct.unpack("<H", rom[i+2:i+4])[0]
      if nv == 0x4770:
        svc_candidates.add(i)

  # Now find references to these candidate blocks in the form of
  # mov r0, cnt + bl offset, where offset points to the candidate block.
  for i in range(0, len(rom) & ~3, 2):
    v = struct.unpack("<H", rom[i:i+2])[0]
    # mov r0, cnt8 (where cnt8 has bit 7 set)
    if (v & 0xFF00) == 0x2000 and (v & 0x80) != 0:
      # Check the next two opcodes, BL-hi and lo
      blo, bhi = struct.unpack("<HH", rom[i+2:i+6])
      if (blo & 0xF800) == 0xF000 and (bhi & 0xF800) == 0xF800:
        # This is a BL, proceed to extract the offset now:
        off = ((blo & 0x7FF) << 12) | ((bhi & 0x7FF) << 1)
        if off & 0x00400000:
          off |= 0xFF800000
        tgt = (i + 2 + 4 + off) & 0xFFFFFFFF  # Target address
        if tgt in svc_candidates:
          # This is a relevant call that needs patching.
          targets.append({
            "inst-type": "swi1-bl-thumb",
            "inst-offset": hex(i + 2),        # patch the BL instruction!
          })

  # Dedup any entries
  targets = sorted([dict(t) for t in {tuple(d.items()) for d in targets}], key=lambda x: x["inst-offset"])
  # Extract ROM info, such as game code
  gcode = rom[0x0AC: 0x0B0].decode("ascii")
  grev = rom[0x0BC]
  return ({
    "filesize": len(rom),
    "sha256": hashlib.sha256(rom).hexdigest(),
    "sha1": hashlib.sha1(rom).hexdigest(),
    "md5": hashlib.md5(rom).hexdigest(),
    "game-code": gcode,
    "game-version": grev,
    "targets": {
      "waitcnt": {
        "patch-sites": targets,
      }
    }
  })

# For local use
if __name__ == "__main__":
  import os, sys, multiprocessing, tqdm, json

  flist = []
  for root, dirs, files in os.walk(sys.argv[1], topdown=False):
    for name in files:
      f = os.path.join(root, name)
      if f.endswith(".gba"):
        flist.append(f)

  def wrapper(f):
    finfo = {
      "filename": os.path.basename(f),
    }
    return finfo | process_rom(open(f, "rb").read())

  with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
    results = list(tqdm.tqdm(p.imap(wrapper, flist), total=len(flist)))

  # Filter out games without any matches.
  results = filter(lambda x: x["targets"]["waitcnt"]["patch-sites"], results)
  # Sort by filename, for proper diffing :)
  results = sorted(results, key=lambda x:x["filename"])

  print(json.dumps(results, indent=2))

