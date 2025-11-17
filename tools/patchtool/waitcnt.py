#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

# Automatic WAITCNT patch generator.
# This script takes ROMs and tries to generate a patch that prevents games
# from updating the WAITCNT register.
#
# Using an emulator (ie. gpsp) to validate whether the patched games are
# actually correctly patched (by detecting the WAITCNT writes).
#
# Use pypy to run this, it's 20x faster than regular python :)

# Strategy:
#  - Look for the WAITCNT constant or some relevant move instruction.
#    - Look for a range of constants (ie. I/O reg space).
#    - Find ARM mov-imm instructions that mov I/O base addr.
#  - Go back N instructions, emulate the code.
#  - Track register values and detect stores to WAITCNT.
#  - Handle branching using backtracking and ABI convention for function calls.
#  - Mark the stores as patch sites, so they can be nop-ified.

import struct, hashlib
import patchtool.arm as arm

EMU_OFFSET     = 2048             # Some reasonable amount
EMU_OFFSET_THB = 2048             # Captures all thumb loads
EMU_OFFSET_ARM = 4096             # Captures all ARM loads
EMU_OFFSET_EX  =  512             # Some instructions after the pool value

ROM_ADDR = 0x08000000
EMU_STCK = 0x02008000             # Use some "reasonable" and plausible SP

TGT_ADDR = 0x04000204

# Four possible constants (4 bit rot + 8 bit constant)
MOVINST = frozenset([0x03A00301, 0x03A00404, 0x03A00510, 0x03A00640])
MOVMASK = 0x0FEF0FFF

# TODO: Move this to some config/set of files.
IGNORE_SEQS = [
  # Found in Mario Party
  b'\x04\x4b'   # ldr     r3, [pc, #16]
  b'\x00\x22'   # movs    r2, #0
  b'\x1a\x70'   # strb    r2, [r3, #0]
  b'\x30\x05'
  b'\xfa\x00'
  b'\x3b\x9d'
  b'\x46\x01'
  b'\xdf\x00'
  b'\xdf\x08'
  b'\x04\x02'   # constant pool (also executed!)
  b'\x00\x04',
]

# Find and clear certain sequences that even though they look like perfectly
# valid code, are actually data that should not be executed.
# This is pretty rare since the chances of it happening by chance are slim.
def clear_bad_seqs(romarr):
  for seq in IGNORE_SEQS:
    while True:
      r = romarr.find(seq)
      if r >= 0:
        romarr = romarr[:r] + (b'\xff' * len(seq)) + romarr[r+len(seq):]
      else:
        break
  return romarr

# Emulates a thumb code chunk and tries to find STR instructions
# that write the WAITCNT register
def emulate_thumb_insts(start, end, rom):
  # Reading ROM function (for PC rel loads)
  def readrom(addr):
    romaddr = (addr & 0x1FFFFFF)
    if romaddr + 4 <= len(rom):
      return struct.unpack("<I", rom[romaddr: romaddr+4])[0]
    return None
  cpust = arm.CPUState(EMU_STCK - 128)

  subrom = clear_bad_seqs(rom[start:end])
  ex = arm.InstExecutor(cpust, TGT_ADDR, TGT_ADDR, TGT_ADDR)
  for i in range(0, end - start, 2):
    op = struct.unpack("<H", subrom[i:i+2])[0]
    ex.addinst(arm.ThumbInst(ex, ROM_ADDR + start + i, op, readrom))

  return [(t, a - ROM_ADDR) for t, a in ex.execute()]


# Emulates an ARM code chunk and tries to find STR/H instructions
# that write the WAITCNT register.
def emulate_arm_insts(start, end, rom):
  # Reading ROM function (for PC rel loads)
  def readrom(addr):
    romaddr = (addr & 0x1FFFFFF)
    if romaddr + 4 <= len(rom):
      return struct.unpack("<I", rom[romaddr: romaddr+4])[0]
    return None
  cpust = arm.CPUState(EMU_STCK - 128)

  subrom = clear_bad_seqs(rom[start:end])
  ex = arm.InstExecutor(cpust, TGT_ADDR, TGT_ADDR, TGT_ADDR)
  for i in range(0, end - start, 4):
    op = struct.unpack("<I", subrom[i:i+4])[0]
    ex.addinst(arm.ARMInst(ex, ROM_ADDR + start + i, op, readrom))

  return [(t, a - ROM_ADDR) for t, a in ex.execute()]

def process_rom(rom, **kwargs):
  targets = []
  for i in range(0, len(rom) & ~3, 4):
    v = struct.unpack("<I", rom[i:i+4])[0]
    # Checks for a wide range of constants.
    if v >= 0x04000000 and v <= 0x04000208 and (v & 1) == 0:
      # Emulate some code before this pool constant
      # (also a bit after, since sometimes the value is used right after!)
      emustart_thb = max(0, i - EMU_OFFSET_THB)
      emustart_arm = max(0, i - EMU_OFFSET_ARM)
      emuend = min(i + EMU_OFFSET_EX, len(rom))
      # No idea what kind of code we found: assume thumb
      for str_type, str_off in emulate_thumb_insts(emustart_thb, emuend, rom):
        targets.append({
          "inst-type": "%s-thumb" % str_type,
          "inst-offset": hex(str_off),
        })
      # Do the same but with ARM code now
      for str_type, str_off in emulate_arm_insts(emustart_arm, emuend, rom):
        targets.append({
          "inst-type": "%s-arm" % str_type,
          "inst-offset": hex(str_off),
        })

    # Found a relevant arm move instruction (mov 0x04000000)
    if (v & MOVMASK) in MOVINST:
      # Emulate some insts before and after hoping to capture a write
      emustart = max(0, i - EMU_OFFSET // 2)
      emuend   = max(0, i + EMU_OFFSET // 2)
      for str_type, str_off in emulate_arm_insts(emustart, emuend, rom):
        targets.append({
          "inst-type": "%s-arm" % str_type,
          "inst-offset": hex(str_off),
        })

  # Dedup entries (happens with ARM code)
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


