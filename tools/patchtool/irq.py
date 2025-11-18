#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2025 David Guillen Fandos <david@davidgf.net>

# Automatic IRQ handler addres patch finder.
# This script takes ROMs and tries to find locations where a game patches
# the IRQ handler address (at 0x03007FFC).
#
# Use pypy to run this, it's 10x faster than regular python :)

# Strategy:
#  - Look for the magic constant 0x03007FFC (or some offseted version).
#  - Find the location that uses it, categorize it, emit a patch.
#  - Use the ARM emulator to find tricky code sequences (ie. ARM code)

import struct, hashlib
import patchtool.arm as arm

# Actual address to look for
TGT_ADDRESS = 0x03007FFC

# Some addresses that games might be using in their constant pool.
SUSPICIOUS_ADDRESSES = frozenset([0x03007FFC, 0x03007000, 0x03007FC0])

ROM_ADDR = 0x08000000
EMU_STCK = 0x02008000             # Use some "reasonable" and plausible SP

EMU_OFFSET     = 2048             # Some reasonable amount

# Four possible constants (4 bit rot + 8 bit constant)
MOVINST = frozenset([0x03A00403, 0x03A0050C, 0x03A00630, 0x03A007C0])
MOVMASK = 0x0FEF0FFF

def imatch(v, mask):
  hmsk = int("".join(["0" if c == "X" else "F" for c in mask]), 16)
  hval = int("".join(["0" if c == "X" else c   for c in mask]), 16)
  v = struct.unpack("<I", v)[0]
  return (v & hmsk) == hval

# Finds LDR rX, [pc+N] instructions pointing to address "addr".
# Returns a list of (offset, reg-number)
def find_thumb_ldr(rom, addr):
  ret = []
  saddr = max(0, addr - 2048)
  for i in range(saddr, addr, 2):
    opc = struct.unpack("<H", rom[i:i+2])[0]
    op, rn, off = (opc >> 11), ((opc >> 8) & 7), opc & 0xFF
    if op == 0x9:
      tgt_addr = (i & ~3) + off * 4 + 4
      if tgt_addr == addr:
        ret.append((i, rn))
  return ret

# Tries to match a sequence such as:
#  LDR rA, [pc+imm]   # Already matched
#  OP (optional) * N
#  STR rX, [rA+0]
# Returns the address of the matched store or None
def validate_thumb_ldr(rom, ldr_addr, regn, str_off, max_gap_size=8):
  # Find the matching STR
  for i in range(max_gap_size):
    iaddr = ldr_addr+(1+i) * 2
    opc = struct.unpack("<H", rom[iaddr : iaddr+2])[0]

    inst = arm.ThumbInst(None, None, opc, None)
    if inst.write_reg() == regn:
      return None    # The loaded register is no longer valid!

    op, rb, rv, off = (opc >> 11), (opc >> 3) & 7, opc & 7, (opc >> 6) & 0x1F
    if op == 0xC and rb == regn and off * 4 == str_off:
      return iaddr

  return None

# Finds LDR rX, [pc+N] instructions pointing to address "addr"
# Returns a list of (offset, register)
def find_arm_ldr(rom, addr):
  ret = []
  minaddr = max(addr - 4096, 0)
  maxaddr = min(addr + 4096, len(rom))
  for i in range(minaddr, maxaddr, 4):
    opc = struct.unpack("<I", rom[i:i+4])[0]
    cond, op, rn, rd, off = opc >> 28, (opc >> 20) & 0xFF, ((opc >> 16) & 0xF), ((opc >> 12) & 0xF), opc & 0xFFF

    if cond == 0xE and rn == 15:  # Match cond and base reg (PC)
      if op == 0x59:     # Check opcode (for imm sign)
        # LDR rd, [rn + imm] load instruction
        tgt_addr = (i + 8) + off
        if tgt_addr == addr:
          ret.append((i, rd))
      elif op == 0x51:
        # LDR rd, [rn - imm] load instruction
        tgt_addr = (i + 8) - off
        if tgt_addr == addr:
          ret.append((i, rd))

  return ret

# Tries to match a sequence such as:
#  LDR rA, [pc+imm]   # Already matched
#  OP * N
#  STR rX, [rA+0]
# Returns the address of the matched store or None
def validate_arm_ldr(rom, ldr_addr, regn, str_off, max_gap_size=8):
  # Contains a following instruction writing some reg (address)
  # and a store instruction using the base address.

  for i in range(max_gap_size):
    iaddr = ldr_addr+(1+i)*4
    opc = struct.unpack("<I", rom[iaddr : iaddr+4])[0]
    cond, op = opc >> 28, (opc >> 20) & 0xFF

    if cond != 0xE:
      return None    # conditional stuff, bail out

    inst = arm.ARMInst(None, None, opc, None)
    if inst.write_reg() == regn:
      return None    # The loaded register is no longer valid!

    # Check for a match
    if cond == 0xE:
      if op == 0x58:
        rn, rd, off = ((opc >> 16) & 0xF), ((opc >> 12) & 0xF), opc & 0xFFF
        if rn == regn and off == str_off:
          return iaddr
      elif op == 0x50:
        rn, rd, off = ((opc >> 16) & 0xF), ((opc >> 12) & 0xF), opc & 0xFFF
        if rn == regn and -off == str_off:
          return iaddr

  return None

# Emulates an ARM code chunk and tries to find STR instructions
# that write the TGT_ADDRESS address.
def emulate_arm_insts(start, end, rom):
  # Reading ROM function (for PC rel loads)
  def readrom(addr):
    romaddr = (addr & 0x1FFFFFF)
    if romaddr + 4 <= len(rom):
      return struct.unpack("<I", rom[romaddr: romaddr+4])[0]
    return None
  cpust = arm.CPUState(EMU_STCK - 128)

  subrom = rom[start:end]
  ex = arm.InstExecutor(cpust, None, None, TGT_ADDRESS)  # Only care about 32 bit writes
  for i in range(0, end - start, 4):
    op = struct.unpack("<I", subrom[i:i+4])[0]
    ex.addinst(arm.ARMInst(ex, ROM_ADDR + start + i, op, readrom))

  return [(t, a - ROM_ADDR) for t, a in ex.execute()]


# Some memclear sequences that we need to patch to avoid NULL clearing.
def check_patch_memclr1(rom, maxcheck=0x200):
  for i in range(0, maxcheck, 4):
    v = struct.unpack("<I", rom[i:i+4])[0]
    if v == 0x03008000:
      for off, _ in find_arm_ldr(rom, i):
        # Check for insts before/after
        if (imatch(rom[off- 4:off   ], "E3A0X403") and   # mov rX, 0x3000000
                                                         # ldr rX, [pc, #off]
            imatch(rom[off+ 4:off+ 8], "E3A0X000") and   # mov rX, 0
            imatch(rom[off+ 8:off+12], "E48XX004") and   # str rX, [rX], #4
            imatch(rom[off+12:off+16], "E15X000X") and   # cmp rX, rX
            imatch(rom[off+16:off+20], "XAXXXXXX")):     # bXX off
          # Found seq! Patch pool constant into 
          return [{
            "inst-type": "mem-clr-seq",
            "offset": hex(off+8),
            "patch-addr": hex(i),
            "patch-value": "0x03007FFC",
          }]
  return []

def check_patch_memclr2(rom, maxcheck=0x200):
  # Check insts sequence
  for off in range(0, maxcheck, 4):
    if (imatch(rom[off   :off+ 4], "E3A0X403") and   # mov rX, 0x3000000
        imatch(rom[off+ 4:off+ 8], "E3A0X902") and   # mov rX, 0x8000
        imatch(rom[off+ 8:off+12], "E3A0X000") and   # mov rX, 0
        imatch(rom[off+12:off+16], "E1CXX0B0") and   # strh rX, [rX]
        imatch(rom[off+16:off+20], "E28XX002") and   # add rX, rX, #2
        imatch(rom[off+20:off+24], "E25XX002")):     # subs rX, rX, #2
      # Found seq! Patch instruction
      pv = struct.unpack("<I", rom[off+ 4:off+ 8])[0]
      pv = (pv & 0xFFFFF000) | 0xC7F   # mov rX, 0x7F00 (max possible value)
      return [{
        "inst-type": "mem-clr-seq",
        "offset": hex(off+12),
        "patch-addr": hex(off+4),
        "patch-value": hex(pv),
      }]

    if (imatch(rom[off   :off+ 4], "E3A0X403") and   # mov rX, 0x3000000
        imatch(rom[off+ 4:off+ 8], "E3A0X000") and   # mov rX, 0
        imatch(rom[off+ 8:off+12], "E3A0X902") and   # mov rX, 0x8000
        imatch(rom[off+12:off+16], "E8AXXXXX") and   # stmia rX!, {rX}
        imatch(rom[off+16:off+20], "E25XX004") and   # subs rX, rX, #4
        imatch(rom[off+20:off+24], "XAXXXXXX")):     # bXX off
      # Found seq! Patch instruction
      pv = struct.unpack("<I", rom[off+8:off+12])[0]
      pv = (pv & 0xFFFFF000) | 0xC7F   # mov rX, 0x7F00 (max possible value)
      return [{
        "inst-type": "mem-clr-seq",
        "offset": hex(off+12),
        "patch-addr": hex(off+8),
        "patch-value": hex(pv),
      }]
  return []

def process_rom(rom, **kwargs):
  targets = []

  # Look for good known clear seqs (usually at the start of the ROM)
  targets += check_patch_memclr1(rom)
  targets += check_patch_memclr2(rom)

  for i in range(0, len(rom) & ~3, 4):
    v = struct.unpack("<I", rom[i:i+4])[0]
    # Find the address constant
    if v in SUSPICIOUS_ADDRESSES:
      str_off = TGT_ADDRESS - v
      # Find the load instruction that uses it. Match the relevant pattern.
      thumb_cand = find_thumb_ldr(rom, i)
      for addr, regn in thumb_cand:
        taddr = validate_thumb_ldr(rom, addr, regn, str_off)
        if taddr:
          if str_off != 0:
            # Patch the instruction offset only.
            opc = struct.unpack("<H", rom[taddr:taddr+2])[0]
            targets.append({
              "inst-type": "irq-thumb-str",
              "offset": hex(taddr),
              "inst-opcode": hex(opc),
            })
          else:
            targets.append({
              "inst-type": "irq-thumb-str",
              "offset": hex(taddr),
              "pool-addr": hex(i),
            })

      arm_cand = find_arm_ldr(rom, i)
      for addr, regn in arm_cand:
        taddr = validate_arm_ldr(rom, addr, regn, str_off)
        if taddr:
          if str_off != 0:
            opc = struct.unpack("<I", rom[taddr:taddr+4])[0]
            targets.append({
              "inst-type": "irq-arm-str",
              "offset": hex(taddr),
              "inst-opcode": hex(opc),
            })
          else:
            targets.append({
              "inst-type": "irq-arm-str",
              "offset": hex(taddr),
              "pool-addr": hex(i),
            })

  # Do this as a second pass, since we prefer patching pool addresses.
  for i in range(0, len(rom) & ~3, 4):
    v = struct.unpack("<I", rom[i:i+4])[0]
    # Found a relevant arm move instruction (mov 0x04000000)
    if (v & MOVMASK) in MOVINST:
      # Emulate some insts before and after hoping to capture a write
      emustart = max(0, i - EMU_OFFSET // 2)
      emuend   = max(0, i + EMU_OFFSET // 2)
      for str_type, str_off in emulate_arm_insts(emustart, emuend, rom):
        if hex(str_off) not in [x["offset"] for x in targets]:
          opc = struct.unpack("<I", rom[str_off:str_off+4])[0]
          targets.append({
            "inst-type": "irq-arm-str",
            "offset": hex(str_off),
            "inst-opcode": hex(opc),
          })


  # Dedup entries (happens with ARM code)
  targets = sorted([dict(t) for t in {tuple(d.items()) for d in targets}], key=lambda x: x["offset"])

  if targets:
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
        "irqhdr": {
          "patch-sites": targets,
        }
      }
    })

