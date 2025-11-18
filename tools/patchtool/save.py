#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2025 David Guillen Fandos <david@davidgf.net>

# Automatic savetype detector and patch-site generator.
# This script takes ROMs and tries to detect the save type they use (SRAM,
# EEPROM or FLASH) and locate relevant interface routines for them.
# It outputs a type and some offsets where the ROMs should be patched.
# No patches are exported for SRAM (since it requires no patching).
#
# Detection works using some strings present in most games.
# Patching works by detecting some known instruction sequences (seems like
# most games use the same libraries) and some known data structures.
#
# Use pypy to run this, it's 20x faster than regular python :)

import sys, struct, re, hashlib

# Using the longest common function start/prologue to avoid false positives

# Packs an instruction sequence into a regex
def packinsts(seq):
  return re.compile(b"".join(b".." if x is None else b"\\x%02x\\x%02x" % (x & 0xFF, x >> 8) for x in seq))

eeprom_v111_readfn = packinsts([
  0xb5b0,   # push    {r4, r5, r7, lr}
  0xb0aa,   # sub     sp, #168
  0x466f,   # mov     r7, sp
  0x6079,   # str     r1, [r7, #4]
  0x1c39,   # adds    r1, r7, #0
  0x8008,   # strh    r0, [r1, #0]
  0x1c38,   # adds    r0, r7, #0
  0x8801,   # ldrh    r1, [r0, #0]
  0x293f,   # cmp     r1, #63 @ 0x3f
  0xd903,   # bls.n   0x48650
  0x4800,   # ldr     r0, [pc, #0]
])   # The function is ~160 instruction long, plenty of room!

# This version adds address sanitization
eeprom_v12x_readfn = packinsts([
  0xb570,   # push    {r4, r5, r6, lr}
  0xb0a2,   # sub     sp, #136
  0x1c0d,   # adds    r5, r1, #0
  0x0400,   # lsls    r0, r0, #16
  0x0c03,   # lsrs    r3, r0, #16
  0x4803,   # ldr     r0, [pc, #12]
  0x6800,   # ldr     r0, [r0, #0]
  0x8880,   # ldrh    r0, [r0, #4]
  0x4283,   # cmp     r3, r0
  0xd305,   # bcc.n
  0x4801,   # ldr     r0, [pc, #4]
])  # Around 80 instructions in the function?

# Write functions come in a bunch of flavours, but essentially the same
eeprom_v111_writefn = packinsts([
  0xb580,   # push    {r7, lr}
  0xb0aa,   # sub     sp, #168
  0x466f,   # mov     r7, sp
  0x6079,   # str     r1, [r7, #4]
  0x1c39,   # adds    r1, r7, #0
  0x8008,   # strh    r0, [r1, #0]
  0x1c38,   # adds    r0, r7, #0
  0x8801,   # ldrh    r1, [r0, #0]
  0x293f,   # cmp     r1, #63
])
eeprom_v12_012_writefn = packinsts([
  0xb530,   # push    {r4, r5, lr}
  0xb0a9,   # sub     sp, #164
  0x1c0d,   # adds    r5, r1, #0
  0x0400,   # lsls    r0, r0, #16
  0x0c04,   # lsrs    r4, r0, #16
  0x4803,   # ldr     r0, [pc, #12]
  0x6800,   # ldr     r0, [r0, #0]
  0x8880,   # ldrh    r0, [r0, #4]
  0x4284,   # cmp     r4, r0
])
eeprom_v12_45_writefn = packinsts([
  0xb5f0,   # push    {r4, r5, r6, r7, lr}
  0xb0ac,   # sub     sp, #176
  0x1c0d,   # adds    r5, r1, #0
  0x0400,   # lsls    r0, r0, #16
  0x0c01,   # lsrs    r1, r0, #16
  0x0612,   # lsls    r2, r2, #24
  0x0e17,   # lsrs    r7, r2, #24
  0x4803,   # ldr     r0, [pc, #12]
  0x6800,   # ldr     r0, [r0, #0]
  0x8880,   # ldrh    r0, [r0, #4]
  0x4281,   # cmp     r1, r0
])
eeprom_v126_writefn = packinsts([
  0xb5f0,   # push    {r4, r5, r6, r7, lr}
  0x4647,   # mov     r7, r8
  0xb480,   # push    {r7}
  0xb0ac,   # sub     sp, #176
  0x1c0e,   # adds    r6, r1, #0
  0x0400,   # lsls    r0, r0, #16
  0x0c05,   # lsrs    r5, r0, #16
  0x0612,   # lsls    r2, r2, #24
  0x0e12,   # lsrs    r2, r2, #24
  0x4690,   # mov     r8, r2
  0x4803,   # ldr     r0, [pc, #12]
  0x6800,   # ldr     r0, [r0, #0]
  0x8880,   # ldrh    r0, [r0, #4]
  0x4285,   # cmp     r5, r0
])


# Functions that run the ID flow (using the 0x90 command), they return a 16 dev:man value
flash_identfn_v1 = packinsts([
  0xb590,          # push  {r4, r7, lr}
  0xb093,          # sub   sp, #0x4c
  0x466f,          # mov   r7, sp
  0x1d39,          # adds  r1, r7, #4
  0x1c08,          # adds  r0, r1, #0
  0xf000, None,    # bl    off
  0x1d38,          # adds  r0, r7, #4
])
flash_identfn_v2 = packinsts([
  0xb530,          # push  {r4, r5, lr}
  0xb091,          # sub   sp, #0x44
  0x4668,          # mov   r0, sp
  0xf000, None,    # bl    off
  0x466d,          # mov   r5, sp
  0x3501,          # adds  r5, #1
  0x4a06,          # ldr   r2, [pc, #24]
])
# Read handlers, they read at a given offset/page into a buffer
flash_v1_read = packinsts([
  0xb590,          # push  {r4, r7, lr}
  0xb0a9,          # sub   sp, #0xa4
  0x466f,          # mov   r7, sp
  0x6079,          # str   r1, [r7, #4]
  0x60ba,          # str   r2, [r7, #8]
  0x60fb,          # str   r3, [r7, #12]
  0x1c39,          # adds  r1, r7, #0
  0x8008,          # strh  r0, [r1, #0]
])
flash_v2_read = packinsts([
  0xb5f0,          # push  {r4, r5, r6, r7, lr}
  0xb0a0,          # sub   sp, #0x80
  0x1c0d,          # adds  r5, r1, #0
  0x1c16,          # adds  r6, r2, #0
  0x1c1f,          # adds  r7, r3, #0
  0x0400,          # lsls  r0, r0, #16
  0x0c04,          # lsrs  r4, r0, #16
  0x4a08,          # ldr   r2, [pc, #32]
  0x8810,          # ldrh  r0, [r2, #0]
  0x4908,          # ldr   r1, [pc, #32]
  0x4008,          # ands  r0, r1
  0x2103,          # movs  r1, #3
  0x4308,          # orrs  r0, r1
])
flash_v3_read = packinsts([
  0xb5f0,          # push {r4, r5, r6, r7, lr}
  0xb0a0,          # sub  sp, #0x80
  0x1c0d,          # adds r5, r1, #0
  0x1c16,          # adds r6, r2, #0
  0x1c1f,          # adds r7, r3, #0
  0x0403,          # lsls r3, r0, #0x10
  0x0c1c,          # lsrs r4, r3, #0x10
  0x4a0f,          # ldr  r2, [pc, #0x3c]
  0x8810,          # ldrh r0, [r2]
  0x490f,          # ldr  r1, [pc, #0x3c]
  0x4008,          # ands r0, r1
])

flash_v3_verify = packinsts([
  0xb530,          # push {r4, r5, lr}
  0xb0c0,          # sub sp, #256
  0x1c0d,          # adds r5, r1, #0
  0x0403,          # lsls r3, r0, #16
  0x0c1c,          # lsrs r4, r3, #16
  None,            # ldr  r2, [pc, #X]
  0x8810,          # ldrh r0, [r2, #0]
  None,            # ldr  r1, [pc, #X]
  0x4008,          # ands r0, r1
  0x2103,          # movs r1, #3
  0x4308,          # orrs r0, r1
  0x8010,          # strh r0, [r2, #0]
  None,            # ldr  r0, [pc, #X]
  0x6800,          # ldr  r0, [r0, #0]
  0x6801,          # ldr  r1, [r0, #0]
  0x2080,          # movs r0, #128
  0x0280,          # lsls r0, r0, #10
  0x4281,          # cmp  r1, r0
  None,            # bne.n OFF
  0x0d18,          # lsrs r0, r3, #20
  0x0600,          # lsls r0, r0, #24
  0x0e00,          # lsrs r0, r0, #24
])
flash_v2_verify = packinsts([
  0xb530,          # push {r4, r5, lr}
  0xb0c0,          # sub sp, #256
  0x1c0d,          # adds r5, r1, #0
  0x0400,          # lsls r0, r0, #16
  0x0c04,          # lsrs r4, r0, #16
  None,            # ldr  r2, [pc, X]
  0x8810,          # ldrh r0, [r2, #0]
  None,            # ldr  r1, [pc, X]
  0x4008,          # ands r0, r1
  0x2103,          # movs r1, #3
  0x4308,          # orrs r0, r1
  0x8010,          # strh r0, [r2, #0]
  None,            # ldr  r0, [pc, X]
  0x2001,          # movs r0, #1
  0x4043,          # eors r3, r0
  0x466a,          # mov  r2, sp
])
flash_v1_verify = packinsts([
  0xb590,          # push    {r4, r7, lr}
  0xb0c9,          # sub     sp, #292
  0x466f,          # mov     r7, sp
  0x6079,          # str     r1, [r7, #4]
  0x1c39,          # adds    r1, r7, #0
  0x8008,          # strh    r0, [r1, #0]
  None,            # ldr     r0, [pc, #X]
  None,            # ldr     r1, [pc, #X]
  0x880a,          # ldrh    r2, [r1, #0]
  None,            # ldr     r3, [pc, #X]
  0x1c11,          # adds    r1, r2, #0
  0x4019,          # ands    r1, r3
  0x1c0a,          # adds    r2, r1, #0
  0x2303,          # movs    r3, #3
  0x1c11,          # adds    r1, r2, #0
])
# A flavour that only verifes the first N bytes, not present in early versions.
flash_v3_verifyn = packinsts([
  0xb570,          # push {r4, r5, r6, lr}
  0xb0c0,          # sub  sp, #256
  0x1c0d,          # adds r5, r1, #0
  0x1c16,          # adds r6, r2, #0
  0x0402,          # lsls r2, r0, #16
  0x0c14,          # lsrs r4, r2, #16
  None,            # ldr  r0, [pc, #X]
  0x6800,          # ldr  r0, [r0, #0]
  0x6801,          # ldr  r1, [r0, #0]
  0x2080,          # movs r0, #128
  0x0280,          # lsls r0, r0, #10
  0x4281,          # cmp  r1, r0
  None,            # bne  off
  0x0d10,          # lsrs r0, r2, #20
  0x0600,          # lsls r0, r0, #24
  0x0e00,          # lsrs r0, r0, #24
])


KNOWN_DEVICE_IDS = {
  0x0000:        0,    # Undefined/default device
  0x3D1F:  64*1024,    # Atmel 64KB (a bit special)
  0xD4BF:  64*1024,    # SST, 64KB
  0x1B32:  64*1024,    # Panasonic, 64KB
  0x1CC2:  64*1024,    # Macronix, 64KB
  0x09C2: 128*1024,    # Macronix, 128KB
  0x1362: 128*1024,    # Sanyo 128KB
}

# From pokefirered reversed sources :)

# struct FlashSetupInfo
#   u16 (*programFlashByte)(u16, u32, u8);    // This function is present only in newer versions!
#   u16 (*programFlashSector)(u16, void *);
#   u16 (*eraseFlashChip)(void);
#   u16 (*eraseFlashSector)(u16);
#   u16 (*WaitForFlashWrite)(u8, u8 *, u8);
#   const u16 *maxTime;             // Points to a 3-4 entry u16 table with timing info (might be on RAM?)
#   struct FlashType {
#     u32 flash_size;               // In bytes
#     struct FlashSector {
#       u32 size;                   // Usually 4096 (could be 128 for Atmel)
#       u8 shift;                   // log2(size), so usually 12 or 7
#       u8 _pad;
#       u16 count;                  // Sector count (flash_size / sector_size)
#       u16 top;                    // Unused? Usually zero?
#       u16 _pad;
#     }
#     u16 wait_states[2];           // Two bits wait states
#     u16 maker_device_id;          // Not that many possible manufacturers really
#     u16 _pad;                     // Compiler inserted
#  };

# Regexes to find the above structure (it produces some false positives)
aproxm_v1 = re.compile(b'...[\\x08\\x09]...[\\x08\\x09]...[\\x08\\x09]...[\\x08\\x09]...[\\x08\\x09\\x03]' +   # 5 ROM pointers
                       b'...\\x00[\\x00\\x80][\\x00\\x10]\\x00\\x00' +   # 24 bit num or smaller, 128/4096 as sector size
                       b'[\\x07\\x0C]\\x00..\\x00\\x00\\x00\\x00' +   # shift (7/12) padded, count (any), top (zero?), pad
                       b'[\\x00\\x01\\x02\\x03]\\x00[\\x00\\x01\\x02\\x03]\\x00', flags=re.DOTALL)   # wait states (0-3)

aproxm_v2 = re.compile(b'...[\\x08\\x09]...[\\x08\\x09]...[\\x08\\x09]...[\\x08\\x09]...[\\x08\\x09]...[\\x08\\x09\\x03]' +   # 6 ROM pointers
                       b'...\\x00[\\x00\\x80][\\x00\\x10]\\x00\\x00' +   # 24 bit num or smaller, 128/4096 as sector size
                       b'[\\x07\\x0C]\\x00..\\x00\\x00\\x00\\x00' +   # shift (7/12) padded, count (any), top (zero?), pad
                       b'[\\x00\\x01\\x02\\x03]\\x00[\\x00\\x01\\x02\\x03]\\x00', flags=re.DOTALL)   # wait states (0-3)

def isp2(n):
  return (n & (n-1) == 0) and n != 0

def is_func_prologue(bseq, numargs=0):
  # Finds a push instruction and allows for some "mov" before that.
  PROLOGUE_SIZE = 3     # How many insts to check for
  VALID_MOVS = [0x46]   # Allow movs
  # Allow for non-arg regs to be written before the push too
  VALID_MOVS += [0x20 | i for i in range(numargs, 4)]   # Add, mov, sub (+imm)
  VALID_MOVS += [0x30 | i for i in range(numargs, 4)]
  VALID_MOVS += [0x80 | i for i in range(numargs, 4)]
  insts = [struct.unpack("<H", bseq[i*2:i*2+2])[0] for i in range(PROLOGUE_SIZE)]

  for inst in insts:
    if (inst & 0xFE00) == 0xB400:
      return True    # Found push inst
    elif (inst >> 8) not in VALID_MOVS:
      return False

  return False

def validate_flash_sizes(fsize, ssize, scnt, sshift, devid):
  # Checks if a flash info entry looks valid.
  if fsize == 0 or ssize == 0:
    return False   # Invalid sizes
  if fsize not in [64*1024, 128*1024]:
    return False   # Invalid size
  if not isp2(ssize):
    return False   # Bad sector size
  if fsize // ssize != scnt:
    return False   # Invalid sector count
  if (1 << (sshift & 0xFF)) != ssize:
    return False   # Invalid sector shift amount

  # Ensure the device ID looks good!
  return devid in KNOWN_DEVICE_IDS

# Extracts data from the structure and validates it (returns None for false positives)
def flash_unpack(boff, fulldata, data, version, check_funcs):
  if version == 1:
    pg_sec, clrfull, clrsec, waitfn, _, fsize, ssize, sshift, scnt, _, _, _, _, devid = struct.unpack("<IIIIIIIHHHHHHH", data[:42])
    pg_byte = None
  else:
    pg_byte, pg_sec, clrfull, clrsec, waitfn, _, fsize, ssize, sshift, scnt, _, _, _, _, devid = struct.unpack("<IIIIIIIIHHHHHHH", data[:46])

  if not validate_flash_sizes(fsize, ssize, scnt, sshift, devid):
    return None

  # Functions are thumb usually, remove last bit
  pg_sec  = pg_sec  & 0x1FFFFFE
  clrfull = clrfull & 0x1FFFFFE
  clrsec  = clrsec  & 0x1FFFFFE
  waitfn  = waitfn  & 0x1FFFFFE

  if check_funcs:
    if (not is_func_prologue(fulldata[pg_sec:pg_sec+64], 2) or
        not is_func_prologue(fulldata[clrfull:clrfull+64]) or
        not is_func_prologue(fulldata[clrsec:clrsec+64], 1) or
        not is_func_prologue(fulldata[waitfn:waitfn+64])):
      return None

  ret = {
    "flashinfo": hex(boff),
    "program_sect": hex(pg_sec),
    "erase_chip":   hex(clrfull),
    "erase_sect":   hex(clrsec),
    "wait_write":   hex(waitfn),
    "flash_size": fsize,
    "device_id": hex(devid),
    "flash_devsize": KNOWN_DEVICE_IDS[devid],
  }

  if pg_byte is not None:
    pg_byte = pg_byte & 0x1FFFFFE
    if check_funcs:
      if not is_func_prologue(fulldata[pg_byte:pg_byte+64], 3):
        return None
    ret["program_byte"] = hex(pg_byte)

  return ret

# Finds flash info tables on ROM.
# Uses a regexp to find candidates and then validates them using some well-known data.
def find_flash_tables(rom, check_funcs=True):
  res0 = [
    flash_unpack(m.start(), rom, rom[m.start() : m.start() + 128], 1, check_funcs)
    for m in aproxm_v1.finditer(rom)
  ]
  res1 = [
    flash_unpack(m.start(), rom, rom[m.start() : m.start() + 128], 2, check_funcs)
    for m in aproxm_v2.finditer(rom)
  ]
  return [x for x in (res0 + res1) if x is not None]

SAVE_STRINGS = {
  # EEPROM versions
  b"EEPROM_V111": ("eeprom", None, eeprom_v111_readfn, eeprom_v111_writefn),    # A couple of games use this older version
  b"EEPROM_V120": ("eeprom", None, eeprom_v12x_readfn, eeprom_v12_012_writefn), # Around 50 games
  b"EEPROM_V121": ("eeprom", None, eeprom_v12x_readfn, eeprom_v12_012_writefn), # Around 50 games
  b"EEPROM_V122": ("eeprom", None, eeprom_v12x_readfn, eeprom_v12_012_writefn), # Around 600 games use this one
  b"EEPROM_V124": ("eeprom", None, eeprom_v12x_readfn, eeprom_v12_45_writefn),  # Around 750 games use this one
  b"EEPROM_V125": ("eeprom", None, eeprom_v12x_readfn, eeprom_v12_45_writefn),  # A couple games use this
  b"EEPROM_V126": ("eeprom", None, eeprom_v12x_readfn, eeprom_v126_writefn),    # A handful of games use this
  # Flash versions
  b"FLASH_V120":    ("flash", "v1", flash_identfn_v1, flash_v1_read, flash_v1_verify),                     # ~2 games
  b"FLASH_V121":    ("flash", "v1", flash_identfn_v1, flash_v1_read, flash_v1_verify),                     # ~15 games
  b"FLASH_V123":    ("flash", "v2", flash_identfn_v2, flash_v2_read, flash_v2_verify),                     # ~15 games
  b"FLASH_V124":    ("flash", "v2", flash_identfn_v2, flash_v2_read, flash_v2_verify),                     # ~20 games
  b"FLASH_V125":    ("flash", "v2", flash_identfn_v2, flash_v2_read, flash_v2_verify),                     # ~2 games
  b"FLASH_V126":    ("flash", "v2", flash_identfn_v2, flash_v2_read, flash_v2_verify),                     # ~60 games
  b"FLASH512_V130": ("flash", "v3", flash_identfn_v2, flash_v3_read, flash_v3_verify, flash_v3_verifyn),   # ~15 games
  b"FLASH512_V131": ("flash", "v3", flash_identfn_v2, flash_v3_read, flash_v3_verify, flash_v3_verifyn),   # ~70 games
  b"FLASH512_V133": ("flash", "v3", flash_identfn_v2, flash_v3_read, flash_v3_verify, flash_v3_verifyn),   # ~10 games (2in1 mostly)
  b"FLASH1M_V102":  ("flash", "v3", flash_identfn_v2, flash_v3_read, flash_v3_verify, flash_v3_verifyn),   # ~20 games
  b"FLASH1M_V103":  ("flash", "v3", flash_identfn_v2, flash_v3_read, flash_v3_verify, flash_v3_verifyn),   # ~50 ROMs (Pokemon)

  # SRAM
  b"SRAM_V110":   ("sram", None, None),
  b"SRAM_V111":   ("sram", None, None),
  b"SRAM_V112":   ("sram", None, None),
  b"SRAM_V113":   ("sram", None, None),
  b"SRAM_F_V100": ("sram", None, None),
  b"SRAM_F_V102": ("sram", None, None),
  b"SRAM_F_V103": ("sram", None, None),
  b"SRAM_F_V110": ("sram", None, None),
}

# Guesses flash size based on device IDs
def flash_guess_size(idlist):
  # Find known 128KB devices
  return 128*1024 if ("0x1362" in idlist or "0x9c2" in idlist) else 64*1024

# Finds all matches for a buffer and a substring
def regexfinder(buf, regex):
  return [hex(x.start()) for x in regex.finditer(buf)]

def find_bx(rom, start):
  while True:
    inst = struct.unpack("<H", rom[start:start+2])[0]
    if (inst & 0xFF87) == 0x4700:
      return start
    start += 2

# For a given list of functions, parses them trying to find the end of the function
def parse_fns_thumb(rom, tgts):
  ret = []
  for t in tgts:
    off = int(t, 16)
    ret.append({"addr": t, "size": find_bx(rom, off) + 2 - off})
  return sorted(ret, key=lambda x: tuple(x.items()))

# Finds all matches for a buffer and a substring
def bytefinder(buf, hay):
  ret = []
  offset = 0
  while True:
    m = buf.find(hay, offset)
    if m < 0:
      return ret
    ret.append(m)
    offset = m + len(hay)

eeprom_savemap = {
  "gba_eeprom_4k": 512,
  "gba_eeprom_64k": 8*1024,
  "gba_eeprom": 8*1024,    # No idea, assume worst case
}

def lookup_eeprom_size(savetypes_3p, gcode):
  for db in savetypes_3p:
    if gcode in db and db[gcode] in eeprom_savemap:
      return eeprom_savemap[db[gcode]]
  return None

def process_rom(rom, **kwargs):
  # Add ROM and index by gamecode/version
  gcode = rom[0x0AC: 0x0B0].decode("ascii")
  grev = rom[0x0BC]

  matches = []
  for hay in SAVE_STRINGS.keys():
    m = bytefinder(rom, hay)
    if len(m) >= 1:
      matches.append(hay)

  if len(matches) == 0:
    # Try to guess if the game uses a password system?
    if (bytefinder(rom, b"assword") or bytefinder(rom, b"ASSWORD") or
        bytefinder(rom, b"code") or bytefinder(rom, b"CODE") or
        bytefinder(rom, b"a\x00s\x00s\x00w\x00o\x00r\x00") or
        bytefinder(rom, b"A\x00S\x00S\x00W\x00O\x00R\x00")):
      pass    # Likely a game that uses passwords/codes, no save memory
    else:
      # print("No save found for ROM", f, file=sys.stderr)
      pass
    return None

  elif len(matches) > 1:
    # Certain FLASH types are compatible, so ignore those as long as they are compat
    subvermap = {}
    for stype in matches:
      gentype, subver, *_ = SAVE_STRINGS[stype]
      if gentype == "flash":
        if gentype not in subvermap:
          subvermap[gentype] = {}
        subvermap[gentype][subver] = subvermap[gentype].get(subver, 0) + 1

    if any(len(e) > 1 for e in subvermap.values()):
      print("Conflicting save types", subvermap, file=sys.stderr)
    elif any(c > 1 for e in subvermap.values() for c in e.values()):
      excl_matches = sorted([m for m in matches if SAVE_STRINGS[m][0] == "flash"])[:-1]
      matches = sorted([m for m in matches if SAVE_STRINGS[m][0] != "flash" or m not in excl_matches])
      print("Flash type conflicts, skipping " + str(excl_matches), file=sys.stderr)

  # Some games have more than one match (at least string signature)
  # but then they might only have a correct set of routines.
  targets = {}
  for stype in matches:
    gentype, subver, *fnhooks = SAVE_STRINGS[stype]

    # Go ahead and find the relevan routine for this save type
    if gentype == "sram":
      # Mark this as an SRAM ROM so we don't apply patches but still save
      targets["sram"] = {}
    elif gentype == "eeprom":
      # Find the offsets for the patchable functions
      readfn, writefn = fnhooks
      rd_tgts = regexfinder(rom, readfn)
      wr_tgts = regexfinder(rom, writefn)

      # Only include the patch if it has both types
      if rd_tgts and wr_tgts:
        assert "eeprom" not in targets
        targets["eeprom"] = {
          "subtype": stype.decode("ascii"),
          "target-info": {
            "read": parse_fns_thumb(rom, rd_tgts),
            "write": parse_fns_thumb(rom, wr_tgts),
          }
        }
        guessed_size = lookup_eeprom_size(kwargs.get("savetypesdb", []), gcode)
        if guessed_size:
          targets["eeprom"]["target-info"]["eeprom-size"] = guessed_size
    elif gentype == "flash":
      # Ident flash and read functions are found using the regular method!
      identfn, readfn, *verifns = fnhooks
      id_tgts = parse_fns_thumb(rom, regexfinder(rom, identfn))
      rd_tgts = parse_fns_thumb(rom, regexfinder(rom, readfn))
      ve_tgts = []
      for m in verifns:
        ve_tgts += regexfinder(rom, m)
      ve_tgts = parse_fns_thumb(rom, ve_tgts)

      # Find the per-device functions by finding the device impl. table
      res = find_flash_tables(rom)

      assert "flash" not in targets

      if res and id_tgts and rd_tgts and ve_tgts:
        targets["flash"] = {
          "subtype": stype.decode("ascii"),
          "target-info": {
            "avail_devids": sorted(set([x["device_id"] for x in res])),
            "flash-size": flash_guess_size([x["device_id"] for x in res]),
            "ident": id_tgts,
            "read": rd_tgts,
            "verify": ve_tgts,
            "writebyte": parse_fns_thumb(rom, set([x["program_byte"] for x in res if "program_byte" in x])),
            "writesect": parse_fns_thumb(rom, set([x["program_sect"] for x in res])),
            "erasefull": parse_fns_thumb(rom, set([x["erase_chip"] for x in res])),
            "erasesect": parse_fns_thumb(rom, set([x["erase_sect"] for x in res])),
          }
        }

  # If a game has only SRAM, mark is as an sram game.
  if targets and all(x == "sram" for x in targets):
    targets = {"sram": {}}
  else:
    # We can have both EEPROM and FLASH sometimes, so we keep both patch-sets
    targets = {k:v for k,v in targets.items() if k != "sram"}

  if targets:
    return ({
      "filesize": len(rom),
      "sha256": hashlib.sha256(rom).hexdigest(),
      "sha1": hashlib.sha1(rom).hexdigest(),
      "md5": hashlib.md5(rom).hexdigest(),
      "game-code": gcode,
      "game-version": grev,
      "targets": targets
    })

