#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

# Given a full unified patch set, generate raw patches in several formats:
#  - JSON: For human inspection
#  - Patch-Database: To use with SuperFW as loadable patch DB
#  - Py: To manually and locally patch ROMs

import json, struct, re

# Check INFO.md for more information.

# Format: Header word (32bits) + 4*N bytes payload
# Header word is: OOOO.NNNA.AAAA.AAAA.AAAA.AAAA.AAAA.AAAA
#  C is an opcode (4 bits), N is a number argument and A is the
#  address to patch.

OPC_WR_BUF    = 0
OPC_NOP_THUMB = 1
OPC_NOP_ARM   = 2
OPC_COPY_BYTE = 3
OPC_COPY_WORD = 4
OPC_PATCH_FN  = 5

OPC_RTC_HD    = 7
OPC_EEPROM_HD = 8
OPC_FLASH_HD  = 9

FUNC_RET0_THUMB  = 0x0
FUNC_RET1_THUMB  = 0x1
FUNC_RET0_ARM    = 0x4
FUNC_RET1_ARM    = 0x5

RTC_PROBE_HNDLR  = 0x0
RTC_RESET_HNDLR  = 0x1
RTC_STSRD_HNDLR  = 0x2
RTC_GETTD_HNDLR  = 0x3

EEPROM_RD_HNDLR  = 0x0
EEPROM_WR_HNDLR  = 0x1

FLASH_READ_HNDLR = 0x0
FLASH_CLRC_HNDLR = 0x1
FLASH_CLRS_HNDLR = 0x2
FLASH_WRTS_HNDLR = 0x3
FLASH_WRBT_HNDLR = 0x4

def pack4(ol):
  return b''.join(struct.pack("<I", x) for x in ol)

def pack2(ol):
  return b''.join(struct.pack("<H", x) for x in ol)

def gen_patchfunc(addr, isthumb, rettrue):
  assert (addr & ~0x1FFFFFF) == 0
  fn_num = (0 if isthumb else 4) + (1 if rettrue else 0)
  return [ (OPC_PATCH_FN << 28) | (fn_num << 25) | addr ]

def gen_cpywords(addr, words):
  assert len(words) <= 8 and len(words) > 0
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_COPY_WORD << 28) | ((len(words) - 1) << 25) | addr ] + words

def gen_cpyhalfword(addr, halfw):
  assert halfw <= 0xFFFF
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_COPY_BYTE << 28) | (1 << 25) | addr ] + [halfw]

def gen_thumbnop(addr):
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_NOP_THUMB << 28) | addr ]

def gen_armnop(addr):
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_NOP_ARM << 28) | addr ]

def gen_prgwr(addr, pgn):
  assert pgn < 8
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_WR_BUF << 28) | (pgn << 25) | addr ]

def gen_rtc_opc(addr, typenum):
  assert typenum >= RTC_PROBE_HNDLR and typenum <= RTC_GETTD_HNDLR
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_RTC_HD << 28) | (typenum << 25) | addr ]

def gen_eeprom_opc(addr, typenum):
  assert typenum >= EEPROM_RD_HNDLR and typenum <= EEPROM_WR_HNDLR
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_EEPROM_HD << 28) | (typenum << 25) | addr ]

def gen_flash_opc(addr, typenum):
  assert typenum >= FLASH_READ_HNDLR and typenum <= FLASH_WRBT_HNDLR
  assert (addr & ~0x1FFFFFF) == 0
  return [ (OPC_FLASH_HD << 28) | (typenum << 25) | addr ]

def encode_arm_bl(inst_addr, target_addr):
  assert target_addr % 4 == 0 and inst_addr % 4 == 0
  off = (target_addr - (inst_addr + 8)) // 4
  if off >= (1 << 23) or off < -(1 << 23):
    return None
  return 0xEA000000 | (off & 0xFFFFFF)

def encode_thumb_bl(inst_addr, target_addr):
  assert target_addr % 2 == 0 and inst_addr % 2 == 0
  off = (target_addr - (inst_addr + 4)) // 2
  if off >= (1 << 21) or off < -(1 << 21):
    return None
  return 0xF800F000 | ((off << 16) & 0x07FF0000) | ((off >> 11) & 0x07FF)

# For SWI1 patching and FLASH emulation we need generate a bunch of snippets:
#  - swi1-waitcnt preserving, ARM + Thumb mode (#0)
#    Calls SWI 1 preserving the state of WAITCNT register
#  - flash64-ident, Thumb mode (#1)
#    Returns a predefined 64KB flash ID
#  - flash128-ident, Thumb mode (#2)
#    Returns a predefined 128KB flash ID

SWI1_WAITCNT_PG_THUMB_OFF = 0
SWI1_WAITCNT_PG_ARM_OFF   = 10*2         # After the Thumb program

SWI1_WAITCNT_THUMB_PG = [
  0x4903,       # ldr r1, [pc, #12]
  0x8809,       # ldrh r1, [r1, #0]
  0xb402,       # push {r1}
  0xdf01,       # svc 1
  0x4902,       # ldr r1, [pc, #8]
  0xbc01,       # pop {r0}
  0x8008,       # strh r0, [r1, #0]
  0x4770,       # bx lr
  0x0204,
  0x0400,
]

SWI1_WAITCNT_ARM_PG = [
  0xe3a01301, # mov r2, #0x04000000
  0xe5912204, # ldr r1, [r2, #0x204]
  0xe52d1004, # push {r1}
  0xef010000, # svc 0x00010000
  0xe49d0004, # pop {r0}
  0xe3a01301, # mov	r1, #0x04000000
  0xe5810204, # str r0, [r1, #0x204]
  0xe12fff1e, # bx lr
]

FLASH_FLASH64_IDENT_PG = [
  # Return  0x1cc2 (Macronix 64KB flash device)
  0x201c,  # movs r0, #0x1c
  0x0200,  # lsls r0, r0, #8
  0x30c2,  # adds r0, #0xc2
  0x4770,  # bx lr
]
FLASH_FLASH128_IDENT_PG = [
  # Return  0x09c2 (Macronix 128KB flash device)
  0x2009,  # movs r0, #0x09
  0x0200,  # lsls r0, r0, #8
  0x30c2,  # adds r0, #0xc2
  0x4770,  # bx lr
]

IRQ_POOL_ADDR_PATCH = [
  0x03007FF4,   # Patches IRQ handler into unused memory address.
]

PROG_SWI1_EMU  = 0
PROG_FLH64_ID  = 1
PROG_FLH128_ID = 2
PROG_IRQH_ADDR = 3

PROGRAMS = [
  # 0: swi1-waitcnt preserving
  pack2(SWI1_WAITCNT_THUMB_PG) + pack4(SWI1_WAITCNT_ARM_PG),
  # 1: flash64-ident
  pack2(FLASH_FLASH64_IDENT_PG),
  # 2: flash128-ident
  pack2(FLASH_FLASH128_IDENT_PG),
  # 3: irq-pool-patch (constant)
  pack4(IRQ_POOL_ADDR_PATCH),
]

ROM_GAMETITLE_OFFSET = 0xA0
MIN_TAILSPACE = 128*1024


# WaitCNT filtering for save routines
# Some save routines update WAITCNT to handle SRAM WS. We can ignore these.
def waitcnt_filter(targets):
  # Extract all the ranges that can be "safely" ignored.
  ranges = []
  if "eeprom" in targets:
    for t in ["read", "write"]:
      for info in targets["eeprom"]["target-info"][t]:
        ranges.append((int(info["addr"], 16), info["size"]))

  if "flash" in targets:
    for t in ["read", "ident", "verify", "erasefull", "erasesect", "writesect", "writebyte"]:
      for info in targets["flash"]["target-info"][t]:
        ranges.append((int(info["addr"], 16), info["size"]))

  def inrange(addr16):
    off = int(addr16, 16)
    for st, size in ranges:
      if off >= st and off < st+size:
        return True
    return False

  if "waitcnt" in targets:
    psites = []
    for i in range(len(targets["waitcnt"]["patch-sites"])):
      if targets["waitcnt"]["patch-sites"][i]["inst-type"] in ["str16-thumb", "str32-thumb"]:
        # Check if we can remove this one
        if not inrange(targets["waitcnt"]["patch-sites"][i]["inst-offset"]):
          psites.append(targets["waitcnt"]["patch-sites"][i])
      else:
        psites.append(targets["waitcnt"]["patch-sites"][i])

    targets["waitcnt"]["patch-sites"] = psites

# WaitCNT patching.
def gen_waitcnt_patch(tlist, romsize, layoutinfo):
  ret = []
  patch_gametitle = set()
  swi1_hdl_offset = None

  # Check if we need to patch SWI1 calls.
  if any(re.match("swi1-.*", t["inst-type"]) for t in tlist):
    if romsize > 32*1024*1024 - 1024:
      # Try to place it at the end of the ROM
      tpad = layoutinfo.get("tail-padding", 0)
      subh = layoutinfo.get("subheaders", [])
      if tpad > MIN_TAILSPACE:
        # Place it at the end of the rom, since it seems padding space
        swi1_hdl_offset = romsize - len(PROGRAMS[PROG_SWI1_EMU])
      elif subh:
        # Try place it at some internal header (usually 2in1 games)
        swi1_hdl_offset = subh[0] + 4   # Use the logo space, nobody checks it here
    else:
      # Emit program 0 after the ROM EOF (since we have plenty of space)
      swi1_hdl_offset = romsize

  # Ensure we write the handling routine there
  if swi1_hdl_offset:
    ret += gen_prgwr(swi1_hdl_offset, PROG_SWI1_EMU)

  for t in tlist:
    # Patch STR/B/H instructions that update the WAITCNT register and/or any other
    # address that can simply be patched out.
    if re.match("str[0-9]+-thumb", t["inst-type"]):
      ret += gen_thumbnop(int(t["inst-offset"], 16))
    elif re.match("str[0-9]+-arm", t["inst-type"]):
      ret += gen_armnop(int(t["inst-offset"], 16))
    elif t["inst-type"] == "word32":
      value = int(t["inst-patchv"], 16)
      ret += gen_cpywords(int(t["inst-offset"], 16), [value])

    # For SWI patching (if required) place a SWI1 handler at the end of the ROM.
    elif re.match("swi1.*", t["inst-type"]):
      if swi1_hdl_offset is None:
        # Could not find space for the routine, so we cannot handle these
        print("Could not patch", t, romsize, layoutinfo) # FIXME: Return a proper log
      else:
        if re.match("swi1-arm", t["inst-type"]):
          # Patch any ARM SWIs using a branch-and-link
          pinst = encode_arm_bl(int(t["inst-offset"], 16), swi1_hdl_offset + SWI1_WAITCNT_PG_ARM_OFF)
          ret += gen_cpywords(int(t["inst-offset"], 16), [pinst])
        elif re.match("swi1-bl-thumb", t["inst-type"]):
          # For thumb mode, try to see if the function is reachable using a regular BL.
          pinst = encode_thumb_bl(int(t["inst-offset"], 16), swi1_hdl_offset + SWI1_WAITCNT_PG_THUMB_OFF)
          if pinst is None:
            # Attempt to place it now in the header (or any reachable subheader really)
            for hdroff in ([0] + layoutinfo.get("subheaders", [])):
              pinst = encode_thumb_bl(int(t["inst-offset"], 16), hdroff + ROM_GAMETITLE_OFFSET)
              if pinst is not None:
                patch_gametitle.add(hdroff + ROM_GAMETITLE_OFFSET)
                ret += gen_cpywords(int(t["inst-offset"], 16), [pinst])
                break

            if pinst is None:
              print("Cannot patch SWI-Thumb-BL", romsize, t, layoutinfo)
          else:
            ret += gen_cpywords(int(t["inst-offset"], 16), [pinst])
        else:
          raise ValueError("Unsupported patch type!")
    else:
      raise ValueError("Unsupported patch type!")

  # Emit a trampoline (2+1 insts) in the gametitle.
  for off in patch_gametitle:
    ret += gen_cpywords(off, [
      0x47084679,   # mov r1, pc + bx r1
      encode_arm_bl(off + 4, swi1_hdl_offset + SWI1_WAITCNT_PG_ARM_OFF)  # BL (ARM mode)
    ])

  return ret

def gen_eeprom_patch(eeprom_info):
  ret = []
  for fn in eeprom_info["read"]:
    ret += gen_eeprom_opc(int(fn["addr"], 16), EEPROM_RD_HNDLR)
  for fn in eeprom_info["write"]:
    ret += gen_eeprom_opc(int(fn["addr"], 16), EEPROM_WR_HNDLR)
  return ret

def gen_rtc_patch(rtc_info):
  ret = []
  ret += gen_rtc_opc(int(rtc_info["probe_fn"], 16), RTC_PROBE_HNDLR)
  ret += gen_rtc_opc(int(rtc_info["reset_fn"], 16), RTC_RESET_HNDLR)
  ret += gen_rtc_opc(int(rtc_info["getstatus_fn"], 16), RTC_STSRD_HNDLR)
  ret += gen_rtc_opc(int(rtc_info["gettimedate_fn"], 16), RTC_GETTD_HNDLR)
  return ret

def gen_layout_patch(layout_info, romsize):
  ret = []
  if "tail-padding" in layout_info:
    tail_size = layout_info["tail-padding"]
    if tail_size >= 4*1024:
      addr = romsize - tail_size
      # Adjust address a bit up, and size too
      addr = ((addr + 1023) >> 10) << 10
      gap_size = romsize - addr - 1024
      assert gap_size > 0
      if gap_size >= 7*1024:
        assert gap_size < 32*1024*1024
        assert addr < 32*1024*1024
        # Simply emit address (multiple of 1024) and size (in KB as well)
        w = (gap_size >> 10) | ((addr >> 10) << 16)
        ret.append(w)
  return ret

def gen_flash_patch(flash_info):
  ret = []
  # Determnine whether this is a 64KB or a 128KB game.
  is128 = flash_info["subtype"].startswith("FLASH1M")

  # Patch the flash-ID functions to return some fixed value
  for ifn in flash_info["target-info"]["ident"]:
    prgn = PROG_FLH128_ID if is128 else PROG_FLH64_ID
    ret += gen_prgwr(int(ifn["addr"], 16), prgn)

  # Patch the flash verify function to always return 0 (verified OK)
  for ifn in flash_info["target-info"]["verify"]:
    ret += gen_patchfunc(int(ifn["addr"], 16), True, False)

  # Emit patching info for every other routine (so that the FW can patch them)
  # with a relevant implementation (usually emulating it using SRAM).
  for pnum, addrtype in {
    FLASH_READ_HNDLR: "read",
    FLASH_CLRC_HNDLR: "erasefull",
    FLASH_CLRS_HNDLR: "erasesect",
    FLASH_WRTS_HNDLR: "writesect",
    FLASH_WRBT_HNDLR: "writebyte",
  }.items():
    for fn in flash_info["target-info"].get(addrtype, []):
      ret += gen_flash_opc(int(fn["addr"], 16), pnum)

  return ret

def gen_irqhdr_patch(irqhdr_psites):
  ret = []

  patch_pool = set()

  for e in irqhdr_psites:
    if e["inst-type"] == "mem-clr-seq":
      # Usually involves patching some instruction.
      ret += gen_cpywords(int(e["patch-addr"], 16), [int(e["patch-value"], 16)])
    elif e["inst-type"] == "irq-arm-str":
      # Usually patch the pool address, unless there is none.
      if "pool-addr" in e:
        patch_pool.add(int(e["pool-addr"], 16))
      else:
        opc = int(e["inst-opcode"], 16)
        cond, op = opc >> 28, (opc >> 20) & 0xFF
        assert op == 0x58   # TODO Support opcode 0x50
        rn, rd, off = ((opc >> 16) & 0xF), ((opc >> 12) & 0xF), opc & 0xFFF
        # We need to subtract 8 to the offset (so 0xFC becomes 0xF4). This might not be
        # possible if the offset is zero, in that case we replace the opcode to 0x50.
        newoff = off - 8
        if newoff >= 0:
          opc = (opc & 0xFFFFF000) | (newoff & 0xFFF)
        else:
          opc = (opc & 0xF00FF000) | (-newoff & 0xFFF) | (0x05000000)

        ret += gen_cpywords(int(e["offset"], 16), [opc])
    elif e["inst-type"] == "irq-thumb-str":
      # Usually patch the pool address, unless there is none.
      if "pool-addr" in e:
        patch_pool.add(int(e["pool-addr"], 16))
      else:
        opc = int(e["inst-opcode"], 16)
        op, imm5 = opc >> 11, (opc >> 6) & 0x1F
        assert op == 0xC
        # We only subtract 2 (since it's scaled by 4)
        assert imm5 >= 2
        opc = (opc & 0xF83F) | (((imm5 - 2) & 0x1F) << 6)

        ret += gen_cpyhalfword(int(e["offset"], 16), opc)

  # Patch pool addresses
  for pooladdr in patch_pool:
    ret += gen_prgwr(pooladdr, PROG_IRQH_ADDR)

  return ret

class GamePatch(object):
  def __init__(self, gamecode, gamever, targets, romsize):
    # Store patches in raw format
    self._gamecode = gamecode
    self._gamever = gamever
    self._romsize = romsize

    # Apply filtering to reduce WAITCNT patch count
    waitcnt_filter(targets)

    self._waitcnt_patches = gen_waitcnt_patch(
      targets.get("waitcnt", {}).get("patch-sites", []),
      romsize,
      targets.get("layout", {}).get("info", {}))

    self._save_patches = []
    self._irq_patches = []
    self._rtc_patches = []
    self._layout_patches = []

    # Provide some hole/trailing info if the ROM is over 31MB. Helps with patching
    if romsize > 31*1024*1024:
      self._layout_patches += gen_layout_patch(targets.get("layout", {}).get("info", {}), romsize)

    if "rtc" in targets:
      self._rtc_patches += gen_rtc_patch(targets["rtc"])

    if "eeprom" in targets:
      self._save_patches += gen_eeprom_patch(targets["eeprom"]["target-info"])

    if "flash" in targets:
      self._save_patches += gen_flash_patch(targets["flash"])

    if "irqhdr" in targets:
      self._irq_patches += gen_irqhdr_patch(targets["irqhdr"].get("patch-sites", []))

    assert all((x & 0xFFFFFFFF) == x for x in self._waitcnt_patches)
    assert all((x & 0xFFFFFFFF) == x for x in self._save_patches)

    # we don't support more than this for now
    assert (len(self._save_patches)) < 32          # Limit to 32, we use three MSB for save type
    assert (len(self._waitcnt_patches)) < 256
    assert (len(self._irq_patches)) < 256
    assert (len(self._rtc_patches)) < 16
    assert (len(self._layout_patches)) <= 1        # Limit it to one single element

    saveflg = 0      # No save
    if "sram" in targets:
      saveflg = 1    # SRAM (32KiB)
    elif "eeprom" in targets:
      if "eeprom-size" not in targets["eeprom"]["target-info"]:
        print("No eeprom size defined for", gamecode, "defaulting to 8KB")
        saveflg = 3
      elif targets["eeprom"]["target-info"]["eeprom-size"] == 512:
        saveflg = 2
      else:
        saveflg = 3
    elif "flash" in targets:
      if targets["flash"]["target-info"]["flash-size"] == 64*1024:
        saveflg = 4    # FLASH 64KiB
      else:
        saveflg = 5    # FLASH 128KiB

    self._save_flags = saveflg << 5
    self._extra_flags = 0x1 if self._layout_patches else 0x0       # Indicate whether we have some layout (tail/hole) info

    self._data = b"".join(struct.pack("<I", x) for x in self._waitcnt_patches + self._save_patches + self._irq_patches + self._rtc_patches + self._layout_patches)

  def gamecode(self):
    return self._gamecode

  def gamecode_eu32(self):
    return struct.unpack("<I", self._gamecode.encode("ascii"))[0]

  def dbheader(self):
    return (len(self._waitcnt_patches) |
            ((len(self._save_patches) | self._save_flags) << 8) |
            (len(self._irq_patches) << 16) |
            ((len(self._rtc_patches) | (self._extra_flags << 4)) << 24))

  def gamever(self):
    return self._gamever

  def payload(self):
    return struct.pack("<I", self.dbheader()) + self._data

  def waitcnt_patches(self):
    return self._waitcnt_patches

  def save_patches(self):
    return self._save_patches

  def layout_patches(self):
    return self._layout_patches

  def irq_patches(self):
    return self._irq_patches

  def rtc_patches(self):
    return self._rtc_patches

  def size(self):
    return len(self._data)


def generate_database(pdict, cdate, version, creator):
  # Generate an index. It contains a bunch of blocks with lists of
  # game code + patch offset (in doublewords). The codes are sorted so that
  # implementations can load it faster by performing a sorted-search
  # Code is 5 bytes (includes version) and 24 bit offset.
  # C C C C V O O O   (Code/Version/Offset)
  bpatches, bidx = [], b""
  for gcode in sorted(pdict.keys()):
    # Header + patches account for all space used.
    pe = pdict[gcode]
    pload = pe.payload()
    if pload in bpatches:
      # Already emitted, re-use it!
      offset = sum(len(x) for x in bpatches[:bpatches.index(pload)])
    else:
      offset = sum(len(x) for x in bpatches)
      bpatches.append(pload)

    # Generate header and index entry
    assert (offset % 4) == 0
    offhdr = struct.pack("<I", pe.gamever() | ((offset // 4) << 8))
    bidx += pe.gamecode().encode("ascii") + offhdr

  bptch = b"".join(bpatches)

  # Pad index to be a multiple of block size as well as patch data
  while len(bidx) % 512 != 0:
    bidx += (b"\x00" * 8)
  while len(bptch) % 512 != 0:
    bptch += b"\x00"

  prg_block = b"".join(
    struct.pack("<B", len(pg)) + pg for pg in PROGRAMS)
  prg_block += (b"\x00" * (512 - len(prg_block)))

  # Database header, contains version and some other fields.
  header = (struct.pack(
      "<IIII",
      0x31424450,         # "PTDB" signature
      0x00010000,         # Version 1.0
      len(pdict),         # Number of game patches in the database
      len(bidx) // 512,   # Number of index blocks
    )
    + cdate               # 8 byte creation date string
    + version             # 8 byte creation date string
    + creator)            # 32 byte creator string
  header += (b"\x00" * (512 - len(header)))

  return header + prg_block + bidx + bptch

if __name__ == "__main__":
  import sys, json, argparse, string, time

  # Parse input args
  parser = argparse.ArgumentParser(prog='patch_gen')
  parser.add_argument('--input', dest='inpatch', required=True, help='Input JSON file containing the patches')
  parser.add_argument('--outfile', dest='outfile', required=True, help='Output path in JSON format')
  parser.add_argument('--format', dest='format', required=True, help='Format: json, db or py')
  parser.add_argument('--creator', dest='creator', type=str, default="unknown", help='Creator name (max 31 utf-8 bytes)')
  parser.add_argument('--creation-date', dest='cdate', type=str, default=None, help='Creation date in YYYYMMDD format (defaults to system time)')
  parser.add_argument('--version', dest='version', type=str, default="00000000", help='Version string (8 utf-8 bytes)')

  args = parser.parse_args()

  if args.format not in ["json", "db", "h", "py"]:
    raise ValueError("Invalid format")

  # Generate the header
  creator = args.creator.encode("utf-8")
  if len(creator) > 31:
    raise ValueError("Creator size is limited to 31 utf-8 bytes")
  creator = creator.ljust(32, b"\x00")

  version = args.version.encode("utf-8")
  if len(version) != 8:
    raise ValueError("Version size must be 8 utf-8 bytes")

  if args.cdate:
    cdate = args.cdate
  else:
    cdate = time.strftime("%Y%m%d", time.localtime())

  if len(cdate) != 8 or not all(x in string.digits for x in cdate):
    raise ValueError("Creation date must have YYYYMMDD format: " + cdate)
  cdate = cdate.encode("ascii")


  # Read input file, ensure we sort by gamecode/version
  pcont = json.load(open(args.inpatch, "r"))

  # Index patches by game code and version, ensure they are unique!
  patches = {}
  for e in pcont:
    key = (e["game-code"], e["game-version"])
    assert key not in patches
    patches[key] = {
      "files": e["files"],
      "romsize": e["romsize"],
      "targets": e["targets"],
    }

  # Generate patch data.
  fpatches = {}
  for key, c in patches.items():
    fpatches[key] = GamePatch(key[0], key[1], c["targets"], c["romsize"])

  # Calculate some metrics and print a report (sizes, types, etc)
  maxsave = max([len(gobj.save_patches())    for gobj in fpatches.values()])
  maxwcnt = max([len(gobj.waitcnt_patches()) for gobj in fpatches.values()])
  maxirqh = max([len(gobj.irq_patches())     for gobj in fpatches.values()])
  maxrtcp = max([len(gobj.rtc_patches())     for gobj in fpatches.values()])
  maxlayo = max([len(gobj.layout_patches())  for gobj in fpatches.values()])

  maxpcnt = max([len(gobj.save_patches()) + len(gobj.waitcnt_patches()) +
                 len(gobj.irq_patches()) + len(gobj.rtc_patches()) + len(gobj.layout_patches())
                 for gobj in fpatches.values()])

  print("Number of games:", len(fpatches), "| Maximum patch count:", maxsave, "(save)", maxwcnt, "(waitcnt)", maxirqh, "(irqhdr)", maxrtcp, "(rtc)", maxlayo, "(layout)", maxpcnt, "(total)")
  if maxpcnt > 128:
    raise ValueError("Limit on patch count is artificially capped at 128 entries!")


  # JSON dump (for py/json formats)
  serp = []
  for gcode in sorted(fpatches.keys()):
    serp.append({
      "gamecode": gcode[0],
      "gamever":  gcode[1],
      "files": patches[gcode]["files"],
      "waitcnt-patches": ["0x%08x" % x for x in fpatches[gcode].waitcnt_patches()],
      "save-patches": ["0x%08x" % x for x in fpatches[gcode].save_patches()],
      "irq-patches": ["0x%08x" % x for x in fpatches[gcode].irq_patches()],
      "rtc-patches": ["0x%08x" % x for x in fpatches[gcode].rtc_patches()],
      "layout-patches": ["0x%08x" % x for x in fpatches[gcode].layout_patches()],
    })

  # Write patches in the supported formats

  if args.format == "json":
    with open(args.outfile, "w") as ofd:
      ofd.write(json.dumps(serp, indent=2))

  elif args.format == "db":
    with open(args.outfile, "wb") as ofd:
      ofd.write(generate_database(fpatches, cdate, version, creator))

  elif args.format == "py":
    with open(args.outfile, "w") as ofd:
      ofd.write("# This file is autogenerated (patch_gen.py)!\n\n")
      ofd.write("import sys, struct, os\n\n")
      ofd.write("if len(sys.argv) <= 1:\n")
      ofd.write("  print('Usage: %s patch-type')\n" % sys.argv[0])
      ofd.write("  sys.exit(1)\n\n")

      ofd.write('PROGRAMS = [\n')
      for pg in PROGRAMS:
        ofd.write("  b'" + "".join('\\x%02x' % c for c in pg) + "',\n")
      ofd.write(']\n\n')

      ofd.write('PATCHES = %s\n\n' % json.dumps(serp, indent=2))

      ofd.write('for p in PATCHES:\n')
      ofd.write('  for f in p["files"]:\n')
      ofd.write('    if not os.path.isfile(f["filename"]): continue\n')
      ofd.write("    with open(f['filename'], 'rb+') as fd:\n")
      ofd.write('      wl = []\n')
      ofd.write('      if sys.argv[1] == "waitcnt":\n')
      ofd.write('        wl += p["waitcnt-patches"]\n')
      ofd.write('      if sys.argv[1] == "save":\n')
      ofd.write('        wl += p["save-patches"]\n')
      ofd.write('      if sys.argv[1] == "irq":\n')
      ofd.write('        wl += p["irq-patches"]\n')
      ofd.write('      i = 0\n')
      ofd.write('      while i < len(wl):\n')
      ofd.write('        w = int(wl[i], 16); opc = w >> 28; n = (w >> 25) & 7; i += 1\n')
      ofd.write('        fd.seek(w & 0x01FFFFFF)\n')
      ofd.write('        if opc == 0: fd.write(PROGRAMS[n])\n')
      ofd.write('        elif opc == 1: fd.write(b"\\xC0\\x46" * (n + 1))\n')
      ofd.write('        elif opc == 2: fd.write(b"\\x00\\x00\\xA0\\xE1" * (n + 1))\n')
      ofd.write('        elif opc == 3:\n')
      ofd.write('          numb = n + 1\n')
      ofd.write('          buf = b"".join(struct.pack("<I", int(x, 16)) for x in wl[i:i+2])\n')
      ofd.write('          fd.write(buf[:numb]); i += (numb + 3) // 4\n')
      ofd.write('        elif opc == 4:\n')
      ofd.write('          numw = n + 1\n')
      ofd.write('          fd.write(b"".join(struct.pack("<I", int(x, 16)) for x in wl[i:i+numw]))\n')
      ofd.write('          i += numw\n')
      ofd.write('        elif opc == 5:\n')
      ofd.write('          print("OPC_PATCH_FN opcode is not handled yet!")\n')
      ofd.write('        else:\n')
      ofd.write('          print("Unhandled opcode", opc)\n')

      # TODO: Handle handler addresses, for now only patch programs

