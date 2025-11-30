#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2025 David Guillen Fandos <david@davidgf.net>

# Automatic RTC patch detector and genertor.
# We aim to detect certain functions that handle the SII (S-3511A)
# RTC device, mapped via GPIO registers.
#
# We use some emulation and detect writes to GPIO ports.
#
# Use pypy to run this, it's 20x faster than regular python :)

import struct, re, hashlib
import patchtool.arm as arm

RTC_STRING = b"SIIRTC_V001"
ROM_ADDR = 0x08000000
EMU_STCK = 0x02008000             # Use some "reasonable" and plausible SP
DATA_RANGE = 1024
PROLOGUE_SIZE = 3

def is_func_prologue(bseq, numargs=0, maxcnt=PROLOGUE_SIZE):
  # Finds a push instruction and allows for some "mov" before that.
  VALID_MOVS = [0x46]   # Allow movs
  # Allow for non-arg regs to be written before the push too
  VALID_MOVS += [0x20 | i for i in range(numargs, 4)]   # Add, mov, sub (+imm)
  VALID_MOVS += [0x30 | i for i in range(numargs, 4)]
  VALID_MOVS += [0x80 | i for i in range(numargs, 4)]
  insts = [struct.unpack("<H", bseq[i*2:i*2+2])[0] for i in range(maxcnt)]

  for inst in insts:
    if (inst & 0xFE00) == 0xB400:
      return True    # Found push inst
    elif (inst >> 8) not in VALID_MOVS:
      return False

  return False

def decode_thumb_bl(baseaddr, rombytes):
  lo, hi = struct.unpack("<HH", rombytes)
  if (lo & 0xF800) == 0xF000 and (hi & 0xF800) == 0xF800:
    hioff = (lo & 0x7FF) << 12
    if hioff & 0x400000:
      hioff -= (1 << 23)

    off = baseaddr + 4 + hioff + (hi & 0x7FF) * 2
    # Ensure the function starts with a push
    return off
  return None

def find_bx(rom, start):
  while start < len(rom) - 4:
    inst = struct.unpack("<H", rom[start:start+2])[0]
    if (inst & 0xFF87) == 0x4700:
      return start
    start += 2

  return 0

def constant_in_range(rom, offset, drange, constant):
  for i in range(offset - drange, offset + drange, 4):
    if i >= 0 and i + 4 <= len(rom):
      data = struct.unpack("<I", rom[i:i+4])[0]
      if data == constant:
        return True
  return False

def find_rom_funcs(rom, check_push=4):
  # Find thumb  branch instructions and record addresses.
  thfuncs = set()
  for i in range(0, len(rom)-4, 2):
    off = decode_thumb_bl(i, rom[i:i+4])
    if off is not None and off > 0 and off < len(rom):
      if check_push:
        if is_func_prologue(rom[off:off+16], 0, check_push):
          thfuncs.add(off)
      else:
        thfuncs.add(off)

  return thfuncs

def find_rtc_func(rom):
  thfuncs = find_rom_funcs(rom)

  ret = {}
  for c in thfuncs:
    if (constant_in_range(rom, c, DATA_RANGE, 0x080000C4) and
        constant_in_range(rom, c, DATA_RANGE, 0x080000C6)):

      fnend = find_bx(rom, c) + 2

      # Find some hallmarks of SiiRTC functions via emulation

      def readrom(addr):
        romaddr = (addr & 0x1FFFFFF)
        if romaddr + 4 <= len(rom):
          return struct.unpack("<I", rom[romaddr: romaddr+4])[0]
        return None

      def store_hook_callback(user_data, write_size, instr, address, value):
        if address == 0x080000C4 and value == 0x1 and user_data["seq"] == 0:
          user_data["seq"] = 1
        elif address == 0x080000C4 and value == 0x5 and user_data["seq"] == 1:
          user_data["seq"] = 2
        elif address == 0x080000C6 and value == 0x7 and user_data["seq"] == 2:
          user_data["seq"] = 3

      usr_data = {"seq": 0, "mov": []}
      def stcb(*args): store_hook_callback(usr_data, *args)
      cpust = arm.CPUState(EMU_STCK - 128)
      ex = arm.InstExecutor(cpust, store_cb=stcb)
      for j in range(c, fnend, 2):
        op = struct.unpack("<H", rom[j:j+2])[0]
        ex.addinst(arm.ThumbInst(ex, ROM_ADDR + j, op, readrom))
        # Inst mov rX, 0x6Y  (2XII)
        if op & 0xF8F0 == 0x2060:
          usr_data["mov"].append(op & 0xFF)
      ex.execute()
      if usr_data["seq"] >= 2 and usr_data["mov"]:
        # This can be several SiiRTC functions, we identify them by command ID.
        opmap = {
          0x60: "reset",
          0x62: "setstatus",
          0x63: "getstatus",
          0x64: "setdatetime",
          0x65: "getdatetime",
          0x66: "settime",
          0x67: "gettime",
          0x68: "getalarm",
          0x69: "setalarm",
        }
        ops = [opmap[x] for x in usr_data["mov"]]
        if len(ops) > 1:
          if "reset" in ops and "setstatus" in ops:
            ops = ["reset"]    # Reset calls set status, might be inlined
          else:
            ops = []

        if ops:
          ret[c] = (ops[0], fnend - c)

  # Find RTC probe, usually calls getstatus, reset, and gettime
  for c in thfuncs:
    fnend = find_bx(rom, c) + 2

    missing = set({"getstatus", "reset", "gettime"})
    for i in range(c, fnend-4, 2):
      off = decode_thumb_bl(i, rom[i:i+4])
      if off is not None and off > 0 and off < len(rom):
        if off in ret:
          if ret[off][0] in missing:
            missing.remove(ret[off][0])

    if len(missing) <= 1:
      ret[c] = ("probe", fnend - c)

  return {v[0]: (k, v[1]) for k,v in ret.items()}

def process_rom(rom, **kwargs):
  # Add ROM and index by gamecode/version
  gcode = rom[0x0AC: 0x0B0].decode("ascii")
  grev = rom[0x0BC]

  if RTC_STRING not in rom:
    return None

  fns = find_rtc_func(rom)
  fns = {k: {"addr": hex(v[0]), "size": v[1]} for k,v in fns.items()}

  if "reset" in fns and "getdatetime" in fns and "getstatus" in fns:
    targets = {
      "getstatus_fn": fns["getstatus"],
      "gettimedate_fn": fns["getdatetime"],
      "gettime_fn": fns["gettime"],
      "reset_fn": fns["reset"],
    }
    if "probe" in fns:
      targets["probe_fn"] = fns["probe"]

    return ({
      "filesize": len(rom),
      "sha256": hashlib.sha256(rom).hexdigest(),
      "sha1": hashlib.sha1(rom).hexdigest(),
      "md5": hashlib.md5(rom).hexdigest(),
      "game-code": gcode,
      "game-version": grev,
      "targets": {
        "rtc": targets
      }
    })


