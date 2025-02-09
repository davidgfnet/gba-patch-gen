#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

# Automatic RTC patch detector and genertor.
# We aim to detect certain functions that handle the SII (S-3511A)
# RTC device, mapped via GPIO registers.
#
# We use signatures, since the functions we want to capture are rather simple
#
# Use pypy to run this, it's 20x faster than regular python :)

import struct, re, hashlib

# Having some issues with regexes and overlapping matches and whatnot
def match_insts(data, mseq):
  initseq = mseq[:mseq.index(None)]
  initm = b"".join(struct.pack("<H", x) for x in initseq)
  ret = []
  off = 0
  while True:
    off = data.find(initm, off)
    if off < 0:
      break
    if all(mseq[j] is None or mseq[j] == (data[off+j*2] | (data[off+j*2+1] << 8)) for j in range(len(mseq))):
      ret.append(off)
    off += 2
  return ret

siirtc_probe_fn = [
  0xb580,       # push {r7, lr}
  0xb084,       # sub sp, #16
  0x466f,       # mov r7, sp
  0x1d39,       # adds r1, r7, #4
  0x1c08,       # adds r0, r1, #0
  0xf000, None, # bl off
  0x0601,       # lsls r1, r0, #24
  0x0e08,       # lsrs r0, r1, #24
  0x2800,       # cmp r0, #0
  None,         # bne.n off
  0x2000,       # movs    r0, #0
]

siirtc_getstatus_fn = [
  0xb590,       # push {r4, r7, lr}
  0xb082,       # sub sp, #8
  0x466f,       # mov r7, sp
  0x6038,       # str r0, [r7, #0]
  0x4802,       # ldr r0, [pc, #8]
  0x7801,       # ldrb r1, [r0, #0]
  0x2901,       # cmp r1, #1
  None,         # bne.n off
  0x2000,       # movs r0, #0
  None,         # b.n off
  None, None,   # [pool data]
  None,         # ldr r0, [pc, #X]
  0x2101,       # movs r1, #1
  0x7001,       # strb r1, [r0, #0]
  None,         # ldr r0, [pc, #X]
  0x2101,       # movs r1, #1
  0x8001,       # strh r1, [r0, #0]
  None,         # ldr r0, [pc, #X]
  0x2105,       # movs r1, #5
  0x8001,       # strh r1, [r0, #0]
  # Need lots of insts, since setstatus is very similar
  None,         # ldr r0, [pc, #X]
  0x2107,       # movs r1, #7
  0x8001,       # strh r1, [r0, #0]
]

siirtc_getdatetime_fn = [
  0xb580,       # push {r7, lr}
  0xb082,       # sub sp, #8
  0x466f,       # mov r7, sp
  0x6038,       # str r0, [r7, #0]
  0x4802,       # ldr r0, [pc, #8]
  0x7801,       # ldrb r1, [r0, #0]
  0x2901,       # cmp r1, #1
  None,         # bne.n off
  0x2000,       # movs r0, #0
  None,         # b.n off
  None, None,   # [pool data]
  None,         # ldr r0, [pc, #X]
  0x2101,       # movs r1, #1
  0x7001,       # strb r1, [r0, #0]
  None,         # ldr r0, [pc, #X]
  0x2101,       # movs r1, #1
  0x8001,       # strh r1, [r0, #0]
  None,         # ldr r0, [pc, #X]
  0x2105,       # movs r1, #5
  0x8001,       # strh r1, [r0, #0]
  None,         # ldr r0, [pc, #X]
  0x2107,       # movs r1, #7
  0x8001,       # strh r1, [r0, #0]
  0x2065,       # movs r0, #101   # This distinguishes set/get
]

siirtc_reset_fn = [
  0xb580,       # push {r7, lr}
  0xb084,       # sub sp, #16
  0x466f,       # mov r7, sp
  0x4803,       # ldr r0, [pc, #12]
  0x7801,       # ldrb r1, [r0, #0]
  0x2901,       # cmp r1, #1
  None,         # bne.n off
  0x2000,       # movs r0, #0
]


RTC_STRING = b"SIIRTC_V001"

# Finds all matches for a buffer and a substring
def regexfinder(buf, seq):
  return [hex(x) for x in match_insts(buf, seq)]

def process_rom(rom):
  # Add ROM and index by gamecode/version
  gcode = rom[0x0AC: 0x0B0].decode("ascii")
  grev = rom[0x0BC]

  if RTC_STRING not in rom:
    return None

  probe_tgt = regexfinder(rom, siirtc_probe_fn)
  getst_tgt = regexfinder(rom, siirtc_getstatus_fn)
  gettd_tgt = regexfinder(rom, siirtc_getdatetime_fn)
  reset_tgt = regexfinder(rom, siirtc_reset_fn)
  if len(probe_tgt) != 1 or len(getst_tgt) != 1 or len(gettd_tgt) != 1 or len(reset_tgt) != 1:
    return None

  targets = {
    "probe_fn": probe_tgt[0],
    "getstatus_fn": getst_tgt[0],
    "gettimedate_fn": gettd_tgt[0],
    "reset_fn": reset_tgt[0],
  }

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
    ret = process_rom(open(f, "rb").read())
    if ret is None:
      return None

    finfo = {
      "filename": os.path.basename(f),
    }
    return ret | finfo

  with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
    patches = list(tqdm.tqdm(p.imap(wrapper, flist), total=len(flist)))

  patches = filter(lambda x: x, patches)
  patches = sorted(patches, key=lambda x:x["filename"])

  print(json.dumps(patches, indent=2))

