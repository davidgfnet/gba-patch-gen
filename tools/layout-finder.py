#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

# Find ROM space to insert patches for ROMs that are 32MB in size.
# Also find some space/holes to place trampolines in smaller roms.

from tqdm import tqdm
import sys, os, struct, json, re, hashlib, multiprocessing

MBYTE = 1048576
LOGOBYTES = (b'\x24\xff\xae\x51\x69\x9a\xa2\x21' +
             b'\x3d\x84\x82\x0a\x84\xe4\x09\xad' +
             b'\x11\x24\x8b\x98\xc0\x81\x7f\x21' +
             b'\xa3\x52\xbe\x19\x93\x09\xce\x20' +
             b'\x10\x46\x4a\x4a\xf8\x27\x31\xec' +
             b'\x58\xc7\xe8\x33\x82\xe3\xce\xbf' +
             b'\x85\xf4\xdf\x94\xce\x4b\x09\xc1' +
             b'\x94\x56\x8a\xc0\x13\x72\xa7\xfc' +
             b'\x9f\x84\x4d\x73\xa3\xca\x9a\x61' +
             b'\x58\x97\xa3\x27\xfc\x03\x98\x76' +
             b'\x23\x1d\xc7\x61\x03\x04\xae\x56' +
             b'\xbf\x38\x84\x00\x40\xa7\x0e\xfd' +
             b'\xff\x52\xfe\x03\x6f\x95\x30\xf1' +
             b'\x97\xfb\xc0\x85\x60\xd6\x80\x25' +
             b'\xa9\x63\xbe\x03\x01\x4e\x38\xe2' +
             b'\xf9\xa2\x34\xff\xbb\x3e\x03\x44' +
             b'\x78\x00\x90\xcb\x88\x11\x3a\x94' +
             b'\x65\xc0\x7c\x63\x87\xf0\x3c\xaf' +
             b'\xd6\x25\xe4\x8b\x38\x0a\xac\x72' +
             b'\x21\xd4\xf8\x07')
HDR_BACKSIZE = 64*1024
HDR_FWDSIZE = 1024*1024

flist = []
for root, dirs, files in os.walk(sys.argv[1], topdown=False):
  for name in files:
    f = os.path.join(root, name)
    if f.endswith(".gba"):
      if os.path.getsize(f) > 4*1024*1024:
        flist.append(f)

def find_eeprom(rom):
  variants = [
    b"EEPROM_V111", b"EEPROM_V120",
    b"EEPROM_V121", b"EEPROM_V122",
    b"EEPROM_V124", b"EEPROM_V125",
    b"EEPROM_V126"
  ]

  for v in variants:
    if rom.find(v) >= 0:
      return True
  return False


def process_rom(f):
  with open(f, "rb") as ifd:
    rom = ifd.read()

    skipend = False
    if len(rom) >= 32*1024*1024:
      # Check for EEPROM ROM dumps
      skipend = find_eeprom(rom)

    # Check the padding space at the end.
    start = 256 if skipend else 0
    v = rom[-start - 1]
    for i in range(len(rom) - start - 1, 0, -1):
      if rom[i] != v:
        break
    tailspace = len(rom) - i

    # Try to find some useful holes.
    holes = []
    i = 0
    while True:
      i = rom[:-tailspace].find(b'\x00' * 128 * 1024, i)
      if i < 0:
        break
      # Check how long the hole is.
      for j in range(i + 128 * 1024, len(rom)):
        if rom[j] != 0:
          break
      holes.append((i, j-i))
      i = j
    while True:
      i = rom[:-tailspace].find(b'\xff' * 128 * 1024, i)
      if i < 0:
        break
      # Check how long the hole is.
      for j in range(i + 128 * 1024, len(rom)):
        if rom[j] != 0xff:
          break
      holes.append((i, j-i))
      i = j

    # Try to find other headers (for other ROMs and/or multiboot)
    # They are usually aligned and have a bunch of free space before them
    header_offsets = []
    pos = len(LOGOBYTES)
    while pos < len(rom):
      pos = rom.find(LOGOBYTES, pos + 4)
      if pos < 0:
        break

      spos = pos - 4
      # Find aligned-ish locations that are not at the very end.
      if (spos & 0x7FFF) == 0 and len(rom) - spos > HDR_FWDSIZE:
        bopc = struct.unpack("<I", rom[spos:spos+4])[0]
        # Validate the branch (first instruction)
        if bopc >> 24 in [0xEA, 0xEB]:
          # Has some valid title (ASCII)
          if all(c < 0x80 for c in rom[spos+0xA0 : spos+0xB2]):
            # Has some padding space right before
            if spos > HDR_BACKSIZE:
              if (all(c == 0x00 for c in rom[spos-HDR_BACKSIZE : spos]) or
                  all(c == 0xFF for c in rom[spos-HDR_BACKSIZE : spos])):
                header_offsets.append(spos)

    # Add ROM and index by gamecode/version
    gcode = rom[0x0AC: 0x0B0].decode("ascii")
    grev = rom[0x0BC]
    return ({
      "filename": os.path.basename(f),
      "filesize": len(rom),
      "sha256": hashlib.sha256(rom).hexdigest(),
      "game-code": gcode,
      "game-version": grev,
      "targets": {
        "layout": {
          "info": {
            "tail-padding": tailspace,
            "holes": holes,
            "subheaders": header_offsets,
          }
        }
      }
    })

with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
  findings = list(tqdm(p.imap(process_rom, flist), total=len(flist)))

findings = filter(lambda x: x, findings)
findings = sorted(findings, key=lambda x:x["filename"])

print(json.dumps(findings, indent=2))

