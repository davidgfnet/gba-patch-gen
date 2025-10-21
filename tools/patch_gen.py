#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

# Given a full unified patch set, generate raw patches in several formats:
#  - JSON: For human inspection
#  - Patch-Database: To use with SuperFW as loadable patch DB
#  - Py: To manually and locally patch ROMs

import patchtool.generator
import json, struct

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
    struct.pack("<B", len(pg)) + pg for pg in patchtool.generator.PROGRAMS)
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
  import sys, argparse, string, time

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
    fpatches[key] = patchtool.generator.GamePatch(key[0], key[1], c["targets"], c["romsize"])

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
      ofd.write(json.dumps(serp, indent=2, sort_keys=True))

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
      for pg in patchtool.generator.PROGRAMS:
        ofd.write("  b'" + "".join('\\x%02x' % c for c in pg) + "',\n")
      ofd.write(']\n\n')

      ofd.write('PATCHES = %s\n\n' % json.dumps(serp, indent=2, sort_keys=True))

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

