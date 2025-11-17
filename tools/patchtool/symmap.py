#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2025 David Guillen Fandos <david@davidgf.net>

# Automatic Save and RTC patch detector and generator.
# Uses a symbol map as input to find save and RTC functions directly.

import struct, re, hashlib
import patchtool.save

# Function names we do care about:
rtc_names = {
  "SiiRtcProbe": "probe_fn",
  "SiiRtcReset": "reset_fn",
  "SiiRtcGetStatus": "getstatus_fn",
  "SiiRtcGetDateTime": "gettimedate_fn",
}

flash_names = {
  "ReadFlashId": "ident",
  "ReadFlash": "read",
  "VerifyFlashSector": "verify",
  "VerifyFlashSectorNBytes": "verify",
}
flash_prefixes = {
  "ProgramFlashSector_": "writesect",
  "ProgramFlashByte_": "writebyte",
  "EraseFlashChip_": "erasefull",
  "EraseFlashSector_": "erasesect",
}

flash_req = frozenset(["ident", "read", "verify", "writesect", "erasefull", "erasesect"])

def process_rom(rom, **kwargs):
  if kwargs.get("sym", None) is None:
    return None

  # Add ROM and index by gamecode/version
  gcode = rom[0x0AC: 0x0B0].decode("ascii")
  grev = rom[0x0BC]

  rtc_info = {}
  flash_info = {}

  # Attempt to parse the symbol file. Format should be like:
  # 080003a4 g 0000015c AgbMain
  for line in kwargs["sym"].split("\n"):
    m = re.match(r"([0-9A-Fa-f]+)\s[a-zA]\s([0-9A-Fa-f]+)\s([^\s]+)", line)
    if m:
      addr = int(m.group(1), 16)
      size = int(m.group(2), 16)
      fnam = m.group(3)

      if (addr >> 25) == 0x4:    # It's in ROM space
        if fnam in rtc_names:
          rtc_info[rtc_names[fnam]] = {
            "addr": hex(addr & 0x1FFFFFF),
            "size": size,
          }
        if fnam in flash_names:
          flash_info[flash_names[fnam]] = flash_info.get(flash_names[fnam], []) + [
          {
            "addr": hex(addr & 0x1FFFFFF),
            "size": size,
          }]
        for pfx, mname in flash_prefixes.items():
          if fnam.startswith(pfx):
            flash_info[mname] = flash_info.get(mname, []) + [
            {
              "addr": hex(addr & 0x1FFFFFF),
              "size": size,
            }]

  targets = {}
  if rtc_info:
    targets["rtc"] = rtc_info

  # Ensure we have full and proper flash info.
  if flash_info:
    if all(x in flash_info for x in flash_req):
      tab = patchtool.save.find_flash_tables(rom, check_funcs=False)
      flash_info["flash-size"] = max(x['flash_size'] for x in tab)
      targets["flash"] = {
        "target-info": flash_info,
      }

  return ({
    "filesize": len(rom),
    "sha256": hashlib.sha256(rom).hexdigest(),
    "sha1": hashlib.sha1(rom).hexdigest(),
    "md5": hashlib.md5(rom).hexdigest(),
    "game-code": gcode,
    "game-version": grev,
    "targets": targets
  })

