#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2025 David Guillen Fandos <david@davidgf.net>

import os, sys, multiprocessing, tqdm, json
import patchtool.symmap

rom_data = open(sys.argv[1], "rb").read()
sym_data = open(sys.argv[2], "rb").read().decode("utf-8")

ret = patchtool.symmap.process_rom(rom_data, sym=sym_data)

if ret is not None:
  ret.update({
    "filename": os.path.basename(sys.argv[1]),
  })

  print(json.dumps(ret, indent=2, sort_keys=True))

