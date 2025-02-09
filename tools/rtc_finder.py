#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

import os, sys, multiprocessing, tqdm, json
import patchtool.rtc

flist = []
for root, dirs, files in os.walk(sys.argv[1], topdown=False):
  for name in files:
    f = os.path.join(root, name)
    if f.endswith(".gba"):
      flist.append(f)

def wrapper(f):
  ret = patchtool.rtc.process_rom(open(f, "rb").read())
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

