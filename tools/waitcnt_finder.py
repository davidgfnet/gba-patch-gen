#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

import os, sys, multiprocessing, tqdm, json
import patchtool.waitcnt

flist = []
for root, dirs, files in os.walk(sys.argv[1], topdown=False):
  for name in files:
    f = os.path.join(root, name)
    if f.endswith(".gba"):
      flist.append(f)

def wrapper(f):
  finfo = {
    "filename": os.path.basename(f),
  }
  return finfo | patchtool.waitcnt.process_rom(open(f, "rb").read())

with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
  results = list(tqdm.tqdm(p.imap(wrapper, flist), total=len(flist)))

results = sorted(results, key=lambda x:x["filename"])

print(json.dumps(results, indent=2))

