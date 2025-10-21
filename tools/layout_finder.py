#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

import os, sys, multiprocessing, tqdm, json
import patchtool.layout

flist = []
for root, dirs, files in os.walk(sys.argv[1], topdown=False):
  for name in files:
    f = os.path.join(root, name)
    if f.endswith(".gba"):
      if os.path.getsize(f) > 4*1024*1024:
        flist.append(f)

def wrapper(f):
  finfo = {
    "filename": os.path.basename(f),
  }
  return finfo | patchtool.layout.process_rom(open(f, "rb").read())

with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
  findings = list(tqdm.tqdm(p.imap(wrapper, flist), total=len(flist)))

findings = sorted(findings, key=lambda x:x["filename"])

print(json.dumps(findings, indent=2, sort_keys=True))

