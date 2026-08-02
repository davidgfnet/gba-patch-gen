#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

import os, sys, multiprocessing, tqdm, json, functools
import patchtool.save

def wrapper(f, savetypes_db):
  ret = patchtool.save.process_rom(open(f, "rb").read(), savetypesdb=savetypes_db)
  if ret is None:
    return None

  finfo = {
    "filename": os.path.basename(f),
  }
  return ret | finfo

if __name__ == "__main__":
  savetypes_db = []
  if len(sys.argv) > 2:
    for fn in sys.argv[2:]:
      savetypes_db.append(json.loads(open(fn).read()))

  flist = []
  for root, dirs, files in os.walk(sys.argv[1], topdown=False):
    for name in files:
      f = os.path.join(root, name)
      if f.endswith(".gba"):
        flist.append(f)

  with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
    patches = list(tqdm.tqdm(p.imap(functools.partial(wrapper, savetypes_db=savetypes_db), flist), total=len(flist)))

  patches = filter(lambda x: x, patches)
  patches = sorted(patches, key=lambda x:x["filename"])

  print(json.dumps(patches, indent=2, sort_keys=True))

