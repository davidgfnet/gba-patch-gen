#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>

# Merges a list of patch files into a single file.
# Performs some sanity checks to ensure the output file is correct.
# The output is indexed on game-code + game-version, which requires
# non-contradictory information (unless the merge can be resolved).

import sys, os, json, argparse, pprint

parser = argparse.ArgumentParser(prog='patch_merge')
parser.add_argument('--input', dest='inpatches', nargs='+', help='Input JSON file containing the patches')
parser.add_argument('--outfile', dest='outfile', required=True, help='Output path for the database')

args = parser.parse_args()

WAITCNT_PATCH_TYPES = frozenset([
  "str8-thumb", "str16-thumb", "str32-thumb",
  "str8-arm", "str16-arm", "str32-arm",
  "word32",
  "swi1-arm", "swi1-bl-thumb"
])

def waitcnt_merge(a, b):
  # Merge and deduplicate patches
  ret = a["patch-sites"] + b["patch-sites"]
  ret = [dict(x) for x in set([tuple(x.items()) for x in ret])]
  return {
    "patch-sites": sorted(ret, key=lambda x: int(x["inst-offset"], 16))
  }

def layout_merge(a, b):
  # Pick a restrictive merge (perhaps a bit too restrictive)
  return {
    "info": {
      "tail-padding": min( a["info"]["tail-padding"], b["info"]["tail-padding"] ),
      "subheaders": sorted(set(a["info"]["subheaders"] + b["info"]["subheaders"])),
      "holes": [] if a["info"]["holes"] != b["info"]["holes"] else a["info"]["holes"],
    }
  }

MERGE_FUNCTIONS = {
  "waitcnt": waitcnt_merge,
  "layout":  layout_merge,
}

# Read all input patches. Games are indexed by Code and Version, but we might
# have multiple entries for each (ie. slightly different ROMs or revisions).
# In that case, it's ok to merge these duplicated entries as low as they are
# "equivalent", that is, their patches are identical or there's a merging
# function that can reconcile them.
patchset, conflicts, gcodes = [], [], set()
for fn in args.inpatches:
  p = json.load(open(fn, "r"))
  # Add info to the patch dict
  gameset = {}
  for e in p:
    key = (e["game-code"], e["game-version"])
    gcodes.add(key)
    if key not in gameset:
      gameset[key] = {
        "targets": e["targets"],
        "filesize": e.get("filesize", None),
        "files": [],
      }
    else:
      for tt, ti in e["targets"].items():
        if tt in gameset[key]:
          # If they are identical, just do nothing.
          if gameset[key][tt] != ti:
            # Attempt to merge or fail.
            if tt in MERGE_FUNCTIONS:
              gameset[key][tt] = MERGE_FUNCTIONS[tt](gameset[key][tt], ti)
            else:
              conflicts.append((key, tt, gameset[key][tt], ti))
        else:
          gameset[key][tt] = ti

    if e.get("filesize", None) != None:
      if "filesize" in gameset[key]:
        assert gameset[key]["filesize"] == e["filesize"]
      gameset[key]["filesize"] = e["filesize"]

    if "filename" in e:
      gameset[key]["files"].append({
        "filename": e["filename"],
        "sha256": e["sha256"]
      })

  patchset.append(gameset)

if conflicts:
  pprint.pprint(conflicts)
  raise ValueError()


# Perform patch-set merging. WaitCNT patches are merged toghether whereas other
# patch types are not allowed to be merged.

conflicts, outp = [], []
for key in sorted(gcodes):
  # Check that file sets are identical, and extract the file set
  fsets, fs = set(), None
  for pset in patchset:
    if key in pset:
      if "files" in pset[key] and pset[key]["files"]:
        fsets.add(tuple(sorted(tuple(sorted(x.items())) for x in pset[key]["files"])))
      if pset[key].get("filesize"):
        fs = pset[key]["filesize"]

  if len(fsets) > 1:
    conflicts.append((key, fsets))
  fsets = sorted([dict(x) for x in list(fsets)[0]], key=lambda x:x["filename"])

  # Go ahead and extract all patch-sets by type.
  patchmap = {}
  for pset in patchset:
    if key in pset:
      for ttype, tinfo in pset[key]["targets"].items():
        if ttype in patchmap:
          if ttype in MERGE_FUNCTIONS:
            patchmap[ttype] = MERGE_FUNCTIONS[ttype](patchmap[ttype], tinfo)
          else:
            conflicts.append("Duplicate entry " + ttype + " for " + str(key) + ": " + str(tinfo))
        else:
          patchmap[ttype] = tinfo

  # Sanity check, ensure we do not have two patches for the same offset!
  if "waitcnt" in patchmap:
    if len(patchmap["waitcnt"]["patch-sites"]) != len(set([x["inst-offset"] for x in patchmap["waitcnt"]["patch-sites"]])):
      raise ValueError("Duplicate patch-site entry for waitcnt " + str(patchmap))
    if any(x["inst-type"] not in WAITCNT_PATCH_TYPES for x in patchmap["waitcnt"]["patch-sites"]):
      raise ValueError("Unknown patch-type for waitcnt " + str(patchmap))

  outp.append({
    "game-code": key[0],
    "game-version": key[1],
    "files": fsets,
    "romsize": fs,
    "targets": patchmap,
  })

if conflicts:
  pprint.pprint(conflicts)
  raise ValueError()

outp = sorted(outp, key=lambda x:(x["game-code"], x["game-version"]))

open(args.outfile, "w").write(json.dumps(outp, indent=2))

