#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Qt GUI for the patch generator
#
# Two programs in one file. Invoked as `main.py --worker ROM --outdir DIR` it
# processes a single ROM and writes a single .patch; invoked with no arguments
# it opens a window and drives a pool of those workers over QProcess, one
# process per ROM, cpu_count() in flight.
#
# Splitting the work across processes keeps the UI responsive and contains
# crashes to a single row. The Qt import sits below the worker dispatch on
# purpose: workers exit before reaching it, so a full pool costs no Qt memory.

import json, os, struct, sys, traceback

PTYPES = ["waitcnt", "irq", "swi1", "save", "layout", "rtc", "symmap"]


# Worker bits

def emit(obj):
  sys.stdout.write(json.dumps(obj) + "\n")
  sys.stdout.flush()


def run_all(rom, sym, types, progresscb=None):
  """Run every requested finder. Each is isolated, so one exploding pass does
     not cost us the others -- the web UI gets this free from separate workers."""
  import importlib

  results, errors = {}, {}
  for i, t in enumerate(types):
    def cb(frac, i=i):
      if progresscb:
        progresscb((i + frac) / len(types))

    try:
      mod = importlib.import_module("patchtool." + t)
      results[t] = mod.process_rom(rom, sym=sym, progresscb=cb)
    except Exception:
      errors[t] = traceback.format_exc()

    if progresscb:
      progresscb((i + 1) / len(types))

  return results, errors


def merge(rom, results):
  """Trivial merge: only one ROM involved, so no reconciliation needed.
     SWI1 folds into WAITCNT; symmap wins over everything (ptype order)."""
  # SWI1 patches are WAITCNT patches found via a different route, and both
  # report them under targets["waitcnt"] -- so fold rather than let the update()
  # below clobber one with the other. If waitcnt is missing entirely, swi1 is
  # left in place and supplies those targets on its own.
  if (results.get("swi1") is not None and results.get("waitcnt") is not None):
    results["waitcnt"]["targets"]["waitcnt"]["patch-sites"] += \
        results["swi1"]["targets"]["waitcnt"]["patch-sites"]
    del results["swi1"]

  # Straight from the ROM header. Every finder also reports these, but there is
  # no reason to depend on any particular one having survived.
  merged = {
    "game-code": rom[0xAC:0xB0].decode("ascii"),
    "game-version": rom[0xBC],
    "files": [],
    "romsize": len(rom),
    "targets": {},
  }
  # Merge in ptype order so later types override earlier ones.
  for t in PTYPES:
    if results.get(t) is not None:
      merged["targets"].update(results[t]["targets"])

  return merged


def pack(merged):
  """Build a .patch file (SUPERFWPATCHV01), not a PatchDB."""
  import patchtool.generator

  gp = patchtool.generator.GamePatch(
      merged["game-code"], merged["game-version"],
      merged["targets"], merged["romsize"])

  hinfo = gp.layout_patches()[0] if gp.layout_patches() else 0

  hdr = b"SUPERFWPATCHV01\x00"
  hdr += struct.pack("<BBBBBxIxxxxxx",
                     len(gp.waitcnt_patches()),
                     len(gp.save_patches()),
                     gp.save_type,
                     len(gp.irq_patches()),
                     len(gp.rtc_patches()),
                     hinfo)

  for prgn in range(4):
    prg = patchtool.generator.PROGRAMS[prgn]
    hdr += struct.pack("<I", len(prg)) + prg + (b"\x00" * (60 - len(prg)))

  content = b"".join(struct.pack("<I", x) for x in (
      gp.waitcnt_patches() + gp.save_patches() +
      gp.irq_patches() + gp.rtc_patches()))
  content += (b"\x00" * (512 - len(content)))

  return hdr + content


def worker_main(argv):
  """Emits line-delimited JSON on stdout:
       {"progress": 0.42}
       {"ok": true, "out": "/path/rom.patch", "errors": {...}}
       {"ok": false, "error": "traceback..."}"""
  import argparse

  ap = argparse.ArgumentParser(prog="main.py --worker")
  ap.add_argument("rom")
  ap.add_argument("--sym", default=None, help="Optional symbol map file")
  ap.add_argument("--outdir", required=True)
  ap.add_argument("--types", default=",".join(PTYPES))
  args = ap.parse_args(argv)

  try:
    rom = open(args.rom, "rb").read()
    sym = open(args.sym, "r").read() if args.sym else None

    types = [t for t in args.types.split(",") if t in PTYPES]

    # Coalesce progress so we don't flood the pipe with near-identical values.
    last = [-1.0]
    def progress(frac):
      if frac - last[0] >= 0.01:
        last[0] = frac
        emit({"progress": frac})

    results, errors = run_all(rom, sym, types, progress)
    blob = pack(merge(rom, results))

    base = os.path.basename(args.rom)
    stem = base.rsplit(".", 1)[0] if "." in base else base
    out = os.path.join(args.outdir, stem + ".patch")
    with open(out, "wb") as f:
      f.write(blob)

    emit({"ok": True, "out": out, "errors": errors})
    return 0

  except Exception:
    emit({"ok": False, "error": traceback.format_exc()})
    return 1


# Bail out before importing Qt. Everything below is GUI-only.
if __name__ == "__main__" and sys.argv[1:2] == ["--worker"]:
  sys.exit(worker_main(sys.argv[2:]))


# GUI

from PySide6.QtCore import QProcess, Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QMainWindow, QMenu, QMessageBox, QProgressBar, QPushButton,
    QStyle, QStyleOptionProgressBar, QStyledItemDelegate, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget)

HERE = os.path.dirname(os.path.abspath(__file__))
COL_CODE, COL_VER, COL_FILE, COL_PROG = range(4)


def worker_argv():
  """How to re-invoke ourselves as a worker. Frozen builds have no script on
     disk, so the exe takes the flag directly."""
  if getattr(sys, "frozen", False):
    return [sys.executable, "--worker"]
  return [sys.executable, os.path.abspath(__file__), "--worker"]


def rom_header(path):
  """Game code (0xAC) and version (0xBC). Cheap enough to do inline on add."""
  try:
    with open(path, "rb") as f:
      hdr = f.read(0xC0)
    return hdr[0xAC:0xB0].decode("ascii", "replace"), str(hdr[0xBC])
  except Exception:
    return "?", "?"


class ProgressDelegate(QStyledItemDelegate):
  """Draws a native progress bar in the last column."""

  def paint(self, painter, option, index):
    frac, label = index.data(Qt.UserRole) or (0.0, "")
    opt = QStyleOptionProgressBar()
    opt.rect = option.rect.adjusted(3, 3, -3, -3)
    opt.minimum, opt.maximum = 0, 100
    opt.progress = int(frac * 100)
    opt.text = label
    opt.textVisible = True
    QApplication.style().drawControl(QStyle.CE_ProgressBar, opt, painter)


class MainWindow(QMainWindow):

  def __init__(self):
    super().__init__()
    self.setWindowTitle("GBA Patch Generator")
    self.resize(820, 460)
    self.setAcceptDrops(True)

    self.jobs = []          # [{path, sym, frac, label, state}], index == row
    self.outdir = None
    self.pending = []       # row indices queued for processing
    self.running = {}       # QProcess -> row index
    self.slots = os.cpu_count() or 4
    self.argv = worker_argv()

    self.table = QTableWidget(0, 4)
    self.table.setHorizontalHeaderLabels(["Code", "Ver", "File", "Progress"])
    self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
    self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    self.table.setItemDelegateForColumn(COL_PROG, ProgressDelegate(self))
    self.table.setContextMenuPolicy(Qt.CustomContextMenu)
    self.table.customContextMenuRequested.connect(self.context_menu)
    hh = self.table.horizontalHeader()
    hh.setSectionResizeMode(COL_FILE, QHeaderView.Stretch)
    for c in (COL_CODE, COL_VER, COL_PROG):
      hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)

    act = QAction("Remove", self)
    act.setShortcut(QKeySequence.Delete)
    act.triggered.connect(self.remove_selected)
    self.table.addAction(act)

    self.b_add = QPushButton("Add ROMs...")
    self.b_out = QPushButton("Output dir...")
    self.b_run = QPushButton("Process")
    self.b_add.clicked.connect(self.add_dialog)
    self.b_out.clicked.connect(self.pick_outdir)
    self.b_run.clicked.connect(self.start)

    self.status = QLabel("No output directory selected")
    self.total = QProgressBar()
    self.total.setTextVisible(False)

    bar = QHBoxLayout()
    for w in (self.b_add, self.b_out, self.b_run):
      bar.addWidget(w)
    bar.addStretch()

    lay = QVBoxLayout()
    lay.addLayout(bar)
    lay.addWidget(self.table)
    lay.addWidget(self.total)
    lay.addWidget(self.status)

    central = QWidget()
    central.setLayout(lay)
    self.setCentralWidget(central)
    self.sync()

  # ---- job list ----

  def add_paths(self, paths):
    have = {j["path"] for j in self.jobs}
    for p in paths:
      p = os.path.abspath(p)
      if p in have or not p.lower().endswith(".gba"):
        continue
      # Pick up an adjacent symbol map automatically, if there is one.
      sym = next((c for c in (p + ".sym", p.rsplit(".", 1)[0] + ".sym")
                  if os.path.exists(c)), None)
      self.jobs.append({"path": p, "sym": sym, "frac": 0.0,
                        "label": "Queued", "state": "queued"})
      have.add(p)
    self.rebuild()

  def add_dialog(self):
    paths, _ = QFileDialog.getOpenFileNames(
        self, "Select GBA ROMs", "", "GBA ROMs (*.gba);;All files (*)")
    self.add_paths(paths)

  def remove_selected(self):
    if self.running:
      return
    rows = {i.row() for i in self.table.selectedIndexes()}
    self.jobs = [j for n, j in enumerate(self.jobs) if n not in rows]
    self.rebuild()

  def context_menu(self, pos):
    if not self.table.selectedIndexes():
      return
    menu = QMenu(self)
    menu.addAction("Remove", self.remove_selected).setEnabled(not self.running)
    menu.exec(self.table.viewport().mapToGlobal(pos))

  def rebuild(self):
    self.table.setRowCount(len(self.jobs))
    for row, j in enumerate(self.jobs):
      code, ver = rom_header(j["path"])
      for col, text in ((COL_CODE, code), (COL_VER, ver),
                        (COL_FILE, os.path.basename(j["path"]))):
        item = QTableWidgetItem(text)
        if col == COL_FILE:
          item.setToolTip(j["path"] + ("  [+sym]" if j["sym"] else ""))
        self.table.setItem(row, col, item)
      self.table.setItem(row, COL_PROG, QTableWidgetItem())
      self.paint_row(row)
    self.sync()

  def paint_row(self, row):
    j = self.jobs[row]
    item = self.table.item(row, COL_PROG)
    if item:
      item.setData(Qt.UserRole, (j["frac"], j["label"]))

  def sync(self):
    busy = bool(self.running or self.pending)
    self.b_run.setEnabled(bool(self.jobs) and bool(self.outdir) and not busy)
    self.b_add.setEnabled(not busy)
    self.b_out.setEnabled(not busy)
    done = sum(1 for j in self.jobs if j["state"] in ("done", "error"))
    self.total.setMaximum(max(1, len(self.jobs)))
    self.total.setValue(done)
    if not self.outdir:
      self.status.setText("No output directory selected")
    elif busy:
      self.status.setText("Processing %d/%d -> %s"
                          % (done, len(self.jobs), self.outdir))
    else:
      self.status.setText("%d ROM(s), output: %s" % (len(self.jobs), self.outdir))

  # ---- drag & drop ----

  def dragEnterEvent(self, e):
    if e.mimeData().hasUrls() and not self.running:
      e.acceptProposedAction()

  def dropEvent(self, e):
    self.add_paths([u.toLocalFile() for u in e.mimeData().urls()])

  # ---- processing ----

  def pick_outdir(self):
    d = QFileDialog.getExistingDirectory(self, "Select output directory")
    if d:
      self.outdir = d
      self.sync()

  def start(self):
    for j in self.jobs:
      j.update(frac=0.0, label="Queued", state="queued")
    for row in range(len(self.jobs)):
      self.paint_row(row)
    self.pending = list(range(len(self.jobs)))
    self.sync()
    self.fill_slots()

  def fill_slots(self):
    while self.pending and len(self.running) < self.slots:
      self.spawn(self.pending.pop(0))
    if not self.pending and not self.running:
      self.finish()

  def spawn(self, row):
    j = self.jobs[row]
    argv = self.argv[1:] + [j["path"], "--outdir", self.outdir]
    if j["sym"]:
      argv += ["--sym", j["sym"]]

    proc = QProcess(self)
    proc.setProcessChannelMode(QProcess.SeparateChannels)
    # patchtool lives in tools/ next to us when running from a checkout.
    env = proc.processEnvironment()
    tools = os.path.join(os.path.dirname(HERE), "tools")
    if os.path.isdir(tools):
      env.insert("PYTHONPATH", tools + os.pathsep + env.value("PYTHONPATH", ""))
    proc.setProcessEnvironment(env)

    proc.setProperty("buf", "")
    proc.readyReadStandardOutput.connect(lambda p=proc: self.on_output(p))
    proc.finished.connect(lambda code, st, p=proc: self.on_finished(p, code))

    self.running[proc] = row
    j.update(label="Running", state="running")
    self.paint_row(row)
    proc.start(self.argv[0], argv)

  def on_output(self, proc):
    row = self.running.get(proc)
    if row is None:
      return
    buf = proc.property("buf") + bytes(proc.readAllStandardOutput()).decode(
        "utf-8", "replace")
    lines = buf.split("\n")
    proc.setProperty("buf", lines.pop())

    j = self.jobs[row]
    for line in lines:
      line = line.strip()
      if not line:
        continue
      try:
        msg = json.loads(line)
      except ValueError:
        continue
      if "progress" in msg:
        j["frac"] = msg["progress"]
        j["label"] = "%d%%" % int(msg["progress"] * 100)
      elif msg.get("ok"):
        j.update(frac=1.0, state="done",
                 label="Done" + (" (partial)" if msg.get("errors") else ""))
        j["errors"] = msg.get("errors") or {}
      else:
        j.update(frac=0.0, state="error", label="Error")
        j["errors"] = {"fatal": msg.get("error", "unknown")}
    self.paint_row(row)

  def on_finished(self, proc, code):
    row = self.running.pop(proc, None)
    if row is not None and self.jobs[row]["state"] == "running":
      # Died without reporting: crash, OOM, bad invocation.
      err = bytes(proc.readAllStandardError()).decode("utf-8", "replace")
      self.jobs[row].update(frac=0.0, state="error", label="Crashed",
                            errors={"fatal": err or "exit code %d" % code})
      self.paint_row(row)
    proc.deleteLater()
    self.sync()
    self.fill_slots()

  def finish(self):
    self.sync()
    bad = [j for j in self.jobs if j["state"] == "error"]
    partial = [j for j in self.jobs if j.get("errors") and j["state"] == "done"]
    if not bad and not partial:
      return
    lines = []
    for j in bad + partial:
      for t, tb in j.get("errors", {}).items():
        lines.append("%s [%s]:\n%s" % (os.path.basename(j["path"]), t, tb))
    box = QMessageBox(self)
    box.setIcon(QMessageBox.Warning)
    box.setWindowTitle("Finished with problems")
    box.setText("%d failed, %d generated with missing patch types."
                % (len(bad), len(partial)))
    box.setDetailedText("\n\n".join(lines))
    box.exec()


def main():
  app = QApplication(sys.argv)
  win = MainWindow()
  win.show()
  return app.exec()


if __name__ == "__main__":
  sys.exit(main())

