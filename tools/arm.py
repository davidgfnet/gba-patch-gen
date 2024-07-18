#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>
#
# Not so minimal ARM decoder and "symbolic" emulator.
# Can emulate most thumb/arm instructions and supports "unknown" values in
# registers and memory. Doesn't support flag calculation nor branch/flow insts
# (at least properly).

import copy, heapq

def asr32(val, amount):
  if amount == 0:
    return val
  elif amount >= 31:
    if val & 0x80000000:
      return 0xFFFFFFFF
    else:
      return 0
  else:
    if val & 0x80000000:
      top = ((1 << amount) - 1)
      return (val >> amount) | (top << (32 - amount))
    else:
      return val >> amount

def add32(x, y): return (x + y) & 0xFFFFFFFF
def sub32(x, y): return (x - y) & 0xFFFFFFFF
def rsb32(x, y): return (y - x) & 0xFFFFFFFF

MEM_IDX_PRE = 0
MEM_IDX_PRE_WB = 1
MEM_IDX_POST_WB = 2

MEM_POST_DEC = 0
MEM_POST_INC = 1
MEM_PRE_DEC  = 2
MEM_PRE_INC  = 3

REG_SP = 13
REG_LR = 14
REG_PC = 15

# Executor helper that can use backtracking to analyze different execution paths.
#
# When a resetting inst is met (usually BX) the path finishes there and
# schedules an initial restart from the next PC.
class InstExecutor(object):
  def __init__(self, initial_state):
    self._init_state = initial_state
    self._insts = []
    self._exec_queue = []
    self._entry_queue = [0]

  def addinst(self, inst):
    self._insts.append(inst)
    self._start_pc = self._insts[0]._pc
    self._end_pc   = self._insts[-1]._pc

  def execute(self):
    assert len(self._insts) > 0

    # Execute blocks as long as they exist.
    ret = []
    while self._exec_queue or self._entry_queue:
      # Cover all paths until no more paths exist
      while self._exec_queue:
        off, state = self._exec_queue[0]
        self._exec_queue = self._exec_queue[1:]
        # Execute all the instructions starting at the specified offset
        for i in range(off, len(self._insts)):
          r = self._insts[i].execute(state)
          if self._insts[i].target_patch:
            ret.append((self._insts[i].target_patch, self._insts[i]._pc))
          if r == True:
            break    # Stop running, this is a terminal instruction.

      if self._entry_queue:
        # Insert a new path with an initial state
        off = heapq.heappop(self._entry_queue)
        # Remove duplicates, a bit of a hack for lack of unique heaps.
        while self._entry_queue and self._entry_queue[0] == off:
          heapq.heappop(self._entry_queue)

        self._exec_queue.append((off, copy.deepcopy(self._init_state)))

    return ret

  def queue_execution(self, start_pc, state):
    # It might be that the PC is out of range
    for i in range(0, len(self._insts)):
      if self._insts[i]._pc == start_pc:
        self._exec_queue.append((i, copy.deepcopy(state)))
        return True
    return False

  # Queues a new starting point (with initial state) at a certain PC
  def queue_startpoint(self, start_pc):
    # It might be that the PC is out of range
    for i in range(0, len(self._insts)):
      if self._insts[i]._pc == start_pc:
        heapq.heappush(self._entry_queue, i)
        return True
    return False

# Holds CPU state as well as some limited memory state (ie. stack pushes)
class CPUState(object):
  def __init__(self, sp_ptr):
    self._ispptr = sp_ptr
    self._branch_state = {}
    self.reset()

  def reset(self):
    self.memmap = {}
    self.regs = [None] * 16
    self.regs[REG_SP] = self._ispptr

  def regreset(self, rl):
    for rn in rl:
      self.regs[rn] = None

  def snapshot_branch(self, target_pc):
    self._branch_state[target_pc] = {
      "regs": copy.deepcopy(self.regs),
      "memm": copy.deepcopy(self.memmap),
    }

  def snapshot_reset(self, next_pc):
    # If we have a branch pointing to the next_pc, we restore that state
    if next_pc in self._branch_state:
      self.regs   = self._branch_state[next_pc]["regs"]
      self.memmap = self._branch_state[next_pc]["memm"]
    else:
      self.reset()

  def _load_data(self, addr, sz):
    ret = 0
    for i, a in enumerate(range(addr, addr+sz)):
      if a not in self.memmap or self.memmap[a] is None:
        return None
      ret = ret | (self.memmap[a] << (i * 8))
    return ret

  def _store_data(self, addr, value, sz):
    if value is None:
      for i, a in enumerate(range(addr, addr+sz)):
        self.memmap[a] = None
    else:
      for i, a in enumerate(range(addr, addr+sz)):
        self.memmap[a] = (value >> (i*8)) & 0xFF

  def load_word(self, addr):
    return self._load_data(addr, 4)

  def load_halfword(self, addr):
    return self._load_data(addr, 2)

  def load_byte(self, addr):
    return self._load_data(addr, 1)

  def store_word(self, addr, value):
    return self._store_data(addr, value, 4)

  def store_halfword(self, addr, value):
    return self._store_data(addr, value, 2)

  def store_byte(self, addr, value):
    return self._store_data(addr, value, 1)

# Decodes and emulates Thumb instructions
class ThumbInst(object):
  def __init__(self, executor, pc, opcode, romcb):
    self._executor = executor
    self._opcode = opcode
    self._pc = pc
    self._emu = lambda _ : None
    self._loadromcb = romcb        # ROM reading callback
    self.target_patch = False

    if (opcode >> 11) == 0:       # LSL
      self._emu = self._emu_shift_imm
      self._shf = lambda x, y: (x << y) & 0xFFFFFFFF
    elif (opcode >> 11) == 1:     # LSR
      self._emu = self._emu_shift_imm
      self._shf = lambda x, y: x >> y
    elif (opcode >> 11) == 2:     # ASR
      self._emu = self._emu_shift_imm
      self._shf = asr32

    elif (opcode >> 9) == 0xC:     # Add rd, rs, rn
      self._emu = self._emu_op3
      self._op3 = lambda x, y: (x + y) & 0xFFFFFFFF
    elif (opcode >> 9) == 0xD:     # Sub rd, rs, rn
      self._emu = self._emu_op3
      self._op3 = lambda x, y: (x - y) & 0xFFFFFFFF
    elif (opcode >> 9) == 0xE:     # Add rd, rs, imm
      self._emu = self._emu_op2imm
      self._op3 = lambda x, y: (x + y) & 0xFFFFFFFF
    elif (opcode >> 9) == 0xF:     # Sub rd, rs, imm
      self._emu = self._emu_op2imm
      self._op3 = lambda x, y: (x - y) & 0xFFFFFFFF

    elif (opcode >> 11) == 0x4:     # MOV reg, imm8
      self._emu = self._emu_movimm8
    elif (opcode >> 11) == 0x5:     # CMP reg, imm8
      self._emu = self._emu_cmpimm8
    elif (opcode >> 11) == 0x6:     # ADD reg, imm8
      self._emu = self._emu_addimm8
    elif (opcode >> 11) == 0x7:     # SUB reg, imm8
      self._emu = self._emu_subimm8

    elif (opcode >> 8) == 0x44:     # ADDhi rd, rs
      self._emu = self._emu_addhi
    elif (opcode >> 8) == 0x45:     # CMPhi rd, rs
      self._emu = self._emu_cmphi
    elif (opcode >> 8) == 0x46:     # MOVhi rd, rs
      self._emu = self._emu_movhi

    elif (opcode >> 11) == 0x14:    # ADD reg, pc, imm
      self._emu = self._emu_addpc
    elif (opcode >> 11) == 0x15:    # ADD reg, sp, imm
      self._emu = self._emu_addsp

    elif (opcode >> 10) == 0x2C:    # ADD sp, +/- imm
      self._emu = self._emu_adjsp


    elif (opcode >> 11) == 9:      # LDR reg, [pc+imm]
      self._emu = self._emu_loadpcrel

    elif (opcode >> 9) == 0x2B:    # LDSB rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._load_cb = self._load_sbyte
    elif (opcode >> 9) == 0x2C:    # LDR rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._load_cb = self._load_word
    elif (opcode >> 9) == 0x2D:    # LDRH rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._load_cb = self._load_halfword
    elif (opcode >> 9) == 0x2E:    # LDRB rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._load_cb = self._load_byte
    elif (opcode >> 9) == 0x2F:    # LDSH rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._load_cb = self._load_shalfword


    elif (opcode >> 11) == 0xD:    # LDR rd, [rb+imm]
      self._emu = self._emu_ldimm
      self._imm = self.imm5() * 4
      self._load_cb = self._load_word
    elif (opcode >> 11) == 0xF:    # LDRB rd, [rb+imm]
      self._emu = self._emu_ldimm
      self._imm = self.imm5()
      self._load_cb = self._load_byte
    elif (opcode >> 11) == 0x11:   # LDRH rd, [rb+imm]
      self._emu = self._emu_ldimm
      self._imm = self.imm5() * 2
      self._load_cb = self._load_halfword

    elif (opcode >> 9) == 0x28:    # STR rd, [rb+ro]
      self._emu = self._emu_st2r
      self._store_cb = self._store_word
    elif (opcode >> 9) == 0x29:    # STRH rd, [rb+ro]
      self._emu = self._emu_st2r
      self._store_cb = self._store_halfword
    elif (opcode >> 9) == 0x2A:    # STRB rd, [rb+ro]
      self._emu = self._emu_st2r
      self._store_cb = self._store_byte

    elif (opcode >> 11) == 0xC:     # STR rd, [rb+imm]
      self._emu = self._emu_stimm
      self._imm = self.imm5() * 4
      self._store_cb = self._store_word
    elif (opcode >> 11) == 0xE:     # STRB rd, [rb+imm]
      self._emu = self._emu_stimm
      self._imm = self.imm5()
      self._store_cb = self._store_byte
    elif (opcode >> 11) == 0x10:    # STRH rd, [rb+imm]
      self._emu = self._emu_stimm
      self._imm = self.imm5() * 2
      self._store_cb = self._store_halfword

    elif (opcode >> 11) == 0x12:    # STR reg, [sp + imm]
      self._emu = self._emu_strsp
      self._imm = self.imm8() * 4
      self._store_cb = self._store_word
    elif (opcode >> 11) == 0x13:    # LDR reg, [sp + imm]
      self._emu = self._emu_ldrsp
      self._imm = self.imm8() * 4
      self._load_cb = self._load_word

    elif (opcode >> 6) == 0x100:     # AND rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: x & y
    elif (opcode >> 6) == 0x101:     # XOR rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: x ^ y
    elif (opcode >> 6) == 0x102:     # LSL rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: (x << y) & 0xFFFFFFFF
    elif (opcode >> 6) == 0x103:     # LSR rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: (x >> y) & 0xFFFFFFFF
    elif (opcode >> 6) == 0x104:     # ASR rd, rs
      self._emu = self._op2bin
      self._op2 = asr32
    elif (opcode >> 6) == 0x105:     # ADC rd, rs
      self._emu = self._op2unk
    elif (opcode >> 6) == 0x106:     # SBC rd, rs
      self._emu = self._op2unk
    elif (opcode >> 6) == 0x107:     # ROR rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: ((x >> (y & 31)) | (x << (32 - (y & 31)))) & 0xFFFFFFFF
    elif (opcode >> 6) == 0x108:     # TST rd, rs
      self._emu = self._op2nop
    elif (opcode >> 6) == 0x109:     # NEG rd, rs
      self._emu = self._op2unary
      self._op2 = lambda x: (~x + 1) & 0xFFFFFFFF
    elif (opcode >> 6) == 0x10A:     # CMP rd, rs
      self._emu = self._op2nop
    elif (opcode >> 6) == 0x10B:     # CMN rd, rs
      self._emu = self._op2nop
    elif (opcode >> 6) == 0x10C:     # ORR rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: x | y
    elif (opcode >> 6) == 0x10D:     # MUL rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: (x * y) & 0xFFFFFFFF
    elif (opcode >> 6) == 0x10E:     # BIC rd, rs
      self._emu = self._op2bin
      self._op2 = lambda x, y: (x & (~y)) & 0xFFFFFFFF
    elif (opcode >> 6) == 0x10F:     # MVN rd, rs
      self._emu = self._op2unary
      self._op2 = lambda x: (~x) & 0xFFFFFFFF

    elif (opcode >> 9) == 0x5A:     # PUSH reglist [+lr]
      self._emu = self._push_regs
      self._rlist = self.imm8() | (0x4000 if opcode & 0x100 else 0)
    elif (opcode >> 9) == 0x5E:     # POP reglist [+pc]
      self._emu = self._pop_regs
      self._rlist = self.imm8() | (0x8000 if opcode & 0x100 else 0)

    elif (opcode >> 11) == 0x18:     # STMIA
      self._emu = self._stmia
    elif (opcode >> 11) == 0x19:     # LDMIA
      self._emu = self._ldmia

    elif (opcode >> 8) == 0x47:
      self._emu = self._reset_bx      # BX rX
    elif (opcode >> 12) == 0xD:
      if (opcode >> 8) == 0xDF:
        self._emu = self._reset_swi   # SWI
      else:
        self._emu = self._reset_condbranch  # B{COND} branch
    elif (opcode >> 11) == 0x1C:
      self._emu = self._reset_branch  # B offset

    elif (opcode >> 11) == 0x1E:
      # BL with low word label
      self._emu = self._bl_low
    elif (opcode >> 11) == 0x1F:
      # BL with high word label
      self._emu = self._bl_jump
    else:
      self._emu = self._badinst

  def execute(self, cpustate):
    return self._emu(cpustate)

  # Decoder
  def rd(self):  return self._opcode & 7

  def rd8(self): return (self._opcode >> 8) & 7

  def ro(self):  return (self._opcode >> 6) & 7

  def rn(self):  return (self._opcode >> 6) & 7

  def rb(self):  return (self._opcode >> 3) & 7

  def rs(self):  return (self._opcode >> 3) & 7

  def rdhi(self):return ((self._opcode >> 4) & 0x08) | (self._opcode & 0x07)

  def rshi(self):return ((self._opcode >> 3) & 0x0F)

  def imm3(self):return (self._opcode >> 6) & 0x7

  def imm5(self):return (self._opcode >> 6) & 0x1F

  def imm8(self):return self._opcode & 0xFF

  def imm71(self):
    if self._opcode & 0x80:
      return -(self._opcode & 0x7F)
    return self._opcode & 0x7F

  def cbr_offset(self):
    return (self._opcode & 0xFF) << 1

  def abr_offset(self):
    v = (self._opcode & 0x000007FF) << 1
    if v & 0x00000800:
      v |= 0xFFFFF000
    return v

  # Callbacks
  def _load_word(self, st, addr):
    return st.load_word(addr)

  def _load_halfword(self, st, addr):
    return st.load_halfword(addr)

  def _load_shalfword(self, st, addr):
    val = st.load_halfword(addr)
    if val is None:
      return None
    if val & 0x8000:
      return 0xFFFF0000 | val
    return val

  def _load_byte(self, st, addr):
    return st.load_byte(addr)

  def _load_sbyte(self, st, addr):
    val = st.load_byte(addr)
    if val is None:
      return None
    if val & 0x80:
      return 0xFFFFFF00 | val
    return val

  def _store_word(self, st, addr, value):
    if addr == 0x04000204:   # Writing 206 as well seems common in some games
      self.target_patch = "str32"
    return st.store_word(addr, value)

  def _store_halfword(self, st, addr, value):
    if addr == 0x04000204:
      self.target_patch = "str16"
    return st.store_halfword(addr, value)

  def _store_byte(self, st, addr, value):
    if (addr & ~1) == 0x04000204:
      if not self._susp_memop:
        self.target_patch = "str8"
    return st.store_byte(addr, value)

  def _badinst(self, st):
    self._executor.queue_startpoint(self._pc + 2)
    return True   # Terminal inst

  def _bl_low(self, st):
    # TODO implement!
    # st.regs[REG_LR] = self._pc + 4 + inst.abr_offset_hi();
    pass

  def _bl_jump(self, st):
    # TODO implement this as a proper branch (ie. like cond branches)
    st.regs[REG_LR] = (self._pc + 2) | 1

    # Assume a regular call, just wipe some registers and continue
    st.regreset([0,1,2,3])

  # Emulation routines!
  def _reset_bx(self, st):
    # See ARM (_bx_msr) for more info
    if st.regs[REG_LR] == self._pc + 2:
      st.regreset([0,1,2,3])
    else:
      self._executor.queue_startpoint(self._pc + 2)
      return True

  def _reset_branch(self, st):
    # Generate an alternative path with the current state
    # (for forward branches only)
    tgt_pc = self._pc + self.abr_offset() + 4
    if tgt_pc > self._pc:
      self._executor.queue_execution(tgt_pc, st)

    # Next code block can be started from anew
    self._executor.queue_startpoint(self._pc + 2)
    return True  # Stop here

  def _reset_condbranch(self, st):
    # Snapshot to track jumps (forward only)
    st.snapshot_branch(self._pc + self.cbr_offset() + 4)

  def _reset_swi(self, st):
    st.regreset([0,1,2,3])   # Treat like a function call

  def _emu_loadpcrel(self, st):
    # Uses the ROM read callback to load the known contant/data
    addr = (self._pc & ~3) + self.imm8() * 4 + 4
    st.regs[self.rd8()] = self._loadromcb(addr)

  def _emu_ld2r(self, st):
    rb = st.regs[self.rb()]
    ro = st.regs[self.ro()]
    if rb is None or ro is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._load_cb(st, rb + ro)

  def _emu_ldimm(self, st):
    rb = st.regs[self.rb()]
    if rb is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._load_cb(st, rb + self._imm)

  def _emu_st2r(self, st):
    rb = st.regs[self.rb()]
    ro = st.regs[self.ro()]
    rd = st.regs[self.rd()]
    # Operations using the same reg (ie. rX+rX) are likely to be garbage data.
    self._susp_memop = self.rb() == self.ro()
    if rb is not None and ro is not None:
      self._store_cb(st, rb + ro, rd)

  def _push_regs(self, st):
    if st.regs[REG_SP] is not None:
      for i in range(16):
        if self._rlist & (1 << i):
          st.regs[REG_SP] -= 4
          addr = st.regs[REG_SP] & ~3
          self._store_word(st, addr, st.regs[i])

  def _pop_regs(self, st):
    if st.regs[REG_SP] is not None:
      for i in range(16):
        if self._rlist & (1 << i):
          addr = st.regs[REG_SP] & ~3
          st.regs[i] = self._load_word(st, addr)
          st.regs[REG_SP] += 4
    else:
      for i in range(16):
        if self._rlist & (1 << i):
          st.regs[i] = None

    # Treat Pop {PC} like a branch (ie BX)
    if self._rlist & 0x8000:
      self._executor.queue_startpoint(self._pc + 2)
      return True

  def _stmia(self, st):
    pass

  def _ldmia(self, st):
    pass

  def _emu_ldrsp(self, st):
    if st.regs[REG_SP] is None:
      st.regs[self.rd8()] = None
    else:
      st.regs[self.rd8()] = self._load_cb(st, st.regs[REG_SP] + self._imm)

  def _emu_strsp(self, st):
    if st.regs[REG_SP] is not None:
      self._store_cb(st, st.regs[REG_SP] + self._imm, st.regs[self.rd8()])

  def _emu_stimm(self, st):
    rb = st.regs[self.rb()]
    rd = st.regs[self.rd()]
    # Byte writes usually use 0/1 offsets.
    self._susp_memop = self._imm >= 2
    if rb is not None:
      self._store_cb(st, rb + self._imm, rd)

  def _emu_shift_imm(self, st):
    rs = st.regs[self.rs()]
    if rs is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._shf(rs, self.imm5())

  def _emu_op3(self, st):
    rs = st.regs[self.rs()]
    rn = st.regs[self.rn()]
    if rs is None or rn is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._op3(rs, rn)

  def _emu_op2imm(self, st):
    rs = st.regs[self.rs()]
    if rs is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._op3(rs, self.imm3())

  def _emu_movimm8(self, st):
    st.regs[self.rd8()] = self.imm8()

  def _emu_cmpimm8(self, st):
    pass

  def _emu_addimm8(self, st):
    rs = st.regs[self.rd8()]
    if rs is not None:
      st.regs[self.rd8()] = (rs + self.imm8()) & 0xFFFFFFFF

  def _emu_subimm8(self, st):
    rs = st.regs[self.rd8()]
    if rs is not None:
      st.regs[self.rd8()] = (rs - self.imm8()) & 0xFFFFFFFF

  def _emu_addhi(self, st):
    ra = st.regs[self.rshi()]
    rb = st.regs[self.rdhi()]
    if ra is None or rb is None:
      st.regs[self.rdhi()] = None
    else:
      st.regs[self.rdhi()] = (ra + rb) & 0xFFFFFFFF

  def _emu_cmphi(self, st):
    pass

  def _emu_movhi(self, st):
    st.regs[self.rdhi()] = st.regs[self.rshi()]

  def _emu_addpc(self, st):
    st.regs[self.rd8()] = ((self._pc & ~3) + 4 + self.imm8() * 4) & 0xFFFFFFFF

  def _emu_addsp(self, st):
    if st.regs[REG_SP] is None:
      st.regs[self.rd8()] = None
    else:
      st.regs[self.rd8()] = (st.regs[REG_SP] + self.imm8() * 4) & 0xFFFFFFFF

  def _emu_adjsp(self, st):
    if st.regs[REG_SP] is not None:
      st.regs[REG_SP] = (st.regs[REG_SP] + self.imm71() * 4) & 0xFFFFFFFF

  def _op2nop(self, st):
    pass

  def _op2unk(self, st):
    st.regs[self.rd()] = None

  def _op2bin(self, st):
    rs = st.regs[self.rs()]
    rd = st.regs[self.rd()]
    if rs is None or rd is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._op2(rs, rd)

  def _op2unary(self, st):
    rs = st.regs[self.rs()]
    if rs is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._op2(rs)


class ARMInst(object):
  def __init__(self, executor, pc, opcode, romcb):
    self._executor = executor
    self._opcode = opcode
    self._pc = pc
    self._emu = lambda _ : None
    self._loadromcb = romcb
    self.target_patch = False

    self._cond = (opcode >> 28) & 0xF

    if self._cond == 0xF:
      self._emu = self._badinst
      return

    op8 = (opcode >> 20) & 0xFF

    if op8 < 32:
      if (opcode & 0x90) == 0x90:
        eop = ((op8 & 31) << 2) | ((opcode >> 5) & 3)
        ops = [
          (self._mulop32,        None,        None           ),   # MUL rd, rm, rs
          (self._emust_halfword, self._mregm, MEM_IDX_POST_WB),   # STRH rd, [rn], -rm
          (self._mulop32,        None,        None           ),   # MUL rd, rm, rs
          (self._emust_halfword, self._mregm, MEM_IDX_POST_WB),   # STRH rd, [rn], -rm

          (self._mulop32,        None,        None           ),   # MULS rd, rm, rs
          (self._emuld_halfword, self._mregm, MEM_IDX_POST_WB),   # LDRH rd, [rn], -rm
          (self._emuld_sbyte,    self._mregm, MEM_IDX_POST_WB),   # LDRSB rd, [rn], -rm
          (self._emuld_shalfword,self._mregm, MEM_IDX_POST_WB),   # LDRSH rd, [rn], -rm

          (self._mlaop32,        None,        None           ),   # MLA rd, rm, rs, rn
          (self._emust_halfword, self._mregm, MEM_IDX_POST_WB),   # STRH rd, [rn], -rm
          (self._mlaop32,        None,        None           ),   # MLA rd, rm, rs, rn
          (self._emust_halfword, self._mregm, MEM_IDX_POST_WB),   # STRH rd, [rn], -rm

          (self._mlaop32,        None,        None           ),   # MLAS rd, rm, rs, rn
          (self._emuld_halfword, self._mregm, MEM_IDX_POST_WB),   # LDRH rd, [rn], -rm
          (self._emuld_sbyte,    self._mregm, MEM_IDX_POST_WB),   # LDRSB rd, [rn], -rm
          (self._emuld_shalfword,self._mregm, MEM_IDX_POST_WB),   # LDRSH rd, [rn], -rm

          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm
          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm
          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm
          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._mimm8, MEM_IDX_POST_WB),   # LDRH rd, [rn], -imm
          (self._emuld_sbyte,    self._mimm8, MEM_IDX_POST_WB),   # LDRSB rd, [rn], -imm
          (self._emuld_shalfword,self._mimm8, MEM_IDX_POST_WB),   # LDRSH rd, [rn], -imm

          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm
          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm
          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm
          (self._emust_halfword, self._mimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], -imm

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._mimm8, MEM_IDX_POST_WB),   # LDRH rd, [rn], -imm
          (self._emuld_sbyte,    self._mimm8, MEM_IDX_POST_WB),   # LDRSB rd, [rn], -imm
          (self._emuld_shalfword,self._mimm8, MEM_IDX_POST_WB),   # LDRSH rd, [rn], -imm


          (self._mulop64u,       None,        None           ),   # UMULL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pregm, MEM_IDX_POST_WB),   # STRH rd, [rn], +rm
          (self._mulop64u,       None,        None           ),   # UMULL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pregm, MEM_IDX_POST_WB),   # STRH rd, [rn], +rm

          (self._mulop64u,       None,        None           ),   # UMULLS rdlo, rdhi, rm, rs
          (self._emuld_halfword, self._pregm, MEM_IDX_POST_WB),   # LDRH rd, [rn], +rm
          (self._emuld_sbyte,    self._pregm, MEM_IDX_POST_WB),   # LDRSB rd, [rn], +rm
          (self._emuld_shalfword,self._pregm, MEM_IDX_POST_WB),   # LDRSH rd, [rn], +rm

          (self._mlaop64u,       None,        None           ),   # UMLAL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pregm, MEM_IDX_POST_WB),   # STRH rd, [rn], +rm
          (self._mlaop64u,       None,        None           ),   # UMLAL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pregm, MEM_IDX_POST_WB),   # STRH rd, [rn], +rm

          (self._mlaop64u,       None,        None           ),   # UMLALS rdlo, rdhi, rm, rs
          (self._emuld_halfword, self._pregm, MEM_IDX_POST_WB),   # LDRH rd, [rn], +rm
          (self._emuld_sbyte,    self._pregm, MEM_IDX_POST_WB),   # LDRSB rd, [rn], +rm
          (self._emuld_shalfword,self._pregm, MEM_IDX_POST_WB),   # LDRSH rd, [rn], +rm

          (self._mulop64s,       None,        None           ),   # SMULL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], +imm
          (self._mulop64s,       None,        None           ),   # SMULL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], +imm

          (self._mulop64s,       None,        None           ),   # SMULLS rdlo, rdhi, rm, rs
          (self._emuld_halfword, self._pimm8, MEM_IDX_POST_WB),   # LDRH rd, [rn], +imm
          (self._emuld_sbyte,    self._pimm8, MEM_IDX_POST_WB),   # LDRSB rd, [rn], +imm
          (self._emuld_shalfword,self._pimm8, MEM_IDX_POST_WB),   # LDRSH rd, [rn], +imm

          (self._mlaop64s,       None,        None           ),   # SMLAL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], +imm
          (self._mlaop64s,       None,        None           ),   # SMLAL rdlo, rdhi, rm, rs
          (self._emust_halfword, self._pimm8, MEM_IDX_POST_WB),   # STRH rd, [rn], +imm

          (self._mlaop64s,       None,        None           ),   # SMLALS rdlo, rdhi, rm, rs
          (self._emuld_halfword, self._pimm8, MEM_IDX_POST_WB),   # LDRH rd, [rn], +imm
          (self._emuld_sbyte,    self._pimm8, MEM_IDX_POST_WB),   # LDRSB rd, [rn], +imm
          (self._emuld_shalfword,self._pimm8, MEM_IDX_POST_WB),   # LDRSH rd, [rn], +imm


          (self._swap32,         None,        None           ),   # SWP rd, rm, [rn]
          (self._emust_halfword, self._mregm, MEM_IDX_PRE    ),   # STRH rd, [rn - rm]
          (self._swap32,         None,        None           ),   # SWP rd, rm, [rn]
          (self._emust_halfword, self._mregm, MEM_IDX_PRE    ),   # STRH rd, [rn - rm]

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._mregm, MEM_IDX_PRE    ),   # LDRH rd, [rn - rm]
          (self._emuld_sbyte,    self._mregm, MEM_IDX_PRE    ),   # LDRSB rd, [rn - rm]
          (self._emuld_shalfword,self._mregm, MEM_IDX_PRE    ),   # LDRSH rd, [rn - rm]

          (self._emust_halfword, self._mregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn - rm]!
          (self._emust_halfword, self._mregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn - rm]!
          (self._emust_halfword, self._mregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn - rm]!
          (self._emust_halfword, self._mregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn - rm]!

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._mregm, MEM_IDX_PRE_WB ),   # LDRH rd, [rn - rm]!
          (self._emuld_sbyte,    self._mregm, MEM_IDX_PRE_WB ),   # LDRSB rd, [rn - rm]!
          (self._emuld_shalfword,self._mregm, MEM_IDX_PRE_WB ),   # LDRSH rd, [rn - rm]!

          (self._swap8,          None,        None           ),   # SWPB rd, rm, [rn]
          (self._emust_halfword, self._mimm8, MEM_IDX_PRE    ),   # STRH rd, [rn - imm]
          (self._swap8,          None,        None           ),   # SWPB rd, rm, [rn]
          (self._emust_halfword, self._mimm8, MEM_IDX_PRE    ),   # STRH rd, [rn - imm]

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._mimm8, MEM_IDX_PRE    ),   # LDRH rd, [rn - imm]
          (self._emuld_sbyte,    self._mimm8, MEM_IDX_PRE    ),   # LDRSB rd, [rn - imm]
          (self._emuld_shalfword,self._mimm8, MEM_IDX_PRE    ),   # LDRSH rd, [rn - imm]

          (self._emust_halfword, self._mimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn - imm]!
          (self._emust_halfword, self._mimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn - imm]!
          (self._emust_halfword, self._mimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn - imm]!
          (self._emust_halfword, self._mimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn - imm]!

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._mimm8, MEM_IDX_PRE_WB ),   # LDRH rd, [rn - imm]!
          (self._emuld_sbyte,    self._mimm8, MEM_IDX_PRE_WB ),   # LDRSB rd, [rn - imm]!
          (self._emuld_shalfword,self._mimm8, MEM_IDX_PRE_WB ),   # LDRSH rd, [rn - imm]!


          (self._emust_halfword, self._pregm, MEM_IDX_PRE    ),   # STRH rd, [rn + rm]
          (self._emust_halfword, self._pregm, MEM_IDX_PRE    ),   # STRH rd, [rn + rm]
          (self._emust_halfword, self._pregm, MEM_IDX_PRE    ),   # STRH rd, [rn + rm]
          (self._emust_halfword, self._pregm, MEM_IDX_PRE    ),   # STRH rd, [rn + rm]

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._pregm, MEM_IDX_PRE    ),   # LDRH rd, [rn + rm]
          (self._emuld_sbyte,    self._pregm, MEM_IDX_PRE    ),   # LDRSB rd, [rn + rm]
          (self._emuld_shalfword,self._pregm, MEM_IDX_PRE    ),   # LDRSH rd, [rn + rm]

          (self._emust_halfword, self._pregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn + rm]!
          (self._emust_halfword, self._pregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn + rm]!
          (self._emust_halfword, self._pregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn + rm]!
          (self._emust_halfword, self._pregm, MEM_IDX_PRE_WB ),   # STRH rd, [rn + rm]!

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._pregm, MEM_IDX_PRE_WB ),   # LDRH rd, [rn + rm]!
          (self._emuld_sbyte,    self._pregm, MEM_IDX_PRE_WB ),   # LDRSB rd, [rn + rm]!
          (self._emuld_shalfword,self._pregm, MEM_IDX_PRE_WB ),   # LDRSH rd, [rn + rm]!

          (self._emust_halfword, self._pimm8, MEM_IDX_PRE    ),   # STRH rd, [rn + imm]
          (self._emust_halfword, self._pimm8, MEM_IDX_PRE    ),   # STRH rd, [rn + imm]
          (self._emust_halfword, self._pimm8, MEM_IDX_PRE    ),   # STRH rd, [rn + imm]
          (self._emust_halfword, self._pimm8, MEM_IDX_PRE    ),   # STRH rd, [rn + imm]

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._pimm8, MEM_IDX_PRE    ),   # LDRH rd, [rn + imm]
          (self._emuld_sbyte,    self._pimm8, MEM_IDX_PRE    ),   # LDRSB rd, [rn + imm]
          (self._emuld_shalfword,self._pimm8, MEM_IDX_PRE    ),   # LDRSH rd, [rn + imm]

          (self._emust_halfword, self._pimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn + imm]!
          (self._emust_halfword, self._pimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn + imm]!
          (self._emust_halfword, self._pimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn + imm]!
          (self._emust_halfword, self._pimm8, MEM_IDX_PRE_WB ),   # STRH rd, [rn + imm]!

          (self._regop_nop,      None,        None           ),
          (self._emuld_halfword, self._pimm8, MEM_IDX_PRE_WB ),   # LDRH rd, [rn + imm]!
          (self._emuld_sbyte,    self._pimm8, MEM_IDX_PRE_WB ),   # LDRSB rd, [rn + imm]!
          (self._emuld_shalfword,self._pimm8, MEM_IDX_PRE_WB ),   # LDRSH rd, [rn + imm]!
        ]
        self._emu, self._opA, self._opB = ops[eop]
      else:
        ops = [
          (self._regop, lambda x, y : x & y), (self._regop, lambda x, y : x & y),   # AND
          (self._regop, lambda x, y : x ^ y), (self._regop, lambda x, y : x ^ y),   # XOR
          (self._regop, sub32              ), (self._regop, sub32              ),   # SUB
          (self._regop, rsb32              ), (self._regop, rsb32              ),   # RSB

          (self._regop, add32              ), (self._regop, add32              ),   # ADD
          (self._regop_unk, None           ), (self._regop_unk, None           ),   # ADC
          (self._regop_unk, None           ), (self._regop_unk, None           ),   # SBC
          (self._regop_unk, None           ), (self._regop_unk, None           ),   # RSC

          (self._regop_mrs, None           ), (self._regop_nop, None           ),   # MRS/TST
          (self._bx_msr, None              ), (self._regop_nop, None           ),   # MSR-BX/TEQ
          (self._regop_mrs_spsr, None      ), (self._regop_nop, None           ),   # MRS[SPSR]/CMP
          (self._spsr_wr, None             ), (self._regop_nop, None           ),   # SPSR/CMN

          (self._regop, lambda x, y : x | y), (self._regop, lambda x, y : x | y),   # ORR
          (self._regop_unary, lambda x : x ), (self._regop_unary, lambda x : x ),   # MOV
          (self._regop, lambda x, y : x & ~y), (self._regop, lambda x, y : x & ~y),   # BIC
          (self._regop_unary, lambda x : ~x), (self._regop_unary, lambda x : ~x),   # MVN
        ]
        self._emu, self._op = ops[op8]
    elif op8 < 64:
      ops = [
          (self._immop, lambda x, y : x & y), (self._immop, lambda x, y : x & y),   # AND
          (self._immop, lambda x, y : x ^ y), (self._immop, lambda x, y : x ^ y),   # XOR
          (self._immop, sub32              ), (self._immop, sub32              ),   # SUB
          (self._immop, rsb32              ), (self._immop, rsb32              ),   # RSB

          (self._immop, add32              ), (self._immop, add32              ),   # ADD
          (self._regop_unk, None           ), (self._regop_unk, None           ),   # ADC
          (self._regop_unk, None           ), (self._regop_unk, None           ),   # SBC
          (self._regop_unk, None           ), (self._regop_unk, None           ),   # RSC

          (self._regop_nop, None           ), (self._regop_nop, None           ),   # (MOVW)/TST
          (self._msr_imm, None             ), (self._regop_nop, None           ),   # MSR/TEQ
          (self._regop_nop, None           ), (self._regop_nop, None           ),   # (MOVT)/CMP
          (self._spsr_wr, None             ), (self._regop_nop, None           ),   # SPSR/CMN

          (self._immop, lambda x, y : x | y), (self._immop, lambda x, y : x | y),   # ORR
          (self._immop_unary, lambda x : x ), (self._immop_unary, lambda x : x ),   # MOV
          (self._immop, lambda x, y : x & ~y), (self._immop, lambda x, y : x & ~y),   # BIC
          (self._immop_unary, lambda x : ~x), (self._immop_unary, lambda x : ~x),   # MVN
        ]
      self._emu, self._op = ops[op8 - 32]
    elif op8 < 128:
      ops = [
          (self._store_word,      self._mimm12,       MEM_IDX_POST_WB),       # STR rd, [rn], -imm
          (self._load_word,       self._mimm12,       MEM_IDX_POST_WB),       # LDR rd, [rn], -imm
          (self._store_word,      self._mimm12,       MEM_IDX_POST_WB),       # STRT rd, [rn], -imm
          (self._load_word,       self._mimm12,       MEM_IDX_POST_WB),       # LDRT rd, [rn], -imm
          (self._store_byte,      self._mimm12,       MEM_IDX_POST_WB),       # STRB rd, [rn], -imm
          (self._load_byte,       self._mimm12,       MEM_IDX_POST_WB),       # LDRB rd, [rn], -imm
          (self._store_byte,      self._mimm12,       MEM_IDX_POST_WB),       # STRBT rd, [rn], -imm
          (self._load_byte,       self._mimm12,       MEM_IDX_POST_WB),       # LDRBT rd, [rn], -imm

          (self._store_word,      self._pimm12,       MEM_IDX_POST_WB),       # STR rd, [rn], +imm
          (self._load_word,       self._pimm12,       MEM_IDX_POST_WB),       # LDR rd, [rn], +imm
          (self._store_word,      self._pimm12,       MEM_IDX_POST_WB),       # STRT rd, [rn], +imm
          (self._load_word,       self._pimm12,       MEM_IDX_POST_WB),       # LDRT rd, [rn], +imm
          (self._store_byte,      self._pimm12,       MEM_IDX_POST_WB),       # STRB rd, [rn], +imm
          (self._load_byte,       self._pimm12,       MEM_IDX_POST_WB),       # LDRB rd, [rn], +imm
          (self._store_byte,      self._pimm12,       MEM_IDX_POST_WB),       # STRBT rd, [rn], +imm
          (self._load_byte,       self._pimm12,       MEM_IDX_POST_WB),       # LDRBT rd, [rn], +imm

          (self._store_word,      self._mimm12,           MEM_IDX_PRE),       # STR rd, [rn - imm]
          (self._load_word,       self._mimm12,           MEM_IDX_PRE),       # LDR rd, [rn - imm]
          (self._store_word,      self._mimm12,        MEM_IDX_PRE_WB),       # STR rd, [rn - imm]!
          (self._load_word,       self._mimm12,        MEM_IDX_PRE_WB),       # LDR rd, [rn - imm]!
          (self._store_byte,      self._mimm12,           MEM_IDX_PRE),       # STRB rd, [rn - imm]
          (self._load_byte,       self._mimm12,           MEM_IDX_PRE),       # LDRB rd, [rn - imm]
          (self._store_byte,      self._mimm12,        MEM_IDX_PRE_WB),       # STRB rd, [rn - imm]!
          (self._load_byte,       self._mimm12,        MEM_IDX_PRE_WB),       # LDRB rd, [rn - imm]!

          (self._store_word,      self._pimm12,           MEM_IDX_PRE),       # STR rd, [rn + imm]
          (self._load_word,       self._pimm12,           MEM_IDX_PRE),       # LDR rd, [rn + imm]
          (self._store_word,      self._pimm12,        MEM_IDX_PRE_WB),       # STR rd, [rn + imm]!
          (self._load_word,       self._pimm12,        MEM_IDX_PRE_WB),       # LDR rd, [rn + imm]!
          (self._store_byte,      self._pimm12,           MEM_IDX_PRE),       # STRB rd, [rn + imm]
          (self._load_byte,       self._pimm12,           MEM_IDX_PRE),       # LDRB rd, [rn + imm]
          (self._store_byte,      self._pimm12,        MEM_IDX_PRE_WB),       # STRB rd, [rn + imm]!
          (self._load_byte,       self._pimm12,        MEM_IDX_PRE_WB),       # LDRB rd, [rn + imm]!

          (self._store_word,      self._mregop,       MEM_IDX_POST_WB),       # STR rd, [rn], -regop
          (self._load_word,       self._mregop,       MEM_IDX_POST_WB),       # LDR rd, [rn], -regop
          (self._store_word,      self._mregop,       MEM_IDX_POST_WB),       # STRT rd, [rn], -regop
          (self._load_word,       self._mregop,       MEM_IDX_POST_WB),       # LDRT rd, [rn], -regop
          (self._store_byte,      self._mregop,       MEM_IDX_POST_WB),       # STRB rd, [rn], -regop
          (self._load_byte,       self._mregop,       MEM_IDX_POST_WB),       # LDRB rd, [rn], -regop
          (self._store_byte,      self._mregop,       MEM_IDX_POST_WB),       # STRBT rd, [rn], -regop
          (self._load_byte,       self._mregop,       MEM_IDX_POST_WB),       # LDRBT rd, [rn], -regop

          (self._store_word,      self._pregop,       MEM_IDX_POST_WB),       # STR rd, [rn], +regop
          (self._load_word,       self._pregop,       MEM_IDX_POST_WB),       # LDR rd, [rn], +regop
          (self._store_word,      self._pregop,       MEM_IDX_POST_WB),       # STRT rd, [rn], +regop
          (self._load_word,       self._pregop,       MEM_IDX_POST_WB),       # LDRT rd, [rn], +regop
          (self._store_byte,      self._pregop,       MEM_IDX_POST_WB),       # STRB rd, [rn], +regop
          (self._load_byte,       self._pregop,       MEM_IDX_POST_WB),       # LDRB rd, [rn], +regop
          (self._store_byte,      self._pregop,       MEM_IDX_POST_WB),       # STRBT rd, [rn], +regop
          (self._load_byte,       self._pregop,       MEM_IDX_POST_WB),       # LDRBT rd, [rn], +regop

          (self._store_word,      self._mregop,           MEM_IDX_PRE),       # STR rd, [rn - regop]
          (self._load_word,       self._mregop,           MEM_IDX_PRE),       # LDR rd, [rn - regop]
          (self._store_word,      self._mregop,        MEM_IDX_PRE_WB),       # STR rd, [rn - regop]!
          (self._load_word,       self._mregop,        MEM_IDX_PRE_WB),       # LDR rd, [rn - regop]!
          (self._store_byte,      self._mregop,           MEM_IDX_PRE),       # STRB rd, [rn - regop]
          (self._load_byte,       self._mregop,           MEM_IDX_PRE),       # LDRB rd, [rn - regop]
          (self._store_byte,      self._mregop,        MEM_IDX_PRE_WB),       # STRB rd, [rn - regop]!
          (self._load_byte,       self._mregop,        MEM_IDX_PRE_WB),       # LDRB rd, [rn - regop]!

          (self._store_word,      self._pregop,           MEM_IDX_PRE),       # STR rd, [rn + regop]
          (self._load_word,       self._pregop,           MEM_IDX_PRE),       # LDR rd, [rn + regop]
          (self._store_word,      self._pregop,        MEM_IDX_PRE_WB),       # STR rd, [rn + regop]!
          (self._load_word,       self._pregop,        MEM_IDX_PRE_WB),       # LDR rd, [rn + regop]!
          (self._store_byte,      self._pregop,           MEM_IDX_PRE),       # STRB rd, [rn + regop]
          (self._load_byte,       self._pregop,           MEM_IDX_PRE),       # LDRB rd, [rn + regop]
          (self._store_byte,      self._pregop,        MEM_IDX_PRE_WB),       # STRB rd, [rn + regop]!
          (self._load_byte,       self._pregop,        MEM_IDX_PRE_WB),       # LDRB rd, [rn + regop]!
      ]
      self._emu = self._emu_ld if op8 & 1 else self._emu_st
      self._memop, self._mem_op2, self._mem_bt = ops[op8 - 64]

    elif op8 < 160:
      ops = [
          (self._emu_stm, False, MEM_POST_DEC),       # STMDA rn, rlist
          (self._emu_ldm, False, MEM_POST_DEC),       # LDMDA rn, rlist
          (self._emu_stm,  True, MEM_POST_DEC),       # STMDA rn!, rlist
          (self._emu_ldm,  True, MEM_POST_DEC),       # LDMDA rn!, rlist
          (self._emu_stm, False, MEM_POST_DEC),       # STMDA rn, rlist^
          (self._emu_ldm, False, MEM_POST_DEC),       # LDMDA rn, rlist^
          (self._emu_stm,  True, MEM_POST_DEC),       # STMDA rn!, rlist^
          (self._emu_ldm,  True, MEM_POST_DEC),       # LDMDA rn!, rlist^

          (self._emu_stm, False, MEM_POST_INC),       # STMIA rn, rlist
          (self._emu_ldm, False, MEM_POST_INC),       # LDMIA rn, rlist
          (self._emu_stm,  True, MEM_POST_INC),       # STMIA rn!, rlist
          (self._emu_ldm,  True, MEM_POST_INC),       # LDMIA rn!, rlist
          (self._emu_stm, False, MEM_POST_INC),       # STMIA rn, rlist^
          (self._emu_ldm, False, MEM_POST_INC),       # LDMIA rn, rlist^
          (self._emu_stm,  True, MEM_POST_INC),       # STMIA rn!, rlist^
          (self._emu_ldm,  True, MEM_POST_INC),       # LDMIA rn!, rlist^

          (self._emu_stm, False, MEM_PRE_DEC),        # STMDB rn, rlist
          (self._emu_ldm, False, MEM_PRE_DEC),        # LDMDB rn, rlist
          (self._emu_stm,  True, MEM_PRE_DEC),        # STMDB rn!, rlist
          (self._emu_ldm,  True, MEM_PRE_DEC),        # LDMDB rn!, rlist
          (self._emu_stm, False, MEM_PRE_DEC),        # STMDB rn, rlist^
          (self._emu_ldm, False, MEM_PRE_DEC),        # LDMDB rn, rlist^
          (self._emu_stm,  True, MEM_PRE_DEC),        # STMDB rn!, rlist^
          (self._emu_ldm,  True, MEM_PRE_DEC),        # LDMDB rn!, rlist^

          (self._emu_stm, False, MEM_PRE_INC),        # STMIB rn, rlist
          (self._emu_ldm, False, MEM_PRE_INC),        # LDMIB rn, rlist
          (self._emu_stm,  True, MEM_PRE_INC),        # STMIB rn!, rlist
          (self._emu_ldm,  True, MEM_PRE_INC),        # LDMIB rn!, rlist
          (self._emu_stm, False, MEM_PRE_INC),        # STMIB rn, rlist^
          (self._emu_ldm, False, MEM_PRE_INC),        # LDMIB rn, rlist^
          (self._emu_stm,  True, MEM_PRE_INC),        # STMIB rn!, rlist^
          (self._emu_ldm,  True, MEM_PRE_INC),        # LDMIB rn!, rlist^
      ]
      self._emu, self._wb, self._mmode = ops[op8 - 128]
    elif op8 < 176:
      self._emu = self._branch_nolink
    elif op8 < 192:
      self._emu = self._branch_link
    elif op8 < 240:
      self._emu = self._badinst     # Unused instruction space
    else:
      self._emu = self._reset_swi

  def execute(self, cpustate):
    cpustate.regs[REG_PC] = self._pc  # Set PC value since ARM can easily read it
    return self._emu(cpustate)

  def _badinst(self, st):
    self._executor.queue_startpoint(self._pc + 4)
    return True   # Terminal inst

  def _reset_swi(self, st):
    st.regreset([0,1,2,3])   # Treat like a function call

  # Memops
  def _store_word(self, st, addr, value):
    if addr == 0x04000204:
      self.target_patch = "str32"
    return st.store_word(addr, value)

  def _store_halfword(self, st, addr, value):
    if addr == 0x04000204:
      self.target_patch = "str16"
    return st.store_halfword(addr, value)

  def _store_byte(self, st, addr, value):
    if (addr & ~1) == 0x04000204:
      self.target_patch = "str8"
    return st.store_byte(addr, value)

  def _load_word(self, st, addr):
    if addr >= 0x08000000 and addr < 0x0E000000:
      return self._loadromcb(addr)
    return st.load_word(addr)

  def _load_halfword(self, st, addr):
    if addr >= 0x08000000 and addr < 0x0E000000:
      v = self._loadromcb(addr)
      if v is not None:
        return v & 0xFFFF
      return None
    return st.load_halfword(addr)

  def _load_shalfword(self, st, addr):
    v = self._load_halfword(st, addr)
    if v is not None:
      if v & 0x8000:
        v |= 0xFFFF0000
    return v

  def _load_byte(self, st, addr):
    if addr >= 0x08000000 and addr < 0x0E000000:
      v = self._loadromcb(addr)
      if v is not None:
        return v & 0xFF
      return None
    return st.load_byte(addr)

  def _load_sbyte(self, st, addr):
    v = self._load_byte(st, addr)
    if v is not None:
      if v & 0x80:
        v |= 0xFFFFFF00
    return v

  def _emu_ld(self, st):
    if st.regs[self.rn()] is None:
      st.regs[self.rd()] = None
      return

    # Calculate effective addr first
    addr = st.regs[self.rn()]
    if self.rn() == REG_PC: addr += 8

    if self._mem_bt in [MEM_IDX_PRE, MEM_IDX_PRE_WB]:
      off = self._mem_op2(st.regs)
      if off is None:
        st.regs[self.rd()] = None
        return
      addr = (addr + off) & 0xFFFFFFFF

    st.regs[self.rd()] = self._memop(st, addr)

    if self._mem_bt == MEM_IDX_POST_WB:
      off = self._mem_op2(st.regs)
      if off is None:
        st.regs[self.rn()] = None
      else:
        st.regs[self.rn()] = (addr + off) & 0xFFFFFFFF

  def _emu_st(self, st):
    if st.regs[self.rn()] is None:
      return

    # Calculate effective addr first
    addr = st.regs[self.rn()]
    if self.rn() == REG_PC: addr += 8
    if self._mem_bt in [MEM_IDX_PRE, MEM_IDX_PRE_WB]:
      off = self._mem_op2(st.regs)
      if off is None:
        return
      addr = (addr + off) & 0xFFFFFFFF

    self._memop(st, addr, st.regs[self.rd()])

    if self._mem_bt == MEM_IDX_POST_WB:
      off = self._mem_op2(st.regs)
      if off is None:
        st.regs[self.rn()] = None
      else:
        st.regs[self.rn()] = (addr + off) & 0xFFFFFFFF

  def _emuld_sbyte(self, st):
    self._memop = self._load_sbyte
    self._mem_op2, self._mem_bt = self._opA, self._opB
    self._emu_ld(st)

  def _emuld_shalfword(self, st):
    self._memop = self._load_shalfword
    self._mem_op2, self._mem_bt = self._opA, self._opB
    self._emu_ld(st)

  def _emuld_halfword(self, st):
    self._memop = self._load_halfword
    self._mem_op2, self._mem_bt = self._opA, self._opB
    self._emu_ld(st)

  def _emust_halfword(self, st):
    self._memop = self._store_halfword
    self._mem_op2, self._mem_bt = self._opA, self._opB
    self._emu_st(st)

  def _emu_ldm(self, st):
    rl = self._rlist()
    nel = rl.bit_count()
    if st.regs[self.rn()] is None:
      for i in range(16):
        if rl & (1 << i):
          st.regs[i] = None
    elif self.rn() == REG_PC:
      return self._badinst(st)   # 99.99% of the time this is a bad inst
    else:
      base = st.regs[self.rn()]
      aof = 4 if (self._mmode == MEM_POST_INC or self._mmode == MEM_PRE_INC) else -4
      endaddr = base + nel * aof

      amap = {
        MEM_PRE_INC:  base + 4,
        MEM_POST_INC: base,
        MEM_PRE_DEC:  endaddr,
        MEM_POST_DEC: endaddr + 4,
      }
      address = amap[self._mmode] & 0xFFFFFFFC

      for i in range(16):
        if rl & (1 << i):
          st.regs[i] = self._load_word(st, address)
          address += 4

      if self._wb:
        st.regs[self.rn()] = endaddr

    if rl & (1 << REG_PC):
      # Popping PC: treat as a branch!
      self._executor.queue_startpoint(self._pc + 4)
      return True

  def _emu_stm(self, st):
    rl = self._rlist()
    nel = rl.bit_count()

    if self.rn() == REG_PC:
      return self._badinst(st)
    elif st.regs[self.rn()] is not None:
      base = st.regs[self.rn()]
      aof = 4 if (self._mmode == MEM_POST_INC or self._mmode == MEM_PRE_INC) else -4
      endaddr = base + nel * aof

      amap = {
        MEM_PRE_INC:  base + 4,
        MEM_POST_INC: base,
        MEM_PRE_DEC:  endaddr,
        MEM_POST_DEC: endaddr + 4,
      }
      address = amap[self._mmode] & 0xFFFFFFFC

      for i in range(16):
        if rl & (1 << i):
          self._store_word(st, address, st.regs[i])
          address += 4

      if self._wb:
        st.regs[self.rn()] = endaddr

  # Calculate operand2 with reg mode
  def _calc_op2_reg(self, regs):
    rm = regs[self.rm()]
    if rm is None:
      return None    # Not 100% accurate in some cases (like LSR#0)

    t = (self._opcode >> 5) & 3
    if (self._opcode & 0x10) != 0:
      # Reg with reg shift/rot
      if self.rm() == REG_PC: rm += 12
      rs = regs[self.rs()]
      if rs is None:
        return None
      rs = rs & 0xFF   #  Limit to LSB
      if self.rs() == REG_PC: rs += 12

      if t == 0:
        return (rm << rs) & 0xFFFFFFFF
      elif t == 1:
        return (rm >> rs) & 0xFFFFFFFF
      elif t == 2:
        return asr32(rm, rs)
      else:
        amount = rs & 31
        return ((rm >> amount) | (rm << (32 - amount))) & 0xFFFFFFFF
    else:
      # Reg with imm shift/rot
      if self.rm() == REG_PC: rm += 8
      imm = (self._opcode >> 7) & 0x1f
      if t == 0:
        return (rm << imm) & 0xFFFFFFFF
      elif t == 1:
        if imm:
          return rm >> imm
        else:
          return 0
      elif t == 2:
        if imm:
          return asr32(rm, imm)
        else:
          return asr32(rm, 32)
      else:
        if imm:
          return ((rm >> imm) | (rm << (32 - imm))) & 0xFFFFFFFF
        else:
          return None    # RRX needs C flag input

  def br_offset(self):
    v = self._opcode & 0xFFFFFF
    if v & 0x800000:
      return (v << 2) | 0xFC000000
    else:
      return v << 2

  def _calc_op2_imm(self):
    sa = self.rot4() * 2;
    imm = self.imm8()
    return ((imm >> sa) | (imm << (32 - sa))) & 0xFFFFFFFF

  def rot4(self):
    return (self._opcode >> 8) & 0xF

  def imm8(self):
    return self._opcode & 0xFF

  def rd(self):
    return (self._opcode >> 12) & 0xF

  def rn(self):
    return (self._opcode >> 16) & 0xF

  def rs(self):
    return (self._opcode >> 8) & 0xF

  def rm(self):
    return self._opcode & 0xF

  def op2sa(self):
    return (self._opcode >> 7) & 0x1F;

  def op2smode(self):
    return (self._opcode >> 5) & 0x3;

  def op2shimm(self, regs):
    rmval = regs[self.rm()]
    if rmval is None:
      return None    # Not 100% accurate in some cases (like LSR#0)
    if self.rm() == REG_PC: rmval += 8

    imm = self.op2sa();      # Shift amount [0..31]
    subop = self.op2smode()
    if subop == 0:
      return rmval << imm
    elif subop == 1:
      if imm:
        return rmval >> imm
      return 0
    elif subop == 2:
      return asr32(rmval, imm if imm else 31)
    else:
      if imm:
        return ((rmval >> imm) | (rmval << (32 - imm))) & 0xFFFFFFFF
      return None  # Unkown C flag value

  # Mem operands
  def _pimm12(self, _):
    return self._opcode & 0xFFF

  def _mimm12(self, _):
    return (~self._pimm12(None) + 1) & 0xFFFFFFFF

  def _pregop(self, regs):
    return self.op2shimm(regs)

  def _mregop(self, regs):
    v = self.op2shimm(regs)
    if v is None:
      return None
    return (~v + 1) & 0xFFFFFFFF

  def _pregm(self, regs):
    rmval = regs[self.rm()]
    if rmval is None:
      return None
    if self.rm() == REG_PC: rmval += 8
    return rmval

  def _mregm(self, regs):
    v = self._pregm(regs)
    if v is None:
      return None
    return (~v + 1) & 0xFFFFFFFF

  def _pimm8(self, _):
    return ((self._opcode >> 4) & 0xF0) | (self._opcode & 0x0F)

  def _mimm8(self, _):
    v = self._pimm8(None)
    return (~v + 1) & 0xFFFFFFFF

  def _rlist(self):
    return self._opcode & 0xFFFF

  # ALU ops such as "OP rd, rn, rm (lsl/lsr/asr/ror) #imm/rn"
  def _regop(self, st):
    val2 = self._calc_op2_reg(st.regs)
    val1 = st.regs[self.rn()]
    if self.rn() == REG_PC and val1 is not None:
      val1 += 12 if self._complex_shift() else 8   # Adjust PC value

    if val1 is None or val2 is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._op(val1, val2)

    if self.rd() == REG_PC:
      # Treat as a branch!
      self._executor.queue_startpoint(self._pc + 4)
      return True

  def _immop(self, st):
    val1 = st.regs[self.rn()]
    if val1 is None:
      st.regs[self.rd()] = None
    else:
      if self.rn() == REG_PC: val1 += 8
      val2 = self._calc_op2_imm()
      st.regs[self.rd()] = self._op(val1, val2)

  def _regop_unary(self, st):
    val2 = self._calc_op2_reg(st.regs)
    if val2 is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = self._op(val2) & 0xFFFFFFFF

    if self.rd() == REG_PC:
      # Treat as a branch!
      self._executor.queue_startpoint(self._pc + 4)
      return True

  def _immop_unary(self, st):
    val2 = self._calc_op2_imm()
    st.regs[self.rd()] = self._op(val2) & 0xFFFFFFFF

  def _regop_mrs(self, st):
    st.regs[self.rd()] = None

  def _regop_mrs_spsr(self, st):
    st.regs[self.rd()] = None

  def _regop_unk(self, st):
    st.regs[self.rd()] = None

  def _msr_imm(self, st):
    if (self._opcode & 0x0000F000) != 0x0000F000:
      return self._badinst(st)

    # TODO Implement MSR?

  def _spsr_wr(self, st):
    pass

  def _regop_nop(self, st):
    pass

  def _branch_link(self, st):
    st.regreset([0,1,2,3])

  def _branch_nolink(self, st):
    if self._cond == 0xE:
      # B, flush on unconditional, or perhaps restore some previous branching state
      st.snapshot_reset(self._pc + 4)
    else:
      # Record condition branch state with the branch target
      st.snapshot_branch(self._pc + self.br_offset() + 8)

  def _bx_msr(self, st):
    if self._opcode & 0x10:
      # BX rn -> Flush CPU state and start over?
      # Interesting find! Often we need to call a thumb routine (ie. BL offset)
      # but we cannot do that since we need mode change, so games do:
      #  MOV LR, PC
      #  BX rX
      # If we detect that LR points to the next instruction we treat as a BL.
      if st.regs[REG_LR] == self._pc + 4:
        st.regreset([0,1,2,3])
      else:
        st.snapshot_reset(self._pc + 4)
    else:
      # MSR cpsr, rm (not implemented!)
      pass

  def _complex_shift(self):
    return (self._opcode & 0x10) != 0

  def _mulop32(self, st):
    opA = st.regs[self.rm()]
    opB = st.regs[self.rs()]
    if opA is None or opB is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = (opA * opB) & 0xFFFFFFFF

  def _mlaop32(self, st):
    opA = st.regs[self.rm()]
    opB = st.regs[self.rs()]
    opC = st.regs[self.rd()]
    if opA is None or opB is None or opC is None:
      st.regs[self.rd()] = None
    else:
      st.regs[self.rd()] = (opC + (opA * opB)) & 0xFFFFFFFF

  def _mulop64u(self, st):
    pass # TODO

  def _mulop64s(self, st):
    pass # TODO

  def _mlaop64u(self, st):
    pass # TODO

  def _mlaop64s(self, st):
    pass # TODO

  def _swap32(self, st):
    pass # TODO

  def _swap8(self, st):
    pass # TODO

