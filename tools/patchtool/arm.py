#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2024 David Guillen Fandos <david@davidgf.net>
#
# Not so minimal ARM decoder and "symbolic" emulator.
# Can emulate most thumb/arm instructions and supports "unknown" values in
# registers and memory. Doesn't support flag calculation nor branch/flow insts
# (at least properly).

import heapq
import patchtool.provenance as provenance

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

def emu_asr32_imm(val, amount):
  sbit = val.get_bit(31)
  if amount >= 31:
    return sbit.replicate(32)
  return val.get_lsb(32 - amount) @ sbit.replicate(amount)

def add32(x, y): return x + y
def sub32(x, y): return x - y
def rsb32(x, y): return y - x

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
#
# store_cb(write_size, instr, address, value)
class InstExecutor(object):
  def __init__(self, initial_state, store_cb=None, load_cb=None):
    self._init_state = initial_state
    self._insts = []
    self._insts_pcmap = {}
    self._exec_queue = []
    self._entry_queue = [0]
    self._user_store_cb = store_cb
    self._user_load_cb = load_cb

  def addinst(self, inst):
    self._insts_pcmap[inst._pc] = len(self._insts)
    self._insts.append(inst)
    self._start_pc = self._insts[0]._pc
    self._end_pc   = self._insts[-1]._pc

  def execute(self):
    if not self._insts:
      return

    # Execute blocks as long as they exist.
    while self._exec_queue or self._entry_queue:
      # Cover all paths until no more paths exist
      while self._exec_queue:
        off, state = self._exec_queue[0]
        self._exec_queue = self._exec_queue[1:]
        # Execute all the instructions starting at the specified offset
        for i in range(off, len(self._insts)):
          r = self._insts[i].execute(state)
          if r == True:
            break    # Stop running, this is a terminal instruction.

      if self._entry_queue:
        # Insert a new path with an initial state
        off = heapq.heappop(self._entry_queue)
        # Remove duplicates, a bit of a hack for lack of unique heaps.
        while self._entry_queue and self._entry_queue[0] == off:
          heapq.heappop(self._entry_queue)

        self._exec_queue.append((off, self._init_state.copy()))

  def queue_execution(self, start_pc, state):
    # It might be that the PC is out of range
    if start_pc in self._insts_pcmap:
      self._exec_queue.append((self._insts_pcmap[start_pc], state.copy()))
      return True
    return False

  # Queues a new starting point (with initial state) at a certain PC
  def queue_startpoint(self, start_pc):
    # It might be that the PC is out of range
    if start_pc in self._insts_pcmap:
      heapq.heappush(self._entry_queue, self._insts_pcmap[start_pc])
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
    self._provst = provenance.ProvenanceState()
    self.regs = [self._provst.reg_init_val32(i) for i in range(16)]
    self.regs[REG_SP] = self._provst.from_uint(self._ispptr)

  def provenance(self):
    return self._provst

  def copy(self):
    ns = CPUState.__new__(CPUState)
    ns._ispptr = self._ispptr
    ns._provst = self._provst
    ns.regs = self.regs[:]
    ns.memmap = dict(self.memmap)
    ns._branch_state = {
      pc: {"regs": e["regs"][:], "memm": dict(e["memm"])}
      for pc, e in self._branch_state.items()
    }
    return ns

  def regreset(self, rl):
    for rn in rl:
      self.regs[rn] = self._provst.fresh_uint()

  def snapshot_branch(self, target_pc):
    self._branch_state[target_pc] = {
      "regs": self.regs[:],
      "memm": dict(self.memmap),
    }

  def snapshot_reset(self, next_pc):
    # If we have a branch pointing to the next_pc, we restore that state
    if next_pc in self._branch_state:
      self.regs   = self._branch_state[next_pc]["regs"]
      self.memmap = self._branch_state[next_pc]["memm"]
    else:
      self.reset()

  def _load_data(self, addr, sz):
    if addr.known():
      ret = self._provst.fresh_uint(num_bits=0)
      addrv = addr.uint()
      for i, a in enumerate(range(addrv, addrv+sz)):
        if a not in self.memmap:
          blk = self._provst.mem_init_val(a, num_bits=8)
        else:
          blk = self.memmap[a]
        ret = ret @ blk
      return ret
    else:
      return self._provst.fresh_uint(num_bits=sz*8)

  def _store_data(self, addr, value, sz):
    if addr.known():
      addrv = addr.uint()
      for i, a in enumerate(range(addrv, addrv+sz)):
        self.memmap[a] = (value >> (i*8)).get_lsb(8)

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
    self._dreg = None
    self._imm = None

    if (opcode >> 11) == 0:       # LSL
      self._emu = self._emu_shift_imm
      self._dreg = self.rd()
      self._shf = lambda x, y: x << y
    elif (opcode >> 11) == 1:     # LSR
      self._emu = self._emu_shift_imm
      self._dreg = self.rd()
      self._shf = lambda x, y: x >> y
    elif (opcode >> 11) == 2:     # ASR
      self._emu = self._emu_shift_imm
      self._dreg = self.rd()
      self._shf = emu_asr32_imm

    elif (opcode >> 9) == 0xC:     # Add rd, rs, rn
      self._emu = self._emu_op3
      self._dreg = self.rd()
      self._op3 = lambda x, y: (x + y)
    elif (opcode >> 9) == 0xD:     # Sub rd, rs, rn
      self._emu = self._emu_op3
      self._dreg = self.rd()
      self._op3 = lambda x, y: (x - y)
    elif (opcode >> 9) == 0xE:     # Add rd, rs, imm
      self._emu = self._emu_op2imm
      self._dreg = self.rd()
      self._op3 = lambda x, y: (x + y)
    elif (opcode >> 9) == 0xF:     # Sub rd, rs, imm
      self._emu = self._emu_op2imm
      self._dreg = self.rd()
      self._op3 = lambda x, y: (x - y)

    elif (opcode >> 11) == 0x4:     # MOV reg, imm8
      self._emu = self._emu_movimm8
      self._dreg = self.rd8()
    elif (opcode >> 11) == 0x5:     # CMP reg, imm8
      self._emu = self._emu_cmpimm8
      self._dreg = self.rd8()
    elif (opcode >> 11) == 0x6:     # ADD reg, imm8
      self._emu = self._emu_addimm8
      self._dreg = self.rd8()
    elif (opcode >> 11) == 0x7:     # SUB reg, imm8
      self._emu = self._emu_subimm8
      self._dreg = self.rd8()

    elif (opcode >> 8) == 0x44:     # ADDhi rd, rs
      self._emu = self._emu_addhi
      self._dreg = self.rdhi()
    elif (opcode >> 8) == 0x45:     # CMPhi rd, rs
      self._emu = self._emu_cmphi
      self._dreg = self.rdhi()
    elif (opcode >> 8) == 0x46:     # MOVhi rd, rs
      self._emu = self._emu_movhi
      self._dreg = self.rdhi()


    elif (opcode >> 11) == 0x14:    # ADD reg, pc, imm
      self._emu = self._emu_addpc
      self._dreg = self.rd8()
    elif (opcode >> 11) == 0x15:    # ADD reg, sp, imm
      self._emu = self._emu_addsp
      self._dreg = self.rd8()

    elif (opcode >> 10) == 0x2C:    # ADD sp, +/- imm
      self._emu = self._emu_adjsp
      self._dreg = REG_SP


    elif (opcode >> 11) == 9:      # LDR reg, [pc+imm]
      self._emu = self._emu_loadpcrel
      self._dreg = self.rd8()

    elif (opcode >> 9) == 0x2B:    # LDSB rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._dreg = self.rd()
      self._load_cb = self._load_sbyte
    elif (opcode >> 9) == 0x2C:    # LDR rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._dreg = self.rd()
      self._load_cb = self._load_word
    elif (opcode >> 9) == 0x2D:    # LDRH rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._dreg = self.rd()
      self._load_cb = self._load_halfword
    elif (opcode >> 9) == 0x2E:    # LDRB rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._dreg = self.rd()
      self._load_cb = self._load_byte
    elif (opcode >> 9) == 0x2F:    # LDSH rd, [rb+ro]
      self._emu = self._emu_ld2r
      self._dreg = self.rd()
      self._load_cb = self._load_shalfword


    elif (opcode >> 11) == 0xD:    # LDR rd, [rb+imm]
      self._emu = self._emu_ldimm
      self._dreg = self.rd()
      self._imm = self.imm5() * 4
      self._load_cb = self._load_word
    elif (opcode >> 11) == 0xF:    # LDRB rd, [rb+imm]
      self._emu = self._emu_ldimm
      self._dreg = self.rd()
      self._imm = self.imm5()
      self._load_cb = self._load_byte
    elif (opcode >> 11) == 0x11:   # LDRH rd, [rb+imm]
      self._emu = self._emu_ldimm
      self._dreg = self.rd()
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
      self._dreg = self.rd8()
      self._imm = self.imm8() * 4
      self._load_cb = self._load_word

    elif (opcode >> 6) == 0x100:     # AND rd, rs
      self._emu = self._op2bin
      self._dreg = self.rd()
      self._op2 = lambda x, y: x & y
    elif (opcode >> 6) == 0x101:     # XOR rd, rs
      self._emu = self._op2bin
      self._dreg = self.rd()
      self._op2 = lambda x, y: x ^ y
    elif (opcode >> 6) == 0x102:     # LSL rd, rs
      self._emu = self._op2bin
      self._dreg = self.rd()
      self._op2 = lambda x, y: (x << y)
    elif (opcode >> 6) == 0x103:     # LSR rd, rs
      self._emu = self._op2bin
      self._dreg = self.rd()
      self._op2 = lambda x, y: (x >> y)
    elif (opcode >> 6) == 0x104:     # ASR rd, rs
      self._emu = self._op2bin_emu_asr32_reg
      self._dreg = self.rd()
    elif (opcode >> 6) == 0x105:     # ADC rd, rs
      self._emu = self._op2unk
      self._dreg = self.rd()
    elif (opcode >> 6) == 0x106:     # SBC rd, rs
      self._emu = self._op2unk
      self._dreg = self.rd()
    elif (opcode >> 6) == 0x107:     # ROR rd, rs
      self._emu = self._op2bin_emu_ror32_reg
      self._dreg = self.rd()
    elif (opcode >> 6) == 0x108:     # TST rd, rs
      self._emu = self._op2nop
    elif (opcode >> 6) == 0x109:     # NEG rd, rs
      self._emu = self._op2unary
      self._dreg = self.rd()
      self._op2 = lambda x: (~x + 1)
    elif (opcode >> 6) == 0x10A:     # CMP rd, rs
      self._emu = self._op2nop
    elif (opcode >> 6) == 0x10B:     # CMN rd, rs
      self._emu = self._op2nop
    elif (opcode >> 6) == 0x10C:     # ORR rd, rs
      self._emu = self._op2bin
      self._dreg = self.rd()
      self._op2 = lambda x, y: x | y
    elif (opcode >> 6) == 0x10D:     # MUL rd, rs
      self._emu = self._op2bin
      self._dreg = self.rd()
      self._op2 = lambda x, y: (x * y)
    elif (opcode >> 6) == 0x10E:     # BIC rd, rs
      self._emu = self._op2bin
      self._dreg = self.rd()
      self._op2 = lambda x, y: (x & (~y))
    elif (opcode >> 6) == 0x10F:     # MVN rd, rs
      self._emu = self._op2unary
      self._dreg = self.rd()
      self._op2 = lambda x: (~x)

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
    # print(hex(self._pc))
    return self._emu(cpustate)

  def write_reg(self):
    return self._dreg

  def imm_value(self):
    return self._imm

  def inst_type(self):
    return "thumb"

  def pc(self):
    return self._pc

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
    ret = st.load_word(addr)
    if self._executor._user_load_cb:
      self._executor._user_load_cb(32, self, addr, ret)
    return ret

  def _load_halfword(self, st, addr):
    ret = st.load_halfword(addr)
    if self._executor._user_load_cb:
      self._executor._user_load_cb(16, self, addr, ret)
    return ret @ st._provst.from_uint(0, num_bits=16)

  def _load_shalfword(self, st, addr):
    val = st.load_halfword(addr)
    sbit = val.get_bit(15)
    return val.get_lsb(16) @ sbit.replicate(16)

  def _load_byte(self, st, addr):
    ret = st.load_byte(addr)
    if self._executor._user_load_cb:
      self._executor._user_load_cb(8, self, addr, ret)
    return ret @ st._provst.from_uint(0, num_bits=24)

  def _load_sbyte(self, st, addr):
    val = st.load_byte(addr)
    sbit = val.get_bit(7)
    return val.get_lsb(8) @ sbit.replicate(24)

  def _store_word(self, st, addr, value):
    if self._executor._user_store_cb:
      self._executor._user_store_cb(32, self, addr, value)
    return st.store_word(addr, value)

  def _store_halfword(self, st, addr, value):
    if self._executor._user_store_cb:
      self._executor._user_store_cb(16, self, addr, value)
    return st.store_halfword(addr, value)

  def _store_byte(self, st, addr, value):
    if self._executor._user_store_cb:
      self._executor._user_store_cb(8, self, addr, value)
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
    st.regs[REG_LR] = st._provst.from_uint((self._pc + 2) | 1)

    # Assume a regular call, just wipe some registers and continue
    st.regreset([0,1,2,3])

  # Emulation routines!
  def _reset_bx(self, st):
    # See ARM (_bx_msr) for more info
    if st.regs[REG_LR].known() and st.regs[REG_LR].uint() == self._pc + 2:
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
    ret = self._loadromcb(addr)
    if self._executor._user_load_cb:
      self._executor._user_load_cb(32, self, st._provst.from_uint(addr), st._provst.from_uint(ret))
    st.regs[self.rd8()] = st._provst.from_uint(ret) if ret is not None else st._provst.fresh_uint(32)

  def _emu_ld2r(self, st):
    st.regs[self.rd()] = self._load_cb(st, st.regs[self.rb()] + st.regs[self.ro()])

  def _emu_ldimm(self, st):
    rb = st.regs[self.rb()]
    st.regs[self.rd()] = self._load_cb(st, rb + st._provst.from_uint(self._imm))

  def _push_regs(self, st):
    if st.regs[REG_SP].known():
      for i in range(16):
        if self._rlist & (1 << i):
          st.regs[REG_SP] = st.regs[REG_SP] + (-4)
          addr = st.regs[REG_SP] & st._provst.from_uint(0xFFFFFFFC)
          self._store_word(st, addr, st.regs[i])

  def _pop_regs(self, st):
    if st.regs[REG_SP].known():
      for i in range(16):
        if self._rlist & (1 << i):
          addr = st.regs[REG_SP] & st._provst.from_uint(0xFFFFFFFC)
          st.regs[i] = self._load_word(st, addr)
          st.regs[REG_SP] = st.regs[REG_SP] + 4
    else:
      for i in range(16):
        if self._rlist & (1 << i):
          st.regs[i] = st._provst.fresh_uint()

    # Treat Pop {PC} like a branch (ie BX)
    if self._rlist & 0x8000:
      self._executor.queue_startpoint(self._pc + 2)
      return True

  def _stmia(self, st):
    pass

  def _ldmia(self, st):
    pass

  def _emu_ldrsp(self, st):
    st.regs[self.rd8()] = self._load_cb(st, st.regs[REG_SP] + st._provst.from_uint(self._imm))

  def _emu_strsp(self, st):
    self._store_cb(st, st.regs[REG_SP] + st._provst.from_uint(self._imm), st.regs[self.rd8()])

  def _emu_stimm(self, st):
    self._store_cb(st, st.regs[self.rb()] + st._provst.from_uint(self._imm), st.regs[self.rd()])

  def _emu_st2r(self, st):
    self._store_cb(st, st.regs[self.rb()] + st.regs[self.ro()], st.regs[self.rd()])

  def _emu_shift_imm(self, st):
    st.regs[self.rd()] = self._shf(st.regs[self.rs()], self.imm5())

  def _emu_op3(self, st):
    st.regs[self.rd()] = self._op3(st.regs[self.rs()], st.regs[self.rn()])

  def _emu_op2imm(self, st):
    st.regs[self.rd()] = self._op3(st.regs[self.rs()], st._provst.from_uint(self.imm3()))

  def _emu_movimm8(self, st):
    st.regs[self.rd8()] = st._provst.from_uint(self.imm8())

  def _emu_cmpimm8(self, st):
    pass

  def _emu_addimm8(self, st):
    st.regs[self.rd8()] = st.regs[self.rd8()] + st._provst.from_uint(self.imm8())

  def _emu_subimm8(self, st):
    st.regs[self.rd8()] = st.regs[self.rd8()] - st._provst.from_uint(self.imm8())

  def _emu_addhi(self, st):
    st.regs[self.rdhi()] = st.regs[self.rshi()] + st.regs[self.rdhi()]

  def _emu_cmphi(self, st):
    pass

  def _emu_movhi(self, st):
    st.regs[self.rdhi()] = st.regs[self.rshi()]

  def _emu_addpc(self, st):
    st.regs[self.rd8()] = st._provst.from_uint(((self._pc & ~3) + 4 + self.imm8() * 4) & 0xFFFFFFFF)

  def _emu_addsp(self, st):
    st.regs[self.rd8()] = st.regs[REG_SP] + st._provst.from_uint(self.imm8() * 4)

  def _emu_adjsp(self, st):
    st.regs[REG_SP] = st.regs[REG_SP] + st._provst.from_uint(self.imm71() * 4)

  def _op2nop(self, st):
    pass

  def _op2unk(self, st):
    st.regs[self.rd()] = st._provst.fresh_uint()

  def _op2bin(self, st):
    st.regs[self.rd()] = self._op2(st.regs[self.rd()], st.regs[self.rs()])

  def _op2unary(self, st):
    st.regs[self.rd()] = self._op2(st.regs[self.rs()])

  def _op2bin_emu_asr32_reg(self, st):
    val, amount = st.regs[self.rd()], st.regs[self.rs()]
    sa = amount.get_lsb(8)
    if sa.known():
      st.regs[self.rd()] = emu_asr32_imm(val, sa.uint())
    else:
      st.regs[self.rd()] = st._provst.fresh_uint()

  def _op2bin_emu_ror32_reg(self, st):
    val, amount = st.regs[self.rd()], st.regs[self.rs()]
    sa = amount.get_lsb(8)
    if sa.known():
      part1 = val >> (sa.uint() & 31)
      part2 = val << (32 - (sa.uint() & 31))
      st.regs[self.rd()] = part1 | part2
    else:
      st.regs[self.rd()] = st._provst.fresh_uint()

class ARMInst(object):
  def __init__(self, executor, pc, opcode, romcb):
    self._executor = executor
    self._opcode = opcode
    self._pc = pc
    self._emu = lambda _ : None
    self._loadromcb = romcb
    self.target_patch = False
    self._dreg = None

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
        self._dreg = self.rd()    # This is an aproximation really... (doesn't work for tst/cmp)
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
      self._dreg = self.rd()    # This is an aproximation
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
      if op8 & 1:
        self._emu = self._emu_ld   # Load opcode
        self._dreg = self.rd()
      else:
        self._emu = self._emu_st   # Store opcode

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

  def write_reg(self):
    return self._dreg

  def inst_type(self):
    return "arm"

  def pc(self):
    return self._pc

  def execute(self, cpustate):
    cpustate.regs[REG_PC] = cpustate._provst.from_uint(self._pc)  # Set PC value since ARM can easily read it
    return self._emu(cpustate)

  def _badinst(self, st):
    self._executor.queue_startpoint(self._pc + 4)
    return True   # Terminal inst

  def _reset_swi(self, st):
    st.regreset([0,1,2,3])   # Treat like a function call

  # Memops
  def _store_word(self, st, addr, value):
    if self._executor._user_store_cb:
      self._executor._user_store_cb(32, self, addr, value)
    return st.store_word(addr, value)

  def _store_halfword(self, st, addr, value):
    if self._executor._user_store_cb:
      self._executor._user_store_cb(16, self, addr, value)
    return st.store_halfword(addr, value)

  def _store_byte(self, st, addr, value):
    if self._executor._user_store_cb:
      self._executor._user_store_cb(8, self, addr, value)
    return st.store_byte(addr, value)

  def _load_word(self, st, addr):
    if addr.known():
      addrv = addr.uint()
      if addrv >= 0x08000000 and addrv < 0x0E000000:
        ret = self._loadromcb(addrv)
        return st._provst.from_uint(ret) if ret is not None else st._provst.fresh_uint(32)
    return st.load_word(addr)

  def _load_halfword(self, st, addr):
    if addr.known():
      addrv = addr.uint()
      if addrv >= 0x08000000 and addrv < 0x0E000000:
        ret = self._loadromcb(addrv)
        ret = st._provst.from_uint(ret) if ret is not None else st._provst.fresh_uint()
        return ret & st._provst.from_uint(0xFFFF)
    return st.load_halfword(addr) @ st._provst.from_uint(0, num_bits=16)

  def _load_shalfword(self, st, addr):
    v = self._load_halfword(st, addr)
    sbit = v.get_bit(15)
    return v.get_lsb(16) @ sbit.replicate(16)

  def _load_byte(self, st, addr):
    if addr.known():
      addrv = addr.uint()
      if addrv >= 0x08000000 and addrv < 0x0E000000:
        ret = self._loadromcb(addrv)
        ret = st._provst.from_uint(ret) if ret is not None else st._provst.fresh_uint()
        return ret & st._provst.from_uint(0xFF)
    return st.load_byte(addr) @ st._provst.from_uint(0, num_bits=24)

  def _load_sbyte(self, st, addr):
    v = self._load_byte(st, addr)
    sbit = v.get_bit(7)
    return v.get_lsb(8) @ sbit.replicate(24)

  def _emu_ld(self, st):
    # Calculate effective addr first
    addr = st.regs[self.rn()]
    if self.rn() == REG_PC:
      addr = addr + 8

    if self._mem_bt in [MEM_IDX_PRE, MEM_IDX_PRE_WB]:
      off = self._mem_op2(st)
      addr = addr + off

    st.regs[self.rd()] = self._memop(st, addr)

    if self._mem_bt == MEM_IDX_POST_WB:
      off = self._mem_op2(st)
      st.regs[self.rn()] = addr + off

  def _emu_st(self, st):
    # Calculate effective addr first
    addr = st.regs[self.rn()]
    if self.rn() == REG_PC:
      addr = addr + 8
    if self._mem_bt in [MEM_IDX_PRE, MEM_IDX_PRE_WB]:
      off = self._mem_op2(st)
      addr = addr + off

    self._memop(st, addr, st.regs[self.rd()])

    if self._mem_bt == MEM_IDX_POST_WB:
      off = self._mem_op2(st)
      st.regs[self.rn()] = addr + off

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
    if self.rn() == REG_PC:
      return self._badinst(st)   # 99.99% of the time this is a bad inst
    else:
      base = st.regs[self.rn()]
      aof = 4 if (self._mmode == MEM_POST_INC or self._mmode == MEM_PRE_INC) else -4
      endaddr = base + (nel * aof)

      amap = {
        MEM_PRE_INC:  base + 4,
        MEM_POST_INC: base,
        MEM_PRE_DEC:  endaddr,
        MEM_POST_DEC: endaddr + 4,
      }
      address = amap[self._mmode] & st._provst.from_uint(0xFFFFFFFC)

      for i in range(16):
        if rl & (1 << i):
          st.regs[i] = self._load_word(st, address)
          address = address + st._provst.from_uint(4)

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
    else:
      base = st.regs[self.rn()]
      aof = 4 if (self._mmode == MEM_POST_INC or self._mmode == MEM_PRE_INC) else -4
      endaddr = base + (nel * aof)

      amap = {
        MEM_PRE_INC:  base + 4,
        MEM_POST_INC: base,
        MEM_PRE_DEC:  endaddr,
        MEM_POST_DEC: endaddr + 4,
      }
      address = amap[self._mmode] & st._provst.from_uint(0xFFFFFFFC)

      for i in range(16):
        if rl & (1 << i):
          self._store_word(st, address, st.regs[i])
          address = address + st._provst.from_uint(4)

      if self._wb:
        st.regs[self.rn()] = endaddr

  # Calculate operand2 with reg mode
  def _calc_op2_reg(self, regs, st):
    if not regs[self.rm()].known():
      return st._provst.fresh_uint()  # Not 100% accurate in some cases (like LSR#0)
    rm = regs[self.rm()].uint()

    t = (self._opcode >> 5) & 3
    if (self._opcode & 0x10) != 0:
      # Reg with reg shift/rot
      if self.rm() == REG_PC: rm += 12
      sa = regs[self.rs()].get_lsb(8)  # Only care about the 8 LSB
      if not sa.known():
        return st._provst.fresh_uint()

      rs = sa.uint()
      if self.rs() == REG_PC: rs += 12

      if t == 0:
        return st._provst.from_uint((rm << rs) & 0xFFFFFFFF)
      elif t == 1:
        return st._provst.from_uint((rm >> rs) & 0xFFFFFFFF)
      elif t == 2:
        return st._provst.from_uint(asr32(rm, rs))
      else:
        amount = rs & 31
        return st._provst.from_uint(((rm >> amount) | (rm << (32 - amount))) & 0xFFFFFFFF)
    else:
      # Reg with imm shift/rot
      if self.rm() == REG_PC: rm += 8
      imm = (self._opcode >> 7) & 0x1f
      if t == 0:
        return st._provst.from_uint((rm << imm) & 0xFFFFFFFF)
      elif t == 1:
        if imm:
          return st._provst.from_uint(rm >> imm)
        else:
          return st._provst.from_uint(0)
      elif t == 2:
        if imm:
          return st._provst.from_uint(asr32(rm, imm))
        else:
          return st._provst.from_uint(asr32(rm, 32))
      else:
        if imm:
          return st._provst.from_uint(((rm >> imm) | (rm << (32 - imm))) & 0xFFFFFFFF)
        else:
          # Bit 31 is unkown (TODO implement flags)
          return st._provst.from_uint(rm >> 1, num_bits=31) @ st._provst.fresh_uint(num_bits=1)

  def br_offset(self):
    v = self._opcode & 0xFFFFFF
    if v & 0x800000:
      return (v << 2) | 0xFC000000
    else:
      return v << 2

  def _calc_op2_imm(self, st):
    sa = self.rot4() * 2;
    imm = self.imm8()
    return st._provst.from_uint(((imm >> sa) | (imm << (32 - sa))) & 0xFFFFFFFF)

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

  def op2shimm(self, regs, st):
    if not regs[self.rm()].known():
      return st._provst.fresh_uint()  # Not 100% accurate in some cases (like LSR#0)

    rmval = regs[self.rm()].uint()
    if self.rm() == REG_PC: rmval += 8

    imm = self.op2sa();      # Shift amount [0..31]
    subop = self.op2smode()
    if subop == 0:
      return st._provst.from_uint((rmval << imm) & 0xFFFFFFFF)
    elif subop == 1:
      if imm:
        return st._provst.from_uint(rmval >> imm)
      return st._provst.from_uint(0)
    elif subop == 2:
      return st._provst.from_uint(asr32(rmval, imm if imm else 31))
    else:
      if imm:
        return st._provst.from_uint(((rmval >> imm) | (rmval << (32 - imm))) & 0xFFFFFFFF)
      # Bit 31 is unkown (TODO implement flags)
      return st._provst.from_uint(rmval >> 1, num_bits=31) @ st._provst.fresh_uint(num_bits=1)


  # Mem operands
  def _pimm12(self, st):
    return st._provst.from_uint(self._opcode & 0xFFF)

  def _mimm12(self, st):
    return ~self._pimm12(st) + 1

  def _pregop(self, st):
    return self.op2shimm(st.regs, st)

  def _mregop(self, st):
    v = self.op2shimm(st.regs, st)
    return ~v + 1

  def _pregm(self, st):
    rmval = st.regs[self.rm()]
    if self.rm() == REG_PC:
      rmval = rmval + 8
    return rmval

  def _mregm(self, st):
    return (~self._pregm(st)) + 1

  def _pimm8(self, st):
    return st._provst.from_uint(((self._opcode >> 4) & 0xF0) | (self._opcode & 0x0F))

  def _mimm8(self, st):
    v = self._pimm8(st)
    return ~v + 1

  def _rlist(self):
    return self._opcode & 0xFFFF

  # ALU ops such as "OP rd, rn, rm (lsl/lsr/asr/ror) #imm/rn"
  def _regop(self, st):
    val2 = self._calc_op2_reg(st.regs, st)
    val1 = st.regs[self.rn()]
    if self.rn() == REG_PC:
      val1 = val1 + (12 if self._complex_shift() else 8)   # Adjust PC value

    st.regs[self.rd()] = self._op(val1, val2)

    if self.rd() == REG_PC:
      # Treat as a branch!
      self._executor.queue_startpoint(self._pc + 4)
      return True

  def _immop(self, st):
    val1 = st.regs[self.rn()]
    if self.rn() == REG_PC:
      val1 = val1 + 8
    val2 = self._calc_op2_imm(st)
    st.regs[self.rd()] = self._op(val1, val2)

  def _regop_unary(self, st):
    val2 = self._calc_op2_reg(st.regs, st)
    st.regs[self.rd()] = self._op(val2)

    if self.rd() == REG_PC:
      # Treat as a branch!
      self._executor.queue_startpoint(self._pc + 4)
      return True

  def _immop_unary(self, st):
    val2 = self._calc_op2_imm(st)
    st.regs[self.rd()] = self._op(val2)

  def _regop_mrs(self, st):
    st.regs[self.rd()] = st._provst.fresh_uint()

  def _regop_mrs_spsr(self, st):
    st.regs[self.rd()] = st._provst.fresh_uint()

  def _regop_unk(self, st):
    st.regs[self.rd()] = st._provst.fresh_uint()

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
      if st.regs[REG_LR].known() and st.regs[REG_LR].uint() == self._pc + 4:
        st.regreset([0,1,2,3])
      else:
        st.snapshot_reset(self._pc + 4)
    else:
      # MSR cpsr, rm (not implemented!)
      pass

  def _complex_shift(self):
    return (self._opcode & 0x10) != 0

  def _mulop32(self, st):
    st.regs[self.rd()] = st.regs[self.rm()] * st.regs[self.rs()]

  def _mlaop32(self, st):
    st.regs[self.rd()] = (st.regs[self.rd()] + (st.regs[self.rm()] * st.regs[self.rs()]))

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

