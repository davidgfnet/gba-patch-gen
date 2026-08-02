#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2026 David Guillen Fandos <david@davidgf.net>
#
# Minimal bit provenance implementation
# Allows us to track certain operations and data beyond "known" or "unknown".
#
# Each data block is a series of 32 bits. Each bit can be zero or one, if it's
# known, otherwise it can be:
#
# Mem Addr: (1 << 31) | (addr << 3) | (bitnum)
# CPU reg:  32 .. 4095
# Any new fresh value: 4096+ (odd values are negated even IDs)

class ProvenanceValue(object):
  def __init__(self, vals, state):
    self._vals = vals
    self._state = state

  # This is a known value.
  def known(self):
    return all(x < 2 for x in self._vals)

  def uint(self):
    assert self.known()
    return sum(x << i for i, x in enumerate(self._vals))

  # Gets the N LSB bits
  def get_lsb(self, num_bits):
    newv = [self._vals[i] for i in range(num_bits)]
    return ProvenanceValue(newv, self._state)

  # Gets just one bit
  def get_bit(self, bitnum):
    newv = [self._vals[bitnum]]
    return ProvenanceValue(newv, self._state)

  # Replicates one or more bits N times.
  def replicate(self, times):
    newv = [x for x in self._vals]
    newv = newv * times
    return ProvenanceValue(newv, self._state)

  # Checks for bit equality
  def __eq__(self, other):
    if len(self._vals) != len(other._vals):
      return False
    return all(self._vals[i] == other._vals[i] for i in range(len(self._vals)))

  # Operator @ as concatenator (LSB first!)
  def __matmul__(self, other):
    newv = [x for x in self._vals] + [x for x in other._vals]
    return ProvenanceValue(newv, self._state)

  # Implements operators to we can "naturally" use them.

  # xor handles some identities: (a ^ a = 0, a ^ !a = 1)
  def __xor__(self, other):
    assert len(self._vals) == len(other._vals)
    return ProvenanceValue([
      self._vals[i] ^ other._vals[i] if self._vals[i] < 2 or other._vals[i] < 2 else
      0                              if self._vals[i] == other._vals[i]         else
      1                              if self._vals[i] == (other._vals[i] ^ 1)   else
      self._state.fresh_bit()
      for i in range(len(self._vals))
    ], self._state)

  # and handles some identities: (a & 0 = 0, a & 1 = a, a & !a = 0)
  def __and__(self, other):
    assert len(self._vals) == len(other._vals)
    return ProvenanceValue([
      self._vals[i] & other._vals[i] if self._vals[i] < 2 and other._vals[i] < 2   else
      other._vals[i]                 if self._vals[i] < 2 and self._vals[i] == 1   else
      0                              if self._vals[i] < 2 and self._vals[i] == 0   else
      self._vals[i]                  if other._vals[i] < 2 and other._vals[i] == 1 else
      0                              if other._vals[i] < 2 and other._vals[i] == 0 else
      self._vals[i]                  if self._vals[i] == other._vals[i]            else
      0                              if self._vals[i] == (other._vals[i] ^ 1)      else
      self._state.fresh_bit()
      for i in range(len(self._vals))
    ], self._state)

  # or handles some identities: (a | 0 = a, a | 1 = 1, a | !a = 1)
  def __or__(self, other):
    assert len(self._vals) == len(other._vals)
    return ProvenanceValue([
      self._vals[i] | other._vals[i] if self._vals[i] < 2 and other._vals[i] < 2   else
      other._vals[i]                 if self._vals[i] < 2 and self._vals[i] == 0   else
      1                              if self._vals[i] < 2 and self._vals[i] == 1   else
      self._vals[i]                  if other._vals[i] < 2 and other._vals[i] == 0 else
      1                              if other._vals[i] < 2 and other._vals[i] == 1 else
      self._vals[i]                  if self._vals[i] == other._vals[i]            else
      1                              if self._vals[i] == (other._vals[i] ^ 1)      else
      self._state.fresh_bit()
      for i in range(len(self._vals))
    ], self._state)

  # invert bit or we flip the ID (odd <-> even)
  def __invert__(self):
    return ProvenanceValue([self._vals[i] ^ 1 for i in range(len(self._vals))], self._state)

  # accepts known shift amounts (and integer constants too)
  def __rshift__(self, other):
    if isinstance(other, ProvenanceValue) and not other.known():
      return self._state.fresh_uint(len(self._vals))

    sa = other.uint() if isinstance(other, ProvenanceValue) else other
    return ProvenanceValue([
      self._vals[i + sa] if i + sa < len(self._vals) else 0 for i in range(len(self._vals))
    ], self._state)

  def __lshift__(self, other):
    if isinstance(other, ProvenanceValue) and not other.known():
      return self._state.fresh_uint(len(self._vals))

    sa = other.uint() if isinstance(other, ProvenanceValue) else other
    return ProvenanceValue([
      0 if i < sa else self._vals[i - sa] for i in range(len(self._vals))
    ], self._state)

  # arithmetic operations are not well handled to be honest
  def __add__(self, other):
    if isinstance(other, int):
      return self + self._state.from_uint(other, num_bits=len(self._vals))
    else:
      assert len(self._vals) == len(other._vals)
      if self.known() and other.known():
        mask = (1 << len(self._vals)) - 1
        return self._state.from_uint((self.uint() + other.uint()) & mask, num_bits=len(self._vals))
      return self._state.fresh_uint(len(self._vals))

  def __sub__(self, other):
    assert len(self._vals) == len(other._vals)
    if self.known() and other.known():
      mask = (1 << len(self._vals)) - 1
      return self._state.from_uint((self.uint() - other.uint()) & mask, num_bits=len(self._vals))
    return self._state.fresh_uint(len(self._vals))

  def __mul__(self, other):
    assert len(self._vals) == len(other._vals)
    if self.known() and other.known():
      mask = (1 << len(self._vals)) - 1
      return self._state.from_uint((self.uint() * other.uint()) & mask, num_bits=len(self._vals))
    return self._state.fresh_uint(len(self._vals))


class ProvenanceState(object):
  def __init__(self):
    self._fresh_val = 4096

  def fresh_bit(self):
    ret = self._fresh_val
    self._fresh_val += 2
    return ret

  def fresh_uint(self, num_bits=32):
    ret = []
    for i in range(num_bits):
      ret.append(self._fresh_val)
      self._fresh_val += 2
    return ProvenanceValue(ret, self)

  def from_uint(self, value, num_bits=32):
    assert(value < (1 << num_bits))
    return ProvenanceValue([(value >> i) & 1 for i in range(num_bits)], self)

  def reg_init_val32(self, regn):
    return ProvenanceValue([regn*32 + 32 + i for i in range(32)], self)

  def mem_init_val(self, addr, num_bits=32):
    return ProvenanceValue([(1 << 31) | ((addr & 0xffffff) << 3) | i for i in range(num_bits)], self)


