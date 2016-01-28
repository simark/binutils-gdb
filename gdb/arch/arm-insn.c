/* Copyright (C) 2015-2016 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "common-defs.h"
#include "arm-insn.h"

/* See arm-insn.h.  */

uint32_t
arm_thumb_branch_relative_distance (CORE_ADDR from, CORE_ADDR to)
{
  uint32_t from_ = ((uint32_t) from) & ~1;
  uint32_t to_   = ((uint32_t) to) & ~1;
  return to_ - from_ - 4;
}

/* See arm-insn.h.  */

int
arm_thumb_is_reachable (CORE_ADDR from, CORE_ADDR to)
{
  int32_t rel = arm_thumb_branch_relative_distance (from, to);
  rel >>= 24;
  return !rel || !(rel + 1);
}

/* See arm-insn.h.  */

uint16_t *
arm_emit_thumb_branch_insn (uint16_t *mem, CORE_ADDR from, CORE_ADDR to)
{
  uint32_t imm10, imm11;
  uint32_t s, j1, j2;
  uint32_t rel;

  rel = arm_thumb_branch_relative_distance (from, to);
  rel >>= 1;

  imm11 = rel & 0x7ff;
  rel >>= 11;
  imm10 = rel & 0x3ff;
  rel >>= 10;
  s  = (rel > 3);
  j1 = s ^ !(rel & 2);
  j2 = s ^ !(rel & 1);

  mem[0] = 0xF000 | (s << 10) | imm10;
  mem[1] = 0x9000 | (j1 << 13) | (j2 << 11) | imm11;

  return mem;
}

/* See arm-insn.h.  */

uint16_t *
arm_emit_thumb_blx_insn (uint16_t *mem, int reg)
{
  reg &= 0xF;
  *mem++ = 0x4780 | (reg << 3);
  return mem;
}

/* See arm-insn.h.  */

uint16_t *
arm_emit_thumb_load_insn (uint16_t *mem, int reg, uint32_t val)
{
  uint32_t imm4, imm3, imm8;
  uint32_t i;

  imm8 = val & 0x00FF;
  val >>= 8;
  imm3 = val & 0x0007;
  val >>= 3;
  i = val & 0x0001;
  val >>= 1;
  imm4 = val & 0x000F;
  val >>= 4;

  *mem++ = 0xF240 | (i << 10) | imm4;
  *mem++ = 0x0000 | (imm3 << 12) | (reg << 8) | imm8;

  imm8 = val & 0x00FF;
  val >>= 8;
  imm3 = val & 0x0007;
  val >>= 3;
  i = val & 0x0001;
  val >>= 1;
  imm4 = val & 0x000F;

  *mem++ = 0xF2C0 | (i << 10) | imm4;
  *mem++ = 0x0000 | (imm3 << 12) | (reg << 8) | imm8;

  return mem;
}

/* See arm-insn.h.  */

uint32_t
arm_arm_branch_relative_distance (CORE_ADDR from, CORE_ADDR to)
{
  return (uint32_t) to - (uint32_t) from - 8;
}

/* See arm-insn.h.  */

int
arm_arm_is_reachable (CORE_ADDR from, CORE_ADDR to)
{
  int32_t rel = arm_arm_branch_relative_distance (from, to);
  rel >>= 25;
  return !rel || !(rel + 1);
}

/* See arm-insn.h.  */

uint32_t *
arm_emit_arm_branch_insn (uint32_t *mem, CORE_ADDR from, CORE_ADDR to)
{
  uint32_t imm24 = arm_arm_branch_relative_distance (from, to);

  imm24 >>= 2;
  imm24 &= 0x00FFFFFF;
  *mem++ = 0xEA000000 | imm24;

  return mem;
}

/* See arm-insn.h.  */

uint32_t *
arm_emit_arm_blx_insn (uint32_t *mem, int reg)
{
  *mem++ = 0xE12FFF30 | (reg & 0xF);
  return mem;
}

/* See arm-insn.h.  */

uint32_t *
arm_emit_arm_load_insn (uint32_t *mem, int reg, uint32_t val)
{
  uint32_t imm4, imm12;

  imm12 = val & 0x0FFF;
  val >>= 12;
  imm4 = val & 0xF;
  val >>= 4;

  *mem++ = 0xE3000000 | ((reg & 0xF) << 12) | (imm4 << 16) | imm12;

  imm12 = val & 0x0FFF;
  val >>= 12;
  imm4 = val & 0xF;

  *mem++ = 0xE3400000 | ((reg & 0xF) << 12) | (imm4 << 16) | imm12;

  return mem;
}
