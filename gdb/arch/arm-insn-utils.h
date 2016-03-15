/* Copyright (C) 2009-2016 Free Software Foundation, Inc.
   Contributed by ARM Ltd.

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

/* Helper macro to mask and shift a value into a bitfield.  */

#ifndef ARM_INSN_UTILS_H
#define ARM_INSN_UTILS_H 1

#define ENCODE(val, size, offset) \
  ((uint32_t) ((val & ((1ULL << size) - 1)) << offset))

enum arm_memory_operand_type
{
  MEMORY_OPERAND_OFFSET,
  MEMORY_OPERAND_PREINDEX,
  MEMORY_OPERAND_POSTINDEX,
};

/* Representation of a memory operand, used for load and store
   instructions.

   The types correspond to the following variants:

   MEMORY_OPERAND_OFFSET:    LDR rt, [rn, #offset]
   MEMORY_OPERAND_PREINDEX:  LDR rt, [rn, #index]!
   MEMORY_OPERAND_POSTINDEX: LDR rt, [rn], #index  */

struct arm_memory_operand
{
  /* Type of the operand.  */
  enum arm_memory_operand_type type;

  /* Index from the base register.  */
  int32_t index;
};

enum arm_operand_type
{
  OPERAND_IMMEDIATE,
  OPERAND_REGISTER,
  OPERAND_MEMORY,
};

/* Helper function to create an offset memory operand.

   For example:
   p += emit_ldr (p, x0, sp, offset_memory_operand (16));  */

struct arm_memory_operand offset_memory_operand (int32_t offset);

/* Helper function to create a pre-index memory operand.

   For example:
   p += emit_ldr (p, x0, sp, preindex_memory_operand (16));  */

struct arm_memory_operand preindex_memory_operand (int32_t index);

/* Helper function to create a post-index memory operand.

   For example:
   p += emit_ldr (p, x0, sp, postindex_memory_operand (16));  */

struct arm_memory_operand postindex_memory_operand (int32_t index);

#endif
