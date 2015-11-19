/* Common code for ARM software single stepping support.

   Copyright (C) 1988-2015 Free Software Foundation, Inc.

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

#ifndef ARM_GET_NEXT_PCS_H
#define ARM_GET_NEXT_PCS_H 1

/* Support routines for instruction parsing.  */
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj,st,fn) (((obj) >> (st)) & submask ((fn) - (st)))
#define bit(obj,st) (((obj) >> (st)) & 1)
#define sbits(obj,st,fn) \
  ((long) (bits(obj,st,fn) | ((long) bit(obj,fn) * ~ submask (fn - st))))
#define BranchDest(addr,instr) \
  ((CORE_ADDR) (((unsigned long) (addr)) + 8 + (sbits (instr, 0, 23) << 2)))


/* Forward declaration.  */
struct arm_get_next_pcs;

/* get_next_pcs operations.  */
struct arm_get_next_pcs_ops
{
  ULONGEST (*read_memory_unsigned_integer) (CORE_ADDR memaddr, int len,
					    int byte_order);
  ULONGEST (*collect_register_unsigned) (struct arm_get_next_pcs* self, int n);
  CORE_ADDR (*syscall_next_pc) (struct arm_get_next_pcs* self, CORE_ADDR pc);
  CORE_ADDR (*addr_bits_remove) (struct arm_get_next_pcs *self, CORE_ADDR val);
};

/* Context for a get_next_pcs call on ARM.  */
struct arm_get_next_pcs
{
  struct arm_get_next_pcs_ops *ops;
  int byte_order;
  int byte_order_for_code;
  int is_thumb;
  int arm_apcs_32;
  const gdb_byte *arm_linux_thumb2_breakpoint;
};

/* Context for a get_next_pcs call on ARM in GDB.  */
struct arm_gdb_get_next_pcs
{
  struct arm_get_next_pcs base;
  struct frame_info *frame;
  struct gdbarch *gdbarch;
};

/* Context for a get_next_pcs call on ARM in GDBServer.  */
struct arm_gdbserver_get_next_pcs
{
  struct arm_get_next_pcs base;
  /* The cache for registry values.  */
  struct regcache *regcache;
};

/* Find the next possible PCs after the current instruction executes.  */
VEC (CORE_ADDR) *arm_get_next_pcs (struct arm_get_next_pcs *ctx,
				   CORE_ADDR pc);

/* Find the next possible PCs for thumb mode.  */
VEC (CORE_ADDR) *thumb_get_next_pcs_raw (struct arm_get_next_pcs *ctx,
					 CORE_ADDR pc,
					 VEC (CORE_ADDR) **next_pcs);

/* Find the next possible PCs for arm mode.  */
VEC (CORE_ADDR) *arm_get_next_pcs_raw (struct arm_get_next_pcs *ctx,
				       CORE_ADDR pc,
				       VEC (CORE_ADDR) **next_pcs);

/* Return 1 if THIS_INSTR might change control flow, 0 otherwise.  */
int arm_instruction_changes_pc (uint32_t this_instr);

/* Return 1 if the 16-bit Thumb instruction INST might change
   control flow, 0 otherwise.  */
int thumb_instruction_changes_pc (unsigned short inst);

/* Return 1 if the 32-bit Thumb instruction in INST1 and INST2
   might change control flow, 0 otherwise.  */
int thumb2_instruction_changes_pc (unsigned short inst1, unsigned short inst2);

#endif /* ARM_GET_NEXT_PCS_H */
