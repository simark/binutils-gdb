/* Copyright (C) 2015 Free Software Foundation, Inc.

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

#ifndef ARM_INSN_H
#define ARM_INSN_H 1

/* All the arm_emit_* functions take a MEM pointer, indicating where to write
   instruction.  They return a pointer to the slot just after the written
   instruction.  */

/* Return the distance in bytes from FROM to TO and adjusted for prefetch.  */

uint32_t arm_thumb_branch_relative_distance (CORE_ADDR from, CORE_ADDR to);

/* Return whether it's possible to jump from FROM to TO using a relative
   branch in thumb mode.  */

int arm_thumb_is_reachable (CORE_ADDR from, CORE_ADDR to);

/* Make a thumb mode relative branch instruction that jumps from FROM to TO.  */

uint16_t * arm_emit_thumb_branch_insn (uint16_t *mem, CORE_ADDR from,
				       CORE_ADDR to);
uint16_t * arm_emit_thumb_branch_cond_insn (uint16_t *mem, CORE_ADDR from,
					    CORE_ADDR to, int cond);

// TODO: to replace with Antoine's new functions.
uint16_t *
arm_emit_thumb_bl_blx_imm_insn (uint16_t *mem, CORE_ADDR from, CORE_ADDR to,
				int exchange);
/* Make a thumb mode blx (branch/link/exchange) instruction that branches to
   the address stored in register REG.  */

uint16_t * arm_emit_thumb_blx_insn (uint16_t *mem, int reg);

/* Make a thumb mode load instruction that loads the immediate value VAL into
   register REG.  */

uint16_t * arm_emit_thumb_load_insn (uint16_t *mem, int reg, uint32_t val);

/* Return the distance in bytes from FROM to TO and adjusted for prefetch.  */

uint32_t arm_arm_branch_relative_distance (CORE_ADDR from, CORE_ADDR to);

/* Return whether it's possible to jump from FROM to TO using a relative
   branch in arm mode.  */

int arm_arm_is_reachable (CORE_ADDR from, CORE_ADDR to);

/* Make an arm mode relative branch instruction that jumps from FROM to TO.  */

uint32_t * arm_emit_arm_branch_insn (uint32_t *mem, CORE_ADDR from,
				     CORE_ADDR to, int cond, int link);

/* Make an arm mode relative branch-link-exchange instruction that jumps from
   FROM to TO.  */

uint32_t * arm_emit_arm_blx_imm_insn (uint32_t *mem, CORE_ADDR from, CORE_ADDR to);

/* Make an arm mode blx (branch/link/exchange) instruction that branches to the
   address stored in register REG.  */

uint32_t * arm_emit_arm_blx_insn (uint32_t *mem, int reg);

/* Make an arm mode load instruction that loads the immediate value VAL into
   register REG.  */

uint32_t * arm_emit_arm_load_insn (uint32_t *mem, int reg, uint32_t val);

#endif /* ARM_INSN_H */
