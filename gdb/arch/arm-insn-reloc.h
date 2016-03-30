/* Copyright (C) 2016 Free Software Foundation, Inc.

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

#ifndef ARM_INSN_RELOC_H
#define ARM_INSN_RELOC_H

struct arm_insn_reloc_data;

struct arm_insn_reloc_visitor
{
  int (*alu_imm) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*alu_reg) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*alu_shifted_reg) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*b_bl_blx) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*block_xfer) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*bx_blx_reg) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*copro_load_store) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*extra_ld_st) (uint32_t insn, struct arm_insn_reloc_data *data,
		      int unprivileged);
  int (*ldr_str_ldrb_strb) (uint32_t insn, struct arm_insn_reloc_data *data,
			    int load, int size, int usermode);
  int (*others) (uint32_t insn, const char *iname,
		 struct arm_insn_reloc_data *data);
  int (*preload) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*preload_reg) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*svc) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*undef) (uint32_t insn, struct arm_insn_reloc_data *data);
  int (*unpred) (uint32_t insn, struct arm_insn_reloc_data *data);
};

extern int arm_relocate_insn (uint32_t insn,
			      struct arm_insn_reloc_visitor *visitor,
			      struct arm_insn_reloc_data *data);

#endif /* ARM_INSN_RELOC_H */
