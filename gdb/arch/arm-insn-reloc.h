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

struct thumb_32bit_insn_reloc_visitor
{
  int (*alu_imm) (uint16_t insn1, uint16_t insn2,
		  struct arm_insn_reloc_data *data);
  int (*b_bl_blx) (uint16_t insn1, uint16_t insn2,
		   struct arm_insn_reloc_data *data);
  int (*block_xfer) (uint16_t insn1, uint16_t insn2,
		     struct arm_insn_reloc_data *data);
  int (*copro_load_store) (uint16_t insn1, uint16_t insn2,
			   struct arm_insn_reloc_data *data);
  int (*load_literal) (uint16_t insn1, uint16_t insn2,
		       struct arm_insn_reloc_data *data, int size);
  int (*load_reg_imm) (uint16_t insn1, uint16_t insn2,
		       struct arm_insn_reloc_data *data, int writeback,
		       int immed);
  int (*others) (uint16_t insn1, uint16_t insn2, const char *iname,
		 struct arm_insn_reloc_data *data);
  int (*pc_relative_32bit) (uint16_t insn1, uint16_t insn2,
			    struct arm_insn_reloc_data *data);
  int (*preload) (uint16_t insn1, uint16_t insn2,
		  struct arm_insn_reloc_data *data);
  int (*undef) (uint16_t insn1, uint16_t insn2,
		struct arm_insn_reloc_data *data);
  int (*table_branch) (uint16_t insn1, uint16_t insn2,
		       struct arm_insn_reloc_data *data);
};

struct thumb_16bit_insn_reloc_visitor
{
  int (*alu_reg) (uint16_t insn, struct arm_insn_reloc_data *data);
  int (*b) (uint16_t insn, struct arm_insn_reloc_data *data);
  int (*bx_blx_reg) (uint16_t insn, struct arm_insn_reloc_data *data);
  int (*cbnz_cbz) (uint16_t insn1, struct arm_insn_reloc_data *data);
  int (*load_literal) (uint16_t insn1, struct arm_insn_reloc_data *data);
  int (*others) (uint16_t insn, const char *iname,
		 struct arm_insn_reloc_data *data);
  int (*pc_relative_16bit) (uint16_t insn, struct arm_insn_reloc_data *data,
			    int rd, unsigned int imm);
  int (*pop_pc_16bit) (uint16_t insn, struct arm_insn_reloc_data *data);
  int (*svc) (uint16_t insn, struct arm_insn_reloc_data *data);
};

/* This function is used to concisely determine if an instruction INSN
   references PC.  Register fields of interest in INSN should have the
   corresponding fields of BITMASK set to 0b1111.  The function
   returns return 1 if any of these fields in INSN reference the PC
   (also 0b1111, r15), else it returns 0.  */

extern int arm_insn_references_pc (uint32_t insn, uint32_t bitmask);

extern int arm_relocate_insn (uint32_t insn,
			      struct arm_insn_reloc_visitor *visitor,
			      struct arm_insn_reloc_data *data);
extern int thumb_32bit_relocate_insn (
  uint16_t insn1, uint16_t insn2,
  struct thumb_32bit_insn_reloc_visitor *visitor,
  struct arm_insn_reloc_data *data);
extern int thumb_16bit_relocate_insn (
  uint16_t insn1,
  struct thumb_16bit_insn_reloc_visitor *visitor,
  struct arm_insn_reloc_data *data);

#endif /* ARM_INSN_RELOC_H */
