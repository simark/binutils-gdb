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

#ifndef ARM_INSN_H
#define ARM_INSN_H 1

/* List of the ARM opcodes we need.  */

enum arm_opcodes
  {
    ARM_ADD     = 0x00800000,
    ARM_B       = 0x0A000000,
    ARM_BIC     = 0x03C00000,
    ARM_BLX     = 0x012FFF30,
    ARM_CMP     = 0x03500000,
    ARM_DMB     = 0xF57FF050,
    ARM_LDR     = 0x04100000,
    ARM_LDREX   = 0x01900F9F,
    ARM_MOV     = 0x01A00000,
    ARM_MOVT    = 0x03400000,
    ARM_MOVW    = 0x03000000,
    ARM_MRS     = 0x010F0000,
    ARM_MSR     = 0x0120F000,
    ARM_POP_A1  = 0x08BD0000,
    ARM_POP_A2  = 0x049D0004,
    ARM_PUSH_A1 = 0x092D0000,
    ARM_PUSH_A2 = 0x052D0004,
    ARM_SBFX    = 0x07A00050,
    ARM_STR     = 0x04000000,
    ARM_STREX   = 0x01800F90,
    ARM_VPOP    = 0x0CBD0B00,
    ARM_VPUSH   = 0x0D2D0B00,
  };

/* List of the Thumb opcodes we need.  */

enum thumb_opcodes
  {
    THUMB_ADD_SP  = 0xB000,
    THUMB_BLX     = 0x4780,
    THUMB_B       = 0xD000,
    THUMB_BIC     = 0xF0200000,
    THUMB_BW      = 0xF0008000,
    THUMB_CMP     = 0x2800,
    THUMB_CMPW    = 0xF1B00F00,
    THUMB_DMB     = 0xF3BF8F50,
    THUMB_LDR     = 0xF1A00000,
    THUMB_LDREX   = 0xE8500F00,
    THUMB_MOVT    = 0xF2C00000,
    THUMB_MOVW    = 0xF2400000,
    THUMB_MOV     = 0x4600,
    THUMB_MRS     = 0xF3EF8000,
    THUMB_MSR     = 0xF3808000,
    THUMB_POP     = 0xBC00,
    THUMB_POPW    = 0xE8BD0000,
    THUMB_PUSH_T1 = 0xB400,
    THUMB_PUSH_T2 = 0xE92D0000,
    THUMB_SBFX    = 0XF3400000,
    THUMB_STR     = 0x6000,
    THUMB_STREX   = 0xE8400000,
    THUMB_VPOP    = 0xECBD0B00,
    THUMB_VPUSH   = 0xED2D0B00,
  };

struct arm_operand
{
  /* Type of the operand.  */
  enum arm_operand_type type;

  /* Value of the operand according to the type.  */
  union
    {
      uint32_t imm;
      uint8_t reg;
      struct arm_memory_operand mem;
    };
};

/* List of condition codes we need.
   See ARM Architecture Reference Manual, section "Conditional execution".  */

enum arm_condition_codes
{
  NE = 0x1, /* NE. Not Equal.  */
  LT = 0xB, /* Signed less than.  */
  AL = 0xE, /* AL. Always.  */
};

/* Helper function to create an immediate operand

   Example:

     p += emit_mov (p, r0, immediate_operand (12));  */

struct arm_operand immediate_operand (uint32_t imm);

/* Helper function to create a register operand.

   Example:

     p += emit_mov (p, r0, register_operand (r1));  */

struct arm_operand register_operand (uint8_t reg);

/* Helper function to create an memory operand.

   Example:

     p += emit_mov (p, r0, immediate_operand (12));  */

struct arm_operand memory_operand (struct arm_memory_operand mem);

/* Encode a bitfield with a repetition of BIT starting at from FROM for
   LENGHT.  Max 16 bits.  */

uint16_t repeat_bit(uint8_t bit, uint8_t from, uint8_t length);

/* Encode a register list bitfield, using a consecutive list of bits from
   FROM with length LENGTH and using an inital value of INITIAL. Max 16
   bits.  */

uint16_t encode_register_list (uint8_t from, uint8_t length, uint16_t initial);

/* Return the distance in bytes from FROM to TO and adjusted for prefetch.  */

uint32_t arm_arm_branch_relative_distance (CORE_ADDR from, CORE_ADDR to);

/* Return the distance in bytes from FROM to TO and adjusted for prefetch.  */

uint32_t arm_thumb_branch_relative_distance (CORE_ADDR from, CORE_ADDR to);

/* Return the distance in bytes from FROM to TO , adjusted for prefetch
   and for alignement when switching from ARM mode to Thumb mode.  */

uint32_t arm_thumb_to_arm_branch_relative_distance (CORE_ADDR from,
						    CORE_ADDR to);

/* Return the offset is bytes adjusted for prefetch.  */

uint32_t arm_arm_branch_adjusted_offset (uint32_t offset);

/* Return the offset in bytes adjusted for prefetch.  */

uint32_t arm_thumb_branch_adjusted_offset (uint32_t offset);

/* Return whether it's possible to jump from FROM to TO using a relative
   branch in arm mode.  */

int arm_arm_is_reachable (CORE_ADDR from, CORE_ADDR to);

/* Return whether it's possible to jump from FROM to TO using a relative
   branch in thumb mode.  */

int arm_thumb_is_reachable (CORE_ADDR from, CORE_ADDR to);

/* Write arm instructions to move the 32bit value VAL into register REG.  */

uint32_t * arm_emit_arm_mov_32 (uint32_t *mem, int reg, uint32_t val);

/* Write thumb instructions to move the 32bit value VAL into register REG.  */

uint16_t * arm_emit_thumb_mov_32 (uint16_t *mem, int reg, uint32_t val);

/* Write ARM branch instructions into *BUF.

   This is a base function to write
   B, BL and BLX instructions with immediate or register operands.

   Proper encodings documentation is provided in the
   arm_emit_arm_{b_,bl_,blx} helper functions.

   L if set a bl instruction will be written.
   X if set a blx instruction will be written.  */

int arm_emit_arm_branch (uint32_t *buf, enum arm_condition_codes cond,
			 struct arm_operand operand,
			 uint8_t l, uint8_t x);

/* Write Thumb branch instructions into *BUF.

   This is a base function to write
   BW, BL and BLX instructions with immediate or register operand.

   Proper encodings documentation is provided in the
   arm_emit_thumb_{bw_,bl_,blx} helper functions.

   REL is the relative offset of the label.
   L if set a bl instruction will be written.
   X if set a blx instruction will be written.  */

int arm_emit_thumb_branch (uint16_t *buf, struct arm_operand operand,
			   uint8_t l, uint8_t x);

/* Write an ARM B instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   B<c> <label>

   COND is the conditionial instruction flag.
   REL is the relative offset of the label.  */

int arm_emit_arm_b (uint32_t *buf, enum arm_condition_codes cond,
		    uint32_t rel);

/* Write an ARM BL instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   BL<c> <label>

   REL is the relative offset of the label.  */

int arm_emit_arm_bl (uint32_t *buf, enum arm_condition_codes cond,
		     uint32_t rel);

/* Write a Thumb BL instruction into *BUF.

   Encoding T1
   BL<c> <label>
   ARMv4T, ARMv5T*, ARMv6*, ARMv7 if J1 == J2 == 1
   ARMv6T2, ARMv7 otherwise
   Outside or last in IT block

   REL is the relative offset of the label.  */

int arm_emit_thumb_bl (uint16_t *buf, uint32_t rel);

/* Write a Thumb B instruction into *BUF.

   Encoding T1
   ARMv4T, ARMv5T*, ARMv6*, ARMv7
   B<c> <label>
   Not permitted in IT block.

   REL is the relative offset of the label.  */

int arm_emit_thumb_b (uint16_t *buf, enum arm_condition_codes cond,
		      uint32_t rel);

/* Write a Thumb B instruction into *BUF.

   Encoding T4
   ARMv6T2, ARMv7
   B<c>.W <label>
   Outside or last in IT block

   REL is the relative offset of the label.  */

int arm_emit_thumb_bw (uint16_t *buf, uint32_t rel);

/* Write a Thumb BW instruction into *BUF.

   Encoding T3
   ARMv6T2, ARMv7
   B<c>.W <label>
   Not permitted in IT block.

   REL is the relative offset of the label.  */

int arm_emit_thumb_bw_cond (uint16_t *buf, enum arm_condition_codes cond,
			    uint32_t rel);

/* Write an ARM BLX instruction into *BUF.

   Register:
   Encoding A1
   ARMv5T*, ARMv6*, ARMv7
   BLX<c> <Rm>

   OPERAND is the register or the immediate value that contains the branch
   target address and instruction set selection bit.  */

int arm_emit_arm_blx (uint32_t * buf,
		      enum arm_condition_codes cond,
		      struct arm_operand operand);

/* Write a Thumb BLX instruction into *BUF.

   Register:
   Encoding T1
   ARMv5T*, ARMv6*, ARMv7
   BLX<c> <Rm>
   Outside or last in IT block

   Immediate:
   Encoding T2
   BLX<c> <label>
   ARMv5T*, ARMv6*, ARMv7 if J1 == J2 == 1
   ARMv6T2, ARMv7 otherwise
   Outside or last in IT block

   OPERAND is the register or the immediate value that contains the branch
   target address and instruction set selection bit.  */


int arm_emit_thumb_blx (uint16_t *buf, struct arm_operand operand);

/* Write an ARM MOVW (Immediate) instruction into *BUF.

   Encoding A2
   ARMv6T2, ARMv7
   MOVW<c> <Rd>, #<imm16>

   RD is the destination register.
   OPERAND is the immediate value to be placed in RD.
*/

int arm_emit_arm_movw (uint32_t *buf, enum arm_condition_codes cond,
		       uint8_t rd,
		       struct arm_operand operand);

/* Write a Thumb MOVW (Immediate) instruction into *BUF.

   Encoding T3
   ARMv6T2, ARMv7
   MOVW<c> <Rd>, #<imm16>

   RD is the destination register.
   OPERAND is the immediate value to be placed in RD.  */

int arm_emit_thumb_movw (uint16_t *buf,
			 uint8_t rd,
			 struct arm_operand operand);

/* Write an ARM MOV instruction into *BUF.

   Encoding A1

   Immediate:
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   MOV{S}<c> <Rd>, #<const>

   Register:
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   MOV{S}<c> <Rd>, <Rm>

   RD is the destination register.
   OPERAND is the immediate value or source register.  */

int arm_emit_arm_mov (uint32_t *buf, enum arm_condition_codes cond,
		      uint8_t rd,
		      struct arm_operand operand);

/* Write an ARM MOVT instruction into *BUF.

   Encoding A1
   ARMv6T2, ARMv7
   MOVT<c> <Rd>, #<imm16>

   RD is the destination register.
   OPERAND is the immediate value to be placed in RD.  */

int arm_emit_arm_movt (uint32_t *buf, enum arm_condition_codes cond,
		       uint8_t rd,
		       struct arm_operand operand);

/* Write a Thumb MOVT instruction into *BUF.

   Encoding T1
   ARMv6T2, ARMv7
   MOVT<c> <Rd>, #<imm16>

   RD is the destination register.
   OPERAND is the immediate value to be placed in RD.  */

int arm_emit_thumb_movt (uint16_t *buf,
			 uint8_t rd,
			 struct arm_operand operand);

/* Write an ARM VPUSH instruction into *BUF.

   Encoding A1
   VFPv2, VFPv3, VFPv4, Advanced SIMD
   VPUSH<c> <list>
   <list> is consecutive 64-bit registers.

   COND is the conditionial instruction flag.
   RS is the starting register.
   LEN is the length of the register list.  */

int arm_emit_arm_vpush (uint32_t *buf, enum arm_condition_codes cond,
			uint8_t rs,
			uint8_t len);

/* Write a Thumb VPUSH instruction into *BUF.

   Encoding T1
   VFPv2, VFPv3, VFPv4, Advanced SIMD
   VPUSH<c> <list>
   <list> is consecutive 64-bit registers.

   COND is the conditionial instruction flag.
   RS is the starting register.
   LEN is the length of the register list.  */

int arm_emit_thumb_vpush (uint16_t *buf,
			  uint8_t rs,
			  uint8_t len);

/* Write an ARM PUSH instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   PUSH<c> <registers>
   <registers> contains more than one register

   COND is the conditionial instruction flag.
   REGISTER_LIST is the register list bitfield.  */

int arm_emit_arm_push_list (uint32_t *buf,
			    enum arm_condition_codes cond,
			    uint16_t register_list);

/* Write a Thumb PUSH instruction into *BUF.

   Encoding T2
   ARMv6T2, ARMv7
   PUSH<c>.W <registers>
   <registers> contains more than one register

   REGISTER_LIST is the register_list bitfield.
   LR denotes the presence of LR in the list.  */

int arm_emit_thumb_push_list (uint16_t *buf,
			      uint16_t register_list,
			      uint8_t lr);

/* Write an ARM PUSH instruction into *BUF.

   Encoding A2
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   PUSH<c> <registers>
   <registers> contains one register, <Rt>

   RT is the register to push.
   COND is the conditionial instruction flag.  */

int arm_emit_arm_push_one (uint32_t *buf,
			    enum arm_condition_codes cond,
			    uint8_t rt);

/* Write a Thumb PUSH instruction into *BUF.

   Encoding T1
   ARMv4T, ARMv5T*, ARMv6*, ARMv7
   PUSH<c> <registers>

   REGISTER_LIST is the registers list to push.
   LR denotes the presence of LR in the list.  */

int arm_emit_thumb_push_one (uint16_t *buf, uint8_t register_list, uint8_t lr);

/* Write an ARM MRS instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   MRS<c> <Rd>, <spec_reg>

   RD is the destination register.  */

int arm_emit_arm_mrs (uint32_t *buf,
		      enum arm_condition_codes cond,
		      uint8_t rd);

/* Write a Thumb MRS instruction into *BUF.

   Encoding T1
   ARMv6T2, ARMv7
   MRS<c> <Rd>, <spec_reg>

   RD is the destination register.  */

int arm_emit_thumb_mrs (uint16_t *buf, uint8_t rd);


/* Write a Thumb MOV Register instruction into *BUF.

   Encoding T1
   MOV<c> <Rd>, <Rm>
   ARMv6*, ARMv7 if <Rd> and <Rm> both from R0-R7
   ARMv4T, ARMv5T*, ARMv6*, ARMv7 otherwise
   If <Rd> is the PC, must be outside or last in IT block.

   RD is the destination register.
   OPERAND is the source register.  */

int arm_emit_thumb_mov (uint16_t *buf, uint8_t rd, struct arm_operand operand);

/* Write an ARM DMB instruction into *BUF.

   Encoding A1
   ARMv7
   DMB <option>

   option is ommited to mean SY.  */

int arm_emit_arm_dmb (uint32_t *buf);

/* Write a Thumb DMB instruction into *BUF.

   Encoding T1
   ARMv7
   DMB <option>

   option is ommited to mean SY.  */

int arm_emit_thumb_dmb (uint16_t *buf);

/* Write an ARM LDREX instruction into *BUF.
   Encoding A1
   ARMv6*, ARMv7
   LDREX<c> <Rt>, [<Rn>]

   COND is the conditionial instruction flag.
   RT is the destination register.
   RN is the base register.  */

int arm_emit_arm_ldrex (uint32_t *buf, enum arm_condition_codes cond,
			uint8_t rt, uint8_t rn);

/* Write a Thumb LDREX instruction into *BUF.

   Encoding T1
   ARMv6T2, ARMv7
   LDREX<c> <Rt>, [<Rn>{, #<imm>}]

   RT is the destination register.
   RN is the base register.

   OPERAND is the immediate offset added to the value of RN to form the
   address.  */

int arm_emit_thumb_ldrex (uint16_t *buf, int8_t rt, uint8_t rn,
			  struct arm_operand operand);

/* Write an ARM CMP (immediate) instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   CMP<c> <Rn>, #<const>

   COND is the conditionial instruction flag.
   RN is the base register.
   OPERAND is the immediate value to be compared with the value obtained
   from RN.  */

int arm_emit_arm_cmp (uint32_t *buf, enum arm_condition_codes cond,
		      uint8_t rn, struct arm_operand operand);


/* Write a Thumb CMP (immediate) instruction into *BUF.

   Encoding T1
   ARMv4T, ARMv5T*, ARMv6*, ARMv7
   CMP<c> <Rn>, #<imm8>

   RN is the base register.
   OPERAND is the immediate value to be compared with the value obtained
   from RN.  */

int arm_emit_thumb_cmp (uint16_t *buf, uint8_t rn, struct arm_operand operand);

/* Write a Thumb CMP.w (immediate) instruction into *BUF.

   Encoding T2
   ARMv6T2, ARMv7
   CMP<c>.W <Rn>, #<const>

   RN is the base register.
   OPERAND is the immediate value to be compared with the value obtained
   from RN.  */

int arm_emit_thumb_cmpw (uint16_t *buf, uint8_t rn, struct arm_operand operand);

/* Write an ARM BIC (immediate) instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   BIC{S}<c> <Rd>, <Rn>, #<const>

   COND is the conditionial instruction flag.
   RD is the destination register.
   RN is the base register.
   OPERAND is the immediate value to be bitwise inverted and ANDed with
   the value obtained from RN.  */

int arm_emit_arm_bic (uint32_t *buf, enum arm_condition_codes cond,
		      uint8_t rd, uint8_t rn, struct arm_operand operand);

/* Write a Thumb BIC (immediate) instruction into *BUF.

   Encoding T1
   ARMv6T2, ARMv7
   BIC{S}<c> <Rd>, <Rn>, #<const>

   RD is the destination register.
   RN is the base register.
   OPERAND is the immediate value to be bitwise inverted and ANDed with
   the value obtained from RN.  */

int arm_emit_thumb_bic (uint16_t *buf, uint8_t rd, uint8_t rn,
		      struct arm_operand operand);

/* Write an ARM STREX instruction into *BUF.

   Encoding A1
   ARMv6*, ARMv7
   STREX<c> <Rd>, <Rt>, [<Rn>]

   COND is the conditionial instruction flag.
   RD is the destination register.
   RT is the source register.
   RN is the base register.  */

int arm_emit_arm_strex (uint32_t *buf, enum arm_condition_codes cond,
			uint8_t rd, uint8_t rt, uint8_t rn);

/* Write a Thumb STREX (immediate) instruction into *BUF.

   Encoding T1
   ARMv6T2, ARMv7
   STREX<c> <Rd>, <Rt>, [<Rn>{, #<imm>}]

   RD is the destination register.
   RT is the source register.
   RN is the base register.
   OPERAND is the immediate offset added to the value of RN to form the
   address.  */

int arm_emit_thumb_strex (uint16_t *buf, uint8_t rd, uint8_t rt, uint8_t rn,
			  struct arm_operand operand);

/* Write an ARM STR (immediate) instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   STR<c> <Rt>, [<Rn>{, #+/-<imm12>}]
   STR<c> <Rt>, [<Rn>], #+/-<imm12>
   STR<c> <Rt>, [<Rn>, #+/-<imm12>]!

   COND is the conditionial instruction flag.
   RT is the source register.
   RN is the base register.
   OPERAND is the immediate offset used for forming the address.  */

int arm_emit_arm_str (uint32_t *buf, enum arm_condition_codes cond,
		      uint8_t rt, uint8_t rn,
		      struct arm_operand operand);

/* Write a Thumb STR (immediate) instruction into *BUF.

   Encoding T1
   ARMv4T, ARMv5T*, ARMv6*, ARMv7
   STR<c> <Rt>, [<Rn>{, #<imm>}]

   RT is the source register.
   RN is the base register.
   OPERAND is the immediate offset used for forming the address.  */

int arm_emit_thumb_str (uint16_t *buf, uint8_t rt, uint8_t rn,
			struct arm_operand operand);

/* Write an ARM ADD (immediate) instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   ADD{S}<c> <Rd>, <Rn>, #<const>

   COND is the conditionial instruction flag.
   RD is the destination register.
   RN is the base register.
   OPERAND is the immediate value to be added to the value obtained from RN.  */

int arm_emit_arm_add (uint32_t *buf, enum arm_condition_codes cond,
		      uint8_t rd, uint8_t rn,
		      struct arm_operand operand);

/* Write a Thumb ADD (SP plus immediate) instruction into *BUF.

   Encoding T2
   ARMv4T, ARMv5T*, ARMv6*, ARMv7
   ADD<c> SP, SP, #<imm>

   OPERAND is the immediate value to be added to the value obtained from SP.  */

int arm_emit_thumb_add_sp (uint16_t *buf, struct arm_operand operand);

/* Write an ARM POP instruction into *BUF.

   Encoding A2
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   POP<c> <registers>
   <registers> contains one register, <Rt>

   RT is the register to be loaded.
 */

int arm_emit_arm_pop_one (uint32_t *buf, enum arm_condition_codes cond,
			  uint8_t rt);

/* Write an ARM POP instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   POP<c> <registers>
   <registers> contains more than one register

   RT is the register to be loaded.  */

int arm_emit_arm_pop_list (uint32_t *buf, enum arm_condition_codes cond,
			   uint16_t register_list);

/* Write a Thumb POP instruction into *BUF.

   Encoding T1
   ARMv4T, ARMv5T*, ARMv6*, ARMv7
   POP<c> <registers>

   REGISTER_LIST is a list of one or more registers to be loaded.
   PC is a flag that triggers the addition of the PC register to the list.  */

int arm_emit_thumb_pop (uint16_t *buf, uint8_t register_list, uint8_t pc);

/* Write a Thumb POPW instruction into *BUF.

   Encoding T2
   ARMv6T2, ARMv7
   POP<c>.W <registers>
   <registers> contains more than one register

   REGISTER_LIST is a list of one or more registers to be loaded.
   PC is a flag that triggers the addition of the PC register to the list.
   LR is a flag that triggers the addition of the LR register to the list.  */

int arm_emit_thumb_popw_list (uint16_t *buf, uint16_t register_list, uint8_t pc,
			      uint8_t lr);

/* Write an ARM MSR instruction into *BUF.

   Encoding A1
   ARMv4*, ARMv5T*, ARMv6*, ARMv7
   MRS<c> <Rd>, <spec_reg>

   RN is the ARM core register to be transferred to <spec_reg>.  */

int arm_emit_arm_msr (uint32_t *buf, enum arm_condition_codes cond,
		      uint8_t rn);

/* Write a Thumb MRS instruction into *BUF.

   Encoding T1
   ARMv6T2, ARMv7
   MRS<c> <Rd>, <spec_reg>

   RN is the ARM core register to be transferred to <spec_reg>.  */

int arm_emit_thumb_msr (uint16_t *buf, uint8_t rn);


/* Write an ARM VPOP instruction into *BUF.

   Encoding A1
   VFPv2, VFPv3, VFPv4, Advanced SIMD
   VPOP <list>

   <list> is consecutive 64-bit registers

   COND is the conditionial instruction flag.
   RS is the starting register.
   LEN is the length of the register list.  */

int arm_emit_arm_vpop (uint32_t *buf, enum arm_condition_codes cond,
		       uint8_t rs,
		       uint8_t len);

/* Write a Thumb VPOP instruction into *BUF.

   Encoding T1
   VFPv2, VFPv3, VFPv4, Advanced SIMD
   VPOP <list>

   COND is the conditionial instruction flag.
   RS is the starting register.
   LEN is the length of the register list.  */

int arm_emit_thumb_vpop (uint16_t *buf,
			 uint8_t rs,
			 uint8_t len);

int arm_emit_arm_ldr_insn (uint32_t *buf, enum arm_condition_codes cond,
			   uint8_t rt,
			   uint8_t rn,
			   struct arm_memory_operand operand);

/* Load immediate encoding T3 */
int arm_emit_thumb_ldr_insn (uint32_t *buf,
			     uint8_t rt,
			     uint8_t rn,
			     struct arm_memory_operand operand);


int arm_emit_arm_sbfx_insn (uint32_t *buf, enum arm_condition_codes cond,
			    uint8_t rd,
			    uint8_t rn,
			    uint32_t lsb,
			    uint32_t width);

/* Emit thumb SBFX, encoding T1.  */
int arm_emit_thumb_sbfx_insn (uint32_t *buf,
			      uint8_t rd,
			      uint8_t rn,
			      uint32_t lsb,
			      uint32_t width);
#endif /* ARM_INSN_H */
