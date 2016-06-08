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

#include "common-defs.h"

#include "arm.h"
#include "arm-insn-reloc.h"

static int
arm_decode_misc_memhint_neon (uint32_t insn,
			      struct arm_insn_reloc_visitor *visitor,
			      struct arm_insn_reloc_data *data)
{
  unsigned int op1 = bits (insn, 20, 26), op2 = bits (insn, 4, 7);
  unsigned int rn = bits (insn, 16, 19);

  if (op1 == 0x10 && (op2 & 0x2) == 0x0 && (rn & 0xe) == 0x0)
    return visitor->others (insn, "cps", data);
  else if (op1 == 0x10 && op2 == 0x0 && (rn & 0xe) == 0x1)
    return visitor->others (insn, "setend", data);
  else if ((op1 & 0x60) == 0x20)
    return visitor->others (insn, "neon dataproc", data);
  else if ((op1 & 0x71) == 0x40)
    return visitor->others (insn, "neon elt/struct load/store", data);
  else if ((op1 & 0x77) == 0x41)
    return visitor->others (insn, "unallocated mem hint", data);
  else if ((op1 & 0x77) == 0x45)
    return visitor->preload (insn, data);  /* pli.  */
  else if ((op1 & 0x77) == 0x51)
    {
      if (rn != 0xf)
	return visitor->preload (insn, data);  /* pld/pldw.  */
      else
	return visitor->unpred (insn, data);
    }
  else if ((op1 & 0x77) == 0x55)
    return visitor->preload (insn, data);  /* pld/pldw.  */
  else if (op1 == 0x57)
    switch (op2)
      {
      case 0x1: return visitor->others (insn, "clrex", data);
      case 0x4: return visitor->others (insn, "dsb", data);
      case 0x5: return visitor->others (insn, "dmb", data);
      case 0x6: return visitor->others (insn, "isb", data);
      default: return visitor->unpred (insn, data);
      }
  else if ((op1 & 0x63) == 0x43)
    return visitor->unpred (insn, data);
  else if ((op2 & 0x1) == 0x0)
    switch (op1 & ~0x80)
      {
      case 0x61:
	return visitor->others (insn, "unallocated mem hint", data);
      case 0x65:
	return visitor->preload_reg (insn, data);  /* pli reg.  */
      case 0x71: case 0x75:
        /* pld/pldw reg.  */
	return visitor->preload_reg (insn, data);
      case 0x63: case 0x67: case 0x73: case 0x77:
	return visitor->unpred (insn, data);
      default:
	return visitor->undef (insn, data);
      }
  else
    return visitor->undef (insn, data);  /* Probably unreachable.  */
}

static int
arm_decode_unconditional (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
			  struct arm_insn_reloc_data *data)
{
  if (bit (insn, 27) == 0)
    return arm_decode_misc_memhint_neon (insn, visitor, data);
  /* Switch on bits: 0bxxxxx321xxx0xxxxxxxxxxxxxxxxxxxx.  */
  else switch (((insn & 0x7000000) >> 23) | ((insn & 0x100000) >> 20))
    {
    case 0x0: case 0x2:
      return visitor->others (insn, "srs", data);

    case 0x1: case 0x3:
      return visitor->others (insn, "rfe", data);

    case 0x4: case 0x5: case 0x6: case 0x7:
      return visitor->b_bl_blx (insn, data);

    case 0x8:
      switch ((insn & 0xe00000) >> 21)
	{
	case 0x1: case 0x3: case 0x4: case 0x5: case 0x6: case 0x7:
	  /* stc/stc2.  */
	  return visitor->copro_load_store (insn, data);

	case 0x2:
	  return visitor->others (insn, "mcrr/mcrr2", data);

	default:
	  return visitor->undef (insn, data);
	}

    case 0x9:
      {
	 int rn_f = (bits (insn, 16, 19) == 0xf);
	switch ((insn & 0xe00000) >> 21)
	  {
	  case 0x1: case 0x3:
	    /* ldc/ldc2 imm (undefined for rn == pc).  */
	    return rn_f ? visitor->undef (insn, data)
			: visitor->copro_load_store (insn, data);

	  case 0x2:
	    return visitor->others (insn, "mrrc/mrrc2", data);

	  case 0x4: case 0x5: case 0x6: case 0x7:
	    /* ldc/ldc2 lit (undefined for rn != pc).  */
	    return rn_f ? visitor->copro_load_store (insn, data)
			: visitor->undef (insn, data);

	  default:
	    return visitor->undef (insn, data);
	  }
      }

    case 0xa:
      return visitor->others (insn, "stc/stc2", data);

    case 0xb:
      if (bits (insn, 16, 19) == 0xf)
        /* ldc/ldc2 lit.  */
	return visitor->copro_load_store (insn, data);
      else
	return visitor->undef (insn, data);

    case 0xc:
      if (bit (insn, 4))
	return visitor->others (insn, "mcr/mcr2", data);
      else
	return visitor->others (insn, "cdp/cdp2", data);

    case 0xd:
      if (bit (insn, 4))
	return visitor->others (insn, "mrc/mrc2", data);
      else
	return visitor->others (insn, "cdp/cdp2", data);

    default:
      return visitor->undef (insn, data);
    }
}


/* Decode miscellaneous instructions in dp/misc encoding space.  */

static int
arm_decode_miscellaneous (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
			  struct arm_insn_reloc_data *data)
{
  unsigned int op2 = bits (insn, 4, 6);
  unsigned int op = bits (insn, 21, 22);

  switch (op2)
    {
    case 0x0:
      return visitor->others (insn, "mrs/msr", data);

    case 0x1:
      if (op == 0x1)  /* bx.  */
	return visitor->bx_blx_reg (insn, data);
      else if (op == 0x3)
	return visitor->others (insn, "clz", data);
      else
	return visitor->undef (insn, data);

    case 0x2:
      if (op == 0x1)
	/* Not really supported.  */
	return visitor->others (insn, "bxj", data);
      else
	return visitor->undef (insn, data);

    case 0x3:
      if (op == 0x1)
	return visitor->bx_blx_reg (insn, data);  /* blx register.  */
      else
	return visitor->undef (insn, data);

    case 0x5:
      return visitor->others (insn, "saturating add/sub", data);

    case 0x7:
      if (op == 0x1)
	return visitor->others (insn, "bkpt", data);
      else if (op == 0x3)
	/* Not really supported.  */
	return visitor->others (insn, "smc", data);

    default:
      return visitor->undef (insn, data);
    }
}

static int
arm_decode_dp_misc (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
		    struct arm_insn_reloc_data *data)
{
  if (bit (insn, 25))
    switch (bits (insn, 20, 24))
      {
      case 0x10:
	return visitor->others (insn, "movw", data);

      case 0x14:
	return visitor->others (insn, "movt", data);

      case 0x12:
      case 0x16:
	return visitor->others (insn, "msr imm", data);

      default:
	return visitor->alu_imm (insn, data);
      }
  else
    {
      uint32_t op1 = bits (insn, 20, 24), op2 = bits (insn, 4, 7);

      if ((op1 & 0x19) != 0x10 && (op2 & 0x1) == 0x0)
	return visitor->alu_reg (insn, data);
      else if ((op1 & 0x19) != 0x10 && (op2 & 0x9) == 0x1)
	return visitor->alu_shifted_reg (insn, data);
      else if ((op1 & 0x19) == 0x10 && (op2 & 0x8) == 0x0)
	return arm_decode_miscellaneous (insn, visitor, data);
      else if ((op1 & 0x19) == 0x10 && (op2 & 0x9) == 0x8)
	return visitor->others (insn, "halfword mul/mla", data);
      else if ((op1 & 0x10) == 0x00 && op2 == 0x9)
	return visitor->others (insn, "mul/mla", data);
      else if ((op1 & 0x10) == 0x10 && op2 == 0x9)
	return visitor->others (insn, "synch", data);
      else if (op2 == 0xb || (op2 & 0xd) == 0xd)
	/* 2nd arg means "unprivileged".  */
	return visitor->extra_ld_st (insn, data, (op1 & 0x12) == 0x02);
    }

  /* Should be unreachable.  */
  return 1;
}


static int
arm_decode_ld_st_word_ubyte (uint32_t insn,
			     struct arm_insn_reloc_visitor *visitor,
			     struct arm_insn_reloc_data *data)
{
  int a = bit (insn, 25), b = bit (insn, 4);
  uint32_t op1 = bits (insn, 20, 24);

  if ((!a && (op1 & 0x05) == 0x00 && (op1 & 0x17) != 0x02)
      || (a && (op1 & 0x05) == 0x00 && (op1 & 0x17) != 0x02 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 0, 4, 0);
  else if ((!a && (op1 & 0x17) == 0x02)
	    || (a && (op1 & 0x17) == 0x02 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 0, 4, 1);
  else if ((!a && (op1 & 0x05) == 0x01 && (op1 & 0x17) != 0x03)
	    || (a && (op1 & 0x05) == 0x01 && (op1 & 0x17) != 0x03 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 1, 4, 0);
  else if ((!a && (op1 & 0x17) == 0x03)
	   || (a && (op1 & 0x17) == 0x03 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 1, 4, 1);
  else if ((!a && (op1 & 0x05) == 0x04 && (op1 & 0x17) != 0x06)
	    || (a && (op1 & 0x05) == 0x04 && (op1 & 0x17) != 0x06 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 0, 1, 0);
  else if ((!a && (op1 & 0x17) == 0x06)
	   || (a && (op1 & 0x17) == 0x06 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 0, 1, 1);
  else if ((!a && (op1 & 0x05) == 0x05 && (op1 & 0x17) != 0x07)
	   || (a && (op1 & 0x05) == 0x05 && (op1 & 0x17) != 0x07 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 1, 1, 0);
  else if ((!a && (op1 & 0x17) == 0x07)
	   || (a && (op1 & 0x17) == 0x07 && !b))
    return visitor->ldr_str_ldrb_strb (insn, data, 1, 1, 1);

  /* Should be unreachable.  */
  return 1;
}

static int
arm_decode_media (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
		  struct arm_insn_reloc_data *data)
{
  switch (bits (insn, 20, 24))
    {
    case 0x00: case 0x01: case 0x02: case 0x03:
      return visitor->others (insn, "parallel add/sub signed", data);

    case 0x04: case 0x05: case 0x06: case 0x07:
      return visitor->others (insn, "parallel add/sub unsigned", data);

    case 0x08: case 0x09: case 0x0a: case 0x0b:
    case 0x0c: case 0x0d: case 0x0e: case 0x0f:
      return visitor->others (insn, "decode/pack/unpack/saturate/reverse",
			      data);

    case 0x18:
      if (bits (insn, 5, 7) == 0)  /* op2.  */
	 {
	  if (bits (insn, 12, 15) == 0xf)
	    return visitor->others (insn, "usad8", data);
	  else
	    return visitor->others (insn, "usada8", data);
	}
      else
	 return visitor->undef (insn, data);

    case 0x1a: case 0x1b:
      if (bits (insn, 5, 6) == 0x2)  /* op2[1:0].  */
	return visitor->others (insn, "sbfx", data);
      else
	return visitor->undef (insn, data);

    case 0x1c: case 0x1d:
      if (bits (insn, 5, 6) == 0x0)  /* op2[1:0].  */
	 {
	  if (bits (insn, 0, 3) == 0xf)
	    return visitor->others (insn, "bfc", data);
	  else
	    return visitor->others (insn, "bfi", data);
	}
      else
	return visitor->undef (insn, data);

    case 0x1e: case 0x1f:
      if (bits (insn, 5, 6) == 0x2)  /* op2[1:0].  */
	return visitor->others (insn, "ubfx", data);
      else
	return visitor->undef (insn, data);
    }

  /* Should be unreachable.  */
  return 1;
}

static int
arm_decode_b_bl_ldmstm (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
			struct arm_insn_reloc_data *data)
{
  if (bit (insn, 25))
    return visitor->b_bl_blx (insn, data);
  else
    return visitor->block_xfer (insn, data);
}

static int
arm_decode_ext_reg_ld_st (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
			  struct arm_insn_reloc_data *data)
{
  unsigned int opcode = bits (insn, 20, 24);

  switch (opcode)
    {
    case 0x04: case 0x05:  /* VFP/Neon mrrc/mcrr.  */
      return visitor->others (insn, "vfp/neon mrrc/mcrr", data);

    case 0x08: case 0x0a: case 0x0c: case 0x0e:
    case 0x12: case 0x16:
      return visitor->others (insn, "vfp/neon vstm/vpush", data);

    case 0x09: case 0x0b: case 0x0d: case 0x0f:
    case 0x13: case 0x17:
      return visitor->others (insn, "vfp/neon vldm/vpop", data);

    case 0x10: case 0x14: case 0x18: case 0x1c:  /* vstr.  */
    case 0x11: case 0x15: case 0x19: case 0x1d:  /* vldr.  */
      /* Note: no writeback for these instructions.  Bit 25 will always be
	 zero though (via caller), so the following works OK.  */
      return visitor->copro_load_store (insn, data);
    }

  /* Should be unreachable.  */
  return 1;
}


static int
arm_decode_svc_copro (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
		      struct arm_insn_reloc_data *data)
{
  unsigned int op1 = bits (insn, 20, 25);
  int op = bit (insn, 4);
  unsigned int coproc = bits (insn, 8, 11);

  if ((op1 & 0x20) == 0x00 && (op1 & 0x3a) != 0x00 && (coproc & 0xe) == 0xa)
    return arm_decode_ext_reg_ld_st (insn, visitor, data);
  else if ((op1 & 0x21) == 0x00 && (op1 & 0x3a) != 0x00
	   && (coproc & 0xe) != 0xa)
    /* stc/stc2.  */
    return visitor->copro_load_store (insn, data);
  else if ((op1 & 0x21) == 0x01 && (op1 & 0x3a) != 0x00
	   && (coproc & 0xe) != 0xa)
    /* ldc/ldc2 imm/lit.  */
    return visitor->copro_load_store (insn, data);
  else if ((op1 & 0x3e) == 0x00)
    return visitor->undef (insn, data);
  else if ((op1 & 0x3e) == 0x04 && (coproc & 0xe) == 0xa)
    return visitor->others (insn, "neon 64bit xfer", data);
  else if (op1 == 0x04 && (coproc & 0xe) != 0xa)
    return visitor->others (insn, "mcrr/mcrr2", data);
  else if (op1 == 0x05 && (coproc & 0xe) != 0xa)
    return visitor->others (insn, "mrrc/mrrc2", data);
  else if ((op1 & 0x30) == 0x20 && !op)
    {
      if ((coproc & 0xe) == 0xa)
	return visitor->others (insn, "vfp dataproc", data);
      else
	return visitor->others (insn, "cdp/cdp2", data);
    }
  else if ((op1 & 0x30) == 0x20 && op)
    return visitor->others (insn, "neon 8/16/32 bit xfer", data);
  else if ((op1 & 0x31) == 0x20 && op && (coproc & 0xe) != 0xa)
    return visitor->others (insn, "mcr/mcr2", data);
  else if ((op1 & 0x31) == 0x21 && op && (coproc & 0xe) != 0xa)
    return visitor->others (insn, "mrc/mrc2", data);
  else if ((op1 & 0x30) == 0x30)
    return visitor->svc (insn, data);
  else
    return visitor->undef (insn, data);  /* Possibly unreachable.  */
}

int
arm_relocate_insn (uint32_t insn, struct arm_insn_reloc_visitor *visitor,
		   struct arm_insn_reloc_data *data)
{
  int err = 1;

  if ((insn & 0xf0000000) == 0xf0000000)
    err = arm_decode_unconditional (insn, visitor, data);
  else switch (((insn & 0x10) >> 4) | ((insn & 0xe000000) >> 24))
    {
    case 0x0: case 0x1: case 0x2: case 0x3:
      err = arm_decode_dp_misc (insn, visitor, data);
      break;

    case 0x4: case 0x5: case 0x6:
      err = arm_decode_ld_st_word_ubyte (insn, visitor, data);
      break;

    case 0x7:
      err = arm_decode_media (insn, visitor, data);
      break;

    case 0x8: case 0x9: case 0xa: case 0xb:
      err = arm_decode_b_bl_ldmstm (insn, visitor, data);
      break;

    case 0xc: case 0xd: case 0xe: case 0xf:
      err = arm_decode_svc_copro (insn, visitor, data);
      break;
    }

  return err;
}

/* Decode shifted register instructions.  */

static int
thumb2_decode_dp_shift_reg (uint16_t insn1, uint16_t insn2,
			    struct thumb_32bit_insn_reloc_visitor *visitor,
			    struct arm_insn_reloc_data *data)
{
  /* PC is only allowed to be used in instruction MOV.  */

  unsigned int op = bits (insn1, 5, 8);
  unsigned int rn = bits (insn1, 0, 3);

  if (op == 0x2 && rn == 0xf) /* MOV */
    return visitor->alu_imm (insn1, insn2, data);
  else
    return visitor->others (insn1, insn2, "dp (shift reg)", data);
}


/* Decode extension register load/store.  Exactly the same as
   arm_decode_ext_reg_ld_st.  */

static int
thumb2_decode_ext_reg_ld_st (uint16_t insn1, uint16_t insn2,
			     struct thumb_32bit_insn_reloc_visitor *visitor,
			     struct arm_insn_reloc_data *data)
{
  unsigned int opcode = bits (insn1, 4, 8);

  switch (opcode)
    {
    case 0x04: case 0x05:
      return visitor->others (insn1, insn2, "vfp/neon vmov", data);

    case 0x08: case 0x0c: /* 01x00 */
    case 0x0a: case 0x0e: /* 01x10 */
    case 0x12: case 0x16: /* 10x10 */
      return visitor->others (insn1, insn2, "vfp/neon vstm/vpush", data);

    case 0x09: case 0x0d: /* 01x01 */
    case 0x0b: case 0x0f: /* 01x11 */
    case 0x13: case 0x17: /* 10x11 */
      return visitor->others (insn1, insn2, "vfp/neon vldm/vpop", data);

    case 0x10: case 0x14: case 0x18: case 0x1c:  /* vstr.  */
      return visitor->others (insn1, insn2, "vstr", data);
    case 0x11: case 0x15: case 0x19: case 0x1d:  /* vldr.  */
      return visitor->copro_load_store (insn1, insn2, data);
    }

  /* Should be unreachable.  */
  return 1;
}


static int
decode_thumb_32bit_ld_mem_hints (uint16_t insn1, uint16_t insn2,
				 struct thumb_32bit_insn_reloc_visitor *visitor,
				 struct arm_insn_reloc_data *data)
{
  int rt = bits (insn2, 12, 15);
  int rn = bits (insn1, 0, 3);
  int op1 = bits (insn1, 7, 8);

  switch (bits (insn1, 5, 6))
    {
    case 0: /* Load byte and memory hints */
      if (rt == 0xf) /* PLD/PLI */
	{
	  if (rn == 0xf)
	    /* PLD literal or Encoding T3 of PLI(immediate, literal).  */
	    return visitor->preload (insn1, insn2, data);
	  else
	    return visitor->others (insn1, insn2, "pli/pld", data);
	}
      else
	{
	  if (rn == 0xf) /* LDRB/LDRSB (literal) */
	    return visitor->load_literal (insn1, insn2, data, 1);
	  else
	    return visitor->others (insn1, insn2, "ldrb{reg, immediate}/ldrbt",
				    data);
	}

      break;
    case 1: /* Load halfword and memory hints.  */
      if (rt == 0xf) /* PLD{W} and Unalloc memory hint.  */
	return visitor->others (insn1, insn2, "pld/unalloc memhint", data);
      else
	{
	  if (rn == 0xf)
	    return visitor->load_literal (insn1, insn2, data, 2);
	  else
	    return visitor->others (insn1, insn2, "ldrh/ldrht", data);
	}
      break;
    case 2: /* Load word */
      {
	int insn2_bit_8_11 = bits (insn2, 8, 11);

	if (rn == 0xf)
	  return visitor->load_literal (insn1, insn2, data, 4);
	else if (op1 == 0x1) /* Encoding T3 */
	  return visitor->load_reg_imm (insn1, insn2, data, 0, 1);
	else /* op1 == 0x0 */
	  {
	    if (insn2_bit_8_11 == 0xc || (insn2_bit_8_11 & 0x9) == 0x9)
	      /* LDR (immediate) */
	      return visitor->load_reg_imm (insn1, insn2, data,
					       bit (insn2, 8), 1);
	    else if (insn2_bit_8_11 == 0xe) /* LDRT */
	      return visitor->others (insn1, insn2, "ldrt", data);
	    else
	      /* LDR (register) */
	      return visitor->load_reg_imm (insn1, insn2, data, 0, 0);
	  }
	break;
      }
    default:
      return visitor->undef (insn1, insn2, data);
    }
  return 0;
}

static int
thumb2_decode_svc_copro (uint16_t insn1, uint16_t insn2,
			 struct thumb_32bit_insn_reloc_visitor *visitor,
			 struct arm_insn_reloc_data *data)
{
  unsigned int coproc = bits (insn2, 8, 11);
  unsigned int bit_5_8 = bits (insn1, 5, 8);
  unsigned int bit_9 = bit (insn1, 9);
  unsigned int bit_4 = bit (insn1, 4);

  if (bit_9 == 0)
    {
      if (bit_5_8 == 2)
	return visitor->others (insn1, insn2,
				"neon 64bit xfer/mrrc/mrrc2/mcrr/mcrr2", data);
      else if (bit_5_8 == 0) /* UNDEFINED.  */
	return visitor->undef (insn1, insn2, data);
      else
	{
	   /*coproc is 101x.  SIMD/VFP, ext registers load/store.  */
	  if ((coproc & 0xe) == 0xa)
	    return thumb2_decode_ext_reg_ld_st (insn1, insn2, visitor, data);
	  else /* coproc is not 101x.  */
	    {
	      if (bit_4 == 0) /* STC/STC2.  */
		return visitor->others (insn1, insn2, "stc/stc2", data);
	      else /* LDC/LDC2 {literal, immeidate}.  */
		return visitor->copro_load_store (insn1, insn2, data);
	    }
	}
    }
  else
    return visitor->others (insn1, insn2, "coproc", data);

  return 0;
}

int
thumb_32bit_relocate_insn (uint16_t insn1, uint16_t insn2,
			   struct thumb_32bit_insn_reloc_visitor *visitor,
			   struct arm_insn_reloc_data *data)
{
  int err = 0;
  unsigned short op = bit (insn2, 15);
  unsigned int op1 = bits (insn1, 11, 12);

  switch (op1)
    {
    case 1:
      {
	switch (bits (insn1, 9, 10))
	  {
	  case 0:
	    if (bit (insn1, 6))
	      {
		/* Load/store {dual, execlusive}, table branch.  */
		if (bits (insn1, 7, 8) == 1 && bits (insn1, 4, 5) == 1
		    && bits (insn2, 5, 7) == 0)
		  err = visitor->table_branch (insn1, insn2, data);
		else
		  /* PC is not allowed to use in load/store {dual, exclusive}
		     instructions.  */
		  err = visitor->others (insn1, insn2, "load/store dual/ex",
					 data);
	      }
	    else /* load/store multiple */
	      {
		switch (bits (insn1, 7, 8))
		  {
		  case 0: case 3: /* SRS, RFE */
		    err = visitor->others (insn1, insn2, "srs/rfe", data);
		    break;
		  case 1: case 2: /* LDM/STM/PUSH/POP */
		    err = visitor->block_xfer (insn1, insn2, data);
		    break;
		  }
	      }
	    break;

	  case 1:
	    /* Data-processing (shift register).  */
	    err = thumb2_decode_dp_shift_reg (insn1, insn2, visitor, data);
	    break;
	  default: /* Coprocessor instructions.  */
	    err = thumb2_decode_svc_copro (insn1, insn2, visitor, data);
	    break;
	  }
      break;
      }
    case 2: /* op1 = 2 */
      if (op) /* Branch and misc control.  */
	{
	  if (bit (insn2, 14)  /* BLX/BL */
	      || bit (insn2, 12) /* Unconditional branch */
	      || (bits (insn1, 7, 9) != 0x7)) /* Conditional branch */
	    err = visitor->b_bl_blx (insn1, insn2, data);
	  else
	    err = visitor->others (insn1, insn2, "misc ctrl", data);
	}
      else
	{
	  if (bit (insn1, 9)) /* Data processing (plain binary imm).  */
	    {
	      int op = bits (insn1, 4, 8);
	      int rn = bits (insn1, 0, 3);
	      if ((op == 0 || op == 0xa) && rn == 0xf)
		err = visitor->pc_relative_32bit (insn1, insn2, data);
	      else
		err = visitor->others (insn1, insn2, "dp/pb", data);
	    }
	  else /* Data processing (modified immeidate) */
	    err = visitor->others (insn1, insn2, "dp/mi", data);
	}
      break;
    case 3: /* op1 = 3 */
      switch (bits (insn1, 9, 10))
	{
	case 0:
	  if (bit (insn1, 4))
	    err = decode_thumb_32bit_ld_mem_hints (insn1, insn2, visitor, data);
	  else /* NEON Load/Store and Store single data item */
	    err = visitor->others (insn1, insn2, "neon elt/struct load/store",
				   data);
	  break;
	case 1: /* op1 = 3, bits (9, 10) == 1 */
	  switch (bits (insn1, 7, 8))
	    {
	    case 0: case 1: /* Data processing (register) */
	      err = visitor->others (insn1, insn2, "dp(reg)", data);
	      break;
	    case 2: /* Multiply and absolute difference */
	      err = visitor->others (insn1, insn2, "mul/mua/diff", data);
	      break;
	    case 3: /* Long multiply and divide */
	      err = visitor->others (insn1, insn2, "lmul/lmua", data);
	      break;
	    }
	  break;
	default: /* Coprocessor instructions */
	  err = thumb2_decode_svc_copro (insn1, insn2, visitor, data);
	  break;
	}
      break;
    default:
      err = 1;
    }

  return err;
}

static int
thumb_decode_pc_relative_16bit (uint16_t insn,
				struct thumb_16bit_insn_reloc_visitor *visitor,
				struct arm_insn_reloc_data *data)
{
  unsigned int rd = bits (insn, 8, 10);
  unsigned int imm8 = bits (insn, 0, 7);

  return visitor->pc_relative_16bit (insn, data, rd, imm8);
}

int
thumb_16bit_relocate_insn (uint16_t insn1,
			   struct thumb_16bit_insn_reloc_visitor *visitor,
			   struct arm_insn_reloc_data *data)
{
  unsigned short op_bit_12_15 = bits (insn1, 12, 15);
  unsigned short op_bit_10_11 = bits (insn1, 10, 11);
  int err = 0;

  /* 16-bit thumb instructions.  */
  switch (op_bit_12_15)
    {
      /* Shift (imme), add, subtract, move and compare.  */
    case 0: case 1: case 2: case 3:
      err = visitor->others (insn1, "shift/add/sub/mov/cmp", data);
      break;
    case 4:
      switch (op_bit_10_11)
	{
	case 0: /* Data-processing */
	  err = visitor->others (insn1, "data-processing", data);
	  break;
	case 1: /* Special data instructions and branch and exchange.  */
	  {
	    unsigned short op = bits (insn1, 7, 9);
	    if (op == 6 || op == 7) /* BX or BLX */
	      err = visitor->bx_blx_reg (insn1, data);
	    else if (bits (insn1, 6, 7) != 0) /* ADD/MOV/CMP high registers.  */
	      err = visitor->alu_reg (insn1, data);
	    else
	      err = visitor->others (insn1, "special data", data);
	  }
	  break;
	default: /* LDR (literal) */
	  err = visitor->load_literal (insn1, data);
	}
      break;
    case 5: case 6: case 7: case 8: case 9: /* Load/Store single data item */
      err = visitor->others (insn1, "ldr/str", data);
      break;
    case 10:
      if (op_bit_10_11 < 2) /* Generate PC-relative address */
	err = thumb_decode_pc_relative_16bit (insn1, visitor, data);
      else /* Generate SP-relative address */
	err = visitor->others (insn1, "sp-relative", data);
      break;
    case 11: /* Misc 16-bit instructions */
      {
	switch (bits (insn1, 8, 11))
	  {
	  case 1: case 3:  case 9: case 11: /* CBNZ, CBZ */
	    err = visitor->cbnz_cbz (insn1, data);
	    break;
	  case 12: case 13: /* POP */
	    if (bit (insn1, 8)) /* PC is in register list.  */
	      err = visitor->pop_pc_16bit (insn1, data);
	    else
	      err = visitor->others (insn1, "pop", data);
	    break;
	  case 15: /* If-Then, and hints */
	    if (bits (insn1, 0, 3))
	      /* If-Then makes up to four following instructions conditional.
		 IT instruction itself is not conditional, so handle it as a
		 common unmodified instruction.  */
	      err = visitor->others (insn1, "If-Then", data);
	    else
	      err = visitor->others (insn1, "hints", data);
	    break;
	  default:
	    err = visitor->others (insn1, "misc", data);
	  }
      }
      break;
    case 12:
      if (op_bit_10_11 < 2) /* Store multiple registers */
	err = visitor->others (insn1, "stm", data);
      else /* Load multiple registers */
	err = visitor->others (insn1, "ldm", data);
      break;
    case 13: /* Conditional branch and supervisor call */
      if (bits (insn1, 9, 11) != 7) /* conditional branch */
	err = visitor->b (insn1, data);
      else
	err = visitor->svc (insn1, data);
      break;
    case 14: /* Unconditional branch */
      err = visitor->b (insn1, data);
      break;
    default:
      err = 1;
    }

  return err;
}
