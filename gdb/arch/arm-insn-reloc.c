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
