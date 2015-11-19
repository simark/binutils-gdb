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

#include "common-defs.h"
#include "gdb_vecs.h"
#include "arm.h"
#include "arm-get-next-pcs.h"

/* Advance the state of the IT block and return that state.  */

static int
thumb_advance_itstate (unsigned int itstate)
{
  /* Preserve IT[7:5], the first three bits of the condition.  Shift
     the upcoming condition flags left by one bit.  */
  itstate = (itstate & 0xe0) | ((itstate << 1) & 0x1f);

  /* If we have finished the IT block, clear the state.  */
  if ((itstate & 0x0f) == 0)
    itstate = 0;

  return itstate;
}

/* See arm-get-next-pcs.h.  */

int
arm_instruction_changes_pc (uint32_t this_instr)
{
  if (bits (this_instr, 28, 31) == INST_NV)
    /* Unconditional instructions.  */
    switch (bits (this_instr, 24, 27))
      {
      case 0xa:
      case 0xb:
	/* Branch with Link and change to Thumb.  */
	return 1;
      case 0xc:
      case 0xd:
      case 0xe:
	/* Coprocessor register transfer.  */
        if (bits (this_instr, 12, 15) == 15)
	  error (_("Invalid update to pc in instruction"));
	return 0;
      default:
	return 0;
      }
  else
    switch (bits (this_instr, 25, 27))
      {
      case 0x0:
	if (bits (this_instr, 23, 24) == 2 && bit (this_instr, 20) == 0)
	  {
	    /* Multiplies and extra load/stores.  */
	    if (bit (this_instr, 4) == 1 && bit (this_instr, 7) == 1)
	      /* Neither multiplies nor extension load/stores are allowed
		 to modify PC.  */
	      return 0;

	    /* Otherwise, miscellaneous instructions.  */

	    /* BX <reg>, BXJ <reg>, BLX <reg> */
	    if (bits (this_instr, 4, 27) == 0x12fff1
		|| bits (this_instr, 4, 27) == 0x12fff2
		|| bits (this_instr, 4, 27) == 0x12fff3)
	      return 1;

	    /* Other miscellaneous instructions are unpredictable if they
	       modify PC.  */
	    return 0;
	  }
	/* Data processing instruction.  Fall through.  */

      case 0x1:
	if (bits (this_instr, 12, 15) == 15)
	  return 1;
	else
	  return 0;

      case 0x2:
      case 0x3:
	/* Media instructions and architecturally undefined instructions.  */
	if (bits (this_instr, 25, 27) == 3 && bit (this_instr, 4) == 1)
	  return 0;

	/* Stores.  */
	if (bit (this_instr, 20) == 0)
	  return 0;

	/* Loads.  */
	if (bits (this_instr, 12, 15) == ARM_PC_REGNUM)
	  return 1;
	else
	  return 0;

      case 0x4:
	/* Load/store multiple.  */
	if (bit (this_instr, 20) == 1 && bit (this_instr, 15) == 1)
	  return 1;
	else
	  return 0;

      case 0x5:
	/* Branch and branch with link.  */
	return 1;

      case 0x6:
      case 0x7:
	/* Coprocessor transfers or SWIs can not affect PC.  */
	return 0;

      default:
	internal_error (__FILE__, __LINE__, _("bad value in switch"));
      }
}

/* See arm-get-next-pcs.h.  */

int
thumb_instruction_changes_pc (unsigned short inst)
{
  if ((inst & 0xff00) == 0xbd00)	/* pop {rlist, pc} */
    return 1;

  if ((inst & 0xf000) == 0xd000)	/* conditional branch */
    return 1;

  if ((inst & 0xf800) == 0xe000)	/* unconditional branch */
    return 1;

  if ((inst & 0xff00) == 0x4700)	/* bx REG, blx REG */
    return 1;

  if ((inst & 0xff87) == 0x4687)	/* mov pc, REG */
    return 1;

  if ((inst & 0xf500) == 0xb100)	/* CBNZ or CBZ.  */
    return 1;

  return 0;
}


/* See arm-get-next-pcs.h.  */

int
thumb2_instruction_changes_pc (unsigned short inst1, unsigned short inst2)
{
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0x8000) == 0x8000)
    {
      /* Branches and miscellaneous control instructions.  */

      if ((inst2 & 0x1000) != 0 || (inst2 & 0xd001) == 0xc000)
	{
	  /* B, BL, BLX.  */
	  return 1;
	}
      else if (inst1 == 0xf3de && (inst2 & 0xff00) == 0x3f00)
	{
	  /* SUBS PC, LR, #imm8.  */
	  return 1;
	}
      else if ((inst2 & 0xd000) == 0x8000 && (inst1 & 0x0380) != 0x0380)
	{
	  /* Conditional branch.  */
	  return 1;
	}

      return 0;
    }

  if ((inst1 & 0xfe50) == 0xe810)
    {
      /* Load multiple or RFE.  */

      if (bit (inst1, 7) && !bit (inst1, 8))
	{
	  /* LDMIA or POP */
	  if (bit (inst2, 15))
	    return 1;
	}
      else if (!bit (inst1, 7) && bit (inst1, 8))
	{
	  /* LDMDB */
	  if (bit (inst2, 15))
	    return 1;
	}
      else if (bit (inst1, 7) && bit (inst1, 8))
	{
	  /* RFEIA */
	  return 1;
	}
      else if (!bit (inst1, 7) && !bit (inst1, 8))
	{
	  /* RFEDB */
	  return 1;
	}

      return 0;
    }

  if ((inst1 & 0xffef) == 0xea4f && (inst2 & 0xfff0) == 0x0f00)
    {
      /* MOV PC or MOVS PC.  */
      return 1;
    }

  if ((inst1 & 0xff70) == 0xf850 && (inst2 & 0xf000) == 0xf000)
    {
      /* LDR PC.  */
      if (bits (inst1, 0, 3) == 15)
	return 1;
      if (bit (inst1, 7))
	return 1;
      if (bit (inst2, 11))
	return 1;
      if ((inst2 & 0x0fc0) == 0x0000)
	return 1;

      return 0;
    }

  if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf000)
    {
      /* TBB.  */
      return 1;
    }

  if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf010)
    {
      /* TBH.  */
      return 1;
    }

  return 0;
}

/* Checks for an atomic sequence of instructions beginning with a LDREX{,B,H,D}
   instruction and ending with a STREX{,B,H,D} instruction.  If such a sequence
   is found, attempt to step through it.  The end of the sequence address is
   added to the next_pcs list.  */

static int
thumb_deal_with_atomic_sequence_raw (struct arm_get_next_pcs* self,
				     CORE_ADDR pc,
				     VEC (CORE_ADDR) **next_pcs)
{
  int byte_order_for_code = self->byte_order_for_code;
  CORE_ADDR breaks[2] = {-1, -1};
  CORE_ADDR loc = pc;
  unsigned short insn1, insn2;
  int insn_count;
  int index;
  int last_breakpoint = 0; /* Defaults to 0 (no breakpoints placed).  */
  const int atomic_sequence_length = 16; /* Instruction sequence length.  */
  ULONGEST status, itstate;

  /* We currently do not support atomic sequences within an IT block.  */
  status = self->ops->collect_register_unsigned (self, ARM_PS_REGNUM);

  itstate = ((status >> 8) & 0xfc) | ((status >> 25) & 0x3);
  if (itstate & 0x0f)
    return 0;

  /* Assume all atomic sequences start with a ldrex{,b,h,d} instruction.  */
  insn1 = self->ops->read_memory_unsigned_integer (loc, 2, byte_order_for_code);

  loc += 2;
  if (thumb_insn_size (insn1) != 4)
    return 0;

  insn2 = self->ops->read_memory_unsigned_integer (loc, 2, byte_order_for_code);

  loc += 2;
  if (!((insn1 & 0xfff0) == 0xe850
        || ((insn1 & 0xfff0) == 0xe8d0 && (insn2 & 0x00c0) == 0x0040)))
    return 0;

  /* Assume that no atomic sequence is longer than "atomic_sequence_length"
     instructions.  */
  for (insn_count = 0; insn_count < atomic_sequence_length; ++insn_count)
    {
      insn1
	= self->ops->read_memory_unsigned_integer (loc, 2,byte_order_for_code);
      loc += 2;

      if (thumb_insn_size (insn1) != 4)
	{
	  /* Assume that there is at most one conditional branch in the
	     atomic sequence.  If a conditional branch is found, put a
	     breakpoint in its destination address.  */
	  if ((insn1 & 0xf000) == 0xd000 && bits (insn1, 8, 11) != 0x0f)
	    {
	      if (last_breakpoint > 0)
		return 0; /* More than one conditional branch found,
			     fallback to the standard code.  */

	      breaks[1] = loc + 2 + (sbits (insn1, 0, 7) << 1);
	      last_breakpoint++;
	    }

	  /* We do not support atomic sequences that use any *other*
	     instructions but conditional branches to change the PC.
	     Fall back to standard code to avoid losing control of
	     execution.  */
	  else if (thumb_instruction_changes_pc (insn1))
	    return 0;
	}
      else
	{
	  insn2 = self->ops->read_memory_unsigned_integer
	    (loc, 2, byte_order_for_code);

	  loc += 2;

	  /* Assume that there is at most one conditional branch in the
	     atomic sequence.  If a conditional branch is found, put a
	     breakpoint in its destination address.  */
	  if ((insn1 & 0xf800) == 0xf000
	      && (insn2 & 0xd000) == 0x8000
	      && (insn1 & 0x0380) != 0x0380)
	    {
	      int sign, j1, j2, imm1, imm2;
	      unsigned int offset;

	      sign = sbits (insn1, 10, 10);
	      imm1 = bits (insn1, 0, 5);
	      imm2 = bits (insn2, 0, 10);
	      j1 = bit (insn2, 13);
	      j2 = bit (insn2, 11);

	      offset = (sign << 20) + (j2 << 19) + (j1 << 18);
	      offset += (imm1 << 12) + (imm2 << 1);

	      if (last_breakpoint > 0)
		return 0; /* More than one conditional branch found,
			     fallback to the standard code.  */

	      breaks[1] = loc + offset;
	      last_breakpoint++;
	    }

	  /* We do not support atomic sequences that use any *other*
	     instructions but conditional branches to change the PC.
	     Fall back to standard code to avoid losing control of
	     execution.  */
	  else if (thumb2_instruction_changes_pc (insn1, insn2))
	    return 0;

	  /* If we find a strex{,b,h,d}, we're done.  */
	  if ((insn1 & 0xfff0) == 0xe840
	      || ((insn1 & 0xfff0) == 0xe8c0 && (insn2 & 0x00c0) == 0x0040))
	    break;
	}
    }

  /* If we didn't find the strex{,b,h,d}, we cannot handle the sequence.  */
  if (insn_count == atomic_sequence_length)
    return 0;

  /* Insert a breakpoint right after the end of the atomic sequence.  */
  breaks[0] = loc;

  /* Check for duplicated breakpoints.  Check also for a breakpoint
     placed (branch instruction's destination) anywhere in sequence.  */
  if (last_breakpoint
      && (breaks[1] == breaks[0]
	  || (breaks[1] >= pc && breaks[1] < loc)))
    last_breakpoint = 0;

  /* Adds the breakpoints to the list to be inserted.  */
  for (index = 0; index <= last_breakpoint; index++)
    {
      VEC_safe_push (CORE_ADDR, *next_pcs,
		     MAKE_THUMB_ADDR (breaks[index]));
    }

  return 1;
}

/* Checks for an atomic sequence of instructions beginning with a LDREX{,B,H,D}
   instruction and ending with a STREX{,B,H,D} instruction.  If such a sequence
   is found, attempt to step through it.  The end of the sequence address is
   added to the next_pcs list.  */

static int
arm_deal_with_atomic_sequence_raw (struct arm_get_next_pcs* self,
				   CORE_ADDR pc,
				   VEC (CORE_ADDR) **next_pcs)
{
  int byte_order_for_code = self->byte_order_for_code;
  CORE_ADDR breaks[2] = {-1, -1};
  CORE_ADDR loc = pc;
  unsigned int insn;
  int insn_count;
  int index;
  int last_breakpoint = 0; /* Defaults to 0 (no breakpoints placed).  */
  const int atomic_sequence_length = 16; /* Instruction sequence length.  */

  /* Assume all atomic sequences start with a ldrex{,b,h,d} instruction.
     Note that we do not currently support conditionally executed atomic
     instructions.  */
  insn = self->ops->read_memory_unsigned_integer (loc, 4, byte_order_for_code);

  loc += 4;
  if ((insn & 0xff9000f0) != 0xe1900090)
    return 0;

  /* Assume that no atomic sequence is longer than "atomic_sequence_length"
     instructions.  */
  for (insn_count = 0; insn_count < atomic_sequence_length; ++insn_count)
    {
      insn = self->ops->read_memory_unsigned_integer
	(loc, 4, byte_order_for_code);

      loc += 4;

      /* Assume that there is at most one conditional branch in the atomic
         sequence.  If a conditional branch is found, put a breakpoint in
         its destination address.  */
      if (bits (insn, 24, 27) == 0xa)
	{
          if (last_breakpoint > 0)
            return 0; /* More than one conditional branch found, fallback
                         to the standard single-step code.  */

	  breaks[1] = BranchDest (loc - 4, insn);
	  last_breakpoint++;
        }

      /* We do not support atomic sequences that use any *other* instructions
         but conditional branches to change the PC.  Fall back to standard
	 code to avoid losing control of execution.  */
      else if (arm_instruction_changes_pc (insn))
	return 0;

      /* If we find a strex{,b,h,d}, we're done.  */
      if ((insn & 0xff9000f0) == 0xe1800090)
	break;
    }

  /* If we didn't find the strex{,b,h,d}, we cannot handle the sequence.  */
  if (insn_count == atomic_sequence_length)
    return 0;

  /* Insert a breakpoint right after the end of the atomic sequence.  */
  breaks[0] = loc;

  /* Check for duplicated breakpoints.  Check also for a breakpoint
     placed (branch instruction's destination) anywhere in sequence.  */
  if (last_breakpoint
      && (breaks[1] == breaks[0]
	  || (breaks[1] >= pc && breaks[1] < loc)))
    last_breakpoint = 0;

  /* Adds the breakpoints to the list to be inserted.  */
  for (index = 0; index <= last_breakpoint; index++)
    {
      VEC_safe_push (CORE_ADDR, *next_pcs, breaks[index]);
    }

  return 1;
}

/* See arm-get-next-pcs.h.  */

VEC (CORE_ADDR) *
arm_get_next_pcs (struct arm_get_next_pcs *self, CORE_ADDR pc)
{
  VEC (CORE_ADDR) *next_pcs = NULL;

  if (self->is_thumb)
    {
      if (!thumb_deal_with_atomic_sequence_raw (self, pc, &next_pcs))
	return thumb_get_next_pcs_raw (self, pc, &next_pcs);
    }
  else
    {
      if (!arm_deal_with_atomic_sequence_raw (self, pc, &next_pcs))
	return arm_get_next_pcs_raw (self, pc, &next_pcs);
    }

  return next_pcs;
}

/* Decode shifted register value.  */

static unsigned long
shifted_reg_val (struct arm_get_next_pcs* self, unsigned long inst,
		 int carry, unsigned long pc_val, unsigned long status_reg)
{
  unsigned long res, shift;
  int rm = bits (inst, 0, 3);
  unsigned long shifttype = bits (inst, 5, 6);

  if (bit (inst, 4))
    {
      int rs = bits (inst, 8, 11);
      shift = (rs == 15
	       ? pc_val + 8
	       : self->ops->collect_register_unsigned (self, rs)) & 0xFF;
    }
  else
    shift = bits (inst, 7, 11);

  res = (rm == ARM_PC_REGNUM
	 ? (pc_val + (bit (inst, 4) ? 12 : 8))
	 : self->ops->collect_register_unsigned (self, rm));

  switch (shifttype)
    {
    case 0:			/* LSL */
      res = shift >= 32 ? 0 : res << shift;
      break;

    case 1:			/* LSR */
      res = shift >= 32 ? 0 : res >> shift;
      break;

    case 2:			/* ASR */
      if (shift >= 32)
	shift = 31;
      res = ((res & 0x80000000L)
	     ? ~((~res) >> shift) : res >> shift);
      break;

    case 3:			/* ROR/RRX */
      shift &= 31;
      if (shift == 0)
	res = (res >> 1) | (carry ? 0x80000000L : 0);
      else
	res = (res >> shift) | (res << (32 - shift));
      break;
    }

  return res & 0xffffffff;
}

/* See arm-get-next-pcs.h.  */

VEC (CORE_ADDR) *
thumb_get_next_pcs_raw (struct arm_get_next_pcs *self,
			CORE_ADDR pc,
			VEC (CORE_ADDR) **next_pcs)
{
  int byte_order = self->byte_order;
  int byte_order_for_code = self->byte_order_for_code;
  unsigned long pc_val = ((unsigned long) pc) + 4;	/* PC after prefetch */
  unsigned short inst1;
  CORE_ADDR nextpc = pc + 2;		/* Default is next instruction.  */
  unsigned long offset;
  ULONGEST status, itstate;

  nextpc = MAKE_THUMB_ADDR (nextpc);
  pc_val = MAKE_THUMB_ADDR (pc_val);

  inst1 = self->ops->read_memory_unsigned_integer (pc, 2, byte_order_for_code);

  /* Thumb-2 conditional execution support.  There are eight bits in
     the CPSR which describe conditional execution state.  Once
     reconstructed (they're in a funny order), the low five bits
     describe the low bit of the condition for each instruction and
     how many instructions remain.  The high three bits describe the
     base condition.  One of the low four bits will be set if an IT
     block is active.  These bits read as zero on earlier
     processors.  */
  status = self->ops->collect_register_unsigned (self, ARM_PS_REGNUM);

  itstate = ((status >> 8) & 0xfc) | ((status >> 25) & 0x3);

  /* If-Then handling.  On GNU/Linux, where this routine is used, we
     use an undefined instruction as a breakpoint.  Unlike BKPT, IT
     can disable execution of the undefined instruction.  So we might
     miss the breakpoint if we set it on a skipped conditional
     instruction.  Because conditional instructions can change the
     flags, affecting the execution of further instructions, we may
     need to set two breakpoints.  */

  if (self->arm_linux_thumb2_breakpoint != NULL)
    {
      if ((inst1 & 0xff00) == 0xbf00 && (inst1 & 0x000f) != 0)
	{
	  /* An IT instruction.  Because this instruction does not
	     modify the flags, we can accurately predict the next
	     executed instruction.  */
	  itstate = inst1 & 0x00ff;
	  pc += thumb_insn_size (inst1);

	  while (itstate != 0 && ! condition_true (itstate >> 4, status))
	    {
	      inst1 = self->ops->read_memory_unsigned_integer
		(pc, 2,byte_order_for_code);
	      pc += thumb_insn_size (inst1);
	      itstate = thumb_advance_itstate (itstate);
	    }

	  VEC_safe_push (CORE_ADDR, *next_pcs,
			 MAKE_THUMB_ADDR (pc));
	  return *next_pcs;
	}
      else if (itstate != 0)
	{
	  /* We are in a conditional block.  Check the condition.  */
	  if (! condition_true (itstate >> 4, status))
	    {
	      /* Advance to the next executed instruction.  */
	      pc += thumb_insn_size (inst1);
	      itstate = thumb_advance_itstate (itstate);

	      while (itstate != 0 && ! condition_true (itstate >> 4, status))
		{
		  inst1 = self->ops->read_memory_unsigned_integer
		    (pc, 2, byte_order_for_code);

		  pc += thumb_insn_size (inst1);
		  itstate = thumb_advance_itstate (itstate);
		}

	      VEC_safe_push (CORE_ADDR, *next_pcs, MAKE_THUMB_ADDR (pc));
	      return *next_pcs;
	    }
	  else if ((itstate & 0x0f) == 0x08)
	    {
	      /* This is the last instruction of the conditional
		 block, and it is executed.  We can handle it normally
		 because the following instruction is not conditional,
		 and we must handle it normally because it is
		 permitted to branch.  Fall through.  */
	    }
	  else
	    {
	      int cond_negated;

	      /* There are conditional instructions after this one.
		 If this instruction modifies the flags, then we can
		 not predict what the next executed instruction will
		 be.  Fortunately, this instruction is architecturally
		 forbidden to branch; we know it will fall through.
		 Start by skipping past it.  */
	      pc += thumb_insn_size (inst1);
	      itstate = thumb_advance_itstate (itstate);

	      /* Set a breakpoint on the following instruction.  */
	      gdb_assert ((itstate & 0x0f) != 0);
	      VEC_safe_push (CORE_ADDR, *next_pcs, MAKE_THUMB_ADDR (pc));

	      cond_negated = (itstate >> 4) & 1;

	      /* Skip all following instructions with the same
		 condition.  If there is a later instruction in the IT
		 block with the opposite condition, set the other
		 breakpoint there.  If not, then set a breakpoint on
		 the instruction after the IT block.  */
	      do
		{
		  inst1 = self->ops->read_memory_unsigned_integer
		    (pc, 2, byte_order_for_code);

		  pc += thumb_insn_size (inst1);
		  itstate = thumb_advance_itstate (itstate);
		}
	      while (itstate != 0 && ((itstate >> 4) & 1) == cond_negated);

	      VEC_safe_push (CORE_ADDR, *next_pcs,
			     MAKE_THUMB_ADDR (pc));

	      return *next_pcs;
	    }
	}
    }
  else if (itstate & 0x0f)
    {
      /* We are in a conditional block.  Check the condition.  */
      int cond = itstate >> 4;

      if (! condition_true (cond, status))
	/* Advance to the next instruction.  All the 32-bit
	   instructions share a common prefix.  */
	VEC_safe_push (CORE_ADDR, *next_pcs,
		       MAKE_THUMB_ADDR (pc + thumb_insn_size (inst1)));

      return *next_pcs;

      /* Otherwise, handle the instruction normally.  */
    }

  if ((inst1 & 0xff00) == 0xbd00)	/* pop {rlist, pc} */
    {
      CORE_ADDR sp;

      /* Fetch the saved PC from the stack.  It's stored above
         all of the other registers.  */
      offset = bitcount (bits (inst1, 0, 7)) * INT_REGISTER_SIZE;

      sp = self->ops->collect_register_unsigned (self, ARM_SP_REGNUM);

      nextpc = self->ops->read_memory_unsigned_integer
	(sp + offset, 4, byte_order);
    }
  else if ((inst1 & 0xf000) == 0xd000)	/* conditional branch */
    {
      unsigned long cond = bits (inst1, 8, 11);
      if (cond == 0x0f)  /* 0x0f = SWI */
	{
	  nextpc = self->ops->syscall_next_pc (self, pc);
	}
      else if (cond != 0x0f && condition_true (cond, status))
	nextpc = pc_val + (sbits (inst1, 0, 7) << 1);
    }
  else if ((inst1 & 0xf800) == 0xe000)	/* unconditional branch */
    {
      nextpc = pc_val + (sbits (inst1, 0, 10) << 1);
    }
  else if (thumb_insn_size (inst1) == 4) /* 32-bit instruction */
    {
      unsigned short inst2;
      inst2 = self->ops->read_memory_unsigned_integer
	(pc + 2, 2, byte_order_for_code);

      /* Default to the next instruction.  */
      nextpc = pc + 4;
      nextpc = MAKE_THUMB_ADDR (nextpc);

      if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0x8000) == 0x8000)
	{
	  /* Branches and miscellaneous control instructions.  */

	  if ((inst2 & 0x1000) != 0 || (inst2 & 0xd001) == 0xc000)
	    {
	      /* B, BL, BLX.  */
	      int j1, j2, imm1, imm2;

	      imm1 = sbits (inst1, 0, 10);
	      imm2 = bits (inst2, 0, 10);
	      j1 = bit (inst2, 13);
	      j2 = bit (inst2, 11);

	      offset = ((imm1 << 12) + (imm2 << 1));
	      offset ^= ((!j2) << 22) | ((!j1) << 23);

	      nextpc = pc_val + offset;
	      /* For BLX make sure to clear the low bits.  */
	      if (bit (inst2, 12) == 0)
		nextpc = nextpc & 0xfffffffc;
	    }
	  else if (inst1 == 0xf3de && (inst2 & 0xff00) == 0x3f00)
	    {
	      /* SUBS PC, LR, #imm8.  */
	      nextpc
		= self->ops->collect_register_unsigned (self, ARM_LR_REGNUM);
	      nextpc -= inst2 & 0x00ff;
	    }
	  else if ((inst2 & 0xd000) == 0x8000 && (inst1 & 0x0380) != 0x0380)
	    {
	      /* Conditional branch.  */
	      if (condition_true (bits (inst1, 6, 9), status))
		{
		  int sign, j1, j2, imm1, imm2;

		  sign = sbits (inst1, 10, 10);
		  imm1 = bits (inst1, 0, 5);
		  imm2 = bits (inst2, 0, 10);
		  j1 = bit (inst2, 13);
		  j2 = bit (inst2, 11);

		  offset = (sign << 20) + (j2 << 19) + (j1 << 18);
		  offset += (imm1 << 12) + (imm2 << 1);

		  nextpc = pc_val + offset;
		}
	    }
	}
      else if ((inst1 & 0xfe50) == 0xe810)
	{
	  /* Load multiple or RFE.  */
	  int rn, offset, load_pc = 1;

	  rn = bits (inst1, 0, 3);
	  if (bit (inst1, 7) && !bit (inst1, 8))
	    {
	      /* LDMIA or POP */
	      if (!bit (inst2, 15))
		load_pc = 0;
	      offset = bitcount (inst2) * 4 - 4;
	    }
	  else if (!bit (inst1, 7) && bit (inst1, 8))
	    {
	      /* LDMDB */
	      if (!bit (inst2, 15))
		load_pc = 0;
	      offset = -4;
	    }
	  else if (bit (inst1, 7) && bit (inst1, 8))
	    {
	      /* RFEIA */
	      offset = 0;
	    }
	  else if (!bit (inst1, 7) && !bit (inst1, 8))
	    {
	      /* RFEDB */
	      offset = -8;
	    }
	  else
	    load_pc = 0;

	  if (load_pc)
	    {
	      CORE_ADDR addr = self->ops->collect_register_unsigned (self, rn);
	      nextpc = self->ops->read_memory_unsigned_integer
		(addr + offset, 4, byte_order);
	    }
	}
      else if ((inst1 & 0xffef) == 0xea4f && (inst2 & 0xfff0) == 0x0f00)
	{
	  /* MOV PC or MOVS PC.  */
	  nextpc
	    = self->ops->collect_register_unsigned (self, bits (inst2, 0, 3));
	  nextpc = MAKE_THUMB_ADDR (nextpc);
	}
      else if ((inst1 & 0xff70) == 0xf850 && (inst2 & 0xf000) == 0xf000)
	{
	  /* LDR PC.  */
	  CORE_ADDR base;
	  int rn, load_pc = 1;

	  rn = bits (inst1, 0, 3);
	  base = self->ops->collect_register_unsigned (self, rn);
	  if (rn == ARM_PC_REGNUM)
	    {
	      base = (base + 4) & ~(CORE_ADDR) 0x3;
	      if (bit (inst1, 7))
		base += bits (inst2, 0, 11);
	      else
		base -= bits (inst2, 0, 11);
	    }
	  else if (bit (inst1, 7))
	    base += bits (inst2, 0, 11);
	  else if (bit (inst2, 11))
	    {
	      if (bit (inst2, 10))
		{
		  if (bit (inst2, 9))
		    base += bits (inst2, 0, 7);
		  else
		    base -= bits (inst2, 0, 7);
		}
	    }
	  else if ((inst2 & 0x0fc0) == 0x0000)
	    {
	      int shift = bits (inst2, 4, 5), rm = bits (inst2, 0, 3);
	      base += self->ops->collect_register_unsigned (self, rm) << shift;
	    }
	  else
	    /* Reserved.  */
	    load_pc = 0;

	  if (load_pc)
	    nextpc
	      = self->ops->read_memory_unsigned_integer (base, 4, byte_order);

	}
      else if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf000)
	{
	  /* TBB.  */
	  CORE_ADDR tbl_reg, table, offset, length;

	  tbl_reg = bits (inst1, 0, 3);
	  if (tbl_reg == 0x0f)
	    table = pc + 4;  /* Regcache copy of PC isn't right yet.  */
	  else
	    table = self->ops->collect_register_unsigned (self, tbl_reg);

	  offset
	    = self->ops->collect_register_unsigned (self, bits (inst2, 0, 3));
	  length = 2 * self->ops->read_memory_unsigned_integer
	    (table + offset, 1, byte_order);
	  nextpc = pc_val + length;
	}
      else if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf010)
	{
	  /* TBH.  */
	  CORE_ADDR tbl_reg, table, offset, length;

	  tbl_reg = bits (inst1, 0, 3);
	  if (tbl_reg == 0x0f)
	    table = pc + 4;  /* Regcache copy of PC isn't right yet.  */
	  else
	    table = self->ops->collect_register_unsigned (self, tbl_reg);

	  offset = 2 * self->ops->collect_register_unsigned
	    (self, bits (inst2, 0, 3));
	  length = 2 * self->ops->read_memory_unsigned_integer
	    (table + offset, 2, byte_order);
	  nextpc = pc_val + length;
	}
    }
  else if ((inst1 & 0xff00) == 0x4700)	/* bx REG, blx REG */
    {
      if (bits (inst1, 3, 6) == 0x0f)
	nextpc = UNMAKE_THUMB_ADDR (pc_val);
      else
	nextpc
	  = self->ops->collect_register_unsigned (self, bits (inst1, 3, 6));
    }
  else if ((inst1 & 0xff87) == 0x4687)	/* mov pc, REG */
    {
      if (bits (inst1, 3, 6) == 0x0f)
	nextpc = pc_val;
      else
	nextpc
	  = self->ops->collect_register_unsigned (self, bits (inst1, 3, 6));

      nextpc = MAKE_THUMB_ADDR (nextpc);
    }
  else if ((inst1 & 0xf500) == 0xb100)
    {
      /* CBNZ or CBZ.  */
      int imm = (bit (inst1, 9) << 6) + (bits (inst1, 3, 7) << 1);
      ULONGEST reg
	= self->ops->collect_register_unsigned (self, bits (inst1, 0, 2));

      if (bit (inst1, 11) && reg != 0)
	nextpc = pc_val + imm;
      else if (!bit (inst1, 11) && reg == 0)
	nextpc = pc_val + imm;
    }

  VEC_safe_push (CORE_ADDR, *next_pcs, nextpc);

  return *next_pcs;
}

/* Get the raw next possible addresses.  PC in next_pcs is the current program
   counter, which is assumed to be executing in ARM mode.

   The values returned have the execution state of the next instruction
   encoded in it.  Use IS_THUMB_ADDR () to see whether the instruction is
   in Thumb-State, and gdbarch_addr_bits_remove () to get the plain memory
   address in GDB and arm_addr_bits_remove in GDBServer.  */

VEC (CORE_ADDR) *
arm_get_next_pcs_raw (struct arm_get_next_pcs *self,
		      CORE_ADDR pc,
		      VEC (CORE_ADDR) ** next_pcs)
{
  int byte_order = self->byte_order;
  unsigned long pc_val;
  unsigned long this_instr = 0;
  unsigned long status;
  CORE_ADDR nextpc;

  pc_val = (unsigned long) pc;
  this_instr = self->ops->read_memory_unsigned_integer (pc, 4, byte_order);

  status = self->ops->collect_register_unsigned (self, ARM_PS_REGNUM);

  nextpc = (CORE_ADDR) (pc_val + 4);	/* Default case */

  if (bits (this_instr, 28, 31) == INST_NV)
    switch (bits (this_instr, 24, 27))
      {
      case 0xa:
      case 0xb:
	{
	  /* Branch with Link and change to Thumb.  */
	  nextpc = BranchDest (pc, this_instr);
	  nextpc |= bit (this_instr, 24) << 1;
	  nextpc = MAKE_THUMB_ADDR (nextpc);
	  break;
	}
      case 0xc:
      case 0xd:
      case 0xe:
	/* Coprocessor register transfer.  */
        if (bits (this_instr, 12, 15) == 15)
	  error (_("Invalid update to pc in instruction"));
	break;
      }
  else if (condition_true (bits (this_instr, 28, 31), status))
    {
      switch (bits (this_instr, 24, 27))
	{
	case 0x0:
	case 0x1:			/* data processing */
	case 0x2:
	case 0x3:
	  {
	    unsigned long operand1, operand2, result = 0;
	    unsigned long rn;
	    int c;

	    if (bits (this_instr, 12, 15) != 15)
	      break;

	    if (bits (this_instr, 22, 25) == 0
		&& bits (this_instr, 4, 7) == 9)	/* multiply */
	      error (_("Invalid update to pc in instruction"));

	    /* BX <reg>, BLX <reg> */
	    if (bits (this_instr, 4, 27) == 0x12fff1
		|| bits (this_instr, 4, 27) == 0x12fff3)
	      {
		rn = bits (this_instr, 0, 3);
		nextpc = ((rn == ARM_PC_REGNUM)
			  ? (pc_val + 8)
			  : self->ops->collect_register_unsigned (self, rn));

		VEC_safe_push (CORE_ADDR, *next_pcs, nextpc);
		return *next_pcs;
	      }

	    /* Multiply into PC.  */
	    c = (status & FLAG_C) ? 1 : 0;
	    rn = bits (this_instr, 16, 19);
	    operand1 = ((rn == ARM_PC_REGNUM)
			? (pc_val + 8)
			: self->ops->collect_register_unsigned (self, rn));

	    if (bit (this_instr, 25))
	      {
		unsigned long immval = bits (this_instr, 0, 7);
		unsigned long rotate = 2 * bits (this_instr, 8, 11);
		operand2 = ((immval >> rotate) | (immval << (32 - rotate)))
		  & 0xffffffff;
	      }
	    else		/* operand 2 is a shifted register.  */
	      operand2 = shifted_reg_val (self, this_instr, c,
					  pc_val, status);

	    switch (bits (this_instr, 21, 24))
	      {
	      case 0x0:	/*and */
		result = operand1 & operand2;
		break;

	      case 0x1:	/*eor */
		result = operand1 ^ operand2;
		break;

	      case 0x2:	/*sub */
		result = operand1 - operand2;
		break;

	      case 0x3:	/*rsb */
		result = operand2 - operand1;
		break;

	      case 0x4:	/*add */
		result = operand1 + operand2;
		break;

	      case 0x5:	/*adc */
		result = operand1 + operand2 + c;
		break;

	      case 0x6:	/*sbc */
		result = operand1 - operand2 + c;
		break;

	      case 0x7:	/*rsc */
		result = operand2 - operand1 + c;
		break;

	      case 0x8:
	      case 0x9:
	      case 0xa:
	      case 0xb:	/* tst, teq, cmp, cmn */
		result = (unsigned long) nextpc;
		break;

	      case 0xc:	/*orr */
		result = operand1 | operand2;
		break;

	      case 0xd:	/*mov */
		/* Always step into a function.  */
		result = operand2;
		break;

	      case 0xe:	/*bic */
		result = operand1 & ~operand2;
		break;

	      case 0xf:	/*mvn */
		result = ~operand2;
		break;
	      }

            /* In 26-bit APCS the bottom two bits of the result are
	       ignored, and we always end up in ARM state.  */
	    if (!self->arm_apcs_32)
	      nextpc = self->ops->addr_bits_remove (self, result);
	      else
	      nextpc = result;
	    break;
	  }

	case 0x4:
	case 0x5:		/* data transfer */
	case 0x6:
	case 0x7:
	  if (bits (this_instr, 25, 27) == 0x3 && bit (this_instr, 4) == 1)
	    {
	      /* Media instructions and architecturally undefined
		 instructions.  */
	      break;
	    }
	  if (bit (this_instr, 20))
	    {
	      /* load */
	      if (bits (this_instr, 12, 15) == 15)
		{
		  /* rd == pc */
		  unsigned long rn;
		  unsigned long base;

		  if (bit (this_instr, 22))
		    error (_("Invalid update to pc in instruction"));

		  /* byte write to PC */
		  rn = bits (this_instr, 16, 19);
		  base = ((rn == ARM_PC_REGNUM)
			  ? (pc_val + 8)
			  : self->ops->collect_register_unsigned (self, rn));

		  if (bit (this_instr, 24))
		    {
		      /* pre-indexed */
		      int c = (status & FLAG_C) ? 1 : 0;
		      unsigned long offset =
		      (bit (this_instr, 25)
		       ? shifted_reg_val (self, this_instr, c,
					  pc_val, status)
		       : bits (this_instr, 0, 11));

		      if (bit (this_instr, 23))
			base += offset;
		      else
			base -= offset;
		    }
		  nextpc =
		    (CORE_ADDR) self->ops->read_memory_unsigned_integer
		    ((CORE_ADDR) base, 4, byte_order);
		}
	    }
	  break;

	case 0x8:
	case 0x9:		/* block transfer */
	  if (bit (this_instr, 20))
	    {
	      /* LDM */
	      if (bit (this_instr, 15))
		{
		  /* loading pc */
		  int offset = 0;
		  unsigned long rn_val
		    = self->ops->collect_register_unsigned
		    (self, bits (this_instr, 16, 19));

		  if (bit (this_instr, 23))
		    {
		      /* up */
		      unsigned long reglist = bits (this_instr, 0, 14);
		      offset = bitcount (reglist) * 4;
		      if (bit (this_instr, 24))		/* pre */
			offset += 4;
		    }
		  else if (bit (this_instr, 24))
		    offset = -4;

		  nextpc = (CORE_ADDR) self->ops->read_memory_unsigned_integer
		    ((CORE_ADDR) (rn_val + offset), 4, byte_order);
		}
	    }
	  break;

	case 0xb:		/* branch & link */
	case 0xa:		/* branch */
	  {
	    nextpc = BranchDest (pc, this_instr);
	    break;
	  }

	case 0xc:
	case 0xd:
	case 0xe:		/* coproc ops */
	  break;
	case 0xf:		/* SWI */
	  {
	    nextpc = self->ops->syscall_next_pc (self, pc);
	  }
	  break;

	default:
	  error (_("Bad bit-field extraction\n"));
	  return *next_pcs;
	}
    }

  VEC_safe_push (CORE_ADDR, *next_pcs, nextpc);
  return *next_pcs;
}
