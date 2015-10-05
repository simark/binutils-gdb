/* GNU/Linux/arm specific low level interface, for the in-process
   agent library for GDB.

   Copyright (C) 2015 Free Software Foundation, Inc.

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

#include "server.h"
#include <stdint.h>
#include <sys/mman.h>
#include "tracepoint.h"

/* Defined in auto-generated file regs-arm.c.  */
void init_registers_arm_with_neon (void);
extern const struct target_desc *tdesc_arm_with_neon;

/* reg map
 */
int index_map[] = {
  2,				/*  0 - r0 */
  3,				/*  1 - r1 */
  4,				/*  2 - r2 */
  5,				/*  3 - r3 */
  6,				/*  4 - r4 */
  7,				/*  5 - r5 */
  8,				/*  6 - r6 */
  9,				/*  7 - r7 */
  10,				/*  8 - r8 */
  11,				/*  9 - r9 */
  12,				/* 10 - r10 */
  13,				/* 11 - r11 */
  14,				/* 12 - r12 */
  -1,				/* 13 - r13 - sp */
  15,				/* 14 - r14 - lr */
  0,				/* 15 - r15 - pc */
  -1,				/* 16 - */
  -1,				/* 17 - */
  -1,				/* 18 - */
  -1,				/* 19 - */
  -1,				/* 20 - */
  -1,				/* 21 - */
  -1,				/* 22 - */
  -1,				/* 23 - */
  -1,				/* 24 - */
  1,				/* 25 - cpsr */
};

void
supply_fast_tracepoint_registers (struct regcache *regcache,
				  const unsigned char *buf)
{
  const uint32_t *regs = (const uint32_t *) buf;
  uint32_t val;
  int i;

  for (i = 0; i < sizeof(index_map) / sizeof(index_map[0]); i++)
    {
      int index = index_map[i];
      if (index != -1)
	{
	  val = regs[index];
	  supply_register (regcache, i, &val);
	}
    }
  /* special for sp   */
  val = (uint32_t) regs + 16 * 4;
  supply_register (regcache, 13, &val);
}

IP_AGENT_EXPORT_FUNC ULONGEST
gdb_agent_get_raw_reg (const unsigned char *raw_regs, int regnum)
{
  /* only for jit  */
  return 0;
}

const char *gdbserver_xmltarget;

void
initialize_low_tracepoint (void)
{
  init_registers_arm_with_neon ();
  ipa_tdesc = tdesc_arm_with_neon;
}
