/* GNU/Linux/arm specific low level interface, for the in-process
   agent library for GDB.

   Copyright (C) 2015-2016 Free Software Foundation, Inc.

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
#include <sys/auxv.h>

/* ARM GNU/Linux HWCAP values.  These are in defined in
   <asm/elf.h> in current kernels.  */
#define HWCAP_VFP       64
#define HWCAP_IWMMXT    512
#define HWCAP_NEON      4096
#define HWCAP_VFPv3     8192
#define HWCAP_VFPv3D16  16384

/* Target description indexes for the IPA.  */
enum arm_linux_tdesc
  {
    ARM_TDESC_ARM = 0,
    ARM_TDESC_ARM_WITH_VFPV2 = 1,
    ARM_TDESC_ARM_WITH_VFPV3 = 2,
    ARM_TDESC_ARM_WITH_NEON = 3,
  };

/* Defined in auto-generated file regs-arm.c.  */
void init_registers_arm (void);
extern const struct target_desc *tdesc_arm;

void init_registers_arm_with_vfpv2 (void);
extern const struct target_desc *tdesc_arm_with_vfpv2;

void init_registers_arm_with_vfpv3 (void);
extern const struct target_desc *tdesc_arm_with_vfpv3;

void init_registers_arm_with_neon (void);
extern const struct target_desc *tdesc_arm_with_neon;

/* 32 bits GPR registers.  */
#define GPR_SIZE 4
/* 64 bits FPR registers.  */
#define FPR_SIZE 8

/* Special registers mappings.  */
#define FT_CR_PC	0
#define FT_CR_CPSR	1 * GPR_SIZE
#define FT_CR_LR	15 * GPR_SIZE
#define FT_CR_GPR_0	2 * GPR_SIZE
#define FT_CR_FPR_0	FT_CR_LR + GPR_SIZE
#define FT_CR_GPR(n)	(FT_CR_GPR_0 + (n * GPR_SIZE))
#define FT_CR_FPR(n)	(FT_CR_FPR_0 + (n * FPR_SIZE))
#define FT_CR_UNAVAIL	-1

/* Mapping between registers collected by the jump pad and GDB's register
   array layout used by regcache for arm core registers.

   See linux-arm-low.c (arm_install_fast_tracepoint_jump_pad) for
   more details.  */

static const int arm_core_ft_collect_regmap[] = {
  FT_CR_GPR (0),  FT_CR_GPR (1),  FT_CR_GPR (2), FT_CR_GPR (3), FT_CR_GPR (4),
  FT_CR_GPR (5),  FT_CR_GPR (6),  FT_CR_GPR (7), FT_CR_GPR (8), FT_CR_GPR (9),
  FT_CR_GPR (10), FT_CR_GPR (11), FT_CR_GPR (12),
  /* SP is calculated rather than collected.  */
  FT_CR_UNAVAIL,
  FT_CR_LR, FT_CR_PC,
  /* Legacy FPA Registers. 16 to 24.  */
  FT_CR_UNAVAIL, FT_CR_UNAVAIL, FT_CR_UNAVAIL, FT_CR_UNAVAIL, FT_CR_UNAVAIL,
  FT_CR_UNAVAIL, FT_CR_UNAVAIL, FT_CR_UNAVAIL, FT_CR_UNAVAIL,
  FT_CR_CPSR,
};

/* Mapping for VFPv2 registers.  */
static const int arm_vfpv2_ft_collect_regmap[] = {
  FT_CR_FPR (0),  FT_CR_FPR (1),  FT_CR_FPR (2),  FT_CR_FPR (3), FT_CR_FPR (4),
  FT_CR_FPR (5),  FT_CR_FPR (6),  FT_CR_FPR (7),  FT_CR_FPR (8), FT_CR_FPR (9),
  FT_CR_FPR (10), FT_CR_FPR (11), FT_CR_FPR (12), FT_CR_FPR (13),
  FT_CR_FPR (14), FT_CR_FPR (15),
};

/* Mapping for VFPv3 registers.  */
static const int arm_vfpv3_ft_collect_regmap[] = {
  FT_CR_FPR (0),  FT_CR_FPR (1),  FT_CR_FPR (2),  FT_CR_FPR (3),  FT_CR_FPR (4),
  FT_CR_FPR (5),  FT_CR_FPR (6),  FT_CR_FPR (7),  FT_CR_FPR (8),  FT_CR_FPR (9),
  FT_CR_FPR (10), FT_CR_FPR (11), FT_CR_FPR (12), FT_CR_FPR (13),
  FT_CR_FPR (14), FT_CR_FPR (15), FT_CR_FPR (16), FT_CR_FPR (17),
  FT_CR_FPR (18), FT_CR_FPR (19), FT_CR_FPR (20), FT_CR_FPR (21),
  FT_CR_FPR (22), FT_CR_FPR (23), FT_CR_FPR (24), FT_CR_FPR (25),
  FT_CR_FPR (26), FT_CR_FPR (27), FT_CR_FPR (28), FT_CR_FPR (29),
  FT_CR_FPR (30), FT_CR_FPR (31),
};

#define ARM_CORE_NUM_FT_COLLECT_REGS \
  (sizeof(arm_core_ft_collect_regmap) / sizeof(arm_core_ft_collect_regmap[0]))

#define ARM_VFPV2_NUM_FT_COLLECT_REGS \
  (sizeof(arm_vfpv2_ft_collect_regmap) / sizeof(arm_vfpv2_ft_collect_regmap[0]))

#define ARM_VFPV3_NUM_FT_COLLECT_REGS \
  (sizeof(arm_vfpv3_ft_collect_regmap) / sizeof(arm_vfpv3_ft_collect_regmap[0]))

void
supply_fast_tracepoint_registers (struct regcache *regcache,
				  const unsigned char *buf)
{
  int i;
  uint32_t val = 0;
  /* Number of extention registers collected.  */
  int num_ext_regs = 0;

  for (i = 0; i < ARM_CORE_NUM_FT_COLLECT_REGS; i++)
    {
      int index = arm_core_ft_collect_regmap[i];
      if (index != FT_CR_UNAVAIL)
	supply_register (regcache, i,
			 (char *) buf + arm_core_ft_collect_regmap[i]);
    }
  if (get_ipa_tdesc (get_ipa_tdesc_idx ()) == tdesc_arm_with_neon
      || get_ipa_tdesc (get_ipa_tdesc_idx ()) == tdesc_arm_with_vfpv3)
    {
      num_ext_regs = ARM_VFPV3_NUM_FT_COLLECT_REGS;

      for (i = 0; i < ARM_VFPV3_NUM_FT_COLLECT_REGS; i++)
	supply_register (regcache, i + ARM_CORE_NUM_FT_COLLECT_REGS,
			 (char *) buf + arm_vfpv3_ft_collect_regmap[i]);
    }
  else if (get_ipa_tdesc (get_ipa_tdesc_idx ()) == tdesc_arm_with_vfpv2)
    {
      num_ext_regs = ARM_VFPV2_NUM_FT_COLLECT_REGS;

      for (i = 0; i < ARM_VFPV2_NUM_FT_COLLECT_REGS; i++)
	supply_register (regcache, i + ARM_CORE_NUM_FT_COLLECT_REGS,
			 (char *) buf + arm_vfpv2_ft_collect_regmap[i]);
    }

  /* SP calculation from stack layout.  */
  val = (uint32_t) buf + 16 * 4 + num_ext_regs * 8;
  supply_register (regcache, 13, &val);
}

ULONGEST
get_raw_reg (const unsigned char *raw_regs, int regnum)
{
  /* Used for JIT conditions.  */
  return 0;
}

const char *gdbserver_xmltarget;

const struct target_desc *
get_ipa_tdesc (int idx)
{
  switch (idx)
    {
    case ARM_TDESC_ARM:
      return tdesc_arm;
    case ARM_TDESC_ARM_WITH_NEON:
      return tdesc_arm_with_neon;
    case ARM_TDESC_ARM_WITH_VFPV2:
      return tdesc_arm_with_vfpv2;
    case ARM_TDESC_ARM_WITH_VFPV3:
      return tdesc_arm_with_vfpv3;
    default:
      internal_error (__FILE__, __LINE__,
		      "unknown ipa tdesc index: %d", idx);
      return tdesc_arm;
    }
}

void *
alloc_jump_pad_buffer (size_t size)
{
  uintptr_t addr;
  void *res = NULL;

  /* Allocate scratch buffer aligned on a page boundary, at a low
   address (close to the main executable's code).  */
  for (addr = size; addr != 0; addr += size)
    {
      res = (char *) mmap ((void *) addr, size,
			   PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (res == (void *) addr)
	break;
      if (res != MAP_FAILED)
	munmap (res, size);
    }
  return res;
}

void
initialize_low_tracepoint (void)
{
  /* Initialize the Linux target descriptions.  */
  init_registers_arm ();
  init_registers_arm_with_vfpv2 ();
  init_registers_arm_with_vfpv3 ();
  init_registers_arm_with_neon ();
}
