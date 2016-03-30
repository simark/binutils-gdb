/* This testcase is part of GDB, the GNU debugger.

   Copyright 2015 Free Software Foundation, Inc.

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Magic number chosen at random.  */
const uint32_t magic_number = 0x2eb2944b;

static void
break_here (void)
{
}

void
fail (void)
{
  exit (1);
}

int global_variable;

#define DEF_TEST_FN(name) \
   static void \
   test_##name (void) \
   { \
      void func_##name (void); \
      \
      global_variable = 0; \
      \
      func_##name (); \
      \
      if (global_variable != magic_number) \
         fail (); \
      \
      break_here (); \
   }

DEF_TEST_FN (arm_b_imm)
DEF_TEST_FN (arm_b_imm_cond)
DEF_TEST_FN (arm_bl_imm)
DEF_TEST_FN (arm_blx_imm)
DEF_TEST_FN (arm_bx_reg)
DEF_TEST_FN (arm_blx_reg)
DEF_TEST_FN (arm_ldm)
DEF_TEST_FN (arm_ldm_pc)
DEF_TEST_FN (arm_stm)

DEF_TEST_FN (thumb_b_imm)
DEF_TEST_FN (thumb_b_imm_cond)
DEF_TEST_FN (thumb_bl_imm)
DEF_TEST_FN (thumb_blx_imm)
DEF_TEST_FN (thumb_ldm)
DEF_TEST_FN (thumb_ldm_pc)
DEF_TEST_FN (thumb_stm)

int
main (void)
{
  test_arm_b_imm ();
  test_arm_b_imm_cond ();
  test_arm_bl_imm ();
  test_arm_blx_imm ();
  test_arm_bx_reg ();
  test_arm_blx_reg ();
  test_arm_ldm ();
  test_arm_ldm_pc ();
  test_arm_stm ();

  
  test_thumb_b_imm ();
  test_thumb_b_imm_cond ();
  test_thumb_bl_imm ();
  test_thumb_blx_imm ();
  test_thumb_ldm ();
  test_thumb_ldm_pc ();
  test_thumb_stm ();

  return 0;
}
