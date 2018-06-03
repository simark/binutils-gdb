/* Copyright 2018 Free Software Foundation, Inc.

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

value_callee:
.quad 0x2021222324252627
value_caller:
.quad 0x1011121314151617

.global callee
callee:
	/* Standard prologue:
	    - push fp (x29) and lr (x30) to the stack.
	    - mov sp to fp  */
.cfi_startproc
	stp x29, x30, [sp, -16]!
.cfi_def_cfa 29, 16
.cfi_offset 29, -16
.cfi_offset 30, -8
	mov x29, sp

	/* Save caller's q8 value on the stack.  */
.cfi_offset 72, -32
	str q8, [sp, -16]!

	/* Put our own q8 value.  */
	adr x0, value_callee
	ld1 { v8.1d }, [x0]
break_here_asm:

	/* Restore caller's q8 value.  */
	ldr q8, [sp], 16
	
	/* Standard epilogue:
	    - pop fo (x29) and lr (x30) from the stack  */
	ldp x29, x30, [sp], 16
	ret
.cfi_endproc


.global caller
caller:
	/* Standard prologue.  */
.cfi_startproc
	stp x29, x30, [sp, -16]!
.cfi_def_cfa 29, 16
.cfi_offset x29, -16
.cfi_offset x30, -8
	add x29, sp, 0

	/* Put our own q8 value.  */
	adr x0, value_caller
	ld1 { v8.1d }, [x0]

	/* Call callee.  */
	bl callee

	/* Store our q8 value in x0 to return it.  */
	str q8, [sp, -16]!
	ldr x0, [sp], 16

	/* Standard epilogue.  */
	ldp x29, x30, [sp], 16
	ret
.cfi_endproc
