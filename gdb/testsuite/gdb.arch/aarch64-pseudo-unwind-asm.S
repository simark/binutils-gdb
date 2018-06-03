.global callee
callee:
.cfi_startproc
	stp x29, x30, [sp, -16]!
.cfi_def_cfa 29, 16
.cfi_offset 29, -16
.cfi_offset 30, -8
	add x29, sp, 0

	# Save caller's v8 value on the stack.
.cfi_offset 72, -32
	str q8, [sp, -16]!

	# Put our own v8 value.
	adr x0, value_callee
	ld1 { v8.1d }, [x0]
break_here_asm:

	ldr q8, [sp], 16
	ldp x29, x30, [sp], 16
	ret
.cfi_endproc

value_callee:
.quad 0x2021222324252627


.global caller
caller:
.cfi_startproc
	stp x29, x30, [sp, -16]!
.cfi_def_cfa 29, 16
.cfi_offset x29, -16
.cfi_offset x30, -8
	add x29, sp, 0

	# Save caller's v8 value on the stack.
.cfi_offset 72, -32
	str q8, [sp, -16]!

	# Put our own v8 value.
	adr x0, value_caller
	ld1 { v8.1d }, [x0]

	bl callee

	adr x0, value_caller
	str q8, [sp, -16]!
	ldr x0, [sp], 16
	
	ldr q8, [sp], 16
	ldp x29, x30, [sp], 16
	ret
.cfi_endproc

value_caller:
.quad 0x1011121314151617

#	# Save caller's rbx value on the stack.
#.cfi_offset rbx, -24
#	push %rbx
#
#	# Put our own rbx value.
#	mov $0x1011121314151617, %rbx
#	call callee
#	
#	# Return the value we put in rbx.
#	mov %rbx, %rax
#
#	pop %rbx
#	pop %rbp
#	ret
#.cfi_endproc
