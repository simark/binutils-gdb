.global callee
callee:
.cfi_startproc
	push {fp, lr}
.cfi_def_cfa fp, 4
.cfi_offset fp, -8
.cfi_offset lr, -4
	add fp, sp, #4

	# Save caller's v8 value on the stack.
.cfi_offset d8, -16
	vpush {d8}

	# Put our own v8 value.
	ldr r0, =value_callee
	vldr d8, [r0]
break_here_asm:

	vpop {d8}
	pop {fp, pc}
.cfi_endproc

value_callee:
.quad 0x2021222324252627


.global caller
caller:
.cfi_startproc
	push {fp, lr}
.cfi_def_cfa fp, 4
.cfi_offset fp, -8
.cfi_offset lr, -4
	add fp, sp, #4

	# Save caller's v8 value on the stack.
.cfi_offset d8, -16
	vpush {d8}

	# Put our own v8 value.
	ldr r0, =value_caller
	vldr d8, [r0]

	bl callee
	
	vpush {d8}
	pop {r0}
	pop {r1}

	vpop {d8}
	pop {fp, pc}	
.cfi_endproc

value_caller:
.quad 0x1011121314151617
