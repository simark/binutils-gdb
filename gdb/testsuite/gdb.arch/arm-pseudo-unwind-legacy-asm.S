.global callee
callee:
.cfi_startproc
	push {fp, lr}
.cfi_def_cfa fp, 4
.cfi_offset fp, -8
.cfi_offset lr, -4
	add fp, sp, #4

	# Save caller's v8 value on the stack.
.cfi_offset 80, -12
	vpush {s16}

	# Put our own v8 value.
	ldr r0, =value_callee
	vldr s16, [r0]
break_here_asm:

	vpop {s16}
	pop {fp, pc}
.cfi_endproc

value_callee:
.quad 0x20212223


.global caller
caller:
.cfi_startproc
	push {fp, lr}
.cfi_def_cfa fp, 4
.cfi_offset fp, -8
.cfi_offset lr, -4
	add fp, sp, #4

	# Save caller's v8 value on the stack.
.cfi_offset 80, -12
	vpush {s16}

	# Put our own v8 value.
	ldr r0, =value_caller
	vldr s16, [r0]

	bl callee
	
	vpush {s16}
	pop {r0}
	mov r1, #0

	vpop {s16}
	pop {fp, pc}	
.cfi_endproc

value_caller:
.quad 0x10111213
