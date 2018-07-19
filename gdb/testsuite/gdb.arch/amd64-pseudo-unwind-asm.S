.global callee
callee:
.cfi_startproc
	push %rbp
.cfi_def_cfa rbp, 16
	mov %rsp, %rbp

	# Save caller's rbx value on the stack.
.cfi_offset rbx, -24
	push %rbx

	# Put our own rbx value.
	mov $0x2021222324252627, %rbx
break_here_asm:

	pop %rbx
	pop %rbp
	ret
.cfi_endproc


.global caller
caller:
.cfi_startproc
	push %rbp
.cfi_def_cfa_offset 16
	mov %rsp, %rbp

	# Save caller's rbx value on the stack.
.cfi_offset rbx, -24
	push %rbx

	# Put our own rbx value.
	mov $0x1011121314151617, %rbx
	call callee

	# Return the value we put in rbx.
	mov %rbx, %rax

	pop %rbx
	pop %rbp
	ret
.cfi_endproc
