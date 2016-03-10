.syntax unified

.text

.macro prologue
push {lr}
.endm

.macro epilogue
pop {pc}
.endm

/* arm b imm */
.arm
.type func_arm_b_imm, STT_FUNC
.global func_arm_b_imm
func_arm_b_imm:
	prologue

insn_arm_b_imm:
	b arm_b_imm_jump

arm_b_imm_jump_back:
	epilogue

arm_b_imm_jump:
	ldr r0, =global_variable
	ldr r1, =magic_number
	ldr r1, [r1]
	str r1, [r0]

	# return to the function
	b arm_b_imm_jump_back


/* arm bl imm */
.arm
.type func_arm_bl_imm, STT_FUNC
.global func_arm_bl_imm
func_arm_bl_imm:
	prologue

insn_arm_bl_imm:
	bl arm_bl_imm_jump

	epilogue

arm_bl_imm_jump:
	ldr r0, =global_variable
	ldr r1, =magic_number
	ldr r1, [r1]
	str r1, [r0]

	# return to the function
	bx lr


/* arm blx imm */
.arm
.type func_arm_blx_imm, STT_FUNC
.global func_arm_blx_imm
func_arm_blx_imm:
	prologue

insn_arm_blx_imm:
	blx arm_blx_imm_jump

	epilogue

.thumb
arm_blx_imm_jump:
	ldr r0, =global_variable
	ldr r1, =magic_number
	ldr r1, [r1]
	str r1, [r0]

	# return to the function
	bx lr


/* arm bx reg */
.arm
.type func_arm_bx_reg, STT_FUNC
.global func_arm_bx_reg
func_arm_bx_reg:
	prologue

	ldr r0, =arm_bx_reg_jump

insn_arm_bx_reg:
	bx r0

arm_bx_reg_jump_back:
	epilogue

.thumb_func
.thumb
arm_bx_reg_jump:
	ldr r0, =global_variable
	ldr r1, =magic_number
	ldr r1, [r1]
	str r1, [r0]

	# return to the function
	ldr r0, =arm_bx_reg_jump_back
	bx r0


/* arm blx reg */
.arm
.type func_arm_blx_reg, STT_FUNC
.global func_arm_blx_reg
func_arm_blx_reg:
	prologue

	ldr r0, =arm_blx_reg_jump

insn_arm_blx_reg:
	blx r0

	epilogue

.thumb_func
.thumb
arm_blx_reg_jump:
	ldr r0, =global_variable
	ldr r1, =magic_number
	ldr r1, [r1]
	str r1, [r0]

	# return to the function
	bx lr


/* arm ldm */
.arm
.type func_arm_ldm, STT_FUNC
.global func_arm_ldm
func_arm_ldm:
	prologue

	ldr r0, =magic_number
	ldr r0, [r0]
	stmfd sp!, {r0}

insn_arm_ldm:
	ldmfd sp!, {r1}
	ldr r0, =global_variable
	str r1, [r0]

	epilogue


/* arm ldm pc */
.arm
.type func_arm_ldm_pc, STT_FUNC
.global func_arm_ldm_pc
func_arm_ldm_pc:
	prologue

	ldr r0, =arm_ldm_pc_jump
	stmfd sp!, {r0}

insn_arm_ldm_pc:
	ldmfd sp!, {pc}

arm_ldm_pc_jump_back:
	epilogue

arm_ldm_pc_jump:
	ldr r0, =global_variable
	ldr r1, =magic_number
	ldr r1, [r1]
	str r1, [r0]
	b arm_ldm_pc_jump_back


/* arm stm */
.arm
.type func_arm_stm, STT_FUNC
.global func_arm_stm
func_arm_stm:
	prologue

	ldr r0, =magic_number
	ldr r0, [r0]

insn_arm_stm:
	stmfd sp!, {r0}

	ldmfd sp!, {r1}
	ldr r0, =global_variable
	str r1, [r0]

	epilogue

