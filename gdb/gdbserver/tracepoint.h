/* Tracepoint code for remote server for GDB.
   Copyright (C) 1993-2016 Free Software Foundation, Inc.

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

#ifndef TRACEPOINT_H
#define TRACEPOINT_H

/* Size for a small buffer to report problems from the in-process
   agent back to GDBserver.  */
#define IPA_BUFSIZ 100

void initialize_tracepoint (void);

#if defined(__GNUC__)
# define ATTR_USED __attribute__((used))
# define ATTR_NOINLINE __attribute__((noinline))
#else
# define ATTR_USED
# define ATTR_NOINLINE
#endif

/* How to make symbol public/exported.  */

#if defined _WIN32 || defined __CYGWIN__
# define EXPORTED_SYMBOL __declspec (dllexport)
#else
# if __GNUC__ >= 4
#  define EXPORTED_SYMBOL __attribute__ ((visibility ("default")))
# else
#  define EXPORTED_SYMBOL
# endif
#endif

/* Use these to make sure the functions and variables the IPA needs to
   export (symbols GDBserver needs to query GDB about) are visible and
   have C linkage.

   Tag exported functions with IP_AGENT_EXPORT_FUNC, tag the
   definitions of exported variables with IP_AGENT_EXPORT_VAR, and
   variable declarations with IP_AGENT_EXPORT_VAR_DECL.  Variables
   must also be exported with C linkage.  As we can't both use extern
   "C" and initialize a variable in the same statement, variables that
   don't have a separate declaration must use
   EXTERN_C_PUSH/EXTERN_C_POP around their definition.  */

#ifdef IN_PROCESS_AGENT
# define IP_AGENT_EXPORT_FUNC EXTERN_C EXPORTED_SYMBOL ATTR_NOINLINE ATTR_USED
# define IP_AGENT_EXPORT_VAR EXPORTED_SYMBOL ATTR_USED
# define IP_AGENT_EXPORT_VAR_DECL EXTERN_C EXPORTED_SYMBOL
#else
# define IP_AGENT_EXPORT_FUNC
# define IP_AGENT_EXPORT_VAR
# define IP_AGENT_EXPORT_VAR_DECL extern
#endif

struct ipa_symbol
{
  CORE_ADDR addr;
  int target_flags;
};

IP_AGENT_EXPORT_VAR_DECL int tracing;

extern int disconnected_tracing;

void tracepoint_look_up_symbols (void);

void stop_tracing (void);

int handle_tracepoint_general_set (char *own_buf);
int handle_tracepoint_query (char *own_buf);

int tracepoint_finished_step (struct thread_info *tinfo, CORE_ADDR stop_pc);
int tracepoint_was_hit (struct thread_info *tinfo, CORE_ADDR stop_pc);

void release_while_stepping_state_list (struct thread_info *tinfo);

extern int current_traceframe;

int in_readonly_region (CORE_ADDR addr, ULONGEST length);
int traceframe_read_mem (int tfnum, CORE_ADDR addr,
			 unsigned char *buf, ULONGEST length,
			 ULONGEST *nbytes);
int fetch_traceframe_registers (int tfnum,
				struct regcache *regcache,
				int regnum);

int traceframe_read_sdata (int tfnum, ULONGEST offset,
			   unsigned char *buf, ULONGEST length,
			   ULONGEST *nbytes);

int traceframe_read_info (int tfnum, struct buffer *buffer);

/* If a thread is determined to be collecting a fast tracepoint, this
   structure holds the collect status.  */

struct fast_tpoint_collect_status
{
  /* The tracepoint that is presently being collected.  */
  int tpoint_num;
  CORE_ADDR tpoint_addr;

  /* The address range in the jump pad of where the original
     instruction the tracepoint jump was inserted was relocated
     to.  */
  CORE_ADDR adjusted_insn_addr;
  CORE_ADDR adjusted_insn_addr_end;
};

int fast_tracepoint_collecting (CORE_ADDR thread_area,
				CORE_ADDR stop_pc,
				struct fast_tpoint_collect_status *status);
void force_unlock_trace_buffer (void);

int handle_tracepoint_bkpts (struct thread_info *tinfo, CORE_ADDR stop_pc);

#ifdef IN_PROCESS_AGENT
void initialize_low_tracepoint (void);
const struct target_desc *get_ipa_tdesc (int idx);
void supply_fast_tracepoint_registers (struct regcache *regcache,
				       const unsigned char *regs);
void supply_static_tracepoint_registers (struct regcache *regcache,
					 const unsigned char *regs,
					 CORE_ADDR pc);
void set_trampoline_buffer_space (CORE_ADDR begin, CORE_ADDR end,
				  char *errmsg);
#else
void stop_tracing (void);

int claim_trampoline_space (ULONGEST used, CORE_ADDR *trampoline);
int have_fast_tracepoint_trampoline_buffer (char *msgbuf);
void gdb_agent_about_to_close (int pid);
#endif

struct traceframe;
struct eval_agent_expr_context;

/* Do memory copies for bytecodes.  */
/* Do the recording of memory blocks for actions and bytecodes.  */

int agent_mem_read (struct eval_agent_expr_context *ctx,
		    unsigned char *to, CORE_ADDR from,
		    ULONGEST len);

LONGEST agent_get_trace_state_variable_value (int num);
void agent_set_trace_state_variable_value (int num, LONGEST val);

/* Record the value of a trace state variable.  */

int agent_tsv_read (struct eval_agent_expr_context *ctx, int n);
int agent_mem_read_string (struct eval_agent_expr_context *ctx,
			   unsigned char *to,
			   CORE_ADDR from,
			   ULONGEST len);

/* The prototype the get_raw_reg function in the IPA.  Each arch's
   bytecode compiler emits calls to this function.  */
IP_AGENT_EXPORT_FUNC ULONGEST gdb_agent_get_raw_reg
  (const unsigned char *raw_regs, int regnum);

/* Returns the address of the get_raw_reg function in the IPA.  */
CORE_ADDR get_raw_reg_func_addr (void);
/* Returns the address of the get_trace_state_variable_value
   function in the IPA.  */
CORE_ADDR get_get_tsv_func_addr (void);
/* Returns the address of the set_trace_state_variable_value
   function in the IPA.  */
CORE_ADDR get_set_tsv_func_addr (void);

enum tracepoint_type
{
  /* Trap based tracepoint.  */
  trap_tracepoint,

  /* A fast tracepoint implemented with a jump instead of a trap.  */
  fast_tracepoint,

  /* A static tracepoint, implemented by a program call into a tracing
     library.  */
  static_tracepoint
};

/* The definition of a tracepoint.  */

/* Tracepoints may have multiple locations, each at a different
   address.  This can occur with optimizations, template
   instantiation, etc.  Since the locations may be in different
   scopes, the conditions and actions may be different for each
   location.  Our target version of tracepoints is more like GDB's
   notion of "breakpoint locations", but we have almost nothing that
   is not per-location, so we bother having two kinds of objects.  The
   key consequence is that numbers are not unique, and that it takes
   both number and address to identify a tracepoint uniquely.  */

struct tracepoint
{
  /* The number of the tracepoint, as specified by GDB.  Several
     tracepoint objects here may share a number.  */
  uint32_t number;

  /* Address at which the tracepoint is supposed to trigger.  Several
     tracepoints may share an address.  */
  CORE_ADDR address;

  /* Tracepoint type.  */
  enum tracepoint_type type;

  /* True if the tracepoint is currently enabled.  */
  int8_t enabled;

  /* The number of single steps that will be performed after each
     tracepoint hit.  */
  uint64_t step_count;

  /* The number of times the tracepoint may be hit before it will
     terminate the entire tracing run.  */
  uint64_t pass_count;

  /* Pointer to the agent expression that is the tracepoint's
     conditional, or NULL if the tracepoint is unconditional.  */
  struct agent_expr *cond;

  /* The list of actions to take when the tracepoint triggers.  */
  uint32_t numactions;
  struct tracepoint_action **actions;

  /* Count of the times we've hit this tracepoint during the run.
     Note that while-stepping steps are not counted as "hits".  */
  uint64_t hit_count;

  /* Cached sum of the sizes of traceframes created by this point.  */
  uint64_t traceframe_usage;

  CORE_ADDR compiled_cond;

  /* Link to the next tracepoint in the list.  */
  struct tracepoint *next;

  /* Optional kind of the breakpoint to be used
   note this can mean different things for different archs as z0
   breakpoint command */
  uint32_t kind;

#ifndef IN_PROCESS_AGENT
  /* The list of actions to take when the tracepoint triggers, in
     string/packet form.  */
  char **actions_str;

  /* The collection of strings that describe the tracepoint as it was
     entered into GDB.  These are not used by the target, but are
     reported back to GDB upon reconnection.  */
  struct source_string *source_strings;

  /* The number of bytes displaced by fast tracepoints. It may subsume
     multiple instructions, for multi-byte fast tracepoints.  This
     field is only valid for fast tracepoints.  */
  uint32_t orig_size;

  /* Only for fast tracepoints.  */
  CORE_ADDR obj_addr_on_target;

  /* Address range where the original instruction under a fast
     tracepoint was relocated to.  (_end is actually one byte past
     the end).  */
  CORE_ADDR adjusted_insn_addr;
  CORE_ADDR adjusted_insn_addr_end;

  /* The address range of the piece of the jump pad buffer that was
     assigned to this fast tracepoint.  (_end is actually one byte
     past the end).*/
  CORE_ADDR jump_pad;
  CORE_ADDR jump_pad_end;

  /* The address range of the piece of the trampoline buffer that was
     assigned to this fast tracepoint.  (_end is actually one byte
     past the end).  */
  CORE_ADDR trampoline;
  CORE_ADDR trampoline_end;

  /* The list of actions to take while in a stepping loop.  These
     fields are only valid for patch-based tracepoints.  */
  int num_step_actions;
  struct tracepoint_action **step_actions;
  /* Same, but in string/packet form.  */
  char **step_actions_str;

  /* Handle returned by the breakpoint or tracepoint module when we
     inserted the trap or jump, or hooked into a static tracepoint.
     NULL if we haven't inserted it yet.  */
  void *handle;
#endif

};

#endif /* TRACEPOINT_H */
