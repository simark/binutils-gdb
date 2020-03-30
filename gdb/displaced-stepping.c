#include "defs.h"

#include "displaced-stepping.h"

#include "gdbarch.h"
#include "gdbthread.h"
#include "target.h"
#include "inferior.h"
#include "gdbcore.h"

displaced_step_copy_insn_closure::~displaced_step_copy_insn_closure() = default;

displaced_step_prepare_status
multiple_displaced_buffer_manager::prepare (thread_info *thread)
{
  gdb_assert (!thread->displaced_step_state.in_progress ());
  displaced_step_buffer_state *buffer = nullptr;

  /* Sanity check.  */
  for (displaced_step_buffer_state &buf : m_buffers)
    gdb_assert (buf.m_current_thread != thread);

  /* Search for an unused buffer.  */
  for (displaced_step_buffer_state &candidate : m_buffers)
    {
      if (candidate.m_current_thread == nullptr)
	{
	  buffer = &candidate;
	  break;
	}
    }

  if (buffer == nullptr)
    return DISPLACED_STEP_PREPARE_STATUS_UNAVAILABLE;

  gdbarch *arch = thread->arch ();

  if (debug_displaced)
    fprintf_unfiltered (gdb_stdlog, "displaced: selected buffer at %s\n",
			paddress (arch, buffer->m_buffer_addr));

  struct regcache *regcache = thread->regcache ();
  ULONGEST len = gdbarch_max_insn_length (arch);
  buffer->m_original_pc = regcache_read_pc (regcache);

  /* Save the original contents of the displaced stepping buffer.  */
  buffer->m_saved_copy.resize (len);

  int status = target_read_memory (buffer->m_buffer_addr, buffer->m_saved_copy.data (), len);
  if (status != 0)
    throw_error (MEMORY_ERROR,
		 _("Error accessing memory address %s (%s) for "
		   "displaced-stepping scratch space."),
		 paddress (arch, buffer->m_buffer_addr), safe_strerror (status));

  if (debug_displaced)
    {
      fprintf_unfiltered (gdb_stdlog, "displaced: saved %s: ",
			  paddress (arch, buffer->m_buffer_addr));
      displaced_step_dump_bytes (gdb_stdlog, buffer->m_saved_copy.data (), len);
    };

  buffer->m_copy_insn_closure
    = gdbarch_displaced_step_copy_insn (arch, buffer->m_original_pc,
					buffer->m_buffer_addr, regcache);
  if (buffer->m_copy_insn_closure == nullptr)
    {
      /* The architecture doesn't know how or want to displaced step
        this instruction or instruction sequence.  Fallback to
        stepping over the breakpoint in-line.  */
      return DISPLACED_STEP_PREPARE_STATUS_ERROR;
    }

  try
    {
      /* Resume execution at the copy.  */
      regcache_write_pc (regcache, buffer->m_buffer_addr);
    }
  catch (...)
    {
      /* Failed to write the PC.  Release the architecture's displaced
         stepping resources and the thread's displaced stepping state.  */
      buffer->m_copy_insn_closure.reset ();

      return DISPLACED_STEP_PREPARE_STATUS_ERROR;
    }

  /* This marks the buffer as being in use.  */
  buffer->m_current_thread = thread;

  return DISPLACED_STEP_PREPARE_STATUS_OK;
}

static void
write_memory_ptid (ptid_t ptid, CORE_ADDR memaddr,
		   const gdb_byte *myaddr, int len)
{
  scoped_restore save_inferior_ptid = make_scoped_restore (&inferior_ptid);

  inferior_ptid = ptid;
  write_memory (memaddr, myaddr, len);
}

static bool
displaced_step_instruction_executed_successfully (gdbarch *arch, gdb_signal signal)
{
  if (signal != GDB_SIGNAL_TRAP)
    return false;

  if (target_stopped_by_watchpoint ())
    {
      // FIXME: Not sure about this condition.
      if (gdbarch_have_nonsteppable_watchpoint (arch)
	  || target_have_steppable_watchpoint)
	return false;
    }

  return true;
}

displaced_step_finish_status
multiple_displaced_buffer_manager::finish (gdbarch *arch, thread_info *thread,
					   gdb_signal sig)
{
  displaced_step_finish_status status;
  displaced_step_buffer_state *buffer = nullptr;

  gdb_assert (thread->displaced_step_state.in_progress ());

  /* Find the buffer this thread was using.  */
  for (displaced_step_buffer_state &candidate : m_buffers)
    {
      if (thread == candidate.m_current_thread)
	{
	  buffer = &candidate;
	  break;
	}
    }

  gdb_assert (buffer != nullptr);

  ULONGEST len = gdbarch_max_insn_length (arch);

  /* Restore memory of the buffer.  */
  write_memory_ptid (thread->ptid, buffer->m_buffer_addr,
		     buffer->m_saved_copy.data (), len);
  if (debug_displaced)
    fprintf_unfiltered (gdb_stdlog, "displaced: restored %s %s\n",
			target_pid_to_str (thread->ptid).c_str (),
			paddress (arch, buffer->m_buffer_addr));

  regcache *rc = get_thread_regcache (thread);

  bool instruction_executed_successfully
    = displaced_step_instruction_executed_successfully (arch, sig);

  if (instruction_executed_successfully)
    {
      gdbarch_displaced_step_fixup (arch, buffer->m_copy_insn_closure.get (),
				    buffer->m_original_pc,
				    buffer->m_buffer_addr, rc);
      status = DISPLACED_STEP_FINISH_STATUS_OK;
    }
  else
    {
      /* Since the instruction didn't complete, all we can do is relocate the
	 PC.  */
      CORE_ADDR pc = regcache_read_pc (rc);
      pc = buffer->m_original_pc + (pc - buffer->m_buffer_addr);
      regcache_write_pc (rc, pc);
      status = DISPLACED_STEP_FINISH_STATUS_NOT_EXECUTED;
    }

  buffer->m_copy_insn_closure.reset ();
  buffer->m_current_thread = nullptr;

  return status;
}

displaced_step_prepare_status
  default_displaced_step_prepare (target_ops *target, thread_info *thread)
{
  gdbarch *arch = thread->arch ();
  return gdbarch_displaced_step_prepare (arch, thread);
}

displaced_step_finish_status
default_displaced_step_finish (target_ops *target,
			       thread_info *thread,
			       gdb_signal sig)
{
  gdbarch *arch = thread->arch ();
  return gdbarch_displaced_step_finish (arch, thread, sig);
}
