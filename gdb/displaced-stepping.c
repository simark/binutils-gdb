#include "defs.h"

#include "displaced-stepping.h"

#include "gdbarch.h"
#include "gdbthread.h"
#include "target.h"
#include "inferior.h"
#include "gdbcore.h"

displaced_step_copy_insn_closure::~displaced_step_copy_insn_closure() = default;

displaced_step_prepare_status
single_displaced_buffer_manager::prepare (thread_info *thread)
{
  /* Is a thread currently using the buffer?  */
  if (m_current_thread != nullptr)
    {
      /* If so, it better not be this thread.  */
      gdb_assert (thread != m_current_thread);
      return DISPLACED_STEP_PREPARE_STATUS_UNAVAILABLE;
    }

  gdbarch *arch = thread->arch ();
  struct regcache *regcache = thread->regcache ();
  ULONGEST len = gdbarch_max_insn_length (arch);
  m_original_pc = regcache_read_pc (regcache);

  /* Save the original contents of the displaced stepping buffer.  */
  m_saved_copy.resize (len);

  int status = target_read_memory (m_buffer_addr, m_saved_copy.data (), len);
  if (status != 0)
    throw_error (MEMORY_ERROR,
		 _("Error accessing memory address %s (%s) for "
		   "displaced-stepping scratch space."),
		 paddress (arch, m_buffer_addr), safe_strerror (status));

  if (debug_displaced)
    {
      fprintf_unfiltered (gdb_stdlog, "displaced: saved %s: ",
			  paddress (arch, m_buffer_addr));
      displaced_step_dump_bytes (gdb_stdlog, m_saved_copy.data (), len);
    };

  m_copy_insn_closure = gdbarch_displaced_step_copy_insn (arch,
							  m_original_pc,
							  m_buffer_addr,
							  regcache);
  if (m_copy_insn_closure == nullptr)
    {
      /* The architecture doesn't know how or want to displaced step
        this instruction or instruction sequence.  Fallback to
        stepping over the breakpoint in-line.  */
      return DISPLACED_STEP_PREPARE_STATUS_ERROR;
    }

  try
    {
      /* Resume execution at the copy.  */
      regcache_write_pc (regcache, m_buffer_addr);
    }
  catch (...)
    {
      /* Failed to write the PC.  Release the architecture's displaced
         stepping resources and the thread's displaced stepping state.  */
      m_copy_insn_closure.reset ();

      return DISPLACED_STEP_PREPARE_STATUS_ERROR;
    }

  /* This marks the buffer as being in use.  */
  m_current_thread = thread;

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
single_displaced_buffer_manager::finish (gdbarch *arch, thread_info *thread,
					 gdb_signal sig)
{
  displaced_step_finish_status status;

  gdb_assert (thread == m_current_thread);

  ULONGEST len = gdbarch_max_insn_length (arch);

  write_memory_ptid (thread->ptid, m_buffer_addr,
		     m_saved_copy.data (), len);
  if (debug_displaced)
    fprintf_unfiltered (gdb_stdlog, "displaced: restored %s %s\n",
			target_pid_to_str (thread->ptid).c_str (),
			paddress (arch, m_buffer_addr));

  regcache *rc = get_thread_regcache (thread);

  bool instruction_executed_successfully
    = displaced_step_instruction_executed_successfully (arch, sig);


  if (instruction_executed_successfully)
    {
      gdbarch_displaced_step_fixup (arch, m_copy_insn_closure.get (), m_original_pc,
				    m_buffer_addr, rc);
      status = DISPLACED_STEP_FINISH_STATUS_OK;
    }
  else
    {
      /* Since the instruction didn't complete, all we can do is relocate the
	 PC.  */
      CORE_ADDR pc = regcache_read_pc (rc);
      pc = m_original_pc + (pc - m_buffer_addr);
      regcache_write_pc (rc, pc);
      status = DISPLACED_STEP_FINISH_STATUS_NOT_EXECUTED;
    }

  m_copy_insn_closure.reset ();
  m_current_thread = nullptr;

  return status;
}
