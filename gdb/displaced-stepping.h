#ifndef DISPLACED_STEPPING_H
#define DISPLACED_STEPPING_H

#include "gdbsupport/array-view.h"
#include "gdbsupport/byte-vector.h"

struct gdbarch;
struct thread_info;
struct target_ops;

enum displaced_step_prepare_status
{
  /* A displaced stepping buffer was successfully allocated and prepared.  */
  DISPLACED_STEP_PREPARE_STATUS_OK,

  /* Something bad happened.  */
  DISPLACED_STEP_PREPARE_STATUS_ERROR,

  /* Not enough resources are available at this time, try again later.  */
  DISPLACED_STEP_PREPARE_STATUS_UNAVAILABLE,
};

enum displaced_step_finish_status
{
  /* The instruction was stepped and fixed up.  */
  DISPLACED_STEP_FINISH_STATUS_OK,

  /* The instruction was not stepped.  */
  DISPLACED_STEP_FINISH_STATUS_NOT_EXECUTED,
};

/* Data returned by a gdbarch displaced_step_copy_insn method, to be passed to
   the matching displaced_step_fixup method.  */

struct displaced_step_copy_insn_closure
{
  virtual ~displaced_step_copy_insn_closure () = 0;
};

typedef std::unique_ptr<displaced_step_copy_insn_closure>
  displaced_step_copy_insn_closure_up;

/* A simple displaced step closure that contains only a byte buffer.  */

struct buf_displaced_step_copy_insn_closure : displaced_step_copy_insn_closure
{
  buf_displaced_step_copy_insn_closure (int buf_size)
  : buf (buf_size)
  {}

  gdb::byte_vector buf;
};

/* Per-inferior displaced stepping state.  */

struct displaced_step_inferior_state
{
  displaced_step_inferior_state ()
  {
    reset ();
  }

  /* Put this object back in its original state.  */
  void reset ()
  {
    failed_before = false;
  }

  /* True if preparing a displaced step ever failed.  If so, we won't
     try displaced stepping for this inferior again.  */
  bool failed_before;

  bool unavailable = false;
};

/* Per-thread displaced stepping state.  */

struct displaced_step_thread_state
{
  /* Return true if this thread is currently executing a displaced step.  */
  bool in_progress () const
  { return m_original_gdbarch != nullptr; }

  /* Return the gdbarch of the thread prior to the step.  */
  gdbarch *get_original_gdbarch () const
  { return m_original_gdbarch; }

  /* Mark this thread as currently executing a displaced step.

     ORIGINAL_GDBARCH is the current gdbarch of the thread (before the step
     is executed).  */
  void set (gdbarch *original_gdbarch)
  { m_original_gdbarch = original_gdbarch; }

  /* mark this thread as no longer executing a displaced step.  */
  void reset ()
  { m_original_gdbarch = nullptr; }

private:
  gdbarch *m_original_gdbarch = nullptr;
};

struct displaced_step_buffer_state
{
  displaced_step_buffer_state (CORE_ADDR buffer_addr)
    : m_buffer_addr (buffer_addr)
  {}

  const CORE_ADDR m_buffer_addr;

  /* When a displaced step operation is using this buffer, this is the original
     PC of the instruction currently begin stepped.  */
  CORE_ADDR m_original_pc = 0;

  /* If set, the thread currently using the buffer.  If unset, the buffer is not
     used.  */
  thread_info *m_current_thread = nullptr;

  /* Saved copy of the bytes in the displaced buffer, to be restored once the
     buffer is no longer used.  */
  gdb::byte_vector m_saved_copy;

  /* Closure obtained from gdbarch_displaced_step_copy_insn, to be passed to
     gdbarch_displaced_step_fixup_insn.  */
  displaced_step_copy_insn_closure_up m_copy_insn_closure;
};

/* Manage access to a single displaced stepping buffer, without any
   sharing.  */

struct multiple_displaced_buffer_manager
{
  multiple_displaced_buffer_manager (gdb::array_view<CORE_ADDR> buffer_addrs)
  {
    gdb_assert (buffer_addrs.size () > 0);

    for (CORE_ADDR buffer_addr : buffer_addrs)
      m_buffers.emplace_back (buffer_addr);
  }

  displaced_step_prepare_status prepare (thread_info *thread);

  displaced_step_finish_status finish (gdbarch *arch, thread_info *thread,
				       gdb_signal sig);

  CORE_ADDR first_buf_addr () const
    {
      return m_buffers[0].m_buffer_addr;
    }

private:
  std::vector<displaced_step_buffer_state> m_buffers;
};

displaced_step_prepare_status
  default_displaced_step_prepare (target_ops *target, thread_info *thread);

displaced_step_finish_status
  default_displaced_step_finish (target_ops *target, thread_info *thread,
				 gdb_signal sig);

#endif /* DISPLACED_STEPPING_H */
