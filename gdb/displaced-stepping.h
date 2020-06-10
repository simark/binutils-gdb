#ifndef DISPLACED_STEPPING_H
#define DISPLACED_STEPPING_H

#include "gdbsupport/byte-vector.h"

struct gdbarch;
struct thread_info;

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

/* Manage access to a single displaced stepping buffer, without any
   sharing.  */

struct single_displaced_buffer_manager
{
  single_displaced_buffer_manager (CORE_ADDR buffer_addr)
    : m_buffer_addr (buffer_addr)
  {}

  displaced_step_prepare_status prepare (thread_info *thread);

  displaced_step_finish_status finish (gdbarch *arch, thread_info *thread,
				       gdb_signal sig);

private:

  CORE_ADDR m_original_pc;
  CORE_ADDR m_buffer_addr;

  /* If set, the thread currently using the buffer.  */
  thread_info *m_current_thread = nullptr;

  gdb::byte_vector m_saved_copy;
  displaced_step_copy_insn_closure_up m_copy_insn_closure;
};


#endif /* DISPLACED_STEPPING_H */
