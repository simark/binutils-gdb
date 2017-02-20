#include "defs.h"
#include "user-selection.h"
#include "inferior.h"
#include "gdbthread.h"
#include "observer.h"
#include "gdbcmd.h"

static user_selection main_user_selection;
static int debug_user_selection = 0;

static void apply_user_selection_to_core (user_selection *us);

user_selection *
get_main_user_selection ()
{
  return &main_user_selection;
}

void
init_user_selection ()
{
  /* Fetch the initial inferior, which should have been added by now.  */
  struct inferior *inf = find_inferior_id (1);

  gdb_assert (inf != nullptr);

  /* The initial inferior is selected by default on startup.  */
  get_main_user_selection ()->select_inferior (inf, false);
}

bool
user_selection::select_inferior (struct inferior *inf, bool notify)
{
  const char *debug_prefix = "user_selection::select_thread";

  gdb_assert (inf != nullptr);

  if (debug_user_selection)
    printf_unfiltered ("%s: num=#%d\n", debug_prefix, inf->num);

  /* No-op if this is already the currently selected inferior.  */
  if (inf == m_inferior)
    {
      if (debug_user_selection)
	printf_unfiltered ("%s: already selected inferior, returning", debug_prefix);

      return false;
    }

  user_selected_what what = USER_SELECTED_INFERIOR | USER_SELECTED_THREAD | USER_SELECTED_FRAME;

  /* This inferior becomes selected.  */
  m_inferior = inf;

  /* Clear the thread and frame fields.  */
  m_thread = nullptr;
  m_frame_id = null_frame_id;
  m_frame_level = INVALID_FRAME_LEVEL;

  if (m_inferior->pid != 0)
    {
      /* This inferior is executing, so it should have threads.  Select the first
         one.  */
      m_thread.reset(iterate_over_threads(
	[inf] (struct thread_info *thread, void *) -> int
	  {
	    return inf->pid == ptid_get_pid (thread->ptid);
	  }
      ));

      /* We expect this inferior to have at least one thread.  If we didn't
         find it, we have a problem.  */
      gdb_assert (m_thread != nullptr);
    }

  if (notify)
    observer_notify_user_selected_context_changed (this, what);

  return true;
}

bool
user_selection::select_thread (struct thread_info *th, bool notify)
{
  const char *debug_prefix = "user_selection::select_thread";
  user_selected_what what = USER_SELECTED_THREAD | USER_SELECTED_FRAME;

  if (debug_user_selection)
    printf_unfiltered ("%s: num=#%d, ptid=%s",
		       debug_prefix, th->global_num,
		       target_pid_to_str (th->ptid));

  /* No-op if this is already the currently selected thread.  */
  if (th == m_thread)
    {
      if (debug_user_selection)
	printf_unfiltered ("%s: already selected thread", debug_prefix);

      return false;
    }

  /* Clear the frame fields.  */
  m_frame_id = null_frame_id;
  m_frame_level = INVALID_FRAME_LEVEL;

  m_thread.reset (th);

  if (m_thread != nullptr)
    {
      if (m_inferior != th->inf)
	{
	  m_inferior = th->inf;

	  what |= USER_SELECTED_INFERIOR;
	}
    }

  sanity_check ();

  if (notify)
    observer_notify_user_selected_context_changed (this, what);

  return true;
}

bool
user_selection::select_frame (struct frame_info *frame, bool notify)
{
  if (frame_id_eq(m_frame_id, get_frame_id (frame))
      && m_frame_level == frame_relative_level (frame))
    {
      return false;
    }

  m_frame_id = get_frame_id (frame);
  m_frame_level = frame_relative_level (frame);

  if (debug_user_selection)
    {
      string_file buf;

      fprint_frame_id (&buf, m_frame_id);
      printf ("Selected frame level %d %s\n", m_frame_level, buf.c_str ());
    }

  if (notify)
    observer_notify_user_selected_context_changed (this, USER_SELECTED_FRAME);

  return true;
}

void
user_selection::sanity_check ()
{
  /* We always have a current inferior.  */
  gdb_assert (m_inferior != nullptr);

  if (m_thread != nullptr)
    {
      gdb_assert (m_thread->inf == m_inferior);
    }

  /* Can't have a current frame without a current thread.  */
  if (m_frame_level >= 0)
    {
      gdb_assert (m_thread != nullptr);
    }
}

static void
apply_user_selection_to_core (user_selection *us)
{
  set_current_inferior (us->inferior ());
  set_current_program_space (us->inferior ()->pspace);

  if (us->thread () != nullptr)
    switch_to_thread (us->thread ()->ptid);
  else
    switch_to_thread (null_ptid);

  if (us->has_valid_frame ())
    {
      int level;
      struct frame_info *fi = us->frame (&level);

      select_frame (fi);
      //restore_selected_frame (fi, level);
    }


}

void
user_selection::try_select_current_frame ()
{
  gdb_assert (!has_valid_frame ());

  /* We need to select the relevant inferior/thread in order for
     get_current_frame to work.  */
  apply_user_selection_to_core (this);

  TRY
    {
      struct frame_info *fi = get_current_frame ();

      m_frame_id = get_frame_id (fi);
      m_frame_level = frame_relative_level (fi);
    }
  CATCH (exception, RETURN_MASK_ALL)
    {
    }
  END_CATCH
}

void
apply_main_user_selection_to_core ()
{
  apply_user_selection_to_core (get_main_user_selection ());
}

/* Callback for the new_thread observer.  */

void
main_user_selection_on_new_thread (struct thread_info *tp)
{
  user_selection *us = get_main_user_selection ();

  /* If:

       1. A new thread is created,
       2. We don't have a currently selected thread,
       3. The inferior of the new thread is the currently selected inferior,

     then we make that new thread the selected one.  It covers the case of
     automatically selecting the initial thread when starting an inferior.  */
  if (us->thread () == nullptr && tp->inf == us->inferior ())
    us->select_thread (tp, false);
}

/* Callback for the on_exited observer.  */
static void
main_user_selection_on_exited (struct inferior *inferior)
{
  user_selection *us = get_main_user_selection ();

  /* When an inferior exits and it's the current inferior, it means we have one
     of its thread currently selected.  */
  if (inferior == us->inferior ())
    {
      us->select_thread (NULL, false);
    }
}

static void
main_user_selection_on_target_resumed (ptid_t ptid)
{
  user_selection *us = get_main_user_selection ();

  /* If our selected thread has been resumed, our frame isn't valid anymore.  */
  if (ptid_match (us->thread ()->ptid, ptid))
    us->select_frame (NULL, false);
}

static void
maint_print_user_selection (char *cmd, int from_tty)
{
  user_selection *us = get_main_user_selection ();

  struct inferior *inf = us->inferior ();

  fprintf_filtered(gdb_stdout, "inferior %p (num=%d)\n", inf, inf->num);

  struct thread_info *tp = us->thread ();

  if (tp != nullptr)
    fprintf_filtered (gdb_stdout,
		      "thread %p (gnum=%d, per-inf-num=%d, inf=%p)\n", tp,
		      tp->global_num, tp->per_inf_num, tp->inf);
  else
    fprintf_filtered(gdb_stdout, "thread null\n");

  struct frame_id frame = us->raw_frame_id ();

  fprint_frame_id (gdb_stdout, frame);
  fprintf_filtered (gdb_stdout, ", level=%d\n", us->raw_frame_level ());
}

void
_initialize_user_selection ()
{
  observer_attach_new_thread (main_user_selection_on_new_thread);
  observer_attach_inferior_exit (main_user_selection_on_exited);
  observer_attach_target_resumed (main_user_selection_on_target_resumed);

  add_setshow_boolean_cmd ("user-selection", class_maintenance,
			   &debug_user_selection, "blah", "blah", "blah", NULL,
			   NULL, &setdebuglist, &showdebuglist);

  add_cmd("user-selection", class_maintenance, maint_print_user_selection, "foo", &maintenanceprintlist);
}
