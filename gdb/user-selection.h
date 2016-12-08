#ifndef USER_SELECTION_H
#define USER_SELECTION_H

#include "observer.h"

class user_selection {
public:

  user_selection ()
  : m_inferior (nullptr),
    m_thread (nullptr),
    m_frame_id (null_frame_id),
    m_frame_level (-1)
  {}

  bool select_inferior (struct inferior *inf, bool notify);
  bool select_thread (struct thread_info *th, bool notify);
  bool select_frame (struct frame_info *frame, bool notify);

  struct inferior *inferior ()
  { return m_inferior; }

  struct thread_info *thread ()
  { return m_thread; }

  struct frame_info *
  frame (int *level = nullptr)
  {
    if (!has_valid_frame ())
      try_select_current_frame ();

    if (!has_valid_frame ())
      return NULL;

    if (level != nullptr)
      *level = m_frame_level;

    return frame_find_by_id (m_frame_id);
  }

  frame_id
  raw_frame_id ()
  { return m_frame_id; }

  int
  raw_frame_level ()
  { return m_frame_level; }

  bool has_valid_frame ()
  { return m_frame_level >= 0; }

private:

  struct inferior *m_inferior;
  struct thread_info *m_thread;

  struct frame_id m_frame_id;
  int m_frame_level;

  void sanity_check ();
  void try_select_current_frame ();
};

void init_user_selection();
user_selection *get_main_user_selection ();
void apply_main_user_selection_to_core ();

#endif /* USER_SELECTION_H */
