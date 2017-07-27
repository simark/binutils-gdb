/* environ.c -- library for manipulating environments for GNU.

   Copyright (C) 1986-2017 Free Software Foundation, Inc.

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

#include "common-defs.h"
#include "environ.h"
#include <algorithm>
#include <utility>

/* See common/environ.h.  */

gdb_environ &
gdb_environ::operator= (gdb_environ &&e)
{
  /* Are we self-moving?  */
  if (&e == this)
    return *this;

  m_environ_vector = std::move (e.m_environ_vector);
  m_user_set_env_list = std::move (e.m_user_set_env_list);
  m_user_unset_env_list = std::move (e.m_user_unset_env_list);
  e.m_environ_vector.clear ();
  e.m_environ_vector.push_back (NULL);
  e.m_user_set_env_list.clear ();
  e.m_user_unset_env_list.clear ();
  return *this;
}

/* See common/environ.h.  */

gdb_environ gdb_environ::from_host_environ ()
{
  extern char **environ;
  gdb_environ e;

  if (environ == NULL)
    return e;

  for (int i = 0; environ[i] != NULL; ++i)
    {
      /* Make sure we add the element before the last (NULL).  */
      e.m_environ_vector.insert (e.m_environ_vector.end () - 1,
				 xstrdup (environ[i]));
    }

  return e;
}

/* See common/environ.h.  */

void
gdb_environ::clear ()
{
  for (char *v : m_environ_vector)
    xfree (v);
  m_environ_vector.clear ();
  m_user_set_env_list.clear ();
  for (const char *v : m_user_unset_env_list)
    xfree ((void *) v);
  m_user_unset_env_list.clear ();
  /* Always add the NULL element.  */
  m_environ_vector.push_back (NULL);
}

/* Helper function to check if STRING contains an environment variable
   assignment of VAR, i.e., if STRING starts with 'VAR='.  Return true
   if it contains, false otherwise.  */

static bool
match_var_in_string (const char *string, const char *var, size_t var_len)
{
  if (strncmp (string, var, var_len) == 0 && string[var_len] == '=')
    return true;

  return false;
}

/* See common/environ.h.  */

const char *
gdb_environ::get (const char *var) const
{
  size_t len = strlen (var);

  for (char *el : m_environ_vector)
    if (el != NULL && match_var_in_string (el, var, len))
      return &el[len + 1];

  return NULL;
}

/* See common/environ.h.  */

void
gdb_environ::set (const char *var, const char *value)
{
  char *fullvar = concat (var, "=", value, NULL);

  /* We have to unset the variable in the vector if it exists.  */
  unset (var, false);

  /* Insert the element before the last one, which is always NULL.  */
  m_environ_vector.insert (m_environ_vector.end () - 1, fullvar);

  /* Mark this environment variable as having been set by the user.
     This will be useful when we deal with setting environment
     variables on the remote target.  */
  m_user_set_env_list.push_back (fullvar);

  /* If this environment variable is marked as unset by the user, then
     remove it from the list, because now the user wants to set
     it.  */
  for (std::vector<const char *>::iterator iter_user_unset
	 = m_user_unset_env_list.begin ();
       iter_user_unset != m_user_unset_env_list.end ();
       ++iter_user_unset)
    if (strcmp (var, *iter_user_unset) == 0)
      {
	void *v = (void *) *iter_user_unset;

	m_user_unset_env_list.erase (iter_user_unset);
	xfree (v);
	break;
      }
}

/* See common/environ.h.  */

void
gdb_environ::unset (const char *var, bool update_unset_list)
{
  size_t len = strlen (var);
  std::vector<char *>::iterator it_env;

  /* We iterate until '.end () - 1' because the last element is
     always NULL.  */
  for (it_env = m_environ_vector.begin ();
       it_env != m_environ_vector.end () - 1;
       ++it_env)
    if (match_var_in_string (*it_env, var, len))
      break;

  if (it_env == m_environ_vector.end () - 1)
    {
      /* No element has been found.  */
      return;
    }

  std::vector<const char *>::iterator it_user_set_env;
  char *found_var = *it_env;

  it_user_set_env = std::remove (m_user_set_env_list.begin (),
				 m_user_set_env_list.end (),
				 found_var);
  if (it_user_set_env != m_user_set_env_list.end ())
    {
      /* We found (and removed) the element from the user_set_env
	 vector.  */
      m_user_set_env_list.erase (it_user_set_env, m_user_set_env_list.end ());
    }

  if (update_unset_list)
    {
      bool found_in_unset = false;

      for (const char *el : m_user_unset_env_list)
	if (strcmp (el, var) == 0)
	  {
	    found_in_unset = true;
	    break;
	  }

      if (!found_in_unset)
	m_user_unset_env_list.push_back (xstrdup (var));
    }

  m_environ_vector.erase (it_env);
  xfree (found_var);
}

/* See common/environ.h.  */

void
gdb_environ::clear_user_set_env ()
{
  std::vector<const char *> copy = m_user_set_env_list;

  for (const char *var : copy)
    {
      std::string varname (var);

      varname.erase (varname.find ('='), std::string::npos);
      unset (varname.c_str (), false);
    }
}

/* See common/environ.h.  */

char **
gdb_environ::envp () const
{
  return const_cast<char **> (&m_environ_vector[0]);
}

/* See common/environ.h.  */

const std::vector<const char *> &
gdb_environ::user_set_envp () const
{
  return m_user_set_env_list;
}

const std::vector<const char *> &
gdb_environ::user_unset_envp () const
{
  return m_user_unset_env_list;
}
