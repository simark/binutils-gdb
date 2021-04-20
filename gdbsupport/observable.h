/* Observers

   Copyright (C) 2016-2021 Free Software Foundation, Inc.

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

#ifndef COMMON_OBSERVABLE_H
#define COMMON_OBSERVABLE_H

#include <algorithm>
#include <functional>
#include <vector>
#include <unordered_set>

/* Print an "observer" debug statement.  */

#define observer_debug_printf(fmt, ...) \
  debug_prefixed_printf_cond (observer_debug, "observer", fmt, ##__VA_ARGS__)

#define OBSERVER_SCOPED_DEBUG_ENTER_EXIT \
  scoped_debug_enter_exit (observer_debug, "observer")

namespace gdb
{

namespace observers
{

extern bool observer_debug;

/* An observer is an entity which is interested in being notified
   when GDB reaches certain states, or certain events occur in GDB.
   The entity being observed is called the observable.  To receive
   notifications, the observer attaches a callback to the observable.
   One observable can have several observers.

   The observer implementation is also currently not reentrant.  In
   particular, it is therefore not possible to call the attach or
   detach routines during a notification.  */

/* The type of a key that can be passed to attach, which can be passed
   to detach to remove associated observers.  Tokens have address
   identity, and are thus usually const globals.  */
struct token
{
  token () = default;

  DISABLE_COPY_AND_ASSIGN (token);
};

template<typename... T>
class observable
{
public:
  typedef std::function<void (T...)> func_type;

private:
  struct observer
  {
    observer (const struct token *token, func_type func, const char *name,
	      const std::vector<const struct token *> &dependencies)
      : token (token), func (func), name (name), dependencies (dependencies)
    {}

    const struct token *token;
    func_type func;
    const char *name;
    std::vector<const struct token *> dependencies;
  };

public:
  explicit observable (const char *name)
    : m_name (name)
  {
  }

  DISABLE_COPY_AND_ASSIGN (observable);

  /* Attach F as an observer to this observable.  F cannot be
     detached.  */
  void attach (const func_type &f, const char *name,
	       std::vector<const struct token *> dependencies = {})
  {
    OBSERVER_SCOPED_DEBUG_ENTER_EXIT;

    observer_debug_printf ("Attaching observable %s to observer %s",
			   name, m_name);

    m_observers.emplace_back (nullptr, f, name, dependencies);
    this->sort_observers ();
  }

  /* Attach F as an observer to this observable.  T is a reference to
     a token that can be used to later remove F.  */
  void attach (const func_type &f, const token &t, const char *name,
	       std::vector<const struct token *> dependencies = {})
  {
    OBSERVER_SCOPED_DEBUG_ENTER_EXIT;

    observer_debug_printf ("Attaching observable %s to observer %s",
			   name, m_name);

    m_observers.emplace_back (&t, f, name, dependencies);
    this->sort_observers ();
  }

  /* Remove observers associated with T from this observable.  T is
     the token that was previously passed to any number of "attach"
     calls.  */
  void detach (const token &t)
  {
    auto iter = std::remove_if (m_observers.begin (),
				m_observers.end (),
				[&] (const observer &o)
				{
				  return o.token == &t;
				});

    observer_debug_printf ("Detaching observable %s from observer %s",
			   iter->name, m_name);

    m_observers.erase (iter, m_observers.end ());
  }

  /* Notify all observers that are attached to this observable.  */
  void notify (T... args)
  {
    observer_debug_printf ("observable %s notify() called", m_name);

    for (auto &&e : m_observers)
      e.func (args...);
  }

private:
  void debug_print_observers ()
  {
    for (const observer &o : m_observers)
      {
	std::string buf = string_printf ("  %s", o.name);

	if (o.token != nullptr)
	  buf += string_printf (" (%p)", o.token);

	if (o.dependencies.size () > 0)
	  {
	    buf += ", depends on:";

	    for (const struct token *dep : o.dependencies)
	      buf += string_printf (" %p", dep);
	  }

	observer_debug_printf ("%s", buf.c_str ());
      }
  }

  /* Sort M_OBSERVERS in a way that satisfies all dependencies.  */
  void sort_observers ()
  {
    observer_debug_printf
      ("Sorting observers for observable %s, order before sorting:", m_name);
    this->debug_print_observers ();

    /* The sorted vector we build.  */
    std::vector<observer> sorted_observers;

    /* The observers remaining to place into SORTED_OBSERVERS.  */
    std::vector<observer> remaining_observers = std::move (m_observers);

    /* The tokens of observers in REMAINING_OBSERVERS.  Note that not all
       observers have tokens, but if an observer A depends on observer B, then
       observer B necessarily has one.  */
    std::unordered_set<const struct token *> remaining_tokens;

    /* Sort REMAINING_OBSERVERS so it is in a known state.  This should help
       make the final order reproducible, and avoid the differences in behaviors
       between machines due to different observer order.  */
    std::sort (remaining_observers.begin (),
	       remaining_observers.end (),
	       [] (const observer &l, const observer &r)
		 {
		   return strcmp (l.name, r.name) < 0;
		 });

    /* Fill REMAINING_TOKENS.  */
    for (const observer &o : remaining_observers)
      if (o.token != nullptr)
	remaining_tokens.insert (o.token);

    while (!remaining_observers.empty ())
      {
	/* Look in REMAINING_OBSERVERS, pick one that has all its dependencies
	   already met (none of its dependencies in REMAINING_TOKENS).  */
	auto has_all_dependencies_met
	  = [&remaining_tokens] (const observer &candidate)
	  {
	    for (const token *dep_token : candidate.dependencies)
	      if (remaining_tokens.find (dep_token) != remaining_tokens.end ())
		return false;

	    return true;
	  };

	auto observer_to_remove = std::find_if (remaining_observers.begin (),
						remaining_observers.end (),
						has_all_dependencies_met);

	/* If we couldn't find an observer to remove, it means there's a
	   cycle.  */
	gdb_assert (observer_to_remove != remaining_observers.end ());

	sorted_observers.push_back (*observer_to_remove);
	remaining_tokens.erase (observer_to_remove->token);
	remaining_observers.erase (observer_to_remove);
      }

    m_observers = std::move (sorted_observers);

    observer_debug_printf ("order after sorting:");
    this->debug_print_observers ();
  }

  std::vector<observer> m_observers;
  const char *m_name;
};

} /* namespace observers */

} /* namespace gdb */

#endif /* COMMON_OBSERVABLE_H */
