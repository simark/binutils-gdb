/* GDB self-testing.
   Copyright (C) 2016-2017 Free Software Foundation, Inc.

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

#include "defs.h"
#include "selftest.h"
#include "selftest-arch.h"
#include <vector>

/* All the tests that have been registered.  */

static std::vector<std::pair<std::string, self_test_function *>> tests;

/* See selftest.h.  */

void
register_self_test (const std::string &name, self_test_function *function)
{
  tests.push_back (std::make_pair (name, function));
}

/* See selftest.h.  */

void
run_self_tests (const char *filter)
{
  int failed = 0;
  int ran = 0;

  printf_filtered (_("Running self-tests.\n"));

  for (auto test : tests)
    {
      QUIT;

      if (filter != NULL && strlen (filter) > 0
	  && test.first.find (filter) == std::string::npos)
	continue;

      ran++;

      TRY
	{
	  test.second ();
	}
      CATCH (ex, RETURN_MASK_ERROR)
	{
	  ++failed;
	  exception_fprintf (gdb_stderr, ex, _("Self test failed: "));
	}
      END_CATCH

      /* Clear GDB internal state.  */
      registers_changed ();
      reinit_frame_cache ();
    }

  printf_filtered (_("Ran %d unit tests, %d failed\n"),
		   ran, failed);

  run_self_tests_with_arch (filter);
}
