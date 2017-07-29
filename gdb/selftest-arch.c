/* GDB self-test for each gdbarch.
   Copyright (C) 2017 Free Software Foundation, Inc.

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

#if GDB_SELF_TEST
#include "selftest.h"
#include "selftest-arch.h"
#include "arch-utils.h"

static std::vector<std::pair<std::string, self_test_foreach_arch_function *>>
  gdbarch_tests;

void
register_self_test_foreach_arch (const std::string &name,
				 self_test_foreach_arch_function *function)
{
  gdbarch_tests.push_back (std::make_pair (name, function));
}

void
run_self_tests_with_arch (const char *filter)
{
  int failed = 0;
  int ran = 0;

  for (const auto &test : gdbarch_tests)
    {
      QUIT;

      if (filter != NULL && strlen (filter) > 0
	  && test.first.find (filter) == std::string::npos)
	continue;

      ran++;

      const char **arches = gdbarch_printable_names ();

      for (int i = 0; arches[i] != NULL; i++)
	{
	  QUIT;

	  if (strcmp ("fr300", arches[i]) == 0)
	    {
	      /* PR 20946 */
	      continue;
	    }
	  else if (strcmp ("powerpc:EC603e", arches[i]) == 0
		   || strcmp ("powerpc:e500mc", arches[i]) == 0
		   || strcmp ("powerpc:e500mc64", arches[i]) == 0
		   || strcmp ("powerpc:titan", arches[i]) == 0
		   || strcmp ("powerpc:vle", arches[i]) == 0
		   || strcmp ("powerpc:e5500", arches[i]) == 0
		   || strcmp ("powerpc:e6500", arches[i]) == 0)
	    {
	      /* PR 19797 */
	      continue;
	    }

	  QUIT;

	  TRY
	    {
	      struct gdbarch_info info;

	      gdbarch_info_init (&info);
	      info.bfd_arch_info = bfd_scan_arch (arches[i]);

	      struct gdbarch *gdbarch = gdbarch_find_by_info (info);
	      SELF_CHECK (gdbarch != NULL);
	      test.second (gdbarch);
	    }
	  CATCH (ex, RETURN_MASK_ERROR)
	    {
	      ++failed;
	      exception_fprintf (gdb_stderr, ex,
				 _("Self test failed: arch %s: "), arches[i]);
	    }
	  END_CATCH

	  /* Clear GDB internal state.  */
	  registers_changed ();
	  reinit_frame_cache ();
	}
    }

  printf_filtered (_("Ran %d arch unit tests, %d failed\n"),
		   ran, failed);
}

#endif
