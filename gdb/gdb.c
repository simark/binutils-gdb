/* Main function for CLI gdb.  
   Copyright (C) 2002-2017 Free Software Foundation, Inc.

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
#include "main.h"
#include "interps.h"

#include <client/linux/handler/exception_handler.h>

static bool
cb (const  google_breakpad::MinidumpDescriptor& descriptor, void* context, bool succeeded)
{
  int pid = fork ();

  if (pid == 0) {
      const char *exec_path = "/bin/echo";
      const char *args[] = {
	  exec_path,
	  "Dump written to: ",
	  descriptor.path(),
	  NULL,
      };

      execv (exec_path, (char **) args);
  }

  return succeeded;
}

int
main (int argc, char **argv)
{
  struct captured_main_args args;

  google_breakpad::MinidumpDescriptor descriptor ("/tmp");
  google_breakpad::ExceptionHandler eh(descriptor, NULL, cb, NULL, true, -1);

  memset (&args, 0, sizeof args);
  args.argc = argc;
  args.argv = NULL;
  args.interpreter_p = INTERP_CONSOLE;
  return gdb_main (&args);
}
