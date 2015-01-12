/* This test program is part of GDB, the GNU debugger.

   Copyright 2011-2014 Free Software Foundation, Inc.

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

/* This is the test program loaded into GDB by the py-unwind test.  */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void *
swap_value (void **location, void *new_value)
{
  void *old_value = *location;
  *location = new_value;
  return old_value;
}

#define MY_FRAME (__builtin_frame_address (0))

static void
break_backtrace ()
{
  /* Save outer frame address, then corrupt the unwind chain by
     setting the outer frame address in it to self.  This is
     ABI-specific: the first word of the frame contains previous frame
     address in amd64.  */
  void *outer_fp = swap_value ((void **)MY_FRAME, MY_FRAME);

  /* Verify the compiler allocates the first local variable one word
     below frame.  This is where test JIT reader expects to find the
     correct outer frame address.  */
  if (&outer_fp + 1 != (void **)MY_FRAME)
    {
      fprintf (stderr, "First variable should be allocated one word below "
               "the frame, got variable's address %p, frame at %p instead\n",
               &outer_fp, MY_FRAME);
      abort();
    }

  /* Now restore it so that we can return.  The test sets the
     breakpoint just before this happens, and GDB will not be able to
     show the backtrace without JIT reader.  */
  swap_value (MY_FRAME, outer_fp); /* break backtrace-broken */
}

static void
break_backtrace_caller ()
{
  break_backtrace ();
}

int
main (int argc, char *argv[])
{
  break_backtrace_caller ();
}
