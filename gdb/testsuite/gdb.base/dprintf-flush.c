/* This testcase is part of GDB, the GNU debugger.

   Copyright (C) 2015 Free Software Foundation, Inc.

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

#include <stdio.h>

static int myflush_called = 0;
static FILE *myflush_arg = NULL;

static void myflush (FILE *f)
{
  myflush_called++;
  myflush_arg = f;
  fflush (f);
}

int
main (int argc, char *argv[])
{
  volatile int a = 0;
  int i;

  for (i = 0; i < 10; i++)
    {
      a++; /* dprintf here */
      a++; /* breakpoint here */
    }

  return a;
}

#include <stdlib.h>
/* Make sure function 'malloc' is linked into program.  One some bare-metal
   port, if we don't use 'malloc', it will not be linked in program.  'malloc'
   is needed, otherwise we'll see such error message

   evaluation of this expression requires the program to have a function
   "malloc".  */
void
bar (void)
{
  void *p = malloc (16);

  free (p);
}
