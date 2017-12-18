/* This testcase is part of GDB, the GNU debugger.

   Copyright 2016-2017 Free Software Foundation, Inc.

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

int next (int i);

int
main (void)
{
  int result = -1;

  result = next (result);
  return result;
}

/* We implement the following function as far away from the first line
   of this file, so as to reduce confusion between line numbers from
   this file, and line numbers from body.inc (which only really has
   one line of code).  */

int
next (int i)  /* break here */
{
#include "break-include.inc"
  return i;
}
