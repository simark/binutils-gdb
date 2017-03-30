/* This testcase is part of GDB, the GNU debugger.

   Copyright 2017 Free Software Foundation, Inc.

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

#include <pthread.h>
#include <assert.h>

static pthread_barrier_t barrier;
static int x = 0;

static void *
thread_2_func (void *varg)
{
  int i;

  /* Tell the main thread the thread has started.  */
  pthread_barrier_wait (&barrier);

  /* Wait until main tells us we can start looping.  */
  pthread_barrier_wait (&barrier);

  for (i = 0; i < 100; i++)
    x++; /* thread_2_func loop tag */

  return NULL;
}

int
main (void)
{
  pthread_t thread2;
  int res;

  pthread_barrier_init (&barrier, NULL, 2);

  res = pthread_create (&thread2, NULL, thread_2_func, NULL);
  assert (res == 0);

  /* Wait until the thread has started.  */
  pthread_barrier_wait (&barrier);

  /* thread started tag */

  /* Tell the thread it can start looping.  */
  pthread_barrier_wait (&barrier);

  res = pthread_join (thread2, NULL);
  assert (res == 0);

  /* main done tag */

  return 0;
}
