/* Copyright 2017 Free Software Foundation, Inc.

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

#include <pthread.h>

static pthread_barrier_t barrier;

static void *
thread_func (void *arg)
{
  /* Notify the main thread that this thread has started.  */
  pthread_barrier_wait (&barrier);

  /* Wait until main gives us the signal that we can quit.  */
  pthread_barrier_wait (&barrier);
  return NULL;
}

static void
thread_started ()
{
}

int main ()
{
  pthread_t thread;

  pthread_barrier_init (&barrier, NULL, 2);

  pthread_create (&thread, NULL, thread_func, NULL);

  /* Wait until the thread has started.  */
  pthread_barrier_wait (&barrier);

  thread_started ();

  /* Tell the thread that it can quit.  */
  pthread_barrier_wait (&barrier);

  pthread_join (thread, NULL);

  return 0;
}
