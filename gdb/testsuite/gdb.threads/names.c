/* This testcase is part of GDB, the GNU debugger.

   Copyright 2015 Free Software Foundation, Inc.

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

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

#define NUM_THREADS 3

struct thread_data
{
  const char *name;
  pthread_barrier_t *barrier;
};

static void *
thread_func (void *varg)
{
  struct thread_data *arg = (struct thread_data *) varg;

  pthread_setname_np (pthread_self (), arg->name);

  pthread_barrier_wait (arg->barrier);

  while (1)
    sleep (1);
}

static void
all_threads_ready (void)
{
}

int
main (int argc, char **argv)
{
  pthread_t threads[NUM_THREADS];
  struct thread_data args[NUM_THREADS];
  pthread_barrier_t barrier;
  int i;
  const char *names[] = { "carrot", "potato", "celery" };

  /* Make sure that NAMES contains NUM_THREADS elements.  */
  assert (sizeof (names) == sizeof(names[0]) * NUM_THREADS);

  assert (0 == pthread_barrier_init (&barrier, NULL, NUM_THREADS + 1));

  pthread_setname_np (pthread_self (), "main");

  for (i = 0; i < NUM_THREADS; i++)
    {
      struct thread_data *arg = &args[i];

      arg->name = names[i];
      arg->barrier = &barrier;

      assert (0 == pthread_create (&threads[i], NULL, thread_func, arg));
    }

  pthread_barrier_wait (&barrier);

  all_threads_ready ();

  return 0;
}
