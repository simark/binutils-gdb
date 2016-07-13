/* This testcase is part of GDB, the GNU debugger.

   Copyright 2016 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <pthread.h>
#include <unistd.h>

#define NUM_THREADS 2

volatile int thread_nb = 1;
volatile int quit = 1;
pthread_barrier_t barrier;

void
child_sub_function ()
{
  pthread_barrier_wait (&barrier);
  while (!quit) /* set break here */
    usleep (1);

  pthread_exit (NULL);
}

void *
child_function (void *args)
{
  ++thread_nb;
  child_sub_function (); /* caller */
}

pthread_t child_thread[NUM_THREADS];

int
main (void)
{
  int i = 0;
  pthread_barrier_init (&barrier, NULL, NUM_THREADS);

  for (i = 0; i < NUM_THREADS; i++)
    {
      pthread_create (&child_thread[i], NULL, child_function, NULL);
    }

  for (i = 0; i < NUM_THREADS; i++)
    {
      pthread_join (child_thread[i], NULL);
    }

  return 0;
}
