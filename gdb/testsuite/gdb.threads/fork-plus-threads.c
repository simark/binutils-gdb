#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>


/* Number of times the main process forks.  */
#define NFORKS 10

/* Number of threads by each fork child.  */
#define NTHREADS 10

static void *
thread_func (void *arg)
{
  /* Empty.  */
}

static void
fork_child (void)
{
  pthread_t threads[NTHREADS];
  int i;
  int ret;

  for (i = 0; i < NTHREADS; i++)
    {
      ret = pthread_create (&threads[i], NULL, thread_func, NULL);
      assert (ret == 0);
    }

  for (i = 0; i < NTHREADS; i++)
    {
      ret = pthread_join (threads[i], NULL);
      assert (ret == 0);
    }
}

int
main (void)
{
  pid_t childs[NFORKS];
  int i;
  int status;
  int num_exited = 0;

  for (i = 0; i < NFORKS; i++)
  {
    pid_t pid;

    pid = fork ();

    if (pid > 0)
      {
	/* Parent.  */
	childs[i] = pid;
      }
    else if (pid == 0)
      {
	/* Child.  */
	fork_child ();
	return 0;
      }
    else
      {
	perror ("fork");
	return 1;
      }
  }

  while (num_exited != NFORKS)
    {
      pid_t pid = wait (&status);

      if (pid == -1)
	{
	  perror ("wait");
	  return 1;
	}

      if (WIFEXITED (status))
        {
	  num_exited++;
	}
      else
	{
	  printf ("Hmm, unexpected wait status 0x%x from child %d\n", status,
	         pid);
	}
    }

  return 0;
}
