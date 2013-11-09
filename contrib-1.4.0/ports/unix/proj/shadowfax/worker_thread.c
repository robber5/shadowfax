#include "worker_thread.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <getopt.h>
#include <pthread.h>

int worker_thread_new(const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio)
{
  int code;
  pthread_t tmp;
  LWIP_UNUSED_ARG(name);
  LWIP_UNUSED_ARG(stacksize);
  LWIP_UNUSED_ARG(prio);

  code = pthread_create(&tmp,
                        NULL, 
                        (void *(*)(void *)) 
                        function, 
                        arg);
  
  return code == 0 ? 0 : -1;;
}



