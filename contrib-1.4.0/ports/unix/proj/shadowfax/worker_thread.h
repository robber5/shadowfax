#ifndef __WORKER_THREAD_H__
#define __WORKER_THREAD_H__

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/api.h"

int worker_thread_new(const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio);

#endif
