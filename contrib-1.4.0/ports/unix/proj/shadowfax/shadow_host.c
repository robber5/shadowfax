/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Steel Mental <steel.mental@gmail.com>
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>


#include "lwip/opt.h"

#include "lwip/init.h"

#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"

#include "lwip/stats.h"

#include "lwip/inet.h"
#include "lwip/inet_chksum.h"

#include "lwip/tcpip.h"
#include "lwip/sockets.h"
#include "lwip/dhcp.h"

#include "netif/udpif.h"

#include "netif/tcpdump.h"

#include "lwip/ip_addr.h"
#include "arch/perf.h"

#include "console.h"
#include "peer_refresher.h"
#include "shell_service.h"
#include "transfer_service.h"
#include "forward_service.h"
#include "misc_cmd.h"
#include "log.h"

/* default udp listen port */
#define DEFAULT_LISTEN_PORT 53

/* (manual) shadow host IP configuration */
static ip_addr_t shadow_ipaddr, shadow_netmask, shadow_gw;

/* (manual) peer host IP configuration */
static u16_t peer_port;
static char * peer_host;

/* nonstatic debug cmd option, exported in lwipopts.h */
unsigned char debug_flags;

static int use_dhcp;
static int run_daemon;
static const char * pid_file = "/var/run/shadow.pid";

/** @todo add options for selecting netif, starting DHCP client etc */

static const char * opt_descs[] = {
  /* turn on debugging output (if build with LWIP_DEBUG) */
  "turn on debugging output (if build with LWIP_DEBUG), default off",
  /* help */
  "show help",
  /* gateway address */
  "set shadow gw, default 192.168.0.1",
  /* ip address */
  "set shadow gw, default 192.168.0.2",
  /* netmask */
  "set shadow netmask, default 255.255.255.0",
  /* shadow dhcp server */
  "use dhcp, default off",
  /* bind which host ip? */
  "set bind host ip address, default 0.0.0.0",
  /* bind which host port? */
  "set host listen port, default 53",
  /* daemon */
  "run as daemon, default off",
  /* pid file */
  "set pid file, default /var/run/shadow.pid",
  NULL
};

static struct option longopts[] = {
  /* turn on debugging output (if build with LWIP_DEBUG) */
  {"debug", no_argument,        NULL, 'v'}, 
  /* help */
  {"help", no_argument, NULL, 'h'},
  /* gateway address */
  {"shadow-gateway", required_argument, NULL, 'g'},
  /* ip address */
  {"shadow-ip", required_argument, NULL, 'i'},
  /* netmask */
  {"shadow-netmask", required_argument, NULL, 'm'},
  /* shadow dhcp server */
  {"shadow-dhcp", no_argument, NULL, 'd'},
  /* bind which host ip? */
  {"bind-ip", required_argument, NULL, 'b'},
  /* bind which host port? */
  {"listen-port", required_argument, NULL, 'l'},
  {"daemon", no_argument, NULL, 'D'},
  {"pid-file", required_argument, NULL, 'p'},
  {NULL,   0,                 NULL,  0}
};

#define NUM_OPTS ((sizeof(longopts) / sizeof(struct option)) - 1)

static void init_netifs(void);

static void clear_cmdline(int argc, char ** argv)
{
    int len = 0;
    int i;
    for(i = 0 ; i < argc ; i ++) {
        len += strlen(argv[i]) + 1;
    }
    memset(argv[0], 0, len);
    snprintf(argv[0], len, "shadow");
}

static void touch_pid(const char * pid_file_name)
{
    FILE * pid_f = NULL;

    if((pid_f = fopen(pid_file_name, "wb")) != NULL) {
        fprintf(pid_f, "%d", getpid());
        fclose(pid_f);
        pid_f = NULL;
    }
}

static void usage(void)
{
  unsigned char i;
  
  printf("shadow_host [options] peer-host peer-port\n");
  printf("options:\n");
  for (i = 0; i < sizeof(longopts)/sizeof(struct option); i++) {
    if(longopts[i].name) {
        printf("-%c --%s : %s\n",longopts[i].val, longopts[i].name, opt_descs[i]);
    }
  }
}

static void
tcpip_init_done(void *arg)
{
  sys_sem_t *sem;
  sem = (sys_sem_t *)arg;
  init_netifs();
  sys_sem_signal(sem);
}

/*-----------------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------------*/

struct netif netif;
struct udpif udpif_state;

static void
init_netifs(void)
{ 
  if(!use_dhcp) {
    netif_set_default(netif_add(&netif,&shadow_ipaddr, &shadow_netmask, &shadow_gw, &udpif_state, udpif_init,
                      tcpip_input));
    netif_set_up(&netif);
    netif_set_default(&netif);
  } else {
    IP4_ADDR(&shadow_gw, 0,0,0,0);
    IP4_ADDR(&shadow_ipaddr, 0,0,0,0);
    IP4_ADDR(&shadow_netmask, 0,0,0,0);

    netif_add(&netif, &shadow_ipaddr, &shadow_netmask, &shadow_gw, &udpif_state, udpif_init,
              tcpip_input);
    netif_set_up(&netif);
    netif_set_default(&netif);
    dhcp_start(&netif);
  }
}

/*-----------------------------------------------------------------------------------*/
static void
main_thread(void *arg)
{
  sys_sem_t sem;

  LWIP_UNUSED_ARG(arg);

  netif_init();

  if(sys_sem_new(&sem, 0) != ERR_OK) {
    LWIP_ASSERT("Failed to create semaphore", 0);
  }
  tcpip_init(tcpip_init_done, &sem);
  sys_sem_wait(&sem);
  SINF("TCP/IP initialized.\n");

  console_init();
  shell_service_init();
  transfer_service_init();
  forward_service_init();
  misc_cmd_init();

  /* Block forever. */
  sys_sem_wait(&sem);
}
/*-----------------------------------------------------------------------------------*/
int
main(int argc, char **argv)
{
  int ch;
  int old_argc = argc;
  char ** old_argv = argv;

  /* startup defaults (may be overridden by one or more opts) */
  IP4_ADDR(&shadow_gw, 192,168,0,1);
  IP4_ADDR(&shadow_netmask, 255,255,255,0);
  IP4_ADDR(&shadow_ipaddr, 192,168,0,2);
  
  bzero(&udpif_state, sizeof(udpif_state));
  udpif_state.local_ip.addr = INADDR_ANY;
  udpif_state.local_port = htons(DEFAULT_LISTEN_PORT);

  /* use debug flags defined by debug.h */
  debug_flags = LWIP_DBG_OFF;
  shadow_quiet = 1;
  
  while ((ch = getopt_long(argc, argv, "Dvhgd:i:m:b:l:p:", longopts, NULL)) != -1) {
    switch (ch) {
      case 'v':
        /*debug_flags |= (LWIP_DBG_ON|LWIP_DBG_TRACE|LWIP_DBG_STATE|LWIP_DBG_FRESH|LWIP_DBG_HALT);*/
        shadow_quiet = 0;
        break;
      case 'd':
        use_dhcp = 1;
        break;
      case 'h':
        usage();
        exit(0);
        break;
      case 'g':
        inet_aton(optarg, &shadow_gw);
        break;
      case 'i':
        inet_aton(optarg, &shadow_ipaddr);
        break;
      case 'm':
        inet_aton(optarg, &shadow_netmask);
        break;
      case 'b':
        inet_aton(optarg, &udpif_state.local_ip);
        break;
      case 'l':
        udpif_state.local_port = (u16_t)htons(atoi(optarg));
        break;
      case 'D':
        run_daemon = 1;
        break;
      case 'p':
        pid_file = optarg;
        break;
      default:
        usage();
        break;
    }
  }

  argc -= optind;
  argv += optind;

  if(argc != 2) {
    usage();
    exit(1);
  }

  if(run_daemon) {
    daemon(0,0);
  }

  if(pid_file) {
    touch_pid(pid_file);
  }

  peer_host = strdup(argv[0]);
  peer_port = (u16_t)htons(atoi(argv[1]));

  clear_cmdline(old_argc, old_argv);

  SINF("System initialized.\n");
    
  sys_thread_new("main_thread", main_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

  peer_refresh(&netif, peer_host, peer_port); /* loop for ever, refresh peer ip */

  return 0;
}
/*-----------------------------------------------------------------------------------*/

