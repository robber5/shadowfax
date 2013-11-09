/**
 * @file
 * Ping sender module
 *
 */

/*
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
 */

/** 
 * This is an example of a "ping" sender (with raw API and socket API).
 * It can be used as a start point to maintain opened a network connection, or
 * like a network "watchdog" for your device.
 *
 */

#include "lwip/opt.h"

#include <getopt.h>

#include "ping.h"

#include "lwip/mem.h"
#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/timers.h"
#include "lwip/inet_chksum.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "cmd.h"
#include "log.h"
#include "worker_thread.h"

/* ping variables */
static u16_t ping_seq_num;
static u32_t ping_time;

/** Prepare a echo ICMP request */
static void
ping_prepare_echo( struct icmp_echo_hdr *iecho, u16_t len)
{
  size_t i;
  size_t data_len = len - sizeof(struct icmp_echo_hdr);

  ICMPH_TYPE_SET(iecho, ICMP_ECHO);
  ICMPH_CODE_SET(iecho, 0);
  iecho->chksum = 0;
  iecho->id     = PING_ID;
  iecho->seqno  = htons(++ping_seq_num);

  /* fill the additional data buffer with some data */
  for(i = 0; i < data_len; i++) {
    ((char*)iecho)[sizeof(struct icmp_echo_hdr) + i] = (char)i;
  }

  iecho->chksum = inet_chksum(iecho, len);
}

/* Ping using the socket ip */
static err_t
ping_send(cmd_out_handle_t * out, int s, ip_addr_t * ping_target)
{
  int err;
  struct icmp_echo_hdr *iecho;
  struct sockaddr_in to;
  size_t ping_size = sizeof(struct icmp_echo_hdr) + PING_DATA_SIZE;

  LWIP_UNUSED_ARG(out);

  iecho = (struct icmp_echo_hdr *)mem_malloc((mem_size_t)ping_size);
  if (!iecho) {
    return ERR_MEM;
  }

  ping_prepare_echo(iecho, (u16_t)ping_size);

  to.sin_len = sizeof(to);
  to.sin_family = AF_INET;
  inet_addr_from_ipaddr(&to.sin_addr, ping_target);

  err = lwip_sendto(s, iecho, ping_size, 0, (struct sockaddr*)&to, sizeof(to));

  mem_free(iecho);

  return (err ? ERR_OK : ERR_VAL);
}

static void
ping_recv(cmd_out_handle_t * out, int s, ip_addr_t * ping_target)
{
  char buf[64];
  int fromlen, len;
  struct sockaddr_in from;
  struct ip_hdr *iphdr;
  struct icmp_echo_hdr *iecho;

  LWIP_UNUSED_ARG(ping_target);

  fromlen = sizeof(from);

  while((len = lwip_recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&from, (socklen_t*)&fromlen)) > 0) {
    if (len >= (int)(sizeof(struct ip_hdr)+sizeof(struct icmp_echo_hdr))) {
      ip_addr_t fromaddr;
      inet_addr_to_ipaddr(&fromaddr, &from.sin_addr);

      cmd_printf(out, "ping: recv ");
      cmd_printf(out, "%"U16_F".%"U16_F".%"U16_F".%"U16_F" %"U32_F" ms\n", 
          ip4_addr1_16(&fromaddr), ip4_addr2_16(&fromaddr), ip4_addr3_16(&fromaddr), ip4_addr4_16(&fromaddr),
          sys_now() - ping_time);

      iphdr = (struct ip_hdr *)buf;
      iecho = (struct icmp_echo_hdr *)(buf + (IPH_HL(iphdr) * 4));
      SDBG("ping_recv quit 1, len is %d\n", len);
      return;
    }
  }

  if (len <= 0) {
    cmd_printf(out, "ping: recv - %"U32_F" ms - timeout\n", sys_now()-ping_time);
  }

  /* do some ping result processing */
  PING_RESULT(0);
  SDBG("ping_recv quit 2, len is %d\n", len);
}


typedef struct _ping_param_t
{
    cmd_slot_t * slot;
    cmd_out_handle_t * out;
    int timeout;
    int count;
    ip_addr_t target;
}ping_param_t;

static void
ping_thread(void * param)
{
  int s;
  ping_param_t *p = (ping_param_t *)param;

  SDBG("create socket, timeout %d, count %d\n", p->timeout, p->count);
  if ((s = lwip_socket(AF_INET, SOCK_RAW, IP_PROTO_ICMP)) < 0) {
    free(param);
    SDBG("ping_thread abort\n");
    return;
  }

  SDBG("create socket down\n");

  lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &p->timeout, sizeof(p->timeout));

  SDBG("setsockopt socket down\n");

  while (p->count --) {

    SDBG("will do ping_send\n");
    if (ping_send(p->out, s, &p->target) == ERR_OK) {
    SDBG("ping_send done\n");

      cmd_printf(p->out, "ping: send ");
      cmd_printf(p->out, "%"U16_F".%"U16_F".%"U16_F".%"U16_F"\n", 
          ip4_addr1_16(&p->target), ip4_addr2_16(&p->target), ip4_addr3_16(&p->target), ip4_addr4_16(&p->target));

      ping_time = sys_now();
      ping_recv(p->out, s, &p->target);
    } else {
      cmd_printf(p->out, "ping: send ");
      cmd_printf(p->out, "%"U16_F".%"U16_F".%"U16_F".%"U16_F" - error\n", 
          ip4_addr1_16(&p->target), ip4_addr2_16(&p->target), ip4_addr3_16(&p->target), ip4_addr4_16(&p->target));
    }
    sys_msleep(PING_DELAY);
  }

  lwip_close(s);

  free(p);

  SDBG("ping_thread quit\n");
}

static int do_ping(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int ch;
    optarg = NULL;
    optind = 0;
    ping_param_t * param;

    param = malloc(sizeof(ping_param_t));
    if(NULL == param) {
        cmd_printf(out,"OOM\n");
        return -1;
    }

    param->count = PING_COUNT;
    param->timeout = PING_RCV_TIMEO;
    param->slot = slot;
    param->out  = out;


    while( (ch = getopt(argc, argv, "n:t:")) != -1) {
        switch(ch) {
        case 'n':
            param->count = atoi(optarg);
            if(param->count <= 0) param->count = PING_COUNT;
            break;
        case 't':
            param->timeout = atoi(optarg);
            if(param->timeout <= 0) param->timeout = PING_RCV_TIMEO;
            break;
        default:
            cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
            free(param);
            return -1;
        }
    }

    argc -= optind;
    argv += optind;

    if(argc != 1) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        free(param);
        return -1;
    }

    if(!inet_aton(argv[0], &param->target)) {
        cmd_printf(out, "invalid ip %s\n", argv[0]);
        free(param);
        return -1;
    }

    worker_thread_new("ping_thread", ping_thread, param, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
    /* param freed by thread */

    return 0;
}

void
ping_init(void)
{
    reg_cmd(do_ping, "ping", "usage: ping [-n count] [-t timeout_ms] host_ip\n");
}

