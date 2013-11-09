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
      if ((iecho->id == PING_ID) && (iecho->seqno == htons(ping_seq_num))) {
        /* do some ping result processing */
        PING_RESULT((ICMPH_TYPE(iecho) == ICMP_ER));
        return;
      } else {
        cmd_printf(out, "ping: drop\n");
      }
    }
  }

  if (len == 0) {
    cmd_printf(out, "ping: recv - %"U32_F" ms - timeout\n", sys_now()-ping_time);
  }

  /* do some ping result processing */
  PING_RESULT(0);
}

static void
start_ping(cmd_out_handle_t * out, ip_addr_t *ping_target, int timeout, int count)
{
  int s;

  if ((s = lwip_socket(AF_INET, SOCK_RAW, IP_PROTO_ICMP)) < 0) {
    return;
  }

  lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  while (count --) {

    if (ping_send(out, s, ping_target) == ERR_OK) {

      cmd_printf(out, "ping: send ");
      cmd_printf(out, "%"U16_F".%"U16_F".%"U16_F".%"U16_F"\n", 
          ip4_addr1_16(ping_target), ip4_addr2_16(ping_target), ip4_addr3_16(ping_target), ip4_addr4_16(ping_target));

      ping_time = sys_now();
      ping_recv(out, s, ping_target);
    } else {
      cmd_printf(out, "ping: send ");
      cmd_printf(out, "%"U16_F".%"U16_F".%"U16_F".%"U16_F" - error\n", 
          ip4_addr1_16(ping_target), ip4_addr2_16(ping_target), ip4_addr3_16(ping_target), ip4_addr4_16(ping_target));
    }
    sys_msleep(PING_DELAY);
  }

  lwip_close(s);
}

static int do_ping(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int count = PING_COUNT;
    int timeout = PING_RCV_TIMEO;
    int ch;
    ip_addr_t ping_target;
    optarg = NULL;
    optind = 0;


    while( (ch = getopt(argc, argv, "n:t:")) != -1) {
        switch(ch) {
        case 'n':
            count = atoi(optarg);
            if(count <= 0) count = PING_COUNT;
            break;
        case 't':
            timeout = atoi(optarg);
            if(timeout <= 0) count = PING_RCV_TIMEO;
            break;
        default:
            cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
            return -1;
        }
    }

    argc -= optind;
    argv += optind;

    if(argc != 1) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        return -1;
    }

    if(!inet_aton(argv[0], &ping_target)) {
        cmd_printf(out, "invalid ip %s\n", argv[0]);
        return -1;
    }
    //start_ping(cmd_out_handle_t * out, ip_addr_t *ping_target, int timeout, int count)
    start_ping(out, &ping_target, timeout, count);

    return 0;
}

void
ping_init(void)
{
    reg_cmd(do_ping, "ping", "usage: ping [-n count] [-t timeout_ms] host_ip\n");
}

