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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "netif/udpif.h"

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "lwip/debug.h"

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"

#include "netif/etharp.h"

#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
#include "netif/tcpdump.h"
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */

#include "encrypt.h"
#include "compress.h"
#include "log.h"

#define IFNAME0 'u'
#define IFNAME1 'd'

#ifndef UDPIF_DEBUG
#define UDPIF_DEBUG LWIP_DBG_OFF
#endif

/* Forward declarations. */
static void  udpif_input(struct netif *netif);

static void udpif_thread(void *data);

/*-----------------------------------------------------------------------------------*/

static void
rand_hw_addr(unsigned char * addr)
{
    int i;
    srand(time(NULL));

    addr[0] = 0x04;
    addr[1] = 0x09; /* Cratos Networks( and my B day ) */

    for(i = 2 ; i < 6 ; i++) {
        addr[i] = rand() % 256;
    }
}

static void
low_level_init(struct netif *netif)
{
  struct udpif *udpif;
  struct sockaddr_in addr;

  udpif = (struct udpif *)netif->state;

  /* Obtain MAC address from network interface. */

  /* (We just fake an address...), need make random */
  /*
  udpif->ethaddr->addr[0] = 0x1;
  udpif->ethaddr->addr[1] = 0x2;
  udpif->ethaddr->addr[2] = 0x3;
  udpif->ethaddr->addr[3] = 0x4;
  udpif->ethaddr->addr[4] = 0x5;
  udpif->ethaddr->addr[5] = 0x6;
  */
  rand_hw_addr(udpif->ethaddr->addr);
  /* Do whatever else is needed to initialize interface. */

  set_key(udpif->enc_handle, udpif->ethaddr->addr, 6);

  udpif->fd = socket(PF_INET, SOCK_DGRAM, 0);
  LWIP_DEBUGF(UDPIF_DEBUG, ("udpif_init: fd %d\n", udpif->fd));
  if(udpif->fd == -1) {
    perror("udpif_init: cannot open socket");
    exit(1);
  }

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = udpif->local_ip.addr;
  addr.sin_port = udpif->local_port;
  
  if(bind(udpif->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
  {
    perror("udpif_init: bind error");
    exit(1);
  }

  sys_thread_new("udpif_thread", udpif_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
  struct pbuf *q;
  char buf[1514];
  char *bufptr;
  struct udpif *udpif;
  struct sockaddr_in addr;
  struct s_compress_header *sh;
  size_t enc_size = 0;

  udpif = (struct udpif *)netif->state;
#if 0
    if(((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop output\n");
    return ERR_OK;
    }
#endif
  /* initiate transfer(); */

  sh = (struct s_compress_header *)(buf + sizeof(struct eth_hdr));
  bufptr = buf + sizeof(struct s_compress_header) + sizeof(struct eth_hdr);


  for(q = p; q != NULL; q = q->next) {
    /* Send the data from the pbuf to the interface, one pbuf at a
       time. The size of the data in each pbuf is kept in the ->len
       variable. */
    /* send data from(q->payload, q->len); */
    memcpy(bufptr, q->payload, q->len);
    bufptr += q->len;
  }

  if(p->tot_len < sizeof(struct eth_hdr))
    return ERR_OK;

  memcpy(buf, buf + sizeof(struct s_compress_header) + sizeof(struct eth_hdr), sizeof(struct eth_hdr)); /* dup ether header*/

  sh->real_size = p->tot_len;

  if(udpif->peer_ip.addr != INADDR_ANY) {
      bzero(&addr, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = udpif->peer_ip.addr;
      addr.sin_port = udpif->peer_port;

      s_compress(sh);
      
      enc_size = sh->comp_size + sizeof(struct s_compress_header);
      s_encrypt(udpif->enc_handle, (byte_t*)(sh), enc_size);

      if(sendto(udpif->fd, buf, enc_size + sizeof(struct eth_hdr), MSG_NOSIGNAL, 
          (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("udpif: sendto");
      }
  }
  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
low_level_input(struct udpif *udpif)
{
  struct pbuf *p, *q;
  u16_t len;
  char buf[1514];
  char *bufptr;
  struct sockaddr_in cliaddr;
  socklen_t cli_len;
  struct s_compress_header * sh;

  /* Obtain the size of the packet and put it into the "len"
     variable. */
  cli_len = sizeof(cliaddr);
  bzero(&cliaddr, sizeof(cliaddr));
  len = recvfrom(udpif->fd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &cli_len);
  if(len < sizeof(struct eth_hdr)) 
      return NULL;

  s_decrypt(udpif->enc_handle, (byte_t*)(buf + sizeof(struct eth_hdr)), len - sizeof(struct eth_hdr));

  sh = (struct s_compress_header * ) (buf+ sizeof(struct eth_hdr));
  if(s_uncompress(sh) != 0)
      return NULL;

#if 0
    if(((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop\n");
    return NULL;
    }
#endif

  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_RAW, sh->real_size, PBUF_POOL);

  if(p != NULL) {
    /* We iterate over the pbuf chain until we have read the entire
       packet into the pbuf. */
    bufptr = buf + sizeof(struct eth_hdr) + sizeof(struct s_compress_header);
    for(q = p; q != NULL; q = q->next) {
      /* Read enough bytes to fill this pbuf in the chain. The
         available data in the pbuf is given by the q->len
         variable. */
      /* read data into(q->payload, q->len); */
      memcpy(q->payload, bufptr, q->len);
      bufptr += q->len;
    }
    /* acknowledge that packet has been read(); */
  } else {
    /* drop packet(); */
  }

  return p;
}
/*-----------------------------------------------------------------------------------*/
static void
udpif_thread(void *arg)
{
  struct netif *netif;
  struct udpif *udpif;
  fd_set fdset;
  int ret;

  netif = (struct netif *)arg;
  udpif = (struct udpif *)netif->state;

  while(1) {
    FD_ZERO(&fdset);
    FD_SET(udpif->fd, &fdset);

    /* Wait for a packet to arrive. */
    ret = select(udpif->fd + 1, &fdset, NULL, NULL, NULL);

    if(ret == 1) {
      /* Handle incoming packet. */
      udpif_input(netif);
    } else if(ret == -1) {
      perror("udpif_thread: select");
    }
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * udpif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
udpif_input(struct netif *netif)
{
  struct udpif *udpif;
  struct eth_hdr *ethhdr;
  struct pbuf *p;


  udpif = (struct udpif *)netif->state;

  p = low_level_input(udpif);

  if(p == NULL) {
    LWIP_DEBUGF(UDPIF_DEBUG, ("udpif_input: low_level_input returned NULL\n"));
    return;
  }
  ethhdr = (struct eth_hdr *)p->payload;

  switch(htons(ethhdr->type)) {
  /* IP or ARP packet? */
  case ETHTYPE_IP:
  case ETHTYPE_ARP:
#if PPPOE_SUPPORT
  /* PPPoE packet? */
  case ETHTYPE_PPPOEDISC:
  case ETHTYPE_PPPOE:
#endif /* PPPOE_SUPPORT */
    /* full packet send to tcpip_thread to process */
    if (netif->input(p, netif) != ERR_OK) {
      LWIP_DEBUGF(NETIF_DEBUG, ("ethernetif_input: IP input error\n"));
       pbuf_free(p);
       p = NULL;
    }
    break;
  default:
    pbuf_free(p);
    break;
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * udpif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t
udpif_init(struct netif *netif)
{
  struct udpif *udpif;

  if(NULL == netif->state) {
      udpif = (struct udpif *)mem_malloc(sizeof(struct udpif));
      if (!udpif) {
        return ERR_MEM;
      }
      netif->state = udpif;
  }
  udpif = (struct udpif *)netif->state;
  if(udpif->enc_handle) {
    free_enc_handle(udpif->enc_handle);
  }
  udpif->enc_handle = new_enc_handle();
  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
  netif->output = etharp_output;
  netif->linkoutput = low_level_output;
  netif->mtu = 1400;
  /* hardware address length */
  netif->hwaddr_len = 6;

  udpif->ethaddr = (struct eth_addr *)&(netif->hwaddr[0]);
 
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

  low_level_init(netif);

  return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/

void udpif_set_peer(struct netif *netif, ip_addr_t * ip, u16_t port)
{
    if(NULL != netif->state) {
        struct udpif * udpif = (struct udpif *)netif->state;
        memcpy(&udpif->peer_ip, ip, sizeof(udpif->peer_ip));
        udpif->peer_port = port;
    }
}
