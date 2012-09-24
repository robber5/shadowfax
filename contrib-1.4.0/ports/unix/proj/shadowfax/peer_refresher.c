#include "peer_refresher.h"
#include "netif/udpif.h"
#include "log.h"

#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
       
#define PEER_REFRESH_INTVL_US 30000000 /* 30 sec */

void peer_refresh(struct netif *netif, const char * peer_host, u16_t peer_port)
{
    struct hostent * ent = NULL;
    ip_addr_t peer_ip;

    (void)peer_host;
    (void)ent;

    while(1) {
        ent = gethostbyname(peer_host);
        if(NULL != ent) {

            SDBG("set peer host %s:%d\n", inet_ntoa(*( struct in_addr*)( ent->h_addr_list[0])), htons(peer_port));   
            peer_ip.addr = (*( struct in_addr*)(( ent->h_addr_list[0]))).s_addr;
            udpif_set_peer(netif, &peer_ip, peer_port);
        }
        usleep(PEER_REFRESH_INTVL_US);
    }
}
