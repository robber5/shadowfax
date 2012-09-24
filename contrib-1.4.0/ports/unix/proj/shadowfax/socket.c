#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "socket.h"
#include "log.h"

int connect_to(const char * host, unsigned short port)
{
    int fd;
    struct hostent * ent = NULL;
    struct sockaddr_in addr;

    ent = gethostbyname(host);
    if(ent == NULL) 
        return -1;

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (*( struct in_addr*)(( ent->h_addr_list[0]))).s_addr;
    addr.sin_port = htons(port);

    if(connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    SDBG("connect to host %s:%d on fd %d\n", inet_ntoa(*( struct in_addr*)( ent->h_addr_list[0])), port, fd);
    
    return fd;
}

