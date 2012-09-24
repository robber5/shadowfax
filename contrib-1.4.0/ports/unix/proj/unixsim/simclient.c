#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>

struct ifreq ifr;


int set_non_block(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    flags = fcntl(fd, F_SETFL, flags|O_NONBLOCK);
    if(flags < 0) return -1;
    return 0;
}

int tun_create(char *dev, int flags)
{
    int fd;
    int err;

    assert(dev != NULL);

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        return fd;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags |= flags;
    if (*dev != '\0')
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    //if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) 
    err = ioctl(fd, (TUNSETIFF), (void *)&ifr); 
    if (err < 0)
    {
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

struct sockaddr_in cli_addr;
struct sockaddr_in srv_addr;
int sock_fd;
int tun_fd;

int main(int argc, char ** argv)
{
    fd_set r_fdset, w_fdset;
    int ret;
    char tun_name[IFNAMSIZ];
    char buffer[4096];

    bzero(&cli_addr, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    cli_addr.sin_port = htons(53);

    bzero(&srv_addr, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = inet_addr("10.26.138.41");
    srv_addr.sin_port = htons(53);
    
    tun_name[0] = '\0';
    tun_fd = tun_create(tun_name, IFF_TAP | IFF_NO_PI);
    printf("TUN name is %s\n", tun_name);

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock_fd == -1) {
        perror("socket: cannot open socket");
        exit(1);
    }

    if(set_non_block(sock_fd) < 0) {
        perror("socket: cannot set non-block socket");
        exit(1);
    }

    if(bind(sock_fd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) == -1)
    {
        perror("bind: bind error");
        exit(1);
    }

    while(1) {
        struct sockaddr_in tmp_addr;
        socklen_t tmp_len;
        int in_len, out_len;

        bzero(&tmp_addr, sizeof(tmp_addr));
        tmp_len = sizeof(tmp_addr);

        FD_ZERO(&r_fdset);FD_ZERO(&w_fdset);

        FD_SET(tun_fd, &r_fdset);FD_SET(tun_fd, &w_fdset);
        FD_SET(sock_fd, &r_fdset);FD_SET(sock_fd, &w_fdset);
        ret = tun_fd > sock_fd ? (tun_fd + 1) : (sock_fd + 1);
        ret = select(ret, &r_fdset, &w_fdset, NULL, NULL);
        if(ret > 0) {
          if(FD_ISSET(tun_fd, &r_fdset) && FD_ISSET(sock_fd, &w_fdset)) {
              /* read packet from tun and write to socket */
            ret = read(tun_fd, buffer, sizeof(buffer));
            if(ret < 0) break;
            in_len = ret;
            ret = sendto(sock_fd, buffer, ret, MSG_NOSIGNAL, 
                (struct sockaddr *)&srv_addr, sizeof(srv_addr));
            if(ret < 0) break;
            out_len = ret;
            printf("tun->net: %d %d\n", in_len, out_len);
          } else if(FD_ISSET(tun_fd, &w_fdset) && FD_ISSET(sock_fd, &r_fdset)) {
              /* read packet from socket and write to tun */
            ret = recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&tmp_addr, &tmp_len);
            if(ret < 0) break;
            in_len = ret;
            ret = write(tun_fd, buffer, ret);
            if(ret < 0) break;
            out_len = ret;
            printf("net->tun: %d %d\n", in_len, out_len);
          }
        } else if(ret == -1) {
          perror("select");
        }
    }
}

