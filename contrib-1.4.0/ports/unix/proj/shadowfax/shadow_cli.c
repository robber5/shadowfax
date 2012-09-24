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
#include <getopt.h>
#include <net/ethernet.h>
#include <string.h>

#include "log.h"
#include "encrypt.h"
#include "compress.h"

static struct ifreq ifr;
static struct sockaddr_in local_addr;
static int sock_fd;
static int tun_fd;
static int debug_on;

static int set_non_block(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    flags = fcntl(fd, F_SETFL, flags|O_NONBLOCK);
    if(flags < 0) return -1;
    return 0;
}

static int tun_create(char *dev, int flags)
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

    err = ioctl(fd, (TUNSETIFF), (void *)&ifr); 
    if (err < 0)
    {
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}


/** @todo add options for selecting netif, starting DHCP client etc */
static struct option longopts[] = {
  /* turn on debugging output (if build with LWIP_DEBUG) */
  {"debug", no_argument,        NULL, 'D'}, 
  /* help */
  {"help", no_argument, NULL, 'h'},
  /* bind which ip? */
  {"bind-ip", required_argument, NULL, 'b'},
  /* bind which port? */
  {"listen-port", required_argument, NULL, 'l'},
  {NULL,   0,                 NULL,  0}
};

static void usage(void)
{
  unsigned char i;
  printf("shadow_cli [options]\n");
  printf("options:\n");
  for (i = 0; i < sizeof(longopts)/sizeof(struct option); i++) {
    printf("-%c --%s\n",longopts[i].val, longopts[i].name);
  }
}

#define DEFAULT_LISTEN_PORT 53
#define CACHE_SIZE          1024

struct addr_cache
{
    struct addr_cache * next;
    u_int8_t eth[ETH_ALEN];
    struct sockaddr_in dst;
    void * enc_handle;
};

struct addr_cache * cache_header[CACHE_SIZE];

static struct addr_cache * lookup_cache_internal(u_int8_t *addr)
{
    unsigned long * val = NULL;
    int i;
    static struct addr_cache * head;

    val = (unsigned long*)addr;
    i = (*val) % CACHE_SIZE;

    if(cache_header[i] == NULL) {
        return NULL;
    } else {
        head = cache_header[i];
        while(head) {
            if(!memcmp(addr, head->eth, sizeof(head->eth))) {
                return head;
            }
            head = head->next;
        }
    }
    return NULL;
}

static int lookup_cache(char * buffer, int len, struct sockaddr_in * addr_dst, void ** handle)
{
    struct ether_header *eh;
    u_int8_t * addr = NULL;
    struct addr_cache * ca = NULL;
    
    if(len < (int)sizeof(struct ether_header)) return -1;

    /* read buffer to get dst ip */
    eh = (struct ether_header *)buffer;

    addr = eh->ether_dhost;

    ca = lookup_cache_internal(addr);
    if(!ca) {
        SWAN("lookup %02x.%02x.%02x.%02x.%02x.%02x fail\n", 
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        *handle = NULL;
        return -1;
    }

    memcpy(addr_dst, &ca->dst, sizeof(struct sockaddr_in));
    SDBG("lookup %02x.%02x.%02x.%02x.%02x.%02x -> %s:%d\n", 
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], inet_ntoa(addr_dst->sin_addr), htons(addr_dst->sin_port));
    *handle = ca->enc_handle;
    return 0;
}

static void update_cache(const char * buffer, int len, const struct sockaddr_in * addr_src, void ** handle)
{
    struct ether_header *eh;
     u_int8_t * addr = NULL;
    struct addr_cache * ca = NULL;
    int i = 0;
    unsigned long * val = NULL;
    
    if(len < (int)sizeof(struct ether_header)) return;


    /* read buffer to get dst ip */
    eh = (struct ether_header *)buffer;

    addr = eh->ether_shost;
    ca = lookup_cache_internal(addr);
    if(ca) {
        memcpy(&ca->dst, addr_src, sizeof(struct sockaddr_in));
        SDBG("update %02x.%02x.%02x.%02x.%02x.%02x -> %s:%d\n", 
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], inet_ntoa(addr_src->sin_addr), htons(addr_src->sin_port));

    } else {
        ca = malloc(sizeof(struct addr_cache));
        memset(ca, 0, sizeof(struct addr_cache));
        memcpy(&ca->dst, addr_src, sizeof(struct sockaddr_in));
        memcpy(ca->eth, eh->ether_shost, sizeof(eh->ether_shost));
        ca->enc_handle = new_enc_handle();
        set_key(ca->enc_handle, eh->ether_shost, sizeof(eh->ether_shost));
        val = (unsigned long*)addr;
        i = (*val) % CACHE_SIZE;
        SDBG("insert %02x.%02x.%02x.%02x.%02x.%02x -> %s:%d\n", 
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], inet_ntoa(addr_src->sin_addr), htons(addr_src->sin_port));
        ca->next = cache_header[i];
        cache_header[i] = ca;
    }
    *handle = ca->enc_handle;
}

int main(int argc, char *argv[])
{
    int ch, ret;
    char tun_name[IFNAMSIZ];


    bzero(&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(DEFAULT_LISTEN_PORT);

    shadow_quiet = 1;

    while ((ch = getopt_long(argc, argv, "D:h:b:l:", longopts, NULL)) != -1) {
        switch(ch) {
        case 'D':
            debug_on = 1;
            break;
        case 'h':
            usage();
            exit(0);
            break;
        case 'b':
            if(inet_aton(optarg, &local_addr.sin_addr) != 0) {
                usage();
                exit(1);
            }
            break;
        case 'l':
            local_addr.sin_port = htons(atoi(optarg));
            break;
        default:
            usage();
            exit(1);
            break;
        }
    }


    tun_name[0] = '\0';
    tun_fd = tun_create(tun_name, IFF_TAP | IFF_NO_PI);
    if(tun_fd < 0) {
        perror("tun_create: cannot open tun");
        exit(1);
    }
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

    if(bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1)
    {
        perror("bind: bind error");
        exit(1);
    }
    while(1) {
        struct sockaddr_in tmp_addr;
        socklen_t tmp_len;
        int in_len, out_len;
        char buffer[4096];
        fd_set r_fdset, w_fdset;
        void * handle;
        struct s_compress_header * sh;
        int enc_size;


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
            ret = read(tun_fd, buffer + sizeof(struct ether_header) + sizeof(struct s_compress_header), 
                sizeof(buffer));
            if(ret < 0) break;
            in_len = ret;
            ret = lookup_cache( buffer + sizeof(struct ether_header) + sizeof(struct s_compress_header), in_len, &tmp_addr, &handle); 
            if(ret == 0)
            {
                sh = (struct s_compress_header *)(buffer + sizeof(struct ether_header));
                sh->real_size = in_len;
                s_compress(sh);
                enc_size = sh->comp_size + sizeof(struct s_compress_header);
                memcpy(buffer, buffer + sizeof(struct ether_header) + sizeof(struct s_compress_header), sizeof(struct ether_header));
                encrypt(handle, (byte_t *)(sh), enc_size);
                ret = sendto(sock_fd, buffer, enc_size + sizeof(struct ether_header),
                    MSG_NOSIGNAL, (struct sockaddr *)&tmp_addr, sizeof(tmp_addr));
                if(ret < 0) break;
            } else {
                /* send to all */
                static struct addr_cache * head;
                int i;
                for(i = 0 ; i < CACHE_SIZE ; i ++) {
                    head = cache_header[i];
                    while(head) {
                        memcpy(&tmp_addr, &head->dst, sizeof(head->dst));
                        sh = (struct s_compress_header *)(buffer + sizeof(struct ether_header));
                        sh->real_size = in_len;
                        s_compress(sh);
                        memcpy(buffer, buffer + sizeof(struct ether_header) + sizeof(struct s_compress_header), sizeof(struct ether_header));
                        encrypt(head->enc_handle, (byte_t *)(sh), sh->comp_size + sizeof(struct s_compress_header));
                        ret = sendto(sock_fd, buffer, sh->comp_size + sizeof(struct s_compress_header) + sizeof(struct ether_header), 
                            MSG_NOSIGNAL, (struct sockaddr *)&tmp_addr, sizeof(tmp_addr));
                        if(ret < 0) break;
                        head = head->next;
                    }
                }

            }
            out_len = ret;
          } else if(FD_ISSET(tun_fd, &w_fdset) && FD_ISSET(sock_fd, &r_fdset)) {
            /* read packet from socket and write to tun */
            ret = recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&tmp_addr, &tmp_len);
            if(ret < 0) break;
            in_len = ret;
            update_cache(buffer, in_len, &tmp_addr, &handle);
            decrypt(handle, (byte_t *)(buffer + sizeof(struct ether_header)), (size_t)in_len - sizeof(struct ether_header));
            sh = (struct s_compress_header * )(buffer + sizeof(struct ether_header));
            if(s_uncompress(sh) != 0) {
                SDBG("uncompress error\n");
                continue;
            }
            ret = write(tun_fd, buffer + sizeof(struct ether_header) + sizeof(struct s_compress_header), sh->real_size);
            if(ret < 0) break;
            out_len = ret;
          }
        } else if(ret == -1) {
          perror("select");
          exit(1);
        }
    }

    return 0;
}
