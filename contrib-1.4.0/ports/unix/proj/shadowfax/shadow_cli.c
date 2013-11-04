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
static int run_daemon;

/*
static int set_non_block(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    flags = fcntl(fd, F_SETFL, flags|O_NONBLOCK);
    if(flags < 0) return -1;
    return 0;
}
*/

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

static const char * opt_descs[]  = {
    "turn debug on, default off",
    "show help",
    "run as daemon, default off",
    "set path of pid file, default /var/run/shadow-cli.pid"
    "set bind ip, default 0.0.0.0",
    "set listen port, default 53",
    "set gw address of tap device, default 192.168.0.1",
    "set gw netmask of tap device, default 255.255.255.0",
    NULL
};
   
/** @todo add options for selecting netif, starting DHCP client etc */
static struct option longopts[] = {
  /* turn on debugging output (if build with LWIP_DEBUG) */
  {"debug", no_argument,        NULL, 'D'}, 
  /* help */
  {"help", no_argument, NULL, 'h'},
  /* run background ?*/
  {"daemon", no_argument, NULL, 'd'},
  /* run background ?*/
  {"pid-file", no_argument, NULL, 'p'},
  /* bind which ip? */
  {"bind-ip", required_argument, NULL, 'b'},
  /* bind which port? */
  {"listen-port", required_argument, NULL, 'l'},
  /* bind which port? */
  {"tap-address", required_argument, NULL, 'i'},
  {"tap-gw-mask", required_argument, NULL, 'g'},
  {NULL,   0,                 NULL,  0}
};

static void usage(void)
{
  unsigned char i;
  printf("shadow_cli [options]\n");
  printf("options:\n");
  for (i = 0; i < sizeof(longopts)/sizeof(struct option); i++) {
    if(longopts[i].name) {
        printf("-%c --%s : %s \n",longopts[i].val, longopts[i].name, opt_descs[i]);
    }
  }
}

#define DEFAULT_LISTEN_PORT 53
#define CACHE_SIZE          1024
#define DEFAULT_TAP_ADDRESS "192.168.0.1"
#define DEFAULT_TAP_GW_MASK "255.255.255.0"
#define DEFAULT_PID_FILE "/var/run/shadow-cli.pid"

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

static void touch_pid(const char * pid_file_name)
{
    FILE * pid_f = NULL;

    if((pid_f = fopen(pid_file_name, "wb")) != NULL) {
        fprintf(pid_f, "%d", getpid());
        fclose(pid_f);
        pid_f = NULL;
    }
}

int main(int argc, char *argv[])
{
    int ch, ret;
    char tun_name[IFNAMSIZ];
    char cmd[4096];
    char tap_address[256] = DEFAULT_TAP_ADDRESS;
    char tap_gw_mask[256] = DEFAULT_TAP_GW_MASK;
    char pid_file[1024] = DEFAULT_PID_FILE;

    bzero(&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(DEFAULT_LISTEN_PORT);

    shadow_quiet = 1;

    while ((ch = getopt_long(argc, argv, "Dhdb:l:i:g:", longopts, NULL)) != -1) {
        switch(ch) {
        case 'd':
            run_daemon = 1;
            break;
        case 'D':
            shadow_quiet = 0;
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
        case 'i':
            strncpy(tap_address, optarg, sizeof(tap_address));
            break;
        case 'g':
            strncpy(tap_gw_mask, optarg, sizeof(tap_gw_mask));
            break;
        case 'p':
            strncpy(pid_file, optarg, sizeof(pid_file));
            break;
        default:
            usage();
            exit(1);
            break;
        }
    }

    if(run_daemon) {
        daemon(0,0);
    }

    touch_pid(pid_file);

    tun_name[0] = '\0';
    tun_fd = tun_create(tun_name, IFF_TAP | IFF_NO_PI);
    if(tun_fd < 0) {
        SERR("tun_create: cannot open tun %m\n");
        exit(1);
    }
    SINF("TUN name is %s\n", tun_name);

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock_fd == -1) {
        SERR("socket: cannot open socket %m\n");
        exit(1);
    }

/*    if(set_non_block(sock_fd) < 0) {
        SERR("socket: cannot set non-block socket: %m\n");
        exit(1);
    }*/

    if(bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1) {
        SERR("bind: bind error: %m\n");
        exit(1);
    }

    snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask %s up", tun_name, tap_address, tap_gw_mask);
    system(cmd);

    while(1) {
        struct sockaddr_in tmp_addr;
        socklen_t tmp_len;
        int in_len, out_len;
        char buffer[4096];
        fd_set r_fdset;
        void * handle;
        struct s_compress_header * sh;
        int enc_size;
        struct timeval timeo;


        bzero(&tmp_addr, sizeof(tmp_addr));
        tmp_len = sizeof(tmp_addr);

        FD_ZERO(&r_fdset);

        FD_SET(tun_fd, &r_fdset); 
        FD_SET(sock_fd, &r_fdset); 
        ret = tun_fd > sock_fd ? (tun_fd + 1) : (sock_fd + 1);
        timeo.tv_sec = 0;
        timeo.tv_usec = 100*1000; /* 100 ms */
        ret = select(ret, &r_fdset, NULL, NULL, &timeo);
        if(ret > 0) {
          if(FD_ISSET(tun_fd, &r_fdset)) {
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
          } else if(FD_ISSET(sock_fd, &r_fdset)) {
            /* read packet from socket and write to tun */
            ret = recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&tmp_addr, &tmp_len);
            if(ret < 0) break;
            in_len = ret;
            update_cache(buffer, in_len, &tmp_addr, &handle);
            decrypt(handle, (byte_t *)(buffer + sizeof(struct ether_header)), (size_t)in_len - sizeof(struct ether_header));
            sh = (struct s_compress_header * )(buffer + sizeof(struct ether_header));
            if(s_uncompress(sh) != 0) {
                continue;
            }
            ret = write(tun_fd, buffer + sizeof(struct ether_header) + sizeof(struct s_compress_header), sh->real_size);
            if(ret < 0) break;
            out_len = ret;
          }
        } else if(ret == -1) {
          SERR("select: %m\n");
          exit(1);
        } else {
          SDBG("no data to process, sleep\n");
        }
    }

    return 0;
}
