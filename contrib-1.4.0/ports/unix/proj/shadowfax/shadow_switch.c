#include <arpa/inet.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "encrypt.h"
#include "compress.h"
#include "list.h"

/* defines */
#define DEB_NET_TUN "/dev/net/tun"
#define DEFAULT_LISTEN_PORT 53
#define CACHE_HASH_SIZE          1024
#define CACHE_TTL_SEC            60
#define DEFAULT_TAP_ADDRESS "192.168.0.1"
#define DEFAULT_TAP_MASK "255.255.255.0"
#define DEFAULT_PID_FILE "/var/run/shadow-switch.pid"

static int sock_fd;
static int tap_fd;
static int run_daemon;
static int is_promiscuous_mode = 0;

struct packet_t
{
    struct ether_header eth;
    char data[];
}__attribute__((packed));
/* data ...*/

struct wrap_packet_t
{
    struct ether_header dup_eth;
    struct s_compress_header sh;
    struct packet_t packet;
}__attribute__((packed));
/* data.. */

#define WRAP_HEADER_SIZE (sizeof(struct ether_header) + sizeof(struct s_compress_header))

struct addr_cache_t
{
    struct list_head link;
    uint8_t eth[ETH_ALEN];
    struct sockaddr_in dst;
    void * enc_handle;
    time_t time_stamp;
};

struct list_head cache_header[CACHE_HASH_SIZE];

static const char * opt_descs[]  = {
    "turn debug on, default off",
    "show help",
    "run as daemon, default off",
    "turn promiscuous mode on, default off",
    "set path of pid file, default /var/run/shadow-cli.pid",
    "set bind ip, default 0.0.0.0",
    "set listen port, default 53",
    "set ip address of tap device, default 192.168.0.1",
    "set netmask of tap device, default 255.255.255.0",
    "set hw address of tap device, default random mac 04:09:xx:xx:xx:xx",
    NULL
};

static struct option longopts[] = {
  /* turn on debugging output (if build with LWIP_DEBUG) */
  {"debug", no_argument,        NULL, 'v'}, 
  /* help */
  {"help", no_argument, NULL, 'h'},
  /* run background ?*/
  {"daemon", no_argument, NULL, 'D'},
  /* promiscuous mode */
  {"promis", no_argument, NULL, 'P'},
  /* run background ?*/
  {"pid-file", no_argument, NULL, 'p'},
  /* bind which ip? */
  {"bind-ip", required_argument, NULL, 'b'},
  /* bind which port? */
  {"listen-port", required_argument, NULL, 'l'},
  /* tap ip address ? */
  {"tap-address", required_argument, NULL, 'i'},
  /* tap net work mask? */
  {"tap-netmask", required_argument, NULL, 'm'},
  {"tap-mac", required_argument, NULL, 'H'},
  {NULL,   0,                 NULL,  0}
};

static void usage(void)
{
  unsigned char i;
  printf("shadow-switch [options]\n");
  printf("options:\n");
  for (i = 0; i < sizeof(longopts)/sizeof(struct option); i++) {
    if(longopts[i].name) {
        printf("     -%c --%s : %s \n",longopts[i].val, longopts[i].name, opt_descs[i]);
    }
  }
}


static int addr_hash(uint8_t * dst_mac)
{
    unsigned long val = dst_mac[0] + dst_mac[1] + dst_mac[2] + dst_mac[3] + dst_mac[4] + dst_mac[5];
    return val % CACHE_HASH_SIZE;
}

static struct addr_cache_t * new_cache_entry(uint8_t * dst_mac, struct sockaddr_in * dst_addr)
{
    struct addr_cache_t * ret = NULL;
    ret = malloc(sizeof(struct addr_cache_t));
    if(NULL != ret) {
        memset(ret, 0, sizeof(struct addr_cache_t));
        memcpy(ret->eth, dst_mac, sizeof(ret->eth));
        memcpy(&ret->dst, dst_addr, sizeof(ret->dst));
        ret->enc_handle = new_enc_handle();
        set_key(ret->enc_handle, ret->eth, sizeof(ret->eth));
        ret->time_stamp = time(NULL);
        INIT_LIST_HEAD(&ret->link);
        SDBG("NEW cache entry %02x:%02x:%02x:%02x:%02x:%02x->%s:%d\n", 
            ret->eth[0], ret->eth[1],ret->eth[2],ret->eth[3],ret->eth[4],ret->eth[5],
            inet_ntoa(ret->dst.sin_addr),
            htons(ret->dst.sin_port)
        );
    }
    return ret;
}

static void free_cache_entry(struct addr_cache_t * entry)
{

    if(NULL != entry) {
        SDBG("DEL cache entry %02x:%02x:%02x:%02x:%02x:%02x->%s:%d\n", 
            entry->eth[0], entry->eth[1],entry->eth[2],entry->eth[3],entry->eth[4],entry->eth[5],
            inet_ntoa(entry->dst.sin_addr),
            htons(entry->dst.sin_port)
         );
        free_enc_handle(entry->enc_handle);
        free(entry);
    }
}

static struct addr_cache_t * lookup_cache(uint8_t * dst_mac)
{
    int i;
    struct list_head *head = NULL;
    struct addr_cache_t *pos = NULL; 

    i = addr_hash(dst_mac);

    head = &cache_header[i];

    list_for_each_entry(pos, head, link) {
        if(!memcmp(dst_mac, pos->eth, sizeof(pos->eth))) {
            SDBG("lookup_cache: %02x:%02x:%02x:%02x:%02x:%02x -> %s:%d\n", 
                pos->eth[0], pos->eth[1],pos->eth[2],pos->eth[3],pos->eth[4],pos->eth[5],
                inet_ntoa(pos->dst.sin_addr),
                htons(pos->dst.sin_port));
            return pos;
        }
    }
    SDBG("lookup_cache: %02x:%02x:%02x:%02x:%02x:%02x failed\n", 
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    return NULL;
}

static struct addr_cache_t * update_cache(uint8_t * dst_mac, struct sockaddr_in * dst_addr)
{
    struct addr_cache_t * ret = NULL;
    int i;

    ret = lookup_cache(dst_mac);
    i = addr_hash(dst_mac);

    if(NULL == ret) {
        ret = new_cache_entry(dst_mac, dst_addr);
        if(NULL != ret) {
            list_add(&cache_header[i], &ret->link);
        }
    } else {
        memcpy(&ret->dst, dst_addr, sizeof(ret->dst));
        ret->time_stamp = time(NULL);
    }

    return ret;
}

static void clear_cache(void)
{
    int i;
    time_t current = time(NULL);
    struct addr_cache_t * pos = NULL, *n = NULL; 
    struct list_head *head = NULL;

    for(i = 0 ; i < CACHE_HASH_SIZE; i ++) {
        head = &cache_header[i];
        list_for_each_entry_safe(pos, n, head, link){
            if(pos->time_stamp + CACHE_TTL_SEC < current) {
                list_del(&pos->link);
                free_cache_entry(pos);
            }
        }
    }
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

static int is_self_mac(uint8_t * mac, uint8_t * self)
{
    return memcmp(self, mac, ETH_ALEN) == 0;
}

static int is_broad_cast_mac(uint8_t * mac)
{
    char mac_str[18]; /* 42:0A:6B:04:8F:B0 */
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return strcmp("FF:FF:FF:FF:FF:FF", mac_str) == 0;
}


static int wrap_packet(struct wrap_packet_t * packet, struct addr_cache_t * cache)
{
    int real_size = 0;
    memcpy(&packet->dup_eth, &packet->packet.eth, sizeof(packet->dup_eth));
    s_compress(&packet->sh);
    real_size = packet->sh.comp_size;
    s_encrypt(cache->enc_handle, (byte_t *)&packet->sh, sizeof(struct s_compress_header) + packet->sh.comp_size);
    return real_size;
}

static int dewrap_packet(struct wrap_packet_t * packet, struct addr_cache_t * cache, size_t len)
{
    if(len < sizeof(struct ether_header) + sizeof(struct s_compress_header)) {
        SERR("invalid packet: len %d too small than %d\n", len, sizeof(struct ether_header) + sizeof(struct s_compress_header));
        return -1;
    }

    s_decrypt(cache->enc_handle, (byte_t *)&packet->sh, len - sizeof(struct ether_header));

    if(packet->sh.comp_size != len - sizeof(struct ether_header) - sizeof(struct s_compress_header)) {
        SERR("invalid packet\n");
        return -1;
    }

    if(s_uncompress(&packet->sh) < 0) {
        SERR("invalid packet\n");
        return -1;
    }

    if(memcmp(&packet->dup_eth, &packet->packet.eth, sizeof(packet->dup_eth))) {
        SERR("invalid packet\n");
        return -1;
    }

    return 0;
}

static int send_raw_packet(struct wrap_packet_t * packet, struct addr_cache_t * cache, int fd)
{
    int ret;
    int size;
    if((size = wrap_packet(packet, cache)) < 0) return -1;
    ret = sendto(fd, packet, size + WRAP_HEADER_SIZE, MSG_NOSIGNAL, (struct sockaddr *)&cache->dst, sizeof(cache->dst));
    return ret;
}

static int broadcast_raw_packet(struct wrap_packet_t * packet,  struct addr_cache_t * exp, int fd)
{
    struct addr_cache_t * pos = NULL;
    struct list_head *head = NULL;
    int i;
    size_t size;
    char buffer[40960];

    size = packet->sh.real_size + WRAP_HEADER_SIZE;
    memcpy(buffer, packet, size);

    for(i = 0 ; i < CACHE_HASH_SIZE ; i ++) {
        head = &cache_header[i];
        list_for_each_entry(pos, head, link) {
            if(pos != exp) {
                if(send_raw_packet(packet, pos, fd) < 0) {
                    return -1;
                }
            }
            memcpy(packet, buffer, size);
        }
    }
    return 0;
}

static struct addr_cache_t * learn_mac(uint8_t * mac, struct sockaddr_in *addr)
{
    return update_cache(mac, addr);
}


static int parse_mac( uint8_t *mac, const char *mac_str )  
{  
    char buffer[18];
    int ret = 0, i;
    unsigned int tmp[6];

    strncpy(buffer, mac_str, sizeof(buffer));
    buffer[17] = 0;

    ret = sscanf(buffer, "%2x:%2x:%2x:%2x:%2x:%2x", 
        (unsigned int *)&tmp[0], 
        (unsigned int *)&tmp[1], 
        (unsigned int *)&tmp[2], 
        (unsigned int *)&tmp[3], 
        (unsigned int *)&tmp[4], 
        (unsigned int *)&tmp[5]);

    for(i = 0 ; i < ETH_ALEN; i ++)
        mac[i] = (uint8_t)tmp[i];

    if(ret == 6) {
        return 0;
    }
    return -1;
}  

static int parse_addr(struct sockaddr_in * addr, const char * addr_str, u_int16_t port)
{
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    if(inet_aton(addr_str, &addr->sin_addr) == 0) {
        return -1;
    }
    return 0;
}

static void
rand_hw_addr(uint8_t * mac, char * mac_str)
{
    int i;
    srand(time(NULL));

    mac[0] = 0x04;
    mac[1] = 0x09; /* Cratos Networks( and my B day ) */

    for(i = 2 ; i < ETH_ALEN ; i++) {
        mac[i] = rand() % 256;
    }

    snprintf(mac_str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int tap_create(char *dev, const struct sockaddr_in * ip_addr, const struct sockaddr_in * netmask, const uint8_t * mac)
{
    int fd = -1, s = -1, i;
    struct ifreq ifr;
    struct sockaddr mac_addr;

    /* create tap device */
    if ((fd = open(DEB_NET_TUN, O_RDWR)) < 0) {
        goto err;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (ioctl(fd, (TUNSETIFF), (void *)&ifr) != 0) {
        SERR("ioctl: %m\n");
        goto err;
    }
    /* save tap device name */
    strcpy(dev, ifr.ifr_name);

    /* create device socket fd */
    if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        SERR("socket: %m\n");
        goto err;
    }
    /* set mac with SIOCSIFHWADDR */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    memset(&mac_addr, 0, sizeof(mac_addr));
    mac_addr.sa_family = ARPHRD_ETHER;
    memcpy(mac_addr.sa_data, mac, 6);
    memcpy(&ifr.ifr_hwaddr, (char *) &mac_addr, sizeof(struct sockaddr));
    
    for( i = 0 ; i < ETH_ALEN; i ++) {
        ifr.ifr_hwaddr.sa_data[i] = mac[i];
    }
    SDBG( "set mac addr %02x:%02x:%02x:%02x:%02x:%02x on interface %s\n",
           mac[0],mac[1], mac[2], mac[3], mac[4], mac[5], ifr.ifr_name);
    if (ioctl(s, SIOCSIFHWADDR, &ifr) != 0) {
        SERR("ioctl: %m\n");
        goto err;
    }

    /* set ip addr with SIOCSIFADDR*/
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    memcpy( (((char *)&ifr + offsetof(struct ifreq, ifr_addr) )),
                        ip_addr, sizeof(struct sockaddr));
    SDBG("set ip address %s on interface %s\n", inet_ntoa(ip_addr->sin_addr), ifr.ifr_name);
    if (ioctl(s, SIOCSIFADDR, &ifr) != 0) {
        SERR("ioctl: %m\n");
        goto err;
    }

    /* set net mask with SIOCSIFNETMASK*/
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    memcpy( (((char *)&ifr + offsetof(struct ifreq, ifr_netmask) )),
                        netmask, sizeof(struct sockaddr));
    SDBG("set net mask %s on interface %s\n", inet_ntoa(netmask->sin_addr), ifr.ifr_name);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) != 0) {
        SERR("ioctl: %m\n");
        goto err;
    }

    /* bring up interface */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    if(ioctl(s, SIOCGIFFLAGS, &ifr) != 0) {
        SERR("ioctl: %m\n");
        goto err;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if(ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
        SERR("ioctl: %m\n");
        goto err;
    }

    close(s);

    return fd;

err:
    if(fd != -1) {
        close(fd);
    }
    if(s != -1) {
        close(s);
    }
    return -1;
}
static int set_non_block(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    flags = fcntl(fd, F_SETFL, flags|O_NONBLOCK);
    if(flags < 0) return -1;
    return 0;
}
int main(int argc, char *argv[])
{
    int ch, ret, i;
    char tap_name[IFNAMSIZ];
    char tap_address_str[16] = DEFAULT_TAP_ADDRESS;
    struct sockaddr_in tap_address;
    char tap_mask_str[16] = DEFAULT_TAP_MASK;
    struct sockaddr_in tap_mask;
    char tap_mac_str[18] = {0};
    uint8_t tap_mac[ETH_ALEN];
    char pid_file[1024] = DEFAULT_PID_FILE;
    struct sockaddr_in udp_address;


    rand_hw_addr(tap_mac, tap_mac_str);
    parse_addr(&tap_address, tap_address_str, 0);
    parse_addr(&tap_mask, tap_mask_str, 0);

    bzero(&udp_address, sizeof(udp_address));
    udp_address.sin_family = AF_INET;
    udp_address.sin_addr.s_addr = htonl(INADDR_ANY);
    udp_address.sin_port = htons(DEFAULT_LISTEN_PORT);

    shadow_quiet = 1;

    for (i = 0 ; i < CACHE_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&cache_header[i]);
    }

    while ((ch = getopt_long(argc, argv, "vhDPb:l:i:m:H:p:", longopts, NULL)) != -1) {
        switch(ch) {
        case 'v':
            shadow_quiet = 0;
            break;
        case 'h':
            usage();
            exit(0);
            break;
        case 'D':
            run_daemon = 1;
            break;
        case 'P':
            is_promiscuous_mode = 1;
            break;
        case 'b':
            if(inet_aton(optarg, &udp_address.sin_addr) != 0) {
                usage();
                exit(1);
            }
            break;
        case 'l':
            udp_address.sin_port = htons(atoi(optarg));
            break;
        case 'i':
            strncpy(tap_address_str, optarg, sizeof(tap_address_str));
            if(parse_addr(&tap_address, tap_address_str, 0) != 0) {
                SERR("invalid ip address %s\n", tap_address_str);
                exit(1);
            }
            break;
        case 'm':
            strncpy(tap_mask_str, optarg, sizeof(tap_mask_str));
            if(parse_addr(&tap_mask, tap_mask_str, 0) != 0) {
                SERR("invalid mask %s\n", tap_mask_str);
                exit(1);
            }
            break;
        case 'H':
            strncpy(tap_mac_str, optarg, sizeof(tap_mac_str));
            if(parse_mac(tap_mac, tap_mac_str) != 0) {
                SERR("invalid mac %s\n", tap_mac_str);
                exit(1);
            }
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

    tap_name[0] = '\0';
    tap_fd = tap_create(tap_name, &tap_address, &tap_mask, tap_mac);
    if(tap_fd < 0) {
        SERR("tap_create: cannot open tap %m\n");
        exit(1);
    }
    SINF("TUN name is %s\n", tap_name);

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock_fd == -1) {
        SERR("socket: cannot open socket %m\n");
        exit(1);
    }

    if(set_non_block(sock_fd) < 0) {
        SERR("socket: cannot set non-block socket: %m\n");
        exit(1);
    }

    if(bind(sock_fd, (struct sockaddr *)&udp_address, sizeof(udp_address)) == -1) {
        SERR("bind: bind error: %m\n");
        exit(1);
    }

    while(1) {
        struct addr_cache_t * cache_src, * cache_dst;
        char buffer[40960];
        struct wrap_packet_t * p_packet = (struct wrap_packet_t *) buffer;
        struct sockaddr_in tmp_addr;
        socklen_t tmp_len;
        struct timeval timeo;
        fd_set r_fdset;

        bzero(&tmp_addr, sizeof(tmp_addr));
        tmp_len = sizeof(tmp_addr);

        FD_ZERO(&r_fdset);

        FD_SET(tap_fd, &r_fdset); 
        FD_SET(sock_fd, &r_fdset); 
        ret = tap_fd > sock_fd ? (tap_fd + 1) : (sock_fd + 1);
        timeo.tv_sec = 0;
        timeo.tv_usec = 10 * 1000; /* 10 ms */
        ret = select(ret, &r_fdset, NULL, NULL, &timeo);
        if(ret > 0) {
          if(FD_ISSET(tap_fd, &r_fdset)) {
            /* read raw packet from tap and write to socket */
            /* packet come from switch self , should send to all other host */
            ret = read(tap_fd, &p_packet->packet, sizeof(buffer) - WRAP_HEADER_SIZE);
            SDBG("read tap fd %d\n", ret);
            if(ret < 0) {
                SERR("read: %m\n");
                break;
            }

            p_packet->sh.real_size = ret;

            cache_dst = lookup_cache(p_packet->packet.eth.ether_dhost);

            if(is_broad_cast_mac(p_packet->packet.eth.ether_dhost)) {
                SDBG("broadcast packet from tap to socket: is_broad_cast_mac\n");
                broadcast_raw_packet(p_packet, NULL, sock_fd);
            } else if(NULL == cache_dst) {
                SDBG("broadcast packet from tap to socket: can not find dst\n");
                broadcast_raw_packet(p_packet, NULL, sock_fd);
            } else {
                SDBG("send packet from tap to socket: found dst\n");
                send_raw_packet(p_packet, cache_dst, sock_fd);
            }
          }
          
          if(FD_ISSET(sock_fd, &r_fdset)) {
            /* read wrap packet from socket and write to tap or socket */
            /* packet come from other host, some should send to tap, some should send to other host */
            ret = recvfrom(sock_fd, p_packet, sizeof(buffer), 0, (struct sockaddr *)&tmp_addr, &tmp_len);
            SDBG("read socket fd %d\n", ret);
            if(ret < 0) {
                SERR("recvfrom: %m\n");
                break;
            }

            
            cache_src = learn_mac(p_packet->dup_eth.ether_shost, &tmp_addr);

            if(NULL == cache_src) {
                SERR("oom\n");
                break;
            }

            /* dewrap packet to raw */
            if( dewrap_packet(p_packet, cache_src, ret) < 0) {
                SERR("invalid packet\n");
                continue;
            }
        
            if(is_self_mac(p_packet->dup_eth.ether_dhost, tap_mac) || /* write to tap0 ? */
                is_broad_cast_mac(p_packet->dup_eth.ether_dhost) || 
                is_promiscuous_mode) { /* send to tap */
                SDBG("write packet from socket to tap\n", ret);
                ret = write(tap_fd, &p_packet->packet, p_packet->sh.real_size);
                if(ret < 0) {
                    SERR("write: %m\n");
                    break;
                }
            }

            if(!is_self_mac(p_packet->dup_eth.ether_dhost, tap_mac)) { /* switch between udp socks ? */
                cache_dst = lookup_cache(p_packet->dup_eth.ether_dhost);
                if(is_broad_cast_mac(p_packet->packet.eth.ether_dhost)) {
                    SDBG("broadcast packet from socket to socket: is_broad_cast_mac\n");
                    broadcast_raw_packet(p_packet, cache_src, sock_fd);
                } else if(NULL == cache_dst) {
                    SDBG("broadcast packet from socket to socket: can not find dst\n");
                    broadcast_raw_packet(p_packet, cache_src, sock_fd);
                } else {
                    SDBG("send packet from tap to socket: found dst\n");
                    send_raw_packet(p_packet, cache_dst, sock_fd);
                }
            }
          }
        } else if(ret == -1) {
          SERR("select: %m\n");
          exit(1);
        } else {
          clear_cache();
        }
    }

    return 0;
}
