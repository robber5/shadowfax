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
#include <time.h>
#include <stdint.h>

#include "log.h"
#include "encrypt.h"
#include "compress.h"

static struct ifreq ifr;
static struct sockaddr_in local_addr;
static int sock_fd;
static int tun_fd;
static int run_daemon;
static int is_promiscuous_mode = 1;
static FILE * dump_file;

typedef struct _pcap_file_header {
	uint8_t magic[4] ; // D4C3B2A1
	uint16_t version_major; 
	uint16_t version_minor; 
	uint32_t thiszone; 
	uint32_t sigfigs;    
	uint32_t snaplen;    
	uint32_t linktype;   
}pcap_file_header_t;

typedef struct _pcap_pkthdr {
	struct timeval ts;  
	uint32_t caplen; 
	uint32_t len;    
}pcap_pkthdr_t;



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
    "set path of pid file, default /var/run/shadow-cli.pid",
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
#define CACHE_HASH_SIZE          1024
#define DEFAULT_TAP_ADDRESS "192.168.0.1"
#define DEFAULT_TAP_GW_MASK "255.255.255.0"
#define DEFAULT_PID_FILE "/var/run/shadow-cli.pid"

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
    struct addr_cache_t * next;
    u_int8_t eth[ETH_ALEN];
    struct sockaddr_in dst;
    void * enc_handle;
};

struct addr_cache_t * cache_header[CACHE_HASH_SIZE];

static int addr_hash(u_int8_t * dst_mac)
{
    unsigned long val = dst_mac[0] + dst_mac[1] + dst_mac[2] + dst_mac[3] + dst_mac[4] + dst_mac[5];
    return val % CACHE_HASH_SIZE;
}

static struct addr_cache_t * lookup_cache(u_int8_t * dst_mac)
{
    int i;
    static struct addr_cache_t * head;

    i = addr_hash(dst_mac);

    if(cache_header[i] == NULL) {
        return NULL;
    } else {
        head = cache_header[i];
        while(head) {
            if(!memcmp(dst_mac, head->eth, sizeof(head->eth))) {
                return head;
            }
            head = head->next;
        }
    }
    return NULL;
}

static struct addr_cache_t * update_cache(u_int8_t * dst_mac, struct sockaddr_in * dst_addr)
{
    struct addr_cache_t * ret = NULL;
    int i;


    ret = lookup_cache(dst_mac);
    if(NULL == ret) {
        i = addr_hash(dst_mac);
        ret = malloc(sizeof(struct addr_cache_t));
        if(NULL != ret) {
            ret->next = cache_header[i];
            cache_header[i] = ret;
            memcpy(ret->eth, dst_mac, sizeof(ret->eth));
            memcpy(&ret->dst, dst_addr, sizeof(ret->dst));
            ret->enc_handle = new_enc_handle();
            set_key(ret->enc_handle, ret->eth, sizeof(ret->eth));
        }
    } else {
         memcpy(&ret->dst, dst_addr, sizeof(ret->dst));
    }

    return ret;
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

static int is_self_mac(u_int8_t * mac, char * self)
{
    char mac_str[18]; /* 42:0A:6B:04:8F:B0 */
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return strcmp(self, mac_str) == 0;
}

static int is_broad_cast_mac(u_int8_t * mac)
{
    char mac_str[18]; /* 42:0A:6B:04:8F:B0 */
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return strcmp("FF:FF:FF:FF:FF:FF", mac_str) == 0;
}


static int wrap_packet(struct wrap_packet_t * packet, struct addr_cache_t * cache)
{
    memcpy(&packet->dup_eth, &packet->packet.eth, sizeof(packet->dup_eth));
    s_compress(&packet->sh);
    encrypt(cache->enc_handle, (byte_t *)&packet->sh, sizeof(struct s_compress_header) + packet->sh.comp_size);
    return 0;
}

static int dewrap_packet(struct wrap_packet_t * packet, struct addr_cache_t * cache, size_t len)
{
    if(len < sizeof(struct ether_header) + sizeof(struct s_compress_header)) {
        printf("invalid packet: len %d too small than %d\n", len, sizeof(struct ether_header) + sizeof(struct s_compress_header));
        return -1;
    }

    decrypt(cache->enc_handle, (byte_t *)&packet->sh, len - sizeof(struct ether_header));

    if(packet->sh.comp_size != len - sizeof(struct ether_header) - sizeof(struct s_compress_header)) {
        printf("invalid packet\n");
        return -1;
    }

    if(s_uncompress(&packet->sh) < 0) {
        printf("invalid packet\n");
        return -1;
    }

    if(memcmp(&packet->dup_eth, &packet->packet.eth, sizeof(packet->dup_eth))) {
        printf("invalid packet\n");
        return -1;
    }

    return 0;
}

static int send_raw_packet(struct wrap_packet_t * packet, struct addr_cache_t * cache, int fd)
{
    if(wrap_packet(packet, cache) < 0) return -1;
    return sendto(fd, packet, packet->sh.comp_size + WRAP_HEADER_SIZE, MSG_NOSIGNAL, (struct sockaddr *)&cache->dst, sizeof(cache->dst));
}

static int broadcast_raw_packet(struct wrap_packet_t * packet, int fd)
{
    struct addr_cache_t * p;
    int i;
    size_t size;
    char buffer[40960];

    size = packet->sh.real_size + WRAP_HEADER_SIZE;
    memcpy(buffer, packet, size);

    for(i = 0 ; i < CACHE_HASH_SIZE ; i ++) {
        p = cache_header[i];
        while(p) {
            if(send_raw_packet(packet, p, fd) < 0) {
                return -1;
            }
            memcpy(packet, buffer, size);
            p = p->next;
        }
    }
    return 0;
}

static struct addr_cache_t * learn_mac(u_int8_t * mac, struct sockaddr_in *addr)
{
    return update_cache(mac, addr);
}

static void
rand_hw_addr(char * mac_str)
{
    int i;
    srand(time(NULL));
    unsigned char addr[6];

    addr[0] = 0x04;
    addr[1] = 0x09; /* Cratos Networks( and my B day ) */

    for(i = 2 ; i < 6 ; i++) {
        addr[i] = rand() % 256;
    }

    snprintf(mac_str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

    SDBG("self mac %s\n", mac_str);
}

static void dump_packet(struct wrap_packet_t * packet)
{
    pcap_pkthdr_t header;

    gettimeofday(&header.ts, NULL);
    header.caplen = header.len = packet->sh.real_size;

    fwrite(&header, sizeof(header), 1, dump_file);
    fwrite(&packet->packet, packet->sh.real_size, 1, dump_file);
    fflush(dump_file);
}

int main(int argc, char *argv[])
{
    int ch, ret;
    char tun_name[IFNAMSIZ];
    char cmd[4096];
    char tap_address[16] = DEFAULT_TAP_ADDRESS;
    char tap_gw_mask[16] = DEFAULT_TAP_GW_MASK;
    char tap_mac[18] = {0};
    char pid_file[1024] = DEFAULT_PID_FILE;
    pcap_file_header_t dump_header;

    rand_hw_addr(tap_mac);

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
        printf("tun_create: cannot open tun %m\n");
        exit(1);
    }
    SINF("TUN name is %s\n", tun_name);

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock_fd == -1) {
        printf("socket: cannot open socket %m\n");
        exit(1);
    }

/*    if(set_non_block(sock_fd) < 0) {
        printf("socket: cannot set non-block socket: %m\n");
        exit(1);
    }*/

    if(bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1) {
        printf("bind: bind error: %m\n");
        exit(1);
    }


    snprintf(cmd, sizeof(cmd), "ifconfig %s hw ether %s", tun_name, tap_mac);
    SINF("run cmd %s\n", cmd);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask %s up", tun_name, tap_address, tap_gw_mask);
    SINF("run cmd %s\n", cmd);
    system(cmd);

    dump_file = fopen("/tmp/dmp", "wb");
    dump_header.magic[0] = 0xd4;
    dump_header.magic[1] = 0xc3;
    dump_header.magic[2] = 0xb2;
    dump_header.magic[3] = 0xa1;
    dump_header.version_major = 2;
    dump_header.version_minor = 4;
    dump_header.thiszone = 0;
    dump_header.snaplen = -1;
    dump_header.linktype = 1;

    fwrite(&dump_header, sizeof(dump_header), 1, dump_file);

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

        FD_SET(tun_fd, &r_fdset); 
        FD_SET(sock_fd, &r_fdset); 
        ret = tun_fd > sock_fd ? (tun_fd + 1) : (sock_fd + 1);
        timeo.tv_sec = 0;
        timeo.tv_usec = 100*1000; /* 100 ms */
        ret = select(ret, &r_fdset, NULL, NULL, &timeo);
        if(ret > 0) {
          if(FD_ISSET(tun_fd, &r_fdset)) {
            /* read raw packet from tun and write to socket */
            /* packet come from switch self , should send to all other host */
            ret = read(tun_fd, &p_packet->packet, sizeof(buffer) - WRAP_HEADER_SIZE);
            SDBG("read tun: %d\n", ret);
            if(ret < 0) {
                printf("read: %m\n");
                break;
            }

            p_packet->sh.real_size = ret;
            SDBG("p_packet->sh.real_size: %d\n", p_packet->sh.real_size);

            dump_packet(p_packet);

            if(is_broad_cast_mac(p_packet->packet.eth.ether_dhost) || 
                (cache_dst = lookup_cache(p_packet->packet.eth.ether_dhost)) == NULL){
                broadcast_raw_packet(p_packet, sock_fd);
            } else {
                send_raw_packet(p_packet, cache_dst, sock_fd);
            }

          } else if(FD_ISSET(sock_fd, &r_fdset)) {
            /* read wrap packet from socket and write to tun or socket */
            /* packet come from other host, some should send to tun, some should send to other host */
            ret = recvfrom(sock_fd, p_packet, sizeof(buffer), 0, (struct sockaddr *)&tmp_addr, &tmp_len);
            SDBG("read sock: %d\n", ret);
            if(ret < 0) {
                printf("recvfrom: %m\n");
                break;
            }

            cache_src = learn_mac(p_packet->dup_eth.ether_shost, &tmp_addr);
            if(NULL == cache_src) {
                break;
            }

            /* dewrap packet to raw */
            if( dewrap_packet(p_packet, cache_src, ret) < 0) {
                break;
            }

             dump_packet(p_packet);
        
            if(is_self_mac(p_packet->dup_eth.ether_dhost, tap_mac) || 
                is_broad_cast_mac(p_packet->dup_eth.ether_dhost) || 
                is_promiscuous_mode) { /* send to tun */
                ret = write(tun_fd, &p_packet->packet, p_packet->sh.real_size);
                if(ret < 0) {
                    printf("write: %m\n");
                    break;
                }
            }

            if(is_broad_cast_mac(p_packet->packet.eth.ether_dhost) || 
                (cache_dst = lookup_cache(p_packet->packet.eth.ether_dhost)) == NULL){
                broadcast_raw_packet(p_packet, sock_fd);
            } else {
                send_raw_packet(p_packet, cache_dst, sock_fd);
            }
          }
        } else if(ret == -1) {
          printf("select: %m\n");
          exit(1);
        } else {
          //SDBG("no data to process, sleep\n");
        }
    }

    return 0;
}
