#ifndef __SHADOW_COMPRESS__
#define __SHADOW_COMPRESS__

#include <sys/types.h>
#include "netif/etharp.h"

#define SHADOW_COMPRESS_MAGIC 0xAABB
#define SHADOW_MAX_COMPRESS_BUFFER 4096
#define SHADOW_COMPRESS_THRES  256 /*  if size < 256, don't compress */

struct s_compress_header /* 8 bytes */
{
    u_int16_t magic;
    u_int16_t flag;
    u_int16_t real_size; /* size before compress */
    u_int16_t comp_size; /* size after compress */
}__attribute__((packed));

void s_compress(struct s_compress_header *buf);
int  s_uncompress(struct s_compress_header *buf);

#endif
