#include "compress.h"
#include <string.h>
#include <zlib.h>

#include "log.h"

void s_compress(struct s_compress_header *buf)
{
    char buffer[SHADOW_MAX_COMPRESS_BUFFER];
    size_t len = sizeof(buffer);
    int ret = 0;
    char * p;

    buf->magic = SHADOW_COMPRESS_MAGIC;
    buf->comp_size = buf->real_size;
    buf->flag = 0;

    if(buf->real_size < SHADOW_COMPRESS_THRES) {
        SDBG("don't compress: buf->real_size  %u < %u\n", buf->real_size, SHADOW_COMPRESS_THRES);
        return;
    }

    if(compressBound(buf->real_size) > sizeof(buffer)) {
        SDBG("don't compress: buf->real_size > %u\n", sizeof(buffer));
    } else {
        p = ((char*)buf) + sizeof(struct s_compress_header);
        ret = compress2((Bytef *)buffer, (uLongf *)&len, (const Bytef *)p, (uLong)buf->real_size, 9);
        if(Z_OK != ret || len > buf->real_size) {
            SDBG("don't compress: ret %d buf->real_size %u buf->comp_size %u\n", ret, buf->real_size, len);
        } else {
            SDBG("compress:  %u -> %u\n", buf->real_size, len);
            memcpy(p, buffer, len);
            buf->comp_size = len;
            buf->flag = 1;
        }
    }
}


int s_uncompress(struct s_compress_header *buf)
{
    char buffer[SHADOW_MAX_COMPRESS_BUFFER];
    size_t len = sizeof(buffer);
    int ret = 0;
    char * p;
    
    if(buf->magic != SHADOW_COMPRESS_MAGIC) {
        SDBG("don't uncompress: buf->magic != %x\n", SHADOW_COMPRESS_MAGIC);
        return -1;
    }

    if(buf->real_size > SHADOW_MAX_COMPRESS_BUFFER || buf->comp_size > SHADOW_MAX_COMPRESS_BUFFER) {
        SDBG("don't uncompress: buf->real_size %u buf->comp_size %u too big\n", buf->real_size, buf->comp_size);
        return -1;
    }

    if(buf->flag == 0) {
        SDBG("don't uncompress: not compressed!\n");
        return 0;
    }

    p = ((char*)buf) + sizeof(struct s_compress_header);

    ret = uncompress ((Bytef *)buffer, (uLongf *)&len, (const Bytef *)p, (uLong)buf->comp_size);
    
    if(ret != Z_OK) {
        SDBG("uncompress fail: ret %d\n", ret);
        return -1;
    }

    if(buf->real_size != len) {
        SDBG("uncompress fail: buf->real_size %u != uncompress size %u\n", buf->real_size, len);
        return -1;
    }

    SDBG("uncompress:  %u -> %u\n", buf->comp_size, buf->real_size);
    memcpy(p, buffer, len);

    return 0;
}
