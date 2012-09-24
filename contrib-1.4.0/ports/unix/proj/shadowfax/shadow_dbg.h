#ifndef __SHADOW_DEBUG__
#define __SHADOW_DEBUG__

void _dbg_print(int level, const char * fmt, ...);


#define SHADOW_DBG 1
#define SHADOW_INF 2
#define SHADOW_WAN 3
#define SHADOW_ERR 4

#define SDBG(fmt, args...) \
    _dbg_print(SHADOW_DBG, fmt, ##args);

#define SINF(fmt, args...) \
    _dbg_print(SHADOW_INF, fmt, ##args);

#define SWAN(fmt, args...) \
    _dbg_print(SHADOW_WAN, fmt, ##args);

#define SERR(fmt, args...) \
    _dbg_print(SHADOW_ERR, fmt, ##args);

#endif
