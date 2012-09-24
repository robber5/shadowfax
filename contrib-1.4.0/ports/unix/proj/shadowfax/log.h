#ifndef __LOG_SNIFF_H__
#define __LOG_SNIFF_H__

#define SHADOW_LOG_INFO  1
#define SHADOW_LOG_WARN  2
#define SHADOW_LOG_ERR   3
#define SHADOW_LOG_DBG   4

extern int shadow_quiet;

void _print_log(int level, const char * fmt, ...);

#define SERR(fmt, args...) \
    _print_log(SHADOW_LOG_ERR, fmt, ##args);

#define SWAN(fmt, args...) \
    _print_log(SHADOW_LOG_WARN, fmt, ##args);

#define SINF(fmt, args...) \
    _print_log(SHADOW_LOG_INFO, fmt, ##args);

#define SDBG(fmt, args...) \
    _print_log(SHADOW_LOG_DBG, fmt, ##args);

#endif
