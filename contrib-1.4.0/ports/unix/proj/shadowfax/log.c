#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include "log.h"

int shadow_quiet;

void _print_log(int level, const char * file, int line, const char * fmt, ...)
{

    va_list ap;
    char buffer[4096];
    struct tm *tmp;
    size_t len = 0;
    const char * log_str = "ERR ";
    struct timeval tv;

    if(shadow_quiet)
        return;

    gettimeofday(&tv, NULL);

    tmp = localtime(&tv.tv_sec);
    len += strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S", tmp);
    len += snprintf(buffer + len, sizeof(buffer) - len, ".%07lu]", tv.tv_usec);
    switch(level) {
        case SHADOW_LOG_ERR:
            log_str = "ERR"; break;
        case SHADOW_LOG_WARN:
            log_str = "WAN"; break;
        case SHADOW_LOG_INFO:
            log_str = "INF"; break;
        case SHADOW_LOG_DBG:
            log_str = "DBG"; break;
        default:
            log_str = "???"; break;

    }
    len += snprintf(buffer + len, sizeof(buffer) - len, "[%s]", log_str);
    len += snprintf(buffer + len, sizeof(buffer) - len, "[%s:%d]", file, line);

    va_start(ap, fmt);
    len += vsnprintf(buffer + len, sizeof(buffer) - len, fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s", buffer);
}

