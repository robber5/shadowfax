#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include "log.h"

int shadow_quiet;

void _print_log(int level, const char * fmt, ...)
{

    va_list ap;
    char buffer[4096];
    time_t t;
    struct tm *tmp;
    size_t len = 0;
    const char * log_str = "ERR ";

    if(shadow_quiet)
        return;

    t = time(NULL);
    tmp = localtime(&t);
    len += strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S]", tmp);
    
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
    len += snprintf(buffer + len, sizeof(buffer) - len, "[%s] ", log_str);

    va_start(ap, fmt);
    len += vsnprintf(buffer + len, sizeof(buffer) - len, fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s", buffer);
}

