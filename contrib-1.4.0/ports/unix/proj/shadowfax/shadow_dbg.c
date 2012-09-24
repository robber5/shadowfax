#include "shadow_dbg.h"

#include <stdio.h>
#include <stdarg.h>

#define MAX_DBG_BUFFER 4096

extern int shadow_quiet;

void _dbg_print(int level, const char * fmt, ...)
{
    char buffer[MAX_DBG_BUFFER];
    va_list ap;
    int len = 0;

    if(shadow_quiet)
        return;

    switch(level) {
        case SHADOW_DBG:
            len = snprintf(buffer, sizeof(buffer), "%s ", "[DBG]");
            break;
        case SHADOW_INF:
            len = snprintf(buffer, sizeof(buffer), "%s ", "[INF]");
            break;
        case SHADOW_WAN:
            len = snprintf(buffer, sizeof(buffer), "%s ", "[WAN]");
            break;
        case SHADOW_ERR:
            len = snprintf(buffer, sizeof(buffer), "%s ", "[ERR]");
            break;
    }

    va_start(ap, fmt);
    vsnprintf (buffer + len, sizeof(buffer) - len, fmt, ap);
    va_end(ap);

    fprintf(stdout, "%s", buffer);

}
