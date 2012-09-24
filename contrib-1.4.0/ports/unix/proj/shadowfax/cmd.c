#include "cmd.h"

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include "console.h"

cmd_slot_t * slot_head;

void reg_cmd(cmd_fn_t fn, const char * cmd, const char * info)
{
    cmd_slot_t * slot = malloc(sizeof(cmd_slot_t));
    if(slot != NULL) {
        memset(slot, 0, sizeof(cmd_slot_t));
        slot->next = slot_head;
        slot->cmd = strdup(cmd);
        slot->fn = fn;
        if(NULL != info) {
            slot->info = strdup(info);
        }
        slot_head = slot;
    }
}

cmd_slot_t * lookup_cmd_slot(const char * cmd)
{
    cmd_slot_t * slot = slot_head;
    while(slot != NULL) {
        if(!strcmp(cmd, slot->cmd)) {
            return slot;
        }
        slot = slot->next;
    }
    return NULL;
}

int cmd_printf(cmd_out_handle_t * handle, const char *format, ...)
{
    char buffer[CONSOLE_MAX_RES_LEN];
    va_list ap;
    int len;
    sfifo_t * f = (sfifo_t *)handle;

    va_start(ap, format);
    len =  vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);

    return sfifo_write(f, buffer, len);
}

void list_all_cmd(cmd_out_handle_t * handle)
{
    cmd_slot_t * slot = slot_head;
    while(slot != NULL) {
        cmd_printf(handle, "%s: %s", slot->cmd, slot->info ? slot->info : "");
        slot = slot->next;
    }
}
