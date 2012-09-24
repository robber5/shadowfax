#include "misc_cmd.h"
#include "cmd.h"

#include "lwip/tcp.h"
#include "lwip/inet.h"

/*
struct tcp_pcb ** const tcp_pcb_lists[] = {&tcp_listen_pcbs.pcbs, &tcp_bound_pcbs,
  &tcp_active_pcbs, &tcp_tw_pcbs};
*/
extern struct tcp_pcb ** const tcp_pcb_lists[];

static int do_netstat(struct cmd_slot * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    struct tcp_pcb *cpcb;
    int i;
    char local_ip[32], remote_ip[32];

    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    for (i = 0; i < 4; i++) {
      for(cpcb = *tcp_pcb_lists[i]; cpcb != NULL; cpcb = cpcb->next) {
        inet_ntoa_r(cpcb->local_ip, local_ip, sizeof(local_ip));
        inet_ntoa_r(cpcb->remote_ip, remote_ip, sizeof(remote_ip));
          /* linux returns EISCONN here, but ERR_USE should be OK for us */
        cmd_printf(out, "%s:%d <---> %s:%d  %s\n",
            local_ip, cpcb->local_port,
            remote_ip, cpcb->remote_port, 
            tcp_debug_state_str(cpcb->state));
      }
    }
    return 0;
}

static int do_close_pcb(struct cmd_slot * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);
    LWIP_UNUSED_ARG(out);

    cmd_printf(out, "not impl yet!\n");
    return -1;
}


void misc_cmd_init(void)
{
    reg_cmd(do_netstat, "netstat", "show all socket\n");
    reg_cmd(do_close_pcb, "close_tcp", "close tcp socket\n");

}

