#include "console.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pthread.h>

#include "lwip/opt.h"
#include "lwip/mem.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/api.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/tcp_impl.h"

#include "fifo.h"
#include "cmd.h"
#include "log.h"

static sys_sem_t console_sem;

struct console_state
{
    struct tcp_pcb *pcb;
    int keep_alive_cnt;
    char command[CONSOLE_MAX_CMD_BUFFER];
    int command_len;
    sfifo_t res;
    sfifo_t req;
};

static void console_close(struct console_state *state)
{
    if(state != NULL) {
        if(state->pcb != NULL) {
            tcp_arg(state->pcb, NULL);
            tcp_sent(state->pcb, NULL);
            tcp_recv(state->pcb, NULL);
            tcp_err(state->pcb, NULL);
            tcp_poll(state->pcb, NULL, 0);
            SDBG("console_close: tcp->state = %d\n", state->pcb->state);
            tcp_close(state->pcb);
            state->pcb = NULL;
        }
        sfifo_close(&state->res);
        sfifo_close(&state->req);
        free(state);
    }
}

static void console_msgerr(void *arg, err_t err)
{
    struct console_state *state = arg;
    LWIP_UNUSED_ARG(err);
    SDBG("console_msgerr called %d\n", err);
    state->pcb = NULL; /* pcb already freed !*/
    console_close(state);
}


static err_t console_send_data(struct tcp_pcb *pcb, struct console_state * state)
{
    int len;
    err_t err;
    char buffer[4096];

    if(pcb == NULL || state == NULL) {
        SDBG("console_send_data pcb or state is NULL\n");
        return ERR_OK;
    }

	if (pcb->state > ESTABLISHED) {
        SDBG("pcb->state > ESTABLISHED\n");
		return ERR_OK;
    }

    len = sfifo_used(&state->res);

    if(len > 0) {
        if(len > tcp_sndbuf(pcb))
            len = tcp_sndbuf(pcb);
        if(len > (int)sizeof(buffer))
            len = (int)sizeof(buffer);

        len = sfifo_try_read(&state->res, buffer, len);

        err = tcp_write(pcb, buffer, len, 1);
        if (err != ERR_OK) {
            SERR("console_msgsent: error writing!\n");
            console_close(state);
            return err;
        }
        sfifo_read_ack(&state->res, len);
        SERR("console_msgsent: send %d bytes\n", len);
    }

    return ERR_OK;
}

/* read data from out_fifo and send it to socket  */
static err_t console_msgsent(void *arg, struct tcp_pcb *pcb, u16_t length)
{
    struct console_state *state = arg;

    LWIP_UNUSED_ARG(length);

	if (pcb->state > ESTABLISHED)
		return ERR_OK;

    return console_send_data(pcb, state);
}

static void write_promote(sfifo_t * fifo)
{
    if(NULL != fifo) {
        if(sfifo_space(fifo) > 7) {
            sfifo_write(fifo, "console>", strlen("console>"));
        }
    }
}

/* fill state->res, state->res_total, state->res_sent */
static int process_cmd(struct console_state *state)
{
    int argc;
    char * argv[256] = {NULL};
    char * str, *saveptr, *token;
    cmd_slot_t * slot;

    for (argc = 0, str = state->command; argc < 255; argc++, str = NULL) {
        token = strtok_r(str, " \r\n\t", &saveptr);
        if(NULL == token)
            break;
        argv[argc] = token;
    }

    if(argv[0] == NULL)
        return 0;

    if(!strcmp(argv[0], "exit")) {
        SDBG("cmd is %s\n", argv[0]);
        return -1;
    }

    if(argv[0][0] == '!') {
        slot = lookup_cmd_slot("!");
    } else if(argv[0][0] == '&') {
        slot = lookup_cmd_slot("&");
    } else {
        slot = lookup_cmd_slot(argv[0]);
    }

    if(slot != NULL) {
        slot->fn(slot, (cmd_out_handle_t *)&state->res, argc, argv);
    } else {
        cmd_printf((cmd_out_handle_t *)&state->res, "unknown command '%s'\n", argv[0]);
    }
    return 0;
}

static err_t console_msgpoll(void *arg, struct tcp_pcb *pcb)
{
    struct console_state *state = arg;
    int to_read, len, i;

	if (pcb->state != ESTABLISHED) {
        SDBG("pcb->state != ESTABLISHED\n");
        console_close(state);
		return ERR_OK;
    }

    
    state->keep_alive_cnt ++;
    if(state->keep_alive_cnt > CONSOLE_KEEP_ALIVE_INTERVAL) {
        state->keep_alive_cnt = 0;
        tcp_keepalive(pcb);
        pcb->keep_cnt_sent ++;
        SDBG("console_msgpoll pcb->keep_cnt_sent %d, max %d\n", pcb->keep_cnt_sent, CONSOLE_MAX_KEEP_ALIVE_CNT);
        if(pcb->keep_cnt_sent > CONSOLE_MAX_KEEP_ALIVE_CNT) {
            SWAN("console_msgpoll: timeout!\n");
            console_close(state);
            return ERR_OK;
        }
    }

    /* get command from req */
    to_read = sizeof(state->command) - state->command_len;
    len = sfifo_try_read(&state->req, state->command + state->command_len, to_read);
    for(i = state->command_len; i < state->command_len + len; i++) {
        if(state->command[i] == '\n') {
            sfifo_read_ack(&state->req, i - state->command_len + 1);
            state->command_len = i + 1;
            break;
        }
    }

    if(state->command[i] == '\n' && state->command_len > 0) {
        state->command[i] = 0;
        if(process_cmd(state)<0) {
            SDBG("process_cmd exit\n");
            console_close(state);
            return ERR_OK;
        }
        state->command_len = 0;
        write_promote(&state->res);
    }


    if(ERR_OK != console_send_data(pcb, state)) {
        SDBG("console_send_data fail\n");
        console_close(state);
        return ERR_OK;
    }


    return ERR_OK;
}

/* push data into buffer */
static err_t console_msgrecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct console_state *state = arg;
    int len, total;
    struct pbuf *q;

    if ((err != ERR_OK) || (p == NULL)) {
        if (p != NULL) {
            /* Inform TCP that we have taken the data. */
            tcp_recved(pcb, p->tot_len);
            pbuf_free(p);
        }
        return ERR_OK;
    }

    len = sfifo_space(&state->req);

    if(len >= p->tot_len) {
        total = 0;
        for (q = p; q != NULL; q = q->next) {
            total += sfifo_write(&state->req, q->payload, q->len);
        }
        SDBG("console_msgrecv total = %d, p->tot_len = %d, p->len = %d\n", total, p->tot_len, p->len);

        tcp_recved(pcb, p->tot_len);

        pbuf_free(p);

        return ERR_OK;
    }
    SWAN("console_msgrecv refuse packet\n");
    return ERR_MEM;
}

static int console_initilize(struct console_state *state, struct tcp_pcb *pcb)
{
	/* Initialize the structure. */

    if(NULL == state) {
        goto fail;
    }

    memset(state, 0, sizeof(struct console_state));

	state->pcb = pcb;

    if(sfifo_init(&state->res, CONSOLE_MAX_RES_BUFFER))
        goto fail;

    if(sfifo_init(&state->req, CONSOLE_MAX_REQ_BUFFER))
        goto fail;

	/* Tell TCP that this is the structure we wish to be passed for our
	   callbacks. */
	tcp_arg(pcb, state);

	/* Tell TCP that we wish to be informed of incoming data by a call
	   to the http_recv() function. */
	tcp_recv(pcb, console_msgrecv);

	/* Tell TCP that we wish be to informed of data that has been
	   successfully sent by a call to the ftpd_sent() function. */
	tcp_sent(pcb, console_msgsent);

	tcp_err(pcb, console_msgerr);

	tcp_poll(pcb, console_msgpoll, 1);

    return 0;

fail:
    return -1;
}


static err_t console_msgaccept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	struct console_state *state = arg;

    LWIP_UNUSED_ARG(err);
    LWIP_UNUSED_ARG(arg);

    SDBG("console_msgaccept called\n");

    state = malloc(sizeof(struct console_state));
	if (state == NULL) {
		SERR("console_msgaccept: Out of memory\n");
		goto fail;
	}
	/* Allocate memory for the structure that holds the state of the
	   connection. */
    if(console_initilize(state, pcb) < 0) {
        SERR("console_connected: console_init failed\n");
        goto fail;
    }

    write_promote(&state->res);

	return ERR_OK;
fail:
    if(NULL != state) {
        console_close(state);
        state = NULL;
    }
    return ERR_CLSD;
}

static int start_console(void)
{
    err_t err;
    struct tcp_pcb *listen_pcb, *pcb;

    listen_pcb = tcp_new();

    if((err = tcp_bind(listen_pcb, IP_ADDR_ANY, CONSOLE_LISTEN_PORT)) != ERR_OK) {
        tcp_close(listen_pcb);
        listen_pcb = NULL;
        SERR("console: tcp_bind error\n");
        return -1;
    }

	pcb = tcp_listen(listen_pcb);
    if(NULL == pcb) {
        tcp_close(listen_pcb);
        listen_pcb = NULL;
        SERR("console: tcp_listen error\n");
        return -1;
    }
    listen_pcb = pcb;

	tcp_accept(listen_pcb, console_msgaccept);

    return 0;

}

static err_t probe_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);

    /* if connect error, msg_err called */

    SDBG("probe_connected called\n");

    tcp_arg(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_close(pcb); 
    sys_sem_signal(&console_sem);
    return ERR_OK;
}

static void probe_msgerr(void *arg, err_t err)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);
    SDBG("probe_msgerr called %d\n", err);
    sys_sem_signal(&console_sem);
}


static void console_thread(void *arg) 
{
	struct tcp_pcb *pcb;
    ip_addr_t remote_addr;
    struct netif * p_netif = NULL;
    err_t err;

    LWIP_UNUSED_ARG(arg);

    sys_sem_new(&console_sem, 0);

    while(1) {
        usleep(CONSOLE_PROBE_INTERVAL * 1000);

        /* find gw */
        p_netif = netif_find((char *)"ud0");
        if(!p_netif)
            continue;

        remote_addr = p_netif->gw;

        pcb = tcp_new();

        tcp_arg(pcb, NULL);
        tcp_err(pcb, probe_msgerr);
        SDBG("try to probe master on %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n", 
            ip4_addr1_16(&remote_addr), ip4_addr2_16(&remote_addr),ip4_addr3_16(&remote_addr),ip4_addr4_16(&remote_addr));
        if((err = tcp_connect(pcb, &remote_addr, CONSOLE_PROBE_PORT, probe_connected)) != ERR_OK) {
            SERR("tcp_connect error %d\n", err);
            tcp_arg(pcb, NULL);
            tcp_err(pcb, NULL);
            tcp_close(pcb);
            continue;
        }
        SDBG("wait on probe quit\n");
        sys_sem_wait(&console_sem);
    }
}

void console_init(void)
{
    start_console();
    sys_thread_new("console_thread", console_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}
