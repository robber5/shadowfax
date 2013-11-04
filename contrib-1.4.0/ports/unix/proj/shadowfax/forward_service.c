#include "forward_service.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <getopt.h>
#include <pthread.h>

#include "lwip/opt.h"
#include "lwip/mem.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/api.h"
#include "lwip/stats.h"
#include "lwip/inet.h"
#include "lwip/tcp.h"
#include "lwip/tcp_impl.h"

#include "fifo.h"
#include "cmd.h"
#include "socket.h"
#include "log.h"


extern char ** environ;

static sys_sem_t rforward_sem;

enum status {
    STOP    = 0,
    STOPPING = 1,
    RUNNING = 2
};
static const char *status_str[3] = 
{
    "STOP",
    "STOPPING",
    "RUNNING"
};

static enum status forward_status;
static struct tcp_pcb *forward_pcb;
static u16_t forward_port;
static int forward_stop_flag;
static int forward_session_cnt;

static enum status rforward_status;
static struct tcp_pcb *rforward_pcb;
static u16_t rforward_port;
static ip_addr_t rforward_ip;
static int rforward_stop_flag;
static int rforward_session_cnt;
static int rforward_interval;

static char * target_host;
static u16_t  target_port;

struct forward_state
{
    int fd_socket;
    struct tcp_pcb *pcb;
    sfifo_t in_fifo;
    sfifo_t out_fifo;
    int keep_alive_cnt;
    int reversed;
    char * target_host;
    u16_t target_port;
};

static int set_fd_nonblock(int fd)
{
    int flags;
    if((flags = fcntl(fd, F_GETFD, 0)) != -1) {
        if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1) {
            return 0;
        }
    }
    return -1;
}

static void forward_close(struct forward_state *state)
{
    if(state != NULL) {
        if(state->fd_socket != -1) {
            close(state->fd_socket); state->fd_socket = -1;
        }
        sfifo_close(&state->in_fifo);
        sfifo_close(&state->out_fifo);
        if(state->pcb != NULL) {
            tcp_arg(state->pcb, NULL);
            tcp_sent(state->pcb, NULL);
            tcp_recv(state->pcb, NULL);
            tcp_err(state->pcb, NULL);
            tcp_poll(state->pcb, NULL, 0);
            SDBG("forward_close: tcp->state = %d\n", state->pcb->state);
            /* if(state->pcb->state != TIME_WAIT) */
                tcp_close(state->pcb);
            state->pcb = NULL;
        }
        if(state->reversed) {
            sys_sem_signal(&rforward_sem);
            rforward_session_cnt --;
            if(rforward_session_cnt <= 0 && rforward_status == STOPPING) {
                rforward_session_cnt = 0;
                rforward_status = STOP;
            }
        } else {
            forward_session_cnt --;
            if(forward_session_cnt <= 0&& forward_status == STOPPING) {
                forward_session_cnt = 0;
                forward_status = STOP;
            }
        }
        free(state);
    }
}

static void forward_msgerr(void *arg, err_t err)
{
    struct forward_state *state = arg;
    LWIP_UNUSED_ARG(err);
    SDBG("forward_msgerr called %d\n", err);
    state->pcb = NULL; /* pcb already freed !*/
    forward_close(state);
}

static err_t forward_send_data(struct tcp_pcb *pcb, struct forward_state * state)
{
    int len;
    err_t err;
    char buffer[4096];

    if(pcb == NULL || state == NULL)
        return ERR_OK;

	if (pcb->state > ESTABLISHED)
		return ERR_OK;

    len = sfifo_used(&state->out_fifo);

    if(len > 0) {
        if(len > tcp_sndbuf(pcb))
            len = tcp_sndbuf(pcb);
        if(len > (int)sizeof(buffer))
            len = (int)sizeof(buffer);

        len = sfifo_try_read(&state->out_fifo, buffer, len);

        err = tcp_write(pcb, buffer, len, 1);
        if (err != ERR_OK) {
            SERR("forward_msgsent: error writing!\n");
            forward_close(state);
            return err;
        }
        sfifo_read_ack(&state->out_fifo, len);
        SERR("forward_msgsent: send %d bytes\n", len);
    }

    return ERR_OK;
}

/* read data from out_fifo and send it to socket  */
static err_t forward_msgsent(void *arg, struct tcp_pcb *pcb, u16_t length)
{
    struct forward_state *state = arg;

    LWIP_UNUSED_ARG(length);

	if (pcb->state > ESTABLISHED)
		return ERR_OK;

    return forward_send_data(pcb, state);
}

static err_t forward_msgpoll(void *arg, struct tcp_pcb *pcb)
{
    struct forward_state *state = arg;
    int len, ret, total;
    char buffer[4096];
    err_t err;

	if (pcb->state != ESTABLISHED) {
        /*dbg_printf("forward_msgpoll: pcb->state %d != ESTABLISHED\n", pcb->state);*/
        forward_close(state);
		return ERR_OK;
    }

    if(!state->reversed && forward_stop_flag) {
        forward_close(state);
		return ERR_OK;
    } else if(state->reversed && rforward_stop_flag) {
        forward_close(state);
		return ERR_OK;
    }

    
    state->keep_alive_cnt ++;
    if(state->keep_alive_cnt > FORWARD_KEEP_ALIVE_INTERVAL) {
        state->keep_alive_cnt = 0;
        tcp_keepalive(pcb);
        pcb->keep_cnt_sent ++;
        SDBG("forward_msgpoll pcb->keep_cnt_sent %d, max %d\n", pcb->keep_cnt_sent, FORWARD_MAX_KEEP_ALIVE_CNT);
        if(pcb->keep_cnt_sent > FORWARD_MAX_KEEP_ALIVE_CNT) {
            SWAN("forward_msgpoll: timeout!\n");
            forward_close(state);
            return ERR_OK;
        }
    }
    

    /* read data from fd_socket, write into out_fifo */
    len = sfifo_space(&state->out_fifo);

    if(len > 0) {
        if(len > (int)sizeof(buffer))
            len = (int)sizeof(buffer);

        ret = read(state->fd_socket, buffer, len);
        if(ret < 0) {
            if(errno != EAGAIN) {
                SWAN("forward_msgpoll: read %d forward error %d\n", state->fd_socket, errno);
                forward_close(state);
                return ERR_OK;
            } else {
                goto write_fd_in;
            }
        } else if(ret == 0) {
            SDBG("forward_msgpoll: read forward return 0\n");
            forward_close(state);
            return ERR_OK;
        }
        
        total = sfifo_write(&state->out_fifo, buffer, ret);
        if((err = forward_send_data(pcb, state)) != ERR_OK) {
            SWAN("forward_send_data error %d\n", err);
            forward_close(state);
            return ERR_OK;
        }
    }

write_fd_in:
    /* read data from in_fifo, write into fd_socket */
    len = sfifo_used(&state->in_fifo);

    if( len > 0) {
        if(len > (int)sizeof(buffer))
            len = (int)sizeof(buffer);
        len = sfifo_try_read(&state->in_fifo, buffer, len);
        ret = write(state->fd_socket, buffer, len);
        if(ret < 0) {
            if(errno != EAGAIN) {
                SWAN("forward_msgpoll: write forward error %d\n", errno);
                forward_close(state);
                return ERR_OK;
            } else {
                return ERR_OK;
            }
        }
        sfifo_read_ack(&state->in_fifo, ret);
    }

    return ERR_OK;
}

/* push data into in_fifo */
static err_t forward_msgrecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct forward_state *state = arg;
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

    len = sfifo_space(&state->in_fifo);

    if(len >= p->tot_len) {
        total = 0;
        for (q = p; q != NULL; q = q->next) {
            total += sfifo_write(&state->in_fifo, q->payload, q->len);
        }
        SDBG("forward_msgrecv total = %d, p->tot_len = %d, p->len = %d\n", total, p->tot_len, p->len);

        tcp_recved(pcb, p->tot_len);

        pbuf_free(p);

        return ERR_OK;
    }
    SWAN("forward_msgrecv refuse packet\n");
    return ERR_MEM;
}

static int forward_init(struct forward_state *state, struct tcp_pcb *pcb)
{
	/* Initialize the structure. */
	state->pcb = pcb;
    state->fd_socket = -1;

    state->target_host = target_host;
    state->target_port = target_port;

    if(sfifo_init(&state->in_fifo, 40960) 
        || sfifo_init(&state->out_fifo, 40960)) {
        goto fail;
    }

    if((state->fd_socket = connect_to(state->target_host, state->target_port)) == -1) {
        goto fail;
    }

    if(set_fd_nonblock(state->fd_socket) != 0) {
        goto fail;
    }

    if(!state->reversed)
        forward_session_cnt ++;

	/* Tell TCP that this is the structure we wish to be passed for our
	   callbacks. */
	tcp_arg(pcb, state);

	/* Tell TCP that we wish to be informed of incoming data by a call
	   to the http_recv() function. */
	tcp_recv(pcb, forward_msgrecv);

	/* Tell TCP that we wish be to informed of data that has been
	   successfully sent by a call to the ftpd_sent() function. */
	tcp_sent(pcb, forward_msgsent);

	tcp_err(pcb, forward_msgerr);

	tcp_poll(pcb, forward_msgpoll, 1);

    return 0;

fail:
    return -1;
}

static err_t forward_msgaccept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	struct forward_state *state;

    LWIP_UNUSED_ARG(err);
    LWIP_UNUSED_ARG(arg);

	/* Allocate memory for the structure that holds the state of the
	   connection. */
	state = malloc(sizeof(struct forward_state));

	if (state == NULL) {
		SERR("forward_msgaccept: Out of memory\n");
		return ERR_MEM;
	}
	memset(state, 0, sizeof(struct forward_state));

    if(forward_init(state, pcb) < 0) {
        goto fail;
    }

	return ERR_OK;
fail:
    if(NULL != state) {
        forward_close(state);
        state = NULL;
    }
    return ERR_CLSD;
}

static err_t forward_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    struct forward_state *state = arg;

    LWIP_UNUSED_ARG(err);

    /* if connect error, msg_err called */

    SDBG("forward_connected called\n");

    if(forward_init(state, pcb) < 0) {
        SERR("forward_connected: forward_init failed\n");
        forward_close(state);
        state = NULL;
    }

    return ERR_OK;
}


static void reverse_forward_thread(void *arg) 
{
    struct forward_state *state;

    LWIP_UNUSED_ARG(arg);

    while(!rforward_stop_flag) {
        usleep(rforward_interval * 1000);
        state = malloc(sizeof(struct forward_state));

        if (state == NULL) {
            SERR("reverse_forward_thread: Out of memory\n");
            return;
        }
        memset(state, 0, sizeof(struct forward_state));

        rforward_pcb = tcp_new();
        SDBG("***new tcp %p***\n", (void *)rforward_pcb);

        state->pcb = rforward_pcb;
        state->reversed = 1; 

        state->fd_socket = -1;

        rforward_session_cnt ++;

        tcp_arg(rforward_pcb, state);
        tcp_err(rforward_pcb, forward_msgerr);

        if(tcp_connect(rforward_pcb, &rforward_ip, rforward_port ,forward_connected) != ERR_OK) {
            tcp_err(rforward_pcb, NULL);
            tcp_arg(rforward_pcb, NULL);
            tcp_close(rforward_pcb);
            free(state);
            continue;
        }
        SDBG("wait on reverse forward quit\n");
        sys_sem_wait(&rforward_sem);
    }
}


/* ------------------------------------------------------------------------------------------------------------------- */

static int do_start_forward(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int ch;
    err_t err;
    struct tcp_pcb *pcb;
    optarg = NULL;
    optind = 0;

    forward_port = FORWARD_SERVICE_PORT;

    if(forward_status != STOP ) {
        cmd_printf(out, "forward service still running");
        return -1;
    }

    while( (ch = getopt(argc, argv, "b:")) != -1) {
        switch(ch) {
        case 'b':
            forward_port = atoi(optarg);
            break;
        default:
            cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
            return -1;
        }
    }
    argc -= optind;
    argv += optind;

    if(argc != 2) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        return -1;
    }

    if(NULL != target_host) {
        free(target_host);
        target_host = NULL;
    }
    target_host = strdup(argv[0]);
    target_port = atoi(argv[1]);
    SDBG("target_host %s target_port %d\n", target_host, target_port);

    if(forward_port <= 0) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        return -1;
    }
    
    forward_pcb = tcp_new();
    forward_stop_flag = 0;

    if((err = tcp_bind(forward_pcb, IP_ADDR_ANY, forward_port)) != ERR_OK) {
        cmd_printf(out, "can not bind to port %d (%s)\n", forward_port, lwip_strerr(err));
        tcp_close(forward_pcb);
        forward_pcb = NULL;
        return -1;
    }

	pcb = tcp_listen(forward_pcb);
    if(NULL == pcb) {
        cmd_printf(out, "can not set to listen state\n");
        tcp_close(forward_pcb);
        forward_pcb = NULL;
        return -1;
    }
    forward_pcb = pcb;

	tcp_accept(forward_pcb, forward_msgaccept);

    forward_status = RUNNING;
    cmd_printf(out, "service started\n");
    return 0;
}

static int do_stop_forward(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    if(forward_session_cnt != 0) {
        forward_status = STOPPING;
    } else {
        forward_status = STOP;
    }
    forward_stop_flag = 1;
    
    if(NULL != forward_pcb) {
        tcp_close(forward_pcb);
        forward_pcb = NULL;
    }

    cmd_printf(out, "stop command issued, use get_forward_status to watch status\n");

    return 0;
}

static int do_get_forward_status(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    cmd_printf(out, "forward status: %s, port is %d, session count %d\n",
        status_str[forward_status],
        forward_port, forward_session_cnt);
    return 0;
}


static int worker_thread_new(const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio)
{
  int code;
  pthread_t tmp;
  LWIP_UNUSED_ARG(name);
  LWIP_UNUSED_ARG(stacksize);
  LWIP_UNUSED_ARG(prio);

  code = pthread_create(&tmp,
                        NULL, 
                        (void *(*)(void *)) 
                        function, 
                        arg);
  
  return code == 0 ? 0 : -1;;
}

static int do_start_rforward(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int ch;
    err_t err;
    struct tcp_pcb *pcb;
    optarg = NULL;
    optind = 0;
       
    LWIP_UNUSED_ARG(err);
    LWIP_UNUSED_ARG(pcb);    

    rforward_port = RFORWARD_CONNECT_PORT;
    rforward_interval = RFORWARD_INTERVAL_MS;

    if(rforward_status != STOP ) {
        cmd_printf(out, "reverse forward service still running");
        return -1;
    }

    while( (ch = getopt(argc, argv, "h:i:c:")) != -1) {
        switch(ch) {
        case 'c':
            rforward_port = atoi(optarg);
            break;
        case 'i':
            rforward_interval = atoi(optarg);
            break;
        case 'h':
            if(!inet_aton(optarg, &rforward_ip))
            cmd_printf(out, "invalid ip addr %s\n", optarg);
            break;
        default:
            cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
            return -1;
        }
    }

    argc -= optind;
    argv += optind;

    if(argc != 2) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        return -1;
    }

    if(NULL != target_host) {
        free(target_host);
        target_host = NULL;
    }
    target_host = strdup(argv[0]);
    target_port = atoi(argv[1]);

    SDBG("target_host %s target_port %d\n", target_host, target_port);

    if(rforward_port <= 0 || rforward_ip.addr == INADDR_ANY) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        return -1;
    }
    
    rforward_stop_flag = 0;   

    if(worker_thread_new("rforward_thread", reverse_forward_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO) != 0) {
        cmd_printf(out, slot->info == NULL ? slot->info : "can not start rforward thread\n");
        tcp_close(rforward_pcb);
        rforward_pcb = 0;
        return -1;
    }
    rforward_status = RUNNING;
    cmd_printf(out, "service started\n");
    return 0;
}

static int do_stop_rforward(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    if(rforward_session_cnt != 0) {
        rforward_status = STOPPING;
    } else {
        rforward_status = STOP;
    }
    rforward_stop_flag = 1;

    sys_sem_signal(&rforward_sem);
    rforward_pcb = NULL;

    cmd_printf(out, "stop command issued, use get_rforward_status to watch status\n");

    return 0;
}

static int do_get_rforward_status(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    char ip_str[32];

    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    inet_ntoa_r(rforward_ip, ip_str, sizeof(ip_str));

    cmd_printf(out, "forward status: %s, ip is %s, port is %d, session count %d\n",
        status_str[rforward_status], ip_str,
        rforward_port, rforward_session_cnt);
    return 0;
}

void forward_service_init(void)
{
    sys_sem_new(&rforward_sem, 0);

    reg_cmd(do_start_forward, "start_forward", "start passive tcp port forward service, usage: start_forward -b [bind port] host port\n");
    reg_cmd(do_stop_forward, "stop_forward", "stop passive tcp port forward service\n");
    reg_cmd(do_get_forward_status, "get_forward_status", "get passive tcp port forward service status\n");

    reg_cmd(do_start_rforward, "start_rforward", "start reverse tcp port forward service, usage: start_rforward -h [peerip] -c [port] -i [interval_ms] host port\n");
    reg_cmd(do_stop_rforward, "stop_rforward", "stop reverse tcp port forward service\n");
    reg_cmd(do_get_rforward_status, "get_rforward_status", "get reverse tcp port forward service status\n");
}
