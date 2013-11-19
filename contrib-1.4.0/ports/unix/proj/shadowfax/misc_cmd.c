#include "misc_cmd.h"
#include "cmd.h"
#include "log.h"
#include "console.h"

#include "lwip/tcp.h"
#include "lwip/inet.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

/*
struct tcp_pcb ** const tcp_pcb_lists[] = {&tcp_listen_pcbs.pcbs, &tcp_bound_pcbs,
  &tcp_active_pcbs, &tcp_tw_pcbs};
*/
extern struct tcp_pcb ** const tcp_pcb_lists[];

static void close_all_fd(int exp)
{
    int i;
    for(i = 0; i <= 65536; i ++) {
        if(exp == i)
            continue;

        close(i);
    }
}

static int do_cmd_netstat(struct cmd_slot * slot, cmd_out_handle_t * out, int argc, char ** argv)
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

/*
static int do_cmd_close_pcb(struct cmd_slot * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);
    LWIP_UNUSED_ARG(out);

    cmd_printf(out, "not impl yet!\n");
    return -1;
}
*/

static int do_cmd_help(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    cmd_slot_t * pslot = NULL;
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);
    LWIP_UNUSED_ARG(slot);
    if(argc == 1) {
        list_all_cmd(out);
    } else {
        pslot = lookup_cmd_slot(argv[1]);
        if(NULL != pslot) {
            cmd_usage(pslot, out);
        } else {
            cmd_printf(out, "unknown cmd %s\n", argv[1]);
        }
    }
      
    return 0;
}

static int do_cmd_exit(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);
    LWIP_UNUSED_ARG(out);
    LWIP_UNUSED_ARG(slot);    
    return 0;
}

static int do_cmd_ifconfig(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);
    LWIP_UNUSED_ARG(slot); 
    struct netif *p_netif = netif_list;
    while(p_netif) {
        cmd_printf(out, "%s%d addr %"U16_F".%"U16_F".%"U16_F".%"U16_F
            " mask %"U16_F".%"U16_F".%"U16_F".%"U16_F
            " gw %"U16_F".%"U16_F".%"U16_F".%"U16_F
            " hw %"X8_F"-%"X8_F"-%"X8_F"-%"X8_F"-%"X8_F"-%"X8_F"\n", 
            p_netif->name,
            p_netif->num,
            ip4_addr1(&p_netif->ip_addr), ip4_addr2(&p_netif->ip_addr),ip4_addr3(&p_netif->ip_addr),ip4_addr4(&p_netif->ip_addr),
            ip4_addr1(&p_netif->netmask), ip4_addr2(&p_netif->netmask),ip4_addr3(&p_netif->netmask),ip4_addr4(&p_netif->netmask),
            ip4_addr1(&p_netif->gw), ip4_addr2(&p_netif->gw),ip4_addr3(&p_netif->gw),ip4_addr4(&p_netif->gw),
            p_netif->hwaddr[0], p_netif->hwaddr[1], p_netif->hwaddr[2], p_netif->hwaddr[3], p_netif->hwaddr[4], p_netif->hwaddr[5]);
        p_netif = p_netif->next;
    }
    return 0;
}

static int do_cmd_version(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);
    LWIP_UNUSED_ARG(slot); 
    cmd_printf(out, "%s\n", SHADOW_HOST_VERSION);
    return 0;
}

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

static void run_command_nowait(const char * cmd, int * status)
{
    const char *argv[5] = {NULL};
    int fd_dev_null = -1;
    pid_t child1 = -1, child2 = -1, wait_ret = -1;

    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = cmd;
    argv[3] = 0;

    if((child1 = fork()) == 0) { /* child */
        /* fork again */
        if((child2 = fork()) == 0) { /* child */
            setsid();
            close_all_fd(-1);
            if((fd_dev_null = open("/dev/null", 0)) < 0) {
                exit(253);
            }
            if((dup2(fd_dev_null, 0)) == -1
                ||(dup2(fd_dev_null, 1)) == -1
                ||(dup2(fd_dev_null, 2)) == -1 ) {
                exit(253);
            }
            if(fd_dev_null != 0) {
                close(fd_dev_null); fd_dev_null = -1;
            }
            execve("/bin/sh", (char **)argv, environ);
            exit(253);
        } else{ /* parent */
            /* nothing , just quit */
            exit(0);
        }
    } else if(child1 > 0) { /* parent */
         wait_ret =  waitpid(child1, status, 0);
    } else {
        SERR("fork error: %m\n");
    }
}

static char * run_command(const char * cmd, int * status)
{
    const char *argv[5] = {NULL};
    char * ret = NULL;
    int read_ret = 0, read_size = 0;
    pid_t child = -1, wait_ret = -1;
    int pipefd[2] = {-1, -1};
    time_t current, start;
    int kill_count = 0;
    int buffer_full = 0;
    int read_end = 0;
    int trunk_mark_size = 0;
    const char * trunk_mark = "\n\n---output trunked---\n";

    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = cmd;
    argv[3] = 0;

    start = time(NULL);
    trunk_mark_size = strlen(trunk_mark);

    ret = malloc(CONSOLE_MAX_RES_LEN);
    if(ret == NULL) {
        goto err;
    }

    memset(ret, 0, CONSOLE_MAX_RES_LEN);

    /*pipefd[0] refers to the read end of the pipe.  
      pipefd[1] refers to the  write  end  of  the pipe.*/
    if(pipe(pipefd) != 0) {
        SERR("pipe: %m\n");
        goto err;
    }

    if(set_fd_nonblock(pipefd[0]) != 0 
        || set_fd_nonblock(pipefd[1]) != 0) {
        SERR("set_fd_nonblock failed\n");
        goto err;
    }

    if((child = fork()) == 0) { /* child */
        int fd_dev_null;
        setsid();
        close_all_fd(pipefd[1]);
        if((fd_dev_null = open("/dev/null", 0)) < 0) {
            exit(253);
        }
        if((dup2(fd_dev_null, 0)) == -1
            ||(dup2(pipefd[1], 1)) == -1
            ||(dup2(pipefd[1], 2)) == -1 ) {
            exit(253);
        }
        if(fd_dev_null != 0) {
            close(fd_dev_null); fd_dev_null = -1;
        }
        close(pipefd[1]); pipefd[1] = -1;
        execve("/bin/sh", (char **)argv, environ);
        exit(253);
    } else if(child > 0) { /* parent */
        /* read pipe into buffer */
        close(pipefd[1]); pipefd[1] = -1;
        while(1) {
            if(!buffer_full && !read_end) {
                read_ret = read(pipefd[0], ret + read_size, 
                    CONSOLE_MAX_RES_LEN - trunk_mark_size - read_size);
                if(read_ret > 0) {
                    start = time(NULL); /* update timeo*/
                    if(read_size + read_ret >= CONSOLE_MAX_RES_LEN - trunk_mark_size) {
                        snprintf(ret + CONSOLE_MAX_RES_LEN - 
                            trunk_mark_size - 1, trunk_mark_size, "%s", trunk_mark);
                        buffer_full = 1;
                    } else {
                        read_size += read_ret;
                    }
                } else if(read_ret < 0 && errno != EAGAIN) {
                    SERR("read : %m\n");
                    read_end = 1;
                } else if(read_ret == 0) {
                    SERR("read : close pipe\n");
                    read_end = 1;
                } else {/* read_ret < 0 && errno == EAGAIN*/
                    SDBG("read : nothing\n");
                    /* nothing */
                }
            }
            
            wait_ret =  waitpid(child, status, WNOHANG | WUNTRACED);
            SDBG("waitpid return: %d\n", wait_ret);
            if(wait_ret < 0) {
                SERR("waitpid : %m\n");
                break; /* error */
            } else if(wait_ret == 0 || buffer_full){ /* not exit */
                /* test time out or buffer full */
                current = time(NULL);
                if(current > start + LOCAL_CMD_TIMEO_SEC || buffer_full) {
                    if(current > start + LOCAL_CMD_TIMEO_SEC) {
                        SWAN("time out, send kill\n");
                    } else {
                        SWAN("buffer full, send kill\n");
                    }
                    kill(child, SIGKILL);
                    kill_count ++;
                    if(kill_count > LOCAL_CMD_MAX_KILL_COUNT) {
                        SWAN("give up kill\n");
                        break; /* give up*/
                    }
                    usleep(10 * 1000); /* 10 ms*/
                }
            } else { /* exit */
                SDBG("child %d exit\n", child);
                if(read_end || buffer_full)
                    break;
            }
        } /* while */
        close(pipefd[0]); pipefd[0] = -1;
    } else {
        SERR("fork error: %m\n");
    }

    ret[CONSOLE_MAX_RES_LEN - 1] = 0;

    SDBG("return result %s\n", ret);

    return ret;
err:
    if(NULL != ret) {
        free(ret);
        ret = NULL;
    }
    if(pipefd[0] != -1) {
        close(pipefd[0]);
    }
    if(pipefd[1] != -1) {
        close(pipefd[1]);
    }
    return ret;
}

static int do_cmd_local_nowait(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int i;
    size_t len = 0, save_len = 0;
    int status;
    char cmd[4096];

    LWIP_UNUSED_ARG(slot);

    memset(cmd, 0, sizeof(cmd));

    if(strlen(argv[0]) != 1) {
        len += strlen(argv[0]);
        save_len += snprintf(cmd + save_len, sizeof(cmd) - save_len, "%s ", argv[0] + 1);
    }

    for(i = 1 ; i < argc; i ++) {
        len += strlen(argv[i]) + 1;
        if(len >= sizeof(cmd)) {
            break;
        }
        save_len += snprintf(cmd + save_len, sizeof(cmd) - save_len, "%s ", argv[i]);
    }

    cmd[sizeof(cmd) - 1] = 0;

    SDBG("do_cmd_local_nowait: cmd is %s\n", cmd);

    run_command_nowait(cmd, &status);
    
    if(WIFEXITED(status)) {
        cmd_printf(out, "---run command '%s' ok, status is %d (EXITED)---\n", cmd, WEXITSTATUS(status));
    } else if(WIFSIGNALED(status)) {
        cmd_printf(out, "---run command '%s' ok, status is %d (KILLED)---\n", cmd, WTERMSIG(status));
    } else {
        cmd_printf(out, "---run command '%s' ok, status is %d (UNKNOWN)---\n", cmd, status);
    }

    return 0;
}

static int do_cmd_local(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    char cmd[4096];
    char * ret;
    int i;
    size_t len = 0, save_len = 0;
    int status;

    LWIP_UNUSED_ARG(slot);

    memset(cmd, 0, sizeof(cmd));

    if(strlen(argv[0]) != 1) {
        len += strlen(argv[0]);
        save_len += snprintf(cmd + save_len, sizeof(cmd) - save_len, "%s ", argv[0] + 1);
    }

    for(i = 1 ; i < argc; i ++) {
        len += strlen(argv[i]) + 1;
        if(len >= sizeof(cmd)) {
            break;
        }
        save_len += snprintf(cmd + save_len, sizeof(cmd) - save_len, "%s ", argv[i]);
    }

    cmd[sizeof(cmd) - 1] = 0;

    SDBG("do_cmd_local: cmd is %s\n", cmd);

    ret = run_command(cmd, &status);
    if(NULL != ret) {
        cmd_printf(out, "%s\n", ret);
    }

    if(WIFEXITED(status)) {
        cmd_printf(out, "---run command '%s' %s, status is %d (EXITED)---\n", cmd,
            ret == NULL ? "fail":"ok", WEXITSTATUS(status));
    } else if(WIFSIGNALED(status)) {
        cmd_printf(out, "---run command '%s' %s, status is %d (KILLED)---\n", cmd, 
            ret == NULL ? "fail":"ok", WTERMSIG(status));
    } else {
        cmd_printf(out, "---run command '%s' %s, status is %d (UNKNOWN)---\n", cmd, 
            ret == NULL ? "fail":"ok", status);
    }
    if(NULL != ret) {
        free(ret);
        ret = NULL;
    }
    return 0;
}

void misc_cmd_init(void)
{
    reg_cmd(do_cmd_netstat, "netstat", "show all socket\n");
//    reg_cmd(do_cmd_close_pcb, "close_tcp", "close tcp socket\n");
    reg_cmd(do_cmd_help, "help", "show help, use help 'cmd' to get usage\n");
    reg_cmd(do_cmd_exit, "exit", "exit console\n");
    reg_cmd(do_cmd_ifconfig, "ifconfig", "show all interface\n");
    reg_cmd(do_cmd_version, "version", "show host version\n");
    reg_cmd(do_cmd_local, "!", "run local command\n");
    reg_cmd(do_cmd_local_nowait, "&", "run local command background\n");
}

