/*
 * Copyright (c) 2002 Florian Schulze.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * ftpd.c - This file is part of the FTP daemon for lwIP
 *
 */

#include "lwip/debug.h"

#include "lwip/stats.h"

#include "transfer_service.h"

#include "lwip/tcp.h"
#include "lwip/tcp_impl.h"

#include "vfs.h"
#include "fifo.h"

#include "cmd.h"
#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <malloc.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>


#define msg110 "110 MARK %s = %s."
/*
         110 Restart marker reply.
             In this case, the text is exact and not left to the
             particular implementation; it must read:
                  MARK yyyy = mmmm
             Where yyyy is User-process data stream marker, and mmmm
             server's equivalent marker (note the spaces between markers
             and "=").
*/
#define msg120 "120 Service ready in nnn minutes."
#define msg125 "125 Data connection already open; transfer starting."
#define msg150 "150 File status okay; about to open data connection."
#define msg150recv "150 Opening BINARY mode data connection for %s (%i bytes)."
#define msg150stor "150 Opening BINARY mode data connection for %s."
#define msg200 "200 Command okay."
#define msg202 "202 Command not implemented, superfluous at this site."
#define msg211 "211 System status, or system help reply."
#define msg212 "212 Directory status."
#define msg213 "213 File status."
#define msg214 "214 %s."
/*
             214 Help message.
             On how to use the server or the meaning of a particular
             non-standard command.  This reply is useful only to the
             human user.
*/
#define msg214SYST "214 %s system type."
/*
         215 NAME system type.
             Where NAME is an official system name from the list in the
             Assigned Numbers document.
*/
#define msg220 "220 shadow FTP Server ready."
/*
         220 Service ready for new user.
*/
#define msg221 "221 Goodbye."
/*
         221 Service closing control connection.
             Logged out if appropriate.
*/
#define msg225 "225 Data connection open; no transfer in progress."
#define msg226 "226 Closing data connection."
/*
             Requested file action successful (for example, file
             transfer or file abort).
*/
#define msg227 "227 Entering Passive Mode (%i,%i,%i,%i,%i,%i)."
/*
         227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
*/
#define msg230 "230 User logged in, proceed."
#define msg250 "250 Requested file action okay, completed."
#define msg257PWD "257 \"%s\" is current directory."
#define msg257 "257 \"%s\" created."
/*
         257 "PATHNAME" created.
*/
#define msg331 "331 User name okay, need password."
#define msg332 "332 Need account for login."
#define msg350 "350 Requested file action pending further information."
#define msg421 "421 Service not available, closing control connection."
/*
             This may be a reply to any command if the service knows it
             must shut down.
*/
#define msg425 "425 Can't open data connection."
#define msg426 "426 Connection closed; transfer aborted."
#define msg450 "450 Requested file action not taken."
/*
             File unavailable (e.g., file busy).
*/
#define msg451 "451 Requested action aborted: local error in processing."
#define msg452 "452 Requested action not taken."
/*
             Insufficient storage space in system.
*/
#define msg500 "500 Syntax error, command unrecognized."
/*
             This may include errors such as command line too long.
*/
#define msg501 "501 Syntax error in parameters or arguments."
#define msg502 "502 Command not implemented."
#define msg503 "503 Bad sequence of commands."
#define msg504 "504 Command not implemented for that parameter."
#define msg530 "530 Not logged in."
#define msg532 "532 Need account for storing files."
#define msg550 "550 Requested action not taken."
/*
             File unavailable (e.g., file not found, no access).
*/
#define msg551 "551 Requested action aborted: page type unknown."
#define msg552 "552 Requested file action aborted."
/*
             Exceeded storage allocation (for current directory or
             dataset).
*/
#define msg553 "553 Requested action not taken."
/*
             File name not allowed.
*/


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

static enum status transfer_status;
static struct tcp_pcb *transfer_pcb;
static u16_t transfer_port;
static int transfer_stop_flag;
static int transfer_session_cnt;
static u16_t port_from;
static u16_t port_to;


enum ftpd_state_e {
	FTPD_USER,
	FTPD_PASS,
	FTPD_IDLE,
	FTPD_NLST,
	FTPD_LIST,
	FTPD_RETR,
	FTPD_RNFR,
	FTPD_STOR,
	FTPD_QUIT
};

static const char *month_table[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

struct ftpd_datastate {
	int connected;
	vfs_dir_t *vfs_dir;
	vfs_dirent_t *vfs_dirent;
	vfs_file_t *vfs_file;
	sfifo_t fifo;
    struct tcp_pcb *datapcb;
	struct ftpd_msgstate *msgfs;
};

struct ftpd_msgstate {
	enum ftpd_state_e state;
	sfifo_t fifo;
	vfs_t *vfs;
	struct ip_addr dataip;
	u16_t dataport;
    struct tcp_pcb *msgpcb;
	struct ftpd_datastate *datafs;
	int passive;
	char *renamefrom;
    int keepalive_cnt;
};

static void send_msg(struct ftpd_msgstate *fsm, const char *msg, ...);
static void ftpd_dataclose(struct ftpd_datastate *fsd);

static void ftpd_dataerr(void *arg, err_t err)
{
	struct ftpd_datastate *fsd = arg;
	SDBG("ftpd_dataerr: %s (%i)\n", lwip_strerr(err), err);
	if (fsd != NULL) {
        fsd->datapcb = NULL; /* already freed */
		ftpd_dataclose(fsd);
    }
}

static void ftpd_dataclose(struct ftpd_datastate *fsd)
{
    if(fsd == NULL)
        return;
    if(fsd->datapcb) {
        tcp_arg(fsd->datapcb, NULL);
        tcp_sent(fsd->datapcb, NULL);
        tcp_recv(fsd->datapcb, NULL);
        tcp_err(fsd->datapcb, NULL);
        tcp_close(fsd->datapcb);
        fsd->datapcb = NULL;
    }
    if(fsd->msgfs) {
	    fsd->msgfs->datafs = NULL;
    }
	sfifo_close(&fsd->fifo);
    if(fsd->vfs_dir) {
        vfs_closedir(fsd->vfs_dir);
        fsd->vfs_dir = NULL;
    }
    if(fsd->vfs_file) {
        vfs_close(fsd->vfs_file);
        fsd->vfs_file = NULL;
    }
	free(fsd);
}

static void send_data(struct ftpd_datastate *fsd)
{
	err_t err;
	u16_t len;

	if (sfifo_used(&fsd->fifo) > 0) {
		int i;

		/* We cannot send more data than space available in the send
		   buffer. */
		if (tcp_sndbuf(fsd->datapcb) < sfifo_used(&fsd->fifo)) {
			len = tcp_sndbuf(fsd->datapcb);
		} else {
			len = (u16_t) sfifo_used(&fsd->fifo);
		}

		i = fsd->fifo.readpos;
		if ((i + len) > fsd->fifo.size) {
			err = tcp_write(fsd->datapcb, fsd->fifo.buffer + i, (u16_t)(fsd->fifo.size - i), 1);
			if (err != ERR_OK) {
				SERR("send_data: error writing!\n");
				return;
			}
			len -= fsd->fifo.size - i;
			fsd->fifo.readpos = 0;
			i = 0;
		}

		err = tcp_write(fsd->datapcb, fsd->fifo.buffer + i, len, 1);
		if (err != ERR_OK) {
			SERR("send_data: error writing!\n");
			return;
		}
		fsd->fifo.readpos += len;
	}
}

static void send_file(struct ftpd_datastate *fsd)
{
	if (!fsd->connected)
		return;

	if (fsd->vfs_file) {
		char buffer[2048];
		int len;

		len = sfifo_space(&fsd->fifo);
		if (len == 0) {
			send_data(fsd);
			return;
		}
		if (len > 2048)
			len = 2048;
		len = vfs_read(buffer, 1, len, fsd->vfs_file);
		if (len == 0) {
			if (vfs_eof(fsd->vfs_file) == 0)
				return;
			vfs_close(fsd->vfs_file);
			fsd->vfs_file = NULL;
			return;
		}
		sfifo_write(&fsd->fifo, buffer, len);
		send_data(fsd);
	} else {
		struct ftpd_msgstate *fsm;

		if (sfifo_used(&fsd->fifo) > 0) {
			send_data(fsd);
			return;
		}
		fsm = fsd->msgfs;
		ftpd_dataclose(fsd);
		fsm->state = FTPD_IDLE;
		send_msg(fsm, msg226);
		return;
	}
}

static char * format_dentry(char * buffer, size_t size, struct ftpd_datastate *fsd, int current_year, int * len)
{
    vfs_stat_t st;
    char mode_str[16] = {0};
    struct tm *p_time, s_time;

    if(vfs_stat(fsd->msgfs->vfs, fsd->vfs_dirent->d_name, &st) != 0)
        return NULL;

    p_time = gmtime_r(&st.st_mtime, &s_time);
    if(NULL == p_time)
        return NULL;

    vfs_mode_string(st.st_mode, mode_str);
    
	if (s_time.tm_year == current_year)
        *len = snprintf(buffer, size, "%s   1 %d     %d  %11lu %s %02i %02d:%02i %s\r\n", 
        mode_str,
        st.st_uid, 
        st.st_gid, 
        st.st_size, 
        month_table[s_time.tm_mon], 
        s_time.tm_mday, 
        s_time.tm_hour, 
        s_time.tm_min, 
        fsd->vfs_dirent->d_name);
	else
        *len = snprintf(buffer, size, "%s   1 %d     %d  %11lu %s %02i %5d %s\r\n", 
        mode_str,
        st.st_uid, 
        st.st_gid, 
        st.st_size, 
        month_table[s_time.tm_mon], 
        s_time.tm_mday, 
        s_time.tm_year + 1900, 
        fsd->vfs_dirent->d_name);

    return buffer;
}

static void send_next_directory(struct ftpd_datastate *fsd, int shortlist)
{
	char buffer[4096];
	int len;

    int current_year = 1900;
    struct tm s_time, * p_time;
    time_t current_time;

    time(&current_time);
    p_time = gmtime_r(&current_time, &s_time);
    if(NULL != p_time) {
        current_year = p_time->tm_year;
    }

	while (1) {
	if (fsd->vfs_dirent == NULL)
		fsd->vfs_dirent = vfs_readdir(fsd->vfs_dir);

	if (fsd->vfs_dirent) {
		if (shortlist) {
			len = snprintf(buffer, sizeof(buffer), "%s\r\n", fsd->vfs_dirent->d_name);
			if (sfifo_space(&fsd->fifo) < len) {
				send_data(fsd);
				return;
			}
			sfifo_write(&fsd->fifo, buffer, len);
			fsd->vfs_dirent = NULL;
		} else {
            if(format_dentry(buffer, sizeof(buffer), fsd, current_year, &len)) {
                if (sfifo_space(&fsd->fifo) < len) {
                    send_data(fsd);
                    return;
                }
                sfifo_write(&fsd->fifo, buffer, len);
            }
			fsd->vfs_dirent = NULL;
		}
	} else {
		struct ftpd_msgstate *fsm;

		if (sfifo_used(&fsd->fifo) > 0) {
			send_data(fsd);
			return;
		}
		fsm = fsd->msgfs;
		ftpd_dataclose(fsd);
		fsm->state = FTPD_IDLE;
		send_msg(fsm, msg226);
		return;
	}
	}
}

static err_t ftpd_datasent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	struct ftpd_datastate *fsd = (struct ftpd_datastate *)arg;
    
    LWIP_UNUSED_ARG(len);
    LWIP_UNUSED_ARG(pcb);

	switch (fsd->msgfs->state) {
	case FTPD_LIST:
		send_next_directory(fsd, 0);
		break;
	case FTPD_NLST:
		send_next_directory(fsd, 1);
		break;
	case FTPD_RETR:
		send_file(fsd);
		break;
	default:
		break;
	}

	return ERR_OK;
}

static err_t ftpd_datarecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	struct ftpd_datastate *fsd = arg;

	if (err == ERR_OK && p != NULL) {
		struct pbuf *q;
		u16_t tot_len;

		for (q = p; q != NULL; q = q->next) {
			int len = 0;
            if(NULL != fsd->vfs_file)
			    len = vfs_write(q->payload, 1, q->len, fsd->vfs_file);
            else
                len = q->len;
			tot_len += len;
			if (len != q->len)
				break;
		}

		/* Inform TCP that we have taken the data. */
		tcp_recved(pcb, tot_len);

		pbuf_free(p);
	}
	if (err == ERR_OK && p == NULL) {
		struct ftpd_msgstate *fsm;

		fsm = fsd->msgfs;

		vfs_close(fsd->vfs_file);
		fsd->vfs_file = NULL;
		ftpd_dataclose(fsd);
		fsm->state = FTPD_IDLE;
		send_msg( fsm, msg226);
	}

	return ERR_OK;
}

static err_t ftpd_dataconnected(void *arg, struct tcp_pcb *pcb, err_t err)
{
	struct ftpd_datastate *fsd = arg;

    LWIP_UNUSED_ARG(err);

	fsd->datapcb = pcb;
	fsd->connected = 1;

	/* Tell TCP that we wish to be informed of incoming data by a call
	   to the http_recv() function. */
	tcp_recv(pcb, ftpd_datarecv);

	/* Tell TCP that we wish be to informed of data that has been
	   successfully sent by a call to the ftpd_sent() function. */
	tcp_sent(pcb, ftpd_datasent);

	tcp_err(pcb, ftpd_dataerr);

	switch (fsd->msgfs->state) {
	case FTPD_LIST:
		send_next_directory(fsd, 0);
		break;
	case FTPD_NLST:
		send_next_directory(fsd, 1);
		break;
	case FTPD_RETR:
		send_file(fsd);
		break;
	default:
		break;
	}

	return ERR_OK;
}

static err_t ftpd_dataaccept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	struct ftpd_datastate *fsd = arg;

    LWIP_UNUSED_ARG(err);

    /* close old listen socket */
    if(fsd->datapcb != NULL) {
        tcp_close(fsd->datapcb);
        fsd->datapcb = NULL;
    }

    SDBG("+++++++++++++++new data pcb %p++++++++++++++++\n", (void *)pcb);
	fsd->datapcb = pcb;
	fsd->connected = 1;

	/* Tell TCP that we wish to be informed of incoming data by a call
	   to the http_recv() function. */
	tcp_recv(pcb, ftpd_datarecv);

	/* Tell TCP that we wish be to informed of data that has been
	   successfully sent by a call to the ftpd_sent() function. */
	tcp_sent(pcb, ftpd_datasent);

	tcp_err(pcb, ftpd_dataerr);

	switch (fsd->msgfs->state) {
	case FTPD_LIST:
		send_next_directory(fsd,0);
		break;
	case FTPD_NLST:
		send_next_directory(fsd,1);
		break;
	case FTPD_RETR:
		send_file(fsd);
		break;
	default:
		break;
	}

	return ERR_OK;
}

static int open_dataconnection(struct ftpd_msgstate *fsm)
{
    SDBG("open_dataconnection called passive = %d\n", fsm->passive);

	if (fsm->passive)
		return 0;

	/* Allocate memory for the structure that holds the state of the
	   connection. */
	fsm->datafs = malloc(sizeof(struct ftpd_datastate));
    memset(fsm->datafs, 0, sizeof(struct ftpd_datastate));

	if (fsm->datafs == NULL) {
		send_msg(fsm, msg451);
		return 1;
	}

	fsm->datafs->msgfs = fsm;
	sfifo_init(&fsm->datafs->fifo, 2000);

	fsm->datafs->datapcb = tcp_new();
	tcp_bind(fsm->datafs->datapcb, &fsm->msgpcb->local_ip, 20);
       
	/* Tell TCP that this is the structure we wish to be passed for our
	   callbacks. */
	tcp_arg(fsm->datafs->datapcb, fsm->datafs);
	tcp_err(fsm->datafs->datapcb, ftpd_dataerr);       
	if(tcp_connect(fsm->datafs->datapcb, &fsm->dataip, fsm->dataport, ftpd_dataconnected) != ERR_OK)
    {
           ftpd_dataclose(fsm->datafs);
           return -1;
    }

	return 0;
}

static void cmd_user(const char *arg, struct ftpd_msgstate *fsm)
{
	send_msg(fsm, msg331);
	fsm->state = FTPD_PASS;
    
    LWIP_UNUSED_ARG(arg);

	/*
	   send_msg(pcb, fs, msgLoginFailed);
	   fs->state = FTPD_QUIT;
	 */
}

static void cmd_pass(const char *arg, struct ftpd_msgstate *fsm)
{
    LWIP_UNUSED_ARG(arg);

	send_msg(fsm, msg230);
	fsm->state = FTPD_IDLE;
	/*
	   send_msg(pcb, fs, msgLoginFailed);
	   fs->state = FTPD_QUIT;
	 */
}

static void cmd_port(const char *arg, struct ftpd_msgstate *fsm)
{
	int nr;
	unsigned pHi, pLo;
	unsigned ip[4];

	nr = sscanf(arg, "%u,%u,%u,%u,%u,%u", &(ip[0]), &(ip[1]), &(ip[2]), &(ip[3]), &pHi, &pLo);
	if (nr != 6) {
		send_msg(fsm, msg501);
	} else {
		IP4_ADDR(&fsm->dataip, (u8_t) ip[0], (u8_t) ip[1], (u8_t) ip[2], (u8_t) ip[3]);
		fsm->dataport = ((u16_t) pHi << 8) | (u16_t) pLo;
		send_msg(fsm, msg200);
	}
}

static void cmd_quit(const char *arg, struct ftpd_msgstate *fsm)
{
    LWIP_UNUSED_ARG(arg);
	send_msg(fsm, msg221);
	fsm->state = FTPD_QUIT;
}

static void cmd_cwd(const char *arg, struct ftpd_msgstate *fsm)
{
	if (!vfs_chdir(fsm->vfs, arg)) {
		send_msg(fsm, msg250);
	} else {
		send_msg(fsm, msg550);
	}
}

static void cmd_cdup(const char *arg, struct ftpd_msgstate *fsm)
{
    LWIP_UNUSED_ARG(arg);
	if (!vfs_chdir(fsm->vfs, "..")) {
		send_msg(fsm, msg250);
	} else {
		send_msg(fsm, msg550);
	}
}

static void cmd_pwd(const char *arg, struct ftpd_msgstate *fsm)
{
	char *path;

    LWIP_UNUSED_ARG(arg);

	if ((path = vfs_getcwd(fsm->vfs, NULL, 0))) {
		send_msg(fsm, msg257PWD, path);
		free(path);
	}
}

static void cmd_list_common(const char *arg, struct ftpd_msgstate *fsm, int shortlist)
{
	vfs_dir_t *vfs_dir;

    SDBG("cmd_list_common arg = %s %s %s\n", arg, fsm->vfs->list_dir, fsm->vfs->cwd);

	vfs_dir = vfs_opendir(fsm->vfs, arg);

	if (!vfs_dir) {
		send_msg(fsm, msg451);
		return;
	}


	if (open_dataconnection(fsm) != 0) {
		vfs_closedir(vfs_dir);
		return;
	}

	fsm->datafs->vfs_dir = vfs_dir;
	fsm->datafs->vfs_dirent = NULL;
	if (shortlist != 0)
		fsm->state = FTPD_NLST;
	else
		fsm->state = FTPD_LIST;

	send_msg(fsm, msg150);
}

static void cmd_nlst(const char *arg, struct ftpd_msgstate *fsm)
{
	cmd_list_common(arg, fsm, 1);
}

static void cmd_list(const char *arg, struct ftpd_msgstate *fsm)
{
	cmd_list_common(arg, fsm, 0);
}

static void cmd_retr(const char *arg, struct ftpd_msgstate *fsm)
{
	vfs_file_t *vfs_file;
	vfs_stat_t st;

	vfs_stat(fsm->vfs, arg, &st);
	if (!VFS_ISREG(st.st_mode)) {
		send_msg(fsm, msg550);
		return;
	}
	vfs_file = vfs_open(fsm->vfs, arg, "rb");
	if (!vfs_file) {
		send_msg(fsm, msg550);
		return;
	}

	send_msg(fsm, msg150recv, arg, st.st_size);

	if (open_dataconnection(fsm) != 0) {
		vfs_close(vfs_file);
		return;
	}

	fsm->datafs->vfs_file = vfs_file;
	fsm->state = FTPD_RETR;
}

static void cmd_stor(const char *arg, struct ftpd_msgstate *fsm)
{
	vfs_file_t *vfs_file;
	if (!(vfs_file = vfs_open(fsm->vfs, arg, "wb"))) {
		send_msg(fsm, msg550);
		return;
	}

	send_msg(fsm, msg150stor, arg);

	if (open_dataconnection(fsm) != 0) {
		vfs_close(vfs_file);
		return;
	}

	fsm->datafs->vfs_file = vfs_file;
	fsm->state = FTPD_STOR;
}

static void cmd_noop(const char *arg, struct ftpd_msgstate *fsm)
{
    LWIP_UNUSED_ARG(arg);
	send_msg(fsm, msg200);
}

static void cmd_syst(const char *arg, struct ftpd_msgstate *fsm)
{
    LWIP_UNUSED_ARG(arg);
	send_msg(fsm, msg214SYST, "UNIX");
}

static void cmd_pasv(const char *arg, struct ftpd_msgstate *fsm)
{
	static u16_t port = 4096;
	static u16_t start_port = 4096;
	struct tcp_pcb *temppcb;

    LWIP_UNUSED_ARG(arg);

	/* Allocate memory for the structure that holds the state of the
	   connection. */
	fsm->datafs = malloc(sizeof(struct ftpd_datastate));

	if (fsm->datafs == NULL) {
		send_msg(fsm, msg451);
		return;
	}
	memset(fsm->datafs, 0, sizeof(struct ftpd_datastate));

    SDBG("---cmd_pasv--\n");

	fsm->datafs->datapcb = tcp_new();
	if (!fsm->datafs->datapcb) {
		ftpd_dataclose(fsm->datafs);
		send_msg(fsm, msg451);
		return;
	}

	sfifo_init(&fsm->datafs->fifo, 2000);

	start_port = port_from;

	while (1) {
		err_t err;

		if(++port > port_to)
			port = port_from;
	
		fsm->dataport = port;
		err = tcp_bind(fsm->datafs->datapcb, &fsm->msgpcb->local_ip, fsm->dataport);
		if (err == ERR_OK)
			break;
		if (start_port == port)
			err = ERR_CLSD;
		if (err == ERR_USE)
			continue;
		if (err != ERR_OK) {
			ftpd_dataclose(fsm->datafs);
			return;
		}
	}
    

	temppcb = tcp_listen(fsm->datafs->datapcb);
	if (!temppcb) {
		ftpd_dataclose(fsm->datafs);
		return;
	}
	fsm->datafs->datapcb = temppcb;
 
	fsm->passive = 1;
	fsm->datafs->connected = 0;
	fsm->datafs->msgfs = fsm;

	/* Tell TCP that this is the structure we wish to be passed for our
	   callbacks. */
	tcp_arg(fsm->datafs->datapcb, fsm->datafs);
	tcp_accept(fsm->datafs->datapcb, ftpd_dataaccept);

    send_msg(fsm, msg227, ip4_addr1(&fsm->msgpcb->local_ip), ip4_addr2(&fsm->msgpcb->local_ip), ip4_addr3(&fsm->msgpcb->local_ip), ip4_addr4(&fsm->msgpcb->local_ip), (fsm->dataport >> 8) & 0xff, (fsm->dataport) & 0xff);

}

static void cmd_abrt(const char *arg, struct ftpd_msgstate *fsm)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(fsm);

	if (fsm->datafs != NULL) {
            ftpd_dataclose(fsm->datafs);
    }
	fsm->state = FTPD_IDLE;
}

static void cmd_type(const char *arg, struct ftpd_msgstate *fsm)
{
	SDBG("Got TYPE -%s-\n", arg);
	send_msg(fsm, msg200);
}

static void cmd_mode(const char *arg, struct ftpd_msgstate *fsm)
{
	SDBG("Got MODE -%s-\n", arg);
	send_msg(fsm, msg502);
}

static void cmd_rnfr(const char *arg, struct ftpd_msgstate *fsm)
{
	if (arg == NULL) {
		send_msg(fsm, msg501);
		return;
	}
	if (*arg == '\0') {
		send_msg(fsm, msg501);
		return;
	}
	if (fsm->renamefrom)
		free(fsm->renamefrom);
	fsm->renamefrom = strdup(arg);
	if (fsm->renamefrom == NULL) {
		send_msg(fsm, msg451);
		return;
	}
	fsm->state = FTPD_RNFR;
	send_msg(fsm, msg350);
}

static void cmd_rnto(const char *arg, struct ftpd_msgstate *fsm)
{
	if (fsm->state != FTPD_RNFR) {
		send_msg(fsm, msg503);
		return;
	}
	fsm->state = FTPD_IDLE;
	if (arg == NULL) {
		send_msg(fsm, msg501);
		return;
	}
	if (*arg == '\0') {
		send_msg(fsm, msg501);
		return;
	}
	if (vfs_rename(fsm->vfs, fsm->renamefrom, arg)) {
		send_msg(fsm, msg450);
	} else {
		send_msg(fsm, msg250);
	}
}

static void cmd_mkd(const char *arg, struct ftpd_msgstate *fsm)
{
	if (arg == NULL) {
		send_msg(fsm, msg501);
		return;
	}
	if (*arg == '\0') {
		send_msg(fsm, msg501);
		return;
	}
	if (vfs_mkdir(fsm->vfs, arg, VFS_IRWXU | VFS_IRWXG | VFS_IRWXO) != 0) {
		send_msg(fsm, msg550);
	} else {
		send_msg(fsm, msg257, arg);
	}
}

static void cmd_rmd(const char *arg, struct ftpd_msgstate *fsm)
{
	vfs_stat_t st;

	if (arg == NULL) {
		send_msg(fsm, msg501);
		return;
	}
	if (*arg == '\0') {
		send_msg(fsm, msg501);
		return;
	}

    if(NULL != fsm->vfs->list_dir) {
        free(fsm->vfs->list_dir);
        fsm->vfs->list_dir = NULL;
    }

	if (vfs_stat(fsm->vfs, arg, &st) != 0) {
		send_msg(fsm, msg550);
		return;
	}
	if (!VFS_ISDIR(st.st_mode)) {
		send_msg(fsm, msg550);
		return;
	}
	if (vfs_rmdir(fsm->vfs, arg) != 0) {
		send_msg(fsm, msg550);
	} else {
		send_msg(fsm, msg250);
	}
}

static void cmd_dele(const char *arg, struct ftpd_msgstate *fsm)
{
	vfs_stat_t st;

	if (arg == NULL) {
		send_msg(fsm, msg501);
		return;
	}
	if (*arg == '\0') {
		send_msg(fsm, msg501);
		return;
	}
	if (vfs_stat(fsm->vfs, arg, &st) != 0) {
		send_msg(fsm, msg550);
		return;
	}
	if (!VFS_ISREG(st.st_mode)) {
		send_msg(fsm, msg550);
		return;
	}
	if (vfs_remove(fsm->vfs, arg) != 0) {
		send_msg(fsm, msg550);
	} else {
		send_msg(fsm, msg250);
	}
}

struct ftpd_command {
	const char *cmd;
	void (*func) (const char *arg, struct ftpd_msgstate * fsm);
};

static struct ftpd_command ftpd_commands[] = {
	{"USER", cmd_user},
	{"PASS", cmd_pass},
	{"PORT", cmd_port},
	{"QUIT", cmd_quit},
	{"CWD", cmd_cwd},
	{"CDUP", cmd_cdup},
	{"PWD", cmd_pwd},
	{"XPWD", cmd_pwd},
	{"NLST", cmd_nlst},
	{"LIST", cmd_list},
	{"RETR", cmd_retr},
	{"STOR", cmd_stor},
	{"NOOP", cmd_noop},
	{"SYST", cmd_syst},
	{"ABOR", cmd_abrt},
	{"TYPE", cmd_type},
	{"MODE", cmd_mode},
	{"RNFR", cmd_rnfr},
	{"RNTO", cmd_rnto},
	{"MKD", cmd_mkd},
	{"XMKD", cmd_mkd},
	{"RMD", cmd_rmd},
	{"XRMD", cmd_rmd},
	{"DELE", cmd_dele},
	{"PASV", cmd_pasv},
	{NULL, NULL}
};

static void send_msgdata(struct ftpd_msgstate *fsm)
{
	err_t err;
	u16_t len;

    if(NULL == fsm)
        return;
       
	if (sfifo_used(&fsm->fifo) > 0) {
		int i;

		/* We cannot send more data than space available in the send
		   buffer. */
		if (tcp_sndbuf(fsm->msgpcb) < sfifo_used(&fsm->fifo)) {
			len = tcp_sndbuf(fsm->msgpcb);
		} else {
			len = (u16_t) sfifo_used(&fsm->fifo);
		}

		i = fsm->fifo.readpos;
		if ((i + len) > fsm->fifo.size) {
			err = tcp_write(fsm->msgpcb, fsm->fifo.buffer + i, (u16_t)(fsm->fifo.size - i), 1);
			if (err != ERR_OK) {
				SERR("send_msgdata: error writing!\n");
				return;
			}
			len -= fsm->fifo.size - i;
			fsm->fifo.readpos = 0;
			i = 0;
		}

		err = tcp_write(fsm->msgpcb, fsm->fifo.buffer + i, len, 1);
		if (err != ERR_OK) {
			SERR("send_msgdata: error writing!\n");
			return;
		}
		fsm->fifo.readpos += len;
	}
}

static void send_msg(struct ftpd_msgstate *fsm, const char *msg, ...)
{
	va_list arg;
	char buffer[1024];
	int len;
           
    if(NULL == fsm)
        return;

	va_start(arg, msg);
	vsnprintf(buffer, sizeof(buffer) - 2, msg, arg);
	va_end(arg);
	strcat(buffer, "\r\n");
	len = strlen(buffer);
	if (sfifo_space(&fsm->fifo) < len)
		return;
	sfifo_write(&fsm->fifo, buffer, len);
	SDBG("response: %s", buffer);
	send_msgdata(fsm);
}
    
static void ftpd_msgclose(struct ftpd_msgstate *fsm);

static void ftpd_msgerr(void *arg, err_t err)
{
	struct ftpd_msgstate *fsm = arg;
	SDBG("ftpd_msgerr: %s (%i) %p\n", lwip_strerr(err), err, arg);

    if(fsm) {
        fsm->msgpcb = NULL; /* already closed! */
        ftpd_msgclose(fsm);
    }
}

static void ftpd_msgclose(struct ftpd_msgstate *fsm)
{
    
    SDBG("ftpd_msgclose called, fsm = %p\n", (void*)fsm);

    if(fsm == NULL)

        return;
    if(fsm->msgpcb) {
        
        tcp_arg(fsm->msgpcb, NULL);
        tcp_sent(fsm->msgpcb, NULL);
        tcp_recv(fsm->msgpcb, NULL); 
        tcp_err(fsm->msgpcb, NULL);
        tcp_close(fsm->msgpcb);
        fsm->msgpcb = NULL;
    }

	if (fsm->datafs) {
		ftpd_dataclose(fsm->datafs);
        fsm->datafs = NULL;
    }

	sfifo_close(&fsm->fifo);

    if(fsm->vfs != NULL) {
	    vfs_closefs(fsm->vfs);
        fsm->vfs = NULL;
    }

	if (fsm->renamefrom) {
		free(fsm->renamefrom);
        fsm->renamefrom = NULL;
    }

    transfer_session_cnt --;

    if(transfer_session_cnt <= 0 && transfer_status == STOPPING) {

        transfer_status = STOP;

    }   
	free(fsm);
}

static err_t ftpd_msgsent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	struct ftpd_msgstate *fsm = arg;

    LWIP_UNUSED_ARG(len);

    LWIP_UNUSED_ARG(pcb);    

	if (pcb->state > ESTABLISHED)
		return ERR_OK;

	if ((sfifo_used(&fsm->fifo) == 0) && (fsm->state == FTPD_QUIT)) {
		ftpd_msgclose(fsm);
    }

	send_msgdata(fsm);

	return ERR_OK;
}

static err_t ftpd_msgrecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	char *text;
	struct ftpd_msgstate *fsm = arg;

	if (err == ERR_OK && p != NULL) {

		/* Inform TCP that we have taken the data. */
		tcp_recved(pcb, p->tot_len);

		text = malloc(p->tot_len + 1);
		if (text) {
			char cmd[5];
			struct pbuf *q;
			char *pt = text;
			struct ftpd_command *ftpd_cmd;

			for (q = p; q != NULL; q = q->next) {
				bcopy(q->payload, (void *)pt, q->len);
				pt += q->len;
			}
			*pt = '\0';

			pt = &text[strlen(text) - 1];
			while (((*pt == '\r') || (*pt == '\n')) && pt >= text)
				*pt-- = '\0';

			SDBG("query: %s\n", text);

			strncpy(cmd, text, 4);
			for (pt = cmd; isalpha(*pt) && pt < &cmd[4]; pt++)
				*pt = toupper(*pt);
			*pt = '\0';

			for (ftpd_cmd = ftpd_commands; ftpd_cmd->cmd != NULL; ftpd_cmd++) {
				if (!strcmp(ftpd_cmd->cmd, cmd))
					break;
			}

			if (strlen(text) < (strlen(cmd) + 1))
				pt = (char *)"";
			else
				pt = &text[strlen(cmd) + 1];

			if (ftpd_cmd->func)
				ftpd_cmd->func(pt, fsm);
			else
				send_msg(fsm, msg502);

			free(text);
		}
		pbuf_free(p);
	}

	return ERR_OK;
}

static err_t ftpd_msgpoll(void *arg, struct tcp_pcb *pcb)
{
	struct ftpd_msgstate *fsm = arg;

    LWIP_UNUSED_ARG(pcb);

	if (fsm == NULL)
		return ERR_OK;

	if (pcb->state != ESTABLISHED) {
        ftpd_msgclose(fsm);
		return ERR_OK;
    }

    fsm->keepalive_cnt ++;
    if(fsm->keepalive_cnt > TRANSFER_KEEP_ALIVE_INTERVAL) {
        fsm->keepalive_cnt = 0;
        tcp_keepalive(pcb);
        pcb->keep_cnt_sent ++;
        SDBG("ftpd_msgpoll pcb->keep_cnt_sent %d, max %d\n", pcb->keep_cnt_sent, TRANSFER_MAX_KEEP_ALIVE_CNT);
        if(pcb->keep_cnt_sent > TRANSFER_MAX_KEEP_ALIVE_CNT) {
            ftpd_msgclose(fsm);
            return ERR_OK;
        }
    }

 
    if(transfer_stop_flag) {

        tcp_abort(fsm->msgpcb);

        return ERR_OK;

    }

	if (fsm->datafs) {
		if (fsm->datafs->connected) {
			switch (fsm->state) {
			case FTPD_LIST:
				send_next_directory(fsm->datafs, 0);
				break;
			case FTPD_NLST:
				send_next_directory(fsm->datafs, 1);
				break;
			case FTPD_RETR:
				send_file(fsm->datafs);
				break;
			default:
				break;
			}
		}
	}

	return ERR_OK;
}
static int ftpd_msginit( struct tcp_pcb *pcb, struct ftpd_msgstate *fsm)

{
    fsm->msgpcb = pcb;
	/* Initialize the structure. */

    sfifo_init(&fsm->fifo, 2000);
	fsm->state = FTPD_IDLE;
    fsm->vfs = vfs_openfs();
	if (!fsm->vfs) {  
		goto fail;
    }


    transfer_session_cnt ++;

    /* Tell TCP that this is the structure we wish to be passed for our
	   callbacks. */

    tcp_arg(pcb, fsm);

	/* Tell TCP that we wish to be informed of incoming data by a call
	   to the http_recv() function. */
 
	tcp_recv(pcb, ftpd_msgrecv);

	/* Tell TCP that we wish be to informed of data that has been
	   successfully sent by a call to the ftpd_sent() function. */

    tcp_sent(pcb, ftpd_msgsent);
    tcp_err(pcb, ftpd_msgerr);
    tcp_poll(pcb, ftpd_msgpoll, 1);
    return 0;

fail:
    return -1;

}


static err_t ftpd_msgaccept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	struct ftpd_msgstate *fsm;

    LWIP_UNUSED_ARG(err);
    LWIP_UNUSED_ARG(arg);

	/* Allocate memory for the structure that holds the state of the
	   connection. */
	fsm = malloc(sizeof(struct ftpd_msgstate));

	if (fsm == NULL) {
		SERR("ftpd_msgaccept: Out of memory\n");
		goto fail;
	}
	memset(fsm, 0, sizeof(struct ftpd_msgstate));

    if(ftpd_msginit(pcb, fsm) < 0) {
        return ERR_OK;
    }
    
send_msg(fsm, msg220);
    return ERR_OK;
fail:
    ftpd_msgclose(fsm);
    return ERR_OK;
}

static int do_start_transfer(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)

{
    
    int ch;
    err_t err;
    struct tcp_pcb *pcb;
    optarg = NULL;
    optind = 0;

    transfer_port = TRANSFER_SERVICE_PORT;
    port_from = TRANSFER_SERVICE_PASV_PORT_FROM;
    port_to = TRANSFER_SERVICE_PASV_PORT_TO;
    
    if(transfer_status != STOP ) {   
        cmd_printf(out, "ftp service still running");     
        return -1;
    }

    
    while( (ch = getopt(argc, argv, "b:f:t:")) != -1) {
        switch(ch) {
            case 'b':
                transfer_port = atoi(optarg);
                break;
            case 'f':
                port_from = atoi(optarg);
                break;
             case 't':
                port_to = atoi(optarg);
                break;
             default:
             cmd_usage(slot, out);
             return -1;
        }
    }
    
    if(port_from > port_to) {
        cmd_usage(slot, out);
        return -1;
    }


    if(transfer_port <= 0) {
        cmd_usage(slot, out);
        return -1;
    }


    transfer_pcb = tcp_new();

    transfer_stop_flag = 0;
    if((err = tcp_bind(transfer_pcb, IP_ADDR_ANY, transfer_port)) != ERR_OK) {
        cmd_printf(out, "can not bind to port %d (%s)\n", transfer_port, lwip_strerr(err));
        tcp_close(transfer_pcb);
        transfer_pcb = NULL;
        return -1;
    }

	pcb = tcp_listen(transfer_pcb);

    if(NULL == pcb) {
        cmd_printf(out, "can not set to listen state\n");
        tcp_close(transfer_pcb);
        transfer_pcb = NULL;
        return -1;
    }

    transfer_pcb = pcb;
    tcp_accept(transfer_pcb, ftpd_msgaccept);
    transfer_status = RUNNING;
    cmd_printf(out, "ftp service started\n");
    return 0;
}



static int do_stop_transfer(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)

{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);

    if(transfer_session_cnt != 0) {
        transfer_status = STOPPING;
    } else {
        transfer_status = STOP;
    }

    transfer_stop_flag = 1;

    if(NULL != transfer_pcb) {
        tcp_close(transfer_pcb);
        transfer_pcb = NULL;
    }
    
    cmd_printf(out, "stop command issued, use ftp status to watch status\n");

    return 0;
}
        


static int do_get_transfer_status(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)

{
    LWIP_UNUSED_ARG(slot);
    LWIP_UNUSED_ARG(argc);
    LWIP_UNUSED_ARG(argv);
    cmd_printf(out, "ftp status: %s, port is %d, session count %d\n", 
        status_str[transfer_status], transfer_port, transfer_session_cnt);

    return 0;

}

static int do_cmd_ftp(cmd_slot_t * slot, cmd_out_handle_t * out, int argc, char ** argv)
{
    int ret = -1;
    if(argc < 2) {
        cmd_usage(slot, out);
        return ret;
    }

    argc --;
    argv ++;

    if(strcmp(argv[0], "start") == 0) {
        ret = do_start_transfer(slot, out, argc, argv);
    } else if(strcmp(argv[0], "stop") == 0) {
        ret = do_stop_transfer(slot, out, argc, argv);
    } else {
        ret = do_get_transfer_status(slot, out, argc, argv);
    }

    return ret;
}

void transfer_service_init(void)
{

    reg_cmd(do_cmd_ftp, "ftp", "usage:\n"
                               "    ftp start <-b bind port> <-f pasv port from> <-t pasv port to>\n"
                               "    ftp stop\n"
                               "    ftp status\n");
}

