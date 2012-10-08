/* [portagent] portagent.h :: global do-it-all include file.
** Copyright (C) 2007 fakehalo [v9@fakehalo.us]
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
**/


/* created at build time. */
#define PA_VERSION			"1.2"
#define PA_CMPTIME			"2010/06/08 01:49:41 UTC"

/* generic buffer sizes. */
#define PA_BUFSIZE_TINY			32
#define PA_BUFSIZE_SMALL		256
#define PA_BUFSIZE_MEDIUM		1024
#define PA_BUFSIZE_LARGE		4096
#define PA_BUFSIZE_GIANT		8192

/* exit() codes. */
#define PA_EXIT_SUCCESS			0
#define PA_EXIT_ERROR			1

/* return() types. */
#define PA_RETURN_SUCCESS		0
#define PA_RETURN_FAIL			1

/* pa_error() / pa_log related. */
#define PA_MSG_INFO			-1
#define PA_MSG_REG			0
#define PA_MSG_WRN			1
#define PA_MSG_ERR			2

/* pa_conn structure status. */
#define PA_CONN_NONE			0 /* no current action. */
#define PA_CONN_CONNECTING		1 /* in the process of connecting to the forwarder. (try) */
#define PA_CONN_CONNECTED		2 /* connected to the forwarder. (try) */
#define PA_CONN_REUSE			3 /* not used, will be recycled. */

#define PA_COMPLETE_FALSE		0 /* not a completed/forwarding connection. */
#define PA_COMPLETE_TRUE_FREE		1 /* complete connection, but still free the initial buffer. */
#define PA_COMPLETE_TRUE		2 /* complete connection. */
#define PA_COMPLETE_WAIT		3 /* one side has closed, but data is still buffered to send one way. */

/* "IF" related levels for processing. */
#define PA_IFLEVEL_NONE			0 /* not in a "IF" clause. */
#define PA_IFLEVEL_GOOD			1 /* (still) good, if a "USE" comes it's good. */
#define PA_IFLEVEL_SKIP			2 /* no match, if a "USE" comes don't use it. */

/* type of queue. */
#define PA_QUEUE_CONN			1
#define PA_QUEUE_FWD			2

/* defaults, if not specified otherwise. */
#define PA_DFL_CONF_FILE		"/etc/portagent.conf"
#define PA_DFL_LISTEN_BACKLOG		5
#define PA_DFL_LISTEN_LIMIT		50
#define PA_DFL_LISTEN_INITIAL		16436 /* highest MTU i've seen. */
#define PA_DFL_LISTEN_QUEUE		0 /* 0 = unlimited. */

/* mark out size specifications. */
#define PA_BYTE				1
#define PA_KILOBYTE			(PA_BYTE * 1024)
#define PA_MEGABYTE			(PA_KILOBYTE * 1024)
#define PA_GIGABYTE			(PA_MEGABYTE * 1024)

/* assumed maximum size for sizes. */
#define PA_SIZE_MAX			0xFFFFFFFF
#define PA_SIZE_MAX_BUF			PA_GIGABYTE

/* portagent "instruction type" enums. */
#define PA_NONE				0
#define PA_USE				1
#define PA_IF				2	/* IF DEFINED */
#define PA_IFL				3	/* IF LIKE */
#define PA_IFR				4	/* IF REGEXP */
#define PA_IP				5
#define PA_IP_NOT			6	
#define PA_PORT				7
#define PA_PORT_NOT			8
#define PA_WRITE_INSIDE			9
#define PA_WRITE_OUTSIDE		10
#define PA_TIMEOUT			11
#define PA_LISTEN			12
#define PA_WITH				13
#define PA_TRY				14
#define PA_BACKLOG			15
#define PA_LIMIT			16
#define PA_INITIAL			17
#define PA_QUEUE			18
#define PA_PIDFILE			19
#define PA_LOGFILE			20
#define PA_USER				21
#define PA_GROUP			22
#define PA_CHROOT			23
/* ... */
#define PA_BAD_INS			255


/* ./configure defines/etc. */
#include "../config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_STRING_H
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* no MSG_NOSIGNAL? oh well, it's just there to be safe. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* what i will do for setproctitle(). */
#define INT_SETPROCTITLE
#ifndef __APPLE_CC__
#ifndef __linux__
#undef INT_SETPROCTITLE
#endif
#endif
#ifdef INT_SETPROCTITLE
#ifndef LINEBUFFER
#define LINEBUFFER 4096
#endif
#endif
#ifndef INT_SETPROCTITLE
#ifndef HAVE_SETPROCTITLE
#define NO_SETPROCTITLE
#endif
#endif


/* config sotrage structures. */
struct pa_ins_s {
	unsigned char type;
	unsigned int len;
	char *ins;
};
struct pa_root_s {
	struct sockaddr_in sock;
	struct pa_ins_s **pa_ins;
	unsigned int pa_ins_i;
	unsigned int backlog;
	unsigned int bufsize;
	unsigned int limit;
	unsigned int used;
	unsigned int queue;
	signed int fd;
};
/* per-connection related structures. */
struct pa_queue_s {
	char data[PA_BUFSIZE_GIANT + 1];
	unsigned int len;
	unsigned int off;
	struct pa_queue_s *next;
};
struct pa_conn_s {
	struct sockaddr_in conn_sock;
	struct sockaddr_in fwd_sock;
	char *data;
	unsigned int data_size;
	ssize_t len;
	time_t timeout;
	unsigned int pa_root;
	unsigned int pa_ins_i;
	unsigned char status;
	unsigned char complete;
	signed int conn_fd;
	signed int fwd_fd;
	struct pa_queue_s *conn_queue;
	struct pa_queue_s *conn_queue_last;
	unsigned char conn_queue_active;
	struct pa_queue_s *fwd_queue;
	struct pa_queue_s *fwd_queue_last;
	unsigned char fwd_queue_active;
	unsigned int queue;
	unsigned short pa_log_id;
};
/* for generic "IF DEFINED"'s. */
struct pa_ifmap_s {
	const char *name;
	unsigned char type;
	unsigned int len;
	char *ins;
};
/* static root config options. */
struct pa_conf_s {
	FILE *logfs;
	FILE *pidfs;
	char *logfile;
	char *pidfile;
	char *chroot;
	uid_t uid;
	gid_t gid;
	unsigned char background;
	unsigned char exit;
};
/* pseudo-setproctitle struct. */
#ifndef NO_SETPROCTITLE
struct pa_proctitle_s {
	char **argv;
	char *largv;
	char *name;
};
#endif


/* prototypes. */

/* conf.c */
signed int pa_ifmap_find(char *);
unsigned char pa_instruction_type(char *);
void pa_conf_parser(char *);
char *pa_trim(char *);
unsigned int pa_literal_parser(char *);

/* msg.c */
void pa_error(unsigned char, char *, ...);
void pa_log(signed int, char *, ...);

/* misc.c */
void pa_signal(signed int);
void pa_queue_new(unsigned int, char *, unsigned int, unsigned char);
void pa_queue_free(unsigned int);
void pa_timeout_set(unsigned int, signed int);
signed int pa_timeout_diff(unsigned int);
unsigned char pa_int_range(unsigned int, char *);
unsigned char pa_ip_match(struct sockaddr_in, char *);
char *pa_port_str();
FILE *pa_fopen(char *, char *, mode_t);
struct sockaddr_in pa_atos(char *);
#ifdef HAVE_GETRLIMIT
void pa_set_limit();
#endif
void pa_set_dir(char *);
void pa_set_perm(uid_t, gid_t);
unsigned int pa_parse_size(char *, unsigned int);
unsigned char pa_likecmp(char *, unsigned int, char *, unsigned int);
unsigned char pa_regcmp(char *, char *);
void pa_exit(signed int);

/* net.c */
void pa_set_nonblock(signed int);
signed int pa_shutdown(signed int);
ssize_t pa_send(unsigned int, unsigned char, char *, size_t, signed int);
ssize_t pa_send_split(unsigned int, unsigned char, char *, size_t, signed int);
fd_set pa_listen_fd_set();
fd_set pa_listen_wfd_set();
signed int pa_find_high_fd();
signed int pa_find_root_by_fd(signed int);
signed int pa_root_tot_conn(signed int);
signed int pa_conn_add(signed int, signed int);
void pa_conn_set(unsigned int, signed int, signed int);
void pa_conn_free(unsigned int);
signed int pa_try_conn(unsigned int, struct sockaddr_in);
signed int pa_listen_new(signed int);
void pa_listen_read(fd_set, fd_set);
void pa_listen_init();
void pa_listen_loop();

/* title.c */
#ifndef NO_SETPROCTITLE
void initsetproctitle(signed int, char **, char **);
#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *, ...);
#endif
#endif
