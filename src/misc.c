/* [portagent] misc.c :: miscellaneous functions for portagent.
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

#include "portagent.h"

/* externs. */
extern struct pa_conf_s pa_conf;
extern struct pa_root_s **pa_root;
extern signed int pa_root_i;
extern struct pa_conn_s **pa_conn;
extern signed int pa_conn_i;


/* all signals come to this. */
void pa_signal(signed int sig) {

#ifdef PA_DEBUG
	puts("+++ pa_signal()");
#endif

	/* all things coming here exit, only allow once. */
	if(pa_conf.exit) return;
	else pa_conf.exit = 1;

	switch(sig) {
		case SIGBUS:
		case SIGILL:
		case SIGSEGV:
			pa_log(PA_MSG_INFO, "portagent unrecoverable error: signal=%d", sig);			

			/* do as little as possible, straight exit; not clean. */
			exit(0);
			break;
		case SIGHUP:
		case SIGQUIT:
		case SIGTERM:
		case SIGINT:
		case SIGTSTP:
			pa_exit(0);
			break;
		default:
			break;
	}

#ifdef PA_DEBUG
	puts("--- pa_signal()");
#endif

	return;
}

/* make a new link in a conn/fwd sendq chain. (all buffers are PA_BUFSIZE_GIANT, so dont worry about size limits) */
void pa_queue_new(unsigned int i, char *data, unsigned int len, unsigned char type) {
	struct pa_queue_s *pa_queue;

	if(!len) return;

#ifdef PA_DEBUG
	puts("+++ pa_queue_new()");
#endif

	pa_conn[i]->queue += len;

	/* past our queue limit, if any? kill the connection. */
	if(pa_root[pa_conn[i]->pa_root]->queue && pa_conn[i]->queue > pa_root[pa_conn[i]->pa_root]->queue) {
		pa_log(i, "connection exceeded queue buffer limitiation. (%u > %u)", pa_conn[i]->queue, pa_root[pa_conn[i]->pa_root]->queue);
		pa_conn_free(i);
		return;
	}

	/* allocate our new connection queue element/structure link. */
	if(!(pa_queue = (struct pa_queue_s *)malloc(sizeof(struct pa_queue_s) + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for an element of a linked queue structure.");

	/* default stuff. */
	pa_queue->len = len;
	pa_queue->off = 0;
	pa_queue->next = 0;
	memcpy(pa_queue->data, data, len);

	/* link up with our list. */
	if(type == PA_QUEUE_CONN) {

		/* first time, start the list. */
		if(!pa_conn[i]->conn_queue)
			pa_conn[i]->conn_queue_last = pa_conn[i]->conn_queue = pa_queue;

		/* just another link in the chain. */
		else {
			pa_conn[i]->conn_queue_last->next = pa_queue;
			pa_conn[i]->conn_queue_last = pa_queue;
		}
	}

	/* PA_QUEUE_FWD */
	else {
		/* first time, start the list. */
		if(!pa_conn[i]->fwd_queue)
			pa_conn[i]->fwd_queue_last = pa_conn[i]->fwd_queue = pa_queue;

		/* just another link in the chain. */
		else {
			pa_conn[i]->fwd_queue_last->next = pa_queue;
			pa_conn[i]->fwd_queue_last = pa_queue;
		}
	}

#ifdef PA_DEBUG
	puts("--- pa_queue_new()");
#endif

	return;
}

/* free both conn/fwd sendq chains, if any. */
void pa_queue_free(unsigned int i) {
	struct pa_queue_s *pa_queue, *pa_queue_next;

#ifdef PA_DEBUG
	puts("+++ pa_queue_free()");
#endif

	/* free all queued conn chains for this connection. */
	pa_queue = pa_conn[i]->conn_queue;
	while(pa_queue) {

		/* find our next chain before we free this one. */
		pa_queue_next = pa_queue->next;

		free(pa_queue);
		pa_queue = pa_queue_next;
	}

	/* free all queued fwd chains for this connection. */
	pa_queue = pa_conn[i]->fwd_queue;
	while(pa_queue) {

		/* find our next chain before we free this one. */
		pa_queue_next = pa_queue->next;

		free(pa_queue);
		pa_queue = pa_queue_next;
	}

	/* let it be known these are gone. */
	pa_conn[i]->conn_queue = 0;
	pa_conn[i]->conn_queue_last = 0;
	pa_conn[i]->conn_queue_active = 0;
	pa_conn[i]->fwd_queue = 0;
	pa_conn[i]->fwd_queue_last = 0;
	pa_conn[i]->fwd_queue_active = 0;
	pa_conn[i]->queue = 0;

#ifdef PA_DEBUG
	puts("--- pa_queue_free()");
#endif

	return;
}

/* set the timeout point for a connection. */
void pa_timeout_set(unsigned int i, signed int timeout) {

#ifdef PA_DEBUG
	puts("*** pa_timeout_set()");
#endif

	if(i > pa_conn_i) return;
	if(timeout < 0) pa_conn[i]->timeout = 0;
	else pa_conn[i]->timeout = time(NULL) + timeout;
	return;
}

/* calculate if the specified time has past from a pa_timeout_set(). */
signed int pa_timeout_diff(unsigned int i) {

#ifdef PA_DEBUG
	puts("*** pa_timeout_diff()");
#endif

	if(i > pa_conn_i) return(-1);
	return(pa_conn[i]->timeout - time(NULL));
}

/* compare a number against a "n-n" number range. */
unsigned char pa_int_range(unsigned int num, char *num_fmt) {
	unsigned int i, hi, lo;
	char *buf, *ptr;

#ifdef PA_DEBUG
	puts("+++ pa_int_range()");
#endif

	/* blank? assume no match. */
	if(!num_fmt || !*num_fmt) return(0);

	if(!(buf = (char *)strdup(num_fmt)))
		pa_error(PA_MSG_ERR, "failed to duplicate memory for wildcard numeric comparing.");

	for(i = 0, ptr = buf; *ptr; ptr++) {
		if(*ptr == '-' && *(ptr + 1)) {
			*ptr = 0;
			ptr++;
			break;
		}
	}

	/* only one digit to test against. */
	if(!*ptr) ptr = buf;

	/* int-ize our two numbers. ('*' for the lowest/higest) */
	if(strlen(buf) == 1 && buf[0] == '*') lo = 0;
	else lo = atoi(buf);
	if(strlen(ptr) == 1 && ptr[0] == '*') hi = (unsigned int)-1;
	else hi = atoi(ptr);

	free(buf);

#ifdef PA_DEBUG
	puts("--- pa_int_range()");
#endif

	/* success? */
	if(num >= lo && num <= hi) return(1);
	else return(0);
}

/* match a wildcard ip against a real ip. (ie. "127.*.*.1-2") */
unsigned char pa_ip_match(struct sockaddr_in sa, char *ip_fmt) {
	unsigned char r;
	unsigned int i;
	char *buf, *ptr, *ptrs[4];

#ifdef PA_DEBUG
	puts("+++ pa_ip_match()");
#endif

	if(!(buf = (char *)strdup(ip_fmt)))
		pa_error(PA_MSG_ERR, "failed to duplicate memory for wildcard ip matching.");

	/* zero'd for later checks, including pass to pa_int_range(). */
	memset(ptrs, 0, sizeof(ptrs));

	for(i = 1, ptrs[0] = ptr = buf; *ptr; ptr++) {
		if(*ptr == '.' && *(ptr + 1) && *(ptr + 1) != '.') {
			*ptr++ = 0;
			ptrs[i++] = ptr;

			if(i >= 4) break;
		}
	}

	/* compare and set the return (success) value. */
	if(pa_int_range((sa.sin_addr.s_addr & 0x000000ff), ptrs[0])
	&& pa_int_range((sa.sin_addr.s_addr & 0x0000ff00) >> 8, ptrs[1])
	&& pa_int_range((sa.sin_addr.s_addr & 0x00ff0000) >> 16, ptrs[2])
	&& pa_int_range((sa.sin_addr.s_addr & 0xff000000) >> 24, ptrs[3]))
		r = 1;
	else
		r = 0;

	free(buf);

#ifdef PA_DEBUG
	puts("--- pa_ip_match()");
#endif

	return(r);
}

/* make a comma-separated list of ports, in string form. */
char *pa_port_str() {
	unsigned int i;
	char *ports, *ptr;

#ifdef PA_DEBUG
	puts("+++ pa_port_str()");
#endif

	/* make it the same maximum size it could possibly be. (max port length and a comma = 6 byte string) */
	if(!(ports = (char *)malloc(pa_root_i * 6 + 2 + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for size parser.");
	memset(ports, 0, pa_root_i * 6 + 2 + 1);

	ptr = ports;
	
	/* make the string. */
	*ptr++ = '[';
	for(i = 0; i < pa_root_i; i++) {
		if(i) *ptr++ = ',';

		/* end at some level of insanity. */
		if(ptr - ports > 32) {
			ptr += sprintf(ptr, "...");
			break;
		}

		else ptr += sprintf(ptr, "%u", htons(pa_root[i]->sock.sin_port));

	}
	*ptr++ = ']';
	*ptr = 0;

#ifdef PA_DEBUG
	puts("--- pa_port_str()");
#endif

	return(ports);
}

/* open a file, create it with mode if needed, and lock it. */
FILE *pa_fopen(char *file, char *mod, mode_t cmod) {
	signed int fd;
	FILE *fp;

	/* where not available, try this. */
#ifndef LOCK_EX
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();
#endif

#ifdef PA_DEBUG
	puts("+++ pa_fopen()");
#endif

	/* shouldn't happen, but why not be safe. */
	if(!file) pa_error(PA_MSG_ERR, "requested to open blank file.");

	/* doesn't exist? attempt to create it with the provided permissions. */
	if ((fd = open(file, O_RDWR | O_CREAT, cmod)) < 0 || !(fp = fdopen(fd, mod)))
		pa_error(PA_MSG_ERR, "failed to open file: %s", file);

	/* make/check the lock on the file, bail if it's in use. */
#ifndef LOCK_EX
	else if (fcntl(fd, F_SETLK, &fl) < 0)
#else
	else if (flock(fd, LOCK_EX | LOCK_NB) < 0)
#endif
		pa_error(PA_MSG_ERR, "failed to lock file: %s", file);

	(void)fcntl(fd, F_SETFD, 1);

#ifdef PA_DEBUG
	puts("--- pa_fopen()");
#endif

	return(fp);
}



/* convert a "host:port" string to sockaddr_in entry. */
struct sockaddr_in pa_atos(char *str) {
	char *buf, *ptr;
	struct sockaddr_in sa;
#ifdef HAVE_GETADDRINFO /* this is not currently detected, just incase gethostbyname() becomes obsolete somewheres. */
	struct addrinfo hi, *res;
#else
	struct hostent *t;
#endif
	struct servent *se;

#ifdef PA_DEBUG
	puts("+++ pa_atos()");
#endif

	if(!(buf = (char *)strdup(str)))
		pa_error(PA_MSG_ERR, "failed to duplicate memory for hostname:port structure conversion.");

	for(ptr = buf; *ptr; ptr++) {
		if(*ptr == ':') { 
			*ptr++ = 0;
			break;
		}
	}
	if(!*ptr) ptr = buf;

	/* zero it out for good measure. */
	memset((char *)&sa, 0, sizeof(struct sockaddr_in));

	/* gotta have this if we want to actually use it. */
	sa.sin_family = AF_INET;

	/* handle the hostname/ip, and put it in the struct. */
	sa.sin_addr.s_addr = inet_addr(buf);
	if((signed int)sa.sin_addr.s_addr == 0 || (signed int)sa.sin_addr.s_addr == -1) {
		sa.sin_addr.s_addr = 0;

#ifdef HAVE_GETADDRINFO /* this is not currently detected, just incase gethostbyname() becomes obsolete somewheres. */
		memset(&hi, 0, sizeof(hi));
		hi.ai_family = PF_UNSPEC;
		hi.ai_socktype = SOCK_STREAM;
		hi.ai_flags |= AI_CANONNAME;

		if(getaddrinfo(buf, NULL, &hi, &res) == 0) {
			while(res) {
				if(res->ai_family == AF_INET) {
					memcpy((char *)&sa.sin_addr.s_addr, &((struct sockaddr_in *) res->ai_addr)->sin_addr, sizeof(sa.sin_addr.s_addr));
					break;
				}
				res = res->ai_next;
			}
			freeaddrinfo(res);
		}
#else
		if((t = gethostbyname(buf)))
			memcpy((char *)&sa.sin_addr.s_addr, (char *)t->h_addr, sizeof(sa.sin_addr.s_addr));
#endif
		if(sa.sin_addr.s_addr == 0)

			/* unresolved? guess 127.0.0.1 then. */
			sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	}

	/* allow post-chroot() "word" port name resolutions to work. */
#ifdef HAVE_SETSERVENT
	setservent(1);
#endif

	/* string representation of a port? */
	if(!isdigit((unsigned char)*ptr) && (se = getservbyname(ptr, "tcp")))
		sa.sin_port = se->s_port;

	/* nope; handle the port, and put it in the struct. (could be zero, would just fail) */
	else
		sa.sin_port = htons(atoi(ptr));

	free(buf);

#ifdef PA_DEBUG
	puts("--- pa_atos()");
#endif

	return(sa);
}

/* check / set open file limititations, if we can. */
#ifdef HAVE_GETRLIMIT
#ifndef RLIMIT_NOFILE
#define RLIMIT_NOFILE RLIMIT_OFILE
#endif
void pa_set_limit() {
	unsigned int i, orig, max;
	struct rlimit rl;

#ifdef PA_DEBUG
	puts("+++ pa_set_limit()");
#endif

	/* don't abort if we don't know, might as well let it go. */
	if(getrlimit(RLIMIT_NOFILE, &rl))
		return;

	/* is it unlimited? we don't need to know any more. */
#ifdef RLIM_INFINITY
	else if(rl.rlim_max == RLIM_INFINITY)
		return;
#endif

	/* all the binded sockets count as open files. */
	max = pa_root_i;

	for(i = 0; i < pa_root_i;i++) {

		/* maximum possible number of connections PLUS the forwards. 2 a piece max, +1 for a fd to drop on the spot. */
		max += ((pa_root[i]->limit * 2) + 1);
	}

	/* add the open pid file/log file possibilities. */
	max += 2;

	/* note: don't worry about stdin/stderr/stdout, they are closed before limits could be reached. */

	/* we need more open files to support our maximum limit. */
	if(max > rl.rlim_max) {
		orig = rl.rlim_max;
		rl.rlim_cur = rl.rlim_max = max;

		/* try to update, panic if it fails. */
		if(setrlimit(RLIMIT_NOFILE, &rl))
			pa_error(PA_MSG_ERR, "potentially more open files are needed than could be allocated, possibly lower your listen limit instructions. (%u needed, %u allocated)", max, orig);
	}

#ifdef PA_DEBUG
	puts("--- pa_set_limit()");
#endif

	return;
}
#endif

/* switch uid/gid/groups to a specified user. (don't abort if non-root) */
void pa_set_dir(char *dir) {
#ifdef PA_DEBUG
	puts("*** pa_set_dir()");
#endif

#ifdef HAVE_CHROOT

	/* don't abort of non-root. */
	if(!dir || getuid()) return;

	if(dir[0] != '/')
		pa_error(PA_MSG_ERR, "chroot directory must be defined with an absolute path.");
	else {

		/* allow post-chroot() "word" port name resolutions to work. */
#ifdef HAVE_SETSERVENT
		setservent(1);
#endif

		if(chroot(dir))
			pa_error(PA_MSG_ERR, "failed to chroot to specified directory.");

		chdir("/");
	}
#else
	pa_error(PA_MSG_WRN, "chroot is not supported on this system.");
#endif
	return;
}

/* switch uid/gid/groups to a specified user. (don't abort if non-root or initgroups fails) */
void pa_set_perm(uid_t uid, gid_t gid) {
	struct passwd *pwd;

#ifdef PA_DEBUG
	puts("*** pa_set_perm()");
#endif

	/* not root OR already the right user/gruop? skip. */
	if(getuid() || (getuid() == uid && getgid() == gid)) return;

	/* don't abort if this fails, not a good enough reason and could happen by accident. */
	if((pwd = getpwuid(uid)))
		initgroups(pwd->pw_name, gid);

	if(setgid(gid)) pa_error(PA_MSG_ERR, "failed to set defined user id: %u", gid);
	if(setuid(uid)) pa_error(PA_MSG_ERR, "failed to set defined group id: %u", uid);

	pa_log(PA_MSG_INFO, "portagent permissions change: userid=%u, groupid=%u", getuid(), getgid());

	return;
}

/* breaks apart a "1M1K"-style filesize strings into integer (byte) form. */
unsigned int pa_parse_size(char *ssize, unsigned int slen) {
	unsigned int i, v, t;
	char *ssize_ptr, *tmp, *tmp_ptr;

#ifdef PA_DEBUG
	puts("+++ pa_parse_size()");
#endif

	/* make it the same maximum size it could possibly be. */
	if(!(tmp = (char *)malloc(slen + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for size parser.");
	memset(tmp, 0, slen + 1);

	ssize_ptr = ssize;
	tmp_ptr = tmp;
	i = 0;
	
	while(*ssize_ptr) {

		/* build up a series of digits into a string to be processed. */
		if(isdigit((unsigned char)*ssize_ptr)) *tmp_ptr++ = *ssize_ptr;

		/* no digit to process? ignore. */
		else if(tmp != tmp_ptr && (v = atoi(tmp)) > 0) {
			t = 0;
			switch(*ssize_ptr) {
				case 'b': /* bytes. */
				case 'B':
					t = PA_BYTE;
					break;
				case 'k': /* bytes. */
				case 'K':
					t = PA_KILOBYTE;
					break;
				case 'm': /* bytes. */
				case 'M':
					t = PA_MEGABYTE;
					break;
				case 'g': /* bytes. */
				case 'G':
					t = PA_GIGABYTE;
					break;
			}

			/* add seconds to the return value, if it doesn't overflow. */
			if(t && v + (i / t) <= (PA_SIZE_MAX / t)) i += v * t;

			memset(tmp, 0, slen + 1);
			tmp_ptr = tmp;
		}
		ssize_ptr++;
	}
	free(tmp);

#ifdef PA_DEBUG
	puts("--- pa_parse_size()");
#endif

	return(i);
}

/* handles "LIKE" / "%string%" style comparisons. */
unsigned char pa_likecmp(char *str, unsigned int str_len, char *exp, unsigned int exp_len) {
	unsigned char l, r, ret;
	unsigned int exp_len_real;
	char *buf, *ptr;
#ifndef HAVE_MEMMEM 
	char  *sptr, *lptr;
#endif

#ifdef PA_DEBUG
	puts("*** pa_likecmp()");
#endif

	/* nothing? guess we won't count that as a match. */
	if(!exp_len) return(0);

	/* just a '%'...sounds like everything and anything, return true. */
	else if((exp_len == 1 && exp[0] == '%')) return(1);

	/* only alloy '%' to work for blanks, that is it. */
	else if(!str_len) return(0);

	/* '%%' stands for any data, except blanks. */
	else if(exp_len == 2 && !memcmp(exp, "%%", 2)) return(1);

	exp_len_real = exp_len;

	/* duplicate the exp buffer so we can mangle it. */
	if(!(buf = (char *)malloc(exp_len + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for 'LIKE' comparing.");
	memset(buf, 0, exp_len + 1);
	memcpy(buf, exp, exp_len);

	ret = l = r = 0;
	ptr = buf;

	/* check right. */
	if(*(ptr + exp_len - 1) == '%') {
		exp_len_real--;
		*(ptr + exp_len - 1) = 0;
		r = 1;
	}

	/* check left. *buf could just be '%' from above, which would now be nulled, count this as both l/r. */
	if(*buf == '%') {
		exp_len_real--;

		*ptr++ = 0;
		l = 1;
	}

	/* run our like-checks. */
	if(l && r) {
#ifdef HAVE_MEMMEM
		if(memmem(str, str_len, ptr, exp_len_real)) ret = 1;
#else
		for(sptr = str, lptr = str + str_len - exp_len_real; sptr <= lptr; sptr++) {
			if(!memcmp(sptr, ptr, exp_len_real)) {
				ret = 1;
				break;
			}
		}
#endif
	}
	else if(l) { 
		if(str_len >= exp_len_real) {
			if(!memcmp(str + str_len - exp_len_real, ptr, exp_len_real)) ret = 1;
		}
	}
	else if(r) {
		if(!memcmp(str, ptr, exp_len_real)) ret = 1;
	}
	else if(str_len == exp_len_real && !memcmp(str, ptr, str_len)){
		ret = 1;
	}

	free(buf);

	return(ret);
}

/* handles "REGEXP" style comparisons. */
unsigned char pa_regcmp(char *str, char *exp) {
	unsigned char r;
	regex_t re;

#ifdef PA_DEBUG
	puts("*** pa_regcmp()");
#endif

	r = 0;

#ifdef REG_EXTENDED
#define PA_REG_BITS (REG_ICASE | REG_NOSUB | REG_EXTENDED)
#else
#define PA_REG_BITS (REG_ICASE | REG_NOSUB)
#endif

	if (!regcomp(&re, exp, PA_REG_BITS)) {
		if (!regexec(&re, str, 0, NULL, 0)){
			r = 1;
		}
		regfree(&re);
	}

	return(r);
}

void pa_exit(signed int e) {
	signed int i;

#ifdef PA_DEBUG
	puts("*** pa_exit()");
#endif

	pa_log(PA_MSG_INFO, "portagent shutting down.");

	/* cleanly free our listening sockets. */
	for(i = 0; i < pa_root_i; i++) {
		pa_shutdown(pa_root[i]->fd);
	}

	/* cleanly free any open connections. */
	for(i = 0; i <= pa_conn_i; i++) {
		if(pa_conn[i]->status != PA_CONN_REUSE)
			pa_conn_free(i);
	}

	/* close the stream, the fds will still remain. */
	if(pa_conf.pidfs) fclose(pa_conf.pidfs);
	if(pa_conf.logfs) fclose(pa_conf.logfs);

	/* release service database, if chroot() */
#ifdef HAVE_ENDSERVENT
	if(pa_conf.chroot) endservent();
#endif

	exit(e);
}
