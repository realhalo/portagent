/* [portagent] msg.c :: error / log message related function(s) for portagent.
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


/* all-purpose error handler, makes life easier. */
void pa_error(unsigned char type, char *fmt, ...) {
	char buf[PA_BUFSIZE_LARGE + 1];
	va_list ap;	

#ifdef PA_DEBUG
	puts("*** pa_error()");
#endif

	memset(buf, 0, PA_BUFSIZE_LARGE);

	va_start(ap, fmt);
	vsnprintf(buf, PA_BUFSIZE_LARGE, fmt, ap);
	va_end(ap);

	/* we're not at console anymore, log it if we can. */
	if(pa_conf.background)
		pa_log(PA_MSG_INFO, "%s: %s\n", (type == PA_MSG_ERR ? "error" : "warning"),  buf);

	/* still at console, print it out. */
	else {
		if(type == PA_MSG_REG) puts(buf);
		else printf("%s: %s\n", (type == PA_MSG_ERR ? "error" : "warning"),  buf);
	}

	if(type == PA_MSG_ERR) exit(PA_EXIT_ERROR);

	return;
}

/* all-purpose log handler, makes life easier. */
void pa_log(signed int i, char *fmt, ...) {
	char buf[PA_BUFSIZE_LARGE + 1], tbuf[PA_BUFSIZE_TINY + 1];
	time_t t;
	struct tm *m;
	va_list ap;

	/* not logging. */
	if(!pa_conf.logfs) return;

#ifdef PA_DEBUG
	puts("*** pa_log()");
#endif

	t = time(NULL);
	m = localtime(&t);

	memset(tbuf, 0, PA_BUFSIZE_TINY + 1);
	strftime(tbuf, PA_BUFSIZE_TINY, "%m/%d/%Y %I:%M:%S%p", m);

	memset(buf, 0, PA_BUFSIZE_LARGE);
	va_start(ap, fmt);
	vsnprintf(buf, PA_BUFSIZE_LARGE, fmt, ap);
	va_end(ap);

	if(i < 0 || i > pa_conn_i)
		fprintf(pa_conf.logfs, "%s [-----:-----] %s\n", tbuf, buf);
	else
		fprintf(pa_conf.logfs, "%s [%.5u:%.5u] %s\n", tbuf, pa_conn[i]->pa_log_id, htons(pa_root[pa_conn[i]->pa_root]->sock.sin_port), buf);

	fflush(pa_conf.logfs);

	return;
}
