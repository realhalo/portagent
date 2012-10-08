/* [portagent] title.c :: pseudo-setproctitle functions for portagent.
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
extern char **environ;

/* globals. */
#ifndef NO_SETPROCTITLE
struct pa_proctitle_s pa_proctitle;
#endif


#ifndef NO_SETPROCTITLE
#ifndef HAVE_SETPROCTITLE
#ifdef INT_SETPROCTITLE
/* pseudo-setproctitle startup. */
void initsetproctitle(signed int argc, char **argv, char **envp) {
	unsigned int i, envpsize;
	char *s;

#ifdef PA_DEBUG
	puts("+++ initsetproctitle()");
#endif

	for(i = 0, envpsize = 0; envp[i] !=0; i++)
		envpsize += strlen(envp[i]) + 1;
	if(!(environ = (char **)malloc((sizeof(char *) * (i + 1)) + envpsize + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for initsetproctitle().");
	s = ((char *)environ) + ((sizeof(char *) * (i + 1)));
	for(i = 0; envp[i] != 0; i++) {
		strcpy(s, envp[i]);
		environ[i] = s;
		s += strlen(s) + 1;
	}
	environ[i] = 0;
	if(!(pa_proctitle.name = (char *)malloc(strlen(argv[0]) + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for initsetproctitle().");
	strcpy(pa_proctitle.name, argv[0]);
	pa_proctitle.argv = argv;
	for(i = 0; i < argc; i++) {
		if(!i || pa_proctitle.largv + 1 == argv[i])
			pa_proctitle.largv = (argv[i] + strlen(argv[i]));
	}
	for(i = 0; envp[i] != 0; i++) {
		if(pa_proctitle.largv + 1 == envp[i])
			pa_proctitle.largv = (envp[i] + strlen(envp[i]));
	}

#ifdef PA_DEBUG
	puts("--- initsetproctitle()");
#endif

	return;
}
/* pseudo-setproctitle set. */
void setproctitle(const char *fmt, ...) {
	unsigned int i;
	char *p, buf[PA_BUFSIZE_LARGE + 1], buf2[PA_BUFSIZE_LARGE + 11 + 1];
	va_list param;

#ifdef PA_DEBUG
	puts("+++ setproctitle()");
#endif

	va_start(param, fmt);
	vsnprintf(buf, sizeof(buf), fmt, param);
	va_end(param);
	sprintf(buf2, "portagent: %s", buf);
	memset(buf, 0, sizeof(buf));
	strncpy(buf, buf2, sizeof(buf) - 1);
	if((i = strlen(buf)) > pa_proctitle.largv - pa_proctitle.argv[0] - 2) {
		i = pa_proctitle.largv - pa_proctitle.argv[0] - 2;
		buf[i] = 0;
	}
	strcpy(pa_proctitle.argv[0], buf);
	p = &pa_proctitle.argv[0][i];
	while(p < pa_proctitle.largv) *p++ = 0;
	pa_proctitle.argv[1] = 0;

#ifdef PA_DEBUG
	puts("--- setproctitle()");
#endif

	return;
}

#else
void initsetproctitle(signed int argc, char **argv, char **envp) { return; }
void setproctitle(const char *fmt, ...) { return; }
#endif
#else
void initsetproctitle(signed int argc, char **argv, char **envp) { return; }
#endif
#endif
