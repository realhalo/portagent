/* [portagent] portagent.c :: core portagent daemon process routine.
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

static const char id[] = "$Id: portagent,v " PA_VERSION " " PA_CMPTIME " fakehalo Exp $";

/* externs. */
extern struct pa_conf_s pa_conf;
#ifndef NO_SETPROCTITLE
extern struct pa_proctitle_s pa_proctitle;
#endif
extern char **environ;


/* process begin. */
int main(signed int argc, char **argv) {
#ifndef NO_SETPROCTITLE
	char *ptr;
#endif

	/* just a version dump? */
	if(argc > 1 && !strcmp(argv[1], "-v")) {
		puts("portagent: version " PA_VERSION);
		exit(0);
	}

	/* set to 1 when ready to goto the background. */
	pa_conf.background = 0;

	/* parse our conf file. */
	pa_conf_parser((argc > 1 ? argv[1] : PA_DFL_CONF_FILE));

	/* see if we are allowed enough open files to work with. */
#ifdef HAVE_GETRLIMIT
	pa_set_limit();
#endif

	/* bind to specified ports. */
	pa_listen_init();

	/* make proctitle show what's going on. */
#ifndef NO_SETPROCTITLE
	initsetproctitle(argc, argv, environ);
	ptr = pa_port_str();
	setproctitle("0 connections %s", ptr);
	free(ptr);
#endif

	/* daemonize ourself. */
#ifdef PA_DEBUG
	switch(0) {
#else
	switch(fork()) {
#endif
		case -1:
			pa_error(PA_MSG_ERR, "failed to fork into daemon mode.");
			break;
		case 0:

			/* detach / new group leader. */
#ifdef HAVE_SETSID
			setsid();
#endif
			/* open log/pid files if they are specified. (before perms/chroot) */
			if(pa_conf.logfile) {
				pa_conf.logfs = pa_fopen(pa_conf.logfile, "a", 0600);
				free(pa_conf.logfile);
			}
			if(pa_conf.pidfile) {
				pa_conf.pidfs = pa_fopen(pa_conf.pidfile, "w", 0644);
				free(pa_conf.pidfile);
				fprintf(pa_conf.pidfs, "%u\n", (unsigned int)getpid());
				fflush(pa_conf.pidfs);
			}

			/* if set, chroot and/or drop privileges afrer ports are binded to. */
			pa_set_dir(pa_conf.chroot);
			pa_set_perm(pa_conf.uid, pa_conf.gid);

			/* it's official, we're good to go. */
			pa_conf.background = 1;

			/* most of these will never happen naturally. */
			signal(SIGBUS, pa_signal);
			signal(SIGILL, pa_signal);
			signal(SIGSEGV, pa_signal);
			signal(SIGHUP, pa_signal);
			signal(SIGQUIT, pa_signal);
			signal(SIGTERM, pa_signal);
			signal(SIGINT, pa_signal);
			signal(SIGTSTP, pa_signal);

			pa_log(PA_MSG_INFO, "portagent now running in the background: pid=%u", getpid());

			/* no standard in/out/error, this is a backgrounded daemon. */
#ifndef PA_DEBUG
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
#endif

			/* a reading loop to never return from. */
			pa_listen_loop();

			break;
	}

	/* bg process never makes it here. */
	exit(0);
}
