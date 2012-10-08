/* [portagent] conf.c :: config file parsing functions for portagent.
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

/* globals. */
struct pa_conf_s pa_conf;
struct pa_root_s **pa_root;
signed int pa_root_i = -1;

/* generic "IF"-map that gets formatted to a "IF LIKE" or "IF REGEXP" based on the name. */
const struct pa_ifmap_s pa_ifmap[] = {
	{"*",			PA_IFL,		0,	"%"},
	{"any",			PA_IFL,		0,	"%"},
	{"input",		PA_IFL,		0,	"%%"},
	{"ascii",		PA_IFR,		0,	"^[^\x80-\xFF]+$"},
	{"extended-ascii",	PA_IFR,		0,	"[\x80-\xFF]"},
	{"readable",		PA_IFR,		0,	"^[^\x01-\x08\x0B-\x0C\x0E-\x1F\x80-\xFF]+$"},
	{"unreadable",		PA_IFR,		0,	"[\x01-\x08\x0B-\x0C\x0E-\x1F\x80-\xFF]"},
	{"http",		PA_IFR,		0,	"^(GET|HEAD|POST|PUT|DELETE) "},
	{"ssh",			PA_IFL,		0,	"SSH-%"},
	{"ftp",			PA_IFL,		0,	"USER %"},
	{"smtp",		PA_IFR,		0,	"^(HELO|helo|EHLO|ehlo)"},
	{"pop",			PA_IFR,		0,	"^(CAPA|capa|USER |user )"},
	{"pop3",		PA_IFR,		0,	"^(CAPA|capa|USER |user )"},
	{"imap",		PA_IFR,		0,	"^[0-9]+ (CAPABILITY|capability|LOGIN|login|LOGOUT|logout|STARTTLS|starttls)"},
#ifdef REG_EXTENDED
	{"auth",		PA_IFR,		0,	"^[0-9]{1,5}[ ]*,[ ]*[0-9]{1,5}"},
#else
	{"auth",		PA_IFR,		0,	"^[0-9]*[ ]*,[ ]*[0-9]*"},
#endif
	{NULL,			0,		0,	NULL}
};

/* find an internally defined static "IF" match. */
signed int pa_ifmap_find(char *name) {
	signed int i;

#ifdef PA_DEBUG
	puts("*** pa_ifmap_find()");
#endif

	for(i = 0; pa_ifmap[i].name; i++) {
		if(!strcasecmp(name, pa_ifmap[i].name))
			return(i);
	}
	return(-1);
}

/* string-to-numeric of config instructions. (keeping syntax flexible) */
unsigned char pa_instruction_type(char *instruction) {

#ifdef PA_DEBUG
	puts("*** pa_instruction_type()");
#endif

	if(!strcasecmp(instruction, "USE")) return(PA_USE);
	else if(!strcasecmp(instruction, "IF DEFINED")) return(PA_IF);
	else if(!strcasecmp(instruction, "IF LIKE")) return(PA_IFL);
	else if(!strcasecmp(instruction, "IF REGEXP")) return(PA_IFR);
	else if(!strcasecmp(instruction, "IP")) return(PA_IP);
	else if(!strcasecmp(instruction, "IP NOT")) return(PA_IP_NOT);
	else if(!strcasecmp(instruction, "PORT")) return(PA_PORT);
	else if(!strcasecmp(instruction, "PORT NOT")) return(PA_PORT_NOT);
	else if(!strcasecmp(instruction, "WRITE CLIENT")) return(PA_WRITE_CLIENT);
	else if(!strcasecmp(instruction, "WRITE SERVER")) return(PA_WRITE_SERVER);
	else if(!strcasecmp(instruction, "WRITE")) return(PA_WRITE_CLIENT);
	else if(!strcasecmp(instruction, "TIMEOUT")) return(PA_TIMEOUT);
	else if(!strcasecmp(instruction, "LISTEN")) return(PA_LISTEN);
	else if(!strcasecmp(instruction, "LISTEN ON")) return(PA_LISTEN);
	else if(!strcasecmp(instruction, "WITH")) return(PA_WITH);
	else if(!strcasecmp(instruction, "TRY")) return(PA_TRY);
	else if(!strcasecmp(instruction, "BACKLOG")) return(PA_BACKLOG);
	else if(!strcasecmp(instruction, "LIMIT")) return(PA_LIMIT);
	else if(!strcasecmp(instruction, "INITIAL BUFFER")) return(PA_INITIAL);
	else if(!strcasecmp(instruction, "QUEUE BUFFER")) return(PA_QUEUE);
	else if(!strcasecmp(instruction, "PIDFILE")) return(PA_PIDFILE);
	else if(!strcasecmp(instruction, "PID FILE")) return(PA_PIDFILE);
	else if(!strcasecmp(instruction, "LOGFILE")) return(PA_LOGFILE);
	else if(!strcasecmp(instruction, "LOG FILE")) return(PA_LOGFILE);
	else if(!strcasecmp(instruction, "USER")) return(PA_USER);
	else if(!strcasecmp(instruction, "GROUP")) return(PA_GROUP);
	else if(!strcasecmp(instruction, "CHROOT")) return(PA_CHROOT);
	else if(!strcasecmp(instruction, "REWRITE CLIENT")) return(PA_REWRITE_CLIENT);
	else if(!strcasecmp(instruction, "REWRITE SERVER")) return(PA_REWRITE_SERVER);
	else if(!strcasecmp(instruction, "REWRITE")) return(PA_REWRITE_CLIENT);
	else if(!strcasecmp(instruction, "AS")) return(PA_AS);
	else if(!strcasecmp(instruction, "KEY CLIENT")) return(PA_KEY_CLIENT);
	else if(!strcasecmp(instruction, "KEY SERVER")) return(PA_KEY_SERVER);
	else if(!strcasecmp(instruction, "KEY")) return(PA_KEY_CLIENT);
	else return(PA_NONE);
}

/* process literals in a string, returns length. (garbles the original string passed, always shrinks if anything) */
unsigned int pa_literal_parser(char *str) {
	signed int var;
	char *ptr;

#ifdef PA_DEBUG
	puts("+++ pa_literal_parser()");
#endif

	for(ptr = str; *ptr; ptr++) {
		switch(*ptr) {

			/* escape indicator. */
			case '\\':
				if(*ptr + 1) {
					switch(*(ptr + 1)) {

						/* escaped quote OR double escape = one escape. */
						case '\'':
						case '\\':
							memmove(ptr, ptr + 1, strlen(ptr));
							break;

						/* the usuals... */
						case 'e':
							memmove(ptr + 1, ptr + 2, strlen(ptr + 1));
							*ptr = (unsigned char)0x1b; /* not POSIX, i found out the hard way. */
							break;
						case 'v':
							memmove(ptr + 1, ptr + 2, strlen(ptr + 1));
							*ptr = (unsigned char)'\v';
							break;
						case 't':
							memmove(ptr + 1, ptr + 2, strlen(ptr + 1));
							*ptr = (unsigned char)'\t';
							break;
						case 'r':
							memmove(ptr + 1, ptr + 2, strlen(ptr + 1));
							*ptr = (unsigned char)'\r';
							break;
						case 'n':
							memmove(ptr + 1, ptr + 2, strlen(ptr + 1));
							*ptr = (unsigned char)'\n';
							break;

						/* hexadecimal. */
						case 'x':
							if(*(ptr + 2) && *(ptr + 3) && isxdigit((unsigned char)*(ptr + 2)) && isxdigit((unsigned char)*(ptr + 3))) {
								if(sscanf(ptr + 2, "%2x", &var) > 0) {
									memmove(ptr + 1, ptr + 4, strlen(ptr + 3));
									*ptr = (unsigned char)var;
								}
							}
							break;
						default:

							/* octal. */
							if(*(ptr + 1) && *(ptr + 2) && *(ptr + 3) && isdigit((unsigned char)*(ptr + 1)) && isdigit((unsigned char)*(ptr + 2)) && isxdigit((unsigned char)*(ptr + 3))) {
								if(sscanf(ptr + 1, "%3o", &var) > 0) {
									memmove(ptr + 1, ptr + 4, strlen(ptr + 3));
									*ptr = (unsigned char)var;

								}
							}
							break;
					}
				}
				break;
		}
	}

#ifdef PA_DEBUG
	puts("--- pa_literal_parser()");
#endif

	return(ptr - str);
}

/* trim the inner-whitespace of a string. (makes sure the whitespace is a single-space too) */
char *pa_trim(char *str) {
	unsigned int i;
	char *ptr;

#ifdef PA_DEBUG
	puts("+++ pa_trim()");
#endif

	for(i = 0, ptr = str; *ptr; ptr++) {
		if(isspace((unsigned char)*ptr)) {
			i++;
		}
		else if(i) {
			memmove(ptr - i + 1, ptr, strlen(ptr - i + 1));
			*(ptr - i) = ' ';
			ptr -= i;
			i = 0;
		}
	}

#ifdef PA_DEBUG
	puts("--- pa_trim()");
#endif

	return(str);
}

/* read and process a "portagent.conf". */
void pa_conf_parser(char *conf_file) {
	unsigned char mode, comment, type, nest;
	unsigned int i, j, k, l, c, len;
	signed int chr;
	char *buf;
	FILE *fp;
	struct hostent *t;
	struct servent *se;
	struct passwd *pwd;
	struct group *grp;

#ifdef PA_DEBUG
	puts("+++ pa_conf_parser()");
#endif

	/* default conf settings. */
	pa_conf.ctx_cache = NULL;
	pa_conf.logfs = NULL;
	pa_conf.logfile = NULL;
	pa_conf.pidfs = NULL;
	pa_conf.pidfile = NULL;
	pa_conf.chroot = NULL;
	pa_conf.uid = getuid();
	pa_conf.gid = getgid();
	pa_conf.background = 0;
	pa_conf.exit = 0;

	if((fp = fopen(conf_file, "r")) == NULL)
		pa_error(PA_MSG_ERR, "%s: could not open file for reading.", conf_file);

	mode = i = comment = c = 0;
	l = 1;
	nest = PA_NONE;

	while((chr = fgetc(fp)) > 0) {

		/* mark our line/column position for error outputts. */
		if(chr == '\n') {
			l++;
			comment = c = 0;
		}
		else if(chr == '\t') c += abs((c % 8) - 8);
		else c++;

		/* commented line OR a '\r' outside of a quote? skip. */
		if(comment || (chr == '\r' && mode != 2)) continue;

		/* waiting for the instruction value. */
		if(!mode) {
			if(isalpha((unsigned char)chr)) {
				mode = i = 1;
				j = 0;
			}
			else if(chr == '#' || chr == ';') comment = 1;
			else if(!isspace((unsigned char)chr))
				pa_error(PA_MSG_ERR, "%s:%u:%u: invalid instruction type. (non-alphabetical phrase)", conf_file, l, c);

		}

		/* reading the instruction type. */
		else if(mode == 1) {
			if(isalpha((unsigned char)chr)) {
				i++;

				/* add / reset trim if there's another word.  */
				i += j;
				j = 0;
			}

			/* remember the extra spaces to trim off the end. */
			else if(isspace((unsigned char)chr)) j++;

			else if(chr == '\'') {
				if(!(buf = (char *)malloc(i + 1)))
					pa_error(PA_MSG_ERR, "failed to allocate memory for instruction type.");
				memset(buf, 0, i + 1);
				fseek(fp, -(int)(i + j + 1), SEEK_CUR);
				fread(buf, 1, i, fp);
				if(j) fseek(fp, (int)j, SEEK_CUR);

				/* +1 to read over the initial single-quote. */
				fseek(fp, 1, SEEK_CUR);

				if(!(type = pa_instruction_type(pa_trim(buf))))
					pa_error(PA_MSG_ERR, "%s:%u:%u: invalid instruction: '%s'", conf_file, l, (c - i - j), buf);

				/* check for proper nesting of instructions. */
				switch(type) {
					case PA_PIDFILE:
					case PA_LOGFILE:
					case PA_USER:
					case PA_GROUP:
					case PA_CHROOT:
						if(nest != PA_NONE) nest = PA_BAD_INS;
						break;
					case PA_LISTEN:
						/* first time OR just another root element? */
						if(pa_root_i < 0) {
							if(!(pa_root = (struct pa_root_s **)malloc(sizeof(struct pa_root_s *) + 2)))
								pa_error(PA_MSG_ERR, "failed to allocate memory for root listening structure.");
						}
						else {
							if(!(pa_root = (struct pa_root_s **)realloc(pa_root, sizeof(struct pa_root_s *) * (pa_root_i + 2))))
								pa_error(PA_MSG_ERR, "failed to re-allocate memory for root listening structure.");

							if(!pa_root[pa_root_i]->backlog) pa_root[pa_root_i]->backlog = PA_DFL_LISTEN_BACKLOG;
							if(!pa_root[pa_root_i]->bufsize) pa_root[pa_root_i]->bufsize = PA_DFL_LISTEN_INITIAL;
							if(!pa_root[pa_root_i]->queue) pa_root[pa_root_i]->queue = PA_DFL_LISTEN_QUEUE;
							if(!pa_root[pa_root_i]->limit) pa_root[pa_root_i]->limit = PA_DFL_LISTEN_LIMIT;
						}

						/* consolidated for both of the above. */
						if(nest == PA_NONE || nest == PA_LISTEN) {
							pa_root_i++;
							if(!(pa_root[pa_root_i] = (struct pa_root_s *)malloc(sizeof(struct pa_root_s) + 1)))
								pa_error(PA_MSG_ERR, "failed to allocate memory for an element of root listening structure.");

							/* default. (s_addr may be changed by the WITH instruction later) */
							pa_root[pa_root_i]->sock.sin_family = AF_INET;
							pa_root[pa_root_i]->sock.sin_addr.s_addr = INADDR_ANY;
							pa_root[pa_root_i]->sock.sin_port = 0;

							/* set later by pa_listen_init(). */
							pa_root[pa_root_i]->fd = -1;

							pa_root[pa_root_i]->pa_ins_i = 0;
							pa_root[pa_root_i]->pa_rewrite_i = 0;

							pa_root[pa_root_i]->backlog = 0;

							pa_root[pa_root_i]->bufsize = 0;
							pa_root[pa_root_i]->queue = 0;

							pa_root[pa_root_i]->limit = 0;
							pa_root[pa_root_i]->used = 0;

							nest = PA_LISTEN;
						}
						else nest = PA_BAD_INS;

						break;
					case PA_IF:
					case PA_IFL:
					case PA_IFR:
						if(nest != PA_LISTEN) nest = PA_BAD_INS;
						else nest = PA_IF;
						break;
					case PA_IP:
					case PA_IP_NOT:
					case PA_PORT:
					case PA_PORT_NOT:
						break;
					case PA_REWRITE_CLIENT:
					case PA_REWRITE_SERVER:
						if(nest != PA_LISTEN) nest = PA_BAD_INS;
						else nest = type;
						break;
					case PA_AS:
						if(nest != PA_REWRITE_CLIENT && nest != PA_REWRITE_SERVER) nest = PA_BAD_INS;
						else nest = PA_LISTEN;
						break;
					case PA_USE:
						if(nest != PA_LISTEN && nest != PA_IF) nest = PA_BAD_INS;
						else nest = PA_LISTEN;
						break;
					case PA_BACKLOG:
					case PA_INITIAL:
					case PA_QUEUE:
					case PA_LIMIT:
					case PA_WRITE_CLIENT:
					case PA_WRITE_SERVER:
					case PA_WITH:
					case PA_TIMEOUT:
					case PA_TRY:
					case PA_KEY_CLIENT:
					case PA_KEY_SERVER:
						if(nest != PA_LISTEN) nest = PA_BAD_INS;
						break;
					default:
						break;
				}

				/* bad nesting checked from switch() above. */
				if(nest == PA_BAD_INS)
					pa_error(PA_MSG_ERR, "%s:%u:%u: invalid instruction placement / nesting: '%s'", conf_file, l, (c - i - j), buf);

				free(buf);
				mode = 2;
				i = 0;
			}
			else pa_error(PA_MSG_ERR, "%s:%u:%u: invalid instruction value indicator. (needs to be a single quote)", conf_file, l, c);
		}

		/* reading the instruction value. */
		else if(mode == 2) {
			if (chr == '\'') {
				if(!(buf = (char *)malloc(i + 1)))
					pa_error(PA_MSG_ERR, "failed to allocate memory for instruction value.");
				memset(buf, 0, i + 1);
				fseek(fp, -(int)(i + 1), SEEK_CUR);
				fread(buf, 1, i, fp);

				/* allow blank "AS ''" instructions, only current case needed. */
				if(!(len = pa_literal_parser(buf)) && type != PA_AS)
					pa_error(PA_MSG_ERR, "%s:%u:%u: blank instruction value.", conf_file, l, c);

				/* +1 to not read the single-quote for the next run. */
				fseek(fp, 1, SEEK_CUR);

				/* add the instruction data to our structure(s). */
				switch(type) {
					case PA_PIDFILE:
						if(pa_conf.pidfile)
							pa_error(PA_MSG_ERR, "%s:%u:%u: pidfile defined more than one time in this configuration.", conf_file, l, c);
						else if(buf[0] != '/')
							pa_error(PA_MSG_ERR, "%s:%u:%u: pidfile must be defined with an absolute path.", conf_file, l, c);
						else
							pa_conf.pidfile = buf;
						break;
					case PA_LOGFILE:
						if(pa_conf.logfile)
							pa_error(PA_MSG_ERR, "%s:%u:%u: logfile defined more than one time in this configuration.", conf_file, l, c);
						else if(buf[0] != '/')
							pa_error(PA_MSG_ERR, "%s:%u:%u: logfile must be defined with an absolute path.", conf_file, l, c);
						else
							pa_conf.logfile = buf;
						break;
					case PA_CHROOT:
						if(pa_conf.chroot)
							pa_error(PA_MSG_ERR, "%s:%u:%u: chroot defined more than one time in this configuration.", conf_file, l, c);
						else if(buf[0] != '/')
							pa_error(PA_MSG_ERR, "%s:%u:%u: chroot must be defined with an absolute path.", conf_file, l, c);
						else
							pa_conf.chroot = buf;
						break;
					case PA_USER:
						if(isdigit((unsigned char)buf[0])) pa_conf.uid = atoi(buf);
						else if((pwd = getpwnam(buf))) pa_conf.uid = pwd->pw_uid;
						free(buf);
						break;
					case PA_GROUP:
						if(isdigit((unsigned char)buf[0])) pa_conf.gid = atoi(buf);
						else if((grp = getgrnam(buf))) pa_conf.gid = grp->gr_gid;
						free(buf);
						break;
					case PA_LISTEN:

						/* string representation of a port? */
						if(!isdigit((unsigned char)buf[0]) && (se = getservbyname(buf, "tcp")))
							pa_root[pa_root_i]->sock.sin_port = se->s_port;

						/* nope; handle the port, and put it in the struct. */
						else
							pa_root[pa_root_i]->sock.sin_port = htons(atoi(buf));

						if(!pa_root[pa_root_i]->sock.sin_port)
							pa_error(PA_MSG_ERR, "%s:%u:%u: bad listening port value: %s", conf_file, l, c, buf);

						/* quick check to see if the port has been defined already. */
						for(k = 0; k < pa_root_i; k++) {
							if(pa_root[k]->sock.sin_port == pa_root[pa_root_i]->sock.sin_port)
								pa_error(PA_MSG_ERR, "%s:%u:%u: listening port already defined in previous instruction: %s", conf_file, l, c, buf);
						}

						free(buf);
						break;
					case PA_WITH:
						if((pa_root[pa_root_i]->sock.sin_addr.s_addr = inet_addr(buf))) {
							if(!(t = gethostbyname(buf)))
								pa_error(PA_MSG_ERR, "%s:%u:%u: could not resolve hostname: %s", conf_file, l, c, buf);
							memcpy((char *)&pa_root[pa_root_i]->sock.sin_addr.s_addr, (char *)t->h_addr, sizeof(pa_root[pa_root_i]->sock.sin_addr.s_addr ));
						}
						free(buf);
						break;
					case PA_BACKLOG:
						if(pa_root[pa_root_i]->backlog)
							pa_error(PA_MSG_ERR, "%s:%u:%u: backlog defined more than one time in this listen block.", conf_file, l, c);
						pa_root[pa_root_i]->backlog = atoi(buf);
						if(!pa_root[pa_root_i]->backlog)
							pa_error(PA_MSG_ERR, "%s:%u:%u: bad backlog value: %s", conf_file, l, c, buf);
						free(buf);
						break;
					case PA_INITIAL:
						if(pa_root[pa_root_i]->bufsize)
							pa_error(PA_MSG_ERR, "%s:%u:%u: initial buffer defined more than one time in this listen block.", conf_file, l, c);
						pa_root[pa_root_i]->bufsize = pa_parse_size(buf, strlen(buf));
						if(!pa_root[pa_root_i]->bufsize)
							pa_root[pa_root_i]->bufsize = atoi(buf);
						if(!pa_root[pa_root_i]->bufsize)
							pa_error(PA_MSG_ERR, "%s:%u:%u: bad initial buffer value: %s", conf_file, l, c, buf);
						else if(pa_root[pa_root_i]->bufsize > PA_SIZE_MAX_BUF)
							pa_error(PA_MSG_ERR, "%s:%u:%u: initial buffer value too large: %s (%u maximum)", conf_file, l, c, buf, PA_SIZE_MAX_BUF);
						free(buf);
						break;
					case PA_QUEUE:
						if(pa_root[pa_root_i]->queue)
							pa_error(PA_MSG_ERR, "%s:%u:%u: queue buffer defined more than one time in this listen block.", conf_file, l, c);
						pa_root[pa_root_i]->queue = pa_parse_size(buf, strlen(buf));
						if(!pa_root[pa_root_i]->queue)
							pa_root[pa_root_i]->queue = atoi(buf);
						if(!pa_root[pa_root_i]->queue)
							pa_error(PA_MSG_ERR, "%s:%u:%u: bad queue buffer value: %s", conf_file, l, c, buf);
						else if(pa_root[pa_root_i]->queue > PA_SIZE_MAX_BUF)
							pa_error(PA_MSG_ERR, "%s:%u:%u: queue buffer value too large: %s (%u maximum)", conf_file, l, c, buf, PA_SIZE_MAX_BUF);
						free(buf);
						break;
					case PA_LIMIT:
						if(pa_root[pa_root_i]->limit)
							pa_error(PA_MSG_ERR, "%s:%u:%u: limit defined more than one time in this listen block.", conf_file, l, c);
						pa_root[pa_root_i]->limit = atoi(buf);
						if(!pa_root[pa_root_i]->limit)
							pa_error(PA_MSG_ERR, "%s:%u:%u: bad limit value: %s", conf_file, l, c, buf);
						free(buf);
						break;
					case PA_REWRITE_CLIENT:
					case PA_REWRITE_SERVER:

						/* first rewrite? */
						if(!pa_root[pa_root_i]->pa_rewrite_i) {
							if(!(pa_root[pa_root_i]->pa_rewrite = (struct pa_rewrite_s **)malloc(sizeof(struct pa_rewrite_s *) + 2)))
								pa_error(PA_MSG_ERR, "failed to allocate memory for rewrite structure.");
						}

						/* just another rewrite. */
						else {
							if(!(pa_root[pa_root_i]->pa_rewrite = (struct pa_rewrite_s **)realloc(pa_root[pa_root_i]->pa_rewrite, sizeof(struct pa_rewrite_s *) * (pa_root[pa_root_i]->pa_rewrite_i + 2))))
								pa_error(PA_MSG_ERR, "failed to re-allocate memory for rewrite structure.");
						}

						/* add our rewrite data. */
						if(!(pa_root[pa_root_i]->pa_rewrite[pa_root[pa_root_i]->pa_rewrite_i] = (struct pa_rewrite_s *)malloc(sizeof(struct pa_rewrite_s) + 1)))
							pa_error(PA_MSG_ERR, "failed to allocate memory for an element of rewrite structure.");

        					/* compile it now, report errors. (since this will be used a lot it's best to only compile it once, now) */
						if(regcomp (&pa_root[pa_root_i]->pa_rewrite[pa_root[pa_root_i]->pa_rewrite_i]->pattern, buf, REG_EXTENDED_FIX))
							pa_error(PA_MSG_ERR, "%s:%u:%u: could not compile regular expression: %s", conf_file, l, c, buf);

						pa_root[pa_root_i]->pa_rewrite[pa_root[pa_root_i]->pa_rewrite_i]->type = type;
						pa_root[pa_root_i]->pa_rewrite[pa_root[pa_root_i]->pa_rewrite_i]->replace = NULL;
						pa_root[pa_root_i]->pa_rewrite[pa_root[pa_root_i]->pa_rewrite_i]->len = 0;

						free(buf);

						break;
					case PA_AS:
						pa_root[pa_root_i]->pa_rewrite[pa_root[pa_root_i]->pa_rewrite_i]->replace = buf;
						pa_root[pa_root_i]->pa_rewrite[pa_root[pa_root_i]->pa_rewrite_i]->len = len;

						/* entry ready / increment total. */
						pa_root[pa_root_i]->pa_rewrite_i++;

						break;
					case PA_IF:
					case PA_IFL:
					case PA_IFR:
					case PA_TIMEOUT:
					case PA_IP:
					case PA_IP_NOT:
					case PA_PORT:
					case PA_PORT_NOT:
					case PA_USE:
					case PA_WRITE_CLIENT:
					case PA_WRITE_SERVER:
					case PA_TRY:
					case PA_KEY_CLIENT:
					case PA_KEY_SERVER:
						/* first instruction? */
						if(!pa_root[pa_root_i]->pa_ins_i) {
							if(!(pa_root[pa_root_i]->pa_ins = (struct pa_ins_s **)malloc(sizeof(struct pa_ins_s *) + 2)))
								pa_error(PA_MSG_ERR, "failed to allocate memory for instruction structure.");
						}

						/* just another instruction. */
						else {
							if(!(pa_root[pa_root_i]->pa_ins = (struct pa_ins_s **)realloc(pa_root[pa_root_i]->pa_ins, sizeof(struct pa_ins_s *) * (pa_root[pa_root_i]->pa_ins_i + 2))))
								pa_error(PA_MSG_ERR, "failed to re-allocate memory for instruction structure.");
						}

						/* add our instruction data. */
						if(!(pa_root[pa_root_i]->pa_ins[pa_root[pa_root_i]->pa_ins_i] = (struct pa_ins_s *)malloc(sizeof(struct pa_ins_s) + 1)))
							pa_error(PA_MSG_ERR, "failed to allocate memory for an element of instruction structure.");

						pa_root[pa_root_i]->pa_ins[pa_root[pa_root_i]->pa_ins_i]->type = type;
						pa_root[pa_root_i]->pa_ins[pa_root[pa_root_i]->pa_ins_i]->len = len;
						pa_root[pa_root_i]->pa_ins[pa_root[pa_root_i]->pa_ins_i]->ins = buf;

						/* hack to load dynamic library early, if it hasn't been already, for CHROOT. */
						if(pa_conf.chroot && (type == PA_USE || type == PA_TRY))
							(void)pa_atos(buf);

						/* entry ready / increment total. */
						pa_root[pa_root_i]->pa_ins_i++;

						break;
					default:
						free(buf);
						break;
				}

				mode = 0;
			}

			/* escape sequence? don't process now but jump for it. */
			else if(chr == '\\') {
				fseek(fp, 1, SEEK_CUR);
				i += 2;
				c++;
			}
			else i++;
		}
	}

	/* some more error checking. */
	if(mode) pa_error(PA_MSG_ERR, "%s:%u:%u: reached EOF during open instruction statement.", conf_file, l, c);
	else if(nest != PA_LISTEN) pa_error(PA_MSG_ERR, "%s:%u:%u: reached EOF inside a non-listen nested statement.", conf_file, l, c);
	else if(pa_root_i < 0) pa_error(PA_MSG_ERR, "%s:%u:%u: reached EOF and not listening on any ports.", conf_file, l, c);


	/* one more check...redundant. */
	if(!pa_root[pa_root_i]->backlog) pa_root[pa_root_i]->backlog = PA_DFL_LISTEN_BACKLOG;
	if(!pa_root[pa_root_i]->bufsize) pa_root[pa_root_i]->bufsize = PA_DFL_LISTEN_INITIAL;
	if(!pa_root[pa_root_i]->queue) pa_root[pa_root_i]->queue = PA_DFL_LISTEN_QUEUE;
	if(!pa_root[pa_root_i]->limit) pa_root[pa_root_i]->limit = PA_DFL_LISTEN_LIMIT;

	/* finish off our last listen instruction. */
	pa_root_i++;

	fclose(fp);

#ifdef PA_DEBUG
	puts("--- pa_conf_parser()");
#endif

	return;
}
