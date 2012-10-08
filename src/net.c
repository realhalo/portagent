/* [portagent] net.c :: socket related routines for portagent.
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
struct pa_conn_s **pa_conn;
signed int pa_conn_i = -1;
unsigned short pa_log_id = 0;
unsigned int pa_total = 0;

/* externs. */
extern struct pa_root_s **pa_root;
extern signed int pa_root_i;
extern const struct pa_ifmap_s pa_ifmap[];


/* set a socket/fd to non-blocking. */
void pa_set_nonblock(signed int fd) {
	int options, so;

#ifdef PA_DEBUG
	puts("+++ pa_set_nonblock()");
#endif

	options = fcntl(fd, F_GETFL);
	if(options < 0)
		pa_error(PA_MSG_ERR, "fcntl() get failed.");

	options = (options | O_NONBLOCK);
	if(fcntl(fd, F_SETFL, options) < 0)
		pa_error(PA_MSG_ERR, "fcntl() set failed.");

	/* putting these here since it applies to all; our queue size is the same. */
	so = PA_BUFSIZE_GIANT;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &so, sizeof(so));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &so, sizeof(so));

#ifdef PA_DEBUG
	puts("--- pa_set_nonblock()");
#endif

	return;
}

/* shutdown and close a socket. (static -1 return just to set the fd to) */
signed int pa_shutdown(signed int s) {

#ifdef PA_DEBUG
	puts("*** pa_shutdown()");
#endif

	if(s < 0) return(-1);
	shutdown(s, 2);
	close(s);
	return(-1);
}

/* send to a socket, or save it in the queue if there is one.  does not handle encryption or splitting large buffers. */
ssize_t pa_send(unsigned int i, unsigned char type, char *buf, size_t len, signed int flags) {
	unsigned char active;
	signed int fd;
	ssize_t s;

#ifdef PA_DEBUG
	puts("+++ pa_send()");
#endif

	/* which connection are we sending to. */
	if(type == PA_QUEUE_CONN) {
		fd = pa_conn[i]->conn_fd;
		active = pa_conn[i]->conn_queue_active;

		/* we'll be active after this either way. */
		pa_conn[i]->conn_queue_active = 1;
	}

	/* ...or PA_QUEUE_FWD. */
	else {
		fd = pa_conn[i]->fwd_fd;
		active = pa_conn[i]->fwd_queue_active;

		/* we'll be active after this either way. */
		pa_conn[i]->fwd_queue_active = 1;
	}

	/* we have stuff in the queue already, so just add to it. */
	if(active) {
		pa_queue_new(i, buf, len, type);
		s = len;
	}

	/* nothing in the queue, send it out now. */
	else {

		/* fd exist yet? */
		if(fd < 0) s = -1;
		else s = send(fd, buf, len, flags);

		/* error? add it to the queue i guess. */
		if(s < 0) {
			pa_queue_new(i, buf, len, type);
			s = len;
		}

		/* didn't send it all? save what's left. */
		else if(s < len) {
			pa_queue_new(i, buf + s, len - s, type);
			s = len - s;
		}

	}

#ifdef PA_DEBUG
	puts("--- pa_send()");
#endif

	return(s);
}

/* splits data that -could- be larger than PA_BUFSIZE_GIANT into multiple segments, then passes to pa_send().  handles encryption. */
ssize_t pa_send_split(unsigned int i, unsigned char type, char *raw_buf, size_t raw_len, signed int flags) {
	struct pa_bf_ctx_s *ctx;
	char *seg, *enc_buf, *buf;
	ssize_t s, t;
	size_t slen;
	unsigned int enc_len, len;

#ifdef PA_DEBUG
	puts("+++ pa_send_split()");
#endif

	ctx = NULL;

	/* this should always be true. */
	if(pa_conn && pa_conn[i]) {
		if(type == PA_QUEUE_CONN && pa_conn[i]->ctx_conn)
			ctx = pa_conn[i]->ctx_conn;

		else if(type == PA_QUEUE_FWD && pa_conn[i]->ctx_fwd)
			ctx = pa_conn[i]->ctx_fwd;
	}

	if(ctx)
		enc_buf = (char *)pa_bf_encrypt_str(i, type, (unsigned char *)raw_buf, (unsigned int)raw_len, &enc_len);
	else {
		enc_buf = 0;
		enc_len = 0;
	}

	buf = (enc_buf ? enc_buf : raw_buf);
	len = (unsigned int)(enc_len ? enc_len : raw_len);

	for(s = t = 0; t < len; t += PA_BUFSIZE_GIANT) {
		slen = len - t;
		if(slen > PA_BUFSIZE_GIANT) slen = PA_BUFSIZE_GIANT;

		if(!(seg = (char *)malloc(slen + 1)))
			pa_error(PA_MSG_ERR, "failed to allocate memory for send segment buffer.");
		memcpy(seg, buf + t, slen);

		s += pa_send(i, type, seg, slen, flags);

		free(seg);
	}

	if(enc_buf)
		free(enc_buf);

#ifdef PA_DEBUG
	puts("--- pa_send_split()");
#endif

	return(s);
}

/* split sending, tunnelling with decryption/rewriting.  */
ssize_t pa_send_tunnel(unsigned int i, unsigned char type, char *buf, size_t len, unsigned char do_rewrite, unsigned char do_dec, signed int flags) {
	char *dec, *rewrite;
	unsigned int dec_len;
	size_t rewrite_len;
	ssize_t s;	

#ifdef PA_DEBUG
	puts("*** pa_send_tunnel()");
#endif

	s = 0;

	/* encrypted tunnel. */
	if(do_dec && (type==PA_QUEUE_CONN?pa_conn[i]->ctx_fwd:pa_conn[i]->ctx_conn)) {
		if((dec = (char *)pa_bf_decrypt_str(i, (type==PA_QUEUE_CONN?PA_QUEUE_FWD:PA_QUEUE_CONN), (unsigned char *)buf, len, &dec_len))) {

			/* rewrite needed? */
			if(do_rewrite && (rewrite = pa_rewrite(pa_conn[i]->pa_root, (type==PA_QUEUE_CONN?PA_REWRITE_SERVER:PA_REWRITE_CLIENT), dec, dec_len, &rewrite_len))) {
				s = pa_send_split(i, (type==PA_QUEUE_CONN?PA_QUEUE_CONN:PA_QUEUE_FWD), rewrite, rewrite_len, MSG_NOSIGNAL);
				free(rewrite);
			}
			else
				/* was pa_send. (v1.2 and below) */
				s = pa_send_split(i, (type==PA_QUEUE_CONN?PA_QUEUE_CONN:PA_QUEUE_FWD), dec, dec_len, MSG_NOSIGNAL);

			free(dec);
		}
	}

	/* not encrypted. */
	else {

		/* rewrite needed? */
		if(do_rewrite && (rewrite = pa_rewrite(pa_conn[i]->pa_root, (type==PA_QUEUE_CONN?PA_REWRITE_SERVER:PA_REWRITE_CLIENT), buf, len, &rewrite_len))) {
			s = pa_send_split(i, (type==PA_QUEUE_CONN?PA_QUEUE_CONN:PA_QUEUE_FWD), rewrite, rewrite_len, MSG_NOSIGNAL);
			free(rewrite);
		}
		else
			/* was pa_send. (v1.2 and below) */
			s = pa_send_split(i, (type==PA_QUEUE_CONN?PA_QUEUE_CONN:PA_QUEUE_FWD), buf, len, MSG_NOSIGNAL);
	}

	return(s);
}


/* get and return the highest listening fd, for select()'s. */
signed int pa_find_high_fd() {
	signed int i, highest;

#ifdef PA_DEBUG
	puts("+++ pa_find_high_fd()");
#endif

	/* check our local bind sockets. */
	for(highest = -1, i = 0; i < pa_root_i; i++) {
		if(pa_root[i]->fd > highest)
			highest = pa_root[i]->fd;
	}

	/* check our connected sockets. (this will probably have the highest one) */
	for(i = 0; i <= pa_conn_i; i++) {
		if(pa_conn[i]->conn_fd > highest)
			highest = pa_conn[i]->conn_fd;
		if(pa_conn[i]->fwd_fd > highest)
			highest = pa_conn[i]->fwd_fd;
	}

#ifdef PA_DEBUG
	puts("--- pa_find_high_fd()");
#endif

	return(highest);
}

/* find the root element by it's file descriptor. */
signed int pa_find_root_by_fd(signed int fd) {
	unsigned int i;
#ifdef PA_DEBUG
	puts("*** pa_find_root_by_fd()");
#endif

	for(i = 0; i < pa_root_i; i++) {
		if(pa_root[i]->fd == fd) return(i);
	}
	return(-1);
}

/* return the number of connections to a root element. (port) */
signed int pa_root_tot_conn(signed int root) {
	signed int i, tot;

#ifdef PA_DEBUG
	puts("*** pa_root_tot_conn()");
#endif

	/* out of bounds, or not allocated at all yet? */
	if(root < 0 || root > pa_root_i) return(-1);
	else if(pa_conn_i < 0) return(0);

	for(i = 0, tot = 0; i <= pa_conn_i; i++) {
		if(pa_conn[i]->pa_root == root && pa_conn[i]->status != PA_CONN_REUSE) tot++;
	}

	return(tot);
}

/* add a new connection to the list. (make room if needed) */
signed int pa_conn_add(signed int root_fd, signed int conn_fd) {
	signed int i;

#ifdef PA_DEBUG
	puts("+++ pa_conn_add()");
#endif

	/* first connection to any of our listens. */
	if(pa_conn_i < 0) {
		if(!(pa_conn = (struct pa_conn_s **)malloc(sizeof(struct pa_conn_s *) * 2)))
			pa_error(PA_MSG_ERR, "failed to allocate memory for root connection structure.");
	}

	/* just another connection OR reuse an old entry instead of allocating a new one. */
	else {

		/* see if we can reuse an old entry first. */
		for(i = 0; i <= pa_conn_i; i++) {
			if(pa_conn[i]->status == PA_CONN_REUSE) {

				/* add our new connection in a reusable slot. */
				pa_conn_set(i, root_fd, conn_fd);

#ifdef PA_DEBUG
				puts("--- pa_conn_add()");
#endif

				/* return our reused entry instead. */
				return(i);
			}
		}

		/* nothing to reuse, make a new entry. */
		if(!(pa_conn = (struct pa_conn_s **)realloc(pa_conn, sizeof(struct pa_conn_s *) * (pa_conn_i + 2))))
			pa_error(PA_MSG_ERR, "failed to re-allocate memory for root connection structure.");
	}

	pa_conn_i++;

	/* allocate our new connection element/structure. */
	if(!(pa_conn[pa_conn_i] = (struct pa_conn_s *)malloc(sizeof(struct pa_conn_s) + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for an element for root connection structure.");

	/* add our new connection. */
	pa_conn_set(pa_conn_i, root_fd, conn_fd);

#ifdef PA_DEBUG
	puts("--- pa_conn_add()");
#endif

	/* return our new entry. */
	return(pa_conn_i);
}

/* set the values for our new/reused connection. */
void pa_conn_set(unsigned int i, signed int root_fd, signed int conn_fd) {
	char *ptr;

#ifdef PA_DEBUG
	puts("+++ pa_conn_set()");
#endif

	pa_conn[i]->pa_root = pa_find_root_by_fd(root_fd);
	pa_conn[i]->pa_ins_i = 0;
	pa_conn[i]->status = PA_CONN_NONE;
	pa_conn[i]->conn_fd = conn_fd;
	pa_conn[i]->fwd_fd = -1;
	pa_conn[i]->data_size = pa_root[pa_conn[i]->pa_root]->bufsize;
	pa_conn[i]->len = 0;
	pa_conn[i]->pa_log_id = pa_log_id++;
	pa_conn[i]->complete = PA_COMPLETE_FALSE;

	pa_conn[i]->conn_queue = 0;
	pa_conn[i]->conn_queue_last = 0;
	pa_conn[i]->conn_queue_active = 0;
	pa_conn[i]->fwd_queue = 0;
	pa_conn[i]->fwd_queue_last = 0;
	pa_conn[i]->conn_queue_last = 0;
	pa_conn[i]->conn_queue_active = 0;
	pa_conn[i]->queue = 0;

	/* encryption/decrytion structure, they will be added as needed. */
	pa_conn[i]->ctx_fwd = 0;
	pa_conn[i]->ctx_conn = 0;

	pa_timeout_set(i, -1);

	/* try to allocate our user-specified size buffer. */
	if(!(pa_conn[i]->data = (char *)malloc(pa_conn[i]->data_size + 1))) {

		/* fallback to default if it fails. */
		pa_conn[i]->data_size = PA_DFL_LISTEN_INITIAL;
		if(!(pa_conn[i]->data = (char *)malloc(PA_DFL_LISTEN_INITIAL + 1)))
			pa_error(PA_MSG_ERR, "failed to allocate memory for initial data buffer.");
	}

	memset(pa_conn[i]->data, 0, pa_conn[i]->data_size + 1);

	/* update. */
#ifndef NO_SETPROCTITLE
	pa_total++;
	ptr = pa_port_str();
	setproctitle("%u %s %s", pa_total, (pa_total == 1 ? "connection" : "connections"), ptr);
	free(ptr);
#endif

#ifdef PA_DEBUG
	puts("--- pa_conn_set()");
#endif

	return;
}

/* free up a connection slot to potentially be reused again later. */
void pa_conn_free(unsigned int i) {
	char *ptr;

#ifdef PA_DEBUG
	puts("+++ pa_conn_free()");
#endif

	/* shouldn't happen, but why not be safe. */
	if(pa_conn[i]->status == PA_CONN_REUSE) return;

	/* close what we have open for this connection. */
	if(pa_conn[i]->conn_fd >= 0) pa_conn[i]->conn_fd = pa_shutdown(pa_conn[i]->conn_fd);
	if(pa_conn[i]->fwd_fd >= 0) pa_conn[i]->fwd_fd = pa_shutdown(pa_conn[i]->fwd_fd);

	/* let it be known this can be reused. */
	pa_conn[i]->status = PA_CONN_REUSE;

	pa_conn[i]->data_size = 0;
	pa_conn[i]->timeout = 0;
	pa_conn[i]->pa_root = 0;
	pa_conn[i]->pa_ins_i = 0;
	pa_conn[i]->pa_log_id = 0;
	pa_conn[i]->complete = PA_COMPLETE_FALSE;

	pa_queue_free(i);

	if(pa_conn[i]->data) 
		free(pa_conn[i]->data);
	pa_conn[i]->data = 0;
	pa_conn[i]->len = 0;

	if(pa_conn[i]->ctx_conn)
		free(pa_conn[i]->ctx_conn);
	pa_conn[i]->ctx_conn = 0;
	if(pa_conn[i]->ctx_fwd) 
		free(pa_conn[i]->ctx_fwd);
	pa_conn[i]->ctx_fwd = 0;

	memset((char *)&pa_conn[i]->conn_sock, 0, sizeof(struct sockaddr_in));
	memset((char *)&pa_conn[i]->fwd_sock, 0, sizeof(struct sockaddr_in));

	/* update. */
#ifndef NO_SETPROCTITLE
	pa_total--;
	ptr = pa_port_str();
	setproctitle("%u %s %s", pa_total, (pa_total == 1 ? "connection" : "connections"), ptr);
	free(ptr);
#endif

#ifdef PA_DEBUG
	puts("--- pa_conn_free()");
#endif

	return;
}

/* try to connect to a forwarded. */
signed int pa_try_conn(unsigned int i, struct sockaddr_in sa) {
	char *rewrite;
	size_t rewrite_len;

	if(i > pa_conn_i || pa_conn[i]->status == PA_CONN_REUSE) return(-1);

#ifdef PA_DEBUG
	puts("+++ pa_try_conn()");
#endif

	/* if we're already "TRY"ing something, close the old one. */
	if(pa_conn[i]->fwd_fd >= 0) {
		pa_log(i, "connection closed by portagent: %s:%u (new try)", inet_ntoa(pa_conn[i]->fwd_sock.sin_addr), htons(pa_conn[i]->fwd_sock.sin_port));
		pa_conn[i]->fwd_fd = pa_shutdown(pa_conn[i]->fwd_fd);

		/* just incase anything is in the pipes still, drop it. */
		pa_queue_free(i);
	}

	memcpy(&pa_conn[i]->fwd_sock, &sa, sizeof(struct sockaddr_in));
	if((pa_conn[i]->fwd_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		pa_error(PA_MSG_ERR, "failed to allocate socket for forwarding.");

	pa_set_nonblock(pa_conn[i]->fwd_fd);

	if (connect(pa_conn[i]->fwd_fd, (struct sockaddr *)&pa_conn[i]->fwd_sock, sizeof(pa_conn[i]->fwd_sock)) == -1) {

		/* should only be "in progress" if we made it here, otherwise it failed. */
		if(errno != EINPROGRESS) {

			/* this was supposed to be the "USE" connection, it failed.  kill it. */
			if(pa_conn[i]->complete) pa_conn_free(i);

			/* just a "TRY", let it go. */
			else {
				pa_conn[i]->status = PA_CONN_NONE;
				pa_conn[i]->fwd_fd = pa_shutdown(pa_conn[i]->fwd_fd);
			}
		}

		/* will be checked later, still trying to connect. */
		else pa_conn[i]->status = PA_CONN_CONNECTING;
	}

	/* immediate connection. */
	else {
		pa_conn[i]->status = PA_CONN_CONNECTED;

		/* encrypted tunnel? send out identity. */
		if(pa_conn[i]->ctx_fwd)
			(void)pa_send(i, PA_QUEUE_FWD, pa_conn[i]->ctx_fwd->identity, PA_IDENTITY_LEN, MSG_NOSIGNAL);

		/* we have initial data to send? send it. */
		if(pa_conn[i]->len) {

			/* rewrite needed? */
			if((rewrite = pa_rewrite(pa_conn[i]->pa_root, PA_REWRITE_CLIENT, pa_conn[i]->data, pa_conn[i]->len, &rewrite_len))) {
				(void)pa_send_split(i, PA_QUEUE_FWD, rewrite, rewrite_len, MSG_NOSIGNAL);
				free(rewrite);
			}
			else
				(void)pa_send_split(i, PA_QUEUE_FWD, pa_conn[i]->data, pa_conn[i]->len, MSG_NOSIGNAL);
		}
	}

#ifdef PA_DEBUG
	puts("--- pa_try_conn()");
#endif

	return(pa_conn[i]->fwd_fd);
}

/* someone has tried to connect to one of the ports, accept it. */
signed int pa_listen_new(signed int fd) {
	signed int new_fd, new, root, tot;
	socklen_t salen;
	struct sockaddr_in sa;

#ifdef PA_DEBUG
	puts("*** pa_listen_new()");
#endif

	salen = sizeof(sa);
	if((new_fd = accept(fd, (struct sockaddr *)&sa, &salen)) < 0)
		return(-1);

	pa_set_nonblock(new_fd);

	/* total connections on this root element. */
	root = pa_find_root_by_fd(fd);
	tot = pa_root_tot_conn(root);

	/* should never happen, and check to see if we past the LIMIT. */
	if(tot < 0 || tot >= pa_root[root]->limit) {
		(void)pa_shutdown(new_fd);
		return(-1);
	}

	/* try to add the connection to our internal list. */
	else if((new = pa_conn_add(fd, new_fd)) < 0) {
		(void)pa_shutdown(new_fd);
		return(-1);
	}

	/* copy our sockaddr into our new connection. */
	memcpy(&pa_conn[new]->conn_sock, &sa, salen);

	pa_log(new, "new connection: %s:%u", inet_ntoa(pa_conn[new]->conn_sock.sin_addr), htons(pa_conn[new]->conn_sock.sin_port));

	return(new_fd);
}

/* we have activity on one of the sockets were listening on. */
void pa_listen_read(fd_set fds, fd_set wfds) {
	struct pa_queue_s *pa_queue;
	char dump[PA_BUFSIZE_GIANT + 1], *rewrite, *dec;
	signed int i, l, r, s, se;
	unsigned int dec_len;
	size_t rewrite_len;
	socklen_t selen;

#ifdef PA_DEBUG
	puts("+++ pa_listen_read()");
#endif

	/* is the activity on the root listening sockets? must be a new connection. */
	for(i = 0; i < pa_root_i; i++) {
		if(FD_ISSET(pa_root[i]->fd, &fds))
			pa_listen_new(pa_root[i]->fd);
	}

	/* some activity from a connection to us? */
	for(i = 0; i <= pa_conn_i; i++) {

		/* read activity? */
		if(pa_conn[i]->conn_fd >= 0 && FD_ISSET(pa_conn[i]->conn_fd, &fds)) {

			/* read what we got. */
			r = recv(pa_conn[i]->conn_fd, dump, PA_BUFSIZE_GIANT, MSG_DONTWAIT);

			/* connection closed remotely(or error), clean it up to be reused later. */
			if(r < 1) {

				/* still stuff going down the pipes? */
				if(pa_conn[i]->complete != PA_COMPLETE_WAIT && pa_conn[i]->fwd_queue_active) {
					pa_log(i, "connection closed by remote: %s:%u (data still queued, wait)", inet_ntoa(pa_conn[i]->conn_sock.sin_addr), htons(pa_conn[i]->conn_sock.sin_port));
					pa_conn[i]->complete = PA_COMPLETE_WAIT;

					/* close the dead socket. */
					pa_conn[i]->conn_fd = pa_shutdown(pa_conn[i]->conn_fd);
				}

				/* nope, just free it.  */
				else {
					pa_log(i, "connection closed by remote: %s:%u", inet_ntoa(pa_conn[i]->conn_sock.sin_addr), htons(pa_conn[i]->conn_sock.sin_port));
					pa_conn_free(i);
				}
			}

			/* data to be handled from the connection. */
			else {

				/* only deal with initial data if we aren't complete. */
				if(!pa_conn[i]->complete) {

					/* calculate the amount of space left in our "initial buffer". */
					l = pa_conn[i]->data_size - pa_conn[i]->len;
					l = (r > l ? l : r);

					/* copy it to our "initial data" buffer. */
					if(l > 0) {
						memcpy(pa_conn[i]->data + pa_conn[i]->len, dump, l);
						pa_conn[i]->len += l;
					}
				}

				/* at this point the initial buffer can go, it's just taking up space. */
				if(pa_conn[i]->complete == PA_COMPLETE_TRUE_FREE) {
					if(pa_conn[i]->data)
						free(pa_conn[i]->data);
					pa_conn[i]->data = 0;
					pa_conn[i]->len = 0;
					pa_conn[i]->complete = PA_COMPLETE_TRUE;
				}

				/* expecting an encrypted tunnel. */
				if(pa_conn[i]->ctx_conn && !pa_conn[i]->ctx_conn->validated) {

					/* valid key? */
					if(r >= PA_IDENTITY_LEN && !memcmp(pa_conn[i]->ctx_conn->identity, dump, PA_IDENTITY_LEN)) {
						pa_conn[i]->ctx_conn->validated = 1;

						r -= PA_IDENTITY_LEN;

						/* validated, with extra data after the identity, move it over. */
						if(r > 0)
							memmove(dump, dump + PA_IDENTITY_LEN, r);
					}

					/* expected key for this connection and didn't get it, kill it. */
					else
						pa_conn_free(i);
				}

				/* tunnel data: conn->fwd. (v1.2 and earlier did not check for PA_CONN_CONNECTING) */
				if(r > 0 && (pa_conn[i]->status == PA_CONN_CONNECTED || pa_conn[i]->status == PA_CONN_CONNECTING)) {

					/* make sure the encryption identity is the first thing in the queue, sending is all that is needed to validate from the client side. */
					if(pa_conn[i]->status == PA_CONN_CONNECTING && pa_conn[i]->ctx_fwd && !pa_conn[i]->ctx_fwd->validated) {
						(void)pa_send(i, PA_QUEUE_FWD, pa_conn[i]->ctx_fwd->identity, PA_IDENTITY_LEN, MSG_NOSIGNAL);
						pa_conn[i]->ctx_fwd->validated = 1;
					}

(void)pa_send_tunnel(i, PA_QUEUE_FWD, dump, r, 1, 1, MSG_NOSIGNAL);

if(0) {
					/* rewrite needed? */
					if((rewrite = pa_rewrite(pa_conn[i]->pa_root, PA_REWRITE_CLIENT, dump, r, &rewrite_len))) {
						(void)pa_send_split(i, PA_QUEUE_FWD, rewrite, rewrite_len, MSG_NOSIGNAL);
						free(rewrite);
					}
					else
						/* was pa_send. (v1.2 and below) */
						(void)pa_send_split(i, PA_QUEUE_FWD, dump, r, MSG_NOSIGNAL);
}
				}
			}
		}

		/* connecting/reading from the forwarder. */
		if(pa_conn[i]->fwd_fd >= 0) {

			/* read activity from the forwarder? */
			if(FD_ISSET(pa_conn[i]->fwd_fd, &fds)) {

				/* tunnel data: fwd->conn. */
				r = recv(pa_conn[i]->fwd_fd, dump, PA_BUFSIZE_GIANT, MSG_DONTWAIT);

				/* fwd connection closed remotely(or error). */
				if(r < 1) {

					/* actively at a "USE" statement, so this is it, close the connection. */
					if(pa_conn[i]->complete) {

						/* still stuff going down the pipes? */
						if(pa_conn[i]->complete != PA_COMPLETE_WAIT && pa_conn[i]->conn_queue_active) {
							pa_log(i, "connection closed by forward: %s:%u (data still queued, wait)", inet_ntoa(pa_conn[i]->fwd_sock.sin_addr), htons(pa_conn[i]->fwd_sock.sin_port));
							pa_conn[i]->complete = PA_COMPLETE_WAIT;

							/* close the dead socket. */
							pa_conn[i]->fwd_fd = pa_shutdown(pa_conn[i]->fwd_fd);
						}

						/* nope, just free it.  */
						else {
							pa_log(i, "connection closed by forward: %s:%u", inet_ntoa(pa_conn[i]->fwd_sock.sin_addr), htons(pa_conn[i]->fwd_sock.sin_port));
							pa_conn_free(i);
						}
					}

					/* otherwise just close/cleanup the socket. */
					else {
						pa_log(i, "connection closed by forward: %s:%u (non-use)", inet_ntoa(pa_conn[i]->fwd_sock.sin_addr), htons(pa_conn[i]->fwd_sock.sin_port));
						pa_conn[i]->status = PA_CONN_NONE;
						pa_conn[i]->fwd_fd = pa_shutdown(pa_conn[i]->fwd_fd);

						/* just incase anything is in the pipes still, drop it. */
						pa_queue_free(i);
					}
				}

				/* write what we read. */
				else {




(void)pa_send_tunnel(i, PA_QUEUE_CONN, dump, r, 1, 1, MSG_NOSIGNAL);

if(0) {
					/* encrypted tunnel. */
					if(pa_conn[i]->ctx_fwd) {
						if((dec = (char *)pa_bf_decrypt_str(i, PA_QUEUE_FWD, (unsigned char *)dump, r, &dec_len))) {

							/* rewrite needed? */
							if((rewrite = pa_rewrite(pa_conn[i]->pa_root, PA_REWRITE_SERVER, dec, dec_len, &rewrite_len))) {
								(void)pa_send_split(i, PA_QUEUE_CONN, rewrite, rewrite_len, MSG_NOSIGNAL);
								free(rewrite);
							}
							else
								/* was pa_send. (v1.2 and below) */
								(void)pa_send_split(i, PA_QUEUE_CONN, dec, dec_len, MSG_NOSIGNAL);

							free(dec);
						}
					}

					/* not encrypted. */
					else {

						/* rewrite needed? */
						if((rewrite = pa_rewrite(pa_conn[i]->pa_root, PA_REWRITE_SERVER, dump, r, &rewrite_len))) {
							(void)pa_send_split(i, PA_QUEUE_CONN, rewrite, rewrite_len, MSG_NOSIGNAL);
							free(rewrite);
						}
						else
							/* was pa_send. (v1.2 and below) */
							(void)pa_send_split(i, PA_QUEUE_CONN, dump, r, MSG_NOSIGNAL);
					}
}
				}
			}

			/* write activity? (initial connecting) */
			else if(FD_ISSET(pa_conn[i]->fwd_fd, &wfds) && pa_conn[i]->status == PA_CONN_CONNECTING) {
				se = 0;
				selen = sizeof(se);

				if (getsockopt(pa_conn[i]->fwd_fd, SOL_SOCKET, SO_ERROR, &se, &selen) == -1 || se != 0) {

					/* failed on a "USE", kill it. */
					if(pa_conn[i]->complete) pa_conn_free(i);

					/* just a "TRY". */
					else {
						pa_conn[i]->fwd_fd = pa_shutdown(pa_conn[i]->fwd_fd);
						pa_conn[i]->status = PA_CONN_NONE;
					}

					if(se != 0) pa_log(i, "connection socket error: %s:%u (%s)", inet_ntoa(pa_conn[i]->conn_sock.sin_addr), htons(pa_conn[i]->conn_sock.sin_port), strerror(se));
					else pa_log(i, "connection socket failed.");
				}
				else {
					pa_conn[i]->status = PA_CONN_CONNECTED;

					/* encrypted tunnel? send out our identity.  validated by sending. (only send once) */
					if(pa_conn[i]->ctx_fwd && !pa_conn[i]->ctx_fwd->validated) {
						(void)pa_send(i, PA_QUEUE_FWD, pa_conn[i]->ctx_fwd->identity, PA_IDENTITY_LEN, MSG_NOSIGNAL);
						pa_conn[i]->ctx_fwd->validated = 1;
					}

					/* we have initial data to send? send it. */
					if(pa_conn[i]->len) {

						/* rewrite needed? */
						if((rewrite = pa_rewrite(pa_conn[i]->pa_root, PA_REWRITE_CLIENT, pa_conn[i]->data, pa_conn[i]->len, &rewrite_len))) {
							(void)pa_send_split(i, PA_QUEUE_FWD, rewrite, rewrite_len, MSG_NOSIGNAL);
							free(rewrite);
						}
						else
							(void)pa_send_split(i, PA_QUEUE_FWD, pa_conn[i]->data, pa_conn[i]->len, MSG_NOSIGNAL);
					}
				}
			}

			/* write activity? (forward send queue) */
			else if(FD_ISSET(pa_conn[i]->fwd_fd, &wfds) && pa_conn[i]->status == PA_CONN_CONNECTED) {

				/* nothing to do? */
				if(!(pa_queue = pa_conn[i]->fwd_queue)) {
					pa_conn[i]->fwd_queue_active = 0;

					/* we're waiting to exit. */
					if(pa_conn[i]->complete == PA_COMPLETE_WAIT) pa_conn_free(i);
				}

				/* there's stuff to be sent. */
				else {
					s = send(pa_conn[i]->fwd_fd, pa_queue->data + pa_queue->off, pa_queue->len - pa_queue->off, MSG_NOSIGNAL);
					if(s >= 0) {
						pa_queue->off += s;

						/* this block is done, move on to the next. */
						if(pa_queue->off >= pa_queue->len) {

							/* point to the next one. (might be null) */
							pa_conn[i]->fwd_queue = pa_queue->next;

							/* shave off. */
							pa_conn[i]->queue -= pa_queue->len;

							free(pa_queue);

							/* the queue is now empty. */
							if(!pa_conn[i]->fwd_queue) {
								pa_conn[i]->fwd_queue_active = 0; 

								/* we're waiting to exit. */
								if(pa_conn[i]->complete == PA_COMPLETE_WAIT) pa_conn_free(i);
							}
						}
					}

					/* send error'd? just panic cause it will be tainted from here on anyways. */
					else{
						pa_log(i, "connection closed due to forwarding send failure: %s:%u", inet_ntoa(pa_conn[i]->fwd_sock.sin_addr), htons(pa_conn[i]->fwd_sock.sin_port));
						pa_conn_free(i);
					}
				}
			}
		}

		/* connecting/reading from the connection. */
		if(pa_conn[i]->conn_fd >= 0) {

			/* write activity? (connection send queue) */
			if(FD_ISSET(pa_conn[i]->conn_fd, &wfds) && pa_conn[i]->status == PA_CONN_CONNECTED) {

				/* nothing to do? */
				if(!(pa_queue = pa_conn[i]->conn_queue)) {
					pa_conn[i]->conn_queue_active = 0;

					/* we're waiting to exit. */
					if(pa_conn[i]->complete == PA_COMPLETE_WAIT) pa_conn_free(i);
				}

				else {
					s = send(pa_conn[i]->conn_fd, pa_queue->data + pa_queue->off, pa_queue->len - pa_queue->off, MSG_NOSIGNAL);

					if(s >= 0) {
						pa_queue->off += s;

						/* this block is done, move on to the next. */
						if(pa_queue->off >= pa_queue->len) {

							/* point to the next one. (might be null) */
							pa_conn[i]->conn_queue = pa_queue->next;

							/* shave off. */
							pa_conn[i]->queue -= pa_queue->len;

							free(pa_queue);

							/* the queue is now empty. */
							if(!pa_conn[i]->conn_queue) {
								pa_conn[i]->conn_queue_active = 0; 

								/* we're waiting to exit. */
								if(pa_conn[i]->complete == PA_COMPLETE_WAIT) pa_conn_free(i);
							}
						}
					}

					/* send error'd? just panic cause it will be tainted from here on anyways. */
					else {
						pa_log(i, "connection closed due to send failure: %s:%u", inet_ntoa(pa_conn[i]->conn_sock.sin_addr), htons(pa_conn[i]->conn_sock.sin_port));
						pa_conn_free(i);
					}
				}
			}
		}
	}

#ifdef PA_DEBUG
	puts("--- pa_listen_read()");
#endif

	return;
}

/* create a fd_set list of all of our binded sockets for select(). */
fd_set pa_listen_fd_set() {
	signed int i;
	fd_set fds;

#ifdef PA_DEBUG
	puts("+++ pa_listen_fd_set()");
#endif

	FD_ZERO(&fds);

	/* add our listening sockets. */
	for(i = 0; i < pa_root_i; i++) {
		if(pa_root[i]->fd >= 0)
			FD_SET(pa_root[i]->fd, &fds);
	}

	/* check our connections. */
	for(i = 0; i <= pa_conn_i; i++) {
		if(pa_conn[i]->status != PA_CONN_REUSE && pa_conn[i]->conn_fd >= 0) {
			FD_SET(pa_conn[i]->conn_fd, &fds);

			/* currently connected to a try/use host? read it too.  */
			if(pa_conn[i]->status == PA_CONN_CONNECTED && pa_conn[i]->fwd_fd >= 0)
				FD_SET(pa_conn[i]->fwd_fd, &fds);
		}
	}

#ifdef PA_DEBUG
	puts("--- pa_listen_fd_set()");
#endif

	return(fds);
}

/* create a fd_set list of all of our write/connecting sockets for select(). */
fd_set pa_listen_wfd_set() {
	signed int i;
	fd_set wfds;

#ifdef PA_DEBUG
	puts("+++ pa_listen_wfd_set()");
#endif

	FD_ZERO(&wfds);

	/* check our connections. */
	for(i = 0; i <= pa_conn_i; i++) {

		/* from connect() attempt. */
		if(pa_conn[i]->status == PA_CONN_CONNECTING && pa_conn[i]->fwd_fd >= 0)
			FD_SET(pa_conn[i]->fwd_fd, &wfds);

		/* stuff in our send queue for conn/fwd. */
		else if(pa_conn[i]->status == PA_CONN_CONNECTED) {
			if(pa_conn[i]->conn_queue_active && pa_conn[i]->conn_fd >= 0)
				FD_SET(pa_conn[i]->conn_fd, &wfds);
			if(pa_conn[i]->fwd_queue_active && pa_conn[i]->fwd_fd >= 0)
				FD_SET(pa_conn[i]->fwd_fd, &wfds);
		}

	}

#ifdef PA_DEBUG
	puts("--- pa_listen_wfd_set()");
#endif

	return(wfds);
}

/* bind to all of our listening sockets. */
void pa_listen_init() {
	signed int so;
	unsigned int i;

#ifdef PA_DEBUG
	puts("+++ pa_listen_init()");
#endif

	/* time to block this, just incase. */
	signal(SIGPIPE, SIG_IGN);

	for(i = 0; i < pa_root_i; i++) {
		if((pa_root[i]->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
			pa_error(PA_MSG_ERR, "failed to allocate socket for listening.");

		/* don't want things showing in use that aren't upon exits. */
		so = 1;
		setsockopt(pa_root[i]->fd, SOL_SOCKET, SO_REUSEADDR, &so, sizeof(so));
#ifdef SO_REUSEPORT
		setsockopt(pa_root[i]->fd, SOL_SOCKET, SO_REUSEPORT, &so, sizeof(so));
#endif

		/* our queue size is the same. */
		so = PA_BUFSIZE_GIANT;
		setsockopt(pa_root[i]->fd, SOL_SOCKET, SO_SNDBUF, &so, sizeof(so));
		setsockopt(pa_root[i]->fd, SOL_SOCKET, SO_RCVBUF, &so, sizeof(so));

		pa_set_nonblock(pa_root[i]->fd);

		if(bind(pa_root[i]->fd, (struct sockaddr *) &pa_root[i]->sock, sizeof(pa_root[i]->sock)) < 0)
			pa_error(PA_MSG_ERR, "failed to bind to port: %u", htons(pa_root[i]->sock.sin_port));
		listen(pa_root[i]->fd, pa_root[i]->backlog);
	}

#ifdef PA_DEBUG
	puts("--- pa_listen_init()");
#endif

	return;
}

/* the main loop that is always running, all action starts here. */
void pa_listen_loop() {
	unsigned char b, this_type, iflevel;
	signed int i, rs, high, this_len, iffirst, ifmap;
	unsigned int j, k, w;
	char *this_ins, *ptr;

char wtf[1024];
unsigned int wtf_size=(2+8+2+16+2+8);

	fd_set fds, wfds;
	struct timeval tv;

	wtf[0] = 8;
	wtf[1] = 0;
	wtf[2] = 'a';
	wtf[3] = 'a';
	wtf[4] = 'a';
	wtf[5] = 'a';
	wtf[6] = 'b';
	wtf[7] = 'b';
	wtf[8] = 'b';
	wtf[9] = 'b';

	wtf[10] = 16;
	wtf[11] = 0;
	wtf[12] = 'c';
	wtf[13] = 'c';
	wtf[14] = 'c';
	wtf[15] = 'c';
	wtf[16] = 'd';
	wtf[17] = 'd';
	wtf[18] = 'd';
	wtf[19] = 'd';
	wtf[20] = 'e';
	wtf[21] = 'e';
	wtf[22] = 'e';
	wtf[23] = 'e';
	wtf[24] = 'f';
	wtf[25] = 'f';
	wtf[26] = 'f';
	wtf[27] = 'f';

	wtf[28] = 8;
	wtf[29] = 0;
	wtf[30] = '0';
	wtf[31] = '0';
	wtf[32] = '0';
	wtf[33] = '0';
	wtf[34] = '1';
	wtf[35] = '1';
	wtf[36] = '1';
	wtf[37] = '1';


	/* select() forever, hopefully. */
	while(1) {

#ifdef PA_DEBUG
		puts("+++ pa_listen_loop()");
#endif

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		fds = pa_listen_fd_set();
		wfds = pa_listen_wfd_set();
		high = pa_find_high_fd() + 1;

		/* select what to wait for. (only timeout if we are waiting on something, saves processing time) */
		if((rs = select(high, &fds, &wfds, (fd_set *)0, (w ? &tv : NULL))) == -1) break;

		/* we have some action, read it. */
		if(rs > 0) pa_listen_read(fds, wfds);

		/* run through all the connections, handle instruction chains. */
		for(w = 0, i = 0; i <= pa_conn_i; i++) {

			b = 0;

			/* run through the instructions of this particular connection. */
			for(iflevel = PA_IFLEVEL_NONE, iffirst = -1, j = pa_conn[i]->pa_ins_i; !b && !pa_conn[i]->complete && j < pa_root[pa_conn[i]->pa_root]->pa_ins_i; j++) {

				/* non-existent connection, skip it until filled. */
				if(pa_conn[i]->status == PA_CONN_REUSE) continue;

				/* to avoid looking like insanity. */
				this_type = pa_root[pa_conn[i]->pa_root]->pa_ins[j]->type;
				this_ins = pa_root[pa_conn[i]->pa_root]->pa_ins[j]->ins;
				this_len = pa_root[pa_conn[i]->pa_root]->pa_ins[j]->len;

				switch(this_type) {
					case PA_TIMEOUT:
						if(iffirst < 0) pa_timeout_set(i, atoi(this_ins));
						pa_conn[i]->pa_ins_i++; /* NEXT. */
						break;
					case PA_WRITE_SERVER:
						if(iffirst < 0) {

							/* formerly would drop data, instead of queueing it for connections that are not fully connected. */
							/* if(pa_conn[i]->fwd_fd >= 0 && pa_conn[i]->status == PA_CONN_CONNECTED) */
							(void)pa_send_split(i, PA_QUEUE_FWD, this_ins, this_len, MSG_NOSIGNAL);
						}
						pa_conn[i]->pa_ins_i++; /* NEXT. */
						break;
					case PA_WRITE_CLIENT:
						if(iffirst < 0) {

							/* this should always be true. */
							if(pa_conn[i]->conn_fd >= 0)
								(void)pa_send_split(i, PA_QUEUE_CONN, this_ins, this_len, MSG_NOSIGNAL);
						}
						pa_conn[i]->pa_ins_i++; /* NEXT. */
						break;
					case PA_TRY:

						/* we've moved ahaed to try multiple "IF"s, "TRY" is where we stop; break out and fall-back after this loop. */
						if(iffirst >= 0) b = 1;

						/* normal "TRY". */
						else {
							/* different instance, reset our "IF" check. */
							iflevel = PA_IFLEVEL_NONE;

							pa_try_conn(i, pa_atos(this_ins));

							pa_conn[i]->pa_ins_i++; /* NEXT. */
						}
						break;
					case PA_KEY_CLIENT:
					case PA_KEY_SERVER:

						/* set the key/enable encryption for this connection. (tunnel) */
						pa_bf_setup(i, (unsigned char *)this_ins, (unsigned int)this_len, this_type);
						pa_conn[i]->pa_ins_i++; /* NEXT. */


/*
pa_bf_decrypt_str(i, PA_QUEUE_CONN, (unsigned char *)wtf, 1, 0);
pa_bf_decrypt_str(i, PA_QUEUE_CONN, (unsigned char *)wtf+1, 2, 0);
pa_bf_decrypt_str(i, PA_QUEUE_CONN, (unsigned char *)wtf+3, 30, 0);

*/
//pa_bf_decrypt_str(i, PA_QUEUE_CONN, (unsigned char *)wtf, wtf_size-2, 0);
//pa_bf_decrypt_str(i, PA_QUEUE_CONN, (unsigned char *)wtf+(wtf_size-2), 2, 0);

						break;
					case PA_IP:
					case PA_IP_NOT:

						/* the original "IF" should be good if we want to care about this. */
						if(iflevel == PA_IFLEVEL_GOOD) {

							/* ip check matched, set accordingly. */
							if(pa_ip_match(pa_conn[i]->conn_sock, this_ins))
								iflevel = (this_type == PA_IP ? PA_IFLEVEL_GOOD : PA_IFLEVEL_SKIP);

							/* not match, reverse. */
							else
								iflevel = (this_type == PA_IP ? PA_IFLEVEL_SKIP : PA_IFLEVEL_GOOD);

						}
						pa_conn[i]->pa_ins_i++; /* NEXT. */

						break;
					case PA_PORT:
					case PA_PORT_NOT:

						/* the original "IF" should be good if we want to care about this. */
						if(iflevel == PA_IFLEVEL_GOOD) {

							/* port check matched, set accordingly. */
							if(pa_int_range(htons(pa_conn[i]->conn_sock.sin_port), this_ins))
								iflevel = (this_type == PA_PORT ? PA_IFLEVEL_GOOD : PA_IFLEVEL_SKIP);

							/* not match, reverse. */
							else
								iflevel = (this_type == PA_PORT ? PA_IFLEVEL_SKIP : PA_IFLEVEL_GOOD);
						}

						pa_conn[i]->pa_ins_i++; /* NEXT. */

						break;
					case PA_USE:
						if(iflevel != PA_IFLEVEL_SKIP) {
							pa_conn[i]->complete = PA_COMPLETE_TRUE_FREE;
							ptr = this_ins;

							/* it wants to use our last (active) "TRY" statments connection. */
							if(!strcmp(this_ins, "-")) {

								/* not connecting/connected, so it's doomed from here on.  kill it. */
								if(pa_conn[i]->status != PA_CONN_CONNECTING && pa_conn[i]->status != PA_CONN_CONNECTED) {
									pa_conn_free(i);

									/* don't log it if it never made it. */
									ptr = 0;
								}

								/* go back and find what "-" was. (the "TRY") */
								else {
									for(k = j; k > 0; k--) {
										if(pa_root[pa_conn[i]->pa_root]->pa_ins[k]->type == PA_TRY) {
											ptr = pa_root[pa_conn[i]->pa_root]->pa_ins[k]->ins;
											break;
										}
									}
								}

							}

							/* otherwise, let's try something new. */
							else
								pa_try_conn(i, pa_atos(this_ins));

							if(ptr) pa_log(i, "connection forwarded: %s", ptr);
						}

						/* skipping this "USE". */
						else {
							iflevel = PA_IFLEVEL_NONE;
							pa_conn[i]->pa_ins_i++; /* NEXT. */
						}
						break;

					case PA_IF:
					case PA_IFL:
					case PA_IFR:
						iflevel = PA_IFLEVEL_NONE;

						/* generic "IF", will set to something below, if anything. */
						if(this_type == PA_IF) {

							/* non-existent reference, abort the rest. */
							if((ifmap = pa_ifmap_find(this_ins)) < 0)
								this_type = PA_NONE;

							/* matched above, switch it out. */
							else {
								this_type = pa_ifmap[ifmap].type;
								this_ins = pa_ifmap[ifmap].ins;
								this_len = (pa_ifmap[ifmap].len ? pa_ifmap[ifmap].len : strlen(this_ins));
							}

						}

						/* "IF LIKE" */
						if(this_type == PA_IFL) {
							if(pa_likecmp(pa_conn[i]->data, pa_conn[i]->len, this_ins, this_len))
								iflevel = PA_IFLEVEL_GOOD;
						}

						/* "IF REGEXP" */
						else if(this_type == PA_IFR) {
							if(pa_regcmp(pa_conn[i]->data, this_ins))
								iflevel = PA_IFLEVEL_GOOD;
						}

						/* "IF" matched OR timeout past. */
						if(iflevel == PA_IFLEVEL_GOOD || pa_timeout_diff(i) <= 0) {

							/* only skip it if it's timed out. */
							if(iflevel == PA_IFLEVEL_NONE) iflevel = PA_IFLEVEL_SKIP;
						}

						/* still waiting for a timeout on this. */		
						else {

							/* mark what to fall-back on after this run, if it fails. (timeout related) */
							if(iffirst < 0) iffirst = pa_conn[i]->pa_ins_i;

							if(iflevel == PA_IFLEVEL_NONE) iflevel = PA_IFLEVEL_SKIP;

							/* increment of waiting situations. */
							w++;
						}

						pa_conn[i]->pa_ins_i++; /* NEXT. */

						break;
					default:
						pa_conn[i]->pa_ins_i++; /* NEXT. */
						break;
				}
			}

			/* we moved ahead from where we are, set it back. (to test multiple "IF"s) */
			if(iffirst >= 0) {
				pa_conn[i]->pa_ins_i = iffirst;
				iffirst = -1;
			}

			/* not forwarding and we hit the end, drop it. */
			if(!pa_conn[i]->complete && pa_conn[i]->pa_ins_i >= pa_root[pa_conn[i]->pa_root]->pa_ins_i) {
				pa_log(i, "connection closed with no match: %s:%u", inet_ntoa(pa_conn[i]->conn_sock.sin_addr), htons(pa_conn[i]->conn_sock.sin_port));

				pa_conn_free(i);
			}

		}
#ifdef PA_DEBUG
		puts("--- pa_listen_loop()");
#endif
	}
	return;
}
