/* [portagent] bf.c :: blowfish encryption functions for portagent. (koc-based)
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
extern struct pa_conn_s **pa_conn;

/* blowfish related functions. */
unsigned long pa_bf_f(struct pa_bf_ctx_s *ctx, unsigned long x) {
	unsigned short a, b, c, d;
	unsigned long y;

	d = x & 0x00FF;
	x >>= 8;
	c = x & 0x00FF;
	x >>= 8;
	b = x & 0x00FF;
	x >>= 8;
	a = x & 0x00FF;
	y = ctx->S[0][a] + ctx->S[1][b];
	y = y ^ ctx->S[2][c];
	y = y + ctx->S[3][d];

	return(y);
}

void pa_bf_encrypt(struct pa_bf_ctx_s *ctx, unsigned int *xl, unsigned int *xr) {
	unsigned long Xl, Xr, temp;
	short i;

#ifdef PA_DEBUG
	puts("*** pa_bf_encrypt()");
#endif

	Xl = *xl;
	Xr = *xr;

	for (i = 0; i < PA_BF_N; ++i) {
		Xl = Xl ^ ctx->P[i];
		Xr = pa_bf_f(ctx, Xl) ^ Xr;
		temp = Xl;
		Xl = Xr;
		Xr = temp;
	}

	temp = Xl;
	Xl = Xr;
	Xr = temp;
	Xr = Xr ^ ctx->P[PA_BF_N];
	Xl = Xl ^ ctx->P[PA_BF_N+1];

	if(xl)
		*xl = Xl;
	if(xr)
		*xr = Xr;

	return;
}

void pa_bf_decrypt(struct pa_bf_ctx_s *ctx, unsigned int *xl, unsigned int *xr) {
	unsigned long Xl, Xr, temp;
	short i;

#ifdef PA_DEBUG
	puts("*** pa_bf_decrypt()");
#endif

	Xl = *xl;
	Xr = *xr;

	for (i = PA_BF_N + 1; i > 1; --i) {
		Xl = Xl ^ ctx->P[i];
		Xr = pa_bf_f(ctx, Xl) ^ Xr;
		temp = Xl;
		Xl = Xr;
		Xr = temp;
	}

	temp = Xl;
	Xl = Xr;
	Xr = temp;

	Xr = Xr ^ ctx->P[1];
	Xl = Xl ^ ctx->P[0];

	if(xl)
		*xl = Xl;
	if(xr)
		*xr = Xr;

	return;
}

unsigned char *pa_bf_encrypt_str(unsigned int i, unsigned char type, unsigned char *buf, unsigned int len, unsigned int *new_len) {
	struct pa_bf_ctx_s *ctx;
	unsigned char *enc, *enc_ptr, *buf_ptr;
	unsigned int m_l, m_r, enc_len, block_len, l, s;
	unsigned short sl;

#ifdef PA_DEBUG
	puts("*** pa_bf_encrypt_str()");
#endif

	l = len;

	/* ceiling of %8 per block, + 2 for the length of the chunk(this string); */
	s = l + ((l % 8) ? 8 - (l % 8) : 0) + 2;
	if(!(enc = (unsigned char *)malloc(s + 1)))
		pa_error(PA_MSG_ERR, "failed to allocate memory for blowfish encryption.");
	memset(enc, 0, s + 1);

	/* this should always be true. */
	if(pa_conn && pa_conn[i]) {
		if(type == PA_QUEUE_CONN && pa_conn[i]->ctx_conn)
			ctx = pa_conn[i]->ctx_conn;
		else if(type == PA_QUEUE_FWD && pa_conn[i]->ctx_fwd)
			ctx = pa_conn[i]->ctx_fwd;
		else
			return(enc);
	}
	else
		return(enc);

	enc_ptr = enc;
	buf_ptr = buf;

	sl = htons((unsigned short)len);
#ifdef PA_BIG_ENDIAN
	*enc_ptr++ = (sl & 0x00ff);
	*enc_ptr++ = (sl & 0xff00) >> 8;
#else
	*enc_ptr++ = (sl & 0xff00) >> 8;
	*enc_ptr++ = (sl & 0x00ff);
#endif

	while(l) {
		m_l = m_r = 0UL;

		for(block_len = 0; block_len < 4; block_len++) {
			m_l = m_l << 8;
			if (l) {
				m_l += *buf_ptr++;
				l--;
			}
			else m_l += 0;
		}
		for(block_len = 0; block_len < 4; block_len++) {
			m_r = m_r << 8;
			if (l) {
				m_r += *buf_ptr++;
				l--;
			}
			else m_r += 0;
		}

		pa_bf_encrypt(ctx, &m_l, &m_r);
		*enc_ptr++ = (unsigned char)(m_l >> 24);
		*enc_ptr++ = (unsigned char)(m_l >> 16);
		*enc_ptr++ = (unsigned char)(m_l >> 8);
		*enc_ptr++ = (unsigned char)m_l;
		*enc_ptr++ = (unsigned char)(m_r >> 24);
		*enc_ptr++ = (unsigned char)(m_r >> 16);
		*enc_ptr++ = (unsigned char)(m_r >> 8);
		*enc_ptr++ = (unsigned char)m_r;
		enc_len += 8;
	}

	if(new_len)
		*new_len = s;

	return(enc);
}

unsigned char *pa_bf_decrypt_str(unsigned int i, unsigned char type, unsigned char *buf, unsigned int len, unsigned int *new_len) {
	struct pa_bf_ctx_s *ctx;
	unsigned char *dec, *dec_ptr, *buf_ptr, *block_ptr, ready, more;
	unsigned int m_l, m_r, l;
	signed int copy_len, dec_len, dec_block_len, block_len, buf_len, off;

#ifdef PA_DEBUG
	puts("*** pa_bf_decrypt_str()");
#endif

	buf_ptr = buf;
	buf_len = len;
	dec = NULL;
	dec_len = 0;
	dec_block_len = 0;

	/* this should always be true. */
	if(pa_conn && pa_conn[i]) {
		if(type == PA_QUEUE_CONN && pa_conn[i]->ctx_conn)
			ctx = pa_conn[i]->ctx_conn;
		else if(type == PA_QUEUE_FWD && pa_conn[i]->ctx_fwd)
			ctx = pa_conn[i]->ctx_fwd;
		else
			return(dec);
	}
	else
		return(dec);

	/* more to do? set at the end if so. (support multiple len-chunks in one buffer) */
	do {
		off = 0;
		more = 0;
		copy_len = 0;

		/* waiting on the 16bit length of the block. */
		if(ctx->buf_block_len <= 0) {

			/* the 16bit len was broken up into 2 send parts? unlikely, but support it. */
			if(buf_len == 1) {
				/* only len, no data; first 8bit, store it for the next time. */
				if(ctx->buf_block_len != -1) {

					/* mark it as waiting for more. */
					ctx->buf_block_len = -1;
					ctx->buf_real_len = (unsigned char)buf_ptr[0];
					ready = 0;
				}

				/* only len, no data; last 8bit, total with the stored value. */
				else {
					ctx->buf_real_len += ((unsigned char)buf_ptr[0] << 8);
					ready = 1;
					off = 1;
				}
			}

			/* more likely. */
			else if(buf_len >= 2) {

				/* full len and data, common. */
				if(ctx->buf_block_len != -1) {

					/* real length, decrypted. */
					ctx->buf_real_len = (unsigned char)buf_ptr[0] + ((unsigned char)buf_ptr[1] << 8);
					off = 2;
				}

				/* last 8bit len and data, anomaly. */
				else {
					ctx->buf_real_len += ((unsigned char)buf_ptr[0] << 8);
					off = 1;
				}

				ready = 1;
			}

			if(ready) {

				/* block length, encrypted. */
				ctx->buf_block_len = ctx->buf_real_len + ((ctx->buf_real_len % 8) ? 8 - (ctx->buf_real_len % 8) : 0);

				/* reset the counter. */
				ctx->buf_cnt = 0;

				/* this should never happen, no data or bigger than the storage buffer. */
				if(!ctx->buf_real_len || ctx->buf_block_len > PA_BUFSIZE_GIANT) {
					pa_conn_free(i);
					return(dec);
				}
			}
		}

		/* we have the length of the string, and are reading until we have it all. */
		if(ctx->buf_block_len > 0) {
			buf_ptr += off;
			buf_len -= off;

			copy_len = buf_len;

			if(copy_len + ctx->buf_cnt > ctx->buf_block_len)
				copy_len = ctx->buf_block_len - ctx->buf_cnt;

			if(copy_len > 0) {

				/* total would be greater than possible, give up. */
				if(ctx->buf_cnt + copy_len > PA_BUFSIZE_GIANT) {
					pa_conn_free(i);
					return(dec);
				}
				else {
					memcpy(ctx->buf + ctx->buf_cnt, buf_ptr, copy_len);
					ctx->buf_cnt += copy_len;
				}
			}
		}

		/* we got all the data we need for this chunk, decrypt! */
		if(ctx->buf_cnt > 0 && ctx->buf_cnt >= ctx->buf_block_len) {

			if(!dec_block_len) {
				if(!(dec = (unsigned char *)malloc(ctx->buf_block_len + 1)))
					pa_error(PA_MSG_ERR, "failed to allocate memory for blowfish decryption.");
				memset(dec, 0, ctx->buf_block_len  + 1);
			}
			else {

				/* re-allocate using dec_block_len (needed for block decryption, always bigger than dec_len) */
				/* use dec_len (real length) for the pointer */
				if(!(dec = (unsigned char *)realloc(dec, dec_block_len + ctx->buf_block_len + 1)))
					pa_error(PA_MSG_ERR, "failed to re-allocate memory for blowfish decryption.");
				memset(dec + dec_block_len, 0, ctx->buf_block_len);
			}

			/* "+ dec_len" accounts for the previous decrypted chunk, if there was one--otherwise just 0. */
			dec_ptr = dec + dec_len;
			dec_len += ctx->buf_real_len;
			dec_block_len += ctx->buf_block_len;

			l = ctx->buf_block_len;

			block_ptr = ctx->buf;

			while(l) {
				m_l = m_r = 0UL;

				for(block_len = 0; block_len < 4; block_len++) {
					m_l = m_l << 8;
					if (l) {
						m_l += *block_ptr++;
						l--;
					}
					else m_l += 0;
				}
				for(block_len = 0; block_len < 4; block_len++) {
					m_r = m_r << 8;
					if (l) {
						m_r += *block_ptr++;
						l--;
					}
					else m_r += 0;
				}

				pa_bf_decrypt(ctx, &m_l, &m_r);
				*dec_ptr++ = (unsigned char)(m_l >> 24);
				*dec_ptr++ = (unsigned char)(m_l >> 16);
				*dec_ptr++ = (unsigned char)(m_l >> 8);
				*dec_ptr++ = (unsigned char)m_l;
				*dec_ptr++ = (unsigned char)(m_r >> 24);
				*dec_ptr++ = (unsigned char)(m_r >> 16);
				*dec_ptr++ = (unsigned char)(m_r >> 8);
				*dec_ptr++ = (unsigned char)m_r;
			}

			buf_ptr += copy_len;
			buf_len -= copy_len;

			/* more to do in this buffer? */
			if(buf_len > 0)
				more = 1;

			/* reset. */
			ctx->buf_real_len = 0;
			ctx->buf_block_len = 0;
			ctx->buf_cnt = 0;
		}

	} while(more);

	/* set the length if desired. */
	if(new_len && dec_len)
		*new_len = dec_len;

	return(dec);
}

void pa_bf_setup(signed int i, unsigned char *key, unsigned int key_len, unsigned char type) {
	struct pa_bf_ctx_s *ctx;
	unsigned char *ptr;
	unsigned int m_l, m_r, kl, x;

#ifdef PA_DEBUG
	puts("*** pa_bf_setup()");
#endif

	kl = key_len;
	if(kl > PA_BF_KEYLEN_MAX) kl = PA_BF_KEYLEN_MAX;
	if(kl < 8) kl = 8;

	/* we're going to want this off the bat, if it doesn't exist. */
	if(!pa_conf.ctx_cache) {
		if(!(pa_conf.ctx_cache = (struct pa_bf_ctx_s **)malloc(sizeof(struct pa_bf_ctx_s *) * 2)))
			pa_error(PA_MSG_ERR, "failed to allocate memory for the blowfish cache.");
		memset(pa_conf.ctx_cache, 0, sizeof(struct pa_bf_ctx_s *) * 2);
	}

	ctx = NULL;

	/* check the cache to see if we don't need to regenerate the ctx block, copy if exists. */
	for(x = 0; pa_conf.ctx_cache[x]; x++) {
		if(kl == pa_conf.ctx_cache[x]->key_len && !memcmp(pa_conf.ctx_cache[x]->key, key, kl)) {

			if(!(ctx = (struct pa_bf_ctx_s *)malloc(sizeof(struct pa_bf_ctx_s) + 1)))
				pa_error(PA_MSG_ERR, "failed to allocate memory for blowfish cache.");
			memcpy(ctx, pa_conf.ctx_cache[x], sizeof(struct pa_bf_ctx_s));
			break;
		}
	}

	/* wasn't found in the cache above, make it. */
	if(!ctx) {

		/* re-allocation the cache, adding 1. (x = max from above) */
		if(!(pa_conf.ctx_cache = (struct pa_bf_ctx_s **)realloc(pa_conf.ctx_cache, sizeof(struct pa_bf_ctx_s *) * (x + 2))))
			pa_error(PA_MSG_ERR, "failed to re-allocate memory for blowfish cache.");

		/* allocate and init encrpytion. */
		if(!(ctx = (struct pa_bf_ctx_s *)malloc(sizeof(struct pa_bf_ctx_s) + 1)))
			pa_error(PA_MSG_ERR, "failed to allocate memory for blowfish block.");

		memset(ctx, 0, sizeof(struct pa_bf_ctx_s));
	
		memcpy(ctx->key, key, kl);
		ctx->key_len = kl;
		pa_bf_init(ctx, key, kl);

//		pa_bf_encrypt(ctx, &m_l, &m_r);
//		sprintf(ctx->identity, "PAE1-%.8X", m_l);
//		sprintf(ctx->identity, "PAE1-BLOWFISH");

		/* if a ':' exists, take the data after as the identity--otherwise use the whole thing. (potential security issue, not advised) */
		if(!(ptr = (unsigned char *)strchr((char *)key, ':')) || (ptr - key) + 1 >= key_len)
			ptr = key;
		else
			ptr++;

		sprintf(ctx->identity, "PAE1-%.8X", pa_crc32(ptr, key_len - (ptr - key)));

fprintf(stderr, "IDENTITY: %s\n", ctx->identity);

		/* copy it to the cache. */
		if(!(pa_conf.ctx_cache[x] = (struct pa_bf_ctx_s *)malloc(sizeof(struct pa_bf_ctx_s) + 1)))
			pa_error(PA_MSG_ERR, "failed to allocate memory for blowfish cache.");
		memcpy(pa_conf.ctx_cache[x], ctx, sizeof(struct pa_bf_ctx_s));

		/* make sure the for() loop knows where to stop. */
		pa_conf.ctx_cache[x+1] = NULL;
	}

	/* negative numbers(-1) don't intend to be used, just to cache. (only used at start, performance ugliness ignored) */
	if(i < 0)
		free(ctx);

	/* real use. */
	else {
		/* place it where it needs to go. */
		if(type == PA_KEY_SERVER) {
			if(pa_conn[i]->ctx_fwd)
				free(pa_conn[i]->ctx_fwd);
			pa_conn[i]->ctx_fwd = ctx;
		}

		/* PA_KEY_CLIENT */
		else {
			if(pa_conn[i]->ctx_conn)
				free(pa_conn[i]->ctx_conn);
			pa_conn[i]->ctx_conn = ctx;
		}
	}

	return;
}

void pa_bf_init(struct pa_bf_ctx_s *ctx, unsigned char *key, int key_len) {
	signed int i, j, k;
	unsigned int data, datal, datar;

#ifdef PA_DEBUG
	puts("*** pa_bf_init()");
#endif

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 256; j++)
			ctx->S[i][j] = PA_BF_ORIG_S[i][j];
	}

	for (j = i = 0; i < PA_BF_N + 2; ++i) {
		data = 0x00000000;
		for (k = 0; k < 4; ++k) {
			data = (data << 8) | key[j];
			j = j + 1;
			if (j >= key_len)
				j = 0;
		}
		ctx->P[i] = PA_BF_ORIG_P[i] ^ data;
	}

	datal = 0x00000000;
	datar = 0x00000000;

	for (i = 0; i < PA_BF_N + 2; i += 2) {
		pa_bf_encrypt(ctx, &datal, &datar);
		ctx->P[i] = datal;
		ctx->P[i+1] = datar;
	}

	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 256; j += 2) {
			pa_bf_encrypt(ctx, &datal, &datar);
			ctx->S[i][j] = datal;
			ctx->S[i][j+1] = datar;
		}
	}
	return;
}
