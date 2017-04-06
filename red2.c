/*
 * HeartBit -- the HeartBeat Simulator Framework
 *
 * Copyright (C) 2014 Bolo -- Josef T. Burger
 *
 * All original work here is distributed via a BSD license terms.
 * Basically you are free to use it and you can't take credit for it.
 *
 * Portions of this may reflect code structure and comments from
 * from the openssl codebase.  Please check the SSL copyright if you
 * create deriviative works that would conflict with any copyrights
 * on that code.
 *
 * The SSL copyright is not present because extracts of code are not
 * copyright violations, and fall under the fair use clause of the
 * copyright act.
 */


#include "red.h"
#include <klee/klee.h>


// t1_red_lib.c

/* ssl/t1_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * ...
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * ....
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */


//vuln func. (it) does heartbeat
int
tls1_process_heartbeat(SSL *s)
	{
	unsigned char *p = &s->s3->rrec.data[0], *pl;
	unsigned short hbtype;
	unsigned int payload;
	unsigned int padding = 16; /* Use minimum padding */

	/* Read type and payload length first */
	hbtype = *p++;
	n2s(p, payload);
	pl = p;

	//not used
	if (s->msg_callback)
		s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
			&s->s3->rrec.data[0], s->s3->rrec.length,
			s, s->msg_callback_arg);

	// REQUEST = 1 , RESPONSE = 2
	if (hbtype == TLS1_HB_REQUEST)
		{
		unsigned char *buffer, *bp;
		int r;

		/* Allocate memory for the response, size is 1 bytes
		 * message type, plus 2 bytes payload length, plus
		 * payload, plus padding
		 */
		//padding = 16, 1=msg type, 2=payload len
		buffer = OPENSSL_malloc(1 + 2 + payload + padding);
		bp = buffer;
		
		/* Enter response type, length and copy payload */
		*bp++ = TLS1_HB_RESPONSE;
		s2n(payload, bp);
		memcpy(bp, pl, payload);
		bp += payload;
		/* Random padding */
		RAND_pseudo_bytes(bp, padding);

		r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

		// not used
		if (r >= 0 && s->msg_callback)
			s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
				buffer, 3 + payload + padding,
				s, s->msg_callback_arg);

		OPENSSL_free(buffer);

		if (r < 0)
			return r;
		}

	else if (hbtype == TLS1_HB_RESPONSE)
		{
		unsigned int seq;
		
		/* We only send sequence numbers (2 bytes unsigned int),
		 * and 16 random bytes, so we just try to read the
		 * sequence number */
		n2s(pl, seq);
		
		if (payload == 18 && seq == s->tlsext_hb_seq)
			{
			s->tlsext_hb_seq++;
			s->tlsext_hb_pending = 0;
			}
		}

	return 0;
	}






// first heartbeat vuln should be here => does hb
int
tls1_heartbeat(SSL *s)
	{
	unsigned char *buf, *p;
	int ret;
	unsigned int payload = 18; /* Sequence number + random bytes */
	unsigned int padding = 16; /* Use minimum padding */

	/* Only send if peer supports and accepts HB requests... */
	if (!(s->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED) ||
	    s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS)
		{
		SSLerr(SSL_F_TLS1_HEARTBEAT,SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT);
		return -1;
		}

	/* ...and there is none in flight yet... */
	if (s->tlsext_hb_pending)
		{
		SSLerr(SSL_F_TLS1_HEARTBEAT,SSL_R_TLS_HEARTBEAT_PENDING);
		return -1;
		}
		
	/* ...and no handshake in progress. */
	if (SSL_in_init(s) || s->in_handshake)
		{
		SSLerr(SSL_F_TLS1_HEARTBEAT,SSL_R_UNEXPECTED_MESSAGE);
		return -1;
		}
		
	/* Check if padding is too long, payload and padding
	 * must not exceed 2^14 - 3 = 16381 bytes in total.
	 */
	OPENSSL_assert(payload + padding <= 16381);

	/* Create HeartBeat message, we just use a sequence number
	 * as payload to distuingish different messages and add
	 * some random stuff.
	 *  - Message Type, 1 byte
	 *  - Payload Length, 2 bytes (unsigned int)
	 *  - Payload, the sequence number (2 bytes uint)
	 *  - Payload, random bytes (16 bytes uint)
	 *  - Padding
	 */
	buf = OPENSSL_malloc(1 + 2 + payload + padding);
	p = buf;
	/* Message Type */
	*p++ = TLS1_HB_REQUEST;
	/* Payload length (18 bytes here) */
	s2n(payload, p);
	/* Sequence number */
	s2n(s->tlsext_hb_seq, p);
	/* 16 random bytes */
	RAND_pseudo_bytes(p, 16);
	p += 16;
	/* Random padding */
	RAND_pseudo_bytes(p, padding);

	ret = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buf, 3 + payload + padding);
	if (ret >= 0)
		{
		if (s->msg_callback)
			s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
				buf, 3 + payload + padding,
				s, s->msg_callback_arg);

		s->tlsext_hb_pending = 1;
		}
		
	OPENSSL_free(buf);

	return ret;
	}



//s3_red.both.c

/* ssl/s3_both.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#ifndef OPENSSL_NO_BUF_FREELISTS
/* On some platforms, malloc() performance is bad enough that you can't just
 * free() and malloc() buffers all the time, so we need to use freelists from
 * unused buffers.  Currently, each freelist holds memory chunks of only a
 * given size (list->chunklen); other sized chunks are freed and malloced.
 * This doesn't help much if you're using many different SSL option settings
 * with a given context.  (The options affecting buffer size are
 * max_send_fragment, read buffer vs write buffer,
 * SSL_OP_MICROSOFT_BIG_WRITE_BUFFER, SSL_OP_NO_COMPRESSION, and
 * SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS.)  Using a separate freelist for every
 * possible size is not an option, since max_send_fragment can take on many
 * different values.
 *
 * If you are on a platform with a slow malloc(), and you're using SSL
 * connections with many different settings for these options, and you need to
 * use the SSL_MOD_RELEASE_BUFFERS feature, you have a few options:
 *    - Link against a faster malloc implementation.
 *    - Use a separate SSL_CTX for each option set.
 *    - Improve this code.
 */
static void *
freelist_extract(SSL_CTX *ctx, int for_read, int sz)
	{
	SSL3_BUF_FREELIST *list;
	SSL3_BUF_FREELIST_ENTRY *ent = NULL;
	void *result = NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
	list = for_read ? ctx->rbuf_freelist : ctx->wbuf_freelist;
	if (list != NULL && sz == (int)list->chunklen)
		ent = list->head;
	if (ent != NULL)
		{
		list->head = ent->next;
		result = ent;
		if (--list->len == 0)
			list->chunklen = 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	if (!result)
		result = OPENSSL_malloc(sz);
	return result;
}

static void
freelist_insert(SSL_CTX *ctx, int for_read, size_t sz, void *mem)
	{
	SSL3_BUF_FREELIST *list;
	SSL3_BUF_FREELIST_ENTRY *ent;

	CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
	list = for_read ? ctx->rbuf_freelist : ctx->wbuf_freelist;
	if (list != NULL &&
	    (sz == list->chunklen || list->chunklen == 0) &&
	    list->len < ctx->freelist_max_len &&
	    sz >= sizeof(*ent))
		{
		list->chunklen = sz;
		ent = mem;
		ent->next = list->head;
		list->head = ent;
		++list->len;
		mem = NULL;
		}

	CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	if (mem)
		OPENSSL_free(mem);
	}
#else
#define freelist_extract(c,fr,sz) OPENSSL_malloc(sz)
#define freelist_insert(c,fr,sz,m) OPENSSL_free(m)
#endif

int ssl3_setup_read_buffer(SSL *s)
	{
	unsigned char *p;
	size_t len,align=0,headerlen;
	
	if (SSL_version(s) == DTLS1_VERSION || SSL_version(s) == DTLS1_BAD_VER)
		headerlen = DTLS1_RT_HEADER_LENGTH;
	else
		headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
	align = (-SSL3_RT_HEADER_LENGTH)&(SSL3_ALIGN_PAYLOAD-1);
#endif

	if (s->s3->rbuf.buf == NULL)
		{
		len = SSL3_RT_MAX_PLAIN_LENGTH
			+ SSL3_RT_MAX_ENCRYPTED_OVERHEAD
			+ headerlen + align;
		if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
			{
			s->s3->init_extra = 1;
			len += SSL3_RT_MAX_EXTRA;
			}
#ifndef OPENSSL_NO_COMP
		if (!(s->options & SSL_OP_NO_COMPRESSION))
			len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
		if ((p=freelist_extract(s->ctx, 1, len)) == NULL)
			goto err;
		s->s3->rbuf.buf = p;
		s->s3->rbuf.len = len;
		}

	s->packet= &(s->s3->rbuf.buf[0]);
	return 1;

err:
	SSLerr(SSL_F_SSL3_SETUP_READ_BUFFER,ERR_R_MALLOC_FAILURE);
	return 0;
	}


// buffer creation here(?)
int ssl3_setup_write_buffer(SSL *s)
	{
	unsigned char *p;
	size_t len,align=0,headerlen;

	if (SSL_version(s) == DTLS1_VERSION || SSL_version(s) == DTLS1_BAD_VER)
		headerlen = DTLS1_RT_HEADER_LENGTH + 1;
	else
		headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
	align = (-SSL3_RT_HEADER_LENGTH)&(SSL3_ALIGN_PAYLOAD-1);
#endif

	if (s->s3->wbuf.buf == NULL)
		{
		len = s->max_send_fragment
			+ SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD
			+ headerlen + align;
#ifndef OPENSSL_NO_COMP
		if (!(s->options & SSL_OP_NO_COMPRESSION))
			len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
		if (!(s->options & SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS))
			len += headerlen + align
				+ SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD;

		if ((p=freelist_extract(s->ctx, 0, len)) == NULL)
			goto err;
		s->s3->wbuf.buf = p;
		s->s3->wbuf.len = len;
		}

	return 1;

err:
	SSLerr(SSL_F_SSL3_SETUP_WRITE_BUFFER,ERR_R_MALLOC_FAILURE);
	return 0;
	}

// buffer creation 1
int ssl3_release_write_buffer(SSL *s)
	{
	if (s->s3->wbuf.buf != NULL)
		{
		freelist_insert(s->ctx, 0, s->s3->wbuf.len, s->s3->wbuf.buf);
		s->s3->wbuf.buf = NULL;
		}
	return 1;
	}

// buffer creation 2
int ssl3_release_read_buffer(SSL *s)
	{
	if (s->s3->rbuf.buf != NULL)
		{
		freelist_insert(s->ctx, 1, s->s3->rbuf.len, s->s3->rbuf.buf);
		s->s3->rbuf.buf = NULL;
		}
	return 1;
	}


//red.c

#define	NONAME	"<noname>"
static char *_name = NONAME;

/* Xxx print addresses in buffers, not offsets */
static int print_addrs = 0;

/* Xxx print more details about unprintable chars */
static int print_detail = 0;

/*  print the contents of a "buffer" to see stolen data */
void print_buffer(FILE *fp, unsigned char *buf, int len);

/* TYPE + LEN part of heartbeat packet before payload */
#define	HB_HDR_LEN	3

FILE	*hbout;


void fill_buffer(unsigned char *s, int len, char *pat, int patlen)
{
	int	l = patlen ? patlen : strlen(pat);

	while (len) {
		if (l > len)
			l = len;
		memcpy(s, pat, l);
		s += l;
		len -= l;
	}
}


void init_rec_buf(SSL3_RECORD *r, SSL3_BUFFER *b)
{
	r->data = r->input = &b->buf[0];
	r->type = 0;
	r->length = b->len;
	r->off = 0;
}


void init_ssl3(SSL3_STATE *s3, SSL *s)
{
	ssl3_setup_read_buffer(s);
	fprintf(hbout,
		"%s: SSL exact read buffer len %d\n",
		_name, s3->rbuf.len);
	ssl3_setup_write_buffer(s);
	fprintf(hbout,
		"%s: SSL exact write buffer len %d\n",
		_name, s3->wbuf.len);

	init_rec_buf(&s3->rrec, &s3->rbuf);
	init_rec_buf(&s3->wrec, &s3->wbuf);

	/* XXX simulate tasty data from prior uses of the read buffer */
	fill_buffer(&s3->rbuf.buf[0], s3->rbuf.len,
		    "|READBUF-PRIVATE-CONFIDENTIAL-SECRET", 0);
	fill_buffer(&s3->wbuf.buf[0], s3->wbuf.len,
		    "|writebuf-private-confidential-secret", 0);

	s3->init_extra = 0;

	s3->major = 0;
	s3->minor = 0;
}



/* Takes a chunk of memory and initializes it */
void init_ssl(SSL *s)
{
	int	i;

	s->packet = 0;
	// So there is packet_length field
	s->packet_length = 0;


	// not used in heartbeat
	s->msg_callback = 0;
	s->msg_callback_arg = 0;

	// called only in real heartbear
	s->tlsext_heartbeat = SSL_TLSEXT_HB_ENABLED;
	s->tlsext_hb_seq = 0;
	s->tlsext_hb_pending = 0;
	s->in_handshake = 0;

	s->version = (SSL_VER_MAJOR << 8) | SSL_VER_MINOR;
	s->max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH;
	s->options = 0;

	s->bio_should_retry = 0;

	s->s3 = &s->_s3;
	init_ssl3(s->s3, s);

	/* Add some extra juicy memory to try and have nice stuff to look
	   at instead of a bunch of binary junk */
	for (i = 0; i < NUM_RAND_ALLOCS; i++) {
		char		text[80t		unsigned char	*p;
		int		pl;

		// s->random_memory = OTHER-PRIVATE-CONFIDENTIAL-SECRET-MEMORY
		sprintf(text, "|OTHER-PRIVATE-CONFIDENTIAL-SECRET-MEMORY-%02d",
			i);
		pl = strlen(text) * 32 * (i+1);
		p = malloc(pl);
		fill_buffer(p, pl, text, 0);

		s->random_memory[i] = p;
	}
}


/* Guarantee memory munging of data to write back so it looks valid ;
   this is similar pattern to what openssl uses */

void encrypt_decrypt(unsigned char *ptr, int len)
{
	int	i;

	for (i = 0; i < len; i++)
		ptr[i] ^= 0xff;
}


/* Get the bytes for a SSL record from the I/O device */
/* Combines ssl_get_record and ssl_read..() */
/* XXX remember, grossly simplified */

void ssl3_get_record(SSL *s)
{
	SSL3_RECORD	*rr = &s->s3->rrec;
	SSL3_BUFFER	*rb = &s->s3->rbuf;
	unsigned char	*p = &rb->buf[0];
	int		n;
	int		version;
	/*
	FILE * klee_stdin;
	FILE * klee_stdin2;
	*/

	//klee_make_symbol(&klee_stdin, SSL_HDR_LEN, "input_1");
	// SSL_HDR_LEN = 5, s->s3->rbuf->buf[0] = p: leaked data
	n = fread(p, 1, SSL_HDR_LEN, klee_stdin);
	//klee_make_symbolic(&n, SSL_HDR_LEN, "SSL_HDR_LEN");
	// p = rb->buf[0] make symbolic here (2)
	klee_make_symbol(p, sizeof(p), "buffer_symbol");

	if (n == 0) {
		exit(0);
	}
	if (n != SSL_HDR_LEN) {
		perror("read SSL_HDR_LEN");
		fprintf(stderr, "%s: ssl3_get_rec: read %d vs %d\n",
			_name,
			n, SSL_HDR_LEN);
		exit(1);
	}

	/* unmarshal the header */
	rr->type = *p++;
	s->s3->major = *p++;
	s->s3->minor = *p++;
	version = (s->s3->major << 8) | s->s3->minor;
	if (s->version != version)
		fprintf(stderr, "%s: version mismatch: ssl %x  packet %x\n",
			_name,
			s->version, version);
	n2s(p, rr->length);

	/* XXXX data length --- need to research it */
	if (rr->length > s->s3->rbuf.len - SSL_HDR_LEN)  {
		fprintf(stderr, "%s: packet length %d > max %d\n", 
			_name,
			rr->length, s->s3->rbuf.len - SSL_HDR_LEN);
		exit(1);
	}

	//klee_make_symbol(&klee_stdin2, rr->lenth, "input2");
	n = fread(p, 1, rr->length, stdin);
	klee_make_symbol(p, rr->length, "symbolic_buffer2");

	if (n == 0) {
		fprintf(stderr, "%s: done\n", _name);
		exit(1);
	}
	if (n != rr->length) {
		perror("fread");
		fprintf(stderr, "%s: packet short read length %d != %d\n", 
			_name,
			n, rr->length);
		exit(1);
	}

	/* point record to buffer and setup packet */
	s->packet = &(s->s3->rbuf.buf[0]);
	s->packet_length = SSL_HDR_LEN + rr->length;	//5 + record length
	rr->input = &s->packet[SSL_HDR_LEN];

	/* not certain about these semantics */
	rb->offset = 0;
	rb->left = s->packet_length;

	/* this is where it all is */
	rr->data = rr->input;

	/* VERIFY MAC  ... which isn't encrypted */
	p = rr->data + rr->length - MAC_SZ;
	if (memcmp(p, MAC, MAC_SZ) != 0) {
		fprintf(stderr, "%s: MAC broken\n", _name);
		exit(1);
	}
	/* Skip the mac, by adjusting the length to remove it */
	rr->length -= MAC_SZ;

	/* decrypt data in place */

	/* touch all the packet bytes just like SSL does */
	encrypt_decrypt(rr->data, rr->length);
}

/* XXX the problem here is that the buffer has to be output
   as a bunch of packets.  This makes things more difficult.
   Do the "simple version" first and then do the full version.
   XXX that drives up the cost more, because you then have to 
   reassemble the packets into a record. */


/* Encode traffic and write ssl packet with the content and ty

pe. */

// data output here
int ssl3_write_bytes(SSL *s, int type, unsigned char *buf, int len)
{
	/* This prints "Stolen" data w/out having to send it out somehere,
	   reassemble it, and do all that extra work */

	fprintf(hbout, "HB PACKET  type %d  len %d:\n", type, len);
	print_buffer(hbout, buf, len);

	return len;
}



void print_buffer(FILE *fp, unsigned char *buf, int len)
{
	int	i;
	int	c;
	int	addr = print_addrs;


	for (i = 0; i < len; i++) {
		if ((i % 64) == 0) {
			if (addr)
				fprintf(fp, "\n  %09lx: ", (long)(buf + i));
			else
				fprintf(fp, "\n\t%04x: ", i);
		}

		c = buf[i];
		if (isprint(c))
			fprintf(fp, "%c", c);
		else if (print_detail) {
			if (c & 0x80) {
				fprintf(fp, "M-");
				c = c & 0x7f;
			}
			if (c < 32) {
				/* do C-@ ... C-Z */
				/* or could do ascii NUL .. US */
				fprintf(fp, "C-");
				c += '@';
			}
			fprintf(fp, "%c", c);
		}
		else
			fprintf(fp, ".");
		/* or if a big chunk of binary stuff ....[count] like strace */
	}
	if (i != len && (i % 64)) {
		if (addr)
			fprintf(fp, "\n  %09lx: ", (long)(buf + i));
		else
			fprintf(fp, "\n\t%04x: ", i);
	}
	else
		fprintf(fp, "\n");
}


void examine_hb_packet(SSL *s)
{
	SSL3_RECORD	*rr = &s->s3->rrec;
	unsigned char	*p = &rr->data[0];
	int		hblen;
	int		hbtype;
	int		seqno = -1;

	hbtype = *p++;
	n2s(p, hblen);
	if (hblen >= 2)	/* grab a seqno if it might be there */
		n2s(p, seqno);


	// Where problem happens.
	// if hblen + HB_HDR_LEN > rr-> length problem happens
	if (hblen + HB_HDR_LEN > rr->length) {
		fprintf(hbout, "%s: heartbleed detected pkt len %d hblen %d\n",
			_name,
			rr->length, hblen);
	}
	else {
		fprintf(hbout,
			"%s: heartbeat likely  pkt len %d  hblen %d  seqno %d\n",
			_name,
			rr->length, hblen, seqno);
	}
}


/* Make this thing look _just_like the interface that is used, to prove
   a point ... */

int ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek)
{
	/* It's simple ... nothing changes at all */
	SSL3_RECORD	*rr = &s->s3->rrec;

	ssl3_get_record(s);


	s->bio_should_retry = 0;

	/* If we are waiting for this kind of packet, return it
	   juast as SSL does to simulate passing results back
	   to user */

	// len == 23
	if (rr->type == type) {
		int	l = len;
		if (l > rr->length)
			l = rr->length;
		memcpy(buf, rr->data, l);
		return l;
	}

	/* Otherwise we have to deal with other packets */

	switch (rr->type) {
		//tls1_RT_HB == 24
	case TLS1_RT_HEARTBEAT:
		fprintf(hbout,
			"%s: received packet type TLS1_RT_HEARTBEAT  length %d\n",
			_name,
			rr->length);
		/* examine it for details */
		// guess not a default func. but for ex hb
		examine_hb_packet(s);
		//vuln func here!
		(void) tls1_process_heartbeat(s);
		s->bio_should_retry++;
		return -1;
		break;

	default:
		fprintf(stderr,
			"%s: process_traffic: unknown: type %d length %d\n",
			_name,
			rr->type, rr->length);
		exit(1);
	}
	return 0;
}






/* This shows how a typical application isn't really aware of the heartbeat
   packets at all.  All it sees is "read again" from ssl.   See how the
   application just gets "read again" when a heartbeat comes through,
   same as a non-blocking I/O, etc  */

//second func.

void process_ssl_traffic(SSL *s)
{
	/* this thing just goes on forever until something goes wrong,
	   and then it aborts from there. */

	unsigned char	buf[80];
	int		n;

	// reading ssl bytes. No checking pt
	for (;;) {

		//len == 23
		n = ssl3_read_bytes(s, SSL3_RT_APPLICATION_DATA,
				    buf, sizeof(buf), 0);
		/* Did we get something useful? */
		if (n > 0) {
			/* Print something useful */
			fprintf(hbout, "%s: data %d: '", _name, n);
			print_buffer(hbout, buf, n);
			fprintf(hbout, "'\n");
			continue;
		}

		/* Keep on reading if there was a retryable error */
		if (n == -1 && !s->bio_should_retry)
			break;

		/* Just simulate retryable errors in this case to
		   prove the point of how applications tend to work
		   between non-blocking I/O, short reads, etc */
	}

	fprintf(stderr, "%s: give-up: non retryable error\n", _name);
}



int main(int argc, char **argv)
{
	char	namebuf[128];

	// SSL packet *s
	SSL	*s = 0;

	// hbout for stdout -> result stdout
	hbout = stdout;

	sprintf(namebuf, "red-blood");
	_name = namebuf;

	s = malloc(sizeof(SSL));
	if (!s) {
		perror("malloc SSL");
		return(1);
	}
	init_ssl(s);


	fprintf(hbout, "%s: starting heartbeat reader\n", _name);

	// starting first function
	process_ssl_traffic(s);

	/* NO ATTEMPT MADE TO CLEAN UP ANYTHING FOR SIMPLICITY */

	_name = NONAME;

	return 0;
}
