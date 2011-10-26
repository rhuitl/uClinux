/*
 * librad.c - RADIUS protocol library.
 *
 * (C) Copyright 2001-2002, Philip Craig (philipc@snapgear.com)
 * (C) Copyright 2001, Lineo Inc. (www.lineo.com)
 * (C) Copyright 2002, SnapGear (www.snapgear.com)
 */

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <md5.h>
#include <magic.h>

#include "radius.h"
#include "librad.h"


#define RESEND_TIMEOUT  3
#define RESEND_COUNT    10
#define RADIUS_ID_FILE "/var/log/radius.id"
#define RADIUS_SESSIONID_FILE "/var/log/radius.sessionid"


static u_char
radius_id(void)
{
	int fd, n;
	u_char id;

	fd = open(RADIUS_ID_FILE, O_RDWR|O_CREAT, 0644);
	if (fd < 0) {
		syslog(LOG_ERR, "RADIUS: open %s failed: %m", RADIUS_ID_FILE);
		return magic();
	}
	if (flock(fd, LOCK_EX) != 0) {
		syslog(LOG_ERR, "RADIUS: flock %s failed: %m", RADIUS_ID_FILE);
	}

	n = read(fd, &id, 1);
	if (n < 1) {
		id = magic();
	} else {
		id++;
	}
	lseek(fd, 0L, SEEK_SET);
	write(fd, &id, 1);
    
	flock(fd, LOCK_UN);
	close(fd);

	return id;
}

u_int
radius_sessionid(void)
{
	int fd, n;
	u_char sessionid;

	fd = open(RADIUS_SESSIONID_FILE, O_RDWR|O_CREAT, 0644);
	if (fd < 0) {
		syslog(LOG_ERR, "RADIUS: open %s failed: %m", RADIUS_SESSIONID_FILE);
		return magic();
	}
	if (flock(fd, LOCK_EX) != 0) {
		syslog(LOG_ERR, "RADIUS: flock %s failed: %m", RADIUS_SESSIONID_FILE);
	}

	n = read(fd, &sessionid, sizeof(sessionid));
	if (n < sizeof(sessionid)) {
		sessionid = magic();
	} else {
		sessionid++;
	}
	lseek(fd, 0L, SEEK_SET);
	write(fd, &sessionid, sizeof(sessionid));

	flock(fd, LOCK_UN);
	close(fd);

	return sessionid;
}

/* If string is NULL, a 'value' attrib is added,
 * otherwise a 'string' attrib is added. */
struct radius_attrib *
radius_add_attrib(
		struct radius_attrib **list, u_long vendor, u_char type,
		u_int value, char *string, u_int length)
{
	struct radius_attrib *attrib, **p;

	attrib = (struct radius_attrib*)malloc(sizeof(*attrib));
	if (attrib == NULL) {
		syslog(LOG_ERR, "RADIUS: out of memory for attribute");
		return NULL;
	}

	attrib->type = type;
	attrib->next = NULL;
	if (string != NULL) {
		attrib->length = length;
		if (attrib->length > AUTH_STRING_LEN) {
			attrib->length = AUTH_STRING_LEN;
		}
		memcpy(attrib->u.string, string, attrib->length);
		attrib->u.string[attrib->length] = '\0';
	}
	else {
		attrib->length = sizeof(attrib->u.value);
		attrib->u.value = htonl(value);
	}
	attrib->vendor = vendor;

	for (p = list; *p != NULL; p = &((*p)->next));
	*p = attrib;

	return attrib;
}

void
radius_free_attrib(struct radius_attrib *list)
{
	struct radius_attrib *p;

	while (list != NULL) {
		p = list->next;
		free(list);
		list = p;
	}
}

static void
radius_random_vector(u_char *vector, int length)
{
	u_int i;

	while (length > 0) {
		i = magic();
		memcpy(vector, &i, (length<sizeof(i)) ? length : sizeof(i));
		vector += sizeof(i);
		length -= sizeof(i);
	}
}

static void
radius_calc_vector(
		char *secret, u_char *buf, int len,
		u_char *vector_in, u_char *vector_out)
{
	int header_len;
	int secret_len;
	MD5_CTX context;

	header_len = ((AUTH_HDR*)buf)->vector - buf;
	secret_len = strlen(secret);
	MD5Init(&context);
	MD5Update(&context, buf, header_len);
	MD5Update(&context, vector_in, AUTH_VECTOR_LEN);
	MD5Update(&context, buf + header_len + AUTH_VECTOR_LEN,
			len - header_len - AUTH_VECTOR_LEN);
	MD5Update(&context, secret, secret_len);
	MD5Final(vector_out, &context);
}

static void
radius_encrypt_attrib(
		char *secret, u_char *vector,
		u_char *to,	u_char *from, int length,
		u_char *salt, int salt_length)
{
	int secret_len;
	int i;
	MD5_CTX context;

	secret_len = strlen(secret);
	while (length > 0) {
		MD5Init(&context);
		MD5Update(&context, secret, secret_len);
		MD5Update(&context, vector, AUTH_VECTOR_LEN);
		if (salt && salt_length) {
			MD5Update(&context, salt, salt_length);
			salt = NULL;
		}
		MD5Final(to, &context);
		for (i=0; i<AUTH_VECTOR_LEN && length>0; i++, length--) {
			to[i] ^= from[i];
		}
		vector = to;
		to += AUTH_VECTOR_LEN;
		from += AUTH_VECTOR_LEN;
	}
}

static void
radius_decrypt_attrib(
		char *secret, u_char *vector,
		u_char *to,	u_char *from, int length,
		u_char *salt, int salt_length)
{
	int secret_len;
	int i;
	MD5_CTX context;

	secret_len = strlen(secret);
	while (length > 0) {
		MD5Init(&context);
		MD5Update(&context, secret, secret_len);
		MD5Update(&context, vector, AUTH_VECTOR_LEN);
		if (salt && salt_length) {
			MD5Update(&context, salt, salt_length);
			salt = NULL;
		}
		MD5Final(to, &context);
		for (i=0; i<AUTH_VECTOR_LEN && length>0; i++, length--) {
			to[i] ^= from[i];
		}
		vector = from;
		to += AUTH_VECTOR_LEN;
		from += AUTH_VECTOR_LEN;
	}
}

/* Returns: encryption salt length, or -1 for no encryption */
static int
radius_attrib_salt_length(struct radius_attrib *attrib)
{
	int encrypt = -1;

	if (attrib->vendor == PW_VENDOR_NONE) {
		switch (attrib->type) {
		case PW_PASSWORD:
			encrypt = 0;
			break;
		}
	}
	else if (attrib->vendor == PW_VENDOR_MICROSOFT) {
		switch (attrib->type) {
		case PW_MS_CHAP_MPPE_KEYS:
			encrypt = 0;
			break;

		case PW_MS_MPPE_SEND_KEY:
		case PW_MS_MPPE_RECV_KEY:
			encrypt = 2;
			break;
		}
	}

	if (encrypt > attrib->length)
		encrypt = -1;

	return encrypt;
}

#define RADIUS_ENCRYPT_ATTRIB_LEN(l) \
	(((l) + AUTH_VECTOR_LEN - 1) & ~(AUTH_VECTOR_LEN-1))

static int
radius_attrib_length(struct radius_attrib *attrib)
{
	int length, salt;

	length = 2;

	salt = radius_attrib_salt_length(attrib);
	if (salt >= 0)
		length += salt + RADIUS_ENCRYPT_ATTRIB_LEN(attrib->length - salt);
	else
		length += attrib->length;

	if (attrib->vendor != PW_VENDOR_NONE)
		length += 2 + sizeof(attrib->vendor);

	return length;
}

/* Return: success: 0, error: -1 */
static int
radius_get_attrib_vendor(struct radius_attrib ***next, u_long vendor,
		u_char *buf, int len, char *secret, u_char *vector)
{
	u_char from_type, from_length;
	u_long from_vendor;
	struct radius_attrib *attrib;
	int salt;

	while (len >= 2) {
		from_type = *buf++;
		from_length = *buf++;
		if (from_length < 2 || from_length > len) {
			syslog(LOG_ERR, "RADIUS: received attribute with invalid length");
			return -1;
		}
		len -= from_length;
		from_length -= 2;

		if (from_type == PW_VENDOR_SPECIFIC && vendor == PW_VENDOR_NONE) {
			if (from_length < sizeof(from_vendor)) {
				syslog(LOG_ERR, "RADIUS: received attribute with invalid length");
				return -1;
			}
			memcpy(&from_vendor, buf, sizeof(from_vendor));
			from_vendor = ntohl(from_vendor);
			buf += sizeof(from_vendor);
			from_length -= sizeof(from_vendor);

			if (radius_get_attrib_vendor(
					next, from_vendor, buf, from_length, secret, vector) < 0)
				return -1;
		}
		else {
			attrib = (struct radius_attrib*)malloc(sizeof(*attrib));
			if (attrib == NULL) {
				syslog(LOG_ERR, "RADIUS: out of memory for attribute");
				return -1;
			}

			attrib->vendor = vendor;
			attrib->type = from_type;
			attrib->length = from_length;
			salt = radius_attrib_salt_length(attrib);
			if (salt >= 0) {
				memcpy(attrib->u.string, buf, salt);
				radius_decrypt_attrib(secret, vector, attrib->u.string+salt,
						buf+salt, attrib->length-salt,
						buf, salt);
			}
			else {
				memcpy(attrib->u.string, buf, attrib->length);
			}
			attrib->u.string[attrib->length] = '\0';
			attrib->next = NULL;
			**next = attrib;
			*next = &attrib->next;
		}
		buf += from_length;
	}
    
	return 0;
}

/* Return: success: 0, error: -1 */
static int
radius_get_attrib(struct radius_attrib **list, u_char *buf, int len,
		char *secret, u_char *vector)
{
	struct radius_attrib **next;

	next = list;
	*next = NULL;
	if (radius_get_attrib_vendor(&next, PW_VENDOR_NONE, buf, len,
			secret, vector) < 0) {
		radius_free_attrib(*list);
		*list = NULL;
		return -1;
	}

	return 0;
}

/* Return: success: length, error: -1 */
static int
radius_put_attrib(u_char *buf, struct radius_attrib *attrib,
		char *secret, u_char *vector)
{
	int length, total, salt;
	u_long vendor;

	total = length = radius_attrib_length(attrib);

	if (attrib->vendor != PW_VENDOR_NONE) {
		*buf++ = PW_VENDOR_SPECIFIC;
		*buf++ = total;
		vendor = htonl(attrib->vendor);
		memcpy(buf, &vendor, sizeof(vendor));
		buf += sizeof(vendor);
		length -= 2 + sizeof(vendor);
	}

	*buf++ = attrib->type;
	*buf++ = length;

	salt = radius_attrib_salt_length(attrib);
	if (salt >= 0) {
		if (secret == NULL || vector == NULL) {
			syslog(LOG_ERR, "RADIUS: no vector to encrypt attribute");
			return -1;
		}
		memcpy(buf, attrib->u.string, salt);
		radius_encrypt_attrib(secret, vector, buf+salt,
				attrib->u.string+salt, attrib->length-salt,
				attrib->u.string, salt);
	}
	else {
		memcpy(buf, attrib->u.string, attrib->length);
	}

	return total;
}

/* Return: success: length, fatal error: -1, error: 0 */
static int
radius_recv(int s, char *secret, u_char *sendbuf,
		u_char *recvbuf, int maxrecvlen, struct sockaddr_in *saremote)
{
	struct sockaddr_in safrom;
	int recvlen, fromlen;
	u_char vector[AUTH_VECTOR_LEN];
	AUTH_HDR *sendheader, *recvheader;

	sendheader = (AUTH_HDR*)sendbuf;
	recvheader = (AUTH_HDR*)recvbuf;

	fromlen = sizeof(safrom);
	recvlen = recvfrom(s, recvbuf, maxrecvlen, 0,
			(struct sockaddr*)&safrom, &fromlen);
	if (recvlen < 0) {
		syslog(LOG_ERR, "RADIUS: recvfrom: %m");
		return -1;
	}

	if (safrom.sin_addr.s_addr != saremote->sin_addr.s_addr) {
		syslog(LOG_WARNING, "RADIUS: received unexpected packet from server %s", inet_ntoa(safrom.sin_addr));
		return 0;
	}

	if (recvlen == 0) {
		syslog(LOG_WARNING, "RADIUS: received zero length packet from server %s", inet_ntoa(safrom.sin_addr));
		return 0;
	}

	if (recvlen < ntohs(recvheader->length)) {
		syslog(LOG_WARNING, "RADIUS: received packet with invalid length from server %s", inet_ntoa(safrom.sin_addr));
		return 0;
	}
	recvlen = ntohs(recvheader->length);

	if ((sendheader->code == PW_AUTHENTICATION_REQUEST
			&& recvheader->code != PW_AUTHENTICATION_ACK
			&& recvheader->code != PW_AUTHENTICATION_REJECT
			&& recvheader->code != PW_ACCESS_CHALLENGE)
			|| (sendheader->code == PW_ACCOUNTING_REQUEST
					&& recvheader->code != PW_ACCOUNTING_RESPONSE)) {
		syslog(LOG_WARNING, "RADIUS: received unexpected packet with code %d from server %s", recvheader->code, inet_ntoa(safrom.sin_addr));
		return 0;
	}

	if (sendheader->id != recvheader->id) {
		syslog(LOG_WARNING, "RADIUS: received packet with mismatched id from server %s", inet_ntoa(safrom.sin_addr));
		return 0;
	}

	radius_calc_vector(secret, recvbuf, recvlen,
			((AUTH_HDR*)sendbuf)->vector, vector);
	if (memcmp(((AUTH_HDR*)recvbuf)->vector, vector,
			AUTH_VECTOR_LEN) != 0) {
		syslog(LOG_WARNING, "RADIUS: received packet with invalid authenticator from server %s", inet_ntoa(safrom.sin_addr));
		return 0;
	}

	return recvlen;
}

/* Send with timeouts/retries */
/* Return: success: length, error: -1 */
static int
radius_send(
		u_long host, int port, char *secret,
		u_char *sendbuf, int sendlen, u_char *recvbuf, int maxrecvlen)
{
	int s;
	struct sockaddr_in salocal, saremote;
	fd_set set;
	struct timeval timeout;
	int ret, recvlen, sendcount;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		syslog(LOG_ERR, "RADIUS: open socket failed: %m");
		return -1;
	}

	memset(&salocal, 0, sizeof(salocal));
	salocal.sin_family = AF_INET;
	salocal.sin_addr.s_addr = htonl(INADDR_ANY);
	salocal.sin_port = 0;

	if (bind(s, (struct sockaddr*)&salocal, sizeof(salocal)) < 0) {
		syslog(LOG_ERR, "RADIUS: bind socket failed: %m");
		close(s);
		return -1;
	}

	memset(&saremote, 0, sizeof(saremote));
	saremote.sin_family = AF_INET;
	saremote.sin_addr.s_addr = htonl(host);
	saremote.sin_port = htons(port);

	if (sendto(s, sendbuf, sendlen, 0,
			(struct sockaddr*)&saremote, sizeof(saremote)) < 0) {
		syslog(LOG_ERR, "RADIUS: sendto failed: %m");
		close(s);
		return -1;
	}
	sendcount = 1;
	while (sendcount < 10) {
		do {
			FD_ZERO(&set);
			FD_SET(s, &set);
			timeout.tv_sec = RESEND_TIMEOUT;
			timeout.tv_usec = 0;
			ret = select(s+1, &set, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			syslog(LOG_ERR, "RADIUS: select failed: %m");
			close(s);
			return -1;
		}
		if (ret == 0) {
			/* Timed out so resend */
			if (sendcount > 3) {
				syslog(LOG_WARNING, "RADIUS: server %s not responding",
						inet_ntoa(saremote.sin_addr));
			}
			if (sendto(s, sendbuf, sendlen, 0,
					(struct sockaddr*)&saremote, sizeof(saremote)) < 0) {
				syslog(LOG_ERR, "RADIUS: sendto failed: %m");
				close(s);
				return -1;
			}
			sendcount++;
		}
		else if (FD_ISSET(s, &set)) {
			recvlen = radius_recv(s, secret, sendbuf,
					recvbuf, maxrecvlen, &saremote);
			if (recvlen != 0) { /* either -1 , or positive */
				close(s);
				return recvlen;
			}
		}
	}

	close(s);
	syslog(LOG_ERR, "RADIUS: maximum retries reached for server %s",
			inet_ntoa(saremote.sin_addr));
	return -1;
}

int
radius_send_access_request(
		u_long host, int port, char *secret,
		struct radius_attrib *attriblist,struct radius_attrib **recvattriblist)
{
	struct radius_attrib *attrib;
	int attriblen, sendlen, recvlen;
	u_char *sendbuf, *p;
	u_char recvbuf[1024];
	AUTH_HDR *header;

	attriblen = 0;
	for (attrib = attriblist; attrib != NULL; attrib = attrib->next)
		attriblen += radius_attrib_length(attrib);

	sendlen = AUTH_HDR_LEN + attriblen;
	sendbuf = (u_char*)malloc(sendlen);
	if (sendbuf == NULL) {
		syslog(LOG_ERR, "RADIUS: out of memory for access request");
		return -1;
	}

	header = (AUTH_HDR*)sendbuf;
	header->code = PW_AUTHENTICATION_REQUEST;
	header->id = radius_id();
	header->length = htons(sendlen);
	radius_random_vector(header->vector, sizeof(header->vector));

	p = sendbuf + AUTH_HDR_LEN;
	for (attrib = attriblist; attrib != NULL; attrib = attrib->next) {
		attriblen = radius_put_attrib(p, attrib, secret, header->vector);
		if (attriblen < 0) {
			free(sendbuf);
			return -1;
		}
		p += attriblen;
	}

	recvlen = radius_send(host, port, secret, sendbuf, sendlen,
			recvbuf, sizeof(recvbuf));
	if (recvlen <= 0) {
		free(sendbuf);
		return -1;
	}

	if (radius_get_attrib(recvattriblist,
			recvbuf + AUTH_HDR_LEN, recvlen - AUTH_HDR_LEN,
			secret, header->vector) < 0) {
		free(sendbuf);
		return -1;
	}

	free(sendbuf);
	return ((AUTH_HDR*)recvbuf)->code;
}

int
radius_send_account_request(
		u_long host, int port, char *secret,
		struct radius_attrib *attriblist,struct radius_attrib **recvattriblist)
{
	struct radius_attrib *attrib;
	int attriblen, sendlen, recvlen;
	u_char *sendbuf, *p;
	u_char recvbuf[1024];
	AUTH_HDR *header;

	attriblen = 0;
	for (attrib = attriblist; attrib != NULL; attrib = attrib->next)
		attriblen += radius_attrib_length(attrib);

	sendlen = AUTH_HDR_LEN + attriblen;
	sendbuf = (u_char*)malloc(sendlen);
	if (sendbuf == NULL) {
		syslog(LOG_ERR, "RADIUS: out of memory for account request");
		return -1;
	}

	header = (AUTH_HDR*)sendbuf;
	header->code = PW_ACCOUNTING_REQUEST;
	header->id = radius_id();
	header->length = htons(sendlen);
	memset(header->vector, 0, AUTH_VECTOR_LEN);

	p = sendbuf + AUTH_HDR_LEN;
	for (attrib = attriblist; attrib != NULL; attrib = attrib->next) {
		attriblen = radius_put_attrib(p, attrib, secret, NULL);
		if (attriblen < 0) {
			free(sendbuf);
			return -1;
		}
		p += attriblen;
	}

	radius_calc_vector(secret, sendbuf, sendlen,
			((AUTH_HDR*)sendbuf)->vector, ((AUTH_HDR*)sendbuf)->vector);

	recvlen = radius_send(host, port, secret, sendbuf, sendlen,
			recvbuf, sizeof(recvbuf));
	free(sendbuf);
	if (recvlen <= 0) {
		return -1;
	}

	if (radius_get_attrib(recvattriblist,
			recvbuf + AUTH_HDR_LEN, recvlen - AUTH_HDR_LEN,
			secret, NULL) < 0) {
		return -1;
	}

	return ((AUTH_HDR*)recvbuf)->code;
}
