/****************************************************************************/

/*
 *	http.c -- get MP3 data from a http address.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@snapgear.com)
 */

/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/****************************************************************************/

/*
 *	Indicate whether we are streaming or not
 */
extern int	http_streaming;

/****************************************************************************/

int httpreadline(int fd, char *buf, int len)
{
	char	c;
	int	size;

	for (len--, size = 0; (size < len); size++) {
		if (read(fd, &c, sizeof(c)) != sizeof(c))
			break;
		if (c == '\n')
			break;
		*buf++ = c;
	}
	*buf = 0;
	return(size);
}

/****************************************************************************/

int openhttp(char *url)
{
	struct sockaddr_in	sin;
	struct hostent		*hp;
	char			*up, *sp;
	char			urlip[256];
	char			urlport[32];
	char			urlfile[256];
	char			buf[256];
	char			relocurl[512];
	int			fd, portnr, n, relocated;

	fd = -1;
	portnr = 80;
	up = url;

	do {
		/* Strip http protocol name from url */
		if (strncmp(up, "http://", 7) == 0)
				up += 7;

		/* Get system name (or IP address) from url */
		for (sp = &urlip[0]; ((*up != ':') && (*up != '/')); up++) {
			if (*up == 0)
				return(-1);
			*sp++ = *up;
			if (sp >= &urlip[sizeof(urlip)-1])
				return(-1);
		}
		*sp = 0;

		/* Get port number if supplied */
		if (*up == ':') {
			for (up++, sp = &urlport[0]; (*up != 0); up++) {
				if (*up == '/')
					break;
				*sp++ = *up;
				if (sp >= &urlport[sizeof(urlport)-1])
					return(-1);
			}
			*sp = 0;
			portnr = atoi(urlport);
		}

		/* Get file path */
		for (sp = &urlfile[0]; (*up != 0); up++) {
			*sp++ = *up;
			if (sp >= &urlfile[sizeof(urlfile)-1])
				return(-1);
		}
		*sp = 0;

		/* Mark whether we are streaming or not... */
		if (urlfile[0] == 0)
			http_streaming++;

		if ((hp = gethostbyname(urlip))) {
			sin.sin_family = hp->h_addrtype;
			memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
		} else {
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = inet_addr(urlip);
		}
		sin.sin_port = htons(portnr);

		/* Open socket to IP address */
		if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
			return(-1);

		if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) < 0)
			return(-1);

		/* Send GET request to server */
		sprintf(buf, "GET %s HTTP/1.0\r\n"
			"User-Agent: mp3play/100\r\n"
			"Accept: audio/mpeg, audio/x-mpegurl, */*\r\n"
			"\r\n",
			urlfile);

		if (write(fd, buf, strlen(buf)) < 0)
			return(-1);

		if (httpreadline(fd, buf, sizeof(buf)) < 0)
			return(-1);

		relocated = 0;
		if ((sp = strchr(buf, ' '))) {
			switch (sp[1]) {
			case '3':
				relocated++;
				break;
			case '2':
				break;
			default:
				return(-1);
			}
		}

		for (;;) {
			if (httpreadline(fd, buf, sizeof(buf)) < 0)
				return(-1);
			if ((buf[0] == '\n') || (buf[0] == '\r'))
				break;
			if (strncmp(buf, "Location:", 9) == 0) {
				strncpy(relocurl, buf+10, sizeof(relocurl));
				up = relocurl;
			}
		}
	} while (relocated);

	return(fd);
}

/****************************************************************************/
