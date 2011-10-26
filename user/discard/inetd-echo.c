/*****************************************************************************/
/*
 *	echo.c -- accept all reads and discard data.
 *
 *	Copyright (C) 2004 David McCullough <davidm@snapgear.com>
 */
/*****************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define	MAX_BUF	8192

unsigned char	buf[MAX_BUF];

int
main(int argc, char *argv[])
{
	int	n, m;
	fd_set rfds;
	unsigned char *cp;

#ifdef TCP_QUICKACK
	n = 0;
	setsockopt(0, IPPROTO_TCP, TCP_QUICKACK, &n, sizeof(n));
#endif

	FD_ZERO(&rfds);
	for (;;) {
		FD_SET(0, &rfds);
		if (select(0 + 1, &rfds, NULL, NULL, NULL) == -1)
			exit(1);
		if ((n = read(0, buf, sizeof(buf))) <= 0)
			exit(1);
		cp = buf;
		do {
			m = write(1, cp, n);
			if (m <= 0)
				exit(1);
			cp += m;
			n -= m;
		} while (n > 0);
	}
}

/*****************************************************************************/
