/* This little program drives a Range Instruments 6500 display via RS232 serial
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>
#include <sys/poll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define SERIALPORT	"/dev/ttyS0"
#define MSG_SIZE	6
#define MESSAGE_FILE	"/etc/display_messages"

static int ofd;
static char inbuf[80] = "wait";
static int scales, button;


/* This little routine wrappers up a short string and sends it to the display.
 * We'll do this zero copy because we can.
 */
static void send_message(const char *msg) {
	struct iovec iov[4];
	int n = 0;
	int j = strlen(msg);
	
	iov[n].iov_base = "\002  ";	/* STX */
	iov[n++].iov_len = 3;
	
	if (j < MSG_SIZE) {			/* Leading space filler */
		iov[n].iov_base = "        ";
		iov[n++].iov_len = MSG_SIZE - j;
	} else if (j > MSG_SIZE)
		j = MSG_SIZE;
	
	iov[n].iov_base = (void *)msg;	/* The message itself */
	iov[n++].iov_len = j;
	
	iov[n].iov_base = " 01\003";	/* display ID, ETX */
	iov[n++].iov_len = 4;
	
	writev(ofd, iov, n);		/* Output it atomically */
}


static void read_input() {
	static char lbuf[80];
	static int pos;
	char c, *p;

	if (read(scales, &c, 1) == 1) {
		if (c != '\n') {
			lbuf[pos++] = c;
			if (pos > 75) pos = 75;
		} else {
			lbuf[pos--] = '\0';
			if (lbuf[pos] == 'G') {
				lbuf[pos] = '\0';
				for (p=lbuf; *p == ' '; p++);
				strcpy(inbuf, p);
			}
			pos = 0;
		}
	}
}

static int skip_messages;
static void check_button(void) {
	char c;
	
	if (read(button, &c, 1) == 1) {
		if (c == '0')
			skip_messages = 1;
		else
			skip_messages = 0;
	}
}


/* This routine produces a short delay.  Timeout is in ms.
 */
static int delay(int n) {
	struct pollfd pfd[2];
	int res;

	pfd[0].fd = scales;
	pfd[0].events = POLLIN | POLLPRI;
	
	pfd[1].fd = button;
	pfd[1].events = POLLIN | POLLPRI;
	
	for(;;) {
		res = poll(pfd, 2, n);
		if (res == -1)
			return (errno == EINTR)?0:1;
		if (res == 0)
			return 0;
		if (pfd[0].revents & pfd[0].events)
			read_input();
		if (pfd[1].revents & pfd[1].events)
			check_button();
		n = 0;
	}
}

static int num_msgs;
static char **msgs;
static time_t lastmod_msgs;

static void read_msgtbl(void) {
	int		 fd;
	char		*buf, *p, *q, *r;
	int		 lines, sz;
	int		 pos;
	struct stat	 st;
	
	inline void addLine(void) {
		char *x;

		while (*q != '\0' && isspace(*q)) q++;
		if (*q != '\0') {
			x = strchr(q, '\0');
			while (x > q && isspace(x[-1]))
				*--x = '\0';
			if (*q != '\0') {
				strcpy(r, q);
				msgs[pos++] = r;
				r = strchr(r, '\0') + 1;
			}

		}
	}

	if (-1 == stat(MESSAGE_FILE, &st))
		return;
	if (st.st_mtime == lastmod_msgs)
		return;
	lastmod_msgs = st.st_mtime;
	
	if (msgs != NULL) {
		free(msgs);
		msgs = NULL;
	}
	fd = open(MESSAGE_FILE, O_RDONLY);
	if (fd == -1)
		return;
	if (-1 == fstat(fd, &st))
		goto fail2;
	buf = malloc(st.st_size + sizeof(char));
	if (buf == NULL)
		goto fail2;
	if (read(fd, buf, st.st_size) != st.st_size)
		goto fail1;
	buf[st.st_size] = '\0';
	for (lines=3, p=buf; *p != '\0'; p++)
		if (*p == '\n') lines++;

	sz = sizeof(char *) * lines + st.st_size + 20;
	msgs = malloc(sz);
	if (msgs == NULL) goto fail1;
	bzero(msgs, sz);
	
	pos = 0;
	r = (char *)(msgs + lines);
	for (p=q=buf; *p != '\0'; )
		if (*p == '\n') {
			*p++ = '\0';
			addLine();
			q = p;
		} else p++;
	addLine();
	msgs[pos] = NULL;
	for (num_msgs=0; msgs[num_msgs] != NULL; num_msgs++);
fail1:	free(buf);
fail2:	close(fd);
}


/* Scroll a message across the display.
 */
static int show_message() {
	int i, j;
	const char *msg;
	
	if (msgs == NULL || num_msgs == 0 || skip_messages) return 0;

	/* Pick a random message */
	if ((i = random() % num_msgs) < 0)
		i += num_msgs;
	msg = msgs[i];
	if (msg == NULL) return 0;
	
	/* Scroll it out slowly */
	j = strlen(msg) - MSG_SIZE;
	if (j < 0) {
		send_message(msg);
		if (delay(1400))
			return 1;
	} else {
		for (i=0; !skip_messages && i<=j; i++) {
			send_message(msg+i);
			if (delay(i==0?600:400))
				return 1;
		}
		if (!skip_messages && delay(400))
			return 1;
	}
	/* Clear the display */
	send_message(inbuf);
	return 0;
}


static int show_value(void) {
	send_message(inbuf);
	return delay(1000);
}

static int open_pipe(int port) {
	int sock;
	struct sockaddr_in sin;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) return -1;
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		return -1;
	return sock;
}

int main(int argc, char *argv[]) {
	struct termios tios;
	int res;

	sleep(20);
	res = open_pipe(468);	sleep(2);	close(res);	sleep(2);
	srandom(time(NULL));
	
	button = open_pipe(468);	if (button < 0) return 1;
	scales = open_pipe(487);	if (scales < 0) return 1;

	/* Open the serial port */
	ofd = open(SERIALPORT, O_RDWR | O_NOCTTY | O_SYNC);
	if (ofd == -1) {
		fprintf(stderr, "cannot open %s\n", SERIALPORT);
		res = 1;
	} else {
		/* Set serial parameters to what we desire */
		tcgetattr(ofd, &tios);
		tios.c_cflag &= ~CSIZE;
		tios.c_cflag &= ~CBAUD;
		tios.c_cflag |= CS8 | B9600;
		tcsetattr(ofd, TCSANOW, &tios);
		
		for (;;) {
			read_msgtbl();
			/* Mostly output the numeric value but sometimes
			 * produce a cheery message.
			 */
			if (((random() % 30)?show_value:show_message)())
				break;
		}
		close(ofd);
		res = 0;
	}
	return res;
}
