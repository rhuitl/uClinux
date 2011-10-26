#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static inline void capture(void) {
	if (fork() == 0) {
		execl("/bin/vidcat", "vidcat",
				"-f", "jpeg",
				"-s", "640x480",
				"-o", "/home/httpd/video/new.jpg",
				NULL);
		exit(1);
	}
	wait(NULL);
	rename("/home/httpd/video/new.jpg", "/home/httpd/video/image.jpg");
}

int main(int argc, char *argv[]) {
	int sock;
	struct sockaddr_in sin;
	char c;
	int cnt = 0;
	char *host;
	
	if (argc == 1)
		host = "192.168.161.44";
	else
		host = argv[1];

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) return 1;
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(500);
	sin.sin_addr.s_addr = inet_addr(host);
	if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		return 1;
	
	for (;;) {
		switch(read(sock, &c, 1)) {
		case 0:	if (++cnt > 10) return 1;	break;
		case 1: if (c == '1') capture();	cnt = 0;	break;
		case -1:				break;
		}
	}
	return 0;
}
