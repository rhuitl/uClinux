#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#define WIDTH	640
#define HEIGHT	480

int main(int argc, char *argv) {
	char fname[1000];
	char size[200];
	int n = getpid();
	
	sprintf(fname, "/home/httpd/video/image%d.jpg", n);
	unlink(fname);
	if (fork() == 0) {
		sprintf(size, "%dx%d", WIDTH, HEIGHT);
		execl("/bin/vidcat", "vidcat",
				"-f", "jpeg",
				"-s", size,
				"-o", fname,
				NULL);
		exit(1);
	}
	wait(NULL);

	/* Output HTML header */
	printf("Content-type: text/html\n");
	printf("\n");
	
	printf("<html><head>\n");
	printf("<meta http-equiv=\"refresh\" content=\"7; URL=/cgi-bin/snapshot\">\n");
	printf("<title>Image Capture</title>\n</head>\n");
	printf("<body>\n");
	printf("<h1>Current image</h1><p>\n");
	printf("<img src=\"/video/image%d.jpg\" width=\"%d\" height=\"%d\">\n", n,
			WIDTH/2, HEIGHT/2);
	printf("<h1>Saved image</h1><p>\n");
	printf("<img src=\"/video/image.jpg\" width=\"640\" height=\"480\">\n");
	printf("</body></html>\n");
	fflush(NULL);
	
	if (fork() == 0) {
		/* Wait a little while and delete our temp file */
		close(0);
		close(1);
		close(2);
		sleep(5);
		unlink(fname);
	}
}
