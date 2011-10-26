/*
 * w3camd.c
 *
 * Copyright (C) 1998 - 2000 Rasca, Berlin
 * EMail: thron@gmx.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <jpeglib.h>
#include "w3socket.h"
#include "w3http.h"
#include "w3v4l.h"
#include "w3jpeg.h"
#include "w3log.h"

#ifndef CAM_PORT
#define CAM_PORT 8999
#endif
#define forever() while(1)
#define MAX_WIDTH	768
#define MAX_HEIGHT	576
#define SERVER_NAME	"w3camd/0.3"
#define SLEEP(n)	usleep((int)(n * 1000000))
#define OFF -1

enum {
	ST_NONE,
	ST_ERROR,
	ST_BUSY,
	ST_READY,
	ST_EXIT,
};

typedef struct {
	int childs;
	pthread_mutex_t childs_lock;
	pthread_cond_t childs_cond;
	int state;
	int width;				/* image width */
	int height;				/* image height */
	int input;
	unsigned char *img;		/* image data for the childs */
	pthread_mutex_t img_lock;
	pthread_cond_t img_cond;
} image_t;

typedef struct {
	int fd;					/* fd for the incoming connection */
	int verbose;
	char *url;
	char *image;
	int image_size;
	image_t *img;
	pthread_t thread;
	/* */
	float refresh;
	int quality;
} conn_t;

typedef struct {
	char *dev;
	image_t *img;
} camera_t;


/*
 * show possible parameters
 */
void
usage (char *pname) {
	fprintf (stderr,
		"Usage: %s [-v] [-p #] [-h host] [-s #x#] [-m #] [-i #] [-d device] \n",
		pname);
	exit (1);
}

/*
 * write jpeg file to filedescriptor fd
 */
int
write_jpeg (image_t *img, int fd, int quality)
{
	JSAMPROW row_ptr[1];
	struct jpeg_compress_struct jpeg;
	struct jpeg_error_mgr jerr;
	char *line, *image;
	int y, x, line_width;

#ifdef DEBUG
	fprintf (stderr, "%s: write_jpeg() width=%d height=%d\n",
		__FILE__, img->width, img->height);
#endif
	line = malloc (img->width * 3);
	if (!line)
		return 0;
	jpeg.err = jpeg_std_error (&jerr);
	jpeg_create_compress (&jpeg);
	jpeg.image_width = img->width;
	jpeg.image_height= img->height;
	jpeg.input_components = 3;
	jpeg.in_color_space = JCS_RGB;
	jpeg_set_defaults (&jpeg);
	jpeg_set_quality (&jpeg, quality, TRUE);
	jpeg.dct_method = JDCT_FASTEST;
	jpeg_io_dest (&jpeg, fd);	/* this is in w3jpeg.c */
	jpeg_start_compress (&jpeg, TRUE);
	row_ptr[0] = line;
	line_width = img->width * 3;
	image = img->img;
	for (y = 0; y < img->height; y++) {
		for (x = 0; x < line_width; x+=3) {
			line[x]   = image[x+2];
			line[x+1] = image[x+1];
			line[x+2] = image[x];
		}
		if (!jpeg_write_scanlines (&jpeg, row_ptr, 1)) {
			jpeg_destroy_compress (&jpeg);
			free (line);
			return 0;
		}
		image += line_width;
	}
	jpeg_finish_compress (&jpeg);
	jpeg_destroy_compress (&jpeg);
	free (line);
	return 1;
}

/*
 * capture images continously
 */
void *
image_thread (void *data)
{
	camera_t *cam = (camera_t *) data;
	image_t *img = cam->img;
	video_t *vid;
#ifdef DEBUG
	printf ("%s: image_thread() img->childs=%d\n", __FILE__, img->childs);
	printf ("%s:  pid = %d\n", __FILE__, getpid());
#endif
WAIT:
	img->state = ST_NONE;
	pthread_mutex_lock (&img->childs_lock);
	forever () {
		pthread_cond_wait (&img->childs_cond, &img->childs_lock);
		log_print ("%s: no. of childs changed: childs=%d\n", __FILE__, img->childs);
		if (img->childs > 0)
			break;
	}
	pthread_mutex_unlock (&img->childs_lock);

	if (!(vid = v4l_init(cam->dev, img->input, img->width, img->height))) {
		img->state = ST_ERROR;
		/* pthread_cond_broadcast (&img->img_cond); */
		log_print("%s: can't init v4l\n", __FILE__);
		goto WAIT;
	}
	vid->width = img->width;
	vid->height= img->height;

	while (img->childs > 0) {
		if (!v4l_image(vid)) {
			img->state = ST_ERROR;
			log_print ("image_thread() error\n");
		} else {
			img->state = ST_BUSY;
			pthread_mutex_lock (&img->img_lock);
			printf ("0x%X 0x%X %dx%d\n", img, vid->mem,vid->width, vid->height);
			memcpy (img->img, vid->mem, vid->width * vid->height * 3);
			printf ("done ..\n");
#ifdef DEBUG
			printf ("%s: unlocking img..\n", __FILE__);
#endif
			pthread_mutex_unlock (&img->img_lock);
			img->state = ST_READY;
			pthread_cond_broadcast (&img->img_cond);
			SLEEP(0.005);
		}
	}
	v4l_fini (vid);
	goto WAIT;
	return (NULL);
}

/*
 */
void
e_help (conn_t *cn)
{
	char buf[16];
	char *e =
		"Usage:\n"
		"  /image[?quality=<#>[&stream]] - retrieve an image\n"
		"  /help                - see these lines\n";

	sprintf (buf, "%d", strlen (e));
	http_status (cn->fd, HTTP_OK);
	http_header (cn->fd, HTTP_SERVER, SERVER_NAME);
	http_header (cn->fd, HTTP_CONTENT_TYPE, "text/plain");
	http_header (cn->fd, HTTP_CONTENT_LENGTH, buf);
	http_header (cn->fd, HTTP_HEADER_END, NULL);
	write (cn->fd, e, strlen(e));
}

/*
 */
void
e_wrong_url (conn_t *cn)
{
	char buf[16];
	char *e = "wrong url!\n  try \"/help\"\n";

	sprintf (buf, "%d", strlen (e));
	http_status (cn->fd, HTTP_BAD_REQUEST);
	http_header (cn->fd, HTTP_SERVER, SERVER_NAME);
	http_header (cn->fd, HTTP_CONTENT_TYPE, "text/plain");
	http_header (cn->fd, HTTP_CONTENT_LENGTH, buf);
	http_header (cn->fd, HTTP_HEADER_END, NULL);
	write (cn->fd, e, strlen(e));
}

/*
 */
void
e_error (conn_t *cn)
{
	char buf[64];
	http_status (cn->fd, HTTP_BAD_REQUEST);
	http_header (cn->fd, HTTP_SERVER, SERVER_NAME);
	http_header (cn->fd, HTTP_CONTENT_TYPE, "text/plain");
	http_header (cn->fd, HTTP_HEADER_END, NULL);
	sprintf (buf, "can't read image! device busy?!\n");
	write (cn->fd, buf, strlen(buf));
}


/*
 * process the requested url
 */
void
process_url (conn_t *cn)
{
	char rfc1123[64];
	time_t gmt;
	int stream = 0;
	char buf[128];
#	define BOUNDARY "--w3camd-ns-boundary--may-not-work-with-ie--"

	gmt = time (NULL);
	strftime (rfc1123, 64, "%a, %d %b %Y %H:%M:%S GMT", gmtime (&gmt));
	
	if (!cn->url) {
		e_wrong_url (cn);
		return;
	}
	if (strncmp (cn->url, "/image", 6) != 0) {
		if (strncmp (cn->url, "/help", 5) == 0)
			e_help (cn);
		else
			e_wrong_url (cn);
		return;
	}
	if (strstr (cn->url, "stream")) {
		stream = 1;
	}
	if (cn->img->state == ST_ERROR) {
		e_error (cn);
		return;
	}
	http_status (cn->fd, HTTP_OK);
	http_header (cn->fd, HTTP_SERVER, SERVER_NAME);
	if (stream) {
		http_header (cn->fd, HTTP_CONTENT_TYPE,
				"multipart/x-mixed-replace;boundary="BOUNDARY);
	} else {
		http_header (cn->fd, HTTP_CONTENT_TYPE, "image/jpeg");
	}
	http_header (cn->fd, HTTP_EXPIRES, rfc1123);
	http_header (cn->fd, HTTP_HEADER_END, NULL);
	forever () {
		pthread_cond_wait (&cn->img->img_cond, &cn->img->img_lock);
		log_print ("process_url() state=%d\n", cn->img->state);
		if (cn->img->state == ST_READY) {
			/* pthread_mutex_lock (&cn->img->img_lock); */
			if (stream) {
				sprintf (buf, "\n%s\n", BOUNDARY);
				write (cn->fd, buf, strlen(buf));
				sprintf (buf, "Content-Type: image/jpeg\n\n");
				write (cn->fd, buf, strlen(buf));
			}
			if (!write_jpeg (cn->img, cn->fd, cn->quality))
				return;
			/* pthread_mutex_unlock (&cn->img->img_lock); */
			if (!stream)
				break;
		}
	}
}

/*
 * child which handles an incoming connection
 */
void *
server_thread (void *data)
{
#define MAX_BUF	1024
#define MAX_ALL	4096
	conn_t *cn = (conn_t *) data;
	int len, inlen = 0;
	char buf  [MAX_BUF+1];
	char inbuf[MAX_ALL+1];
	char **args, *val;

	buf  [MAX_BUF] = '\0';
	inbuf[MAX_BUF] = '\0';

	if (cn->verbose)
		printf ("server_thread() state=%d\n", cn->img->state);

	forever () {
		len = read (cn->fd, buf, MAX_BUF);
		if (len <= 0) {
			/* client closed connection */
			goto CLIENT_END;
			return (NULL);
		}
		buf[len] = '\0';
		if (inlen + len > MAX_ALL) {
			log_print ("input overrun\n");
			break;
		}
		memcpy (inbuf+inlen, buf, len);
		inlen += len;
		if (strstr (inbuf, "\n\n")		||
			strstr (inbuf, "\r\n\r\n")	||
			strstr (inbuf, "\r\r")		)
			break;
	}
	inbuf[inlen] = '\0';
	cn->url = http_parse (inbuf, &args);
	if (cn->verbose > 1)
		log_print ("getting url=%s\n", cn->url);
	if (args) {
		val = http_arg_val (args, "refresh");
		if (val)	/* not used until now */
			cn->refresh = atof (val);
		val = http_arg_val (args, "quality");
		if (val)
			cn->quality = atoi (val);
	}
	if (cn->verbose > 2) {
		printf ("  quality=%d\n", cn->quality);
		printf ("  refresh=%f\n", cn->refresh);
	}
	process_url (cn);
	close (cn->fd);
	cn->img->childs--;
	if (args) {
		http_free_args (args);
	}
	free (cn->url);
	if (cn->verbose) {
		printf ("connection closed\n");
	}
CLIENT_END:
	pthread_detach (cn->thread);
	free (cn);
	return (NULL);
}

/*
 */
static void
on_sig_pipe (int signum)
{
	log_print ("** signal pipe received\n");
}

static void
on_signal (int signum)
{
	log_print ("%d received signal %d\n", getpid(), signum);
	exit (1);
}


/*
 * let's start up
 */
int
main (int argc, char *argv[])
{
	int c, sd, cd, fps = 25, input = -1;
	int verbose = 0, max_connections = 10;
	int width = 240, height = 180;
	int port = CAM_PORT;
	char *host = "localhost";	/* default host to run on */
	conn_t *cn;
	image_t *img;
	pthread_t ithread;
	camera_t cam;

	cam.dev = "/dev/video0";

	/* parse arguments
	 */
	while ((c = getopt (argc, argv, "vp:h:i:s:f:m:d:")) != EOF) {
		switch (c) {
			case 'd':
				cam.dev = optarg;
				break;
			case 'f':
				fps = atoi(optarg);
				break;
			case 'h':
				host = optarg;
				break;
			case 'i':
				input = atoi(optarg);
				break;
			case 'm':
				max_connections = atoi(optarg);
				break;
			case 'p':
				port = atoi (optarg);
				break;
			case 's':
				sscanf (optarg, "%dx%d", &width, &height);
				break;
			case 'v':
				verbose++;
				break;
			default:
				usage (argv[0]);
				break;
		}
	}

	if (verbose)
		log_print ("main thread pid = %d\n", getpid());

	img = malloc (sizeof (image_t) + 3 * MAX_WIDTH * MAX_HEIGHT);
	if (!img)
		exit (1);
	img->img = (unsigned char *)(img + 1);
	img->childs = 0;
	img->width = width;
	img->height= height;
	img->state = ST_NONE;
	img->input = input;
	cam.img = img;

	signal (SIGPIPE, on_sig_pipe);
	signal (SIGSEGV, on_signal);

	pthread_mutex_init (&img->childs_lock, NULL);
	pthread_mutex_init (&img->img_lock, NULL);
	pthread_cond_init  (&img->childs_cond, NULL);
	pthread_cond_init  (&img->img_cond, NULL);

	sd = bind_port (host, port);
	if (verbose)
		printf ("bind %s:%d to file descriptor %d\n", host, port, sd);
	if (sd < 0) {
		return (-1);
	}

	pthread_create (&ithread, NULL, image_thread, (void *)&cam);

	forever () {
		cd = accept_con (sd);
		if (cd < 0) {
			printf ("oops!? accept_con() returned < 0\n");
			continue;
		}
		if (verbose)
			printf ("incoming connection..\n");
		if ((img->childs+1) > max_connections) {
			if (verbose)
				printf ("too much connections!\n");
			continue;
		}
		pthread_mutex_lock (&img->childs_lock);
		img->childs++;
		pthread_cond_broadcast (&img->childs_cond);
		pthread_mutex_unlock (&img->childs_lock);

		cn = malloc (sizeof (conn_t));
		if (!cn)
			exit (2);
		cn->fd = cd;
		cn->img = img;
		cn->verbose = verbose;
		cn->quality = 75;

		if (verbose)
			printf ("serving connection, (childs=%d)\n", cn->img->childs);
		/* child */
		pthread_create (&cn->thread, NULL, server_thread, cn);
	}
	return (0);
}

