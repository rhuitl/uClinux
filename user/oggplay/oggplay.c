/****************************************************************************/

/*
 *	oggplay.c -- Play OGG VORBIS data files
 *
 *	(C) Copyright 2007-2008, Paul Dale (Paul_Dale@au.securecomputing.com)
 *	(C) Copyright 1999-2002, Greg Ungerer (gerg@snapgear.com)
 *      (C) Copyright 1997-1997, Stéphane TAVENARD
 *          All Rights Reserved
 *
 *	This code is a derivitive of Stephane Tavenard's mpegdev_demo.c.
 *
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 * 
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/****************************************************************************/
#define _BSD_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <ivorbiscodec.h>
#include <ivorbisfile.h>
#include <linux/soundcard.h>
#include <sys/resource.h>
#include <config/autoconf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <math.h>

#ifdef CONFIG_USER_SETKEY_SETKEY
#include <key/key.h>
#endif

#include "base64.h"

/****************************************************************************/

static int	verbose;
static int	quiet;
static int	lcd_line, lcd_time;
static int	lcdfd = -1;
static int	gotsigusr1;
static int	printtime;
static int	onlytags;
static int	crypto_keylen = 0;
static char	*crypto_key = NULL;
static int	buffer_size = 8192;
static int      advertisement;
static char     *npip         = NULL;
static char     *npproxy      = NULL;
static time_t   npwait;		// select/socket timeout in msec

#define MAX_BUF      4096
#define MAX_HOSTNAME  256
#define MAX_DISPLAY   60

#define EREAD_TIMEOUT -2
#define EREAD_ERROR   -1
#define EREAD_EOF      0

/****************************************************************************/

/*
 *	OV data stream support.
 */
static const char	 *trk_filename;
static FILE		 *trk_fd;
static OggVorbis_File	  vf;
static int		  dspfd, dsphw;


/****************************************************************************/

/*
 *	Trivial signal handler, processing is done from the main loop.
 */

static void usr1_handler(int ignore)
{
	gotsigusr1 = 1;
}

/****************************************************************************/
/*
 *  Encode a string for incorporation into a URL.  See this page
 *  http://www.blooberry.com/indexdot/html/topics/urlencoding.htm
 *
 *  Reserved and Unsafe characters are combined into a single string
 *  called unsafe.
*/

char *url_encode( char *str )
{
  int size = 0;
  char *ch, *bk;
  char *p, *buf;
  static char unsafe[]     = "$&+,/:;=?@ \"'<>#%{}|\\^~[]`";
  static char char2hex[16] = "0123456789ABCDEF";

  bk = ch  = str;
  if( str == NULL ) return(NULL);

  do{
    if( strchr( unsafe, *ch ))
      size += 2;
    ch++; size ++;
  } while( *ch );

  buf = (char*)malloc( size +1 );
  p   = buf;
  ch  = bk;
  do{
    if( strchr( unsafe, *ch )){
      const char c = *ch;
      *p++ = '%';
      *p++ = char2hex[(c >> 4) & 0xf];
      *p++ = char2hex[c & 0xf];
    }
    else{
      *p++ = *ch;
    }
    ch ++;
  } while( *ch );

  *p = '\0';
  return( buf );
}

/****************************************************************************
 *	Implement the now playing HTTP GET feature
 */

/* time_t is specified in milliseconds, here is a chart, just to be clear
 * on the orders of magnitude:
 *
 * timeout of 2500 milliseconds will set the timeval structure parameters
 * to 
 *   tv.tv_sec  = 2;          seconds
 *   tv.tv_usec = 500,000;    MICROseconds where 1 million == 1 second
 */
static size_t np_read(int fd, char buf[], size_t len, time_t timeout)
{
  int n;
  fd_set rset;
  struct timeval tv;
  FD_ZERO(&rset);
  FD_SET(fd, &rset);
  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;
  if (select(fd+1, &rset, NULL, NULL, &tv) > 0)
    n = recv(fd, buf, len, MSG_DONTWAIT);
  else
    n = EREAD_TIMEOUT;
  return n;
}



/***
 * readln, with a timeout.
 ***/
static size_t np_readln(int fd, char buf[], size_t len, time_t timeout)
{
  size_t i = 0;
  size_t n = 0;
  char a[4];
  while (i < (len-1)) {
    n = np_read(fd, a, 1, timeout);
    if (n == 1) {
      buf[i++] = a[0];
      if (a[0] == '\n')
	break;
    } else if ((n == EREAD_TIMEOUT) || (n == EREAD_ERROR) || (n == EREAD_EOF)) {
      buf[i] = '\0';
      return n;
    }
  }
  buf[i] = '\0';
  return i;
}


static int now_playing(char **user_comments)
{
  char *p;
  char *title = NULL;
  char *artist = NULL;
  char *organization = NULL;
  const char *song_id = NULL;
  char hostname[MAX_HOSTNAME];
  char remoteip[MAX_HOSTNAME];
  char *proxy_ip = NULL;
  int   proxy_port = 80;
  char *proxy_username = NULL;
  char *proxy_password = NULL;
  char url[MAX_BUF];
  char buf[MAX_BUF];
  int  sock = 0;

  struct hostent *host;
  struct sockaddr_in sa;
 
  while( user_comments && *user_comments ) {
    p = *user_comments;
    if (strncasecmp(p, "title=", sizeof("title=")-1) == 0) {
      p += sizeof("title=")-1;
      title = strdup(p);
    } else if (strncasecmp(p, "artist=", sizeof("artist=")-1) == 0) {
      p += sizeof("artist=")-1;
      artist = strdup(p);
    } else if (strncasecmp(p, "organization=", sizeof("organization=")-1) == 0) {
      p += sizeof("organization=")-1;
      organization = strdup(p);
    }
    user_comments++;
  }
  
  song_id = strrchr(trk_filename, '/');
  if(song_id == NULL)
    song_id = trk_filename;
  else
    song_id++;
  p = strchr(song_id, '.');
  if( p != NULL )
    *p = (int)NULL;

  if( gethostname(hostname,sizeof(hostname)) != 0 ) {
    fprintf(stderr, "now_playing: Unable to get mbox hostname, %d\n", errno);
    return(0);
  }
     
  /* build the URL */

  title = title ? url_encode(title) : "";
  artist = artist ? url_encode(artist) : "";
  organization = organization ? url_encode(organization) : "";

  memset(url,0,sizeof(url));

  /* build the HTTP buffer */

  memset(buf,0,sizeof(buf));

  if( npproxy ) {
    char *p;
    int j;
    p = strtok(npproxy, ":"); /* proxy_ip:port:username:password */
    proxy_ip = strdup(p);
    
    if( (p = strtok(NULL, ":")) )
      proxy_port = atoi(p);

    if( (p = strtok(NULL, ":")) )
      proxy_username = strdup(p);

    if( (p = strtok(NULL, ":")) )
      proxy_password = strdup(p);

    j =  snprintf(buf, MAX_BUF, "GET http://%s/tsplay?mbox=%s&channel=%d&song_id=%s&title=%s&artist=%s&organization=%s&commercial=%d HTTP/1.0\r\nUser-Agent: trusonic-nowplaying 1.0\r\nHost: %s\r\n",
		  npip, hostname, lcd_line, song_id, title, artist, organization, advertisement, npip);
    if( j >= MAX_BUF ) {
      fprintf(stderr, "now_playing: url construct exceeds max buffer size\n");
      return(0);
    }

    if( proxy_username && proxy_password ) {
      char plaintext[MAX_BUF];
      char b64encoded[MAX_BUF];
      memset(plaintext,0,sizeof(plaintext));
      memset(b64encoded,0,sizeof(b64encoded));
      if( snprintf(plaintext, MAX_BUF, "%s:%s", proxy_username, proxy_password) >= MAX_BUF ) {
	fprintf(stderr, "now_playing: plaintext auth exceed max buffer size, %s\n", plaintext);
	return(0);
      }

      base64_encode(b64encoded, plaintext, strlen(plaintext));
      strcat(buf, "Proxy-Authorization: Basic ");
      strcat(buf, b64encoded);
      strcat(buf, "\r\n");
    }
    strcat(buf, "\r\n");	/* The final CRLF for the HTTP request */
  } else {
    int j;
    /* No proxy involved, we're connecting directly to the server */
    j =  snprintf(buf, MAX_BUF, "GET /tsplay?mbox=%s&channel=%d&song_id=%s&title=%s&artist=%s&organization=%s&commercial=%d HTTP/1.0\r\nUser-Agent: trusonic-nowplaying 1.0\r\n\r\n",
		  hostname, lcd_line, song_id, title, artist, organization, advertisement);
    if( j >= MAX_BUF ) {
      fprintf(stderr, "now_playing: url construct exceeds max buffer size\n");
      return(0);
    }
  }

  /* We're ready to make the HTTP request */

  strncpy(remoteip, proxy_ip ? proxy_ip : npip, sizeof(remoteip) ); /* Choose IP of proxy if present */

  if( ((host = gethostbyname(remoteip)) == NULL) ) {
    fprintf(stderr, "now_playing: Unable to resolve now playing ip: %s, %d\n", remoteip, errno);
  } else if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "now_playing: Unable to open a socket, %d\n", errno);
  } else {
    long arg;
    int res, status;
    // set the socket non-blocking - just temporarily
    arg = fcntl(sock, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(sock, F_SETFL, arg);

    // Try to connect with a timeout set in npwait
    status = 1;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(proxy_port);
    memcpy(&(sa.sin_addr), host->h_addr, host->h_length);
    res = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    if( res < 0 ) {
      if( errno == EINPROGRESS ) {
	struct timeval tv;
	fd_set myset;

	tv.tv_sec = npwait / 1000;
	tv.tv_usec = (npwait % 1000) * 1000;
	FD_ZERO(&myset);
	FD_SET(sock, &myset);
	if( select(sock+1, NULL, &myset, NULL, &tv) > 0 ) {
	  int valopt;
	  socklen_t lon;
	  lon = sizeof(int);
	  getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
	  if( valopt ) {
	    fprintf(stderr, "now_playing: can't connect() %d - %s\n", valopt, strerror(valopt));
	    status = 0;
	  }
	} else {
	  fprintf(stderr, "now_playing: connect() timeout or error %d - %s, waited %d msec\n", errno, strerror(errno), (int)npwait);
	  status = 0;
	}
      } else {
	fprintf(stderr, "now_playing: connect() error %d - %s\n", errno, strerror(errno));
	status = 0;
      }
    }
    if( status ) {
      int n;

      // Set to blocking mode again
      arg = fcntl(sock, F_GETFL, NULL); 
      arg &= (~O_NONBLOCK); 
      fcntl(sock, F_SETFL, arg); 

      // Send the GET request
      n = send(sock, buf, strlen(buf), 0);
      if (n < strlen(buf)) {
	fprintf(stderr, "now_playing: Unable to write to %s, %d\n", remoteip, errno);
      } else {
	char respbuf[MAX_BUF];
	memset(respbuf,0,sizeof(respbuf));
	while ((n = np_readln(sock, respbuf, sizeof(respbuf), npwait)) != EREAD_EOF) {
	  if (n == EREAD_TIMEOUT) {
	    fprintf(stderr, "now_playing: Read HTTP response timed out, %d\n", (int)npwait);
	    break;
	  } else if (n == 2)
	    break;		/* a blank line */
	  else if (strncmp(respbuf, "HTTP/1.", 7) == 0) {
	    int response;
	    response = atoi(respbuf+9);
	    if( response != 200 )
	      fprintf(stderr, "now_playing: unexpected HTTP response %d, remote_ip %s, %s\n", response, remoteip, buf);
	  }
	}
      }
      close(sock);
    }
  }
  return(1);
}

/****************************************************************************/

/*
 *	Print out the name on a display device if present.
 */

static void lcdtitle(char **user_comments)
{
	const char *title = NULL;
	const char *artist = NULL;
	char displaybuf[MAX_DISPLAY];
	int	ivp;
	struct  iovec iv[4];
	char	prebuf[10];
	char	*p;
	int	j;

	/* Install a signal handler to allow updates to be forced */
	signal(SIGUSR1, usr1_handler);

	/* Determine the name to display.  We use the tag if it is
	 * present and the basename of the file if not.
	 */
	while( user_comments && *user_comments ) {
	  p = *user_comments;
	  if (strncasecmp(p, "title=", sizeof("title=")-1) == 0) {
	    p += sizeof("title=")-1;
	    title = strdup(p);
	  } else if (strncasecmp(p, "artist=", sizeof("artist=")-1) == 0) {
	    p += sizeof("artist=")-1;
	    artist = strdup(p);
	  }
	  user_comments++;
	}

	/* There is not title in the Ogg comments, so use the filename */

	if( title == NULL ) {
	  title = strrchr(trk_filename, '/');
	  if (title == NULL)
	    title = trk_filename;
	  else
	    title++;
	  p = strchr(title, '.');
	  if( p != NULL)
	    *p = (int) NULL;
	  j = snprintf(displaybuf, MAX_DISPLAY, "%s", title);
	  if( j >= MAX_DISPLAY )
	    displaybuf[MAX_DISPLAY] = '\0'; /* output truncated, make sure last char is null */
	} else {
	  j = snprintf(displaybuf, MAX_DISPLAY, "%s / %s", title, artist);
	  if( j >= MAX_DISPLAY )
	    displaybuf[MAX_BUF] = '\0'; /* output truncated, make sure last char is null */
	}
	    
	if (lcd_line) {
		/* Lock the file so we can access it... */
		if (flock(lcdfd, LOCK_SH | LOCK_NB) == -1)
			return;
		if (lcd_line == 0) {
			prebuf[0] = '\f';
			prebuf[1] = '\0';
		} else if (lcd_line == 1) {
			strcpy(prebuf, "\003\005");
		} else if (lcd_line == 2) {
			strcpy(prebuf, "\003\v\005");
		}

		/*
		 * Now we'll write the title out.  We'll do this atomically
		 * just in case two players decide to coexecute...
		 */
		ivp = 0;
		iv[ivp].iov_len = strlen(prebuf) * sizeof(char);
		iv[ivp++].iov_base = prebuf;
		
		iv[ivp].iov_len = strlen(displaybuf) * sizeof(char);
		iv[ivp++].iov_base = (void *)displaybuf;
		
		//postbuf = '\n';
		//iv[ivp].iov_len = sizeof(char);
		//iv[ivp++].iov_base = &postbuf;
		writev(lcdfd, iv, ivp);

		/* Finally, unlock it since we've finished. */
		flock(lcdfd, LOCK_UN);
	}
}

/****************************************************************************/

/*
 *	Output time info to display device.
 */

static void lcdtime(time_t sttime)
{
	static time_t	lasttime;
	time_t		t;
	char		buf[15], *p;
	int		m, s;

	t = time(NULL) - sttime;
	if (t != lasttime && flock(lcdfd, LOCK_SH | LOCK_NB) == 0) {
		p = buf;
		*p++ = '\003';
		if (lcd_time == 2)
			*p++ = '\v';
		*p++ = '\005';
		m = t / 60;
		s = t % 60;
		if (s < 0) s += 60;
		sprintf(p, "%02d:%02d", m, s);
		write(lcdfd, buf, strlen(buf));
		flock(lcdfd, LOCK_UN);
	}
	lasttime = t;
}

/****************************************************************************/

/*
 *	Configure DSP engine settings for playing this track.
 */
 
static void setdsp(int fd)
{
	int v;

	v = 44100;
	if (ioctl(fd, SNDCTL_DSP_SPEED, &v) < 0) {
		fprintf(stderr, "ioctl(SNDCTL_DSP_SPEED)->%d\n", errno);
		exit(1);
	}

	v = 1;
	if (ioctl(fd, SNDCTL_DSP_STEREO, &v) < 0) {
		fprintf(stderr, "ioctl(SNDCTL_DSP_STEREO)->%d\n", errno);
		exit(1);
	}

#if BYTE_ORDER == LITTLE_ENDIAN
	v = AFMT_S16_LE;
#else
	v = AFMT_S16_BE;
#endif
	if (ioctl(fd, SNDCTL_DSP_SAMPLESIZE, &v) < 0) {
		fprintf(stderr, "ioctl(SNDCTL_DSP_SAMPLESIZE)->%d\n", errno);
		exit(1);
	}
}


/****************************************************************************/

static void usage(int rc)
{
	printf("usage: oggplay [-hviqzRPZ] [-s <time>] "
		"[-d <device>] [-w <msec>] [-c <key>]"
		"[-l <line> [-t]] [-p <pause>]ogg-files...\n\n"
		"\t\t-h            this help\n"
		"\t\t-v            verbose stdout output\n"
		"\t\t-b <size>     set the input file buffer size\n"
		"\t\t-i            display file tags and exit\n"
		"\t\t-q            quiet (don't print title)\n"
		"\t\t-R            repeat tracks forever\n"
		"\t\t-z            shuffle tracks\n"
		"\t\t-Z            psuedo-random tracks (implicit -R)\n"
		"\t\t-P            print time to decode/play\n"
		"\t\t-s <time>     sleep between playing tracks\n"
		"\t\t-d <device>   audio device for playback\n"
		"\t\t-D            don't configure audio device as per a DSP device\n"
		"\t\t-l <line>     display title on LCD line (0,1,2) (0 = no title)\n"
		"\t\t-t <line>     display time on LCD line (1,2)\n"
		"\t\t-c <key>      decrypt using key\n"
		"\t\t-0 <bytes>    emit <bytes> zero bytes after playing a track\n"
	        "\t\t-m <ip>       enables Now Playing feature to IP address\n"
	        "\t\t-a            commercial (advertisement) flag\n"
	        "\t\t-p <ip:port:username:password>  use proxy for now playing feature\n"
	        "\t\t-w <msec>     now playing HTTP GET timeout in milliseconds\n"
		);
	exit(rc);
}

/****************************************************************************/
/* define custom OV decode call backs so that we can handle encrypted content.
 */

static int fread_wrap(unsigned char *ptr, size_t sz, size_t n, FILE *f) {
	if (f == NULL)
		return -1;
	const size_t r = fread(ptr, sz, n, f);
	if (crypto_keylen > 0 && r > 0) {
		long pos = (ftell(f) - r) % crypto_keylen;
		int i;

		for (i=0; i<r; i++) {
			ptr[i] ^= crypto_key[pos++];
			if (pos >= crypto_keylen)
				pos = 0;
		}
	}
	return r;
}

static int fseek_wrap(FILE *f, ogg_int64_t off, int whence){
	if (f == NULL)
		return -1;
	return fseek(f, (int)off, whence);
}

static ov_callbacks ovcb = {
	(size_t (*)(void *, size_t, size_t, void *))	&fread_wrap,
	(int (*)(void *, ogg_int64_t, int))		&fseek_wrap,
	(int (*)(void *))				&fclose,
	(long (*)(void *))				&ftell
};

/****************************************************************************/

static int play_one(const char *file) {
	char		pcmout[65536];
	int		current_section;
	time_t		sttime;
	unsigned long	us;
	struct timeval	tvstart, tvend;
	char		**user_comments = NULL;

	trk_filename = file;

	trk_fd = fopen(trk_filename, "r");

	if (trk_fd == NULL) {
		fprintf(stderr, "ERROR: Unable to open '%s', errno=%d\n",
			trk_filename, errno);
		return 1;
	}
	setvbuf(trk_fd, NULL, _IOFBF, buffer_size);
retry:	if (ov_open_callbacks(trk_fd, &vf, NULL, 0, ovcb) < 0) {
		if (crypto_keylen > 0) {
			crypto_keylen = 0;
			rewind(trk_fd);
			goto retry;
		}
		fclose(trk_fd);
		fprintf(stderr, "ERROR: Unable to ov_open '%s', errno=%d\n",
			trk_filename, errno);
		return 1;
	}
	user_comments = ov_comment(&vf, -1)->user_comments;

	if (onlytags) {
		char **ptr = user_comments;
		while (ptr && *ptr) {
			puts(*ptr);
			ptr++;
		}
		return 0;
	}

	if (dsphw)
		setdsp(dspfd);
	if (lcd_line)
		lcdtitle(user_comments);

	if (npip) {
	  pid_t np_pid;
	  np_pid = fork();
	  if( np_pid == 0) {
	    exit(now_playing(user_comments));
	  }
	  /* Let init automatically clean up our child processes */
	  signal(SIGCHLD, SIG_IGN);
	}
	gettimeofday(&tvstart, NULL);
	sttime = time(NULL);

	/* We are all set, decode the file and play it */
	for (;;) {
		const long ret = ov_read(&vf, pcmout, sizeof(pcmout), &current_section);
		if (ret == 0)
			break;
		else if (ret < 0) {
			ov_clear(&vf);
			return 1;
		}
		write(dspfd, pcmout, ret);
		if (gotsigusr1) {
			gotsigusr1 = 0;
			if (lcd_line)
				lcdtitle(user_comments);
		}
		if (lcd_time)
			lcdtime(sttime);
	}
	ov_clear(&vf);

	if (printtime) {
		gettimeofday(&tvend, NULL);
		us = ((tvend.tv_sec - tvstart.tv_sec) * 1000000) +
		    (tvend.tv_usec - tvstart.tv_usec);
		printf("Total time = %d.%06d seconds\n",
		       (int)(us / 1000000), (int)(us % 1000000));
	}
	return 0;
}

static void paddy(int fd, int len) {
	char buf[2000];
	int n;

	bzero(buf, sizeof(buf));

	while (len > 0) {
		n = sizeof(buf);
		if (len < n)
			n = len;
		n = write(fd, buf, n);
		if (n == 0)
			break;
		if (n == -1) {
			if (errno != EINTR)
				break;
		} else
			len -= n;
	}
}

int main(int argc, char *argv[])
{
	int		c, i, j, slptime;
	int		repeat;
 	int		argnr, startargnr, rand, shuffle;
	char		*device, *argvtmp;
	pid_t		pid;
	int		zerobytes;

	signal(SIGUSR1, SIG_IGN);

	verbose = 0;
	quiet = 0;
	shuffle = 0;
	rand = 0;
	repeat = 0;
	printtime = 0;
	slptime = 0;
	device = "/dev/dsp";
	dsphw = 0;
	onlytags = 0;
	zerobytes = 0;
	advertisement = 0;

	while ((c = getopt(argc, argv, "?hivqzt:RZPs:d:Dl:Vc:b:0:m:ap:w:")) >= 0) {
		switch (c) {
		case 'b':
			buffer_size = atoi(optarg);
			if (buffer_size < 1)
				buffer_size = 1;
			break;
		case 'V':
			printf("%s version 1.0\n", argv[0]);
			return 0;
		case 'v':
			verbose++;
			break;
		case 'q':
			verbose = 0;
			quiet++;
			break;
		case 'R':
			repeat++;
			break;
		case 'z':
			shuffle++;
			break;
		case 'Z':
			rand++;
			repeat++;
			break;
		case 'P':
			printtime++;
			break;
		case 's':
			slptime = atoi(optarg);
			break;
		case 'd':
			device = optarg;
			break;
		case 'D':
			dsphw = 1;
			break;
		case 'l':
			lcd_line = atoi(optarg);
			break;
		case 't':
			lcd_time = atoi(optarg);
			break;
		case 'i':
			onlytags = 1;
			break;
		case 'c':
			crypto_key = strdup(optarg);
			crypto_keylen = strlen(crypto_key);
			{	char *p = optarg;
				while (*p != '\0')
					*p++ = '\0';
			}
			break;
		case '0':
			zerobytes = (atoi(optarg) + 1) & ~1;
			if (zerobytes < 0)
				zerobytes = 0;
			break;
		case 'm':
		  npip = strdup(optarg);
		  break;
		case 'a':
		  advertisement = 1;
		  break;
		case 'p':
		  npproxy = strdup(optarg); /* proxy_ip:port:username:password */
		  break;
		case 'w':
		  npwait = atoi(optarg);
		  if( npwait < 250 || npwait> 10000 )
		    npwait = 250; /* just a safety measure */
		  break;
		case 'h':
		case '?':
			usage(0);
			break;
		}
	}

	argnr = optind;
	if (argnr >= argc)
		usage(1);
	startargnr = argnr;

#ifdef CONFIG_USER_SETKEY_SETKEY
	/* If we've got the crypto key driver installed and the user hasn't
	 * specified a crypto key already, we load it from the driver.
	 */
	if (crypto_key == NULL) {
		static unsigned char key[128];

		if ((i = getdriverkey(key, sizeof(key))) > 0) {
			crypto_key = (char *) key;
			crypto_keylen = i;
		}
	}
#endif

	/* Make ourselves the top priority process! */
	setpriority(PRIO_PROCESS, 0, -20);
	srandom(time(NULL) ^ getpid());

	/* Open the audio playback device */
	if ((dspfd = open(device, (O_WRONLY | O_CREAT | O_TRUNC), 0660)) < 0) {
		fprintf(stderr, "ERROR: Can't open output device '%s', "
			"errno=%d\n", device, errno);
		exit(0);
	}

	/* Open LCD device if we are going to use it */
	if ((lcd_line > 0) || (lcd_time > 0)) {
		lcdfd = open("/dev/lcdtxt", O_WRONLY);
		if (lcdfd < 0) {
			lcd_time = 0;
			lcd_line = 0;
		}
	}

nextall:
	/* Shuffle tracks if slected */
	if (shuffle) {
		rand = 0;
		for (i=startargnr; i<argc-1; i++) {
			j = (((unsigned int) random()) % (argc - i)) + i;
			argvtmp = argv[j];
			argv[j] = argv[i];
			argv[i] = argvtmp;
		}
	}

nextfile:
	if (rand) {
		argnr = (((unsigned int) random()) % (argc - startargnr)) +
			startargnr;
	}

	pid = fork();
	if (pid == 0) {
		exit(play_one(argv[argnr]));
	} else if (pid > 0) {
		int status;

		for (;;) {
			if (waitpid(pid, &status, 0) == -1)
				if (errno != EINTR)
					break;
		}
	} else if (errno == ENOSYS)
		play_one(argv[argnr]);
	else
		perror("fork()");

	if (slptime)
		sleep(slptime);

	if (++argnr < argc)
		goto nextfile;

	if (repeat) {
		argnr = startargnr;
		goto nextall;
	}

	paddy(dspfd, zerobytes);
	close(dspfd);
	if (lcdfd >= 0)
		close(lcdfd);
	return 0;
}

/****************************************************************************/
