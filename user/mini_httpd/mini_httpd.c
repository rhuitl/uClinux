/* mini_httpd - small HTTP server
**
** Copyright © 1999,2000 by Jef Poskanzer <jef@acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/


#include "version.h"
#include "port.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#endif /* USE_SSL */


#define ERR_DIR "errors"
#define DEFAULT_HTTP_PORT 80
#ifdef USE_SSL
#define DEFAULT_HTTPS_PORT 443
#ifdef EMBED
#define CERT_FILE "/etc/config/cert.pem"
#define KEY_FILE  "/etc/config/key.pem"
#else /* EMBED */
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#endif /* EMBED */
#endif /* USE_SSL */
#define DEFAULT_USER "nobody"
#define CGI_NICE 10
#define CGI_PATH "/usr/local/bin:/usr/ucb:/bin:/usr/bin"
#define CGI_LD_LIBRARY_PATH "/usr/local/lib:/usr/lib"
#define AUTH_FILE ".htpasswd"

#define METHOD_GET 1
#define METHOD_HEAD 2
#define METHOD_POST 3

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif


/* A multi-family sockaddr. */
typedef union {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
#ifdef HAVE_SOCKADDR_IN6
    struct sockaddr_in6 sa_in6;
#endif /* HAVE_SOCKADDR_IN6 */
#ifdef HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage sa_stor;
#endif /* HAVE_SOCKADDR_STORAGE */
    } usockaddr;


static char* argv0;
static int debug;
static int port;
static int do_chroot;
static int vhost;
static char* user;
static char* cgi_pattern;
static char* hostname;
static char hostname_buf[500];
static u_int hostaddr;
static char* logfile;
static char* pidfile;
static char* charset;
static FILE* logfp;
static int listen4_fd, listen6_fd;
#ifdef USE_SSL
static int do_ssl;
static SSL_CTX* ssl_ctx;
#endif /* USE_SSL */


/* Request variables. */
static int conn_fd;
#ifdef USE_SSL
static SSL* ssl;
#endif /* USE_SSL */
static usockaddr client_addr;
static char* request;
static int request_size, request_len, request_idx;
static int method;
static char* path;
static char* file;
struct stat sb;
static char* query;
static char* protocol;
static int status;
static long bytes;
static char* req_hostname;

static char* authorization;
static long content_length;
static char* content_type;
static char* cookie;
static char* host;
static time_t if_modified_since;
static char* referer;
static char* useragent;

static char* remoteuser;


/* Forwards. */
static void usage( void );
static int initialize_listen_socket( usockaddr* usaP );
static void handle_request( void );
static void de_dotdot( char* file );
static void do_file( void );
static void do_dir( void );
static void do_cgi( void );
static void cgi_interpose_input( int wfd );
static void cgi_interpose_output( int rfd, int parse_headers );
static char** make_argp( void );
static char** make_envp( void );
static char* build_env( char* fmt, char* arg );
static void auth_check( char* dirname );
static void send_authenticate( char* realm );
static char* virtual_file( char* file );
static void send_error( int s, char* title, char* extra_header, char* text );
static void send_error_body( int s, char* title, char* text );
static int send_error_file( char* filename );
static void send_error_tail( void );
static void add_headers( int s, char* title, char* extra_header, char* mime_type, long b, time_t mod );
static void start_request( void );
static void add_to_request( char* str, int len );
static char* get_request_line( void );
static void start_response( void );
static void add_to_response( char* str, int len );
static void send_response( void );
static int my_read( char* buf, int size );
static int my_write( char* buf, int size );
static void add_to_buf( char** bufP, int* bufsizeP, int* buflenP, char* str, int len );
static void make_log_entry( void );
static char* get_method_str( int m );
static char* get_mime_type( char* name );
static void handle_sigterm( int sig );
static void handle_sigchld( int sig );
static void lookup_hostname( usockaddr* usa4P, size_t sa4_len, int* gotv4P, usockaddr* usa6P, size_t sa6_len, int* gotv6P );
static char* ntoa( usockaddr* usaP );
static size_t sockaddr_len( usockaddr* usaP );
static void strdecode( char* to, char* from );
static int hexit( char c );
static int b64_decode( const char* str, unsigned char* space, int size );
static int match( const char* pattern, const char* string );
static int match_one( const char* pattern, int patternlen, const char* string );


int
main( int argc, char** argv )
    {
    int argn;
    uid_t uid;
    usockaddr host_addr4;
    usockaddr host_addr6;
    int gotv4, gotv6;
    fd_set afdset;
    int maxfd;
    usockaddr usa;
    int sz, r;

    /* Parse args. */
    argv0 = argv[0];
    debug = 0;
    port = -1;
    do_chroot = 0;
    vhost = 0;
    cgi_pattern = (char*) 0;
    charset = "iso-8859-1";
    user = DEFAULT_USER;
    hostname = (char*) 0;
    logfile = (char*) 0;
    pidfile = (char*) 0;
    logfp = (FILE*) 0;
#ifdef USE_SSL
    do_ssl = 0;
#endif /* USE_SSL */
    argn = 1;
    while ( argn < argc && argv[argn][0] == '-' )
	{
	if ( strcmp( argv[argn], "-D" ) == 0 )
	    debug = 1;
#ifdef USE_SSL
	else if ( strcmp( argv[argn], "-S" ) == 0 )
	    do_ssl = 1;
#endif /* USE_SSL */
	else if ( strcmp( argv[argn], "-p" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    port = atoi( argv[argn] );
	    }
	else if ( strcmp( argv[argn], "-c" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    cgi_pattern = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-u" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    user = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-h" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    hostname = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-r" ) == 0 )
	    do_chroot = 1;
	else if ( strcmp( argv[argn], "-v" ) == 0 )
	    vhost = 1;
	else if ( strcmp( argv[argn], "-l" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    logfile = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-i" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    pidfile = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-T" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    charset = argv[argn];
	    }
	else
	    usage();
	++argn;
	}
    if ( argn != argc )
	usage();

    if ( port == -1 )
	{
#ifdef USE_SSL
	if ( do_ssl )
	    port = DEFAULT_HTTPS_PORT;
	else
	    port = DEFAULT_HTTP_PORT;
#else /* USE_SSL */
	port = DEFAULT_HTTP_PORT;
#endif /* USE_SSL */
	}

    if ( logfile != (char*) 0 )
	{
	/* Open the log file. */
	logfp = fopen( logfile, "a" );
	if ( logfp == (FILE*) 0 )
	    {
	    perror( logfile );
	    exit( 1 );
	    }
	}

    /* Look up hostname. */
    lookup_hostname(
	&host_addr4, sizeof(host_addr4), &gotv4,
	&host_addr6, sizeof(host_addr6), &gotv6 );
    if ( hostname == (char*) 0 )
	{
	(void) gethostname( hostname_buf, sizeof(hostname_buf) );
	hostname = hostname_buf;
	}
    if ( ! ( gotv4 || gotv6 ) )
	{
	(void) fprintf( stderr, "can't find any valid address\n" );
	exit( 1 );
	}

    /* Initialize listen sockets.  Try v6 first because of a Linux peculiarity; 
    ** unlike other systems, it has magical v6 sockets that also listen for v4,
    ** but if you bind a v4 socket first then the v6 bind fails.
    */
    if ( gotv6 )
	listen6_fd = initialize_listen_socket( &host_addr6 );
    else
	listen6_fd = -1;
    if ( gotv4 )
	listen4_fd = initialize_listen_socket( &host_addr4 );
    else
	listen4_fd = -1;
    /* If we didn't get any valid sockets, fail. */
    if ( listen4_fd == -1 && listen6_fd == -1 )
	{
	(void) fprintf( stderr, "can't bind to any address\n" );
	exit( 1 );
	}

#ifdef USE_SSL
    if ( do_ssl )
	{
	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new( SSLv23_server_method() );
	if ( SSL_CTX_use_certificate_file( ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM ) == 0 ||
	     SSL_CTX_use_PrivateKey_file( ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM ) == 0 ||
	     SSL_CTX_check_private_key( ssl_ctx ) == 0 )
	    {
	    ERR_print_errors_fp( stderr );
	    exit( 1 );
	    }
	}
#endif /* USE_SSL */

    if ( ! debug )
	{
	/* Make ourselves a daemon. */
#ifdef HAVE_DAEMON
	if ( daemon( 1, 1 ) < 0 )
	    {
	    perror( "daemon" );
	    exit( 1 );
	    }
#else
	switch ( fork() )
	    {
	    case 0:
	    break;
	    case -1:
	    perror( "fork" );
	    exit( 1 );
	    default:
	    exit( 0 );
	    }
#ifdef HAVE_SETSID
	(void) setsid();
#endif
#endif
	}
    else
	{
	/* Even if we don't daemonize, we still want to disown our parent
	** process.
	*/
#ifdef HAVE_SETSID
	(void) setsid();
#endif /* HAVE_SETSID */
	}

    if ( pidfile != (char*) 0 )
        {
	/* Write the PID file. */
	FILE* pidfp = fopen( pidfile, "w" );
        if ( pidfp == (FILE*) 0 )
            {
	    perror( pidfile );
            exit( 1 );
            }
        (void) fprintf( pidfp, "%d\n", (int) getpid() );
        (void) fclose( pidfp );
        }

    /* Read zone info now, in case we chroot(). */
    tzset();

#ifndef EMBED
    /* If we're root, start becoming someone else. */
    if ( getuid() == 0 )
	{
	struct passwd* pwd;
	pwd = getpwnam( user );
	if ( pwd == (struct passwd*) 0 )
	    {
	    (void) fprintf( stderr, "%s: unknown user - '%s'\n", argv0, user );
	    exit( 1 );
	    }
	/* Set aux groups to null. */
	if ( setgroups( 0, (const gid_t*) 0 ) < 0 )
	    {
	    perror( "setgroups" );
	    exit( 1 );
	    }
	/* Set primary group. */
	if ( setgid( pwd->pw_gid ) < 0 )
	    {
	    perror( "setgid" );
	    exit( 1 );
	    }
	/* Try setting aux groups correctly - not critical if this fails. */
	if ( initgroups( user, pwd->pw_gid ) < 0 )
	    perror( "initgroups" );
#ifdef HAVE_SETLOGIN
	/* Set login name. */
	(void) setlogin( user );
#endif /* HAVE_SETLOGIN */
	/* Save the new uid for setting after we chroot(). */
	uid = pwd->pw_uid;
	}
#endif /* EMBED */

    /* Chroot if requested. */
    if ( do_chroot )
	{
	char cwd[1000];
	(void) getcwd( cwd, sizeof(cwd) - 1 );
	if ( chroot( cwd ) < 0 )
	    {
	    perror( "chroot" );
	    exit( 1 );
	    }
	/* Always chdir to / after a chroot. */
	if ( chdir( "/" ) < 0 )
	    {
	    perror( "chroot chdir" );
	    exit( 1 );
	    }

	}

#ifndef EMBED
    /* If we're root, become someone else. */
    if ( getuid() == 0 )
	{
	/* Set uid. */
	if ( setuid( uid ) < 0 )
	    {
	    perror( "setuid" );
	    exit( 1 );
	    }
	/* Check for unnecessary security exposure. */
	if ( ! do_chroot )
	    (void) fprintf( stderr,
		"%s: started as root without requesting chroot(), warning only\n", argv0 );
	}
#endif /* EMBED */

    /* Catch various termination signals. */
    (void) signal( SIGTERM, handle_sigterm );
    (void) signal( SIGINT, handle_sigterm );
    (void) signal( SIGHUP, handle_sigterm );
    (void) signal( SIGUSR1, handle_sigterm );

    /* Catch defunct children. */
    (void) signal( SIGCHLD, handle_sigchld );

    /* And get EPIPE instead of SIGPIPE. */
    (void) signal( SIGPIPE, SIG_IGN );

    /* Main loop. */
    for (;;)
	{
	/* Possibly do a select() on the possible two listen fds. */
	FD_ZERO( &afdset );
	maxfd = -1;
	if ( listen4_fd != -1 )
	    {
	    FD_SET( listen4_fd, &afdset );
	    if ( listen4_fd > maxfd )
		maxfd = listen4_fd;
	    }
	if ( listen6_fd != -1 )
	    {
	    FD_SET( listen6_fd, &afdset );
	    if ( listen6_fd > maxfd )
		maxfd = listen6_fd;
	    }
	if ( listen4_fd != -1 && listen6_fd != -1 )
	    if ( select( maxfd + 1, &afdset, (fd_set*) 0, (fd_set*) 0, (struct timeval*) 0 ) < 0 )
		{
		perror( "select" );
		exit( 1 );
		}
	/* (If we don't have two listen fds, we can just skip the select()
	** and fall through.  Whichever listen fd we do have will do a
	** blocking accept() instead.)
	*/

	/* Accept the new connection. */
	sz = sizeof(usa);
	if ( listen4_fd != -1 && FD_ISSET( listen4_fd, &afdset ) )
	    conn_fd = accept( listen4_fd, &usa.sa, &sz );
	else if ( listen6_fd != -1 && FD_ISSET( listen6_fd, &afdset ) )
	    conn_fd = accept( listen6_fd, &usa.sa, &sz );
	else
	    {
	    (void) fprintf( stderr, "%s: select failure\n", argv0 );
	    exit( 1 );
	    }
	if ( conn_fd < 0 )
	    {
	    if ( errno == EINTR )
		continue;	/* try again */
	    perror( "accept" );
	    exit( 1 );
	    }

	/* Fork a sub-process to handle the connection. */
	r = fork();
	if ( r < 0 )
	    {
	    perror( "fork" );
	    exit( 1 );
	    }
	if ( r == 0 )
	    {
	    /* Child process. */
	    client_addr = usa;
	    if ( listen4_fd != -1 )
		(void) close( listen4_fd );
	    if ( listen6_fd != -1 )
		(void) close( listen6_fd );
	    handle_request();
	    exit( 0 );
	    }
	(void) close( conn_fd );
	}
    }


static void
usage( void )
    {
#ifdef USE_SSL
    (void) fprintf( stderr, "usage:  %s [-D] [-S] [-p port] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset]\n", argv0 );
#else /* USE_SSL */
    (void) fprintf( stderr, "usage:  %s [-D] [-p port] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset]\n", argv0 );
#endif /* USE_SSL */
    exit( 1 );
    }


static int
initialize_listen_socket( usockaddr* usaP )
    {
    int listen_fd;
    int i;

    listen_fd = socket( usaP->sa.sa_family, SOCK_STREAM, 0 );
    if ( listen_fd < 0 )
	{
	perror( "socket" );
	return -1;
	}
    (void) fcntl( listen_fd, F_SETFD, 1 );
    i = 1;
    if ( setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*) &i, sizeof(i) ) < 0 )
	{
	perror( "setsockopt" );
	return -1;
	}
    if ( bind( listen_fd, &usaP->sa, sockaddr_len( usaP ) ) < 0 )
	{
	perror( "bind" );
	return -1;
	}
    if ( listen( listen_fd, 1024 ) < 0 )
	{
	perror( "listen" );
	return -1;
	}
    return listen_fd;
    }


/* This runs in a child process, and exits when done, so cleanup is
** not needed.
*/
static void
handle_request( void )
    {
    char* method_str;
    char* line;
    char* cp;

    /* Initialize the request variables. */
    remoteuser = (char*) 0;
    method = -1;
    path = (char*) 0;
    file = (char*) 0;
    query = "";
    protocol = "HTTP/1.0";
    status = 0;
    bytes = -1;
    req_hostname = (char*) 0;

    authorization = (char*) 0;
    content_type = (char*) 0;
    content_length = -1;
    cookie = (char*) 0;
    host = (char*) 0;
    if_modified_since = (time_t) -1;
    referer = "";
    useragent = "";

#ifdef USE_SSL
    if ( do_ssl )
	{
	ssl = SSL_new( ssl_ctx );
	SSL_set_fd( ssl, conn_fd );
	if ( SSL_accept( ssl ) == 0 )
	    {
	    ERR_print_errors_fp( stderr );
	    exit( 1 );
	    }
	}
#endif /* USE_SSL */

    /* Read in the request. */
    start_request();
    for (;;)
	{
	char buf[10000];
	int r = my_read( buf, sizeof(buf) );
	if ( r <= 0 )
	    break;
	add_to_request( buf, r );
	if ( strstr( request, "\r\n\r\n" ) != (char*) 0 ||
	     strstr( request, "\n\n" ) != (char*) 0 )
	    break;
	}

    /* Parse the first line of the request. */
    method_str = get_request_line();
    path = strpbrk( method_str, " \t\n\r" );
    if ( path == (char*) 0 )
	send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );
    *path++ = '\0';
    path += strspn( path, " \t\n\r" );
    protocol = strpbrk( path, " \t\n\r" );
    if ( protocol == (char*) 0 )
	send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );
    *protocol++ = '\0';
    query = strchr( path, '?' );
    if ( query == (char*) 0 )
	query = "";
    else
	*query++ = '\0';

    /* Parse the rest of the request headers. */
    while ( ( line = get_request_line() ) != (char*) 0 )
	{
	if ( line[0] == '\0' )
	    break;
	else if ( strncasecmp( line, "Authorization:", 14 ) == 0 )
	    {
	    cp = &line[14];
	    cp += strspn( cp, " \t" );
	    authorization = cp;
	    }
	else if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
	    {
	    cp = &line[15];
	    cp += strspn( cp, " \t" );
	    content_length = atol( cp );
	    }
	else if ( strncasecmp( line, "Content-Type:", 13 ) == 0 )
	    {
	    cp = &line[13];
	    cp += strspn( cp, " \t" );
	    content_type = cp;
	    }
	else if ( strncasecmp( line, "Cookie:", 7 ) == 0 )
	    {
	    cp = &line[7];
	    cp += strspn( cp, " \t" );
	    cookie = cp;
	    }
	else if ( strncasecmp( line, "Host:", 5 ) == 0 )
	    {
	    cp = &line[5];
	    cp += strspn( cp, " \t" );
	    host = cp;
	    }
	else if ( strncasecmp( line, "If-Modified-Since:", 18 ) == 0 )
	    {
	    cp = &line[18];
	    cp += strspn( cp, " \t" );
	    if_modified_since = tdate_parse( cp );
	    }
	else if ( strncasecmp( line, "Referer:", 8 ) == 0 )
	    {
	    cp = &line[8];
	    cp += strspn( cp, " \t" );
	    referer = cp;
	    }
	else if ( strncasecmp( line, "User-Agent:", 11 ) == 0 )
	    {
	    cp = &line[11];
	    cp += strspn( cp, " \t" );
	    useragent = cp;
	    }
	}

    if ( strcasecmp( method_str, get_method_str( METHOD_GET ) ) == 0 )
	method = METHOD_GET;
    else if ( strcasecmp( method_str, get_method_str( METHOD_HEAD ) ) == 0 )
	method = METHOD_HEAD;
    else if ( strcasecmp( method_str, get_method_str( METHOD_POST ) ) == 0 )
	method = METHOD_POST;
    else
	send_error( 501, "Not Implemented", (char*) 0, "That method is not implemented." );

    strdecode( path, path );
    if ( path[0] != '/' )
	send_error( 400, "Bad Request", (char*) 0, "Bad filename." );
    file = &(path[1]);
    if ( file[0] == '\0' )
	file = "./";
    de_dotdot( file );
    if ( file[0] == '/' ||
	 ( file[0] == '.' && file[1] == '.' &&
	   ( file[2] == '\0' || file[2] == '/' ) ) )
	send_error( 400, "Bad Request", (char*) 0, "Illegal filename." );
    if ( vhost )
	file = virtual_file( file );

    if ( stat( file, &sb ) < 0 )
	send_error( 404, "Not Found", (char*) 0, "File not found." );
    if ( ! S_ISDIR( sb.st_mode ) )
	do_file();
    else
	{
	char idx[10000];
	if ( file[strlen(file) - 1] != '/' )
	    {
	    char location[10000];
	    (void) snprintf( location, sizeof(location), "Location: %s/", path );
	    send_error( 302, "Found", location, "Directories must end with a slash." );
	    }
	(void) snprintf( idx, sizeof(idx), "%sindex.html", file );
	if ( stat( idx, &sb ) >= 0 )
	    {
	    file = idx;
	    do_file();
	    }
	else
	    {
	    (void) snprintf( idx, sizeof(idx), "%sindex.htm", file );
	    if ( stat( idx, &sb ) >= 0 )
		{
		file = idx;
		do_file();
		}
	    else
		{
		(void) snprintf( idx, sizeof(idx), "%sindex.cgi", file );
		if ( stat( idx, &sb ) >= 0 )
		    {
		    file = idx;
		    do_file();
		    }
		else
		    do_dir();
		}
	    }
	}

#ifdef USE_SSL
    SSL_free( ssl );
#endif /* USE_SSL */
    }


static void
de_dotdot( char* file )
    {
    char* cp;
    char* cp2;
    int l;

    /* Elide any xxx/../ sequences. */
    while ( ( cp = strstr( file, "/../" ) ) != (char*) 0 )
	{
	for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
	    continue;
	if ( cp2 < file )
	    break;
	(void) strcpy( cp2, cp + 3 );
	}

    /* Also elide any xxx/.. at the end. */
    while ( ( l = strlen( file ) ) > 3 &&
	    strcmp( ( cp = file + l - 3 ), "/.." ) == 0 )
	{
	for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
	    continue;
	if ( cp2 < file )
	    break;
	*cp2 = '\0';
	}
    }


static void
do_file( void )
    {
    char buf[10000];
    char* type;
    char fixed_type[500];
    char* cp;
    int fd;
    void* ptr;

    /* Check authorization for this directory. */
    (void) strncpy( buf, file, sizeof(buf) );
    cp = strrchr( buf, '/' );
    if ( cp == (char*) 0 )
	(void) strcpy( buf, "." );
    else
	*cp = '\0';
    auth_check( buf );

    /* Check if the filename is the AUTH_FILE itself - that's verboten. */
    if ( strcmp( file, AUTH_FILE ) == 0 ||
	 ( strcmp( &(file[strlen(file) - sizeof(AUTH_FILE) + 1]), AUTH_FILE ) == 0 &&
	   file[strlen(file) - sizeof(AUTH_FILE)] == '/' ) )
	send_error( 403, "Forbidden", (char*) 0, "File is protected." );

    /* Is it CGI? */
    if ( cgi_pattern != (char*) 0 && match( cgi_pattern, file ) )
	{
	do_cgi();
	return;
	}

    fd = open( file, O_RDONLY );
    if ( fd < 0 )
	send_error( 403, "Forbidden", (char*) 0, "File is protected." );
    type = get_mime_type( file );
    (void) snprintf( fixed_type, sizeof(fixed_type), type, charset );
    if ( if_modified_since != (time_t) -1 &&
	 if_modified_since >= sb.st_mtime )
	{
	add_headers(
	    304, "Not Modified", (char*) 0, fixed_type, sb.st_size,
	    sb.st_mtime );
	send_response();
	return;
	}
    add_headers( 200, "Ok", (char*) 0, fixed_type, sb.st_size, sb.st_mtime );
    send_response();
    if ( method == METHOD_HEAD )
	return;
    if ( sb.st_size > 0 )	/* avoid zero-length mmap */
	{
	ptr = mmap( 0, sb.st_size, PROT_READ, MAP_SHARED, fd, 0 );
	if ( ptr != (void*) -1 )
	    {
	    (void) my_write( ptr, sb.st_size );
	    (void) munmap( ptr, sb.st_size );
	    }
	}
    (void) close( fd );
    }


static void
do_dir( void )
    {
    char buf[10000];
    int buflen;
    char command[10000];
    char* contents;
    int contents_size, contents_len;
    FILE* fp;

    /* Check authorization for this directory. */
    auth_check( file );

    contents_size = 0;
    buflen = snprintf( buf, sizeof(buf),
	"<HTML><HEAD><TITLE>Index of %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#99cc99\"><H4>Index of %s</H4>\n<PRE>\n",
	file, file );
    add_to_buf( &contents, &contents_size, &contents_len, buf, buflen );

    /* Magic HTML ls command! */
    if ( strchr( file, '\'' ) == (char*) 0 )
	{
	(void) snprintf(
	    command, sizeof(command),
	    "ls -lgF '%s' | tail +2 | sed -e 's/^\\([^ ][^ ]*\\)\\(  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)\\(  *[^ ][^ ]*\\)  *\\([^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)  *\\(.*\\)$/\\1 \\3  \\4  |\\5/' -e '/ -> /!s,|\\([^*]*\\)$,|<A HREF=\"\\1\">\\1</A>,' -e '/ -> /!s,|\\(.*\\)\\([*]\\)$,|<A HREF=\"\\1\">\\1</A>\\2,' -e '/ -> /s,|\\([^@]*\\)\\(@* -> \\),|<A HREF=\"\\1\">\\1</A>\\2,' -e 's/|//'",
	    file );
	fp = popen( command, "r" );
	for (;;)
	    {
	    int r;
	    r = fread( buf, 1, sizeof(buf), fp );
	    if ( r <= 0 )
		break;
	    add_to_buf( &contents, &contents_size, &contents_len, buf, r );
	    }
	(void) pclose( fp );
	}

    buflen = snprintf( buf, sizeof(buf),
	"</PRE>\n<HR>\n<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n</BODY></HTML>\n",
	SERVER_URL, SERVER_SOFTWARE );
    add_to_buf( &contents, &contents_size, &contents_len, buf, buflen );

    add_headers( 200, "Ok", (char*) 0, "text/html", contents_len, sb.st_mtime );
    if ( method == METHOD_HEAD )
	{
	send_response();
	return;
	}
    add_to_response( contents, contents_len );
    send_response();
    }


static void
do_cgi( void )
    {
    char** argp;
    char** envp;
    int parse_headers;
    char* binary;
    char* directory;

    if ( method != METHOD_GET && method != METHOD_POST )
	send_error( 501, "Not Implemented", (char*) 0, "That method is not implemented for CGI." );

    /* Make the environment vector. */
    envp = make_envp();

    /* Make the argument vector. */
    argp = make_argp();

    /* Set up stdin.  For POSTs we may have to set up a pipe from an
    ** interposer process, depending on if we've read some of the data
    ** into our buffer.  We also have to do this for all SSL CGIs.
    */
#ifdef USE_SSL
    if ( ( method == METHOD_POST && request_len > request_idx ) || do_ssl )
#else /* USE_SSL */
    if ( ( method == METHOD_POST && request_len > request_idx ) )
#endif /* USE_SSL */
	{
	int p[2];
	int r;

	if ( pipe( p ) < 0 )
	    send_error( 500, "Internal Error", (char*) 0, "Something unexpected went wrong making a pipe." );
	r = fork();
	if ( r < 0 )
	    send_error( 500, "Internal Error", (char*) 0, "Something unexpected went wrong forking an interposer." );
	if ( r == 0 )
	    {
	    /* Interposer process. */
	    (void) close( p[0] );
	    cgi_interpose_input( p[1] );
	    exit( 0 );
	    }
	(void) close( p[1] );
	(void) dup2( p[0], STDIN_FILENO );
	}
    else
	{
	/* Otherwise, the request socket is stdin. */
	(void) dup2( conn_fd, STDIN_FILENO );
	}

    /* Set up stdout/stderr.  For SSL, or if we're doing CGI header parsing,
    ** we need an output interposer too.
    */
    if ( strncmp( argp[0], "nph-", 4 ) == 0 )
	parse_headers = 0;
    else
	parse_headers = 1;
#ifdef USE_SSL
    if ( parse_headers || do_ssl )
#else /* USE_SSL */
    if ( parse_headers )
#endif /* USE_SSL */
	{
	int p[2];
	int r;

	if ( pipe( p ) < 0 )
	    send_error( 500, "Internal Error", (char*) 0, "Something unexpected went wrong making a pipe." );
	r = fork();
	if ( r < 0 )
	    send_error( 500, "Internal Error", (char*) 0, "Something unexpected went wrong forking an interposer." );
	if ( r == 0 )
	    {
	    /* Interposer process. */
	    (void) close( p[1] );
	    cgi_interpose_output( p[0], parse_headers );
	    exit( 0 );
	    }
	(void) close( p[0] );
	(void) dup2( p[1], STDOUT_FILENO );
	(void) dup2( p[1], STDERR_FILENO );
	}
    else
	{
	/* Otherwise, the request socket is stdout/stderr. */
	(void) dup2( conn_fd, STDOUT_FILENO );
	(void) dup2( conn_fd, STDERR_FILENO );
	}

    /* Set priority. */
    (void) nice( CGI_NICE );

    /* Split the program into directory and binary, so we can chdir()
    ** to the program's own directory.  This isn't in the CGI 1.1
    ** spec, but it's what other HTTP servers do.
    */
    directory = strdup( file );
    if ( directory == (char*) 0 )
	binary = file;	/* ignore errors */
    else
	{
	binary = strrchr( directory, '/' );
	if ( binary == (char*) 0 )
	    binary = file;
	else
	    {
	    *binary++ = '\0';
	    (void) chdir( directory );	/* ignore errors */
	    }
	}

    /* Default behavior for SIGPIPE. */
    (void) signal( SIGPIPE, SIG_DFL );

    /* Run the program. */
    (void) execve( binary, argp, envp );

    /* Something went wrong. */
    send_error( 500, "Internal Error", (char*) 0, "Something unexpected went wrong running a CGI program." );
    }


/* This routine is used only for POST requests.  It reads the data
** from the request and sends it to the child process.  The only reason
** we need to do it this way instead of just letting the child read
** directly is that we have already read part of the data into our
** buffer.
**
** Oh, and it's also used for all SSL CGIs.
*/
static void
cgi_interpose_input( int wfd )
    {
    int c, r;
    char buf[1024];

    c = request_len - request_idx;
    if ( c > 0 )
	{
	if ( write( wfd, &(request[request_idx]), c ) != c )
	    return;
	}
    while ( c < content_length )
	{
	r = my_read( buf, MIN( sizeof(buf), content_length - c ) );
	if ( r == 0 )
	    sleep( 1 );
	else if ( r < 0 )
	    {
	    if ( errno == EAGAIN )
		sleep( 1 );
	    else
		return;
	    }
	else
	    {
	    if ( write( wfd, buf, r ) != r )
		return;
	    c += r;
	    }
	}
    }


/* This routine is used for parsed-header CGIs and for all SSL CGIs. */
static void
cgi_interpose_output( int rfd, int parse_headers )
    {
    int r;
    char buf[1024];

    if ( ! parse_headers )
	{
	/* If we're not parsing headers, write out the default status line
	** and proceed to the echo phase.
	*/
	char http_head[] = "HTTP/1.0 200 OK\r\n";
	(void) my_write( http_head, sizeof(http_head) );
	}
    else
	{
	/* Header parsing.  The idea here is that the CGI can return special
	** headers such as "Status:" and "Location:" which change the return
	** status of the response.  Since the return status has to be the very
	** first line written out, we have to accumulate all the headers
	** and check for the special ones before writing the status.  Then
	** we write out the saved headers and proceed to echo the rest of
	** the response.
	*/
	int headers_size, headers_len;
	char* headers;
	char* br;
	int status;
	char* title;
	char* cp;

	/* Slurp in all headers. */
	headers_size = 0;
	add_to_buf( &headers, &headers_size, &headers_len, (char*) 0, 0 );
	for (;;)
	    {
	    r = read( rfd, buf, sizeof(buf) );
	    if ( r <= 0 )
		{
		br = &(headers[headers_len]);
		break;
		}
	    add_to_buf( &headers, &headers_size, &headers_len, buf, r );
	    if ( ( br = strstr( headers, "\r\n\r\n" ) ) != (char*) 0 ||
		 ( br = strstr( headers, "\n\n" ) ) != (char*) 0 )
		break;
	    }

	/* Figure out the status. */
	status = 200;
	if ( ( cp = strstr( headers, "Status:" ) ) != (char*) 0 &&
	     cp < br &&
	     ( cp == headers || *(cp-1) == '\n' ) )
	    {
	    cp += 7;
	    cp += strspn( cp, " \t" );
	    status = atoi( cp );
	    }
	if ( ( cp = strstr( headers, "Location:" ) ) != (char*) 0 &&
	     cp < br &&
	     ( cp == headers || *(cp-1) == '\n' ) )
	    status = 302;

	/* Write the status line. */
	switch ( status )
	    {
	    case 200: title = "OK"; break;
	    case 302: title = "Found"; break;
	    case 304: title = "Not Modified"; break;
	    case 400: title = "Bad Request"; break;
	    case 401: title = "Unauthorized"; break;
	    case 403: title = "Forbidden"; break;
	    case 404: title = "Not Found"; break;
	    case 408: title = "Request Timeout"; break;
	    case 500: title = "Internal Error"; break;
	    case 501: title = "Not Implemented"; break;
	    case 503: title = "Service Temporarily Overloaded"; break;
	    default: title = "Something"; break;
	    }
	(void) snprintf(
	    buf, sizeof(buf), "HTTP/1.0 %d %s\r\n", status, title );
	(void) my_write( buf, strlen( buf ) );

	/* Write the saved headers. */
	(void) my_write( headers, headers_len );
	}

    /* Echo the rest of the output. */
    for (;;)
	{
	r = read( rfd, buf, sizeof(buf) );
	if ( r <= 0 )
	    return;
	if ( my_write( buf, r ) != r )
	    return;
	}
    }


/* Set up CGI argument vector.  We don't have to worry about freeing
** stuff since we're a sub-process.  This gets done after make_envp() because
** we scribble on query.
*/
static char**
make_argp( void )
    {
    char** argp;
    int argn;
    char* cp1;
    char* cp2;

    /* By allocating an arg slot for every character in the query, plus
    ** one for the filename and one for the NULL, we are guaranteed to
    ** have enough.  We could actually use strlen/2.
    */
    argp = (char**) malloc( ( strlen( query ) + 2 ) * sizeof(char*) );
    if ( argp == (char**) 0 )
	return (char**) 0;

    argp[0] = strrchr( file, '/' );
    if ( argp[0] != (char*) 0 )
	++argp[0];
    else
	argp[0] = file;

    argn = 1;
    /* According to the CGI spec at http://hoohoo.ncsa.uiuc.edu/cgi/cl.html,
    ** "The server should search the query information for a non-encoded =
    ** character to determine if the command line is to be used, if it finds
    ** one, the command line is not to be used."
    */
    if ( strchr( query, '=' ) == (char*) 0 )
	{
	for ( cp1 = cp2 = query; *cp2 != '\0'; ++cp2 )
	    {
	    if ( *cp2 == '+' )
		{
		*cp2 = '\0';
		strdecode( cp1, cp1 );
		argp[argn++] = cp1;
		cp1 = cp2 + 1;
		}
	    }
	if ( cp2 != cp1 )
	    {
	    strdecode( cp1, cp1 );
	    argp[argn++] = cp1;
	    }
	}

    argp[argn] = (char*) 0;
    return argp;
    }


/* Set up CGI environment variables. Be real careful here to avoid
** letting malicious clients overrun a buffer.  We don't have
** to worry about freeing stuff since we're a sub-process.
*/
static char**
make_envp( void )
    {
    static char* envp[50];
    int envn;
    char* cp;
    char buf[256];

    envn = 0;
    envp[envn++] = build_env( "PATH=%s", CGI_PATH );
    envp[envn++] = build_env( "LD_LIBRARY_PATH=%s", CGI_LD_LIBRARY_PATH );
    envp[envn++] = build_env( "SERVER_SOFTWARE=%s", SERVER_SOFTWARE );
    if ( ! vhost )
	cp = hostname;
    else
	cp = req_hostname;	/* already computed by virtual_file() */
    if ( cp != (char*) 0 )
	envp[envn++] = build_env( "SERVER_NAME=%s", cp );
    envp[envn++] = "GATEWAY_INTERFACE=CGI/1.1";
    envp[envn++] = "SERVER_PROTOCOL=HTTP/1.0";
    (void) snprintf( buf, sizeof(buf), "%d", port );
    envp[envn++] = build_env( "SERVER_PORT=%s", buf );
    envp[envn++] = build_env(
	"REQUEST_METHOD=%s", get_method_str( method ) );
    envp[envn++] = build_env( "SCRIPT_NAME=%s", path );
    if ( query[0] != '\0' )
	envp[envn++] = build_env( "QUERY_STRING=%s", query );
    envp[envn++] = build_env( "REMOTE_ADDR=%s", ntoa( &client_addr ) );
    if ( referer[0] != '\0' )
	envp[envn++] = build_env( "HTTP_REFERER=%s", referer );
    if ( useragent[0] != '\0' )
	envp[envn++] = build_env( "HTTP_USER_AGENT=%s", useragent );
    if ( cookie != (char*) 0 )
	envp[envn++] = build_env( "HTTP_COOKIE=%s", cookie );
    if ( content_type != (char*) 0 )
	envp[envn++] = build_env( "CONTENT_TYPE=%s", content_type );
    if ( content_length != -1 )
	{
	(void) snprintf( buf, sizeof(buf), "%ld", content_length );
	envp[envn++] = build_env( "CONTENT_LENGTH=%s", buf );
	}
    if ( remoteuser != (char*) 0 )
	envp[envn++] = build_env( "REMOTE_USER=%s", remoteuser );
    if ( authorization != (char*) 0 )
	envp[envn++] = build_env( "AUTH_TYPE=%s", "Basic" );
    if ( getenv( "TZ" ) != (char*) 0 )
	envp[envn++] = build_env( "TZ=%s", getenv( "TZ" ) );

    envp[envn] = (char*) 0;
    return envp;
    }


static char*
build_env( char* fmt, char* arg )
    {
    char* cp;
    int size;
    static char* buf;
    static int maxbuf = 0;

    size = strlen( fmt ) + strlen( arg );
    if ( size > maxbuf )
	{
	if ( maxbuf == 0 )
	    {
	    maxbuf = 256;
	    buf = (char*) malloc( maxbuf );
	    }
	else
	    {
	    maxbuf *= 2;
	    buf = (char*) realloc( (void*) buf, maxbuf );
	    }
	if ( buf == (char*) 0 )
	    {
	    (void) fprintf( stderr, "%s: out of memory\n", argv0 );
	    exit( 1 );
	    }
	}
    (void) snprintf( buf, maxbuf, fmt, arg );
    cp = strdup( buf );
    if ( cp == (char*) 0 )
	{
	(void) fprintf( stderr, "%s: out of memory\n", argv0 );
	exit( 1 );
	}
    return cp;
    }


static void
auth_check( char* dirname )
    {
    char authpath[10000];
    struct stat sb;
    char authinfo[500];
    char* authpass;
    static char line[10000];
    int l;
    FILE* fp;
    char* cryp;

    /* Construct auth filename. */
    if ( dirname[strlen(dirname) - 1] == '/' )
	(void) snprintf( authpath, sizeof(authpath), "%s%s", dirname, AUTH_FILE );
    else
	(void) snprintf( authpath, sizeof(authpath), "%s/%s", dirname, AUTH_FILE );

    /* Does this directory have an auth file? */
    if ( stat( authpath, &sb ) < 0 )
	/* Nope, let the request go through. */
	return;

    /* Does this request contain authorization info? */
    if ( authorization == (char*) 0 )
	/* Nope, return a 401 Unauthorized. */
	send_authenticate( dirname );

    /* Basic authorization info? */
    if ( strncmp( authorization, "Basic ", 6 ) != 0 )
	send_authenticate( dirname );

    /* Decode it. */
    l = b64_decode( &(authorization[6]), authinfo, sizeof(authinfo) );
    authinfo[l] = '\0';
    /* Split into user and password. */
    authpass = strchr( authinfo, ':' );
    if ( authpass == (char*) 0 )
	/* No colon?  Bogus auth info. */
	send_authenticate( dirname );
    *authpass++ = '\0';

    /* Open the password file. */
    fp = fopen( authpath, "r" );
    if ( fp == (FILE*) 0 )
	/* The file exists but we can't open it?  Disallow access. */
	send_error( 403, "Forbidden", (char*) 0, "File is protected." );

    /* Read it. */
    while ( fgets( line, sizeof(line), fp ) != (char*) 0 )
	{
	/* Nuke newline. */
	l = strlen( line );
	if ( line[l - 1] == '\n' )
	    line[l - 1] = '\0';
	/* Split into user and encrypted password. */
	cryp = strchr( line, ':' );
	if ( cryp == (char*) 0 )
	    continue;
	*cryp++ = '\0';
	/* Is this the right user? */
	if ( strcmp( line, authinfo ) == 0 )
	    {
	    /* Yes. */
	    (void) fclose( fp );
	    /* So is the password right? */
	    if ( strcmp( crypt( authpass, cryp ), cryp ) == 0 )
		{
		/* Ok! */
		remoteuser = line;
		return;
		}
	    else
		/* No. */
		send_authenticate( dirname );
	    }
	}

    /* Didn't find that user.  Access denied. */
    (void) fclose( fp );
    send_authenticate( dirname );
    }


static void
send_authenticate( char* realm )
    {
    char header[10000];

    (void) snprintf(
	header, sizeof(header), "WWW-Authenticate: Basic realm=\"%s\"", realm );
    send_error( 401, "Unauthorized", header, "Authorization required." );
    }


static char*
virtual_file( char* file )
    {
    char* cp;
    static char vfile[10000];

    /* Use the request's hostname, or fall back on the IP address. */
    if ( host != (char*) 0 )
	req_hostname = host;
    else
	{
	usockaddr usa;
	int sz = sizeof(usa);
	if ( getsockname( conn_fd, &usa.sa, &sz ) < 0 )
	    req_hostname = "UNKNOWN_HOST";
	else
	    req_hostname = ntoa( &usa );
	}
    /* Pound it to lower case. */
    for ( cp = req_hostname; *cp != '\0'; ++cp )
	if ( isupper( *cp ) )
	    *cp = tolower( *cp );
    (void) snprintf( vfile, sizeof(vfile), "%s/%s", req_hostname, file );
    return vfile;
    }


static void
send_error( int s, char* title, char* extra_header, char* text )
    {
    add_headers( s, title, extra_header, "text/html", -1, -1 );

    send_error_body( s, title, text );

    send_error_tail();

    send_response();

#ifdef USE_SSL
    SSL_free( ssl );
#endif /* USE_SSL */
    exit( 1 );
    }


static void
send_error_body( int s, char* title, char* text )
    {
    char filename[1000];
    char buf[10000];
    int buflen;

    if ( vhost && req_hostname != (char*) 0 )
	{
	/* Try virtual-host custom error page. */
	(void) snprintf(
	    filename, sizeof(filename), "%s/%s/err%d.html",
	    req_hostname, ERR_DIR, s );
	if ( send_error_file( filename ) )
	    return;
	}

    /* Try server-wide custom error page. */
    (void) snprintf(
	filename, sizeof(filename), "%s/err%d.html", ERR_DIR, s );
    if ( send_error_file( filename ) )
	return;

    /* Send built-in error page. */
    buflen = snprintf(
	buf, sizeof(buf),
	"<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#cc9999\"><H4>%d %s</H4>\n",
	s, title, s, title );
    add_to_response( buf, buflen );
    buflen = snprintf( buf, sizeof(buf), "%s\n", text );
    add_to_response( buf, buflen );
    }


static int
send_error_file( char* filename )
    {
    FILE* fp;
    char buf[1000];
    int r;

    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	return 0;
    for (;;)
	{
	r = fread( buf, 1, sizeof(buf), fp );
	if ( r <= 0 )
	    break;
	add_to_response( buf, r );
	}
    (void) fclose( fp );
    return 1;
    }


static void
send_error_tail( void )
    {
    char buf[500];
    int buflen;

    if ( match( "**MSIE**", useragent ) )
	{
	int n;
	buflen = snprintf( buf, sizeof(buf), "<!--\n" );
	add_to_response( buf, buflen );
	for ( n = 0; n < 6; ++n )
	    {
	    buflen = snprintf( buf, sizeof(buf), "Padding so that MSIE deigns to show this error instead of its own canned one.\n" );
	    add_to_response( buf, buflen );
	    }
	buflen = snprintf( buf, sizeof(buf), "-->\n" );
	add_to_response( buf, buflen );
	}

    buflen = snprintf( buf, sizeof(buf), "<HR>\n<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n</BODY></HTML>\n", SERVER_URL, SERVER_SOFTWARE );
    add_to_response( buf, buflen );
    }


static void
add_headers( int s, char* title, char* extra_header, char* mime_type, long b, time_t mod )
    {
    time_t now;
    char timebuf[100];
    char buf[10000];
    int buflen;
    const char* rfc1123_fmt = "%a, %d %b %Y %H:%M:%S GMT";

    status = s;
    bytes = b;
    make_log_entry();
    start_response();
    buflen = snprintf( buf, sizeof(buf), "%s %d %s\r\n", protocol, status, title );
    add_to_response( buf, buflen );
    buflen = snprintf( buf, sizeof(buf), "Server: %s\r\n", SERVER_SOFTWARE );
    add_to_response( buf, buflen );
    now = time( (time_t*) 0 );
    (void) strftime( timebuf, sizeof(timebuf), rfc1123_fmt, gmtime( &now ) );
    buflen = snprintf( buf, sizeof(buf), "Date: %s\r\n", timebuf );
    add_to_response( buf, buflen );
    if ( extra_header != (char*) 0 )
	{
	buflen = snprintf( buf, sizeof(buf), "%s\r\n", extra_header );
	add_to_response( buf, buflen );
	}
    if ( mime_type != (char*) 0 )
	{
	buflen = snprintf( buf, sizeof(buf), "Content-type: %s\r\n", mime_type );
	add_to_response( buf, buflen );
	}
    if ( bytes >= 0 )
	{
	buflen = snprintf( buf, sizeof(buf), "Content-length: %ld\r\n", bytes );
	add_to_response( buf, buflen );
	}
    if ( mod != (time_t) -1 )
	{
	(void) strftime( timebuf, sizeof(timebuf), rfc1123_fmt, gmtime( &mod ) );
	buflen = snprintf( buf, sizeof(buf), "Last-modified: %s\r\n", timebuf );
	add_to_response( buf, buflen );
	}
    buflen = snprintf( buf, sizeof(buf), "Connection: close\r\n\r\n" );
    add_to_response( buf, buflen );
    }


static void
start_request( void )
    {
    request_size = 0;
    request_idx = 0;
    }

static void
add_to_request( char* str, int len )
    {
    add_to_buf( &request, &request_size, &request_len, str, len );
    }

static char*
get_request_line( void )
    {
    int i;
    char c;

    for ( i = request_idx; request_idx < request_len; ++request_idx )
	{
	c = request[request_idx];
	if ( c == '\n' || c == '\r' )
	    {
	    request[request_idx] = '\0';
	    ++request_idx;
	    if ( c == '\r' && request_idx < request_len &&
		 request[request_idx] == '\n' )
		{
		request[request_idx] = '\0';
		++request_idx;
		}
	    return &(request[i]);
	    }
	}
    return (char*) 0;
    }


static char* response;
static int response_size, response_len;

static void
start_response( void )
    {
    response_size = 0;
    }

static void
add_to_response( char* str, int len )
    {
    add_to_buf( &response, &response_size, &response_len, str, len );
    }

static void
send_response( void )
    {
    (void) my_write( response, response_len );
    }


static int
my_read( char* buf, int size )
    {
#ifdef USE_SSL
    if ( do_ssl )
	return SSL_read( ssl, buf, size );
    else
	return read( conn_fd, buf, size );
#else /* USE_SSL */
    return read( conn_fd, buf, size );
#endif /* USE_SSL */
    }


static int
my_write( char* buf, int size )
    {
#ifdef USE_SSL
    if ( do_ssl )
	return SSL_write( ssl, buf, size );
    else
	return write( conn_fd, buf, size );
#else /* USE_SSL */
    return write( conn_fd, buf, size );
#endif /* USE_SSL */
    }


static void
add_to_buf( char** bufP, int* bufsizeP, int* buflenP, char* str, int len )
    {
    if ( *bufsizeP == 0 )
	{
	*bufsizeP = len + 500;
	*buflenP = 0;
	*bufP = (char*) malloc( *bufsizeP );
	}
    else if ( *buflenP + len >= *bufsizeP )
	{
	*bufsizeP = *buflenP + len + 500;
	*bufP = (char*) realloc( (void*) *bufP, *bufsizeP );
	}
    if ( *bufP == (char*) 0 )
	{
	(void) fprintf( stderr, "%s: out of memory\n", argv0 );
	exit( 1 );
	}
    (void) memcpy( &((*bufP)[*buflenP]), str, len );
    *buflenP += len;
    (*bufP)[*buflenP] = '\0';
    }


static void
make_log_entry( void )
    {
    char* ru;
    char url[500];
    char bytes_str[40];
    time_t now;
    struct tm* t;
    const char* cernfmt_nozone = "%d/%b/%Y:%H:%M:%S";
    char date_nozone[100];
    int zone;
    char sign;
    char date[100];

    if ( logfp == (FILE*) 0 )
	return;

    /* Format the user. */
    if ( remoteuser != (char*) 0 )
	ru = remoteuser;
    else
	ru = "-";
    now = time( (time_t*) 0 );
    /* If we're vhosting, prepend the hostname to the url.  This is
    ** a little weird, perhaps writing separate log files for
    ** each vhost would make more sense.
    */
    if ( vhost )
	(void) snprintf( url, sizeof(url), "/%s%s", req_hostname, path );
    else
	(void) snprintf( url, sizeof(url), "%s", path );
    /* Format the bytes. */
    if ( bytes >= 0 )
	(void) snprintf( bytes_str, sizeof(bytes_str), "%ld", bytes );
    else
	(void) strcpy( bytes_str, "-" );
    /* Format the time, forcing a numeric timezone (some log analyzers
    ** are stoooopid about this).
    */
    t = localtime( &now );
    (void) strftime( date_nozone, sizeof(date_nozone), cernfmt_nozone, t );
#ifdef HAVE_TM_GMTOFF
    zone = t->tm_gmtoff / 60L;
#else
    zone = - ( timezone / 60L );
    /* Probably have to add something about daylight time here. */
#endif
    if ( zone >= 0 )
	sign = '+';
    else
	{
	sign = '-';
	zone = -zone;
	}
    zone = ( zone / 60 ) * 100 + zone % 60;
    (void) snprintf( date, sizeof(date), "%s %c%04d", date_nozone, sign, zone );
    /* And write the log entry. */
    (void) fprintf( logfp,
	"%.80s - %.80s [%s] \"%.80s %.200s %.80s\" %d %s \"%.200s\" \"%.80s\"\n",
	ntoa( &client_addr ), ru, date, get_method_str( method ), url,
	protocol, status, bytes_str, referer, useragent );
    (void) fflush( logfp );
    }


static char*
get_method_str( int m )
    {
    switch ( m )
	{
	case METHOD_GET: return "GET";
	case METHOD_HEAD: return "HEAD";
	case METHOD_POST: return "POST";
	default: return (char*) 0;
	}
    }


static char*
get_mime_type( char* name )
    {
    struct {
	char* ext;
	char* type;
	} table[] = {
#include "mime_types.h"
	};
    int fl = strlen( name );
    int i;

    for ( i = 0; i < sizeof(table) / sizeof(*table); ++i )
	{
	int el = strlen( table[i].ext );
	if ( strcasecmp( &(name[fl - el]), table[i].ext ) == 0 )
	    return table[i].type;
	}
    return "text/plain; charset=%s";
    }


static void
handle_sigterm( int sig )
    {
    (void) fprintf( stderr, "%s: exiting due to signal %d\n", argv0, sig );
    exit( 1 );
    }


static void
handle_sigchld( int sig )
    {
    pid_t pid;
    int status;

    /* Reap defunct children until there aren't any more. */
    for (;;)
	{
#ifdef HAVE_WAITPID
	pid = waitpid( (pid_t) -1, &status, WNOHANG );
#else /* HAVE_WAITPID */
	pid = wait3( &status, WNOHANG, (struct rusage*) 0 );
#endif /* HAVE_WAITPID */
	if ( (int) pid == 0 )		/* none left */
	    break;
	if ( (int) pid < 0 )
	    {
	    if ( errno == EINTR )	/* because of ptrace */
		continue;
	    /* ECHILD shouldn't happen with the WNOHANG option,
	    ** but with some kernels it does anyway.  Ignore it.
	    */
	    if ( errno != ECHILD )
		perror( "child wait" );
	    break;
	    }
	}
    }


static void
lookup_hostname( usockaddr* usa4P, size_t sa4_len, int* gotv4P, usockaddr* usa6P, size_t sa6_len, int* gotv6P )
    {
#if defined(HAVE_GETADDRINFO) && defined(HAVE_GAI_STRERROR)

    struct addrinfo hints;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv4;
    struct addrinfo* aiv6;
    int gaierr;
    char strport[10];

    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf( strport, sizeof(strport), "%d", port );
    if ( (gaierr = getaddrinfo( hostname, strport, &hints, &ai )) != 0 )
	{
	(void) fprintf( stderr, "getaddrinfo %.80s - %s\n", hostname, gai_strerror( gaierr ) );
	exit( 1 );
	}

    /* Find the first IPv4 and IPv6 entries. */
    aiv4 = (struct addrinfo*) 0;
    aiv6 = (struct addrinfo*) 0;
    for ( ai2 = ai; ai2 != (struct addrinfo*) 0; ai2 = ai2->ai_next )
	{
	switch ( ai2->ai_family )
	    {
	    case AF_INET:
	    if ( aiv4 == (struct addrinfo*) 0 )
		aiv4 = ai2;
	    break;
#if defined(AF_INET6) && defined(HAVE_SOCKADDR_IN6)
	    case AF_INET6:
	    if ( aiv6 == (struct addrinfo*) 0 )
		aiv6 = ai2;
	    break;
#endif /* AF_INET6 && HAVE_SOCKADDR_IN6 */
	    }
	}

    if ( aiv4 == (struct addrinfo*) 0 )
	*gotv4P = 0;
    else
	{
	if ( sa4_len < aiv4->ai_addrlen )
	    {
	    (void) fprintf(
		stderr, "%.80s - sockaddr too small (%d < %d)\n",
		hostname, sa4_len, aiv4->ai_addrlen );
	    exit( 1 );
	    }
	memset( usa4P, 0, sa4_len );
	memcpy( usa4P, aiv4->ai_addr, aiv4->ai_addrlen );
	*gotv4P = 1;
	}
    if ( aiv6 == (struct addrinfo*) 0 )
	*gotv6P = 0;
    else
	{
	if ( sa6_len < aiv6->ai_addrlen )
	    {
	    (void) fprintf(
		stderr, "%.80s - sockaddr too small (%d < %d)\n",
		hostname, sa6_len, aiv6->ai_addrlen );
	    exit( 1 );
	    }
	memset( usa6P, 0, sa6_len );
	memcpy( usa6P, aiv6->ai_addr, aiv6->ai_addrlen );
	*gotv6P = 1;
	}

    freeaddrinfo( ai );

#else /* HAVE_GETADDRINFO && HAVE_GAI_STRERROR */

    struct hostent* he;

    *gotv6P = 0;

    memset( usa4P, 0, sa4_len );
    usa4P->sa.sa_family = AF_INET;
    if ( hostname == (char*) 0 )
	usa4P->sa_in.sin_addr.s_addr = htonl( INADDR_ANY );
    else
	{
	usa4P->sa_in.sin_addr.s_addr = inet_addr( hostname );
	if ( (int) usa4P->sa_in.sin_addr.s_addr == -1 )
	    {
	    he = gethostbyname( hostname );
	    if ( he == (struct hostent*) 0 )
		{
#ifdef HAVE_HSTRERROR
		(void) fprintf( stderr, "gethostbyname %.80s - %s\n", hostname, hstrerror( h_errno ) );
#else /* HAVE_HSTRERROR */
		(void) fprintf( stderr, "gethostbyname %.80s failed\n", hostname );
#endif /* HAVE_HSTRERROR */
		exit( 1 );
		}
	    if ( he->h_addrtype != AF_INET )
		{
		(void) fprintf( stderr, "%.80s - non-IP network address\n", hostname );
		exit( 1 );
		}
	    (void) memcpy(
		&usa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length );
	    }
	}
    usa4P->sa_in.sin_port = htons( port );
    *gotv4P = 1;

#endif /* HAVE_GETADDRINFO && HAVE_GAI_STRERROR */
    }


static char*
ntoa( usockaddr* usaP )
    {
#ifdef HAVE_GETNAMEINFO
    static char str[200];

    if ( getnameinfo( &usaP->sa, sockaddr_len( usaP ), str, sizeof(str), 0, 0, NI_NUMERICHOST ) != 0 )
	{
	str[0] = '?';
	str[1] = '\0';
	}
    return str;

#else /* HAVE_GETNAMEINFO */

    return inet_ntoa( usaP->sa_in.sin_addr );

#endif /* HAVE_GETNAMEINFO */
    }


static size_t
sockaddr_len( usockaddr* usaP )
    {
    switch ( usaP->sa.sa_family )
	{
	case AF_INET: return sizeof(struct sockaddr_in);
#if defined(AF_INET6) && defined(HAVE_SOCKADDR_IN6)
	case AF_INET6: return sizeof(struct sockaddr_in6);
#endif /* AF_INET6 && HAVE_SOCKADDR_IN6 */
	default:
	(void) fprintf(
	    stderr, "unknown sockaddr family - %d\n", usaP->sa.sa_family );
	exit( 1 );
	}
    }


/* Copies and decodes a string.  It's ok for from and to to be the
** same string.
*/
static void
strdecode( char* to, char* from )
    {
    for ( ; *from != '\0'; ++to, ++from )
	{
	if ( from[0] == '%' && isxdigit( from[1] ) && isxdigit( from[2] ) )
	    {
	    *to = hexit( from[1] ) * 16 + hexit( from[2] );
	    from += 2;
	    }
	else
	    *to = *from;
	}
    *to = '\0';
    }


static int
hexit( char c )
    {
    if ( c >= '0' && c <= '9' )
	return c - '0';
    if ( c >= 'a' && c <= 'f' )
	return c - 'a' + 10;
    if ( c >= 'A' && c <= 'F' )
	return c - 'A' + 10;
    return 0;           /* shouldn't happen, we're guarded by isxdigit() */
    }


/* Base-64 decoding.  This represents binary data as printable ASCII
** characters.  Three 8-bit binary bytes are turned into four 6-bit
** values, like so:
**
**   [11111111]  [22222222]  [33333333]
**
**   [111111] [112222] [222233] [333333]
**
** Then the 6-bit values are represented using the characters "A-Za-z0-9+/".
*/

static int b64_decode_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
    };

/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
static int
b64_decode( const char* str, unsigned char* space, int size )
    {
    const char* cp;
    int space_idx, phase;
    int d, prev_d;
    unsigned char c;

    space_idx = 0;
    phase = 0;
    for ( cp = str; *cp != '\0'; ++cp )
	{
	d = b64_decode_table[*cp];
	if ( d != -1 )
	    {
	    switch ( phase )
		{
		case 0:
		++phase;
		break;
		case 1:
		c = ( ( prev_d << 2 ) | ( ( d & 0x30 ) >> 4 ) );
		if ( space_idx < size )
		    space[space_idx++] = c;
		++phase;
		break;
		case 2:
		c = ( ( ( prev_d & 0xf ) << 4 ) | ( ( d & 0x3c ) >> 2 ) );
		if ( space_idx < size )
		    space[space_idx++] = c;
		++phase;
		break;
		case 3:
		c = ( ( ( prev_d & 0x03 ) << 6 ) | d );
		if ( space_idx < size )
		    space[space_idx++] = c;
		phase = 0;
		break;
		}
	    prev_d = d;
	    }
	}
    return space_idx;
    }


/* Simple shell-style filename matcher.  Only does ? * and **, and multiple
** patterns separated by |.  Returns 1 or 0.
*/
int
match( const char* pattern, const char* string )
    {
    const char* or;

    for (;;)
	{
	or = strchr( pattern, '|' );
	if ( or == (char*) 0 )
	    return match_one( pattern, strlen( pattern ), string );
	if ( match_one( pattern, or - pattern, string ) )
	    return 1;
	pattern = or + 1;
	}
    }


static int
match_one( const char* pattern, int patternlen, const char* string )
    {
    const char* p;

    for ( p = pattern; p - pattern < patternlen; ++p, ++string )
	{
	if ( *p == '?' && *string != '\0' )
	    continue;
	if ( *p == '*' )
	    {
	    int i, pl;
	    ++p;
	    if ( *p == '*' )
		{
		/* Double-wildcard matches anything. */
		++p;
		i = strlen( string );
		}
	    else
		/* Single-wildcard matches anything but slash. */
		i = strcspn( string, "/" );
	    pl = patternlen - ( p - pattern );
	    for ( ; i >= 0; --i )
		if ( match_one( p, pl, &(string[i]) ) )
		    return 1;
	    return 0;
	    }
	if ( *p != *string )
	    return 0;
	}
    if ( *string == '\0' )
	return 1;
    return 0;
    }
