/* This is a standalone application that allows the IPC code to
 * vfork and exec in relative safety.
 */
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#define COMM_OK		  (0)
#define COMM_ERROR	 (-1)
#define COMM_NOMESSAGE	 (-3)
#define COMM_TIMEOUT	 (-4)
#define COMM_SHUTDOWN	 (-5)
#define COMM_INPROGRESS  (-6)
#define COMM_ERR_CONNECT (-7)
#define COMM_ERR_DNS     (-8)
#define COMM_ERR_CLOSING (-9)

#define IPC_NONE 0
#define IPC_TCP_SOCKET 1
#define IPC_UDP_SOCKET 2
#define IPC_FIFO 3


static inline void
no_suid(void)
{
    uid_t uid;
/*    leave_suid();*/
    uid = geteuid();

    setuid(0);
    setuid(uid);
}

static inline int
ignoreErrno(int ierrno)
{
    switch (ierrno) {
    case EINPROGRESS:
    case EWOULDBLOCK:
#if EAGAIN != EWOULDBLOCK
    case EAGAIN:
#endif
    case EALREADY:
    case EINTR:
#ifdef ERESTART
    case ERESTART:
#endif
	return 1;
    default:
	return 0;
    }
    /* NOTREACHED */
}

static inline int
comm_connect_addr(int sock, const struct sockaddr_in *address)
{
    int status = COMM_OK;
    int x;
#if 0
    int err = 0;
    socklen_t errlen;
#endif
    assert(ntohs(address->sin_port) != 0);
    /* Establish connection. */
    errno = 0;
#if 1
	x = connect(sock, (struct sockaddr *) address, sizeof(*address));
#else
	errlen = sizeof(err);
	x = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
	if (x == 0)
	    errno = err;
#endif
    if (errno == 0 || errno == EISCONN)
	status = COMM_OK;
    else if (ignoreErrno(errno))
	status = COMM_INPROGRESS;
    else
	return COMM_ERROR;
    return status;
}

static inline int
ipcCloseAllFD(int prfd, int pwfd, int crfd, int cwfd)
{
    if (prfd >= 0)
	close(prfd);
    if (prfd != pwfd)
	if (pwfd >= 0)
	    close(pwfd);
    if (crfd >= 0)
	close(crfd);
    if (crfd != cwfd)
	if (cwfd >= 0)
	    close(cwfd);
    return -1;
}


int main(int argc, char *argv[]) {
    struct sockaddr_in PS;
    int prfd, pwfd, crfd, cwfd, cefd;
    int type;
    char *prog, *debugOptions;

    const char *hello_string = "hi there\n";
    int fd, t1, t2, t3, x;
    int tmp_s;
    char *env_str;

    /* Decode passed args */
    if (argc < 12)
	return(1);
    prog = *++argv;
    debugOptions = *++argv;
    type = atoi(*++argv);
    prfd = atoi(*++argv);
    pwfd = atoi(*++argv);
    crfd = atoi(*++argv);
    cwfd = atoi(*++argv);
    cefd = atoi(*++argv);
    PS.sin_family = atoi(*++argv);
    PS.sin_port = atoi(*++argv);
    PS.sin_addr.s_addr = atol(*++argv);

	
    /* child */
    no_suid();			/* give up extra priviliges */
    /* close shared socket with parent */
    close(prfd);
    if (pwfd != prfd)
	close(pwfd);
    pwfd = prfd = -1;

    if (type == IPC_TCP_SOCKET) {
	if ((fd = accept(crfd, NULL, NULL)) < 0) {
	    return(1);
	}
	close(crfd);
	cwfd = crfd = fd;
    } else if (type == IPC_UDP_SOCKET) {
	if (comm_connect_addr(crfd, &PS) == COMM_ERROR)
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
    }
    if (type == IPC_UDP_SOCKET) {
	x = send(cwfd, hello_string, strlen(hello_string), 0);
	if (x < 0) {
	    return(1);
	}
    } else {
	if (write(cwfd, hello_string, strlen(hello_string)) < 0) {
	    return(1);
	}
    }
    env_str = calloc((tmp_s = strlen(debugOptions) + 32), 1);
    snprintf(env_str, tmp_s, "SQUID_DEBUG=%s", debugOptions);
    putenv(env_str);
    /*
     * This double-dup stuff avoids problems when one of 
     *  crfd, cwfd, or debug_log are in the rage 0-2.
     */
    do {
	x = open("/dev/null", 0, 0444);
    } while (x < 3);
    t1 = dup(crfd);
    t2 = dup(cwfd);
    t3 = dup(cefd);
    assert(t1 > 2 && t2 > 2 && t3 > 2);
    close(crfd);
    close(cwfd);
    close(cefd);
    dup2(t1, 0);
    dup2(t2, 1);
    dup2(t3, 2);
    close(t1);
    close(t2);
    close(t3);
    setsid();
    execvp(prog, argv);
    return(1);
}
