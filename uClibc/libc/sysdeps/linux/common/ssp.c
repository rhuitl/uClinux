/*
 * Distributed under the terms of the GNU Lesser General Public License
 * $Header: $
 *
 * This is a modified version of Hiroaki Etoh's stack smashing routines
 * implemented for glibc.
 *
 * The following people have contributed input to this code.
 * Ned Ludd - <solar[@]gentoo.org>
 * Alexander Gabert - <pappy[@]gentoo.org>
 * The PaX Team - <pageexec[@]freemail.hu>
 * Peter S. Mazinger - <ps.m[@]gmx.net>
 * Yoann Vandoorselaere - <yoann[@]prelude-ids.org>
 * Robert Connolly - <robert[@]linuxfromscratch.org>
 * Cory Visi <cory[@]visi.name>
 * Mike Frysinger <vapier[@]gentoo.org>
 */

#if defined __SSP__ || defined __SSP_ALL__
#error "file must not be compiled with stack protection enabled on it. Use -fno-stack-protector"
#endif

#ifdef __PROPOLICE_BLOCK_SEGV__
# define SSP_SIGTYPE SIGSEGV
#else
# define SSP_SIGTYPE SIGABRT
#endif

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syslog.h>

libc_hidden_proto(memset)
libc_hidden_proto(strlen)
libc_hidden_proto(sigaction)
libc_hidden_proto(sigfillset)
libc_hidden_proto(sigdelset)
libc_hidden_proto(sigprocmask)
libc_hidden_proto(write)
libc_hidden_proto(openlog)
libc_hidden_proto(syslog)
libc_hidden_proto(closelog)
libc_hidden_proto(kill)
libc_hidden_proto(getpid)
libc_hidden_proto(_exit)

static void block_signals(void)
{
	struct sigaction sa;
	sigset_t mask;

	sigfillset(&mask);

	sigdelset(&mask, SSP_SIGTYPE);	/* Block all signal handlers */
	sigprocmask(SIG_BLOCK, &mask, NULL);	/* except SSP_SIGTYPE */

	/* Make the default handler associated with the signal handler */
	memset(&sa, 0, sizeof(struct sigaction));
	sigfillset(&sa.sa_mask);	/* Block all signals */
	sa.sa_flags = 0;
	sa.sa_handler = SIG_DFL;
	sigaction(SSP_SIGTYPE, &sa, NULL);
}

static void ssp_write(int fd, const char *msg1, const char *msg2, const char *msg3)
{
	write(fd, msg1, strlen(msg1));
	write(fd, msg2, strlen(msg2));
	write(fd, msg3, strlen(msg3));
	write(fd, "()\n", 3);
	openlog("ssp", LOG_CONS | LOG_PID, LOG_USER);
	syslog(LOG_INFO, "%s%s%s()", msg1, msg2, msg3);
	closelog();
}

static attribute_noreturn void terminate(void)
{
	(void) kill(getpid(), SSP_SIGTYPE);
	_exit(127);
}

void __stack_smash_handler(char func[], int damaged __attribute__ ((unused))) attribute_noreturn;
void __stack_smash_handler(char func[], int damaged)
{
	static const char message[] = ": stack smashing attack in function ";

	block_signals();

	ssp_write(STDERR_FILENO, __uclibc_progname, message, func);

	/* The loop is added only to keep gcc happy. */
	while(1)
		terminate();
}

void __stack_chk_fail(void) attribute_noreturn;
void __stack_chk_fail(void)
{
	static const char msg1[] = "stack smashing detected: ";
	static const char msg3[] = " terminated";

	block_signals();

	ssp_write(STDERR_FILENO, msg1, __uclibc_progname, msg3);

	/* The loop is added only to keep gcc happy. */
	while(1)
		terminate();
}

#if 0
void __chk_fail(void) attribute_noreturn;
void __chk_fail(void)
{
	static const char msg1[] = "buffer overflow detected: ";
	static const char msg3[] = " terminated";

	block_signals();

	ssp_write(STDERR_FILENO, msg1, __uclibc_progname, msg3);

	/* The loop is added only to keep gcc happy. */
	while(1)
		terminate();
}
#endif
