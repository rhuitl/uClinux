/* unistd.h <ndf@linux.mit.edu> */
#include <features.h>
#include <sys/types.h>

#ifndef __UNISTD_H
#define __UNISTD_H

#include <errno.h>
#include <asm/unistd.h>

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

__BEGIN_DECLS

extern int vhangup __P ((void));
extern int close __P ((int));
extern int read __P ((int __fd, void * __buf, size_t __nbytes));
extern int write __P ((int __fd, __const void * __buf, size_t __n));
extern off_t lseek __P ((int __fd, off_t __n, int __whence));
extern int pipe __P ((int __pipedes[2]));
extern unsigned int alarm __P ((unsigned int __seconds));
extern int sleep __P ((unsigned int __seconds));
extern void usleep __P ((unsigned long __microseconds));
extern int pause __P ((void));
extern char*    crypt __P((__const char *__key, __const char *__salt));
extern int isatty __P ((int __fd));
extern char *ttyname __P ((int __fd));
extern int readlink __P ((__const char *__path, char *__buf, size_t __len));
extern int link __P ((__const char *__from, __const char *__to));
extern int symlink __P ((__const char *__from, __const char *__to));
extern int readlink __P ((__const char *__path, char *__buf, size_t __len));
extern int unlink __P ((__const char *__name));
extern char *getcwd __P ((char *__buf, size_t __size));
extern int fchdir __P ((int __fd));
extern int chdir __P ((__const char *__path));
extern int chown __P ((__const char *__file,
                       uid_t __owner, gid_t __group));

extern int fchown __P ((int __fd,
                       uid_t __owner, gid_t __group));

extern int chroot __P ((__const char *__path));

extern int truncate __P ((__const char *path, __off_t __length));
extern int ftruncate __P ((int __fd, __off_t __length));

extern int fsync __P ((int __fd));

extern int sync __P ((void));

extern int rmdir __P ((__const char *__path));

extern int access __P ((__const char *__name, int __type));

extern int _clone __P ((int (*fn)(void *arg), void *child_stack, int flags, void *arg));
extern long sysconf __P ((int name));
extern pid_t getpid __P ((void));
extern pid_t getppid __P ((void));
extern pid_t getpgrp __P ((void));
extern pid_t tcgetpgrp __P ((int));

extern int setpgrp __P ((void));
extern int tcsetpgrp __P ((int, pid_t));
extern pid_t setsid __P ((void));

extern int sethostname __P ((__const char *name, size_t len));
extern int gethostname __P ((char *__name, size_t __len));
extern int getdomainname __P ((char *__name, size_t __len));
extern int setdomainname __P ((__const char *__name, size_t __len));

extern char *getpass __P ((__const char *__prompt));

extern int getdtablesize __P ((void));
extern pid_t vfork __P ((void));
extern void _exit __P ((int __status)) __attribute__ ((__noreturn__));
extern int dup __P ((int __fd));
extern int dup2 __P ((int __fd, int __fd2));
extern int execl __P ((__const char *__path, __const char *__arg, ...));
extern int execlp __P ((__const char *__file, __const char *__arg, ...));
extern int execle __P ((__const char *__path, __const char *__arg, ...));
extern int execv __P ((__const char *__path, char *__const __argv[]));
extern int execvp __P ((__const char *__file, char *__const __argv[]));
extern int execve __P ((__const char *__filename, char *__const __argv[], char *__const envp[]));
extern int execvep __P (( __const char *file, char * __const argv[], char * __const envp[]));

extern void *sbrk __P ((ptrdiff_t __delta));

extern int setuid __P ((uid_t uid));
extern int seteuid __P ((uid_t euid));
extern int setreuid __P ((uid_t ruid, uid_t euid));
extern uid_t getuid __P ((void));
extern uid_t geteuid __P ((void));
extern gid_t getgid __P ((void));
extern gid_t getegid __P ((void));
extern int setgid __P ((gid_t gid));
extern int setegid __P ((gid_t egid));
extern int setregid __P ((gid_t rgid, gid_t egid));
extern int getgroups __P ((int size, gid_t list[]));

extern int getopt __P((int argc, char *__const argv[], __const char *optstring));
extern char *optarg;
extern int optind, opterr, optopt;
__END_DECLS


#define fork fork_not_available_use_vfork
#define clone clone_not_available_use__clone
		

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#ifndef R_OK
#define	R_OK	4		/* Test for read permission.  */
#define	W_OK	2		/* Test for write permission.  */
#define	X_OK	1		/* Test for execute permission.  */
#define	F_OK	0		/* Test for existence.  */
#endif


/* And now we'll include the sysconf definitions */
#include <bits/confname.h>

extern char **environ;

#endif /* __UNISTD_H */

