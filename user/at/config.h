/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define for DGUX with <sys/dg_sys_info.h>.  */
/* #undef DGUX */

/* Define if the `getloadavg' function needs to be run setuid or setgid.  */
#define GETLOADAVG_PRIVILEGED 1

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef gid_t */

/* Define if you don't have vprintf but do have _doprnt.  */
/* #undef HAVE_DOPRNT */

/* Define if your system has its own `getloadavg' function.  */
#define HAVE_GETLOADAVG 1

/* Define if you have <sys/wait.h> that is POSIX.1 compatible.  */
#define HAVE_SYS_WAIT_H 1

/* Define if you have the vprintf function.  */
#define HAVE_VPRINTF 1

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef mode_t */

/* Define if your struct nlist has an n_un member.  */
/* #undef NLIST_NAME_UNION */

/* Define if you have <nlist.h>.  */
/* #undef NLIST_STRUCT */

/* Define to `long' if <sys/types.h> doesn't define.  */
/* #undef off_t */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef pid_t */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define on System V Release 4.  */
/* #undef SVR4 */

/* Define if your <sys/time.h> declares struct tm.  */
/* #undef TM_IN_SYS_TIME */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef uid_t */

/* Define for Encore UMAX.  */
/* #undef UMAX */

/* Define for Encore UMAX 4.3 that has <inq_status/cpustats.h>
   instead of <sys/cpustats.h>.  */
/* #undef UMAX4_3 */

#define SPOOLDIR "/var/spool/cron"

#define PIDFILE "/var/run/atd.pid"

/* #undef MAILX */

/* #undef SENDMAIL */

#define MAILC "/bin/mail"

#define ATJOB_DIR "/var/spool/cron/atjobs"

#define ATSPOOL_DIR "/var/spool/cron/atspool"

#define PIDFILE "/var/run/atd.pid"

#define DEFAULT_AT_QUEUE 'a'

#define DEFAULT_BATCH_QUEUE 'b'

#define HAVE_ATTRIBUTE_NORETURN 1

/* Define if you have the getcwd function.  */
#define HAVE_GETCWD 1

/* Define if you have the mktime function.  */
#define HAVE_MKTIME 1

/* Define if you have the setresuid function.  */
#define HAVE_SETRESUID 1

/* Define if you have the setreuid function.  */
#define HAVE_SETREUID 1

/* Define if you have the sigaction function.  */
#define HAVE_SIGACTION 1

/* Define if you have the strftime function.  */
#define HAVE_STRFTIME 1

/* Define if you have the waitpid function.  */
#define HAVE_WAITPID 1

/* Define if you have the <dirent.h> header file.  */
#define HAVE_DIRENT_H 1

/* Define if you have the <errno.h> header file.  */
#define HAVE_ERRNO_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <getopt.h> header file.  */
#define HAVE_GETOPT_H 1

/* Define if you have the <mach/mach.h> header file.  */
/* #undef HAVE_MACH_MACH_H */

/* Define if you have the <ndir.h> header file.  */
/* #undef HAVE_NDIR_H */

/* Define if you have the <stdarg.h> header file.  */
#define HAVE_STDARG_H 1

/* Define if you have the <sys/dir.h> header file.  */
/* #undef HAVE_SYS_DIR_H */

/* Define if you have the <sys/fcntl.h> header file.  */
#define HAVE_SYS_FCNTL_H 1

/* Define if you have the <sys/ndir.h> header file.  */
/* #undef HAVE_SYS_NDIR_H */

/* Define if you have the <syslog.h> header file.  */
#define HAVE_SYSLOG_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the dgc library (-ldgc).  */
/* #undef HAVE_LIBDGC */

/* Define if you have the fl library (-lfl).  */
#define HAVE_LIBFL 1

/* Define location of spool directories */

#define SPOOLDIR "/var/spool/cron"

/* Define location for PID file */

#define PIDFILE "/var/run/atd.pid"

/* Define mail command for sending; use at most one */

/* #undef MAILX */

/* #undef SENDMAIL */

#define MAILC "/bin/mail"

/* Where do we place out input directories? */

#define ATJOB_DIR "/var/spool/cron/atjobs"

/* Where do we spool our output? */

#define ATSPOOL_DIR "/var/spool/cron/atspool"

/* What's the name of our PID file? */

#define PIDFILE "/var/run/atd.pid"

/* Default queues for at and batch */

#define DEFAULT_AT_QUEUE 'a'

#define DEFAULT_BATCH_QUEUE 'b'

#define HAVE_ATTRIBUTE_NORETURN 1
