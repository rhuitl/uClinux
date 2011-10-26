
#include <unistd.h>
#include <time.h>
#include <features.h>
#include <limits.h>
#include <linux/a.out.h>

/* Get the value of the system variable NAME.  */
/* The man page specifies that errno isn't set by this call which makes things
 * a little easier for us.  This routine has been coded with space efficiency in
 * mind -- i.e. if something isn't defined we don't include that branch in the
 * switch statement.
 */
long int
sysconf (name)
     int name;
{
  switch (name)
    {
    default:
      return -1;

#ifdef ARG_MAX
    case _SC_ARG_MAX:
        return ARG_MAX;			// Maximum length of args to exec() family
#endif
#ifdef _POSIX_CHILD_MAX
    case _SC_CHILD_MAX:
        return _POSIX_CHILD_MAX;  	// Number simultaneous processes per user
#endif	
#ifdef CLK_TCK
    case _SC_CLK_TCK:
        return CLK_TCK;			// Clock ticks per second
#endif
#ifdef FOPEN_MAX
    case _SC_STREAM_MAX:
        return FOPEN_MAX;		// Max number of streams open
#endif
#ifdef TZNAME_MAX
    case _SC_TZNAME_MAX:
        return TZNAME_MAX;		// Bytes in timezone name
#endif
#ifdef _POSIX_OPEN_MAX
    case _SC_OPEN_MAX:
        return _POSIX_OPEN_MAX;		// Number of files per process
#endif

    case _SC_VERSION:
        return 199009L;			// Date of POSIX.1 standard approval

#ifdef BC_BASE_MAX
    case _SC_BC_BASE_MAX:
        return BC_BASE_MAX;		// Maximum base accepted by bc
#endif
#ifdef BC_DIM_MAX
    case _SC_BC_DIM_MAX:
        return BC_DIM_MAX;		// Max value of elements in bc array
#endif
#ifdef BC_SCALE_MAX
    case _SC_BC_SCALE_MAX:
        return BC_SCALE_MAX;		// Max scale allowed in bc
#endif
#ifdef BC_STRING_MAX
    case _SC_BC_STRING_MAX:
        return BC_STRING_MAX;		// Max string length accepted by bc
#endif
#ifdef COLL_WEIGHTS_MAX
    case _SC_COLL_WEIGHTS_MAX:
        return COLL_WEIGHTS_MAX;	// See man page...
#endif
#ifdef EXPR_NEST_MAX
    case _SC_EXPR_NEST_MAX:
        return EXPR_NEST_MAX;		// Max number of expressions nested by expr
#endif
#ifdef LINE_MAX
    case _SC_LINE_MAX:
        return LINE_MAX;		// Max input line length for utilities
#endif
#ifdef RE_DUP_MAX
    case _SC_RE_DUP_MAX:
        return RE_DUP_MAX;		// See man page...
#endif
#ifdef POSIX2_VERSION
    case _SC_2_VERSION:
        return POSIX2_VERSION;		// Version of POSIX.2 standard
#endif
#ifdef PAGE_SIZE
    case _SC_PAGESIZE:
//    case _SC_PAGE_SIZE:
        return PAGE_SIZE;		// Size of a page in bytes
#endif
/* We don't support these two yet
    case _SC_PHYS_PAGES:
        return ;		// Number of pages of physical memory
    case _SC_AVPHYS_PAGES:
        return ;		// Number of pages of currently available
*/


// These aren't mentioned in the man page but they are in the header
#ifdef CHAR_BIT
    case _SC_CHAR_BIT:
      return CHAR_BIT;
    case _SC_LONG_BIT:
      return sizeof (long int) * CHAR_BIT;
    case _SC_WORD_BIT:
      return sizeof (int) * CHAR_BIT;
#endif
#ifdef CHAR_MAX
    case _SC_CHAR_MAX:
      return CHAR_MAX;
#endif
#ifdef CHAR_MIN
    case _SC_CHAR_MIN:
      return CHAR_MIN;
#endif
#ifdef INT_MAX
    case _SC_INT_MAX:
      return INT_MAX;
#endif
#ifdef INT_MIN
    case _SC_INT_MIN:
      return INT_MIN;
#endif
#ifdef MB_LEN_MAX
    case _SC_MB_LEN_MAX:
      return MB_LEN_MAX;
#endif
#ifdef NZERO
    case _SC_NZERO:
      return NZERO;
#endif
#ifdef _POSIX_SSIZE_MAX
    case _SC_SSIZE_MAX:
      return _POSIX_SSIZE_MAX;
    case _SC_SCHAR_MAX:
      return SCHAR_MAX;
#endif
#ifdef SCHAR_MAX
    case _SC_SCHAR_MIN:
      return SCHAR_MIN;
#endif
#ifdef SCHAR_MIN
    case _SC_SHRT_MAX:
      return SHRT_MAX;
#endif
#ifdef SHRT_MAX
    case _SC_SHRT_MIN:
      return SHRT_MIN;
#endif
#ifdef UCHAR_MAX
    case _SC_UCHAR_MAX:
      return UCHAR_MAX;
#endif
#ifdef UINT_MAX
    case _SC_UINT_MAX:
      return UINT_MAX;
#endif
#ifdef ULONG_MAX
    case _SC_ULONG_MAX:
      return ULONG_MAX;
#endif
#ifdef USHRT_MAX
    case _SC_USHRT_MAX:
      return USHRT_MAX;
#endif
#ifdef INT_MAX
    case _SC_ATEXIT_MAX:
      /* We have no limit since we use lists.  */
      return INT_MAX;
#endif
#ifdef BUFSIZ
    case _SC_PASS_MAX:
      /* We have no limit but since the return value might be used to
	 allocate a buffer we restrict the value.  */
      return BUFSIZ;
#endif
#ifdef	CHARCLASS_NAME_MAX
    case _SC_CHARCLASS_NAME_MAX:
      return CHARCLASS_NAME_MAX;
#endif
#ifdef	EQUIV_CLASS_MAX
    case _SC_EQUIV_CLASS_MAX:
      return EQUIV_CLASS_MAX;
#endif


// This section contains the true/false return codes
// Only the first two are mentioned in the man page.
// We make an interesting mess of this lot by grouping the true and
// false bunches together.
/* First the truies */
#ifdef _POSIX_JOB_CONTROL
    case _SC_JOB_CONTROL:		// POSIX job control supported
#endif
#ifdef _POSIX_SAVED_IDS
    case _SC_SAVED_IDS:			// Saved UID and GID supported
#endif
#ifdef POSIX2_C_DEV
    case _SC_2_C_DEV:			// POSIX.2 C language development facilities
#endif
#ifdef POSIX2_FORT_RUN
    case _SC_2_FORT_DEV:		//  POSIX.2 Fortran language development facilities
#endif
#ifdef POSIX2_FORT_RUN
    case _SC_2_FORT_RUN:		//  POSIX.2 Fortran language development facilities
#endif
#ifdef _POSIX2_LOCALEDEF
    case _SC_2_LOCALEDEF:		// localedef supported
#endif
#ifdef POSIX2_SW_DEV
    case _SC_2_SW_DEV:			// POSIX.2 software dev utilities supported
#endif
	return 1;
	
/* And now the falsies */
#ifndef _POSIX_JOB_CONTROL
    case _SC_JOB_CONTROL:		// POSIX job control supported
#endif
#ifndef _POSIX_SAVED_IDS
    case _SC_SAVED_IDS:			// Saved UID and GID supported
#endif
#ifndef POSIX2_C_DEV
    case _SC_2_C_DEV:			// POSIX.2 C language development facilities
#endif
#ifndef POSIX2_FORT_RUN
    case _SC_2_FORT_DEV:		//  POSIX.2 Fortran language development facilities
#endif
#ifndef POSIX2_FORT_RUN
    case _SC_2_FORT_RUN:		//  POSIX.2 Fortran language development facilities
#endif
#ifndef _POSIX2_LOCALEDEF
    case _SC_2_LOCALEDEF:		// localedef supported
#endif
#ifndef POSIX2_SW_DEV
    case _SC_2_SW_DEV:			// POSIX.2 software dev utilities supported
#endif
	return 0;
	
	

/* Plus the following ones...
 * all of which we'll leave undefined for the moment.
    case _SC_NPROCESSORS_CONF:
      return __get_nprocs_conf ();

    case _SC_NPROCESSORS_ONLN:
      return __get_nprocs ();

    case _SC_NGROUPS_MAX:
    case _SC_REALTIME_SIGNALS:
    case _SC_PRIORITY_SCHEDULING:
    case _SC_TIMERS:
    case _SC_ASYNCHRONOUS_IO:
    case _SC_PRIORITIZED_IO:
    case _SC_SYNCHRONIZED_IO:
    case _SC_FSYNC:
    case _SC_MAPPED_FILES:
    case _SC_MEMLOCK:
    case _SC_MEMLOCK_RANGE:
    case _SC_MEMORY_PROTECTION:
    case _SC_MESSAGE_PASSING:
    case _SC_SEMAPHORES:
    case _SC_SHARED_MEMORY_OBJECTS:

    case _SC_AIO_LISTIO_MAX:
    case _SC_AIO_MAX:
    case _SC_AIO_PRIO_DELTA_MAX:
    case _SC_DELAYTIMER_MAX:
    case _SC_MQ_OPEN_MAX:
    case _SC_MQ_PRIO_MAX:
    case _SC_RTSIG_MAX:
    case _SC_SEM_NSEMS_MAX:
    case _SC_SEM_VALUE_MAX:
    case _SC_SIGQUEUE_MAX:
    case _SC_TIMER_MAX:

    case _SC_PII:
    case _SC_PII_XTI:
    case _SC_PII_SOCKET:
    case _SC_PII_OSI:
    case _SC_POLL:
    case _SC_SELECT:
    case _SC_UIO_MAXIOV:
    case _SC_PII_INTERNET_STREAM:
    case _SC_PII_INTERNET_DGRAM:
    case _SC_PII_OSI_COTS:
    case _SC_PII_OSI_CLTS:
    case _SC_PII_OSI_M:
    case _SC_T_IOV_MAX:

    case _SC_2_C_BIND:
    case _SC_2_CHAR_TERM:
    case _SC_2_C_VERSION:
    case _SC_2_UPE:

    case _SC_THREADS:
    case _SC_THREAD_SAFE_FUNCTIONS:
    case _SC_GETGR_R_SIZE_MAX:
    case _SC_GETPW_R_SIZE_MAX:
    case _SC_LOGIN_NAME_MAX:
    case _SC_TTY_NAME_MAX:
    case _SC_THREAD_DESTRUCTOR_ITERATIONS:
    case _SC_THREAD_KEYS_MAX:
    case _SC_THREAD_STACK_MIN:
    case _SC_THREAD_THREADS_MAX:
    case _SC_THREAD_ATTR_STACKADDR:
    case _SC_THREAD_ATTR_STACKSIZE:
    case _SC_THREAD_PRIORITY_SCHEDULING:
    case _SC_THREAD_PRIO_INHERIT:
    case _SC_THREAD_PRIO_PROTECT:
    case _SC_THREAD_PROCESS_SHARED:

    case _SC_XOPEN_VERSION:
    case _SC_XOPEN_XCU_VERSION:
    case _SC_XOPEN_UNIX:
    case _SC_XOPEN_CRYPT:
    case _SC_XOPEN_ENH_I18N:
    case _SC_XOPEN_SHM:
    case _SC_XOPEN_XPG2:
    case _SC_XOPEN_XPG3:
    case _SC_XOPEN_XPG4:

    case _SC_NL_ARGMAX:
    case _SC_NL_LANGMAX:
    case _SC_NL_MSGMAX:
    case _SC_NL_NMAX:
    case _SC_NL_SETMAX:
    case _SC_NL_TEXTMAX:

    case _SC_XBS5_ILP32_OFF32:
    case _SC_XBS5_ILP32_OFFBIG:
    case _SC_XBS5_LP64_OFF64:
    case _SC_XBS5_LPBIG_OFFBIG:

    case _SC_XOPEN_LEGACY:
    case _SC_XOPEN_REALTIME:
    case _SC_XOPEN_REALTIME_THREADS:
*/
      break;
    }
  return -1;
}
