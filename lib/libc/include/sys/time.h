#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <features.h>
#include <linux/types.h>
#include <linux/time.h>

#define	DST_NONE	0	/* not on dst */
#define	DST_USA		1	/* USA style dst */
#define	DST_AUST	2	/* Australian style dst */
#define	DST_WET		3	/* Western European dst */
#define	DST_MET		4	/* Middle European dst */
#define	DST_EET		5	/* Eastern European dst */
#define	DST_CAN		6	/* Canada */
#define	DST_GB		7	/* Great Britain and Eire */
#define	DST_RUM		8	/* Rumania */
#define	DST_TUR		9	/* Turkey */
#define	DST_AUSTALT	10	/* Australian style with shift in 1986 */

#ifdef __SVR4_I386_ABI_L1__
typedef struct timestruc {
    time_t tv_sec;
    long   tv_nsec;
} timestruc_t;
#endif /* __SVR4_I386_ABI_L1__ */

/*
 * Operations on timevals.
 *
 * NB: timercmp does not work for >= or <=.
 * 
 */
#define	timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#define	timercmp(tvp, uvp, cmp)	\
	(((tvp)->tv_sec == (uvp)->tv_sec && (tvp)->tv_usec cmp (uvp)->tv_usec) \
	|| (tvp)->tv_sec cmp (uvp)->tv_sec)
#define	timerclear(tvp)		((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define	timeradd(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;			      \
    if ((result)->tv_usec >= 1000000)					      \
      {									      \
	++(result)->tv_sec;						      \
	(result)->tv_usec -= 1000000;					      \
      }									      \
  } while (0)
#define	timersub(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
    if ((result)->tv_usec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_usec += 1000000;					      \
    }									      \
  } while (0)

#include <time.h>
#include <sys/types.h>

__BEGIN_DECLS

extern int	__gettimeofday __P ((struct timeval * __tp,
			struct timezone * __tz));
extern int	gettimeofday __P ((struct timeval * __tp,
			struct timezone * __tz));
extern int	__settimeofday __P ((__const struct timeval *__tv,
			__const struct timezone *__tz));
extern int	settimeofday __P ((__const struct timeval *__tv,
			__const struct timezone *__tz));

extern int	__select __P ((int __width, fd_set * __readfds,
			fd_set * __writefds, fd_set * __exceptfds,
			struct timeval * __timeout));
extern int	select __P ((int __width, fd_set * __readfds,
			fd_set * __writefds, fd_set * __exceptfds,
			struct timeval * __timeout));

extern int	__getitimer __P ((int __which,
			struct itimerval *__value));
extern int	getitimer __P ((int __which,
			struct itimerval *__value));
extern int	__setitimer __P ((int __which,
			__const struct itimerval *__value,
			struct itimerval *__ovalue));
extern int	setitimer __P ((int __which,
			__const struct itimerval *__value,
			struct itimerval *__ovalue));

extern int	__adjtime __P ((struct timeval * __itv,
			struct timeval * __otv));
extern int	adjtime __P ((struct timeval * __itv,
			struct timeval * __otv));

extern int	__utimes __P((char *__path, struct timeval *tvp));
extern int	utimes __P((char *__path, struct timeval *tvp));

__END_DECLS

#endif /*_SYS_TIME_H*/
