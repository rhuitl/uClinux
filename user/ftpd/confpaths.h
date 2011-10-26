/* Define PATH_* macros from paths in $(top_srcdir)/paths. */

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif


#ifndef PATH_BSHELL
#define PATH_BSHELL _PATH_BSHELL
#endif
#ifndef PATH_CONSOLE
#define PATH_CONSOLE _PATH_CONSOLE
#endif
#ifndef PATH_DEFPATH
#define PATH_DEFPATH _PATH_DEFPATH
#endif
#ifndef PATH_DEV
#define PATH_DEV _PATH_DEV
#endif
#ifndef PATH_TTY_PFX
#define PATH_TTY_PFX _PATH_DEV
#endif
#ifndef PATH_DEVNULL
#define PATH_DEVNULL _PATH_DEVNULL
#endif
#ifndef PATH_UTMP
#define PATH_UTMP _PATH_UTMP
#endif
#ifndef PATH_WTMP
#define PATH_WTMP _PATH_WTMP
#endif
#ifndef PATH_LASTLOG
#define PATH_LASTLOG _PATH_LASTLOG
#endif
#ifndef PATH_LOG
#define PATH_LOG _PATH_LOG
#endif
#ifndef PATH_KLOG
#define PATH_KLOG _PATH_KLOG
#endif
#ifndef PATH_NOLOGIN
#define PATH_NOLOGIN _PATH_NOLOGIN
#endif
#ifndef PATH_TMP
#define PATH_TMP _PATH_TMP
#endif
#ifndef PATH_TTY
#define PATH_TTY _PATH_TTY
#endif
#ifndef PATH_HEQUIV
#define PATH_HEQUIV _PATH_HEQUIV
#endif
