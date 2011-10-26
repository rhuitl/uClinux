#ifndef _config_h_INCLUDED
#define NDEBUG
#define OS_IS_LINUX
#define HAVE_ATEXIT
#define VERSION "0.3.9"

#if defined(mc68000)
#include "config-coldfire.h"
#elif defined(i386)
#include "config-i386.h"
#else
#error Your architecture is not supported
#endif

#endif /* _config_h_INCLUDED */
