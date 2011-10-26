/*
 * util.h
 *
 * Some useful defines.
 *
 * $Id: util.h,v 1.4 1998/09/09 21:06:38 gert Exp $
 *
 */

/*
 * Generic constants
 */

#undef TRUE
#undef FALSE

#define TRUE (0==0)
#define FALSE (0==1)

#undef OK
#undef FAIL

#define OK (0)
#define FAIL (-1)
#define UNKNOWN_EVENT (-2)

#define INTERRUPTED (0x4d00)

#ifndef M_PI
# define M_PI 3.14159265358979323846
#endif

/*
 * Special modem control characters
 */

#undef ETX
#undef NL
#undef CR
#undef DLE
#undef XON
#undef XOFF
#undef DC4
#undef CAN
#undef FS

#define ETX  (0x03)
#define NL   (0x0a)
#define CR   (0x0d)
#define DLE  (0x10)
#define XON  (0x11)
#define XOFF (0x13)
#define DC4  (0x14)
#define CAN  (0x18)
#define FS   (0x1c)

/*
 * Check, that the system we are running on has proper bit sizes and
 * does proper handling of right bit shift operations
 */

extern void check_system (void);

/*
 * Useful path concatenation function
 */

extern void make_path (char *result, char *path, char *name);

/*
 * Wildmat match for strings
 */
 
extern int wildmat(char *text, char *p, int length);
