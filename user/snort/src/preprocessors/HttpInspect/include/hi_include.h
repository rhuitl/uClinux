#ifndef __HI_INCLUDE_H__
#define __HI_INCLUDE_H__

#define HI_UNKNOWN_METHOD 1
#define HI_POST_METHOD 2
#define HI_GET_METHOD 4

#include "rules.h" /* For UINT64 */

typedef struct _hi_stats {
    UINT64 unicode;
    UINT64 double_unicode;
    UINT64 non_ascii;        /* Non ASCII-representable character in URL */
    UINT64 base36;
    UINT64 dir_trav;         /* '../' */
    UINT64 slashes;          /* '//' */
    UINT64 self_ref;         /* './' */
    UINT64 post;             /* Number of POST methods encountered */
    UINT64 get;              /* Number of GETs */
    UINT64 post_params;      /* Number of sucesfully extract post parameters */
    UINT64 total;
} HIStats;

extern HIStats hi_stats;

#ifndef INLINE

#ifdef WIN32
#define INLINE __inline
#else
#define INLINE inline
#endif

#endif /* endif for INLINE */

#endif
