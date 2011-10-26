#include <features.h>
#ifdef __UCLIBC_SUSV3_LEGACY__
# define memset bzero
# include "memset.S"
#endif
