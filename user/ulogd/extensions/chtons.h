#ifndef _CHTONS_H_
#define _CHTONS_H_

#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#      define BITNR(X) ((X)^31)
#      if !defined(__constant_htonl)
#              define __constant_htonl(x) (x)
#      endif
#      if !defined(__constant_htons)
#              define __constant_htons(x) (x)
#      endif
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#      define BITNR(X) ((X)^7)
#      if !defined(__constant_htonl)
#              define __constant_htonl(x) \
        ((unsigned long int)((((unsigned long int)(x) & 0x000000ffU) << 24) | \
                             (((unsigned long int)(x) & 0x0000ff00U) <<  8) | \
                             (((unsigned long int)(x) & 0x00ff0000U) >>  8) | \
                             (((unsigned long int)(x) & 0xff000000U) >> 24)))
#      endif
#      if !defined(__constant_htons)
#              define __constant_htons(x) \
        ((unsigned short int)((((unsigned short int)(x) & 0x00ff) << 8) | \
                              (((unsigned short int)(x) & 0xff00) >> 8)))
#      endif
#else
#      error "Don't know if bytes are big- or little-endian!"
#endif

#endif
