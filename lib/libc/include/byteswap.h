#ifndef _BYTESWAP_H_
#define _BYTESWAP_H_ 1

#define bswap_16(x) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#define bswap_32(x) ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |\
                     (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

#endif /* _BYTESWAP_H_ */
