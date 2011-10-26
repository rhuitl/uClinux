#ifndef _BITS_BYTESWAP_H
#define _BITS_BYTESWAP_H 1

/* CRIS specific byte swap operations: 16, 32 and 64-bit */

/* Swap bytes in 16 bit value.  */
#define __bswap_constant_16(x) \
({ \
	unsigned short __x = (x); \
	((unsigned short)( \
		(((unsigned short)(__x) & (unsigned short)0x00ffu) << 8) |   \
		(((unsigned short)(__x) & (unsigned short)0xff00u) >> 8) )); \
})

#if defined __GNUC__ && __GNUC__ >= 2
#  define __bswap_16(x) \
	__extension__ 							\
	({ unsigned short __bswap_16_v; 				\
	   if (__builtin_constant_p (x)) 				\
	   	__bswap_16_v = __bswap_constant_16 (x); 		\
	   else 							\
	   	__asm__ ("swapb %0" : "=r" (__bswap_16_v) : "0" (x)); 	\
	   __bswap_16_v; })
#else
#  define __bswap_16(x) __bswap_constant_16 (x)
#endif


/* Swap bytes in 32 bit value.  */
#define __bswap_constant_32(x) \
({ \
	unsigned long __x = (x); \
	((unsigned long)( \
		(((unsigned long)(__x) & (unsigned long)0x000000fful) << 24) | \
		(((unsigned long)(__x) & (unsigned long)0x0000ff00ul) <<  8) | \
		(((unsigned long)(__x) & (unsigned long)0x00ff0000ul) >>  8) | \
		(((unsigned long)(__x) & (unsigned long)0xff000000ul) >> 24) )); \
})

#if defined __GNUC__ && __GNUC__ >= 2
#  define __bswap_32(x) \
	__extension__ 							\
	({ unsigned long __bswap_32_v; 					\
	   if (__builtin_constant_p (x)) 				\
	   	__bswap_32_v = __bswap_constant_32 (x); 		\
	   else 							\
	   	__asm__ ("swapwb %0" : "=r" (__bswap_32_v) : "0" (x)); 	\
	   __bswap_32_v; })
#else
#  define __bswap_32(x) __bswap_constant_32 (x)
#endif


/* Swap bytes in 64 bit value.  */
# define __bswap_constant_64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)                                   \
      | (((x) & 0x00ff000000000000ull) >> 40)                                 \
      | (((x) & 0x0000ff0000000000ull) >> 24)                                 \
      | (((x) & 0x000000ff00000000ull) >> 8)                                  \
      | (((x) & 0x00000000ff000000ull) << 8)                                  \
      | (((x) & 0x0000000000ff0000ull) << 24)                                 \
      | (((x) & 0x000000000000ff00ull) << 40)                                 \
      | (((x) & 0x00000000000000ffull) << 56))

#if defined __GNUC__ && __GNUC__ >= 2
# define __bswap_64(x) \
     (__extension__                                                           \
      ({ union { __extension__ unsigned long long int __ll;                   \
                 unsigned int __l[2]; } __w, __r;                             \
         if (__builtin_constant_p (x))                                        \
           __r.__ll = __bswap_constant_64 (x);                                \
         else                                                                 \
           {                                                                  \
             __w.__ll = (x);                                                  \
             __r.__l[0] = __bswap_32 (__w.__l[1]);                            \
             __r.__l[1] = __bswap_32 (__w.__l[0]);                            \
           }                                                                  \
         __r.__ll; }))
#else
#  define __bswap_64(x) __bswap_constant_64 (x)
#endif

#endif /* _BITS_BYTESWAP_H */
