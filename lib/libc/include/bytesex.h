
#if defined(__ARMEB__)
#define __BYTE_ORDER __BIG_ENDIAN
#endif

#if !defined(__ARMEB__) && defined(arm_elf)
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

/* fallback to big-endian for all m68k platforms */
#if !defined(__BYTE_ORDER)
#define __BYTE_ORDER __BIG_ENDIAN
#endif

