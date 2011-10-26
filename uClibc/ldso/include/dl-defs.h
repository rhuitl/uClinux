/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2000-2006 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Lesser General Public License version 2.1 or later.
 */

#ifndef _LD_DEFS_H
#define _LD_DEFS_H

#define FLAG_ANY             -1
#define FLAG_TYPE_MASK       0x00ff
#define FLAG_LIBC4           0x0000
#define FLAG_ELF             0x0001
#define FLAG_ELF_LIBC5       0x0002
#define FLAG_ELF_LIBC6       0x0003
#define FLAG_ELF_UCLIBC      0x0004
#define FLAG_REQUIRED_MASK   0xff00
#define FLAG_SPARC_LIB64     0x0100
#define FLAG_IA64_LIB64      0x0200
#define FLAG_X8664_LIB64     0x0300
#define FLAG_S390_LIB64      0x0400
#define FLAG_POWERPC_LIB64   0x0500
#define FLAG_MIPS64_LIBN32   0x0600
#define FLAG_MIPS64_LIBN64   0x0700

#define LIB_ANY	     -1
#define LIB_DLL       0
#define LIB_ELF       1
#define LIB_ELF64     0x80
#define LIB_ELF_LIBC5 2
#define LIB_ELF_LIBC6 3
#define LIB_ELF_LIBC0 4

#if defined(__LDSO_PRELOAD_FILE_SUPPORT__) || defined(__LDSO_CACHE_SUPPORT__)
#ifndef __LDSO_BASE_FILENAME__
#define __LDSO_BASE_FILENAME__ "ld.so"
#endif
#define LDSO_BASE_PATH UCLIBC_RUNTIME_PREFIX "etc/" __LDSO_BASE_FILENAME__

#ifdef __LDSO_PRELOAD_FILE_SUPPORT__
#define LDSO_PRELOAD LDSO_BASE_PATH ".preload"
#endif

#ifdef __LDSO_CACHE_SUPPORT__
#define LDSO_CONF    LDSO_BASE_PATH ".conf"
#define LDSO_CACHE   LDSO_BASE_PATH ".cache"

#define LDSO_CACHE_MAGIC "ld.so-"
#define LDSO_CACHE_MAGIC_LEN (sizeof LDSO_CACHE_MAGIC -1)
#define LDSO_CACHE_VER "1.7.0"
#define LDSO_CACHE_VER_LEN (sizeof LDSO_CACHE_VER -1)

typedef struct {
	char magic   [LDSO_CACHE_MAGIC_LEN];
	char version [LDSO_CACHE_VER_LEN];
	int nlibs;
} header_t;

typedef struct {
	int flags;
	int sooffset;
	int liboffset;
} libentry_t;

#ifdef __ARCH_USE_MMU__
#define LDSO_CACHE_MMAP_FLAGS (MAP_SHARED)
#else
#define LDSO_CACHE_MMAP_FLAGS (MAP_PRIVATE)
#endif
#endif	/* __LDSO_CACHE_SUPPORT__ */

#endif

/* Provide a means for a port to pass additional arguments to the _dl_start
   function.  */
#ifndef DL_START
# define DL_START(X) static void * __attribute_used__ _dl_start(X)
#endif

/* Machines in which different sections may be relocated by different
 * amounts should define this and LD_RELOC_ADDR.  If you change this,
 * make sure you change struct link_map in include/link.h accordingly
 * such that it matches a prefix of struct elf_resolve.
 */
#ifndef DL_LOADADDR_TYPE
# define DL_LOADADDR_TYPE ElfW(Addr)
#endif

/* When DL_LOADADDR_TYPE is not a scalar value, or some different
 * computation is needed to relocate an address, define this.
 */
#ifndef DL_RELOC_ADDR
# define DL_RELOC_ADDR(LOADADDR, ADDR) \
	((LOADADDR) + (ADDR))
#endif

/* Initialize a LOADADDR representing the loader itself.  It's only
 * called from DL_BOOT, so additional arguments passed to it may be
 * referenced.
 */
#ifndef DL_INIT_LOADADDR_BOOT
# define DL_INIT_LOADADDR_BOOT(LOADADDR, BASEADDR) \
	((LOADADDR) = (BASEADDR))
#endif

/* Define if any declarations/definitions of local variables are
 * needed in a function that calls DT_INIT_LOADADDR or
 * DL_INIT_LOADADDR_HDR.  Declarations must be properly terminated
 * with a semicolon, and non-declaration statements are forbidden.
 */
#ifndef DL_INIT_LOADADDR_EXTRA_DECLS
# define DL_INIT_LOADADDR_EXTRA_DECLS /* int i; */
#endif

/* Prepare a DL_LOADADDR_TYPE data structure for incremental
 * initialization with DL_INIT_LOADADDR_HDR, given pointers to a base
 * load address and to program headers.
 */
#ifndef DL_INIT_LOADADDR
# define DL_INIT_LOADADDR(LOADADDR, BASEADDR, PHDR, PHDRCNT) \
	((LOADADDR) = (BASEADDR))
#endif

/* Initialize a LOADADDR representing the program.  It's called from
 * DL_BOOT only.
 */
#ifndef DL_INIT_LOADADDR_PROG
# define DL_INIT_LOADADDR_PROG(LOADADDR, BASEADDR) \
	((LOADADDR) = (DL_LOADADDR_TYPE)(BASEADDR))
#endif

/* Convert a DL_LOADADDR_TYPE to an identifying pointer.  Used mostly
 * for debugging.
 */
#ifndef DL_LOADADDR_BASE
# define DL_LOADADDR_BASE(LOADADDR) (LOADADDR)
#endif

/* Test whether a given ADDR is more likely to be within the memory
 * region mapped to TPNT (a struct elf_resolve *) than to TFROM.
 * Everywhere that this is used, TFROM is initially NULL, and whenever
 * a potential match is found, it's updated.  One might want to walk
 * the chain of elf_resolve to locate the best match and return false
 * whenever TFROM is non-NULL, or use an exact-matching algorithm
 * using additional information encoded in DL_LOADADDR_TYPE to test
 * for exact containment.
 */
#ifndef DL_ADDR_IN_LOADADDR
# define DL_ADDR_IN_LOADADDR(ADDR, TPNT, TFROM) \
	((void*)(TPNT)->loadaddr < (void*)(ADDR) \
	 && (!(TFROM) || (TFROM)->loadaddr < (TPNT)->loadaddr))
#endif

/* Use this macro to convert a pointer to a function's entry point to
 * a pointer to function.  The pointer is assumed to have already been
 * relocated.  LOADADDR is passed because it may contain additional
 * information needed to compute the pointer to function.
 */
#ifndef DL_ADDR_TO_FUNC_PTR
# define DL_ADDR_TO_FUNC_PTR(ADDR, LOADADDR) ((void(*)(void))(ADDR))
#endif

/* On some platforms, computing a pointer to function is more
   expensive than calling a function at a given address, so this
   alternative is provided.  The function signature must be given
   within parentheses, as in a type cast.  */
#ifndef DL_CALL_FUNC_AT_ADDR
# define DL_CALL_FUNC_AT_ADDR(ADDR, LOADADDR, SIGNATURE, ...) \
  ((*SIGNATURE DL_ADDR_TO_FUNC_PTR ((ADDR), (LOADADDR)))(__VA_ARGS__))
#endif

/* An alignment value for a memory block returned by _dl_malloc. */
#ifndef DL_MALLOC_ALIGN
# define DL_MALLOC_ALIGN (__WORDSIZE / 8)
#endif

#endif	/* _LD_DEFS_H */
