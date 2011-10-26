#ident "@(#)getdisk.c $Id: getdisk.c,v 4.4 2004/11/08 20:10:27 gert Exp $ Copyright (c) 1994 Elegant Communications Inc."

/*

	This software is graciously provided by Elegant Communications Inc.,
	on the proviso that it is only used in Gert Doering's
	mgetty+sendfax program.

	getdiskstats()	- disk partition statistics function.
    
	The key to configuration is choosing the right one of the
	following five types:
	    BSDSTATFS     - BSD/hp-ux/SunOS/Dynix/vrios/OSF-1
			    2-parameter statfs()
	    ULTRIXSTATFS  - Ultrix wacko statfs
	    SVR4	  - SVR4 statvfs()
	    SVR3	  - SVR3/88k/Apollo 4-parameter statfs()
	    USTAT	  - ustat(), no statfs etc.
	
    The first section of code uses symbolic names to indicate which
    platform needs which type of partition grabbing.  In mgetty, this
    source will automatically choose the right variant with ISC, AIX,
    HP/UX, 3b1, sun and linux (I hope).  If your system doesn't
    automatically select by itself, try defining the "v*" macro from
    below that seems closest to your system.  For example, if you have a
    3b2, insert "vu3b2" into CCFLAGS in the top-level makefile.  If
    you succeed, please let us know:  which "v*" macro you used, and
    whether your C compiler predefines a macro designating your system.
    Eg:  HP/UX predefines "__hpux" - instead of a "vhpux" macro,
    we key on "__hpux".

	If all else fails, try USTAT which is fairly generic, but
	doesn't return as much information as stat[v]fs does.
	
	getdiskstats(char * path, mntinf *mi)

		path: pointer to file on partition to be statfs/ustat'd
		mi: pointer to mntinf structure that will filled to
		    contain the partition statistics of the partition
		    that has file "path".
		returns: 0 on success.
 */

#include <stdio.h>

#include "policy.h"
#include "mgetty.h"

/* some systems define this in an include file somewhere below, and mgetty.h
   defines it as well. So just #undef it, we don't need it here anyway
 */
#undef MAXPATH


/* for the most part, these defines are simply used to show which
   systems need which type of statfs/ustat().  They can all be
   removed if the correct one of the 5 selectors is chosen
   (say) in Makefile.  There are, after these defines, a few
   more #ifs that further figure out inclusions and other
   things where the 5 selectors themselves are inadequate - in
   many cases, they'll just turn out to be the defines that they
   use on their systems already.  For example, "vu3b2" is just
   our jargon for a 3b2.
 */
#if defined(vmiti) || defined(vtandem) || defined(vmips) || defined(ISC) || \
	defined(M_UNIX) || defined(m88k) || \
	defined(vm68k) || defined(vu3b2) || \
	defined(vxps) || defined(vu6050) || defined(vs5k80) || \
	defined(vs5k50) || defined(vdpx2) || defined(vdynptx) || \
	defined(venc)
# define SVR3
#endif

#if defined(vpyr) || defined(vsnxdyn) || defined(__hpux) || defined(vdynix) || \
    defined(vaix) || defined(_AIX) || defined(vaixps2) || defined(sunos4) || \
    defined(linux) || defined(__osf__) || defined(BSD)
# define BSDSTATFS	/* as used from the att universe of Pyramid! :-) */
#endif

/* If your system is SVR4, the mgetty+sendfax Makefile should already
   predefine SVR4
 */
#if defined(vdrs) || defined(vdrs6k) || defined(vdcosx) || defined(vamiga) || \
	defined(vnecews) || defined(vnecup) || defined(vnecnpx) || \
	defined(vsnx386) || defined(vsnxmips) || defined(vsolaris)
# define SVR4
#endif

#ifdef ultrix
# define ULTRIXSTATFS
#endif

#if defined(_3B1_)
# define USTAT
#endif

/* imported from NetBSD pkgsrc */
#if defined(__NetBSD__) && (__NetBSD_Version__ > 200030000)
#undef BSDSTATFS
#define        SVR4
#endif 

#if defined(SVR4)
# define SVR3
#endif

#if defined(BSDSTATFS) || defined(ULTRIXSTATFS) || \
    defined(SVR3) || defined(SVR4) || defined(USTAT)
# define HASDISKSTAT
#endif

/* END OF STATFS type fiddling */

/* this is the beginning of getdiskstats() proper
 */

#ifdef ULTRIXSTATFS
#  include <sys/param.h>
#endif

#ifdef HASDISKSTAT
# if !defined(vsnxdyn) && !defined(vdomain) && !defined(_AIX)
#  include <sys/types.h>
#  include <sys/param.h>
#  include <sys/mount.h>
# endif

# ifdef BSDSTATFS
#  ifdef _AIX
#   include <sys/statfs.h>
#  else
#   ifdef __osf__
#    include <sys/mount.h>
#   else
#    if !defined(BSD) || defined(NeXT)
#     include <sys/vfs.h>
#    endif 	/* !BSD */
#   endif	/* !__osf__ */
#  endif	/* _AIX */

#  define MYSTATFS(a,b) statfs(a,b)
#  define STATFSS statfs

# else		/* !BSDSTATFS */

#  ifdef ULTRIXSTATFS	/* oh grotty, oh stupid, oh-nonstandard one */
#   define MYSTATFS(a,b) statfs(a,b)
#   define STATFSS fs_data
#   define f_bavail fd_req.bfreen
#   define f_ffree fd_req.gfree
#   define f_bfree fd_req.bfree
#   define f_frsize fd_req.bsize
#   define f_bsize fd_req.bsize
#   define f_blocks fd_req.btot
#   define f_files  fd_req.gtot


#  else
#   ifdef USTAT
#    include <sys/stat.h>
#    include <ustat.h>

#    define STATFSS ustat
#    define MYSTATFS(a,b) (stat(a, &stb) == 0 ? ustat(stb.st_dev, b) : -1)
#    define f_bfree f_tfree
#    define f_bavail f_tfree
#    define f_ffree f_tinode
#   endif

#   ifdef SVR4

#    include <sys/statvfs.h>
#    define STATFSS statvfs
#    define MYSTATFS(a,b) statvfs(a,b)

#   else

#    if defined(SVR3) || defined(vdomain)	/* eg: Apollo/88k */

#     include <sys/statfs.h>
#     include <sys/param.h>
#     define f_bavail f_bfree
#     define STATFSS statfs
#     define MYSTATFS(a,b) statfs(a,b,sizeof(struct STATFSS),0)

#    endif /* SVR3 */
#   endif /* SVR4 */
#  endif /* ULTRIXSTATFS */
# endif /* BSDSTATFS */
#endif /* HASDISKSTAT */

long minfreespace = MINFREESPACE;

/* returns how many "minfreesize" hunks will fit onto the freespace
   left on the partition that contains "path".
   Ie: if you have 2.5Mb free, and minfreespace is 1Mb, you get
   back "2".
 */

#ifndef TESTDISK
int checkspace _P1 ((path), char *path)
{
#ifdef HASDISKSTAT
    struct mountinfo mi;
    unsigned int kbytes;

    if (getdiskstats(path, &mi))
	return(1);

    /* the "shift" stuff is actually a division by 1024, to get "kbytes"
     * instead of bytes.  But if we do it that way, we risk 32bit overflows 
     * on disks > 4G, or "0" if mi_bsize is 512 or 256.
     */
    kbytes = (mi.mi_bavail>>2) * (mi.mi_bsize>>8);

    lprintf( L_NOISE, "%d Mb free on %s", kbytes/1024, path );
    return( kbytes / minfreespace);
#else
    return(1);
#endif
}
#endif

/* All of the configuration crap above is simply so that this function
   compiles.
   
   Returns 0 on success, 1 otherwise.
   a "mntinf" structure is passed back containing the stat[v]fs/ustat
   information on the partition containing "path".
 */

int
getdiskstats _P2 ((path, mi), char *path, mntinf *mi)
{
#ifdef HASDISKSTAT
    struct STATFSS info;

#ifdef USTAT
    struct stat stb;
#endif

    if (MYSTATFS(path, &info) < 0) {
	return(1);
    }
    /* Systems known to lie & have NBPSCTR */
#if defined(ISC) || defined(M_UNIX) || defined(m88k)
    /*
     * Interactive 1.0.6 lies - it says bsize is 1024, but returns a frag
     * size of zero instead of 512.  NBPSCTR (Number of Bytes per Physical
     * SeCToR) is defined as 512 in <sys/param.h>.  This "bug" is probably
     * due to 386/ix 1.0.6's default to only support 1024 byte filesystems
     * (FsTYPE == 2), both in the kernel, and out, in which case BSIZE is
     * 1024 too!  (Smarter systems define FsTYPE to 3 outside of the kernel.)
     *
     * SCO Unix 3.2.2 also lies.
     */
    mi->mi_bsize = (info.f_frsize > 0) ? info.f_frsize : NBPSCTR;
#else
# if defined(vmips) || defined(USTAT)
    /*
     * Mips 4.52 also lies - it claims bsize and frsize both as 1024, but
     * it still uses a block size of 512 when reporting total/free blocks.
     */
    /*
     * classic SVR2 ustat() implementations have no block size in the
     * ustat structure, but has NBPSCTR in sys/param.h
     */
    mi->mi_bsize = NBPSCTR;
# else
    /* Systems that don't define f_frsize at all 
     * OR give a meaningless value.
     */
#  if defined(BSDSTATFS) || defined(m88k)
    mi->mi_bsize = info.f_bsize;
#  else
    /* if frag size is given, it is the units for blocks
     * otherwise, it is either bsize or somebody is running
     * old code that lies
     */
    mi->mi_bsize = (info.f_frsize > 0) ? info.f_frsize : info.f_bsize;
#  endif
# endif
#endif
    /*
     * WARNING: on some systems (vrios & SVR4) the value for f_frsize (or
     * f_bsize) may be correct for the remote system's real filesystem when
     * used over NFS, but almost every NFS implementation will only return
     * f_bfree (and f_bavail) in units of 1 Kb blocks and usually return -1
     * for f_files and f_ffree.  XRSAdf doesn't really have to be concerned
     * with this inconsistancy, though the eXpert handler must be careful.
     */
#ifdef USTAT
    mi->mi_blocks = mi->mi_files = -1;
#else
    mi->mi_blocks = info.f_blocks;
    mi->mi_files = info.f_files;
#endif /* USTAT */
    mi->mi_bfree = info.f_bfree;
    mi->mi_bavail = info.f_bavail;	/* may be duplicate of f_bfree */
    mi->mi_ffree = info.f_ffree;
    
    return(0);
#else
    return(-1);
#endif /* STATFS */
}

/* Test program */

#ifdef TESTDISK

#if ! defined(HASDISKSTAT)
#include "ERROR: don't know how to get fs info - see Makefile for defines"
#endif

int main(argc, argv) int argc; char **argv; {
    struct mountinfo mi;
    argv++;

    printf("%s personality\n",
#ifdef USTAT
	"ustat()"
#endif
#ifdef ULTRIXSTATFS
	"ultrix statfs()"
#endif
#ifdef BSDSTATFS
	"BSD statfs()"
#endif
#ifdef SVR3
	"SVR3 4parameter statfs()"
#endif
#ifdef SVR4
	"SVR4 statvfs()"
#endif
	);
    while(*argv) {
	if (getdiskstats(*argv, &mi)) {
	    fprintf(stderr, "statfs on %s failed\n", *argv);
	} else {
	    printf( "STATFS report on %s:\n", *argv );
	    printf( "\tfundamental file system block size      %ld\n", mi.mi_bsize);
	    printf( "\ttotal data blocks in file system        %ld\n", mi.mi_blocks);
	    printf( "\tfree block in fs                        %ld\n", mi.mi_bfree);
	    printf( "\tfree blocks avail to non-superuser      %ld\n", mi.mi_bavail);
	    printf( "\ttotal file nodes in file system         %ld\n", mi.mi_files);
	    printf( "\tfree file nodes in fs                   %ld\n", mi.mi_ffree);
	}
	argv++;
    }
    exit(0);
}
#endif
