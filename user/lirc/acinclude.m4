## $Id: acinclude.m4,v 1.6 2000/12/23 11:23:57 columbus Exp $
##
## additional m4 macros
##
## (C) 1999 Christoph Bartelmus (lirc@bartelmus.de)
##


dnl check for kernel source

AC_DEFUN(AC_PATH_KERNEL_SOURCE_SEARCH,
[
  kerneldir=missing
  no_kernel=yes

  if test `uname` != "Linux"; then
    kerneldir="not running Linux"
  else
    for dir in /usr/src/kernel-source-`uname -r` /usr/src/linux-`uname -r` /usr/src/linux ${ac_kerneldir}; do
      if test -d $dir; then
        kerneldir=`dirname $dir/Makefile`/
        no_kernel=no
      fi;
    done
  fi

  if test x${no_kernel} != xyes; then
    if test -f ${kerneldir}/Makefile; then
      if test "${ac_pkss_mktemp}" = "yes"; then
        ac_pkss_makefile=`mktemp /tmp/LIRCMF.XXXXXX`
      else
        ac_pkss_makefile=/tmp/LIRCMF.XXXXXX
      fi
      cat ${kerneldir}/Makefile >${ac_pkss_makefile}
      echo "lirc_tell_me_what_cc_is:" >>${ac_pkss_makefile}
      echo "	echo \$(CC)" >>${ac_pkss_makefile}

      kernelcc=`make -s -C ${kerneldir} -f ${ac_pkss_makefile} lirc_tell_me_what_cc_is`
      rm -f ${ac_pkss_makefile}
    else
      kerneldir="no Makefile found"
      no_kernel=yes
    fi
  fi
  ac_cv_have_kernel="no_kernel=${no_kernel} \
		kerneldir=\"${kerneldir}\" \
		kernelcc=\"${kernelcc}\""
]
)

AC_DEFUN(AC_PATH_KERNEL_SOURCE,
[
  AC_CHECK_PROG(ac_pkss_mktemp,mktemp,yes,no)
  AC_PROVIDE([AC_PATH_KERNEL_SOURCE])
  AC_MSG_CHECKING(for Linux kernel sources)

  AC_ARG_WITH(kerneldir,
    [  --with-kerneldir=DIR    kernel sources in DIR], 

    ac_kerneldir=${withval}
    AC_PATH_KERNEL_SOURCE_SEARCH,

    ac_kerneldir=""
    AC_CACHE_VAL(ac_cv_have_kernel,AC_PATH_KERNEL_SOURCE_SEARCH)
  )
  
  eval "$ac_cv_have_kernel"

  AC_SUBST(kerneldir)
  AC_SUBST(kernelcc)
  AC_MSG_RESULT(${kerneldir})
]
)
