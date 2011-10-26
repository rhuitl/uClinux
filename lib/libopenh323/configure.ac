AC_INIT(include/h323.h)

AC_PROG_CXX
AC_HEADER_STDC

dnl this must be updated for every minor revision, and for
dnl builds when and as necessary
REQUIRED_PWLIB_MAJOR=1
REQUIRED_PWLIB_MINOR=10
REQUIRED_PWLIB_BUILD=0

dnl ########################################################################
dnl set the OpenH323 directory to the current directory

OPENH323DIR=`pwd`
AC_SUBST(OPENH323DIR)

dnl ########################################################################
dnl set the PREFIX accordingly
if test "x$prefix" = "xNONE"; then
   INSTALLPREFIX="/usr/local"
else
   INSTALLPREFIX="${prefix}"
fi

AC_SUBST(INSTALLPREFIX)


dnl ########################################################################
dnl set LIBDIR accordingly
LIBDIR="${libdir}"

AC_SUBST(LIBDIR)


dnl ########################################################################
dnl extract the OpenH323 version
MAJOR_VERSION=`cat ${OPENH323DIR}/version.h | grep MAJOR_VERSION | cut -f3 -d' '`
MINOR_VERSION=`cat ${OPENH323DIR}/version.h | grep MINOR_VERSION | cut -f3 -d' '`
BUILD_NUMBER=`cat ${OPENH323DIR}/version.h | grep BUILD_NUMBER | cut -f3 -d' '`
OPENH323_VERSION="${MAJOR_VERSION}.${MINOR_VERSION}.${BUILD_NUMBER}"
AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(BUILD_NUMBER)
AC_SUBST(OPENH323_VERSION)
AC_SUBST(MAJOR_VERSION, $MAJOR_VERSION)
AC_SUBST(MINOR_VERSION, $MINOR_VERSION)
AC_SUBST(BUILD_NUMBER, $BUILD_NUMBER)

echo "OpenH323 version is ${OPENH323_VERSION}"

AC_DEFINE_UNQUOTED(OPENH323_MAJOR,   ${MAJOR_VERSION})
AC_DEFINE_UNQUOTED(OPENH323_MINOR,   ${MINOR_VERSION})
AC_DEFINE_UNQUOTED(OPENH323_BUILD,   ${BUILD_NUMBER})
AC_DEFINE_UNQUOTED(OPENH323_VERSION, "$OPENH323_VERSION")

dnl ########################################################################
dnl look for ptlib, use a preference order of explicit PWLIBDIR, directory
dnl at same level, home directory, /usr/local or /usr.

#if test "${PWLIBDIR:-unset}" != "unset" ; then
#  AC_CHECK_FILE(${PWLIBDIR}/version.h, HAS_PTLIB=1)
#fi
#if test "${HAS_PTLIB:-unset}" = "unset" ; then
#  AC_CHECK_FILE(${OPENH323DIR}/../pwlib/version.h, HAS_PTLIB=1)
#  if test "${HAS_PTLIB:-unset}" != "unset" ; then
#    PWLIBDIR="${OPENH323DIR}/../pwlib"
#  else
#    AC_CHECK_FILE(${HOME}/pwlib/include/ptlib.h, HAS_PTLIB=1)
#    if test "${HAS_PTLIB:-unset}" != "unset" ; then
#      PWLIBDIR="${HOME}/pwlib"
#    else
#      AC_CHECK_FILE(/usr/local/include/ptlib.h, HAS_PTLIB=1)
#      if test "${HAS_PTLIB:-unset}" != "unset" ; then
#        AC_PATH_PROG(PTLIB_CONFIG, ptlib-config, , /usr/local/bin)
#      else
#        AC_CHECK_FILE(/usr/include/ptlib.h, HAS_PTLIB=1)
#        if test "${HAS_PTLIB:-unset}" != "unset" ; then
#          AC_PATH_PROG(PTLIB_CONFIG, ptlib-config, , /usr/share/pwlib/make/)
#        fi
#      fi
#    fi
#  fi
#fi

if test "${HAS_PTLIB:-unset}" = "unset" ; then
  echo "Cannot find pwlib - please install or set PWLIBDIR and try again"
  exit
fi

if test "${PWLIBDIR:-unset}" = "unset" ; then
  if test "${PTLIB_CONFIG:-unset}" = "unset" ; then
    echo "Cannot find ptlib-config - please install and try again"
    exit
  fi
  PWLIBDIR=`$PTLIB_CONFIG --prefix`
fi

if test "x$PWLIBDIR" = "x/usr" -o "x$PWLIBDIR" = "x/usr/"; then
  PWLIBDIR="/usr/share/pwlib/"
fi
if test "x$PWLIBDIR" = "x/usr/local" -o "x$PWLIBDIR" = "x/usr/"; then
  PWLIBDIR="/usr/local/share/pwlib/"
fi

echo "PWLib prefix set to.... $PWLIBDIR"

if test "${PWLIBDIR:-unset}" = "unset" ; then
  PWVERSION=`$PTLIB_CONFIG --version`
  PW_MAJOR_VERSION=`echo $PW_VERSION | cut -d'.' -f1`
  PW_MINOR_VERSION=`echo $PW_VERSION | cut -d'.' -f2`
  PW_BUILD_NUMBER=`echo $PW_VERSION | cut -d'.' -f3`
  
else
  PW_MAJOR_VERSION=`cat ${PWLIBDIR}/version.h | grep MAJOR_VERSION | cut -f3 -d' '`
  PW_MINOR_VERSION=`cat ${PWLIBDIR}/version.h | grep MINOR_VERSION | cut -f3 -d' '`
  PW_BUILD_NUMBER=`cat ${PWLIBDIR}/version.h | grep BUILD_NUMBER | cut -f3 -d' '`
  PWVERSION="${PW_MAJOR_VERSION}.${PW_MINOR_VERSION}.${PW_BUILD_NUMBER}"
fi

AC_ARG_ENABLE(versioncheck,
		[  --disable-versioncheck    disable PWLib version check],
		PWLIB_VERSION_CHECK=$enableval)

AC_MSG_CHECKING(Checking PWLib version ${PWVERSION})
if test "${PWLIB_VERSION_CHECK}x" = "nox" ; then
  AC_MSG_RESULT(check disabled)
else
  if test $PW_MAJOR_VERSION -lt $REQUIRED_PWLIB_MAJOR ; then
    AC_MSG_RESULT(Major version less than required $REQUIRED_PWLIB_MAJOR)
    exit 1
  fi
  if test $PW_MINOR_VERSION -lt $REQUIRED_PWLIB_MINOR ; then
    AC_MSG_RESULT(Minor version less than required $REQUIRED_PWLIB_MINOR)
    exit 1
  fi
  if test $PW_BUILD_NUMBER -lt $REQUIRED_PWLIB_BUILD ; then
    AC_MSG_RESULT(Build version less than required $REQUIRED_PWLIB_BUILD)
    exit 1
  fi
  AC_MSG_RESULT(ok)
fi

AC_SUBST(PWLIBDIR)

dnl ########################################################################
dnl check for setting minimum size

AC_ARG_ENABLE(minsize,
       [  --enable-minsize        minimise the size of the lib by disabling least used options])

dnl these are the default configure settings
default_ixj=yes
default_audio=yes
default_video=yes
default_asntracing=yes
default_h450=yes
default_h501=yes
default_t38=yes
default_h248=yes
default_h460=yes
default_t120=yes
default_transnexusosp=yes
default_h263avcodec=no
default_vich263=no
AC_MSG_NOTICE(2345)

if test "${enable_minsize}x" = "yesx" ; then
	AC_MSG_NOTICE(1234)
  default_ixj=no
  default_audio=yes
  default_video=yes
  default_asntracing=no
  default_h450=no
  default_h501=no
  default_t38=no
  default_h248=no
  default_h460=no
  default_t120=no
  default_transnexusosp=no
  default_h263avcodec=no
  default_vich263=no
fi


dnl ########################################################################
dnl check for disbling ASN tracing

AC_ARG_ENABLE(asntracing,
       [  --disable-asntracing    disable ASN tracing])

if test "${enable_asntracing}z" = "z" ; then
  enable_asntracing=$default_asntracing
fi

if test "$enable_asntracing" = "no" ; then
  AC_MSG_NOTICE(Disabling ASN tracing)
  AC_SUBST(NOTRACE, 1)
fi

dnl ########################################################################
dnl Enable audio subsystems

dnl MSWIN_DISPLAY audio,Audio Software Codecs
dnl MSWIN_DEFINE  audio,H323_AUDIO_CODECS

AC_ARG_ENABLE(audio,
       [  --disable-audio         disable audio codecs])

if test "${enable_audio}z" = "z" ; then
  enable_audio=yes
fi

if test "$enable_audio" = "no" ; then
  AC_MSG_NOTICE(Disabling audio functions)
  AC_SUBST(NOAUDIOCODECS, 1)
else
  AC_DEFINE(H323_AUDIO_CODECS, 1)

  AC_ARG_ENABLE(embeddedgsm,
         [  --enable-embeddedgsm    embed GSM codec via static linking],
         EMBEDDED_GSM=$enableval)
  if test "${EMBEDDED_GSM}x" != "x" ; then
    AC_MSG_NOTICE(Embedding GSM codec)
    LDFLAGS="$LDFLAGS -L${OPENH323DIR}/plugins/audio/GSM0610"
    ENDLDLIBS="$ENDLDLIBS -lgsm0610_audio_s"
    AC_CHECK_LIB(gsm, gsm_create, GSM=1)
    if test "x$GSM" != "x"; then
      ENDLDLIBS="$ENDLDLIBS -lgsm"
    fi
    AC_DEFINE(H323_EMBEDDED_GSM)
  fi
fi

dnl ########################################################################
dnl Enable video subsystems

dnl MSWIN_DISPLAY video,Video System
dnl MSWIN_DEFINE  video,H323_VIDEO

AC_ARG_ENABLE(video,
       [  --disable-video         disable video functions])

if test "${enable_video}z" = "z" ; then
  enable_video=$default_video
fi

if test "$enable_video" = "no" ; then
  AC_MSG_NOTICE(Disabling video support)
  AC_SUBST(NOVIDEO, 1)
else
  AC_DEFINE(H323_VIDEO, 1)
fi

dnl ########################################################################
dnl look for avcodec compatible with RFC 2190

dnl MSWIN_DISPLAY    rfc2190,ffmpeg RFC2190 AVCODEC Library
dnl MSWIN_CHECK_FILE rfc2190,avcodec_rfc2190.h,H323_RFC2190_AVCODEC=1
dnl MSWIN_DIR_SYMBOL rfc2190,H323_RFC2190_AVCODEC_DIR
dnl MSWIN_CHECK_DIR  rfc2190,..\ffmpeg\libavcodec\
dnl MSWIN_CHECK_DIR  rfc2190,..\external\ffmpeg\libavcodec\
dnl MSWIN_CHECK_DIR  rfc2190,\ffmpeg\libavcodec\
dnl MSWIN_CHECK_DIR  rfc2190,c:\ffmpeg\libavcodec\

H323_RFC2190_AVCODEC=
H323_RFC2190_AVCODEC_DIR=
H323_AVCODEC=
H323_VICH263=

if test "$enable_video" = "yes" ; then

  AC_ARG_ENABLE(rfc2190avcodec,
         [  --enable-rfc2190avcodec   set directory for H263 using RFC2190-compatible ffmpeg])

  if test "${enable_rfc2190avcodec}x" = "x" ; then
    AC_MSG_NOTICE(Skipping tests for RFC 2190 H.263 support)
  else
    AC_MSG_NOTICE(Checking for RFC2190 H.263 codec)
    H323_RFC2190_AVCODEC_DIR=$enable_rfc2190avcodec
    AC_CHECK_HEADER(${H323_RFC2190_AVCODEC_DIR}/avcodec.h, H323_RFC2190_AVCODEC=1)
    if test "${H323_RFC2190_AVCODEC}" == "1" ; then
      AC_DEFINE(H323_RFC2190_AVCODEC)
      H323_RFC2190_AVCODEC=1
      H323_RFC2190_AVCODEC_DIR=${H323_RFC2190_AVCODEC_DIR}
      STDCCFLAGS="${STDCCFLAGS} -I${H323_RFC2190_AVCODEC_DIR}"
    fi
  fi

  dnl ########################################################################
  dnl look for avcodec from library.

  dnl MSWIN_DISPLAY    ffh263,ffmpeg AVCODEC Library
  dnl MSWIN_CHECK_FILE ffh263,avcodec.h,H323_AVCODEC=1
  dnl MSWIN_DIR_SYMBOL ffh263,H323_AVCODEC_DIR
  dnl MSWIN_CHECK_DIR  ffh263,..\ffmpeg\libavcodec\
  dnl MSWIN_CHECK_DIR  ffh263,..\external\ffmpeg\libavcodec\
  dnl MSWIN_CHECK_DIR  ffh263,\ffmpeg\libavcodec\
  dnl MSWIN_CHECK_DIR  ffh263,c:\ffmpeg\libavcodec\
  dnl MSWIN_IF_FEATURE ffh263,!rfc2190

  AC_ARG_ENABLE(h263avcodec,
         [  --enable-h263avcodec  enable search for H.263 using non-RFC2190-compatible ffmpeg])
  if test "${enable_h263avcodec}z" = "z" ; then
    enable_h263avcodec=$default_h263avcodec
  fi

  if test "$enable_h263avcodec" = "no" ; then
    AC_MSG_NOTICE(Disabled non-RFC2190 H.263 using ffmpeg)
  else
    AC_CHECK_HEADERS(avcodec.h, H323_AVCODEC=1)

    if test "${H323_AVCODEC}z" != "z" ; then
      AC_CHECK_LIB(avcodec, avcodec_open, H323_AVCODEC=1, H323_AVCODEC=)
    fi

    if test "${H323_AVCODEC}z" != "z" ; then
      AC_CHECK_FILE(/usr/local/include/ffmpeg/avcodec.h, H323_AVCODEC=1)
    fi

    if test "${H323_AVCODEC}z" = "z" ; then
      AC_MSG_NOTICE(Unable to find non-RFC2190 H.263 using ffmpeg)
    else
      H323_AVCODEC=1
      AC_DEFINE(H323_AVCODEC, 1, "ffmpeg based avodec found")
      AVCODECINCLUDEDIR=/usr/local/include/ffmpeg
      AVCODECLIBDIR=/usr/local/lib
      STDCCFLAGS="$STDCCFLAGS -I${AVCODECINCLUDEDIR}"

      AC_MSG_NOTICE(Enabled non-RFC2190 H.263 using ffmpeg)
    fi
  fi

  dnl ########################################################################
  dnl look for vich263 library

  dnl MSWIN_DISPLAY    vich263,VIC H.263 Library
  dnl MSWIN_CHECK_FILE vich263,encoder-h263.h,H323_VICH263=1
  dnl MSWIN_DIR_SYMBOL vich263,H323_VICH263_DIR
  dnl MSWIN_CHECK_DIR  vich263,..\vich263\
  dnl MSWIN_CHECK_DIR  vich263,..\external\vich263\
  dnl MSWIN_CHECK_DIR  vich263,\vich263\
  dnl MSWIN_CHECK_DIR  vich263,c:\vich263\
  dnl MSWIN_IF_FEATURE vich263,!rfc2190,!ffh263

  AC_ARG_ENABLE(vich263,
         [  --enable-vich263        enable search for H.263 using VIC])
  if test "${enable_vich263}z" = "z" ; then
    enable_vich263=$default_vich263
  fi

  if test "$enable_vich263" = "no" ; then
    AC_MSG_NOTICE(Disabled H.263 using VIC)
  else
    AC_CHECK_HEADERS(encoder-h263.h, H323_VICH263=1)
    if test "${H323_VICH263}z" != "z" ; then
      AC_CHECK_FILE(/usr/local/lib/libvich263.so, H323_VICH263=1, H323_VICH263=)
    fi

    if test "${H323_VICH263}z" != "z" ; then
     AC_CHECK_FILE(/usr/local/include/vich263/encoder-h263.h, H323_VICH263=1)
    fi

    if test "${H323_VICH263}z" = "z" ; then
      AC_MSG_NOTICE(Unable to find H.263 using VIC)
    else
      H323_VICH263=1
      AC_DEFINE(H323_VICH263, 1, "vic H263 codec found")
      VICH263INCLUDEDIR=/usr/local/include/vich263
      VICH263LIBDIR=/usr/local/lib
      STDCCFLAGS="$STDCCFLAGS -I${VICH263INCLUDEDIR}"
      AC_MSG_NOTICE(Enabled H.263 using VIC)
    fi
  fi
fi

AC_SUBST(H323_RFC2190_AVCODEC)
AC_SUBST(H323_RFC2190_AVCODEC_DIR)
AC_SUBST(H323_AVCODEC)
AC_SUBST(H323_VICH263)


dnl ########################################################################
dnl look for Transnexus OSP Toolkit

dnl MSWIN_DISPLAY    transnexus_osp,Transnexus OSP Toolkit
dnl MSWIN_CHECK_FILE transnexus_osp,include/osp/ospcryptowrap.h,H323_TRANSNEXUS_OSP=1
dnl MSWIN_DIR_SYMBOL transnexus_osp,H323_TRANSNEXUS_OSP_DIR
dnl MSWIN_CHECK_DIR  transnexus_osp,lib\
dnl MSWIN_CHECK_DIR  transnexus_osp,pthread\lib
dnl MSWIN_CHECK_DIR  transnexus_osp,pthread\include

AC_ARG_ENABLE(transnexusosp,
       [  --disable-transnexusosp disable support for the Transnexus OSP toolkit])

if test "${enable_transnexusosp}z" = "z" ; then
  enable_transnexusosp=$default_transnexusosp
fi

OLD_LDFLAGS=$LDFLAGS

if test "$enable_transnexusosp" = "no" ; then
  AC_MSG_NOTICE(Disabling support for the Transnexus OSP toolkit)
else
  AC_CHECK_HEADERS(osp/osp.h, HAS_TRANSNEXUS_OSP=1)
  if test "${HAS_TRANSNEXUS_OSP}x" = "1x" ; then
    AC_CHECK_LIB(osp, OSPPInit, HAS_TRANSNEXUS_OSP=1, HAS_TRANSNEXUS_OSP=, -lssl)
    if test "${HAS_TRANSNEXUS_OSP}x" = "1x" ; then
      H323_TRANSNEXUS_OSP=1
      AC_DEFINE(H323_TRANSNEXUS_OSP)
      LDLIBS="${LDLIBS} -losp"
      OSP_INCLUDE="#include <osp/osp.h>"
    else
      unset ac_cv_lib_osp_OSPPInit
      LDFLAGS="-L/usr/local/lib $OLD_LDFLAGS"
      AC_CHECK_LIB(osp, OSPPInit, HAS_TRANSNEXUS_OSP=1, HAS_TRANSNEXUS_OSP=, -lssl)
      if test "${HAS_TRANSNEXUS_OSP}x" = "1x" ; then
        H323_TRANSNEXUS_OSP=1
        AC_DEFINE(H323_TRANSNEXUS_OSP)
        STDCCFLAGS="$STDCCFLAGS -I/usr/local/include"
        LDLIBS="${LDLIBS} -losp"
        OSP_INCLUDE='#include "/usr/local/include/osp/osp.h"'
      else
        unset ac_cv_lib_osp_OSPPInit
        LDFLAGS="$OLD_LDFLAGS"
        AC_CHECK_LIB(osptk, OSPPInit, HAS_TRANSNEXUS_OSP=1, HAS_TRANSNEXUS_OSP=, -lssl)
        if test "${HAS_TRANSNEXUS_OSP}x" = "1x" ; then
          H323_TRANSNEXUS_OSP=1
          AC_DEFINE(H323_TRANSNEXUS_OSP)
          LDLIBS="${LDLIBS} -losptk"
          OSP_INCLUDE="#include <osp/osp.h>"
        else
          unset ac_cv_lib_osp_OSPPInit
          LDFLAGS="-L/usr/local/lib $OLD_LDFLAGS"
          AC_CHECK_LIB(osptk, OSPPInit, HAS_TRANSNEXUS_OSP=1, HAS_TRANSNEXUS_OSP=, -lssl)
          if test "${HAS_TRANSNEXUS_OSP}x" = "1x" ; then
            H323_TRANSNEXUS_OSP=1
            AC_DEFINE(H323_TRANSNEXUS_OSP)
            STDCCFLAGS="$STDCCFLAGS -I/usr/local/include"
            LDLIBS="${LDLIBS} -losptk"
            OSP_INCLUDE='#include "/usr/local/include/osp/osp.h"'
          fi
        fi
      fi
    fi
  fi
fi

LDFLAGS=$OLD_LDFLAGS

if test "${H323_TRANSNEXUS_OSP}x" != "x" ; then
  if test "${OSP_INCLUDE}x" != "x" ; then
    AC_MSG_CHECKING(for new OSP toolkit API)
    AC_TRY_COMPILE(${OSP_INCLUDE},
      [int main(int ac,char **av) { OSPTTRANHANDLE h; OSPTTIME t; OSPPTransactionReportUsage(h, 0, t, 0, 0, 0, 0, NULL, NULL); return 0; } ], H323_NEW_OSP_API=, H323_NEW_OSP_API=1)
    if test "${H323_NEW_OSP_API}x" != "x" ; then
      AC_MSG_RESULT(yes)
      AC_DEFINE(H323_NEW_OSP_API)
    else
      AC_MSG_RESULT(no)
    fi
  fi
fi

AC_SUBST(H323_TRANSNEXUS_OSP)

dnl ########################################################################
dnl check for disabling T.38

dnl MSWIN_DISPLAY t38,T.38
dnl MSWIN_DEFINE  t38,H323_T38

AC_ARG_ENABLE(t38,
       [  --disable-t38           disable T.38])
if test "${enable_t38}x" = "x" ; then
  enable_t38=$default_t38
fi
if test "$enable_t38" = "yes" ; then
  AC_MSG_NOTICE(Enabling T.38)
  H323_T38=1
  AC_DEFINE(H323_T38, 1)
else
  H323_T38=
  AC_MSG_NOTICE(Disabling T.38)
fi
AC_SUBST(H323_T38)

dnl ########################################################################
dnl check for disabling H.248

dnl MSWIN_DISPLAY h248,H.248
dnl MSWIN_DEFINE  h248,H323_H248

AC_ARG_ENABLE(h248,
       [  --disable-h248          enable H.248])
if test "${enable_h248}x" = "x" ; then
  enable_h248=$default_h248
fi
if test "$enable_h248" = "yes" ; then
  H323_H248=1
  AC_DEFINE(H323_H248, 1)
else
  H323_H248=
  AC_MSG_NOTICE(Disabling H.248)
fi
AC_SUBST(H323_H248)

dnl ########################################################################
dnl check for disabling H.450

dnl MSWIN_DISPLAY h450,H.450
dnl MSWIN_DEFINE  h450,H323_H450

AC_ARG_ENABLE(h450,
       [  --disable-h450          disable H.450])
if test "${enable_h450}x" = "x" ; then
  enable_h450=$default_h450
fi
if test "$enable_h450" = "yes" ; then
  H323_H450=1
  AC_DEFINE(H323_H450, 1)
else
  H323_H450=
  AC_MSG_NOTICE(Disabling H.450)
fi
AC_SUBST(H323_H450)

dnl ########################################################################
dnl check for disabling H.460

dnl MSWIN_DISPLAY h460,H.460
dnl MSWIN_DEFINE  h460,H323_H460

AC_ARG_ENABLE(h460,
       [  --disable-h460          disable H.460])
if test "${enable_h460}x" = "x" ; then
  enable_h460=$default_h460
fi
if test "$enable_h460" = "yes" ; then
  H323_H460=1
  AC_DEFINE(H323_H460, 1)
else
  H323_H460=
  AC_MSG_NOTICE(Disabling H.460)
fi
AC_SUBST(H323_H460)

dnl ########################################################################
dnl check for disabling H.501

dnl MSWIN_DISPLAY h501,H.501
dnl MSWIN_DEFINE  h501,H323_H501

AC_ARG_ENABLE(h501,
       [  --disable-h501          disable H.501])
if test "${enable_h501}x" = "x" ; then
  enable_h501=$default_h501
fi
if test "$enable_h501" = "yes" ; then
  H323_H501=1
  AC_DEFINE(H323_H501, 1)
else
  H323_H501=
  AC_MSG_NOTICE(Disabling H.501)
fi
AC_SUBST(H323_H501)

dnl ########################################################################
dnl check for enabling T.120

dnl MSWIN_DISPLAY t120,T.120
dnl MSWIN_DEFINE  t120,H323_T120

AC_ARG_ENABLE(t120,
       [  --disable-t120          disable T.120])
if test "${enable_t120}x" = "x" ; then
  enable_t120=$default_t120
fi
if test "$enable_t120" = "no" ; then
  H323_T120=
  AC_MSG_NOTICE(Disabling T.120)
else
  H323_T20=1
  AC_DEFINE(H323_T120, 1)
fi
AC_SUBST(H323_T120)

dnl ########################################################################

dnl ########################################################################
dnl
dnl feature detections migrated from Makefile
dnl 
dnl MSWIN_DISPLAY ixj,Quicknet Internet xJACK cards
dnl MSWIN_DEFINE  ixj,HAS_IXJ

AC_ARG_ENABLE(ixj,
       [  --disable-ixj           disable Quicknet card support])
if test "${enable_ixj}x" = "x" ; then
  enable_ixj=$default_ixj
fi

HAS_IXJ=
H323_IXJ=
if test "$enable_ixj" = "no" ; then
  AC_MSG_NOTICE(Disabling IXJ support)
else
  AC_CHECK_HEADERS(linux/telephony.h sys/telephony.h /usr/local/include/sys/telephony.h, HAS_IXJ=1)
  if test "${HAS_IXJ}z" != "z" ; then
    AC_MSG_CHECKING(if ixjuser.h actually compiles)
    AC_TRY_COMPILE([#include <linux/ixjuser.h>],
                   [int main(int ac,char **av) { return 0; }], HAS_IXJ=1, HAS_IXJ=)
    if test "x$HAS_IXJ" != "x" ; then
      H323_IXJ=1
      AC_DEFINE(HAS_IXJ, 1)
      AC_MSG_RESULT(yes)
    else
      AC_MSG_RESULT(no)
    fi
  fi
fi
AC_SUBST(H323_IXJ)

dnl ########################################################################
dnl make directives

AC_SUBST(STDCCFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LDLIBS)
AC_SUBST(ENDLDLIBS)
AC_PROG_INSTALL

AC_CONFIG_FILES(openh323u.mak)
AC_CONFIG_FILES(Makefile)


dnl ########################################################################
dnl Header file

AC_CONFIG_HEADERS(include/openh323buildopts.h)


dnl ########################################################################
dnl Output configured files

AC_CONFIG_SUBDIRS(plugins)

AC_OUTPUT()


dnl ########################################################################
dnl check if upad128_t is defined (Solaris)

if test "${OSTYPE:-unknown}" = "solaris"; then
  AC_MSG_CHECKING(for upad128_t)
  AC_TRY_COMPILE([#include <sys/types.h>],
                 [upad128_t upad; upad._q = 0.0;], has_upad128_t=y)
  if test ${has_upad128_t} == "y"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(P_HAS_UPAD128_T)
  else
    AC_MSG_RESULT(no)
  fi
fi


