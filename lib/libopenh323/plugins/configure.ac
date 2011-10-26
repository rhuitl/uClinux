AC_INIT(configure.ac)

AC_PROG_CXX
AC_HEADER_STDC

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
AC_CANONICAL_TARGET()
LDSO=
case "$target_os" in
	solaris*) LDSO="-Bdynamic -G -h" ;;
        darwin*)  ;;
        *)        LDSO="-shared -Wl,-soname,";;
esac
AC_SUBST(LDSO, ${LDSO})

dnl ########################################################################
dnl look for amr-nb_float

H323_GSMAMR_NB_FLOAT=0
if test -r "./audio/gsm-amr/src/c-code/interf_dec.h" ; then
  AC_MSG_NOTICE(Enabling GSM-AMR plugin)
  H323_GSMAMR_NB_FLOAT=1
else
  AC_MSG_NOTICE(GSM-AMR plugin disabled (no 3GPP source))
fi
AC_SUBST(H323_GSMAMR_NB_FLOAT, $H323_GSMAMR_NB_FLOAT)


dnl ########################################################################
dnl look for embedded GSM

H323_EMBEDDED_GSM=0
AC_ARG_ENABLE(embeddedgsm,
       [  --enable-embeddedgsm    embed GSM codec via static linking],
       H323_EMBEDDED_GSM=$enableval)
if test "${H323_EMBEDDED_GSM}" != "0" ; then
  AC_MSG_NOTICE(Embedding GSM codec)
  LDFLAGS="$LDFLAGS -L../../plugins/audio/GSM0610"
  ENDLDLIBS="$ENDLDLIBS -libgsm0610_audio"
  AC_DEFINE(H323_EMBEDDED_GSM)
  H323_EMBEDDED_GSM=1
fi
AC_SUBST(H323_EMBEDDED_GSM, $H323_EMBEDDED_GSM)

dnl ########################################################################
dnl Look for system GSM
dnl
dnl Note that we can only use llibgsm if it is compiled with WAV49
dnl

H323_SYSTEM_GSM=0
localgsm="xxx"
AC_ARG_ENABLE(localgsm,
       [  --enable-localgsm         use local version of GSM library rather than system version],
       localgsm=$enableval)

if test "${localgsm}" = "yes" ; then
  AC_MSG_NOTICE(Forcing use of local GSM sources)
elif test "${localgsm}" = "no" ; then
  AC_MSG_NOTICE(Forcing use of system GSM library)
  H323_SYSTEM_GSM=1
else
  AC_CHECK_LIB(gsm, gsm_create, GSM=1)
  if test "x$GSM" != "x"; then
    AC_MSG_CHECKING(if system GSM library has WAV49)
    OLD_LIBS=$LIBS
    LIBS="-lgsm"
    AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([[
    #include <gsm.h>
]],[[
    int option = 0;
    gsm handle = gsm_create();
    return (gsm_option(handle, GSM_OPT_WAV49, &option) == -1) ? 1 : 0;
]])], GSM=2) 
    if test "x$GSM" == "x2"; then
      H323_SYSTEM_GSM=1
      AC_MSG_RESULT(yes)
      AC_MSG_NOTICE(Using system gsm)
    else
      AC_MSG_RESULT(no)
    fi
    LIBS=$OLD_LIBS
  fi
fi
AC_SUBST(H323_SYSTEM_GSM, $H323_SYSTEM_GSM)
AC_DEFINE_UNQUOTED(H323_SYSTEM_GSM, $H323_SYSTEM_GSM)

dnl ########################################################################
dnl Look for system libspeex

localspeex="xxx"
AC_ARG_ENABLE(localspeex,
       [  --enable-localspeex       use local version of Speex library rather than system version],
       localspeex=$enableval)

if test "${localspeex}" = "yes" ; then
  AC_MSG_NOTICE(Forcing use of local Speex sources)
elif test "${localspeex}" = "no" ; then
  AC_MSG_NOTICE(Forcing use of system Speex library)
  AC_DEFINE(H323_SYSTEM_SPEEX, 1)
  AC_SUBST(H323_SYSTEM_SPEEX, 1)
else
  AC_CHECK_LIB(speex, speex_encoder_destroy, SPEEX=1)
  if test "x$SPEEX" = "x"; then
    AC_MSG_NOTICE(Forcing use of local Speex library)
  else
    AC_MSG_CHECKING(system Speex version)
    cat > t.c <<C_FILE
    #include <speex.h>
    #include <speex_header.h>
    #include <stdio.h>
    int main(int argc,char *argv[])
    {
      SpeexHeader header;
      speex_init_header(&header, 1, 1, &speex_nb_mode);
      printf("%s\n", header.speex_version);
    }
C_FILE
    cc -o t t.c -lspeex > /dev/null 2>&1
    if test \! -x t ; then
      AC_MSG_RESULT(cannot determine - using library version)
    else
      SYSVER=`./t`
      rm -f t t.c
      AC_MSG_RESULT($SYSVER)
      AC_MSG_CHECKING(library Speex version)
      LIBVER=`grep "#define VERSION" ./audio/Speex/libspeex/misc.h | sed -e 's/^.*speex\-//' -e 's/\"//'`
      AC_MSG_RESULT($LIBVER)
      AC_MSG_CHECKING(Speex versions)
      cat > t.pl <<P_FILE
      [
      \$sysver = @ARGV[0];
      \$libver = @ARGV[1];
      @lib = split /\./, \$libver;
      while (@lib < 3) {
        @lib[0+@lib] = "0";
      }
      @sys = split /\./, \$sysver;
      while (@sys < 3) {
        @sys[0+@sys] = "0";
      }
      \$i = 0;
      while (\$i < 3) {
        #print "comparing " . @sys[\$i] . " and " . @lib[\$i] . "\n";
        if (\@sys[\$i] < @lib[\$i]) {
          print "0";
          die;
        }
        \$i++;
      }
      print "1";
      ]
P_FILE
      SPEEX=`perl t.pl $SYSVER $LIBVER`
      rm t.pl
      if test "x$SPEEX" = "x" ; then
        AC_MSG_RESULT(library version is more recent)
      else
        AC_MSG_RESULT(system version is more recent)
        AC_DEFINE(H323_SYSTEM_SPEEX, 1)
        AC_SUBST(H323_SYSTEM_SPEEX, 1)
      fi
    fi
  fi
fi

dnl ########################################################################

AC_CONFIG_FILES(audio/gsm-amr/Makefile)
AC_CONFIG_FILES(audio/GSM0610/Makefile)
AC_CONFIG_FILES(audio/iLBC/Makefile)
AC_CONFIG_FILES(audio/Speex/Makefile)
AC_CONFIG_FILES(audio/LPC_10/Makefile)
AC_CONFIG_FILES(audio/G726/Makefile)
AC_CONFIG_FILES(audio/IMA_ADPCM/Makefile)

dnl ########################################################################
dnl Header file

dnl ########################################################################
dnl Output configured files

AC_OUTPUT()

