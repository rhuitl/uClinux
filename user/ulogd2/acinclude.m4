dnl @synopsis CT_CHECK_POSTGRES_DB
dnl
dnl This macro tries to find the headers and libraries for the
dnl PostgreSQL database to build client applications.
dnl
dnl If includes are found, the variable PQINCPATH will be set. If
dnl libraries are found, the variable PQLIBPATH will be set. if no check
dnl was successful, the script exits with a error message.
dnl
dnl @category InstalledPackages
dnl @author Christian Toepp <c.toepp@gmail.com>
dnl @version 2005-12-30
dnl @license AllPermissive

AC_DEFUN([CT_CHECK_POSTGRES_DB], [

AC_ARG_WITH(pgsql,
	[  --with-pgsql=PREFIX		Prefix of your PostgreSQL installation],
	[pg_prefix=$withval], [pg_prefix=])
AC_ARG_WITH(pgsql-inc,
	[  --with-pgsql-inc=PATH		Path to the include directory of PostgreSQL],
	[pg_inc=$withval], [pg_inc=])
AC_ARG_WITH(pgsql-lib,
	[  --with-pgsql-lib=PATH		Path to the libraries of PostgreSQL],
	[pg_lib=$withval], [pg_lib=])


AC_SUBST(PQINCPATH)
AC_SUBST(PQLIBPATH)
AC_SUBST(PQLIBS)
PQLIBS=-lpq

if test "$pg_prefix" != "no"; then

AC_MSG_CHECKING([for PostgreSQL pg_config program])
for d in $pg_prefix/bin /usr/bin /usr/local/bin /usr/local/pgsql/bin /opt/pgsql/bin /opt/packages/pgsql/bin
do
	if test -x $d/pg_config
	then
		AC_MSG_RESULT(found pg_config in $d)
		PQINCPATH=`$d/pg_config --includedir`
		PQLIBPATH=`$d/pg_config --libdir`
		break
	fi
done

if test "$PQINCPATH" = ""; then

if test "$pg_prefix" != ""; then
   AC_MSG_CHECKING([for PostgreSQL includes in $pg_prefix/include])
   if test -f "$pg_prefix/include/libpq-fe.h" ; then
      PQINCPATH="-I$pg_prefix/include"
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(libpq-fe.h not found)
   fi
   AC_MSG_CHECKING([for PostgreSQL libraries in $pg_prefix/lib])
   if test -f "$pg_prefix/lib/libpq.so" ; then
      PQLIBPATH="-L$pg_prefix/lib"
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(libpq.so not found)
   fi
else
  if test "$pg_inc" != ""; then
    AC_MSG_CHECKING([for PostgreSQL includes in $pg_inc])
    if test -f "$pg_inc/libpq-fe.h" ; then
      PQINCPATH="-I$pg_inc"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(libpq-fe.h not found)
    fi
  fi
  if test "$pg_lib" != ""; then
    AC_MSG_CHECKING([for PostgreSQL libraries in $pg_lib])
    if test -f "$pg_lib/libpq.so" ; then
      PQLIBPATH="-L$pg_lib"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(libpq.so not found)
    fi
  fi
fi

fi

if test "$PQINCPATH" = "" ; then
  AC_CHECK_HEADER([libpq-fe.h], [], AC_MSG_WARN(libpq-fe.h not found))
fi
if test "$PQLIBPATH" = "" ; then
  AC_CHECK_LIB(pq, PQconnectdb, [], AC_MSG_WARN(libpq.so not found))
fi

fi

])


dnl @synopsis CT_CHECK_MYSQL_DB
dnl
dnl This macro tries to find the headers and librariess for the
dnl MySQL database to build client applications.
dnl
dnl If includes are found, the variable MYSQL_INC will be set. If
dnl libraries are found, the variable MYSQL_LIB will be set. if no check
dnl was successful, the script exits with a error message.
dnl
dnl @category InstalledPackages
dnl @author Harald Welte <laforge@gnumonks.org>
dnl @version 2006-01-07
dnl @license AllPermissive

AC_DEFUN([CT_CHECK_MYSQL_DB], [

AC_ARG_WITH(mysql,
	[  --with-mysql=PREFIX		Prefix of your MySQL installation],
	[my_prefix=$withval], [my_prefix=])
AC_ARG_WITH(mysql-inc,
	[  --with-mysql-inc=PATH		Path to the include directory of MySQL],
	[my_inc=$withval], [my_inc=])
AC_ARG_WITH(mysql-lib,
	[  --with-mysql-lib=PATH		Path to the libraries of MySQL],
	[my_lib=$withval], [my_lib=])


AC_SUBST(MYSQL_INC)
AC_SUBST(MYSQL_LIB)

if test "$my_prefix" != "no"; then

AC_MSG_CHECKING([for MySQL mysql_config program])
for d in $my_prefix/bin /usr/bin /usr/local/bin /usr/local/mysql/bin /opt/mysql/bin /opt/packages/mysql/bin
do
	if test -x $d/mysql_config
	then
		AC_MSG_RESULT(found mysql_config in $d)
		MYSQL_INC=`$d/mysql_config --include`
		MYSQL_LIB=`$d/mysql_config --libs`
		break
	fi
done

if test "$MYSQL_INC" = ""; then

if test "$my_prefix" != ""; then
   AC_MSG_CHECKING([for MySQL includes in $my_prefix/include])
   if test -f "$my_prefix/include/mysql.h" ; then
      MYSQL_INC="-I$my_prefix/include"
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(mysql.h not found)
   fi
   AC_MSG_CHECKING([for MySQL libraries in $my_prefix/lib])
   if test -f "$my_prefix/lib/libmysql.so" ; then
      MYSQL_LIB="-L$my_prefix/lib -lmysqlclient"
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(libmysqlclient.so not found)
   fi
else
  if test "$my_inc" != ""; then
    AC_MSG_CHECKING([for MySQL includes in $my_inc])
    if test -f "$my_inc/mysql.h" ; then
      MYSQL_INC="-I$my_inc"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(mysql.h not found)
    fi
  fi
  if test "$my_lib" != ""; then
    AC_MSG_CHECKING([for MySQL libraries in $my_lib])
    if test -f "$my_lib/libmysqlclient.so" ; then
      MYSQL_LIB="-L$my_lib -lmysqlclient"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(libmysqlclient.so not found)
    fi
  fi
fi

fi

if test "$MYSQL_INC" = "" ; then
  AC_CHECK_HEADER([mysql.h], [], AC_MSG_WARN(mysql.h not found))
fi
if test "$MYSQL_LIB" = "" ; then
  AC_CHECK_LIB(mysqlclient, mysql_close, [], AC_MSG_WARN(libmysqlclient.so not found))
fi

fi

])

dnl @synopsis CT_CHECK_PCAP
dnl
dnl This macro tries to find the headers and libraries for libpcap.
dnl
dnl If includes are found, the variable PCAP_INC will be set. If
dnl libraries are found, the variable PCAP_LIB will be set. if no check
dnl was successful, the script exits with a error message.
dnl
dnl @category InstalledPackages
dnl @author Harald Welte <laforge@gnumonks.org>
dnl @version 2006-01-07
dnl @license AllPermissive

AC_DEFUN([CT_CHECK_PCAP], [

AC_ARG_WITH(pcap,
	[  --with-pcap=PREFIX		Prefix of your libpcap installation],
	[pcap_prefix=$withval], [pcap_prefix=])
AC_ARG_WITH(pcap-inc,
	[  --with-pcap-inc=PATH		Path to the include directory of pcap],
	[pcap_inc=$withval], [pcap_inc=/usr/include])
AC_ARG_WITH(pcap-lib,
	[  --with-pcap-lib=PATH		Path to the libraries of pcap],
	[pcap_lib=$withval], [pcap_lib=/usr/lib])


AC_SUBST(PCAP_INC)
AC_SUBST(PCAP_LIB)

if test "$pcap_prefix" != "no"; then

if test "$pcap_prefix" != ""; then
   AC_MSG_CHECKING([for libpcap includes in $pcap_prefix/include])
   if test -f "$pcap_prefix/include/pcap.h" ; then
      PCAP_INC="-I$pcap_prefix/include"
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(pcap.h not found)
   fi
   AC_MSG_CHECKING([for libpcap in $pcap_prefix/lib])
   if test -f "$pcap_prefix/lib/libpcap.so" ; then
      PCAP_LIB="-L$pcap_prefix/lib -lpcap";
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(libpcap.so not found)
   fi
else
  if test "$pcap_inc" != ""; then
    AC_MSG_CHECKING([for libpcap includes in $pcap_inc])
    if test -f "$pcap_inc/pcap.h" ; then
      PCAP_INC="-I$pcap_inc"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(pcap.h not found)
    fi
  fi
  if test "$pcap_lib" != ""; then
    AC_MSG_CHECKING([for libpcap in $pcap_lib])
    if test -f "$pcap_lib/libpcap.so" ; then
      PCAP_LIB="-L$pcap_lib -lpcap";
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(libpcap.so not found)
    fi
  fi
fi

if test "$PCAP_INC" = "" ; then
  AC_CHECK_HEADER([pcap.h], [], AC_MSG_WARN(pcap.h not found))
fi
if test "$PCAP_LIB" = "" ; then
  AC_CHECK_LIB(pcap, pcap_close, [], AC_MSG_WARN(libpcap.so not found))
fi

fi

])

dnl @synopsis CT_CHECK_SQLITE3_DB
dnl
dnl This macro tries to find the headers and libraries for the
dnl SQLITE3 database to build client applications.
dnl
dnl If includes are found, the variable SQLITE3_INC will be set. If
dnl libraries are found, the variable SQLITE3_LIB will be set. if no check
dnl was successful, the script exits with a error message.
dnl
dnl @category InstalledPackages
dnl @author Harald Welte <laforge@gnumonks.org>
dnl @version 2006-01-07
dnl @license AllPermissive

AC_DEFUN([CT_CHECK_SQLITE3_DB], [

AC_ARG_WITH(sqlite3,
	[  --with-sqlite3=PREFIX		Prefix of your SQLITE3 installation],
	[sqlite3_prefix=$withval], [sqlite3_prefix=])
AC_ARG_WITH(sqlite3-inc,
	[  --with-sqlite3-inc=PATH		Path to the include directory of MySQL],
	[sqlite3_inc=$withval], [sqlite3_inc=/usr/include])
AC_ARG_WITH(sqlite3-lib,
	[  --with-sqlite3-lib=PATH		Path to the libraries of MySQL],
	[sqlite3_lib=$withval], [sqlite3_lib=/usr/lib])


AC_SUBST(SQLITE3_INC)
AC_SUBST(SQLITE3_LIB)

if test "$sqlite3_prefix" != "no"; then

AC_MSG_CHECKING([for sqlite3 pkg-config program])
for d in $sqlite3_prefix/bin /usr/bin /usr/local/bin /usr/local/sqlite3/bin /opt/sqlite3/bin /opt/packages/sqlite3/bin
do
	if test -x $d/pkg-config
	then
		AC_MSG_RESULT(found pkg-config in $d)
		$d/pkg-config --exists sqlite3
		if test "$?" != "0"; then
			AC_MSG_RESULT(pkg-config doesn't know sqlite3)
			break
		fi
		SQLITE3_INC=`$d/pkg-config --cflags sqlite3`
		SQLITE3_LIB=`$d/pkg-config --libs sqlite3`
		break
	fi
done

if test "$SQLITE3_INC" = ""; then

if test "$sqlite3_prefix" != ""; then
   AC_MSG_CHECKING([for SQLITE3 includes in $sqlite3_prefix/include])
   if test -f "$sqlite3_prefix/include/sqlite3.h" ; then
      SQLITE3_INC="-I$sqlite3_prefix/include"
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(sqlite3.h not found)
   fi
   AC_MSG_CHECKING([for SQLITE3 libraries in $sqlite3_prefix/lib])
   if test -f "$sqlite3_prefix/lib/libsqlite3.so" ; then
      SQLITE3_LIB="-L$sqlite3_prefix/lib -lsqlite3"
      AC_MSG_RESULT([yes])
   else
      AC_MSG_WARN(libsqlite3.so not found)
   fi
else
  if test "$sqlite3_inc" != ""; then
    AC_MSG_CHECKING([for SQLITE3 includes in $sqlite3_inc])
    if test -f "$sqlite3_inc/sqlite3.h" ; then
      SQLITE3_INC="-I$sqlite3_inc"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(sqlite3.h not found)
    fi
  fi
  if test "$sqlite3_lib" != ""; then
    AC_MSG_CHECKING([for SQLITE3 libraries in $sqlite3_lib])
    if test -f "$sqlite3_lib/libsqlite3.so" ; then
      SQLITE3_LIB="-L$sqlite3_lib -lsqlite3"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_WARN(libsqlite3.so not found)
    fi
  fi
fi

fi

if test "$SQLITE3_INC" = "" ; then
  AC_CHECK_HEADER([sqlite3.h], [], AC_MSG_WARN(sqlite3.h not found))
fi
if test "$SQLITE3_LIB" = "" ; then
  AC_CHECK_LIB(sqlite3, sqlite3_close, [], AC_MSG_WARN(libsqlite3.so not found))
fi

fi

])
