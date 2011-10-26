#! /bin/bash

# Copyright (C) 2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
#  
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


: ${srcdir=.}
. ${srcdir}/testsuite/functions

outfile_err=`mktemp /tmp/ip-sentinel.check.XXXXXX`
outfile_out=`mktemp /tmp/ip-sentinel.check.XXXXXX`

trap "rm -f ${outfile_err} ${outfile_out}" EXIT

execfile=./simulate

function execprog()
{
    local ext=$(basename "$basefile")
    local cfg=
    local inp=
    ext=${ext##simulate-}

    case "$ext" in
	L-*|R-*) cfg=${srcdir}/testsuite/data/simulate.cfg
		 inp=${srcdir}/testsuite/data/simulate.inp
		 ;;
	*)	 cfg=${basefile}.cfg
		 inp=${basefile}.inp
		 ;;
    esac

    "$@" ${execfile} -i ${cfg} $(cat ${basefile}.cmd) eth0 \
    <${inp} 10>${outfile_out} 1>&10
}

function verify()
{
    sed -e "${REPLACE_REGEX}" ${outfile_out} |
	$DIFF ${basefile}.out - || exit 1
}


file ${execfile} | grep -q 'statically linked' || {
    exists ef       && { execprog ef 2>&1 | sed -e '1,2d'; } && verify
    exists valgrind && execprog valgrind --tool=memcheck -q --logfile-fd=10  && verify
}

execprog && verify
