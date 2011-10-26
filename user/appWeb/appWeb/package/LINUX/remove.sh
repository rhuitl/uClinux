#!/bin/bash
#
#	Removal script for Mbedthis AppWeb
#
#	Usage: remove [configFile]
#
################################################################################
#
#	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#	The latest version of this code is available at http://www.mbedthis.com
#
#	This software is open source; you can redistribute it and/or modify it 
#	under the terms of the GNU General Public License as published by the 
#	Free Software Foundation; either version 2 of the License, or (at your 
#	option) any later version.
#
#	This program is distributed WITHOUT ANY WARRANTY; without even the 
#	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
#	See the GNU General Public License for more details at:
#	http://www.mbedthis.com/downloads/gplLicense.html
#	
#	This General Public License does NOT permit incorporating this software 
#	into proprietary programs. If you are unable to comply with the GPL, a 
#	commercial license for this software and support services are available
#	from Mbedthis Software at http://www.mbedthis.com
#
################################################################################
#
#	The configFile is of the format:
#		useRPM=[YN]						# Use RPM packages or tar balls
#		removeBin=[YN]					# Remove the installed binary
#
# NOTE: We require a saved setup file exist in /etc/Mbedthis AppWebInstall.conf
#

home=`pwd`
binName=appWeb-!!BLD_VERSION!!-!!BLD_NUMBER!!
docName=appWeb-doc-!!BLD_VERSION!!-!!BLD_NUMBER!!
useRPM=N
removeBin=Y
removeDoc=Y
#runDaemon=N

###############################################################################
# 
# Get a yes/no answer from the user. Usage: ans=`yesno "prompt" "default"`
# Echos 1 for Y or 0 for N
#

yesno() {
	echo -n "$1 [$2] : " 1>&2
	while [ 1 ] 
	do
		read ans
		if [ "$ans" = "" ]
		then echo $2 ; break
		elif [ "$ans" = "Y" -o "$ans" = "y" ]
		then echo "Y" ; break
		elif [ "$ans" = "N" -o "$ans" = "n" ]
		then echo "N" ; break
		fi
		echo -e "\nMust enter a 'y' or 'n'\n " 1>&1
	done
}

###############################################################################
#
#	Instruct a running GXP to exit
#
remove() {
	if [ "$removeBin" = "Y" ] 
	then
		if [ -f /usr/sbin/appWeb ] 
		then
			/sbin/service appWeb stop 2>&1 >/dev/null
			pid=`pidof /usr/sbin/appWeb`
			[ "$pid" != "" ] && kill -9 $pid
			rm -f /var/lock/subsys/appWeb
			rm -f /var/log/appWeb
			rm -rf /var/run/appWeb
		fi
	fi

	if [ "$useRPM" = "Y" ]
	then
		if [ "$removeDoc" = "Y" ] 
		then
			cd $docDir/samples
			make clean 2>&1 >/dev/null
			cd $docDir
			echo "Running \"rpm -e $docName\""
			removeIntermediateFiles '*.o' '*.lo' '*.so' '*.a' make.rules 
			removeIntermediateFiles .config.h.sav make.log .changes
			rpm -e $docName
			cleanDir
			rmdir $docDir 2>/dev/null
		fi
		if [ "$removeBin" = "Y" ] 
		then
			echo "Running \"rpm -e $binName\""
			cd $binDir
			removeIntermediateFiles access.log error.log '*.log.old' \
				appWeb.conf .appWeb_pid.log '.httpClient_pid.log' make.log
			rpm -e $binName
			cleanDir
			rmdir $binDir 2>/dev/null
			if [ -x $incDir ]
			then
				cd $incDir
				cleanDir
				rmdir $incDir 2>/dev/null
			fi
		fi
	else
		if [ "$removeDoc" = "Y" ]
		then
			cd $docDir/samples
			rm -f needConfigure needBuild
			LD_LIBRARY_PATH=$LD_LIBRARY_PATH:ANYTHING_WITH_bin
			make BUILD_CHECK= clean 2>&1 >/dev/null
			cd $docDir/..
			removeFiles $docDir/fileList.txt
			cd $docDir
			removeIntermediateFiles '*.o' '*.lo' '*.so' '*.a' make.rules
			removeIntermediateFiles .config.h.sav make.log .changes
			cleanDir
			rmdir $docDir 2>/dev/null
		fi
		if [ "$removeBin" = "Y" ]
		then
			/sbin/chkconfig --del appWeb
			rm /etc/rc.d/init.d/appWeb
			cd /
			removeFiles $binDir/fileList.txt
			cd $binDir
			removeIntermediateFiles access.log error.log '*.log.old' appWeb.conf
			cleanDir
			rmdir $binDir 2>/dev/null
			if [ -x $incDir ]
			then
				cd $incDir
				cleanDir
				rmdir $incDir 2>/dev/null
			fi
		fi
		if [ "$removeBin" = "Y" -a "$removeDoc" = "Y" ]
		then
			rm -f /etc/appWeb.conf
		fi
		if [ ! -d $binDir -a ! -d $docDir ]
		then
			rm -f /etc/appWeb.conf
		fi

		cd /var/appWeb
		cleanDir
		rmdir /var/appWeb 2>/dev/null
	fi
	echo
	echo "Mbedthis AppWeb removal successful"
}

###############################################################################
#
# Clean a directory. Usage: removeFiles fileList
#

removeFiles() {
	if [ ! -f $1 ]
	then
		echo "Can't find file list: $1, continuing ..."
	fi
	echo "Removing files using the file list: $1 ..."
	cat $1 | while read f
	do
		rm -f "$f"
	done
}

###############################################################################
#
# Cleanup empty directories. Usage: cleanDir directory
#
cleanDir() {

	echo "Cleaning `pwd` ..."
	if [ `pwd` = "/" ]
	then
		echo "Configuration error: clean directory was '/'"
		return
	fi
	find . -type d -print | sort -r | grep -v '^\.$' | while read d
	do
		count=`ls "$d" | wc -l | sed -e 's/ *//'`
		[ "$count" = "0" ] && rmdir "$d"
		if [ "$count" != "0" ] 
		then 
			f=`echo "$d" | sed -e 's/\.\///'`
			echo "Directory `pwd`/${f}, still has user data"
		fi
	done 
}

###############################################################################
#
# Cleanup intermediate files
#
removeIntermediateFiles() {

	find `pwd` -type d -print | while read d
	do
		before=`pwd`
		cd "${d}"
		eval rm -f $*
		cd "${before}"
	done
}

###############################################################################
#
# Main program for remove script
#

if [ `id -u` != "0" ]
then
	echo "You must be root to remove this product."
	exit 255
fi

#
# Get defaults from the installation configuration file
#
if [ ! -f /etc/appWebInstall.conf ]
then
	echo "Can't locate the /etc/appWebInstall.conf setup file"
	echo "Can't locate the installed product to remove it using \"remove\"."
	echo "If you installed using the bare RPM images, use"
	echo "rpm -e appWeb"
	echo "If all else fails, try re-installing to repair the"
	echo "missing file and then run the removal script again".
	exit 255
fi

.  /etc/appWebInstall.conf
[ "$installBin" = "N" ] && removeBin="N"

#
# Headless removal. Expect an argument that supplies a config file.
#
if [ $# -ge 1 ]
then
	if [ ! -f $1 ]
	then
		echo "Could not find config file \"$1\""
		exit 255
	else
		. $1 
		remove
	fi
	exit 0
fi

echo -e "\nMbedthis AppWeb !!BLD_VERSION!!-!!BLD_NUMBER!! Removal\n"

if [ ! -d $binDir -a ! -d $docDir ]
then
	echo "Can't find either a binary package for Mbedthis AppWeb "
	echo "to remove."
	exit 255
fi

echo "Enter requested information or press <ENTER> to accept the defaults. "

#
# Confirm the configuration
#
finished=N
while [ "$finished" = "N" ]
do
	echo
	if [ -r $binDir/remove ]
	then
		removeBin=`yesno "Remove binary package" "$removeBin"`
	else
		removeBin=N
	fi
	if [ -r $docDir/remove ]
	then
		removeDoc=`yesno "Remove documentation and samples package" "$removeDoc"`
	else
		removeDoc=N
	fi

	echo -e "\nProceed removing with these instructions:" 
	echo -e "    Remove binary package: $removeBin"
	echo -e "    Remove documentation and samples package: $removeDoc"

	echo
	finished=`yesno "Accept these instructions" "Y"`
done

#
# Do the real work
#
remove

##
##  Local variables:
##  tab-width: 4
##  c-basic-offset: 4
##  End:
##  vim:tw=78
##  vim600: sw=4 ts=4 fdm=marker
##  vim<600: sw=4 ts=4
##
