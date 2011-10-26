#!/bin/bash
#
#	Installation script for Mbedthis AppWeb
#
# 	Usage: install [configFile]
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
#		docDir=documentationPath		# Where to install the doc
#		installBin=[YN]					# Install binary package
#		installDoc=[YN]					# Install doc package
#		runDaemon=[YN]					# Run the program as a daemon
#		httpPort=portNumber				# Http port to listen on
#		sslPort=portNumber				# SSL port to listen on
#

home=`pwd`
useRPM=N

site=127.0.0.1
page=/

baseName=appWeb-!!BLD_VERSION!!-!!BLD_NUMBER!!
binName=${baseName}-LINUX-i386
docName=appWeb-doc-!!BLD_VERSION!!-!!BLD_NUMBER!!

binRpmName=$binName.rpm
docRpmName=$docName.rpm

binPkgName=$binName.tar
docPkgName=$docName.tar

binDir="!!BLD_PREFIX!!"				# Fixed and can't be relocated
docDir=/usr/share/appWeb-!!BLD_VERSION!!
incDir=/usr/include/appWeb

installBin=Y
installDoc=Y

runDaemon=Y
httpPort=7777
sslPort=4443

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
# Get input from the user. Usage: ans=`ask "prompt" "default"`
# Returns the answer or default if <ENTER> is pressed
#

ask() {
	default=$2
	echo -n "$1 [$default] : " 1>&2
	read ans
	if [ "$ans" = "" ]
	then echo $default
	fi
	echo $ans
}

###############################################################################
#
# Save the setup
#

saveSetup() {
	#
	# Ensure the docDir is saved as an absolute path
	#
	firstChar=`echo $docDir | sed -e 's/\(.\).*/\1/'`
	[ "$firstChar" != "/" ] && docDir=`pwd`/$docDir
	firstChar=`echo $incDir | sed -e 's/\(.\).*/\1/'`
	[ "$firstChar" != "/" ] && incDir=`pwd`/$incDir

	echo -e "useRPM=$useRPM\nbinDir=$binDir\ndocDir=$docDir\nincDir=$incDir\ninstallBin=$installBin\ninstallDoc=$installDoc\nrunDaemon=$runDaemon\nhttpPort=$httpPort\nsslPort=$sslPort" >/etc/appWebInstall.conf
}

###############################################################################
# 
# Execute the install
#

install () {
	if [ "$useRPM" = "Y" ] 
	then
		#
		# Now extract the binary package
		#
		if [ $installBin = "Y" ]
		then
			echo -e "\nRunning \"rpm -Uhv $home/$binRpmName\""
			rpm -Uhv $home/$binRpmName
		fi
		if [ $installDoc = "Y" ]
		then
			firstChar=`echo $docDir | sed -e 's/\(.\).*/\1/'`
			[ "$firstChar" != "/" ] && docDir=`pwd`/$docDir
			echo
			echo "Running: \"rpm -Uhv --prefix=$docDir $home/$docRpmName\""
			rpm -Uhv --prefix=$docDir $home/$docRpmName
		fi
	else
		#
		# Now extract the binary package
		#
		if [ $installBin = "Y" ]
		then
			echo -e "\nRunning:"
			echo "cd /"
			cd /
			echo -e "tar xf $home/$binPkgName"
			gzip -dc $home/$binPkgName.gz | tar x
			cd $home
			#
			#	RPM installs do this in the spec file
			#
			rm -f /var/log/appWeb
			ln -s ${binDir}/logs /var/log/appWeb
			chmod 700 ${binDir}/logs 
		fi

		if [ $installDoc = "Y" ]
		then
			mkdir -p $docDir
			chmod 755 $docDir
			chown root.root $docDir
			echo -e "\nRunning:"
			echo "cd $docDir/.."
			#
			#	Files in the archive begin with ./doc or ./samples
			#
			cd $docDir/..
			echo "tar xf $home/$docPkgName"
			gzip -dc $home/$docPkgName.gz | tar x 
			cd $home
		fi
	fi

	#
	#	Create the configuration file /etc/appWeb/appWeb.conf
	#
	if [ "$installBin" = "Y" ] 
	then
		cd $binDir
		if [ ! -f appWeb.conf ] 
		then
			cat new.conf |
				sed -e "s!^Listen .*\(7777\)!Listen $httpPort!" | \
				sed -e "s!^Listen .*\(4443\)!Listen $sslPort!" | \
				sed -e "s!^\(ServerName http:[^:]*\).*!\1:$httpPort!" \
				>appWeb.conf
		fi
		cd $home
	fi

	pid=`pidof /usr/sbin/appWeb`
	if [ "$pid" != "" ] 
	then
		echo "Terminating Mbedthis AppWeb ..."
		kill -2 $pid
	fi

	if [ "$runDaemon" = "N" ]
	then
		:
	else
		/sbin/service appWeb stop >/dev/null
		/sbin/chkconfig --add appWeb
		/sbin/chkconfig --level 5 appWeb on
		/sbin/service appWeb start
	fi
	echo -e "\nMbedthis AppWeb installation successful."

	if [ $installBin = "Y" -a "$runDaemon" = "Y" ]
	then
		echo -e "\nStarting browser to view the Home Page."
		for f in /usr/bin/htmlview /usr/bin/mozilla /usr/bin/konqueror
		do
			if [ -x ${f} ]
			then
				${f} http://$site:$httpPort$page &
				break
			fi
		done
	fi
}

###############################################################################
#
# Main program for install script
#

if [ `id -u` != "0" ]
then
	echo "You must be root to install this product."
	exit 255
fi

#
# Headless install. Expect an argument that supplies an install config file.
#
if [ $# -ge 1 ]
then
	if [ ! -f $1 ]
	then
		echo "Could not find installation config file \"$1\"."
		exit 255
	else
		. $1 
		install
	fi
	exit 0
fi

#
# Try to guess if we should default to using RPM
#
[ -f $binRpmName ] && useRPM=Y

#
# Manual install
#
echo -e "\nMbedthis AppWeb !!BLD_VERSION!!-!!BLD_NUMBER!! Installation\n"

echo "Enter requested configuration information or press <ENTER> to accept"
echo -e "the defaults. "

#
# Confirm the configuration
#
finished=N
while [ "$finished" = "N" ]
do
	echo
	useRPM=`yesno "Use Red Hat Package Manager (RPM) to install" $useRPM`
	installBin=`yesno "Install binary package" "$installBin"`
	installDoc=`yesno "Install documentation and samples package" "$installDoc"`
	if [ "$installDoc" = "Y" -a "$useRPM" = "Y" ] 
	then
		docDir=`ask "Documentation and samples installation directory" $docDir`
	fi
	if [ "$installBin" = "Y" ]
	then
		runDaemon=`yesno "Start appWeb automatically at system boot" \
			$runDaemon`
		httpPort=`ask "Enter the HTTP port number" "$httpPort"`
		sslPort=`ask "Enter the SSL port number (zero to disable)" "$sslPort"`
	else
		runDaemon=N
	fi

	echo -e "\nInstalling with this configuration:" 
	echo -e "    Use RPM to install: $useRPM"
	echo -e "    Install binary package: $installBin"
	echo -e "    Install documentation and samples package: $installDoc"
	if [ "$installDoc" = "Y" ]
	then
		echo -e "    Documentation and samples installation directory: $docDir"
	fi
	if [ "$installBin" = "Y" ]
	then
		echo -e "    Start automatically at system boot: $runDaemon"
		echo -e "    HTTP port number: $httpPort"
		echo -e "    SSL port number: $sslPort"
	fi

	echo
	finished=`yesno "Accept this configuration" "Y"`
done

if [ $installBin = "N" -a $installDoc = "N" ]
then
	echo -e "\nNothing to install, exiting. "
	exit 0
fi

if [ "$useRPM" = "Y" ]
then
	binPak=$binRpmName
	docPak=$docRpmName
else
	binPak=$binPkgName.gz
	docPak=$docPkgName.gz
fi

if [ ! -f $binPak -o ! -f $docPak ]
then
	echo -e "\nYou may be be missing a necessary image file. "
	echo "Check that you have the correct Mbedthis AppWeb image".
	echo -n "You should be using the image: "
	if [ "$useRPM" = "Y" ] 
	then
		echo "appWeb-!!BLD_VERSION!!-!!BLD_NUMBER!!.rpm.tar.gz"
	else
		echo "appWeb-!!BLD_VERSION!!-!!BLD_NUMBER!!.self.tar.gz"
	fi
	[ `yesno "Do you wish to continue" "N"` = "N" ] && exit 255
fi

#
# Save the install settings. Remove.sh will need this
#
saveSetup

#
# Do the real work
#
install

##
##  Local variables:
##  tab-width: 4
##  c-basic-offset: 4
##  End:
##  vim:tw=78
##  vim600: sw=4 ts=4 fdm=marker
##  vim<600: sw=4 ts=4
##
