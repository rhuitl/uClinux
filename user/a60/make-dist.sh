#! /bin/sh
##
## make-dist.sh:					june 1991
## (schoenfr)
##
## use:  make-dist.sh <files for dist>
##
## Make a distribution tar-file. The file will named like:
## ``a60-0.16.tar.Z'' and extract into such a directory.
##

set -e

if [ $# -eq 0 ] ; then
	echo 'use: make-dist.sh <files for dist>'
	exit 1
fi

##
## use version number from version.h:
##
ver=`sed -n -e 's/.* v\(.\...\).*$/\1/p' < version.h`
dir="a60-$ver"

echo "Version is $ver"

##
## files to be included:
##
files="$*"

##
## create appropriate directory and copy the files:
##

mkdir $dir

echo -n "Copying to $dir ... "
gtar cf - $files | (cd $dir ; gtar xBf -)
echo "done."

##
## now $dir is the distribution:
##

echo -n "Creating $dir.tar.Z ... "
gtar czf "$dir".tar.Z $dir
echo "done."

ls -l "$dir".tar.Z

echo -n "Cleaning up ... "
rm -rf $dir
echo "done".

exit 0
