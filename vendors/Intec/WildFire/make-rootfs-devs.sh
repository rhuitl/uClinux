#!/bin/sh
# This script is run to make the devices

dev_file=`pwd`/$1
dev_dir=$2

echo "Making the devices"

if [ "$1" = "" ]; then
	echo " must specify device list file"
	exit 1
fi


add_devices()
{
	perms="0 0 666"
	while read type node name; do
		devtype=${type%%rw*}
	
		case $devtype in
			"d")
				mkdir -p $(pwd)/$node
				chmod +rwx $(pwd)/$node
				;;
			"c" |	"b")
				maj=${node%%,*}
				min=${node##*,}			
				
				make_dev $(pwd)/$name ${devtype} ${maj} ${min} ${perms}
				;;				
				
		esac	
	done 
}

make_dev() 
{   
	mknod $1 $2 $3 $4 
	if [ "$?" != "0" ]; then
		echo "error $0: mknod returned $?"
	fi
	chown $5:$6 $1
	chmod $7 $1
}  


cd $2
add_devices	< ${dev_file}
