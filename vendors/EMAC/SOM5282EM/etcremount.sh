#!/bin/sh
insmod cfnvram
if (exec "mount -t ext2 /dev/nvram /etc") 
 then echo "/etc/ mounted read-write";
 else {
 #make fs and copy ROM defaults to it 
 echo "invalid NVRAM filesystem, restoring /etc defaults"
 cp -r /etc/ /tmp/
 mke2fs -i 1024 /dev/nvram
 mount -t ext2 /dev/nvram /etc
 mv /tmp/etc/* /etc/
#remove the ram image, which is always copied from ROM 
rm /etc/ramfs.img 
#remove lost and found
rm -r /etc/lost+found
#rip out config directory, It doesn't seem to be needed by anything
#but the uClinux build keeps making it for some reason
rm -r /etc/config
#remove this script, always called from ROM
rm /etc/etcremount.sh
 }
 fi
 

