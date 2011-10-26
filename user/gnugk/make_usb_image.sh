#!/bin/sh

STRIP_FILE_LIST="lib/pwlib/lib/libpt_linux_arm_d.so.1.10.3 lib/libopenh323/lib/libh323_linux_arm_n.so.1.19.0 user/gnugk/obj_linux_arm_n/gnugk" 
NORMAL_FILE_LIST="user/gnugk/gnugk  user/gnugk/gnugk.ini  user/gnugk/README.txt"
PRE_SIZE=0
POST_SIZE=0

# Build all required files
make lib/pwlib_only
make lib/libopenh323_only
make user/gnugk_only

rm -rf gk/
mkdir gk/

for file in $STRIP_FILE_LIST
do
    if [ -f $file ]
    then
        FILE_NAME=`basename $file`
        if [ $FILE_NAME == gnugk ]
        then
            FILE_NAME=$FILE_NAME.real
        fi
        cp -v $file gk/$FILE_NAME
        FILE_SIZE=`du $file | cut -f 1`
        PRE_SIZE=`expr $PRE_SIZE + $FILE_SIZE`
        arm-linux-3.3.2-strip gk/$FILE_NAME
        
        FILE_SIZE=`du gk/$FILE_NAME | cut -f 1`
        POST_SIZE=`expr $POST_SIZE + $FILE_SIZE`
    else
        echo "Couldn't find $file!"
        exit 1
    fi
done

for file in $NORMAL_FILE_LIST
do
    if [ -f $file ]
    then
        cp -av $file gk/
    else
        echo "Couldn't find $file!"
        exit 1
    fi
done

echo "Pre-size   : $PRE_SIZE KB"
echo "Post-size  : $POST_SIZE KB"

tar cjf gnugk_SG565.tar.bz2 gk/
