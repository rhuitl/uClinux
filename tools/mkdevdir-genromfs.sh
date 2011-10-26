#! /bin/sh

# A little tool to generate /dev directories in a form that genromfs
# understands.  It takes as inputs the romfs directory, and the
# device table (which is in the same format that genext2fs understands)

while read filename type mode uid gid major minor start inc count ; do
case "$filename" in
'#'*)    true ;;
*)
    case $type in
	d)
	    mkdir -p $1$filename
	    ;;
	[cb])
	    x=`basename $filename`
	    y=`dirname $filename`
	    touch "$1$y/@$x,$type,$major,$minor"
	    chmod $mode "$1$y/@$x,$type,$major,$minor"
	    ;;
    esac
esac
done <$2
