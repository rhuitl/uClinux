#!/bin/sh

# md4convert.sh
#
#	md4convert.sh is a shell script replaces all the MD4 signatures in 
#	the specified Tripwire database.  This script was written to help
#	re-adjust the databases after it was discovered that the MD4 routines
#	included in Tripwire releases before version 1.0.3 generated 
#	incorrect signatures.  
#
# Gene Kim
# Purdue University
# April 28, 1993
#

## predefined filenames
file=/tmp/genek/tw.db_flounder.Eng.Sun.COM

## names of temporary files
tmpfile=/tmp/tw.list
outfile=/tmp/tw.tmp
sigfile=/tmp/tw.sig

## make backup files (very conservatively)
# copy the files to the right places
if [ -f $file.BAK ] 
then
    echo "### $file.BAK already exists!  "
    echo "### Cannot backup file.  Remove the file and run this script again."
    exit 1
fi

echo "### Backing up $file to $file.BAK"
cp $file $file.BAK

## place {filename, md4sig} pairings in $tmpfile
echo "### Scanning new file signatures"
rm -f $outfile
cat $file | egrep -v '^#' | egrep -v '^@' | awk ' BEGIN { NF = " "; } \
	{ if ($13 == $14 && $14 == $15 && \
		$15 == $16 && $16 == $17 && $17 == $18 && $18 == $19 && \
		$19 == $20 && $20 == $21 && $21 == $22 && $22 == 0) { next; } \
		else {print $1;}} ' > $tmpfile
for filename in `cat $tmpfile`
do
    # this works unreliably, so we have to look for all nullsigs up above
    if [ -f $filename ] 
        then
	sigfetch -5 $filename > $sigfile
	if [ $? -eq 0 ] 
	then
	    sig=`cat $sigfile | sed 's/.*: //'` 
	    echo Scanning: $filename
	    echo $filename $sig >> $outfile
	fi
    fi
done

## merge the two files together
echo "### Substituting and merging signature files..."
newfile=/tmp/tw.new
awk ' \
# signatures begin at field 12 \
BEGIN	{  \
	    FS = " ";  \
	    filename = "/tmp/tw.tmp"; \
 \
	    # get new values from tmpfile, put into associative array \
	    while(getline newline <filename) { \
		split(newline, newarray); \
		#print newarray[1] "-->" newarray[2]; \
		signatures[newarray[1]] = newarray[2]; \
	    } \
 \
	} \
/^#/ 	{ print $0; next; } \
/^@@/	{ print $0; next; } \
{ \
	if (signatures[1]) { \
	    print "-->", signatures[$1], "<---";
	    $17 = signatures[$1]; \
	} \
	print $0; \
 \
} ' < $file > $newfile

echo "### Copying new database file to $file"
cp $newfile $file
