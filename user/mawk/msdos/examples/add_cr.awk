
# add_cr.awk
# converts from Unix (LF only) text files to
# DOS (CRLF) text files
#
# works on both unix and dos 
# if used on unix change COPY and DEL in BEGIN section
#
# mawk -f add_cr.awk  [files]

# with no files reads stdin writes stdout
# otherwise the original is overwritten
#
# If a file of the form `@file', then arguments are read from
# `file', one per line

#
# To add cr's to the whole distribution
#
# mawk -f doslist.awk packing.lis | mawk "{print $2}" > list
# mawk -f add_cr.awk  @list
#


# read arguments for @file into ARGV[]
function reset_argv(T, i, j, flag, file) #all args local
{
  for( i = 1 ; i < ARGC ; i++ ) 
  {
    T[i] = ARGV[i]
    if ( T[i] ~ /^@/ ) flag = 1
  }

  if ( ! flag )  return

  # need to read from a @file into ARGV
  j = 1
  for( i = 1 ; i < ARGC ; i++ )
  {
    if ( T[i] !~ /^@/ ) ARGV[j++] = T[i]
    else
    {
      T[i] = substr(T[i],2)
      # read arguments from T[i]
      while ( (getline file < T[i]) > 0 ) ARGV[j++] = file
    }
  }
  ARGC = j
}
   
  
BEGIN {
  COPY = "copy"    # unix: "cp"
  DEL = "del"      # unix: "rm"

  tmpfile = ENVIRON["MAWKTMPDIR"] "MAWK.TMP"

  reset_argv()
}


FILENAME == "-" {
   # just write to stdout
   printf "%s\r\n" , $0
   next
}

FILENAME != filename {
   
   if ( filename )
   {
     close(tmpfile)
     syscmd = sprintf( "%s %s %s", COPY, tmpfile, filename )
     system(syscmd)
   }

   filename = FILENAME
}

{ printf "%s\r\n" , $0 > tmpfile }


END {
  if ( filename )  
  {
    close(tmpfile)
    syscmd = sprintf( "%s %s %s", COPY, tmpfile, filename )
    system(syscmd)
    system(DEL " " tmpfile)
  }
}

   
