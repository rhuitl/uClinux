
# print truncated DOS file names
# from packing.list (packing.lis)
#
#  mawk -f doslist.awk packing.lis


# discard blanks and comments
/^#/ || /^[ \t]*$/ {next}


function dos_name(s,	n, front, X)
{
  #lowercase, split on extension and truncate pieces
  s = tolower(s)
  n = split(s, X, ".")

  front = substr(X[1],1,8)

  if ( n == 1 )  return front
  else return front "." substr(X[2], 1, 3)
}

{
  n = split($1, X, "/")
  new = dos_name(X[1])

  for( i = 2 ; i <= n ; i++ )
	new = new "\\" dos_name(X[i])

  printf "%-30s%s\n", $1, new
}


