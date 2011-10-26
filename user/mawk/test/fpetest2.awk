BEGIN { 
  x = 100
  do { y = x ; x *= 1000 } while ( y != x )
  print "loop terminated"
}
