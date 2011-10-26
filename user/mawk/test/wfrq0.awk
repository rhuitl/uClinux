
#   this program finds the twenty most freq
#   words in document using a heap sort at the end
#
#

function down_heap(i,  		k,hold) 
{
  while ( 1 )
  {
      if ( compare(heap[2*i], heap[2*i+1]) <= 0 ) k = 2*i
      else  k = 2*i + 1 

      if ( compare(heap[i],heap[k]) <= 0 )  return

      hold = heap[k] ; heap[k] = heap[i] ; heap[i] = hold 
      i = k
   }
}

# compares two values of form  "number word"
#    by number and breaks ties by word (reversed)

function  compare(s1, s2,	t, X)
{
  t = (s1+0) - (s2+0)  # forces types to number

  if ( t == 0 )
  {
    split(s1, X);  s1 = X[2]
    split(s2, X); s2 = X[2]
    if ( s2 < s1 )  return -1
    return s1 < s2
  }

  return t
}


BEGIN { RS = "[^a-zA-Z]+" ;  BIG = "999999:" }

{ cnt[$0]++ }

END { delete  cnt[ "" ]

# load twenty values
j = 1
for( i in cnt )
{
  heap[j] = num_word( cnt[i] , i )
  delete cnt[i] ;
  if ( ++j == 21 )  break ;
}

# make some sentinals
for( i = j ; i < 43 ; i++ )  heap[i] = BIG

h_empty = j  # save the first empty slot
# make a heap with the smallest in slot 1
for( i = h_empty - 1 ; i > 0 ; i-- )  down_heap(i) 

# examine the rest of the values
for ( i in cnt )
{
  j = num_word(cnt[i], i)
  if ( compare(j, heap[1]) > 0 )
  { # its bigger
    # take the smallest out of the heap and readjust
    heap[1] = j
    down_heap(1)
  }
}

h_empty-- ;

# what's left are the twenty largest
# smallest at the top
#

i = 20
while ( h_empty > 1 )
{
  buffer[i--] = heap[1]
  heap[1] = heap[h_empty]
  heap[h_empty] = BIG
  down_heap(1)
  h_empty--
}
  buffer[i--] = heap[1]

  for(j = 1 ; j <= 20 ; j++ )  print buffer[j]
}


function num_word(num, word)
{
  return sprintf("%3d %s", num, word)
}
