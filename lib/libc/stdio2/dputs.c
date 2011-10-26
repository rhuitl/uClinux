dputs(char *b)
{
  while(*b) write (1,b++,1);
}
