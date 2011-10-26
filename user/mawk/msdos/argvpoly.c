
/*  argvpoly.c
    --  set arguments via POLYSHELL (now Thompson Shell??)
    --  no errors, don't change anything if
    --  it seems shell is not activated   */

/* POLYSHELL puts the shell expanded command line
   in the environment variable CMDLINE.  Ascii 0 is
   replaced by \xff.
*/

char *strchr(char *, int), *getenv(char *) ;
char *basename(char *) ;
void *malloc(unsigned) ;
int  strcmp(char *, char *) ;

static  char *basename(char *s)
/* strip path and extension , upcase the rest */
{ 
  register char *p ;

  for ( p = strchr(s,0) ; p > s ; p-- )
    switch( p[-1] )
     { case '\\' :
       case ':'  :
       case '/'  :  return p ;
       case '.'  :  p[-1] = 0 ;  break ;
       default   :
	    if ( p[-1] >= 'a' && p[-1] <= 'z' )   p[-1] -= 32 ;
	    break ;
     }

  return  p ;
}

/*---------------------
  reargv  --  recompute  argc and argv for PolyShell
    if not under shell do nothing
 *-------------------------------  */

extern  char *progname ;
extern  unsigned char _osmajor ;

void  reargv(int *argcp , char ***argvp)
{ register char *p ;
  char **v , *q, *cmdline, **vx ;
  int cnt, cntx ;

  if ( _osmajor == 2 )  /* ugh */
     (*argvp)[0] = progname ;
  else  (*argvp)[0] = basename( (*argvp)[0] ) ;

  if ( ! (cmdline = getenv("CMDLINE")) )  return ;

  if ( *(q = strchr(cmdline,0) - 1) != 0xff )
      return ;  /*  shexpand set wrong */

  for ( *q = 0, cnt = 1 , p = cmdline ; p < q ; p++ )
     if ( *p == 0xff ) { cnt++ ; *p = 0 ; }

  if ( ! (v = (char **) malloc((cnt+1)*sizeof(char*))) )
       return ;  /* shouldn't happen */

  p = cmdline ;
  vx = v ; cntx = cnt ;
  while ( cnt )
   { *v++ = p ;
     cnt-- ;
     while ( *p )  p++ ;
     p++ ;
   }
  *v = (char *) 0 ;
  v = vx ;

  v[0] = basename( v[0] ) ;
  if ( strcmp(v[0], (*argvp)[0]) )  return  ;/* running under command
	and sh earlier  */
  /* running under PolyShell  */
  *argcp = cntx ;  *argvp = v ;
}
