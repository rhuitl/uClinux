/*
 * $Id: scrnio.c,v 1.6 2004/01/25 11:31:40 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This module provides basic screen output routines.
 *
 */

#include "arj.h"

#if CONSOLE_SET==CT_NATIVE||TARGET==OS2
 #define KNOW_DIMENSIONS
#endif

#include <stdarg.h>

#if CONSOLE_SET==CT_NATIVE
 #if TARGET==DOS
  #include <conio.h>
  #include <dos.h>
 #elif TARGET==OS2
 #endif
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Local variables */

#ifdef KNOW_DIMENSIONS
 static unsigned char w_rows=0, w_columns;
#endif
#if TARGET==WIN32
 static HANDLE hcons;
#endif
#if CONSOLE_SET==CT_ANSI||CONSOLE_SET==CT_NATIVE
 static unsigned char curattr=7;
 #if CONSOLE_SET==CT_ANSI
  static char ansicolors[8]={30, 34, 32, 36, 31, 35, 33, 37};
  static int background_touched=0;
 #endif
#endif
int scr_sentry=0;

/* Queries screen dimensions, excluding window region */

#ifdef KNOW_DIMENSIONS
static void get_dimensions()
{
 #if TARGET==DOS
  union REGS r;

  r.h.ah=0x0F;
  int86(0x10, &r, &r);
  w_columns=(unsigned int)r.h.ah;
  w_rows=*(unsigned char FAR *)0x00000484L+1;
 #elif TARGET==OS2
  VIOMODEINFO modedata;

  modedata.cb=sizeof(modedata);
  VioGetMode(&modedata, 0);
  w_columns=modedata.col;
  w_rows=modedata.row;
 #elif TARGET==WIN32
  CONSOLE_SCREEN_BUFFER_INFO csbi;

  GetConsoleScreenBufferInfo(hcons=GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
  w_columns=csbi.dwSize.X;
  w_rows=csbi.dwSize.Y;
 #endif
}
#endif

/* Positions the cursor at row y, column x (top-left screen corner is 1, 1) */

#if CONSOLE_SET!=CT_BORLAND&&CONSOLE_SET!=CT_MSGRAPH
void gotoxy(int x, int y)
{
 #if CONSOLE_SET==CT_NATIVE
  #if TARGET==DOS
   union REGS r;

   r.h.ah=2;
   r.h.bh=0;
   r.h.dh=(char)y-1;
   r.h.dl=(char)x-1;
   int86(0x10, &r, &r);
  #elif TARGET==OS2
   VioSetCurPos((USHORT)y-1, (USHORT)x-1, 0);
  #elif TARGET==WIN32
   COORD xy;

   if(w_rows==0)
    get_dimensions();
   xy.X=x-1;
   xy.Y=y-1;
   SetConsoleCursorPosition(hcons, xy);
  #endif
 #elif CONSOLE_SET==CT_ANSI
  printf("\x1B[%u;%uH", y, x);
 #endif
}
#endif

/* Refreshes the ANSI attributes */

#if CONSOLE_SET==CT_ANSI
static void kick_attr()
{
 if(!background_touched)
 {
  if(curattr%8==7)
   printf("\x1B[0m");
  else
   printf("\x1B[0;%um", (unsigned int)ansicolors[curattr%8]);
 }
 else
 {
  printf("\x1B[0;%u;%um", (unsigned int)ansicolors[curattr%8],
                          (unsigned int)(ansicolors[(curattr>>4)%8])+10);
 }
 if(curattr&8)
  printf("\x1B[1m");
}
#else
 #define kick_attr()
#endif

/* Sets the background color to c, color index is the same as on PCs. The
   colors 8..15 do NOT enable blinking. */

#if CONSOLE_SET!=CT_BORLAND&&CONSOLE_SET!=CT_MSGRAPH
void textbackground(int c)
{
 curattr=(curattr%16+(c<<4))%128;
 kick_attr();
 #if CONSOLE_SET==CT_ANSI
  background_touched=1;
 #endif
}
#endif

/* Sets the foreground color to c, 16...31 enables blinking. */

#if CONSOLE_SET!=CT_BORLAND&&CONSOLE_SET!=CT_MSGRAPH
void textcolor(int c)
{
 curattr=(curattr&112)+((c&16)<<3)+c%16;
 kick_attr();
}
#endif

/* Sets text attributes */

#if CONSOLE_SET!=CT_BORLAND&&SFX_LEVEL>=ARJSFX
void textattr(int c)
{
 #if CONSOLE_SET==CT_MSGRAPH
  _settextcolor((short)((c&128)?16:0)+c%16);
  _setbkcolor((short)(c%128)>>4);
 #elif CONSOLE_SET==CT_NATIVE||CONSOLE_SET==CT_ANSI
  curattr=(unsigned char)c;
 #endif
 kick_attr();
}
#endif

/* Returns current column, 1...<screen width> */

#if CONSOLE_SET!=CT_BORLAND&&CONSOLE_SET!=CT_ANSI
int wherex()
{
 #if CONSOLE_SET==CT_MSGRAPH
  struct rccoord coord;

  coord=_gettextposition();
  return((int)coord.col);
 #elif CONSOLE_SET==CT_NATIVE
  #if TARGET==DOS
   union REGS r;

   r.h.ah=3;
   r.h.bh=0;
   int86(0x10, &r, &r);
   return((int)r.h.dl+1);
  #elif TARGET==OS2
   USHORT x, y;

   VioGetCurPos(&y, &x, 0);
   return(x+1);
  #elif TARGET==WIN32
   CONSOLE_SCREEN_BUFFER_INFO csbi;

   GetConsoleScreenBufferInfo(hcons, &csbi);
   return(csbi.dwCursorPosition.X+1);
  #endif
 #endif
}
#endif

/* Returns current row, 1...<screen height> */

#if CONSOLE_SET!=CT_BORLAND&&CONSOLE_SET!=CT_ANSI
int wherey()
{
 #if CONSOLE_SET==CT_MSGRAPH
  struct rccoord coord;

  coord=_gettextposition();
  return((int)coord.row);
 #elif CONSOLE_SET==CT_NATIVE
  #if TARGET==DOS
   union REGS r;

   r.h.ah=3;
   r.h.bh=0;
   int86(0x10, &r, &r);
   return((int)r.h.dh+1);
  #elif TARGET==OS2
   USHORT x, y;

   VioGetCurPos(&y, &x, 0);
   return(y+1);
  #elif TARGET==WIN32
   CONSOLE_SCREEN_BUFFER_INFO csbi;

   GetConsoleScreenBufferInfo(hcons, &csbi);
   return(csbi.dwCursorPosition.Y+1);
  #endif
 #endif
}
#endif

/* Returns the current text attribute */

#if SFX_LEVEL>=ARJSFX
unsigned char getcurattr()
{
 #if CONSOLE_SET==CT_BORLAND
  struct text_info r;

  gettextinfo(&r);
  return(r.attribute);
 #elif CONSOLE_SET==CT_MSGRAPH
  unsigned char textcolor;

  textcolor=(unsigned char)_gettextcolor();
  return(textcolor%16+((unsigned char)_getbkcolor()<<4)+((textcolor&16)?128:0));
 #elif CONSOLE_SET==CT_NATIVE||CONSOLE_SET==CT_ANSI
  return(curattr);
 #endif
}
#endif

/* Clears the entire screen or window */

#if CONSOLE_SET!=CT_BORLAND&&CONSOLE_SET!=CT_MSGRAPH
void clrscr()
{
 #if CONSOLE_SET==CT_NATIVE
  #if TARGET==DOS
   unsigned int st_x, st_y;
   union REGS r;

   get_dimensions();
   r.x.ax=0x600;
   r.h.bh=(unsigned char)curattr;
    r.x.cx=0;
   r.h.dh=w_rows-1;
   r.h.dl=w_columns-1;
   int86(0x10, &r, &r);
   gotoxy(1, 1);
  #elif TARGET==OS2
   static BYTE cell[]={' ', 0};
   int i;

   get_dimensions();
   cell[1]=(BYTE)curattr;
   for(i=0; i<w_rows; i++)
    VioWrtNCell(cell, w_columns, i, 0, 0);
   gotoxy(1, 1);
  #elif TARGET==WIN32
   int i;
   DWORD dummy;
   COORD xy;

   get_dimensions();
   xy.X=0;
   for(i=0; i<w_rows; i++)
   {
    xy.Y=i;
    FillConsoleOutputCharacter(hcons, 0x20, w_columns, xy, &dummy);
    FillConsoleOutputAttribute(hcons, (WORD)curattr, w_columns, xy, &dummy);
   };
   gotoxy(1, 1);
  #endif
 #elif CONSOLE_SET==CT_ANSI
  printf("\x1B[2J");
 #endif
}
#endif

/* Clears all characters from current position to the end of line */

#if CONSOLE_SET!=CT_BORLAND
void clreol()
{
 #if CONSOLE_SET==CT_MSGRAPH
  struct videoconfig vc;
  struct rccoord st_coord;
  short x;
  unsigned char c=' ';

  _getvideoconfig(&vc);
  st_coord=_gettextposition();
  for(x=st_coord.col; x<=vc.numtextcols; x++)
  {
   _settextposition(st_coord.row, x);
   _outmem((unsigned char FAR *)&c, 1);
  }
  _settextposition(st_coord.row, st_coord.col);
 #elif CONSOLE_SET==CT_NATIVE
  unsigned int x, st_x, y;
  #if TARGET==DOS
   union REGS r;
  #elif TARGET==OS2
   char c[2]={32, 0};
  #endif

  y=wherey();
  get_dimensions();
  for(x=st_x=wherex(); x<=w_columns; x++)
  {
   #if TARGET==DOS
    gotoxy(x, y);
    r.x.ax=0x920;
    r.x.bx=curattr;
    r.x.cx=1;
    int86(0x10, &r, &r);
   #elif TARGET==OS2
    c[1]=curattr;
    VioWrtCharStrAtt((PCH)&c, 1, y-1, x-1, &curattr, 0);
   #elif TARGET==WIN32
    DWORD dummy;
    COORD xy;

    get_dimensions();
    xy.X=x-1;
    xy.Y=y-1;
    FillConsoleOutputCharacter(hcons, 0x20, w_columns-x, xy, &dummy);
    FillConsoleOutputAttribute(hcons, (WORD)curattr, w_columns-x, xy, &dummy);
   #endif
  }
  gotoxy(st_x, y);
 #elif CONSOLE_SET==CT_ANSI
  printf("\x1B[K");
 #endif
}
#endif

/* Writes a single character to the console, with scrolling */

#if CONSOLE_SET!=CT_BORLAND
void wputch(int c)
{
 #if CONSOLE_SET==CT_MSGRAPH
  char p[2];

  p[0]=c;
  p[1]='\0';
  _outtext((char FAR *)p);
 #elif CONSOLE_SET==CT_NATIVE
  {
   unsigned int row, column;
   #if TARGET==DOS
    union REGS r;
   #elif TARGET==OS2
    BYTE cell[2];
   #elif TARGET==WIN32
    CHAR_INFO ci;
    COORD xy, xysp;
    SMALL_RECT sr;
   #endif

   if(w_rows==0)
    get_dimensions();
   row=wherey();
   column=wherex();
   switch(c)
   {
    case BEL:
     fputc(BEL, stdout);               /* Not as correct but is expected to do
                                          its job - the output goes to screen,
                                          the sounds flow to stdout */
     break;
    case 8:
     if(column>1)
      column--;
     break;
    case 10:
     row++;
     column=1;
     break;
    case 13:
     column=1;
     break;
    default:
     #if TARGET==DOS
      r.h.ah=9;
      r.h.al=(unsigned char)c;
      r.x.bx=curattr;
      r.x.cx=1;
      int86(0x10, &r, &r);
     #elif TARGET==OS2
      VioWrtCharStrAtt((PCH)&c, 1, row-1, column-1, &curattr, 0);
     #elif TARGET==WIN32
      ci.Char.UnicodeChar=0;
      ci.Char.AsciiChar=(CHAR)c;
      ci.Attributes=curattr;
      xy.X=xy.Y=1;
      xysp.X=0;
      xysp.Y=0;
      sr.Left=sr.Right=column-1;
      sr.Top=sr.Bottom=row-1;
      WriteConsoleOutput(hcons, &ci, xy, xysp, &sr);
     #endif
     column++;
   }
   if(column>w_columns)
   {
    column=1;
    row++;
   }
   while(row>w_rows)
   {
    #if TARGET==DOS
     r.x.ax=0x601;
     r.h.bh=(unsigned char)curattr;
     r.x.cx=0x100;
     r.h.dh=w_rows-1;
     r.h.dl=w_columns-1;
     int86(0x10, &r, &r);
    #elif TARGET==OS2
     cell[0]=' ';
     cell[1]=curattr;
     VioScrollUp(0, 0, w_rows-1, w_columns-1, 1, cell, 0);
    #elif TARGET==WIN32
     sr.Top=1;
     sr.Left=0;
     sr.Right=w_columns-1;
     sr.Bottom=w_rows-1;
     xy.X=0;
     xy.Y=0;
     ci.Char.UnicodeChar=0x20;
     ci.Attributes=curattr;
     ScrollConsoleScreenBuffer(hcons, &sr, NULL, xy, &ci);
    #else
     #error BUG: wputch() routine not implemented
    #endif
    row--;
   }
   gotoxy(column, row);
  }
 #elif CONSOLE_SET==CT_ANSI
  putchar(c);
 #endif
}
#endif

/* High-level functions, dropped for ANSI */

#if CONSOLE_SET!=CT_ANSI

/* Borland calls this cprintf(). We call this scrprintf(). */

#if CONSOLE_SET!=CT_BORLAND&&defined(ARJDISP)
void scrprintf(char *fmt, ...)
{
 char text[1024];
 va_list marker;

 va_start(marker, fmt);
 vsprintf(text, fmt, marker);
 va_end(marker);
 scr_out(text);
}
#endif

#endif  /* !CT_ANSI */


/* A general routine for outputting unformatted text onto screen */

#if defined(ARJDISP)||defined(COLOR_OUTPUT)
void scr_out(char *str)
{
 #if CONSOLE_SET==CT_BORLAND
  #ifdef ARJDISP
   char strform[]="%s";
  #endif

  kbhit();
  cprintf(strform, str);
 #elif CONSOLE_SET==CT_MSGRAPH
  /* Needs a special hack. Microsoft allows the backspace character to be
     passed. */
  char t[128];
  int i=0;
  int xpos;

  while(str[0]!='\0')
  {
   kbhit();                             /* To check for Ctrl+C */
   while(str[i]!='\0'&&(i<sizeof(t)-1))
   {
    if(str[i]==8)
    {
     if(i>0)
     {
      t[i]='\0';
      str+=i;
      i=0;
      _outtext((char FAR *)t);
     }
     str++;
     xpos=wherex()-1;
     _settextposition(wherey(), max(xpos, 1));
    }
    else
    {
     t[i]=str[i];
     i++;
    }
   }
   t[i]='\0';
   _outtext((char FAR *)t);
   str+=i;
   i=0;
  }
  if(i>0)
  {
   t[i]='\0';
   _outtext((char FAR *)t);
  }
 #elif CONSOLE_SET==CT_NATIVE||CONSOLE_SET==CT_ANSI
  char *t_ptr;

  #if TARGET==DOS
   kbhit();                             /* To check for Ctrl+C */
  #endif
  for(t_ptr=str; *t_ptr!='\0'; t_ptr++)
   wputch((int)*t_ptr);
 #else
  #error scr_out() not implemented
 #endif
}
#endif

/* For ANSI, we have to reset the terminal. Do it here (on other console
   types, it's a null macro) */

#if CONSOLE_SET==CT_ANSI
void scrn_reset()
{
 printf("\x1B[0m\n");
}
#endif

/* Helper routine for ARJ to know the screen height */

int query_screen_height()
{
#ifdef KNOW_DIMENSIONS
 get_dimensions();
 return(w_rows);
#else
 return(25);
#endif
}

/* Prepares for wrapping around the right margin if the given length exceeds
   it */

void check_wrap(int i)
{
 #if SFX_LEVEL>=ARJ&&defined(KNOW_DIMENSIONS)&&(defined(ARJDISP)||defined(COLOR_OUTPUT))
  if(wherex()+i>w_columns)
   scr_out(lf);
 #endif
}
