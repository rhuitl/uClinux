/*
 * $Id: scrnio.h,v 1.5 2003/09/14 22:14:48 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in SCRNIO.C are declared here.
 *
 */

#ifndef SCRNIO_INCLUDED
#define SCRNIO_INCLUDED

/* Console routine sets */

#define CT_BORLAND                 0    /* Borland library (small and nice) */
#define CT_MSGRAPH                 1    /* Microsoft GRAPHICS.LIB (powerful,
                                           wide-compatible but huge) */
#define CT_NATIVE                  2    /* OS-dependent library (NOT impl.) */
#define CT_ANSI                    3    /* Reimplement screen I/O to ANSI
                                           sequences. Only useful for
                                           ARJDISP. */

/* Pick an appropriate set */

#if COMPILER==BCC
 #define CONSOLE_SET      CT_BORLAND
 #define NEED_CRLF
#elif COMPILER==MSC&&defined(FORCE_MSGRAPH)
 #define CONSOLE_SET      CT_MSGRAPH
#elif defined(DIRECT_TO_ANSI)&&TARGET!=OS2
 #define CONSOLE_SET         CT_ANSI
 #define NEED_CRLF
#else
 #define CONSOLE_SET       CT_NATIVE
#endif

/* Graphic libraries */

#if CONSOLE_SET==CT_BORLAND
 #include <conio.h>
#elif CONSOLE_SET==CT_MSGRAPH
 #include <graph.h>
#endif

/* Screen Sentry. That would help eliminate some extra (duplicate) output. One
   procedure raises a sentry, another one clobbers it. ASR fix 14/09/2003 */

extern int scr_sentry;
#define SET_SENTRY() scr_sentry=0;
#define CLOBBER_SENTRY() scr_sentry=1;
#define CHECK_SENTRY() (scr_sentry==0)

/* Prototypes */

#if CONSOLE_SET==CT_MSGRAPH
 #define gotoxy(x, y) _settextposition((short)y, (short)x)
 #define textbackground(c) _setbkcolor((short)c)
 #define textcolor(c) _settextcolor((short)c)
 #define clrscr() _clearscreen(_GWINDOW)
#elif CONSOLE_SET!=CT_BORLAND
 void gotoxy(int x, int y);
 void textbackground(int c);
 void textcolor(int c);
 void clrscr();
#endif
#if CONSOLE_SET==CT_BORLAND
 #define wputch(c)          putch(c)
 #define scrprintf             cprintf
 #define scrn_reset()
#else
 void textattr(int c);
 int wherex();
 int wherey();
 void clreol();
 #if CONSOLE_SET==CT_ANSI
  #define wputch(c) putch(c)
  #define scrprintf printf
  void scrn_reset();
 #else
  void wputch(int c);
  void scrprintf(char *fmt, ...);
  #define scrn_reset()
 #endif
#endif
void scr_out(char *str);
unsigned char getcurattr();
int query_screen_height();
void check_wrap(int i);

#endif
