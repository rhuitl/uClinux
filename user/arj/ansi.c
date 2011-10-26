/*
 * $Id: ansi.c,v 1.1.1.1 2002/03/27 23:25:18 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Routines to display ANSI  comments are  located here. Not all  routines are
 * supported - first of all, this restriction applies  to graphic commands. It
 * has to be noted that the code  comes from  some PASCAL snippet - therefore,
 * arrays are 1-based.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

#define TEXTCOLOR_MASK          0x07    /* Basic colors */
#define TEXTFORE_MASK           0x0F    /* Text */
#define TESTBACK_MASK           0xF0    /* Background */
#define TEXT_BRIGHT                8    /* Bright text bit */
#define TEXT_BLINK              0x80    /* Blinking text bit */

#ifndef DIRECT_TO_ANSI

static char ansi_initialized=0;         /* 1 once init_ansi() is called */
static char ansi_commands[]="HFABCDNJMSUK";

static int esc_found;                   /* 1 if the last character was ESC */
static int ansi_seq_found;              /* 1 if a valid sequence is detected */
static char ansi_ptr;                   /* Offset within internal buffer */
static char ansi_buf[22];               /* Internal buffer */
static int ansi_bright;                 /* 1 will enable bright characters */
static int ansi_blink;                  /* 1 makes the blinking or bright
                                           background (0x80) */
static unsigned char ansi_saved_x;      /* Saved X coordinate */
static unsigned char ansi_saved_y;      /* Saved Y coordinate */

/* Initializes ANSI display structures */

static void init_ansi()
{
 memset(ansi_buf, 32, sizeof(ansi_buf));
 ansi_bright=ansi_blink=0;
 esc_found=0;
 ansi_seq_found=0;
 ansi_ptr=0;
 ansi_saved_x=ansi_saved_y=1;
}

/* Processes the ANSI sequence stored in the buffer */

static void process_ansi_cmd()
{
 char pad_buf[20];
 char cur_pos;
 char tmp_pos;                          /* Temporary pointer */
 char dec_pos;
 char param;                            /* Current decimal position */
 char tmp_color=0;
 char tmp_back;

 param=0;
 dec_pos=1;
 pad_buf[1]=pad_buf[2]=1;
 for(cur_pos=1; cur_pos!=ansi_ptr; cur_pos++)
 {
  if(param==0)                          /* Parameters start at 1 */
   param++;
  if(isdigit((int)ansi_buf[cur_pos])&&dec_pos<3)
  {
   pad_buf[param]=(dec_pos==1)?ansi_buf[cur_pos]-'0':pad_buf[param]*10+ansi_buf[cur_pos]-'0';
   dec_pos++;
  }
  else
  {
   if(ansi_buf[cur_pos]==ANSI_DELIMITER)
   {
    if(dec_pos==1)
     pad_buf[param]=1;
    param++;
    dec_pos=1;
   }
  }
 }
 /* The parameters are referenced as (X; Y) */
 switch(ansi_buf[ansi_ptr])
 {
  /* Move the cursor X rows up */
  case 'A':
   gotoxy(wherex(), wherey()-pad_buf[1]);
   break;
  /* Move the cursor X rows down */
  case 'B':
   gotoxy(wherex(), wherey()+pad_buf[1]);
   break;
  /* Move the cursor X columns left */
  case 'C':
   gotoxy(wherex()+pad_buf[1], wherey());
   break;
  /* Move the cursor X columns right */
  case 'D':
   gotoxy(wherex()-pad_buf[1], wherey());
   break;
  /* Set the cursor position to (Y; X) */
  case 'F':
  case 'H':
   gotoxy(pad_buf[2], pad_buf[1]);
   break;
  /* Clear the screen (quite incorrect, since only ^[[2J does it) */
  case 'J':
   clrscr();
   break;
  /* Clear all character from current position to end of line */
  case 'K':
   clreol();
   break;
  /* Set the text attributes */
  case 'M':
   for(tmp_pos=1; tmp_pos<=param; tmp_pos++)
   {
    switch(pad_buf[tmp_pos])
    {
     /* Set the default attributes */
     case 0:
      textcolor(7);
      textbackground(0);
      ansi_bright=ansi_blink=0;
      break;
     /* Set the bright mode on */
     case 1:
      ansi_bright=1;
      textcolor(getcurattr()&TEXTFORE_MASK|TEXT_BRIGHT);
      break;
     /* Set the blinking mode on */
     case 5:
      ansi_blink=1;
      textattr(getcurattr()|TEXT_BLINK);
      break;
     /* Set the inverse video on. The code in original ARJ is a bit incorrect
        here, because it swaps the foreground and background colors. */
     case 7:
      textattr(0x70);
      break;
     /* Make the text invisible by setting the foreground color the same
        as the background color. */
     case 8:
      tmp_back=(getcurattr()>>4)|TEXTCOLOR_MASK;
      textcolor(tmp_back);
      break;
     /* Set the text foreground color */
     case 30:
     case 31:
     case 32:
     case 33:
     case 34:
     case 35:
     case 36:
     case 37:
      switch(pad_buf[tmp_pos])
      {
       case 30:
        tmp_color=0;
        break;
       case 31:
        tmp_color=4;
        break;
       case 32:
        tmp_color=2;
        break;
       case 33:
        tmp_color=6;
        break;
       case 34:
        tmp_color=1;
        break;
       case 35:
        tmp_color=5;
        break;
       case 36:
        tmp_color=3;
        break;
       case 37:
        tmp_color=7;
        break;
      }
      if(ansi_bright)
       tmp_color|=TEXT_BRIGHT;
      if(ansi_blink)
       tmp_color|=TEXT_BLINK;
      textcolor(tmp_color);
      break;
     /* Set the background colors */
     case 40:
      textbackground(0);
      break;
     case 41:
      textbackground(4);
      break;
     case 42:
      textbackground(2);
      break;
     case 43:
      textbackground(6);
      break;
     case 44:
      textbackground(1);
      break;
     case 45:
      textbackground(5);
      break;
     case 46:
      textbackground(3);
      break;
     case 47:
      textbackground(7);
      break;
    }
   }
   break;
  /* Save the current cursor coordinates */
  case 'S':
   ansi_saved_x=(unsigned char)wherex();
   ansi_saved_y=(unsigned char)wherey();
   break;
  /* Restore the saved coordinates */
  case 'U':
   gotoxy((int)ansi_saved_x, (int)ansi_saved_y);
   break;
 }
}

/* Accumulates given characters and displays ANSI sequences once they're
   formed */

void display_ansi(char c)
{
 if(!ansi_initialized)
 {
  init_ansi();
  ansi_initialized=1;
 }
 if(c==ANSI_ESC)
 {
  esc_found=1;
  return;
 }
 if(c==ANSI_BRACKET&&esc_found)
 {
  ansi_seq_found=1;
  return;
 }
 if(esc_found&&ansi_seq_found)
 {
  ansi_buf[++ansi_ptr]=toupper(c);
  if(ansi_ptr<sizeof(ansi_buf))
  {
   if(strchr(ansi_commands, toupper(c))!=NULL)
   {
    process_ansi_cmd();
    esc_found=ansi_seq_found=0;
    ansi_ptr=0;
   }
  }
  else
  {
   esc_found=ansi_seq_found=0;
   ansi_ptr=0;
  }
 }
 else
  wputch((int)c);
}

#endif /* !defined(DIRECT_TO_ANSI) */
