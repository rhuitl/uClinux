/*
 * $Id: arjdisp.c,v 1.5 2003/06/22 11:12:28 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This is a sample graphical interface program.
 *
 */

#include "arj.h"

#include <stdlib.h>

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Local variables */

static char *archive_name;
static char *filename;
static long uncompsize;
static long bytes;
static long compsize;
static char cmd_verb;
static char msg_lf[]="\n";
char strform[]="%s";                    /* Export it for scrnio.c, too
                                           (a byte saved is a byte gained) */

/* Pseudographical controls */

#if TARGET==UNIX
static char indo='*';
static char win_top   []="/----------------------------------------------------------------------------\\";
static char win_border[]="|";
static char win_bottom[]="\\----------------------------------------------------------------------------/";
static char ind_top   []="+--------------------------------------------------+";
static char ind_middle[]="|..................................................|";
static char ind_bottom[]="+--------------------------------------------------+";
#else
static char indo='²';
static char win_top   []="ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿";
static char win_border[]="³";
static char win_bottom[]="ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ";
static char ind_top   []="ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿";
static char ind_middle[]="³þþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþþ³";
static char ind_bottom[]="ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ";
#endif

/* Shows the initial screen */

static void show_init_scrn()
{
 int i;
 char *t;

 textbackground(1);
 textcolor(7);
 clrscr();
 gotoxy(2, 2);
 scrprintf(win_top);
 for(i=3; i<24; i++)
 {
  gotoxy(2, i); scrprintf(win_border);
  gotoxy(79, i); scrprintf(win_border);
 }
 gotoxy(2, 24); scrprintf(win_bottom);
 gotoxy(10, 5);
 scrprintf(M_ARJDISP_COPYRIGHT);
 gotoxy(10, 6);
 scrprintf(M_ARJDISP_DISTRIBUTION);
 gotoxy(10, 7);
 scrprintf(M_ARJDISP_LICENSE);
 gotoxy(16, 10);
 scrprintf(M_PROCESSING_ARCHIVE, archive_name);
 t=strtok(M_ARJDISP_INFO, msg_lf);
 i=13;
 while(t!=NULL&&i<=23)
 {
  gotoxy(10, i++);
  scrprintf(strform, t);
  t=strtok(NULL, msg_lf);
 }
 gotoxy(16, 20);
 scrprintf(M_PRESS_ANY_KEY);
 uni_getch();
 gotoxy(1, 24);
}

/* Archive processing screen */

static void show_proc_scrn()
{
 int i;
 static char progress[80];

 textbackground(1);
 textcolor(7);
 if(bytes==0L)
 {
  clrscr();
  gotoxy(2, 2);
  scrprintf(win_top);
  for(i=3; i<24; i++)
  {
   gotoxy(2, i); scrprintf(win_border);
   gotoxy(79, i); scrprintf(win_border);
  }
  gotoxy(2, 24); scrprintf(win_bottom);
  gotoxy(10, 5);
  scrprintf(M_ARJDISP_COPYRIGHT);
  gotoxy(10, 6);
  scrprintf(M_ARJDISP_DISTRIBUTION);
  gotoxy(10, 7);
  scrprintf(M_ARJDISP_LICENSE);
  gotoxy(16, 10);
  scrprintf(M_PROCESSING_ARCHIVE, archive_name);
  gotoxy(16, 12);
  switch(cmd_verb)
  {
   case ARJ_CMD_ADD:
   case ARJ_CMD_FRESHEN:
   case ARJ_CMD_MOVE:
   case ARJ_CMD_UPDATE:
    scrprintf(M_ADDING_FILE, filename);
    break;
   case ARJ_CMD_TEST:
    scrprintf(M_TESTING_FILE, filename);
    break;
   case ARJ_CMD_EXTR_NP:
   case ARJ_CMD_EXTRACT:
    scrprintf(M_EXTRACTING_FILE, filename);
    break;
   default:
    scrprintf(M_PROCESSING_FILE, filename);
    break;
  }
  gotoxy(15, 14);
  scrprintf(ind_top);
  gotoxy(15, 15);
  scrprintf(ind_middle);
  gotoxy(15, 16);
  scrprintf(ind_bottom);
  gotoxy(16, 18);
  scrprintf(M_ARJDISP_CTR_START);
 }
 else
 {
  i=calc_percentage(bytes, uncompsize)/20;
  gotoxy(16, 15);
  memset(progress, indo, i);
  progress[i]='\0';
  scrprintf(progress);
  gotoxy(16, 18);
  scrprintf(M_ARJDISP_CTR, calc_percentage(bytes, uncompsize)/10);
 }
 gotoxy(16, 15);
 if(bytes==uncompsize)
  gotoxy(1, 24);
}

/* Ending screen */

static void show_ending_scrn()
{
 int i;

 textbackground(1);
 textcolor(7);
 clrscr();
 gotoxy(2, 2);
 scrprintf(win_top);
 for(i=3; i<24; i++)
 {
  gotoxy(2, i); scrprintf(win_border);
  gotoxy(79, i); scrprintf(win_border);
 }
 gotoxy(2, 24); scrprintf(win_bottom);
 gotoxy(10, 5);
 scrprintf(M_ARJDISP_COPYRIGHT);
 gotoxy(10, 6);
 scrprintf(M_ARJDISP_DISTRIBUTION);
 gotoxy(10, 7);
 scrprintf(M_ARJDISP_LICENSE);
 gotoxy(16, 10);
 scrprintf(M_FINISHED_PROCESSING, archive_name);
 gotoxy(1, 24);
 scrn_reset();
 arj_delay(2);
}

/* Main routine */

int main(int argc, char **argv)
{
 if(argc==2)
 {
  if(!strcmp(argv[1], "test"))
   system("arj t arj*" EXE_EXTENSION " -hep -*");
 }
 if(argc!=7)
  error(M_ARJDISP_BANNER);
 archive_name=argv[1];
 filename=argv[2];
 uncompsize=atol(argv[3]);
 bytes=atol(argv[4]);
 compsize=atol(argv[5]);
 cmd_verb=argv[6][0];
 if(cmd_verb=='+')
  show_init_scrn();
 else if(cmd_verb=='-')
  show_ending_scrn();
 else
  show_proc_scrn();
 return(0);
}
