#!/bin/sh
# This is a shell archive (shar 3.32)
# made 11/16/1993 15:42 UTC by gert@greenie
# Source directory /u/gert/mgetty/contrib
#
# existing files WILL be overwritten
#
# This shar contains:
# length  mode       name
# ------ ---------- ------------------------------------------
#   1194 -rw-r--r-- faxiobe/Makefile
#   1449 -rw-r--r-- faxiobe/README
#   6146 -rw-r--r-- faxiobe/faxiobe.c
#     98 -rwxr-xr-x faxiobe/nofax
#
if touch 2>&1 | fgrep 'amc' > /dev/null
 then TOUCH=touch
 else TOUCH=true
fi
# ============= faxiobe/Makefile ==============
if test ! -d 'faxiobe'; then
    echo "x - creating directory faxiobe"
    mkdir 'faxiobe'
fi
echo "x - extracting faxiobe/Makefile (Text)"
sed 's/^X//' << 'SHAR_EOF' > faxiobe/Makefile &&
X
X# binary will be installed in DESTDIR with make install
X
XDESTDIR=/usr/local/sbin
X
X# set DIALPREF to a prefix to be added to the faxnumber
X
XDIALPREF=\"8,\"
X
X# define GHOSTSCRIPT and SENDFAX correct for you site
X
XGHOSTSCRIPT=\"/usr/local/bin/gs\"
XSENDFAX=\"/usr/local/sbin/sendfax -v\"
X
X# define NOFAX for a dummy program instead of sendfax
X# this is for debugging. A sample "nofax" is in the distribution.
X
XNOFAX=\"/usr/local/bin/nofax\"
X
X# BUGGYMODEM is defined for our Zyxel 1496EG+.
X# ARRGH!
XDEFINES=-DDIALPREF="$(DIALPREF)" -DGHOSTSCRIPT="$(GHOSTSCRIPT)"\
X        -DSENDFAX="$(SENDFAX)" -DNOFAX="$(NOFAX)" -DBUGGYMODEM
X
X# Use this for working modems....
X#DEFINES=-DDIALPREF="$(DIALPREF)" -DGHOSTSCRIPT="$(GHOSTSCRIPT)"\
X#        -DSENDFAX="$(SENDFAX)" -DNOFAX="$(NOFAX)" -DBUGGYMODEM
X
Xfaxiobe: faxiobe.o
X	$(CC) -o faxiobe faxiobe.o $(LDFLAGS) -lqb
X
Xfaxiobe.o: faxiobe.c
X	$(CC) -c $(CFLAGS) $(DEFINES) faxiobe.c
X
Xclean:
X	/bin/rm -f *.o *~ core faxiobe
X	
Xinstall: faxiobe
X	[ -d $(DESTDIR) ] || mkdir $(DESTDIR)
X	/usr/ucb/install -m 2755 -o bin -g printq faxiobe $(DESTDIR)
X
X### ignore the following....
X
Xtarfile: clean
X	tar czvf /nfs/sahara/ftp/pub/source/faxiobe-1.04.tar.gz -C .. faxiobe
X	
SHAR_EOF
$TOUCH -am 1115104093 faxiobe/Makefile &&
chmod 0644 faxiobe/Makefile ||
echo "restore of faxiobe/Makefile failed"
set `wc -c faxiobe/Makefile`;Wc_c=$1
if test "$Wc_c" != "1194"; then
	echo original size 1194, current size $Wc_c
fi
# ============= faxiobe/README ==============
echo "x - extracting faxiobe/README (Text)"
sed 's/^X//' << 'SHAR_EOF' > faxiobe/README &&
X				-*-text-*-
X
X
Xfaxiobe: a fax backend for AIX. (C) Michael Staats 1993
X	 free software according the Gnu Public License, see
X	 File copying.
X
XIf you want to understand what this program does, ask info about
X"piobe" and "Understanding Backend Routines in libqb".
X
XLook at the Makefile and define GHOSTSCRIPT and SENDFAX correctly for
Xyour site. Sendfax is the the sendfax program from the mgetty+sendfax
Xpackacge by Gert Doering.
X
XDefine DIALPREF to a string wich will be put in front of the fax
Xnumber. Leave it empty if you don't need any prefixes or want
Xthe user to provide them with the faxnumber.
X
XDefine NOFAX to a program to be called instead of sendfax for
Xdebugging purpose. There is a small shell script in the distribution.
XIt exits with an exitvalue of the faxnumber, so you can debug the
Xerrorhandling. 
X
XInstall it as a printer, just with a different backend.
XA sample local queue definition could be (in /etc/qconfig):
X
X========================= entry in /etc/qconfig ===============
X
X* Local queue fax
X
Xfax:
X	device = modem
X	discipline = fcfs
X	acctfile = /var/adm/acct/fax
Xmodem:
X	backend = /usr/local/sbin/faxiobe
X
X===============================================================
X
XThen you can send a fax with
X
Xlp -d fax -o -n<FAXNUMBER> [ -o -fg3 ] files ...
X
Xor
X
Xlp -d fax [ -o -fg3 ] -o to=<FAXNUMBER> files ...
X
XI'm sorry that I don't have the time to provide more documentation.
X
XMichael (michael@hal6000.thp.Uni-Duisburg.DE)
SHAR_EOF
$TOUCH -am 1115103993 faxiobe/README &&
chmod 0644 faxiobe/README ||
echo "restore of faxiobe/README failed"
set `wc -c faxiobe/README`;Wc_c=$1
if test "$Wc_c" != "1449"; then
	echo original size 1449, current size $Wc_c
fi
# ============= faxiobe/faxiobe.c ==============
echo "x - extracting faxiobe/faxiobe.c (Text)"
sed 's/^X//' << 'SHAR_EOF' > faxiobe/faxiobe.c &&
X/* faxiobe: A fax backend for AIX.
X   (C) Michael Staats (michael@hal6000.thp.Uni-Duisburg.DE)
X*/
Xstatic const char *What = 
X"@(#) faxiobe - A fax backend for AIX.\n"
X"@(#) (C) Michael Staats (michael@hal6000.thp.Uni-Duisburg.DE)\n"
X"@(#) free software according GNU Public License";
X
X#include <stdio.h>
X#include <string.h>
X#include <signal.h>
X#include <IN/standard.h>
X#include <IN/backend.h>
X
X#define MAXRETRY "3"
X#define SLEEPTIME 300   /* make multiple of 10 please */
X
X#ifndef GHOSTSCRIPT
X#define GHOSTSCRIPT "/usr/local/bin/gs"
X#endif
X
X#ifndef SENDFAX
X#define SENDFAX "/usr/local/sbin/sendfax"
X#endif
X
X#ifndef NOFAX
X#define NOFAX "/usr/local/bin/nofax"
X#endif
X
X#ifndef DIALPREF
X#define DIALPREF "8,"
X#endif
X
X#ifndef SPOOLDIR
X#define SPOOLDIR "/var/spool/fax/outgoing"
X#endif
X
X/* #define DEBUG */
X
X#ifdef DEBUG
X#define USE_NOFAX
X#endif
X
X#define LATER  ", I'll try again later...\n"
X#define FAILED "Your fax failed, "
X
X/* define this empty if you modem is not buggy, ours is :-( */
X
X#ifdef BUGGYMODEM
X#define BUGGYMODEMT "\nOur modem has a little BUG, so please switch it OFF and\
X after 5 seconds ON\n again. If you do not do this, NO incoming calls (faxes)\
Xwill be recognized!!!!\n\n"
X#else
X#define BUGGYMODEMT
X#endif
X
X#define MSGMOD (get_mail_only()?DOMAIL:DOWRITE)
X
X#define RETRY 99
X
Xchar *msg[] = {
X    FAILED "unknown commandline option.\n",
X    FAILED "specify Faxnumber with -o -n<number>\n",
X    FAILED "ghostscript Error. Maybe input is not PostScript?\n",    
X    FAILED "unknown input format specified.\n",
X    FAILED "fatal sendfax error.\n" BUGGYMODEMT,
X    FAILED "fork() failed, no automatic retry.\n",
X    "Fax failed completely, always errors after " MAXRETRY " trials...\n"
X};
X
X
Xchar *sfmsg[] = {
X    "", "",  /* 0 1 */
X    "Cannot open fax device" LATER, 
X    "Error initializing modem" LATER BUGGYMODEMT,  
X    "Line busy" LATER BUGGYMODEMT,  /* 4 */
X    "","","","","",     /* 5 6 7 8 9 */
X    "Error ocurred while dialing" LATER BUGGYMODEMT, 
X    "",
X    "Error transmitting page(s)" LATER
X};
X
X#define PS 1
X#define G3 2
X
Xtypedef struct { char *fstring; int fint; } fstruct;
X
Xstatic const fstruct formats[] = {{"ps", PS}, {"g3", G3}, {NULL, 0}};
X
X#define TRUE  1
X#define FALSE 0
X
X#ifdef DEBUG
X#define D(a) { a; }
X#else
X#define D(a) {}
X#endif
X
X
Xchar *tmpf = NULL; 
X
Xint rmfiles();
Xint do_rmfiles();
X
Xmain(int argc, char *argv[])
X{
X#ifdef DEBUG
X    FILE *deb = fopen("/dev/console", "w");
X#endif    
X    FILE *fptr;
X    char *cmd;
X    int l, i, ffarg, ev;
X    int  rm      = FALSE;
X    char *format = "ps";
X    int  iformat;
X    char *faxno  = NULL;
X    int  retry;
X    char *g3files;
X    fstruct *fs;
X          
X    log_init();
X        
X    D(int ii;
X      fprintf(deb,"%s called, argc = %d args = ",argv[0],argc);
X      for (ii=1; ii<argc; ii++) fprintf(deb,"\"%s\" ",argv[ii]);
X      fprintf(deb,"get_from()=%s, get_to()=%s.\n", get_from(), get_to());
X      );
X    
X    for (i=1; i < argc && argv[i][0] == '-'; i++) switch (argv[i][1]) {
X      case 'n':faxno  = argv[i] + 2;       break;
X      case 'f':format = argv[i] + 2;       break;
X      default:
X	sysnot(get_to(), "", msg[0], MSGMOD);
X	exit(EXITOTHER+1);
X    }
X    if (strncmp(argv[i], "to=", 3) == 0 && faxno == NULL) 
X      faxno = argv[i++] + 3;
X    
X    ffarg = i;
X    
X    if (faxno == NULL || *faxno == 0) {
X	sysnot(get_to(), "", msg[1], MSGMOD);
X	exit(EXITOTHER+1);
X    }
X    
X    /* format defaults to "ps" */
X    for (iformat = -1,fs = &formats[0]; fs->fstring != NULL; fs++) 
X      if (strcmp(format, fs->fstring) == 0) iformat = fs->fint;
X
X    switch (iformat) {
X      case PS: 
X	signal(SIGTERM, rmfiles);
X	rm = TRUE;
X	
X	tmpf = malloc(50+strlen(faxno));
X	
X	sprintf(tmpf,"%s/faxf-%s.%d",SPOOLDIR, faxno, getpid());
X	
X	l=strlen(tmpf);
X	for (i = ffarg; i < argc; i++) l+=strlen(argv[i])+3;
X	
X	cmd = malloc(l+200);
X	log_status(INIT);
X	
X	sprintf(cmd,"%s -q -sDEVICE=dfaxhigh -dNOPAUSE -sOutputFile=%s.%%02d ",
X		GHOSTSCRIPT, tmpf);
X	for (i = ffarg; i < argc; i++) {
X	    strcat(cmd, "\"");
X	    strcat(cmd, argv[i]);
X	    strcat(cmd, "\" "); 
X	}
X	strcat(cmd, "< /dev/null");
X	D(fprintf(deb,"faxiobe: cmdline=%s\n",cmd););
X	system(cmd);
X	  
X	sprintf(cmd,"%s.01", tmpf);
X	if ((fptr = fopen(cmd, "r")) == NULL) {
X	    sysnot(get_to(), "", msg[2], MSGMOD);
X	    exit(EXITOTHER+1);
X	} else fclose(fptr);
X	
X	g3files = malloc(strlen(tmpf)+3);
X	sprintf(g3files,"%s.??", tmpf);
X	free(cmd);
X	break;
X      case G3:
X	for (l = 0, i = ffarg; i < argc; i++) l+=strlen(argv[i])+3;
X	g3files = malloc(l+1);
X    	for (i = ffarg; i < argc; i++) {
X	    strcat(g3files, "\""); 
X	    strcat(g3files, argv[i]);
X	    strcat(g3files, "\" "); 
X	}
X	break;
X      default:
X	sysnot(get_to(), "", msg[3],  MSGMOD);
X	exit(EXITOTHER+1);
X	break;
X    }
X    
X    cmd = malloc(strlen(g3files) + 80);
X
X#ifdef USE_NOFAX
X    sprintf(cmd,"%s \"%s\" %s", NOFAX, faxno, g3files); /**/
X#else    
X    sprintf(cmd,"%s \"%s%s\" %s", SENDFAX, DIALPREF, faxno, g3files); /**/
X#endif
X
X    retry = 0;
X    do {
X	log_percent(0);
X	log_status(SENDING);
X	D(fprintf(deb,"sendfax command=%s\n",cmd););
X	ev = system(cmd) >> 8;
X
X	D(fprintf(stderr,"exitval sendfax %d\n",ev););
X	switch(ev) {
X	  case  0:
X	    ev = EXITOK;
X	    break;
X	  case  2:
X	  case  3:
X	  case  4:
X	  case 10:
X	  case 12:
X	    if (retry==0) 
X	      sysnot(get_to(), "", sfmsg[ev], MSGMOD);
X	    log_status(WAITING);
X	    for (i=0; i < 10; i++) {
X		log_percent(10*i);    /* hm, this doesn't work.... */
X		D(fprintf(deb,"%d %% ",i););
X		sleep(SLEEPTIME/10);
X	    }
X	    log_percent(0);
X	    log_status(RUNNING);
X	    retry++;
X	    ev = RETRY;
X	    break;
X	  default:
X	    sysnot(get_to(), "", msg[4], MSGMOD);
X	    ev = EXITFATAL;
X	    break;
X	}
X    } while (ev == RETRY && retry < atoi(MAXRETRY));
X
X    if (ev == RETRY) {
X	sysnot(get_to(), "", msg[6], MSGMOD);
X	ev = EXITOTHER+1;
X    }
X
X    free(cmd);
X    if (rm) do_rmfiles();
X    log_status(READY);
X    if (ev == EXITOK) log_charge(1);
X    exit(ev);
X}
X
Xint rmfiles() {
X    do_rmfiles();
X    exit(EXITSIGNAL);
X}
X
Xint do_rmfiles()
X{
X    char *cmd;
X    if (tmpf == NULL) return(0);
X    cmd = malloc(strlen(tmpf) + 20);
X    sprintf(cmd, "/bin/rm -f %s.??", tmpf);
X    return(system(cmd));
X}
X	
X	    
SHAR_EOF
$TOUCH -am 1115102793 faxiobe/faxiobe.c &&
chmod 0644 faxiobe/faxiobe.c ||
echo "restore of faxiobe/faxiobe.c failed"
set `wc -c faxiobe/faxiobe.c`;Wc_c=$1
if test "$Wc_c" != "6146"; then
	echo original size 6146, current size $Wc_c
fi
# ============= faxiobe/nofax ==============
echo "x - extracting faxiobe/nofax (Text)"
sed 's/^X//' << 'SHAR_EOF' > faxiobe/nofax &&
X#!/bin/ksh
X{
Xdate
Xecho "Nofax called with $@"
Xll $2
Xecho "exiting with $1"
X}>/dev/console
Xexit $1
SHAR_EOF
$TOUCH -am 1113131693 faxiobe/nofax &&
chmod 0755 faxiobe/nofax ||
echo "restore of faxiobe/nofax failed"
set `wc -c faxiobe/nofax`;Wc_c=$1
if test "$Wc_c" != "98"; then
	echo original size 98, current size $Wc_c
fi
exit 0
