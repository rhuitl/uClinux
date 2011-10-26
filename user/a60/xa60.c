/*
 * Simple X11 edit-and-go frontend for the NASE A60 interpreter.
 * Copyright (C) 1991,1992 Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * This file is part of NASE A60.
 * 
 * NASE A60 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * NASE A60 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NASE A60; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * xa60.c:						may 1991
 *
 * first steps to a simple X frontend for edit and go fun.
 * (nothing serious - be warned)
 */

#include <stdio.h>

#ifdef USG
#ifndef SYSV
/* commonly expected by X11R4: */
#define SYSV
#endif /* ! SYSV */
#endif /* USG */

#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>
#include <X11/Xaw/Cardinals.h>
#include <X11/Xaw/AsciiText.h>
#include <X11/Xaw/Command.h>
#include <X11/Xaw/Paned.h>
#include <X11/Xaw/Box.h>

#define VERSION		"xa60  v0.11,  June 1991"

#define A60PATH		"a60"
#define A60FLAGS	"-X"

/*
 * define as 1 to include a save button; this is not necessary,
 * because the text is saved before every execution. (and upon exit) 
 */
#define SAVE_BUTTEN	0


static String fallback_resources [] = { 
    "*input: 			True",
    "*showGrip: 		on",
    "*paned.width:		560",

    "*etext*height:		360", 
    "*etext*editType: 		edit",
    "*etext*scrollVertical: 	whenNeeded",
    "*etext*autoFill: 		on",

    "*otext*height:		240", 
    "*otext*editType:		append",
    "*otext*scrollVertical: 	whenNeeded",
    "*otext*wrap:		line",
    "*otext*displayCaret:	False",

    "*bexit*label: 		Exit",
    "*bexit*shapeStyle:		oval",
    "*bexit*borderWidth:	2",

    "*clear*label: 		Clear",
    "*clear*shapeStyle:		oval",
#if SAVE_BUTTEN
    "*save*label: 		Save",
    "*save*shapeStyle:		oval",
#endif
    "*go*label: 		Go",
    "*go*shapeStyle:		oval",

    "*fnlab*borderWidth:	0",

    NULL,
};


/* selected input file: */
static char *fname = (char *) 0;

/* temporary textbuffer (and its length): */
static char *txt_buf = (char *) 0;
static int txt_max = 0;
static int txt_len;

/* global ... */
static Widget etext, otext;

/* forward: */
static void have_a_run ();


/*
 * create a temporary file; a simple name is enough.
 * static storage is ok.
 */

static char *
mk_fname ()
{
	static char tmp [128];

	sprintf (tmp, "/tmp/nase-%d", getpid () % 999);

	return tmp;
}


static void
read_file ()
{
	FILE *fp;
	int ch;
	
	fp = fopen (fname, "r");

	if (! fp) {
		fp = fopen (fname, "w");
		if (! fp) {
			fprintf (stderr, "cannot open `%s' for writing...\n",
				 fname);
			exit (1);
		}

		/*
		 * insert some default text:
		 */
	
		fprintf (fp, "begin\n    vprint (\"Hi!\")\nend\n");
		fclose (fp);

		fp = fopen (fname, "r");
	}

	if (! fp) {
		fprintf (stderr, "cannot open `%s' for reading...\n",
			 fname);
		exit (1);
	}

	txt_len = 0;

	do {
		if (txt_len + 10 > txt_max) {
			txt_max += 1000;
			if (! txt_buf)
				txt_buf = XtMalloc (txt_max);
			else
				txt_buf = XtRealloc (txt_buf, txt_max);
		}
		
		ch = fgetc (fp);

		if (ch != EOF)
			txt_buf [txt_len++] = ch;
	} while (ch != EOF);

	fclose (fp);
}


static void
append_text (w, str)
Widget w;
char *str;
{
	XawTextBlock tb;
	int rc, point;
	
	tb.firstPos = 0;
	tb.length = strlen (str);
	tb.ptr = str;
	tb.format = FMT8BIT;
	
	point = XawTextGetInsertionPoint (w);

	rc = XawTextReplace (w, point, point, &tb);
	
	XawTextSetInsertionPoint (w, point + strlen (str));

	if (rc == XawPositionError)
		printf ("** xa60 internal error: XawPositionError ...\n");
	else if (rc == XawEditError)
		printf ("** xa60 internal error: XawEditError ...\n");
}


static void
set_caret (lno)
int lno;
{
	Arg args[1];
	String str;
	int i, n;

	XtSetArg(args[0], XtNstring, &str);
	XtGetValues(etext, args, ONE);


	/* look for character position of line lno : */

	for (n = 0, i = 1; str [n] && i < lno; n++)
		i += str [n] == '\n';

	XawTextSetInsertionPoint (etext, n);
}

/*
 * saving the text means: print the string (which contains the
 * complete text).
 * If this fails - abort.
 */

static void
save_file (txt)
char *txt;
{
	FILE *fp;

	fp = fopen (fname, "w");
	if (! fp) {
		fprintf (stderr, "cannot open `%s' for writing...\n",
			 fname);
		exit (1);
	}

	fprintf (fp, "%s\n", txt);
	fclose (fp);
}


/*
 * The callbacks for the Three buttons:  Exit, Clear, Save and Go:
 */

/* ARGSUSED */
static void
cb_clear (w, text_ptr, call_data)
Widget w;
XtPointer text_ptr, call_data;
{
	Widget text = (Widget) text_ptr;
	Arg args[1];
	
	XtSetArg (args[0], XtNstring, "");
	XtSetValues (text, args, ONE);
}


/* ARGSUSED */
static void
cb_save (w, text_ptr, call_data)
Widget w;
XtPointer text_ptr, call_data;
{
	Widget text = (Widget) text_ptr;
	Arg args[1];
	String str;

	XtSetArg(args[0], XtNstring, &str);
	XtGetValues(text, args, ONE);

	save_file (str);
}


/* ARGSUSED */
static void
cb_bexit (w, text_ptr, call_data)
Widget w;
XtPointer text_ptr, call_data;
{
	cb_save (w, text_ptr, call_data);
	
	exit (0);
}


/* ARGSUSED */
static void
cb_go (w, text_ptr, call_data)
Widget w;
XtPointer text_ptr, call_data;
{
	cb_save (w, text_ptr, call_data);

	have_a_run ();
}


/*
 * Try to get a linenumber from this line: error lines are looking like:
 * nase.a60: 12: parse error
 * return the linenumber or return a 0.
 */

static int
is_error_line (s)
char *s;
{
	int lno = 0;

	int len = strlen (fname);

	if (! strncmp (fname, s, len) && s [len] == ':')
		lno = atoi (s + len + 1);

	return lno;
}


/*
 * read the lines from fp look about an error message (to set the
 * caret [cursor]) and append the line to the output.
 */

static void
process_a60 (fp)
FILE *fp;
{
	char buf [1024];			/* fixed length :-( */
	int cursor_set = 0, lno;

	while (buf == fgets (buf, 1024, fp)) {
		append_text (otext, buf);

		if (! cursor_set) {
			lno = is_error_line (buf);
			if (lno) {
				set_caret (lno);
				cursor_set = 1;
			}
		}
	}
}


/*
 * process the buffer through a60. a single directional pipe is enough
 * and i'll use popen.
 * (may be a fork providing a stdin from this process would be nice)
 */

static void
have_a_run ()
{
	FILE *fp;
	char cmd [100];
	char tmp [100];

	sprintf (cmd, "%s %s %s", A60PATH, A60FLAGS, fname);
	fp = popen (cmd, "r");

	if (! fp) {
		sprintf (tmp, "cannot execute `%s'.\n", cmd);
		append_text (otext, tmp);
	}
	else {
		sprintf (tmp, "*** a60 starting:\n");
		append_text (otext, tmp);
		process_a60 (fp);
		pclose (fp);
		append_text (otext, "*** a60 done.\n\n");
	}
}



static void 
usage ()
{
	fprintf (stderr, "Use:  xa60  [ -V ] | [ <source file> ]\n");
	
	exit (1);
}


/*
 * M A I N
 */

int
main (argc, argv)
int argc;
char *argv[];
{
	XtAppContext app_con;
	Widget toplevel, paned, box, clear, bexit, go;
	Arg args[1];
	char *fn_str;
#if SAVE_BUTTEN
	Widget save;
#endif

	toplevel = XtAppInitialize (&app_con, "XA60", NULL, ZERO,
			   &argc, argv, fallback_resources, NULL, ZERO);

	/*
	 * Check to see that all arguments were processed, and if not then
	 * report an error and exit.
	 */
	
	if (argc > 2)
		usage ();

 	if (argc == 2) 
	{
		if (! strcmp (argv [1], "-V")) 
		{
			printf ("Version:  %s.\n", VERSION);
			exit (0);
		}
		else if (! strcmp (argv [1], "-h")) 
		{
			usage ();
		}
		else {
			fname = argv [1];
		}
	}
	else {
		fname = mk_fname ();
	}

	fn_str = XtMalloc (strlen (fname) + 20);
	sprintf (fn_str, " File: %s", fname);

	read_file ();
	
	paned = XtCreateManagedWidget ("paned", panedWidgetClass, toplevel, 
				       NULL, ZERO);
	
	box = XtCreateManagedWidget ("box", boxWidgetClass, paned, 
				     NULL, ZERO);
	
	bexit = XtCreateManagedWidget ("bexit", commandWidgetClass, box, 
				       NULL, ZERO);
	
	clear = XtCreateManagedWidget ("clear", commandWidgetClass, box, 
				       NULL, ZERO);
#if SAVE_BUTTEN
	save = XtCreateManagedWidget ("save", commandWidgetClass, box, 
				      NULL, ZERO);
#endif
	go = XtCreateManagedWidget ("go", commandWidgetClass, box, 
				    NULL, ZERO);

	XtSetArg (args[0], XtNlabel, fn_str);
	XtCreateManagedWidget ("fnlab", labelWidgetClass, box, args, ONE);

	XtSetArg (args[0], XtNstring, txt_buf);
	etext = XtCreateManagedWidget ("etext", asciiTextWidgetClass, paned, 
				     args, ONE);

	XtSetArg (args[0], XtNstring, "See:\n");
	otext = XtCreateManagedWidget ("otext", asciiTextWidgetClass, paned, 
				      args, ONE);

	XtAddCallback (bexit, XtNcallback, cb_bexit, (XtPointer) etext);
	XtAddCallback (clear, XtNcallback, cb_clear, (XtPointer) etext);
#if SAVE_BUTTEN
	XtAddCallback (save, XtNcallback, cb_save, (XtPointer) etext);
#endif
	XtAddCallback (go, XtNcallback, cb_go, (XtPointer) etext);

	XtRealizeWidget (toplevel);
	XtAppMainLoop (app_con);

	/* not reached */
	return 0;
}

/* end of xa60.c */

