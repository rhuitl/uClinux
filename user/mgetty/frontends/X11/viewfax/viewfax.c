/* Program to view fax files on an X-window screen
   Copyright (C) 1990, 1995, 2004  Frank D. Cringle.

This file is part of viewfax - g3/g4 fax processing software.
     
viewfax is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.
     
This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.
     
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
/* NewImage() needs to fiddle with the Display structure */
#define XLIB_ILLEGAL_ACCESS
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <X11/keysymdef.h>
#include <X11/cursorfont.h>
#include "faxexpand.h"

#define VERSION "2.6"

/* If moving the image around with the middle mouse button is jerky or
   slow, try defining USE_MOTIONHINT.  It may help (it may also make
   things worse - it depends on the server implementation) */
#undef USE_MOTIONHINT

struct pagenode *firstpage, *lastpage, *thispage, *helppage;
struct pagenode defaultpage;

/* access the 'extra' field in a pagenode */
#define Pimage(p)	((XImage *)(p)->extra)

/* getopt declarations */
extern int getopt();
extern char *optarg;
extern int optind, opterr, optopt;

/* forward declarations */
static XImage *FlipImage(XImage *xi);
static XImage *MirrorImage(XImage *xi);
static XImage *NewImage(int w, int h, char *data, int bit_order);
static XImage *RotImage(XImage *Image);
static XImage *ZoomImage(XImage *Big);
static void FreeImage(XImage *Image);
static int GetImage(struct pagenode *pn);
static void SetupDisplay(int argc, char **argv);
static void ShowLoop(void);
static int release(int quit);
static char *suffix(char *opt, const char *str);

/* X variables */
static char *DispName = NULL;
static char *PrintCmd = NULL;
static char *EditCmd = NULL;
static char *Geometry = NULL;
static Display *Disp;
static Window Root;
static Window Win;
static int Default_Screen;
static GC PaintGC;
static Cursor WorkCursor;
static Cursor ReadyCursor;
static Cursor MoveCursor;
static Cursor LRCursor;
static Cursor UDCursor;

char *ProgName;
int verbose = 0;

static int abell = 0;			/* audio bell */
static int vbell = 1;			/* visual bell */
static int Wheelinv = 0;		/* mouse scrolls by page */
static int zfactor = 0;			/* zoom factor */

static size_t Memused = 0;		/* image memory usage */
static size_t Memlimit = 4*1024*1024;	/* try not to exceed */

#undef min
#undef max
#define min(a,b)	((a)<(b)?(a):(b))
#define max(a,b)	((a)>(b)?(a):(b))

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

/* OK, OK - this is a dreadful hack.  But it adequately distinguishes
   modern big- and little- endian hosts.  We only need this to set the
   byte order in XImage structures */
static union { t32bits i; unsigned char b[4]; } bo;
#define ByteOrder	bo.b[3]

static char Banner[] =
"\nviewfax version " VERSION ",\n"
"Copyright (C) 1990, 1995, 2004 Frank D. Cringle.\n"
"viewfax comes with ABSOLUTELY NO WARRANTY; for details see the\n"
"file \"COPYING\" in the distribution directory.\n\n";

static char Usage[] =
"usage: %s <flags> file ...\n"
"\t-f\tfine resolution (default unless filename begins with 'fn')\n"
"\t-n\tnormal resolution\n"
"\t-h\theight (number of fax lines)\n"
"\t-w\twidth (dots per fax line)\n"
"\t-l\tturn image 90 degrees (landscape mode)\n"
"\t-u\tturn image upside down\n"
"\t-i\tinvert (black/white)\n"
"\t-d\t(or -display) use an alternate X display\n"
"\t-g\t(or -geometry) size and position of window\n"
"\t-b\tuse audio (-ba) or visual (-bv) warning bell\n"
"\t-m\tmemory usage limit\n"
"\t-r\tfax data is packed ls-bit first in input bytes\n"
"\t-v\tverbose messages\n"
"\t-W\tmousewheel scrolls by page\n"
"\t-z\tinitial zoom factor\n"
"\t-2\traw files are g3-2d\n"
"\t-4\traw files are g4\n";

int
main(int argc, char **argv)
{
    int c;
    int err = 0;

    bo.i = 1;
    defaultpage.vres = 2;
    defaultpage.expander = g31expand;
    PrintCmd = getenv("VIEWFAX_PRINT");
    EditCmd = getenv("VIEWFAX_EDIT");
    opterr = 0;			/* suppress getopt error message */

    if ((ProgName = strrchr(argv[0], '/')) == NULL)
	ProgName = argv[0];
    else
	ProgName++;
    while ((c = getopt(argc, argv, "b:d:fg:h:ilm:nruvWw:z:24")) != -1)
	switch(c) {
	case 'b':
	    abell = vbell = 0;
	    while (*optarg) {
		abell |= (*optarg == 'a');
		vbell |= (*optarg == 'v');
		optarg++;
	    }
	    break;
	case 'd':		/* display name */
	    if (*(DispName = suffix(optarg, "isplay")) == 0)
		DispName = argv[optind++];
	    break;
	case 'f':		/* fine resolution */
	    defaultpage.vres = 1;
	    break;
	case 'g':		/* geometry */
	    if (*(Geometry = suffix(optarg, "eometry")) == 0)
		Geometry = argv[optind++];
	    break;
	case 'h':		/* user thinks this is the height */
	    defaultpage.height = atoi(optarg);
	    break;
	case 'i':		/* invert black/white */
	    defaultpage.inverse = 1;
	    break;
	case 'l':		/* landscape */
	    defaultpage.orient |= TURN_L;
	    break;
	case 'm':		/* memory usage limit */
	    Memlimit = atoi(optarg);
	    switch(optarg[strlen(optarg)-1]) {
	    case 'M':
	    case 'm':
		Memlimit *= 1024;
	    case 'K':
	    case 'k':
		Memlimit *= 1024;
	    }
	    break;
	case 'n':		/* normal resolution */
	    defaultpage.vres = 0;
	    break;
	case 'r':		/* reverse input bits */
	    defaultpage.lsbfirst = 1;
	    break;
	case 'u':		/* upside down */
	    defaultpage.orient |= TURN_U;
	    break;
	case 'v':		/* verbose messages */
	    verbose = 1;
	    break;
	case 'w':		/* user thinks this is the width */
	    defaultpage.width = atoi(optarg);
	    break;
	case 'W':		/* mouse scroll by page */
	    Wheelinv = 1;
	    break;
	case 'z':		/* zoom factor */
	    c = atoi(optarg);
	    if (c <= 0)
		c = 1;
	    for (zfactor = 1; c > 1; c >>= 1)
		zfactor <<= 1;	/* constrain to a power of 2 */
	    break;
	case '2':
	    defaultpage.expander = g32expand;
	    break;
	case '4':
	    defaultpage.expander = g4expand;
	    break;
	default:
	    err++;
	    break;
	}

    if (defaultpage.expander == g4expand && defaultpage.height == 0) {
	fputs("-h value is required to interpret raw g4 faxes\n", stderr);
	err++;
    }

    if (err) {
	fprintf(stderr, Usage, ProgName);
	exit(EXIT_FAILURE);
    }

    if (optind == argc) {
	fputs(Banner, stdout);
	exit(0);
    }

    if (verbose)
	fputs(Banner, stdout);

    firstpage = lastpage = thispage = helppage = NULL;
    for (; optind < argc; optind++)
	(void) notetiff(argv[optind]);

    if (firstpage == NULL)
	exit(EXIT_FAILURE);

    if ((Disp = XOpenDisplay(DispName)) == NULL) {
	fprintf(stderr, "%s: can't open display %s\n", ProgName,
		DispName ? DispName : XDisplayName((char *) NULL));
	exit(EXIT_FAILURE);
    }
    Default_Screen = XDefaultScreen(Disp);
    faxinit();
    thispage = firstpage;
    while (!GetImage(firstpage))
	/* try again */;
    SetupDisplay(argc, argv);
    ShowLoop();
    exit(0);
}

/* return mismatching suffix of option name */
static char *
suffix(char *opt, const char *prefix)
{
    while (*opt && *opt == *prefix) {
	opt++; prefix++;
    }
    return opt;
}

/* Change orientation of all following pages */
static void
TurnFollowing(int How, struct pagenode *pn)
{
    while (pn) {
	if (Pimage(pn)) {
	    FreeImage(Pimage(pn));
	    pn->extra = NULL;
	}
	pn->orient ^= How;
	pn = pn->next;
    }
}

static void
drawline(pixnum *run, int LineNum, struct pagenode *pn)
{
    t32bits *p, *p1;		/* p - current line, p1 - low-res duplicate */
    pixnum *r;			/* pointer to run-lengths */
    t32bits pix;		/* current pixel value */
    t32bits acc;		/* pixel accumulator */
    int nacc;			/* number of valid bits in acc */
    int tot;			/* total pixels in line */
    int n;

    LineNum += pn->stripnum * pn->rowsperstrip;
    if (LineNum >= pn->height) {
	if (verbose && LineNum == pn->height)
	    fputs("Height exceeded\n", stderr);
	return;
    }
    p = (t32bits *) (Pimage(pn)->data + LineNum*(2-pn->vres)*Pimage(pn)->bytes_per_line);
    p1 = pn->vres ? NULL : p + Pimage(pn)->bytes_per_line/sizeof(*p);
    r = run;
    acc = 0;
    nacc = 0;
    pix = pn->inverse ? ~0 : 0;
    tot = 0;
    while (tot < pn->width) {
	n = *r++;
	tot += n;
	/* Watch out for buffer overruns, e.g. when n == 65535.  */
	if (tot > pn->width)
	    break;
	if (pix)
	    acc |= (~(t32bits)0 >> nacc);
	else if (nacc)
	    acc &= (~(t32bits)0 << (32 - nacc));
	else
	    acc = 0;
	if (nacc + n < 32) {
	    nacc += n;
	    pix = ~pix;
	    continue;
	}
	*p++ = acc;
	if (p1)
	    *p1++ = acc;
	n -= 32 - nacc;
	while (n >= 32) {
	    n -= 32;
	    *p++ = pix;
	    if (p1)
		*p1++ = pix;
	}
	acc = pix;
	nacc = n;
	pix = ~pix;
    }
    if (nacc) {
	*p++ = acc;
	if (p1)
	    *p1++ = acc;
    }
}

static int
GetPartImage(struct pagenode *pn, int n)
{
    unsigned char *Data = getstrip(pn, n);

    if (Data == NULL)
	return 0;
    pn->stripnum = n;
    (*pn->expander)(pn, drawline);
    free(Data);
    return 1;
}

static int
GetImage(struct pagenode *pn)
{
    int i;
    XImage *tp;

    if (pn->strips == NULL) {
	/* raw file; maybe we don't have the height yet */
	unsigned char *Data = getstrip(pn, 0);
	if (Data == NULL)
	    return 0;
	pn->extra = NewImage(pn->width, pn->vres ?
			     pn->height : 2*pn->height, NULL, 1);
	(*pn->expander)(pn, drawline);
    }
    else {
	/* multi-strip tiff */
	pn->extra = NewImage(pn->width, pn->vres ?
			     pn->height : 2*pn->height, NULL, 1);
	tp = Pimage(pn);
	pn->stripnum = 0;
	for (i = 0; i < pn->nstrips; i++) {
	    if (verbose) printf("\texpanding strip #%d\n", i);
	    if (GetPartImage(pn, i) == 0) {
		/* pn may no longer exist */
		FreeImage(tp);
		return 0;
	    }
	}
    }
    if (pn->orient & TURN_U)
	pn->extra = FlipImage(Pimage(pn));
    if (pn->orient & TURN_M)
	pn->extra = MirrorImage(Pimage(pn));
    if (pn->orient & TURN_L)
	pn->extra = RotImage(Pimage(pn));
    if (verbose) printf("\tmemused = %lu\n", (unsigned long) Memused);
    return 1;
}

static void
DoExtCmd(char *cmd, int shift)
{
    char *syscmd;

    if (cmd == NULL) return;
    if (shift == 0) {
	syscmd = xmalloc(strlen(cmd) + strlen(thispage->pathname) + 16);
	sprintf(syscmd, "%s -p %d %s", cmd, thispage->pageno,
		thispage->pathname);
    }
    else {
	struct pagenode *pn = firstpage;
	char *prev = NULL;
	int size = strlen(cmd) + 1;

	do {
	    if (prev != pn->pathname)
		size += strlen(pn->pathname) + 1;
	    prev = pn->pathname;
	} while ((pn = pn->next) != NULL);
	syscmd = xmalloc(size);
	pn = firstpage;
	prev = NULL;
	strcpy(syscmd, cmd);
	do {
	    if (prev != pn->pathname) {
		strcat(syscmd, " ");
		strcat(syscmd, pn->pathname);
	    }
	    prev = pn->pathname;
	} while ((pn = pn->next) != NULL);
    }
    system(syscmd);
    free(syscmd);
}

#ifndef _HAVE_USLEEP
static int
usleep(unsigned usecs)
{
    struct timeval t;

    t.tv_sec = usecs/10000000;
    t.tv_usec = usecs%1000000;
    (void) select(1, NULL, NULL, NULL, &t);
    return 0;
}
#endif

#ifndef REAL_ROOT
/* Function Name: GetVRoot
 * Description: Gets the root window, even if it's a virtual root
 * Arguments: the display and the screen
 * Returns: the root window for the client
 *
 * by David Elliott, taken from the x-faq
 */
static Window
GetVRoot(Display *dpy, int scr)
{
    Window rootReturn, parentReturn, *children;
    unsigned int numChildren;
    Window root = RootWindow(dpy, scr);
    Atom __SWM_VROOT = None;
    int i;
 
    __SWM_VROOT = XInternAtom(dpy, "__SWM_VROOT", False);
    XQueryTree(dpy, root, &rootReturn, &parentReturn, &children,
	       &numChildren);
    for (i = 0; i < numChildren; i++) {
        Atom actual_type;
        int actual_format;
        unsigned long nitems, bytesafter;
        Window *newRoot = NULL;
 
        if (XGetWindowProperty(dpy, children[i], __SWM_VROOT, 0, 1,
			       False, XA_WINDOW, &actual_type,
			       &actual_format, &nitems, &bytesafter,
			       (unsigned char **) &newRoot)
					== Success && newRoot) {
	    if (children) XFree(children);
	    return *newRoot;
	}
    }
    return root;
}
#endif

static Atom wm_delete_window;

/* Area the user would like us to use, derived from -geometry */
static struct {
    int v, x, y;
    unsigned int w, h;
} Area = {0, 0, 0};

/* nominal border width */
#define BW 4

/* Figure out the zoom factor needed to fit the fax on the available display */
static void
SetupDisplay(int argc, char **argv)
{
    int Width, Height, i;
    XSetWindowAttributes Attr;
    XSizeHints size_hints;
    Atom wm_protocols;
    int faxh = Pimage(thispage)->height;
    int faxw = Pimage(thispage)->width;

#ifdef REAL_ROOT
    Root = RootWindow(Disp, Default_Screen);
    Width = Area.w = DisplayWidth(Disp, Default_Screen);
    Height = Area.h = DisplayHeight(Disp, Default_Screen);
#elif TVTWM_BIGWINDOW
    XWindowAttributes RootWA;
    Root = GetVRoot(Disp, Default_Screen);
    XGetWindowAttributes(Disp, Root, &RootWA);
    Width = Area.w = RootWA.width;
    Height = Area.h = RootWA.height;
#else
    Root = GetVRoot(Disp, Default_Screen);
    Width = Area.w = DisplayWidth(Disp, Default_Screen);
    Height = Area.h = DisplayHeight(Disp, Default_Screen);
#endif
    if (Geometry)
	Area.v = XParseGeometry(Geometry, &Area.x, &Area.y,
				&Area.w, &Area.h);
    Area.w = max(64, Area.w);
    Area.h = max(64, Area.h);

    if (zfactor == 0)
	for (zfactor = 1;
	     faxw / zfactor > Area.w ||
	     faxh / zfactor > Area.h;
	     zfactor *= 2)
	    ;
    Attr.background_pixel = WhitePixel(Disp, Default_Screen);
    Attr.border_pixel = BlackPixel(Disp, Default_Screen);

    for (size_hints.width = faxw, i = 1; i < zfactor; i *= 2)
	size_hints.width = (size_hints.width + 1) /2;
    for (size_hints.height = faxh, i = 1; i < zfactor; i *= 2)
	size_hints.height = (size_hints.height + 1) /2;

    switch (Area.v & (XValue|XNegative)) {
    case XValue:
	size_hints.x = Area.x + BW;
	break;
    case XValue|XNegative:
	Area.x = Width + Area.x - 2*BW - Area.w;
	size_hints.x = Area.x + Area.w - size_hints.width;
	break;
    default:
	size_hints.x = Area.x + (Area.w - size_hints.width)/2;
    }
    switch (Area.v & (YValue|YNegative)) {
    case YValue:
	size_hints.y = Area.y + BW;
	break;
    case YValue|YNegative:
	Area.y = Height + Area.y - 2*BW - Area.h;
	size_hints.y = Area.y + Area.h - size_hints.height;
	break;
    default:
	size_hints.y = Area.y + (Area.h - size_hints.height)/2;
    }

    size_hints.max_width = size_hints.width;
    size_hints.max_height = size_hints.height;
    size_hints.flags = PSize|PMaxSize;
    if (Area.v & (XValue|YValue)) size_hints.flags |= USPosition;
    if (Area.v & (HeightValue|WidthValue)) size_hints.flags |= USSize;
	
    Win = XCreateWindow(Disp, Root, size_hints.x, size_hints.y,
			size_hints.width, size_hints.height,
			BW, 0, InputOutput, CopyFromParent,
			CWBackPixel|CWBorderPixel, &Attr);
#ifdef PWinGravity
{
    XWMHints wm_hints;
    XClassHint class_hints;
    XTextProperty windowName, iconName;

    if (!XStringListToTextProperty(&thispage->name, 1, &windowName) ||
	!XStringListToTextProperty(&ProgName, 1, &iconName)) {
	fprintf(stderr, "%s: can't make window/icon name\n", ProgName);
	exit(EXIT_FAILURE);
    }
    wm_hints.initial_state = NormalState;
    wm_hints.input = True;
    wm_hints.flags = StateHint|InputHint;
    class_hints.res_name = ProgName;
    class_hints.res_class = "Faxview";
    XSetWMProperties(Disp, Win, &windowName, &iconName, argv, argc,
		     &size_hints, &wm_hints, &class_hints);
}
#else
    XSetStandardProperties(Disp, Win, thispage->name, ProgName,
			   None, argv, argc, &size_hints);
#endif

    PaintGC = XCreateGC(Disp, Win, 0L, (XGCValues *) NULL);
    XSetForeground(Disp, PaintGC, BlackPixel(Disp, Default_Screen));
    XSetBackground(Disp, PaintGC, WhitePixel(Disp, Default_Screen));
    XSetFunction(Disp, PaintGC, GXcopy);
    WorkCursor = XCreateFontCursor(Disp, XC_watch);
    ReadyCursor = XCreateFontCursor(Disp, XC_plus);
    MoveCursor = XCreateFontCursor(Disp, XC_fleur);
    LRCursor = XCreateFontCursor(Disp, XC_sb_h_double_arrow);
    UDCursor = XCreateFontCursor(Disp, XC_sb_v_double_arrow);
    XSelectInput(Disp, Win, Button2MotionMask | ButtonPressMask |
		 ButtonReleaseMask | ExposureMask | KeyPressMask |
		 SubstructureNotifyMask | OwnerGrabButtonMask |
#ifdef USE_MOTIONHINT
		 PointerMotionHintMask |
#endif
		 StructureNotifyMask);
    wm_protocols = XInternAtom(Disp, "WM_PROTOCOLS", False);
    wm_delete_window = XInternAtom(Disp, "WM_DELETE_WINDOW", False);
    XChangeProperty(Disp, Win, wm_protocols, XA_ATOM, 32,
                    PropModeAppend, (unsigned char * ) &wm_delete_window, 1);
    XMapRaised(Disp, Win);
}

#define MAXZOOM	10

/* After requesting a window size change, we throw away key and button presses
   until we get the notification that the size has changed.  If for some
   reason the notification does not come, we resume processing as normal after
   PATIENCE milliseconds */
#define PATIENCE 10000

static void
ShowLoop(void)
{
    XEvent Event;

    /* centre of image within window */
    int x = 0, ox = 0, offx = 0, nx;	/* x, old x, offset x, new x */
    int y = 0, oy = 0, offy = 0, ny;	/* y, old y, offset y, new y */

    int oz, Resize = 0, Refresh = 0;	/* old zoom, window size changed,
					   needs updating */
    int PaneWidth, PaneHeight;		/* current size of our window */
    int AbsX, AbsY;		/* absolute position of centre of window */
    int FrameWidth, FrameHeight, FrameX, FrameY;/* size/offset of decoration */
    int Oversize = 0;		/* window manager insists on oversize window */
    int Reparented = 0;
    int i;
    XImage *Image, *Images[MAXZOOM];
    struct pagenode *viewpage = NULL;	/* page viewed when help requested */
    XSizeHints size_hints;
    Time Lasttime = 0;		/* time of last accepted key/button press */
    int ExpectConfNotify = 1;

    XDefineCursor(Disp, Win, WorkCursor);
    XFlush(Disp);
    for (oz = 0; oz < MAXZOOM; oz++)
	Images[oz] = NULL;
    Image = Images[0] = Pimage(thispage);
    for (oz = 0; oz < MAXZOOM && zfactor > (1 << oz); oz++)
	Images[oz+1] = ZoomImage(Images[oz]);
    Image = Images[oz];

    /* some reasonable values,
       just in case we do not get a configurenotify first */
    AbsX = Area.w/2;
    AbsY = Area.h/2;
    FrameWidth = FrameHeight = FrameX = FrameY = 0;
    PaneWidth = Image->width;
    PaneHeight = Image->height;

    XDefineCursor(Disp, Win, ReadyCursor);

    for (;;) {
	XNextEvent(Disp, &Event);
	do {
	    switch(Event.type) {
	    case MappingNotify:
		XRefreshKeyboardMapping((XMappingEvent *)(&Event));
		break;
	    case ClientMessage:
		if (Event.xclient.data.l[0] == wm_delete_window) {
		    XCloseDisplay(Disp);
		    exit(EXIT_FAILURE);
		}
		break;
	    case Expose:
	    {
		XExposeEvent *p = (XExposeEvent *) &Event;
		XPutImage(Disp, Win, PaintGC, Image,
			  p->x + x - PaneWidth/2,
			  p->y + y - PaneHeight/2,
			  p->x, p->y,
			  p->width, p->height);
	    }
		break;
	    case ReparentNotify:
	    {
		Window Myroot = Root;
		Window Parent = Event.xreparent.parent;
		Window Frame = Parent;	/* I should be so lucky! */
		Window *Mykids;
		unsigned int Nkids;
		XWindowAttributes MyWA, FrameWA;

		if (Parent != Root)
		    do {
			Frame = Parent;
			while (!XQueryTree(Disp, Frame, &Myroot,
					   &Parent, &Mykids, &Nkids))
			    release(1);
			if (Mykids) XFree(Mykids);
		    } while (Parent != Root);
		while (!XGetWindowAttributes(Disp, Win, &MyWA))
		    release(1);
/* bang! */	while (!XGetWindowAttributes(Disp, Frame, &FrameWA))
		    release(1);
		/* if area is partly constrained, stay where the WM put you */
		if ((Area.v & (XValue|WidthValue)) == WidthValue) {
		    Area.v |= XValue;
		    Area.x = FrameWA.x;
		}
		if ((Area.v & (YValue|HeightValue)) == HeightValue) {
		    Area.v |= YValue;
		    Area.y = FrameWA.y;
		}
		XTranslateCoordinates(Disp, Win, Frame, 0, 0,
				      &FrameX, &FrameY, &Parent);
		FrameWidth = FrameWA.width - MyWA.width;
		FrameHeight = FrameWA.height - MyWA.height;
		Reparented = ExpectConfNotify = 1;
	    }
		break;
	    case ConfigureNotify:
	    {
		XConfigureEvent *p = (XConfigureEvent *) &Event;
		int NewX = AbsX;
		int NewY = AbsY;
#ifdef REAL_ROOT
		if (p->send_event || !Reparented) {
		    NewX = p->x + p->width/2;
		    NewY = p->y + p->height/2;
		}
#else
		/* support tvtwm */
		if (!Reparented) {
		    NewX = p->x + p->border_width + p->width/2;
		    NewY = p->y + p->border_width + p->height/2;
		}
		else if (p->send_event) {
		    /* the event info is viewport-relative, we need absolute */
		    Window w;
		    XTranslateCoordinates(Disp, Win, Root, 0, 0,
					  &NewX, &NewY, &w);
		    NewX += p->width/2;
		    NewY += p->height/2;
		}
#endif
		if (!ExpectConfNotify) {
		    /* user intervention */
		    if (PaneWidth != p->width)
			Area.w = p->width + FrameWidth;
		    if (PaneHeight != p->height)
			Area.h = p->height + FrameHeight;
		    if (NewX != AbsX || NewY != AbsY) {
			Area.x = NewX - p->width/2 - FrameX;
			Area.y = NewY - p->height/2 - FrameY;
		    }
		}
		AbsX = NewX; AbsY = NewY;
		PaneWidth = p->width;
		PaneHeight = p->height;
		Oversize = PaneWidth > Image->width ||
		    PaneHeight > Image->height;
		ExpectConfNotify = 0;
	    }
		break;
	    case KeyPress:
		if (ExpectConfNotify &&
		    (Event.xkey.time < (Lasttime + PATIENCE)))
		    break;
		Lasttime = Event.xkey.time;
		ExpectConfNotify = 0;
		switch(XKeycodeToKeysym(Disp, Event.xkey.keycode, 0)) {
		case XK_Help:
		case XK_h:
		    if (helppage == NULL) {
			if (!notetiff(HELPFILE))
			    goto nopage;
			else {
			    helppage = lastpage;
			    lastpage = helppage->prev;
			    lastpage->next = helppage->prev = NULL;
			}
		    }
		    viewpage = thispage;
		    thispage = helppage;
		    goto newpage;
		    break;
		case XK_m:
		    XDefineCursor(Disp, Win, WorkCursor);
		    XFlush(Disp);
		    thispage->extra = Images[0] = MirrorImage(Images[0]);
		    thispage->orient ^= TURN_M;
		    for (i = 1; Images[i]; i++) {
			FreeImage(Images[i]);
			Images[i] = ZoomImage(Images[i-1]);
		    }
		    Image = Images[oz];
		    if (Event.xkey.state & ShiftMask)
			TurnFollowing(TURN_M, thispage->next);
		    XPutImage(Disp, Win, PaintGC, Image,
			      x-PaneWidth/2, y-PaneHeight/2,
			      0, 0, PaneWidth, PaneHeight);
		    XDefineCursor(Disp, Win, ReadyCursor);
		    break;
		case XK_z:
		    if (Event.xkey.state & ShiftMask)
			goto Zoomout;
		    else
			goto Zoomin;
		case XK_Print:
		    DoExtCmd(PrintCmd, Event.xkey.state & ShiftMask);
		    break;
		case XK_e:
		    DoExtCmd(EditCmd, Event.xkey.state & ShiftMask);
		    break;
		case XK_Up:
		    y -= PaneHeight / 2;
		    break;
		case XK_Down:
		    y += PaneHeight / 2;
		    break;
		case XK_Left:
		    x -= PaneWidth / 2;
		    break;
		case XK_Right:
		    x += PaneWidth / 2;
		    break;
		case XK_Home:
		case XK_R7:		/* sun4 keyboard */
		    if (Event.xkey.state & ShiftMask) {
			thispage = firstpage;
			goto newpage;
		    }
		    x = 0;
		    y = 0;
		    break;
		case XK_End:
		case XK_R13:
		    if (Event.xkey.state & ShiftMask) {
			thispage = lastpage;
			goto newpage;
		    }
		    x = Image->width;
		    y = Image->height;
		    break;
		case XK_l:
		    XDefineCursor(Disp, Win, WorkCursor);
		    XFlush(Disp);
		    thispage->extra = Image = RotImage(Images[0]);
		    thispage->orient ^= TURN_L;
		    for (i = 1; Images[i]; i++) {
			FreeImage(Images[i]);
			Images[i] = NULL;
		    }
		    Images[0] = Image;
		    for (i = 1; i <= oz; i++)
			Images[i] = ZoomImage(Images[i-1]);
		    Image = Images[oz];
		    if (Event.xkey.state & ShiftMask)
			TurnFollowing(TURN_L, thispage->next);
		{ int t = x; x = y; y = t; }
		    Refresh = Resize = 1;
		    XDefineCursor(Disp, Win, ReadyCursor);
		    break;
		case XK_p:
		case XK_minus:
		case XK_Prior:
		case XK_R9:
		case XK_BackSpace:
		  prevpage:
		    if (thispage->prev == NULL)
			goto nopage;
		    thispage = thispage->prev;
		    goto newpage;
		case XK_n:
		case XK_plus:
		case XK_space:
		case XK_Next:
		case XK_R15:
		  nextpage:
		    if (thispage->next == NULL) {
		    nopage:
			if (abell) {
			    putchar('\a');
			    fflush(stdout);
			}
			if (vbell) {
			    XAddPixel(Image, 1);
			    XPutImage(Disp, Win, PaintGC, Image,
				      x-PaneWidth/2, y-PaneHeight/2,
				      0, 0, PaneWidth, PaneHeight);
			    XSync(Disp, 0);
			    (void) usleep(200000);
			    XAddPixel(Image, 1);
			    XPutImage(Disp, Win, PaintGC, Image,
				      x-PaneWidth/2, y-PaneHeight/2,
				      0, 0, PaneWidth, PaneHeight);
			}
			break;
		    }
		    thispage = thispage->next;
		newpage:
		    XDefineCursor(Disp, Win, WorkCursor);
		    XFlush(Disp);
		    /* if old image was not resized by the user, fit new one */
		    Resize = ((PaneWidth == Image->width ||
			       PaneWidth == Area.w - FrameWidth) &&
			      (PaneHeight == Image->height ||
			       PaneHeight == Area.h - FrameHeight));
		    for (i = 1; Images[i]; i++) {
			FreeImage(Images[i]);
			Images[i] = NULL;
		    }
		    if (Pimage(thispage) == NULL)
			while (!GetImage(thispage))
			    /* try again */;
		    Images[0] = Pimage(thispage);
		    XStoreName(Disp, Win, thispage->name);
		    for (i = 1; i <= oz; i++)
			Images[i] = ZoomImage(Images[i-1]);
		    Image = Images[oz];
		    Refresh = 1;
		    XDefineCursor(Disp, Win, ReadyCursor);
		    break;
		case XK_u:
		    XDefineCursor(Disp, Win, WorkCursor);
		    XFlush(Disp);
		    thispage->extra = Images[0] = FlipImage(Images[0]);
		    thispage->orient ^= TURN_U;
		    for (i = 1; Images[i]; i++) {
			FreeImage(Images[i]);
			Images[i] = ZoomImage(Images[i-1]);
		    }
		    Image = Images[oz];
		    if (Event.xkey.state & ShiftMask)
			TurnFollowing(TURN_U, thispage->next);
		    XPutImage(Disp, Win, PaintGC, Image,
			      x-PaneWidth/2, y-PaneHeight/2,
			      0, 0, PaneWidth, PaneHeight);
		    XDefineCursor(Disp, Win, ReadyCursor);
		    break;
		case XK_q:
		    if (viewpage) {
			thispage = viewpage;
			viewpage = NULL;
			goto newpage;
		    }
		    XCloseDisplay(Disp);
#ifdef xmalloc
		    malloc_shutdown();
#endif
		    exit((Event.xkey.state & ShiftMask) ? EXIT_FAILURE : 0);
		}
		break;
	    case ButtonPress:
		if (ExpectConfNotify &&
		    (Event.xbutton.time < (Lasttime + PATIENCE)))
		    break;
		Lasttime = Event.xbutton.time;
		ExpectConfNotify = 0;
		switch (Event.xbutton.button) {
		case Button1:
		Zoomout:
		    if (oz > 0) {
			Image = Images[--oz];
			zfactor >>= 1;
			x *= 2;
			y *= 2;
			Resize = Refresh = 1;
		    }
		    break;
		case Button2:
		    switch (((Image->width > PaneWidth)<<1) |
			    (Image->height > PaneHeight)) {
		    case 0:
			break;
		    case 1:
			XDefineCursor(Disp, Win, UDCursor);
			break;
		    case 2:
			XDefineCursor(Disp, Win, LRCursor);
			break;
		    case 3:
			XDefineCursor(Disp, Win, MoveCursor);
		    }
		    XFlush(Disp);
		    offx = Event.xbutton.x;
		    offy = Event.xbutton.y;
		    break;
		case Button3:
		Zoomin:
		    if (oz < MAXZOOM && Image->width >= 64 && zfactor < 32) {
			Image = Images[++oz];
			zfactor <<= 1;
			x /= 2;
			y /= 2;
			Resize = Refresh = 1;
		    }
		    break;
		case Button4:
		    if ((Event.xkey.state & ShiftMask) ^ Wheelinv)
			goto prevpage;
		    y -= PaneHeight / 30;
		    break;
		case Button5:
		    if ((Event.xkey.state & ShiftMask) ^ Wheelinv)
			goto nextpage;
		    y += PaneHeight / 30;
		    break;
		}		    
		if (Image == NULL) {
		    for (i = oz; i && (Images[i] == NULL); i--)
			;
		    for (; i != oz; i++)
			Images[i+1] = ZoomImage(Images[i]);
		    Image = Images[oz];
		}
		break;
	    case MotionNotify:
#ifdef USE_MOTIONHINT
	    {
		unsigned int Junk;
		Window JunkW;
		XQueryPointer(Disp, Event.xmotion.window, &JunkW, &JunkW,
			      &Junk, &Junk, &nx, &ny, &Junk);
	    }
#else
		do {
		    nx = Event.xmotion.x;
		    ny = Event.xmotion.y;
		} while (XCheckTypedEvent(Disp, MotionNotify, &Event));
#endif
		x += offx - nx;
		y += offy - ny;
		offx = nx;
		offy = ny;
		break;
	    case ButtonRelease:
		if (Event.xbutton.button == Button2) {
		    XDefineCursor(Disp, Win, ReadyCursor);
		    XFlush(Disp);
		}
	    }
	} while (XCheckWindowEvent(Disp, Win,
				   KeyPressMask|ButtonPressMask, &Event));

	/* if someone thinks we should resize the window and it is not
	   already the right size, or if the window is too big and we
	   have not already tried to make it smaller ... */
	if ((Resize && !(Image->width == PaneWidth &&
			 Image->height == PaneHeight)) ||
	    (!Oversize && (Image->width < PaneWidth ||
			   Image->height < PaneHeight))) {
	    int PosX = AbsX - PaneWidth/2 - FrameX;
	    int PosY = AbsY - PaneHeight/2 - FrameY;
	    XWindowChanges New;
	    int ChangeMask = 0;

	    New.width = min(Area.w - FrameWidth, Image->width);
	    New.height = min(Area.h - FrameHeight, Image->height);
	    /* expect an expose if size must change */
	    Refresh &= (New.width == PaneWidth && New.height == PaneHeight);
	    New.x = max(Area.x, AbsX-New.width/2-FrameX);
	    New.x = min(New.x, Area.w-(New.width+FrameWidth)+Area.x);
	    New.y = max(Area.y, AbsY-New.height/2-FrameY);
	    New.y = min(New.y, Area.h-(New.height+FrameHeight)+Area.y);

	    /* mwm takes max_size very seriously! */
	    size_hints.flags = 0;
	    XSetNormalHints(Disp, Win, &size_hints);

	    size_hints.flags = PMaxSize;
	    size_hints.x = PosX;
	    size_hints.y = PosY;
	    size_hints.width = PaneWidth;
	    size_hints.height = PaneHeight;
	    /* only move a coordinate if the ideal new value is different
	       from the current value and either the other dimension has
	       changed or the current value is out of area */
	    if (PosX != New.x &&
		(New.height != PaneHeight || PosX < Area.x || 
		 PosX > Area.w-New.width-FrameWidth-Area.x)) {
		ChangeMask |= CWX;
		size_hints.x = New.x;
		size_hints.flags |= PPosition;
	    }
	    if (PosY != New.y &&
		(New.width != PaneWidth || PosY < Area.y ||
		 PosY > Area.h-New.height-FrameHeight-Area.y)) {
		ChangeMask |= CWY;
		size_hints.y = New.y;
		size_hints.flags |= PPosition;
	    }
	    if (New.width != PaneWidth) {
		ChangeMask |= CWWidth;
		size_hints.width = New.width;
		size_hints.flags |= PSize;
		ExpectConfNotify = Reparented;
	    }
	    if (New.height != PaneHeight) {
		ChangeMask |= CWHeight;
		size_hints.height = New.height;
		size_hints.flags |= PSize;
		ExpectConfNotify = Reparented;
	    }
	    New.border_width = 1;	/* ICCCM 4.1.5 */
	    ChangeMask |= CWBorderWidth;
	    XConfigureWindow(Disp, Win, ChangeMask, &New);
	    size_hints.max_width = Image->width;
	    size_hints.max_height = Image->height;
	    XSetNormalHints(Disp, Win, &size_hints);
	}
	x = max(x, PaneWidth/2);
	x = min(x, Image->width-PaneWidth/2);
	y = max(y, PaneHeight/2);
	y = min(y, Image->height-PaneHeight/2);
	if (x != ox || y != oy || Refresh)
	    XPutImage(Disp, Win, PaintGC, Image,
		      x-PaneWidth/2, y-PaneHeight/2,
		      0, 0, PaneWidth, PaneHeight);
	ox = x;
	oy = y;
	Resize = Refresh = 0;
    }
}

/* run this region through perl to generate the zoom table:
$lim = 1;
@c = ("0", "1", "1", "2");
print "static unsigned char Z[] = {\n";
for ($i = 0; $i < 16; $i++) {
    for ($j = 0; $j < 16; $j++) {
	$b1 = ($c[$j&3]+$c[$i&3]) > $lim;
	$b2 = ($c[($j>>2)&3]+$c[($i>>2)&3]) > $lim;
	printf " %X,", ($b2 << 1) | $b1;
    }
    print "\n";
}
print "};\n";
*/
static unsigned char Z[] = {
 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 2, 2, 2, 3,
 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 2, 3, 3, 3,
 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 2, 3, 3, 3,
 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3,
 0, 0, 0, 1, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3,
 0, 1, 1, 1, 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3,
 0, 1, 1, 1, 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3,
 1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
 0, 0, 0, 1, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3,
 0, 1, 1, 1, 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3,
 0, 1, 1, 1, 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3,
 1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3,
 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3,
 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3,
 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
};

#define nib(n,w)	(((w)>>((n)<<2))&15)
#define zak(a,b)	Z[(a<<4)|b]

/* 2 -> 1 zoom, 4 pixels -> 1 pixel
   if #pixels <= $lim (see above), new pixel is white,
   else black.
*/
static XImage *
ZoomImage(XImage *Big)
{
    XImage *Small;
    int w, h;
    int i, j;

    XDefineCursor(Disp, Win, WorkCursor);
    XFlush(Disp);
    w = (Big->width+1) / 2;
    h = (Big->height+1) / 2;
    Small = NewImage(w, h, NULL, Big->bitmap_bit_order);
    Small->xoffset = (Big->xoffset+1)/2;
    for (i = 0; i < Big->height; i += 2) {
	t32bits *pb0 = (t32bits *) (Big->data + i * Big->bytes_per_line);
	t32bits *pb1 = pb0 + ((i == Big->height-1) ? 0 : Big->bytes_per_line/4);
	t32bits *ps = (t32bits *) (Small->data + i * Small->bytes_per_line / 2);
	for (j = 0; j < Big->bytes_per_line/8; j++) {
	    t32bits r1, r2;
	    t32bits t0 = *pb0++;
	    t32bits t1 = *pb1++;
	    r1 = (zak(nib(7,t0),nib(7,t1))<<14) |
		 (zak(nib(6,t0),nib(6,t1))<<12) |
		 (zak(nib(5,t0),nib(5,t1))<<10) |
		 (zak(nib(4,t0),nib(4,t1))<<8) |
		 (zak(nib(3,t0),nib(3,t1))<<6) |
		 (zak(nib(2,t0),nib(2,t1))<<4) |
		 (zak(nib(1,t0),nib(1,t1))<<2) |
		 (zak(nib(0,t0),nib(0,t1)));
	    t0 = *pb0++;
	    t1 = *pb1++;
	    r2 = (zak(nib(7,t0),nib(7,t1))<<14) |
		 (zak(nib(6,t0),nib(6,t1))<<12) |
		 (zak(nib(5,t0),nib(5,t1))<<10) |
		 (zak(nib(4,t0),nib(4,t1))<<8) |
		 (zak(nib(3,t0),nib(3,t1))<<6) |
		 (zak(nib(2,t0),nib(2,t1))<<4) |
		 (zak(nib(1,t0),nib(1,t1))<<2) |
		 (zak(nib(0,t0),nib(0,t1)));
	    *ps++ = (Big->bitmap_bit_order) ?
		(r1<<16)|r2 : (r2<<16)|r1;
	}
	for ( ; j < Small->bytes_per_line/4; j++) {
	    t32bits r1;
	    t32bits t0 = *pb0++;
	    t32bits t1 = *pb1++;
	    r1 = (zak(nib(7,t0),nib(7,t1))<<14) |
		 (zak(nib(6,t0),nib(6,t1))<<12) |
		 (zak(nib(5,t0),nib(5,t1))<<10) |
		 (zak(nib(4,t0),nib(4,t1))<<8) |
		 (zak(nib(3,t0),nib(3,t1))<<6) |
		 (zak(nib(2,t0),nib(2,t1))<<4) |
		 (zak(nib(1,t0),nib(1,t1))<<2) |
		 (zak(nib(0,t0),nib(0,t1)));
	    *ps++ = (Big->bitmap_bit_order) ?
		(r1<<16) : r1;
	}
    }
    XDefineCursor(Disp, Win, ReadyCursor);
    return Small;
}

static XImage *
FlipImage(XImage *Image)
{
    XImage *New = NewImage(Image->width, Image->height,
			   Image->data, !Image->bitmap_bit_order);
    t32bits *p1 = (t32bits *) Image->data;
    t32bits *p2 = (t32bits *) (Image->data + Image->height *
			     Image->bytes_per_line - 4);

    /* the first shall be last ... */
    while (p1 < p2) {
	t32bits t = *p1;
	*p1++ = *p2;
	*p2-- = t;
    }

    /* let Xlib twiddle the bits */
    New->xoffset = 32 - (Image->width & 31) - Image->xoffset;
    New->xoffset &= 31;

    Image->data = NULL;
    FreeImage(Image);
    return New;
}

static XImage *
MirrorImage(XImage *Image)
{
    int i;
    XImage *New = NewImage(Image->width, Image->height,
			   Image->data, !Image->bitmap_bit_order);

    /* reverse order of 32-bit words in each line */
    for (i = 0; i < Image->height; i++) {
	t32bits *p1 = (t32bits *) (Image->data + Image->bytes_per_line * i);
	t32bits *p2 = p1 + Image->bytes_per_line/4 - 1;
	while (p1 < p2) {
	    t32bits t = *p1;
	    *p1++ = *p2;
	    *p2-- = t;
	}
    }

    /* let Xlib twiddle the bits */
    New->xoffset = 32 - (Image->width & 31) - Image->xoffset;
    New->xoffset &= 31;

    Image->data = NULL;
    FreeImage(Image);
    return New;
}

static XImage *
RotImage(XImage *Image)
{
    XImage *New;
    int w = Image->height;
    int h = Image->width;
    int i, j, k, shift;
    int order = Image->bitmap_bit_order;
    int offs = h+Image->xoffset-1;

    New = NewImage(w, h, NULL, 1);

    k = (32 - Image->xoffset) & 3;
    for (i = h - 1; i && k; i--, k--) {
	t32bits *sp = (t32bits *) Image->data + (offs-i)/32;
	t32bits *dp = (t32bits *) (New->data+i*New->bytes_per_line);
	t32bits d0;
	shift = (offs-i)&31;
	if (order) shift = 31-shift;
	for (j = 0; j < w; j++) {
	    t32bits t = *sp;
	    sp += Image->bytes_per_line/4;
	    d0 |= ((t >> shift) & 1);
	    if ((j & 31) == 31)
		*dp++ = d0;
	    d0 <<= 1;;
	}
	if (j & 31)
	    *dp++ = d0<<(31-j);
    }
    for ( ; i >= 3; i-=4) {
	t32bits *sp = (t32bits *) Image->data + (offs-i)/32;
	t32bits *dp0 = (t32bits *) (New->data+i*New->bytes_per_line);
	t32bits *dp1 = dp0 - New->bytes_per_line/4;
	t32bits *dp2 = dp1 - New->bytes_per_line/4;
	t32bits *dp3 = dp2 - New->bytes_per_line/4;
	t32bits d0, d1, d2, d3;
	shift = (offs-i)&31;
	if (order) shift = 28-shift;
	for (j = 0; j < w; j++) {
	    t32bits t = *sp >> shift;
	    sp += Image->bytes_per_line/4;
	    d0 |= t & 1; t >>= 1;
	    d1 |= t & 1; t >>= 1;
	    d2 |= t & 1; t >>= 1;
	    d3 |= t & 1; t >>= 1;
	    if ((j & 31) == 31) {
		if (order) {
		    *dp0++ = d3;
		    *dp1++ = d2;
		    *dp2++ = d1;
		    *dp3++ = d0;
		}
		else {
		    *dp0++ = d0;
		    *dp1++ = d1;
		    *dp2++ = d2;
		    *dp3++ = d3;
		}
	    }
	    d0 <<= 1; d1 <<= 1; d2 <<= 1; d3 <<= 1;
	}
	if (j & 31) {
	    if (order) {
		*dp0++ = d3<<(31-j);
		*dp1++ = d2<<(31-j);
		*dp2++ = d1<<(31-j);
		*dp3++ = d0<<(31-j);
	    }
	    else {
		*dp0++ = d0<<(31-j);
		*dp1++ = d1<<(31-j);
		*dp2++ = d2<<(31-j);
		*dp3++ = d3<<(31-j);
	    }
	}
    }
    for (; i >= 0; i--) {
	t32bits *sp = (t32bits *) Image->data + (offs-i)/32;
	t32bits *dp = (t32bits *) (New->data+i*New->bytes_per_line);
	t32bits d0;
	shift = (offs-i)&31;
	if (order) shift = 31-shift;
	for (j = 0; j < w; j++) {
	    t32bits t = *sp;
	    sp += Image->bytes_per_line/4;
	    d0 |= ((t >> shift) & 1);
	    if ((j & 31) == 31)
		*dp++ = d0;
	    d0 <<= 1;;
	}
	if (j & 31)
	    *dp++ = d0<<(31-j);
    }
    FreeImage(Image);
    return New;
}

/* release some non-essential memory or abort */
#define Try(n)								\
    if (n && n != thispage && n->extra) {				\
	FreeImage(n->extra);						\
	n->extra = NULL;						\
	return 1;							\
    }

static int
release(int quit)
{
    struct pagenode *pn;

    if (thispage) {
	/* first consider "uninteresting" pages */
	for (pn = firstpage->next; pn; pn = pn->next)
	    if (pn->extra && pn != thispage && pn != thispage->prev &&
		pn != thispage->next && pn != lastpage) {
		FreeImage(Pimage(pn));
		pn->extra = NULL;
		return 1;
	    }
	Try(lastpage);
	Try(firstpage);
	Try(thispage->prev);
	Try(thispage->next);
    }
    if (!quit)
	return 0;
    fprintf(stderr, "%s(release): insufficient memory\n", ProgName);
    exit(EXIT_FAILURE);
}

static XImage *
NewImage(int w, int h, char *data, int bit_order)
{
    XImage *new;
    /* This idea is taken from xwud/xpr.  Use a fake display with the
       desired bit/byte order to get the image routines initialised
       correctly */
    Display fake;

    fake = *Disp;
    if (data == NULL)
	data = xmalloc(((w + 31) & ~31) * h / 8);
    fake.byte_order = ByteOrder;
    fake.bitmap_unit = 32;
    fake.bitmap_bit_order = bit_order;

    while ((new = XCreateImage(&fake, DefaultVisual(Disp, Default_Screen),
			       1, XYBitmap, 0, data, w, h, 32, 0)) == NULL)
	(void) release(1);
    Memused += new->bytes_per_line * new->height;
    return new;
}

static void
FreeImage(XImage *Image)
{
    if (Image->data)
	Memused -= Image->bytes_per_line * Image->height;
    XDestroyImage(Image);
}

#ifndef xmalloc
char *
xmalloc(unsigned int size)
{
    char *p;

    while (Memused + size > Memlimit && release(0))
	;
    while ((p = malloc(size)) == NULL)
	(void) release(1);
    return p;
}
#endif
