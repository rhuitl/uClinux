/*      $Id: irxevent.c,v 5.5 2001/03/03 21:34:58 columbus Exp $      */

/****************************************************************************
 ** irxevent.c **************************************************************
 ****************************************************************************
 *
 * irxevent  - infra-red xevent sender
 *
 * Heinrich Langos  <heinrich@null.net>
 * small modifications by Christoph Bartelmus <lirc@bartelmus.de>
 *
 * irxevent is based on irexec (Copyright (C) 1998 Trent Piepho)
 * and irx.c (no copyright notice found)
 *
 *  =======
 *  HISTORY
 *  =======
 *
 * 0.1 
 *     -Initial Release
 *
 * 0.2 
 *     -no more XWarpPointer... sending Buttonclicks to off-screen
 *      applications works becaus i also fake the EnterNotify and LeaveNotify
 *     -support for keysymbols rather than characters... so you can use
 *      Up or Insert or Control_L ... maybe you could play xquake than :*)
 *
 * 0.3
 *     -bugfix for looking for subwindows of non existing windows 
 *     -finaly a README file
 *
 * 0.3a (done by Christoph Bartelmus)
 *     -read from a shared .lircrc file 
 *     -changes to comments
 *     (chris, was that all you changed?)
 *
 * 0.4
 *     -fake_timestamp() to solve gqmpeg problems 
 *     -Shift Control and other mod-keys may work. (can't check it right now)
 *      try ctrl-c or shift-Page_up or whatever ...
 *      modifiers: shift, caps, ctrl, alt, meta, numlock, mod3, mod4, scrlock
 *     -size of 'char *keyname' changed from 64 to 128 to allow all mod-keys. 
 *     -updated irxevent.README
 *
 * 0.4.1
 *     -started to make smaller version steps :-)
 *     -Use "CurrentWindow" as window name to send events to the window
 *      that -you guessed it- currently has the focus.
 *
 * 0.4.2
 *     -fixed a stupid string bug in key sending.
 *     -updated irxevent.README to be up to date with the .lircrc format.
 *
 * 0.4.3
 *     -changed DEBUG functions to actually produce some output :)
 *
 * 0.5.0
 *     -fixed finding subwindows recursively
 *     -added xy_Key (though xterm and xemacs still don´t like me)
 *     -added compilation patch from Ben Hochstedler 
 *      <benh@eeyore.moneng.mei.com> for compiling on systems 
 * 	without strsep() (like some solaris)
 *
 *
 * see http://www.wh9.tu-dresden.de/~heinrich/lirc/irxevent/irxevent.keys
 * for a the key names. (this one is for you Pablo :-) )
 *
 * for more information see the irxevent.README file
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <sys/time.h>
#include <unistd.h>

#include "lirc_client.h"

/* #define DEBUG */
#ifdef DEBUG
void debugprintf(char *format_str, ...)
{
        va_list ap;
        va_start(ap,format_str);
        vfprintf(stderr,format_str,ap);
        va_end(ap);
}
#else
void debugprintf(char *format_str, ...)
{
}
#endif


struct keymodlist_t {
        char *name;
        Mask mask;
};
static struct keymodlist_t keymodlist[]=
{
  {"SHIFT",   ShiftMask},
  {"CAPS",    LockMask},
  {"CTRL",    ControlMask},
  {"ALT",     Mod1Mask},{"META",    Mod1Mask},
  {"NUMLOCK", Mod2Mask},
  {"MOD3",    Mod3Mask},  /* I don't have a clue what key maps to this. */
  {"MOD4",    Mod4Mask},  /* I don't have a clue what key maps to this. */
  {"SCRLOCK", Mod5Mask},
  {NULL,0},
};

const char *key_delimiter ="-";
const char *active_window_name ="CurrentWindow";


char *progname;
Display *dpy;
Window root;
XEvent xev;
Window w,subw;

Time fake_timestamp()
     /*seems that xfree86 computes the timestamps like this     */
     /*strange but it relies on the *1000-32bit-wrap-around     */
     /*if anybody knows exactly how to do it, please contact me */
{
  int  tint;
  struct timeval  tv;
  struct timezone tz; /* is not used since ages */
  gettimeofday(&tv,&tz);
  tint=(int)tv.tv_sec*1000;
  tint=tint/1000*1000;
  tint=tint+tv.tv_usec/1000;
  return (Time)tint;
}

Window find_window(Window top,char *name)
{
  char *wname,*iname;
  XClassHint xch;
  Window *children,foo;
  int revert_to_return;
  unsigned int nc;
  if (!strcmp(active_window_name,name)){
    XGetInputFocus(dpy, &foo, &revert_to_return);
    return(foo);
  }
  /* First the base case */
  if (XFetchName(dpy,top,&wname)){
    if (!strncmp(wname,name,strlen(name)))  {
      XFree(wname);
      debugprintf("found it by wname %x \n",top);
      return(top);  /* found it! */
    };
    XFree(wname);
  };

  if(XGetIconName(dpy,top,&iname)){
    if (!strncmp(iname,name,strlen(name)))  {
      XFree(iname);
      debugprintf("found it by iname %x \n",top);
      return(top);  /* found it! */
    };
    XFree(iname);
  };

  if(XGetClassHint(dpy,top,&xch))  {
    if(!strcmp(xch.res_class,name))  {
      XFree(xch.res_name); XFree(xch.res_class);
      debugprintf("res_class '%s' res_name '%s' %x \n", xch.res_class,xch.res_name,top);
      return(top);  /* found it! */
    };
    if(!strcmp(xch.res_name,name))  {
      XFree(xch.res_name); XFree(xch.res_class);
      debugprintf("res_class '%s' res_name '%s' %x \n", xch.res_class,xch.res_name,top);
      return(top);  /* found it! */
    };
    XFree(xch.res_name); XFree(xch.res_class);
  };

  if(!XQueryTree(dpy,top,&foo,&foo,&children,&nc) || children==NULL) {
    return(0);  /* no more windows here */
  };

  /* check all the sub windows */
  for(;nc>0;nc--)  {
    top = find_window(children[nc-1],name);
    if(top) break;  /* we found it somewhere */
  };
  if(children!=NULL) XFree(children);
  return(top);
}

Window find_sub_sub_window(Window top,int *x, int *y)
{
  Window base;
  Window *children,foo,target=0;
  unsigned int nc,
    rel_x,rel_y,width,height,border,depth,
    new_x=1,new_y=1,
    targetsize=1000000;

  base=top;
  if (!base) {return base;};
  if(!XQueryTree(dpy,base,&foo,&foo,&children,&nc) || children==NULL) {
    return(base);  /* no more windows here */
  };
  debugprintf("found subwindows %d\n",nc);

  /* check if we hit a sub window and find the smallest one */
  for(;nc>0;nc--)  {
    if(XGetGeometry(dpy, children[nc-1], &foo, &rel_x, &rel_y, 
		    &width, &height, &border, &depth)){
      if ((rel_x<=*x)&&(*x<=rel_x+width)&&(rel_y<=*y)&&(*y<=rel_y+height)){
	debugprintf("found a subwindow %x +%d +%d  %d x %d   \n",children[nc-1], rel_x,rel_y,width,height);
	if ((width*height)<targetsize){
	  target=children[nc-1];
	  targetsize=width*height;
	  new_x=*x-rel_x;
	  new_y=*y-rel_y;
	  /*bull's eye ...*/
	  target=find_sub_sub_window(target,&new_x,&new_y);
	}
      }	
    }
  };
  if(children!=NULL) XFree(children);
  if (target){
    *x=new_x;
    *y=new_y;
    return target;
  }else
    return base;
}



Window find_sub_window(Window top,char *name,int *x, int *y)
{
  Window base;
  Window *children,foo,target=0;
  unsigned int nc,
    rel_x,rel_y,width,height,border,depth,
    new_x=1,new_y=1,
    targetsize=1000000;

  base=find_window(top, name);
  if (!base) {return base;};
  if(!XQueryTree(dpy,base,&foo,&foo,&children,&nc) || children==NULL) {
    return(base);  /* no more windows here */
  };
  debugprintf("found subwindows %d\n",nc);

  /* check if we hit a sub window and find the smallest one */
  for(;nc>0;nc--)  {
    if(XGetGeometry(dpy, children[nc-1], &foo, &rel_x, &rel_y, 
		    &width, &height, &border, &depth)){
      if ((rel_x<=*x)&&(*x<=rel_x+width)&&(rel_y<=*y)&&(*y<=rel_y+height)){
	debugprintf("found a subwindow %x +%d +%d  %d x %d   \n",children[nc-1], rel_x,rel_y,width,height);
	if ((width*height)<targetsize){
	  target=children[nc-1];
	  targetsize=width*height;
	  new_x=*x-rel_x;
	  new_y=*y-rel_y;
	  /*bull's eye ...*/
	  target=find_sub_sub_window(target,&new_x,&new_y);
	}
      }	
    }
  };
  if(children!=NULL) XFree(children);
  if (target){
    *x=new_x;
    *y=new_y;
    return target;
  }else
    return base;
}


void make_button(int button,int x,int y,XButtonEvent *xev)
{
  xev->type = ButtonPress;
  xev->display=dpy;
  xev->root=root;
  xev->subwindow=None;
  xev->time=fake_timestamp();
  xev->x=x;xev->y=y;
  xev->x_root=1; xev->y_root=1;
  xev->state=0;
  xev->button=button;
  xev->same_screen=True;

  return;
}

void make_key(char *keyname,int x, int y,XKeyEvent *xev)
{
  char *part, *part2;
  struct keymodlist_t *kmlptr;
#ifndef HAVE_STRSEP
  char tmpkeyname[128];
  strncpy(tmpkeyname,keyname,128);
#endif
  part2=malloc(128);

  xev->type = KeyPress;
  xev->display=dpy;
  xev->root=root;
  xev->subwindow = None;
  xev->time=fake_timestamp();
  xev->x=x; xev->y=y;
  xev->x_root=1; xev->y_root=1;
  xev->same_screen = True;

  xev->state=0;
#ifdef HAVE_STRSEP
  while ((part=strsep(&keyname, key_delimiter)))
#else
  while ((part=strtok(tmpkeyname, key_delimiter)))
#endif
    {
      part2=strncpy(part2,part,128);
      //      debugprintf("-   %s \n",part);
      kmlptr=keymodlist;
      while (kmlptr->name)
	{
	  //	  debugprintf("--  %s %s \n", kmlptr->name, part);
	  if (!strcasecmp(kmlptr->name, part))
	    xev->state|=kmlptr->mask;
	  kmlptr++;
	}
      //      debugprintf("--- %s \n",part);
    } 
  //  debugprintf("*** %s \n",part);
  //  debugprintf("*** %s \n",part2);
  xev->keycode=XKeysymToKeycode(dpy,XStringToKeysym(part2));
  debugprintf("state 0x%x, keycode 0x%x\n",xev->state, xev->keycode);
  free(part2);
  return ;
}

void sendfocus(Window w,int in_out)
{
  XFocusChangeEvent focev;

  focev.display=dpy;
  focev.type=in_out;
  focev.window=w;
  focev.mode=NotifyNormal;
  focev.detail=NotifyPointer;
  XSendEvent(dpy,w,True,FocusChangeMask,(XEvent*)&focev);
  XSync(dpy,True);
  
  return;
}

void sendpointer_enter_or_leave(Window w,int in_out)
{
  XCrossingEvent crossev;
  crossev.type=in_out;
  crossev.display=dpy;
  crossev.window=w;
  crossev.root=root;
  crossev.subwindow=None;
  crossev.time=fake_timestamp();
  crossev.x=1;
  crossev.y=1;
  crossev.x_root=1;
  crossev.y_root=1;
  crossev.mode=NotifyNormal;
  crossev.detail=NotifyNonlinear;
  crossev.same_screen=True;
  crossev.focus=True;
  crossev.state=0;
  XSendEvent(dpy,w,True,EnterWindowMask|LeaveWindowMask,(XEvent*)&crossev);
  XSync(dpy,True);
  return;
}

void sendkey(char *keyname,int x,int y,Window w,Window s)
{
  make_key(keyname ,x,y,(XKeyEvent*)&xev);
  xev.xkey.window=w;
  xev.xkey.subwindow=s;

  if (s) sendfocus(s,FocusIn);

  XSendEvent(dpy,w,True,KeyPressMask,&xev);
  xev.type = KeyRelease;
  usleep(2000);
  xev.xkey.time = fake_timestamp();
  if (s) sendfocus(s,FocusOut);
  XSendEvent(dpy,w,True,KeyReleaseMask,&xev);
  XSync(dpy,True);
  return;
}

void sendbutton(int button, int x, int y, Window w,Window s)
{
  make_button(button,x,y,(XButtonEvent*)&xev);
  xev.xbutton.window=w;
  xev.xbutton.subwindow=s;
  sendpointer_enter_or_leave(w,EnterNotify);
  sendpointer_enter_or_leave(s,EnterNotify);

  XSendEvent(dpy,w,True,ButtonPressMask,&xev);
  XSync(dpy,True);
  xev.type = ButtonRelease;
  xev.xkey.state|=0x100;
  usleep(1000);
  xev.xkey.time = fake_timestamp(); 
  XSendEvent(dpy,w,True,ButtonReleaseMask,&xev);
  sendpointer_enter_or_leave(s,LeaveNotify);
  sendpointer_enter_or_leave(w,LeaveNotify);
  XSync(dpy,True);

  return;
}


int check(char *s)
{
  int d;
  char *buffer;

  buffer=malloc(strlen(s));
  if(buffer==NULL)
    {
      fprintf(stderr,"%s: out of memory\n",progname);
      return(-1);
    }

  if(2!=sscanf(s,"Key %s %s\n",buffer,buffer) &&
     4!=sscanf(s,"Button %d %d %d %s\n",&d,&d,&d,buffer) &&
     4!=sscanf(s,"xy_Key %d %d %s %s\n",&d,&d,buffer,buffer))
    {
      fprintf(stderr,"%s: bad config string \"%s\"\n",progname,s);
      free(buffer);
      return(-1);
    }
  free(buffer);  
  return(0);
}

int main(int argc, char *argv[])
{
  char keyname[128];
  int pointer_button,pointer_x,pointer_y;
  char windowname[64];
  struct lirc_config *config;

  progname=argv[0];
  if(argc>2)  {
    fprintf(stderr,"Usage: %s <config file>\n",argv[0]);
    exit(1);
  };

  dpy=XOpenDisplay(NULL);
  if(dpy==NULL) {
    fprintf(stderr,"Can't open DISPLAY.\n");
    exit(1);
  }
  root=RootWindow(dpy,DefaultScreen(dpy));

  if(lirc_init("irxevent",1)==-1) exit(EXIT_FAILURE);

  if(lirc_readconfig(argc==2 ? argv[1]:NULL,&config,check)==0)
    {
      char *ir;
      char *c;
      int ret;
      
      while(lirc_nextcode(&ir)==0)
	{
	  if(ir==NULL) continue;
	  while((ret=lirc_code2char(config,ir,&c))==0 && c!=NULL)
	    {
	      debugprintf("Recieved code: %sSending event: ",ir);
	      if(2==sscanf(c,"Key %s %s\n",keyname,windowname))
		{
		  if((w=find_window(root,windowname)))
		    {
		      debugprintf("keyname: %s \t windowname: %s\n",keyname,windowname);
		      sendkey(keyname,1,1,w,0);
		    }
		  else
		    {
		      debugprintf("target window '%s' not found \n",windowname);
		    }
		}
	      else if(4==sscanf(c,"Button %d %d %d %s\n",
				&pointer_button,&pointer_x,
				&pointer_y,windowname))
		{
		  
		  if((w=find_window(root,windowname)) &&
		     (subw=find_sub_window(root,windowname,&pointer_x,&pointer_y)))
		    {
		      if (w==subw) subw=0;
		      debugprintf(" %s\n",c);
		      sendbutton(pointer_button,pointer_x,pointer_y,w,subw);
		    }
		  else
		    {
		      debugprintf("target window '%s' not found \n",windowname);
		    }
		}
	      else if(4==sscanf(c,"xy_Key %d %d %s %s\n",
				&pointer_x,&pointer_y,
				keyname,windowname))
		{
		  
		  if((w=find_window(root,windowname))&& (subw=find_sub_window(root,windowname,&pointer_x,&pointer_y)))
		    {
		      debugprintf(" %s\n",c);
		      if (w==subw) subw=0;
		      sendkey(keyname,pointer_x,pointer_y,w,subw);
		    }
		  else
		    {
		      debugprintf("target window '%s' not found \n",windowname);
		    }
		}
	    }
	  free(ir);
	  if(ret==-1) break;
	}
      lirc_freeconfig(config);
    }
  
  lirc_deinit();
  
  exit(0);
}
