/*-
 * Copyright (c) 1993-1994 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and the Network Research Group at
 *      Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/************ Change log
 *
 * $Log: grabber.h,v $
 * Revision 1.12  2003/01/06 22:18:01  rogerh
 * Add NetBSD grabber code. Submitted by Andreas Wrede.
 *
 * Revision 1.11  2001/05/10 05:25:44  robertj
 * Removed need for VIC code to use ptlib.
 *
 * Revision 1.10  2000/12/19 22:22:34  dereks
 * Remove connection to grabber-OS.cxx files. grabber-OS.cxx files no longer used.
 * Video data is now read from a video channel, using the pwlib classes.
 *
 * Revision 1.9  2000/09/22 02:40:13  dereks
 * Tidied code for generating test images.
 * Added mechanism to ensure the entire frame is sent on startup.
 *
 * Revision 1.8  2000/09/08 06:41:38  craigs
 * Added ability to set video device
 * Added ability to select test input frames
 *
 * Revision 1.7  2000/09/08 03:42:04  dereks
 * Add function to report to user the failed opening of the video device.
 *
 * Revision 1.6  2000/08/25 03:18:50  dereks
 * Add change log facility (Thanks Robert for the info on implementation)
 *
 *
 *
 ********/


#ifndef grabber_h
#define grabber_h
#include "videoframe.h"

#define CIF_WIDTH   352
#define CIF_HEIGHT  288

#if 0
class Grabber {
 public:
                Grabber();
	virtual ~Grabber();
	virtual void Start();
	virtual void Stop();
	virtual void Grab(VideoFrame *vf);
        virtual void SetSize(int _width,int _height);
	        void FailedToOpen(char *videoDeviceName);
                void GrabMovingBlocksTestFrame(void);
                void GrabMovingLineTestFrame(void);

	u_int framesize;   //bytes in frame, w*h
	u_char* frame;     //pointer to memory holding image obtained by grabber.
 protected:
	int  running;
        int  width;
        int  height;
        int  operational; //boolean indicating if grabber is working.
        char *mem;        //Memory mapped to output of the driver for video grabbing.
        int  grab_count;  //count of frames grabbed by grabber.
        int  port_;       // video input or test image to use
};

#if P_LINUX
#include "grabber-linux.h"
#elif _WIN32
#include "grabber-windows.h"
#elif P_FREEBSD
#include "grabber-bsd.h"
#elif P_OPENBSD
#include "grabber-bsd.h"
#elif P_NETBSD
#include "grabber-bsd.h"
#else
#include "grabber-generic.h"
#endif

#endif   //ifdef GRABBER_H


#endif




