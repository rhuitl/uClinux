From a4mp@loki.cc.pdx.edu Wed Oct  6 18:12:34 1993
Return-Path: <a4mp@loki.cc.pdx.edu>
Received: from arthur.cs.purdue.edu by barnum.cs.purdue.edu (5.65c/PURDUE_CS-1.2)
	id <AA13001@barnum.cs.purdue.edu>; Wed, 6 Oct 1993 18:12:33 -0500
Received: from pdxgate.cs.pdx.edu by arthur.cs.purdue.edu (5.65c/PURDUE_CS-1.2)
	id <AA01430@arthur.cs.purdue.edu>; Wed, 6 Oct 1993 18:12:28 -0500
Received:  from loki.cc.pdx.edu by pdxgate.cs.pdx.edu (4.1/pdx-gateway-evision: 1.30 
	id AA25253; Wed, 6 Oct 93 16:12:21 PDT
Received:  from loki.cc.pdx.edu
	by loki.cc.pdx.edu (5.65/pdx-client-evision: 1.19F 
	id AA14453; Wed, 6 Oct 93 23:12:09 GMT
From: a4mp@loki.cc.pdx.edu (Michael Perrone)
Message-Id:  <9310062312.AA14453@loki.cc.pdx.edu>
Subject: Re: Ptx 2.0 files for tripwire 1.0.4
To: spaf (Gene Spafford)
Date: Wed, 6 Oct 93 16:12:07 PDT
Cc: gkim
In-Reply-To: <199310040639.AA24668@uther.cs.purdue.edu>; from "Gene Spafford" at Oct 4, 93 1:39 am
X-Mailer: ELM [version 2.3 PL11]
Status: ORr

Gene Spafford writes:
> 
> Please send the files to us -- we'd love to have them in the next
> release!
> 
> --spaf
> 

Okay, what follows is "conf-ptx2.h"
I'll let you know if this file works under ptx 2.1 in a week or two.

 -- Michael Perrone --




-------- CUT HERE -------------
/* conf-ptx2.h 
 *
 *	Tripwire configuration file
 *
 * Michael Perrone -- a4mp@loki.cc.pdx.edu 
 * Portland State University                 
 */

/* include file for bsd types such as u_long */

#include <netinet/in_systm.h>


/***
 *** Operating System specifics
 ***	
 ***	If the answer to a question in the comment is "Yes", then
 ***	change the corresponding "#undef" to a "#define"
 ***/

/*
 * Even though ptx 2 is based on SVR4, there is some stuff
 * missing that tripwire expects for SYSV = 4
 */

#define SYSV 3

/*
 * ptx has never had this - use system call "time"
 */

#define NOGETTIMEOFDAY

/* 
 * does your system have a <malloc.h> like System V? 
 * ptx does
 */

#define MALLOCH 	

/* 
 * does your system have a <stdlib.h> like POSIX says you should? 
 * ptx has stdlib.h
 */

#define STDLIBH

/*
 * does your system use readdir(3) that returns (struct dirent *)?
 * ptx does
 */

#define DIRENT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 * ptx uses <strings.h>
 */

#define STRINGH
 
/* 
 * does your system have gethostname(2) (instead of uname(2))?
 * ptx provides both calls.
 */

#undef GETHOSTNAME

