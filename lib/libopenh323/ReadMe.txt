			  OpenH323 Library
			  ================



The OpenH323 project aims to create a full featured, interoperable, Open
Source implementation of the ITU H.323 teleconferencing protocol that can be
used by personal developers and commercial users without charge.

OpenH323 development is coordinated by an Australian company, Equivalence Pty
Ltd (http://www.equival.com), but is open to any interested party. Commercial
and private use of the OpenH323 code, including use in commercial products
and resale,  is enouraged through use of the MPL (Mozilla Public license).


For more details see http://www.openh323.org

You can subscribe to the mailing list at http://www.openh323.org/mailman/listinfo

Frequently asked questions are answered at http://www.openh323.org/faq.html



Building the OpenH323 Code
==========================

This page describes how to compile the OpenH323 code release. Note these
instructions will always refer to the latest snapshot available on the
download page.

The OpenH323 source will have been compiled and tested under Linux x86, and
Windows NT. If it does not compile for you then the problem is likely to be a
setup/configuration problem with your system and not a problem with the
source code itself.

The libraries and applications should also compile on Windows 95/98, BeOS
(thanks Yuri!), Linux PPC, FreeBSD x86, OpenBSD x86 (thanks Roger!) and
Solaris Sparc & x86. They are not automatically compiled on every release
however so there could be problems, but the chances are that there aren't.
Note also that not all of these platforms may have ports of the sound
interface.

We are also happy to port it to other Unix flavours providing people out
there can provide an account and a fair bit of disk space!

These instructions should contain all of the steps need. If you have a problem,
please double check that you have performed ALL of the steps below,
particularly setting the include file paths under MSVC. Some of the more
common errors are described below.

If you get a lot of compile or link errors, then the chances are that you
have missed something in the list. If you are positive that something is
wrong and you have followed the instructions, then send an e-mail to the
mailing list, and we'll answer it for everyone to see. Bear in mind that the
first question asked will be "did you follow the instructions".




Windows
-------

1.  Download the pwlib_1.xx.zip and openh323_1.x.zip files from the OpenH323
    download page. 

2.  Follow the instructions for building PWLib. 

3.  Start MSVC (v5 or v6). If you have another compiler you are on your own!
    Go into the Tools menu, Options item, Directories tab and add to the
    beginning of the Include files path (note the order is important!):

	C:\OpenH323\Include

    and add to the Lib Files path and the Executable Files path the following:

	C:\OpenH323\Lib

    Also make sure the last directory is in your PATH environment variable.

    Note this is in addition to the ones in PWLib!!
 
4.  Use the OpenH323.dsw file to build the sample code, eg SimpH323.

    The build should automatically create a file openh323/include/openh323buildopts.h
    via the configure.exe program that should be in the openh323 directory. If
    you have any problems try running the program directly from a command
    line. Use ".\configure --help" to get information on options such as
    forcing a feature or library dependency.

    Note there are additional notes in the "Platform Specific Issues" on how
    to compile the various libraries in a manner suitable for use by OpenH323
    under Windows.

5.  Run the program, and you are on your own! 



Unix
----

1.  Download the pwlib_min_1.xx.tar.gz and openh323_1.xx.tar.gz files from
    the OpenH323 download page. 

2.  Follow the instructions for building PWLib. 

3.  Extract the contents of the openh323_1.x.tar.gz file somewhere, eg:

      cd
      tar -xzvf openh323_1.1alpha1.tar.gz
 
4.  If you have not installed OpenH323 in your home directory (~/openh323)
    then you will have to define the environment variable OPENH323DIR to
    point to the correct directory.

    Also make sure you have added the $OPENH323DIR/lib directory to your
    LD_LIBRARY_PATH environment variable if you intend to use shared libraries
    (the default under Linux).

    There are examples for sh/bash and csh/tcsh below.
 
5.  Build the H323 bootstrap code. Enter:

	cd $(OPENH323DIR)
        ./configure
	make opt

    This may take some time, especially with the h245_*.cxx and h225.cxx
    files. You may also need to add more swap space - 64M of real memory and
    64M of swap might just be enough, if your machine does nothing else! Some
    people have reported needing as much as 256M of swap - if your compiler
    bombs out with a "virtual memory exhausted" error compiling h245_*.cxx
    and h225.cxx, then increase your swap space.
 
    Less space is required if you build the debug version - Debug builds on 64M ram are
    very achievable. Opt builds on 164M ram are doable, but only just.

6.  The result should be an executable called simph323, which will be located
    in a directory dependent on the platform, eg sample/simple/obj_linux_x86_d.
    To run it, use the following command:

	./sample/simple/obj_linux_x86_r/simph323

    and you should get the usage help text.

9.  Now you're on your own! 



Voice Age G.729 Codec
=====================

For the Windows system it is possible to also have a G.729 codec
for non-commercial use by adding the Voice Age G.729A library to the system.
To do this:

1.  Get the Voice Age G.729 library from http://www.voiceage.com/g729/

2.  Unpack it somewhere, preferably at teh same level as OpenH323, eg if
    c:\work\openh323, then c:\work\va_g729a

3.  Re-run the configure program.

4.  Recompile your project.



H263 Codec
==========

  H263 is a video compression format which is especially suited for low
  bandwidth situations, such as a dial up link. By adding the requisite
  library, recompiling openh323 and ohphone applications, H263 support is
  available.

  Three H.263 codecs are available in the Openh323 codebase:

    1) A fully RFC2190 compliant version using FFMPEG
    2) An older non-RFC2190 compliant version also using FFMPEG
    3) A non-RFC2190 compliant version using vich263

  1) Fully RFC2190 compliant using FFMPEG.
  This is the only H.263 codec currently interoperable with other RFC2190 compliant
  applications like NetMeeting. As such, it is the recommended H.263 codec for use
  in all future applications based on OpenH323.

  2) Non-RFC2190 compliant using FFMPEG.
  This H263 codec was labelled as non standard. Some hacks were added to the packets
  generated by ffmpeg to get it working in a voip environment.

  1) + 2) FFMPEG license issue
  FFMPEG is licensed as either LGPL or GPL, depending on which components were used
  at built time. Please check the configure script for further information.
  OpenH323 assumes a LGPL license, and dynamically loads the FFMPEG library at run-time
  in accordance with those terms.

  3) VICH263
   Andrew Morrow who did the hard part of the implementation reports that:
    I got something working using vic's H.263 (not plus) in OpenH323.

   It does not interoperate with NetMeeting, but it does interoperate with
   IBM's J323/JMF.


Unix
----
    The library was built with

      cd external/ffmpeg
      ./configure --enable-shared --disable-a52 --disable-pp --disable-ffserver --disable-ffplay
      cd libavcodec
      make 
      
    The code is in the CVS, external/ffmpeg directory at sourceforge.
    Instructions on using the cvs are at http://sourceforge.net/cvs/?group_id=80674

      cd external/vich263
      make

    If you have the external directory on your box, with vich263 and ffmpeg, but do
    not wish to enable ffmpeg or vich263, you can
        
      cd openh323
      ./configure
      make

    On recompiling the openh323 directory, you will not do configure again, so
    your ffmpeg and vich263 settings will remain.

    Should you wish to build in support for all H263 codecs, do:

      export H323_VICH263=1
      export H323_AVCODEC=1
      cd openh323
      ./configure --avcodec-dir=<<dir>> --enable-rfc2190avcodec=<<dir>>
      make

    Now, if you just want one of the codecs, just have the appropriate export statement.
    Note that when you do ./configure, there is a clear statement what codec is on.
    If you wish to remove both codecs, (after doing a configure with them on), do

      export H323_VICH263=""
      export H323_AVCODEC=""
      cd openh323
      ./configure
      make

    Now, these settings are fixed, and remain in place on subsequent makes. Thus,
    on recompiling the openh323 dir, you don't need to rerun configure.

    Now, to test the operation of the H263 codec. I used the command below in
    the ohphone directory:
     
      ./obj_linux_x86_r/ohphone -ln --videotest --videolocal \
            --videoreceive sdl --videodevice fake --videoinput 1 \
            --videobitrate 24

    This brings up a SDL display window with two copies of the same image. The
    image on the right is generated by the fake video device, on channel 1.
    The image on the left is the decoded form of an image that has been
    encoded with H263.

    Wait a while, and then type q, the display will tell you what bit rate
    was achieved, and the frame rate. The achieved bit rate should always be
    less than that specified in the --videobitrate option

    Now, you can try the H261 codec instead. To use H261, add to the command
    line -D 263, so your command line becomes:

      ./obj_linux_x86_r/ohphone -ln --videotest --videolocal \
            --videoreceive sdl --videodevice fake --videoinput 1 \
            --videobitrate 24 -D 263

    Get mean, set a bit rate of 12 Kilobits/sec

    Now, you might have a problem with it not finding the libavcodec.so library.
    In this case, you need to extend your LD_LIBRARY_PATH

      export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

    or append to /etc/ld.so.conf the directory /usr/local/lib and rerun ldconfig

      ldconfig -C /etc/ld.so.conf   Do this command as root.

    Alternatively, append to the configure command above the phrase
    --prefix=/usr. This will cause all the ffmpeg stuff to go in system
    directories, where it will be found guaranteed.


Windows
-------
    The ffmpeg codec is built with MinGW and MSys.

    Move ffmpeg directory from c:\external to c:\msys\1.0\home\administrator

    Start msys

      cd ffmpeg
      ./configure --extra-cflags="-mno-cygwin -mms-bitfields" --extra-ldflags="-Wl,--add-stdcall-alias" --enable-mingw32 --enable-shared --disable-a52 --disable-pp --disable-ffserver --disable-ffplay
      cd libavcodec
      make

    Move ffmpeg back to c:\external

    Move c:\external\ffmpeg\libavcodec.dll to c:\openh323\lib

    Compile libvich263
    Go to external\vich263
    Open the libvich263 workspace.
    Select batch build, buld release and debug.
    Leave libvich263.lib where it puts this library.

    Open up a dos terminal, and go to c:\openh323

      configure

    Check that options are set correctly in c:\openh323\include\openh323buildopts.h

    If it fails to build openh323buildopts.h, well, it is OK.
    Copy from pwlib/tools/configure the files configure.cpp and configure.dsp to the directory c:\openh323
    Open configure.dsp project in msvc, build and run configure.exe

    Recompile the OpenH323Lib and OpenH323DLL projects to create new OpenH323 libraries.


More information
----------------
    License details and a precompiled FFMPEG library:
      http://www.voxgratia.org/h263_codec.html

    MinGW/MSys and FFMPEG library building instructions:
      http://www.salyens.com/?page=ffcodec



Common errors
=============

Here are common errors you might encounter for both Windows and Unix builds.

  An error like:
    "Makefile", line 175: Missing dependency operator
    "Makefile", line 177: Need an operator
    "Makefile", line 179: Missing dependency operator
    "Makefile", line 181: Need an operator
    "Makefile", line 183: Missing dependency operator
    "Makefile", line 185: Need an operator

	Indicates you are using BSD Unix's Make command. You need to use
	gmake (GNU Make).

  Thinking there are missing files.

	A number of files, eg h235.h, h225.h etc, are generated files that are
	created during the build process. If they are missing then something
	probably went wrong with installation of flex/bison.

  An error like:
    Linking...
    LINK : fatal error LNK1181: cannot open input file "ptlib.lib"
    Error executing link.exe.

	Indicates you have not set the paths in MSVC directories.

  An error like:
    Performing Bison Step
    c:\tools\share\bison.simple: No such file or directory

	Indicates you have not installed bison correctly. In particular the
	bison.simple file must be available to bison. Check the bison
	documentation for details on this.

  Attempting to compile GUI systems under Unix.

	There are a number of partial implementations of the GUI code in the
	$PWLIBDIR/src/pwlib directory tree. These are not required to get the
	OhPhone application compiled. If you get those systems from the CVS
	then you are basically on your own. Do not ask for support unless you
	intend to help with the implementation!


See the FAQ at http://www.openh323.org/~openh323/fom.cgi for more.



Example environment for sh/bash
-------------------------------

PWLIBDIR=$HOME/pwlib
export PWLIBDIR
OPENH323DIR=$HOME/openh323
export OPENH323DIR
LD_LIBRARY_PATH=$PWLIBDIR/lib:$OPENH323DIR/lib
export LD_LIBRARY_PATH
Example environment for csh/tcsh:

setenv PWLIBDIR $HOME/pwlib
setenv OPENH323DIR $HOME/openh323
setenv LD_LIBRARY_PATH $PWLIBDIR/lib:$OPENH323DIR/lib




Bison problem under Unix
------------------------

The bison.simple file on many releases will not compile with the options used
by the PWLib getdate.y grammar. The options are required to make the date
parser thread safe so it is necessary to edit the bison.simple file to fix
the problem.

The file is usually at /usr/lib/bison.simple but in the tradition of unix
could actually be anywhere. We leave it up to you to find it.

The code:

/* Prevent warning if -Wstrict-prototypes. */
#ifdef __GNUC__
int yyparse (void);
#endif
should be changed to

/* Prevent warning if -Wstrict-prototypes. */
#ifdef __GNUC__
#ifndef YYPARSE_PARAM
int yyparse (void);
#endif
#endif

To prevent the incorrect function prototype from being defined. The getdate.y
should then produce a getdate.tab.c file that will actually compile.




Licensing
---------

The bulk of this library is licensed under the MPL (Mozilla Public License)
version 1.0. In simple terms this license allows you to use the library for
any purpose, commercial or otherwise, provided the library is kept in tact
as a separate entity and any changes made to the library are made publicly
available under the same (MPL) license. It is important to realise that that
refers to changes to the library and not your application that is merely
linked to the library.

Note that due to a restriction in the GPL, any application you write that
uses anything another than GPL, eg our library with MPL, is technically in
breach of the GPL license. However, it should be noted that MPL does not
care about the license of the final application, and as only the author of
the GPL application is in breach of his own license and is unlikely to sue
themselves for that breach, in practice there is no problem with a GPL
application using an MPL or any other commercial library.



Portions of this library are derived from TOAST, using the copyright:

Copyright 1992, 1993, 1994 by Jutta Degener and Carsten Bormann,
Technische Universitaet Berlin

Any use of this software is permitted provided that this notice is not
removed and that neither the authors nor the Technische Universitaet Berlin
are deemed to have made any representations as to the suitability of this
software for any purpose nor are held responsible for any defects of
this software.  THERE IS ABSOLUTELY NO WARRANTY FOR THIS SOFTWARE.

As a matter of courtesy, the authors request to be informed about uses
this software has found, about bugs in this software, and about any
improvements that may be of general interest.



Portions of this library is derived from vic, http://www-nrg.ee.lbl.gov/vic/
Their copyright notice is below.

 * Copyright (c) 1993-1995 The Regents of the University of California.
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
 *      This product includes software developed by the Network Research
 *      Group at Lawrence Berkeley National Laboratory.
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


Building on a unix box - how do I use the CVS - quick start - with all H263 codecs
---------------------------------------------------------------------------------
1)Remove all pwlib/openh323 from system directories.
   (like /usr/local/src/   or /usr/include  etc)

2)create a directory, (call it cvs_h323)

3)cd cvs_h323

4)In cvs_h323, create a file called environment.

The contents of the file are::::: export PWLIBDIR=~/cvs_h323/pwlib
export OPENH323DIR=~/cvs_h323/openh323

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/cvs_h323/pwlib/lib 
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/cvs_h323/openh323/lib: 
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/cvs_h323/external/ffmpeg/libavcodec:
export CVSROOT=:pserver:anonymous@cvs.sourceforge.net:/cvsroot/openh323

5) source environment

6) cvs login (For the password, just press enter)

7) cvs -z3 co ptlib_unix openh323 contrib external

8) cd pwlib

9) ./configure

10) make all

11) cd ../external/ffmpeg (Now, read above for building and installing ffmpeg
                     & vich263) If you don't want h263 codecs, skip this line.

12) cd ../openh323

13) export H323_VICH263=1; export H323_AVCODEC=1 (If you don't want h263 codecs, skip this line.)

14) ./configure --enable-rfc2190avcodec=~/cvs_h323/external/ffmpeg/libavcodec 
         (((There should be messages about finding vic & ffmpeg)))

15) make all

16) cd ../contrib/openmcu   (or ../contrib/ohphone, or whereever)

17) make all

			  __oo^oo__
