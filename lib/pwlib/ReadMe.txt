			Portable Windows Libary
			=======================


Contents
--------

	1.	Introduction
	2.	Apologies
	3.	CVS Access
	4.	Building PWLib
	5.	Using PWLib
        6.      IPv6 issues
	7.	Platform Specific Issues
	8.	Conclusion
	9.	Licensing



================================================================================

1. Introduction
---------------

PWLib is a moderately large class library that has its genesis many years ago as
a method to product applications to run on both Microsoft Windows and Unix
X-Windows systems. It also was to have a Macintosh port as well but this never
eventuated. The parts of the library relating to GUI functions have also been 
removed.

Since then the system has grown to include many classes that assist in writing
complete multi-platform applications. Classes for I/O portability, multi-threading
portability, aid in producing unix daemons and NT services portably and all
sorts of internet protocols were added over the years.

All this over and above basic "container" classes such as arrays, linear lists,
sorted lists (RB Tree) and dictionaries (hash tables) which were all created
before STL was standardized. Future versions of PWLib will see many of these
classes replaced or supplemented by STL.

The library was used extensively for all our in-house products. Then we decided
to support the open H323 project by throwing in some of the code written for
one of our products. Thus, required PWLib so it got thrown into the open source
world as well.



================================================================================

2. Apologies (not)
------------------

As you start using the library, the inevitable question "why did they do it that
way?" will come up. The more experienced out there will know that there are
several reasons for the way things are:

   *   Carefully considered design,
   *   Workarounds for portability and compiler subtleties,
   *   History, it may be too hard to change an early design decision,
   *   Complete arbitrariness, the absence of any compelling reason.

So, when you ask the next question "why didn't you do it this way?" The answer
will be one of the above. The last one being a synonym for "we didn't think of
that!"

The bottom line is, use the library as is or change it as you require. You can
even send in suggestions for improvements (or merely changes) and we may (or may
not) include them in the base line code. Just do not send us any mail starting
with the words "Why did you..." as the answer is quite likely to be "Because!"



================================================================================

3. CVS Access
-------------

There is a public CVS archive available at cvs.sourceforge.net. To avoid
everyone getting all of the code platforms, we have provided CVS "modules"
that allow the Windows and Unix source trees to be extracted seperately.

The available modules are:

	pwlib			This ReadMe.txt file only
	ptlib_unix		Unix libraries only
	ptlib_win32		Windows libraries only
	pwlib_win32		Windows libraries + GUI (no longer supported)
	openh323		OpenH323 only

Note that the ptlib_unix, ptlib_win32 and pwlib_win32 modules all extract 
subcomponents of the pwlib directory tree using the CVS modules file - they
are not different directories.

To extract one of these modules, use a command line like the following:

        cvs -z3 -d :pserver:anonymous@cvs.sourceforge.net:/cvsroot/openh323 co module

where "module" is one of the module names specified above.

If you would like see the structure of the CVS, then use the View CVS tool at:

	http://cvs.sourceforge.net/viewcvs.py/openh323/


================================================================================

4. Building PWLib
-----------------

This library is multi-platform, however there are only two major build systems
that are used. The Microsoft DevStudio environment for Windows and the GNU make
system for all of the various unix systems.

SPECIAL NOTE FOR MSVC 6 USERS:
------------------------------
If you are using MSVC 6 then please run the "msvc6_upgrade.bat" script in the 
PWLIB top directory before continuing. If you skip this step, you will not
be able to compile PWLib on MSVC 6. If you change the build environment to bypass 
this step, then DLL versions of PWLib will not function correctly. For more 
information, please see:

http://www.voxgratia.org/docs/pwlib_windows.html#msvc_headers 


4.1. For Windows
----------------

Note that more complete instructions can be found at the following URL, but here 
are the basics:

	http://www.voxgratia.org/docs/pwlib_windows.html 

1.  Note you will need the bison and flex tools to compile some parts of the
    system. You can get a copy from http://www.openh323.org/bin/flexbison.zip,
    follow the instructions included in that package and put the executables
    somewhere in your path.

2.  Start MSVC (v5, v6 or v7 (.NET)). If you have another compiler you are on
    your own! Add these folders to the Include Files path as follows:
    
    In VisualStudio v5/6 go into the Tools menu, Options item, Directories tab.
    
    In VisualStudio v7, go into the Tools menu, Options item. In the Options
    dialog, open the Projects folder, VC++ Directories item. In the 'Show
    Directories for:' list, select 'Include files'.
	
		C:\PWLib\Include
		
    Add the following to the Lib Files path and the Executable Files path:
	
		C:\PWLib\Lib
		
    The Lib folder is created as parts of PWLib are built. Also add this
    directory to your PATH environment variable (so the MergeSym tool can 
    be found).

2.  The build should automatically create a file pwlib/include/ptbuildopts.h
    via the configure.exe program that should be in the pwlib directory. If
    you have any problems try running the program directly from a command
    line. Use ".\configure --help" to get information on options such as
    forcing a feature or library dependency.

    Note there are additional notes in the "Platform Specific Issues" on how
    to compile the various libraries in a manner suitable for use by PWLib
    under Windows.

3.  In VisualStudio v5/6 open the pwlib.dsw file in the pwlib top directory.
    If you have the minimum library it will come up with several requests to
    find .dsp files, just cancel past these.
	
    In VisualStudio v7 open the pwlib.sln file in the pwlib top directory.

4.  That's it, now you're on your own!



These are the project relationships:

project             dependencies                             output
-------             ------------                             ------
Console             (none)                                   ptlibs.lib
MergeSym            ptlibs.lib                               mergesym.exe
PTLib               ptlibs.lib, mergesym.exe                 ptlib.dll & lib
Console Components  (none)                                   ptclib.lib
MSDevWizard         (none)                                   PWLibWizard.awx
XMLRPC              ptlibs.lib, ptclib.lib                   xmlrpc.exe
PacketVXD           (none)                                   epacket.vxd

Debug versions append 'd' to filename, ie: ptlibsd.lib.

MSDevWizard will not build in VisualStudio v7 and so is not included as a project.



--------------------------------------------------------------------------------
4.2. For unix.
--------------

1.	If you have not put pwlib it into your home directory (~/pwlib) then
	you will have to defined the environment variable PWLIBDIR to point to
	the correct directory.
        Also make sure you have added the $PWLIBDIR/lib directory to your 
        LD_LIBRARY_PATH environment variable if you intend to use shared 
        libraries (the default).

2.	Build the debug and release versions of the PWLib library as follows:
		cd ~/pwlib
                ./configure
		make
	This may take some time. Note, you will need bison and flex for this to
	compile, most unix systems have these. WARNING: there is a bug in most 
	of the bison.simple files. See below for details.

	PWLib requires GNU Make. If GNU Make (gmake) is not your default make
	program (eg FreeBSD users), you will need to install GNU Make first
	and then use
		cd ~/pwlib
                ./configure
		gmake


	If you are getting huge numbers of errors during the compile, then it 
        is likely your platform is not supported, or you have incorrectly set 
        the OSTYPE and MACHTYPE variables.

3.	That's all there is to it, you are now on your own!



Bison problem under Unix

The bison.simple file on many releases will not compile with the options used 
by the PWLib getdate.y grammar. The options are required to make the date 
parser thread safe so it is necessary to edit the bison.simple file to fix the 
problem.

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




================================================================================

5. Using PWLib
--------------

What documentation there is consists of this document and all of the header
files. It was intended that a post processer go through the header files and
produces HTML help files, but this never got completed.


5.1. Tutorial
-------------

Detailed tutorials will almost certainly not be forthcoming. However, at least
giving you an indication on how to start an application would be usefull, so
here is the infamous "Hello world!" program.


// hello.cxx

#include <ptlib.h>

class Hello : public PProcess
{
  PCLASSINFO(Hello, PProcess)
  public:
    void Main();
};

PCREATE_PROCESS(Hello)

void Hello::Main()
{
  cout << "Hello world!\n";
}

// End of hello.cxx


The CREATE_PROCESS macro actually defines the main() function and creates an
instance of Hello. This assures that everything is initialised in the correct
order. C++ does initialisation of global statics badly (and destruction is even
worse), so try to put everything into your PProcess descedent rather than
globals.

A GUI application is very similar but is descended off PApplication rather than
PProcess, and would create a window as a descendent off the PMainWindow class.

The following is a simple Makefile for Unix platforms for the hello world 
program.


# Simple makefile for PTLib

PROG    = hello
SOURCES = hello.cxx

ifndef PWLIBDIR
PWLIBDIR=$(HOME)/pwlib
endif

include $(PWLIBDIR)/make/ptlib.mak

# End of Makefile



--------------------------------------------------------------------------------
5.2. PWlib Classes
------------------

The classes in PWLib fall into the following broad categories

	Containers
	I/O
	Threads & Processes


5.2.1. Containers

While there are a number of container classes you wourld rarely actually descend
off them, you would use macros that declare type safe descendents. These are
simply templates instantiations when using a compiler that supports templates
in a simple manner (GNU C++ does not qualify in our opinion).

5.2.2. I/O

There are many classes descendend from a basic primitive call a PChannel, which
represents an entity for doing I/O. There are classes for files, serial ports,
various types of socket and pipes to sub-processes.

5.2.3. Threads & Processes

These classes support lightweight threading and functionality to do with the
process as a whole (for example argument parsing). The threading will be
pre-emptive on platforms that support it (Win32, platforms with pthreads eg
Linux and FreeBSD) and cooperative on those that don't.




================================================================================

6. IPv6 support in pwlib
------------------------

The IPv6 support in pwlib is still experimental. You have to get the latest
CVS version to compile it (does work since 7th November 2002). Pwlib can be
compiled with or without the IPv6 support.

When compiled with the IPv6 support, applications using only IPv4 are still 
fully backward compatible. Pwlib is able to manage simultaneously IPv4 and
IPv6 connections.



--------------------------------------------------------------------------------
6.1. Windows platforms
----------------------

According to microsoft, IPv6 is not supported under 9x, experimental on Win2000, 
supported on XP.
You must use a compiler with IPv6 aware includes and libraries:
  - VC6 must be patched to support RFC 2553 structure. (See 7.1 and 7.2 for patch)
  - .Net should be ok (to be confirmed)
The port as been performed with VC6 patched on a win2000 platform.

For more informations about IPv6 support:
  Microsoft IPv6 support: 
    http://research.microsoft.com/msripv6/
  IPv6 for win2000: 
    http://msdn.microsoft.com/downloads/sdks/platform/tpipv6.asp
  IPv6 for XP: 
    http://www.microsoft.com/windowsxp/pro/techinfo/administration/ipv6/default.asp



6.1.1. Windows platforms: Win2000
---------------------------------
Go to Microsoft win2000 IPv6 tech preview web page.
http://msdn.microsoft.com/downloads/sdks/platform/tpipv6.asp
Download the 'tpipv6-001205.exe' file and read carrefully the faq.
http://msdn.microsoft.com/downloads/sdks/platform/tpipv6/faq.asp

This program is designed for win2000 English Service pack 1.
To install it on newer Service pack, you have to modify some files.
Again, read the Faq.
 
This install the IPv6 driver and the IPv6 includes.



6.1.2. Windows platforms: XP
----------------------------
Read the IPv6 faq for windows XP
http://www.microsoft.com/windowsxp/pro/techinfo/administration/ipv6/default.asp

The 'ipv6 install' command installs only the IPv6 drivers.
You need to install additionnals IPv6 includes for VC6.
.NET should be ready. (to be confirmed ....)



6.1.3. Compiling
----------------
To compile pwlib and openh323 with the IPv6 support you have to set an 
environment variable:
IPV6FLAG=1
Set it using: [Start]/[Configuration pannel]/[System]/[Environment]

Add the IPv6 SDK include path in your Visual C++ 6 environment:
[Tools]/[Options]/[Directories]/[Include files]



--------------------------------------------------------------------------------
6.2. Linux platforms
--------------------

Recent Linux distributions support IPv6.
2.4 kernels are IPv6 aware.

Linux IPv6 Faq:
http://www.tldp.org/HOWTO/Linux+IPv6-HOWTO/



6.2.1. Enabling IPv6 support
----------------------------
IPv6 can be compiled statically in the kernel or compiled as a module.
To load the IPv6 module, as 'root'
#modprobe ipv6



6.2.2. Compiling
--------------
Check that IPv6 is really on
#ls /proc/net/if_inet6
If this file exists, then IPv6 support is compiled in pwlib and openh323.



--------------------------------------------------------------------------------
6.3. Testing
------------

The test application sources can be found in the directory: openh323/samples/simple
Once compiled the binaries are in simple/debug, release, obj_linux_x86_d, or
obj_linux_x86_r.
Under windows, the test application is simple.exe
Under linux, the test application is simh323
IPv6 support can be tested on only one machine. Just open two shell/command windows.



6.3.1. IPv6 Address and port notation
-------------------------------------
IPv4 address and port are written in dot notation: xx.xx.xx.xx:4000
IPv6 global address are written in semi-colon notation: [xx:xx:xx:xx::xx]:4000
IPv6 scoped address ad a field for the scope: [xx:xx:xx:xx::xx%scope]:4000

Exemples:
Global address
[3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5]:4000
[3ffe:0b80:0002:f9c1::500b:0ea5]:4000

Scoped address
[fe80::232:56ff:fe95:315%lnc0]:4000
Scoped address are not supported yet.



6.3.2. Tests configuration
--------------------------
Tests 1,2,3 run on a single dual stack machine.
  IPv4 Address: 127.0.0.1, 10.0.0.6
  IPv6 Address: ::1, 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5

Tests 4,5,6 run on two dual stack machine.
PC1
  IPv4 Address: 10.0.0.6
  IPv6 Address: ::1, 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5
PC2
  IPv4 Address: 10.0.0.8
  IPv6 Address: ::1, 3ffe:0b80:0002:f9c1:0000:0000:500b:0eb6



6.3.3. Test 1: IPv4 <--> IPv4 local call
----------------------------------------
This test checks the backward compatibility with IPv4

In first shell/command window, listen on 127.0.0.1, wait for a call.
simple.exe -tttt -n -i 127.0.0.1 -l -a
In second shell/command window, listen on 10.0.0.6, call 127.0.0.1
simple.exe -tttt -n -i  10.0.0.6 -n 127.0.0.1



6.3.4. Test 2: IPv6 <--> IPv6 local call 
----------------------------------------
This test checks the IPv6 support

In first shell/command window, listen on ::1, wait for a call.
simple.exe -tttt -n -i ::1 -l -a
In second shell/command window, listen on IPv6 address, call ::1
simple.exe -tttt -n -i 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5 -n [::1]


6.3.5. Test 3: IPv4 <--> IPv6 local call
----------------------------------------
This test checks that simultaneous IPv4 and IPv6 calls are supported.

In first shell/command window, listen on 127.0.0.1, wait for a call.
simple.exe -tttt -n -i 127.0.0.1 -l -a
In second shell/command window, listen on IPv6 address, call 127.0.0.1
simple.exe -tttt -n -i 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5 -n 127.0.0.1



6.3.6. Test 4: IPv4 <--> IPv4 call between two hosts
----------------------------------------------------
This test checks the backward compatibility with IPv4

First host, listen on 10.0.0.6, wait for a call.
simple.exe -tttt -n -i 127.0.0.1 -l -a
Second host, listen on 10.0.0.8, call 10.0.0.6
simple.exe -tttt -n -i  10.0.0.8 -n 10.0.0.6



6.3.7. Test 5: IPv6 <--> IPv6 call between two hosts
----------------------------------------------------
This test checks the IPv6 support

First host, listen on 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5, wait for a call.
simple.exe -tttt -n -i 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5 -l -a
Second host, listen on 3ffe:0b80:0002:f9c1:0000:0000:500b:0eb6, call 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5
simple.exe -tttt -n -i 3ffe:0b80:0002:f9c1:0000:0000:500b:0eb6 -n [3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5]



6.3.8. Test 6: IPv4 <--> IPv6 call between two hosts
----------------------------------------------------
This test checks that simultaneous IPv4 and IPv6 calls are supported.

First host, listen on 10.0.0.6, wait for a call.
simple.exe -tttt -n -i 10.0.0.6 -l -a
Second host, listen on 3ffe:0b80:0002:f9c1:0000:0000:500b:0eb6, call 10.0.0.6
simple.exe -tttt -n -i 3ffe:0b80:0002:f9c1:0000:0000:500b:0eb6 -n 10.0.0.6



--------------------------------------------------------------------------------
6.4. Known limitations
--------------------

You must use IPv6 address with global scope. Tests with IPv6 local link address
fail.



--------------------------------------------------------------------------------
6.5. Questions
--------------

6.5.1. How to patch my VC6 includes files ?
-----------------------------------------

To patch you Developper studio Visual C++ version 6, just edit the file
"C:\Program Files\Microsoft Visual Studio\VC98\Include\ws2tcpip.h", and add
the sin6_scope_id field in the sockadd_in6 structure.
struct sockaddr_in6 {
          short     sin6_family;         /* AF_INET6 */
          u_short sin6_port;  /* Transport level port number */
          u_long    sin6_flowinfo; /* IPv6 flow information */
          struct in_addr6 sin6_addr; /* IPv6 address */
          u_long    sin6_scope_id; /* scope id (new in RFC2553) */ <--- Add this one
};

This may have an impact on you system stability, use it only on
experimental platforms. Using .NET compiler should be a better solution.



6.5.2. Why do I need to modify my Visual C++6 include files ? 
-----------------------------------------------------------

Visual Studio C++ version 6 implements the old RFC 2133 in file "ws2tcpip.h".
RFC 2133 defines a 24 byte sockaddr_in6 structure.
struct sockaddr_in6 {
          short     sin6_family;         /* AF_INET6 */
          u_short sin6_port;  /* Transport level port number */
          u_long    sin6_flowinfo; /* IPv6 flow information */
          struct in_addr6 sin6_addr; /* IPv6 address */
};


This RFC as been replaced by RFC 2553.
RFC 2133 defines a 28 byte addsock_in6 structure.
struct sockaddr_in6 {
          short     sin6_family;         /* AF_INET6 */
          u_short sin6_port;  /* Transport level port number */
          u_long    sin6_flowinfo; /* IPv6 flow information */
          struct in_addr6 sin6_addr; /* IPv6 address */
          u_long    sin6_scope_id; /* scope id (new in RFC2553) */
};



6.5.3. How to get an ipv6 address with a Global scope ?
-----------------------------------------------------

6.5.3.1. Manually
-----------------

Set one manually if you're not connected to IPv4 Internet or IPv6 backbone:
#ip -6 addr add 3ffe:0b80:0002:f9c1:0000:0000:500b:0ea5 dev eth0
(this address is owned by freenet6.net).

Check the address is set.
#ifconfig
eth0      Lien encap:Ethernet  HWaddr 00:08:D5:10:C7:BB
          inet adr:12.0.0.2  Bcast:12.255.255.255  Masque:255.0.0.0
          adr inet6: 3ffe:b80:2:f9c1::500b:ea5/128 Scope:Global  <- - - Ok, Global scope
          adr inet6: fe80::208:c7ff:fe59:bbc7/10 Scope:Lien <- - - [ Can't use this one ]
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:9 errors:0 dropped:0 overruns:9 carrier:0
          collisions:0
          RX bytes:0 (0.0 b)  TX bytes:534 (534.0 b)


6.5.3.2. Tunnel broker
----------------------

Get one from a free IPv6 tunnel broker.
Exemple: 
http://www.freenet6.net : Canadian tunnel broker
http://tb.ngnet.it      : Italian tunnel broker (Telecom Italia Research)


Note: The current (10/2002) freenet6 windows binary is buggy, use it to get the 
values, and set manually your tunnel.



--------------------------------------------------------------------------------
6.6. Troubles
------------

6.6.1. Listen on ::1:1720 failed: Address family not supported by protocol
-----------------------------------------------------------------------
IPv6 module is not loaded in the kernel.
#modprobe ipv6



6.6.2. SimpleH323	TCP Could not open H.323 listener port on 1720
--------------------------------------------------------------
Add some traces: -t on the command line. 



6.6.3. SimpleH323	TCP Listen on fe80::2b0:d0ff:fedf:d6bf:1720 failed: Invalid argument
------------------------------------------------------------------------------------
This address is a local scope address. As the scope_id field is always set to 0,
its value is invalid.

Use address with global scope.




================================================================================

7. Platform Specific Issues
---------------------------
PWLib has been ported to several platforms. However on some systems not all of
the functionality has been implemented. This could be due to lack of support
at the OS level or simply due to lack of time or documentation when developing
the port.


--------------------------------------------------------------------------------
7.1. FreeBSD Issues
-------------------

Port Maintained by Roger Hardiman <roger@freebsd.org>
GetRouteTable() in socket.cxx has been added. It is used by
OenH323Proxy, but is not fully tested.


--------------------------------------------------------------------------------
7.2. OpenBSD Issues
-------------------

Port Maintained by Roger Hardiman <roger@freebsd.org>
GetRouteTable() in socket.cxx has been added. It is used by
OenH323Proxy, but is not fully tested.


--------------------------------------------------------------------------------
7.3. NetBSD Issues
------------------

Port Maintained by Roger Hardiman <roger@freebsd.org>
GetRouteTable() in socket.cxx has been added. It is used by
OenH323Proxy, but is not fully tested.

There are now three ways to do pthreads in NetBSD.
a) unproven threads - from the packages tree.
b) GNU pth threads - from the packages tree.
c) Native pthreads - added to the kernel on 15th January 2003.

The choice can be made by editing pwlib/make/unix.mak
Native threads is the default and the best solution.

--------------------------------------------------------------------------------
7.4. Mac OS X (Darwin) Issues
-----------------------------

Port maintained by Roger Hardiman <roger@freebsd.org> but recently
Shawn Pai-Hsiang Hsiao <shawn@eecs.harvard.edu> has been leading
development.
Threads cannot be suspended once they are running, and trying to Suspend
a running thread will generate an Assertion Error.
Theads can be created in 'suspended' mode and then started with Resume
This is due to a lack of pthread_kill() in Dawrin 1.2
See http://www.publicsource.apple.com/bugs/X/Libraries/2686231.html

GetRouteTable() in socket.cxx has been added. It is used by
OenH323Proxy, but is not fully tested.

localtime_r() and gm_time() are missing.
So in osutil.cxx I have implemented os_localtime() and os_gmtime()
with localtime() and gm_time() which may not be thread safe.

There is also no implementation for dynamic library functions.

Audio is supported using the coreaudio library.

Video support is being added by Shawn and users interested in this should
check Shawn's web site at http://sourceforge.net/projects/xmeeting/

--------------------------------------------------------------------------------
7.5. BeOS Issues
----------------

Port Maintained by Yuri Kiryanov <openh323@kiryanov.com>. 
Current version supported is BeOS 5.0.2. 

Most important issue is lack of variable sample frequency from system sound producer node.
I made quite a few attempts to implement sound resampler in code, 
even with help of Be engineers, but eventually decided to wait until new Media Kit
with resampler built-in. 
Also network code needed more things, as OOB, which was promised in BONE. 
BONE will allow to make less #defines in network code as well.
As update will hit the Net, I'll get back to it ASAP.  

Look for more port-related info on http://www.dogsbone.com/be


--------------------------------------------------------------------------------
7.6. Windows CE Issues
----------------------

Port Maintained by Yuri Kiryanov <openh323@kiryanov.com>. 
Versions supported is 2.x and 3.x (PocketPC). 
Look for more port-related info on http://www.pocketbone.com

Detailed how-to provided by Frank Naranjo <frank@mivideo.net>.
An html version of this readme is available at ;
http://www.mivideo.net/videophone


7.6.1. HOW-TO build and test Windows CE OpenH323 Port POCKETBONE
----------------------------------------------------------------
March 30 2002, Currently, there is NO source available that compiles
and Tx/Rx Video and Audio for pocketbone. Only the released binary
10b1 in Oct 2001 works! The current CVS version Mar 30 2002, 
is supposed to be 10b1, but its' internaly noted as 0.9beta1. 

Since the code in the CVS has not changed much since October when 
the 10b1 version was released, maybe with the right #ifdef DEFINES
and registry keys configured it might work.

We will dig into the diffs, and debug this unfinished release. 
But, maybe Yuri Kiryanov might release source and its related binary
for a version that works one day, along with all the required
configuration parameters to build it. 

It would be nice to be in a ZIP file, so it is not subject to changes,
as in the CVS. 

7.6.2. Collecting the Required Files
------------------------------------
There are three source modules required to build Pocketbone, 
two of them, openh323 and pwlib libraries and the contributed 
pocketbone module. Using WinCVS  u can get the latest sources
from CVS at openh323.org . Using CVS you should 'checkout' the
'pwlib', 'openh323' and 'contrib' modules. You can save some 
time and space and 'checkout' only the 'contrib/pocketbone' module.
Make certain when u checkout pwlib and openh323 that the .vcp
files are there. If not, u can always access them thru the web 
interface for CVS at openh323.org. You will also need the eVC 
( embedded Visual C 3.0) software from Microsoft to build it.

The new eVC version 4.0 is available FREE for 120 day trial 
now ( since Feb 2002 ). You cannot use MS Visual Studio to
build an embedded system. The new eVC 4.0 has not been used 
to build pocketbone yet from the CVS or herein. 

Place all three source modules in a single directory. i.e.., 
contrib,openh323 and pwlib.
( note that pocketbone is in the contrib directory ). Using eVC,
open the project workspace located in the contrib/pocketbone
(Pocketbone.vcp). It should automatically find the other two
modules (openh323 and pwlib ) and load their respective .vcp files. 

7.6.3. Steps to Build POCKETBONE
--------------------------------
To build POCKETBONE you first need to build the two libraries,
pwlib and openh323. You should build these two libraries using
MS Visual C++, they will need to be built with eVC for the embedded
solution. Both PWLIB and OPENH323 directories contain a .VCP file 
included within the POCKETBONE sources.

Before you can build POCKETBONE however, you will need to configure
your eVC so it knows where to find the required include, library 
and executable files. A  .VCP  project file is available within
each of the three source modules in the CVS or ZIP files. 

-When you download the zip files or the versions from the CVS,
your source directory tree should look like this: 

< Your source dir > \ contrib \ Pocketbone
< Your source dir > \ pwlib
< Your source dir > \ openh323

The pockebone.vcw file expects this configuration. Once you start eVC,
all you need to do is open the project file; 
< Your source dir> \ contrib \ pocketbone \ pocketbone.vcw 

eVC will then find the other project files for PWLIB and OPENH323,
otherwise it will ask you. Select which CPU or platform version
to create; the emulator version X86EMDbg,or the ARM version. 
The ARM versions have a DEBUG and RELEASE version.
Select the Platform :"Pocket PC", CPUs:" Win32(WCE ARM)" selection.

Set of directories which you have to be defined in eVC regardless
of target platform:
 
Tools->Options->Directories, option Include files.
-------------------------------------------------
< Standard include paths > 
< Your source dir > \ pwlib \ include \ ptlib \ wince
< Your source dir > \ pwlib \ include \ ptlib \ wince \ sys 
< Your source dir > \ pwlib \ include \ pwlib \ mswin 
< Your source dir > \ pwlib \ include \ ptlib \ msos 
< Your source dir > \ pwlib \ include 
< Your source dir > \ openh323 \ include 
< Your gapi source dir > \ inc

Get  Gapi source files at;
http://www.microsoft.com/mobile/downloads/developer/gapi.asp

Here are some 'fake' functions to avoid needing Platform 
Builder or loading SNMP libraries for gatekeeper functionality.
( thanks to Jehan Bing ) http://www.mivideo.net/jh_snmp_c.txt

Platform Builder 3.0 was free under an 120 day evaluation, 
just as the new 4.0 platform builder ( since Feb 20002) 
which also includes the new 4.0 eVC. It is NOT necessary 
to build pocketbone with the SNMP libraries provided you
include the 'fake' calls in Jehan Bing's functions file
provided above. 

Tools->Options->Directories, option Executeable AND Library .
------------------------------------------------------------
< Your source dir for location of ptlib.dll >    
< Your source dir for location of Gapi files ( gx.dll )  > \ lib 
< Your source dir >   PWLIB \ Lib (even if does not exist ) 
< Your source dir >   OPENH323 \ Lib ( even if doesn't exist ) 
< Your source dir for location of snmpapi.lib and snmp_mibii.lib  >

( if you have Platform builder )   
click for Zip file for eVC 4.0 Platform Builder Libraries )

Using the BUILD ALL start the build process. The PWLIB library
is built first, then the OPENH323 library, then finally the 
POCKETBONE executable. the EVC will automatically download the 
executable to the iPAQ should you have activeSync and the iPAQ
in the cradle.eVC will copy the executeable to the start menu.

To run select POCKETBONE from the 'start' menu . Enter an IP 
using the keyboard, nit the buttons, since the do not always
work right. The keypad buttons only works on the 9a1 version.

Make any Option settings required such as gatekeeper, trace,
or audio settings. Then press 'Call' to initiate the call. 
You should hear and see the other party right away. 
On some versions full screen video is displayed.
There will be a button to toggle from this full screen in 
the future, along with Volume and mute buttons. 
You are on your own ! Please test and make any comments 
here regarding any problems or suggestions. 

In order to build POCKETBONE for other platforms, 
all you need to do is select the different platforms. 
Although, there will undoubtedly be changes required 
in the source for different platforms. These changes can 
usually be handled with #ifdef statements in the code. 
In order to maintain a single set of source files for 
different platforms.

7.6.4. Latest CVS version March 20 2002
---------------------------------------
PWLIB.zip ( 7,424 Kb)  
"http://www.mivideo.net/videophone/cvs 4 20 pwlib.zip"

OPENH323.zip ( 22,887 Kb) 
"http://www.mivideo.net/videophone/cvs 4 20 openh323.zip"

CONTRIB.zip ( 5,034 Kb) 
"http://www.mivideo.net/videophone/cvs 4 20 contrib.zip"
  
These zip files contain Complete! BUILT files for ARM and X86em
versions using eVC 3.0 and fake SNMP functions file (link above),
to avoid using SNMP libraries. 
For those who asked for it for comparisons !

Noted internally as version 0.9beta1, NOT .10b1 as was stated by
Yuri in the archives to be in this CVS version. This version has
trace options available along with a ( Remote / Local ) 
functionality and different bitmap to reflect it.
ARM Dbg ( 4,222 Kb)
http://www.mivideo.net/videophone/420DPocketBone.exe

ARM Rel ( 2,316 Kb )  
http://www.mivideo.net/videophone/420RPocketBone.exe

Note this version NOT size similar to 9a1 or 10b1 ! 
Yet, its the latest from the CVS as of date shown ! 
Other than the different BMPs used in 10b1 what else differs ?

testing from 4/22/2002  ;
- No Video or Audio Tx/Rx to CuSeeme 5.0.0.43 ( RadVision Stack)
- soft reset ! required after calls sometimes to get correct IP
- Audio OK when called from Cisco ATA 186
- The Remote and Local tabs have no effect.
-Talk button appears even though running on a Pocket PC
 and the 'walkie-talkie is NOT clicked.
 

7.6.5. PocketBone 10b1 Binary zip for iPAQ
------------------------------------------
http://www.mivideo.net/videophone/PocketBone10b1.zip
( 2,317,824 bytes 10/24/2001).

Screen looks like; 
http://www.mivideo.net/videophone/PocketBone.jpg

Notes : Video receiving from NetMeeting has no green stripes. 
Transmits test video by default. Internally noted as 0.10beta1.
Audio and Video works fine. No trace options. If Full screen 
option is enabled, there is NO way out of it other than 'soft reset'

There is NO known source files for this version ! Neither will 
there probably ever be. It is the last release from October 2001
before the Open Source version took a back seat to the commercial
development of iFON at Tabletmedia.com.
http://www.tabletmedia.com/ifon.asp

Unpack the binary zip file and copy PocketBone.exe to
\Windows\Start Menu and gx.dll to \Windows. 

7.6.6. PocketBone .9a1 binary ARMREl
------------------------------------
( 2,257 Kb 8/9/2001 )
The main bitmap for this version looks like;
http://www.mivideo.net/videophone7alpha3b.jpg
The working .9a1 binary version from the link below 
was released as version .9a1. 
Internally it is noted as 0.7alpha3. This version transmits
default H261 video color bar screen. It can receive video
and Tx and Rx audio. There are a few problems with this version.
Calling from CuSeeme 5.0 client sending 160x240 video 
this version displays video full screen and locks up the display,
so you cannot do anything else to restore except a 'soft reset'.
'Your mileage may vary'. Should you have better luck, 
please let me know at nubeus@bellsouth.net.

Also, I have not been able to initiate a call with it. 
The display shows the [Remote / Local ] tabs along with
an [FS] switch at the lower right of the display. 
It also has an early address book non-working icon where
you enter the IP along with icons for [Dialpad / Calls]
which are not functioning. The number buttons do work correctly !
 The ZIP sources above does NOT build 
the 0.9a1 version although it was supposed to according to Yuri
and the mailing list. The version it creates is noted internally
only in trace file as 0.7a3. It connects, but does not
transmit video and audio. It crashes when called.

Version .9a1 Binary is at 
http://www.mivideo.net/videophone/PocketBone9a1.zip
( internally noted as 0.7alpha3 !! ) ( 2,250,240 bytes 8/9/2001) 

Source Zip files which should, but does NOT match binary above !

Pocketbone source Zip (1,952 Kb )
http://www.mivideo.net/pocketbone.zip
ARMREl ( 2,257 Kb )      ARMDbg ( 4,177 Kb )

PwLib source Zip ( 1,830 Kb )
http://www.mivideo.net/pwlib.zip

OpenH323 source Zip (1,692 Kb) 
http://www.mivideo.net/openh323.zip

7.6.7. General Usage Notes
--------------------------

- PocketBone performs best on iPAQ Pocket PC 2002.
  An iPAQ 3630 with CE 3.0 and the Pocket PC 2002 
  update will do fine ! Pocketbone takes up less than 3mb,
  and getting smaller every version.

- By default PocketBone connects to NetMeeting using MS-GSM.
  If your NetMeeting does not have GSM codec installed, 
  get it here. What Microsoft calls GSM 6.10 is not what
  everyone understands as GSM 6.10 compression. NetMeeting
  must be set to "GSM 6.10" (MS-GSM), iPAQ to MS-GSM. 
  Then they connect. 

- If you are running PocketBone and you found an error 
  saying "Missing components", get gx.dll (part of GAPI) 
  from here and place it to \Windows directory. 

- To enable gateway call, e.g. through Cisco AS5300, 
  set following:
  Go to Options/Gates, set gateway IP address, set gatekeeper
  address, check "Use Gatekeeper", "Require Gatekeeper". 
  Switch to Options/General, set name, e.g. "ipaq" in "User"
  field. Add your extension, e.g. "3620" and your cisco id,
  e.g."3620!cisco" to "Aliases". Check "Disable fast-start"
  to avoid fast-start problems when call connected earlier 
  for expense of clarity of first few seconds of call. 
  You won't be able to receive calls if you are not registered
  on gatekeeper .You have to rearrange audio codecs located
  at Options/Audio. Move GSM-06.10 and/or G.711 on top of 
  the list and disable MS-GSM codec. MS-GSM codec is 
  incompatible with non-MS products. 

- If your connection is good enough, try reduce jitter 
  buffer size ( Options / Audio ). It will decrease audio latency. 

- Full-duplex sound driver has been released by Compaq for
  Pocket PC 2000. Get it here (look for Full Duplex Driver link).
  The off-the-shelf iPaq 2000 is half-duplex. Do not forget to 
  uncheck Walkie-Talkie in Options/Audio and restart the app. 

- Should you get link error : LINK : fatal error LNK1181: 
  cannot open input file "snmpapi.lib" then the library is not
  included in "Object/library modules:" at "Project - Settings -
  Link" in eVC. 

- Some people reported problems with building code when compiler
  reports some SNMP includes missing. You will need to obtain 
  Platform Builder, and then add include and lib directory to 
  project settings in order to be able to link snmpapi.lib and 
  snmp_mibii.lib from the Platform Builder directory. 
  (\PUBLIC\COMMON\OAK\LIB\ARM\SA1100\CE\RETAIL). 

- Video won't work out-of-box on x86 emulator. Get GAPI emulator
  and try figuring it out.

- Supports full-screen CIF video. Audio clicking removed 

- If you had installed an old version before, please remove 
  old registry settings located at: 
  HKEY_CURRENT_USER\Software\OpenH323\PocketBone\CurrentVersion

- To enable video receive with QCIF size, make sure registry
  has "VideoSize"=1 and "H261_QCIF"=1. 

- If you have problems on connection, go to registry and disable
  video receiving.Find following key in registry:
  HKEY_CURRENT_USER\Software\OpenH323\PocketBone\CurrentVersion\Options
  Then add DWORD value of 0 with name of "VideoSize". 

- In order to improve UDP performance ( videoconferencing ) 
  you have to change registry setting on iPAQ value to 16(maximum)
  HKEY_LOCAL_MACHINE\Comm\Afd
On NetMeeting go to Video settings,
  choose "Better Image". 

- If you get following when trying to run PocketBone:
  "Cannot find PocketBone or one of it's components. Make sure
  the path and file name are correct and all the required 
  libraries are available...", install GAPI (Game API) gx.h and gx.dll. 
 
- When in Walkie-Talkie mode, re-assign a recorder button on
  your iPAQ to PocketBone. It will allow you to use this 
  recorder button as a switch to change PocketBone from "listen"
  mode to "talk" mode and back. Only required when iPAQ is used
  in half-duplex. Version .9a1 and .10b1 work fine in full 
  duplex on a PPC. rfer to;
  http://www.mivideo.net/Buttons.jpg

7.6.8. Testing
--------------
Ohphone can be used to test Pocketbone as well as Netmeeting.
Although Netmeeting does not hold up to the H323 standard well.
and has been forsaken for the new Instant Messenger from Microsoft.
CuSeeme 5.0 on the other hand is built with the RadVision H323 stack,
a better implementation of the H323 standard. Pocketbone adheres
thru the work of many contributors of the openh323.org project
to the H323 v4 standard. It does not have patented codecs 
integrated due to licensing restrictions but there are hooks
in it should the codec be recognized in the system. Please refer
to the openh323.org site for details.
 
Cisco ATA 186 IP phones,
either in H323 or when set to IP phones work quite well . 
Testing has been done on HP Jornada and Casio PDAs. 
Results will soon follow along with configurations, notes and source Zip files.

7.6.9. Links 
------------
Keep in touch with the PDA global activities thru http://www.infosync.no/

7.6.10. Futures
--------------
Porting to other platforms such as Palm, and other CPUs such as MIPS, SH3,
SH4 are not too difficult.

HOW-TO step-by-step will be provided as new platforms are ported and tested.
If you have ported this to another platform, your configuration info would
be appreciated.

Please forward comments of this how-to page to nubeus@bellsouth.net
an html version of this readme is available at ;
http://www.mivideo.net/videophone


--------------------------------------------------------------------------------
7.7. Solaris Issues
-------------------
On Solaris 8, you need to install GNU Ld (the loader) to get
shared libraries to compile. (otherwise there is an error with -soname)
You can get around this by using the static libraries and
compiling with make optnoshared and make debugnoshared

There is currently no implementation of GetRouteTable() in socket.cxx
so OpenH323Proxy will not work.


--------------------------------------------------------------------------------
7.8. Build libraries under Windows
----------------------------------

Unfortunately building libraries that were intended for Unix based systems
under Windows can sometimes be difficult. Here are some notes on the subsystems
that PWLib uses.

7.8.1. OpenSSL under Windows
----------------------------
The standard build for OpenSSL off http://www.openssl.org does work though it
is rather tricky and requires things like Perl to be installed on your
Windows box. However the build does work and is correct for PWlib use. Make
sure you build the non-DLL Debug and Release versions.

7.8.2. EXPAT under Windows
---------------------------
The easiest way is to get the one in the OpenH323 CVS. This is guranteed to
work. Use the following command to do this:

  cvs -d :pserver:anonymous@cvs.sourceforge.net:/cvsroot/openh323 co external/expat

and then use the expat.dsw file to build the Debug and Release libraries.

7.8.3. OpenLDAP under Windows
---------------------------
To use OpenLDAP with PWLib you have to compile the OpenLDAP library as a DLL.
Unfortunately, the standard distribution does not do this. So there is a file in
PWLib called pwlib/tools/openldap-2.1.12-win32.zip which contains altered build
files for that version of OpenLDAP. Note if you have a different version these
files may not work.

To build the DLL:

   1   Get OpenLDAP v 2.1.17 via tar file at
         ftp://ftp.openldap.org/pub/OpenLDAP/openldap-release/openldap-2.1.17.tgz
       or anonymous CVS using tag at
         :pserver:anonymous@cvs.OpenLDAP.org:/repo/OpenLDAP
       using tag OPENLDAP_REL_ENG_2_1_17
   2   Unpack it somewhere, eg c:\work\openldap
   3   Unzip the openldap-2.1.17-win32.zip file that directory
   4   Open openldap/build/main.dsw
   5   use Batch build to and select the "dll" project and build the "DLL Debug"
       and "DLL Release" targets.
   6   Put the resulting openldap/DLLRelease/openldap.dll and
       openldap/DLLDebug/openldapd.dll files in your path.

7.8.4 SDL under Windows
-----------------------
Version 1.2.5 has support for Windows and MSVC so you just need to download it
from http://www.libsdl.org/ and follow the build instructions.

7.8.5 SASL under Windows
------------------------
The standard distribution of Cyrus SASL comes with makefiles for Windows and
clear instructions on how to build the library. The current implementation
in PWLib was tested with Cyrus SASL version 2.1.18. Tarballs can be downloaded
from:

    http://asg.web.cmu.edu/sasl/sasl-library.html


--------------------------------------------------------------------------------
7.9. ESD (Esound)
-----------------

Most targets come with native sound support.
However there is also support for the ESD (esound) daemon which provides
full duplex audio via network sockets.
To compile pwlib to use ESD, you need to set the ESDDIR environment variable
to point to the directory you have installed ESD into.
Then compile pwlib.


================================================================================

8. Conclusion
-------------

This package is far from a "product". There is very limited documentation and
support will be on an ad-hoc basis, send us an e-mail and we will probably
answer your question if it isn't too difficult.

It is supplied mainly to support the open H323 project, but that shouldn't stop
you from using it in whatever project you have in mind if you so desire. We like
it and use it all the time, and we don't want to get into any religious wars of
this class library over that one.




================================================================================

9. Licensing                 
------------

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


The random number generator is based on code originally by Bob Jenkins.


Portions of this library are from the REGEX library and is under the
following license:

Copyright 1992, 1993, 1994, 1997 Henry Spencer.  All rights reserved.
This software is not subject to any license of the American Telephone
and Telegraph Company or of the Regents of the University of California.

Permission is granted to anyone to use this software for any purpose on
any computer system, and to alter it and redistribute it, subject
to the following restrictions:

1. The author is not responsible for the consequences of use of this
   software, no matter how awful, even if they arise from flaws in it.

2. The origin of this software must not be misrepresented, either by
   explicit claim or by omission.  Since few users ever read sources,
   credits must appear in the documentation.

3. Altered versions must be plainly marked as such, and must not be
   misrepresented as being the original software.  Since few users
   ever read sources, credits must appear in the documentation.

4. This notice may not be removed or altered.


The in-band DTMF decoding code was taken from FreeBSD's dtmfdecode.c
application written by Poul-Henning Kamp. It has the following
license:
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------



================================================================================
Equivalence Pty. Ltd.
Home of OpenH323 and the Open Phone Abstraction Library (OPAL)

support@equival.com.au
http://www.equival.com.au (US Mirror - http://www.equival.com)

================================================================================
