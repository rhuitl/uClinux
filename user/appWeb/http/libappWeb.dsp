# Microsoft Developer Studio Project File - Name="libappWeb" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libappWeb - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libappWeb.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libappWeb.mak" CFG="libappWeb.mak - Win32"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libappWeb - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library"
!MESSAGE "libappWeb - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library"
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libappWeb - Win32 Release" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\bin\Release"
# PROP Intermediate_Dir "..\obj\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3  -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL -I. -I../mpr -Imodules -I..  -O1 -D_NDEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\bin\Release\libappWeb.dll -dll  -entry:_DllMainCRTStartup@12 -def:../obj/Release/libappWeb.def   -machine:ix86 -nodefaultlib -incremental:no -nologo   ../obj/Release/buf.obj ../obj/Release/daemon.obj ../obj/Release/embedded.obj ../obj/Release/file.obj ../obj/Release/hash.obj ../obj/Release/list.obj ../obj/Release/log.obj ../obj/Release/malloc.obj ../obj/Release/mpr.obj ../obj/Release/os.obj ../obj/Release/select.obj ../obj/Release/socket.obj ../obj/Release/task.obj ../obj/Release/thread.obj ../obj/Release/timer.obj  -libpath:"../bin/Release"  ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib

# Begin Special Build Tool
PreLink_Desc=Export symbols for ..\bin\Release\libappWeb.dll
PreLink_Cmds=..\bin\dumpext -o ../obj/Release/libappWeb.def libappWeb.dll ../obj/Release/alias.obj ../obj/Release/auth.obj ../obj/Release/buf.obj ../obj/Release/client.obj ../obj/Release/crypt.obj ../obj/Release/daemon.obj ../obj/Release/date.obj ../obj/Release/dir.obj ../obj/Release/embedded.obj ../obj/Release/file.obj ../obj/Release/handler.obj ../obj/Release/hash.obj ../obj/Release/host.obj ../obj/Release/http.obj ../obj/Release/list.obj ../obj/Release/location.obj ../obj/Release/log.obj ../obj/Release/malloc.obj ../obj/Release/module.obj ../obj/Release/mpr.obj ../obj/Release/os.obj ../obj/Release/request.obj ../obj/Release/rom.obj ../obj/Release/select.obj ../obj/Release/server.obj ../obj/Release/socket.obj ../obj/Release/task.obj ../obj/Release/thread.obj ../obj/Release/timer.obj ../obj/Release/url.obj 
# End Special Build Tool

!ENDIF

!IF  "$(CFG)" == "libappWeb - Win32 Debug" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\bin\Debug"
# PROP Intermediate_Dir "..\obj\Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3  -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL -I. -I../mpr -Imodules -I..  -Zi -Od -GZ -D_DEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\bin\Debug\libappWeb.dll -dll  -entry:_DllMainCRTStartup@12 -def:../obj/Debug/libappWeb.def   -machine:ix86 -nodefaultlib -incremental:no -nologo -debug  ../obj/Debug/buf.obj ../obj/Debug/daemon.obj ../obj/Debug/embedded.obj ../obj/Debug/file.obj ../obj/Debug/hash.obj ../obj/Debug/list.obj ../obj/Debug/log.obj ../obj/Debug/malloc.obj ../obj/Debug/mpr.obj ../obj/Debug/os.obj ../obj/Debug/select.obj ../obj/Debug/socket.obj ../obj/Debug/task.obj ../obj/Debug/thread.obj ../obj/Debug/timer.obj  -libpath:"../bin/Debug"  ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib

# Begin Special Build Tool
PreLink_Desc=Export symbols for ..\bin\Debug\libappWeb.dll
PreLink_Cmds=..\bin\dumpext -o ../obj/Debug/libappWeb.def libappWeb.dll ../obj/Debug/alias.obj ../obj/Debug/auth.obj ../obj/Debug/buf.obj ../obj/Debug/client.obj ../obj/Debug/crypt.obj ../obj/Debug/daemon.obj ../obj/Debug/date.obj ../obj/Debug/dir.obj ../obj/Debug/embedded.obj ../obj/Debug/file.obj ../obj/Debug/handler.obj ../obj/Debug/hash.obj ../obj/Debug/host.obj ../obj/Debug/http.obj ../obj/Debug/list.obj ../obj/Debug/location.obj ../obj/Debug/log.obj ../obj/Debug/malloc.obj ../obj/Debug/module.obj ../obj/Debug/mpr.obj ../obj/Debug/os.obj ../obj/Debug/request.obj ../obj/Debug/rom.obj ../obj/Debug/select.obj ../obj/Debug/server.obj ../obj/Debug/socket.obj ../obj/Debug/task.obj ../obj/Debug/thread.obj ../obj/Debug/timer.obj ../obj/Debug/url.obj 
# End Special Build Tool

!ENDIF


# Begin Target

# Name "libappWeb - Win32 Release"
# Name "libappWeb - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE=alias.cpp
# End Source File

# Begin Source File
SOURCE=auth.cpp
# End Source File

# Begin Source File
SOURCE=client.cpp
# End Source File

# Begin Source File
SOURCE=crypt.cpp
# End Source File

# Begin Source File
SOURCE=date.cpp
# End Source File

# Begin Source File
SOURCE=dir.cpp
# End Source File

# Begin Source File
SOURCE=handler.cpp
# End Source File

# Begin Source File
SOURCE=host.cpp
# End Source File

# Begin Source File
SOURCE=http.cpp
# End Source File

# Begin Source File
SOURCE=location.cpp
# End Source File

# Begin Source File
SOURCE=module.cpp
# End Source File

# Begin Source File
SOURCE=request.cpp
# End Source File

# Begin Source File
SOURCE=rom.cpp
# End Source File

# Begin Source File
SOURCE=server.cpp
# End Source File

# Begin Source File
SOURCE=url.cpp
# End Source File

# End Group

# Begin Group "Header Files"
# PROP Default_Filter "h;"
# Begin Source File
SOURCE=.\capi.h
# End Source File

# Begin Source File
SOURCE=.\client.h
# End Source File

# Begin Source File
SOURCE=.\compatApi.h
# End Source File

# Begin Source File
SOURCE=.\http.h
# End Source File

# Begin Source File
SOURCE=.\shared.h
# End Source File

# End Group
# End Target
# End Project
