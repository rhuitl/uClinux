# Microsoft Developer Studio Project File - Name="libmpr" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libmpr - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libmpr.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libmpr.mak" CFG="libmpr.mak - Win32"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libmpr - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library"
!MESSAGE "libmpr - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library"
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libmpr - Win32 Release" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\bin\Release"
# PROP Intermediate_Dir "..\obj\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3  -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL  -I..  -O1 -D_NDEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\bin\Release\libmpr.dll -dll  -entry:mprDllMain -def:../obj/Release/libmpr.def   -machine:ix86 -nodefaultlib -incremental:no -nologo    -libpath:"../bin/Release"  ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib

# Begin Special Build Tool
PreLink_Desc=Export symbols for ..\bin\Release\libmpr.dll
PreLink_Cmds=..\bin\dumpext -o ../obj/Release/libmpr.def libmpr.dll ../obj/Release/buf.obj ../obj/Release/embedded.obj ../obj/Release/file.obj ../obj/Release/mpr.obj ../obj/Release/hash.obj ../obj/Release/list.obj ../obj/Release/log.obj ../obj/Release/malloc.obj ../obj/Release/select.obj ../obj/Release/socket.obj ../obj/Release/task.obj ../obj/Release/timer.obj ../obj/Release/os.obj ../obj/Release/daemon.obj ../obj/Release/thread.obj  ../obj/Release/stdcpp.obj
# End Special Build Tool

!ENDIF

!IF  "$(CFG)" == "libmpr - Win32 Debug" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\bin\Debug"
# PROP Intermediate_Dir "..\obj\Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3  -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL  -I..  -Zi -Od -GZ -D_DEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\bin\Debug\libmpr.dll -dll  -entry:mprDllMain -def:../obj/Debug/libmpr.def   -machine:ix86 -nodefaultlib -incremental:no -nologo -debug   -libpath:"../bin/Debug"  ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib

# Begin Special Build Tool
PreLink_Desc=Export symbols for ..\bin\Debug\libmpr.dll
PreLink_Cmds=..\bin\dumpext -o ../obj/Debug/libmpr.def libmpr.dll ../obj/Debug/buf.obj ../obj/Debug/embedded.obj ../obj/Debug/file.obj ../obj/Debug/mpr.obj ../obj/Debug/hash.obj ../obj/Debug/list.obj ../obj/Debug/log.obj ../obj/Debug/malloc.obj ../obj/Debug/select.obj ../obj/Debug/socket.obj ../obj/Debug/task.obj ../obj/Debug/timer.obj ../obj/Debug/os.obj ../obj/Debug/daemon.obj ../obj/Debug/thread.obj  ../obj/Debug/stdcpp.obj
# End Special Build Tool

!ENDIF


# Begin Target

# Name "libmpr - Win32 Release"
# Name "libmpr - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE=buf.cpp
# End Source File

# Begin Source File
SOURCE=embedded.cpp
# End Source File

# Begin Source File
SOURCE=file.cpp
# End Source File

# Begin Source File
SOURCE=mpr.cpp
# End Source File

# Begin Source File
SOURCE=hash.cpp
# End Source File

# Begin Source File
SOURCE=list.cpp
# End Source File

# Begin Source File
SOURCE=log.cpp
# End Source File

# Begin Source File
SOURCE=malloc.cpp
# End Source File

# Begin Source File
SOURCE=select.cpp
# End Source File

# Begin Source File
SOURCE=stdcpp.cpp
# End Source File

# Begin Source File
SOURCE=socket.cpp
# End Source File

# Begin Source File
SOURCE=task.cpp
# End Source File

# Begin Source File
SOURCE=timer.cpp
# End Source File

# Begin Source File
SOURCE=WIN\os.cpp
# End Source File

# Begin Source File
SOURCE=WIN\daemon.cpp
# End Source File

# Begin Source File
SOURCE=WIN\thread.cpp
# End Source File

# End Group

# Begin Group "Header Files"
# PROP Default_Filter "h;"
# Begin Source File
SOURCE=.\mpr.h
# End Source File

# Begin Source File
SOURCE=.\mprOs.h
# End Source File

# End Group
# Begin Group "Resource Files"
# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"

# Begin Source File
SOURCE=.\mpr.rc
# End Source File

# End Group
# End Target
# End Project
