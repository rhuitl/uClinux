# Microsoft Developer Studio Project File - Name="libphp4Module" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libphp4Module - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libphp4Module.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libphp4Module.mak" CFG="libphp4Module.mak - Win32"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libphp4Module - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library"
!MESSAGE "libphp4Module - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library"
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libphp4Module - Win32 Release" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\..\bin\Release"
# PROP Intermediate_Dir "..\..\..\obj\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3 -DPHP4 -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL -I../.. -I../../../mpr -I../../../../../packages/php/php-4.3.6 -I../../../../../packages/php/php-4.3.6/main -I../../../../../packages/php/php-4.3.6/Zend -I../../../../../packages/php/php-4.3.6/TSRM -I../../..  -O1 -D_NDEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\..\..\bin\Release\libphp4Module.dll -dll  -entry:_DllMainCRTStartup@12 -def:../../../obj/Release/libphp4Module.def   -machine:ix86 -nodefaultlib -incremental:no -nologo    -libpath:"../../../../../packages/php/php-4.3.6/libs" -libpath:"../../../bin/Release"  libappWeb.lib libphp4.lib ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib

# Begin Special Build Tool
PreLink_Desc=Export symbols for ..\..\..\bin\Release\libphp4Module.dll
PreLink_Cmds=..\..\..\bin\dumpext -o ../../../obj/Release/libphp4Module.def libphp4Module.dll   ../../../obj/Release/php4Handler.obj
# End Special Build Tool

!ENDIF

!IF  "$(CFG)" == "libphp4Module - Win32 Debug" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\..\bin\Debug"
# PROP Intermediate_Dir "..\..\..\obj\Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3 -DPHP4 -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL -I../.. -I../../../mpr -I../../../../../packages/php/php-4.3.6 -I../../../../../packages/php/php-4.3.6/main -I../../../../../packages/php/php-4.3.6/Zend -I../../../../../packages/php/php-4.3.6/TSRM -I../../..  -Zi -Od -GZ -D_DEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\..\..\bin\Debug\libphp4Module.dll -dll  -entry:_DllMainCRTStartup@12 -def:../../../obj/Debug/libphp4Module.def   -machine:ix86 -nodefaultlib -incremental:no -nologo -debug   -libpath:"../../../../../packages/php/php-4.3.6/libs" -libpath:"../../../bin/Debug"  libappWeb.lib libphp4.lib ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib

# Begin Special Build Tool
PreLink_Desc=Export symbols for ..\..\..\bin\Debug\libphp4Module.dll
PreLink_Cmds=..\..\..\bin\dumpext -o ../../../obj/Debug/libphp4Module.def libphp4Module.dll   ../../../obj/Debug/php4Handler.obj
# End Special Build Tool

!ENDIF


# Begin Target

# Name "libphp4Module - Win32 Release"
# Name "libphp4Module - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE=php4Handler.cpp
# End Source File

# End Group

# Begin Group "Header Files"
# PROP Default_Filter "h;"
# Begin Source File
SOURCE=.\php4Handler.h
# End Source File

# End Group
# End Target
# End Project
