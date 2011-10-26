# Microsoft Developer Studio Project File - Name="winAppWeb" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=winAppWeb - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "winAppWeb.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "winAppWeb.mak" CFG="winAppWeb.mak - Win32"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "winAppWeb - Win32 Release" (based on "Win32 (x86) Application"
!MESSAGE "winAppWeb - Win32 Debug" (based on "Win32 (x86) Application"
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "winAppWeb - Win32 Release" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\bin\Release"
# PROP Intermediate_Dir ".\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3  -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL -I../mpr -I../ejs -I../http -I../http/modules -I../../../packages/php/php-4.3.6 -I../../../packages/php/php-4.3.6/main -I../../../packages/php/php-4.3.6/Zend -I../../../packages/php/php-4.3.6/TSRM -I../../../packages/php/php-5.0.0RC3 -I../../../packages/php/php-5.0.0RC3/main -I../../../packages/php/php-5.0.0RC3/Zend -I../../../packages/php/php-5.0.0RC3/TSRM -I../../../packages/openssl/openssl-0.9.7d/include -I..  -O1 -D_NDEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\bin\Release\winAppWeb.exe -subsystem:WINDOWS -entry:WinMainCRTStartup   -machine:ix86 -nodefaultlib -incremental:no -nologo   shell32.lib  -libpath:"../bin/Release"  libappWeb.lib ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib


!ENDIF

!IF  "$(CFG)" == "winAppWeb - Win32 Debug" 

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\bin\Debug"
# PROP Intermediate_Dir ".\Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""

# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409

# ADD BASE CPP 
# ADD CPP  -W3  -nologo -MDd -FD -DWIN -D_DLL -D_MT -D_WINDOWS -DWIN32 -D_WIN32_WINNT=0x500 -D_X86_=1 -GX- -D_USRDLL -I../mpr -I../ejs -I../http -I../http/modules -I../../../packages/php/php-4.3.6 -I../../../packages/php/php-4.3.6/main -I../../../packages/php/php-4.3.6/Zend -I../../../packages/php/php-4.3.6/TSRM -I../../../packages/php/php-5.0.0RC3 -I../../../packages/php/php-5.0.0RC3/main -I../../../packages/php/php-5.0.0RC3/Zend -I../../../packages/php/php-5.0.0RC3/TSRM -I../../../packages/openssl/openssl-0.9.7d/include -I..  -Zi -Od -GZ -D_DEBUG /c
LINK32=link.exe
# ADD BASE LINK32 
# ADD LINK32 -out:..\bin\Debug\winAppWeb.exe -subsystem:WINDOWS -entry:WinMainCRTStartup   -machine:ix86 -nodefaultlib -incremental:no -nologo -debug  shell32.lib  -libpath:"../bin/Debug"  libappWeb.lib ws2_32.lib advapi32.lib user32.lib kernel32.lib oldnames.lib msvcrt.lib


!ENDIF


# Begin Target

# Name "winAppWeb - Win32 Release"
# Name "winAppWeb - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE=winAppWeb.cpp
# End Source File

# Begin Source File
SOURCE=romFiles.cpp
# End Source File

# Begin Source File
SOURCE=appWebStaticLink.cpp
# End Source File

# End Group

# Begin Group "Header Files"
# PROP Default_Filter "h;"
# Begin Source File
SOURCE=.\appWeb.h
# End Source File

# End Group
# Begin Group "Resource Files"
# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"

# Begin Source File
SOURCE=.\appWeb.rc
# End Source File

# End Group
# End Target
# End Project
