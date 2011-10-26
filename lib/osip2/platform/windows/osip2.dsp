# Microsoft Developer Studio Project File - Name="osip2" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=osip2 - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "osip2.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "osip2.mak" CFG="osip2 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "osip2 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "osip2 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "osip2 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".libs"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIP2_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\..\include" /D "NDEBUG" /D "OSIP2_EXPORTS" /D "AC_BUG" /D "ENABLE_TRACE" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIP_MT" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 msvcrt.lib osipparser2.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib /libpath:".libs"

!ELSEIF  "$(CFG)" == "osip2 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".libs"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIP2_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "..\..\include" /D "_DEBUG" /D "ENABLE_DEBUG" /D "OSIP2_EXPORTS" /D "AC_BUG" /D "ENABLE_TRACE" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIP_MT" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 msvcrtd.lib osipparser2.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /nodefaultlib /pdbtype:sept /libpath:".libs"

!ENDIF 

# Begin Target

# Name "osip2 - Win32 Release"
# Name "osip2 - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\src\osip2\fsm_misc.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\ict.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\ict_fsm.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\ist.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\ist_fsm.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\nict.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\nict_fsm.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\nist.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\nist_fsm.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\osip.c
# End Source File
# Begin Source File

SOURCE=.\osip2.def
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\osip_dialog.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\osip_event.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\osip_negotiation.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\osip_time.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\osip_transaction.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\port_condv.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\port_fifo.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\port_sema.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\port_thread.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\src\osip2\fsm.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\internal.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\osip.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\osip_condv.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\osip_dialog.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\osip_fifo.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\osip_mt.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\osip_negotiation.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osip2\osip_time.h
# End Source File
# Begin Source File

SOURCE=..\..\src\osip2\xixt.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
