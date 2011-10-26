# Microsoft Developer Studio Project File - Name="ferret" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=ferret - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ferret.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ferret.mak" CFG="ferret - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ferret - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "ferret - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ferret - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\WpdPack\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD BASE RSC /l 0x1009 /d "NDEBUG"
# ADD RSC /l 0x1009 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib setargv.obj ..\WpdPack\Lib\Packet.lib ..\WpdPack\Lib\wpcap.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "ferret - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 2
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /Gm /GX /ZI /Od /I "..\WpdPack\Include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D "_AFXDLL" /FR /YX /FD /GZ /c
# ADD BASE RSC /l 0x1009 /d "_DEBUG"
# ADD RSC /l 0x1009 /d "_DEBUG" /d "_AFXDLL"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 setargv.obj ..\WpdPack\Lib\Packet.lib ..\WpdPack\Lib\wpcap.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "ferret - Win32 Release"
# Name "ferret - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "PROTOS"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\arp.c
# End Source File
# Begin Source File

SOURCE=.\callwaveiam.c
# End Source File
# Begin Source File

SOURCE=.\cisco.c
# End Source File
# Begin Source File

SOURCE=.\cups.c
# End Source File
# Begin Source File

SOURCE=.\dhcp.c
# End Source File
# Begin Source File

SOURCE=.\dns.c
# End Source File
# Begin Source File

SOURCE=.\ethernet.c
# End Source File
# Begin Source File

SOURCE=.\gre.c
# End Source File
# Begin Source File

SOURCE=.\http.c
# End Source File
# Begin Source File

SOURCE=.\icmp.c
# End Source File
# Begin Source File

SOURCE=.\ieee8021x.c
# End Source File
# Begin Source File

SOURCE=.\igmp.c
# End Source File
# Begin Source File

SOURCE=.\ip.c
# End Source File
# Begin Source File

SOURCE=.\ipv6.c
# End Source File
# Begin Source File

SOURCE=.\isakkmp.c
# End Source File
# Begin Source File

SOURCE=.\ldap.c
# End Source File
# Begin Source File

SOURCE=.\msnms.c
# End Source File
# Begin Source File

SOURCE=.\netbios_dgm.c
# End Source File
# Begin Source File

SOURCE=.\pop3.c
# End Source File
# Begin Source File

SOURCE=.\ppp.c
# End Source File
# Begin Source File

SOURCE=.\smb_dgm.c
# End Source File
# Begin Source File

SOURCE=.\smtp.c
# End Source File
# Begin Source File

SOURCE=.\snmp.c
# End Source File
# Begin Source File

SOURCE=.\srvloc.c
# End Source File
# Begin Source File

SOURCE=.\ssdp.c
# End Source File
# Begin Source File

SOURCE=.\tcp.c
# End Source File
# Begin Source File

SOURCE=.\udp.c
# End Source File
# Begin Source File

SOURCE=.\upnp.c
# End Source File
# Begin Source File

SOURCE=.\wifi80211.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\ferret.c
# End Source File
# Begin Source File

SOURCE=.\main.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\ferret.h
# End Source File
# Begin Source File

SOURCE=.\formats.h
# End Source File
# Begin Source File

SOURCE=.\netframe.h
# End Source File
# Begin Source File

SOURCE=.\protos.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\readme.txt
# End Source File
# End Target
# End Project
