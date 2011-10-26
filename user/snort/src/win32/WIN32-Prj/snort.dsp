# Microsoft Developer Studio Project File - Name="snort" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=snort - Win32 Oracle Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "snort.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "snort.mak" CFG="snort - Win32 Oracle Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "snort - Win32 MySQL Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 MySQL Release" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 SQLServer Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 SQLServer Release" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 Oracle Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 Oracle Release" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "snort___Win32_MySQL_Debug"
# PROP BASE Intermediate_Dir "snort___Win32_MySQL_Debug"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "snort___Win32_MySQL_Debug"
# PROP Intermediate_Dir "snort___Win32_MySQL_Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /FR /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "..\..\preprocessors\Stream5" /D "_DEBUG" /D "DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /D "DYNAMIC_PLUGIN" /FR /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib wpcap.lib libpcap.lib advapi32.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"
# ADD LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib wpcap.lib libpcap.lib advapi32.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "snort___Win32_MySQL_Release"
# PROP BASE Intermediate_Dir "snort___Win32_MySQL_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "snort___Win32_MySQL_Release"
# PROP Intermediate_Dir "snort___Win32_MySQL_Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "..\..\preprocessors\Stream5" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /D "DYNAMIC_PLUGIN" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /machine:I386 /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"
# ADD LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /machine:I386 /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "snort___Win32_SQLServer_Debug"
# PROP BASE Intermediate_Dir "snort___Win32_SQLServer_Debug"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "snort___Win32_SQLServer_Debug"
# PROP Intermediate_Dir "snort___Win32_SQLServer_Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MSSQL" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fr /YX"snort.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "..\..\preprocessors\Stream5" /D "_DEBUG" /D "DEBUG" /D "ENABLE_MSSQL" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /D "DYNAMIC_PLUGIN" /Fr /YX"snort.h" /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"
# ADD LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "snort___Win32_SQLServer_Release"
# PROP BASE Intermediate_Dir "snort___Win32_SQLServer_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "snort___Win32_SQLServer_Release"
# PROP Intermediate_Dir "snort___Win32_SQLServer_Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MSSQL" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /YX"snort.pch" /FD /c
# SUBTRACT BASE CPP /Fr
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "..\..\preprocessors\Stream5" /D "NDEBUG" /D "ENABLE_MSSQL" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /D "DYNAMIC_PLUGIN" /YX"snort.pch" /FD /c
# SUBTRACT CPP /Fr
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /machine:I386 /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"
# ADD LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /machine:I386 /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet"

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "snort___Win32_Oracle_Debug"
# PROP BASE Intermediate_Dir "snort___Win32_Oracle_Debug"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "snort___Win32_Oracle_Debug"
# PROP Intermediate_Dir "snort___Win32_Oracle_Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "D:\oracle\ora92\oci\include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_ORACLE" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fr /YX"snort.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "D:\oracle\ora92\oci\include" /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "..\..\preprocessors\Stream5" /D "_DEBUG" /D "DEBUG" /D "ENABLE_ORACLE" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /D "DYNAMIC_PLUGIN" /Fr /YX"snort.h" /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib oci.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" /libpath:"D:\oracle\ora92\oci\lib\msvc"
# ADD LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib oci.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" /libpath:"D:\oracle\ora92\oci\lib\msvc"

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "snort___Win32_Oracle_Release"
# PROP BASE Intermediate_Dir "snort___Win32_Oracle_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "snort___Win32_Oracle_Release"
# PROP Intermediate_Dir "snort___Win32_Oracle_Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "D:\oracle\ora92\oci\include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_ORACLE" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /YX"snort.pch" /FD /c
# SUBTRACT BASE CPP /Fr
# ADD CPP /nologo /MT /W3 /GX /O2 /I "D:\oracle\ora92\oci\include" /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /I "..\..\preprocessors\Stream5" /D "NDEBUG" /D "ENABLE_ORACLE" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /D "DYNAMIC_PLUGIN" /YX"snort.pch" /FD /c
# SUBTRACT CPP /Fr
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib oci.lib /nologo /subsystem:console /machine:I386 /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" /libpath:"D:\oracle\ora92\oci\lib\msvc"
# ADD LINK32 user32.lib wsock32.lib pcre.lib wpcap.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib oci.lib /nologo /subsystem:console /machine:I386 /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" /libpath:"D:\oracle\ora92\oci\lib\msvc"

!ENDIF 

# Begin Target

# Name "snort - Win32 MySQL Debug"
# Name "snort - Win32 MySQL Release"
# Name "snort - Win32 SQLServer Debug"
# Name "snort - Win32 SQLServer Release"
# Name "snort - Win32 Oracle Debug"
# Name "snort - Win32 Oracle Release"
# Begin Group "Source"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "Detection Plugins"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\..\detection-plugins\sp_asn1.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_asn1.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_asn1_detect.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_asn1_detect.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_byte_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_byte_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_byte_jump.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_byte_jump.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_clientserver.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_clientserver.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_dsize_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_dsize_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_flowbits.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_flowbits.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ftpbounce.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ftpbounce.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_code_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_code_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_id_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_id_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_seq_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_seq_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_type_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_icmp_type_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_fragbits.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_fragbits.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_id_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_id_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_proto.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_proto.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_same_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_same_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_tos_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ip_tos_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ipoption_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ipoption_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_isdataat.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_isdataat.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_pattern_match.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_pattern_match.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_pcre.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_pcre.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_react.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_react.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_respond.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_respond.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_rpc_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_rpc_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_session.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_session.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_ack_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_ack_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_flag_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_flag_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_seq_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_seq_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_win_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_tcp_win_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ttl_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_ttl_check.h"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_urilen_check.c"
# End Source File
# Begin Source File

SOURCE="..\..\detection-plugins\sp_urilen_check.h"
# End Source File
# End Group
# Begin Group "Output Plugins"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_fast.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_fast.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_full.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_full.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_prelude.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_prelude.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_sf_socket.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_sf_socket.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_syslog.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_syslog.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_unixsock.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_alert_unixsock.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_csv.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_csv.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_database.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_database.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_log_ascii.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_log_ascii.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_log_null.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_log_null.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_log_tcpdump.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_log_tcpdump.h"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_unified.c"
# End Source File
# Begin Source File

SOURCE="..\..\output-plugins\spo_unified.h"
# End Source File
# End Group
# Begin Group "Parser"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\parser\IpAddrSet.c
# End Source File
# Begin Source File

SOURCE=..\..\parser\IpAddrSet.h
# End Source File
# End Group
# Begin Group "Preprocessors"

# PROP Default_Filter ""
# Begin Group "Flow"

# PROP Default_Filter ""
# Begin Group "Int Snort"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\..\preprocessors\flow\int-snort\flow_packet.c"
# End Source File
# Begin Source File

SOURCE="..\..\preprocessors\flow\int-snort\flow_packet.h"
# End Source File
# End Group
# Begin Group "Portscan"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\flowps.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\flowps.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\flowps_snort.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\flowps_snort.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\scoreboard.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\scoreboard.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\server_stats.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\server_stats.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\unique_tracker.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\portscan\unique_tracker.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\preprocessors\flow\common_defs.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_cache.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_cache.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_callback.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_callback.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_class.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_class.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_config.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_error.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_hash.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_hash.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_print.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_print.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_stat.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\flow\flow_stat.h
# End Source File
# End Group
# Begin Group "HttpInspect"

# PROP Default_Filter ""
# Begin Group "Anomaly Detection"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\anomaly_detection\hi_ad.c
# End Source File
# End Group
# Begin Group "Client"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\client\hi_client.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\client\hi_client_norm.c
# End Source File
# End Group
# Begin Group "Event Output"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\event_output\hi_eo_log.c
# End Source File
# End Group
# Begin Group "Include"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_ad.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_client.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_client_norm.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_eo.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_eo_events.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_eo_log.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_include.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_mi.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_norm.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_return_codes.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_server.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_si.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_ui_config.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_ui_iis_unicode_map.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_ui_server_lookup.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_util.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_util_hbm.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_util_kmap.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\include\hi_util_xmalloc.h
# End Source File
# End Group
# Begin Group "Mode Inspection"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\mode_inspection\hi_mi.c
# End Source File
# End Group
# Begin Group "Normalization"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\normalization\hi_norm.c
# End Source File
# End Group
# Begin Group "Server"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\server\hi_server.c
# End Source File
# End Group
# Begin Group "Session Inspection"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\session_inspection\hi_si.c
# End Source File
# End Group
# Begin Group "User Interface"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\user_interface\hi_ui_config.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\user_interface\hi_ui_iis_unicode_map.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\user_interface\hi_ui_server_lookup.c
# End Source File
# End Group
# Begin Group "Utils"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\utils\hi_util_hbm.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\utils\hi_util_kmap.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\HttpInspect\utils\hi_util_xmalloc.c
# End Source File
# End Group
# End Group
# Begin Group "Stream5"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_icmp.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_icmp.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_session.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_session.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_tcp.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_tcp.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_udp.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\snort_stream5_udp.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\stream5_common.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\Stream5\stream5_common.h
# End Source File
# End Group
# Begin Source File

SOURCE="..\..\preprocessors\perf-base.c"
# End Source File
# Begin Source File

SOURCE="..\..\preprocessors\perf-base.h"
# End Source File
# Begin Source File

SOURCE="..\..\preprocessors\perf-event.c"
# End Source File
# Begin Source File

SOURCE="..\..\preprocessors\perf-event.h"
# End Source File
# Begin Source File

SOURCE="..\..\preprocessors\perf-flow.c"
# End Source File
# Begin Source File

SOURCE="..\..\preprocessors\perf-flow.h"
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\perf.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\perf.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\portscan.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\portscan.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\sfprocpidstats.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\sfprocpidstats.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\snort_httpinspect.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\snort_httpinspect.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\snort_stream4_session.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\snort_stream4_session.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_arpspoof.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_arpspoof.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_bo.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_bo.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_flow.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_flow.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_frag2.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_frag2.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_frag3.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_frag3.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_httpinspect.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_httpinspect.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_perfmonitor.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_perfmonitor.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_rpc_decode.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_rpc_decode.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_sfportscan.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_sfportscan.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_stream4.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_stream4.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_stream5.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_stream5.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_telnet_negotiation.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\spp_telnet_negotiation.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\str_search.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\str_search.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\stream.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\stream_api.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\stream_api.h
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\stream_ignore.c
# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\stream_ignore.h
# End Source File
# End Group
# Begin Group "SFUtil"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\sfutil\acsmx.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\acsmx.h

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\sfutil\acsmx2.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\acsmx2.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\asn1.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\asn1.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\bitop.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\bnfa_search.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\bnfa_search.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\getopt.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\getopt1.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\getopt_long.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\ipobj.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\ipobj.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\mpse.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\mpse.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfeventq.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfeventq.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfghash.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfghash.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfhashfcn.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfhashfcn.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfksearch.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfksearch.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sflsq.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sflsq.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfmemcap.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfmemcap.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfsnprintfappend.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfsnprintfappend.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfthd.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfthd.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfxhash.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfxhash.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\util_math.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\util_math.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\util_net.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\util_net.h
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\util_str.c
# End Source File
# Begin Source File

SOURCE=..\..\sfutil\util_str.h
# End Source File
# End Group
# Begin Group "DynamicPlugins"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_common.h"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_detection.h"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_engine.h"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_meta.h"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_plugins.c"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_preprocessor.h"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sp_dynamic.c"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sp_dynamic.h"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sp_preprocopt.c"
# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sp_preprocopt.h"
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\bounds.h
# End Source File
# Begin Source File

SOURCE=..\..\byte_extract.c
# End Source File
# Begin Source File

SOURCE=..\..\byte_extract.h
# End Source File
# Begin Source File

SOURCE=..\..\cdefs.h
# End Source File
# Begin Source File

SOURCE=..\..\checksum.h
# End Source File
# Begin Source File

SOURCE=..\..\codes.c
# End Source File
# Begin Source File

SOURCE=..\..\codes.h
# End Source File
# Begin Source File

SOURCE=..\..\debug.c
# End Source File
# Begin Source File

SOURCE=..\..\debug.h
# End Source File
# Begin Source File

SOURCE=..\..\decode.c
# End Source File
# Begin Source File

SOURCE=..\..\decode.h
# End Source File
# Begin Source File

SOURCE=..\..\detect.c
# End Source File
# Begin Source File

SOURCE=..\..\detect.h
# End Source File
# Begin Source File

SOURCE=..\..\event.h
# End Source File
# Begin Source File

SOURCE=..\..\event_queue.c
# End Source File
# Begin Source File

SOURCE=..\..\event_queue.h
# End Source File
# Begin Source File

SOURCE=..\..\event_wrapper.c
# End Source File
# Begin Source File

SOURCE=..\..\event_wrapper.h
# End Source File
# Begin Source File

SOURCE=..\..\fatal.h
# End Source File
# Begin Source File

SOURCE=..\..\fpcreate.c
# End Source File
# Begin Source File

SOURCE=..\..\fpcreate.h
# End Source File
# Begin Source File

SOURCE=..\..\fpdetect.c
# End Source File
# Begin Source File

SOURCE=..\..\fpdetect.h
# End Source File
# Begin Source File

SOURCE=..\..\generators.h
# End Source File
# Begin Source File

SOURCE=..\..\inline.c
# End Source File
# Begin Source File

SOURCE=..\..\inline.h
# End Source File
# Begin Source File

SOURCE=..\..\ipv6.c
# End Source File
# Begin Source File

SOURCE=..\..\ipv6.h
# End Source File
# Begin Source File

SOURCE=..\..\log.c
# End Source File
# Begin Source File

SOURCE=..\..\log.h
# End Source File
# Begin Source File

SOURCE=..\..\mempool.c
# End Source File
# Begin Source File

SOURCE=..\..\mempool.h
# End Source File
# Begin Source File

SOURCE=..\..\mstring.c
# End Source File
# Begin Source File

SOURCE=..\..\mstring.h
# End Source File
# Begin Source File

SOURCE=..\..\packet_time.c
# End Source File
# Begin Source File

SOURCE=..\..\packet_time.h
# End Source File
# Begin Source File

SOURCE=..\..\parser.c
# End Source File
# Begin Source File

SOURCE=..\..\parser.h
# End Source File
# Begin Source File

SOURCE=..\..\pcrm.c
# End Source File
# Begin Source File

SOURCE=..\..\pcrm.h
# End Source File
# Begin Source File

SOURCE=..\..\plugbase.c
# End Source File
# Begin Source File

SOURCE=..\..\plugbase.h
# End Source File
# Begin Source File

SOURCE=..\..\plugin_enum.h
# End Source File
# Begin Source File

SOURCE=..\..\prototypes.h
# End Source File
# Begin Source File

SOURCE=..\..\rules.h
# End Source File
# Begin Source File

SOURCE=..\..\sf_sdlist.c
# End Source File
# Begin Source File

SOURCE=..\..\sf_sdlist.h
# End Source File
# Begin Source File

SOURCE=..\..\sfthreshold.c
# End Source File
# Begin Source File

SOURCE=..\..\sfthreshold.h
# End Source File
# Begin Source File

SOURCE=..\..\signature.c
# End Source File
# Begin Source File

SOURCE=..\..\signature.h
# End Source File
# Begin Source File

SOURCE=..\..\smalloc.h
# End Source File
# Begin Source File

SOURCE=..\..\snort.c
# End Source File
# Begin Source File

SOURCE=..\..\snort.h
# End Source File
# Begin Source File

SOURCE=..\..\snort_packet_header.h
# End Source File
# Begin Source File

SOURCE=..\..\snprintf.c
# End Source File
# Begin Source File

SOURCE=..\..\snprintf.h
# End Source File
# Begin Source File

SOURCE=..\..\spo_plugbase.h
# End Source File
# Begin Source File

SOURCE=..\..\strlcatu.c
# End Source File
# Begin Source File

SOURCE=..\..\strlcatu.h
# End Source File
# Begin Source File

SOURCE=..\..\strlcpyu.c
# End Source File
# Begin Source File

SOURCE=..\..\strlcpyu.h
# End Source File
# Begin Source File

SOURCE=..\..\sys_include.h
# End Source File
# Begin Source File

SOURCE=..\..\tag.c
# End Source File
# Begin Source File

SOURCE=..\..\tag.h
# End Source File
# Begin Source File

SOURCE=..\..\timersub.h
# End Source File
# Begin Source File

SOURCE=..\..\ubi_BinTree.c
# End Source File
# Begin Source File

SOURCE=..\..\ubi_BinTree.h
# End Source File
# Begin Source File

SOURCE=..\..\ubi_SplayTree.c
# End Source File
# Begin Source File

SOURCE=..\..\ubi_SplayTree.h
# End Source File
# Begin Source File

SOURCE=..\..\util.c
# End Source File
# Begin Source File

SOURCE=..\..\util.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE="..\WIN32-Code\MSG00001.bin"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\name.mc"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.mc"

BuildCmds= \
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc

"..\WIN32-Code\name.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\name.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\MSG00001.BIN" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.mc"

BuildCmds= \
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc

"..\WIN32-Code\name.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\name.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\MSG00001.BIN" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.mc"

BuildCmds= \
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc

"..\WIN32-Code\name.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\name.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\MSG00001.BIN" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.mc"

BuildCmds= \
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc

"..\WIN32-Code\name.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\name.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\MSG00001.BIN" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.mc"

BuildCmds= \
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc

"..\WIN32-Code\name.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\name.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\MSG00001.BIN" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.mc"

BuildCmds= \
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc

"..\WIN32-Code\name.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\name.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\WIN32-Code\MSG00001.BIN" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\name.rc"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

# PROP BASE Exclude_From_Build 1
# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "_DEBUG" ..\WIN32-Code\name.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

# PROP BASE Exclude_From_Build 1
# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "NDEBUG" ..\WIN32-Code\name.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

# PROP BASE Exclude_From_Build 1
# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "_DEBUG" ..\WIN32-Code\name.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

# PROP BASE Exclude_From_Build 1
# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "NDEBUG" ..\WIN32-Code\name.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

# PROP BASE Exclude_From_Build 1
# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "_DEBUG" ..\WIN32-Code\name.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

# PROP BASE Exclude_From_Build 1
# PROP Ignore_Default_Tool 1
# Begin Custom Build
InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "NDEBUG" ..\WIN32-Code\name.rc

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Win32"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\WIN32-Includes\rpc\auth.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\NET\Bpf.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\rpc\clnt.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\config.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\gnuc.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\inet_aton.c"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\misc.c"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\name.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\WinPCAP\pcap.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\pcre.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\pcreposix.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\rpc\rpc_msg.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\stdint.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\strtok_r.c"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\syslog.c"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\syslog.h"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\UNISTD.H"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Code\win32_service.c"
# End Source File
# Begin Source File

SOURCE="..\WIN32-Includes\rpc\xdr.h"
# End Source File
# End Group
# End Target
# End Project
