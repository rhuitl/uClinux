# Microsoft Developer Studio Project File - Name="osipparser2" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=osipparser2 - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "osipparser2.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "osipparser2.mak" CFG="osipparser2 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "osipparser2 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "osipparser2 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "osipparser2 - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIPPARSER2_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\..\include" /I "..\..\src\osipparser2" /D "NDEBUG" /D "SYSTEM_LOGGER_ENABLED" /D "OSIPPARSER2_EXPORTS" /D "AC_BUG" /D "ENABLE_TRACE" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIP_MT" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 msvcrt.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /nodefaultlib /libpath:".libs"

!ELSEIF  "$(CFG)" == "osipparser2 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "osipparser2___Win32_Debug"
# PROP BASE Intermediate_Dir "osipparser2___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".libs"
# PROP Intermediate_Dir "osipparser2___Win32_Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIPPARSER2_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "..\..\include" /I "..\..\src\osipparser2" /D "_DEBUG" /D "ENABLE_DEBUG" /D "SYSTEM_LOGGER_ENABLED" /D "OSIPPARSER2_EXPORTS" /D "AC_BUG" /D "ENABLE_TRACE" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OSIP_MT" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 msvcrtd.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /nodefaultlib /pdbtype:sept

!ENDIF 

# Begin Target

# Name "osipparser2 - Win32 Release"
# Name "osipparser2 - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_accept.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_accept_encoding.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_accept_language.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_authentication_info.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_proxy_authentication_info.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_alert_info.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_allow.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_authorization.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_body.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_call_id.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_call_info.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_contact.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_content_disposition.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_content_encoding.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_content_length.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_content_type.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_cseq.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_error_info.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_from.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_header.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_list.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_md5c.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_message.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_message_parse.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_message_to_str.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_mime_version.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_parser_cfg.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_port.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_proxy_authenticate.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_proxy_authorization.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_record_route.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_rfc3264.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_route.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_to.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_uri.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_via.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\osip_www_authenticate.c
# End Source File
# Begin Source File

SOURCE=.\osipparser2.def
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\sdp_accessor.c
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\sdp_message.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_accept.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_accept_encoding.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_accept_language.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_alert_info.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_allow.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_authorization.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_body.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_call_id.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_call_info.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_const.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_contact.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_content_disposition.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_content_encoding.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_content_length.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_content_type.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_cseq.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_error_info.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_from.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_header.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_headers.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_list.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_md5.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_message.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_mime_version.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_parser.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_port.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_proxy_authenticate.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_proxy_authorization.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_record_route.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_rfc3264.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_route.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_to.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\osip_uri.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_via.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\headers\osip_www_authenticate.h
# End Source File
# Begin Source File

SOURCE=..\..\src\osipparser2\parser.h
# End Source File
# Begin Source File

SOURCE=..\..\include\osipparser2\sdp_message.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
