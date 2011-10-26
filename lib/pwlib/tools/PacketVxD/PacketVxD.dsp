# Microsoft Developer Studio Project File - Name="PacketVxD" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=PacketVxD - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "PacketVxD.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PacketVxD.mak" CFG="PacketVxD - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PacketVxD - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe
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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /Gz /Zp1 /W3 /I "ddk\include" /I "..\..\msos\include" /D "NDIS_STDCALL" /D "CHICAGO" /D "IS_32" /D DEBLEVEL=0 /Zl /FD /bzalign /Gs /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0xc09 /d "NDEBUG"
# ADD RSC /l 0xc09 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 libndis.clb vxdwraps.clb /nologo /pdb:none /machine:I386 /nodefaultlib /out:"../../lib/EPacket.vxd" /libpath:"ddk\lib" -vxd
# Begin Target

# Name "PacketVxD - Win32 Release"
# Begin Source File

SOURCE=.\epacket.c
# End Source File
# Begin Source File

SOURCE=.\epacket.def
# End Source File
# Begin Source File

SOURCE=.\lock.c
# End Source File
# Begin Source File

SOURCE=.\Ndisdev.asm
# Begin Custom Build - Asembling...
IntDir=.\Release
InputPath=.\Ndisdev.asm
InputName=Ndisdev

"$(IntDir)/$(InputName).obj" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	ml -c -coff -W2 -Zd -Cx -Zm -Iddk\include -DIS_32 -DMASM6 -DVMMSYS -DSEGNUM=3         -DBLD_COFF -DDEVICE=EPACKET -DNDIS_STDCALL -DDEBLEVEL=0 -DCHICAGO         -Fo$(IntDir)/$(InputName).obj $(InputPath)

# End Custom Build
# End Source File
# End Target
# End Project
