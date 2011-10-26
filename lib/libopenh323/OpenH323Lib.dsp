# Microsoft Developer Studio Project File - Name="OpenH323Lib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=OPENH323LIB - WIN32 DEBUG
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "OpenH323Lib.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "OpenH323Lib.mak" CFG="OPENH323LIB - WIN32 DEBUG"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "OpenH323Lib - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "OpenH323Lib - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "OpenH323Lib - Win32 No Trace" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 1
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "lib"
# PROP BASE Intermediate_Dir "lib\Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "lib"
# PROP Intermediate_Dir "lib\Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MD /W4 /GR /GX /Zd /O2 /Ob0 /D "NDEBUG" /D "PTRACING" /Yu"ptlib.h" /Fd"lib\OpenH323.pdb" /FD /c
# ADD BASE RSC /l 0xc09
# ADD RSC /l 0xc09
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"lib\OpenH323s.lib"

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "lib"
# PROP BASE Intermediate_Dir "lib\Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "lib"
# PROP Intermediate_Dir "lib\Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MDd /W4 /Gm /GR /GX /Zi /Od /D "_DEBUG" /D "PTRACING" /FR /Yu"ptlib.h" /Fd"lib\OpenH323d.pdb" /FD /c
# ADD BASE RSC /l 0xc09
# ADD RSC /l 0xc09
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"lib\OpenH323sd.lib"

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "lib"
# PROP BASE Intermediate_Dir "lib\NoTrace"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "lib"
# PROP Intermediate_Dir "lib\NoTrace"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W4 /GX /O1 /Ob2 /I "./include" /D "NDEBUG" /D "PTRACING" /Yu"ptlib.h" /FD /c
# ADD CPP /nologo /MD /W4 /GR /GX /O1 /Ob2 /D "NDEBUG" /D "PASN_NOPRINTON" /D "PASN_LEANANDMEAN" /Yu"ptlib.h" /Fd"lib\OpenH323n.pdb" /FD /c
# ADD BASE RSC /l 0xc09
# ADD RSC /l 0xc09
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"lib\OpenH323sn.lib"

!ENDIF 

# Begin Target

# Name "OpenH323Lib - Win32 Release"
# Name "OpenH323Lib - Win32 Debug"
# Name "OpenH323Lib - Win32 No Trace"
# Begin Group "Source Files"

# PROP Default_Filter ".cxx"
# Begin Source File

SOURCE=.\src\channels.cxx
# End Source File
# Begin Source File

SOURCE=.\src\codecs.cxx
# End Source File
# Begin Source File

SOURCE=.\src\ffh263codec.cxx
# End Source File
# Begin Source File

SOURCE=.\src\g711.c

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# ADD CPP /W1
# SUBTRACT CPP /D "PTRACING" /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

# ADD CPP /W1
# SUBTRACT CPP /D "PTRACING" /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

# ADD CPP /W1
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\gkclient.cxx
# End Source File
# Begin Source File

SOURCE=.\src\gkserver.cxx
# End Source File
# Begin Source File

SOURCE=.\src\guid.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h225ras.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h235auth.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h235auth1.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h261codec.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h263codec.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323annexg.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323caps.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323ep.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323neg.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323pdu.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323pluginmgr.cxx

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# ADD CPP /Ob0

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\h323rtp.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323t120.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323t38.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h323trans.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h450pdu.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h4601.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h501pdu.cxx
# End Source File
# Begin Source File

SOURCE=.\src\hid.cxx
# End Source File
# Begin Source File

SOURCE=.\src\ixjwin32.cxx
# End Source File
# Begin Source File

SOURCE=.\src\jitter.cxx
# End Source File
# Begin Source File

SOURCE=.\src\lid.cxx
# End Source File
# Begin Source File

SOURCE=.\src\mediafmt.cxx

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# ADD CPP /Ob0

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\opalosp.cxx
# End Source File
# Begin Source File

SOURCE=.\src\OpalUSBDevice.cxx
# End Source File
# Begin Source File

SOURCE=.\src\opalvxml.cxx
# End Source File
# Begin Source File

SOURCE=.\src\opalwavfile.cxx
# End Source File
# Begin Source File

SOURCE=.\src\peclient.cxx
# End Source File
# Begin Source File

SOURCE=.\src\precompile.cxx
# ADD CPP /Yc"ptlib.h"
# End Source File
# Begin Source File

SOURCE=.\src\q931.cxx
# End Source File
# Begin Source File

SOURCE=.\src\rfc2190avcodec.cxx
# End Source File
# Begin Source File

SOURCE=.\src\rfc2833.cxx
# End Source File
# Begin Source File

SOURCE=.\src\rtp.cxx
# End Source File
# Begin Source File

SOURCE=.\src\rtp2wav.cxx
# End Source File
# Begin Source File

SOURCE=.\src\svcctrl.cxx
# End Source File
# Begin Source File

SOURCE=.\src\t120proto.cxx
# End Source File
# Begin Source File

SOURCE=.\src\t38proto.cxx
# End Source File
# Begin Source File

SOURCE=.\src\transports.cxx
# End Source File
# Begin Source File

SOURCE=.\src\vblasterlid.cxx
# End Source File
# Begin Source File

SOURCE=.\src\vpblid.cxx
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\x224.cxx
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ".h"
# Begin Source File

SOURCE=.\include\channels.h
# End Source File
# Begin Source File

SOURCE=.\include\codecs.h
# End Source File
# Begin Source File

SOURCE=.\include\ffh263codec.h
# End Source File
# Begin Source File

SOURCE=.\include\gkclient.h
# End Source File
# Begin Source File

SOURCE=.\include\gkserver.h
# End Source File
# Begin Source File

SOURCE=.\include\guid.h
# End Source File
# Begin Source File

SOURCE=.\include\h225ras.h
# End Source File
# Begin Source File

SOURCE=.\include\h235auth.h
# End Source File
# Begin Source File

SOURCE=.\include\h261codec.h
# End Source File
# Begin Source File

SOURCE=.\include\h263codec.h
# End Source File
# Begin Source File

SOURCE=.\include\h323.h
# End Source File
# Begin Source File

SOURCE=.\include\h323annexg.h
# End Source File
# Begin Source File

SOURCE=.\include\h323caps.h
# End Source File
# Begin Source File

SOURCE=.\include\h323con.h
# End Source File
# Begin Source File

SOURCE=.\include\h323ep.h
# End Source File
# Begin Source File

SOURCE=.\include\h323neg.h
# End Source File
# Begin Source File

SOURCE=.\include\h323pdu.h
# End Source File
# Begin Source File

SOURCE=.\include\h323pluginmgr.h
# End Source File
# Begin Source File

SOURCE=.\include\h323rtp.h
# End Source File
# Begin Source File

SOURCE=.\include\h323t120.h
# End Source File
# Begin Source File

SOURCE=.\include\h323t38.h
# End Source File
# Begin Source File

SOURCE=.\include\h323trans.h
# End Source File
# Begin Source File

SOURCE=.\include\h450pdu.h
# End Source File
# Begin Source File

SOURCE=.\include\h4601.h
# End Source File
# Begin Source File

SOURCE=.\include\hid.h
# End Source File
# Begin Source File

SOURCE=.\include\ixjlid.h
# End Source File
# Begin Source File

SOURCE=.\include\jitter.h
# End Source File
# Begin Source File

SOURCE=.\include\lid.h
# End Source File
# Begin Source File

SOURCE=.\include\mediafmt.h
# End Source File
# Begin Source File

SOURCE=.\include\OpalUSBDevice.h
# End Source File
# Begin Source File

SOURCE=.\include\opalvxml.h
# End Source File
# Begin Source File

SOURCE=.\include\opalwavfile.h
# End Source File
# Begin Source File

SOURCE=.\include\peclient.h
# End Source File
# Begin Source File

SOURCE=.\include\q931.h
# End Source File
# Begin Source File

SOURCE=.\include\rfc2190avcodec.h
# End Source File
# Begin Source File

SOURCE=.\include\rfc2833.h
# End Source File
# Begin Source File

SOURCE=.\include\rtp.h
# End Source File
# Begin Source File

SOURCE=.\include\rtp2wav.h
# End Source File
# Begin Source File

SOURCE=.\include\svcctrl.h
# End Source File
# Begin Source File

SOURCE=.\include\t120proto.h
# End Source File
# Begin Source File

SOURCE=.\include\t38.h
# End Source File
# Begin Source File

SOURCE=.\include\t38proto.h
# End Source File
# Begin Source File

SOURCE=.\include\transports.h
# End Source File
# Begin Source File

SOURCE=.\include\vblasterlid.h
# End Source File
# Begin Source File

SOURCE=.\include\vpblid.h
# End Source File
# Begin Source File

SOURCE=.\include\x224.h
# End Source File
# End Group
# Begin Group "ASN Files"

# PROP Default_Filter ".asn"
# Begin Source File

SOURCE=.\src\gccpdu.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\gccpdu.cxx
# End Source File
# Begin Source File

SOURCE=.\include\gccpdu.h
# End Source File
# Begin Source File

SOURCE=.\src\h225.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\include\h225.h
# End Source File
# Begin Source File

SOURCE=.\src\h225_1.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h225_2.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h235.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h235.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h235.h
# End Source File
# Begin Source File

SOURCE=.\src\h245.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\include\h245.h
# End Source File
# Begin Source File

SOURCE=.\src\h245_1.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h245_2.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h245_3.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h248.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h248.cxx
# End Source File
# Begin Source File

SOURCE=.\src\h248.h
# End Source File
# Begin Source File

SOURCE=.\src\h4501.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4501.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4501.h
# End Source File
# Begin Source File

SOURCE=.\src\h45010.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h45010.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h45010.h
# End Source File
# Begin Source File

SOURCE=.\src\h45011.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h45011.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h45011.h
# End Source File
# Begin Source File

SOURCE=.\src\h4502.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4502.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4502.h
# End Source File
# Begin Source File

SOURCE=.\src\h4503.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4503.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4503.h
# End Source File
# Begin Source File

SOURCE=.\src\h4504.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4504.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4504.h
# End Source File
# Begin Source File

SOURCE=.\src\h4505.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4505.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4505.h
# End Source File
# Begin Source File

SOURCE=.\src\h4506.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4506.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4506.h
# End Source File
# Begin Source File

SOURCE=.\src\h4507.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4507.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4507.h
# End Source File
# Begin Source File

SOURCE=.\src\h4508.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4508.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4508.h
# End Source File
# Begin Source File

SOURCE=.\src\h4509.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h4509.cxx
# End Source File
# Begin Source File

SOURCE=.\include\h4509.h
# End Source File
# Begin Source File

SOURCE=.\src\h501.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\h501.cxx
# End Source File
# Begin Source File

SOURCE=.\src\mcspdu.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\mcspdu.cxx
# End Source File
# Begin Source File

SOURCE=.\include\mcspdu.h
# End Source File
# Begin Source File

SOURCE=.\src\t38.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\t38.cxx
# End Source File
# Begin Source File

SOURCE=.\src\x880.asn
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\src\x880.cxx
# End Source File
# Begin Source File

SOURCE=.\include\x880.h
# End Source File
# End Group
# Begin Group "VIC Files"

# PROP Default_Filter ""
# Begin Group "C Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\vic\bv.c

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# ADD CPP /w /W0 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

# ADD CPP /w /W0 /D "WIN32"
# SUBTRACT CPP /D "PTRACING" /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

# ADD CPP /w /W0 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\vic\huffcode.c

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# ADD CPP /w /W0 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

# ADD CPP /w /W0 /D "WIN32"
# SUBTRACT CPP /D "PTRACING" /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

# ADD CPP /w /W0 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# End Group
# Begin Group "CXX Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\src\vic\dct.cxx

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# ADD CPP /W1 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

# ADD CPP /W1 /D "WIN32"
# SUBTRACT CPP /D "PTRACING" /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

# ADD CPP /W1 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=".\src\vic\encoder-h261.cxx"
# ADD CPP /W1
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=.\src\vic\p64.cxx

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

# ADD CPP /W1 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

# ADD CPP /W1 /D "WIN32"
# SUBTRACT CPP /D "PTRACING" /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

# ADD CPP /W1 /D "WIN32"
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\vic\p64encoder.cxx
# ADD CPP /W1
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=.\src\vic\transmitter.cxx
# ADD CPP /W1
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=.\src\vic\vid_coder.cxx
# ADD CPP /W1
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# End Group
# Begin Group "H Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\src\vic\bsd-endian.h"
# End Source File
# Begin Source File

SOURCE=.\src\vic\config.h
# End Source File
# Begin Source File

SOURCE=.\src\vic\dct.h
# End Source File
# Begin Source File

SOURCE=".\src\vic\encoder-h261.h"
# End Source File
# Begin Source File

SOURCE=.\src\vic\grabber.h
# End Source File
# Begin Source File

SOURCE=".\src\vic\p64-huff.h"
# End Source File
# Begin Source File

SOURCE=.\src\vic\p64.h
# End Source File
# Begin Source File

SOURCE=.\src\vic\p64encoder.h
# End Source File
# Begin Source File

SOURCE=.\src\vic\transmitter.h
# End Source File
# Begin Source File

SOURCE=.\src\vic\vid_coder.h
# End Source File
# End Group
# End Group
# Begin Source File

SOURCE=.\include\openh323buildopts.h
# End Source File
# Begin Source File

SOURCE=.\include\openh323buildopts.h.in

!IF  "$(CFG)" == "OpenH323Lib - Win32 Release"

USERDEP__OPENH="configure.in"	
# Begin Custom Build - Configuring Build Options
InputPath=.\include\openh323buildopts.h.in

".\include\openh323buildopts.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\configure --exclude-env=MSVC_PWLIB_CONFIGURE_EXCLUDE_DIRS

# End Custom Build

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 Debug"

USERDEP__OPENH="configure.ac"	
# Begin Custom Build - Configuring Build Options
InputPath=.\include\openh323buildopts.h.in

".\include\openh323buildopts.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\configure --exclude-env=MSVC_PWLIB_CONFIGURE_EXCLUDE_DIRS

# End Custom Build

!ELSEIF  "$(CFG)" == "OpenH323Lib - Win32 No Trace"

USERDEP__OPENH="configure.in"	
# Begin Custom Build - Configuring Build Options
InputPath=.\include\openh323buildopts.h.in

".\include\openh323buildopts.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\configure --exclude-env=MSVC_PWLIB_CONFIGURE_EXCLUDE_DIRS

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
