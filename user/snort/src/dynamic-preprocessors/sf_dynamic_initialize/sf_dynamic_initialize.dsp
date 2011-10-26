# Microsoft Developer Studio Project File - Name="sf_dynamic_initialize" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Generic Project" 0x010a

CFG=sf_dynamic_initialize - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sf_dynamic_initialize.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sf_dynamic_initialize.mak" CFG="sf_dynamic_initialize - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sf_dynamic_initialize - Win32 Release" (based on "Win32 (x86) Generic Project")
!MESSAGE "sf_dynamic_initialize - Win32 Debug" (based on "Win32 (x86) Generic Project")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
MTL=midl.exe

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "sf_dynamic_initialize - Win32 Release"
# Name "sf_dynamic_initialize - Win32 Debug"
# Begin Source File

SOURCE=..\..\sfutil\bitop.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\sfutil\bitop.h
InputName=bitop

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\sfutil\bitop.h
InputName=bitop

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\debug.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\debug.h
InputName=debug

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\debug.h
InputName=debug

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\preprocids.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\preprocids.h
InputName=preprocids

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\preprocids.h
InputName=preprocids

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\profiler.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\profiler.h
InputName=profiler

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\profiler.h
InputName=profiler

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_common.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_common.h"
InputName=sf_dynamic_common

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_common.h"
InputName=sf_dynamic_common

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_engine.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_engine.h"
InputName=sf_dynamic_engine

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_engine.h"
InputName=sf_dynamic_engine

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_meta.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_meta.h"
InputName=sf_dynamic_meta

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_meta.h"
InputName=sf_dynamic_meta

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_preproc_example\sf_dynamic_preproc_lib.c"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_preproc_example\sf_dynamic_preproc_lib.c"
InputName=sf_dynamic_preproc_lib

"..\include\$(InputName).c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_preproc_example\sf_dynamic_preproc_lib.c"
InputName=sf_dynamic_preproc_lib

"..\include\$(InputName).c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_preproc_example\sf_dynamic_preproc_lib.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_preproc_example\sf_dynamic_preproc_lib.h"
InputName=sf_dynamic_preproc_lib

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_preproc_example\sf_dynamic_preproc_lib.h"
InputName=sf_dynamic_preproc_lib

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_dynamic_preprocessor.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_preprocessor.h"
InputName=sf_dynamic_preprocessor

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_dynamic_preprocessor.h"
InputName=sf_dynamic_preprocessor

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_engine\sf_snort_packet.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\sf_snort_packet.h"
InputName=sf_snort_packet

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\sf_snort_packet.h"
InputName=sf_snort_packet

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_engine\sf_snort_plugin_api.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\sf_snort_plugin_api.h"
InputName=sf_snort_plugin_api

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\sf_snort_plugin_api.h"
InputName=sf_snort_plugin_api

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfhashfcn.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\sfutil\sfhashfcn.h
InputName=sfhashfcn

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\sfutil\sfhashfcn.h
InputName=sfhashfcn

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_engine\examples\sfsnort_dynamic_detection_lib.c"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\examples\sfsnort_dynamic_detection_lib.c"
InputName=sfsnort_dynamic_detection_lib

"..\include\$(InputName).c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\examples\sfsnort_dynamic_detection_lib.c"
InputName=sfsnort_dynamic_detection_lib

"..\include\$(InputName).c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\..\dynamic-plugins\sf_engine\examples\sfsnort_dynamic_detection_lib.h"

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\examples\sfsnort_dynamic_detection_lib.h"
InputName=sfsnort_dynamic_detection_lib

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath="..\..\dynamic-plugins\sf_engine\examples\sfsnort_dynamic_detection_lib.h"
InputName=sfsnort_dynamic_detection_lib

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\sfutil\sfxhash.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\sfutil\sfxhash.h
InputName=sfxhash

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\sfutil\sfxhash.h
InputName=sfxhash

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir ..\include 
	copy $(InputPath) ..\include 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\str_search.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\preprocessors\str_search.h
InputName=str_search

BuildCmds= \
	mkdir ..\include \
	copy $(InputPath) ..\include\$(InputName).h.new \
	c:\cygwin\bin\sed -e "s/Packet /SFSnortPacket /" ..\include\$(InputName).h.new > ..\include\$(InputName).h \
	

"..\include\$(InputName).h.new" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\preprocessors\str_search.h
InputName=str_search

BuildCmds= \
	mkdir ..\include \
	copy $(InputPath) ..\include\$(InputName).h.new \
	c:\cygwin\bin\sed -e "s/Packet /SFSnortPacket /" ..\include\$(InputName).h.new > ..\include\$(InputName).h \
	

"..\include\$(InputName).h.new" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\preprocessors\stream_api.h

!IF  "$(CFG)" == "sf_dynamic_initialize - Win32 Release"

# Begin Custom Build
InputPath=..\..\preprocessors\stream_api.h
InputName=stream_api

BuildCmds= \
	mkdir ..\include \
	copy $(InputPath) ..\include\$(InputName).h.new \
	c:\cygwin\bin\sed -e "s/Packet /SFSnortPacket /" ..\include\$(InputName).h.new > ..\include\$(InputName).h \
	

"..\include\$(InputName).h.new" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sf_dynamic_initialize - Win32 Debug"

# Begin Custom Build
InputPath=..\..\preprocessors\stream_api.h
InputName=stream_api

BuildCmds= \
	mkdir ..\include \
	copy $(InputPath) ..\include\$(InputName).h.new \
	c:\cygwin\bin\sed -e "s/Packet /SFSnortPacket /" ..\include\$(InputName).h.new > ..\include\$(InputName).h \
	

"..\include\$(InputName).h.new" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\include\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
