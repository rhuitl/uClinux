#
# $Id: makefile,v 1.11 2004/06/18 16:19:37 andrew_belov Exp $
# ----------------------------------------------------------------------------
# This file  is  intended  for building  ARJ on/for platforms where  the NMAKE
# syntax is  supported. If you are  using a GCC/EMX build, refer to scripts in
# the "gnu" directory.
#
# It's essential that the following versions of NMAKE are used:
#
#             DOS            Microsoft NMAKE v 1.36 or higher
#             OS/2, WinNT    Microsoft NMAKE/2 v 1.21 or NMAKE/Win32 v 1.40+
#
# Parameters:
#             NP_SFX         disables executable packing
#             COMMERCIAL     produces commercial package (where available)
#             DEBUG          includes debug information and extra data
#
#             FORCE_MSGRAPH  with Microsoft C for DOS, enables GRAPHICS.LIB
#             LIBC           in 32-bit OS/2, enables LIBCS.LIB, req. LIBCPATH
#                            (e.g. LIBC=1 LIBCPATH=E:\OS2TK45\H\LIBC)
#                            with Visual C++, enables MSVCRT.LIB (/MD)
#             USE_COLORS     enable colored output
#
# IMPORTANT: Due to DOS path size limitations, the subdirectory names must be
#            as short as possible.
#

!ifndef MODE
MODE = OS232
!endif

!ifndef LOCALE
LOCALE = en
!endif

!ifndef RESFILE
RESFILE = resource\resource.txt
!endif

!ifndef C_DEFS
C_DEFS = $(BASEDIR_T)c_defs.h
!endif

!ifndef ASM_DEFS
ASM_DEFS = $(BASEDIR_T)asm_defs.inc
!endif

!ifdef COMMERCIAL
PACKAGE = c
!else
PACKAGE = s
!endif

!ifdef DEBUG
DEBUG_SM = d
!else
DEBUG_SM = r
!endif

##
## DOS realmode section
##
!if "$(MODE)" == "DOS16"
OS_ID = DOS
LZEXE = lzexe.exe
CRP_OBJS_E = $(BASEDIR)\arjcrypt\det_x86.obj $(BASEDIR)\arjcrypt\gost_asm.obj
ARJ_OBJS_E = $(BASEDIR)\arj\arj_xms.obj
!ifndef COMPILER
COMPILER = MSC7
!endif
#
# Assembly language options are the same - we'll use MASM everywhere
#
ASM = ml.exe
ASMOPT = /I$(BASEDIR) /c /Fo$@ %s
STD_ASMOPT = /DMODL=MEDIUM /DARJUTIL $(ASMOPT)
STB_ASMOPT = /DMODL=SMALL /DSFXSTUB $(ASMOPT)
!if "$(COMPILER)" == "BC40"
SFV_ASMOPT = /DMODL=MEDIUM /DARJSFX $(ASMOPT)
!else
SFV_ASMOPT = /DMODL=SMALL /DARJSFX $(ASMOPT)
!endif
SFX_ASMOPT = /DMODL=SMALL /DARJSFX /DNO_FAR $(ASMOPT)
SFJ_ASMOPT = /DMODL=SMALL /DARJSFXJR /DNO_FAR $(ASMOPT)
REJ_ASMOPT = /DMODL=SMALL /DREARJ /DNO_FAR $(ASMOPT)
REG_ASMOPT = /DMODL=SMALL /DREGISTER /DNO_FAR $(ASMOPT)
ADI_ASMOPT = /DMODL=SMALL /DARJDISP /DNO_FAR $(ASMOPT)
CRP_ASMOPT = /DMODL=SMALL $(ASMOPT)
#
# Borland C compilers section
#
!if "$(COMPILER)" == "TC10"
CC_CODE = $(COMPILER)
CC = tcc.exe
COPT = -I$(BASEDIR) -o$@ @settings\$(CC_CODE).sts %s
LINKER = tlink.exe
LINKLIB = E:\LANG\TCC10\LIB^\
LINKOPT =
!else if "$(COMPILER)" == "BC31"
CC_CODE = $(COMPILER)
CC = bcc.exe
LINKER = tlink.exe
COPT = -I$(BASEDIR) -o$@ @settings\$(CC_CODE).sts %s
LINKLIB =
LINKOPT =
!else if "$(COMPILER)" == "BC40"
CC_CODE = $(COMPILER)
CC = bcc.exe
LINKER = tlink.exe
COPT = -I$(BASEDIR) -o$@ @settings\$(CC_CODE).sts %s
LINKLIB =
LINKOPT =
!endif
!if "$(COMPILER)" == "TC10"||"$(COMPILER)" == "BC31"||"$(COMPILER)" == "BC40"
# Executables
ARJ = arj.exe
ARJSFXV = arjsfxv.exe
ARJSFX = arjsfx.exe
ARJSFXJR = arjsfxjr.exe
ARJCRYPT = arjcrypt.com
REARJ = rearj.exe
REGISTER = register.exe
ARJDISP = arjdisp.exe
POSTPROC = postproc.exe
JOIN = join.exe
MSGBIND = msgbind.exe
TODAY = today.exe
MAKE_KEY = make_key.exe
PACKAGER = packager.exe
MAKESTUB = makestub.exe
SFXSTUB = sfxstub.exe
# C options
STD_COPT = -mm -DARJUTIL $(COPT)
ARJ_COPT = -mm -DSFL=4 $(COPT)
!if "$(COMPILER)" == "BC40"
SFV_COPT = -mm -DSFL=3 $(COPT)
REJ_COPT = -mm -DREARJ $(COPT)
!else
SFV_COPT = -ms -DSFL=3 $(COPT)
REJ_COPT = -ms -DREARJ $(COPT)
!endif
SFX_COPT = -ms -DSFL=2 $(COPT)
SFJ_COPT = -ms -DSFL=1 $(COPT)
REG_COPT = -ms -DREGISTER $(COPT)
ADI_COPT = -ms -DARJDISP $(COPT)
FAR_COPT = -zRA -zSA -zTFAR_DATA $(ARJ_COPT)
FDS_COPT = -zRF -zSF -zTFAR_DATA $(ARJ_COPT)
NEAR_COPT = -zC_TEXT $(ARJ_COPT)
CRP_COPT = -mt $(COPT)
# Linkup objects
STD_OBJ = $(LINKLIB)c0m
ARJ_OBJ = $(LINKLIB)c0m
STB_OBJ =
!if "$(COMPILER)" == "BC40"
SFV_OBJ = $(LINKLIB)c0m
REJ_OBJ = $(LINKLIB)c0m
!else
SFV_OBJ = $(LINKLIB)c0s
REJ_OBJ = $(LINKLIB)c0s
!endif
SFX_OBJ = $(LINKLIB)c0s
SFJ_OBJ = $(LINKLIB)c0s
REG_OBJ = $(LINKLIB)c0s
ADI_OBJ = $(LINKLIB)c0s
CRP_OBJ = /t $(LINKLIB)c0t
# Supplemental objects
ARJ_OBJS_S = $(BASEDIR)\arj\fmemcmp.obj
# Libraries
STD_LIB = $(LINKLIB)cm
ARJ_LIB = $(LINKLIB)cm
STB_LIB =
!if "$(COMPILER)" == "BC40"
SFV_LIB = $(LINKLIB)cm
REJ_LIB = $(LINKLIB)cm
!else
SFV_LIB = $(LINKLIB)cs
REJ_LIB = $(LINKLIB)cs
!endif
SFX_LIB = $(LINKLIB)cs
SFJ_LIB = $(LINKLIB)cs
REG_LIB = $(LINKLIB)cs
ADI_LIB = $(LINKLIB)cs
CRP_LIB = $(LINKLIB)cs
!endif
LRF = echo > NUL
#
# Microsoft C compilers section
#
!if "$(COMPILER)" == "MSC6"
CC_CODE = $(COMPILER)
CC = cl.exe
COPT = /I$(BASEDIR) /Fo$@ %s
NEARPOPT =
LINKER = link.exe
LINKLIB =
LINKOPT = /NOE
!else if "$(COMPILER)" == "MSC7"||"$(COMPILER)" == "MSVC10"||"$(COMPILER)" == "MSVC15"
CC_CODE = $(COMPILER)
CC = cl.exe
LINKER = link.exe
COPT = /I$(BASEDIR) /Fo$@ @settings\$(CC_CODE).sts %s
NEARPOPT = /Gx
LINKLIB =
LINKOPT = /NOE
!else if "$(COMPILER)" == "QC25"
CC_CODE = $(COMPILER)
!if "$(COMPILER)" == "QC25"
CC = _qcl.exe
LINKER = qlink.exe
!else
CC = cl.exe
LINKER = link.exe
!endif
COPT = /I$(BASEDIR) /I. /Fo$@ /Gs /Zp /c %s
MSC_OPT = /Olrg
LINKLIB =
LINKOPT = /NOE
!endif
!if "$(COMPILER)" == "MSC6"||"$(COMPILER)" == "MSC7"||"$(COMPILER)" == "MSVC10"||"$(COMPILER)" == "MSVC15"||"$(COMPILER)" == "QC25"
# Executables
ARJ = arj.exe
ARJSFXV = arjsfxv.exe
ARJSFX = arjsfx.exe
ARJSFXJR = arjsfxjr.exe
ARJCRYPT = arjcrypt.com
REARJ = rearj.exe
REGISTER = register.exe
ARJDISP = arjdisp.exe
POSTPROC = postproc.exe
JOIN = join.exe
MSGBIND = msgbind.exe
TODAY = today.exe
MAKE_KEY = make_key.exe
PACKAGER = packager.exe
MAKESTUB = makestub.exe
SFXSTUB = sfxstub.exe
# C options
!if "$(COMPILER)" == "QC25"||"$(FORCE_MSGRAPH)" != ""
MEM_MARGINAL = /AM
!else
MEM_MARGINAL = /AS
!endif
STD_COPT = $(MSC_OPT) /AM /DARJUTIL $(COPT)
ARJ_COPT = $(MSC_OPT) /AM /DSFL=4 $(COPT)
SFV_COPT = $(MSC_OPT) $(MEM_MARGINAL) /DSFL=3 $(COPT)
SFX_COPT = $(MSC_OPT) /AS /DSFL=2 $(COPT)
SFJ_COPT = $(MSC_OPT) /AS /DSFL=1 $(COPT)
REJ_COPT = $(MSC_OPT) $(MEM_MARGINAL) /DREARJ $(COPT)
REG_COPT = $(MSC_OPT) /AS /DREGISTER $(COPT)
ADI_COPT = $(MSC_OPT) /AS /DARJDISP $(COPT)
FAR_COPT = /NDARJ_MSG $(NEARP_OPT) $(ARJ_COPT)
FDS_COPT = /NDFARD_SEG $(ARJ_COPT)
NEAR_COPT = /NT_TEXT $(ARJ_COPT)
CRP_COPT = /Ot /AT $(COPT)
# Linkup objects
STD_OBJ = /STACK:8192
ARJ_OBJ = /STACK:6144 $(LINKLIB)VARSTCK
STB_OBJ =
SFV_OBJ = /STACK:8192 $(LINKLIB)VARSTCK
SFX_OBJ = /STACK:4096 $(LINKLIB)VARSTCK
SFJ_OBJ = /STACK:2048 $(LINKLIB)VARSTCK
REJ_OBJ = /STACK:8192 $(LINKLIB)VARSTCK
REG_OBJ =
ADI_OBJ =
CRP_OBJ = /TINY $(LINKLIB)CRTCOM.LIB
# Supplemental objects
# Libraries
STD_LIB = $(LINKLIB)
!ifdef FORCE_MSGRAPH
ARJ_LIB = $(LINKLIB)+$(LINKLIB)graphics
SFV_LIB = $(LINKLIB)+$(LINKLIB)graphics
ADI_LIB = $(LINKLIB)+$(LINKLIB)graphics
REJ_LIB = $(LINKLIB)+$(LINKLIB)graphics
!else
ARJ_LIB = $(LINKLIB)
SFV_LIB = $(LINKLIB)
ADI_LIB = $(LINKLIB)
REJ_LIB = $(LINKLIB)
!endif
STB_LIB =
SFX_LIB = $(LINKLIB)
SFJ_LIB = $(LINKLIB)
REG_LIB = $(LINKLIB)
CRP_LIB = $(LINKLIB)
!endif
LRF = echo > NUL
!endif
##
## OS/2 protected mode section
##
!if "$(MODE)" == "OS216"
OS_ID = OS2
!ifndef COMPILER
COMPILER = MSC6
!endif
#
# Assembly language options are the same - we'll use MASM everywhere
#
ASM = ml.exe
ASMOPT = /I$(BASEDIR) /c /Fo$@ %s
STD_ASMOPT = /DMODL=MEDIUM /DARJUTIL $(ASMOPT)
STB_ASMOPT = /DMODL=SMALL /DSFXSTUB $(ASMOPT)
SFV_ASMOPT = /DMODL=SMALL /DARJSFX $(ASMOPT)
SFX_ASMOPT = /DMODL=SMALL /DARJSFX /DNO_FAR $(ASMOPT)
SFJ_ASMOPT = /DMODL=SMALL /DARJSFXJR /DNO_FAR $(ASMOPT)
REJ_ASMOPT = /DMODL=SMALL /DREARJ /DNO_FAR $(ASMOPT)
REG_ASMOPT = /DMODL=SMALL /DREGISTER /DNO_FAR $(ASMOPT)
ADI_ASMOPT = /DMODL=SMALL /DARJDISP /DNO_FAR $(ASMOPT)
CRP_ASMOPT = /DMODL=SMALL $(ASMOPT)
#
# Microsoft C v 6.0 compiler
#
!if "$(COMPILER)" == "MSC6"
CC_CODE = $(COMPILER)_OS2
CC = cl.exe
!ifdef DEBUG
MSCDBG = /Zd
MSLINKDBG = /CODEVIEW /MAP:full
MAKESYM = 1
!endif
COPT = /I$(BASEDIR) /I. /Fo$@ $(MSCDBG) %s
NEARPOPT =
LINKER = link.exe
LINKLIB =
LINKOPT = /NOE /PMTYPE:VIO
# Executables
ARJ = arj.exe
ARJSFXV = arjsfxv.exe
ARJSFX = arjsfx.exe
ARJSFXJR = arjsfxjr.exe
ARJCRYPT = arjcrypt.dll
REARJ = rearj.exe
REGISTER = register.exe
ARJDISP = arjdisp.exe
POSTPROC = postproc.exe
JOIN = join.exe
MSGBIND = msgbind.exe
TODAY = today.exe
MAKE_KEY = make_key.exe
PACKAGER = packager.exe
MAKESTUB = makestub.exe
SFXSTUB = sfxstub.exe
# C options
STD_COPT = /Olrg /AM /DARJUTIL $(COPT)
ARJ_COPT = /Olrg /AM /DSFL=4 $(COPT)
SFV_COPT = /Olrg /AS /DSFL=3 $(COPT)
SFX_COPT = /Olrg /AS /DSFL=2 $(COPT)
SFJ_COPT = /Olrg /AS /DSFL=1 $(COPT)
REJ_COPT = /Olrg /AS /DREARJ $(COPT)
REG_COPT = /Olrg /AS /DREGISTER $(COPT)
ADI_COPT = /Olrg /AS /DARJDISP $(COPT)
FAR_COPT = /Olrg /NDARJ_MSG $(NEARP_OPT) $(ARJ_COPT)
FDS_COPT = /NDFARD_SEG $(ARJ_COPT)
NEAR_COPT = /NT_TEXT $(ARJ_COPT)
CRP_COPT = /Ot /ALw /Zl $(COPT)
# Linkup objects
STD_OBJ = $(MSLINKDBG) /STACK:8192
ARJ_OBJ = $(MSLINKDBG) /STACK:6144 $(LINKLIB)VARSTCK
STB_OBJ = $(MSLINKDBG)
SFV_OBJ = $(MSLINKDBG) /EXEPACK /STACK:6144 $(LINKLIB)VARSTCK
SFX_OBJ = $(MSLINKDBG) /EXEPACK /STACK:6144 $(LINKLIB)VARSTCK
SFJ_OBJ = $(MSLINKDBG) /EXEPACK /STACK:2048 $(LINKLIB)VARSTCK
REJ_OBJ = $(MSLINKDBG) /STACK:10240 $(LINKLIB)VARSTCK
REG_OBJ = $(MSLINKDBG)
ADI_OBJ = $(MSLINKDBG) /EXEPACK $(APILMR)
CRP_OBJ = $(MSLINKDBG) /STACK:2048
# Supplemental objects
# Libraries
STD_LIB = $(LINKLIB)OS2+$(LINKLIB)MLIBCEP
ARJ_LIB = $(LINKLIB)OS2+$(LINKLIB)MLIBEEP
STB_LIB = $(LINKLIB)OS2
SFV_LIB = $(LINKLIB)OS2+$(LINKLIB)SLIBEEP
SFX_LIB = $(LINKLIB)OS2+$(LINKLIB)SLIBEEP
SFJ_LIB = $(LINKLIB)OS2+$(LINKLIB)SLIBEEP
REJ_LIB = $(LINKLIB)OS2+$(LINKLIB)SLIBCEP
REG_LIB = $(LINKLIB)OS2+$(LINKLIB)SLIBEEP
ADI_LIB = $(LINKLIB)OS2+$(LINKLIB)SLIBCEP
CRP_LIB = $(LINKLIB)OS2+$(LINKLIB)LLIBCDLL
# New executable definitions
STD_DEF = $(CC_CODE)\default.def
ARJ_DEF = $(CC_CODE)\arj.def
STB_DEF = $(CC_CODE)\sfxstub.def
SFV_DEF = $(CC_CODE)\arjsfxv.def
SFX_DEF = $(CC_CODE)\arjsfx.def
SFJ_DEF = $(CC_CODE)\arjsfxjr.def
REJ_DEF = $(CC_CODE)\rearj.def
REG_DEF = $(CC_CODE)\register.def
ADI_DEF = $(CC_CODE)\arjdisp.def
CRP_DEF = $(CC_CODE)\arjcrypt.def
!endif
LRF = echo > NUL
!endif
##
## OS/2 protected mode LX section
##
!if "$(MODE)" == "OS232"
OS_ID = OS2
!ifndef COMPILER
COMPILER = VACPP
!endif
#
# Assembly language options are the same - we'll use MASM everywhere
#
ASM = ml.exe
ASMOPT = /I$(BASEDIR) /c /Fo$@ %s
STD_ASMOPT = /DMODL=FLAT /DARJUTIL $(ASMOPT)
STB_ASMOPT = /DMODL=FLAT /DSFXSTUB $(ASMOPT)
SFV_ASMOPT = /DMODL=FLAT /DARJSFX $(ASMOPT)
SFX_ASMOPT = /DMODL=FLAT /DARJSFX $(ASMOPT)
SFJ_ASMOPT = /DMODL=FLAT /DARJSFXJR /DNO_FAR $(ASMOPT)
REJ_ASMOPT = /DMODL=FLAT /DREARJ /DNO_FAR $(ASMOPT)
REG_ASMOPT = /DMODL=FLAT /DREGISTER /DNO_FAR $(ASMOPT)
ADI_ASMOPT = /DMODL=FLAT /DARJDISP /DNO_FAR $(ASMOPT)
CRP_ASMOPT = /DMODL=FLAT $(ASMOPT)
#
# IBM C Set/2 v 2.xx or 3.65
#
!if "$(COMPILER)" == "CSET2" || "$(COMPILER)" == "VACPP"
CC_CODE = $(COMPILER)
CC = icc.exe
!ifdef LIBC
LIBCKLUDGE = /Rn /Gp /Gn- /I$(LIBCPATH)
!else
LIBCKLUDGE =
!endif
!ifdef DEBUG
CSETDBG = /Ti+
CLNKDBG = /DE /MAP:full
NP_SFX = 1
MAKESYM = 1
!else
!if "$(COMPILER)" == "CSET2"
CSETSTK = /Gs-
CSETDBG = /Gi /O /Oi-
!else
CSETDBG = /Gi
VAC_SPEED = /O /Oi-
VAC_SIZE = /Oc
!endif
!endif
!if "$(COMPILER)" == "VACPP"
VACPP_COPT = /Gs /qarch=x86 /qnoro /qtune=pentium2 /Wpro- /Wcnd-
!else
VACPP_COPT = /G4
!endif
COPT = /I$(BASEDIR) /Fo$@ /c /Sp /I. $(LIBCKLUDGE) $(CSETDBG) $(VACPP_COPT) /Tl5 %s
NEARPOPT =
!if "$(COMPILER)" == "VACPP"
LINKER = ilink.exe /NOFREE
!else
LINKER = link386.exe
!endif
# C options
STD_COPT = $(VAC_SIZE) $(CSETSTK) /DARJUTIL $(COPT)
ARJ_COPT = $(VAC_SPEED) $(CSETSTK) /DSFL=4 $(COPT)
ARJ_RECOPT = $(VAC_SIZE) $(CSETSTK) /DSFL=4 $(COPT)
SFV_COPT = $(VAC_SIZE) $(CSETSTK) /DSFL=3 $(COPT)
SFX_COPT = $(VAC_SIZE) $(CSETSTK) /DSFL=2 $(COPT)
SFJ_COPT = $(VAC_SIZE) $(CSETSTK) /DSFL=1 $(COPT)
REJ_COPT = /Gs+ /DREARJ $(COPT)
REG_COPT = $(VAC_SIZE) $(CSETSTK) /DREGISTER $(COPT)
ADI_COPT = $(VAC_SIZE) $(CSETSTK) /DARJDISP $(COPT)
FAR_COPT = $(NEARP_OPT) $(ARJ_COPT)
FDS_COPT = /NDFARD_SEG $(ARJ_COPT)
NEAR_COPT = $(CSETSTK) $(ARJ_COPT)
CRP_COPT = /Ge- $(COPT)
# LIBC hack for linking
!ifdef LIBC
!if "$(COMPILER)" == "VACPP"
LINKLIB = LIBCSI+OS2386+VACPP\VACPP365
!else
LINKLIB = LIBCS+OS2386
!endif
LINKOPT = /NOD /NOE /PMTYPE:VIO
WARPPACK = /EXEPACK:2
!else
LINKLIB =
LINKOPT = /NOE /PMTYPE:VIO
WARPPACK = /EXEPACK
!endif
# Executables
ARJ = arj.exe
ARJSFXV = arjsfxv.exe
ARJSFX = arjsfx.exe
ARJSFXJR = arjsfxjr.exe
ARJCRYPT = arjcrypt.dll
REARJ = rearj.exe
REGISTER = register.exe
ARJDISP = arjdisp.exe
POSTPROC = postproc.exe
JOIN = join.exe
MSGBIND = msgbind.exe
TODAY = today.exe
MAKE_KEY = make_key.exe
PACKAGER = packager.exe
MAKESTUB = makestub.exe
SFXSTUB = sfxstub.exe
# Linkup objects
STD_OBJ = $(WARPPACK) /STACK:18432
ARJ_OBJ = /STACK:73728
STB_OBJ = $(WARPPACK)
SFV_OBJ = $(WARPPACK) /STACK:16384
SFX_OBJ = $(WARPPACK) /STACK:16384
SFJ_OBJ = $(WARPPACK) /STACK:8192
REJ_OBJ = /STACK:73728
REG_OBJ = $(WARPPACK)
ADI_OBJ = $(WARPPACK)
CRP_OBJ = /STACK:2048
# Supplemental objects
# Libraries
STD_LIB = $(LINKLIB)
ARJ_LIB = $(LINKLIB)
STB_LIB = $(LINKLIB)
SFV_LIB = $(LINKLIB)
SFX_LIB = $(LINKLIB)
SFJ_LIB = $(LINKLIB)
REJ_LIB = $(LINKLIB)
REG_LIB = $(LINKLIB)
ADI_LIB = $(LINKLIB)
CRP_LIB = $(LINKLIB)
# New executable definitions
STD_DEF = CSET2\default.def
ARJ_DEF = CSET2\arj.def
STB_DEF = CSET2\sfxstub.def
SFV_DEF = CSET2\arjsfxv.def
SFX_DEF = CSET2\arjsfx.def
SFJ_DEF = CSET2\arjsfxjr.def
REJ_DEF = CSET2\rearj.def
REG_DEF = CSET2\register.def
ADI_DEF = CSET2\arjdisp.def
CRP_DEF = CSET2\arjcrypt.def
#
# MetaWare High C/C++ v 3.xx
#
!elseif "$(COMPILER)" == "HIGHC"
CC_CODE = $(COMPILER)
CC = hc.exe
!ifdef DEBUG
HCDBG = -g -on=Emit_names
CLNKDBG = /DE /MAP:full
NP_SFX = 1
MAKESYM = 1
!else
HCDBG =
HCOPTIM = -O7 -Hpentium -Hon=Optimize_FP -Hoff=BEHAVED
!endif
!ifdef LIBC
HCLIBC = -I$(LIBCPATH) -D__EXTENDED__
!endif
COPT = -I$(BASEDIR) -o $@ -c -I. $(HCDBG) $(HCLIBC) -Hpragma=Offwarn(553) %s
NEARPOPT =
LINKER = link386.exe
# C options
STD_COPT = -DARJUTIL $(HCOPTIM) $(COPT)
ARJ_COPT = -DSFL=4 $(HCOPTIM) $(COPT)
SFV_COPT = -DSFL=3 $(HCOPTIM) $(COPT)
SFX_COPT = -DSFL=2 $(HCOPTIM) $(COPT)
SFJ_COPT = -DSFL=1 $(HCOPTIM) $(COPT)
REJ_COPT = -Hon=Check_stack -DREARJ $(HCOPTIM) $(COPT)
REG_COPT = -DREGISTER $(HCOPTIM) $(COPT)
ADI_COPT = -DARJDISP $(HCOPTIM) $(COPT)
FAR_COPT = $(NEARP_OPT) $(HCOPTIM) $(ARJ_COPT)
FDS_COPT = $(HCOPTIM) $(ARJ_COPT)
NEAR_COPT = $(HCOPTIM) $(ARJ_COPT)
CRP_COPT = $(COPT)
# LIBC hack for linking
!ifdef LIBC
LINKLIB = HIGHC\HCD_OMF+OS2386+LIBCSS+HC
LINKOPT = /NOD /NOE /PMTYPE:VIO
WARPPACK = /EXEPACK:2
!else
LINKLIB = HC+HCNA+OS2386
LINKOPT = /NOE /PMTYPE:VIO
WARPPACK = /EXEPACK
!endif
#
# OpenWatcom C/C++
#
!elseif "$(COMPILER)" == "WATCOM"
CC_CODE = WCC2_32
CC = wcc386.exe
!ifdef DEBUG
WCCDBG = -d2 -en
CLNKDBG = /DE
NP_SFX = 1
MAKESYM = 1
!else
WCCDBG = -5
WCCSIZE = -os
# This yields top speed but is pretty unsafe. See below.
WCCSPD = -otx
!endif
!ifdef LIBC
WCCLIBC = -i=$(LIBCPATH) -D__EXTENDED__ -zl -D_LNK_CONV=_System
!endif
COPT = -i=$(BASEDIR) -wcd=107 -fo=$@ -s -i=. $(WCCDBG) $(WCCLIBC) -ze %s
NEARPOPT =
LINKER = link386.exe
# C options
STD_COPT = -DARJUTIL $(WCCSIZE) $(COPT)
ARJ_COPT = -DSFL=4 $(WCCSIZE) $(COPT)
# This is a Watcom speed freak. Now we just have to set it by default.
ARJ_COPTS = -DSFL=4 $(WCCSPD) $(COPT)
SFV_COPT = -DSFL=3 $(WCCSIZE) $(COPT)
SFX_COPT = -DSFL=2 $(WCCSIZE) $(COPT)
SFJ_COPT = -DSFL=1 $(WCCSIZE) $(COPT)
REJ_COPT = -DREARJ $(WCCSIZE) $(COPT)
REG_COPT = -DREGISTER $(WCCSIZE) $(COPT)
ADI_COPT = -DARJDISP $(WCCSIZE) $(COPT)
FAR_COPT = $(NEARP_OPT) $(ARJ_COPT)
FDS_COPT = $(ARJ_COPT)
# One more fix for Watcom.
NEAR_COPT = $(ARJ_COPTS)
CRP_COPT = $(WCCSIZE) $(COPT)
# LIBC hack for linking
!ifdef LIBC
LINKLIB = WCC2_32\OWATCOMR+OS2386+LIBCSS
LINKOPT = /MAP:full /NOE /PMTYPE:VIO
WARPPACK = /EXEPACK:2
!else
!error Not supported!
LINKLIB = WCC2_32\OWATCOMC+OS2386+clib3r
LINKOPT = /MAP:full /NOD /NOE /PMTYPE:VIO
WARPPACK = /EXEPACK
!endif
!endif
# Linkup objects
STD_OBJ = $(CLNKDBG) $(WARPPACK) /STACK:18432
ARJ_OBJ = $(CLNKDBG) /STACK:73728
STB_OBJ = $(CLNKDBG) $(WARPPACK)
SFV_OBJ = $(CLNKDBG) $(WARPPACK) /STACK:16384
SFX_OBJ = $(CLNKDBG) $(WARPPACK) /STACK:16384
SFJ_OBJ = $(CLNKDBG) $(WARPPACK) /STACK:8192
REJ_OBJ = $(CLNKDBG) /STACK:73728
REG_OBJ = $(CLNKDBG) $(WARPPACK) /STACK:8192
ADI_OBJ = $(CLNKDBG) $(WARPPACK) /STACK:16384
CRP_OBJ = $(CLNKDBG) /STACK:2048
# Supplemental objects
# Libraries
STD_LIB = $(LINKLIB)
ARJ_LIB = $(LINKLIB)
STB_LIB = $(LINKLIB)
SFV_LIB = $(LINKLIB)
SFX_LIB = $(LINKLIB)
SFJ_LIB = $(LINKLIB)
REJ_LIB = $(LINKLIB)
REG_LIB = $(LINKLIB)
ADI_LIB = $(LINKLIB)
CRP_LIB = $(LINKLIB)
# New executable definitions
STD_DEF = CSET2\default.def
ARJ_DEF = CSET2\arj.def
STB_DEF = CSET2\sfxstub.def
SFV_DEF = CSET2\arjsfxv.def
SFX_DEF = CSET2\arjsfx.def
SFJ_DEF = CSET2\arjsfxjr.def
REJ_DEF = CSET2\rearj.def
REG_DEF = CSET2\register.def
ADI_DEF = CSET2\arjdisp.def
CRP_DEF = CSET2\arjcrypt.def
# Executables
ARJ = arj.exe
ARJSFXV = arjsfxv.exe
ARJSFX = arjsfx.exe
ARJSFXJR = arjsfxjr.exe
ARJCRYPT = arjcrypt.dll
REARJ = rearj.exe
REGISTER = register.exe
ARJDISP = arjdisp.exe
POSTPROC = postproc.exe
JOIN = join.exe
MSGBIND = msgbind.exe
TODAY = today.exe
MAKE_KEY = make_key.exe
PACKAGER = packager.exe
MAKESTUB = makestub.exe
SFXSTUB = sfxstub.exe
LRF = echo > NUL
!endif
##
## Win32 PE section
##
!if "$(MODE)" == "WIN32"
OS_ID = WIN32
!ifndef COMPILER
COMPILER = MSVC
!endif
# No assembler inlays anymore (use portable C snippets as in EMX)
NO_ASM = 1
# For the free-form COFF MS Linker:
NEWLINK = 1
#
# Visual C++ v 2.20 (9.10)
#
!if "$(COMPILER)" == "MSVC"
CC_CODE = $(COMPILER)
CC = cl.exe
!ifdef DEBUG
ADD_COPT = /Ge /Zi /Od
ADD_LINKOPT = /DEBUG
!else
MSVC_SIZE = /Os
MSVC_SPEED = /Ot
ADD_COPT = /G4 /Oy
ADD_LINKOPT = /RELEASE /DEFAULTLIB:NTDLL
!endif
!ifdef LIBC
LIBC_COPT = /MD
!else
LIBC_COPT = /ML
!endif
COPT = /c /I$(BASEDIR) /W2 /GX $(LIBC_COPT) $(ADD_COPT) /I. /Fo$@ %s
LINKER = link.exe
# C options
STD_COPT = $(MSVC_SIZE) $(CSETSTK) /DARJUTIL $(COPT)
ARJ_COPT = $(MSVC_SPEED) $(CSETSTK) /DSFL=4 $(COPT)
ARJ_RECOPT = $(MSVC_SIZE) $(CSETSTK) /DSFL=4 $(COPT)
SFV_COPT = $(MSVC_SIZE) $(CSETSTK) /DSFL=3 $(COPT)
SFX_COPT = $(MSVC_SIZE) $(CSETSTK) /DSFL=2 $(COPT)
SFJ_COPT = $(MSVC_SIZE) $(CSETSTK) /DSFL=1 $(COPT)
REJ_COPT = /Ge /DREARJ $(COPT)
REG_COPT = $(MSVC_SIZE) $(CSETSTK) /DREGISTER $(COPT)
ADI_COPT = $(MSVC_SIZE) $(CSETSTK) /DARJDISP $(COPT)
FAR_COPT = $(NEARP_OPT) $(ARJ_COPT)
FDS_COPT = $(ARJ_COPT)
NEAR_COPT = $(CSETSTK) $(ARJ_COPT)
CRP_COPT = /LD /DDLL $(COPT)
LINKLIB = largeint.lib
LINKOPT = $(ADD_LINKOPT)
# Executables
ARJ = arj.exe
ARJSFXV = arjsfxv.exe
ARJSFX = arjsfx.exe
ARJSFXJR = arjsfxjr.exe
ARJCRYPT = arjcrypt.dll
REARJ = rearj.exe
REGISTER = register.exe
ARJDISP = arjdisp.exe
POSTPROC = postproc.exe
JOIN = join.exe
MSGBIND = msgbind.exe
TODAY = today.exe
MAKE_KEY = make_key.exe
PACKAGER = packager.exe
MAKESTUB = makestub.exe
SFXSTUB = sfxstub.exe
# Linkup objects
STD_OBJ = /SUBSYSTEM:CONSOLE,3.10 /STACK:65536,32768
ARJ_OBJ = /SUBSYSTEM:CONSOLE,3.10 /STACK:73728,16384
STB_OBJ = /SUBSYSTEM:CONSOLE,3.10
SFV_OBJ = /SUBSYSTEM:CONSOLE,3.10 /STACK:65536,16384
SFX_OBJ = /SUBSYSTEM:CONSOLE,3.10 /STACK:65536,16384
SFJ_OBJ = /SUBSYSTEM:CONSOLE,3.10 /STACK:65536,8192
REJ_OBJ = /SUBSYSTEM:CONSOLE,3.10 /STACK:73728,24576
REG_OBJ = /SUBSYSTEM:CONSOLE,3.10
ADI_OBJ = /SUBSYSTEM:CONSOLE,3.10
CRP_OBJ = /SUBSYSTEM:WINDOWS,3.10 /DLL
# Supplemental objects
# Libraries
STD_LIB = $(LINKLIB)
ARJ_LIB = $(LINKLIB)
STB_LIB = $(LINKLIB)
SFV_LIB = $(LINKLIB)
SFX_LIB = $(LINKLIB)
SFJ_LIB = $(LINKLIB)
REJ_LIB = $(LINKLIB)
REG_LIB = $(LINKLIB)
ADI_LIB = $(LINKLIB)
CRP_LIB = $(LINKLIB)
# Only declare some exports for the DLL
CRP_DEF = /DEF:WIN32\arjcrypt.def
!endif
!endif

!ifndef NEWLINK
LAST_LINKOPT = ;
!else
MAP_LINKOPT = /MAP:
OUT_LINKOPT = /OUT:
LRF = echo
!endif

# Buggy optimizer treatment section:
#
# + Options for RECOVERY.C (the VisualAge C++ optimizer fails here)

!ifndef ARJ_RECOPT
ARJ_RECOPT = $(ARJ_COPT)
!endif

# + ARJ speed-optimized modules (encoding/decoding/security).

!ifndef ARJ_COPTS
ARJ_COPTS = $(ARJ_COPT)
!endif

# Base directory macros (one in UNIX format, for preprocessors to be happy)

BASEDIR = $(CC_CODE)\$(LOCALE)\$(DEBUG_SM)$(PACKAGE)
BASEDIR_T = $(CC_CODE)\$(LOCALE)\$(DEBUG_SM)$(PACKAGE)^\
BASEDIR_P = $(CC_CODE)\$(LOCALE)\$(DEBUG_SM)c
BASEDIR_U = $(CC_CODE)/$(LOCALE)/$(DEBUG_SM)$(PACKAGE)/

.SUFFIXES: .c .asm .obj .exe

#
# Main dependency tree
#

all:                        init                            \
                            timestamp                       \
                            $(BASEDIR)\arj\$(ARJ)           \
                            $(BASEDIR)\arjcrypt\$(ARJCRYPT) \
                            $(BASEDIR)\rearj\$(REARJ)       \
                            $(BASEDIR)\register\$(REGISTER) \
                            $(BASEDIR)\arjdisp\$(ARJDISP)   \
                            $(BASEDIR)\tools\$(PACKAGER)    \
!ifdef COMMERCIAL
                            $(BASEDIR)\tools\$(MAKE_KEY)    \
!endif
                            dispose

#
# Pre-compile initialization
#

init:
 @if exist $(BASEDIR_T)stubincl.inc del $(BASEDIR_T)stubincl.inc
# Create C defines file
 @echo /* This is an automatically generated file */ >$(C_DEFS)
!ifdef COMMERCIAL
 @echo #define COMMERCIAL >>$(C_DEFS)
!endif
!ifdef LIBC
 @echo #define LIBC >>$(C_DEFS)
!endif
!ifdef MAKESYM
 @echo #define MAKESYM >>$(C_DEFS)
!endif
!ifdef NP_SFX
 @echo #define NP_SFX >>$(C_DEFS)
!endif
!ifdef DEBUG
 @echo #define DEBUG >>$(C_DEFS)
!endif
!ifdef FORCE_MSGRAPH
 @echo #define FORCE_MSGRAPH >>$(C_DEFS)
!endif
!ifdef USE_COLORS
 @echo #define USE_COLORS >>$(C_DEFS)
!endif
 @echo #define LOCALE LANG_$(LOCALE) >>$(C_DEFS)
 @echo #define LOCALE_DESC "$(LOCALE)" >>$(C_DEFS)
!if "$(COMPILER)" != "HIGHC"
 @echo #define HAVE_MIN >>$(C_DEFS)
 @echo #define HAVE_MAX >>$(C_DEFS)
!endif
 @echo #define HAVE_STRLWR >>$(C_DEFS)
 @echo #define HAVE_STRUPR >>$(C_DEFS)
# Create ASM defines file
 @echo ; This is an automatically generated file >$(ASM_DEFS)
!ifndef COMMERCIAL
 @echo NC_CRC EQU 1>>$(ASM_DEFS)
!endif
!ifdef DEBUG
 @echo DEBUG EQU 1>>$(ASM_DEFS)
!endif
!if "$(MODE)" == "OS232"
 @echo FLATMODE EQU 1>>$(ASM_DEFS)
!endif
!if "$(COMPILER)" == "MSC6"||"$(COMPILER)" == "MSC7"||"$(COMPILER)" == "MSVC10"||"$(COMPILER)" == "MSVC15"||"$(COMPILER)" == "QC25"
 @echo MSC EQU 1>>$(ASM_DEFS)
!endif
# Environment-specific preparations
!if "$(MODE)" == "OS216"||"$(MODE)" == "OS232"
!if "$(COMPILER)" != "HIGHC"
 @echo #define _OS2 >>$(C_DEFS)
!endif
 @echo _OS2 EQU 1 >>$(ASM_DEFS)
!endif
!if "$(COMPILER)" == "MSC6"
!if "$(MODE)" == "DOS16"
 @SET CL=/B1C1L /I. /c /Zp /Gs
!else if "$(MODE)" == "OS216"
 @SET CL=/B2C2L /c /G2 /Zp /Gs /Lp /Zl
!endif
!endif

#
# Update timestamp file
#

timestamp: $(BASEDIR)\tools\$(TODAY)
 $(BASEDIR)\tools\$(TODAY) $(LOCALE) $(BASEDIR)

#
# Final cleanup
#

dispose:
 @if exist $(BASEDIR_T)stubincl.inc del $(BASEDIR_T)stubincl.inc
 @if exist $(C_DEFS) del $(C_DEFS)
 @if exist $(ASM_DEFS) del $(ASM_DEFS)
!if "$(COMPILER)" == "MSC6"
 @SET CL=
!endif

#
# Message resource compiler (must be the FIRST program to compile)
# Timestamp utility
# Comment creation utility
# Postprocessing utility
# Join utility
# Stub message section converter
# Packaging tool
#

$(BASEDIR)\tools\$(MSGBIND): \
                         $(BASEDIR)\tools\msgbind.obj \
                         $(BASEDIR)\tools\filemode.obj \
                         $(BASEDIR)\tools\arjdata.obj \
                         $(BASEDIR)\tools\crc32.obj
 $(LRF) @<<$(BASEDIR_T)msgbind.lrf
!ifdef NEWLINK
$(LINKOPT) $(STD_OBJ) $(**: = ^
)
!else
$(LINKOPT) $(STD_OBJ) $(**: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STD_LIB)
<<
 $(LINKER) @$(BASEDIR_T)msgbind.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)msgbind.lrf del $(BASEDIR_T)msgbind.lrf

$(BASEDIR)\tools\$(TODAY): \
                         $(BASEDIR)\tools\today.obj \
                         $(BASEDIR)\tools\filemode.obj
 $(LRF) @<<$(BASEDIR_T)today.lrf
!ifdef NEWLINK
$(LINKOPT) $(STD_OBJ) $(**: = ^
)
!else
$(LINKOPT) $(STD_OBJ) $(**: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STD_LIB)
<<
 $(LINKER) @$(BASEDIR_T)today.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)today.lrf del $(BASEDIR_T)today.lrf

$(BASEDIR)\tools\$(MAKE_KEY): \
                         $(BASEDIR)\tools\make_key.obj \
                         $(BASEDIR)\tools\crc32.obj    \
                         $(BASEDIR)\tools\misc.obj     \
                         $(BASEDIR)\tools\arj_proc.obj \
                         $(BASEDIR)\tools\arjsec_h.obj \
                         $(BASEDIR)\tools\arjsec_l.obj
 $(LRF) @<<$(BASEDIR_T)make_key.lrf
!ifdef NEWLINK
$(LINKOPT) $(STD_OBJ) $(**: = ^
)
!else
$(LINKOPT) $(STD_OBJ) $(**: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STD_LIB)
<<
 $(LINKER) @$(BASEDIR_T)make_key.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)make_key.lrf del $(BASEDIR_T)make_key.lrf

$(BASEDIR)\tools\$(POSTPROC): \
                         $(BASEDIR)\tools\postproc.obj \
                         $(BASEDIR)\tools\filemode.obj \
                         $(BASEDIR)\tools\crc32.obj
 $(LRF) @<<$(BASEDIR_T)postproc.lrf
!ifdef NEWLINK
$(LINKOPT) $(STD_OBJ) $(**: = ^
)
!else
$(LINKOPT) $(STD_OBJ) $(**: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STD_LIB)
$(STD_DEF)
<<
 $(LINKER) @$(BASEDIR_T)postproc.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)postproc.lrf del $(BASEDIR_T)postproc.lrf

$(BASEDIR)\tools\$(JOIN): \
                         $(BASEDIR)\tools\join.obj \
                         $(BASEDIR)\tools\filemode.obj
 $(LRF) @<<$(BASEDIR_T)join.lrf
!ifdef NEWLINK
$(LINKOPT) $(STD_OBJ) $(**: = ^
)
!else
$(LINKOPT) $(STD_OBJ) $(**: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STD_LIB)
$(STD_DEF)
<<
 $(LINKER) @$(BASEDIR_T)join.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)join.lrf del $(BASEDIR_T)join.lrf

$(BASEDIR)\tools\$(MAKESTUB): \
                         $(BASEDIR)\tools\makestub.obj \
                         $(BASEDIR)\tools\filemode.obj \
                         $(BASEDIR)\tools\nmsg_stb.obj
 $(LRF) @<<$(BASEDIR_T)makestub.lrf
!ifdef NEWLINK
$(LINKOPT) $(STD_OBJ) $(**: = ^
)
!else
$(LINKOPT) $(STD_OBJ) $(**: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STD_LIB)
$(STD_DEF)
<<
 $(LINKER) @$(BASEDIR_T)makestub.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)makestub.lrf del $(BASEDIR_T)makestub.lrf

$(BASEDIR)\tools\$(PACKAGER): \
                         $(BASEDIR)\tools\packager.obj \
                         $(BASEDIR)\tools\filemode.obj \
                         $(BASEDIR)\tools\arjdata.obj
 $(LRF) @<<$(BASEDIR_T)packager.lrf
!ifdef NEWLINK
$(LINKOPT) $(STD_OBJ) $(**: = ^
)
!else
$(LINKOPT) $(STD_OBJ) $(**: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STD_LIB)
<<
 $(LINKER) @$(BASEDIR_T)packager.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)packager.lrf del $(BASEDIR_T)packager.lrf

$(BASEDIR)\tools\msgbind.obj: msgbind.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\today.obj: today.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\make_key.obj: make_key.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\postproc.obj: postproc.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\join.obj: join.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\makestub.obj: makestub.c $(BASEDIR)\nmsg_stb.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\packager.obj: packager.c
 $(CC) $(STD_COPT)

$(BASEDIR)\tools\arjdata.obj: arjdata.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\filemode.obj: filemode.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\crc32.obj: crc32.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\misc.obj: misc.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\arjsec_h.obj: arjsec_h.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\arjsec_l.obj: arjsec_l.c
 $(CC) $(STD_COPT)
$(BASEDIR)\tools\nmsg_stb.obj: $(BASEDIR)\nmsg_stb.c
 $(CC) $(STD_COPT)

$(BASEDIR)\nmsg_stb.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_stb $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# ARJCRYPT utility
#

CRP_OBJS = $(BASEDIR)\arjcrypt\arjcrypt.obj \
           $(BASEDIR)\arjcrypt\integr.obj   \
           $(BASEDIR)\arjcrypt\gost.obj     \
           $(BASEDIR)\arjcrypt\gost_t.obj   \
           $(BASEDIR)\arjcrypt\nmsg_crp.obj \
           $(CRP_OBJS_E)
$(BASEDIR)\arjcrypt\$(ARJCRYPT): $(CRP_OBJS) \
                                 $(BASEDIR)\tools\$(POSTPROC)
 $(LRF) @<<$(BASEDIR_T)arjcrypt.lrf
!ifdef NEWLINK
$(LINKOPT) $(CRP_OBJ) $(CRP_OBJS: = ^
)
!else
$(LINKOPT) $(CRP_OBJ) $(CRP_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(CRP_LIB)
$(CRP_DEF)
<<
 $(LINKER) @$(BASEDIR_T)arjcrypt.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)arjcrypt.lrf del $(BASEDIR_T)arjcrypt.lrf
 $(BASEDIR)\tools\postproc $(BASEDIR)\arjcrypt\$(ARJCRYPT)

!ifndef NO_ASM
$(BASEDIR)\arjcrypt\integr.obj: integr.asm
 $(ASM) $(CRP_ASMOPT)
!else
$(BASEDIR)\arjcrypt\integr.obj: integr.c
 $(CC) $(CRP_COPT)
!endif
$(BASEDIR)\arjcrypt\gost.obj: gost.c
 $(CC) $(CRP_COPT)
$(BASEDIR)\arjcrypt\gost_t.obj: gost_t.c
 $(CC) $(CRP_COPT)
$(BASEDIR)\arjcrypt\arjcrypt.obj: arjcrypt.c $(BASEDIR)\nmsg_crp.c
 $(CC) $(CRP_COPT)
!if "$(MODE)"=="DOS16"
$(BASEDIR)\arjcrypt\det_x86.obj: det_x86.asm
 $(ASM) $(CRP_ASMOPT)
!endif
$(BASEDIR)\arjcrypt\nmsg_crp.obj: $(BASEDIR)\nmsg_crp.c
 $(CC) $(CRP_COPT)
!if "$(MODE)"=="DOS16"
$(BASEDIR)\arjcrypt\gost_asm.obj: gost_asm.asm
 $(ASM) $(CRP_ASMOPT)
!endif
arjcrypt.c: $(BASEDIR)\nmsg_crp.c
$(BASEDIR)\nmsg_crp.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_crp $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# SFX stub
#

STB_OBJS = $(BASEDIR)\sfxstub\sfxstub.obj \
!ifdef NO_ASM
$(BASEDIR)\tools\nmsg_stb.obj
!endif

$(BASEDIR)\sfxstub\$(SFXSTUB): $(STB_OBJS)
 $(LRF) @<<$(BASEDIR_T)sfxstub.lrf
!ifdef NEWLINK
$(LINKOPT) $(STB_OBJ) $(STB_OBJS: = ^
)
!else
$(LINKOPT) $(STB_OBJ) $(STB_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(STB_LIB)
$(STB_DEF)
<<
 $(LINKER) @$(BASEDIR_T)sfxstub.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)sfxstub.lrf del $(BASEDIR_T)sfxstub.lrf
 $(BASEDIR)\tools\postproc $(BASEDIR)\sfxstub\$(SFXSTUB) -sfx

!ifndef NO_ASM
$(BASEDIR)\sfxstub\sfxstub.obj: sfxstub.asm $(BASEDIR)\tools\$(MAKESTUB)
 $(BASEDIR)\tools\$(MAKESTUB) $(BASEDIR_T)stubincl.inc
 $(ASM) $(STB_ASMOPT)
!else
$(BASEDIR)\sfxstub\sfxstub.obj: sfxstub.c $(BASEDIR)\tools\nmsg_stb.obj $(BASEDIR)\tools\$(POSTPROC)
 $(CC) -I$(BASEDIR) -DSFXSTUB $(COPT)
!endif

#
# ARJSFXV module
#

SFV_OBJS = $(BASEDIR)\arjsfxv\arjsfxv.obj  \
           $(BASEDIR)\arjsfxv\sfx_id.obj   \
           $(BASEDIR)\arjsfxv\filemode.obj \
           $(BASEDIR)\arjsfxv\date_sig.obj \
           $(BASEDIR)\arjsfxv\fmsg_sfv.obj \
           $(BASEDIR)\arjsfxv\imsg_sfv.obj \
           $(BASEDIR)\arjsfxv\nmsg_sfv.obj \
           $(BASEDIR)\arjsfxv\decode.obj   \
           $(BASEDIR)\arjsfxv\fardata.obj  \
           $(BASEDIR)\arjsfxv\arj_user.obj \
           $(BASEDIR)\arjsfxv\arj_arcv.obj \
           $(BASEDIR)\arjsfxv\arj_file.obj \
           $(BASEDIR)\arjsfxv\crc32.obj    \
           $(BASEDIR)\arjsfxv\misc.obj     \
           $(BASEDIR)\arjsfxv\debug.obj    \
           $(BASEDIR)\arjsfxv\arj_proc.obj \
           $(BASEDIR)\arjsfxv\environ.obj  \
           $(BASEDIR)\arjsfxv\ntstream.obj \
           $(BASEDIR)\arjsfxv\ea_mgr.obj   \
           $(BASEDIR)\arjsfxv\uxspec.obj   \
           $(BASEDIR)\arjsfxv\ext_hdr.obj  \
           $(BASEDIR)\arjsfxv\arjtypes.obj \
           $(BASEDIR)\arjsfxv\exe_sear.obj \
           $(BASEDIR)\arjsfxv\chk_fmsg.obj \
           $(BASEDIR)\arjsfxv\filelist.obj \
           $(BASEDIR)\arjsfxv\arjsec_h.obj \
!ifdef COMMERCIAL
           $(BASEDIR)\arjsfxv\arjsec_l.obj \
!endif
           $(BASEDIR)\arjsfxv\garble.obj   \
           $(BASEDIR)\arjsfxv\scrnio.obj   \
           $(BASEDIR)\arjsfxv\ansi.obj     \
           $(BASEDIR)\arjsfxv\externs.obj

$(BASEDIR)\arjsfxv\$(ARJSFXV): $(SFV_OBJS) \
                                $(BASEDIR)\tools\$(POSTPROC)
 $(LRF) @<<$(BASEDIR_T)arjsfxv.lrf
!ifdef NEWLINK
$(LINKOPT) $(SFV_OBJ) $(SFV_OBJS: = ^
)
!else
$(LINKOPT) $(SFV_OBJ) $(SFV_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(SFV_LIB)
$(SFV_DEF)
<<
 $(LINKER) @$(BASEDIR_T)arjsfxv.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)arjsfxv.lrf del $(BASEDIR_T)arjsfxv.lrf
 $(BASEDIR)\tools\postproc $(BASEDIR)\arjsfxv\$(ARJSFXV) -sfx

!ifndef NO_ASM
$(BASEDIR)\arjsfxv\sfx_id.obj: sfx_id.asm
 $(ASM) $(SFV_ASMOPT)
!else
$(BASEDIR)\arjsfxv\sfx_id.obj: sfx_id.c
 $(CC) $(SFV_COPT)
!endif
$(BASEDIR)\arjsfxv\filemode.obj: filemode.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\date_sig.obj: $(BASEDIR)\date_sig.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\fmsg_sfv.obj: $(BASEDIR)\fmsg_sfv.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\imsg_sfv.obj: $(BASEDIR)\imsg_sfv.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\nmsg_sfv.obj: $(BASEDIR)\nmsg_sfv.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\decode.obj: decode.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arjsfxv.obj: arjsfx.c $(BASEDIR)\fmsg_sfv.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\fardata.obj: fardata.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arj_user.obj: arj_user.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arj_arcv.obj: arj_arcv.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arj_file.obj: arj_file.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\crc32.obj: crc32.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\misc.obj: misc.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\debug.obj: debug.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arj_proc.obj: arj_proc.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\environ.obj: environ.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\ntstream.obj: ntstream.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\ea_mgr.obj: ea_mgr.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\uxspec.obj: uxspec.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\ext_hdr.obj: ext_hdr.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arjtypes.obj: arjtypes.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\exe_sear.obj: exe_sear.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\chk_fmsg.obj: chk_fmsg.c $(BASEDIR)\msg_sfv.h
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\filelist.obj: filelist.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arjsec_h.obj: arjsec_h.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\arjsec_l.obj: arjsec_l.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\garble.obj: garble.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\scrnio.obj: scrnio.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\ansi.obj: ansi.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\arjsfxv\externs.obj: externs.c
 $(CC) $(SFV_COPT)
$(BASEDIR)\fmsg_sfv.c $(BASEDIR)\imsg_sfv.c $(BASEDIR)\nmsg_sfv.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_sfv $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# ARJSFX module
#

SFX_OBJS = $(BASEDIR)\arjsfx\arjsfx.obj   \
           $(BASEDIR)\arjsfx\sfx_id.obj   \
           $(BASEDIR)\arjsfx\filemode.obj \
           $(BASEDIR)\arjsfx\fmsg_sfx.obj \
           $(BASEDIR)\arjsfx\imsg_sfx.obj \
           $(BASEDIR)\arjsfx\nmsg_sfx.obj \
           $(BASEDIR)\arjsfx\decode.obj   \
           $(BASEDIR)\arjsfx\fardata.obj  \
           $(BASEDIR)\arjsfx\arj_user.obj \
           $(BASEDIR)\arjsfx\arj_arcv.obj \
           $(BASEDIR)\arjsfx\arj_file.obj \
           $(BASEDIR)\arjsfx\crc32.obj    \
           $(BASEDIR)\arjsfx\misc.obj     \
           $(BASEDIR)\arjsfx\debug.obj    \
           $(BASEDIR)\arjsfx\arj_proc.obj \
           $(BASEDIR)\arjsfx\environ.obj  \
           $(BASEDIR)\arjsfx\arjtypes.obj \
           $(BASEDIR)\arjsfx\exe_sear.obj \
           $(BASEDIR)\arjsfx\chk_fmsg.obj \
           $(BASEDIR)\arjsfx\arjsec_h.obj \
!ifdef COMMERCIAL
           $(BASEDIR)\arjsfx\arjsec_l.obj \
!endif
           $(BASEDIR)\arjsfx\garble.obj   \
           $(BASEDIR)\arjsfx\externs.obj

$(BASEDIR)\arjsfx\$(ARJSFX): $(SFX_OBJS) \
                              $(BASEDIR)\tools\$(POSTPROC)
 $(LRF) @<<$(BASEDIR_T)arjsfx.lrf
!ifdef NEWLINK
$(LINKOPT) $(SFX_OBJ) $(SFX_OBJS: = ^
)
!else
$(LINKOPT) $(SFX_OBJ) $(SFX_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(SFX_LIB)
$(SFX_DEF)
<<
 $(LINKER) @$(BASEDIR_T)arjsfx.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)arjsfx.lrf del $(BASEDIR_T)arjsfx.lrf
 $(BASEDIR)\tools\postproc $(BASEDIR)\arjsfx\$(ARJSFX) -sfx

!ifndef NO_ASM
$(BASEDIR)\arjsfx\sfx_id.obj: sfx_id.asm
 $(ASM) $(SFX_ASMOPT)
!else
$(BASEDIR)\arjsfx\sfx_id.obj: sfx_id.c
 $(CC) $(SFX_COPT)
!endif
$(BASEDIR)\arjsfx\filemode.obj: filemode.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\fmsg_sfx.obj: $(BASEDIR)\fmsg_sfx.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\imsg_sfx.obj: $(BASEDIR)\imsg_sfx.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\nmsg_sfx.obj: $(BASEDIR)\nmsg_sfx.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\decode.obj: decode.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arjsfx.obj: arjsfx.c $(BASEDIR)\fmsg_sfx.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\fardata.obj: fardata.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arj_user.obj: arj_user.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arj_arcv.obj: arj_arcv.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arj_file.obj: arj_file.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\crc32.obj: crc32.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\misc.obj: misc.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\debug.obj: debug.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arj_proc.obj: arj_proc.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\environ.obj: environ.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arjtypes.obj: arjtypes.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\exe_sear.obj: exe_sear.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\chk_fmsg.obj: chk_fmsg.c $(BASEDIR)\msg_sfx.h
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arjsec_h.obj: arjsec_h.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\arjsec_l.obj: arjsec_l.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\garble.obj: garble.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\arjsfx\externs.obj: externs.c
 $(CC) $(SFX_COPT)
$(BASEDIR)\fmsg_sfx.c $(BASEDIR)\imsg_sfx.c $(BASEDIR)\nmsg_sfx.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_sfx $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# ARJSFXJR module
#

SFJ_OBJS = $(BASEDIR)\arjsfxjr\arjsfxjr.obj \
           $(BASEDIR)\arjsfxjr\sfx_id.obj   \
           $(BASEDIR)\arjsfxjr\fmsg_sfj.obj \
           $(BASEDIR)\arjsfxjr\nmsg_sfj.obj \
           $(BASEDIR)\arjsfxjr\debug.obj    \
           $(BASEDIR)\arjsfxjr\crc32.obj    \
           $(BASEDIR)\arjsfxjr\environ.obj

$(BASEDIR)\arjsfxjr\$(ARJSFXJR): $(SFJ_OBJS) \
                                  $(BASEDIR)\tools\$(POSTPROC)
 $(LRF) @<<$(BASEDIR_T)arjsfxjr.lrf
!ifdef NEWLINK
$(LINKOPT) $(SFJ_OBJ) $(SFJ_OBJS: = ^
)
!else
$(LINKOPT) $(SFJ_OBJ) $(SFJ_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(SFJ_LIB)
$(SFJ_DEF)
<<
 $(LINKER) @$(BASEDIR_T)arjsfxjr.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)arjsfxjr.lrf del $(BASEDIR_T)arjsfxjr.lrf
 $(BASEDIR)\tools\postproc $(BASEDIR)\arjsfxjr\$(ARJSFXJR) -sfx

!ifndef NO_ASM
$(BASEDIR)\arjsfxjr\sfx_id.obj: sfx_id.asm
 $(ASM) $(SFJ_ASMOPT)
!else
$(BASEDIR)\arjsfxjr\sfx_id.obj: sfx_id.c
 $(CC) $(SFJ_COPT)
!endif
$(BASEDIR)\arjsfxjr\fmsg_sfj.obj: $(BASEDIR)\fmsg_sfj.c
 $(CC) $(SFJ_COPT)
$(BASEDIR)\arjsfxjr\nmsg_sfj.obj: $(BASEDIR)\nmsg_sfj.c
 $(CC) $(SFJ_COPT)
$(BASEDIR)\arjsfxjr\arjsfxjr.obj: arjsfxjr.c $(BASEDIR)\nmsg_sfj.c
 $(CC) $(SFJ_COPT)
$(BASEDIR)\arjsfxjr\crc32.obj: crc32.c
 $(CC) $(SFJ_COPT)
$(BASEDIR)\arjsfxjr\debug.obj: debug.c
 $(CC) $(SFJ_COPT)
$(BASEDIR)\arjsfxjr\environ.obj: environ.c
 $(CC) $(SFJ_COPT)
$(BASEDIR)\fmsg_sfj.c $(BASEDIR)\nmsg_sfj.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_sfj $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# ARJ itself
#

ARJ_OBJS = $(BASEDIR)\arj\arj.obj      \
           $(BASEDIR)\arj\filemode.obj \
           $(BASEDIR)\arj\date_sig.obj \
           $(BASEDIR)\arj\fmsg_arj.obj \
           $(BASEDIR)\arj\imsg_arj.obj \
           $(BASEDIR)\arj\nmsg_arj.obj \
           $(BASEDIR)\arj\integr.obj   \
           $(BASEDIR)\arj\file_reg.obj \
           $(BASEDIR)\arj\decode.obj   \
           $(BASEDIR)\arj\encode.obj   \
           $(BASEDIR)\arj\enc_gwy.obj  \
           $(BASEDIR)\arj\fardata.obj  \
           $(BASEDIR)\arj\arj_user.obj \
           $(BASEDIR)\arj\arj_arcv.obj \
           $(BASEDIR)\arj\arj_file.obj \
           $(BASEDIR)\arj\crc32.obj    \
           $(BASEDIR)\arj\misc.obj     \
           $(BASEDIR)\arj\debug.obj    \
           $(BASEDIR)\arj\arj_proc.obj \
           $(BASEDIR)\arj\environ.obj  \
           $(BASEDIR)\arj\ntstream.obj \
           $(BASEDIR)\arj\ea_mgr.obj   \
           $(BASEDIR)\arj\uxspec.obj   \
           $(BASEDIR)\arj\ext_hdr.obj  \
           $(BASEDIR)\arj\arjtypes.obj \
           $(BASEDIR)\arj\exe_sear.obj \
           $(BASEDIR)\arj\chk_fmsg.obj \
           $(BASEDIR)\arj\filelist.obj \
           $(BASEDIR)\arj\arjsec_h.obj \
           $(BASEDIR)\arj\arjsec_l.obj \
           $(BASEDIR)\arj\garble.obj   \
           $(BASEDIR)\arj\scrnio.obj   \
           $(BASEDIR)\arj\ansi.obj     \
           $(BASEDIR)\arj\crc16tab.obj \
           $(BASEDIR)\arj\recovery.obj \
           $(BASEDIR)\arj\gost.obj     \
           $(BASEDIR)\arj\gost40.obj   \
           $(BASEDIR)\arj\gost_t.obj   \
           $(BASEDIR)\arj\externs.obj  \
           $(ARJ_OBJS_S)               \
           $(ARJ_OBJS_E)
$(BASEDIR)\arj\$(ARJ): $(ARJ_OBJS)    \
                        $(BASEDIR)\tools\$(JOIN) \
                        $(BASEDIR)\tools\$(POSTPROC) \
                        $(BASEDIR)\sfxstub\$(SFXSTUB) \
                        $(BASEDIR)\arjsfxv\$(ARJSFXV) \
                        $(BASEDIR)\arjsfx\$(ARJSFX) \
                        $(BASEDIR)\arjsfxjr\$(ARJSFXJR) \
                        resource\$(LOCALE)\arjl.txt \
                        resource\$(LOCALE)\arjs.txt
 $(LRF) @<<$(BASEDIR_T)arj.lrf
!ifdef NEWLINK
$(LINKOPT) $(ARJ_OBJ) $(ARJ_OBJS: = ^
)
!else
$(LINKOPT) $(ARJ_OBJ) $(ARJ_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(ARJ_LIB)
$(ARJ_DEF)
<<
 $(LINKER) @$(BASEDIR_T)arj.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)arj.lrf del $(BASEDIR_T)arj.lrf
 $(BASEDIR)\tools\join $(BASEDIR)\arj\$(ARJ) $(BASEDIR)\arjsfxjr\$(ARJSFXJR)
 $(BASEDIR)\tools\join $(BASEDIR)\arj\$(ARJ) $(BASEDIR)\arjsfx\$(ARJSFX)
 $(BASEDIR)\tools\join $(BASEDIR)\arj\$(ARJ) $(BASEDIR)\arjsfxv\$(ARJSFXV)
 $(BASEDIR)\tools\join $(BASEDIR)\arj\$(ARJ) $(BASEDIR)\sfxstub\$(SFXSTUB)
 if exist $(BASEDIR_T)help.arj del $(BASEDIR_T)help.arj
 $(BASEDIR)\arj\$(ARJ) a $(BASEDIR_T)help.arj -+ -2e -e -jm -jh65535 -jt -t1g resource\$(LOCALE)\arj?.txt
 $(BASEDIR)\tools\join $(BASEDIR)\arj\$(ARJ) $(BASEDIR_T)help.arj
 if exist $(BASEDIR_T)help.arj del $(BASEDIR_T)help.arj
 $(BASEDIR)\tools\postproc $(BASEDIR)\arj\$(ARJ)

!ifndef NO_ASM
$(BASEDIR)\arj\integr.obj: integr.asm
 $(ASM) $(STD_ASMOPT)
!else
$(BASEDIR)\arj\integr.obj: integr.c
 $(CC) $(STD_COPT)
!endif
$(BASEDIR)\arj\file_reg.obj: file_reg.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\decode.obj: decode.c
 $(CC) $(NEAR_COPT)
!ifndef NO_ASM
$(BASEDIR)\arj\fmemcmp.obj: fmemcmp.asm
 $(ASM) $(STD_ASMOPT)
!endif
$(BASEDIR)\arj\encode.obj: encode.c
 $(CC) $(NEAR_COPT)
$(BASEDIR)\arj\date_sig.obj: $(BASEDIR)\date_sig.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arj.obj: arj.c $(BASEDIR)\nmsg_arj.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\enc_gwy.obj: enc_gwy.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\fardata.obj: fardata.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arj_user.obj: arj_user.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arj_arcv.obj: arj_arcv.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arj_file.obj: arj_file.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\crc32.obj: crc32.c
 $(CC) $(ARJ_COPTS)
$(BASEDIR)\arj\misc.obj: misc.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\debug.obj: debug.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arj_proc.obj: arj_proc.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\environ.obj: environ.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\ntstream.obj: ntstream.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\ea_mgr.obj: ea_mgr.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\uxspec.obj: uxspec.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\ext_hdr.obj: ext_hdr.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arjtypes.obj: arjtypes.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\exe_sear.obj: exe_sear.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\chk_fmsg.obj: chk_fmsg.c $(BASEDIR)\msg_arj.h
 $(CC) $(ARJ_COPT)
!ifndef NO_ASM
$(BASEDIR)\arj\arj_xms.obj: arj_xms.asm
 $(ASM) $(STD_ASMOPT)
!endif
$(BASEDIR)\arj\filelist.obj: filelist.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arjsec_h.obj: arjsec_h.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\arjsec_l.obj: arjsec_l.c
 $(CC) $(ARJ_COPTS)
$(BASEDIR)\arj\garble.obj: garble.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\scrnio.obj: scrnio.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\ansi.obj: ansi.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\recovery.obj: recovery.c
 $(CC) $(ARJ_RECOPT)
$(BASEDIR)\arj\crc16tab.obj: crc16tab.c
 $(CC) $(FDS_COPT)
$(BASEDIR)\arj\gost.obj: gost.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\gost_t.obj: gost_t.c
 $(CC) $(FDS_COPT)
$(BASEDIR)\arj\gost40.obj: gost40.c
 $(CC) $(ARJ_COPTS)
$(BASEDIR)\arj\filemode.obj: filemode.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\fmsg_arj.obj: $(BASEDIR)\fmsg_arj.c
 $(CC) $(FAR_COPT)
$(BASEDIR)\arj\imsg_arj.obj: $(BASEDIR)\imsg_arj.c
 $(CC) $(FAR_COPT)
$(BASEDIR)\arj\nmsg_arj.obj: $(BASEDIR)\nmsg_arj.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\arj\externs.obj: externs.c
 $(CC) $(ARJ_COPT)
$(BASEDIR)\fmsg_arj.c $(BASEDIR)\imsg_arj.c $(BASEDIR)\nmsg_arj.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_arj $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# REARJ utility
#

REJ_OBJS = $(BASEDIR)\rearj\rearj.obj    \
           $(BASEDIR)\rearj\integr.obj   \
           $(BASEDIR)\rearj\filemode.obj \
           $(BASEDIR)\rearj\date_sig.obj \
           $(BASEDIR)\rearj\fmsg_rej.obj \
           $(BASEDIR)\rearj\nmsg_rej.obj \
           $(BASEDIR)\rearj\file_reg.obj \
           $(BASEDIR)\rearj\fardata.obj  \
           $(BASEDIR)\rearj\arj_file.obj \
           $(BASEDIR)\rearj\crc32.obj    \
           $(BASEDIR)\rearj\misc.obj     \
           $(BASEDIR)\rearj\debug.obj    \
           $(BASEDIR)\rearj\arj_proc.obj \
           $(BASEDIR)\rearj\environ.obj  \
           $(BASEDIR)\rearj\arjtypes.obj \
           $(BASEDIR)\rearj\filelist.obj \
           $(BASEDIR)\rearj\scrnio.obj   \
           $(BASEDIR)\rearj\arjsec_h.obj \
           $(BASEDIR)\rearj\arjsec_l.obj \
           $(BASEDIR)\rearj\externs.obj

$(BASEDIR)\rearj\$(REARJ): $(REJ_OBJS) \
                            $(BASEDIR)\tools\$(POSTPROC)
 $(LRF) @<<$(BASEDIR_T)rearj.lrf
!ifdef NEWLINK
$(LINKOPT) $(REJ_OBJ) $(REJ_OBJS: = ^
)
!else
$(LINKOPT) $(REJ_OBJ) $(REJ_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(REJ_LIB)
$(REJ_DEF)
<<
 $(LINKER) @$(BASEDIR_T)rearj.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)rearj.lrf del $(BASEDIR_T)rearj.lrf
 $(BASEDIR)\tools\postproc $(BASEDIR)\rearj\$(REARJ)

!ifndef NO_ASM
$(BASEDIR)\rearj\integr.obj: integr.asm
 $(ASM) $(REJ_ASMOPT)
!else
$(BASEDIR)\rearj\integr.obj: integr.c
 $(CC) $(REJ_COPT)
!endif
$(BASEDIR)\rearj\filemode.obj: filemode.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\date_sig.obj: $(BASEDIR)\date_sig.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\fmsg_rej.obj: $(BASEDIR)\fmsg_rej.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\nmsg_rej.obj: $(BASEDIR)\nmsg_rej.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\file_reg.obj: file_reg.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\rearj.obj: rearj.c $(BASEDIR)\fmsg_rej.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\fardata.obj: fardata.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\arj_file.obj: arj_file.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\crc32.obj: crc32.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\misc.obj: misc.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\debug.obj: debug.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\arj_proc.obj: arj_proc.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\environ.obj: environ.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\arjtypes.obj: arjtypes.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\filelist.obj: filelist.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\scrnio.obj: scrnio.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\arjsec_h.obj: arjsec_h.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\arjsec_l.obj: arjsec_l.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\rearj\externs.obj: externs.c
 $(CC) $(REJ_COPT)
$(BASEDIR)\fmsg_rej.c $(BASEDIR)\nmsg_rej.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_rej $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# Registration wizard
#

REG_OBJS = $(BASEDIR)\register\register.obj \
           $(BASEDIR)\register\integr.obj   \
           $(BASEDIR)\register\filemode.obj \
           $(BASEDIR)\register\fmsg_reg.obj \
           $(BASEDIR)\register\nmsg_reg.obj \
           $(BASEDIR)\register\fardata.obj  \
           $(BASEDIR)\register\crc32.obj    \
           $(BASEDIR)\register\debug.obj    \
           $(BASEDIR)\register\arj_proc.obj \
           $(BASEDIR)\register\environ.obj

$(BASEDIR)\register\$(REGISTER): $(REG_OBJS) \
                                 $(BASEDIR)\tools\$(POSTPROC)
 $(LRF) @<<$(BASEDIR_T)register.lrf
!ifdef NEWLINK
$(LINKOPT) $(REG_OBJ) $(REG_OBJS: = ^
)
!else
$(LINKOPT) $(REG_OBJ) $(REG_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(REG_LIB)
$(REG_DEF)
<<
 $(LINKER) @$(BASEDIR_T)register.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)register.lrf del $(BASEDIR_T)register.lrf
 $(BASEDIR)\tools\postproc $(BASEDIR)\register\$(REGISTER) -sfx

!ifndef NO_ASM
$(BASEDIR)\register\integr.obj: integr.asm
 $(ASM) $(REG_ASMOPT)
!else
$(BASEDIR)\register\integr.obj: integr.c
 $(CC) $(REG_COPT)
!endif
$(BASEDIR)\register\filemode.obj: filemode.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\fmsg_reg.obj: $(BASEDIR)\fmsg_reg.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\nmsg_reg.obj: $(BASEDIR)\nmsg_reg.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\register.obj: register.c $(BASEDIR)\nmsg_reg.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\fardata.obj: fardata.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\crc32.obj: crc32.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\debug.obj: debug.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\arj_proc.obj: arj_proc.c
 $(CC) $(REG_COPT)
$(BASEDIR)\register\environ.obj: environ.c
 $(CC) $(REG_COPT)
$(BASEDIR)\fmsg_reg.c $(BASEDIR)\nmsg_reg.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_reg $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# Demonstration display program
#

ADI_OBJS = $(BASEDIR)\arjdisp\arjdisp.obj \
           $(BASEDIR)\arjdisp\nmsg_adi.obj \
           $(BASEDIR)\arjdisp\fardata.obj \
           $(BASEDIR)\arjdisp\debug.obj \
           $(BASEDIR)\arjdisp\arj_proc.obj \
           $(BASEDIR)\arjdisp\environ.obj \
           $(BASEDIR)\arjdisp\scrnio.obj

$(BASEDIR)\arjdisp\$(ARJDISP): $(ADI_OBJS)
 $(LRF) @<<$(BASEDIR_T)arjdisp.lrf
!ifdef NEWLINK
$(LINKOPT) $(ADI_OBJ) $(ADI_OBJS: = ^
)
!else
$(LINKOPT) $(ADI_OBJ) $(ADI_OBJS: = +^
)
!endif
$(OUT_LINKOPT)$@
$(MAP_LINKOPT)$(@R).map
$(ADI_LIB)
$(ADI_DEF)
<<
 $(LINKER) @$(BASEDIR_T)arjdisp.lrf$(LAST_LINKOPT)
 if exist $(BASEDIR_T)arjdisp.lrf del $(BASEDIR_T)arjdisp.lrf

$(BASEDIR)\arjdisp\nmsg_adi.obj: $(BASEDIR)\nmsg_adi.c
 $(CC) $(ADI_COPT)
$(BASEDIR)\arjdisp\arjdisp.obj: arjdisp.c $(BASEDIR)\nmsg_adi.c
 $(CC) $(ADI_COPT)
$(BASEDIR)\arjdisp\fardata.obj: fardata.c
 $(CC) $(ADI_COPT)
$(BASEDIR)\arjdisp\debug.obj: debug.c
 $(CC) $(ADI_COPT)
$(BASEDIR)\arjdisp\arj_proc.obj: arj_proc.c
 $(CC) $(ADI_COPT)
$(BASEDIR)\arjdisp\environ.obj: environ.c
 $(CC) $(ADI_COPT)
$(BASEDIR)\arjdisp\scrnio.obj: scrnio.c
 $(CC) $(ADI_COPT)
$(BASEDIR)\nmsg_adi.c: $(BASEDIR)\tools\$(MSGBIND) $(RESFILE)
 $(BASEDIR)\tools\msgbind $(RESFILE) msg_adi $(OS_ID) $(PACKAGE) $(LOCALE) $(BASEDIR)

#
# Pre-compilation actions
#

prepare:
 -md $(CC_CODE)
 -md $(CC_CODE)\$(LOCALE)
 -md $(BASEDIR)
 -md $(BASEDIR)\tools
 -md $(BASEDIR)\arjcrypt
 -md $(BASEDIR)\sfxstub
 -md $(BASEDIR)\arjsfxv
 -md $(BASEDIR)\arjsfx
 -md $(BASEDIR)\arjsfxjr
 -md $(BASEDIR)\arj
 -md $(BASEDIR)\rearj
 -md $(BASEDIR)\register
 -md $(BASEDIR)\arjdisp

#
# Cleanup
#

cleanup:
 echo y|del $(CC_CODE)\$(LOCALE)\*.*
 echo y|del $(BASEDIR)\*.*
 echo y|del $(BASEDIR)\tools\*.*
 echo y|del $(BASEDIR)\arjcrypt\*.*
 echo y|del $(BASEDIR)\sfxstub\*.*
 echo y|del $(BASEDIR)\arjsfxv\*.*
 echo y|del $(BASEDIR)\arjsfx\*.*
 echo y|del $(BASEDIR)\arjsfxjr\*.*
 echo y|del $(BASEDIR)\arj\*.*
 echo y|del $(BASEDIR)\rearj\*.*
 echo y|del $(BASEDIR)\register\*.*
 echo y|del $(BASEDIR)\arjdisp\*.*

#
# Packaging
#

package: all
 -md retail
# Was: $(BASEDIR_P) $(BASEDIR)
 $(BASEDIR)\tools\packager $(BASEDIR) $(BASEDIR)
