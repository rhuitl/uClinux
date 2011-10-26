# Microsoft Developer Studio Generated NMAKE File, Based on snort.dsp
!IF "$(CFG)" == ""
CFG=SNORT - WIN32 MSSQL RELEASE
!MESSAGE No configuration specified. Defaulting to SNORT - WIN32 MSSQL RELEASE.
!ENDIF 

!IF "$(CFG)" != "snort - Win32 Release" && "$(CFG)" != "snort - Win32 Debug"  && "$(CFG)" != "snort - Win32 Flexresp Release" && "$(CFG)" != "snort - Win32 Flexresp Debug" && "$(CFG)" != "snort - Win32 MySQL Release" && "$(CFG)" != "snort - Win32 MySQL Debug" && "$(CFG)" != "snort - Win32 MSSQL Release" && "$(CFG)" != "snort - Win32 MSSQL Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "snort.mak" CFG="SNORT - WIN32 MSSQL RELEASE"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "snort - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 Flexresp Release" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 Flexresp Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 MySQL Release" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 MySQL Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 MSSQL Release" (based on "Win32 (x86) Console Application")
!MESSAGE "snort - Win32 MSSQL Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "snort - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\snort.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\Win32-Includes" /I "..\\" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\snort.pdb" /machine:I386 /out:"$(OUTDIR)\snort.exe" /libpath:"..\Win32-Libraries" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "$(OUTDIR)\snort.ilk"
	-@erase "$(OUTDIR)\snort.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\Win32-Includes" /I "..\\" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\snort.pdb" /debug /machine:I386 /nodefaultlib:"libcmt.lib" /out:"$(OUTDIR)\snort.exe" /pdbtype:sept /libpath:"..\Win32-Libraries" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"

OUTDIR=.\snort___Win32_MySQL_Debug
INTDIR=.\snort___Win32_MySQL_Debug
# Begin Custom Macros
OutDir=.\snort___Win32_MySQL_Debug
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "$(OUTDIR)\snort.ilk"
	-@erase "$(OUTDIR)\snort.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\\" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "ENABLE_MYSQL" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib mysqlclient.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\snort.pdb" /debug /machine:I386 /out:"$(OUTDIR)\snort.exe" /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"

OUTDIR=.\snort___Win32_Flexresp_Release
INTDIR=.\snort___Win32_Flexresp_Release
# Begin Custom Macros
OutDir=.\snort___Win32_Flexresp_Release
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\snort.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\Win32-Includes" /I "..\\" /I "..\Win32-Includes\libnet" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "ENABLE_RESPONSE" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib libnetnt.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\snort.pdb" /machine:I386 /out:"$(OUTDIR)\snort.exe" /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\libnet" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"

OUTDIR=.\snort___Win32_Flexresp_Debug
INTDIR=.\snort___Win32_Flexresp_Debug
# Begin Custom Macros
OutDir=.\snort___Win32_Flexresp_Debug
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "$(OUTDIR)\snort.ilk"
	-@erase "$(OUTDIR)\snort.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\Win32-Includes" /I "..\\" /I "..\Win32-Includes\libnet" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "ENABLE_RESPONSE" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib libnetnt.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\snort.pdb" /debug /machine:I386 /nodefaultlib:"libcmt.lib" /out:"$(OUTDIR)\snort.exe" /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\libnet" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

OUTDIR=.\snort___Win32_MySQL_Release
INTDIR=.\snort___Win32_MySQL_Release
# Begin Custom Macros
OutDir=.\snort___Win32_MySQL_Release
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe" "$(OUTDIR)\snort.bsc"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\avl_tree.sbr"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\checksum.sbr"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\codes.sbr"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\debug.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\getopt.sbr"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\log.sbr"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\misc.sbr"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mstring.sbr"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\parser.sbr"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\plugbase.sbr"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\rules.sbr"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort.sbr"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\snprintf.sbr"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_dsize_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.sbr"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.sbr"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.sbr"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_proto.sbr"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.sbr"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.sbr"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.sbr"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pattern_match.sbr"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_priority.sbr"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_react.sbr"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_reference.sbr"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_respond.sbr"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_rpc_check.sbr"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_session.sbr"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.sbr"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.sbr"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_fast.sbr"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_full.sbr"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_smb.sbr"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.sbr"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.sbr"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_csv.sbr"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_database.sbr"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.sbr"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_unified.sbr"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spo_xml.sbr"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_anomsensor.sbr"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_bo.sbr"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_defrag.sbr"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_http_decode.sbr"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_minfrag.sbr"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan.sbr"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.sbr"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.sbr"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\spp_unidecode.sbr"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcatu.sbr"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strlcpyu.sbr"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\syslog.sbr"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\tag.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\snort.bsc"
	-@erase "$(OUTDIR)\snort.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\Win32-Includes" /I "..\Win32-Includes\mysql" /I "..\\" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "ENABLE_MYSQL" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\avl_tree.sbr" \
	"$(INTDIR)\checksum.sbr" \
	"$(INTDIR)\codes.sbr" \
	"$(INTDIR)\debug.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\log.sbr" \
	"$(INTDIR)\mstring.sbr" \
	"$(INTDIR)\parser.sbr" \
	"$(INTDIR)\plugbase.sbr" \
	"$(INTDIR)\rules.sbr" \
	"$(INTDIR)\snort.sbr" \
	"$(INTDIR)\snprintf.sbr" \
	"$(INTDIR)\sp_dsize_check.sbr" \
	"$(INTDIR)\sp_icmp_code_check.sbr" \
	"$(INTDIR)\sp_icmp_id_check.sbr" \
	"$(INTDIR)\sp_icmp_seq_check.sbr" \
	"$(INTDIR)\sp_icmp_type_check.sbr" \
	"$(INTDIR)\sp_ip_fragbits.sbr" \
	"$(INTDIR)\sp_ip_id_check.sbr" \
	"$(INTDIR)\sp_ip_proto.sbr" \
	"$(INTDIR)\sp_ip_same_check.sbr" \
	"$(INTDIR)\sp_ip_tos_check.sbr" \
	"$(INTDIR)\sp_ipoption_check.sbr" \
	"$(INTDIR)\sp_pattern_match.sbr" \
	"$(INTDIR)\sp_priority.sbr" \
	"$(INTDIR)\sp_react.sbr" \
	"$(INTDIR)\sp_reference.sbr" \
	"$(INTDIR)\sp_respond.sbr" \
	"$(INTDIR)\sp_rpc_check.sbr" \
	"$(INTDIR)\sp_session.sbr" \
	"$(INTDIR)\sp_tcp_ack_check.sbr" \
	"$(INTDIR)\sp_tcp_flag_check.sbr" \
	"$(INTDIR)\sp_tcp_seq_check.sbr" \
	"$(INTDIR)\sp_tcp_win_check.sbr" \
	"$(INTDIR)\sp_ttl_check.sbr" \
	"$(INTDIR)\spo_alert_fast.sbr" \
	"$(INTDIR)\spo_alert_full.sbr" \
	"$(INTDIR)\spo_alert_smb.sbr" \
	"$(INTDIR)\spo_alert_syslog.sbr" \
	"$(INTDIR)\spo_alert_unixsock.sbr" \
	"$(INTDIR)\spo_csv.sbr" \
	"$(INTDIR)\spo_database.sbr" \
	"$(INTDIR)\spo_log_tcpdump.sbr" \
	"$(INTDIR)\spo_unified.sbr" \
	"$(INTDIR)\spo_xml.sbr" \
	"$(INTDIR)\spp_anomsensor.sbr" \
	"$(INTDIR)\spp_bo.sbr" \
	"$(INTDIR)\spp_defrag.sbr" \
	"$(INTDIR)\spp_http_decode.sbr" \
	"$(INTDIR)\spp_minfrag.sbr" \
	"$(INTDIR)\spp_portscan.sbr" \
	"$(INTDIR)\spp_rpc_decode.sbr" \
	"$(INTDIR)\spp_tcp_stream.sbr" \
	"$(INTDIR)\spp_tcp_stream2.sbr" \
	"$(INTDIR)\spp_tcp_stream3.sbr" \
	"$(INTDIR)\spp_telnet_negotiation.sbr" \
	"$(INTDIR)\spp_unidecode.sbr" \
	"$(INTDIR)\strlcatu.sbr" \
	"$(INTDIR)\strlcpyu.sbr" \
	"$(INTDIR)\tag.sbr" \
	"$(INTDIR)\getopt.sbr" \
	"$(INTDIR)\misc.sbr" \
	"$(INTDIR)\syslog.sbr"

"$(OUTDIR)\snort.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib mysqlclient.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\snort.pdb" /machine:I386 /out:"$(OUTDIR)\snort.exe" /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"

OUTDIR=.\snort___Win32_MSSQL_Release
INTDIR=.\snort___Win32_MSSQL_Release
# Begin Custom Macros
OutDir=.\snort___Win32_MSSQL_Release
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe" "$(OUTDIR)\snort.bsc"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\avl_tree.sbr"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\checksum.sbr"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\codes.sbr"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\debug.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\getopt.sbr"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\log.sbr"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\misc.sbr"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mstring.sbr"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\parser.sbr"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\plugbase.sbr"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\rules.sbr"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort.sbr"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\snprintf.sbr"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_dsize_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.sbr"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.sbr"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.sbr"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_proto.sbr"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.sbr"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.sbr"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.sbr"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pattern_match.sbr"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_priority.sbr"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_react.sbr"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_reference.sbr"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_respond.sbr"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_rpc_check.sbr"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_session.sbr"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.sbr"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.sbr"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_fast.sbr"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_full.sbr"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_smb.sbr"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.sbr"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.sbr"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_csv.sbr"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_database.sbr"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.sbr"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_unified.sbr"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spo_xml.sbr"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_anomsensor.sbr"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_bo.sbr"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_defrag.sbr"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_http_decode.sbr"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_minfrag.sbr"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan.sbr"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.sbr"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.sbr"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\spp_unidecode.sbr"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcatu.sbr"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strlcpyu.sbr"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\syslog.sbr"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\tag.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\snort.bsc"
	-@erase "$(OUTDIR)\snort.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\Win32-Includes" /I "..\\" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "ENABLE_MSSQL" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX"snort.pch" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\avl_tree.sbr" \
	"$(INTDIR)\checksum.sbr" \
	"$(INTDIR)\codes.sbr" \
	"$(INTDIR)\debug.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\log.sbr" \
	"$(INTDIR)\mstring.sbr" \
	"$(INTDIR)\parser.sbr" \
	"$(INTDIR)\plugbase.sbr" \
	"$(INTDIR)\rules.sbr" \
	"$(INTDIR)\snort.sbr" \
	"$(INTDIR)\snprintf.sbr" \
	"$(INTDIR)\sp_dsize_check.sbr" \
	"$(INTDIR)\sp_icmp_code_check.sbr" \
	"$(INTDIR)\sp_icmp_id_check.sbr" \
	"$(INTDIR)\sp_icmp_seq_check.sbr" \
	"$(INTDIR)\sp_icmp_type_check.sbr" \
	"$(INTDIR)\sp_ip_fragbits.sbr" \
	"$(INTDIR)\sp_ip_id_check.sbr" \
	"$(INTDIR)\sp_ip_proto.sbr" \
	"$(INTDIR)\sp_ip_same_check.sbr" \
	"$(INTDIR)\sp_ip_tos_check.sbr" \
	"$(INTDIR)\sp_ipoption_check.sbr" \
	"$(INTDIR)\sp_pattern_match.sbr" \
	"$(INTDIR)\sp_priority.sbr" \
	"$(INTDIR)\sp_react.sbr" \
	"$(INTDIR)\sp_reference.sbr" \
	"$(INTDIR)\sp_respond.sbr" \
	"$(INTDIR)\sp_rpc_check.sbr" \
	"$(INTDIR)\sp_session.sbr" \
	"$(INTDIR)\sp_tcp_ack_check.sbr" \
	"$(INTDIR)\sp_tcp_flag_check.sbr" \
	"$(INTDIR)\sp_tcp_seq_check.sbr" \
	"$(INTDIR)\sp_tcp_win_check.sbr" \
	"$(INTDIR)\sp_ttl_check.sbr" \
	"$(INTDIR)\spo_alert_fast.sbr" \
	"$(INTDIR)\spo_alert_full.sbr" \
	"$(INTDIR)\spo_alert_smb.sbr" \
	"$(INTDIR)\spo_alert_syslog.sbr" \
	"$(INTDIR)\spo_alert_unixsock.sbr" \
	"$(INTDIR)\spo_csv.sbr" \
	"$(INTDIR)\spo_database.sbr" \
	"$(INTDIR)\spo_log_tcpdump.sbr" \
	"$(INTDIR)\spo_unified.sbr" \
	"$(INTDIR)\spo_xml.sbr" \
	"$(INTDIR)\spp_anomsensor.sbr" \
	"$(INTDIR)\spp_bo.sbr" \
	"$(INTDIR)\spp_defrag.sbr" \
	"$(INTDIR)\spp_http_decode.sbr" \
	"$(INTDIR)\spp_minfrag.sbr" \
	"$(INTDIR)\spp_portscan.sbr" \
	"$(INTDIR)\spp_rpc_decode.sbr" \
	"$(INTDIR)\spp_tcp_stream.sbr" \
	"$(INTDIR)\spp_tcp_stream2.sbr" \
	"$(INTDIR)\spp_tcp_stream3.sbr" \
	"$(INTDIR)\spp_telnet_negotiation.sbr" \
	"$(INTDIR)\spp_unidecode.sbr" \
	"$(INTDIR)\strlcatu.sbr" \
	"$(INTDIR)\strlcpyu.sbr" \
	"$(INTDIR)\tag.sbr" \
	"$(INTDIR)\getopt.sbr" \
	"$(INTDIR)\misc.sbr" \
	"$(INTDIR)\syslog.sbr"

"$(OUTDIR)\snort.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib Ntwdblib.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\snort.pdb" /machine:I386 /out:"$(OUTDIR)\snort.exe" /libpath:"..\Win32-Libraries" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"

OUTDIR=.\snort___Win32_MSSQL_Debug
INTDIR=.\snort___Win32_MSSQL_Debug
# Begin Custom Macros
OutDir=.\snort___Win32_MSSQL_Debug
# End Custom Macros

ALL : "$(OUTDIR)\snort.exe" "$(OUTDIR)\snort.bsc"


CLEAN :
	-@erase "$(INTDIR)\avl_tree.obj"
	-@erase "$(INTDIR)\avl_tree.sbr"
	-@erase "$(INTDIR)\checksum.obj"
	-@erase "$(INTDIR)\checksum.sbr"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\codes.sbr"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\debug.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\getopt.sbr"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\log.sbr"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\misc.sbr"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mstring.sbr"
	-@erase "$(INTDIR)\name.res"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\parser.sbr"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\plugbase.sbr"
	-@erase "$(INTDIR)\rules.obj"
	-@erase "$(INTDIR)\rules.sbr"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort.sbr"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\snprintf.sbr"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_dsize_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_code_check.obj"
	-@erase "$(INTDIR)\sp_icmp_code_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_id_check.obj"
	-@erase "$(INTDIR)\sp_icmp_id_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_seq_check.obj"
	-@erase "$(INTDIR)\sp_icmp_seq_check.sbr"
	-@erase "$(INTDIR)\sp_icmp_type_check.obj"
	-@erase "$(INTDIR)\sp_icmp_type_check.sbr"
	-@erase "$(INTDIR)\sp_ip_fragbits.obj"
	-@erase "$(INTDIR)\sp_ip_fragbits.sbr"
	-@erase "$(INTDIR)\sp_ip_id_check.obj"
	-@erase "$(INTDIR)\sp_ip_id_check.sbr"
	-@erase "$(INTDIR)\sp_ip_proto.obj"
	-@erase "$(INTDIR)\sp_ip_proto.sbr"
	-@erase "$(INTDIR)\sp_ip_same_check.obj"
	-@erase "$(INTDIR)\sp_ip_same_check.sbr"
	-@erase "$(INTDIR)\sp_ip_tos_check.obj"
	-@erase "$(INTDIR)\sp_ip_tos_check.sbr"
	-@erase "$(INTDIR)\sp_ipoption_check.obj"
	-@erase "$(INTDIR)\sp_ipoption_check.sbr"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pattern_match.sbr"
	-@erase "$(INTDIR)\sp_priority.obj"
	-@erase "$(INTDIR)\sp_priority.sbr"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_react.sbr"
	-@erase "$(INTDIR)\sp_reference.obj"
	-@erase "$(INTDIR)\sp_reference.sbr"
	-@erase "$(INTDIR)\sp_respond.obj"
	-@erase "$(INTDIR)\sp_respond.sbr"
	-@erase "$(INTDIR)\sp_rpc_check.obj"
	-@erase "$(INTDIR)\sp_rpc_check.sbr"
	-@erase "$(INTDIR)\sp_session.obj"
	-@erase "$(INTDIR)\sp_session.sbr"
	-@erase "$(INTDIR)\sp_tcp_ack_check.obj"
	-@erase "$(INTDIR)\sp_tcp_ack_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_flag_check.obj"
	-@erase "$(INTDIR)\sp_tcp_flag_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_seq_check.obj"
	-@erase "$(INTDIR)\sp_tcp_seq_check.sbr"
	-@erase "$(INTDIR)\sp_tcp_win_check.obj"
	-@erase "$(INTDIR)\sp_tcp_win_check.sbr"
	-@erase "$(INTDIR)\sp_ttl_check.obj"
	-@erase "$(INTDIR)\sp_ttl_check.sbr"
	-@erase "$(INTDIR)\spo_alert_fast.obj"
	-@erase "$(INTDIR)\spo_alert_fast.sbr"
	-@erase "$(INTDIR)\spo_alert_full.obj"
	-@erase "$(INTDIR)\spo_alert_full.sbr"
	-@erase "$(INTDIR)\spo_alert_smb.obj"
	-@erase "$(INTDIR)\spo_alert_smb.sbr"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.sbr"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.sbr"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_csv.sbr"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_database.sbr"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.sbr"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_unified.sbr"
	-@erase "$(INTDIR)\spo_xml.obj"
	-@erase "$(INTDIR)\spo_xml.sbr"
	-@erase "$(INTDIR)\spp_anomsensor.obj"
	-@erase "$(INTDIR)\spp_anomsensor.sbr"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_bo.sbr"
	-@erase "$(INTDIR)\spp_defrag.obj"
	-@erase "$(INTDIR)\spp_defrag.sbr"
	-@erase "$(INTDIR)\spp_http_decode.obj"
	-@erase "$(INTDIR)\spp_http_decode.sbr"
	-@erase "$(INTDIR)\spp_minfrag.obj"
	-@erase "$(INTDIR)\spp_minfrag.sbr"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan.sbr"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream.obj"
	-@erase "$(INTDIR)\spp_tcp_stream.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream2.obj"
	-@erase "$(INTDIR)\spp_tcp_stream2.sbr"
	-@erase "$(INTDIR)\spp_tcp_stream3.obj"
	-@erase "$(INTDIR)\spp_tcp_stream3.sbr"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.sbr"
	-@erase "$(INTDIR)\spp_unidecode.obj"
	-@erase "$(INTDIR)\spp_unidecode.sbr"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcatu.sbr"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strlcpyu.sbr"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\syslog.sbr"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\tag.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\snort.bsc"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "$(OUTDIR)\snort.ilk"
	-@erase "$(OUTDIR)\snort.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\Win32-Includes" /I "..\\" /D "WIN32" /D "DEBUG" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MSSQL" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX"snort.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\avl_tree.sbr" \
	"$(INTDIR)\checksum.sbr" \
	"$(INTDIR)\codes.sbr" \
	"$(INTDIR)\debug.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\log.sbr" \
	"$(INTDIR)\mstring.sbr" \
	"$(INTDIR)\parser.sbr" \
	"$(INTDIR)\plugbase.sbr" \
	"$(INTDIR)\rules.sbr" \
	"$(INTDIR)\snort.sbr" \
	"$(INTDIR)\snprintf.sbr" \
	"$(INTDIR)\sp_dsize_check.sbr" \
	"$(INTDIR)\sp_icmp_code_check.sbr" \
	"$(INTDIR)\sp_icmp_id_check.sbr" \
	"$(INTDIR)\sp_icmp_seq_check.sbr" \
	"$(INTDIR)\sp_icmp_type_check.sbr" \
	"$(INTDIR)\sp_ip_fragbits.sbr" \
	"$(INTDIR)\sp_ip_id_check.sbr" \
	"$(INTDIR)\sp_ip_proto.sbr" \
	"$(INTDIR)\sp_ip_same_check.sbr" \
	"$(INTDIR)\sp_ip_tos_check.sbr" \
	"$(INTDIR)\sp_ipoption_check.sbr" \
	"$(INTDIR)\sp_pattern_match.sbr" \
	"$(INTDIR)\sp_priority.sbr" \
	"$(INTDIR)\sp_react.sbr" \
	"$(INTDIR)\sp_reference.sbr" \
	"$(INTDIR)\sp_respond.sbr" \
	"$(INTDIR)\sp_rpc_check.sbr" \
	"$(INTDIR)\sp_session.sbr" \
	"$(INTDIR)\sp_tcp_ack_check.sbr" \
	"$(INTDIR)\sp_tcp_flag_check.sbr" \
	"$(INTDIR)\sp_tcp_seq_check.sbr" \
	"$(INTDIR)\sp_tcp_win_check.sbr" \
	"$(INTDIR)\sp_ttl_check.sbr" \
	"$(INTDIR)\spo_alert_fast.sbr" \
	"$(INTDIR)\spo_alert_full.sbr" \
	"$(INTDIR)\spo_alert_smb.sbr" \
	"$(INTDIR)\spo_alert_syslog.sbr" \
	"$(INTDIR)\spo_alert_unixsock.sbr" \
	"$(INTDIR)\spo_csv.sbr" \
	"$(INTDIR)\spo_database.sbr" \
	"$(INTDIR)\spo_log_tcpdump.sbr" \
	"$(INTDIR)\spo_unified.sbr" \
	"$(INTDIR)\spo_xml.sbr" \
	"$(INTDIR)\spp_anomsensor.sbr" \
	"$(INTDIR)\spp_bo.sbr" \
	"$(INTDIR)\spp_defrag.sbr" \
	"$(INTDIR)\spp_http_decode.sbr" \
	"$(INTDIR)\spp_minfrag.sbr" \
	"$(INTDIR)\spp_portscan.sbr" \
	"$(INTDIR)\spp_rpc_decode.sbr" \
	"$(INTDIR)\spp_tcp_stream.sbr" \
	"$(INTDIR)\spp_tcp_stream2.sbr" \
	"$(INTDIR)\spp_tcp_stream3.sbr" \
	"$(INTDIR)\spp_telnet_negotiation.sbr" \
	"$(INTDIR)\spp_unidecode.sbr" \
	"$(INTDIR)\strlcatu.sbr" \
	"$(INTDIR)\strlcpyu.sbr" \
	"$(INTDIR)\tag.sbr" \
	"$(INTDIR)\getopt.sbr" \
	"$(INTDIR)\misc.sbr" \
	"$(INTDIR)\syslog.sbr"

"$(OUTDIR)\snort.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib libpcap.lib advapi32.lib Ntwdblib.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\snort.pdb" /debug /machine:I386 /out:"$(OUTDIR)\snort.exe" /pdbtype:sept /libpath:"..\Win32-Libraries" 
LINK32_OBJS= \
	"$(INTDIR)\avl_tree.obj" \
	"$(INTDIR)\checksum.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\rules.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_icmp_code_check.obj" \
	"$(INTDIR)\sp_icmp_id_check.obj" \
	"$(INTDIR)\sp_icmp_seq_check.obj" \
	"$(INTDIR)\sp_icmp_type_check.obj" \
	"$(INTDIR)\sp_ip_fragbits.obj" \
	"$(INTDIR)\sp_ip_id_check.obj" \
	"$(INTDIR)\sp_ip_proto.obj" \
	"$(INTDIR)\sp_ip_same_check.obj" \
	"$(INTDIR)\sp_ip_tos_check.obj" \
	"$(INTDIR)\sp_ipoption_check.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_priority.obj" \
	"$(INTDIR)\sp_react.obj" \
	"$(INTDIR)\sp_reference.obj" \
	"$(INTDIR)\sp_respond.obj" \
	"$(INTDIR)\sp_rpc_check.obj" \
	"$(INTDIR)\sp_session.obj" \
	"$(INTDIR)\sp_tcp_ack_check.obj" \
	"$(INTDIR)\sp_tcp_flag_check.obj" \
	"$(INTDIR)\sp_tcp_seq_check.obj" \
	"$(INTDIR)\sp_tcp_win_check.obj" \
	"$(INTDIR)\sp_ttl_check.obj" \
	"$(INTDIR)\spo_alert_fast.obj" \
	"$(INTDIR)\spo_alert_full.obj" \
	"$(INTDIR)\spo_alert_smb.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\spo_xml.obj" \
	"$(INTDIR)\spp_anomsensor.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_defrag.obj" \
	"$(INTDIR)\spp_http_decode.obj" \
	"$(INTDIR)\spp_minfrag.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_tcp_stream.obj" \
	"$(INTDIR)\spp_tcp_stream2.obj" \
	"$(INTDIR)\spp_tcp_stream3.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_unidecode.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("snort.dep")
!INCLUDE "snort.dep"
!ELSE 
!MESSAGE Warning: cannot find "snort.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "snort - Win32 Release" || "$(CFG)" == "snort - Win32 Debug" || "$(CFG)" == "snort - Win32 MySQL Debug" || "$(CFG)" == "snort - Win32 Flexresp Release" || "$(CFG)" == "snort - Win32 Flexresp Debug" || "$(CFG)" == "snort - Win32 MySQL Release" || "$(CFG)" == "snort - Win32 MSSQL Release" || "$(CFG)" == "snort - Win32 MSSQL Debug"
SOURCE=..\avl_tree.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\avl_tree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\avl_tree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\avl_tree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\avl_tree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\avl_tree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\avl_tree.obj"	"$(INTDIR)\avl_tree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\avl_tree.obj"	"$(INTDIR)\avl_tree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\avl_tree.obj"	"$(INTDIR)\avl_tree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\checksum.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\checksum.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\checksum.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\checksum.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\checksum.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\checksum.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\checksum.obj"	"$(INTDIR)\checksum.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\checksum.obj"	"$(INTDIR)\checksum.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\checksum.obj"	"$(INTDIR)\checksum.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\codes.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\codes.obj"	"$(INTDIR)\codes.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\codes.obj"	"$(INTDIR)\codes.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\codes.obj"	"$(INTDIR)\codes.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\debug.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\debug.obj"	"$(INTDIR)\debug.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\debug.obj"	"$(INTDIR)\debug.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\debug.obj"	"$(INTDIR)\debug.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\decode.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\decode.obj"	"$(INTDIR)\decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\decode.obj"	"$(INTDIR)\decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\decode.obj"	"$(INTDIR)\decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\log.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\log.obj"	"$(INTDIR)\log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\log.obj"	"$(INTDIR)\log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\log.obj"	"$(INTDIR)\log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\mstring.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\mstring.obj"	"$(INTDIR)\mstring.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\mstring.obj"	"$(INTDIR)\mstring.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\mstring.obj"	"$(INTDIR)\mstring.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\parser.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\parser.obj"	"$(INTDIR)\parser.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\parser.obj"	"$(INTDIR)\parser.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\parser.obj"	"$(INTDIR)\parser.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\plugbase.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\plugbase.obj"	"$(INTDIR)\plugbase.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\plugbase.obj"	"$(INTDIR)\plugbase.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\plugbase.obj"	"$(INTDIR)\plugbase.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\rules.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\rules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\rules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\rules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\rules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\rules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\rules.obj"	"$(INTDIR)\rules.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\rules.obj"	"$(INTDIR)\rules.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\rules.obj"	"$(INTDIR)\rules.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\snort.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\snort.obj"	"$(INTDIR)\snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\snort.obj"	"$(INTDIR)\snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\snort.obj"	"$(INTDIR)\snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\snprintf.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\snprintf.obj"	"$(INTDIR)\snprintf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\snprintf.obj"	"$(INTDIR)\snprintf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\snprintf.obj"	"$(INTDIR)\snprintf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_dsize_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_dsize_check.obj"	"$(INTDIR)\sp_dsize_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_dsize_check.obj"	"$(INTDIR)\sp_dsize_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_dsize_check.obj"	"$(INTDIR)\sp_dsize_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_icmp_code_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_code_check.obj"	"$(INTDIR)\sp_icmp_code_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_icmp_code_check.obj"	"$(INTDIR)\sp_icmp_code_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_icmp_code_check.obj"	"$(INTDIR)\sp_icmp_code_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_icmp_id_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_id_check.obj"	"$(INTDIR)\sp_icmp_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_icmp_id_check.obj"	"$(INTDIR)\sp_icmp_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_icmp_id_check.obj"	"$(INTDIR)\sp_icmp_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_icmp_seq_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_seq_check.obj"	"$(INTDIR)\sp_icmp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_icmp_seq_check.obj"	"$(INTDIR)\sp_icmp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_icmp_seq_check.obj"	"$(INTDIR)\sp_icmp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_icmp_type_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_type_check.obj"	"$(INTDIR)\sp_icmp_type_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_icmp_type_check.obj"	"$(INTDIR)\sp_icmp_type_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_icmp_type_check.obj"	"$(INTDIR)\sp_icmp_type_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_ip_fragbits.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_fragbits.obj"	"$(INTDIR)\sp_ip_fragbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_ip_fragbits.obj"	"$(INTDIR)\sp_ip_fragbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_ip_fragbits.obj"	"$(INTDIR)\sp_ip_fragbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_ip_id_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_id_check.obj"	"$(INTDIR)\sp_ip_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_ip_id_check.obj"	"$(INTDIR)\sp_ip_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_ip_id_check.obj"	"$(INTDIR)\sp_ip_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_ip_proto.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_proto.obj"	"$(INTDIR)\sp_ip_proto.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_ip_proto.obj"	"$(INTDIR)\sp_ip_proto.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_ip_proto.obj"	"$(INTDIR)\sp_ip_proto.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_ip_same_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_same_check.obj"	"$(INTDIR)\sp_ip_same_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_ip_same_check.obj"	"$(INTDIR)\sp_ip_same_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_ip_same_check.obj"	"$(INTDIR)\sp_ip_same_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_ip_tos_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_tos_check.obj"	"$(INTDIR)\sp_ip_tos_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_ip_tos_check.obj"	"$(INTDIR)\sp_ip_tos_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_ip_tos_check.obj"	"$(INTDIR)\sp_ip_tos_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_ipoption_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ipoption_check.obj"	"$(INTDIR)\sp_ipoption_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_ipoption_check.obj"	"$(INTDIR)\sp_ipoption_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_ipoption_check.obj"	"$(INTDIR)\sp_ipoption_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_pattern_match.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_pattern_match.obj"	"$(INTDIR)\sp_pattern_match.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_pattern_match.obj"	"$(INTDIR)\sp_pattern_match.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_pattern_match.obj"	"$(INTDIR)\sp_pattern_match.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_priority.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_priority.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_priority.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_priority.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_priority.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_priority.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_priority.obj"	"$(INTDIR)\sp_priority.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_priority.obj"	"$(INTDIR)\sp_priority.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_priority.obj"	"$(INTDIR)\sp_priority.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_react.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_react.obj"	"$(INTDIR)\sp_react.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_react.obj"	"$(INTDIR)\sp_react.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_react.obj"	"$(INTDIR)\sp_react.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_reference.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_reference.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_reference.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_reference.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_reference.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_reference.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_reference.obj"	"$(INTDIR)\sp_reference.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_reference.obj"	"$(INTDIR)\sp_reference.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_reference.obj"	"$(INTDIR)\sp_reference.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_respond.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_respond.obj"	"$(INTDIR)\sp_respond.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_respond.obj"	"$(INTDIR)\sp_respond.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_respond.obj"	"$(INTDIR)\sp_respond.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_rpc_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_rpc_check.obj"	"$(INTDIR)\sp_rpc_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_rpc_check.obj"	"$(INTDIR)\sp_rpc_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_rpc_check.obj"	"$(INTDIR)\sp_rpc_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_session.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_session.obj"	"$(INTDIR)\sp_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_session.obj"	"$(INTDIR)\sp_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_session.obj"	"$(INTDIR)\sp_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_tcp_ack_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_ack_check.obj"	"$(INTDIR)\sp_tcp_ack_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_tcp_ack_check.obj"	"$(INTDIR)\sp_tcp_ack_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_tcp_ack_check.obj"	"$(INTDIR)\sp_tcp_ack_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_tcp_flag_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_flag_check.obj"	"$(INTDIR)\sp_tcp_flag_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_tcp_flag_check.obj"	"$(INTDIR)\sp_tcp_flag_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_tcp_flag_check.obj"	"$(INTDIR)\sp_tcp_flag_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_tcp_seq_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_seq_check.obj"	"$(INTDIR)\sp_tcp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_tcp_seq_check.obj"	"$(INTDIR)\sp_tcp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_tcp_seq_check.obj"	"$(INTDIR)\sp_tcp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_tcp_win_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_win_check.obj"	"$(INTDIR)\sp_tcp_win_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_tcp_win_check.obj"	"$(INTDIR)\sp_tcp_win_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_tcp_win_check.obj"	"$(INTDIR)\sp_tcp_win_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\sp_ttl_check.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ttl_check.obj"	"$(INTDIR)\sp_ttl_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\sp_ttl_check.obj"	"$(INTDIR)\sp_ttl_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\sp_ttl_check.obj"	"$(INTDIR)\sp_ttl_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_alert_fast.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_fast.obj"	"$(INTDIR)\spo_alert_fast.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_alert_fast.obj"	"$(INTDIR)\spo_alert_fast.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_alert_fast.obj"	"$(INTDIR)\spo_alert_fast.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_alert_full.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_full.obj"	"$(INTDIR)\spo_alert_full.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_alert_full.obj"	"$(INTDIR)\spo_alert_full.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_alert_full.obj"	"$(INTDIR)\spo_alert_full.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_alert_smb.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_alert_smb.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_alert_smb.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_smb.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_alert_smb.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_alert_smb.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_smb.obj"	"$(INTDIR)\spo_alert_smb.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_alert_smb.obj"	"$(INTDIR)\spo_alert_smb.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_alert_smb.obj"	"$(INTDIR)\spo_alert_smb.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_alert_syslog.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_syslog.obj"	"$(INTDIR)\spo_alert_syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_alert_syslog.obj"	"$(INTDIR)\spo_alert_syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_alert_syslog.obj"	"$(INTDIR)\spo_alert_syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_alert_unixsock.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_unixsock.obj"	"$(INTDIR)\spo_alert_unixsock.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_alert_unixsock.obj"	"$(INTDIR)\spo_alert_unixsock.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_alert_unixsock.obj"	"$(INTDIR)\spo_alert_unixsock.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_csv.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_csv.obj"	"$(INTDIR)\spo_csv.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_csv.obj"	"$(INTDIR)\spo_csv.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_csv.obj"	"$(INTDIR)\spo_csv.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_database.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_database.obj"	"$(INTDIR)\spo_database.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_database.obj"	"$(INTDIR)\spo_database.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_database.obj"	"$(INTDIR)\spo_database.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_log_tcpdump.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_log_tcpdump.obj"	"$(INTDIR)\spo_log_tcpdump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_log_tcpdump.obj"	"$(INTDIR)\spo_log_tcpdump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_log_tcpdump.obj"	"$(INTDIR)\spo_log_tcpdump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_unified.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_unified.obj"	"$(INTDIR)\spo_unified.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_unified.obj"	"$(INTDIR)\spo_unified.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_unified.obj"	"$(INTDIR)\spo_unified.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spo_xml.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spo_xml.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spo_xml.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_xml.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spo_xml.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spo_xml.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_xml.obj"	"$(INTDIR)\spo_xml.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spo_xml.obj"	"$(INTDIR)\spo_xml.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spo_xml.obj"	"$(INTDIR)\spo_xml.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_anomsensor.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_anomsensor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_anomsensor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_anomsensor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_anomsensor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_anomsensor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_anomsensor.obj"	"$(INTDIR)\spp_anomsensor.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_anomsensor.obj"	"$(INTDIR)\spp_anomsensor.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_anomsensor.obj"	"$(INTDIR)\spp_anomsensor.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_bo.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_bo.obj"	"$(INTDIR)\spp_bo.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_bo.obj"	"$(INTDIR)\spp_bo.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_bo.obj"	"$(INTDIR)\spp_bo.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_defrag.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_defrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_defrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_defrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_defrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_defrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_defrag.obj"	"$(INTDIR)\spp_defrag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_defrag.obj"	"$(INTDIR)\spp_defrag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_defrag.obj"	"$(INTDIR)\spp_defrag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_http_decode.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_http_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_http_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_http_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_http_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_http_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_http_decode.obj"	"$(INTDIR)\spp_http_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_http_decode.obj"	"$(INTDIR)\spp_http_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_http_decode.obj"	"$(INTDIR)\spp_http_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_minfrag.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_minfrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_minfrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_minfrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_minfrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_minfrag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_minfrag.obj"	"$(INTDIR)\spp_minfrag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_minfrag.obj"	"$(INTDIR)\spp_minfrag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_minfrag.obj"	"$(INTDIR)\spp_minfrag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_portscan.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_portscan.obj"	"$(INTDIR)\spp_portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_portscan.obj"	"$(INTDIR)\spp_portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_portscan.obj"	"$(INTDIR)\spp_portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_rpc_decode.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_rpc_decode.obj"	"$(INTDIR)\spp_rpc_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_rpc_decode.obj"	"$(INTDIR)\spp_rpc_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_rpc_decode.obj"	"$(INTDIR)\spp_rpc_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_tcp_stream.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_tcp_stream.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_tcp_stream.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_tcp_stream.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_tcp_stream.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_tcp_stream.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_tcp_stream.obj"	"$(INTDIR)\spp_tcp_stream.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_tcp_stream.obj"	"$(INTDIR)\spp_tcp_stream.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_tcp_stream.obj"	"$(INTDIR)\spp_tcp_stream.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_tcp_stream2.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_tcp_stream2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_tcp_stream2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_tcp_stream2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_tcp_stream2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_tcp_stream2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_tcp_stream2.obj"	"$(INTDIR)\spp_tcp_stream2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_tcp_stream2.obj"	"$(INTDIR)\spp_tcp_stream2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_tcp_stream2.obj"	"$(INTDIR)\spp_tcp_stream2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_tcp_stream3.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_tcp_stream3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_tcp_stream3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_tcp_stream3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_tcp_stream3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_tcp_stream3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_tcp_stream3.obj"	"$(INTDIR)\spp_tcp_stream3.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_tcp_stream3.obj"	"$(INTDIR)\spp_tcp_stream3.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_tcp_stream3.obj"	"$(INTDIR)\spp_tcp_stream3.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_telnet_negotiation.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_telnet_negotiation.obj"	"$(INTDIR)\spp_telnet_negotiation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_telnet_negotiation.obj"	"$(INTDIR)\spp_telnet_negotiation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_telnet_negotiation.obj"	"$(INTDIR)\spp_telnet_negotiation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\spp_unidecode.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\spp_unidecode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\spp_unidecode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_unidecode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\spp_unidecode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\spp_unidecode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_unidecode.obj"	"$(INTDIR)\spp_unidecode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\spp_unidecode.obj"	"$(INTDIR)\spp_unidecode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\spp_unidecode.obj"	"$(INTDIR)\spp_unidecode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\strlcatu.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\strlcatu.obj"	"$(INTDIR)\strlcatu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\strlcatu.obj"	"$(INTDIR)\strlcatu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\strlcatu.obj"	"$(INTDIR)\strlcatu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\strlcpyu.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\strlcpyu.obj"	"$(INTDIR)\strlcpyu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\strlcpyu.obj"	"$(INTDIR)\strlcpyu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\strlcpyu.obj"	"$(INTDIR)\strlcpyu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\tag.c

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\tag.obj"	"$(INTDIR)\tag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\tag.obj"	"$(INTDIR)\tag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\tag.obj"	"$(INTDIR)\tag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\name.rc"

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "_DEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "_DEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "_DEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\name.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\name.res" /i "\Users\Download\Snort\snort-1.8\WIN32-Code" /d "_DEBUG" $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\getopt.c"

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\getopt.obj"	"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\getopt.obj"	"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\getopt.obj"	"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\misc.c"

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\misc.obj"	"$(INTDIR)\misc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\misc.obj"	"$(INTDIR)\misc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\misc.obj"	"$(INTDIR)\misc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\syslog.c"

!IF  "$(CFG)" == "snort - Win32 Release"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Debug"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Release"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Flexresp Debug"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\syslog.obj"	"$(INTDIR)\syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Release"


"$(INTDIR)\syslog.obj"	"$(INTDIR)\syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MSSQL Debug"


"$(INTDIR)\syslog.obj"	"$(INTDIR)\syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 


!ENDIF 

