# Microsoft Developer Studio Generated NMAKE File, Based on snort.dsp
!IF "$(CFG)" == ""
CFG=snort - Win32 Oracle Debug
!MESSAGE No configuration specified. Defaulting to snort - Win32 Oracle Debug.
!ENDIF 

!IF "$(CFG)" != "snort - Win32 MySQL Debug" && "$(CFG)" != "snort - Win32 MySQL Release" && "$(CFG)" != "snort - Win32 SQLServer Debug" && "$(CFG)" != "snort - Win32 SQLServer Release" && "$(CFG)" != "snort - Win32 Oracle Debug" && "$(CFG)" != "snort - Win32 Oracle Release"
!MESSAGE Invalid configuration "$(CFG)" specified.
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
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

OUTDIR=.\snort___Win32_MySQL_Debug
INTDIR=.\snort___Win32_MySQL_Debug
# Begin Custom Macros
OutDir=.\snort___Win32_MySQL_Debug
# End Custom Macros

ALL : "..\WIN32-Code\name.rc" "..\WIN32-Code\name.h" "..\WIN32-Code\MSG00001.BIN" "$(OUTDIR)\snort.exe" "$(OUTDIR)\snort.bsc"


CLEAN :
	-@erase "$(INTDIR)\acsmx.obj"
	-@erase "$(INTDIR)\acsmx.sbr"
	-@erase "$(INTDIR)\acsmx2.obj"
	-@erase "$(INTDIR)\acsmx2.sbr"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\asn1.sbr"
	-@erase "$(INTDIR)\byte_extract.obj"
	-@erase "$(INTDIR)\byte_extract.sbr"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\codes.sbr"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\debug.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\detect.obj"
	-@erase "$(INTDIR)\detect.sbr"
	-@erase "$(INTDIR)\event_queue.obj"
	-@erase "$(INTDIR)\event_queue.sbr"
	-@erase "$(INTDIR)\event_wrapper.obj"
	-@erase "$(INTDIR)\event_wrapper.sbr"
	-@erase "$(INTDIR)\flow.obj"
	-@erase "$(INTDIR)\flow.sbr"
	-@erase "$(INTDIR)\flow_cache.obj"
	-@erase "$(INTDIR)\flow_cache.sbr"
	-@erase "$(INTDIR)\flow_callback.obj"
	-@erase "$(INTDIR)\flow_callback.sbr"
	-@erase "$(INTDIR)\flow_class.obj"
	-@erase "$(INTDIR)\flow_class.sbr"
	-@erase "$(INTDIR)\flow_hash.obj"
	-@erase "$(INTDIR)\flow_hash.sbr"
	-@erase "$(INTDIR)\flow_packet.obj"
	-@erase "$(INTDIR)\flow_packet.sbr"
	-@erase "$(INTDIR)\flow_print.obj"
	-@erase "$(INTDIR)\flow_print.sbr"
	-@erase "$(INTDIR)\flow_stat.obj"
	-@erase "$(INTDIR)\flow_stat.sbr"
	-@erase "$(INTDIR)\flowps.obj"
	-@erase "$(INTDIR)\flowps.sbr"
	-@erase "$(INTDIR)\flowps_snort.obj"
	-@erase "$(INTDIR)\flowps_snort.sbr"
	-@erase "$(INTDIR)\fpcreate.obj"
	-@erase "$(INTDIR)\fpcreate.sbr"
	-@erase "$(INTDIR)\fpdetect.obj"
	-@erase "$(INTDIR)\fpdetect.sbr"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\getopt.sbr"
	-@erase "$(INTDIR)\hi_ad.obj"
	-@erase "$(INTDIR)\hi_ad.sbr"
	-@erase "$(INTDIR)\hi_client.obj"
	-@erase "$(INTDIR)\hi_client.sbr"
	-@erase "$(INTDIR)\hi_client_norm.obj"
	-@erase "$(INTDIR)\hi_client_norm.sbr"
	-@erase "$(INTDIR)\hi_eo_log.obj"
	-@erase "$(INTDIR)\hi_eo_log.sbr"
	-@erase "$(INTDIR)\hi_mi.obj"
	-@erase "$(INTDIR)\hi_mi.sbr"
	-@erase "$(INTDIR)\hi_norm.obj"
	-@erase "$(INTDIR)\hi_norm.sbr"
	-@erase "$(INTDIR)\hi_server.obj"
	-@erase "$(INTDIR)\hi_server.sbr"
	-@erase "$(INTDIR)\hi_si.obj"
	-@erase "$(INTDIR)\hi_si.sbr"
	-@erase "$(INTDIR)\hi_ui_config.obj"
	-@erase "$(INTDIR)\hi_ui_config.sbr"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.obj"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.sbr"
	-@erase "$(INTDIR)\hi_ui_server_lookup.obj"
	-@erase "$(INTDIR)\hi_ui_server_lookup.sbr"
	-@erase "$(INTDIR)\hi_util_hbm.obj"
	-@erase "$(INTDIR)\hi_util_hbm.sbr"
	-@erase "$(INTDIR)\hi_util_kmap.obj"
	-@erase "$(INTDIR)\hi_util_kmap.sbr"
	-@erase "$(INTDIR)\hi_util_xmalloc.obj"
	-@erase "$(INTDIR)\hi_util_xmalloc.sbr"
	-@erase "$(INTDIR)\inet_aton.obj"
	-@erase "$(INTDIR)\inet_aton.sbr"
	-@erase "$(INTDIR)\inline.obj"
	-@erase "$(INTDIR)\inline.sbr"
	-@erase "$(INTDIR)\IpAddrSet.obj"
	-@erase "$(INTDIR)\IpAddrSet.sbr"
	-@erase "$(INTDIR)\ipobj.obj"
	-@erase "$(INTDIR)\ipobj.sbr"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\log.sbr"
	-@erase "$(INTDIR)\mempool.obj"
	-@erase "$(INTDIR)\mempool.sbr"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\misc.sbr"
	-@erase "$(INTDIR)\mpse.obj"
	-@erase "$(INTDIR)\mpse.sbr"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mstring.sbr"
	-@erase "$(INTDIR)\mwm.obj"
	-@erase "$(INTDIR)\mwm.sbr"
	-@erase "$(INTDIR)\packet_time.obj"
	-@erase "$(INTDIR)\packet_time.sbr"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\parser.sbr"
	-@erase "$(INTDIR)\pcrm.obj"
	-@erase "$(INTDIR)\pcrm.sbr"
	-@erase "$(INTDIR)\perf-base.obj"
	-@erase "$(INTDIR)\perf-base.sbr"
	-@erase "$(INTDIR)\perf-event.obj"
	-@erase "$(INTDIR)\perf-event.sbr"
	-@erase "$(INTDIR)\perf-flow.obj"
	-@erase "$(INTDIR)\perf-flow.sbr"
	-@erase "$(INTDIR)\perf.obj"
	-@erase "$(INTDIR)\perf.sbr"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\plugbase.sbr"
	-@erase "$(INTDIR)\portscan.obj"
	-@erase "$(INTDIR)\portscan.sbr"
	-@erase "$(INTDIR)\scoreboard.obj"
	-@erase "$(INTDIR)\scoreboard.sbr"
	-@erase "$(INTDIR)\server_stats.obj"
	-@erase "$(INTDIR)\server_stats.sbr"
	-@erase "$(INTDIR)\sf_sdlist.obj"
	-@erase "$(INTDIR)\sf_sdlist.sbr"
	-@erase "$(INTDIR)\sfeventq.obj"
	-@erase "$(INTDIR)\sfeventq.sbr"
	-@erase "$(INTDIR)\sfghash.obj"
	-@erase "$(INTDIR)\sfghash.sbr"
	-@erase "$(INTDIR)\sfhashfcn.obj"
	-@erase "$(INTDIR)\sfhashfcn.sbr"
	-@erase "$(INTDIR)\sfksearch.obj"
	-@erase "$(INTDIR)\sfksearch.sbr"
	-@erase "$(INTDIR)\sflsq.obj"
	-@erase "$(INTDIR)\sflsq.sbr"
	-@erase "$(INTDIR)\sfmemcap.obj"
	-@erase "$(INTDIR)\sfmemcap.sbr"
	-@erase "$(INTDIR)\sfprocpidstats.obj"
	-@erase "$(INTDIR)\sfprocpidstats.sbr"
	-@erase "$(INTDIR)\sfsnprintfappend.obj"
	-@erase "$(INTDIR)\sfsnprintfappend.sbr"
	-@erase "$(INTDIR)\sfthd.obj"
	-@erase "$(INTDIR)\sfthd.sbr"
	-@erase "$(INTDIR)\sfthreshold.obj"
	-@erase "$(INTDIR)\sfthreshold.sbr"
	-@erase "$(INTDIR)\sfxhash.obj"
	-@erase "$(INTDIR)\sfxhash.sbr"
	-@erase "$(INTDIR)\signature.obj"
	-@erase "$(INTDIR)\signature.sbr"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort.sbr"
	-@erase "$(INTDIR)\snort_httpinspect.obj"
	-@erase "$(INTDIR)\snort_httpinspect.sbr"
	-@erase "$(INTDIR)\snort_stream4_session.obj"
	-@erase "$(INTDIR)\snort_stream4_session.sbr"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\snprintf.sbr"
	-@erase "$(INTDIR)\sp_asn1.obj"
	-@erase "$(INTDIR)\sp_asn1.sbr"
	-@erase "$(INTDIR)\sp_byte_check.obj"
	-@erase "$(INTDIR)\sp_byte_check.sbr"
	-@erase "$(INTDIR)\sp_byte_jump.obj"
	-@erase "$(INTDIR)\sp_byte_jump.sbr"
	-@erase "$(INTDIR)\sp_clientserver.obj"
	-@erase "$(INTDIR)\sp_clientserver.sbr"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_dsize_check.sbr"
	-@erase "$(INTDIR)\sp_flowbits.obj"
	-@erase "$(INTDIR)\sp_flowbits.sbr"
	-@erase "$(INTDIR)\sp_ftpbounce.obj"
	-@erase "$(INTDIR)\sp_ftpbounce.sbr"
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
	-@erase "$(INTDIR)\sp_isdataat.obj"
	-@erase "$(INTDIR)\sp_isdataat.sbr"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pattern_match.sbr"
	-@erase "$(INTDIR)\sp_pcre.obj"
	-@erase "$(INTDIR)\sp_pcre.sbr"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_react.sbr"
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
	-@erase "$(INTDIR)\spo_alert_prelude.obj"
	-@erase "$(INTDIR)\spo_alert_prelude.sbr"
	-@erase "$(INTDIR)\spo_alert_sf_socket.obj"
	-@erase "$(INTDIR)\spo_alert_sf_socket.sbr"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.sbr"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.sbr"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_csv.sbr"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_database.sbr"
	-@erase "$(INTDIR)\spo_log_ascii.obj"
	-@erase "$(INTDIR)\spo_log_ascii.sbr"
	-@erase "$(INTDIR)\spo_log_null.obj"
	-@erase "$(INTDIR)\spo_log_null.sbr"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.sbr"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_unified.sbr"
	-@erase "$(INTDIR)\spp_arpspoof.obj"
	-@erase "$(INTDIR)\spp_arpspoof.sbr"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_bo.sbr"
	-@erase "$(INTDIR)\spp_conversation.obj"
	-@erase "$(INTDIR)\spp_conversation.sbr"
	-@erase "$(INTDIR)\spp_flow.obj"
	-@erase "$(INTDIR)\spp_flow.sbr"
	-@erase "$(INTDIR)\spp_frag2.obj"
	-@erase "$(INTDIR)\spp_frag2.sbr"
	-@erase "$(INTDIR)\spp_frag3.obj"
	-@erase "$(INTDIR)\spp_frag3.sbr"
	-@erase "$(INTDIR)\spp_httpinspect.obj"
	-@erase "$(INTDIR)\spp_httpinspect.sbr"
	-@erase "$(INTDIR)\spp_perfmonitor.obj"
	-@erase "$(INTDIR)\spp_perfmonitor.sbr"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan.sbr"
	-@erase "$(INTDIR)\spp_portscan2.obj"
	-@erase "$(INTDIR)\spp_portscan2.sbr"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.sbr"
	-@erase "$(INTDIR)\spp_sfportscan.obj"
	-@erase "$(INTDIR)\spp_sfportscan.sbr"
	-@erase "$(INTDIR)\spp_stream4.obj"
	-@erase "$(INTDIR)\spp_stream4.sbr"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.sbr"
	-@erase "$(INTDIR)\spp_xlink2state.obj"
	-@erase "$(INTDIR)\spp_xlink2state.sbr"
	-@erase "$(INTDIR)\str_search.obj"
	-@erase "$(INTDIR)\str_search.sbr"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcatu.sbr"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strlcpyu.sbr"
	-@erase "$(INTDIR)\strtok_r.obj"
	-@erase "$(INTDIR)\strtok_r.sbr"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\syslog.sbr"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\tag.sbr"
	-@erase "$(INTDIR)\ubi_BinTree.obj"
	-@erase "$(INTDIR)\ubi_BinTree.sbr"
	-@erase "$(INTDIR)\ubi_SplayTree.obj"
	-@erase "$(INTDIR)\ubi_SplayTree.sbr"
	-@erase "$(INTDIR)\unique_tracker.obj"
	-@erase "$(INTDIR)\unique_tracker.sbr"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util.sbr"
	-@erase "$(INTDIR)\util_math.obj"
	-@erase "$(INTDIR)\util_math.sbr"
	-@erase "$(INTDIR)\util_net.obj"
	-@erase "$(INTDIR)\util_net.sbr"
	-@erase "$(INTDIR)\util_str.obj"
	-@erase "$(INTDIR)\util_str.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(INTDIR)\win32_service.obj"
	-@erase "$(INTDIR)\win32_service.sbr"
	-@erase "$(INTDIR)\xlink2state.obj"
	-@erase "$(INTDIR)\xlink2state.sbr"
	-@erase "$(OUTDIR)\snort.bsc"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "$(OUTDIR)\snort.ilk"
	-@erase "$(OUTDIR)\snort.pdb"
	-@erase "..\WIN32-Code\MSG00001.BIN"
	-@erase "..\WIN32-Code\name.h"
	-@erase "..\WIN32-Code\name.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\sp_asn1.sbr" \
	"$(INTDIR)\sp_byte_check.sbr" \
	"$(INTDIR)\sp_byte_jump.sbr" \
	"$(INTDIR)\sp_clientserver.sbr" \
	"$(INTDIR)\sp_dsize_check.sbr" \
	"$(INTDIR)\sp_flowbits.sbr" \
	"$(INTDIR)\sp_ftpbounce.sbr" \
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
	"$(INTDIR)\sp_isdataat.sbr" \
	"$(INTDIR)\sp_pattern_match.sbr" \
	"$(INTDIR)\sp_pcre.sbr" \
	"$(INTDIR)\sp_react.sbr" \
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
	"$(INTDIR)\spo_alert_prelude.sbr" \
	"$(INTDIR)\spo_alert_sf_socket.sbr" \
	"$(INTDIR)\spo_alert_syslog.sbr" \
	"$(INTDIR)\spo_alert_unixsock.sbr" \
	"$(INTDIR)\spo_csv.sbr" \
	"$(INTDIR)\spo_database.sbr" \
	"$(INTDIR)\spo_log_ascii.sbr" \
	"$(INTDIR)\spo_log_null.sbr" \
	"$(INTDIR)\spo_log_tcpdump.sbr" \
	"$(INTDIR)\spo_unified.sbr" \
	"$(INTDIR)\IpAddrSet.sbr" \
	"$(INTDIR)\flow_packet.sbr" \
	"$(INTDIR)\flowps.sbr" \
	"$(INTDIR)\flowps_snort.sbr" \
	"$(INTDIR)\scoreboard.sbr" \
	"$(INTDIR)\server_stats.sbr" \
	"$(INTDIR)\unique_tracker.sbr" \
	"$(INTDIR)\flow.sbr" \
	"$(INTDIR)\flow_cache.sbr" \
	"$(INTDIR)\flow_callback.sbr" \
	"$(INTDIR)\flow_class.sbr" \
	"$(INTDIR)\flow_hash.sbr" \
	"$(INTDIR)\flow_print.sbr" \
	"$(INTDIR)\flow_stat.sbr" \
	"$(INTDIR)\hi_ad.sbr" \
	"$(INTDIR)\hi_client.sbr" \
	"$(INTDIR)\hi_client_norm.sbr" \
	"$(INTDIR)\hi_eo_log.sbr" \
	"$(INTDIR)\hi_mi.sbr" \
	"$(INTDIR)\hi_norm.sbr" \
	"$(INTDIR)\hi_server.sbr" \
	"$(INTDIR)\hi_si.sbr" \
	"$(INTDIR)\hi_ui_config.sbr" \
	"$(INTDIR)\hi_ui_iis_unicode_map.sbr" \
	"$(INTDIR)\hi_ui_server_lookup.sbr" \
	"$(INTDIR)\hi_util_hbm.sbr" \
	"$(INTDIR)\hi_util_kmap.sbr" \
	"$(INTDIR)\hi_util_xmalloc.sbr" \
	"$(INTDIR)\perf-base.sbr" \
	"$(INTDIR)\perf-event.sbr" \
	"$(INTDIR)\perf-flow.sbr" \
	"$(INTDIR)\perf.sbr" \
	"$(INTDIR)\portscan.sbr" \
	"$(INTDIR)\sfprocpidstats.sbr" \
	"$(INTDIR)\snort_httpinspect.sbr" \
	"$(INTDIR)\snort_stream4_session.sbr" \
	"$(INTDIR)\spp_arpspoof.sbr" \
	"$(INTDIR)\spp_bo.sbr" \
	"$(INTDIR)\spp_conversation.sbr" \
	"$(INTDIR)\spp_flow.sbr" \
	"$(INTDIR)\spp_frag2.sbr" \
	"$(INTDIR)\spp_frag3.sbr" \
	"$(INTDIR)\spp_httpinspect.sbr" \
	"$(INTDIR)\spp_perfmonitor.sbr" \
	"$(INTDIR)\spp_portscan.sbr" \
	"$(INTDIR)\spp_portscan2.sbr" \
	"$(INTDIR)\spp_rpc_decode.sbr" \
	"$(INTDIR)\spp_sfportscan.sbr" \
	"$(INTDIR)\spp_stream4.sbr" \
	"$(INTDIR)\spp_telnet_negotiation.sbr" \
	"$(INTDIR)\spp_xlink2state.sbr" \
	"$(INTDIR)\str_search.sbr" \
	"$(INTDIR)\xlink2state.sbr" \
	"$(INTDIR)\acsmx.sbr" \
	"$(INTDIR)\acsmx2.sbr" \
	"$(INTDIR)\asn1.sbr" \
	"$(INTDIR)\ipobj.sbr" \
	"$(INTDIR)\mpse.sbr" \
	"$(INTDIR)\mwm.sbr" \
	"$(INTDIR)\sfeventq.sbr" \
	"$(INTDIR)\sfghash.sbr" \
	"$(INTDIR)\sfhashfcn.sbr" \
	"$(INTDIR)\sfksearch.sbr" \
	"$(INTDIR)\sflsq.sbr" \
	"$(INTDIR)\sfmemcap.sbr" \
	"$(INTDIR)\sfsnprintfappend.sbr" \
	"$(INTDIR)\sfthd.sbr" \
	"$(INTDIR)\sfxhash.sbr" \
	"$(INTDIR)\util_math.sbr" \
	"$(INTDIR)\util_net.sbr" \
	"$(INTDIR)\util_str.sbr" \
	"$(INTDIR)\byte_extract.sbr" \
	"$(INTDIR)\codes.sbr" \
	"$(INTDIR)\debug.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\detect.sbr" \
	"$(INTDIR)\event_queue.sbr" \
	"$(INTDIR)\event_wrapper.sbr" \
	"$(INTDIR)\fpcreate.sbr" \
	"$(INTDIR)\fpdetect.sbr" \
	"$(INTDIR)\inline.sbr" \
	"$(INTDIR)\log.sbr" \
	"$(INTDIR)\mempool.sbr" \
	"$(INTDIR)\mstring.sbr" \
	"$(INTDIR)\packet_time.sbr" \
	"$(INTDIR)\parser.sbr" \
	"$(INTDIR)\pcrm.sbr" \
	"$(INTDIR)\plugbase.sbr" \
	"$(INTDIR)\sf_sdlist.sbr" \
	"$(INTDIR)\sfthreshold.sbr" \
	"$(INTDIR)\signature.sbr" \
	"$(INTDIR)\snort.sbr" \
	"$(INTDIR)\snprintf.sbr" \
	"$(INTDIR)\strlcatu.sbr" \
	"$(INTDIR)\strlcpyu.sbr" \
	"$(INTDIR)\tag.sbr" \
	"$(INTDIR)\ubi_BinTree.sbr" \
	"$(INTDIR)\ubi_SplayTree.sbr" \
	"$(INTDIR)\util.sbr" \
	"$(INTDIR)\getopt.sbr" \
	"$(INTDIR)\inet_aton.sbr" \
	"$(INTDIR)\misc.sbr" \
	"$(INTDIR)\strtok_r.sbr" \
	"$(INTDIR)\syslog.sbr" \
	"$(INTDIR)\win32_service.sbr"

"$(OUTDIR)\snort.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib pcre.lib libpcap.lib advapi32.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\snort.pdb" /debug /machine:I386 /out:"$(OUTDIR)\snort.exe" /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" 
LINK32_OBJS= \
	"$(INTDIR)\sp_asn1.obj" \
	"$(INTDIR)\sp_byte_check.obj" \
	"$(INTDIR)\sp_byte_jump.obj" \
	"$(INTDIR)\sp_clientserver.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_flowbits.obj" \
	"$(INTDIR)\sp_ftpbounce.obj" \
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
	"$(INTDIR)\sp_isdataat.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_pcre.obj" \
	"$(INTDIR)\sp_react.obj" \
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
	"$(INTDIR)\spo_alert_prelude.obj" \
	"$(INTDIR)\spo_alert_sf_socket.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_ascii.obj" \
	"$(INTDIR)\spo_log_null.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\IpAddrSet.obj" \
	"$(INTDIR)\flow_packet.obj" \
	"$(INTDIR)\flowps.obj" \
	"$(INTDIR)\flowps_snort.obj" \
	"$(INTDIR)\scoreboard.obj" \
	"$(INTDIR)\server_stats.obj" \
	"$(INTDIR)\unique_tracker.obj" \
	"$(INTDIR)\flow.obj" \
	"$(INTDIR)\flow_cache.obj" \
	"$(INTDIR)\flow_callback.obj" \
	"$(INTDIR)\flow_class.obj" \
	"$(INTDIR)\flow_hash.obj" \
	"$(INTDIR)\flow_print.obj" \
	"$(INTDIR)\flow_stat.obj" \
	"$(INTDIR)\hi_ad.obj" \
	"$(INTDIR)\hi_client.obj" \
	"$(INTDIR)\hi_client_norm.obj" \
	"$(INTDIR)\hi_eo_log.obj" \
	"$(INTDIR)\hi_mi.obj" \
	"$(INTDIR)\hi_norm.obj" \
	"$(INTDIR)\hi_server.obj" \
	"$(INTDIR)\hi_si.obj" \
	"$(INTDIR)\hi_ui_config.obj" \
	"$(INTDIR)\hi_ui_iis_unicode_map.obj" \
	"$(INTDIR)\hi_ui_server_lookup.obj" \
	"$(INTDIR)\hi_util_hbm.obj" \
	"$(INTDIR)\hi_util_kmap.obj" \
	"$(INTDIR)\hi_util_xmalloc.obj" \
	"$(INTDIR)\perf-base.obj" \
	"$(INTDIR)\perf-event.obj" \
	"$(INTDIR)\perf-flow.obj" \
	"$(INTDIR)\perf.obj" \
	"$(INTDIR)\portscan.obj" \
	"$(INTDIR)\sfprocpidstats.obj" \
	"$(INTDIR)\snort_httpinspect.obj" \
	"$(INTDIR)\snort_stream4_session.obj" \
	"$(INTDIR)\spp_arpspoof.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_conversation.obj" \
	"$(INTDIR)\spp_flow.obj" \
	"$(INTDIR)\spp_frag2.obj" \
	"$(INTDIR)\spp_frag3.obj" \
	"$(INTDIR)\spp_httpinspect.obj" \
	"$(INTDIR)\spp_perfmonitor.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_portscan2.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_sfportscan.obj" \
	"$(INTDIR)\spp_stream4.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_xlink2state.obj" \
	"$(INTDIR)\str_search.obj" \
	"$(INTDIR)\xlink2state.obj" \
	"$(INTDIR)\acsmx.obj" \
	"$(INTDIR)\acsmx2.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\ipobj.obj" \
	"$(INTDIR)\mpse.obj" \
	"$(INTDIR)\mwm.obj" \
	"$(INTDIR)\sfeventq.obj" \
	"$(INTDIR)\sfghash.obj" \
	"$(INTDIR)\sfhashfcn.obj" \
	"$(INTDIR)\sfksearch.obj" \
	"$(INTDIR)\sflsq.obj" \
	"$(INTDIR)\sfmemcap.obj" \
	"$(INTDIR)\sfsnprintfappend.obj" \
	"$(INTDIR)\sfthd.obj" \
	"$(INTDIR)\sfxhash.obj" \
	"$(INTDIR)\util_math.obj" \
	"$(INTDIR)\util_net.obj" \
	"$(INTDIR)\util_str.obj" \
	"$(INTDIR)\byte_extract.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\detect.obj" \
	"$(INTDIR)\event_queue.obj" \
	"$(INTDIR)\event_wrapper.obj" \
	"$(INTDIR)\fpcreate.obj" \
	"$(INTDIR)\fpdetect.obj" \
	"$(INTDIR)\inline.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mempool.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\packet_time.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\pcrm.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\sf_sdlist.obj" \
	"$(INTDIR)\sfthreshold.obj" \
	"$(INTDIR)\signature.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\ubi_BinTree.obj" \
	"$(INTDIR)\ubi_SplayTree.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\inet_aton.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\strtok_r.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\win32_service.obj" \
	"..\WIN32-Code\name.res"

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

ALL : "..\WIN32-Code\name.rc" "..\WIN32-Code\name.h" "..\WIN32-Code\MSG00001.BIN" "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\acsmx.obj"
	-@erase "$(INTDIR)\acsmx2.obj"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\byte_extract.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\detect.obj"
	-@erase "$(INTDIR)\event_queue.obj"
	-@erase "$(INTDIR)\event_wrapper.obj"
	-@erase "$(INTDIR)\flow.obj"
	-@erase "$(INTDIR)\flow_cache.obj"
	-@erase "$(INTDIR)\flow_callback.obj"
	-@erase "$(INTDIR)\flow_class.obj"
	-@erase "$(INTDIR)\flow_hash.obj"
	-@erase "$(INTDIR)\flow_packet.obj"
	-@erase "$(INTDIR)\flow_print.obj"
	-@erase "$(INTDIR)\flow_stat.obj"
	-@erase "$(INTDIR)\flowps.obj"
	-@erase "$(INTDIR)\flowps_snort.obj"
	-@erase "$(INTDIR)\fpcreate.obj"
	-@erase "$(INTDIR)\fpdetect.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\hi_ad.obj"
	-@erase "$(INTDIR)\hi_client.obj"
	-@erase "$(INTDIR)\hi_client_norm.obj"
	-@erase "$(INTDIR)\hi_eo_log.obj"
	-@erase "$(INTDIR)\hi_mi.obj"
	-@erase "$(INTDIR)\hi_norm.obj"
	-@erase "$(INTDIR)\hi_server.obj"
	-@erase "$(INTDIR)\hi_si.obj"
	-@erase "$(INTDIR)\hi_ui_config.obj"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.obj"
	-@erase "$(INTDIR)\hi_ui_server_lookup.obj"
	-@erase "$(INTDIR)\hi_util_hbm.obj"
	-@erase "$(INTDIR)\hi_util_kmap.obj"
	-@erase "$(INTDIR)\hi_util_xmalloc.obj"
	-@erase "$(INTDIR)\inet_aton.obj"
	-@erase "$(INTDIR)\inline.obj"
	-@erase "$(INTDIR)\IpAddrSet.obj"
	-@erase "$(INTDIR)\ipobj.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\mempool.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mpse.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mwm.obj"
	-@erase "$(INTDIR)\packet_time.obj"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\pcrm.obj"
	-@erase "$(INTDIR)\perf-base.obj"
	-@erase "$(INTDIR)\perf-event.obj"
	-@erase "$(INTDIR)\perf-flow.obj"
	-@erase "$(INTDIR)\perf.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\portscan.obj"
	-@erase "$(INTDIR)\scoreboard.obj"
	-@erase "$(INTDIR)\server_stats.obj"
	-@erase "$(INTDIR)\sf_sdlist.obj"
	-@erase "$(INTDIR)\sfeventq.obj"
	-@erase "$(INTDIR)\sfghash.obj"
	-@erase "$(INTDIR)\sfhashfcn.obj"
	-@erase "$(INTDIR)\sfksearch.obj"
	-@erase "$(INTDIR)\sflsq.obj"
	-@erase "$(INTDIR)\sfmemcap.obj"
	-@erase "$(INTDIR)\sfprocpidstats.obj"
	-@erase "$(INTDIR)\sfsnprintfappend.obj"
	-@erase "$(INTDIR)\sfthd.obj"
	-@erase "$(INTDIR)\sfthreshold.obj"
	-@erase "$(INTDIR)\sfxhash.obj"
	-@erase "$(INTDIR)\signature.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort_httpinspect.obj"
	-@erase "$(INTDIR)\snort_stream4_session.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_asn1.obj"
	-@erase "$(INTDIR)\sp_byte_check.obj"
	-@erase "$(INTDIR)\sp_byte_jump.obj"
	-@erase "$(INTDIR)\sp_clientserver.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_flowbits.obj"
	-@erase "$(INTDIR)\sp_ftpbounce.obj"
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
	-@erase "$(INTDIR)\sp_isdataat.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pcre.obj"
	-@erase "$(INTDIR)\sp_react.obj"
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
	-@erase "$(INTDIR)\spo_alert_prelude.obj"
	-@erase "$(INTDIR)\spo_alert_sf_socket.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_ascii.obj"
	-@erase "$(INTDIR)\spo_log_null.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spp_arpspoof.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_conversation.obj"
	-@erase "$(INTDIR)\spp_flow.obj"
	-@erase "$(INTDIR)\spp_frag2.obj"
	-@erase "$(INTDIR)\spp_frag3.obj"
	-@erase "$(INTDIR)\spp_httpinspect.obj"
	-@erase "$(INTDIR)\spp_perfmonitor.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan2.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_sfportscan.obj"
	-@erase "$(INTDIR)\spp_stream4.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_xlink2state.obj"
	-@erase "$(INTDIR)\str_search.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strtok_r.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\ubi_BinTree.obj"
	-@erase "$(INTDIR)\ubi_SplayTree.obj"
	-@erase "$(INTDIR)\unique_tracker.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_math.obj"
	-@erase "$(INTDIR)\util_net.obj"
	-@erase "$(INTDIR)\util_str.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\win32_service.obj"
	-@erase "$(INTDIR)\xlink2state.obj"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "..\WIN32-Code\MSG00001.BIN"
	-@erase "..\WIN32-Code\name.h"
	-@erase "..\WIN32-Code\name.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib pcre.lib libpcap.lib advapi32.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\snort.pdb" /machine:I386 /out:"$(OUTDIR)\snort.exe" /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" 
LINK32_OBJS= \
	"$(INTDIR)\sp_asn1.obj" \
	"$(INTDIR)\sp_byte_check.obj" \
	"$(INTDIR)\sp_byte_jump.obj" \
	"$(INTDIR)\sp_clientserver.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_flowbits.obj" \
	"$(INTDIR)\sp_ftpbounce.obj" \
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
	"$(INTDIR)\sp_isdataat.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_pcre.obj" \
	"$(INTDIR)\sp_react.obj" \
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
	"$(INTDIR)\spo_alert_prelude.obj" \
	"$(INTDIR)\spo_alert_sf_socket.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_ascii.obj" \
	"$(INTDIR)\spo_log_null.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\IpAddrSet.obj" \
	"$(INTDIR)\flow_packet.obj" \
	"$(INTDIR)\flowps.obj" \
	"$(INTDIR)\flowps_snort.obj" \
	"$(INTDIR)\scoreboard.obj" \
	"$(INTDIR)\server_stats.obj" \
	"$(INTDIR)\unique_tracker.obj" \
	"$(INTDIR)\flow.obj" \
	"$(INTDIR)\flow_cache.obj" \
	"$(INTDIR)\flow_callback.obj" \
	"$(INTDIR)\flow_class.obj" \
	"$(INTDIR)\flow_hash.obj" \
	"$(INTDIR)\flow_print.obj" \
	"$(INTDIR)\flow_stat.obj" \
	"$(INTDIR)\hi_ad.obj" \
	"$(INTDIR)\hi_client.obj" \
	"$(INTDIR)\hi_client_norm.obj" \
	"$(INTDIR)\hi_eo_log.obj" \
	"$(INTDIR)\hi_mi.obj" \
	"$(INTDIR)\hi_norm.obj" \
	"$(INTDIR)\hi_server.obj" \
	"$(INTDIR)\hi_si.obj" \
	"$(INTDIR)\hi_ui_config.obj" \
	"$(INTDIR)\hi_ui_iis_unicode_map.obj" \
	"$(INTDIR)\hi_ui_server_lookup.obj" \
	"$(INTDIR)\hi_util_hbm.obj" \
	"$(INTDIR)\hi_util_kmap.obj" \
	"$(INTDIR)\hi_util_xmalloc.obj" \
	"$(INTDIR)\perf-base.obj" \
	"$(INTDIR)\perf-event.obj" \
	"$(INTDIR)\perf-flow.obj" \
	"$(INTDIR)\perf.obj" \
	"$(INTDIR)\portscan.obj" \
	"$(INTDIR)\sfprocpidstats.obj" \
	"$(INTDIR)\snort_httpinspect.obj" \
	"$(INTDIR)\snort_stream4_session.obj" \
	"$(INTDIR)\spp_arpspoof.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_conversation.obj" \
	"$(INTDIR)\spp_flow.obj" \
	"$(INTDIR)\spp_frag2.obj" \
	"$(INTDIR)\spp_frag3.obj" \
	"$(INTDIR)\spp_httpinspect.obj" \
	"$(INTDIR)\spp_perfmonitor.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_portscan2.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_sfportscan.obj" \
	"$(INTDIR)\spp_stream4.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_xlink2state.obj" \
	"$(INTDIR)\str_search.obj" \
	"$(INTDIR)\xlink2state.obj" \
	"$(INTDIR)\acsmx.obj" \
	"$(INTDIR)\acsmx2.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\ipobj.obj" \
	"$(INTDIR)\mpse.obj" \
	"$(INTDIR)\mwm.obj" \
	"$(INTDIR)\sfeventq.obj" \
	"$(INTDIR)\sfghash.obj" \
	"$(INTDIR)\sfhashfcn.obj" \
	"$(INTDIR)\sfksearch.obj" \
	"$(INTDIR)\sflsq.obj" \
	"$(INTDIR)\sfmemcap.obj" \
	"$(INTDIR)\sfsnprintfappend.obj" \
	"$(INTDIR)\sfthd.obj" \
	"$(INTDIR)\sfxhash.obj" \
	"$(INTDIR)\util_math.obj" \
	"$(INTDIR)\util_net.obj" \
	"$(INTDIR)\util_str.obj" \
	"$(INTDIR)\byte_extract.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\detect.obj" \
	"$(INTDIR)\event_queue.obj" \
	"$(INTDIR)\event_wrapper.obj" \
	"$(INTDIR)\fpcreate.obj" \
	"$(INTDIR)\fpdetect.obj" \
	"$(INTDIR)\inline.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mempool.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\packet_time.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\pcrm.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\sf_sdlist.obj" \
	"$(INTDIR)\sfthreshold.obj" \
	"$(INTDIR)\signature.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\ubi_BinTree.obj" \
	"$(INTDIR)\ubi_SplayTree.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\inet_aton.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\strtok_r.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\win32_service.obj" \
	"..\WIN32-Code\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

OUTDIR=.\snort___Win32_SQLServer_Debug
INTDIR=.\snort___Win32_SQLServer_Debug
# Begin Custom Macros
OutDir=.\snort___Win32_SQLServer_Debug
# End Custom Macros

ALL : "..\WIN32-Code\name.rc" "..\WIN32-Code\name.h" "..\WIN32-Code\MSG00001.BIN" "$(OUTDIR)\snort.exe" "$(OUTDIR)\snort.bsc"


CLEAN :
	-@erase "$(INTDIR)\acsmx.obj"
	-@erase "$(INTDIR)\acsmx.sbr"
	-@erase "$(INTDIR)\acsmx2.obj"
	-@erase "$(INTDIR)\acsmx2.sbr"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\asn1.sbr"
	-@erase "$(INTDIR)\byte_extract.obj"
	-@erase "$(INTDIR)\byte_extract.sbr"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\codes.sbr"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\debug.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\detect.obj"
	-@erase "$(INTDIR)\detect.sbr"
	-@erase "$(INTDIR)\event_queue.obj"
	-@erase "$(INTDIR)\event_queue.sbr"
	-@erase "$(INTDIR)\event_wrapper.obj"
	-@erase "$(INTDIR)\event_wrapper.sbr"
	-@erase "$(INTDIR)\flow.obj"
	-@erase "$(INTDIR)\flow.sbr"
	-@erase "$(INTDIR)\flow_cache.obj"
	-@erase "$(INTDIR)\flow_cache.sbr"
	-@erase "$(INTDIR)\flow_callback.obj"
	-@erase "$(INTDIR)\flow_callback.sbr"
	-@erase "$(INTDIR)\flow_class.obj"
	-@erase "$(INTDIR)\flow_class.sbr"
	-@erase "$(INTDIR)\flow_hash.obj"
	-@erase "$(INTDIR)\flow_hash.sbr"
	-@erase "$(INTDIR)\flow_packet.obj"
	-@erase "$(INTDIR)\flow_packet.sbr"
	-@erase "$(INTDIR)\flow_print.obj"
	-@erase "$(INTDIR)\flow_print.sbr"
	-@erase "$(INTDIR)\flow_stat.obj"
	-@erase "$(INTDIR)\flow_stat.sbr"
	-@erase "$(INTDIR)\flowps.obj"
	-@erase "$(INTDIR)\flowps.sbr"
	-@erase "$(INTDIR)\flowps_snort.obj"
	-@erase "$(INTDIR)\flowps_snort.sbr"
	-@erase "$(INTDIR)\fpcreate.obj"
	-@erase "$(INTDIR)\fpcreate.sbr"
	-@erase "$(INTDIR)\fpdetect.obj"
	-@erase "$(INTDIR)\fpdetect.sbr"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\getopt.sbr"
	-@erase "$(INTDIR)\hi_ad.obj"
	-@erase "$(INTDIR)\hi_ad.sbr"
	-@erase "$(INTDIR)\hi_client.obj"
	-@erase "$(INTDIR)\hi_client.sbr"
	-@erase "$(INTDIR)\hi_client_norm.obj"
	-@erase "$(INTDIR)\hi_client_norm.sbr"
	-@erase "$(INTDIR)\hi_eo_log.obj"
	-@erase "$(INTDIR)\hi_eo_log.sbr"
	-@erase "$(INTDIR)\hi_mi.obj"
	-@erase "$(INTDIR)\hi_mi.sbr"
	-@erase "$(INTDIR)\hi_norm.obj"
	-@erase "$(INTDIR)\hi_norm.sbr"
	-@erase "$(INTDIR)\hi_server.obj"
	-@erase "$(INTDIR)\hi_server.sbr"
	-@erase "$(INTDIR)\hi_si.obj"
	-@erase "$(INTDIR)\hi_si.sbr"
	-@erase "$(INTDIR)\hi_ui_config.obj"
	-@erase "$(INTDIR)\hi_ui_config.sbr"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.obj"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.sbr"
	-@erase "$(INTDIR)\hi_ui_server_lookup.obj"
	-@erase "$(INTDIR)\hi_ui_server_lookup.sbr"
	-@erase "$(INTDIR)\hi_util_hbm.obj"
	-@erase "$(INTDIR)\hi_util_hbm.sbr"
	-@erase "$(INTDIR)\hi_util_kmap.obj"
	-@erase "$(INTDIR)\hi_util_kmap.sbr"
	-@erase "$(INTDIR)\hi_util_xmalloc.obj"
	-@erase "$(INTDIR)\hi_util_xmalloc.sbr"
	-@erase "$(INTDIR)\inet_aton.obj"
	-@erase "$(INTDIR)\inet_aton.sbr"
	-@erase "$(INTDIR)\inline.obj"
	-@erase "$(INTDIR)\inline.sbr"
	-@erase "$(INTDIR)\IpAddrSet.obj"
	-@erase "$(INTDIR)\IpAddrSet.sbr"
	-@erase "$(INTDIR)\ipobj.obj"
	-@erase "$(INTDIR)\ipobj.sbr"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\log.sbr"
	-@erase "$(INTDIR)\mempool.obj"
	-@erase "$(INTDIR)\mempool.sbr"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\misc.sbr"
	-@erase "$(INTDIR)\mpse.obj"
	-@erase "$(INTDIR)\mpse.sbr"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mstring.sbr"
	-@erase "$(INTDIR)\mwm.obj"
	-@erase "$(INTDIR)\mwm.sbr"
	-@erase "$(INTDIR)\packet_time.obj"
	-@erase "$(INTDIR)\packet_time.sbr"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\parser.sbr"
	-@erase "$(INTDIR)\pcrm.obj"
	-@erase "$(INTDIR)\pcrm.sbr"
	-@erase "$(INTDIR)\perf-base.obj"
	-@erase "$(INTDIR)\perf-base.sbr"
	-@erase "$(INTDIR)\perf-event.obj"
	-@erase "$(INTDIR)\perf-event.sbr"
	-@erase "$(INTDIR)\perf-flow.obj"
	-@erase "$(INTDIR)\perf-flow.sbr"
	-@erase "$(INTDIR)\perf.obj"
	-@erase "$(INTDIR)\perf.sbr"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\plugbase.sbr"
	-@erase "$(INTDIR)\portscan.obj"
	-@erase "$(INTDIR)\portscan.sbr"
	-@erase "$(INTDIR)\scoreboard.obj"
	-@erase "$(INTDIR)\scoreboard.sbr"
	-@erase "$(INTDIR)\server_stats.obj"
	-@erase "$(INTDIR)\server_stats.sbr"
	-@erase "$(INTDIR)\sf_sdlist.obj"
	-@erase "$(INTDIR)\sf_sdlist.sbr"
	-@erase "$(INTDIR)\sfeventq.obj"
	-@erase "$(INTDIR)\sfeventq.sbr"
	-@erase "$(INTDIR)\sfghash.obj"
	-@erase "$(INTDIR)\sfghash.sbr"
	-@erase "$(INTDIR)\sfhashfcn.obj"
	-@erase "$(INTDIR)\sfhashfcn.sbr"
	-@erase "$(INTDIR)\sfksearch.obj"
	-@erase "$(INTDIR)\sfksearch.sbr"
	-@erase "$(INTDIR)\sflsq.obj"
	-@erase "$(INTDIR)\sflsq.sbr"
	-@erase "$(INTDIR)\sfmemcap.obj"
	-@erase "$(INTDIR)\sfmemcap.sbr"
	-@erase "$(INTDIR)\sfprocpidstats.obj"
	-@erase "$(INTDIR)\sfprocpidstats.sbr"
	-@erase "$(INTDIR)\sfsnprintfappend.obj"
	-@erase "$(INTDIR)\sfsnprintfappend.sbr"
	-@erase "$(INTDIR)\sfthd.obj"
	-@erase "$(INTDIR)\sfthd.sbr"
	-@erase "$(INTDIR)\sfthreshold.obj"
	-@erase "$(INTDIR)\sfthreshold.sbr"
	-@erase "$(INTDIR)\sfxhash.obj"
	-@erase "$(INTDIR)\sfxhash.sbr"
	-@erase "$(INTDIR)\signature.obj"
	-@erase "$(INTDIR)\signature.sbr"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort.sbr"
	-@erase "$(INTDIR)\snort_httpinspect.obj"
	-@erase "$(INTDIR)\snort_httpinspect.sbr"
	-@erase "$(INTDIR)\snort_stream4_session.obj"
	-@erase "$(INTDIR)\snort_stream4_session.sbr"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\snprintf.sbr"
	-@erase "$(INTDIR)\sp_asn1.obj"
	-@erase "$(INTDIR)\sp_asn1.sbr"
	-@erase "$(INTDIR)\sp_byte_check.obj"
	-@erase "$(INTDIR)\sp_byte_check.sbr"
	-@erase "$(INTDIR)\sp_byte_jump.obj"
	-@erase "$(INTDIR)\sp_byte_jump.sbr"
	-@erase "$(INTDIR)\sp_clientserver.obj"
	-@erase "$(INTDIR)\sp_clientserver.sbr"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_dsize_check.sbr"
	-@erase "$(INTDIR)\sp_flowbits.obj"
	-@erase "$(INTDIR)\sp_flowbits.sbr"
	-@erase "$(INTDIR)\sp_ftpbounce.obj"
	-@erase "$(INTDIR)\sp_ftpbounce.sbr"
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
	-@erase "$(INTDIR)\sp_isdataat.obj"
	-@erase "$(INTDIR)\sp_isdataat.sbr"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pattern_match.sbr"
	-@erase "$(INTDIR)\sp_pcre.obj"
	-@erase "$(INTDIR)\sp_pcre.sbr"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_react.sbr"
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
	-@erase "$(INTDIR)\spo_alert_prelude.obj"
	-@erase "$(INTDIR)\spo_alert_prelude.sbr"
	-@erase "$(INTDIR)\spo_alert_sf_socket.obj"
	-@erase "$(INTDIR)\spo_alert_sf_socket.sbr"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.sbr"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.sbr"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_csv.sbr"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_database.sbr"
	-@erase "$(INTDIR)\spo_log_ascii.obj"
	-@erase "$(INTDIR)\spo_log_ascii.sbr"
	-@erase "$(INTDIR)\spo_log_null.obj"
	-@erase "$(INTDIR)\spo_log_null.sbr"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.sbr"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_unified.sbr"
	-@erase "$(INTDIR)\spp_arpspoof.obj"
	-@erase "$(INTDIR)\spp_arpspoof.sbr"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_bo.sbr"
	-@erase "$(INTDIR)\spp_conversation.obj"
	-@erase "$(INTDIR)\spp_conversation.sbr"
	-@erase "$(INTDIR)\spp_flow.obj"
	-@erase "$(INTDIR)\spp_flow.sbr"
	-@erase "$(INTDIR)\spp_frag2.obj"
	-@erase "$(INTDIR)\spp_frag2.sbr"
	-@erase "$(INTDIR)\spp_frag3.obj"
	-@erase "$(INTDIR)\spp_frag3.sbr"
	-@erase "$(INTDIR)\spp_httpinspect.obj"
	-@erase "$(INTDIR)\spp_httpinspect.sbr"
	-@erase "$(INTDIR)\spp_perfmonitor.obj"
	-@erase "$(INTDIR)\spp_perfmonitor.sbr"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan.sbr"
	-@erase "$(INTDIR)\spp_portscan2.obj"
	-@erase "$(INTDIR)\spp_portscan2.sbr"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.sbr"
	-@erase "$(INTDIR)\spp_sfportscan.obj"
	-@erase "$(INTDIR)\spp_sfportscan.sbr"
	-@erase "$(INTDIR)\spp_stream4.obj"
	-@erase "$(INTDIR)\spp_stream4.sbr"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.sbr"
	-@erase "$(INTDIR)\spp_xlink2state.obj"
	-@erase "$(INTDIR)\spp_xlink2state.sbr"
	-@erase "$(INTDIR)\str_search.obj"
	-@erase "$(INTDIR)\str_search.sbr"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcatu.sbr"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strlcpyu.sbr"
	-@erase "$(INTDIR)\strtok_r.obj"
	-@erase "$(INTDIR)\strtok_r.sbr"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\syslog.sbr"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\tag.sbr"
	-@erase "$(INTDIR)\ubi_BinTree.obj"
	-@erase "$(INTDIR)\ubi_BinTree.sbr"
	-@erase "$(INTDIR)\ubi_SplayTree.obj"
	-@erase "$(INTDIR)\ubi_SplayTree.sbr"
	-@erase "$(INTDIR)\unique_tracker.obj"
	-@erase "$(INTDIR)\unique_tracker.sbr"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util.sbr"
	-@erase "$(INTDIR)\util_math.obj"
	-@erase "$(INTDIR)\util_math.sbr"
	-@erase "$(INTDIR)\util_net.obj"
	-@erase "$(INTDIR)\util_net.sbr"
	-@erase "$(INTDIR)\util_str.obj"
	-@erase "$(INTDIR)\util_str.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(INTDIR)\win32_service.obj"
	-@erase "$(INTDIR)\win32_service.sbr"
	-@erase "$(INTDIR)\xlink2state.obj"
	-@erase "$(INTDIR)\xlink2state.sbr"
	-@erase "$(OUTDIR)\snort.bsc"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "$(OUTDIR)\snort.ilk"
	-@erase "$(OUTDIR)\snort.pdb"
	-@erase "..\WIN32-Code\MSG00001.BIN"
	-@erase "..\WIN32-Code\name.h"
	-@erase "..\WIN32-Code\name.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_MSSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fr"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX"snort.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\sp_asn1.sbr" \
	"$(INTDIR)\sp_byte_check.sbr" \
	"$(INTDIR)\sp_byte_jump.sbr" \
	"$(INTDIR)\sp_clientserver.sbr" \
	"$(INTDIR)\sp_dsize_check.sbr" \
	"$(INTDIR)\sp_flowbits.sbr" \
	"$(INTDIR)\sp_ftpbounce.sbr" \
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
	"$(INTDIR)\sp_isdataat.sbr" \
	"$(INTDIR)\sp_pattern_match.sbr" \
	"$(INTDIR)\sp_pcre.sbr" \
	"$(INTDIR)\sp_react.sbr" \
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
	"$(INTDIR)\spo_alert_prelude.sbr" \
	"$(INTDIR)\spo_alert_sf_socket.sbr" \
	"$(INTDIR)\spo_alert_syslog.sbr" \
	"$(INTDIR)\spo_alert_unixsock.sbr" \
	"$(INTDIR)\spo_csv.sbr" \
	"$(INTDIR)\spo_database.sbr" \
	"$(INTDIR)\spo_log_ascii.sbr" \
	"$(INTDIR)\spo_log_null.sbr" \
	"$(INTDIR)\spo_log_tcpdump.sbr" \
	"$(INTDIR)\spo_unified.sbr" \
	"$(INTDIR)\IpAddrSet.sbr" \
	"$(INTDIR)\flow_packet.sbr" \
	"$(INTDIR)\flowps.sbr" \
	"$(INTDIR)\flowps_snort.sbr" \
	"$(INTDIR)\scoreboard.sbr" \
	"$(INTDIR)\server_stats.sbr" \
	"$(INTDIR)\unique_tracker.sbr" \
	"$(INTDIR)\flow.sbr" \
	"$(INTDIR)\flow_cache.sbr" \
	"$(INTDIR)\flow_callback.sbr" \
	"$(INTDIR)\flow_class.sbr" \
	"$(INTDIR)\flow_hash.sbr" \
	"$(INTDIR)\flow_print.sbr" \
	"$(INTDIR)\flow_stat.sbr" \
	"$(INTDIR)\hi_ad.sbr" \
	"$(INTDIR)\hi_client.sbr" \
	"$(INTDIR)\hi_client_norm.sbr" \
	"$(INTDIR)\hi_eo_log.sbr" \
	"$(INTDIR)\hi_mi.sbr" \
	"$(INTDIR)\hi_norm.sbr" \
	"$(INTDIR)\hi_server.sbr" \
	"$(INTDIR)\hi_si.sbr" \
	"$(INTDIR)\hi_ui_config.sbr" \
	"$(INTDIR)\hi_ui_iis_unicode_map.sbr" \
	"$(INTDIR)\hi_ui_server_lookup.sbr" \
	"$(INTDIR)\hi_util_hbm.sbr" \
	"$(INTDIR)\hi_util_kmap.sbr" \
	"$(INTDIR)\hi_util_xmalloc.sbr" \
	"$(INTDIR)\perf-base.sbr" \
	"$(INTDIR)\perf-event.sbr" \
	"$(INTDIR)\perf-flow.sbr" \
	"$(INTDIR)\perf.sbr" \
	"$(INTDIR)\portscan.sbr" \
	"$(INTDIR)\sfprocpidstats.sbr" \
	"$(INTDIR)\snort_httpinspect.sbr" \
	"$(INTDIR)\snort_stream4_session.sbr" \
	"$(INTDIR)\spp_arpspoof.sbr" \
	"$(INTDIR)\spp_bo.sbr" \
	"$(INTDIR)\spp_conversation.sbr" \
	"$(INTDIR)\spp_flow.sbr" \
	"$(INTDIR)\spp_frag2.sbr" \
	"$(INTDIR)\spp_frag3.sbr" \
	"$(INTDIR)\spp_httpinspect.sbr" \
	"$(INTDIR)\spp_perfmonitor.sbr" \
	"$(INTDIR)\spp_portscan.sbr" \
	"$(INTDIR)\spp_portscan2.sbr" \
	"$(INTDIR)\spp_rpc_decode.sbr" \
	"$(INTDIR)\spp_sfportscan.sbr" \
	"$(INTDIR)\spp_stream4.sbr" \
	"$(INTDIR)\spp_telnet_negotiation.sbr" \
	"$(INTDIR)\spp_xlink2state.sbr" \
	"$(INTDIR)\str_search.sbr" \
	"$(INTDIR)\xlink2state.sbr" \
	"$(INTDIR)\acsmx.sbr" \
	"$(INTDIR)\acsmx2.sbr" \
	"$(INTDIR)\asn1.sbr" \
	"$(INTDIR)\ipobj.sbr" \
	"$(INTDIR)\mpse.sbr" \
	"$(INTDIR)\mwm.sbr" \
	"$(INTDIR)\sfeventq.sbr" \
	"$(INTDIR)\sfghash.sbr" \
	"$(INTDIR)\sfhashfcn.sbr" \
	"$(INTDIR)\sfksearch.sbr" \
	"$(INTDIR)\sflsq.sbr" \
	"$(INTDIR)\sfmemcap.sbr" \
	"$(INTDIR)\sfsnprintfappend.sbr" \
	"$(INTDIR)\sfthd.sbr" \
	"$(INTDIR)\sfxhash.sbr" \
	"$(INTDIR)\util_math.sbr" \
	"$(INTDIR)\util_net.sbr" \
	"$(INTDIR)\util_str.sbr" \
	"$(INTDIR)\byte_extract.sbr" \
	"$(INTDIR)\codes.sbr" \
	"$(INTDIR)\debug.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\detect.sbr" \
	"$(INTDIR)\event_queue.sbr" \
	"$(INTDIR)\event_wrapper.sbr" \
	"$(INTDIR)\fpcreate.sbr" \
	"$(INTDIR)\fpdetect.sbr" \
	"$(INTDIR)\inline.sbr" \
	"$(INTDIR)\log.sbr" \
	"$(INTDIR)\mempool.sbr" \
	"$(INTDIR)\mstring.sbr" \
	"$(INTDIR)\packet_time.sbr" \
	"$(INTDIR)\parser.sbr" \
	"$(INTDIR)\pcrm.sbr" \
	"$(INTDIR)\plugbase.sbr" \
	"$(INTDIR)\sf_sdlist.sbr" \
	"$(INTDIR)\sfthreshold.sbr" \
	"$(INTDIR)\signature.sbr" \
	"$(INTDIR)\snort.sbr" \
	"$(INTDIR)\snprintf.sbr" \
	"$(INTDIR)\strlcatu.sbr" \
	"$(INTDIR)\strlcpyu.sbr" \
	"$(INTDIR)\tag.sbr" \
	"$(INTDIR)\ubi_BinTree.sbr" \
	"$(INTDIR)\ubi_SplayTree.sbr" \
	"$(INTDIR)\util.sbr" \
	"$(INTDIR)\getopt.sbr" \
	"$(INTDIR)\inet_aton.sbr" \
	"$(INTDIR)\misc.sbr" \
	"$(INTDIR)\strtok_r.sbr" \
	"$(INTDIR)\syslog.sbr" \
	"$(INTDIR)\win32_service.sbr"

"$(OUTDIR)\snort.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib pcre.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\snort.pdb" /debug /machine:I386 /out:"$(OUTDIR)\snort.exe" /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" 
LINK32_OBJS= \
	"$(INTDIR)\sp_asn1.obj" \
	"$(INTDIR)\sp_byte_check.obj" \
	"$(INTDIR)\sp_byte_jump.obj" \
	"$(INTDIR)\sp_clientserver.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_flowbits.obj" \
	"$(INTDIR)\sp_ftpbounce.obj" \
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
	"$(INTDIR)\sp_isdataat.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_pcre.obj" \
	"$(INTDIR)\sp_react.obj" \
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
	"$(INTDIR)\spo_alert_prelude.obj" \
	"$(INTDIR)\spo_alert_sf_socket.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_ascii.obj" \
	"$(INTDIR)\spo_log_null.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\IpAddrSet.obj" \
	"$(INTDIR)\flow_packet.obj" \
	"$(INTDIR)\flowps.obj" \
	"$(INTDIR)\flowps_snort.obj" \
	"$(INTDIR)\scoreboard.obj" \
	"$(INTDIR)\server_stats.obj" \
	"$(INTDIR)\unique_tracker.obj" \
	"$(INTDIR)\flow.obj" \
	"$(INTDIR)\flow_cache.obj" \
	"$(INTDIR)\flow_callback.obj" \
	"$(INTDIR)\flow_class.obj" \
	"$(INTDIR)\flow_hash.obj" \
	"$(INTDIR)\flow_print.obj" \
	"$(INTDIR)\flow_stat.obj" \
	"$(INTDIR)\hi_ad.obj" \
	"$(INTDIR)\hi_client.obj" \
	"$(INTDIR)\hi_client_norm.obj" \
	"$(INTDIR)\hi_eo_log.obj" \
	"$(INTDIR)\hi_mi.obj" \
	"$(INTDIR)\hi_norm.obj" \
	"$(INTDIR)\hi_server.obj" \
	"$(INTDIR)\hi_si.obj" \
	"$(INTDIR)\hi_ui_config.obj" \
	"$(INTDIR)\hi_ui_iis_unicode_map.obj" \
	"$(INTDIR)\hi_ui_server_lookup.obj" \
	"$(INTDIR)\hi_util_hbm.obj" \
	"$(INTDIR)\hi_util_kmap.obj" \
	"$(INTDIR)\hi_util_xmalloc.obj" \
	"$(INTDIR)\perf-base.obj" \
	"$(INTDIR)\perf-event.obj" \
	"$(INTDIR)\perf-flow.obj" \
	"$(INTDIR)\perf.obj" \
	"$(INTDIR)\portscan.obj" \
	"$(INTDIR)\sfprocpidstats.obj" \
	"$(INTDIR)\snort_httpinspect.obj" \
	"$(INTDIR)\snort_stream4_session.obj" \
	"$(INTDIR)\spp_arpspoof.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_conversation.obj" \
	"$(INTDIR)\spp_flow.obj" \
	"$(INTDIR)\spp_frag2.obj" \
	"$(INTDIR)\spp_frag3.obj" \
	"$(INTDIR)\spp_httpinspect.obj" \
	"$(INTDIR)\spp_perfmonitor.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_portscan2.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_sfportscan.obj" \
	"$(INTDIR)\spp_stream4.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_xlink2state.obj" \
	"$(INTDIR)\str_search.obj" \
	"$(INTDIR)\xlink2state.obj" \
	"$(INTDIR)\acsmx.obj" \
	"$(INTDIR)\acsmx2.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\ipobj.obj" \
	"$(INTDIR)\mpse.obj" \
	"$(INTDIR)\mwm.obj" \
	"$(INTDIR)\sfeventq.obj" \
	"$(INTDIR)\sfghash.obj" \
	"$(INTDIR)\sfhashfcn.obj" \
	"$(INTDIR)\sfksearch.obj" \
	"$(INTDIR)\sflsq.obj" \
	"$(INTDIR)\sfmemcap.obj" \
	"$(INTDIR)\sfsnprintfappend.obj" \
	"$(INTDIR)\sfthd.obj" \
	"$(INTDIR)\sfxhash.obj" \
	"$(INTDIR)\util_math.obj" \
	"$(INTDIR)\util_net.obj" \
	"$(INTDIR)\util_str.obj" \
	"$(INTDIR)\byte_extract.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\detect.obj" \
	"$(INTDIR)\event_queue.obj" \
	"$(INTDIR)\event_wrapper.obj" \
	"$(INTDIR)\fpcreate.obj" \
	"$(INTDIR)\fpdetect.obj" \
	"$(INTDIR)\inline.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mempool.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\packet_time.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\pcrm.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\sf_sdlist.obj" \
	"$(INTDIR)\sfthreshold.obj" \
	"$(INTDIR)\signature.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\ubi_BinTree.obj" \
	"$(INTDIR)\ubi_SplayTree.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\inet_aton.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\strtok_r.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\win32_service.obj" \
	"..\WIN32-Code\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

OUTDIR=.\snort___Win32_SQLServer_Release
INTDIR=.\snort___Win32_SQLServer_Release
# Begin Custom Macros
OutDir=.\snort___Win32_SQLServer_Release
# End Custom Macros

ALL : "..\WIN32-Code\name.rc" "..\WIN32-Code\name.h" "..\WIN32-Code\MSG00001.BIN" "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\acsmx.obj"
	-@erase "$(INTDIR)\acsmx2.obj"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\byte_extract.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\detect.obj"
	-@erase "$(INTDIR)\event_queue.obj"
	-@erase "$(INTDIR)\event_wrapper.obj"
	-@erase "$(INTDIR)\flow.obj"
	-@erase "$(INTDIR)\flow_cache.obj"
	-@erase "$(INTDIR)\flow_callback.obj"
	-@erase "$(INTDIR)\flow_class.obj"
	-@erase "$(INTDIR)\flow_hash.obj"
	-@erase "$(INTDIR)\flow_packet.obj"
	-@erase "$(INTDIR)\flow_print.obj"
	-@erase "$(INTDIR)\flow_stat.obj"
	-@erase "$(INTDIR)\flowps.obj"
	-@erase "$(INTDIR)\flowps_snort.obj"
	-@erase "$(INTDIR)\fpcreate.obj"
	-@erase "$(INTDIR)\fpdetect.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\hi_ad.obj"
	-@erase "$(INTDIR)\hi_client.obj"
	-@erase "$(INTDIR)\hi_client_norm.obj"
	-@erase "$(INTDIR)\hi_eo_log.obj"
	-@erase "$(INTDIR)\hi_mi.obj"
	-@erase "$(INTDIR)\hi_norm.obj"
	-@erase "$(INTDIR)\hi_server.obj"
	-@erase "$(INTDIR)\hi_si.obj"
	-@erase "$(INTDIR)\hi_ui_config.obj"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.obj"
	-@erase "$(INTDIR)\hi_ui_server_lookup.obj"
	-@erase "$(INTDIR)\hi_util_hbm.obj"
	-@erase "$(INTDIR)\hi_util_kmap.obj"
	-@erase "$(INTDIR)\hi_util_xmalloc.obj"
	-@erase "$(INTDIR)\inet_aton.obj"
	-@erase "$(INTDIR)\inline.obj"
	-@erase "$(INTDIR)\IpAddrSet.obj"
	-@erase "$(INTDIR)\ipobj.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\mempool.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mpse.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mwm.obj"
	-@erase "$(INTDIR)\packet_time.obj"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\pcrm.obj"
	-@erase "$(INTDIR)\perf-base.obj"
	-@erase "$(INTDIR)\perf-event.obj"
	-@erase "$(INTDIR)\perf-flow.obj"
	-@erase "$(INTDIR)\perf.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\portscan.obj"
	-@erase "$(INTDIR)\scoreboard.obj"
	-@erase "$(INTDIR)\server_stats.obj"
	-@erase "$(INTDIR)\sf_sdlist.obj"
	-@erase "$(INTDIR)\sfeventq.obj"
	-@erase "$(INTDIR)\sfghash.obj"
	-@erase "$(INTDIR)\sfhashfcn.obj"
	-@erase "$(INTDIR)\sfksearch.obj"
	-@erase "$(INTDIR)\sflsq.obj"
	-@erase "$(INTDIR)\sfmemcap.obj"
	-@erase "$(INTDIR)\sfprocpidstats.obj"
	-@erase "$(INTDIR)\sfsnprintfappend.obj"
	-@erase "$(INTDIR)\sfthd.obj"
	-@erase "$(INTDIR)\sfthreshold.obj"
	-@erase "$(INTDIR)\sfxhash.obj"
	-@erase "$(INTDIR)\signature.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort_httpinspect.obj"
	-@erase "$(INTDIR)\snort_stream4_session.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_asn1.obj"
	-@erase "$(INTDIR)\sp_byte_check.obj"
	-@erase "$(INTDIR)\sp_byte_jump.obj"
	-@erase "$(INTDIR)\sp_clientserver.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_flowbits.obj"
	-@erase "$(INTDIR)\sp_ftpbounce.obj"
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
	-@erase "$(INTDIR)\sp_isdataat.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pcre.obj"
	-@erase "$(INTDIR)\sp_react.obj"
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
	-@erase "$(INTDIR)\spo_alert_prelude.obj"
	-@erase "$(INTDIR)\spo_alert_sf_socket.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_ascii.obj"
	-@erase "$(INTDIR)\spo_log_null.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spp_arpspoof.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_conversation.obj"
	-@erase "$(INTDIR)\spp_flow.obj"
	-@erase "$(INTDIR)\spp_frag2.obj"
	-@erase "$(INTDIR)\spp_frag3.obj"
	-@erase "$(INTDIR)\spp_httpinspect.obj"
	-@erase "$(INTDIR)\spp_perfmonitor.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan2.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_sfportscan.obj"
	-@erase "$(INTDIR)\spp_stream4.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_xlink2state.obj"
	-@erase "$(INTDIR)\str_search.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strtok_r.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\ubi_BinTree.obj"
	-@erase "$(INTDIR)\ubi_SplayTree.obj"
	-@erase "$(INTDIR)\unique_tracker.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_math.obj"
	-@erase "$(INTDIR)\util_net.obj"
	-@erase "$(INTDIR)\util_str.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\win32_service.obj"
	-@erase "$(INTDIR)\xlink2state.obj"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "..\WIN32-Code\MSG00001.BIN"
	-@erase "..\WIN32-Code\name.h"
	-@erase "..\WIN32-Code\name.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MSSQL" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fp"$(INTDIR)\snort.pch" /YX"snort.pch" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib pcre.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\snort.pdb" /machine:I386 /out:"$(OUTDIR)\snort.exe" /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" 
LINK32_OBJS= \
	"$(INTDIR)\sp_asn1.obj" \
	"$(INTDIR)\sp_byte_check.obj" \
	"$(INTDIR)\sp_byte_jump.obj" \
	"$(INTDIR)\sp_clientserver.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_flowbits.obj" \
	"$(INTDIR)\sp_ftpbounce.obj" \
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
	"$(INTDIR)\sp_isdataat.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_pcre.obj" \
	"$(INTDIR)\sp_react.obj" \
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
	"$(INTDIR)\spo_alert_prelude.obj" \
	"$(INTDIR)\spo_alert_sf_socket.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_ascii.obj" \
	"$(INTDIR)\spo_log_null.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\IpAddrSet.obj" \
	"$(INTDIR)\flow_packet.obj" \
	"$(INTDIR)\flowps.obj" \
	"$(INTDIR)\flowps_snort.obj" \
	"$(INTDIR)\scoreboard.obj" \
	"$(INTDIR)\server_stats.obj" \
	"$(INTDIR)\unique_tracker.obj" \
	"$(INTDIR)\flow.obj" \
	"$(INTDIR)\flow_cache.obj" \
	"$(INTDIR)\flow_callback.obj" \
	"$(INTDIR)\flow_class.obj" \
	"$(INTDIR)\flow_hash.obj" \
	"$(INTDIR)\flow_print.obj" \
	"$(INTDIR)\flow_stat.obj" \
	"$(INTDIR)\hi_ad.obj" \
	"$(INTDIR)\hi_client.obj" \
	"$(INTDIR)\hi_client_norm.obj" \
	"$(INTDIR)\hi_eo_log.obj" \
	"$(INTDIR)\hi_mi.obj" \
	"$(INTDIR)\hi_norm.obj" \
	"$(INTDIR)\hi_server.obj" \
	"$(INTDIR)\hi_si.obj" \
	"$(INTDIR)\hi_ui_config.obj" \
	"$(INTDIR)\hi_ui_iis_unicode_map.obj" \
	"$(INTDIR)\hi_ui_server_lookup.obj" \
	"$(INTDIR)\hi_util_hbm.obj" \
	"$(INTDIR)\hi_util_kmap.obj" \
	"$(INTDIR)\hi_util_xmalloc.obj" \
	"$(INTDIR)\perf-base.obj" \
	"$(INTDIR)\perf-event.obj" \
	"$(INTDIR)\perf-flow.obj" \
	"$(INTDIR)\perf.obj" \
	"$(INTDIR)\portscan.obj" \
	"$(INTDIR)\sfprocpidstats.obj" \
	"$(INTDIR)\snort_httpinspect.obj" \
	"$(INTDIR)\snort_stream4_session.obj" \
	"$(INTDIR)\spp_arpspoof.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_conversation.obj" \
	"$(INTDIR)\spp_flow.obj" \
	"$(INTDIR)\spp_frag2.obj" \
	"$(INTDIR)\spp_frag3.obj" \
	"$(INTDIR)\spp_httpinspect.obj" \
	"$(INTDIR)\spp_perfmonitor.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_portscan2.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_sfportscan.obj" \
	"$(INTDIR)\spp_stream4.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_xlink2state.obj" \
	"$(INTDIR)\str_search.obj" \
	"$(INTDIR)\xlink2state.obj" \
	"$(INTDIR)\acsmx.obj" \
	"$(INTDIR)\acsmx2.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\ipobj.obj" \
	"$(INTDIR)\mpse.obj" \
	"$(INTDIR)\mwm.obj" \
	"$(INTDIR)\sfeventq.obj" \
	"$(INTDIR)\sfghash.obj" \
	"$(INTDIR)\sfhashfcn.obj" \
	"$(INTDIR)\sfksearch.obj" \
	"$(INTDIR)\sflsq.obj" \
	"$(INTDIR)\sfmemcap.obj" \
	"$(INTDIR)\sfsnprintfappend.obj" \
	"$(INTDIR)\sfthd.obj" \
	"$(INTDIR)\sfxhash.obj" \
	"$(INTDIR)\util_math.obj" \
	"$(INTDIR)\util_net.obj" \
	"$(INTDIR)\util_str.obj" \
	"$(INTDIR)\byte_extract.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\detect.obj" \
	"$(INTDIR)\event_queue.obj" \
	"$(INTDIR)\event_wrapper.obj" \
	"$(INTDIR)\fpcreate.obj" \
	"$(INTDIR)\fpdetect.obj" \
	"$(INTDIR)\inline.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mempool.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\packet_time.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\pcrm.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\sf_sdlist.obj" \
	"$(INTDIR)\sfthreshold.obj" \
	"$(INTDIR)\signature.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\ubi_BinTree.obj" \
	"$(INTDIR)\ubi_SplayTree.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\inet_aton.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\strtok_r.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\win32_service.obj" \
	"..\WIN32-Code\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

OUTDIR=.\snort___Win32_Oracle_Debug
INTDIR=.\snort___Win32_Oracle_Debug
# Begin Custom Macros
OutDir=.\snort___Win32_Oracle_Debug
# End Custom Macros

ALL : "..\WIN32-Code\name.rc" "..\WIN32-Code\name.h" "..\WIN32-Code\MSG00001.BIN" "$(OUTDIR)\snort.exe" "$(OUTDIR)\snort.bsc"


CLEAN :
	-@erase "$(INTDIR)\acsmx.obj"
	-@erase "$(INTDIR)\acsmx.sbr"
	-@erase "$(INTDIR)\acsmx2.obj"
	-@erase "$(INTDIR)\acsmx2.sbr"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\asn1.sbr"
	-@erase "$(INTDIR)\byte_extract.obj"
	-@erase "$(INTDIR)\byte_extract.sbr"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\codes.sbr"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\debug.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\detect.obj"
	-@erase "$(INTDIR)\detect.sbr"
	-@erase "$(INTDIR)\event_queue.obj"
	-@erase "$(INTDIR)\event_queue.sbr"
	-@erase "$(INTDIR)\event_wrapper.obj"
	-@erase "$(INTDIR)\event_wrapper.sbr"
	-@erase "$(INTDIR)\flow.obj"
	-@erase "$(INTDIR)\flow.sbr"
	-@erase "$(INTDIR)\flow_cache.obj"
	-@erase "$(INTDIR)\flow_cache.sbr"
	-@erase "$(INTDIR)\flow_callback.obj"
	-@erase "$(INTDIR)\flow_callback.sbr"
	-@erase "$(INTDIR)\flow_class.obj"
	-@erase "$(INTDIR)\flow_class.sbr"
	-@erase "$(INTDIR)\flow_hash.obj"
	-@erase "$(INTDIR)\flow_hash.sbr"
	-@erase "$(INTDIR)\flow_packet.obj"
	-@erase "$(INTDIR)\flow_packet.sbr"
	-@erase "$(INTDIR)\flow_print.obj"
	-@erase "$(INTDIR)\flow_print.sbr"
	-@erase "$(INTDIR)\flow_stat.obj"
	-@erase "$(INTDIR)\flow_stat.sbr"
	-@erase "$(INTDIR)\flowps.obj"
	-@erase "$(INTDIR)\flowps.sbr"
	-@erase "$(INTDIR)\flowps_snort.obj"
	-@erase "$(INTDIR)\flowps_snort.sbr"
	-@erase "$(INTDIR)\fpcreate.obj"
	-@erase "$(INTDIR)\fpcreate.sbr"
	-@erase "$(INTDIR)\fpdetect.obj"
	-@erase "$(INTDIR)\fpdetect.sbr"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\getopt.sbr"
	-@erase "$(INTDIR)\hi_ad.obj"
	-@erase "$(INTDIR)\hi_ad.sbr"
	-@erase "$(INTDIR)\hi_client.obj"
	-@erase "$(INTDIR)\hi_client.sbr"
	-@erase "$(INTDIR)\hi_client_norm.obj"
	-@erase "$(INTDIR)\hi_client_norm.sbr"
	-@erase "$(INTDIR)\hi_eo_log.obj"
	-@erase "$(INTDIR)\hi_eo_log.sbr"
	-@erase "$(INTDIR)\hi_mi.obj"
	-@erase "$(INTDIR)\hi_mi.sbr"
	-@erase "$(INTDIR)\hi_norm.obj"
	-@erase "$(INTDIR)\hi_norm.sbr"
	-@erase "$(INTDIR)\hi_server.obj"
	-@erase "$(INTDIR)\hi_server.sbr"
	-@erase "$(INTDIR)\hi_si.obj"
	-@erase "$(INTDIR)\hi_si.sbr"
	-@erase "$(INTDIR)\hi_ui_config.obj"
	-@erase "$(INTDIR)\hi_ui_config.sbr"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.obj"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.sbr"
	-@erase "$(INTDIR)\hi_ui_server_lookup.obj"
	-@erase "$(INTDIR)\hi_ui_server_lookup.sbr"
	-@erase "$(INTDIR)\hi_util_hbm.obj"
	-@erase "$(INTDIR)\hi_util_hbm.sbr"
	-@erase "$(INTDIR)\hi_util_kmap.obj"
	-@erase "$(INTDIR)\hi_util_kmap.sbr"
	-@erase "$(INTDIR)\hi_util_xmalloc.obj"
	-@erase "$(INTDIR)\hi_util_xmalloc.sbr"
	-@erase "$(INTDIR)\inet_aton.obj"
	-@erase "$(INTDIR)\inet_aton.sbr"
	-@erase "$(INTDIR)\inline.obj"
	-@erase "$(INTDIR)\inline.sbr"
	-@erase "$(INTDIR)\IpAddrSet.obj"
	-@erase "$(INTDIR)\IpAddrSet.sbr"
	-@erase "$(INTDIR)\ipobj.obj"
	-@erase "$(INTDIR)\ipobj.sbr"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\log.sbr"
	-@erase "$(INTDIR)\mempool.obj"
	-@erase "$(INTDIR)\mempool.sbr"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\misc.sbr"
	-@erase "$(INTDIR)\mpse.obj"
	-@erase "$(INTDIR)\mpse.sbr"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mstring.sbr"
	-@erase "$(INTDIR)\mwm.obj"
	-@erase "$(INTDIR)\mwm.sbr"
	-@erase "$(INTDIR)\packet_time.obj"
	-@erase "$(INTDIR)\packet_time.sbr"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\parser.sbr"
	-@erase "$(INTDIR)\pcrm.obj"
	-@erase "$(INTDIR)\pcrm.sbr"
	-@erase "$(INTDIR)\perf-base.obj"
	-@erase "$(INTDIR)\perf-base.sbr"
	-@erase "$(INTDIR)\perf-event.obj"
	-@erase "$(INTDIR)\perf-event.sbr"
	-@erase "$(INTDIR)\perf-flow.obj"
	-@erase "$(INTDIR)\perf-flow.sbr"
	-@erase "$(INTDIR)\perf.obj"
	-@erase "$(INTDIR)\perf.sbr"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\plugbase.sbr"
	-@erase "$(INTDIR)\portscan.obj"
	-@erase "$(INTDIR)\portscan.sbr"
	-@erase "$(INTDIR)\scoreboard.obj"
	-@erase "$(INTDIR)\scoreboard.sbr"
	-@erase "$(INTDIR)\server_stats.obj"
	-@erase "$(INTDIR)\server_stats.sbr"
	-@erase "$(INTDIR)\sf_sdlist.obj"
	-@erase "$(INTDIR)\sf_sdlist.sbr"
	-@erase "$(INTDIR)\sfeventq.obj"
	-@erase "$(INTDIR)\sfeventq.sbr"
	-@erase "$(INTDIR)\sfghash.obj"
	-@erase "$(INTDIR)\sfghash.sbr"
	-@erase "$(INTDIR)\sfhashfcn.obj"
	-@erase "$(INTDIR)\sfhashfcn.sbr"
	-@erase "$(INTDIR)\sfksearch.obj"
	-@erase "$(INTDIR)\sfksearch.sbr"
	-@erase "$(INTDIR)\sflsq.obj"
	-@erase "$(INTDIR)\sflsq.sbr"
	-@erase "$(INTDIR)\sfmemcap.obj"
	-@erase "$(INTDIR)\sfmemcap.sbr"
	-@erase "$(INTDIR)\sfprocpidstats.obj"
	-@erase "$(INTDIR)\sfprocpidstats.sbr"
	-@erase "$(INTDIR)\sfsnprintfappend.obj"
	-@erase "$(INTDIR)\sfsnprintfappend.sbr"
	-@erase "$(INTDIR)\sfthd.obj"
	-@erase "$(INTDIR)\sfthd.sbr"
	-@erase "$(INTDIR)\sfthreshold.obj"
	-@erase "$(INTDIR)\sfthreshold.sbr"
	-@erase "$(INTDIR)\sfxhash.obj"
	-@erase "$(INTDIR)\sfxhash.sbr"
	-@erase "$(INTDIR)\signature.obj"
	-@erase "$(INTDIR)\signature.sbr"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort.sbr"
	-@erase "$(INTDIR)\snort_httpinspect.obj"
	-@erase "$(INTDIR)\snort_httpinspect.sbr"
	-@erase "$(INTDIR)\snort_stream4_session.obj"
	-@erase "$(INTDIR)\snort_stream4_session.sbr"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\snprintf.sbr"
	-@erase "$(INTDIR)\sp_asn1.obj"
	-@erase "$(INTDIR)\sp_asn1.sbr"
	-@erase "$(INTDIR)\sp_byte_check.obj"
	-@erase "$(INTDIR)\sp_byte_check.sbr"
	-@erase "$(INTDIR)\sp_byte_jump.obj"
	-@erase "$(INTDIR)\sp_byte_jump.sbr"
	-@erase "$(INTDIR)\sp_clientserver.obj"
	-@erase "$(INTDIR)\sp_clientserver.sbr"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_dsize_check.sbr"
	-@erase "$(INTDIR)\sp_flowbits.obj"
	-@erase "$(INTDIR)\sp_flowbits.sbr"
	-@erase "$(INTDIR)\sp_ftpbounce.obj"
	-@erase "$(INTDIR)\sp_ftpbounce.sbr"
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
	-@erase "$(INTDIR)\sp_isdataat.obj"
	-@erase "$(INTDIR)\sp_isdataat.sbr"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pattern_match.sbr"
	-@erase "$(INTDIR)\sp_pcre.obj"
	-@erase "$(INTDIR)\sp_pcre.sbr"
	-@erase "$(INTDIR)\sp_react.obj"
	-@erase "$(INTDIR)\sp_react.sbr"
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
	-@erase "$(INTDIR)\spo_alert_prelude.obj"
	-@erase "$(INTDIR)\spo_alert_prelude.sbr"
	-@erase "$(INTDIR)\spo_alert_sf_socket.obj"
	-@erase "$(INTDIR)\spo_alert_sf_socket.sbr"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.sbr"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.sbr"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_csv.sbr"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_database.sbr"
	-@erase "$(INTDIR)\spo_log_ascii.obj"
	-@erase "$(INTDIR)\spo_log_ascii.sbr"
	-@erase "$(INTDIR)\spo_log_null.obj"
	-@erase "$(INTDIR)\spo_log_null.sbr"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.sbr"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spo_unified.sbr"
	-@erase "$(INTDIR)\spp_arpspoof.obj"
	-@erase "$(INTDIR)\spp_arpspoof.sbr"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_bo.sbr"
	-@erase "$(INTDIR)\spp_conversation.obj"
	-@erase "$(INTDIR)\spp_conversation.sbr"
	-@erase "$(INTDIR)\spp_flow.obj"
	-@erase "$(INTDIR)\spp_flow.sbr"
	-@erase "$(INTDIR)\spp_frag2.obj"
	-@erase "$(INTDIR)\spp_frag2.sbr"
	-@erase "$(INTDIR)\spp_frag3.obj"
	-@erase "$(INTDIR)\spp_frag3.sbr"
	-@erase "$(INTDIR)\spp_httpinspect.obj"
	-@erase "$(INTDIR)\spp_httpinspect.sbr"
	-@erase "$(INTDIR)\spp_perfmonitor.obj"
	-@erase "$(INTDIR)\spp_perfmonitor.sbr"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan.sbr"
	-@erase "$(INTDIR)\spp_portscan2.obj"
	-@erase "$(INTDIR)\spp_portscan2.sbr"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.sbr"
	-@erase "$(INTDIR)\spp_sfportscan.obj"
	-@erase "$(INTDIR)\spp_sfportscan.sbr"
	-@erase "$(INTDIR)\spp_stream4.obj"
	-@erase "$(INTDIR)\spp_stream4.sbr"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.sbr"
	-@erase "$(INTDIR)\spp_xlink2state.obj"
	-@erase "$(INTDIR)\spp_xlink2state.sbr"
	-@erase "$(INTDIR)\str_search.obj"
	-@erase "$(INTDIR)\str_search.sbr"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcatu.sbr"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strlcpyu.sbr"
	-@erase "$(INTDIR)\strtok_r.obj"
	-@erase "$(INTDIR)\strtok_r.sbr"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\syslog.sbr"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\tag.sbr"
	-@erase "$(INTDIR)\ubi_BinTree.obj"
	-@erase "$(INTDIR)\ubi_BinTree.sbr"
	-@erase "$(INTDIR)\ubi_SplayTree.obj"
	-@erase "$(INTDIR)\ubi_SplayTree.sbr"
	-@erase "$(INTDIR)\unique_tracker.obj"
	-@erase "$(INTDIR)\unique_tracker.sbr"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util.sbr"
	-@erase "$(INTDIR)\util_math.obj"
	-@erase "$(INTDIR)\util_math.sbr"
	-@erase "$(INTDIR)\util_net.obj"
	-@erase "$(INTDIR)\util_net.sbr"
	-@erase "$(INTDIR)\util_str.obj"
	-@erase "$(INTDIR)\util_str.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(INTDIR)\win32_service.obj"
	-@erase "$(INTDIR)\win32_service.sbr"
	-@erase "$(INTDIR)\xlink2state.obj"
	-@erase "$(INTDIR)\xlink2state.sbr"
	-@erase "$(OUTDIR)\snort.bsc"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "$(OUTDIR)\snort.ilk"
	-@erase "$(OUTDIR)\snort.pdb"
	-@erase "..\WIN32-Code\MSG00001.BIN"
	-@erase "..\WIN32-Code\name.h"
	-@erase "..\WIN32-Code\name.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "D:\oracle\ora92\oci\include" /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_ORACLE" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fr"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX"snort.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\sp_asn1.sbr" \
	"$(INTDIR)\sp_byte_check.sbr" \
	"$(INTDIR)\sp_byte_jump.sbr" \
	"$(INTDIR)\sp_clientserver.sbr" \
	"$(INTDIR)\sp_dsize_check.sbr" \
	"$(INTDIR)\sp_flowbits.sbr" \
	"$(INTDIR)\sp_ftpbounce.sbr" \
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
	"$(INTDIR)\sp_isdataat.sbr" \
	"$(INTDIR)\sp_pattern_match.sbr" \
	"$(INTDIR)\sp_pcre.sbr" \
	"$(INTDIR)\sp_react.sbr" \
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
	"$(INTDIR)\spo_alert_prelude.sbr" \
	"$(INTDIR)\spo_alert_sf_socket.sbr" \
	"$(INTDIR)\spo_alert_syslog.sbr" \
	"$(INTDIR)\spo_alert_unixsock.sbr" \
	"$(INTDIR)\spo_csv.sbr" \
	"$(INTDIR)\spo_database.sbr" \
	"$(INTDIR)\spo_log_ascii.sbr" \
	"$(INTDIR)\spo_log_null.sbr" \
	"$(INTDIR)\spo_log_tcpdump.sbr" \
	"$(INTDIR)\spo_unified.sbr" \
	"$(INTDIR)\IpAddrSet.sbr" \
	"$(INTDIR)\flow_packet.sbr" \
	"$(INTDIR)\flowps.sbr" \
	"$(INTDIR)\flowps_snort.sbr" \
	"$(INTDIR)\scoreboard.sbr" \
	"$(INTDIR)\server_stats.sbr" \
	"$(INTDIR)\unique_tracker.sbr" \
	"$(INTDIR)\flow.sbr" \
	"$(INTDIR)\flow_cache.sbr" \
	"$(INTDIR)\flow_callback.sbr" \
	"$(INTDIR)\flow_class.sbr" \
	"$(INTDIR)\flow_hash.sbr" \
	"$(INTDIR)\flow_print.sbr" \
	"$(INTDIR)\flow_stat.sbr" \
	"$(INTDIR)\hi_ad.sbr" \
	"$(INTDIR)\hi_client.sbr" \
	"$(INTDIR)\hi_client_norm.sbr" \
	"$(INTDIR)\hi_eo_log.sbr" \
	"$(INTDIR)\hi_mi.sbr" \
	"$(INTDIR)\hi_norm.sbr" \
	"$(INTDIR)\hi_server.sbr" \
	"$(INTDIR)\hi_si.sbr" \
	"$(INTDIR)\hi_ui_config.sbr" \
	"$(INTDIR)\hi_ui_iis_unicode_map.sbr" \
	"$(INTDIR)\hi_ui_server_lookup.sbr" \
	"$(INTDIR)\hi_util_hbm.sbr" \
	"$(INTDIR)\hi_util_kmap.sbr" \
	"$(INTDIR)\hi_util_xmalloc.sbr" \
	"$(INTDIR)\perf-base.sbr" \
	"$(INTDIR)\perf-event.sbr" \
	"$(INTDIR)\perf-flow.sbr" \
	"$(INTDIR)\perf.sbr" \
	"$(INTDIR)\portscan.sbr" \
	"$(INTDIR)\sfprocpidstats.sbr" \
	"$(INTDIR)\snort_httpinspect.sbr" \
	"$(INTDIR)\snort_stream4_session.sbr" \
	"$(INTDIR)\spp_arpspoof.sbr" \
	"$(INTDIR)\spp_bo.sbr" \
	"$(INTDIR)\spp_conversation.sbr" \
	"$(INTDIR)\spp_flow.sbr" \
	"$(INTDIR)\spp_frag2.sbr" \
	"$(INTDIR)\spp_frag3.sbr" \
	"$(INTDIR)\spp_httpinspect.sbr" \
	"$(INTDIR)\spp_perfmonitor.sbr" \
	"$(INTDIR)\spp_portscan.sbr" \
	"$(INTDIR)\spp_portscan2.sbr" \
	"$(INTDIR)\spp_rpc_decode.sbr" \
	"$(INTDIR)\spp_sfportscan.sbr" \
	"$(INTDIR)\spp_stream4.sbr" \
	"$(INTDIR)\spp_telnet_negotiation.sbr" \
	"$(INTDIR)\spp_xlink2state.sbr" \
	"$(INTDIR)\str_search.sbr" \
	"$(INTDIR)\xlink2state.sbr" \
	"$(INTDIR)\acsmx.sbr" \
	"$(INTDIR)\acsmx2.sbr" \
	"$(INTDIR)\asn1.sbr" \
	"$(INTDIR)\ipobj.sbr" \
	"$(INTDIR)\mpse.sbr" \
	"$(INTDIR)\mwm.sbr" \
	"$(INTDIR)\sfeventq.sbr" \
	"$(INTDIR)\sfghash.sbr" \
	"$(INTDIR)\sfhashfcn.sbr" \
	"$(INTDIR)\sfksearch.sbr" \
	"$(INTDIR)\sflsq.sbr" \
	"$(INTDIR)\sfmemcap.sbr" \
	"$(INTDIR)\sfsnprintfappend.sbr" \
	"$(INTDIR)\sfthd.sbr" \
	"$(INTDIR)\sfxhash.sbr" \
	"$(INTDIR)\util_math.sbr" \
	"$(INTDIR)\util_net.sbr" \
	"$(INTDIR)\util_str.sbr" \
	"$(INTDIR)\byte_extract.sbr" \
	"$(INTDIR)\codes.sbr" \
	"$(INTDIR)\debug.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\detect.sbr" \
	"$(INTDIR)\event_queue.sbr" \
	"$(INTDIR)\event_wrapper.sbr" \
	"$(INTDIR)\fpcreate.sbr" \
	"$(INTDIR)\fpdetect.sbr" \
	"$(INTDIR)\inline.sbr" \
	"$(INTDIR)\log.sbr" \
	"$(INTDIR)\mempool.sbr" \
	"$(INTDIR)\mstring.sbr" \
	"$(INTDIR)\packet_time.sbr" \
	"$(INTDIR)\parser.sbr" \
	"$(INTDIR)\pcrm.sbr" \
	"$(INTDIR)\plugbase.sbr" \
	"$(INTDIR)\sf_sdlist.sbr" \
	"$(INTDIR)\sfthreshold.sbr" \
	"$(INTDIR)\signature.sbr" \
	"$(INTDIR)\snort.sbr" \
	"$(INTDIR)\snprintf.sbr" \
	"$(INTDIR)\strlcatu.sbr" \
	"$(INTDIR)\strlcpyu.sbr" \
	"$(INTDIR)\tag.sbr" \
	"$(INTDIR)\ubi_BinTree.sbr" \
	"$(INTDIR)\ubi_SplayTree.sbr" \
	"$(INTDIR)\util.sbr" \
	"$(INTDIR)\getopt.sbr" \
	"$(INTDIR)\inet_aton.sbr" \
	"$(INTDIR)\misc.sbr" \
	"$(INTDIR)\strtok_r.sbr" \
	"$(INTDIR)\syslog.sbr" \
	"$(INTDIR)\win32_service.sbr"

"$(OUTDIR)\snort.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib pcre.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib oci.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\snort.pdb" /debug /machine:I386 /out:"$(OUTDIR)\snort.exe" /pdbtype:sept /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" /libpath:"D:\oracle\ora92\oci\lib\msvc" 
LINK32_OBJS= \
	"$(INTDIR)\sp_asn1.obj" \
	"$(INTDIR)\sp_byte_check.obj" \
	"$(INTDIR)\sp_byte_jump.obj" \
	"$(INTDIR)\sp_clientserver.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_flowbits.obj" \
	"$(INTDIR)\sp_ftpbounce.obj" \
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
	"$(INTDIR)\sp_isdataat.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_pcre.obj" \
	"$(INTDIR)\sp_react.obj" \
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
	"$(INTDIR)\spo_alert_prelude.obj" \
	"$(INTDIR)\spo_alert_sf_socket.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_ascii.obj" \
	"$(INTDIR)\spo_log_null.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\IpAddrSet.obj" \
	"$(INTDIR)\flow_packet.obj" \
	"$(INTDIR)\flowps.obj" \
	"$(INTDIR)\flowps_snort.obj" \
	"$(INTDIR)\scoreboard.obj" \
	"$(INTDIR)\server_stats.obj" \
	"$(INTDIR)\unique_tracker.obj" \
	"$(INTDIR)\flow.obj" \
	"$(INTDIR)\flow_cache.obj" \
	"$(INTDIR)\flow_callback.obj" \
	"$(INTDIR)\flow_class.obj" \
	"$(INTDIR)\flow_hash.obj" \
	"$(INTDIR)\flow_print.obj" \
	"$(INTDIR)\flow_stat.obj" \
	"$(INTDIR)\hi_ad.obj" \
	"$(INTDIR)\hi_client.obj" \
	"$(INTDIR)\hi_client_norm.obj" \
	"$(INTDIR)\hi_eo_log.obj" \
	"$(INTDIR)\hi_mi.obj" \
	"$(INTDIR)\hi_norm.obj" \
	"$(INTDIR)\hi_server.obj" \
	"$(INTDIR)\hi_si.obj" \
	"$(INTDIR)\hi_ui_config.obj" \
	"$(INTDIR)\hi_ui_iis_unicode_map.obj" \
	"$(INTDIR)\hi_ui_server_lookup.obj" \
	"$(INTDIR)\hi_util_hbm.obj" \
	"$(INTDIR)\hi_util_kmap.obj" \
	"$(INTDIR)\hi_util_xmalloc.obj" \
	"$(INTDIR)\perf-base.obj" \
	"$(INTDIR)\perf-event.obj" \
	"$(INTDIR)\perf-flow.obj" \
	"$(INTDIR)\perf.obj" \
	"$(INTDIR)\portscan.obj" \
	"$(INTDIR)\sfprocpidstats.obj" \
	"$(INTDIR)\snort_httpinspect.obj" \
	"$(INTDIR)\snort_stream4_session.obj" \
	"$(INTDIR)\spp_arpspoof.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_conversation.obj" \
	"$(INTDIR)\spp_flow.obj" \
	"$(INTDIR)\spp_frag2.obj" \
	"$(INTDIR)\spp_frag3.obj" \
	"$(INTDIR)\spp_httpinspect.obj" \
	"$(INTDIR)\spp_perfmonitor.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_portscan2.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_sfportscan.obj" \
	"$(INTDIR)\spp_stream4.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_xlink2state.obj" \
	"$(INTDIR)\str_search.obj" \
	"$(INTDIR)\xlink2state.obj" \
	"$(INTDIR)\acsmx.obj" \
	"$(INTDIR)\acsmx2.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\ipobj.obj" \
	"$(INTDIR)\mpse.obj" \
	"$(INTDIR)\mwm.obj" \
	"$(INTDIR)\sfeventq.obj" \
	"$(INTDIR)\sfghash.obj" \
	"$(INTDIR)\sfhashfcn.obj" \
	"$(INTDIR)\sfksearch.obj" \
	"$(INTDIR)\sflsq.obj" \
	"$(INTDIR)\sfmemcap.obj" \
	"$(INTDIR)\sfsnprintfappend.obj" \
	"$(INTDIR)\sfthd.obj" \
	"$(INTDIR)\sfxhash.obj" \
	"$(INTDIR)\util_math.obj" \
	"$(INTDIR)\util_net.obj" \
	"$(INTDIR)\util_str.obj" \
	"$(INTDIR)\byte_extract.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\detect.obj" \
	"$(INTDIR)\event_queue.obj" \
	"$(INTDIR)\event_wrapper.obj" \
	"$(INTDIR)\fpcreate.obj" \
	"$(INTDIR)\fpdetect.obj" \
	"$(INTDIR)\inline.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mempool.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\packet_time.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\pcrm.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\sf_sdlist.obj" \
	"$(INTDIR)\sfthreshold.obj" \
	"$(INTDIR)\signature.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\ubi_BinTree.obj" \
	"$(INTDIR)\ubi_SplayTree.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\inet_aton.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\strtok_r.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\win32_service.obj" \
	"..\WIN32-Code\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

OUTDIR=.\snort___Win32_Oracle_Release
INTDIR=.\snort___Win32_Oracle_Release
# Begin Custom Macros
OutDir=.\snort___Win32_Oracle_Release
# End Custom Macros

ALL : "..\WIN32-Code\name.rc" "..\WIN32-Code\name.h" "..\WIN32-Code\MSG00001.BIN" "$(OUTDIR)\snort.exe"


CLEAN :
	-@erase "$(INTDIR)\acsmx.obj"
	-@erase "$(INTDIR)\acsmx2.obj"
	-@erase "$(INTDIR)\asn1.obj"
	-@erase "$(INTDIR)\byte_extract.obj"
	-@erase "$(INTDIR)\codes.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\detect.obj"
	-@erase "$(INTDIR)\event_queue.obj"
	-@erase "$(INTDIR)\event_wrapper.obj"
	-@erase "$(INTDIR)\flow.obj"
	-@erase "$(INTDIR)\flow_cache.obj"
	-@erase "$(INTDIR)\flow_callback.obj"
	-@erase "$(INTDIR)\flow_class.obj"
	-@erase "$(INTDIR)\flow_hash.obj"
	-@erase "$(INTDIR)\flow_packet.obj"
	-@erase "$(INTDIR)\flow_print.obj"
	-@erase "$(INTDIR)\flow_stat.obj"
	-@erase "$(INTDIR)\flowps.obj"
	-@erase "$(INTDIR)\flowps_snort.obj"
	-@erase "$(INTDIR)\fpcreate.obj"
	-@erase "$(INTDIR)\fpdetect.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\hi_ad.obj"
	-@erase "$(INTDIR)\hi_client.obj"
	-@erase "$(INTDIR)\hi_client_norm.obj"
	-@erase "$(INTDIR)\hi_eo_log.obj"
	-@erase "$(INTDIR)\hi_mi.obj"
	-@erase "$(INTDIR)\hi_norm.obj"
	-@erase "$(INTDIR)\hi_server.obj"
	-@erase "$(INTDIR)\hi_si.obj"
	-@erase "$(INTDIR)\hi_ui_config.obj"
	-@erase "$(INTDIR)\hi_ui_iis_unicode_map.obj"
	-@erase "$(INTDIR)\hi_ui_server_lookup.obj"
	-@erase "$(INTDIR)\hi_util_hbm.obj"
	-@erase "$(INTDIR)\hi_util_kmap.obj"
	-@erase "$(INTDIR)\hi_util_xmalloc.obj"
	-@erase "$(INTDIR)\inet_aton.obj"
	-@erase "$(INTDIR)\inline.obj"
	-@erase "$(INTDIR)\IpAddrSet.obj"
	-@erase "$(INTDIR)\ipobj.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\mempool.obj"
	-@erase "$(INTDIR)\misc.obj"
	-@erase "$(INTDIR)\mpse.obj"
	-@erase "$(INTDIR)\mstring.obj"
	-@erase "$(INTDIR)\mwm.obj"
	-@erase "$(INTDIR)\packet_time.obj"
	-@erase "$(INTDIR)\parser.obj"
	-@erase "$(INTDIR)\pcrm.obj"
	-@erase "$(INTDIR)\perf-base.obj"
	-@erase "$(INTDIR)\perf-event.obj"
	-@erase "$(INTDIR)\perf-flow.obj"
	-@erase "$(INTDIR)\perf.obj"
	-@erase "$(INTDIR)\plugbase.obj"
	-@erase "$(INTDIR)\portscan.obj"
	-@erase "$(INTDIR)\scoreboard.obj"
	-@erase "$(INTDIR)\server_stats.obj"
	-@erase "$(INTDIR)\sf_sdlist.obj"
	-@erase "$(INTDIR)\sfeventq.obj"
	-@erase "$(INTDIR)\sfghash.obj"
	-@erase "$(INTDIR)\sfhashfcn.obj"
	-@erase "$(INTDIR)\sfksearch.obj"
	-@erase "$(INTDIR)\sflsq.obj"
	-@erase "$(INTDIR)\sfmemcap.obj"
	-@erase "$(INTDIR)\sfprocpidstats.obj"
	-@erase "$(INTDIR)\sfsnprintfappend.obj"
	-@erase "$(INTDIR)\sfthd.obj"
	-@erase "$(INTDIR)\sfthreshold.obj"
	-@erase "$(INTDIR)\sfxhash.obj"
	-@erase "$(INTDIR)\signature.obj"
	-@erase "$(INTDIR)\snort.obj"
	-@erase "$(INTDIR)\snort_httpinspect.obj"
	-@erase "$(INTDIR)\snort_stream4_session.obj"
	-@erase "$(INTDIR)\snprintf.obj"
	-@erase "$(INTDIR)\sp_asn1.obj"
	-@erase "$(INTDIR)\sp_byte_check.obj"
	-@erase "$(INTDIR)\sp_byte_jump.obj"
	-@erase "$(INTDIR)\sp_clientserver.obj"
	-@erase "$(INTDIR)\sp_dsize_check.obj"
	-@erase "$(INTDIR)\sp_flowbits.obj"
	-@erase "$(INTDIR)\sp_ftpbounce.obj"
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
	-@erase "$(INTDIR)\sp_isdataat.obj"
	-@erase "$(INTDIR)\sp_pattern_match.obj"
	-@erase "$(INTDIR)\sp_pcre.obj"
	-@erase "$(INTDIR)\sp_react.obj"
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
	-@erase "$(INTDIR)\spo_alert_prelude.obj"
	-@erase "$(INTDIR)\spo_alert_sf_socket.obj"
	-@erase "$(INTDIR)\spo_alert_syslog.obj"
	-@erase "$(INTDIR)\spo_alert_unixsock.obj"
	-@erase "$(INTDIR)\spo_csv.obj"
	-@erase "$(INTDIR)\spo_database.obj"
	-@erase "$(INTDIR)\spo_log_ascii.obj"
	-@erase "$(INTDIR)\spo_log_null.obj"
	-@erase "$(INTDIR)\spo_log_tcpdump.obj"
	-@erase "$(INTDIR)\spo_unified.obj"
	-@erase "$(INTDIR)\spp_arpspoof.obj"
	-@erase "$(INTDIR)\spp_bo.obj"
	-@erase "$(INTDIR)\spp_conversation.obj"
	-@erase "$(INTDIR)\spp_flow.obj"
	-@erase "$(INTDIR)\spp_frag2.obj"
	-@erase "$(INTDIR)\spp_frag3.obj"
	-@erase "$(INTDIR)\spp_httpinspect.obj"
	-@erase "$(INTDIR)\spp_perfmonitor.obj"
	-@erase "$(INTDIR)\spp_portscan.obj"
	-@erase "$(INTDIR)\spp_portscan2.obj"
	-@erase "$(INTDIR)\spp_rpc_decode.obj"
	-@erase "$(INTDIR)\spp_sfportscan.obj"
	-@erase "$(INTDIR)\spp_stream4.obj"
	-@erase "$(INTDIR)\spp_telnet_negotiation.obj"
	-@erase "$(INTDIR)\spp_xlink2state.obj"
	-@erase "$(INTDIR)\str_search.obj"
	-@erase "$(INTDIR)\strlcatu.obj"
	-@erase "$(INTDIR)\strlcpyu.obj"
	-@erase "$(INTDIR)\strtok_r.obj"
	-@erase "$(INTDIR)\syslog.obj"
	-@erase "$(INTDIR)\tag.obj"
	-@erase "$(INTDIR)\ubi_BinTree.obj"
	-@erase "$(INTDIR)\ubi_SplayTree.obj"
	-@erase "$(INTDIR)\unique_tracker.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_math.obj"
	-@erase "$(INTDIR)\util_net.obj"
	-@erase "$(INTDIR)\util_str.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\win32_service.obj"
	-@erase "$(INTDIR)\xlink2state.obj"
	-@erase "$(OUTDIR)\snort.exe"
	-@erase "..\WIN32-Code\MSG00001.BIN"
	-@erase "..\WIN32-Code\name.h"
	-@erase "..\WIN32-Code\name.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "D:\oracle\ora92\oci\include" /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_ORACLE" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fp"$(INTDIR)\snort.pch" /YX"snort.pch" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\name.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\snort.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib wsock32.lib pcre.lib libpcap.lib advapi32.lib Ntwdblib.lib mysqlclient.lib libnetnt.lib odbc32.lib oci.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\snort.pdb" /machine:I386 /out:"$(OUTDIR)\snort.exe" /libpath:"..\Win32-Libraries" /libpath:"..\Win32-Libraries\mysql" /libpath:"..\Win32-Libraries\libnet" /libpath:"D:\oracle\ora92\oci\lib\msvc" 
LINK32_OBJS= \
	"$(INTDIR)\sp_asn1.obj" \
	"$(INTDIR)\sp_byte_check.obj" \
	"$(INTDIR)\sp_byte_jump.obj" \
	"$(INTDIR)\sp_clientserver.obj" \
	"$(INTDIR)\sp_dsize_check.obj" \
	"$(INTDIR)\sp_flowbits.obj" \
	"$(INTDIR)\sp_ftpbounce.obj" \
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
	"$(INTDIR)\sp_isdataat.obj" \
	"$(INTDIR)\sp_pattern_match.obj" \
	"$(INTDIR)\sp_pcre.obj" \
	"$(INTDIR)\sp_react.obj" \
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
	"$(INTDIR)\spo_alert_prelude.obj" \
	"$(INTDIR)\spo_alert_sf_socket.obj" \
	"$(INTDIR)\spo_alert_syslog.obj" \
	"$(INTDIR)\spo_alert_unixsock.obj" \
	"$(INTDIR)\spo_csv.obj" \
	"$(INTDIR)\spo_database.obj" \
	"$(INTDIR)\spo_log_ascii.obj" \
	"$(INTDIR)\spo_log_null.obj" \
	"$(INTDIR)\spo_log_tcpdump.obj" \
	"$(INTDIR)\spo_unified.obj" \
	"$(INTDIR)\IpAddrSet.obj" \
	"$(INTDIR)\flow_packet.obj" \
	"$(INTDIR)\flowps.obj" \
	"$(INTDIR)\flowps_snort.obj" \
	"$(INTDIR)\scoreboard.obj" \
	"$(INTDIR)\server_stats.obj" \
	"$(INTDIR)\unique_tracker.obj" \
	"$(INTDIR)\flow.obj" \
	"$(INTDIR)\flow_cache.obj" \
	"$(INTDIR)\flow_callback.obj" \
	"$(INTDIR)\flow_class.obj" \
	"$(INTDIR)\flow_hash.obj" \
	"$(INTDIR)\flow_print.obj" \
	"$(INTDIR)\flow_stat.obj" \
	"$(INTDIR)\hi_ad.obj" \
	"$(INTDIR)\hi_client.obj" \
	"$(INTDIR)\hi_client_norm.obj" \
	"$(INTDIR)\hi_eo_log.obj" \
	"$(INTDIR)\hi_mi.obj" \
	"$(INTDIR)\hi_norm.obj" \
	"$(INTDIR)\hi_server.obj" \
	"$(INTDIR)\hi_si.obj" \
	"$(INTDIR)\hi_ui_config.obj" \
	"$(INTDIR)\hi_ui_iis_unicode_map.obj" \
	"$(INTDIR)\hi_ui_server_lookup.obj" \
	"$(INTDIR)\hi_util_hbm.obj" \
	"$(INTDIR)\hi_util_kmap.obj" \
	"$(INTDIR)\hi_util_xmalloc.obj" \
	"$(INTDIR)\perf-base.obj" \
	"$(INTDIR)\perf-event.obj" \
	"$(INTDIR)\perf-flow.obj" \
	"$(INTDIR)\perf.obj" \
	"$(INTDIR)\portscan.obj" \
	"$(INTDIR)\sfprocpidstats.obj" \
	"$(INTDIR)\snort_httpinspect.obj" \
	"$(INTDIR)\snort_stream4_session.obj" \
	"$(INTDIR)\spp_arpspoof.obj" \
	"$(INTDIR)\spp_bo.obj" \
	"$(INTDIR)\spp_conversation.obj" \
	"$(INTDIR)\spp_flow.obj" \
	"$(INTDIR)\spp_frag2.obj" \
	"$(INTDIR)\spp_frag3.obj" \
	"$(INTDIR)\spp_httpinspect.obj" \
	"$(INTDIR)\spp_perfmonitor.obj" \
	"$(INTDIR)\spp_portscan.obj" \
	"$(INTDIR)\spp_portscan2.obj" \
	"$(INTDIR)\spp_rpc_decode.obj" \
	"$(INTDIR)\spp_sfportscan.obj" \
	"$(INTDIR)\spp_stream4.obj" \
	"$(INTDIR)\spp_telnet_negotiation.obj" \
	"$(INTDIR)\spp_xlink2state.obj" \
	"$(INTDIR)\str_search.obj" \
	"$(INTDIR)\xlink2state.obj" \
	"$(INTDIR)\acsmx.obj" \
	"$(INTDIR)\acsmx2.obj" \
	"$(INTDIR)\asn1.obj" \
	"$(INTDIR)\ipobj.obj" \
	"$(INTDIR)\mpse.obj" \
	"$(INTDIR)\mwm.obj" \
	"$(INTDIR)\sfeventq.obj" \
	"$(INTDIR)\sfghash.obj" \
	"$(INTDIR)\sfhashfcn.obj" \
	"$(INTDIR)\sfksearch.obj" \
	"$(INTDIR)\sflsq.obj" \
	"$(INTDIR)\sfmemcap.obj" \
	"$(INTDIR)\sfsnprintfappend.obj" \
	"$(INTDIR)\sfthd.obj" \
	"$(INTDIR)\sfxhash.obj" \
	"$(INTDIR)\util_math.obj" \
	"$(INTDIR)\util_net.obj" \
	"$(INTDIR)\util_str.obj" \
	"$(INTDIR)\byte_extract.obj" \
	"$(INTDIR)\codes.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\detect.obj" \
	"$(INTDIR)\event_queue.obj" \
	"$(INTDIR)\event_wrapper.obj" \
	"$(INTDIR)\fpcreate.obj" \
	"$(INTDIR)\fpdetect.obj" \
	"$(INTDIR)\inline.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mempool.obj" \
	"$(INTDIR)\mstring.obj" \
	"$(INTDIR)\packet_time.obj" \
	"$(INTDIR)\parser.obj" \
	"$(INTDIR)\pcrm.obj" \
	"$(INTDIR)\plugbase.obj" \
	"$(INTDIR)\sf_sdlist.obj" \
	"$(INTDIR)\sfthreshold.obj" \
	"$(INTDIR)\signature.obj" \
	"$(INTDIR)\snort.obj" \
	"$(INTDIR)\snprintf.obj" \
	"$(INTDIR)\strlcatu.obj" \
	"$(INTDIR)\strlcpyu.obj" \
	"$(INTDIR)\tag.obj" \
	"$(INTDIR)\ubi_BinTree.obj" \
	"$(INTDIR)\ubi_SplayTree.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\inet_aton.obj" \
	"$(INTDIR)\misc.obj" \
	"$(INTDIR)\strtok_r.obj" \
	"$(INTDIR)\syslog.obj" \
	"$(INTDIR)\win32_service.obj" \
	"..\WIN32-Code\name.res"

"$(OUTDIR)\snort.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("snort.dep")
!INCLUDE "snort.dep"
!ELSE 
!MESSAGE Warning: cannot find "snort.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "snort - Win32 MySQL Debug" || "$(CFG)" == "snort - Win32 MySQL Release" || "$(CFG)" == "snort - Win32 SQLServer Debug" || "$(CFG)" == "snort - Win32 SQLServer Release" || "$(CFG)" == "snort - Win32 Oracle Debug" || "$(CFG)" == "snort - Win32 Oracle Release"
SOURCE="..\..\detection-plugins\sp_asn1.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_asn1.obj"	"$(INTDIR)\sp_asn1.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_asn1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_asn1.obj"	"$(INTDIR)\sp_asn1.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_asn1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_asn1.obj"	"$(INTDIR)\sp_asn1.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_asn1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_byte_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_byte_check.obj"	"$(INTDIR)\sp_byte_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_byte_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_byte_check.obj"	"$(INTDIR)\sp_byte_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_byte_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_byte_check.obj"	"$(INTDIR)\sp_byte_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_byte_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_byte_jump.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_byte_jump.obj"	"$(INTDIR)\sp_byte_jump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_byte_jump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_byte_jump.obj"	"$(INTDIR)\sp_byte_jump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_byte_jump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_byte_jump.obj"	"$(INTDIR)\sp_byte_jump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_byte_jump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_clientserver.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_clientserver.obj"	"$(INTDIR)\sp_clientserver.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_clientserver.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_clientserver.obj"	"$(INTDIR)\sp_clientserver.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_clientserver.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_clientserver.obj"	"$(INTDIR)\sp_clientserver.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_clientserver.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_dsize_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_dsize_check.obj"	"$(INTDIR)\sp_dsize_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_dsize_check.obj"	"$(INTDIR)\sp_dsize_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_dsize_check.obj"	"$(INTDIR)\sp_dsize_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_dsize_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_flowbits.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_flowbits.obj"	"$(INTDIR)\sp_flowbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_flowbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_flowbits.obj"	"$(INTDIR)\sp_flowbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_flowbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_flowbits.obj"	"$(INTDIR)\sp_flowbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_flowbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ftpbounce.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ftpbounce.obj"	"$(INTDIR)\sp_ftpbounce.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ftpbounce.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ftpbounce.obj"	"$(INTDIR)\sp_ftpbounce.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ftpbounce.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ftpbounce.obj"	"$(INTDIR)\sp_ftpbounce.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ftpbounce.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_icmp_code_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_code_check.obj"	"$(INTDIR)\sp_icmp_code_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_icmp_code_check.obj"	"$(INTDIR)\sp_icmp_code_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_icmp_code_check.obj"	"$(INTDIR)\sp_icmp_code_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_icmp_code_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_icmp_id_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_id_check.obj"	"$(INTDIR)\sp_icmp_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_icmp_id_check.obj"	"$(INTDIR)\sp_icmp_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_icmp_id_check.obj"	"$(INTDIR)\sp_icmp_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_icmp_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_icmp_seq_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_seq_check.obj"	"$(INTDIR)\sp_icmp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_icmp_seq_check.obj"	"$(INTDIR)\sp_icmp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_icmp_seq_check.obj"	"$(INTDIR)\sp_icmp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_icmp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_icmp_type_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_icmp_type_check.obj"	"$(INTDIR)\sp_icmp_type_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_icmp_type_check.obj"	"$(INTDIR)\sp_icmp_type_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_icmp_type_check.obj"	"$(INTDIR)\sp_icmp_type_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_icmp_type_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ip_fragbits.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_fragbits.obj"	"$(INTDIR)\sp_ip_fragbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ip_fragbits.obj"	"$(INTDIR)\sp_ip_fragbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ip_fragbits.obj"	"$(INTDIR)\sp_ip_fragbits.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ip_fragbits.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ip_id_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_id_check.obj"	"$(INTDIR)\sp_ip_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ip_id_check.obj"	"$(INTDIR)\sp_ip_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ip_id_check.obj"	"$(INTDIR)\sp_ip_id_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ip_id_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ip_proto.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_proto.obj"	"$(INTDIR)\sp_ip_proto.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ip_proto.obj"	"$(INTDIR)\sp_ip_proto.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ip_proto.obj"	"$(INTDIR)\sp_ip_proto.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ip_proto.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ip_same_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_same_check.obj"	"$(INTDIR)\sp_ip_same_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ip_same_check.obj"	"$(INTDIR)\sp_ip_same_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ip_same_check.obj"	"$(INTDIR)\sp_ip_same_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ip_same_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ip_tos_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ip_tos_check.obj"	"$(INTDIR)\sp_ip_tos_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ip_tos_check.obj"	"$(INTDIR)\sp_ip_tos_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ip_tos_check.obj"	"$(INTDIR)\sp_ip_tos_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ip_tos_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ipoption_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ipoption_check.obj"	"$(INTDIR)\sp_ipoption_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ipoption_check.obj"	"$(INTDIR)\sp_ipoption_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ipoption_check.obj"	"$(INTDIR)\sp_ipoption_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ipoption_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_isdataat.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_isdataat.obj"	"$(INTDIR)\sp_isdataat.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_isdataat.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_isdataat.obj"	"$(INTDIR)\sp_isdataat.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_isdataat.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_isdataat.obj"	"$(INTDIR)\sp_isdataat.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_isdataat.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_pattern_match.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_pattern_match.obj"	"$(INTDIR)\sp_pattern_match.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_pattern_match.obj"	"$(INTDIR)\sp_pattern_match.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_pattern_match.obj"	"$(INTDIR)\sp_pattern_match.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_pattern_match.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_pcre.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_pcre.obj"	"$(INTDIR)\sp_pcre.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_pcre.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_pcre.obj"	"$(INTDIR)\sp_pcre.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_pcre.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_pcre.obj"	"$(INTDIR)\sp_pcre.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_pcre.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_react.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_react.obj"	"$(INTDIR)\sp_react.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_react.obj"	"$(INTDIR)\sp_react.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_react.obj"	"$(INTDIR)\sp_react.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_react.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_respond.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_respond.obj"	"$(INTDIR)\sp_respond.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_respond.obj"	"$(INTDIR)\sp_respond.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_respond.obj"	"$(INTDIR)\sp_respond.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_respond.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_rpc_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_rpc_check.obj"	"$(INTDIR)\sp_rpc_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_rpc_check.obj"	"$(INTDIR)\sp_rpc_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_rpc_check.obj"	"$(INTDIR)\sp_rpc_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_rpc_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_session.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_session.obj"	"$(INTDIR)\sp_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_session.obj"	"$(INTDIR)\sp_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_session.obj"	"$(INTDIR)\sp_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_tcp_ack_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_ack_check.obj"	"$(INTDIR)\sp_tcp_ack_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_tcp_ack_check.obj"	"$(INTDIR)\sp_tcp_ack_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_tcp_ack_check.obj"	"$(INTDIR)\sp_tcp_ack_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_tcp_ack_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_tcp_flag_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_flag_check.obj"	"$(INTDIR)\sp_tcp_flag_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_tcp_flag_check.obj"	"$(INTDIR)\sp_tcp_flag_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_tcp_flag_check.obj"	"$(INTDIR)\sp_tcp_flag_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_tcp_flag_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_tcp_seq_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_seq_check.obj"	"$(INTDIR)\sp_tcp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_tcp_seq_check.obj"	"$(INTDIR)\sp_tcp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_tcp_seq_check.obj"	"$(INTDIR)\sp_tcp_seq_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_tcp_seq_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_tcp_win_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_tcp_win_check.obj"	"$(INTDIR)\sp_tcp_win_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_tcp_win_check.obj"	"$(INTDIR)\sp_tcp_win_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_tcp_win_check.obj"	"$(INTDIR)\sp_tcp_win_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_tcp_win_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\detection-plugins\sp_ttl_check.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sp_ttl_check.obj"	"$(INTDIR)\sp_ttl_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sp_ttl_check.obj"	"$(INTDIR)\sp_ttl_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sp_ttl_check.obj"	"$(INTDIR)\sp_ttl_check.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sp_ttl_check.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_alert_fast.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_fast.obj"	"$(INTDIR)\spo_alert_fast.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_alert_fast.obj"	"$(INTDIR)\spo_alert_fast.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_alert_fast.obj"	"$(INTDIR)\spo_alert_fast.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_alert_fast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_alert_full.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_full.obj"	"$(INTDIR)\spo_alert_full.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_alert_full.obj"	"$(INTDIR)\spo_alert_full.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_alert_full.obj"	"$(INTDIR)\spo_alert_full.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_alert_full.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_alert_prelude.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_prelude.obj"	"$(INTDIR)\spo_alert_prelude.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_prelude.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_alert_prelude.obj"	"$(INTDIR)\spo_alert_prelude.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_alert_prelude.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_alert_prelude.obj"	"$(INTDIR)\spo_alert_prelude.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_alert_prelude.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_alert_sf_socket.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_sf_socket.obj"	"$(INTDIR)\spo_alert_sf_socket.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_sf_socket.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_alert_sf_socket.obj"	"$(INTDIR)\spo_alert_sf_socket.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_alert_sf_socket.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_alert_sf_socket.obj"	"$(INTDIR)\spo_alert_sf_socket.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_alert_sf_socket.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_alert_syslog.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_syslog.obj"	"$(INTDIR)\spo_alert_syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_alert_syslog.obj"	"$(INTDIR)\spo_alert_syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_alert_syslog.obj"	"$(INTDIR)\spo_alert_syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_alert_syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_alert_unixsock.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_alert_unixsock.obj"	"$(INTDIR)\spo_alert_unixsock.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_alert_unixsock.obj"	"$(INTDIR)\spo_alert_unixsock.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_alert_unixsock.obj"	"$(INTDIR)\spo_alert_unixsock.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_alert_unixsock.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_csv.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_csv.obj"	"$(INTDIR)\spo_csv.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_csv.obj"	"$(INTDIR)\spo_csv.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_csv.obj"	"$(INTDIR)\spo_csv.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_csv.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_database.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_database.obj"	"$(INTDIR)\spo_database.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_database.obj"	"$(INTDIR)\spo_database.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_database.obj"	"$(INTDIR)\spo_database.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_database.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_log_ascii.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_log_ascii.obj"	"$(INTDIR)\spo_log_ascii.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_log_ascii.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_log_ascii.obj"	"$(INTDIR)\spo_log_ascii.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_log_ascii.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_log_ascii.obj"	"$(INTDIR)\spo_log_ascii.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_log_ascii.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_log_null.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_log_null.obj"	"$(INTDIR)\spo_log_null.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_log_null.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_log_null.obj"	"$(INTDIR)\spo_log_null.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_log_null.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_log_null.obj"	"$(INTDIR)\spo_log_null.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_log_null.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_log_tcpdump.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_log_tcpdump.obj"	"$(INTDIR)\spo_log_tcpdump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_log_tcpdump.obj"	"$(INTDIR)\spo_log_tcpdump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_log_tcpdump.obj"	"$(INTDIR)\spo_log_tcpdump.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_log_tcpdump.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\output-plugins\spo_unified.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spo_unified.obj"	"$(INTDIR)\spo_unified.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spo_unified.obj"	"$(INTDIR)\spo_unified.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spo_unified.obj"	"$(INTDIR)\spo_unified.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spo_unified.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\parser\IpAddrSet.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\IpAddrSet.obj"	"$(INTDIR)\IpAddrSet.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\IpAddrSet.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\IpAddrSet.obj"	"$(INTDIR)\IpAddrSet.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\IpAddrSet.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\IpAddrSet.obj"	"$(INTDIR)\IpAddrSet.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\IpAddrSet.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\preprocessors\flow\int-snort\flow_packet.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow_packet.obj"	"$(INTDIR)\flow_packet.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow_packet.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow_packet.obj"	"$(INTDIR)\flow_packet.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow_packet.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow_packet.obj"	"$(INTDIR)\flow_packet.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow_packet.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\portscan\flowps.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flowps.obj"	"$(INTDIR)\flowps.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flowps.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flowps.obj"	"$(INTDIR)\flowps.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flowps.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flowps.obj"	"$(INTDIR)\flowps.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flowps.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\portscan\flowps_snort.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flowps_snort.obj"	"$(INTDIR)\flowps_snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flowps_snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flowps_snort.obj"	"$(INTDIR)\flowps_snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flowps_snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flowps_snort.obj"	"$(INTDIR)\flowps_snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flowps_snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\portscan\scoreboard.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\scoreboard.obj"	"$(INTDIR)\scoreboard.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\scoreboard.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\scoreboard.obj"	"$(INTDIR)\scoreboard.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\scoreboard.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\scoreboard.obj"	"$(INTDIR)\scoreboard.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\scoreboard.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\portscan\server_stats.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\server_stats.obj"	"$(INTDIR)\server_stats.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\server_stats.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\server_stats.obj"	"$(INTDIR)\server_stats.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\server_stats.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\server_stats.obj"	"$(INTDIR)\server_stats.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\server_stats.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\portscan\unique_tracker.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\unique_tracker.obj"	"$(INTDIR)\unique_tracker.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\unique_tracker.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\unique_tracker.obj"	"$(INTDIR)\unique_tracker.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\unique_tracker.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\unique_tracker.obj"	"$(INTDIR)\unique_tracker.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\unique_tracker.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\flow.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow.obj"	"$(INTDIR)\flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow.obj"	"$(INTDIR)\flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow.obj"	"$(INTDIR)\flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\flow_cache.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow_cache.obj"	"$(INTDIR)\flow_cache.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow_cache.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow_cache.obj"	"$(INTDIR)\flow_cache.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow_cache.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow_cache.obj"	"$(INTDIR)\flow_cache.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow_cache.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\flow_callback.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow_callback.obj"	"$(INTDIR)\flow_callback.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow_callback.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow_callback.obj"	"$(INTDIR)\flow_callback.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow_callback.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow_callback.obj"	"$(INTDIR)\flow_callback.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow_callback.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\flow_class.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow_class.obj"	"$(INTDIR)\flow_class.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow_class.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow_class.obj"	"$(INTDIR)\flow_class.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow_class.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow_class.obj"	"$(INTDIR)\flow_class.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow_class.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\flow_hash.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow_hash.obj"	"$(INTDIR)\flow_hash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow_hash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow_hash.obj"	"$(INTDIR)\flow_hash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow_hash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow_hash.obj"	"$(INTDIR)\flow_hash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow_hash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\flow_print.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow_print.obj"	"$(INTDIR)\flow_print.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow_print.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow_print.obj"	"$(INTDIR)\flow_print.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow_print.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow_print.obj"	"$(INTDIR)\flow_print.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow_print.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\flow\flow_stat.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\flow_stat.obj"	"$(INTDIR)\flow_stat.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\flow_stat.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\flow_stat.obj"	"$(INTDIR)\flow_stat.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\flow_stat.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\flow_stat.obj"	"$(INTDIR)\flow_stat.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\flow_stat.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\anomaly_detection\hi_ad.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_ad.obj"	"$(INTDIR)\hi_ad.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_ad.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_ad.obj"	"$(INTDIR)\hi_ad.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_ad.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_ad.obj"	"$(INTDIR)\hi_ad.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_ad.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\client\hi_client.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_client.obj"	"$(INTDIR)\hi_client.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_client.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_client.obj"	"$(INTDIR)\hi_client.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_client.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_client.obj"	"$(INTDIR)\hi_client.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_client.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\client\hi_client_norm.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_client_norm.obj"	"$(INTDIR)\hi_client_norm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_client_norm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_client_norm.obj"	"$(INTDIR)\hi_client_norm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_client_norm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_client_norm.obj"	"$(INTDIR)\hi_client_norm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_client_norm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\event_output\hi_eo_log.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_eo_log.obj"	"$(INTDIR)\hi_eo_log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_eo_log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_eo_log.obj"	"$(INTDIR)\hi_eo_log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_eo_log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_eo_log.obj"	"$(INTDIR)\hi_eo_log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_eo_log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\mode_inspection\hi_mi.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_mi.obj"	"$(INTDIR)\hi_mi.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_mi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_mi.obj"	"$(INTDIR)\hi_mi.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_mi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_mi.obj"	"$(INTDIR)\hi_mi.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_mi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\normalization\hi_norm.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_norm.obj"	"$(INTDIR)\hi_norm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_norm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_norm.obj"	"$(INTDIR)\hi_norm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_norm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_norm.obj"	"$(INTDIR)\hi_norm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_norm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\server\hi_server.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_server.obj"	"$(INTDIR)\hi_server.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_server.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_server.obj"	"$(INTDIR)\hi_server.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_server.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_server.obj"	"$(INTDIR)\hi_server.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_server.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\session_inspection\hi_si.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_si.obj"	"$(INTDIR)\hi_si.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_si.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_si.obj"	"$(INTDIR)\hi_si.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_si.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_si.obj"	"$(INTDIR)\hi_si.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_si.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\user_interface\hi_ui_config.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_ui_config.obj"	"$(INTDIR)\hi_ui_config.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_ui_config.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_ui_config.obj"	"$(INTDIR)\hi_ui_config.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_ui_config.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_ui_config.obj"	"$(INTDIR)\hi_ui_config.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_ui_config.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\user_interface\hi_ui_iis_unicode_map.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_ui_iis_unicode_map.obj"	"$(INTDIR)\hi_ui_iis_unicode_map.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_ui_iis_unicode_map.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_ui_iis_unicode_map.obj"	"$(INTDIR)\hi_ui_iis_unicode_map.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_ui_iis_unicode_map.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_ui_iis_unicode_map.obj"	"$(INTDIR)\hi_ui_iis_unicode_map.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_ui_iis_unicode_map.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\user_interface\hi_ui_server_lookup.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_ui_server_lookup.obj"	"$(INTDIR)\hi_ui_server_lookup.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_ui_server_lookup.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_ui_server_lookup.obj"	"$(INTDIR)\hi_ui_server_lookup.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_ui_server_lookup.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_ui_server_lookup.obj"	"$(INTDIR)\hi_ui_server_lookup.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_ui_server_lookup.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\utils\hi_util_hbm.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_util_hbm.obj"	"$(INTDIR)\hi_util_hbm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_util_hbm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_util_hbm.obj"	"$(INTDIR)\hi_util_hbm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_util_hbm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_util_hbm.obj"	"$(INTDIR)\hi_util_hbm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_util_hbm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\utils\hi_util_kmap.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_util_kmap.obj"	"$(INTDIR)\hi_util_kmap.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_util_kmap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_util_kmap.obj"	"$(INTDIR)\hi_util_kmap.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_util_kmap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_util_kmap.obj"	"$(INTDIR)\hi_util_kmap.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_util_kmap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\HttpInspect\utils\hi_util_xmalloc.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\hi_util_xmalloc.obj"	"$(INTDIR)\hi_util_xmalloc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\hi_util_xmalloc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\hi_util_xmalloc.obj"	"$(INTDIR)\hi_util_xmalloc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\hi_util_xmalloc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\hi_util_xmalloc.obj"	"$(INTDIR)\hi_util_xmalloc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\hi_util_xmalloc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\preprocessors\perf-base.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\perf-base.obj"	"$(INTDIR)\perf-base.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\perf-base.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\perf-base.obj"	"$(INTDIR)\perf-base.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\perf-base.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\perf-base.obj"	"$(INTDIR)\perf-base.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\perf-base.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\preprocessors\perf-event.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\perf-event.obj"	"$(INTDIR)\perf-event.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\perf-event.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\perf-event.obj"	"$(INTDIR)\perf-event.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\perf-event.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\perf-event.obj"	"$(INTDIR)\perf-event.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\perf-event.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\..\preprocessors\perf-flow.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\perf-flow.obj"	"$(INTDIR)\perf-flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\perf-flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\perf-flow.obj"	"$(INTDIR)\perf-flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\perf-flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\perf-flow.obj"	"$(INTDIR)\perf-flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\perf-flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\perf.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\perf.obj"	"$(INTDIR)\perf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\perf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\perf.obj"	"$(INTDIR)\perf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\perf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\perf.obj"	"$(INTDIR)\perf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\perf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\portscan.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\portscan.obj"	"$(INTDIR)\portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\portscan.obj"	"$(INTDIR)\portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\portscan.obj"	"$(INTDIR)\portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\sfprocpidstats.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfprocpidstats.obj"	"$(INTDIR)\sfprocpidstats.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfprocpidstats.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfprocpidstats.obj"	"$(INTDIR)\sfprocpidstats.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfprocpidstats.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfprocpidstats.obj"	"$(INTDIR)\sfprocpidstats.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfprocpidstats.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\snort_httpinspect.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\snort_httpinspect.obj"	"$(INTDIR)\snort_httpinspect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\snort_httpinspect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\snort_httpinspect.obj"	"$(INTDIR)\snort_httpinspect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\snort_httpinspect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\snort_httpinspect.obj"	"$(INTDIR)\snort_httpinspect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\snort_httpinspect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\snort_stream4_session.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\snort_stream4_session.obj"	"$(INTDIR)\snort_stream4_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\snort_stream4_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\snort_stream4_session.obj"	"$(INTDIR)\snort_stream4_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\snort_stream4_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\snort_stream4_session.obj"	"$(INTDIR)\snort_stream4_session.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\snort_stream4_session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_arpspoof.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_arpspoof.obj"	"$(INTDIR)\spp_arpspoof.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_arpspoof.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_arpspoof.obj"	"$(INTDIR)\spp_arpspoof.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_arpspoof.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_arpspoof.obj"	"$(INTDIR)\spp_arpspoof.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_arpspoof.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_bo.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_bo.obj"	"$(INTDIR)\spp_bo.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_bo.obj"	"$(INTDIR)\spp_bo.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_bo.obj"	"$(INTDIR)\spp_bo.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_bo.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_conversation.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_conversation.obj"	"$(INTDIR)\spp_conversation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_conversation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_conversation.obj"	"$(INTDIR)\spp_conversation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_conversation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_conversation.obj"	"$(INTDIR)\spp_conversation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_conversation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_flow.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_flow.obj"	"$(INTDIR)\spp_flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_flow.obj"	"$(INTDIR)\spp_flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_flow.obj"	"$(INTDIR)\spp_flow.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_flow.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_frag2.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_frag2.obj"	"$(INTDIR)\spp_frag2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_frag2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_frag2.obj"	"$(INTDIR)\spp_frag2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_frag2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_frag2.obj"	"$(INTDIR)\spp_frag2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_frag2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_frag3.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_frag3.obj"	"$(INTDIR)\spp_frag3.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_frag3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_frag3.obj"	"$(INTDIR)\spp_frag3.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_frag3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_frag3.obj"	"$(INTDIR)\spp_frag3.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_frag3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_httpinspect.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_httpinspect.obj"	"$(INTDIR)\spp_httpinspect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_httpinspect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_httpinspect.obj"	"$(INTDIR)\spp_httpinspect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_httpinspect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_httpinspect.obj"	"$(INTDIR)\spp_httpinspect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_httpinspect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_perfmonitor.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_perfmonitor.obj"	"$(INTDIR)\spp_perfmonitor.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_perfmonitor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_perfmonitor.obj"	"$(INTDIR)\spp_perfmonitor.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_perfmonitor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_perfmonitor.obj"	"$(INTDIR)\spp_perfmonitor.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_perfmonitor.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_portscan.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_portscan.obj"	"$(INTDIR)\spp_portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_portscan.obj"	"$(INTDIR)\spp_portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_portscan.obj"	"$(INTDIR)\spp_portscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_portscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_portscan2.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_portscan2.obj"	"$(INTDIR)\spp_portscan2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_portscan2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_portscan2.obj"	"$(INTDIR)\spp_portscan2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_portscan2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_portscan2.obj"	"$(INTDIR)\spp_portscan2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_portscan2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_rpc_decode.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_rpc_decode.obj"	"$(INTDIR)\spp_rpc_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_rpc_decode.obj"	"$(INTDIR)\spp_rpc_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_rpc_decode.obj"	"$(INTDIR)\spp_rpc_decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_rpc_decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_sfportscan.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_sfportscan.obj"	"$(INTDIR)\spp_sfportscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_sfportscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_sfportscan.obj"	"$(INTDIR)\spp_sfportscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_sfportscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_sfportscan.obj"	"$(INTDIR)\spp_sfportscan.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_sfportscan.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_stream4.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_stream4.obj"	"$(INTDIR)\spp_stream4.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_stream4.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_stream4.obj"	"$(INTDIR)\spp_stream4.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_stream4.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_stream4.obj"	"$(INTDIR)\spp_stream4.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_stream4.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_telnet_negotiation.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_telnet_negotiation.obj"	"$(INTDIR)\spp_telnet_negotiation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_telnet_negotiation.obj"	"$(INTDIR)\spp_telnet_negotiation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_telnet_negotiation.obj"	"$(INTDIR)\spp_telnet_negotiation.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_telnet_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\spp_xlink2state.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\spp_xlink2state.obj"	"$(INTDIR)\spp_xlink2state.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\spp_xlink2state.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\spp_xlink2state.obj"	"$(INTDIR)\spp_xlink2state.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\spp_xlink2state.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\spp_xlink2state.obj"	"$(INTDIR)\spp_xlink2state.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\spp_xlink2state.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\str_search.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\str_search.obj"	"$(INTDIR)\str_search.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\str_search.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\str_search.obj"	"$(INTDIR)\str_search.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\str_search.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\str_search.obj"	"$(INTDIR)\str_search.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\str_search.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\preprocessors\xlink2state.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\xlink2state.obj"	"$(INTDIR)\xlink2state.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\xlink2state.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\xlink2state.obj"	"$(INTDIR)\xlink2state.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\xlink2state.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\xlink2state.obj"	"$(INTDIR)\xlink2state.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\xlink2state.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\acsmx.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\acsmx.obj"	"$(INTDIR)\acsmx.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\acsmx.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\acsmx.obj"	"$(INTDIR)\acsmx.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\acsmx.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\acsmx.obj"	"$(INTDIR)\acsmx.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\acsmx.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\acsmx2.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\acsmx2.obj"	"$(INTDIR)\acsmx2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\acsmx2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\acsmx2.obj"	"$(INTDIR)\acsmx2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\acsmx2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\acsmx2.obj"	"$(INTDIR)\acsmx2.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\acsmx2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\asn1.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\asn1.obj"	"$(INTDIR)\asn1.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\asn1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\asn1.obj"	"$(INTDIR)\asn1.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\asn1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\asn1.obj"	"$(INTDIR)\asn1.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\asn1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\ipobj.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\ipobj.obj"	"$(INTDIR)\ipobj.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\ipobj.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\ipobj.obj"	"$(INTDIR)\ipobj.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\ipobj.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\ipobj.obj"	"$(INTDIR)\ipobj.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\ipobj.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\mpse.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\mpse.obj"	"$(INTDIR)\mpse.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\mpse.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\mpse.obj"	"$(INTDIR)\mpse.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\mpse.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\mpse.obj"	"$(INTDIR)\mpse.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\mpse.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\mwm.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\mwm.obj"	"$(INTDIR)\mwm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\mwm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\mwm.obj"	"$(INTDIR)\mwm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\mwm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\mwm.obj"	"$(INTDIR)\mwm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\mwm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfeventq.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfeventq.obj"	"$(INTDIR)\sfeventq.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfeventq.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfeventq.obj"	"$(INTDIR)\sfeventq.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfeventq.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfeventq.obj"	"$(INTDIR)\sfeventq.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfeventq.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfghash.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfghash.obj"	"$(INTDIR)\sfghash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfghash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfghash.obj"	"$(INTDIR)\sfghash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfghash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfghash.obj"	"$(INTDIR)\sfghash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfghash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfhashfcn.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfhashfcn.obj"	"$(INTDIR)\sfhashfcn.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfhashfcn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfhashfcn.obj"	"$(INTDIR)\sfhashfcn.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfhashfcn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfhashfcn.obj"	"$(INTDIR)\sfhashfcn.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfhashfcn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfksearch.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfksearch.obj"	"$(INTDIR)\sfksearch.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfksearch.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfksearch.obj"	"$(INTDIR)\sfksearch.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfksearch.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfksearch.obj"	"$(INTDIR)\sfksearch.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfksearch.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sflsq.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sflsq.obj"	"$(INTDIR)\sflsq.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sflsq.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sflsq.obj"	"$(INTDIR)\sflsq.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sflsq.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sflsq.obj"	"$(INTDIR)\sflsq.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sflsq.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfmemcap.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfmemcap.obj"	"$(INTDIR)\sfmemcap.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfmemcap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfmemcap.obj"	"$(INTDIR)\sfmemcap.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfmemcap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfmemcap.obj"	"$(INTDIR)\sfmemcap.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfmemcap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfsnprintfappend.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfsnprintfappend.obj"	"$(INTDIR)\sfsnprintfappend.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfsnprintfappend.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfsnprintfappend.obj"	"$(INTDIR)\sfsnprintfappend.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfsnprintfappend.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfsnprintfappend.obj"	"$(INTDIR)\sfsnprintfappend.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfsnprintfappend.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfthd.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfthd.obj"	"$(INTDIR)\sfthd.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfthd.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfthd.obj"	"$(INTDIR)\sfthd.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfthd.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfthd.obj"	"$(INTDIR)\sfthd.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfthd.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\sfxhash.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfxhash.obj"	"$(INTDIR)\sfxhash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfxhash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfxhash.obj"	"$(INTDIR)\sfxhash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfxhash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfxhash.obj"	"$(INTDIR)\sfxhash.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfxhash.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\util_math.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\util_math.obj"	"$(INTDIR)\util_math.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\util_math.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\util_math.obj"	"$(INTDIR)\util_math.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\util_math.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\util_math.obj"	"$(INTDIR)\util_math.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\util_math.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\util_net.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\util_net.obj"	"$(INTDIR)\util_net.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\util_net.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\util_net.obj"	"$(INTDIR)\util_net.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\util_net.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\util_net.obj"	"$(INTDIR)\util_net.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\util_net.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfutil\util_str.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\util_str.obj"	"$(INTDIR)\util_str.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\util_str.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\util_str.obj"	"$(INTDIR)\util_str.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\util_str.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\util_str.obj"	"$(INTDIR)\util_str.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\util_str.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\byte_extract.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

CPP_SWITCHES=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

"$(INTDIR)\byte_extract.obj"	"$(INTDIR)\byte_extract.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

CPP_SWITCHES=/nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fp"$(INTDIR)\snort.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

"$(INTDIR)\byte_extract.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

CPP_SWITCHES=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MYSQL" /D "ENABLE_MSSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fr"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX"snort.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

"$(INTDIR)\byte_extract.obj"	"$(INTDIR)\byte_extract.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

CPP_SWITCHES=/nologo /MT /W3 /GX /O2 /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_MSSQL" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fp"$(INTDIR)\snort.pch" /YX"snort.pch" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

"$(INTDIR)\byte_extract.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

CPP_SWITCHES=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "D:\oracle\ora92\oci\include" /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_ORACLE" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fr"$(INTDIR)\\" /Fp"$(INTDIR)\snort.pch" /YX"snort.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

"$(INTDIR)\byte_extract.obj"	"$(INTDIR)\byte_extract.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

CPP_SWITCHES=/nologo /MT /W3 /GX /O2 /I "D:\oracle\ora92\oci\include" /I "..\..\.." /I "..\.." /I "..\..\sfutil" /I "..\Win32-Includes" /I "..\Win32-Includes\WinPCAP" /I "..\Win32-Includes\mysql" /I "..\Win32-Includes\libnet" /I "..\..\output-plugins" /I "..\..\detection-plugins" /I "..\..\preprocessors" /I "..\..\preprocessors\flow" /I "..\..\preprocessors\portscan" /I "..\..\preprocessors\flow\int-snort" /I "..\..\preprocessors\HttpInspect\Include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D __BEGIN_DECLS="" /D __END_DECLS="" /D "HAVE_CONFIG_H" /D "ENABLE_ORACLE" /D "ENABLE_MYSQL" /D "ENABLE_ODBC" /D "ENABLE_RESPONSE" /D "ENABLE_WIN32_SERVICE" /Fp"$(INTDIR)\snort.pch" /YX"snort.pch" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

"$(INTDIR)\byte_extract.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ENDIF 

SOURCE=..\..\codes.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\codes.obj"	"$(INTDIR)\codes.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\codes.obj"	"$(INTDIR)\codes.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\codes.obj"	"$(INTDIR)\codes.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\codes.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\debug.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\debug.obj"	"$(INTDIR)\debug.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\debug.obj"	"$(INTDIR)\debug.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\debug.obj"	"$(INTDIR)\debug.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\decode.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\decode.obj"	"$(INTDIR)\decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\decode.obj"	"$(INTDIR)\decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\decode.obj"	"$(INTDIR)\decode.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\decode.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\detect.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\detect.obj"	"$(INTDIR)\detect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\detect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\detect.obj"	"$(INTDIR)\detect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\detect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\detect.obj"	"$(INTDIR)\detect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\detect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\event_queue.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\event_queue.obj"	"$(INTDIR)\event_queue.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\event_queue.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\event_queue.obj"	"$(INTDIR)\event_queue.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\event_queue.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\event_queue.obj"	"$(INTDIR)\event_queue.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\event_queue.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\event_wrapper.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\event_wrapper.obj"	"$(INTDIR)\event_wrapper.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\event_wrapper.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\event_wrapper.obj"	"$(INTDIR)\event_wrapper.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\event_wrapper.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\event_wrapper.obj"	"$(INTDIR)\event_wrapper.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\event_wrapper.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\fpcreate.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\fpcreate.obj"	"$(INTDIR)\fpcreate.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\fpcreate.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\fpcreate.obj"	"$(INTDIR)\fpcreate.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\fpcreate.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\fpcreate.obj"	"$(INTDIR)\fpcreate.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\fpcreate.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\fpdetect.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\fpdetect.obj"	"$(INTDIR)\fpdetect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\fpdetect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\fpdetect.obj"	"$(INTDIR)\fpdetect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\fpdetect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\fpdetect.obj"	"$(INTDIR)\fpdetect.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\fpdetect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\inline.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\inline.obj"	"$(INTDIR)\inline.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\inline.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\inline.obj"	"$(INTDIR)\inline.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\inline.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\inline.obj"	"$(INTDIR)\inline.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\inline.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\log.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\log.obj"	"$(INTDIR)\log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\log.obj"	"$(INTDIR)\log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\log.obj"	"$(INTDIR)\log.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\mempool.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\mempool.obj"	"$(INTDIR)\mempool.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\mempool.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\mempool.obj"	"$(INTDIR)\mempool.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\mempool.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\mempool.obj"	"$(INTDIR)\mempool.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\mempool.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\mstring.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\mstring.obj"	"$(INTDIR)\mstring.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\mstring.obj"	"$(INTDIR)\mstring.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\mstring.obj"	"$(INTDIR)\mstring.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\mstring.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\packet_time.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\packet_time.obj"	"$(INTDIR)\packet_time.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\packet_time.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\packet_time.obj"	"$(INTDIR)\packet_time.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\packet_time.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\packet_time.obj"	"$(INTDIR)\packet_time.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\packet_time.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\parser.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\parser.obj"	"$(INTDIR)\parser.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\parser.obj"	"$(INTDIR)\parser.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\parser.obj"	"$(INTDIR)\parser.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\parser.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\pcrm.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\pcrm.obj"	"$(INTDIR)\pcrm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\pcrm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\pcrm.obj"	"$(INTDIR)\pcrm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\pcrm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\pcrm.obj"	"$(INTDIR)\pcrm.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\pcrm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\plugbase.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\plugbase.obj"	"$(INTDIR)\plugbase.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\plugbase.obj"	"$(INTDIR)\plugbase.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\plugbase.obj"	"$(INTDIR)\plugbase.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\plugbase.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sf_sdlist.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sf_sdlist.obj"	"$(INTDIR)\sf_sdlist.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sf_sdlist.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sf_sdlist.obj"	"$(INTDIR)\sf_sdlist.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sf_sdlist.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sf_sdlist.obj"	"$(INTDIR)\sf_sdlist.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sf_sdlist.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\sfthreshold.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\sfthreshold.obj"	"$(INTDIR)\sfthreshold.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\sfthreshold.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\sfthreshold.obj"	"$(INTDIR)\sfthreshold.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\sfthreshold.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\sfthreshold.obj"	"$(INTDIR)\sfthreshold.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\sfthreshold.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\signature.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\signature.obj"	"$(INTDIR)\signature.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\signature.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\signature.obj"	"$(INTDIR)\signature.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\signature.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\signature.obj"	"$(INTDIR)\signature.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\signature.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\snort.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\snort.obj"	"$(INTDIR)\snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\snort.obj"	"$(INTDIR)\snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\snort.obj"	"$(INTDIR)\snort.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\snort.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\snprintf.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\snprintf.obj"	"$(INTDIR)\snprintf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\snprintf.obj"	"$(INTDIR)\snprintf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\snprintf.obj"	"$(INTDIR)\snprintf.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\strlcatu.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\strlcatu.obj"	"$(INTDIR)\strlcatu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\strlcatu.obj"	"$(INTDIR)\strlcatu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\strlcatu.obj"	"$(INTDIR)\strlcatu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\strlcatu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\strlcpyu.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\strlcpyu.obj"	"$(INTDIR)\strlcpyu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\strlcpyu.obj"	"$(INTDIR)\strlcpyu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\strlcpyu.obj"	"$(INTDIR)\strlcpyu.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\strlcpyu.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\tag.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\tag.obj"	"$(INTDIR)\tag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\tag.obj"	"$(INTDIR)\tag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\tag.obj"	"$(INTDIR)\tag.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\tag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\ubi_BinTree.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\ubi_BinTree.obj"	"$(INTDIR)\ubi_BinTree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\ubi_BinTree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\ubi_BinTree.obj"	"$(INTDIR)\ubi_BinTree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\ubi_BinTree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\ubi_BinTree.obj"	"$(INTDIR)\ubi_BinTree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\ubi_BinTree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\ubi_SplayTree.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\ubi_SplayTree.obj"	"$(INTDIR)\ubi_SplayTree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\ubi_SplayTree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\ubi_SplayTree.obj"	"$(INTDIR)\ubi_SplayTree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\ubi_SplayTree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\ubi_SplayTree.obj"	"$(INTDIR)\ubi_SplayTree.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\ubi_SplayTree.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\..\util.c

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\util.obj"	"$(INTDIR)\util.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\util.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\util.obj"	"$(INTDIR)\util.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\util.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\util.obj"	"$(INTDIR)\util.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\util.obj" : $(SOURCE) "$(INTDIR)" "..\WIN32-Code\name.h"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\name.mc"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

InputPath="..\WIN32-Code\name.mc"

"..\WIN32-Code\name.h"	"..\WIN32-Code\name.rc"	"..\WIN32-Code\MSG00001.bin" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

InputPath="..\WIN32-Code\name.mc"

"..\WIN32-Code\name.h"	"..\WIN32-Code\name.rc"	"..\WIN32-Code\MSG00001.bin" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

InputPath="..\WIN32-Code\name.mc"

"..\WIN32-Code\name.h"	"..\WIN32-Code\name.rc"	"..\WIN32-Code\MSG00001.bin" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

InputPath="..\WIN32-Code\name.mc"

"..\WIN32-Code\name.h"	"..\WIN32-Code\name.rc"	"..\WIN32-Code\MSG00001.bin" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

InputPath="..\WIN32-Code\name.mc"

"..\WIN32-Code\name.h"	"..\WIN32-Code\name.rc"	"..\WIN32-Code\MSG00001.bin" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

InputPath="..\WIN32-Code\name.mc"

"..\WIN32-Code\name.h"	"..\WIN32-Code\name.rc"	"..\WIN32-Code\MSG00001.bin" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	mc -h ..\WIN32-Code -r ..\WIN32-Code ..\WIN32-Code\name.mc
<< 
	

!ENDIF 

SOURCE="..\WIN32-Code\name.rc"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"

InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "_DEBUG" ..\WIN32-Code\name.rc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"

InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "NDEBUG" ..\WIN32-Code\name.rc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"

InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "_DEBUG" ..\WIN32-Code\name.rc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"

InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "NDEBUG" ..\WIN32-Code\name.rc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"

InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "_DEBUG" ..\WIN32-Code\name.rc
<< 
	

!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"

InputPath="..\WIN32-Code\name.rc"

"..\WIN32-Code\name.res" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	rc /l 0x409 /fo"..\WIN32-Code\name.res" /i "..\WIN32-Code" /d "NDEBUG" ..\WIN32-Code\name.rc
<< 
	

!ENDIF 

SOURCE="..\WIN32-Code\getopt.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\getopt.obj"	"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\getopt.obj"	"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\getopt.obj"	"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\inet_aton.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\inet_aton.obj"	"$(INTDIR)\inet_aton.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\inet_aton.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\inet_aton.obj"	"$(INTDIR)\inet_aton.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\inet_aton.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\inet_aton.obj"	"$(INTDIR)\inet_aton.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\inet_aton.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\misc.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\misc.obj"	"$(INTDIR)\misc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\misc.obj"	"$(INTDIR)\misc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\misc.obj"	"$(INTDIR)\misc.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\misc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\strtok_r.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\strtok_r.obj"	"$(INTDIR)\strtok_r.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\strtok_r.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\strtok_r.obj"	"$(INTDIR)\strtok_r.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\strtok_r.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\strtok_r.obj"	"$(INTDIR)\strtok_r.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\strtok_r.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\syslog.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\syslog.obj"	"$(INTDIR)\syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\syslog.obj"	"$(INTDIR)\syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\syslog.obj"	"$(INTDIR)\syslog.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\syslog.obj" : $(SOURCE) "$(INTDIR)" "..\WIN32-Code\name.h"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE="..\WIN32-Code\win32_service.c"

!IF  "$(CFG)" == "snort - Win32 MySQL Debug"


"$(INTDIR)\win32_service.obj"	"$(INTDIR)\win32_service.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 MySQL Release"


"$(INTDIR)\win32_service.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Debug"


"$(INTDIR)\win32_service.obj"	"$(INTDIR)\win32_service.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 SQLServer Release"


"$(INTDIR)\win32_service.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Debug"


"$(INTDIR)\win32_service.obj"	"$(INTDIR)\win32_service.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "snort - Win32 Oracle Release"


"$(INTDIR)\win32_service.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 


!ENDIF 

