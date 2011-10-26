#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# It is released under the GNU Public Licence
#

if(description)
{
 script_id(11154);
 script_version ("$Revision: 1.22 $");
# script_cve_id("CVE-MAP-NOMATCH"); 
 name["english"] = "Unknown services banners";
 name["francais"] = "Bannières des services inconnus";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This plugin prints the banners from unknown service so that
the Nessus team can take them into account.

Risk factor : None";


 desc["francais"] = "
Ce plugin affiche les bannières des services inconnus de façon à
ce que l'équipe Nessus puisse en tenir compte.

Facteur de risque : Aucun";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Displays the unknown services banners";
 summary["francais"] = "Affiche les bannières des services inconnus";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_END); 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Misc.";
 family["francais"] = "Divers";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie(
   "PC_anywhere_tcp.nasl",
   "SHN_discard.nasl",
   "X.nasl",
   "apcnisd_detect.nasl",
   "alcatel_backdoor_switch.nasl",
   "asip-status.nasl",
   "auth_enabled.nasl",
   "bugbear.nasl",
   "cifs445.nasl",
   "cp-firewall-auth.nasl",
   "dcetest.nasl",
   "dns_server.nasl",
   "echo.nasl",
   "find_service1.nasl",
   "find_service2.nasl",
   "mldonkey_telnet.nasl",
   "mssqlserver_detect.nasl",
   "mysql_version.nasl",
   "nessus_detect.nasl",
   "qmtp_detect.nasl",
   "radmin_detect.nasl",
   "rpc_portmap.nasl",
   "rpcinfo.nasl",
   "rsh.nasl",
   "rtsp_detect.nasl",
   "telnet.nasl",
   "xtel_detect.nasl",
   "xtelw_detect.nasl");
   if (NASL_LEVEL >= 3000)
   {
    script_dependencies (
    "veritas_agent_detect.nasl",
    "veritas_netbackup_vmd_detect.nasl",
    "veritas_netbackup_detect.nasl",
    "hp_openview_ovalarmsrv.nasl",
    "hp_openview_ovtopmd.nasl",
    "hp_openview_ovuispmd.nasl");
   }
 script_require_ports("Services/unknown");
 exit(0);
}

#
include("misc_func.inc");
include("dump.inc");

port = get_unknown_svc();
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (port == 139) exit(0);	# Avoid silly messages
if (! service_is_unknown(port: port)) exit(0);

a = get_unknown_banner2(port: port, dontfetch: 1);
if (isnull(a)) exit(0);
banner = a[0]; type = a[1];
if (!banner) exit(0);

h = hexdump(ddata: banner);
if( strlen(banner) >= 3 )
{
 m = strcat('An unknown server is running on this port.\nIf you know what it is, please send this banner to the Nessus team:\nType=',
 type, '\n', h);
 security_note(port: port, data: m);
}

