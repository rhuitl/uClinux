#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10209);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0648");
 name["english"] = "X25 service";
 name["francais"] = "Service X25";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The X25 RPC service is running.  This service may allow an intruder
to connect via an X25 gateway rather than by TCP/IP. In addition to that,
it may become a security threat if a security vulnerability is
found.

If you do not use this service, then disable it. 

Risk factor : Low / Medium";


 desc["francais"] = "
Le service RPC X25 tourne.
Si vous ne l'utilisez pas, alors
désactivez-le puisqu'il risque de
devenir un jour une faille de 
sécurité si une vulnerabilité 
est trouvée.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks the presence of a RPC service";
 summary["francais"] = "vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);


RPC_PROG = 100022;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_warning(port);
 else security_warning(port, protocol:"udp");
}
