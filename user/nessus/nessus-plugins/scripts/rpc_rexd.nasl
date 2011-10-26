#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10224);
 script_bugtraq_id(37);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0627");
 name["english"] = "rexd service";
 name["francais"] = "Service rexd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The rexd RPC service is running. 
If you do not use this service, then
disable it as it may become a security
threat in the future, if a vulnerability
is discovered.

Risk factor : Low";


 desc["francais"] = "
Le service RPC rexd tourne.
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



RPC_PROG = 100017;
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
