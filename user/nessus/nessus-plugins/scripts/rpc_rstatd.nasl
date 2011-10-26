#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10227);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0624");
 name["english"] = "rstatd service";
 name["francais"] = "Service rstatd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The rstatd RPC service is running.  It provides an attacker interesting
information such as :

	- the CPU usage
	- the system uptime
	- its network usage
	- and more
	
Letting this service run is not recommended.
Risk factor : Low";


 desc["francais"] = "
Le service RPC rstatd tourne.
Il donne à un pirate des informations
sensibles telles que :

	- l'usage du CPU
	- l'uptime du système
	- l'usage réseau
	- et bien plus
	
C'est générallement une mauvaise
idée de laisser ce service ouvert.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the presence of a RPC service";
 summary["francais"] = "Vérifie la présence d'un service RPC";
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

if ( report_paranoia < 1 ) exit(0);



RPC_PROG = 100001;
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
