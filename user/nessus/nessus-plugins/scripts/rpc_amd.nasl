#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE. Changed description to match version
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10211);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0014");
 script_bugtraq_id(614);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0704");
 
 name["english"] = "amd service";
 name["francais"] = "Service amd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The amd RPC service is running. 
There is a bug in older versions of
this service less than am-utils-6.0.1 that allow an intruder to
execute arbitrary commands on your system.

Risk factor : High";


 desc["francais"] = "
Le service RPC amd tourne.
Il y a un bug dans certaines versions
de ce service qui permettent à un pirate
d'executer des commandes arbitraires sur
votre système.


Facteur de risque : Elevé";


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



RPC_PROG = 300019;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
}
