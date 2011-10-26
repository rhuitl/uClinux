#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10216);
 script_bugtraq_id(353);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0059");
 name["english"] = "fam service";
 name["francais"] = "Service fam";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The fam RPC service is running. 
Several versions of this service have a well-known buffer overflow condition
that allows intruders to execute arbitrary commands as root on this system.

Solution : disable this service in /etc/inetd.conf
See also : http://www.nai.com/nai_labs/asp_set/advisory/16_fam_adv.asp
Risk factor : High";


 desc["francais"] = "
Le service RPC fam tourne.
Plusieurs versions de ce serveurs
contiennent un bug permettant à 
des pirates d'executer des commandes
en tant que root via celui-ci grace
à un dépassement de buffer.


Solution : désactivez ce service dans /etc/inetd.conf
Plus d'informations : http://www.nai.com/nai_labs/asp_set/advisory/16_fam_adv.asp
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks the presence of a RPC service";
 summary["francais"] = "vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 if ( ! defined_func("bn_random") )
 	script_dependencie("rpc_portmap.nasl");
 else
 	script_dependencie("rpc_portmap.nasl", "ssh_get_info.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include('global_settings.inc');

if ( get_kb_item("Host/RedHat/release") ) exit(0);
if ( report_paranoia < 2 ) exit(0);

RPC_PROG = 391002;
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
