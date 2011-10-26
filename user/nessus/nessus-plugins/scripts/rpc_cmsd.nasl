#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details 
#

if(description)
{
 script_id(10213);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-a-0008");
 script_bugtraq_id(428, 524, 5356);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0320", "CVE-1999-0696", "CVE-2002-0391");
 name["english"] = "cmsd service";
 name["francais"] = "Service cmsd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The cmsd RPC service is running. 
This service has a long history of security holes, so you should really
know what you are doing if you decide to let it run.

*** No security hole regarding this program has been tested, so 
*** this might be a false positive

Solution : We suggest that you disable this service.
Risk factor : High";


 desc["francais"] = "
Le service RPC cmsd tourne.
Ce service a une longue histoire
de problèmes de sécurité, donc 
vous devriez vraiment savoir ce
que vous faites si vous décidez
de le laisser tourner.

* AUCUN PROBLEME DE SECURITE 
  N'A ETE TESTE, DONC CETTE
  ALERTE EST PEUT ETRE 
  FAUSE *

Il est recommandé que vous désactiviez
ce service.

Facteur de risque : Elevé";


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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


RPC_PROG = 100068;
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
