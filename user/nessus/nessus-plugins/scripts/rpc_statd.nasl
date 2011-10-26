#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10235);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-a-0006");
 script_bugtraq_id(127, 450, 6831, 11785);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0018", "CVE-1999-0019", "CVE-1999-0493");
 
 name["english"] = "statd service";
 name["francais"] = "Service statd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The statd RPC service is running.  This service has a long history of 
security holes, so you should really know what you are doing if you decide
to let it run.

*** No security hole regarding this program have been tested, so
*** this might be a false positive.

Solution : We suggest that you disable this service.
Risk factor : High";


 desc["francais"] = "
Le service RPC statd tourne.
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


# RHEL not affected
if ( get_kb_item("Host/RedHat/release") ) exit(0);

RPC_PROG = 100024;
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
