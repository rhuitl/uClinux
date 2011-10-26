#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10212);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-a-0006");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0014");
 script_bugtraq_id(235, 614);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0210", "CVE-1999-0704");
 name["english"] = "automountd service";
 name["francais"] = "Service automountd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The automountd service is running.

There is a bug in the Solaris rpc.statd
and automountd which allow an attacker
to execute any command remotely as root.

*** THIS VULNERABILITY WAS NOT TESTED 
*** AND MAY BE A FALSE POSITIVE

Solution : Disable your automountd and ask your
vendor if you are vulnerable.

Risk factor : High";


 desc["francais"] = "
Le service automountd tourne.

Il y a un bug dans la version Solaris de
rpc.statd et automountd qui permet à un
pirate de passer root sur le système
distant.

*** CETTE VULNERABILITE N'A PAS ETE TESTEE
*** ET PEUT ETRE UNE FAUSSE ALERTE
   
Solution : Désactivez votre automountd
et demandez à votre vendeur si vous etes
vulnerables

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
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

RPC_PROG = 100099;
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
