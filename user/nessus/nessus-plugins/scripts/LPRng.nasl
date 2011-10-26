#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10522);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-t-0005");
 script_bugtraq_id(1712);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0917");
 
 name["english"] = "LPRng malformed input";
 name["francais"] = "Entrées mal formées dans LPRng";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
LPRng seems to be running.

This daemon has a flaw (until version 3.6.24 at least) that would
let anyone to remotely execute arbitrary commands on the server.

*** Nessus could not remotely determine with certainty that the 
version of LPRng this machine is running is vulnerable or not.

Solution: Make sure that you are running version 3.6.25 or newer 
and filter incoming connections to TCP port 515.

Risk factor : High";

	
 desc["francais"] = "
LPRng semble tourner.

Ce daemon (au moins jusqu'a la version 3.6.25) est vulnérable
à un bug permettant d'executer de code arbitraire en tant que
root, à distance.

*** Nessus ne peut déterminer à distance si une version
*** vulnérable tourne

Solution : Assurez-vous de faire tourner LPRng 3.6.25 ou plus récent, filtrez
les connections vers ce port
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for a vulnerable version of LPRng";
 summary["francais"] = "Vérifie la présence de LPRng";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(515);
 exit(0);
}


if(get_port_state(515))
{
soc = open_sock_tcp(515);
if(soc)
{
 snd = raw_string(9)+ string("lp") + raw_string(0x0A);

 send(socket:soc, data:snd);
 r = recv(socket:soc, length:1024);
 if("SPOOLCONTROL" >< r)
 {
  security_warning(515);
 }
}
}
