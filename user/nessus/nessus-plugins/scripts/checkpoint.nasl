#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10044);
 script_version ("$Revision: 1.10 $");
 name["english"] = "Checkpoint FW-1 identification";
 name["francais"] = "Identification de FW-1 de Checkpoint";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host has the three tcp ports 256, 257 and 258 
open.

It's very likely that this host is a Checkpoint Firewall/1.

Letting attackers know that you are running FW/1 will
help them to focus their attack or will make them
change their strategy. 

You should not let them know such information.

Solution : do not allow any connection on the
firewall itself, except for the firewall 
protocol, and allow that for trusted sources
only.

If you have a router which performs packet 
filtering, then add ACL that disallows the
connection to these ports for unauthorized
systems.

See also : http://www.phoneboy.com/fom-serve/cache/405.html
Risk factor : Low";


 desc["francais"] = "
Le système distant a les trois ports tcp 
256, 257 et 258 ouverts.

Il est très probable que ce système soit en
fait un Firewall/1 de Checkpoint.

Laisser des pirates obtenir ce type d'informations
va les aider à focaliser leurs attaques ou va
les faire changer de stratégie.

Vous ne devriez pas leur donner ces informations.

Solution : refusez toutes les connections sur
le firewall en lui-meme, sauf pour le protocole
de celui-ci, mais seulement pour des machines
autorisées.

Si vous possédez un routeur qui filtre les paquets,
alors ajouter des ACL qui empechent la connection
à ces ports pour des systèmes non autorisés.

Plus d'informations : http://www.phoneboy.com/fom-serve/cache/405.html
Facteur de risque : faible.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines if the remote host is a FW/1";
 summary["francais"] = "Determine si la machine distante est un FW/1";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(256,257,258);
 exit(0);
}

#
# The script code starts here
#

if((get_port_state(256))&&
   (get_port_state(257))&&
   (get_port_state(258)))
{
 # open a socket on these ports to check
 # (get_port_state() returns TRUE when the 
 # host has not been scanned
 
 soc1 = open_sock_tcp(256);
 if(!soc1)exit(0);
 close(soc1);
 
 soc2 = open_sock_tcp(257);
 if(!soc2)exit(0);
 close(soc2);

 soc3 = open_sock_tcp(258);
 if(!soc3)exit(0);
 close(soc3);
 
 # post the warning on every port
 security_warning(256);
 security_warning(257);
 security_warning(258); 
}
