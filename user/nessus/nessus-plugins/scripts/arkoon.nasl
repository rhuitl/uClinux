#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14377);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Arkoon identification";
 name["francais"] = "Identification de Arkoon";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host has the three TCP ports 822, 1750, 1751
open.

It's very likely that this host is an Arkoon security dedicated
appliance with ports

 TCP/822  dedicated to ssh service
 TCP/1750 dedicated to Arkoon Manager
 TCP/1751 dedicated to Arkoon Monitoring

Letting attackers know that you are using an Arkoon 
appliance will help them to focus their attack or will 
make them change their strategy. 

You should not let them know such information.

Solution : do not allow any connection on the
firewall itself, except for the firewall 
protocol, and allow that for trusted sources
only.

If you have a router which performs packet 
filtering, then add ACL that disallows the
connection to these ports for unauthorized
systems.

See also : http://www.arkoon.net
Risk factor : Low";


 desc["francais"] = "
Le système distant a les trois ports TCP 
822, 1750 et 1751 ouverts.

Il est très probable que ce système soit en
fait une appliance Arkoon dédié à la sécurité avec les ports:

 TCP/822  dédié au service ssh
 TCP/1750 dédié à Arkoon Manager
 TCP/1751 dédié à Arkoon Monitoring

Laisser des pirates obtenir ce type d'informations
va les aider à focaliser leurs attaques ou va
les faire changer de stratégie.

Vous ne devriez pas leur donner ces informations.

Solution : refusez toutes les connections sur
le firewall lui-meme, sauf pour le protocole
de celui-ci, mais seulement pour des machines
autorisées.

Si vous possédez un routeur qui filtre les paquets,
alors ajouter des ACL qui empechent la connection
à ces ports pour des systèmes non autorisés.

Plus d'informations : http://www.arkoon.net
Facteur de risque : faible.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines if the remote host is an Arkoon";
 summary["francais"] = "Determine si la machine distante est une appliance Arkoon";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(822,1750,1751,1752);
 exit(0);
}

#
# The script code starts here
#

if((get_port_state(822))&&
   (get_port_state(1750))&&
   (get_port_state(1751)))
{
 
 soc1 = open_sock_tcp(822);
 if(!soc1)exit(0);
 banner = recv_line(socket:soc1, length:1024);
 close(soc1);
 #SSH-1.5-SSF
 if (!(egrep(pattern:"SSH-[0-9.]+-SSF",string:banner)))
 exit(0);
 
 soc2 = open_sock_tcp(1750);
 if(!soc2)exit(0);
 close(soc2);

 soc3 = open_sock_tcp(1751);
 if(!soc3)exit(0);
 close(soc3);
 
 # post the warning on every port
 security_note(0);
}
exit(0);
