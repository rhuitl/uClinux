#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14378);
 script_version ("$Revision: 1.3 $");
 name["english"] = "NetAsq identification";
 name["francais"] = "Identification de NetAsq";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "

It's very likely that this remote host is a NetAsq IPS-Firewalls
with port TCP/1300 open to allow Firewall Manager tool to
remotely configure it.

Letting attackers know that you are using a NetAsq 
will help them to focus their attack or will 
make them change their strategy. 

You should not let them know such information.

Solution : do not allow any connection on the
firewall itself, except from trusted network.

See also : http://www.netasq.com
Risk factor : Low";


 desc["francais"] = "

Il est très probable que ce système soit en
fait un IPS-Firewalls NetAsq avec le port TCP/1300 ouvert pour 
permettre à l'outil Firewall Manager de l'administrer
de manière distante.

Laisser des pirates obtenir ce type d'informations
va les aider à focaliser leurs attaques ou va
les faire changer de stratégie.

Vous ne devriez pas leur donner ces informations.

Solution : refusez toutes les connections sur
le firewall lui-meme, execpté des réseaux de confiance.

Plus d'informations : http://www.netasq.fr
Facteur de risque : faible.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines if the remote host is a NetAsq";
 summary["francais"] = "Determine si la machine distante est un NetAsq";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(1300);
 exit(0);
}

#
# The script code starts here
#

port=1300;

if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 req=string("NESSUS\r\n");
 send(socket:soc, data:req);
 r=recv(socket:soc,length:512);
 
 if (ereg(pattern:"^200 code=[0-9]+ msg=.*", string:r))
 {
 	req=string("QUIT\r\n");
 	send(socket:soc, data:req);
 	r=recv(socket:soc,length:512);
	if (ereg(pattern:"^103 code=[0-9]+ msg=.*", string:r))
	{
		security_warning(port);
	}
 }
 close(soc);
}
exit(0);
