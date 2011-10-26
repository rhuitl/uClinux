#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10151);
 script_bugtraq_id(7538);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "NetBus 1.x";
 name["francais"] = "NetBus 1.x";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "NetBus 1.x is installed. 

This backdoor/administration tool allows 
anyone to partially take the control of 
the remote system.

An attacker may use it to steal your
password or prevent your from working
properly.

Furthermore, Netbus authentication may be bypassed.

Solution : 
http://members.spree.com/NetBus/remove_1.html
http://members.spree.com/NetBus/remove_2.html

Risk factor : High";


 desc["francais"] = "NetBus 1.x est installé.

Cette backdoor/programme d'administration permet 
à n'importe qui de prendre partiellement
le controle de la machine distante.

Un pirate peut l'utiliser pour voler
vos mots de passes ou vous empecher
de travailler convenablement.

Solution : 
http://members.spree.com/NetBus/remove_1.html
http://members.spree.com/NetBus/remove_2.html

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of NetBus 1.x";
 summary["francais"] = "Determines la presence de NetBus 1.x";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(12345, "Services/netbus");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/netbus");
if(!port)port = 12345;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {

#
# Anti-deception toolkit check
# 
  r = recv(socket:soc, length:1024);
  close(soc);
  if("NetBus" >< r){
  	security_hole(port);
	}
  }
}
