#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10066);
 script_version ("$Revision: 1.19 $");
 
 name["english"] = "FakeBO buffer overflow";
 name["francais"] = "Dépassement de buffer dans FakeBO";
 name["deutsch"] = "Überlauf des Buffers in FakeBO";
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "
We detected a possible buffer overflow 
in the service FakeBO.
An attacker may connect to this port, 
then send a specially crafted buffer
which will give him a shell.

Solution : disable this service. It's 
useless anyway. At worst, upgrade.

Reference : http://online.securityfocus.com/archive/1/12437

Risk factor : High";


 desc["francais"] = "Un dépassement de buffer
possible à été detecté sur ce service
(FakeBO).

Un pirate peut se connecter à ce port et
envoyer un buffer spécialement préparé qui
lui donnera un shell.

Solution : désactivez ce service, il
ne sert à rien de toute facon. Au pire,
mettez-le à jour.

Facteur de risque : Elevé";


 desc["deutsch"] = "Ein möglicher Überlauf des
Buffers in diesem Dienst (FakeBO) wurde erkannt.

Ein Angreifer könnte sich über diesen Port
verbinden und ein speziell gestaltetes 
Datenpaket senden welches ihm eine Shell gibt.

Lösung: Abstellen des Dienstes, er ist ohnehin
sinnlos. Notfalls eine neuere Version installieren.

Risikofaktor : Hoch";

 script_description(english:desc["english"], francais:desc["francais"], deutsch:desc["deutsch"]);
 
 summary["english"] = "Overflows FakeBO's buffers";
 summary["francais"] = "Remplit un peu trop les buffers de FakeBO";
 summary["deutsch"] = "Überflutet FakeBO's Buffer";
 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
		deutsch:"Dieses Skript ist Copyright geschützt. (C) 1999 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 family["deutsch"] = "Ferngesteuertes Erlangen einer Shell";
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/netbus", 12345);
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
  a = recv_line(socket:soc, length:1024);
  if("NetBus" >< a)
  { 
   if(safe_checks())
   {
    report = "
If the remote service is FakeBO, it
might be vulnerable to a buffer overflow

An attacker may connect to this port, 
then send a specially crafted buffer
which will give him a shell.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : disable this service. It's 
useless anyway. At worst, upgrade.

Risk factor : High";
     security_hole(port:port, data:report);
     exit(0);
   }
   s = crap(5001);
   send(socket:soc, data:s);
   close(soc);
   
   flaw = 0;
   soc2 = open_sock_tcp(port);
   if(!soc2)flaw = 1;
   else
   {
    d = recv(socket:soc2, length:1024);
    if(!d)flaw = 1;
    close(soc2);
   }
   
   if(flaw)security_hole(port);
  }
 }
}
