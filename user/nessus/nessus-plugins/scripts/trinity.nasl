#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10501);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2000-0138");
 
 name["english"] = "Trinity v3 Detect";
 name["francais"] = "Detection de Trinity v3";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host appears to be running
Trinity v3, which is a trojan that can be 
used to control your system or make it 
attack another network (this is 
actually called a distributed denial
of service attack tool)

It is very likely that this host
has been compromised

Solution : Restore your system from backups,
	   contact CERT and your local
	   authorities

Risk factor : Critical";



 desc["francais"] = "
Le systeme distant semble faire tourner
trinity v3 qui peut etre utilisé pour prendre 
le controle de celui-ci ou pour attaquer un 
autre réseau (outil de déni de service 
distribué)

Il est très probable que ce systeme a été
compromis

Solution : reinstallez votre système à partir
	   des sauvegardes, et contactez le CERT
	   et les autorités locales
	   
Facteur de risque : Critique";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects the presence of trinity v3";
 summary["francais"] = "Detecte la présence de trinity v3";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(33270);
 
 exit(0);
}

#
# The script code starts here
#

if(get_port_state(33270))
{
 soc = open_sock_tcp(33270);
 if(soc)
 {
  req = string("!@#\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  req = string("id\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  if("uid" >< r)security_hole(33270);
  close(soc);
 }
}
