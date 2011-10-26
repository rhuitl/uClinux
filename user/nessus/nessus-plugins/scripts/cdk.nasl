#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to Xavier HUMBERT <xavier@xavhome.fr.eu.org> for giving
# me a copy of CDK
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10036);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "CDK Detect";
 name["francais"] = "Detection de CDK";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host appears to be running CDK, which is a backdoor that can be 
used to control your system.  

To use it, an attacker just has to connect onto this port, and send the 
password 'ypi0ca'

It is very likely that this host has been compromised

Solution : Restore your system from backups, contact CERT and your local
	   authorities
Risk factor : Critical";



 desc["francais"] = "
Le systeme distant semble faire tourner
CDK qui peut etre utilisé pour prendre le 
controle de celui-ci.

Pour l'utiliser, un pirate n'a qu'a
se connecter sur ce port et envoyer
le mot de passe 'ypi0ca'

Il est très probable que ce systeme a été
compromis

Solution : reinstallez votre système à partir
	   des sauvegardes, et contactez le CERT
	   et les autorités locales
	   
Facteur de risque : Critique";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects the presence of CDK";
 summary["francais"] = "Detecte la présence de CDK";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(15858, 79);
 
 exit(0);
}


include('global_settings.inc');


if(get_port_state(15858))
{
 soc = open_sock_tcp(15858);
 if(soc)
 {
  data = string("ypi0ca\r\n");
  send(socket:soc, data:data);
  r = recv(socket:soc, length:1024);
  if("Welcome" >< r)
  {
   security_hole(15858);
  }
  close(soc);
 }
}

if ( report_paranoia < 1 ) exit(0);

if(get_port_state(79))
{
 soc2 = open_sock_tcp(79);
 if(soc2)
 {
  data = string("ypi0ca\r\n");
  send(socket:soc2, data:data);
  r = recv(socket:soc2, length:4);
  if("bash" >< r)
  {
   security_hole(79);
  }
  close(soc2);
 }
}
