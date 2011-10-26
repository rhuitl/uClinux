#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10098);
 script_bugtraq_id(776);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0237"); 
 name["english"] = "guestbook.cgi";
 name["francais"] = "guestbook.cgi";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "The 'guestbook.cgi' is installed. This CGI has
 a well known security flaw that lets anyone execute arbitrary
 commands with the privileges of the http daemon (root or nobody).

Solution :  remove it from /cgi-bin.

Risk factor : High";

desc["francais"] = "Le cgi 'guestbook.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody).

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";



 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks for the presence of /cgi-bin/guestbook.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/guestbook.cgi";
   
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin",
         francais:"Ce script est Copyright (C) 1999 Mathieu Perrin");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 
 exit(0);
}	  
  
#
# The script code starts here
#
exit(0); # FPs
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"guestbook.cgi", port:port);
if(res)
{
 security_hole(port);
}
   
