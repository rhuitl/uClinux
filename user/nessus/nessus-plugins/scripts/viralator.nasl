# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# GPL
# References:
# http://marc.theaimsgroup.com/?l=bugtraq&m=100463639800515&w=2

if(description)
{
 script_id(11107);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(3495);
 script_cve_id("CVE-2001-0849");
 name["english"] = "viralator";
 script_name(english:name["english"]);
 
 desc["english"] = "The CGI 'viralator.cgi' is installed.
Some versions of this CGI are don't check properly the user
input and allow anyone to execute arbitrary commands with
the privileges of the web server

** No flaw was tested. Your script might be a safe version.

Solutions : Upgrade this script to version 0.9pre2 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/viralator.cgi";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"viralator.cgi", port:port);
if( res )security_hole(port);



