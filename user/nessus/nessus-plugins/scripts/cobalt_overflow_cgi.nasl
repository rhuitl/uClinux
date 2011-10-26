#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# GPL
#

if(description)
{
 script_id(11190);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "overflow.cgi detection";
 script_name(english:name["english"]);
 
 desc["english"] = "/cgi-bin/.cobalt/overflow/overflow.cgi was detected.
Some versions of this CGI allow remote users to execute arbitrary commands
with the privileges of the web server.

*** Nessus just checked the presence of this file 
*** but did not try to exploit the flaw, so this might
*** be a false positive
   
See: http://www.cert.org/advisories/CA-2002-35.html

Solution : get a newer software from Cobalt
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a CGI";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 81, 444);
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"/cgi-bin/.cobalt/overflow/overflow.cgi", port:port);
if(res) security_hole(port);
