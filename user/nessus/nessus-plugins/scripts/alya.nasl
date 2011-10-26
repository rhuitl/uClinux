# This script was written by Jason Lidow <jason@brandx.net>


if(description)
{
 script_id(11118); 
 script_version ("$Revision: 1.7 $");
 name["english"] = "alya.cgi";
 script_name(english:name["english"]);
 
 desc["english"] = "
alya.cgi is a cgi backdoor distributed with 
multiple rootkits.

Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Detects /cgi-bin/alya.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Jason Lidow");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"alya.cgi");
if( res )security_hole(port);
