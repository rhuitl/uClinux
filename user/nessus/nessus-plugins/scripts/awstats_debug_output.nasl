#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16456);
 script_bugtraq_id(12545, 12543, 12572);
 script_version("$Revision: 1.4 $");

 name["english"] = "AWStats Debug Remote Information Disclosure And Code Execution Vulnerabilities";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.4 $");
 
 desc["english"] = "
The remote host is running AWStats, a free real-time logfile analyzer.

The remote version of this software is prone to a command execution flaw
as well as an information disclosure vulnerability. 

An attacker may exploit this feature to obtain more information about the
set up of the remote host or to execute arbitrary commands with the privileges
of the web server.

Solution : Upgrade a newer version of this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of a debug output in AWStats";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
 req = http_get(item:url +"/awstats.pl?debug=2", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "DEBUG 2 - PluginMode=" >< res ) 
 {
        security_hole(port);
        exit(0);
 }
}

check(url:"/awstats");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
