#
# This script was written by Tenable Network Security 
#

if(description)
{
 script_id(16475);
 script_bugtraq_id(12567);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "Lighttpd Remote CGI Script Disclosure Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Lighttpd, a small webserver.

This version of Lighttpd is vulnerable to a flaw wherein an attacker,
requesting a CGI script appended by a '%00', will be able to read the
source of the script.

Solution : Upgrade to lighttpd 1.3.8 or later
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Sami HTTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit (0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if ( egrep(pattern:"^Server: lighttpd/(0\.|1\.([0-2]\.|3\.[0-7][^0-9]))", string:banner) ) 
 {
   security_warning(port);
 }

