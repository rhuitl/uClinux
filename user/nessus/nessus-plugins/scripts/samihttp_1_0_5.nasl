#
# This script was written by Tenable Network Security 
#

if(description)
{
 script_id(16468);
 script_bugtraq_id(12559);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "Sami HTTP Server Multiple vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running Sami HTTP Server, an HTTP server
for Windows.

The remote version of this software is prone to multiple vulnerabilities.
Sami HTTP server is vulnerable to a denial of service attack. An attacker
can exploit this flaw by sending '\r\n\r\n' string.

Sami HTTP server is vulnerable to a directory traversal vulnerability.
An attacker may exploit this flaw to gain access to sensitive data like
password file.

Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Sami HTTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Denial of Service";
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

if ( egrep(pattern:"Server:.*Sami HTTP Server v(0\.|1\.0\.[0-5][^0-9])", string:banner) ) 
 {
   security_hole(port);
 }

