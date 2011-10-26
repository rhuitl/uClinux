#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15421);
 script_bugtraq_id(11326);
 script_version("$Revision: 1.1 $");
 name["english"] = "NetworkActive Web Server Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running NetworkActive Web Server - an alternative web server.

There is a vulnerability in the remote version of this software which may allow
an attacker to cause a denial of service against the remote server by sending
an HTTP GET request containing a '%25' character.

Solution : Upgrade to the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of NetworkActive Web Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
if ( egrep(pattern:"^Server: NetworkActiv-Web-Server/(0\.[0-9]|1\.0[^0-9])", string:banner) ) 
 {
   security_hole(port);
 }
