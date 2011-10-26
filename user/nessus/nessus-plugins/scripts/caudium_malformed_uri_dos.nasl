#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15625);
 script_bugtraq_id( 11567 );
 script_version("$Revision: 1.1 $");
 name["english"] = "Caudium Web Server Malformed URI DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Caudium Web Server. 

The remote version of this software is vulnerable to an attack 
wherein a malformed URI causes the webserver to stop responding to 
requests. 

An attacker, exploiting this flaw, would only need to be able to 
connect to the Webserver and issue an HTTP 'GET' request to
disable this service.

Solution : Upgrade to Caudium 1.4.4 RC2 or newer
Risk Factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Caudium";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 443);
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
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server: Caudium/(0\..*|1\.[0-3]\.*|1\.4\.[0-3])", string:serv) )
 {
   security_hole(port);
 }
