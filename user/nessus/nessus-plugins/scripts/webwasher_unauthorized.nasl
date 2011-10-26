#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16277);
 script_cve_id("CVE-2005-0316");
 script_bugtraq_id(12394); 
 script_version ("$Revision: 1.4 $");

 name["english"] = "WebWasher Classic HTTP CONNECT Unauthorized Access Weakness";

 script_name(english:name["english"]);
 
 desc["english"] = "
There is a flaw in the remote WebWasher Proxy.  The Proxy, when issued 
a CONNECT command for 127.0.0.1 (or localhost/loopback), will comply with
the request and initiate a connection to the local machine.

This bypasses any sort of firewalling as well as gives access to local
applications which are only bound to the loopback.

Solution: Upgrade to a version of WebWasher greater than 3.3.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of WebWasher Proxy";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

req = http_get(item:"/nessus345678.html", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
if( r == NULL )exit(0);

if ( "<html><head><title>WebWasher - Error 400: Bad Request</title>" >< r )
{
 if (egrep(pattern:"<small><i>generated .* by .* \(WebWasher ([0-2]\..*|3\.[0-3])\)</i></small>", string:r))
 {
   security_hole(port);
   exit(0);
 }
}
