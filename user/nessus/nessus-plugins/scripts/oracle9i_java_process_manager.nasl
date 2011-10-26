#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10851);
 script_bugtraq_id(4293);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2002-0563");
 name["english"] = "Oracle 9iAS Java Process Manager";
 name["francais"] = "Oracle 9iAS Java Process Manager";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

It is possible to obtain the list of Java processes running on the
remote host anonymously, as well as to start and stop them.

Description :

The remote host is an Oracle 9iAS server. By default, accessing
the location /oprocmgr-status via HTTP lets an attacker obtain
the list of processes running on the remote host, and even to
to start or stop them.

Solution : 

Restrict access to /oprocmgr-status in httpd.conf

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Oracle9iAS Java Process Manager";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for /oprocmgr-status

 req = http_get(item:"/oprocmgr-status", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Module Name" >< r)	
 	security_hole(port);

 }
}
