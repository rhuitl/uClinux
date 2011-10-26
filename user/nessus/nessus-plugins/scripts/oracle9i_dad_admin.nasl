#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10849);
 script_version("$Revision: 1.9 $");
 name["english"] = "Oracle 9iAS DAD Admin interface";
 name["francais"] = "Oracle 9iAS DAD Admin interface";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
In a default installation of Oracle 9iAS, it is possible to access the 
mod_plsql DAD Admin interface. Access to these pages should be restricted.


Solution: 
Edit the wdbsvr.app file, and change the setting 'administrators=' to 
named users who are allowed admin privileges.

Reference : http://online.securityfocus.com/archive/1/155881

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for presence of Oracle9iAS DAD Admin interface";
 
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
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/portal30/admin_/", port:port);	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Gateway Configuration Menu" >< r)	
 	security_hole(port);

 }
}
