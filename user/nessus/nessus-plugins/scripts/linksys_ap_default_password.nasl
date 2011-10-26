#
# This script was written by Renaud Deraison
#
# GPL
#
#

if(description)
{
 script_version ("$Revision: 1.7 $");
 script_id(11522);

 script_xref(name:"OSVDB", value:"821");

 script_name(english:"Linksys Router default password");
 
 
 desc["english"] = "
The remote Linksys device has its default password (no username / 'admin')
set. 

An attacker may connect to it and reconfigure it using this account.

Solution : Connect to this port with a web browser, and click on the 'Password'
section to set a strong password
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for the linksys default account";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

req = http_get(item:"/", port:port);
res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);

if ( egrep ( pattern:"^HTTP/.* 401 .*", string:res ) )
{
 req -= string("\r\n\r\n");
 req += string("\r\nAuthorization: Basic OmFkbWlu\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if (res == NULL ) exit(0);
 if ( egrep ( pattern:"^HTTP/.* 200 .*", string:res) )
	security_hole(port);
}

