#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

A CheckPoint Firewall-1 Client Authentication web server is listening on 
this port.

Description :

The CheckPoint Firewall-1 Client Authentication web server is used to 
authenticate a user via HTTP. Once authenticated, the user can get more 
privileges on the network (ie: get access to hosts which were previously 
blocked by the firewall).

Solution :

If you do not use this feature, disable it.

Risk factor : 

None";

if(description)
{
 script_id(10676);
 script_version ("$Revision: 1.11 $");
 script_name(english:"CheckPoint Firewall-1 HTTP Client Authentication Detection");
 script_description(desc["english"]);

 script_summary(english:"Connects to FW1 Client Authentication Server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencies("http_version.nasl");
 script_require_ports(900);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = 900;
if (! get_port_state(port) ) exit(0);

res = http_get_cache(item:"/", port:port);
if ( ! res ) exit(0);

if ('<INPUT TYPE="hidden" NAME="STATE" VALUE="1">' >< res  && 'FireWall-1 message: ' >< res )
	{
		security_note(port);
 		register_service(port:port, proto:"cp-client-auth-web-svr");
	}
