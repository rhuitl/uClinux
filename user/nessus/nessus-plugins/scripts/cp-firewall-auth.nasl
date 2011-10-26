#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

A CheckPoint Firewall-1 Client Authentication server is listening on 
this port.

Description :

The CheckPoint Firewall-1 Client Authentication server is used to 
authenticate a user via telnet. Once authenticated, the user can get more 
privileges on the network (ie: get access to hosts which were previously 
blocked by the firewall).

Solution :

If you do not use this feature, disable it.

Risk factor : 

None";

if(description)
{
 script_id(10675);
 script_version ("$Revision: 1.8 $");
 script_name(english:"CheckPoint Firewall-1 Telnet Client Authentication Detection");
 script_description(desc["english"]);

 script_summary(english:"Connects to FW1 Client Authentication Server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_require_ports(259);
 exit(0);
}

include("misc_func.inc");

if ( ! get_port_state(259) ) exit(0);

soc = open_sock_tcp(259);
if ( ! soc ) exit(0);

r = recv_line(socket:soc, length:4096);
if ( "Check Point FireWall-1 Client Authentication Server running on " >< r )
{
 register_service(port:259, proto:"cp-client-auth-svr");
 report = desc["english"] + '\n\nPlugin output :\n\nThe banner of the remote service is :\n' + r;
 security_note(port:259, data:report);
}
 
