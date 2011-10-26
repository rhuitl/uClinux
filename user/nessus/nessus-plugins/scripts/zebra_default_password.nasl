#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16205);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(10935);
 
 script_name(english:"Zebra default password");
	     

 script_description(english:"
The remote host is running Zebra, a routing daemon.

The remote Zebra installation is set up with the password
'zebra'. An attacker may log in using this password and control
the routing tables of the remote host.

Solution : Edit zebra.conf and set up a strong password
Risk Factor : High");
		 
script_summary(english:"Logs into the remote host");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Firewalls");
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/zebra", 2601);
 exit(0);
}


include('telnet_func.inc');

port = get_kb_item("Services/zebra");
if ( ! port ) port = 2601;
if ( ! get_port_state(port) ) exit(0);


soc = open_sock_tcp(port);
if(!soc)return(0);

res = telnet_negotiate(socket:soc);
res += recv_until(socket:soc, pattern:"Password: ");
if ( ! res ) exit(0);

send(socket:soc, data:'zebra\r\n'); # Default password
res = recv_until(socket:soc, pattern:"> "); # Wait for the cmd prompt
send(socket:soc, data:'list\r\n'); # Issue a 'list' command
res = recv(socket:soc, length:4096);
if ( "show memory" >< res )
	security_hole(port);
