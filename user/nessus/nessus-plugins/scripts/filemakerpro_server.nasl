#
# (C) 2003 Renaud Deraison
#
#

if (description)
{
  	script_id(11586);
  	script_bugtraq_id(7315);
 	script_version ("$Revision: 1.3 $");
	script_name(english: "FileMakerPro Detection");
	script_description(english:"
The remote host is running a FileMakerPro server on this port.

There is a flaw in the design of the FileMakerPro server which
makes the database authentication occur on the client side. 

An attacker may exploit this flaw to gain access to your databases
without knowing their password, only by connecting to this port
with a rogue client.

Solution : Do not store any sensitive data in your FileMakerPro database.
Risk factor : High");


	script_summary(english: "connects to port 49727 and says 'hello'");
	script_category(ACT_GATHER_INFO);
	script_family(english: "Remote file access");
	script_copyright(english: "This script is (C) 2003 Renaud Deraison");
	script_dependencie("find_service.nes");
	script_require_ports(5003);
	exit(0);
}

include("misc_func.inc");

port = 5003;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:raw_string(0x00, 0x04, 0x13, 0x00));
 r = recv(socket:soc, length:3);
 if(r == raw_string(0x00, 0x06, 0x14)){
  register_service(port:port, proto:"filemakerpro-server");
  security_hole(port);
 }
}

