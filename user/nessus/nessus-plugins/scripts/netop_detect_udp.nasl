#
# This NASL script has been produced as a collaboration between:
#
# - Martin O'Neal of Corsaire (http://www.corsaire.com)  
# - Jakob Bohm of Danware (http://www.danware.dk)
# 
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Neither Corsaire 
# or Danware accept any responsibility for any damage caused by the use or misuse 
# of this information.
# 




############## description ################

# declare description
if(description)
{
	script_id(15766);
	script_version ("$Revision: 1.3 $");
	name["english"]="NetOp products UDP detection";
	script_name(english:name["english"]);
	desc["english"]="
This script detects if the remote system has a Danware NetOp
program enabled and running on UDP.  These programs are used
for remote system administration, for telecommuting and for
live online training and usually allow authenticated users to
access the local system remotely.


Specific information will be given depending on the program
detected

Risk factor: Depends on the specific program detected";

	script_description(english:desc["english"]);
	summary["english"]=
	   "Determines if the remote host has any Danware NetOp program active on UDP";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english: "This NASL script is Copyright 2004 Corsaire Limited and Danware Data A/S.");
	script_family(english:"Service detection");
	script_dependencies("find_service.nes","find_service2.nasl");

	exit(0);
}



############## declarations ################

# includes
include('netop.inc');

# declare function
function test(port)
{
	# open connection
	socket=open_sock_udp(port);
	
	# check that connection succeeded
	if(socket)
	{
		########## packet one of one ##########
		
		# send packet
	  	send(socket:socket,data:helo_pkt_udp);
	
		# recieve response
		banner_pkt = recv(socket:socket, length:1500, timeout: 3);
		
		close(socket);
	    	
		# check response contains correct contents and
		#   log response accordingly.
		
		netop_check_and_add_banner();
	}
}



############## script ################

# initialise variables
local_var socket;
local_var ports;
addr=get_host_ip();
proto_nam='udp';

# test default ports
test(port:6502);
test(port:1971);

# retrieve and test unknown services
ports = get_kb_list("Ports/udp/*");
if ( isnull(ports) ) exit(0);
foreach port (keys(ports))
{
 	port = int ( port - "Ports/udp/" );
	if(get_udp_port_state(port))test(port:port);
}

exit(0);



############## End of UDP-specific detection script ################

