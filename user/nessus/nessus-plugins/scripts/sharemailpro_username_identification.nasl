#
# This script was written by Tenable Network Security
# 
#
# See the Nessus Scripts License for details
#
# ref: 
#

if(description)
{
 script_id(11654);
 script_bugtraq_id(7658);
 script_version ("$Revision: 1.3 $");
 
 script_name(english:"ShareMailPro Username Identification");
	     
 script_description(english:"
The remote ShareMail server issues a special error message
when a user attempts to log in using a nonexistent POP
account.

An attacker may use this flaw to make a list of valid accounts
by looking at the error messages it receives at authentication
time.

Solution : None at this time
Risk factor : Low");
 
 script_summary(english:"Checks for the pop login error");

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here : 
#


port = get_kb_item("Services/pop3");
if(!port)port = 110;

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 banner = recv_line(socket:soc, length:4096);
 if(!banner)exit(0);
 send(socket:soc, data:string("USER nessus", rand(), rand(), "\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r)exit(0);
 if("-ERR sorry" >< r) { security_warning(port); }
}
