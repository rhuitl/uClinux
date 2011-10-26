#
# This script was written by Tenable Network Security
# 
#
# See the Nessus Scripts License for details
#
# ref: http://marc.theaimsgroup.com/?l=bugtraq&m=105353283720837&w=2
#

if(description)
{
 script_id(11648);
 script_version ("$Revision: 1.3 $");
 
 script_name(english:"BlackMoon FTP user disclosure");
	     
 script_description(english:"
The remote FTP server issues a special error message
when a user attempts to log in using a nonexistent
account.

An attacker may use this flaw to make a list of valid accounts
by looking at the error messages it receives at authentication
time.

Solution : None at this time
Risk factor : Low");
 
 script_summary(english:"Checks for the ftp login error message");

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "logins.nasl", "smtp_settings.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 banner = ftp_recv_line(socket:soc);
 if(!banner)exit(0);
 send(socket:soc, data:string("USER nessus", rand(), rand(), "\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r)exit(0);
 
 send(socket:soc, data:string("PASS whatever\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r) exit(0);
 close(soc);
 if("530-Account does not exist" >< r) security_warning(port);
}
