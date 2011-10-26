#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Pluto 26.6.00: rcvd_line -> rcvd
#
#T

if(description)
{
 script_id(10068);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0612");
 name["english"] = "Finger";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the 'finger' service.

The purpose of this service is to show who is currently logged
into the remote system, and to give information about the users
of the remote system. 
 
It provides useful information to attackers, since it allows them 
to gain usernames, determine how used a machine is, and see when
each user logged in for the last time. 


Solution :  
 Comment out the 'finger' line in /etc/inetd.conf and restart
 the inetd process

Risk factor : Low";

script_description(english:desc["english"]);
 
 summary["english"] = "Checks for finger";

script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("root\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  if(egrep(pattern:".*User|[lL]ogin|logged.*", string:data))
  {
 report = "
The 'finger' service provides useful information to attackers, since it allows 
them to gain usernames, check if a machine is being used, and so on... 

Here is the output we obtained for 'root' : " + string("\n\n", data, "\n\n") + 

"Solution : comment out the 'finger' line in /etc/inetd.conf
Risk factor : Low";

  	security_warning(port:port, data:report);
	set_kb_item(name:"finger/active", value:TRUE);
	}
  close(soc);
 }
}
