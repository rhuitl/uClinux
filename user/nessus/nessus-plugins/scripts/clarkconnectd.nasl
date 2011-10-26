#
# Written by Renaud Deraison
#
#
# See the Nessus Scripts License for details
#
# Ref:
# Message-ID: <004201c2dc64$34aa6de0$24029dd9@tuborg>
# From: Knud Erik Højgaard <kain@ircop.dk>
# To: <bugtraq@securityfocus.com>
# Subject: clarkconnect(d) information disclosure


if(description)
{
 script_id(11277);
 script_bugtraq_id(6934);
 
 script_version ("$Revision: 1.1 $");
 name["english"] = "clarkconnectd detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The daemon 'clarkconnectd' seems to be running on
this port. This daemon can provide various sensitive
information to people connecting to it, such as the
list of running processes, the content of /var/log/messages,
the snort log file and more.

An attacker may use it to gain more knowledge about
this host.


Solution : Disable this service
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "clarkconnectd detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports(10005);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = 10005;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:string("P\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n"));
r = recv(socket:soc, length:1024);
close(soc);
if(egrep(string:r, pattern:"root.*init")){
	register_service(port:port, proto:"clarkconnectd");
	security_warning(port);
	}
