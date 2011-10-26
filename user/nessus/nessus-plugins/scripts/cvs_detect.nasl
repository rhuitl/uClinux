#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10051);
 script_version ("$Revision: 1.13 $");
 name["english"] = "CVS pserver detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A CVS pserver is listening on the remote port

Description :

CVS (Concurrent Versions System) is an open source versioning system.
A cvs server can be accessed either using third party tools (ie: rsh
or ssh), or via the 'pserver' protocol, which is unencrypted.

Solution :

Use cvs on top of RSH or SSH if possible

Risk factor : 

None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Detects a CVS pserver";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Service detection");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
# The script code starts here
#
port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
req = string("BEGIN AUTH REQUEST\n",
	"/\n",
	"\n",
	"A\n",
	"END AUTH REQUEST\n");
send(socket:soc, data:req);
r = recv_line(socket:soc, length:4096);
close(soc);
if("repository" >< r || "I HATE" >< r)
	security_note(port);
