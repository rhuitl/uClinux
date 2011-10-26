#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10731); 
 script_version ("$Revision: 1.10 $");
 name["english"] = "healthd detection";
 script_name(english:name["english"]);
 
desc["english"] = "
Synopsis :

healthd is listening on the remote port

Description :

The remote host is running healthd, a daemon which uses the
sensors of the remote host to report the temperature of various
of its components.

It is recommended to not let anyone connect to this port.

See also :

http://healthd.thehousleys.net/


Solution : 

Filter incoming traffic to this port, or disable this service
if you do not use it

Risk factor : 

None";

 script_description(english:desc["english"]);
 
 summary["english"] = "healthd detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_family(english: "Service detection");

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("find_service.nes");
 script_require_ports("Services/healthd", 1281);
 exit(0);
}

#
# The script code starts here
#
include('misc_func.inc');

port = get_kb_item("Services/healthd");
if ( ! port ) port = 1281;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'CFG Nessus\r\n');
r = recv_line(socket:soc, length:255);
if ( r && r =~ "^ERROR: Unknown class" )
{
 register_service(proto:"healthd", port:port);
 security_note(port);
}
 
