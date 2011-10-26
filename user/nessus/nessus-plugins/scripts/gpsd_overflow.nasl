#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16265);
 script_bugtraq_id(12371);
 script_version("$Revision: 1.3 $");

 name["english"] = "gpsd remote format string vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running GPSD, a daemon which monitors a GPS device
and publishes its data over the network.

The remote version of this software is vulnerable to format string attack
due to the way it uses the syslog() call. An attacker may exploit this flaw
to execute arbitrary code on the remote host.

Solution : Upgrade to gpsd 2.8 or newer

See also : http://gpsd.berlios.de/

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote gpsd server";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/gpsd", 2947);
 exit(0);
}


port = get_kb_item("Services/gpsd");
if ( ! port ) port = 2947;

if ( ! get_port_state( port ) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'HELP\r\n');
r = recv_line(socket:soc, length:4096);
if ( ! r || "GPSD," >!< r ) exit(0);

version = ereg_replace(pattern:".*GPSD,.* ([0-9.]+) .*", string:r, replace:"\1");
if ( version == r ) exit(0);

if ( ereg(pattern:"^([01]|2\.[0-7]$)", string:version) )
	security_hole(port);
