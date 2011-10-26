#
# (C) Tenable Network Security
#

if (description) {
  script_id(19607);
  script_version("$Revision: 1.2 $");

  name["english"] = "HP OpenView Topology Manager Daemon Detection";
  script_name(english:name["english"]);
  
  desc["english"] = "
Synopsis :

An HP OpenView Topology Manager service is listening on this port.

Description :

The remote host is running HP OpenView Topology Manager Daemon 
for IP discovery and layout. This service is part of the HP OpenView
Management suite.

Solution :

If this service is not needed, disable it or filter incoming traffic to 
this port.

Risk factor : 

None";
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HP OpenView Topology Manager Daemon";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_require_ports(2532);
  exit(0);
}

include ("misc_func.inc");

port = 2532;
soc = open_sock_tcp (port);
if (!soc) exit (0);

req = raw_string (0x00,0x00,0x00,0x06,0x6e,0x65,0x73,0x73,0x75,0x73);

send (socket:soc, data:req);
buf = recv(socket:soc, length:16);

if ("0000000c000000020000000100000000" >< hexstr(buf))
{
  register_service (port:port, proto:"ovtopmd");
  security_note(port);
}
