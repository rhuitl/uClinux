#
# (C) Tenable Network Security
#



if(description)
{
  script_id(16462);
  script_version ("$Revision: 1.2 $");
 
  script_name(english:"Rio Karma Network Port");
 
  desc["english"] = "
Synopsis :

A hardware device which may not be approved by your corporate security
policy is plugged on the network.

Description :

The remote device seems to be a Rio Karma MP3 player, running the Rio Kama
file upload service.

Make sure the use of such network devices are done in accordance with your 
corporate security policy.

Solution :

If this device is not needed, disable it or filter incoming traffic
to this IP address.

Risk factor : 

None";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detects a Rio Karma MP3 Player";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"Service detection");
  script_dependencie("find_service.nes");
  script_require_ports(8302);

  exit(0);
}


include("misc_func.inc");

if ( get_port_state(8302) == 0 ) exit(0);
soc = open_sock_tcp(8302);
if ( ! soc ) exit(0);

send(socket:soc, data:raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08));
r = recv(socket:soc, length:8);
if ( hexstr(r) == "5269c58d01000000" )
{
 register_service(port:8302, proto:"rio-karma-upload");
 security_note(8302);
}
