#
# (C) Tenable Network Security
#
#

  desc["english"] = "
Synopsis :

apcnisd, a daemon to manager a APC batter backup unit, is listening
on the remote port.

Description :

apcnisd is listening on this port.  This software is used to remotely 
manage APC battery backup units. Access to this port should be restricted
to authorized hosts only, as a flaw or a lack of authentication in this
service may allow an attacker to turn off the devices plugged into the
remote APC.

Solution :

Filter incoming traffic to this port.

Risk factor :

None";

if(description)
{
  script_id(11483);
  script_version ("$Revision: 1.7 $");
 
  script_name(english:"apcnisd detection");
 

  script_description(english:desc["english"]);
 
  summary["english"] = "Detects acpnisd";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  family["english"] = "Service detection";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "find_service2.nasl");
  script_require_ports("Services/unknown", 7000);

  exit(0);
}

include ("misc_func.inc");
include ("global_settings.inc");

if ( thorough_tests )
{
 port = get_unknown_svc(7000);
 if (! port) exit(0);
}
else port = 7000;

if (! get_port_state(port)) exit(0);

if (! service_is_unknown(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = raw_string(0x00, 0x06) + "status";

send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if("APC" >< r && "MODEL" >< r)
{
 report = desc["english"] + '\n\nPlugin output :\n' + r;
 register_service(port:port, proto:"apcnisd");
 security_note(port:port, data:report);
 exit(0);
}
