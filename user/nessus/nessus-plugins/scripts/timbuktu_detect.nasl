#
# (C) Tenable Network Security
#



if(description)
{
  script_id(15891);
  script_version ("$Revision: 1.8 $");
 
  script_name(english:"Timbuktu Detection");
 
  desc["english"] = "
Synopsis :

A remote control service is running on the remote port.

Description :

Timbuktu Pro seems to be running on the remote host on this port. 

Timbuktu Pro is a remote control tool which lets a remote user take 
the control of the remote system (like the Terminal Services under Windows).

Make sure the use of this software is done in accordance with your corporate
security policy.

See also : 

http://www.netopia.com

Solution : 

If this service is not needed, disable it or filter incoming traffic
to this port. Otherwise make sure to use strong passwords for authentication.

Risk factor : 

None";


  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Timbuktu";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
  script_family(english:"Service detection");
  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown", 407);
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

if ( thorough_tests )
{
 port = get_unknown_svc(407);
 if ( ! port ) exit(0);
}
else port = 407;

if ( ! service_is_unknown(port:port) ) exit(0);
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:raw_string(0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

data = recv(socket:soc, length:6);
if ( strlen(data) == 6 && ord(data[0]) == 1 && ord(data[1]) == 1 ) 
 	{
	length = ord(data[5]);
	data = recv(socket:soc, length:length);
	if ( strlen(data) != length ) exit(0);
	#length = ord(data[38]);
	#if ( length + 39 >= strlen(data) ) exit(0);
	#hostname = substr(data, 39, 39 + length - 1);
 	security_note ( port );
	}
