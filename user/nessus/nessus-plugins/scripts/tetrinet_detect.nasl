#
# This script was written by Michel Arboi <mikhail@nessus.org>
# GPL
# 


if(description)
{
 script_id(19608);
 script_version ("$Revision: 1.6 $");
 script_name(english: "Tetrinet server detection");
 
 desc = "
Synopsis :

A game server has been detected on the remote host.


Description :

The remote host runs a Tetrinet game server on this port. Make
sure the use of this software is done in accordance to your
security policy.

Solution :

If this service is not needed, disable it or filter incoming 
traffic to this port.

Risk factor : 

None";


 script_description(english:desc);

 script_summary(english: "Detect Tetrinet game server");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Service detection");
 script_require_ports("Services/unknown", 31457);
 script_dependencie("find_service.nes", "find_service2.nasl");
 exit(0);
}

########

include("misc_func.inc");
include("global_settings.inc");

c = '00469F2CAA22A72F9BC80DB3E766E7286C968E8B8FF212\xff';
if (thorough_tests)
 {
  port = get_unknown_svc(31457);
  if ( ! port ) exit(0);
 }
else
 port = 31457;
if (! get_port_state(port) || ! service_is_unknown(port: port)) exit(0);

s = open_sock_tcp(port);
if (!s) exit(0);

send(socket: s, data:c);
b = recv(socket: s, length: 1024);
if ( ! b ) exit(0);
if (match(string: b, pattern: 'winlist *'))
{
 security_note(port: port);
 register_service(port: port, proto: 'tetrinet');
}
