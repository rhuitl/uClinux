#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
  script_id(12117);
  script_version ("$Revision: 1.5 $");

  name["english"] = "HALO Network Server Detection";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

A game server has been detected on the remote host.

Description :

The remote host is running a version of HALO Network Server.
The Server is used to host Internet and Local Area Network (LAN)
games.  

Make sure that the use of this program is done in accordance with your
corporate security policy.

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";


  script_description(english:desc["english"]);
  summary["english"] = "Detects HALO Tournament Server";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  script_family(english:"Service detection");
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}


include("global_settings.inc");
if ( ! thorough_tests ) exit(0);
# start script
port = 2302;

sock = open_sock_udp(port);
if ( ! sock ) exit(0);

send (socket:sock, data:raw_string(0x5C, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5C) );

r = recv(socket:sock, length:512, timeout:3);

if ( ! r ) exit(0);

# OK, there are two modes...mode 1 is when the server is actively serving up a game
# in which case you'll get a long verbose reply from the server
# in mode 2, the server is in IDLE state and is not actively serving a game
# in mode 2, the server will just send back a quick 5 byte error msg to client

# mode 1
if (egrep(string:r, pattern:"hostname.*gamever.*maxplayers")) {
    security_note(port);
} 

# mode 2
if ( (strlen(r) == 5) && (ord(r[0]) == 0xFE) && (ord(r[0]) == 0xFE) ) security_note(port);
