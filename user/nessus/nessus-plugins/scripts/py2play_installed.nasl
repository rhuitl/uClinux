#
# (C) Tenable Network Security
#


if (description) {
  script_id(19759);
  script_version("$Revision: 1.6 $");

  name["english"] = "Py2Play Game Engine Detection";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

A game server has been detected on the remote host.

Description :

The remote host is running Py2Play, a peer-to-peer network game engine. Make
sure that this service has been installed in accordance with your security
policy.

See also : 

http://home.gna.org/oomadness/en/index.html

Solution :

If this service is not needed, disable it or filter incoming traffic to this port.

Risk factor : 

None";

  script_description(english:desc["english"]);

  summary["english"] = "Detects Py2Play Game Engine";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/unknown", 36079);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(36079);
  if (!port) exit(0);
}
else port = 36079;
if (!get_port_state(port)) exit(0);


# Add a player.
soc = open_sock_tcp(port);
if (!soc) exit(0);

c = "+";
send(socket:soc, data:c);
player = string(SCRIPT_NAME, "_", unixtime());
c = string("S'", player, "'\np1\n.");
send(socket:soc, data:c);
close(soc);


# Now list players.
soc = open_sock_tcp(port);
if (!soc) exit(0);

c = "p";
send(socket:soc, data:c);
s = recv(socket:soc, length:1024);
if (!strlen(s)) exit(0);


# There's a problem if...
if (
  # it looks like a Python pickle and...
  (ord(s[0]) == 0x80 && ord(s[1]) == 0x02) &&
  # our player was added.
  player >< s
) {
  security_note(port);

  register_service(port:port, ipproto:"tcp", proto:"py2play");
}
