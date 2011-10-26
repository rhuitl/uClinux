#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A network sound server is listening on the remote port.

Description :

The remote host is running a YIFF sound server, an open-source
network sound server.

See also :

http://wolfpack.twu.net/YIFF/

Risk factor : 

None";


if (description) {
  script_id(20092);
  script_version("$Revision: 1.3 $");

  script_name(english:"YIFF Sound Server Detection");
  script_summary(english:"Detects a YIFF sound server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/unknown", 9433);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(9433);
  if (!port)exit(0);
}
else port = 9433;
if (!get_tcp_port_state(port)) exit(0);


# Send a request for sound attributes, which is the first packet yplay sends.
soc = open_sock_tcp(port);
if (!soc) exit(0);

# nb: the actual name is irrelevant.
file = string("/usr/share/sounds/", SCRIPT_NAME, ".wav");
req = raw_string(
                                        # packet size, to be added later
  0x00, 0x0a,                           # constant (YSoundObjectAttributes from include/Y2/Y.h)
  0x00, 0x00,                           # constant (YSoundObjectAttributesGet from include/Y2/Y.h)
  file
);
req = raw_string(
  0x00, 0x00, 0x00, (strlen(req)+4),    # packet size, as promised
  req
);

send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:64);
if (isnull(res)) exit(0);


# It's a YIFF sound server if...
if (
  # it looks like a sound attributes response and...
  strlen(res) >= 22 && 
  substr(res, 4, 7) == raw_string(0x00, 0x0a, 0x00, 0x01) && 
  (
    # either the packet has our filename or...
    substr(res, 22) == file ||
    # it doesn't have a filename at all (ie, filename not found).
    strlen(res) == 22
  )
) {
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"yiff");

  security_note(port);
}
