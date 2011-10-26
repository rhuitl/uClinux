#
# (C) Tenable Network Security
#


if (description) {
  script_id(20734);
  script_version("$Revision: 1.2 $");

  script_name(english:"CORBA IIOP Listener Detection");
  script_summary(english:"Detects a CORBA IIOP listener");

  desc = "
Synopsis :

There is a CORBA IIOP listener active on the remote host. 

Description :

The remote host is running a CORBA Internet Inter-ORB Protocol (IIOP)
listener on the specified port.  CORBA is a vendor-independent
architecture for applications that work together, and IIOP is a
protocol by which such applications can communicate over TCP/IP. 

See also :

http://www.omg.org/cgi-bin/doc?formal/04-03-01

Risk factor :

None";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 683);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(683);
  if (!port) exit(0);
}
else port = 683;
if (!get_tcp_port_state(port)) exit(0);


# Send a bogus request.
soc = open_sock_tcp(port);
if (!soc) exit(0);

req = raw_string(
                                       # message header
  "GIOP",                              #   magic
  0x01, 0x00,                          #   GIOP version (1.0)
  0x01,                                #   byte order (little-endian)
  0x00,                                #   message type (request)
  0x24, 0x00, 0x00, 0x00,              #   message size
                                       # request header
  0x00, 0x00, 0x00, 0x00,              #   service context list
  0x01, 0x00, 0x00, 0x00,              #   request ID
  0x01,                                #   response expected
  0x00, 0x00, 0x00,                    #   padding
  0x06, 0x00, 0x00, 0x00,              #   object key length and...
  rand_str(length:6),                  #     value
  0x00, 0x00,                          #   padding
  0x04, 0x00, 0x00, 0x00,              #   operation, length and...
  "get", 0x00,                         #     string value
  0x00, 0x00, 0x00, 0x00               #   requesting principal length
);
send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:1024);
close(soc);
if (isnull(res)) exit(0);


# It's IIOP if...
if (
  # the response is long enough and...
  strlen(res) >= 12 &&
  # it has the magic string "GIOP" and is for version 1.0 and...
  substr(res, 0, 5) == raw_string("GIOP", 0x01, 0x00) &&
  # it's a reply.
  ord(res[7]) == 1
) {
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"corba-iiop");

  security_note(port);
}
