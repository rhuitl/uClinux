#
# (C) Tenable Network Security
#


if (description) {
  script_id(20870);
  script_version("$Revision: 1.2 $");

  script_name(english:"LDAP Server Detection");
  script_summary(english:"Detects an LDAP server");

  desc = "
Synopsis :

There is an LDAP server active on the remote host. 

Description :

The remote host is running a Lightweight Directory Access Protocol, or
LDAP, server.  LDAP is a protocol for providing access to directory
services over TCP/IP. 

See also :

http://en.wikipedia.org/wiki/LDAP

Risk factor :

None";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 389);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(389);
  if (!port) exit(0);
}
else port = 389;
if (!get_tcp_port_state(port)) exit(0);


# Send a search request.
soc = open_sock_tcp(port);
if (!soc) exit(0);

msgid = rand() % 255;
req = raw_string(
  0x30,                                # universal sequence
  0x2f,                                # length of the request
  0x02, 0x01, msgid,                    # message id
  0x63,                                # search request
  0x2a,                                #   length
  0x04, 0x10,                          #   base DN
    "dc=nessus,dc=org",
  0x0a, 0x01, 0x02,                    #   scope (subtree)
  0x0a, 0x01, 0x00,                    #   dereference (never)
  0x02, 0x01, 0x00,                    #   size limit (0)
  0x02, 0x01, 0x00,                    #   time limit (0)
  0x01, 0x01, 0x00,                    #   attributes only (false)
  0xa2, 0x05, 0x87, 0x03,              #   filter (!(foo=*))
    "foo", 0x30, 0x00
);
send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:1024);
close(soc);
if (isnull(res)) exit(0);


# It's an LDAP server if...
if (
  # the response is a universal sequence and...
  res[0] == raw_string(0x30) &&
  # the response is long enough and...
  strlen(res) > 5 &&
  # it's a search result corresponding to our message id.
  substr(res, 2, 5) == raw_string(0x02, 0x01, msgid, 0x65)
) {
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"ldap");

  security_note(port);
}
