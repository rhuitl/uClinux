#
# (C) Tenable Network Security
#


if (description) {
  script_id(20340);
  script_version("$Revision: 1.2 $");

  script_name(english:"Network Block Device Server Detection");
  script_summary(english:"Detects a NBD server");

  desc = "
Synopsis :

The remote host is running a remote storage service.

Description :

The remote host is running a Network Block Device (NBD) server, which
allows one Linux host to use another as one of its block devices.

See also :

http://nbd.sourceforge.net/

Risk factor : 

None";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 2000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# nb: 2000 is used in the examples in the man pages but 
#     there's no default port.
if (thorough_tests) {
  port = get_unknown_svc(2000);
  if ( ! port ) exit(0);
}
else port = 2000;
if (!get_tcp_port_state(port)) exit(0);


# Establish a connection and examine the banner.
soc = open_sock_tcp(port);
if (soc) {
  res = recv(socket:soc, length:256);
  if (res == NULL) exit(0);

  # It's an NBD server if ...
  #
  # nb: clieserv.h from the source describes the initial packets from the server.
  if (
    # it is the right size and...
    strlen(res) == 152 &&
    # it starts with INIT_PASSWD and...
    stridx(res, "NBDMAGIC") == 0 &&
    # it's followed by cliserv_magic
    stridx(res, raw_string(0x00, 0x00, 0x42, 0x02, 0x81, 0x86, 0x12, 0x53)) == 8
  ) {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"nbd");

    security_note(port);
  }

  close(soc);
}
