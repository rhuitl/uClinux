#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22410);
  script_version("$Revision: 1.1 $");

  script_name(english:"Derby Network Server Detection");
  script_summary(english:"Detects a Derby Network Server");

  desc = "
Synopsis :

A Derby Network Server is listening on the remote host. 

Description :

The remote host is running a Derby (formerly Cloudscape) Network
Server, which allows for network access to the Derby database engine
on that host.  Derby itself is a Java-based relational database
developed by the Apache foundation. 

See also :

http://db.apache.org/derby/
http://en.wikipedia.org/wiki/Apache_Derby

Risk factor :

None";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1527);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(1527);
  if (!port) exit(0);
}
else port = 1527;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Probe the service.
#
# nb: this is based on NetworkServerControlImpl.java from Derby's source.
req = "CMD:" +                         # command header
  mkword(1) +                          # protocol version
  mkbyte(0) +                          # locale
  mkbyte(0) +                          # always zero
  mkbyte(6);                           # command (6 => sysinfo)
raw_string("CMD:", 0x00, 0x01, 0x00, 0x00, 0x06);
send(socket:soc, data:req);
res = recv(socket:soc, length:4096);


# If...
if (
  # the response is long enough and...
  strlen(res) > 6 &&
  # it starts with a reply header and..
  substr(res, 0, 3) == "RPY:" &&
  # the word at pos 5 is the length of the message and
  getword(blob:res, pos:5) == (strlen(res) - 7) &&
  # the message has either...
  (
    # an error because we're not on the loopback interface or...
    "DRDA_NeedLocalHost" >< res ||
    # a response to the sysinfo command
    "Network Server Information" >< res
  )
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"derby");
  security_note(port);
}
