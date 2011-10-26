#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A Firebird / InterBase database server is listening on the remote
host. 

Description :

The remote host is running either a Firebird or an InterBase database
server. 

See also :

http://www.firebirdsql.org/
http://www.borland.com/us/products/interbase/

Risk factor :

None";


if (description)
{
  script_id(22269);
  script_version("$Revision: 1.2 $");

  script_name(english:"Firebird / InterBase Database Server Detection");
  script_summary(english:"Detects a Firebird / InterBase database server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 3050);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(3050);
  if (!port) exit(0);
}
else port = 3050;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a connection request.
path = string("/opt/firebird/", SCRIPT_NAME, ".gdb");
if (strlen(path) % 4 == 0) pad1 = "";
else pad1 = crap(data:raw_string(0x00), length:(4-(strlen(path)%4)));
me = this_host_name();
user = "nessus";
if ((strlen(me+user)+2) % 4 == 0) pad2 = "";
else pad2 = crap(data:raw_string(0x00), length:(4-((strlen(me+user)+2) % 4)));

req = mkdword(1) +                     # opcode (1 => connect)
  mkdword(0x13) +                      # ?
  mkdword(0x02) +                      # ?
  mkdword(0x24) +                      # ? (OS perhaps, 0x24 => unix, 0x1d => Windows)
  mkdword(strlen(path)) + path +       # path
  pad1 +                               # padding
  mkdword(2) +                         # ?
  mkdword(strlen(user+me)+6) +         # length
  mkbyte(0x01) +                       # ?
  mkbyte(strlen(user)) + user +        # user running isql
  mkbyte(0x04) +                       # ?
  mkbyte(strlen(me)) + me +            # my hostname
  mkbyte(6) + mkbyte(0) + pad2 +       # padding 
  mkdword(8) +                         # ?
    mkdword(1) +
    mkdword(2) +
    mkdword(3) +
    mkdword(2) +
    mkdword(0x0a) +
    mkdword(1) +
    mkdword(2) +
    mkdword(3) +
    mkdword(4);
send(socket:soc, data:req);
res = recv(socket:soc, length:2048);
close(soc);


# If ...
if (
  # response is 16 chars long and...
  strlen(res) == 16 &&
  # has an 'accept' opcode and...
  getdword(blob:res, pos:0) == 3 &&
  (
    # either we're not paranoid or
    report_paranoia < 2 ||
    # the full packet looks like what we'd get from running isql.
    (
      getdword(blob:res, pos:4) == 0x0a && 
      getdword(blob:res, pos:8) == 1 && 
      getdword(blob:res, pos:12) == 3
    )
  )
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"gds_db");
  security_note(port);
}
