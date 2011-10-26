#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A Pervasive PSQL / Btrieve server is listening on the remote host. 

Description :

The remote host is running Pervasive PSQL / Btrieve, a commercial
database engine. 

See also :

http://www.pervasive.com/psql/

Solution :

Limit incoming traffic to this port if desired. 

Risk factor :

None";


if (description)
{
  script_id(22528);
  script_version("$Revision: 1.1 $");

  script_name(english:"Pervasive PSQL / Btrieve Server Detection");
  script_summary(english:"Detects a Pervasive PSQL / Btrieve server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 3351);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(3351);
  if (!port) exit(0);
}
else port = 3351;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to authenticate.
user = SCRIPT_NAME;
pass = string(unixtime());
zero = raw_string(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
req = 
  mkdword(48) +
  mkword(1) +
  user + crap(data:zero, length:20-strlen(user)) +
  pass + crap(data:zero, length:20-strlen(pass)) +
  mkword(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# It's Pervasive PSQL / Btrieve if...
if (
  # the word at the first byte is the packet length and...
  (strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res)) &&
  # it's followed by a 1.
  getword(blob:res, pos:4) == 1
) 
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"btrieve");

  security_note(port);
}
