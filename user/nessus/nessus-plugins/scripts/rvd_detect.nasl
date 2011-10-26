#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21676);
  script_version("$Revision: 1.2 $");

  script_name(english:"Rendezvous Daemon Detection");
  script_summary(english:"Gets info about rvd");

  desc = "
Synopsis :

There is a Rendezvous daemon listening on the remote host. 

Description :

The remote host is running a Rendezvous daemon on the specified port. 
Rendezvous is a commercial messaging software product used for
building distributed applications, and a Rendezvous daemon is the
central communications component of the software. 

See also :

http://www.tibco.com/software/messaging/rendezvous.jsp

Risk factor :

None";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 7500);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests)
{
  port = get_unknown_svc(7500);
  if (!port) exit(0);
}
else port = 7500;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Make sure the banner looks like it's from rvd.
res = recv(socket:soc, length:512);
pkt1 = 
  mkdword(0) + mkdword(4) + 
  mkdword(0);
if (strlen(res) != strlen(pkt1) || res != pkt1) exit(0);


# Send the first packet and check the return.
send(socket:soc, data:pkt1);
res = recv(socket:soc, length:512);
pkt2 = 
  mkdword(2) + mkdword(2) + 
  mkdword(0) + mkdword(1) +
  mkdword(0) + mkdword(0x4000000) + 
  mkdword(0x4000000) + mkdword(0) +
  mkdword(0) + mkdword(0) + 
  mkdword(0) + mkdword(0) +
  mkdword(0) + mkdword(0) + 
  mkdword(0) + mkdword(0);
if (strlen(res) != strlen(pkt2) || res != pkt2) exit(0);


# Send a second packet and check the return.
pkt2 = insstr(pkt2, mkdword(3), 0, 3);
send(socket:soc, data:pkt2);
pkt3 = insstr(pkt2, mkdword(1), 0, 3);
res = recv(socket:soc, length:512);
close(soc);
if (strlen(res) != strlen(pkt3) || res != pkt3) exit(0);


# This must be rvd since we've gotten the three packets we expected.
register_service(port:port, ipproto:"tcp", proto:"rvd");
security_note(port);
