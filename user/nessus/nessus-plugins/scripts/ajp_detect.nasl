#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

There is an AJP connector listening on the remote host. 

Description :

The remote host is running an AJP (Apache JServ Protocol) connector, a
service by which a standalone web server such as Apache communicates
over TCP with a Java servlet container such as Tomcat. 

See also :

http://tomcat.apache.org/connectors-doc/
http://tomcat.apache.org/connectors-doc/common/ajpv13a.html

Risk factor :

None";


if (description)
{
  script_id(21186);
  script_version("$Revision: 1.2 $");

  script_name(english:"AJP Connector Detection");
  script_summary(english:"Sends AJP ping / nop packets");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 8007, 8009);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests)
{
  port = get_unknown_svc(8009);
  if ( ! port ) exit(0);
}
else port = 8009;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Various packets.
#
# - ajp13.
cping = raw_string(
  0x12, 0x34,                           # magic, web server -> container
  0x00, 0x01,                           # length
  0x0A                                  # CPing
);
cpong = raw_string(
  "AB",                                 # magic, container -> web server
  0x00, 0x01,                           # length
  0x09                                  # CPong
);
# - ajp12.
nop  = raw_string(0x00);
ping = raw_string(0xFE, 0x00);
pong = raw_string(0x00);


# Send a CPing and read the response.
send(socket:soc, data:cping);
res = recv(socket:soc, length:32);
close(soc);


proto = NULL;
if (res) 
{
  # It's an AJP13 connector if the response is a CPong.
  if (res == cpong) proto = "ajp13";
}
else {
  # Check whether it's AJP12.
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  send(socket:soc, data:ping);
  res = recv(socket:soc, length:32);
  close(soc);

  # If it looks like a valid reply...
  if (res && res == pong)
  {
    # Try a additional set of tests since the reply 
    # isn't necesssarily uncommon.
    soc = open_sock_tcp(port);
    if (!soc) exit(0);

    # Send a NOP packet; we shouldn't get a response.
    send(socket:soc, data:nop);
    res = recv(socket:soc, length:32);
    if (strlen(res)) exit(0);

    # Send a Ping; we should get a valid response.
    send(socket:soc, data:ping);
    res = recv(socket:soc, length:32);
    close(soc);

    # It's AJP12 if it looks like a valid response.
    if (res && res == pong) proto = "ajp12";
  }
}


# Register and report the service if detection was successful.
if (proto)
{
  register_service(port:port, ipproto:"tcp", proto:proto);

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "The connector listing on this port supports the ", proto, " protocol.\n"
  );
  security_note(port:port, data:report);
}
