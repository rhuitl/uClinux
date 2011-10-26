#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A Java RMI remote object is listening on the remote host. 

Description :

The remote host is running a Java RMI remote object, which allows
one Java virtual machine to invoke methods on an object on another,
possibly remotely.

See also :

http://java.sun.com/products/jndi/tutorial/objects/storing/remote.html
http://java.sun.com/j2se/1.5.0/docs/guide/rmi/spec/rmiTOC.html
http://java.sun.com/j2se/1.5.0/docs/guide/rmi/spec/rmi-protocol3.html

Risk factor :

None";


if (description)
{
  script_id(22363);
  script_version("$Revision: 1.1 $");

  script_name(english:"RMI Remote Object Detection");
  script_summary(english:"Detects a remote object");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("rmiregistry_detect.nasl");
  script_require_ports("Services/unknown");

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! thorough_tests ) exit(0);

port = get_unknown_svc(0);             # nb: no default
if (!port) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Probe the service.
#
# nb: with the stream procotol, an endpoint must respond with an
#     endpoint identifier.
req1 = "JRMI" +                        # magic
  mkword(2) +                          # version
  mkbyte(0x4b);                        # protocol (0x4b => stream protocol)
send(socket:soc, data:req1);
res = recv(socket:soc, length:64);


# If...
if (
  # the response is long enough and...
  strlen(res) > 6 &&
  # it's a ProtocolAck and...
  getbyte(blob:res, pos:0) == 0x4e &&
  # it contains room for an endpoint identifier
  getword(blob:res, pos:1) + 7 == strlen(res)
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"rmi_remote_object");

  if (report_verbosity) name = get_kb_item("Services/rmi/" + port + "/name");
  if (name)
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "The remote object is referenced as :\n",
      "\n",
      "  rmi://", get_host_name(), ":", port, "/", name, "\n"
    );
  else report = desc;

  security_note(port:port, data:report);
}
