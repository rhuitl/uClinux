#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

A DCE/RPC server is listening on the remote host. 

Description :

The remote host is running a Windows RPC service. This service
replies to the RPC Bind Request with a Bind Ack response.

However it is not possible to determine the uuid of this service.

Risk factor :

None";


if (description)
{
 script_id(22319);
 script_version("$Revision: 1.1 $");

 script_name(english:"MSRPC Service Detection");
 script_summary(english:"Detects an MSRPC Service");

 script_description(english:desc);

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 script_require_ports("Services/unknown");
 script_dependencies("find_service2.nasl", "dcetest.nasl");

 exit(0);
}


include ('smb_func.inc');
include("misc_func.inc");
include("global_settings.inc");

if ( ! thorough_tests ) exit(0);

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

session_init (socket:soc);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"6e657373-7573-7465-6e61-626c65736563", vers:1);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

if (!resp || (strlen(resp) != 60))
  exit (0);

if ((ord(resp[0]) == 5) &&  # version
    (ord(resp[1]) == 0) &&  # version minor
    (ord(resp[2]) == 12))   # bind ack
{
 register_service(port:port, proto:"DCERPC");
 security_note (port); 
}
