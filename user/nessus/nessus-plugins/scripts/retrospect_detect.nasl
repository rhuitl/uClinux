#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

There is a backup client installed on the remote host. 

Description :

The remote host is running a Retrospect backup client. Retrospect 
is a commercial backup product from EMC / Dantz. 

See also :

http://www.emcinsignia.com/

Risk factor :

None";


if (description) {
  script_id(20995);
  script_version("$Revision: 1.5 $");

  script_name(english:"Retrospect Client Detection");
  script_summary(english:"Detects a Retrospect Client");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/unknown", 497);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


function getosinfo (info)
{
 local_var major, minor;

 major = info >>> 16;
 minor = info & 0xFFFF;

 if (major > 10)
   return "Netware";

 if (major >= 2)
   return "Windows";

 if (major == 0)
 {
  if (minor == 0)
    return "RedHat Linux";

  if (minor == 1)
    return "Solaris";

  if ((minor >> 8) == 0x10)
    return string ("MacOS 10.", (minor >> 4) & 0x0F, ".", minor & 0xF);

  else
    return "Unknown Unix";
 }

 return "Unknown";
}


if (thorough_tests) {
  port = get_unknown_svc(497);
  if ( ! port ) exit(0);
}
else port = 497;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Packet sent by the server to test a client.
req = raw_string(
  0x00, 0x65, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
);
send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:1024);
close(soc);
if (isnull(res)) exit(0);


# It's a Retrospect client if...
if (
  # the size is correct.
  strlen(res) == 230 &&
  # the initial byte sequence is correct.
  substr(res, 0, 7) == raw_string(0x00, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0xda) 
) {
  # Extract some interesting bits of info.
  set_byte_order(BYTE_ORDER_BIG_ENDIAN);
  ostype = getdword(blob:res, pos:54);

  name = substr(res, 118);
  name = name - strstr(name, raw_string(0x00));

  ver = substr(res, 214);
  ver = ver - strstr(ver, raw_string(0x00));

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"retrospect");
  register_service(port:port, ipproto:"udp", proto:"retrospect");

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "  Client Name : ", name, "\n",
    "  Version     : ", ver, "\n",
    "  OS Type     : ", getosinfo (info:ostype), "\n"
  );

  security_note(port:port, data:report);

  set_kb_item(name:"Retrospect/"+port+"/Version", value:ver);
  set_kb_item(name:"Retrospect/"+port+"/OSType", value:ostype);
}
