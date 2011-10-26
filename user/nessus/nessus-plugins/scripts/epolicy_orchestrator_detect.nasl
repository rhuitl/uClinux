#
# (C) Tenable Network Security
#


if (description)
{
 script_id(22493);
 script_version("$Revision: 1.1 $");

 script_name(english:"ePolicy Orchestrator detection");
 script_summary(english:"Checks for McAfee ePO");
 
 desc = "
Synopsis :

The remote web server is an ePO console.

Description :

The remote host appears to be running McAfee ePolicy Orchestrator (ePO),
a security management solution.

Risk factor :

None";

  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include ("byte_func.inc");
include ("http_func.inc");
include ("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

set_byte_order (BYTE_ORDER_LITTLE_ENDIAN);

req = crap (data:"B", length:12) + crap (data:"A", length:0x3F) + raw_string (0) + crap (data:"C", length:0x100);

data = "PO" + mkdword(0x30000001) + mkdword(strlen(req)) + req;

data = string (
	"POST  /spipe?Source=nessus HTTP/1.0\r\n",
	"Content-Length: ", strlen(data), "\r\n",
	"\r\n",
	data
	);

buf = http_keepalive_send_recv (port:port, data:data, bodyonly:TRUE);

for (i=0;i<strlen(buf);i++)
  buf[i] = raw_string(ord(buf[i]) ^ 0xAA);

if (buf[0] != "P" || buf[1] != "O")
  exit (0);

code = getdword (blob:buf, pos:2);
if (code != 0x30000001)
  exit (0);

if ("RequestPublicKey" >< buf && "PackageType" >< buf)
  security_note (port);
