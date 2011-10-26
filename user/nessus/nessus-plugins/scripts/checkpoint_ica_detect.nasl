#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host is a firewall. 

Description :

The remote host is running Check Point Firewall-1 and is operating a
web server on this port for its internal certificate authority (ICA),
which provides users with certificate revocation lists and registers
users when using the Policy Server. 

Note that it is not known whether it is possible to disable this
service or limit its access to only certain interfaces or addresses. 

See also :

http://www.checkpoint.com/products/firewall-1/index.html

Risk factor :

None";


if (description)
{
  script_id(22094);
  script_version("$Revision: 1.2 $");

  script_name(english:"Check Point Firewall-1 ICA Service Detection");
  script_summary(english:"Checks for Check Point ICA Service");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 18264);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:18264);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (banner && "Server: Check Point SVN" >< banner)
{
  res = http_get_cache(item:"/", port:port);
  if (res == NULL) exit(0);

  if ("<TITLE>Check Point Certificate Services</TITLE>" >< res)
  {
    security_note(port);

    register_service(port:port, ipproto:"tcp", proto:"cp_ica");
  }
}
