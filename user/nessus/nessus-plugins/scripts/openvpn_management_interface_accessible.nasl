#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21330);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2229");
  script_xref(name:"OSVDB", value:"25660");

  script_name(english:"OpenVPN Unprotected Management Interface Vulnerability");
  script_summary(english:"Looks for banner of OpenVPN Management Interface");

  desc = "
Synopsis :

The remote VPN server can be managed remotely without authentication. 

Description :

The remote host is running OpenVPN, an open-source SSL VPN. 

The version of OpenVPN installed on the remote host does not require
authentication to access the server's management interface.  An
attacker can leverage this issue to gain complete control over the
affected application simply by telneting in. 

See also :

http://www.securityfocus.com/archive/1/432863/30/60/threaded
http://openvpn.net/management.html

Solution :

Disable the management interface or bind it only to a specific
address, such as 127.0.0.1.

Risk factor :

Low / CVSS Base Score : 3.6
(AV:R/AC:H/Au:NR/C:P/I:N/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 7505);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# nb: there is no default port, but the documentation uses 7505.
if (thorough_tests) {
  port = get_unknown_svc(7505);
  if (!port) exit(0);
}
else port = 7505;
if (!port || !get_tcp_port_state(port)) exit(0);


# Check the server's banner.
banner = get_kb_item("Banner/"+port);
if (banner && "OpenVPN Management Interface Version" >< banner)
  security_note(port);
