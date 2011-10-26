#
# (C) Tenable Network Security
#


if (description) {
  script_id(20217);
  script_version("$Revision: 1.5 $");

  script_name(english:"iTunes Music Sharing Enabled");
  script_summary(english:"Checks for whether music sharing is enabled in iTunes");
 
  desc = "
Synopsis :

The remote host contains an application that may not match your corporate
security policy.

Description :

The version of iTunes on the remote host is configured to stream music between
hosts.

Such song sharing may not be in accordance with your security policy.

Solution :

Disable song sharing if desired or limit access to this port.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:3689);
if (!get_port_state(port)) exit(0);


# Look for the iTunes banner.
banner = get_http_banner(port:port);
if (!banner) exit(0);
if ("DAAP-Server: iTunes/" >< banner) {
  set_kb_item(name:"iTunes/" + port + "/enabled", value:TRUE);
  security_note(port);
}
