#
# (C) Tenable Network Security
#


if (description) {
  script_id(19600);
  script_version("$Revision: 1.1 $");

  name["english"] = "MERCUR Messaging Control Server Multiple Buffer overflow Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running MERCUR Messaging Control Server, a
telnet/web server to control MERCUR Messaging softwares.

The remote version of this software is vulnerable to multiple
buffer overflow vulnerabilites.
An attacker can exploit those flaws by sending specially crafted
packets to port 32000.
A successful exploitation of this vulnerability would result
in remote code execution.

See also : http://www.atrium-software.com/download/McrReadMe_EN.txt
Solution : Upgrade MERCUR Messaging to version 2005+SP3 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple buffer overflows in MERCUR Messaging Control Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports(32000);

  exit(0);
}


port = 32000;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

buf = recv (socket:soc, length:100);
if (!buf || ("MERCUR Control-Service" >!< buf))
  exit (0);

if (egrep (pattern:"^MERCUR Control-Service \(v([0-4]\.|5\.00\.(0[0-9]*|10)( |\)))", string:buf))
  security_hole(port);
