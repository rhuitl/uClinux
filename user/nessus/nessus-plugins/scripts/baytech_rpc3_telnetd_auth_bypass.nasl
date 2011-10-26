#
# (C) Tenable Network Security
#


if (description) {
  script_id(17663);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0957");
  script_bugtraq_id(12955);

  name["english"] = "BayTech RPC3 Telnet Daemon Authentication Bypass Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote TELNET server is affected by an authentication bypass flaw. 

Description :

The remote host is running a version of Bay Technical Associates RPC3
TELNET Daemon that lets a user bypass authentication by sending a
special set of keystrokes at the username prompt.  Since BayTech RPC3
devices provide remote power management, this vulnerability enables an
attacker to cause a denial of service, shut down the device itself as
well as any connected devices. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=111230568025271&w=2

Solution : 

None at this time.  Filter incoming traffic to port 23 on this device. 

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for authentication bypass vulnerability in BayTech RPC3 Telnet daemon";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_port_state(port)) exit(0);


buf = get_telnet_banner(port:port);
if (!buf || "RPC-3 Telnet Host" >!< buf) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);
buf = telnet_negotiate(socket:soc);
# If the banner indicates it's an RPC3 device...
if ("RPC-3 Telnet Host" >< buf) {
  # Send an ESC.
  send(socket:soc, data:raw_string(0x1b, "\r\n"));
  res = recv(socket:soc, length:1024);
  # If we get a command prompt, there's a problem.
  if (egrep(string:res, pattern:"^RPC-?3>")) security_hole(port);
}
close(soc);
